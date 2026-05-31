const std = @import("std");
const dbmod = @import("db.zig");
const rowmod = @import("row.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Value = rowmod.Value;
const Field = rowmod.Field;
const Table = querymod.Table;
const pkField = querymod.pkField;

/// Table export/import to CSV and JSON, the two data-interchange formats
/// every other tool speaks. Rows are schema-less (`row.zig`'s `Row` is an
/// ordered field list, not a fixed struct), so both formats use a shared
/// "column set" step: scan once, then take the union of every field name
/// seen across every row (first-seen order, primary key first) as the
/// header/key set - a row missing a given column just omits that cell/key
/// rather than writing an empty or null placeholder, which is what makes
/// import's "cell absent" case unambiguous from "cell present but empty
/// text" (`s:` with a zero-length payload is a real, distinct encoding).
///
/// Every cell/value is written as a type-tagged string (`i:`/`f:`/`b:`/
/// `s:`/`x:`/`n:`, mirroring `Value.parseCli`'s prefixes plus `x:` for raw
/// bytes and `n:` for `.none`) rather than native CSV numbers or JSON
/// numbers/booleans - this is what lets both formats share one
/// encode/decode pair and round-trip every `ValueTag` exactly, including
/// floats (encoded as the exact bit pattern in hex, not a decimal that
/// could lose precision on the way back in).
fn encodeCell(allocator: Allocator, value: Value) ![]u8 {
    return switch (value) {
        .none => try allocator.dupe(u8, "n:"),
        .boolean => |b| try allocator.dupe(u8, if (b) "b:true" else "b:false"),
        .int => |v| try std.fmt.allocPrint(allocator, "i:{d}", .{v}),
        .float => |v| try std.fmt.allocPrint(allocator, "f:{x}", .{@as(u64, @bitCast(v))}),
        .text => |s| try std.fmt.allocPrint(allocator, "s:{s}", .{s}),
        .bytes => |b| blk: {
            var out = std.ArrayList(u8).init(allocator);
            errdefer out.deinit();
            try out.appendSlice("x:");
            for (b) |byte| try out.writer().print("{x:0>2}", .{byte});
            break :blk out.toOwnedSlice();
        },
    };
}

fn decodeCell(allocator: Allocator, text: []const u8) !Value {
    if (text.len < 2 or text[1] != ':') return error.InvalidCell;
    const payload = text[2..];
    return switch (text[0]) {
        'n' => .{ .none = {} },
        'b' => if (std.mem.eql(u8, payload, "true"))
            .{ .boolean = true }
        else if (std.mem.eql(u8, payload, "false"))
            .{ .boolean = false }
        else
            error.InvalidCell,
        'i' => .{ .int = std.fmt.parseInt(i64, payload, 10) catch return error.InvalidCell },
        'f' => blk: {
            const bits = std.fmt.parseInt(u64, payload, 16) catch return error.InvalidCell;
            break :blk .{ .float = @as(f64, @bitCast(bits)) };
        },
        's' => .{ .text = try allocator.dupe(u8, payload) },
        'x' => blk: {
            if (payload.len % 2 != 0) return error.InvalidCell;
            const bytes = try allocator.alloc(u8, payload.len / 2);
            errdefer allocator.free(bytes);
            var i: usize = 0;
            while (i < bytes.len) : (i += 1) {
                bytes[i] = std.fmt.parseInt(u8, payload[i * 2 .. i * 2 + 2], 16) catch return error.InvalidCell;
            }
            break :blk .{ .bytes = bytes };
        },
        else => error.InvalidCell,
    };
}

/// Union of every field name across `rows`, primary key first, everything
/// else in first-seen order - the shared column list both CSV's header row
/// and JSON's per-object keys iterate over.
fn collectColumns(allocator: Allocator, rows: []const rowmod.Row) ![][]const u8 {
    var columns = std.ArrayList([]const u8).init(allocator);
    errdefer columns.deinit();
    try columns.append(pkField);
    for (rows) |r| {
        for (r.fields.items) |f| {
            if (std.mem.eql(u8, f.name, pkField)) continue;
            var seen = false;
            for (columns.items) |c| {
                if (std.mem.eql(u8, c, f.name)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) try columns.append(f.name);
        }
    }
    return columns.toOwnedSlice();
}

// ---------------------------------------------------------------- CSV -----

fn writeCsvField(writer: anytype, field: []const u8) !void {
    const needsQuote = std.mem.indexOfAny(u8, field, ",\"\r\n") != null;
    if (!needsQuote) {
        try writer.writeAll(field);
        return;
    }
    try writer.writeByte('"');
    for (field) |c| {
        if (c == '"') try writer.writeByte('"');
        try writer.writeByte(c);
    }
    try writer.writeByte('"');
}

pub fn exportCsvWriter(allocator: Allocator, table: *Table, writer: anytype) !usize {
    const rows = try table.scanAll();
    defer querymod.freeRows(allocator, rows);

    const columns = try collectColumns(allocator, rows);
    defer allocator.free(columns);

    for (columns, 0..) |c, i| {
        if (i > 0) try writer.writeByte(',');
        try writeCsvField(writer, c);
    }
    try writer.writeByte('\n');

    for (rows) |r| {
        for (columns, 0..) |c, i| {
            if (i > 0) try writer.writeByte(',');
            if (r.get(c)) |v| {
                const cell = try encodeCell(allocator, v);
                defer allocator.free(cell);
                try writeCsvField(writer, cell);
            }
        }
        try writer.writeByte('\n');
    }
    return rows.len;
}

pub fn exportCsv(allocator: Allocator, table: *Table, path: []const u8) !usize {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buffered = std.io.bufferedWriter(file.writer());
    const n = try exportCsvWriter(allocator, table, buffered.writer());
    try buffered.flush();
    return n;
}

/// A minimal RFC4180-shaped reader: comma-separated fields, `"..."`
/// quoting with `""` as an escaped quote, records terminated by `\n` or
/// `\r\n`. Fields are freshly allocated (never slices into `data`) so a
/// quoted field's unescaped content can differ in length from its source
/// bytes.
const CsvReader = struct {
    data: []const u8,
    pos: usize = 0,

