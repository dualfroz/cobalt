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

    fn atEnd(self: *const CsvReader) bool {
        return self.pos >= self.data.len;
    }

    fn readField(self: *CsvReader, allocator: Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        if (!self.atEnd() and self.data[self.pos] == '"') {
            self.pos += 1;
            while (true) {
                if (self.atEnd()) return error.MalformedCsv;
                const c = self.data[self.pos];
                if (c == '"') {
                    self.pos += 1;
                    if (!self.atEnd() and self.data[self.pos] == '"') {
                        try out.append('"');
                        self.pos += 1;
                    } else {
                        break;
                    }
                } else {
                    try out.append(c);
                    self.pos += 1;
                }
            }
        } else {
            while (!self.atEnd()) {
                const c = self.data[self.pos];
                if (c == ',' or c == '\n' or c == '\r') break;
                try out.append(c);
                self.pos += 1;
            }
        }
        return out.toOwnedSlice();
    }

    /// Returns the next record (list of owned field slices), or null at
    /// end of input. Caller owns every field and the returned slice.
    fn nextRecord(self: *CsvReader, allocator: Allocator) !?[][]u8 {
        if (self.atEnd()) return null;
        var fields = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (fields.items) |f| allocator.free(f);
            fields.deinit();
        }

        while (true) {
            try fields.append(try self.readField(allocator));
            if (self.atEnd()) break;
            const c = self.data[self.pos];
            if (c == ',') {
                self.pos += 1;
                continue;
            } else if (c == '\n') {
                self.pos += 1;
                break;
            } else if (c == '\r') {
                self.pos += 1;
                if (!self.atEnd() and self.data[self.pos] == '\n') self.pos += 1;
                break;
            }
            return error.MalformedCsv;
        }
        return try fields.toOwnedSlice();
    }
};

pub fn importCsvContent(allocator: Allocator, table: *Table, content: []const u8) !usize {
    var csv = CsvReader{ .data = content };
    const header = try csv.nextRecord(allocator) orelse return 0;
    defer {
        for (header) |h| allocator.free(h);
        allocator.free(header);
    }

    var pkIndex: ?usize = null;
    for (header, 0..) |h, i| {
        if (std.mem.eql(u8, h, pkField)) {
            pkIndex = i;
            break;
        }
    }
    const pkIdx = pkIndex orelse return error.MissingPrimaryKey;

    var count: usize = 0;
    while (try csv.nextRecord(allocator)) |record| {
        defer {
            for (record) |f| allocator.free(f);
            allocator.free(record);
        }
        if (record.len != header.len) return error.MalformedCsv;

        var pk: ?Value = null;
        defer if (pk) |p| p.free(allocator);
        var fields = std.ArrayList(Field).init(allocator);
        defer {
            for (fields.items) |f| f.value.free(allocator);
            fields.deinit();
        }

        for (record, 0..) |cell, i| {
            if (cell.len == 0) continue;
            const value = try decodeCell(allocator, cell);
            if (i == pkIdx) {
                pk = value;
            } else {
                try fields.append(.{ .name = header[i], .value = value });
            }
        }
        const pkValue = pk orelse return error.MissingPrimaryKey;
        try table.put(pkValue, fields.items);
        count += 1;
    }
    return count;
}

pub fn importCsv(allocator: Allocator, table: *Table, path: []const u8) !usize {
    const content = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 30);
    defer allocator.free(content);
    return importCsvContent(allocator, table, content);
}

// --------------------------------------------------------------- JSON -----

pub fn exportJsonWriter(allocator: Allocator, table: *Table, writer: anytype) !usize {
    const rows = try table.scanAll();
    defer querymod.freeRows(allocator, rows);

    const columns = try collectColumns(allocator, rows);
    defer allocator.free(columns);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arenaAllocator = arena.allocator();

    var array = std.json.Array.init(arenaAllocator);
    for (rows) |r| {
        var object = std.json.ObjectMap.init(arenaAllocator);
        for (columns) |c| {
            if (r.get(c)) |v| {
                const cell = try encodeCell(arenaAllocator, v);
                try object.put(c, .{ .string = cell });
            }
        }
        try array.append(.{ .object = object });
    }

    try std.json.stringify(std.json.Value{ .array = array }, .{ .whitespace = .indent_2 }, writer);
    try writer.writeByte('\n');
    return rows.len;
}

pub fn exportJson(allocator: Allocator, table: *Table, path: []const u8) !usize {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buffered = std.io.bufferedWriter(file.writer());
    const n = try exportJsonWriter(allocator, table, buffered.writer());
    try buffered.flush();
    return n;
}

pub fn importJsonContent(allocator: Allocator, table: *Table, content: []const u8) !usize {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch return error.MalformedJson;
    defer parsed.deinit();

    const array = switch (parsed.value) {
        .array => |a| a,
        else => return error.MalformedJson,
    };

    var count: usize = 0;
    for (array.items) |entry| {
        const object = switch (entry) {
            .object => |o| o,
            else => return error.MalformedJson,
        };

        var pk: ?Value = null;
        defer if (pk) |p| p.free(allocator);
        var fields = std.ArrayList(Field).init(allocator);
        defer {
            for (fields.items) |f| f.value.free(allocator);
            fields.deinit();
        }

        for (object.keys(), object.values()) |name, jv| {
            const cell = switch (jv) {
                .string => |s| s,
                else => return error.MalformedJson,
            };
            const value = try decodeCell(allocator, cell);
            if (std.mem.eql(u8, name, pkField)) {
                pk = value;
            } else {
                try fields.append(.{ .name = name, .value = value });
            }
        }
        const pkValue = pk orelse return error.MissingPrimaryKey;
        try table.put(pkValue, fields.items);
        count += 1;
    }
    return count;
}

pub fn importJson(allocator: Allocator, table: *Table, path: []const u8) !usize {
    const content = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 30);
    defer allocator.free(content);
    return importJsonContent(allocator, table, content);
}

// --------------------------------------------------------------- tests ----

const testing = std.testing;

test "encodeCell decodeCell round trip every value tag" {
    const allocator = testing.allocator;
    const values = [_]Value{
        .{ .none = {} },
        .{ .boolean = true },
        .{ .boolean = false },
        .{ .int = -42 },
        .{ .int = 0 },
        .{ .float = 3.5 },
        .{ .float = -0.001 },
        .{ .text = "hello, \"world\"\n" },
        .{ .text = "" },
        .{ .bytes = &.{ 0, 1, 2, 255 } },
    };
    for (values) |v| {
        const cell = try encodeCell(allocator, v);
        defer allocator.free(cell);
        const decoded = try decodeCell(allocator, cell);
        defer decoded.free(allocator);
        try testing.expectEqual(@as(rowmod.ValueTag, v), @as(rowmod.ValueTag, decoded));
        try testing.expect(Value.eql(v, decoded));
    }
}

test "decodeCell rejects malformed cells" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidCell, decodeCell(allocator, ""));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "x"));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "q:1"));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "i:notanumber"));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "b:maybe"));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "x:abc"));
    try testing.expectError(error.InvalidCell, decodeCell(allocator, "x:zz"));
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

fn seedTable(table: *Table) !void {
    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
        .{ .name = "active", .value = .{ .boolean = true } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow, poland \"old town\"\nsecond line" } },
        .{ .name = "score", .value = .{ .float = -12.5 } },
    });
    try table.put(.{ .int = 3 }, &.{});
}

fn expectRoundTripped(table: *Table) !void {
    var r1 = (try table.get(.{ .int = 1 })).?;
    defer r1.deinit();
    try testing.expectEqualStrings("warsaw", r1.get("city").?.text);
    try testing.expectEqual(@as(i64, 30), r1.get("age").?.int);
    try testing.expectEqual(true, r1.get("active").?.boolean);

    var r2 = (try table.get(.{ .int = 2 })).?;
    defer r2.deinit();
    try testing.expectEqualStrings("krakow, poland \"old town\"\nsecond line", r2.get("city").?.text);
    try testing.expectEqual(@as(f64, -12.5), r2.get("score").?.float);
    try testing.expect(r2.get("age") == null);

    // Row 3 was put with zero extra fields, so its only field is the
    // primary key itself (`put` always stores that under `pkField`).
    var r3 = (try table.get(.{ .int = 3 })).?;
    defer r3.deinit();
    try testing.expectEqual(@as(usize, 1), r3.count());
    try testing.expectEqual(@as(i64, 3), r3.get(pkField).?.int);
}

test "csv export then import round trips every row and field exactly" {
    const allocator = testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "people");
    defer table.deinit();
    try seedTable(&table);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const exported = try exportCsvWriter(allocator, &table, buf.writer());
    try testing.expectEqual(@as(usize, 3), exported);

    var dstTmp = std.testing.tmpDir(.{});
    defer dstTmp.cleanup();
    var dstDb = try openTemp(&dstTmp, allocator);
    defer dstDb.close();
    var dstTable = try Table.open(&dstDb, allocator, "people");
    defer dstTable.deinit();

    const imported = try importCsvContent(allocator, &dstTable, buf.items);
    try testing.expectEqual(@as(usize, 3), imported);

    try expectRoundTripped(&dstTable);
}

