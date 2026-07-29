const std = @import("std");

const Allocator = std.mem.Allocator;

/// Dynamically typed value stored inside a row field, an index key, or a
/// primary key. Kept small and copyable by tag; owned byte payloads (text,
/// bytes) are heap-allocated and must be freed by whoever owns the Row/Value.
pub const ValueTag = enum(u8) {
    none = 0,
    boolean = 1,
    int = 2,
    float = 3,
    text = 4,
    bytes = 5,
};

pub const Value = union(ValueTag) {
    none: void,
    boolean: bool,
    int: i64,
    float: f64,
    text: []const u8,
    bytes: []const u8,

    pub fn dupe(self: Value, allocator: Allocator) !Value {
        return switch (self) {
            .text => |s| .{ .text = try allocator.dupe(u8, s) },
            .bytes => |s| .{ .bytes = try allocator.dupe(u8, s) },
            else => self,
        };
    }

    pub fn free(self: Value, allocator: Allocator) void {
        switch (self) {
            .text => |s| allocator.free(s),
            .bytes => |s| allocator.free(s),
            else => {},
        }
    }

    pub fn eql(a: Value, b: Value) bool {
        return compare(a, b) == .eq;
    }

    /// Parses a single CLI/query-language token into a typed Value, using the
    /// same `i:`/`f:`/`b:`/`s:` type-prefix convention throughout the CLI
    /// (unprefixed tokens default to text). The returned `.text`/`.bytes`
    /// payload (when present) is a slice into `text` - callers that need it
    /// to outlive `text` must `dupe` the result.
    pub fn parseCli(text: []const u8) error{InvalidValue}!Value {
        if (std.mem.startsWith(u8, text, "i:")) {
            const n = std.fmt.parseInt(i64, text[2..], 10) catch return error.InvalidValue;
            return .{ .int = n };
        } else if (std.mem.startsWith(u8, text, "f:")) {
            const f = std.fmt.parseFloat(f64, text[2..]) catch return error.InvalidValue;
            return .{ .float = f };
        } else if (std.mem.startsWith(u8, text, "b:")) {
            if (std.mem.eql(u8, text[2..], "true")) return .{ .boolean = true };
            if (std.mem.eql(u8, text[2..], "false")) return .{ .boolean = false };
            return error.InvalidValue;
        } else if (std.mem.startsWith(u8, text, "s:")) {
            return .{ .text = text[2..] };
        } else {
            return .{ .text = text };
        }
    }
};

/// Total order across all values: first by type tag, then by payload. This
/// keeps a well-defined ordering even when a field holds mixed types across
/// rows, which the ordered byte encoding below must mirror exactly.
pub fn compare(a: Value, b: Value) std.math.Order {
    const ta = @intFromEnum(@as(ValueTag, a));
    const tb = @intFromEnum(@as(ValueTag, b));
    if (ta != tb) return std.math.order(ta, tb);
    return switch (a) {
        .none => .eq,
        .boolean => |av| std.math.order(@intFromBool(av), @intFromBool(b.boolean)),
        .int => |av| std.math.order(av, b.int),
        .float => |av| std.math.order(av, b.float),
        .text => |av| std.mem.order(u8, av, b.text),
        .bytes => |av| std.mem.order(u8, av, b.bytes),
    };
}

pub const Field = struct {
    name: []const u8,
    value: Value,
};

/// Self-describing, schema-less row: an ordered list of named fields. Rows
/// are the unit stored under a table's primary-key row keys and are what
/// query.zig hands back from scans and index lookups.
pub const Row = struct {
    allocator: Allocator,
    fields: std.ArrayList(Field),

    pub fn init(allocator: Allocator) Row {
        return .{ .allocator = allocator, .fields = std.ArrayList(Field).init(allocator) };
    }

    pub fn deinit(self: *Row) void {
        for (self.fields.items) |f| {
            self.allocator.free(f.name);
            f.value.free(self.allocator);
        }
        self.fields.deinit();
    }

    /// Sets a field, replacing any existing field with the same name. Copies
    /// both the name and any owned payload of `value` into the row.
    pub fn set(self: *Row, name: []const u8, value: Value) !void {
        const owned = try value.dupe(self.allocator);
        errdefer owned.free(self.allocator);
        for (self.fields.items) |*f| {
            if (std.mem.eql(u8, f.name, name)) {
                f.value.free(self.allocator);
                f.value = owned;
                return;
            }
        }
        const nameCopy = try self.allocator.dupe(u8, name);
        try self.fields.append(.{ .name = nameCopy, .value = owned });
    }

    pub fn get(self: *const Row, name: []const u8) ?Value {
        for (self.fields.items) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    pub fn count(self: *const Row) usize {
        return self.fields.items.len;
    }

    /// Serializes the row to a self-contained byte blob suitable as a Db
    /// value: [u32 fieldCount] { [u16 nameLen][name][u8 tag][payload] }*.
    pub fn encode(self: *const Row, allocator: Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try putU32(&out, @intCast(self.fields.items.len));
        for (self.fields.items) |f| {
            try putU16(&out, @intCast(f.name.len));
            try out.appendSlice(f.name);
            try out.append(@intFromEnum(@as(ValueTag, f.value)));
            switch (f.value) {
                .none => {},
                .boolean => |v| try out.append(if (v) 1 else 0),
                .int => |v| try putU64(&out, @bitCast(v)),
                .float => |v| try putU64(&out, @bitCast(v)),
                .text, .bytes => |s| {
                    try putU32(&out, @intCast(s.len));
                    try out.appendSlice(s);
                },
            }
        }
        return out.toOwnedSlice();
    }

    pub fn decode(allocator: Allocator, data: []const u8) !Row {
        var row = Row.init(allocator);
        errdefer row.deinit();
        var pos: usize = 0;
        const fieldCount = try readU32(data, &pos);
        var i: u32 = 0;
        while (i < fieldCount) : (i += 1) {
            const nameLen = try readU16(data, &pos);
            if (pos + nameLen > data.len) return error.Malformed;
            const name = data[pos .. pos + nameLen];
            pos += nameLen;
            if (pos >= data.len) return error.Malformed;
            const tag: ValueTag = std.meta.intToEnum(ValueTag, data[pos]) catch return error.Malformed;
            pos += 1;
            const value: Value = switch (tag) {
                .none => .{ .none = {} },
                .boolean => blk: {
                    if (pos >= data.len) return error.Malformed;
                    const b = data[pos];
                    pos += 1;
                    break :blk .{ .boolean = b != 0 };
                },
                .int => .{ .int = @bitCast(try readU64(data, &pos)) },
                .float => .{ .float = @bitCast(try readU64(data, &pos)) },
                .text => blk: {
                    const len = try readU32(data, &pos);
                    if (pos + len > data.len) return error.Malformed;
                    const s = data[pos .. pos + len];
                    pos += len;
                    break :blk .{ .text = s };
                },
                .bytes => blk: {
                    const len = try readU32(data, &pos);
                    if (pos + len > data.len) return error.Malformed;
                    const s = data[pos .. pos + len];
                    pos += len;
                    break :blk .{ .bytes = s };
                },
            };
            try row.set(name, value);
        }
        if (pos != data.len) return error.Malformed;
        return row;
    }
};

fn putU16(out: *std.ArrayList(u8), v: u16) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    try out.appendSlice(&b);
}

fn putU32(out: *std.ArrayList(u8), v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(&b);
}

fn putU64(out: *std.ArrayList(u8), v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(&b);
}

fn readU16(data: []const u8, pos: *usize) !u16 {
    if (pos.* + 2 > data.len) return error.Malformed;
    const v = std.mem.readInt(u16, data[pos.*..][0..2], .little);
    pos.* += 2;
    return v;
}

fn readU32(data: []const u8, pos: *usize) !u32 {
    if (pos.* + 4 > data.len) return error.Malformed;
    const v = std.mem.readInt(u32, data[pos.*..][0..4], .little);
    pos.* += 4;
    return v;
}

fn readU64(data: []const u8, pos: *usize) !u64 {
    if (pos.* + 8 > data.len) return error.Malformed;
    const v = std.mem.readInt(u64, data[pos.*..][0..8], .little);
    pos.* += 8;
    return v;
}

/// Appends an order-preserving byte encoding of `value` to `out`, such that
/// lexicographic byte comparison of two encodings matches `compare()` of the
/// original values. Used to build index keys and primary-key suffixes that
/// must sort correctly inside the LSM tree's byte-ordered keyspace.
///
/// Text/bytes payloads are escaped (0x00 -> 0x00 0xFF) and terminated with
/// 0x00 0x00 so that concatenating several encoded values back to back stays
/// unambiguous and order-preserving (no payload can be a byte-for-byte prefix
/// of another once escaped and terminated).
pub fn appendOrdered(out: *std.ArrayList(u8), value: Value) !void {
    try out.append(@intFromEnum(@as(ValueTag, value)));
    switch (value) {
        .none => {},
        .boolean => |v| try out.append(if (v) 1 else 0),
        .int => |v| {
            const flipped: u64 = @as(u64, @bitCast(v)) ^ 0x8000000000000000;
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, flipped, .big);
            try out.appendSlice(&b);
        },
        .float => |v| {
            var bits: u64 = @bitCast(v);
            if (bits & 0x8000000000000000 != 0) {
                bits = ~bits;
            } else {
                bits |= 0x8000000000000000;
            }
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, bits, .big);
            try out.appendSlice(&b);
        },
        .text, .bytes => |s| {
            for (s) |byte| {
                if (byte == 0x00) {
                    try out.appendSlice(&.{ 0x00, 0xFF });
                } else {
                    try out.append(byte);
                }
            }
            try out.appendSlice(&.{ 0x00, 0x00 });
        },
    }
}

pub fn encodeOrdered(allocator: Allocator, value: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try appendOrdered(&out, value);
    return out.toOwnedSlice();
}

/// Encodes a single standalone Value using the same (non order-preserving)
/// tag+payload format as a Row field, minus the field name. Used to store
/// primary keys as index-entry values, where later exact reconstruction
/// matters more than byte ordering.
pub fn encodeValue(allocator: Allocator, value: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(@intFromEnum(@as(ValueTag, value)));
    switch (value) {
        .none => {},
        .boolean => |v| try out.append(if (v) 1 else 0),
        .int => |v| try putU64(&out, @bitCast(v)),
        .float => |v| try putU64(&out, @bitCast(v)),
        .text, .bytes => |s| {
            try putU32(&out, @intCast(s.len));
            try out.appendSlice(s);
        },
    }
    return out.toOwnedSlice();
}

pub fn decodeValue(allocator: Allocator, data: []const u8) !Value {
    var pos: usize = 0;
    if (pos >= data.len) return error.Malformed;
    const tag: ValueTag = std.meta.intToEnum(ValueTag, data[pos]) catch return error.Malformed;
    pos += 1;
    return switch (tag) {
        .none => .{ .none = {} },
        .boolean => blk: {
            if (pos >= data.len) return error.Malformed;
            break :blk .{ .boolean = data[pos] != 0 };
        },
        .int => .{ .int = @bitCast(try readU64(data, &pos)) },
        .float => .{ .float = @bitCast(try readU64(data, &pos)) },
        .text => blk: {
            const len = try readU32(data, &pos);
            if (pos + len > data.len) return error.Malformed;
            break :blk .{ .text = try allocator.dupe(u8, data[pos .. pos + len]) };
        },
        .bytes => blk: {
            const len = try readU32(data, &pos);
            if (pos + len > data.len) return error.Malformed;
            break :blk .{ .bytes = try allocator.dupe(u8, data[pos .. pos + len]) };
        },
    };
}

test "row set get overwrite and free" {
    const allocator = std.testing.allocator;
    var row = Row.init(allocator);
    defer row.deinit();

    try row.set("name", .{ .text = "ada" });
    try row.set("age", .{ .int = 30 });
    try row.set("name", .{ .text = "ada lovelace" });

    try std.testing.expectEqual(@as(usize, 2), row.count());
    try std.testing.expectEqualStrings("ada lovelace", row.get("name").?.text);
    try std.testing.expectEqual(@as(i64, 30), row.get("age").?.int);
    try std.testing.expect(row.get("missing") == null);
}

test "row encode decode round trip all types" {
    const allocator = std.testing.allocator;
    var row = Row.init(allocator);
    defer row.deinit();

    try row.set("id", .{ .int = -42 });
    try row.set("score", .{ .float = 3.5 });
    try row.set("active", .{ .boolean = true });
    try row.set("bio", .{ .text = "hello world" });
    try row.set("blob", .{ .bytes = &.{ 0, 1, 2, 255 } });
    try row.set("nothing", .{ .none = {} });

    const encoded = try row.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try Row.decode(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(i64, -42), decoded.get("id").?.int);
    try std.testing.expectEqual(@as(f64, 3.5), decoded.get("score").?.float);
    try std.testing.expectEqual(true, decoded.get("active").?.boolean);
    try std.testing.expectEqualStrings("hello world", decoded.get("bio").?.text);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 255 }, decoded.get("blob").?.bytes);
    try std.testing.expectEqual(ValueTag.none, @as(ValueTag, decoded.get("nothing").?));
}

test "row decode rejects malformed data" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.Malformed, Row.decode(allocator, &.{ 1, 0, 0, 0 }));
    try std.testing.expectError(error.Malformed, Row.decode(allocator, &.{ 1, 0, 0, 0, 5, 0, 'a' }));
}

test "compare orders by type tag then payload" {
    try std.testing.expectEqual(std.math.Order.lt, compare(.{ .none = {} }, .{ .boolean = false }));
    try std.testing.expectEqual(std.math.Order.lt, compare(.{ .int = 5 }, .{ .float = 0.0 }));
    try std.testing.expectEqual(std.math.Order.lt, compare(.{ .int = -5 }, .{ .int = 3 }));
    try std.testing.expectEqual(std.math.Order.gt, compare(.{ .text = "b" }, .{ .text = "a" }));
    try std.testing.expect(Value.eql(.{ .text = "x" }, .{ .text = "x" }));
}

test "appendOrdered preserves int order across sign boundary" {
    const allocator = std.testing.allocator;
    const values = [_]i64{ std.math.minInt(i64), -1000, -1, 0, 1, 1000, std.math.maxInt(i64) };
    var prev: ?[]u8 = null;
    defer if (prev) |p| allocator.free(p);
    for (values) |v| {
        const encoded = try encodeOrdered(allocator, .{ .int = v });
        if (prev) |p| {
            try std.testing.expect(std.mem.order(u8, p, encoded) == .lt);
            allocator.free(p);
        }
        prev = encoded;
    }
}

test "appendOrdered preserves float order across sign and magnitude" {
    const allocator = std.testing.allocator;
    const values = [_]f64{ -100.0, -1.5, -0.001, 0.0, 0.001, 1.5, 100.0 };
    var prev: ?[]u8 = null;
    defer if (prev) |p| allocator.free(p);
    for (values) |v| {
        const encoded = try encodeOrdered(allocator, .{ .float = v });
        if (prev) |p| {
            try std.testing.expect(std.mem.order(u8, p, encoded) == .lt);
            allocator.free(p);
        }
        prev = encoded;
    }
}

test "appendOrdered escapes embedded zero bytes unambiguously" {
    const allocator = std.testing.allocator;
    const a = try encodeOrdered(allocator, .{ .text = "ab" });
    defer allocator.free(a);
    const b = try encodeOrdered(allocator, .{ .text = "ab\x00c" });
    defer allocator.free(b);
    const c = try encodeOrdered(allocator, .{ .text = "ab" ++ "c"[0..0] });
    defer allocator.free(c);
    // "ab" must sort before "ab\x00c" (shorter, unescaped terminator wins),
    // and the escaped embedded zero must not corrupt ordering.
    try std.testing.expect(std.mem.order(u8, a, b) == .lt);
    try std.testing.expect(std.mem.eql(u8, a, c));
}

test "encodeValue decodeValue round trip" {
    const allocator = std.testing.allocator;
    const original = Value{ .text = "primary-key-42" };
    const encoded = try encodeValue(allocator, original);
    defer allocator.free(encoded);
    const decoded = try decodeValue(allocator, encoded);
    defer decoded.free(allocator);
    try std.testing.expectEqualStrings("primary-key-42", decoded.text);

    const intEncoded = try encodeValue(allocator, .{ .int = -7 });
    defer allocator.free(intEncoded);
    const intDecoded = try decodeValue(allocator, intEncoded);
    try std.testing.expectEqual(@as(i64, -7), intDecoded.int);
}

test "appendOrdered text ordering matches string ordering" {
    const allocator = std.testing.allocator;
    const words = [_][]const u8{ "apple", "banana", "banjo", "zebra" };
    var prev: ?[]u8 = null;
    defer if (prev) |p| allocator.free(p);
    for (words) |w| {
        const encoded = try encodeOrdered(allocator, .{ .text = w });
        if (prev) |p| {
            try std.testing.expect(std.mem.order(u8, p, encoded) == .lt);
            allocator.free(p);
        }
        prev = encoded;
    }
}

test "parseCli honors type prefixes and defaults to text" {
    try std.testing.expectEqual(@as(i64, 42), (try Value.parseCli("i:42")).int);
    try std.testing.expectEqual(@as(i64, -3), (try Value.parseCli("i:-3")).int);
    try std.testing.expectEqual(@as(f64, 1.5), (try Value.parseCli("f:1.5")).float);
    try std.testing.expectEqual(true, (try Value.parseCli("b:true")).boolean);
    try std.testing.expectEqual(false, (try Value.parseCli("b:false")).boolean);
    try std.testing.expectEqualStrings("hi", (try Value.parseCli("s:hi")).text);
    try std.testing.expectEqualStrings("plain", (try Value.parseCli("plain")).text);
}

test "parseCli rejects malformed prefixed values" {
    try std.testing.expectError(error.InvalidValue, Value.parseCli("i:notanumber"));
    try std.testing.expectError(error.InvalidValue, Value.parseCli("f:notafloat"));
    try std.testing.expectError(error.InvalidValue, Value.parseCli("b:maybe"));
}
