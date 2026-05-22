const std = @import("std");
const encode = @import("encode.zig");

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;

pub const Op = struct {
    kind: Kind,
    key: []u8,
    value: []u8,
};

pub const WriteBatch = struct {
    allocator: Allocator,
    ops: std.ArrayList(Op),

    pub fn init(allocator: Allocator) WriteBatch {
        return .{ .allocator = allocator, .ops = std.ArrayList(Op).init(allocator) };
    }

    pub fn deinit(self: *WriteBatch) void {
        for (self.ops.items) |op| {
            self.allocator.free(op.key);
            self.allocator.free(op.value);
        }
        self.ops.deinit();
    }

    pub fn put(self: *WriteBatch, key: []const u8, value: []const u8) !void {
        const keyCopy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(keyCopy);
        const valueCopy = try self.allocator.dupe(u8, value);
        try self.ops.append(.{ .kind = .value, .key = keyCopy, .value = valueCopy });
    }

    pub fn delete(self: *WriteBatch, key: []const u8) !void {
        const keyCopy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(keyCopy);
        const valueCopy = try self.allocator.dupe(u8, &.{});
        try self.ops.append(.{ .kind = .tombstone, .key = keyCopy, .value = valueCopy });
    }

    pub fn count(self: *const WriteBatch) usize {
        return self.ops.items.len;
    }
};

test "write batch accumulates typed ops" {
    const allocator = std.testing.allocator;
    var batch = WriteBatch.init(allocator);
    defer batch.deinit();

    try batch.put("alpha", "one");
    try batch.put("bravo", "two");
    try batch.delete("charlie");

    try std.testing.expectEqual(@as(usize, 3), batch.count());
    try std.testing.expectEqual(Kind.value, batch.ops.items[0].kind);
    try std.testing.expectEqualStrings("bravo", batch.ops.items[1].key);
    try std.testing.expectEqual(Kind.tombstone, batch.ops.items[2].kind);
    try std.testing.expectEqual(@as(usize, 0), batch.ops.items[2].value.len);
}
