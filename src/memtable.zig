const std = @import("std");
const encode = @import("encode.zig");

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Record = encode.Record;

const maxLevel = 16;

const Node = struct {
    key: []u8,
    value: []u8,
    seq: u64,
    kind: Kind,
    forward: []?*Node,
    backward: ?*Node,
};

pub const Memtable = struct {
    allocator: Allocator,
    head: *Node,
    level: usize,
    byteSize: usize,
    count: usize,
    rngState: u64,

    pub fn init(allocator: Allocator) !Memtable {
        const head = try makeNode(allocator, &.{}, &.{}, 0, .value, maxLevel);
        return .{
            .allocator = allocator,
            .head = head,
            .level = 1,
            .byteSize = 0,
            .count = 0,
            .rngState = 0x243f6a8885a308d3,
        };
    }

    pub fn deinit(self: *Memtable) void {
        var node = self.head.forward[0];
        while (node) |current| {
            const nextNode = current.forward[0];
            self.freeNode(current);
            node = nextNode;
        }
        self.allocator.free(self.head.forward);
        self.allocator.destroy(self.head);
    }

    pub fn clear(self: *Memtable) void {
        var node = self.head.forward[0];
        while (node) |current| {
            const nextNode = current.forward[0];
            self.freeNode(current);
            node = nextNode;
        }
        var i: usize = 0;
        while (i < maxLevel) : (i += 1) self.head.forward[i] = null;
        self.level = 1;
        self.byteSize = 0;
        self.count = 0;
    }

    pub fn upsert(self: *Memtable, kind: Kind, seq: u64, key: []const u8, value: []const u8) !void {
        var update: [maxLevel]*Node = undefined;
        var node = self.head;
        var lvl: usize = self.level;
        while (lvl > 0) {
            lvl -= 1;
            while (node.forward[lvl]) |next| {
                if (std.mem.order(u8, next.key, key) == .lt) {
                    node = next;
                } else break;
            }
            update[lvl] = node;
        }

        const candidate = node.forward[0];
        if (candidate) |existing| {
            if (std.mem.eql(u8, existing.key, key)) {
                const newValue = try self.allocator.dupe(u8, value);
                self.byteSize = self.byteSize - existing.value.len + newValue.len;
                self.allocator.free(existing.value);
                existing.value = newValue;
                existing.seq = seq;
                existing.kind = kind;
                return;
            }
        }

        const newLevel = self.randomLevel();
        if (newLevel > self.level) {
            var i = self.level;
            while (i < newLevel) : (i += 1) update[i] = self.head;
            self.level = newLevel;
        }

        const created = try makeNode(self.allocator, key, value, seq, kind, newLevel);
        var i: usize = 0;
        while (i < newLevel) : (i += 1) {
            created.forward[i] = update[i].forward[i];
            update[i].forward[i] = created;
        }
        created.backward = if (update[0] == self.head) null else update[0];
        if (created.forward[0]) |successor| successor.backward = created;
        self.byteSize += key.len + value.len;
        self.count += 1;
    }

    pub fn find(self: *const Memtable, key: []const u8) ?Record {
        var node = self.head;
        var lvl: usize = self.level;
        while (lvl > 0) {
            lvl -= 1;
            while (node.forward[lvl]) |next| {
                if (std.mem.order(u8, next.key, key) == .lt) {
                    node = next;
                } else break;
            }
        }
        const candidate = node.forward[0];
        if (candidate) |existing| {
            if (std.mem.eql(u8, existing.key, key)) return nodeRecord(existing);
        }
        return null;
    }

    pub fn findAsOf(self: *const Memtable, key: []const u8, maxSeq: u64) ?Record {
        const rec = self.find(key) orelse return null;
        if (rec.seq > maxSeq) return null;
        return rec;
    }

    pub fn cursor(self: *const Memtable, start: ?[]const u8) Cursor {
        var node = self.head;
        if (start) |startKey| {
            var lvl: usize = self.level;
            while (lvl > 0) {
                lvl -= 1;
                while (node.forward[lvl]) |next| {
                    if (std.mem.order(u8, next.key, startKey) == .lt) {
                        node = next;
                    } else break;
                }
            }
        }
        return .{ .current = node.forward[0] };
    }

    pub fn cursorRev(self: *const Memtable, end: ?[]const u8, endInclusive: bool) ReverseCursor {
        var node = self.head;
        var lvl: usize = self.level;
        while (lvl > 0) {
            lvl -= 1;
            while (node.forward[lvl]) |next| {
                const withinEnd = if (end) |bound|
                    (if (endInclusive) std.mem.order(u8, next.key, bound) != .gt else std.mem.order(u8, next.key, bound) == .lt)
                else
                    true;
                if (withinEnd) {
                    node = next;
                } else break;
            }
        }
        return .{ .current = if (node == self.head) null else node };
    }

    fn randomLevel(self: *Memtable) usize {
        var lvl: usize = 1;
        while (lvl < maxLevel and (self.nextRandom() & 0x3) == 0) : (lvl += 1) {}
        return lvl;
    }

    fn nextRandom(self: *Memtable) u64 {
        var x = self.rngState;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rngState = x;
        return x;
    }

    fn freeNode(self: *Memtable, node: *Node) void {
        self.allocator.free(node.key);
        self.allocator.free(node.value);
        self.allocator.free(node.forward);
        self.allocator.destroy(node);
    }
};

pub const Cursor = struct {
    current: ?*Node,

    pub fn valid(self: *const Cursor) bool {
        return self.current != null;
    }

    pub fn record(self: *const Cursor) Record {
        return nodeRecord(self.current.?);
    }

    pub fn advance(self: *Cursor) void {
        self.current = self.current.?.forward[0];
    }
};

pub const ReverseCursor = struct {
    current: ?*Node,

    pub fn valid(self: *const ReverseCursor) bool {
        return self.current != null;
    }

    pub fn record(self: *const ReverseCursor) Record {
        return nodeRecord(self.current.?);
    }

    pub fn advance(self: *ReverseCursor) void {
        self.current = self.current.?.backward;
    }
};

fn nodeRecord(node: *Node) Record {
    return .{ .key = node.key, .value = node.value, .seq = node.seq, .kind = node.kind };
}

fn makeNode(allocator: Allocator, key: []const u8, value: []const u8, seq: u64, kind: Kind, level: usize) !*Node {
    const node = try allocator.create(Node);
    errdefer allocator.destroy(node);
    node.key = try allocator.dupe(u8, key);
    errdefer allocator.free(node.key);
    node.value = try allocator.dupe(u8, value);
    errdefer allocator.free(node.value);
    node.seq = seq;
    node.kind = kind;
    node.backward = null;
    node.forward = try allocator.alloc(?*Node, level);
    var i: usize = 0;
    while (i < level) : (i += 1) node.forward[i] = null;
    return node;
}

test "memtable put get" {
    const allocator = std.testing.allocator;
    var mt = try Memtable.init(allocator);
    defer mt.deinit();

    try mt.upsert(.value, 1, "banana", "yellow");
    try mt.upsert(.value, 2, "apple", "red");
    try mt.upsert(.value, 3, "cherry", "dark");

    try std.testing.expectEqualStrings("red", mt.find("apple").?.value);
    try std.testing.expectEqualStrings("yellow", mt.find("banana").?.value);
    try std.testing.expectEqual(@as(?Record, null), mt.find("durian"));
    try std.testing.expectEqual(@as(usize, 3), mt.count);
}

test "memtable overwrite and tombstone" {
    const allocator = std.testing.allocator;
    var mt = try Memtable.init(allocator);
    defer mt.deinit();

    try mt.upsert(.value, 1, "key", "first");
    try mt.upsert(.value, 2, "key", "second");
    try std.testing.expectEqualStrings("second", mt.find("key").?.value);
    try std.testing.expectEqual(@as(usize, 1), mt.count);

    try mt.upsert(.tombstone, 3, "key", "");
    try std.testing.expectEqual(Kind.tombstone, mt.find("key").?.kind);
}

test "memtable sorted cursor" {
    const allocator = std.testing.allocator;
    var mt = try Memtable.init(allocator);
    defer mt.deinit();

    var buf: [16]u8 = undefined;
    var i: usize = 200;
    while (i > 0) : (i -= 1) {
        const key = try std.fmt.bufPrint(&buf, "k{d:0>4}", .{i});
        try mt.upsert(.value, i, key, "v");
    }

    var cur = mt.cursor(null);
    var prev: [16]u8 = undefined;
    var prevLen: usize = 0;
    var seen: usize = 0;
    while (cur.valid()) : (cur.advance()) {
        const rec = cur.record();
        if (prevLen > 0) try std.testing.expect(std.mem.order(u8, prev[0..prevLen], rec.key) == .lt);
        @memcpy(prev[0..rec.key.len], rec.key);
        prevLen = rec.key.len;
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 200), seen);
}

test "memtable cursor seek" {
    const allocator = std.testing.allocator;
    var mt = try Memtable.init(allocator);
    defer mt.deinit();

    try mt.upsert(.value, 1, "a", "1");
    try mt.upsert(.value, 2, "c", "3");
    try mt.upsert(.value, 3, "e", "5");

    var cur = mt.cursor("b");
    try std.testing.expectEqualStrings("c", cur.record().key);
}

test "memtable reverse cursor descends" {
    const allocator = std.testing.allocator;
    var mt = try Memtable.init(allocator);
    defer mt.deinit();

    var buf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "k{d:0>4}", .{i});
        try mt.upsert(.value, i + 1, key, "v");
    }

    var cur = mt.cursorRev(null, false);
    var expected: usize = 50;
    var seen: usize = 0;
    while (cur.valid()) : (cur.advance()) {
        expected -= 1;
        const key = try std.fmt.bufPrint(&buf, "k{d:0>4}", .{expected});
        try std.testing.expectEqualStrings(key, cur.record().key);
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 50), seen);

    var bounded = mt.cursorRev("k0010", false);
    try std.testing.expectEqualStrings("k0009", bounded.record().key);

    var inclusive = mt.cursorRev("k0010", true);
    try std.testing.expectEqualStrings("k0010", inclusive.record().key);
}
