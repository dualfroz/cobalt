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
