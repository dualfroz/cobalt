const std = @import("std");

const Allocator = std.mem.Allocator;

pub const BlockKey = struct {
    fileId: u64,
    offset: u64,
};

pub const CacheStats = struct {
    hits: u64 = 0,
    misses: u64 = 0,

    pub fn hitRate(self: CacheStats) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }
};

const Node = struct {
    key: BlockKey,
    bytes: []u8,
    prev: ?*Node,
    next: ?*Node,
};

pub const BlockCache = struct {
    allocator: Allocator,
    capacityBytes: usize,
    currentBytes: usize,
    map: std.AutoHashMap(BlockKey, *Node),
    head: ?*Node,
    tail: ?*Node,
    stats: CacheStats,

    pub fn init(allocator: Allocator, capacityBytes: usize) BlockCache {
        return .{
            .allocator = allocator,
            .capacityBytes = capacityBytes,
            .currentBytes = 0,
            .map = std.AutoHashMap(BlockKey, *Node).init(allocator),
            .head = null,
            .tail = null,
            .stats = .{},
        };
    }

    pub fn deinit(self: *BlockCache) void {
        var node = self.head;
        while (node) |current| {
            const nextNode = current.next;
            self.allocator.free(current.bytes);
            self.allocator.destroy(current);
            node = nextNode;
        }
        self.map.deinit();
    }

    pub fn get(self: *BlockCache, key: BlockKey) ?[]const u8 {
        if (self.map.get(key)) |node| {
            self.detach(node);
            self.pushFront(node);
            self.stats.hits += 1;
            return node.bytes;
        }
        self.stats.misses += 1;
        return null;
    }

    pub fn put(self: *BlockCache, key: BlockKey, bytes: []const u8) !void {
        if (self.map.get(key)) |node| {
            self.currentBytes = self.currentBytes - node.bytes.len + bytes.len;
            self.allocator.free(node.bytes);
            node.bytes = try self.allocator.dupe(u8, bytes);
            self.detach(node);
            self.pushFront(node);
            try self.evict();
            return;
        }
        const node = try self.allocator.create(Node);
        errdefer self.allocator.destroy(node);
        node.* = .{
            .key = key,
            .bytes = try self.allocator.dupe(u8, bytes),
            .prev = null,
            .next = null,
        };
        errdefer self.allocator.free(node.bytes);
        try self.map.put(key, node);
        self.currentBytes += node.bytes.len;
        self.pushFront(node);
        try self.evict();
    }

    fn evict(self: *BlockCache) !void {
        while (self.currentBytes > self.capacityBytes and self.map.count() > 1) {
            const victim = self.tail orelse break;
            self.detach(victim);
            _ = self.map.remove(victim.key);
            self.currentBytes -= victim.bytes.len;
            self.allocator.free(victim.bytes);
            self.allocator.destroy(victim);
        }
    }

    fn detach(self: *BlockCache, node: *Node) void {
        if (node.prev) |p| p.next = node.next else self.head = node.next;
        if (node.next) |n| n.prev = node.prev else self.tail = node.prev;
        node.prev = null;
        node.next = null;
    }

    fn pushFront(self: *BlockCache, node: *Node) void {
        node.prev = null;
        node.next = self.head;
        if (self.head) |h| h.prev = node;
        self.head = node;
        if (self.tail == null) self.tail = node;
    }
};
