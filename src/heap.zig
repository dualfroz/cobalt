const std = @import("std");
const Allocator = std.mem.Allocator;

/// Binary heap ordered by `lessThan(context, a, b)`: parent never compares
/// greater than either child under that relation. Pass a comparator that
/// returns `a > b` to get a max-heap out of the same implementation.
pub fn MinHeap(comptime T: type, comptime Context: type, comptime lessThan: fn (context: Context, a: T, b: T) bool) type {
    return struct {
        items: std.ArrayList(T),
        context: Context,

        const Self = @This();

        pub fn init(allocator: Allocator, context: Context) Self {
            return .{ .items = std.ArrayList(T).init(allocator), .context = context };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit();
        }

        pub fn len(self: *const Self) usize {
            return self.items.items.len;
        }

        pub fn peek(self: *const Self) ?T {
            if (self.items.items.len == 0) return null;
            return self.items.items[0];
        }

        pub fn push(self: *Self, item: T) !void {
            try self.items.append(item);
            self.siftUp(self.items.items.len - 1);
        }

        pub fn pop(self: *Self) ?T {
            if (self.items.items.len == 0) return null;
            const top = self.items.items[0];
            const last = self.items.pop();
            if (self.items.items.len > 0) {
                self.items.items[0] = last;
                self.siftDown(0);
            }
            return top;
        }

        /// Swap the root for `item` and restore the heap property in one
        /// siftDown, instead of a pop() (siftDown) followed by a push()
        /// (siftUp). Caller must ensure the heap is non-empty.
        pub fn replaceTop(self: *Self, item: T) T {
            const old = self.items.items[0];
            self.items.items[0] = item;
            self.siftDown(0);
            return old;
        }

        fn siftUp(self: *Self, startIdx: usize) void {
            var idx = startIdx;
            while (idx > 0) {
                const parent = (idx - 1) / 2;
                if (!lessThan(self.context, self.items.items[idx], self.items.items[parent])) break;
                std.mem.swap(T, &self.items.items[idx], &self.items.items[parent]);
                idx = parent;
            }
        }

        fn siftDown(self: *Self, startIdx: usize) void {
            var idx = startIdx;
            const n = self.items.items.len;
            while (true) {
                const left = idx * 2 + 1;
                const right = idx * 2 + 2;
                var smallest = idx;
                if (left < n and lessThan(self.context, self.items.items[left], self.items.items[smallest])) smallest = left;
                if (right < n and lessThan(self.context, self.items.items[right], self.items.items[smallest])) smallest = right;
                if (smallest == idx) break;
                std.mem.swap(T, &self.items.items[idx], &self.items.items[smallest]);
                idx = smallest;
            }
        }

        /// Debug helper: verifies the heap invariant holds at every node.
        pub fn isValid(self: *const Self) bool {
            const n = self.items.items.len;
            var idx: usize = 0;
            while (idx < n) : (idx += 1) {
                const left = idx * 2 + 1;
                const right = idx * 2 + 2;
                if (left < n and lessThan(self.context, self.items.items[left], self.items.items[idx])) return false;
                if (right < n and lessThan(self.context, self.items.items[right], self.items.items[idx])) return false;
            }
            return true;
        }
    };
}

fn u32Less(_: void, a: u32, b: u32) bool {
    return a < b;
}
const U32Heap = MinHeap(u32, void, u32Less);

test "heap: empty peek/pop return null" {
    var heap = U32Heap.init(std.testing.allocator, {});
    defer heap.deinit();
    try std.testing.expectEqual(@as(?u32, null), heap.peek());
    try std.testing.expectEqual(@as(?u32, null), heap.pop());
    try std.testing.expectEqual(@as(usize, 0), heap.len());
}

test "heap: push/pop yields ascending order" {
    var heap = U32Heap.init(std.testing.allocator, {});
    defer heap.deinit();
    const values = [_]u32{ 5, 1, 9, 3, 3, 7, 0, 42, 2 };
    for (values) |v| try heap.push(v);
    try std.testing.expectEqual(values.len, heap.len());

    var sorted = values;
    std.mem.sort(u32, &sorted, {}, std.sort.asc(u32));

    for (sorted) |expected| {
        try std.testing.expectEqual(@as(?u32, expected), heap.peek());
        try std.testing.expectEqual(@as(?u32, expected), heap.pop());
    }
    try std.testing.expectEqual(@as(usize, 0), heap.len());
}

test "heap: peek does not remove" {
    var heap = U32Heap.init(std.testing.allocator, {});
    defer heap.deinit();
    try heap.push(10);
    try heap.push(4);
    try std.testing.expectEqual(@as(?u32, 4), heap.peek());
    try std.testing.expectEqual(@as(?u32, 4), heap.peek());
    try std.testing.expectEqual(@as(usize, 2), heap.len());
}

test "heap: replaceTop matches pop-then-push" {
    var a = U32Heap.init(std.testing.allocator, {});
    defer a.deinit();
    var b = U32Heap.init(std.testing.allocator, {});
    defer b.deinit();
    for ([_]u32{ 8, 2, 6, 1, 9 }) |v| {
        try a.push(v);
        try b.push(v);
    }

    const old = a.replaceTop(5);
    try std.testing.expectEqual(@as(u32, 1), old);
    _ = b.pop();
    try b.push(5);

    while (a.len() > 0) {
        try std.testing.expectEqual(a.pop().?, b.pop().?);
    }
}

test "heap: random stress matches sort reference and stays valid" {
    var prng = std.Random.DefaultPrng.init(0xC0BA17);
    const random = prng.random();
    var heap = U32Heap.init(std.testing.allocator, {});
    defer heap.deinit();

    var reference = std.ArrayList(u32).init(std.testing.allocator);
    defer reference.deinit();

    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const v = random.intRangeAtMost(u32, 0, 1000);
        try heap.push(v);
        try reference.append(v);
        try std.testing.expect(heap.isValid());
    }

    std.mem.sort(u32, reference.items, {}, std.sort.asc(u32));
    for (reference.items) |expected| {
        try std.testing.expectEqual(@as(?u32, expected), heap.pop());
        try std.testing.expect(heap.isValid());
    }
    try std.testing.expectEqual(@as(usize, 0), heap.len());
}

test "heap: interleaved push and pop stays valid" {
    var prng = std.Random.DefaultPrng.init(0xFEED);
    const random = prng.random();
    var heap = U32Heap.init(std.testing.allocator, {});
    defer heap.deinit();

    var count: usize = 0;
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        if (count == 0 or random.boolean()) {
            try heap.push(random.intRangeAtMost(u32, 0, 100));
            count += 1;
        } else {
            const popped = heap.pop();
            try std.testing.expect(popped != null);
            count -= 1;
        }
        try std.testing.expect(heap.isValid());
        try std.testing.expectEqual(count, heap.len());
    }
}

fn descU32(_: void, a: u32, b: u32) bool {
    return a > b;
}
const MaxU32Heap = MinHeap(u32, void, descU32);

test "heap: inverted comparator behaves as a max-heap" {
    var heap = MaxU32Heap.init(std.testing.allocator, {});
    defer heap.deinit();
    for ([_]u32{ 3, 1, 4, 1, 5, 9, 2, 6 }) |v| try heap.push(v);

    var sorted = [_]u32{ 3, 1, 4, 1, 5, 9, 2, 6 };
    std.mem.sort(u32, &sorted, {}, std.sort.desc(u32));
    for (sorted) |expected| try std.testing.expectEqual(@as(?u32, expected), heap.pop());
}

const Weighted = struct { key: []const u8, seq: u32 };

fn keyLess(_: void, a: Weighted, b: Weighted) bool {
    return std.mem.order(u8, a.key, b.key) == .lt;
}
const KeyHeap = MinHeap(Weighted, void, keyLess);

test "heap: k-way merge of pre-sorted lists matches full sort" {
    const allocator = std.testing.allocator;
    const lists = [_][]const []const u8{
        &[_][]const u8{ "apple", "cherry", "fig", "kiwi" },
        &[_][]const u8{ "banana", "date", "eggplant" },
        &[_][]const u8{"lemon"},
        &[_][]const u8{},
    };

    const Cursor = struct { list: []const []const u8, idx: usize };
    var cursors: [lists.len]Cursor = undefined;
    for (lists, 0..) |list, i| cursors[i] = .{ .list = list, .idx = 0 };

    var heap = KeyHeap.init(allocator, {});
    defer heap.deinit();
    for (cursors, 0..) |c, i| {
        if (c.idx < c.list.len) try heap.push(.{ .key = c.list[c.idx], .seq = @intCast(i) });
    }

    var merged = std.ArrayList([]const u8).init(allocator);
    defer merged.deinit();
    while (heap.pop()) |top| {
        try merged.append(top.key);
        var c = &cursors[top.seq];
        c.idx += 1;
        if (c.idx < c.list.len) try heap.push(.{ .key = c.list[c.idx], .seq = top.seq });
    }

    var expected = std.ArrayList([]const u8).init(allocator);
    defer expected.deinit();
    for (lists) |list| try expected.appendSlice(list);
    std.mem.sort([]const u8, expected.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    try std.testing.expectEqual(expected.items.len, merged.items.len);
    for (expected.items, merged.items) |e, m| try std.testing.expectEqualStrings(e, m);
}
