const std = @import("std");

const Allocator = std.mem.Allocator;

pub const defaultCapacity: usize = 256;

pub const Message = struct {
    channel: []u8,
    payload: []u8,

    pub fn deinit(self: Message, allocator: Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.payload);
    }
};

pub const Subscriber = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(Message),
    capacity: usize,
    dropped: usize = 0,
    closed: bool = false,
    id: u64 = 0,
    channels: [][]u8,

    fn init(allocator: Allocator, capacity: usize, channels: [][]u8) Subscriber {
        return .{
            .allocator = allocator,
            .queue = std.ArrayList(Message).init(allocator),
            .capacity = capacity,
            .channels = channels,
        };
    }

    fn push(self: *Subscriber, msg: Message) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) {
            msg.deinit(self.allocator);
            return;
        }
        if (self.capacity == 0) {
            msg.deinit(self.allocator);
            self.dropped += 1;
            return;
        }
        if (self.queue.items.len >= self.capacity) {
            const old = self.queue.orderedRemove(0);
            old.deinit(self.allocator);
            self.dropped += 1;
        }
        self.queue.append(msg) catch {
            msg.deinit(self.allocator);
            self.dropped += 1;
            return;
        };
        self.cond.signal();
    }

    pub fn waitMessage(self: *Subscriber) ?Message {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.queue.items.len == 0 and !self.closed) {
            self.cond.wait(&self.mutex);
        }
        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }

    pub fn close(self: *Subscriber) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) return;
        self.closed = true;
        self.cond.broadcast();
    }

    pub fn isClosed(self: *Subscriber) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }

    pub fn droppedCount(self: *Subscriber) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.dropped;
    }

    fn deinitContents(self: *Subscriber) void {
        for (self.queue.items) |m| m.deinit(self.allocator);
        self.queue.deinit();
        for (self.channels) |c| self.allocator.free(c);
        self.allocator.free(self.channels);
    }
};

pub const Hub = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    channels: std.StringHashMap(std.ArrayList(*Subscriber)),
    byId: std.AutoHashMap(u64, *Subscriber),
    nextId: u64 = 0,

    pub fn init(allocator: Allocator) Hub {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(std.ArrayList(*Subscriber)).init(allocator),
            .byId = std.AutoHashMap(u64, *Subscriber).init(allocator),
        };
    }

    pub fn deinit(self: *Hub) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        self.channels.deinit();
        self.byId.deinit();
    }

    pub fn subscribe(self: *Hub, channelNames: []const []const u8, capacity: usize) !*Subscriber {
        var unique = std.ArrayList([]const u8).init(self.allocator);
        defer unique.deinit();
        for (channelNames) |name| {
            var seen = false;
            for (unique.items) |u| {
                if (std.mem.eql(u8, u, name)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) try unique.append(name);
        }

        const owned = try self.allocator.alloc([]u8, unique.items.len);
        var ownedCount: usize = 0;
        errdefer {
            for (owned[0..ownedCount]) |c| self.allocator.free(c);
            self.allocator.free(owned);
        }
        for (unique.items, 0..) |name, i| {
            owned[i] = try self.allocator.dupe(u8, name);
            ownedCount += 1;
        }

        const sub = try self.allocator.create(Subscriber);
        errdefer self.allocator.destroy(sub);
        sub.* = Subscriber.init(self.allocator, capacity, owned);

        self.mutex.lock();
        defer self.mutex.unlock();

        const id = self.nextId;
        self.nextId += 1;
        sub.id = id;
        try self.byId.put(id, sub);
        errdefer _ = self.byId.remove(id);

        var registered: usize = 0;
        errdefer {
            for (owned[0..registered]) |name| {
                if (self.channels.getPtr(name)) |list| {
                    for (list.items, 0..) |s, idx| {
                        if (s == sub) {
                            _ = list.swapRemove(idx);
                            break;
                        }
                    }
                }
            }
        }
        for (owned) |name| {
            const gop = try self.channels.getOrPut(name);
            if (!gop.found_existing) {
                gop.key_ptr.* = self.allocator.dupe(u8, name) catch |err| {
                    _ = self.channels.remove(name);
                    return err;
                };
                gop.value_ptr.* = std.ArrayList(*Subscriber).init(self.allocator);
            }
            try gop.value_ptr.append(sub);
            registered += 1;
        }

        return sub;
    }

    pub fn closeSubscriber(self: *Hub, sub: *Subscriber) void {
        sub.close();
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.byId.remove(sub.id);
        for (sub.channels) |name| {
            if (self.channels.getPtr(name)) |list| {
                for (list.items, 0..) |s, idx| {
                    if (s == sub) {
                        _ = list.swapRemove(idx);
                        break;
                    }
                }
                if (list.items.len == 0) {
                    if (self.channels.fetchRemove(name)) |kv| {
                        kv.value.deinit();
                        self.allocator.free(kv.key);
                    }
                }
            }
        }
    }

    pub fn unsubscribe(self: *Hub, id: u64, channelNames: []const []const u8) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const sub = self.byId.get(id) orelse return error.UnknownSubscriber;

        var kept = try std.ArrayList([]u8).initCapacity(self.allocator, sub.channels.len);
        errdefer kept.deinit();
        var removed: usize = 0;
        for (sub.channels) |name| {
            var matches = false;
            for (channelNames) |target| {
                if (std.mem.eql(u8, name, target)) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                kept.appendAssumeCapacity(name);
                continue;
            }
            removed += 1;
            if (self.channels.getPtr(name)) |list| {
                for (list.items, 0..) |s, idx| {
                    if (s == sub) {
                        _ = list.swapRemove(idx);
                        break;
                    }
                }
                if (list.items.len == 0) {
                    if (self.channels.fetchRemove(name)) |kv| {
                        kv.value.deinit();
                        self.allocator.free(kv.key);
                    }
                }
            }
            self.allocator.free(name);
        }
        self.allocator.free(sub.channels);
        sub.channels = try kept.toOwnedSlice();

        if (sub.channels.len == 0) {
            _ = self.byId.remove(id);
            sub.close();
        }
        return removed;
    }

    pub fn destroySubscriber(self: *Hub, sub: *Subscriber) void {
        sub.deinitContents();
        self.allocator.destroy(sub);
    }

    pub fn channelSubscriberCount(self: *Hub, channel: []const u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.channels.get(channel)) |list| return list.items.len;
        return 0;
    }

    pub fn publish(self: *Hub, allocator: Allocator, channel: []const u8, payload: []const u8) !usize {
        self.mutex.lock();
        errdefer self.mutex.unlock();
        const subs = if (self.channels.get(channel)) |list| list.items else &[_]*Subscriber{};
        const snapshot = try allocator.alloc(*Subscriber, subs.len);
        defer allocator.free(snapshot);
        @memcpy(snapshot, subs);
        self.mutex.unlock();

        for (snapshot) |sub| {
            const channelCopy = self.allocator.dupe(u8, channel) catch continue;
            const payloadCopy = self.allocator.dupe(u8, payload) catch {
                self.allocator.free(channelCopy);
                continue;
            };
            sub.push(.{ .channel = channelCopy, .payload = payloadCopy });
        }
        return snapshot.len;
    }
};

fn destroy(hub: *Hub, sub: *Subscriber) void {
    hub.closeSubscriber(sub);
    hub.destroySubscriber(sub);
}

test "publish delivers a copy to a single subscriber on the channel it named" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"weather"}, defaultCapacity);
    defer destroy(&hub, sub);

    const delivered = try hub.publish(allocator, "weather", "sunny");
    try std.testing.expectEqual(@as(usize, 1), delivered);

    const msg = sub.waitMessage().?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("weather", msg.channel);
    try std.testing.expectEqualStrings("sunny", msg.payload);
}

test "publish to a channel with no subscribers returns 0 without crashing" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const delivered = try hub.publish(allocator, "nobody-home", "hello");
    try std.testing.expectEqual(@as(usize, 0), delivered);
}

test "every subscriber on a channel gets its own independent copy" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const a = try hub.subscribe(&.{"orders"}, defaultCapacity);
    defer destroy(&hub, a);
    const b = try hub.subscribe(&.{"orders"}, defaultCapacity);
    defer destroy(&hub, b);

    const delivered = try hub.publish(allocator, "orders", "order-42");
    try std.testing.expectEqual(@as(usize, 2), delivered);

    const ma = a.waitMessage().?;
    defer ma.deinit(allocator);
    const mb = b.waitMessage().?;
    defer mb.deinit(allocator);
    try std.testing.expectEqualStrings("order-42", ma.payload);
    try std.testing.expectEqualStrings("order-42", mb.payload);
    try std.testing.expect(ma.payload.ptr != mb.payload.ptr);
}

test "a subscriber on several channels gets messages tagged with the right channel" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{ "a", "b" }, defaultCapacity);
    defer destroy(&hub, sub);

    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "b", "from-b"));
    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "a", "from-a"));

    const first = sub.waitMessage().?;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("b", first.channel);
    try std.testing.expectEqualStrings("from-b", first.payload);

    const second = sub.waitMessage().?;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("a", second.channel);
    try std.testing.expectEqualStrings("from-a", second.payload);
}

test "subscribing to the same channel name twice still delivers only once" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{ "dup", "dup" }, defaultCapacity);
    defer destroy(&hub, sub);

    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "dup", "x"));
    const msg = sub.waitMessage().?;
    defer msg.deinit(allocator);
    sub.close();
    try std.testing.expect(sub.waitMessage() == null);
}

test "closing a subscriber unregisters it - a later publish no longer reaches it" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    hub.closeSubscriber(sub);

    try std.testing.expectEqual(@as(usize, 0), try hub.publish(allocator, "ch", "too-late"));
    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("ch"));

    hub.destroySubscriber(sub);
}

test "waitMessage drains already-queued messages before returning null on close" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer hub.destroySubscriber(sub);

    _ = try hub.publish(allocator, "ch", "one");
    _ = try hub.publish(allocator, "ch", "two");
    hub.closeSubscriber(sub);

    const m1 = sub.waitMessage().?;
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("one", m1.payload);
    const m2 = sub.waitMessage().?;
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("two", m2.payload);
    try std.testing.expect(sub.waitMessage() == null);
}

test "a full mailbox drops the oldest message, not the newest" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, 2);
    defer destroy(&hub, sub);

    _ = try hub.publish(allocator, "ch", "1");
    _ = try hub.publish(allocator, "ch", "2");
    _ = try hub.publish(allocator, "ch", "3");
    try std.testing.expectEqual(@as(usize, 1), sub.droppedCount());

    const m1 = sub.waitMessage().?;
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("2", m1.payload);
    const m2 = sub.waitMessage().?;
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("3", m2.payload);
}

test "capacity zero drops every message without ever panicking" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, 0);
    defer destroy(&hub, sub);

    _ = try hub.publish(allocator, "ch", "gone");
    _ = try hub.publish(allocator, "ch", "also-gone");
    try std.testing.expectEqual(@as(usize, 2), sub.droppedCount());
    sub.close();
    try std.testing.expect(sub.waitMessage() == null);
}

test "closing a subscriber wakes a thread already blocked in waitMessage" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer hub.destroySubscriber(sub);

    const Waiter = struct {
        fn run(s: *Subscriber, result: *?Message) void {
            result.* = s.waitMessage();
        }
    };
    var result: ?Message = undefined;
    result = Message{ .channel = &.{}, .payload = &.{} };
    const t = try std.Thread.spawn(.{}, Waiter.run, .{ sub, &result });
    hub.closeSubscriber(sub);
    t.join();
    try std.testing.expect(result == null);
}

test "publishing after closeSubscriber but before destroySubscriber never touches freed memory" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    hub.closeSubscriber(sub);
    try std.testing.expectEqual(@as(usize, 0), try hub.publish(allocator, "ch", "x"));
    hub.destroySubscriber(sub);
}

test "concurrent publishers hammering one subscriber deliver every message intact" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const publisherCount = 4;
    const perPublisher = 200;
    const sub = try hub.subscribe(&.{"ch"}, publisherCount * perPublisher);
    defer destroy(&hub, sub);

    const Publisher = struct {
        fn run(h: *Hub, alloc: Allocator, tag: usize) void {
            var buf: [32]u8 = undefined;
            var i: usize = 0;
            while (i < perPublisher) : (i += 1) {
                const text = std.fmt.bufPrint(&buf, "{d}:{d}", .{ tag, i }) catch unreachable;
                _ = h.publish(alloc, "ch", text) catch unreachable;
            }
        }
    };

    var threads: [publisherCount]std.Thread = undefined;
    for (0..publisherCount) |i| {
        threads[i] = try std.Thread.spawn(.{}, Publisher.run, .{ &hub, allocator, i });
    }
    for (threads) |t| t.join();

    try std.testing.expectEqual(@as(usize, 0), sub.droppedCount());

    var seenPerTag = [_]usize{0} ** publisherCount;
    var total: usize = 0;
    while (sub.waitMessage()) |msg| {
        defer msg.deinit(allocator);
        total += 1;
        var it = std.mem.splitScalar(u8, msg.payload, ':');
        const tag = std.fmt.parseInt(usize, it.next().?, 10) catch unreachable;
        seenPerTag[tag] += 1;
        if (total == publisherCount * perPublisher) break;
    }
    try std.testing.expectEqual(@as(usize, publisherCount * perPublisher), total);
    for (seenPerTag) |count| try std.testing.expectEqual(@as(usize, perPublisher), count);
}

test "subscribe leaves nothing registered when it fails partway through" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var hub = Hub.init(failing.allocator());
    defer hub.deinit();

    try std.testing.expectError(error.OutOfMemory, hub.subscribe(&.{ "a", "b", "c", "d" }, defaultCapacity));
    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("a"));
    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("b"));
}

test "push under memory pressure drops the message and counts it instead of leaking" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = failing.allocator();
    const channels = try std.testing.allocator.alloc([]u8, 0);
    var sub = Subscriber.init(allocator, defaultCapacity, channels);
    defer sub.deinitContents();

    const channel = try std.testing.allocator.dupe(u8, "ch");
    const payload = try std.testing.allocator.dupe(u8, "x");
    sub.push(.{ .channel = channel, .payload = payload });

    try std.testing.expectEqual(@as(usize, 1), sub.droppedCount());
    try std.testing.expectEqual(@as(usize, 0), sub.queue.items.len);
}

test "publish tolerates an out-of-memory snapshot allocation without leaking" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer destroy(&hub, sub);

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, hub.publish(failing.allocator(), "ch", "x"));
}

test "subscribe assigns each subscriber a distinct, increasing id" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const a = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer destroy(&hub, a);
    const b = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer destroy(&hub, b);

    try std.testing.expect(a.id != b.id);
    try std.testing.expect(b.id > a.id);
}

test "unsubscribe from a subset of channels leaves the rest delivering" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{ "weather", "orders", "alerts" }, defaultCapacity);
    defer destroy(&hub, sub);

    const removed = try hub.unsubscribe(sub.id, &.{"orders"});
    try std.testing.expectEqual(@as(usize, 1), removed);

    try std.testing.expectEqual(@as(usize, 0), try hub.publish(allocator, "orders", "too-late"));
    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "weather", "sunny"));
    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "alerts", "fire"));

    const m1 = sub.waitMessage().?;
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("sunny", m1.payload);
    const m2 = sub.waitMessage().?;
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("fire", m2.payload);

    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("orders"));
    try std.testing.expectEqual(@as(usize, 1), hub.channelSubscriberCount("weather"));
}

test "unsubscribe naming a channel the subscriber was never on counts zero, no error" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"weather"}, defaultCapacity);
    defer destroy(&hub, sub);

    const removed = try hub.unsubscribe(sub.id, &.{"nonexistent"});
    try std.testing.expectEqual(@as(usize, 0), removed);
    try std.testing.expectEqual(@as(usize, 1), try hub.publish(allocator, "weather", "still-here"));
    const msg = sub.waitMessage().?;
    defer msg.deinit(allocator);
}

test "unsubscribe from every remaining channel closes the subscriber outright" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{ "a", "b" }, defaultCapacity);
    defer hub.destroySubscriber(sub);

    const removed = try hub.unsubscribe(sub.id, &.{ "a", "b" });
    try std.testing.expectEqual(@as(usize, 2), removed);

    try std.testing.expect(sub.isClosed());
    try std.testing.expect(sub.waitMessage() == null);
    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("a"));
    try std.testing.expectEqual(@as(usize, 0), hub.channelSubscriberCount("b"));

    try std.testing.expectError(error.UnknownSubscriber, hub.unsubscribe(sub.id, &.{"a"}));

    hub.closeSubscriber(sub);
}

test "unsubscribe wakes a thread already blocked in waitMessage when it empties the set" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    defer hub.destroySubscriber(sub);

    const Waiter = struct {
        fn run(s: *Subscriber, result: *?Message) void {
            result.* = s.waitMessage();
        }
    };
    var result: ?Message = undefined;
    result = Message{ .channel = &.{}, .payload = &.{} };
    const t = try std.Thread.spawn(.{}, Waiter.run, .{ sub, &result });
    _ = try hub.unsubscribe(sub.id, &.{"ch"});
    t.join();
    try std.testing.expect(result == null);
}

test "unsubscribe rejects an id nobody ever issued" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    try std.testing.expectError(error.UnknownSubscriber, hub.unsubscribe(999, &.{"ch"}));
}

test "closeSubscriber removes the id, so a later unsubscribe by that id is rejected" {
    const allocator = std.testing.allocator;
    var hub = Hub.init(allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(&.{"ch"}, defaultCapacity);
    const id = sub.id;
    hub.closeSubscriber(sub);
    defer hub.destroySubscriber(sub);

    try std.testing.expectError(error.UnknownSubscriber, hub.unsubscribe(id, &.{"ch"}));
}
