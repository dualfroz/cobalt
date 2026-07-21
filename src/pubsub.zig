const std = @import("std");

const Allocator = std.mem.Allocator;

/// Default bound on how many undelivered messages a single subscriber's
/// mailbox holds before the oldest is dropped to make room for the newest -
/// see `Subscriber.push`'s doc comment for why drop-oldest (never blocking
/// the publisher) is the chosen backpressure policy.
pub const defaultCapacity: usize = 256;

/// One delivered message: which channel it arrived on (a subscriber can
/// listen to several, so the tag travels with the payload) and the payload
/// bytes themselves, both independently owned copies - `publish` never
/// hands the same buffer to two subscribers.
pub const Message = struct {
    channel: []u8,
    payload: []u8,

    pub fn deinit(self: Message, allocator: Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.payload);
    }
};

/// One subscriber's private mailbox: a bounded FIFO of `Message`s plus the
/// synchronization a consumer thread needs to block until either a new
/// message arrives or the subscription is closed. A `Subscriber` is always
/// created by `Hub.subscribe` and must be retired through
/// `Hub.closeSubscriber` then `Hub.destroySubscriber`, in that order (see
/// their doc comments for why the two steps are separate).
pub const Subscriber = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(Message),
    capacity: usize,
    dropped: usize = 0,
    closed: bool = false,
    /// Assigned by `Hub.subscribe` (monotonically increasing per `Hub`
    /// instance, never reused within its lifetime) so a control connection
    /// that never saw this `Subscriber`'s pointer - a separate `unsubscribe`
    /// request, possibly on a different TCP connection entirely - can still
    /// name it. Only meaningful together with the `Hub` that assigned it;
    /// not persisted, not unique across process restarts.
    id: u64 = 0,
    /// Channel names this subscriber is registered under in whichever `Hub`
    /// created it - copied here (not just left as entries in
    /// `Hub.channels`) so `Hub.closeSubscriber`/`Hub.unsubscribe` can find
    /// every channel to unregister from without the caller having to
    /// remember the original subscribe list.
    channels: [][]u8,

    fn init(allocator: Allocator, capacity: usize, channels: [][]u8) Subscriber {
        return .{
            .allocator = allocator,
            .queue = std.ArrayList(Message).init(allocator),
            .capacity = capacity,
            .channels = channels,
        };
    }

    /// Delivers one message, taking ownership of it. Never blocks: a
    /// `capacity` of zero drops every message immediately (a legal, if
    /// degenerate, "nobody's listening yet" mailbox); otherwise, once the
    /// mailbox is at `capacity`, the oldest queued message is dropped (and
    /// freed) to make room, `dropped` is incremented, and the new message
    /// is appended - so `waitMessage` always eventually surfaces the most
    /// RECENT messages a slow subscriber missed, never the oldest stale
    /// ones. A message pushed after `close()` is silently freed and does
    /// not count as delivered or dropped - a closed subscriber is never
    /// coming back to read it, and `dropped` exists to describe backpressure
    /// on a live subscriber, not the ordinary end of one.
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

    /// Blocks until a message is available or the subscription is closed
    /// with an empty mailbox, whichever happens first. A close with
    /// messages still queued is drained first - `waitMessage` keeps
    /// returning them in order before finally returning `null`, so a
    /// consumer never loses a message that was successfully enqueued
    /// before `close()` ran. Ownership of the returned `Message` passes to
    /// the caller, who must `deinit` it.
    pub fn waitMessage(self: *Subscriber) ?Message {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.queue.items.len == 0 and !self.closed) {
            self.cond.wait(&self.mutex);
        }
        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }

    /// Idempotent: marks the mailbox closed and wakes every thread blocked
    /// in `waitMessage`. Safe to call from any thread, any number of times
    /// concurrently - a watcher thread noticing a client disconnect and a
    /// publisher noticing a dead connection can both call it without
    /// coordinating between themselves.
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

    /// Frees the mailbox's own queued messages and the subscriber's
    /// channel-name copies, then the caller frees the `Subscriber` struct
    /// itself via `Hub.destroySubscriber`. Only the thread that owns this
    /// subscriber past its last `waitMessage`/close call may reach this -
    /// see `Hub.destroySubscriber`'s doc comment for the ownership handoff
    /// it depends on.
    fn deinitContents(self: *Subscriber) void {
        for (self.queue.items) |m| m.deinit(self.allocator);
        self.queue.deinit();
        for (self.channels) |c| self.allocator.free(c);
        self.allocator.free(self.channels);
    }
};

/// The channel registry every `Subscriber` is filed under. Completely
/// independent of `Db` - publish/subscribe never touches storage, so a
/// `Hub`'s own mutex is never held anywhere near `Db`'s (see `server.zig`'s
/// `dispatch`, which handles the `subscribe`/`publish` opcodes before it
/// ever reaches for `Server.mutex`, so a slow or permanently-open
/// subscriber connection can never stall a read or write against the
/// store).
pub const Hub = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    channels: std.StringHashMap(std.ArrayList(*Subscriber)),
    /// Every currently-live subscriber, keyed by the `id` `subscribe`
    /// assigned it - lets `unsubscribe` (see its doc comment) look one up by
    /// the bare number a client saw in its subscribe ack, without needing
    /// the original `*Subscriber` pointer, which never crosses a second TCP
    /// connection. Entries are removed exactly when `closeSubscriber` runs
    /// (or `unsubscribe` empties a subscriber's channel set and closes it
    /// itself), so a stale or already-closed id reliably misses here rather
    /// than risking a dangling pointer.
    byId: std.AutoHashMap(u64, *Subscriber),
    nextId: u64 = 0,

    pub fn init(allocator: Allocator) Hub {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(std.ArrayList(*Subscriber)).init(allocator),
            .byId = std.AutoHashMap(u64, *Subscriber).init(allocator),
        };
    }

    /// Frees every remaining channel's subscriber list and key copy, and the
    /// id registry. Does NOT touch any `Subscriber` still registered -
    /// callers must `closeSubscriber` (which also unregisters, so in an
    /// orderly shutdown this map is already empty by the time `deinit` runs)
    /// and `destroySubscriber` every subscriber they created first, the same
    /// "caller drains, then frees the container" ordering `Db`/`Server`
    /// already use elsewhere in this codebase.
    pub fn deinit(self: *Hub) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        self.channels.deinit();
        self.byId.deinit();
    }

    /// Creates a new subscriber registered under every name in
    /// `channelNames` (duplicate names collapse to one registration, so a
    /// message published on a channel a caller listed twice is still only
    /// ever delivered once). `capacity` bounds its mailbox (see
    /// `Subscriber.push`). Returns a pointer the caller must eventually
    /// pass to `closeSubscriber` then `destroySubscriber`, in that order.
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
                    // The map entry was already inserted with `name`'s
                    // pointer as a placeholder key by `getOrPut` itself;
                    // remove it before propagating so `deinit`/`subscribe`
                    // never iterate over a key pointing into memory this
                    // function is about to free via `owned`'s errdefer.
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

    /// Stops delivering new messages to `sub` and unregisters it from every
    /// channel it was subscribed to, wakes any thread blocked in its
    /// `waitMessage`, and drops a channel's map entry entirely once its
    /// subscriber list becomes empty (an unsubscribed-from channel is a
    /// completely normal, permanent steady state, not a reason to keep an
    /// empty list around forever). Safe to call more than once (from a
    /// watcher thread and a failed publish both noticing the same dead
    /// connection, say) - both `Subscriber.close` and the unregister loop
    /// below are no-ops the second time. Does NOT free `sub` itself - see
    /// `destroySubscriber`.
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

