const std = @import("std");
const dbmod = @import("db.zig");
const row = @import("row.zig");
const txnmod = @import("txn.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Transaction = txnmod.Transaction;

/// Redis-like typed collections layered over the flat KV keyspace, sharing
/// one Db with tables/indexes (row.zig/index.zig use tags 'R'/'I'/'M'; every
/// key here starts with 'X' so the two namespaces never collide):
///   "X" "C\0" name                         -> raw i64 (counter)
///   "X" "H\0" name "\0" field               -> raw bytes (hash field)
///   "X" "S\0" name "\0" member               -> empty marker (set member)
///   "X" "L\0" name "\0M"                    -> raw {headSeq i64, tailSeq i64} (list meta)
///   "X" "L\0" name "\0E\0" orderedInt(seq)  -> raw bytes (list element)
///   "X" "Z\0" name "\0M\0" member            -> raw f64 (zset member -> score)
///   "X" "Z\0" name "\0S\0" orderedFloat(score) orderedText(member) -> empty marker (zset score index)
pub const nsTag: u8 = 'X';
const sep: u8 = 0x00;
const maxConflictRetries: usize = 64;

fn appendSegment(out: *std.ArrayList(u8), segment: []const u8) !void {
    try out.appendSlice(segment);
    try out.append(sep);
}

fn putI64(out: *std.ArrayList(u8), v: i64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, v, .big);
    try out.appendSlice(&b);
}

fn readI64(data: []const u8) !i64 {
    if (data.len != 8) return error.Malformed;
    return std.mem.readInt(i64, data[0..8], .big);
}

fn putF64(out: *std.ArrayList(u8), v: f64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, @bitCast(v), .big);
    try out.appendSlice(&b);
}

fn readF64(data: []const u8) !f64 {
    if (data.len != 8) return error.Malformed;
    return @bitCast(std.mem.readInt(u64, data[0..8], .big));
}

/// Every atomic collection mutator below retries up to `maxConflictRetries`
/// times on error.Conflict, re-reading current state fresh through `txn.get`
/// on each attempt rather than replaying a stale value. `error.TooManyConflicts`
/// is returned only if the retry budget is exhausted.
/// Identifies which typed collection a name belongs to - used by collttl.zig
/// to expire a WHOLE collection (every physical key under its namespace),
/// since unlike a flat key a collection has no single Db key of its own
/// (except Counter, see `exists`/`drop` below).
pub const Kind = enum {
    counter,
    hash,
    set,
    list,
    zset,

    pub fn parse(s: []const u8) ?Kind {
        if (std.mem.eql(u8, s, "counter")) return .counter;
        if (std.mem.eql(u8, s, "hash")) return .hash;
        if (std.mem.eql(u8, s, "set")) return .set;
        if (std.mem.eql(u8, s, "list")) return .list;
        if (std.mem.eql(u8, s, "zset")) return .zset;
        return null;
    }

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .counter => "counter",
            .hash => "hash",
            .set => "set",
            .list => "list",
            .zset => "zset",
        };
    }

    pub fn tagByte(self: Kind) u8 {
        return switch (self) {
            .counter => 'C',
            .hash => 'H',
            .set => 'S',
            .list => 'L',
            .zset => 'Z',
        };
    }

    /// Inverse of `tagByte`, null on any other byte. Used to decode a
    /// `Kind` back out of a wire payload (`protocol.zig`'s `coll_ttl_op`)
    /// or a marker key (`collttl.zig`'s `sweepExpired`), which previously
    /// duplicated this exact switch inline.
    pub fn fromTagByte(b: u8) ?Kind {
        return switch (b) {
            'C' => .counter,
            'H' => .hash,
            'S' => .set,
            'L' => .list,
            'Z' => .zset,
            else => null,
        };
    }
};

/// Prefix common to every physical key a Hash/Set/List/ZSet named `name`
/// owns - each of those four kinds always segments as
/// nsTag+kindTag+sep+name+sep+<rest>, so this single prefix reaches every
/// field/member/element/score-entry at once. Counter is the one kind NOT
/// covered here: its single key has no trailing separator after `name`
/// (see Counter.key), so a same-named counter is handled separately in
/// `exists`/`drop` below rather than through a prefix scan.
fn genericPrefix(allocator: Allocator, k: Kind, name: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(nsTag);
    try appendSegment(&out, &[_]u8{k.tagByte()});
    try appendSegment(&out, name);
    return out.toOwnedSlice();
}

/// True if `name` currently has any physical presence under `k`'s namespace.
/// A counter counts as existing once `set`/`incrBy` has stored a value for
/// it, even 0 - that stored 0 is real data, not the "absent" default
/// Counter.get returns for a name nothing ever touched.
pub fn collectionExists(db: *Db, allocator: Allocator, k: Kind, name: []const u8) !bool {
    if (k == .counter) {
        const ck = try Counter.key(allocator, name);
        defer allocator.free(ck);
        const raw = try db.get(allocator, ck) orelse return false;
        allocator.free(raw);
        return true;
    }
    const p = try genericPrefix(allocator, k, name);
    defer allocator.free(p);
    var it = try db.scanPrefix(allocator, p);
    defer it.deinit();
    return (try it.next()) != null;
}

/// Deletes every physical key belonging to `name` under `k`'s namespace -
/// every field of a hash, the meta record and every element of a list, both
/// the member row and score-index row of every zset entry. Returns the
/// count of physical keys removed. This is what makes a collection-level
/// TTL (collttl.zig) actually mean something: expiring a collection has to
/// remove ALL of it, not just one key the way ttl.zig's flat-key expiry does.
pub fn dropCollection(db: *Db, allocator: Allocator, k: Kind, name: []const u8) !usize {
    if (k == .counter) {
        const ck = try Counter.key(allocator, name);
        defer allocator.free(ck);
        const raw = try db.get(allocator, ck) orelse return 0;
        allocator.free(raw);
        try db.delete(ck);
        return 1;
    }

    const p = try genericPrefix(allocator, k, name);
    defer allocator.free(p);

    var keys = std.ArrayList([]u8).init(allocator);
    defer {
        for (keys.items) |kk| allocator.free(kk);
        keys.deinit();
    }
    {
        // Collect first, delete after: db.delete mid-scan would mutate the
        // memtable structure a live RangeIterator's cursors are threaded
        // through (same reasoning as ttl.zig's sweepExpired).
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();
        while (try it.next()) |entry| {
            try keys.append(try allocator.dupe(u8, entry.key));
        }
    }
    for (keys.items) |kk| try db.delete(kk);
    return keys.items.len;
}

fn prefixUpperBound(allocator: Allocator, prefix: []const u8) !?[]u8 {
    var end = prefix.len;
    while (end > 0 and prefix[end - 1] == 0xff) end -= 1;
    if (end == 0) return null;
    const upper = try allocator.alloc(u8, end);
    @memcpy(upper, prefix[0..end]);
    upper[end - 1] += 1;
    return upper;
}

// ---------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------

pub const Counter = struct {
    fn key(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "C");
        try out.appendSlice(name);
        return out.toOwnedSlice();
    }

    pub fn get(db: *Db, allocator: Allocator, name: []const u8) !i64 {
        const k = try key(allocator, name);
        defer allocator.free(k);
        const raw = try db.get(allocator, k) orelse return 0;
        defer allocator.free(raw);
        return readI64(raw);
    }

    pub fn set(db: *Db, allocator: Allocator, name: []const u8, value: i64) !void {
        const k = try key(allocator, name);
        defer allocator.free(k);
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try putI64(&out, value);
        try db.put(k, out.items);
    }

    /// Atomically adds `delta` to the counter (creating it at 0 if absent)
    /// and returns the new value. Uses an OCC transaction so concurrent
    /// increments never lose an update to a lost read-modify-write race.
    pub fn incrBy(db: *Db, allocator: Allocator, name: []const u8, delta: i64) !i64 {
        const k = try key(allocator, name);
        defer allocator.free(k);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            const current: i64 = blk: {
                const raw = try txn.get(allocator, k) orelse break :blk 0;
                defer allocator.free(raw);
                break :blk try readI64(raw);
            };
            const next = current + delta;

            var out = std.ArrayList(u8).init(allocator);
            defer out.deinit();
            try putI64(&out, next);
            try txn.put(k, out.items);

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return next;
        }
        return error.TooManyConflicts;
    }
};

// ---------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------

pub const HashField = struct {
    field: []u8,
    value: []u8,

    pub fn free(self: HashField, allocator: Allocator) void {
        allocator.free(self.field);
        allocator.free(self.value);
    }
};

pub const Hash = struct {
    fn prefix(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "H");
        try appendSegment(&out, name);
        return out.toOwnedSlice();
    }

    fn fieldKey(allocator: Allocator, name: []const u8, field: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "H");
        try appendSegment(&out, name);
        try out.appendSlice(field);
        return out.toOwnedSlice();
    }

    /// Sets a field, returning true if the field was newly created.
    pub fn set(db: *Db, allocator: Allocator, name: []const u8, field: []const u8, value: []const u8) !bool {
        const k = try fieldKey(allocator, name, field);
        defer allocator.free(k);
        const existing = try db.get(allocator, k);
        if (existing) |raw| allocator.free(raw);
        try db.put(k, value);
        return existing == null;
    }

    pub fn get(db: *Db, allocator: Allocator, name: []const u8, field: []const u8) !?[]u8 {
        const k = try fieldKey(allocator, name, field);
        defer allocator.free(k);
        return db.get(allocator, k);
    }

    pub fn exists(db: *Db, allocator: Allocator, name: []const u8, field: []const u8) !bool {
        const raw = try get(db, allocator, name, field) orelse return false;
        allocator.free(raw);
        return true;
    }

    /// Deletes a field, returning true if it existed.
    pub fn del(db: *Db, allocator: Allocator, name: []const u8, field: []const u8) !bool {
        const existed = try exists(db, allocator, name, field);
        if (!existed) return false;
        const k = try fieldKey(allocator, name, field);
        defer allocator.free(k);
        try db.delete(k);
        return true;
    }

    pub fn len(db: *Db, allocator: Allocator, name: []const u8) !usize {
        const p = try prefix(allocator, name);
        defer allocator.free(p);
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();
        var count: usize = 0;
        while (try it.next()) |_| count += 1;
        return count;
    }

    /// Returns every field/value pair currently stored under `name`. Caller
    /// owns the returned slice and each entry's `field`/`value` buffers.
    pub fn getAll(db: *Db, allocator: Allocator, name: []const u8) ![]HashField {
        const p = try prefix(allocator, name);
        defer allocator.free(p);

        var results = std.ArrayList(HashField).init(allocator);
        errdefer {
            for (results.items) |f| f.free(allocator);
            results.deinit();
        }

        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();
        while (try it.next()) |entry| {
            const field = try allocator.dupe(u8, entry.key[p.len..]);
            errdefer allocator.free(field);
            const value = try allocator.dupe(u8, entry.value);
            try results.append(.{ .field = field, .value = value });
        }
        return results.toOwnedSlice();
    }
};

// ---------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------

pub const Set = struct {
    fn prefix(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "S");
        try appendSegment(&out, name);
        return out.toOwnedSlice();
    }

    fn memberKey(allocator: Allocator, name: []const u8, member: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "S");
        try appendSegment(&out, name);
        try out.appendSlice(member);
        return out.toOwnedSlice();
    }

    /// Returns true if the member was newly added (false if already present).
    pub fn add(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !bool {
        if (try isMember(db, allocator, name, member)) return false;
        const k = try memberKey(allocator, name, member);
        defer allocator.free(k);
        try db.put(k, &.{});
        return true;
    }

    /// Returns true if the member was present and has been removed.
    pub fn remove(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !bool {
        if (!try isMember(db, allocator, name, member)) return false;
        const k = try memberKey(allocator, name, member);
        defer allocator.free(k);
        try db.delete(k);
        return true;
    }

    pub fn isMember(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !bool {
        const k = try memberKey(allocator, name, member);
        defer allocator.free(k);
        const raw = try db.get(allocator, k) orelse return false;
        allocator.free(raw);
        return true;
    }

    pub fn card(db: *Db, allocator: Allocator, name: []const u8) !usize {
        const members_ = try members(db, allocator, name);
        defer {
            for (members_) |m| allocator.free(m);
            allocator.free(members_);
        }
        return members_.len;
    }

    /// Returns every member currently in the set. Caller owns the slice and
    /// each element.
    pub fn members(db: *Db, allocator: Allocator, name: []const u8) ![][]u8 {
        const p = try prefix(allocator, name);
        defer allocator.free(p);

        var results = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (results.items) |m| allocator.free(m);
            results.deinit();
        }

        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();
        while (try it.next()) |entry| {
            try results.append(try allocator.dupe(u8, entry.key[p.len..]));
        }
        return results.toOwnedSlice();
    }

    fn containsSorted(haystack: [][]const u8, needle: []const u8) bool {
        for (haystack) |h| {
            if (std.mem.eql(u8, h, needle)) return true;
        }
        return false;
    }

    /// Members present in every one of `names`. Caller owns the result.
    pub fn intersect(db: *Db, allocator: Allocator, names: []const []const u8) ![][]u8 {
        var results = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (results.items) |m| allocator.free(m);
            results.deinit();
        }
        if (names.len == 0) return results.toOwnedSlice();

        const first = try members(db, allocator, names[0]);
        defer {
            for (first) |m| allocator.free(m);
            allocator.free(first);
        }

        outer: for (first) |candidate| {
            for (names[1..]) |other| {
                if (!try isMember(db, allocator, other, candidate)) continue :outer;
            }
            try results.append(try allocator.dupe(u8, candidate));
        }
        return results.toOwnedSlice();
    }

    /// Members present in any of `names`, deduplicated. Caller owns the result.
    pub fn unionOf(db: *Db, allocator: Allocator, names: []const []const u8) ![][]u8 {
        var results = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (results.items) |m| allocator.free(m);
            results.deinit();
        }

        for (names) |name| {
            const ms = try members(db, allocator, name);
            defer {
                for (ms) |m| allocator.free(m);
                allocator.free(ms);
            }
            for (ms) |m| {
                var seen = false;
                for (results.items) |existing| {
                    if (std.mem.eql(u8, existing, m)) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) try results.append(try allocator.dupe(u8, m));
            }
        }
        return results.toOwnedSlice();
    }

    /// Members in `name` that are not in any set of `others`. Caller owns the result.
    pub fn difference(db: *Db, allocator: Allocator, name: []const u8, others: []const []const u8) ![][]u8 {
        var results = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (results.items) |m| allocator.free(m);
            results.deinit();
        }

        const base = try members(db, allocator, name);
        defer {
            for (base) |m| allocator.free(m);
            allocator.free(base);
        }

        outer: for (base) |candidate| {
            for (others) |other| {
                if (try isMember(db, allocator, other, candidate)) continue :outer;
            }
            try results.append(try allocator.dupe(u8, candidate));
        }
        return results.toOwnedSlice();
    }
};

// ---------------------------------------------------------------------
// List (double-ended queue keyed by a monotonic sequence range)
// ---------------------------------------------------------------------

const ListMeta = struct {
    // Elements occupy sequence numbers (head+1 .. tail-1) inclusive; an
    // empty list has tail == head + 1. Pushing left decrements head and
    // writes at the new head; pushing right increments tail and writes at
    // the slot just below the new tail.
    head: i64,
    tail: i64,
};

pub const List = struct {
    fn metaKey(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "L");
        try appendSegment(&out, name);
        try out.append('M');
        return out.toOwnedSlice();
    }

    fn elementPrefix(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "L");
        try appendSegment(&out, name);
        try appendSegment(&out, "E");
        return out.toOwnedSlice();
    }

    fn elementKey(allocator: Allocator, name: []const u8, seq: i64) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "L");
        try appendSegment(&out, name);
        try appendSegment(&out, "E");
        try row.appendOrdered(&out, .{ .int = seq });
        return out.toOwnedSlice();
    }

    fn readMeta(txn: *Transaction, allocator: Allocator, k: []const u8) !ListMeta {
        const raw = try txn.get(allocator, k) orelse return ListMeta{ .head = 0, .tail = 1 };
        defer allocator.free(raw);
        if (raw.len != 16) return error.Malformed;
        return .{
            .head = std.mem.readInt(i64, raw[0..8], .big),
            .tail = std.mem.readInt(i64, raw[8..16], .big),
        };
    }

    fn writeMeta(txn: *Transaction, k: []const u8, meta: ListMeta) !void {
        var buf: [16]u8 = undefined;
        std.mem.writeInt(i64, buf[0..8], meta.head, .big);
        std.mem.writeInt(i64, buf[8..16], meta.tail, .big);
        try txn.put(k, &buf);
    }

    pub fn pushLeft(db: *Db, allocator: Allocator, name: []const u8, value: []const u8) !void {
        const mk = try metaKey(allocator, name);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            var meta = try readMeta(&txn, allocator, mk);
            const seq = meta.head;
            meta.head -= 1;

            const ek = try elementKey(allocator, name, seq);
            defer allocator.free(ek);
            try txn.put(ek, value);
            try writeMeta(&txn, mk, meta);

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return;
        }
        return error.TooManyConflicts;
    }

    pub fn pushRight(db: *Db, allocator: Allocator, name: []const u8, value: []const u8) !void {
        const mk = try metaKey(allocator, name);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            var meta = try readMeta(&txn, allocator, mk);
            const seq = meta.tail;
            meta.tail += 1;

            const ek = try elementKey(allocator, name, seq);
            defer allocator.free(ek);
            try txn.put(ek, value);
            try writeMeta(&txn, mk, meta);

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return;
        }
        return error.TooManyConflicts;
    }

