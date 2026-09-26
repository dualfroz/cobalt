const std = @import("std");
const dbmod = @import("db.zig");
const row = @import("row.zig");
const txnmod = @import("txn.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Transaction = txnmod.Transaction;

pub const nsTag: u8 = 0xFA;
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

fn genericPrefix(allocator: Allocator, k: Kind, name: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(nsTag);
    try appendSegment(&out, &[_]u8{k.tagByte()});
    try appendSegment(&out, name);
    return out.toOwnedSlice();
}

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

    pub fn add(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !bool {
        if (try isMember(db, allocator, name, member)) return false;
        const k = try memberKey(allocator, name, member);
        defer allocator.free(k);
        try db.put(k, &.{});
        return true;
    }

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

const ListMeta = struct {
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

    pub fn popLeft(db: *Db, allocator: Allocator, name: []const u8) !?[]u8 {
        const mk = try metaKey(allocator, name);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            var meta = try readMeta(&txn, allocator, mk);
            if (meta.tail - meta.head <= 1) return null;
            const seq = meta.head + 1;
            meta.head += 1;

            const ek = try elementKey(allocator, name, seq);
            defer allocator.free(ek);
            const value = try txn.get(allocator, ek) orelse return error.Malformed;
            errdefer allocator.free(value);
            try txn.delete(ek);
            try writeMeta(&txn, mk, meta);

            txn.commit() catch |err| {
                allocator.free(value);
                if (err == error.Conflict) continue;
                return err;
            };
            return value;
        }
        return error.TooManyConflicts;
    }

    pub fn popRight(db: *Db, allocator: Allocator, name: []const u8) !?[]u8 {
        const mk = try metaKey(allocator, name);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            var meta = try readMeta(&txn, allocator, mk);
            if (meta.tail - meta.head <= 1) return null;
            const seq = meta.tail - 1;
            meta.tail -= 1;

            const ek = try elementKey(allocator, name, seq);
            defer allocator.free(ek);
            const value = try txn.get(allocator, ek) orelse return error.Malformed;
            errdefer allocator.free(value);
            try txn.delete(ek);
            try writeMeta(&txn, mk, meta);

            txn.commit() catch |err| {
                allocator.free(value);
                if (err == error.Conflict) continue;
                return err;
            };
            return value;
        }
        return error.TooManyConflicts;
    }

    pub fn len(db: *Db, allocator: Allocator, name: []const u8) !usize {
        const mk = try metaKey(allocator, name);
        defer allocator.free(mk);
        const raw = try db.get(allocator, mk) orelse return 0;
        defer allocator.free(raw);
        if (raw.len != 16) return error.Malformed;
        const head = std.mem.readInt(i64, raw[0..8], .big);
        const tail = std.mem.readInt(i64, raw[8..16], .big);
        return @intCast(tail - head - 1);
    }

    pub fn range(db: *Db, allocator: Allocator, name: []const u8, start: i64, stop: i64) ![][]u8 {
        const total: i64 = @intCast(try len(db, allocator, name));

        var results = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (results.items) |m| allocator.free(m);
            results.deinit();
        }
        if (total == 0) return results.toOwnedSlice();

        var lo = if (start < 0) total + start else start;
        var hi = if (stop < 0) total + stop else stop;
        if (lo < 0) lo = 0;
        if (hi > total - 1) hi = total - 1;
        if (lo > hi) return results.toOwnedSlice();

        const p = try elementPrefix(allocator, name);
        defer allocator.free(p);
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();

        var idx: i64 = 0;
        while (try it.next()) |entry| {
            if (idx >= lo and idx <= hi) {
                try results.append(try allocator.dupe(u8, entry.value));
            }
            idx += 1;
        }
        return results.toOwnedSlice();
    }
};

pub const ZMember = struct {
    member: []u8,
    score: f64,

    pub fn free(self: ZMember, allocator: Allocator) void {
        allocator.free(self.member);
    }
};

pub const ZSet = struct {
    fn memberKey(allocator: Allocator, name: []const u8, member: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "Z");
        try appendSegment(&out, name);
        try appendSegment(&out, "M");
        try out.appendSlice(member);
        return out.toOwnedSlice();
    }

    fn scorePrefix(allocator: Allocator, name: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "Z");
        try appendSegment(&out, name);
        try appendSegment(&out, "S");
        return out.toOwnedSlice();
    }

    fn scoreEntryKey(allocator: Allocator, name: []const u8, scoreVal: f64, member: []const u8) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "Z");
        try appendSegment(&out, name);
        try appendSegment(&out, "S");
        try row.appendOrdered(&out, .{ .float = scoreVal });
        try row.appendOrdered(&out, .{ .text = member });
        return out.toOwnedSlice();
    }

    fn scoreBound(allocator: Allocator, name: []const u8, scoreVal: f64) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.append(nsTag);
        try appendSegment(&out, "Z");
        try appendSegment(&out, name);
        try appendSegment(&out, "S");
        try row.appendOrdered(&out, .{ .float = scoreVal });
        return out.toOwnedSlice();
    }

    pub fn add(db: *Db, allocator: Allocator, name: []const u8, member: []const u8, scoreVal: f64) !void {
        const mk = try memberKey(allocator, name, member);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            const old = try txn.get(allocator, mk);
            if (old) |raw| {
                defer allocator.free(raw);
                const oldScore = try readF64(raw);
                if (oldScore == scoreVal) return;
                const oldEntryKey = try scoreEntryKey(allocator, name, oldScore, member);
                defer allocator.free(oldEntryKey);
                try txn.delete(oldEntryKey);
            }

            var scoreBuf = std.ArrayList(u8).init(allocator);
            defer scoreBuf.deinit();
            try putF64(&scoreBuf, scoreVal);
            try txn.put(mk, scoreBuf.items);

            const entryKey = try scoreEntryKey(allocator, name, scoreVal, member);
            defer allocator.free(entryKey);
            try txn.put(entryKey, &.{});

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return;
        }
        return error.TooManyConflicts;
    }

    pub fn score(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !?f64 {
        const mk = try memberKey(allocator, name, member);
        defer allocator.free(mk);
        const raw = try db.get(allocator, mk) orelse return null;
        defer allocator.free(raw);
        return try readF64(raw);
    }

    pub fn incrBy(db: *Db, allocator: Allocator, name: []const u8, member: []const u8, delta: f64) !f64 {
        const mk = try memberKey(allocator, name, member);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            const oldRaw = try txn.get(allocator, mk);
            const oldScore: f64 = if (oldRaw) |raw| blk: {
                defer allocator.free(raw);
                break :blk try readF64(raw);
            } else 0.0;
            const newScore = oldScore + delta;

            if (oldRaw != null) {
                const oldEntryKey = try scoreEntryKey(allocator, name, oldScore, member);
                defer allocator.free(oldEntryKey);
                try txn.delete(oldEntryKey);
            }

            var scoreBuf = std.ArrayList(u8).init(allocator);
            defer scoreBuf.deinit();
            try putF64(&scoreBuf, newScore);
            try txn.put(mk, scoreBuf.items);

            const entryKey = try scoreEntryKey(allocator, name, newScore, member);
            defer allocator.free(entryKey);
            try txn.put(entryKey, &.{});

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return newScore;
        }
        return error.TooManyConflicts;
    }

    pub fn remove(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !bool {
        const mk = try memberKey(allocator, name, member);
        defer allocator.free(mk);

        var attempt: usize = 0;
        while (attempt < maxConflictRetries) : (attempt += 1) {
            var txn = Transaction.begin(db);
            defer txn.deinit();

            const raw = try txn.get(allocator, mk) orelse return false;
            defer allocator.free(raw);
            const existingScore = try readF64(raw);

            try txn.delete(mk);
            const entryKey = try scoreEntryKey(allocator, name, existingScore, member);
            defer allocator.free(entryKey);
            try txn.delete(entryKey);

            txn.commit() catch |err| {
                if (err == error.Conflict) continue;
                return err;
            };
            return true;
        }
        return error.TooManyConflicts;
    }

    pub fn card(db: *Db, allocator: Allocator, name: []const u8) !usize {
        const p = try scorePrefix(allocator, name);
        defer allocator.free(p);
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();
        var count: usize = 0;
        while (try it.next()) |_| count += 1;
        return count;
    }

    fn decodeScoreEntry(allocator: Allocator, name: []const u8, key: []const u8) !ZMember {
        const p = try scorePrefix(allocator, name);
        defer allocator.free(p);
        if (key.len <= p.len or !std.mem.startsWith(u8, key, p)) return error.Malformed;
        const rest = key[p.len..];

        if (rest.len < 9 or rest[0] != @intFromEnum(row.ValueTag.float)) return error.Malformed;
        var bits = std.mem.readInt(u64, rest[1..9], .big);
        if (bits & 0x8000000000000000 != 0) {
            bits &= 0x7fffffffffffffff;
        } else {
            bits = ~bits;
        }
        const decodedScore: f64 = @bitCast(bits);

        const memberPart = rest[9..];
        if (memberPart.len < 3 or memberPart[0] != @intFromEnum(row.ValueTag.text)) return error.Malformed;
        var unescaped = std.ArrayList(u8).init(allocator);
        errdefer unescaped.deinit();
        var i: usize = 1;
        while (i < memberPart.len) {
            if (memberPart[i] == 0x00) {
                if (i + 1 >= memberPart.len) return error.Malformed;
                if (memberPart[i + 1] == 0x00) break;
                if (memberPart[i + 1] == 0xFF) {
                    try unescaped.append(0x00);
                    i += 2;
                    continue;
                }
                return error.Malformed;
            }
            try unescaped.append(memberPart[i]);
            i += 1;
        }
        return .{ .member = try unescaped.toOwnedSlice(), .score = decodedScore };
    }

    pub fn rangeByRank(db: *Db, allocator: Allocator, name: []const u8, start: i64, stop: i64) ![]ZMember {
        const total: i64 = @intCast(try card(db, allocator, name));

        var results = std.ArrayList(ZMember).init(allocator);
        errdefer {
            for (results.items) |m| m.free(allocator);
            results.deinit();
        }
        if (total == 0) return results.toOwnedSlice();

        var lo = if (start < 0) total + start else start;
        var hi = if (stop < 0) total + stop else stop;
        if (lo < 0) lo = 0;
        if (hi > total - 1) hi = total - 1;
        if (lo > hi) return results.toOwnedSlice();

        const p = try scorePrefix(allocator, name);
        defer allocator.free(p);
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();

        var idx: i64 = 0;
        while (try it.next()) |entry| {
            if (idx >= lo and idx <= hi) {
                try results.append(try decodeScoreEntry(allocator, name, entry.key));
            }
            idx += 1;
        }
        return results.toOwnedSlice();
    }

    pub fn rangeByScore(db: *Db, allocator: Allocator, name: []const u8, min: f64, max: f64) ![]ZMember {
        var results = std.ArrayList(ZMember).init(allocator);
        errdefer {
            for (results.items) |m| m.free(allocator);
            results.deinit();
        }

        const startBound = try scoreBound(allocator, name, min);
        defer allocator.free(startBound);
        const maxBound = try scoreBound(allocator, name, max);
        defer allocator.free(maxBound);
        const endBound = try prefixUpperBound(allocator, maxBound) orelse try allocator.dupe(u8, maxBound);
        defer allocator.free(endBound);

        var it = try db.scanRange(allocator, .{
            .start = startBound,
            .end = endBound,
            .startInclusive = true,
            .endInclusive = false,
        });
        defer it.deinit();

        while (try it.next()) |entry| {
            try results.append(try decodeScoreEntry(allocator, name, entry.key));
        }
        return results.toOwnedSlice();
    }

    pub fn rank(db: *Db, allocator: Allocator, name: []const u8, member: []const u8) !?usize {
        const target = try score(db, allocator, name, member) orelse return null;

        const p = try scorePrefix(allocator, name);
        defer allocator.free(p);
        var it = try db.scanPrefix(allocator, p);
        defer it.deinit();

        var idx: usize = 0;
        while (try it.next()) |entry| {
            const decoded = try decodeScoreEntry(allocator, name, entry.key);
            defer decoded.free(allocator);
            if (decoded.score == target and std.mem.eql(u8, decoded.member, member)) return idx;
            idx += 1;
        }
        return null;
    }
};

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

test "counter incrBy accumulates and get defaults to zero" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expectEqual(@as(i64, 0), try Counter.get(&db, allocator, "hits"));
    try std.testing.expectEqual(@as(i64, 5), try Counter.incrBy(&db, allocator, "hits", 5));
    try std.testing.expectEqual(@as(i64, 3), try Counter.incrBy(&db, allocator, "hits", -2));
    try std.testing.expectEqual(@as(i64, 3), try Counter.get(&db, allocator, "hits"));

    try Counter.set(&db, allocator, "hits", 100);
    try std.testing.expectEqual(@as(i64, 100), try Counter.get(&db, allocator, "hits"));
}

test "counter incrBy rejects a real external conflict" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    const k = try Counter.key(allocator, "race");
    defer allocator.free(k);

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    _ = try txn.get(allocator, k);
    try db.put(k, "external");
    try txn.put(k, "mine");
    try std.testing.expectError(error.Conflict, txn.commit());
}

test "hash set get del getAll" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expect(try Hash.set(&db, allocator, "user:1", "name", "ada"));
    try std.testing.expect(!try Hash.set(&db, allocator, "user:1", "name", "ada lovelace"));
    try std.testing.expect(try Hash.set(&db, allocator, "user:1", "age", "36"));

    const name = (try Hash.get(&db, allocator, "user:1", "name")).?;
    defer allocator.free(name);
    try std.testing.expectEqualStrings("ada lovelace", name);

    try std.testing.expectEqual(@as(usize, 2), try Hash.len(&db, allocator, "user:1"));

    const all = try Hash.getAll(&db, allocator, "user:1");
    defer {
        for (all) |f| f.free(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 2), all.len);

    try std.testing.expect(try Hash.del(&db, allocator, "user:1", "age"));
    try std.testing.expect(!try Hash.del(&db, allocator, "user:1", "age"));
    try std.testing.expectEqual(@as(usize, 1), try Hash.len(&db, allocator, "user:1"));
    try std.testing.expect(try Hash.get(&db, allocator, "user:1", "age") == null);
}

test "set add remove isMember card members" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expect(try Set.add(&db, allocator, "tags", "zig"));
    try std.testing.expect(!try Set.add(&db, allocator, "tags", "zig"));
    try std.testing.expect(try Set.add(&db, allocator, "tags", "db"));

    try std.testing.expect(try Set.isMember(&db, allocator, "tags", "zig"));
    try std.testing.expect(!try Set.isMember(&db, allocator, "tags", "rust"));
    try std.testing.expectEqual(@as(usize, 2), try Set.card(&db, allocator, "tags"));

    const members = try Set.members(&db, allocator, "tags");
    defer {
        for (members) |m| allocator.free(m);
        allocator.free(members);
    }
    try std.testing.expectEqual(@as(usize, 2), members.len);

    try std.testing.expect(try Set.remove(&db, allocator, "tags", "zig"));
    try std.testing.expect(!try Set.remove(&db, allocator, "tags", "zig"));
    try std.testing.expectEqual(@as(usize, 1), try Set.card(&db, allocator, "tags"));
}

test "set intersect union difference across multiple sets" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try Set.add(&db, allocator, "a", "1");
    _ = try Set.add(&db, allocator, "a", "2");
    _ = try Set.add(&db, allocator, "a", "3");
    _ = try Set.add(&db, allocator, "b", "2");
    _ = try Set.add(&db, allocator, "b", "3");
    _ = try Set.add(&db, allocator, "b", "4");

    const inter = try Set.intersect(&db, allocator, &.{ "a", "b" });
    defer {
        for (inter) |m| allocator.free(m);
        allocator.free(inter);
    }
    try std.testing.expectEqual(@as(usize, 2), inter.len);

    const uni = try Set.unionOf(&db, allocator, &.{ "a", "b" });
    defer {
        for (uni) |m| allocator.free(m);
        allocator.free(uni);
    }
    try std.testing.expectEqual(@as(usize, 4), uni.len);

    const diff = try Set.difference(&db, allocator, "a", &.{"b"});
    defer {
        for (diff) |m| allocator.free(m);
        allocator.free(diff);
    }
    try std.testing.expectEqual(@as(usize, 1), diff.len);
    try std.testing.expectEqualStrings("1", diff[0]);
}

test "list push pop both ends preserve order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try List.pushRight(&db, allocator, "queue", "b");
    try List.pushRight(&db, allocator, "queue", "c");
    try List.pushLeft(&db, allocator, "queue", "a");
    try std.testing.expectEqual(@as(usize, 3), try List.len(&db, allocator, "queue"));

    const first = (try List.popLeft(&db, allocator, "queue")).?;
    defer allocator.free(first);
    try std.testing.expectEqualStrings("a", first);

    const last = (try List.popRight(&db, allocator, "queue")).?;
    defer allocator.free(last);
    try std.testing.expectEqualStrings("c", last);

    try std.testing.expectEqual(@as(usize, 1), try List.len(&db, allocator, "queue"));
    try std.testing.expect(try List.popLeft(&db, allocator, "empty") == null);
}

test "list range supports negative indices redis style" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try List.pushRight(&db, allocator, "l", "0");
    try List.pushRight(&db, allocator, "l", "1");
    try List.pushRight(&db, allocator, "l", "2");
    try List.pushRight(&db, allocator, "l", "3");
    try List.pushRight(&db, allocator, "l", "4");

    const full = try List.range(&db, allocator, "l", 0, -1);
    defer {
        for (full) |v| allocator.free(v);
        allocator.free(full);
    }
    try std.testing.expectEqual(@as(usize, 5), full.len);
    try std.testing.expectEqualStrings("0", full[0]);
    try std.testing.expectEqualStrings("4", full[4]);

    const lastTwo = try List.range(&db, allocator, "l", -2, -1);
    defer {
        for (lastTwo) |v| allocator.free(v);
        allocator.free(lastTwo);
    }
    try std.testing.expectEqual(@as(usize, 2), lastTwo.len);
    try std.testing.expectEqualStrings("3", lastTwo[0]);
    try std.testing.expectEqualStrings("4", lastTwo[1]);

    const clamped = try List.range(&db, allocator, "l", -100, 100);
    defer {
        for (clamped) |v| allocator.free(v);
        allocator.free(clamped);
    }
    try std.testing.expectEqual(@as(usize, 5), clamped.len);
}

test "zset add score incrBy remove rank" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try ZSet.add(&db, allocator, "leaderboard", "alice", 10);
    try ZSet.add(&db, allocator, "leaderboard", "bob", 20);
    try ZSet.add(&db, allocator, "leaderboard", "carol", 5);

    try std.testing.expectEqual(@as(f64, 10), (try ZSet.score(&db, allocator, "leaderboard", "alice")).?);
    try std.testing.expectEqual(@as(usize, 3), try ZSet.card(&db, allocator, "leaderboard"));

    const newScore = try ZSet.incrBy(&db, allocator, "leaderboard", "alice", 100);
    try std.testing.expectEqual(@as(f64, 110), newScore);

    try std.testing.expectEqual(@as(usize, 0), (try ZSet.rank(&db, allocator, "leaderboard", "carol")).?);
    try std.testing.expectEqual(@as(usize, 2), (try ZSet.rank(&db, allocator, "leaderboard", "alice")).?);
    try std.testing.expect(try ZSet.rank(&db, allocator, "leaderboard", "missing") == null);

    try std.testing.expect(try ZSet.remove(&db, allocator, "leaderboard", "bob"));
    try std.testing.expect(!try ZSet.remove(&db, allocator, "leaderboard", "bob"));
    try std.testing.expectEqual(@as(usize, 2), try ZSet.card(&db, allocator, "leaderboard"));
}

test "zset rangeByRank and rangeByScore return ascending order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try ZSet.add(&db, allocator, "z", "a", -5.5);
    try ZSet.add(&db, allocator, "z", "b", 0);
    try ZSet.add(&db, allocator, "z", "c", 3.25);
    try ZSet.add(&db, allocator, "z", "d", 100);

    const byRank = try ZSet.rangeByRank(&db, allocator, "z", 0, -1);
    defer {
        for (byRank) |m| m.free(allocator);
        allocator.free(byRank);
    }
    try std.testing.expectEqual(@as(usize, 4), byRank.len);
    try std.testing.expectEqualStrings("a", byRank[0].member);
    try std.testing.expectEqualStrings("d", byRank[3].member);

    const top2 = try ZSet.rangeByRank(&db, allocator, "z", -2, -1);
    defer {
        for (top2) |m| m.free(allocator);
        allocator.free(top2);
    }
    try std.testing.expectEqual(@as(usize, 2), top2.len);
    try std.testing.expectEqualStrings("c", top2[0].member);
    try std.testing.expectEqualStrings("d", top2[1].member);

    const byScore = try ZSet.rangeByScore(&db, allocator, "z", -1.0, 50.0);
    defer {
        for (byScore) |m| m.free(allocator);
        allocator.free(byScore);
    }
    try std.testing.expectEqual(@as(usize, 2), byScore.len);
    try std.testing.expectEqualStrings("b", byScore[0].member);
    try std.testing.expectEqualStrings("c", byScore[1].member);
}

test "Kind.parse accepts the five CLI names and rejects the rest" {
    try std.testing.expectEqual(Kind.counter, Kind.parse("counter").?);
    try std.testing.expectEqual(Kind.hash, Kind.parse("hash").?);
    try std.testing.expectEqual(Kind.set, Kind.parse("set").?);
    try std.testing.expectEqual(Kind.list, Kind.parse("list").?);
    try std.testing.expectEqual(Kind.zset, Kind.parse("zset").?);
    try std.testing.expect(Kind.parse("bogus") == null);
}

test "Kind.fromTagByte is the exact inverse of tagByte for all five kinds" {
    const kinds = [_]Kind{ .counter, .hash, .set, .list, .zset };
    for (kinds) |k| {
        try std.testing.expectEqual(k, Kind.fromTagByte(k.tagByte()).?);
    }
    try std.testing.expect(Kind.fromTagByte('?') == null);
}

test "exists and drop cover counter (single key, no trailing separator)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expect(!try collectionExists(&db, allocator, .counter, "hits"));
    _ = try Counter.incrBy(&db, allocator, "hits", 0);
    try std.testing.expect(try collectionExists(&db, allocator, .counter, "hits"));

    _ = try Counter.incrBy(&db, allocator, "hitsExtra", 7);

    try std.testing.expectEqual(@as(usize, 1), try dropCollection(&db, allocator, .counter, "hits"));
    try std.testing.expect(!try collectionExists(&db, allocator, .counter, "hits"));
    try std.testing.expectEqual(@as(i64, 7), try Counter.get(&db, allocator, "hitsExtra"));
}

test "drop removes every field of a hash and every element+meta of a list" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try Hash.set(&db, allocator, "user:1", "name", "ada");
    _ = try Hash.set(&db, allocator, "user:1", "age", "36");
    try std.testing.expect(try collectionExists(&db, allocator, .hash, "user:1"));
    try std.testing.expectEqual(@as(usize, 2), try dropCollection(&db, allocator, .hash, "user:1"));
    try std.testing.expect(!try collectionExists(&db, allocator, .hash, "user:1"));
    try std.testing.expectEqual(@as(usize, 0), try Hash.len(&db, allocator, "user:1"));

    try List.pushRight(&db, allocator, "queue", "a");
    try List.pushRight(&db, allocator, "queue", "b");
    try std.testing.expect(try collectionExists(&db, allocator, .list, "queue"));
    try std.testing.expectEqual(@as(usize, 3), try dropCollection(&db, allocator, .list, "queue"));
    try std.testing.expect(!try collectionExists(&db, allocator, .list, "queue"));
    try std.testing.expectEqual(@as(usize, 0), try List.len(&db, allocator, "queue"));

    try std.testing.expectEqual(@as(usize, 0), try dropCollection(&db, allocator, .set, "never-existed"));
}

test "drop removes both the member row and score-index row of every zset entry" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try ZSet.add(&db, allocator, "leaderboard", "alice", 10);
    try ZSet.add(&db, allocator, "leaderboard", "bob", 20);
    try std.testing.expect(try collectionExists(&db, allocator, .zset, "leaderboard"));
    try std.testing.expectEqual(@as(usize, 4), try dropCollection(&db, allocator, .zset, "leaderboard"));
    try std.testing.expect(!try collectionExists(&db, allocator, .zset, "leaderboard"));
    try std.testing.expectEqual(@as(usize, 0), try ZSet.card(&db, allocator, "leaderboard"));
}

test "zset add is a no-op when the score does not change" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try ZSet.add(&db, allocator, "z", "a", 5.0);
    try ZSet.add(&db, allocator, "z", "a", 5.0);
    try std.testing.expectEqual(@as(usize, 1), try ZSet.card(&db, allocator, "z"));
    try std.testing.expectEqual(@as(f64, 5.0), (try ZSet.score(&db, allocator, "z", "a")).?);
}
