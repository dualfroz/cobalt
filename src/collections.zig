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

