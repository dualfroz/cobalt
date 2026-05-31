const std = @import("std");
const dbmod = @import("db.zig");
const ttlmod = @import("ttl.zig");
const collmod = @import("collections.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Kind = collmod.Kind;
pub const TtlResult = ttlmod.TtlResult;

/// Per-collection expiry markers, sibling to ttl.zig's per-key markers but
/// for a different unit: a typed collection (Counter/Hash/Set/List/ZSet) is
/// not one physical Db key, it is a whole namespace of them (every field of
/// a hash, every element of a list, both rows of every zset entry), so
/// "expiring" one here always means dropping the ENTIRE namespace via
/// collections.drop, not a single db.delete.
///   "Y" <kind tag byte> 0x00 <name> -> raw i128 (expiresAtNanos, big-endian)
///
/// This used to share ttl.zig's 'T' tag (with a leading 0x01 sub-byte to
/// keep individual marker keys from colliding byte-for-byte). That was a
/// real bug, not just an odd design: ttl.zig's own `sweepExpired` scans by
/// the single-byte prefix "T", and every collttl marker IS a byte-for-byte
/// extension of that same prefix, so the flat sweeper's scan matched them
/// too. Both modules store the identical i128-expiresAt payload shape, so
/// `readI128` on a collttl marker "succeeded" without error; if it looked
/// due, the flat sweeper would `db.delete` a harmless nonexistent flat key
/// and then reconstruct and delete the ORIGINAL collttl marker key via its
/// own `clearExpire(key[1..])` - silently clearing the collection's expiry
/// marker without ever calling `collections.dropCollection`, so the
/// collection's actual data was never removed even though flat-key
/// `ttlSweptTotal` had counted a phantom reap for it. Caught by a real
/// test that runs both sweepers against the same Db at once (see
/// server.zig's "flat ttl sweeper and the coll ttl sweeper enabled at once"
/// test) - a manual `ttl expire-sweep`/`ttl_op sweep` run on a Db that also
/// has due collection markers would trip the same bug even with only one
/// sweeper. Fixed by giving collttl.zig its own top-level tag ('Y', not
/// used by row.zig/index.zig/collections.zig/auth.zig/ttl.zig), so it is
/// prefix-disjoint from every other namespace, not merely full-key-disjoint
/// the way the shared-'T' scheme assumed.
pub const nsTag: u8 = 'Y';
const collSub: u8 = 0x01;
const sep: u8 = 0x00;

fn markerKey(allocator: Allocator, k: Kind, name: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, name.len + 3);
    out[0] = nsTag;
    out[1] = collSub;
    out[2] = k.tagByte();
    // name is appended without its own leading separator on purpose: the
    // fixed 3-byte header (nsTag, collSub, kindTag) already makes every
    // marker key length-disjoint per kind boundary at byte 2, so no two
    // different (kind, name) pairs can ever produce the same marker key.
    @memcpy(out[3..], name);
    return out;
}

fn putI128(out: *std.ArrayList(u8), v: i128) !void {
    var b: [16]u8 = undefined;
    std.mem.writeInt(i128, &b, v, .big);
    try out.appendSlice(&b);
}

fn readI128(data: []const u8) !i128 {
    if (data.len != 16) return error.Malformed;
    return std.mem.readInt(i128, data[0..16], .big);
}

/// Sets (or replaces) an absolute expiry deadline on the collection `name`
/// of kind `k`. Does not verify the collection currently exists - callers
/// that need existence-checked semantics (the CLI `coll <kind> expire`
/// command) check collections.exists first, same as ttl.zig's setExpireAt
/// vs the CLI's flat-key `expire`.
pub fn setExpireAt(db: *Db, allocator: Allocator, k: Kind, name: []const u8, expiresAtNanos: i128) !void {
    const mk = try markerKey(allocator, k, name);
    defer allocator.free(mk);
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try putI128(&out, expiresAtNanos);
    try db.put(mk, out.items);
}

pub fn setExpireSeconds(db: *Db, allocator: Allocator, k: Kind, name: []const u8, nowNanos: i128, seconds: u64) !void {
    try setExpireAt(db, allocator, k, name, nowNanos + @as(i128, @intCast(seconds)) * ttlmod.secondNanos);
}

pub fn getExpiresAt(db: *Db, allocator: Allocator, k: Kind, name: []const u8) !?i128 {
    const mk = try markerKey(allocator, k, name);
    defer allocator.free(mk);
    const raw = try db.get(allocator, mk) orelse return null;
    defer allocator.free(raw);
    return try readI128(raw);
}

pub fn clearExpire(db: *Db, allocator: Allocator, k: Kind, name: []const u8) !void {
    const mk = try markerKey(allocator, k, name);
    defer allocator.free(mk);
    try db.delete(mk);
}

/// Redis TTL(2)-shaped result, same three cases as ttl.zig's `remaining`:
/// `.noKey` when the collection has no physical presence at all,
/// `.noExpiry` when it exists but carries no marker, `.seconds` otherwise.
pub fn remaining(db: *Db, allocator: Allocator, k: Kind, name: []const u8, nowNanos: i128) !TtlResult {
    if (!try collmod.collectionExists(db, allocator, k, name)) return .noKey;
    const expiresAt = try getExpiresAt(db, allocator, k, name) orelse return .noExpiry;
    if (nowNanos >= expiresAt) return .{ .seconds = 0 };
    return .{ .seconds = @intCast(@divFloor(expiresAt - nowNanos, ttlmod.secondNanos)) };
}

/// Lazily enforces expiry on access: if the collection carries a due
/// marker, drops every physical key it owns (collections.drop - a real
/// multi-key delete through the normal WAL/tombstone path, not a pretend
/// removal) plus the marker itself, and reports true. The CLI's `coll`
/// dispatcher calls this before every non-TTL operation so a caller never
/// observes a logically-expired collection just because no sweep has run.
pub fn expireIfDue(db: *Db, allocator: Allocator, k: Kind, name: []const u8, nowNanos: i128) !bool {
    const expiresAt = try getExpiresAt(db, allocator, k, name) orelse return false;
    if (!ttlmod.isDue(expiresAt, nowNanos)) return false;
    _ = try collmod.dropCollection(db, allocator, k, name);
    try clearExpire(db, allocator, k, name);
    return true;
}

/// Same lazy check as `expireIfDue`, applied to every name in `names`
/// instead of a single one. Closes the gap documented at the `Set`
/// multi-set operations' call sites (`intersect`/`unionOf`/`difference`):
/// those accept more than one set name, but only the first one was ever
/// checked on the read path (the CLI's blanket single-name check runs on
/// `args[0]` before dispatch), leaving `args[1..]` reachable only through
/// the periodic/manual sweep. Returns the count actually reaped, same
/// counting convention as `sweepExpired`.
pub fn expireIfDueMany(db: *Db, allocator: Allocator, k: Kind, names: []const []const u8, nowNanos: i128) !usize {
    var reaped: usize = 0;
    for (names) |name| {
        if (try expireIfDue(db, allocator, k, name, nowNanos)) reaped += 1;
    }
    return reaped;
}

/// Active sweep across every kind at once: scans the whole collection-TTL
/// marker namespace, drops every collection whose marker is due. Returns
/// the number of collections reaped (not the number of physical keys - a
/// dropped hash with 5 fields counts once here, same granularity as
/// ttl.zig's sweepExpired counts flat keys).
pub fn sweepExpired(db: *Db, allocator: Allocator, nowNanos: i128) !usize {
    const Due = struct { k: Kind, name: []u8 };
    var due = std.ArrayList(Due).init(allocator);
    defer {
        for (due.items) |d| allocator.free(d.name);
        due.deinit();
    }
    {
        const prefix = &[_]u8{ nsTag, collSub };
        var iter = try db.scanPrefix(allocator, prefix);
        defer iter.deinit();
        while (try iter.next()) |entry| {
            // entry.key = nsTag collSub kindTag name...
            if (entry.key.len < 3) continue;
            const k: Kind = Kind.fromTagByte(entry.key[2]) orelse continue;
            const expiresAt = try readI128(entry.value);
            if (ttlmod.isDue(expiresAt, nowNanos)) {
                try due.append(.{ .k = k, .name = try allocator.dupe(u8, entry.key[3..]) });
            }
        }
    }
    for (due.items) |d| {
        _ = try collmod.dropCollection(db, allocator, d.k, d.name);
        try clearExpire(db, allocator, d.k, d.name);
    }
    return due.items.len;
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

test "remaining reports noKey for a collection that was never created" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, .hash, "missing", 0));
}

test "remaining reports noExpiry then counted seconds for a real hash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Hash.set(&db, allocator, "profile", "name", "ada");
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, .hash, "profile", 0));

    try setExpireSeconds(&db, allocator, .hash, "profile", 1000, 30);
    const r = try remaining(&db, allocator, .hash, "profile", 1000);
    try std.testing.expectEqual(@as(u64, 30), r.seconds);
}

test "expireIfDue drops every field of a hash, not just one key" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Hash.set(&db, allocator, "session:1", "user", "ada");
    _ = try collmod.Hash.set(&db, allocator, "session:1", "role", "admin");
    try setExpireSeconds(&db, allocator, .hash, "session:1", 0, 5);

    try std.testing.expect(!try expireIfDue(&db, allocator, .hash, "session:1", 4 * ttlmod.secondNanos));
    try std.testing.expectEqual(@as(usize, 2), try collmod.Hash.len(&db, allocator, "session:1"));

    try std.testing.expect(try expireIfDue(&db, allocator, .hash, "session:1", 5 * ttlmod.secondNanos));
    try std.testing.expectEqual(@as(usize, 0), try collmod.Hash.len(&db, allocator, "session:1"));
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "session:1"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, .hash, "session:1"));
}

test "expireIfDueMany reaps only the due names among several, mirroring a Set.intersect call" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Set.add(&db, allocator, "a", "x");
    _ = try collmod.Set.add(&db, allocator, "b", "x");
    _ = try collmod.Set.add(&db, allocator, "c", "x");
    try setExpireSeconds(&db, allocator, .set, "b", 0, 5);

    // Mirrors `coll set inter a b c`: the CLI's blanket lazy check only
    // ever covered args[0] ("a"); this call is what now covers args[1..].
    const reaped = try expireIfDueMany(&db, allocator, .set, &.{ "b", "c" }, 5 * ttlmod.secondNanos);
    try std.testing.expectEqual(@as(usize, 1), reaped);

    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .set, "b"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "a"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "c"));

    // Now Set.intersect(a, c) sees a live pair and finds the real member,
    // instead of silently intersecting against a phantom "b" that a
    // periodic sweep hadn't reaped yet.
    const inter = try collmod.Set.intersect(&db, allocator, &.{ "a", "c" });
    defer {
        for (inter) |m| allocator.free(m);
        allocator.free(inter);
    }
    try std.testing.expectEqual(@as(usize, 1), inter.len);
    try std.testing.expectEqualStrings("x", inter[0]);
}

test "expireIfDueMany is a no-op count of zero when nothing is due" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Set.add(&db, allocator, "a", "x");
    _ = try collmod.Set.add(&db, allocator, "b", "x");

    try std.testing.expectEqual(@as(usize, 0), try expireIfDueMany(&db, allocator, .set, &.{ "a", "b" }, 0));
}

test "clearExpire makes a collection immortal again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try collmod.List.pushRight(&db, allocator, "queue", "job-1");
    try setExpireSeconds(&db, allocator, .list, "queue", 0, 1);
    try clearExpire(&db, allocator, .list, "queue");

    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, .list, "queue", 100 * ttlmod.secondNanos));
    try std.testing.expect(!try expireIfDue(&db, allocator, .list, "queue", 100 * ttlmod.secondNanos));
    try std.testing.expectEqual(@as(usize, 1), try collmod.List.len(&db, allocator, "queue"));
}

test "sweepExpired reaps due collections of every kind without touching live ones" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Counter.incrBy(&db, allocator, "hits", 3);
    try setExpireSeconds(&db, allocator, .counter, "hits", 0, 1);

    _ = try collmod.Hash.set(&db, allocator, "profile", "name", "ada");
    try setExpireSeconds(&db, allocator, .hash, "profile", 0, 100);

    try collmod.ZSet.add(&db, allocator, "leaderboard", "alice", 10);
    try setExpireSeconds(&db, allocator, .zset, "leaderboard", 0, 1);

    _ = try collmod.Set.add(&db, allocator, "tags", "zig");

    const reaped = try sweepExpired(&db, allocator, 2 * ttlmod.secondNanos);
    try std.testing.expectEqual(@as(usize, 2), reaped);

    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .counter, "hits"));
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .zset, "leaderboard"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .hash, "profile"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "tags"));

    // Idempotent: a second sweep at the same instant finds nothing left.
    try std.testing.expectEqual(@as(usize, 0), try sweepExpired(&db, allocator, 2 * ttlmod.secondNanos));
}

test "collection sweep survives a wal reopen: markers are durable" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator);
        defer db.close();
        _ = try collmod.Hash.set(&db, allocator, "durable", "k", "v");
        try setExpireSeconds(&db, allocator, .hash, "durable", 0, 5);
    }

    var db = try openTemp(&tmp, allocator);
    defer db.close();
    const r = try remaining(&db, allocator, .hash, "durable", 1 * ttlmod.secondNanos);
    try std.testing.expectEqual(@as(u64, 4), r.seconds);

    try std.testing.expectEqual(@as(usize, 1), try sweepExpired(&db, allocator, 10 * ttlmod.secondNanos));
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "durable"));
}

test "markers for the same name under different kinds never collide" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    _ = try collmod.Hash.set(&db, allocator, "shared", "f", "v");
    _ = try collmod.Set.add(&db, allocator, "shared", "m");

    try setExpireSeconds(&db, allocator, .hash, "shared", 0, 5);
    // The set named "shared" must still read as noExpiry - the marker for
    // the hash "shared" must not leak across the kind boundary.
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, .set, "shared", 0));

    const hashResult = try remaining(&db, allocator, .hash, "shared", 0);
    try std.testing.expectEqual(@as(u64, 5), hashResult.seconds);
}
