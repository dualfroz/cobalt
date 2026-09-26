const std = @import("std");
const dbmod = @import("db.zig");
const ttlmod = @import("ttl.zig");
const collmod = @import("collections.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Kind = collmod.Kind;
pub const TtlResult = ttlmod.TtlResult;

pub const nsTag: u8 = 0xFB;
const collSub: u8 = 0x01;
const sep: u8 = 0x00;

fn markerKey(allocator: Allocator, k: Kind, name: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, name.len + 3);
    out[0] = nsTag;
    out[1] = collSub;
    out[2] = k.tagByte();
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

pub fn remaining(db: *Db, allocator: Allocator, k: Kind, name: []const u8, nowNanos: i128) !TtlResult {
    if (!try collmod.collectionExists(db, allocator, k, name)) return .noKey;
    const expiresAt = try getExpiresAt(db, allocator, k, name) orelse return .noExpiry;
    if (nowNanos >= expiresAt) return .{ .seconds = 0 };
    return .{ .seconds = @intCast(@divFloor(expiresAt - nowNanos, ttlmod.secondNanos)) };
}

pub fn expireIfDue(db: *Db, allocator: Allocator, k: Kind, name: []const u8, nowNanos: i128) !bool {
    const expiresAt = try getExpiresAt(db, allocator, k, name) orelse return false;
    if (!ttlmod.isDue(expiresAt, nowNanos)) return false;
    _ = try collmod.dropCollection(db, allocator, k, name);
    try clearExpire(db, allocator, k, name);
    return true;
}

pub fn expireIfDueMany(db: *Db, allocator: Allocator, k: Kind, names: []const []const u8, nowNanos: i128) !usize {
    var reaped: usize = 0;
    for (names) |name| {
        if (try expireIfDue(db, allocator, k, name, nowNanos)) reaped += 1;
    }
    return reaped;
}

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

    const reaped = try expireIfDueMany(&db, allocator, .set, &.{ "b", "c" }, 5 * ttlmod.secondNanos);
    try std.testing.expectEqual(@as(usize, 1), reaped);

    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .set, "b"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "a"));
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "c"));

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
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, .set, "shared", 0));

    const hashResult = try remaining(&db, allocator, .hash, "shared", 0);
    try std.testing.expectEqual(@as(u64, 5), hashResult.seconds);
}
