const std = @import("std");
const dbmod = @import("db.zig");
const auth = @import("auth.zig");
const index = @import("index.zig");
const collections = @import("collections.zig");
const collttl = @import("collttl.zig");
const ttl = @import("ttl.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;

pub const Entry = struct { owner: []const u8, tag: u8 };

pub const internalFloor: u8 = 0xF5;
const userKeyEnd = [_]u8{internalFloor};

pub const KeyspaceError = error{ReservedKey};

pub const registry = [_]Entry{
    .{ .owner = "auth", .tag = auth.nsTag },
    .{ .owner = "index.row", .tag = index.rowTag },
    .{ .owner = "index.index", .tag = index.indexTag },
    .{ .owner = "index.compositeIndex", .tag = index.compositeIndexTag },
    .{ .owner = "index.meta", .tag = index.metaTag },
    .{ .owner = "collections", .tag = collections.nsTag },
    .{ .owner = "collttl", .tag = collttl.nsTag },
    .{ .owner = "ttl", .tag = ttl.nsTag },
};

fn assertAllDistinct() void {
    @setEvalBranchQuota(10_000);
    for (registry, 0..) |a, i| {
        for (registry[i + 1 ..]) |b| {
            if (a.tag == b.tag) {
                @compileError("keyspace tag collision: '" ++ &[_]u8{a.tag} ++ "' claimed by both '" ++ a.owner ++ "' and '" ++ b.owner ++ "' - pick a different top-level byte for one of them");
            }
        }
    }
}

fn assertAllReserved() void {
    for (registry) |e| {
        if (e.tag < internalFloor) {
            @compileError("keyspace tag of '" ++ e.owner ++ "' is below internalFloor and would collide with user keys");
        }
    }
}

comptime {
    assertAllDistinct();
    assertAllReserved();
}

pub fn isFree(tag: u8) bool {
    for (registry) |e| {
        if (e.tag == tag) return false;
    }
    return true;
}

pub fn isInternal(key: []const u8) bool {
    return key.len > 0 and key[0] >= internalFloor;
}

pub fn checkUserKey(key: []const u8) KeyspaceError!void {
    if (isInternal(key)) return KeyspaceError.ReservedKey;
}

pub fn userScanOptions(options: dbmod.ScanOptions) dbmod.ScanOptions {
    var clamped = options;
    if (options.end) |bound| {
        if (std.mem.order(u8, bound, &userKeyEnd) == .lt) return clamped;
    }
    clamped.end = &userKeyEnd;
    clamped.endInclusive = false;
    return clamped;
}

pub const UserIterator = ttl.LiveIterator(dbmod.RangeIterator);
pub const UserReverseIterator = ttl.LiveIterator(dbmod.ReverseRangeIterator);

pub fn scanUser(db: *Db, allocator: Allocator, options: dbmod.ScanOptions, nowNanos: i128) !UserIterator {
    return ttl.liveOnly(db, allocator, try db.scanRange(allocator, userScanOptions(options)), nowNanos);
}

pub fn scanUserReverse(db: *Db, allocator: Allocator, options: dbmod.ScanOptions, nowNanos: i128) !UserReverseIterator {
    return ttl.liveOnly(db, allocator, try db.scanReverse(allocator, userScanOptions(options)), nowNanos);
}

pub fn scanUserPrefix(db: *Db, allocator: Allocator, prefix: []const u8, nowNanos: i128) !UserIterator {
    if (isInternal(prefix)) return ttl.liveOnly(db, allocator, try db.scanRange(allocator, .{ .start = &userKeyEnd, .end = &userKeyEnd }), nowNanos);
    if (prefix.len == 0) return scanUser(db, allocator, .{}, nowNanos);
    return ttl.liveOnly(db, allocator, try db.scanPrefix(allocator, prefix), nowNanos);
}

test "registry has no duplicate top-level tags (runtime mirror of the comptime check)" {
    for (registry, 0..) |a, i| {
        for (registry[i + 1 ..]) |b| {
            try std.testing.expect(a.tag != b.tag);
        }
    }
}

test "registry pins the exact set of tags currently in use" {
    var seen = std.AutoHashMap(u8, void).init(std.testing.allocator);
    defer seen.deinit();
    for (registry) |e| try seen.put(e.tag, {});
    try std.testing.expectEqual(@as(usize, 8), seen.count());
    inline for (.{ 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC }) |expected| {
        try std.testing.expect(seen.contains(expected));
    }
}

test "isFree reports the registered tags as taken and an unused byte as free" {
    try std.testing.expect(!isFree(0xF5));
    try std.testing.expect(!isFree(0xFC));
    try std.testing.expect(isFree(0xFD));
    try std.testing.expect(isFree('T'));
    try std.testing.expect(isFree(0));
}

test "checkUserKey rejects only keys starting in the reserved range" {
    try checkUserKey("Tsession:9");
    try checkUserKey("Alice");
    try checkUserKey("");
    try checkUserKey(&[_]u8{ 0x00, 0x01 });
    try checkUserKey("\xF0\x9F\x98\x80");
    try checkUserKey(&[_]u8{ 0xF4, 0xFF });
    try std.testing.expectError(KeyspaceError.ReservedKey, checkUserKey(&[_]u8{0xF5}));
    try std.testing.expectError(KeyspaceError.ReservedKey, checkUserKey(&[_]u8{ ttl.nsTag, 'k' }));
    try std.testing.expectError(KeyspaceError.ReservedKey, checkUserKey(&[_]u8{0xFF}));
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const dbPath = try std.fs.path.join(allocator, &.{ base, "store" });
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

fn seedMixedKeyspace(db: *Db, allocator: Allocator) !void {
    try db.put("Alice", "user-a");
    try db.put("Tsession:9", "user-t");
    try db.put("zeta", "user-z");
    try db.put("session:9", "live");
    try ttl.setExpireSeconds(db, allocator, "session:9", std.time.nanoTimestamp(), 3600);
    _ = try collections.Counter.incrBy(db, allocator, "hits", 3);
    try collttl.setExpireSeconds(db, allocator, .counter, "hits", std.time.nanoTimestamp(), 3600);
    try auth.Store.init(db).createUser(allocator, "root", "pw", .admin, 16);
}

fn expectUserKeys(expected: []const []const u8, iter: anytype) !void {
    var seen: usize = 0;
    while (try iter.next()) |entry| {
        try std.testing.expect(seen < expected.len);
        try std.testing.expectEqualStrings(expected[seen], entry.key);
        seen += 1;
    }
    try std.testing.expectEqual(expected.len, seen);
}

test "user scans return only user keys while modules still see their own namespaces" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();
    try seedMixedKeyspace(&db, allocator);
    const now = std.time.nanoTimestamp();

    {
        var iter = try scanUser(&db, allocator, .{}, now);
        defer iter.deinit();
        try expectUserKeys(&.{ "Alice", "Tsession:9", "session:9", "zeta" }, &iter);
    }
    {
        var iter = try scanUserReverse(&db, allocator, .{}, now);
        defer iter.deinit();
        try expectUserKeys(&.{ "zeta", "session:9", "Tsession:9", "Alice" }, &iter);
    }
    {
        var iter = try scanUser(&db, allocator, .{ .start = "B", .end = &[_]u8{0xFF} }, now);
        defer iter.deinit();
        try expectUserKeys(&.{ "Tsession:9", "session:9", "zeta" }, &iter);
    }
    {
        var iter = try scanUserPrefix(&db, allocator, "", now);
        defer iter.deinit();
        try expectUserKeys(&.{ "Alice", "Tsession:9", "session:9", "zeta" }, &iter);
    }
    {
        var iter = try scanUserPrefix(&db, allocator, "T", now);
        defer iter.deinit();
        try expectUserKeys(&.{"Tsession:9"}, &iter);
    }
    {
        var iter = try scanUserPrefix(&db, allocator, &[_]u8{ttl.nsTag}, now);
        defer iter.deinit();
        try expectUserKeys(&.{}, &iter);
    }

    try std.testing.expect((try ttl.getExpiresAt(&db, allocator, "session:9")) != null);
    try std.testing.expectEqual(@as(?i128, null), try ttl.getExpiresAt(&db, allocator, "Tsession:9"));
    try std.testing.expectEqual(@as(i64, 3), try collections.Counter.get(&db, allocator, "hits"));
    _ = try auth.Store.init(&db).verify(allocator, "root", "pw");
}

test "user scans hide keys whose ttl is due and keep them until a read or sweep reaps them" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("cache:a", "stale");
    try ttl.setExpireAt(&db, allocator, "cache:a", 10 * ttl.secondNanos);
    try db.put("cache:b", "fresh");
    try ttl.setExpireAt(&db, allocator, "cache:b", 100 * ttl.secondNanos);
    try db.put("cache:c", "forever");
    try db.put("cache:d", "deadline");
    try ttl.setExpireAt(&db, allocator, "cache:d", 50 * ttl.secondNanos);

    const now = 50 * ttl.secondNanos;
    {
        var iter = try scanUser(&db, allocator, .{}, now);
        defer iter.deinit();
        try expectUserKeys(&.{ "cache:b", "cache:c" }, &iter);
    }
    {
        var iter = try scanUserReverse(&db, allocator, .{}, now);
        defer iter.deinit();
        try expectUserKeys(&.{ "cache:c", "cache:b" }, &iter);
    }
    {
        var iter = try scanUserPrefix(&db, allocator, "cache:", now);
        defer iter.deinit();
        try expectUserKeys(&.{ "cache:b", "cache:c" }, &iter);
    }
    {
        var iter = try scanUserPrefix(&db, allocator, "", now);
        defer iter.deinit();
        try expectUserKeys(&.{ "cache:b", "cache:c" }, &iter);
    }
    {
        var iter = try scanUser(&db, allocator, .{}, 0);
        defer iter.deinit();
        try expectUserKeys(&.{ "cache:a", "cache:b", "cache:c", "cache:d" }, &iter);
    }

    const stillStored = (try db.get(allocator, "cache:a")).?;
    defer allocator.free(stillStored);
    try std.testing.expectEqualStrings("stale", stillStored);
    try std.testing.expectEqual(@as(usize, 2), try ttl.sweepExpired(&db, allocator, now));
}

test "ttl sweep never mistakes a user key that looks like a ttl marker for one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("Tsession:9", "user");
    try db.put("Tgone", &[_]u8{0} ** 16);
    try db.put("gone", "x");
    try ttl.setExpireAt(&db, allocator, "gone", 0);

    try std.testing.expectEqual(@as(usize, 1), try ttl.sweepExpired(&db, allocator, std.time.nanoTimestamp()));
    const kept = (try db.get(allocator, "Tsession:9")).?;
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("user", kept);
    const keptLookalike = (try db.get(allocator, "Tgone")).?;
    defer allocator.free(keptLookalike);
    try std.testing.expectEqual(@as(usize, 16), keptLookalike.len);
}
