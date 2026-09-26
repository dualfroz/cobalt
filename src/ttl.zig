const std = @import("std");
const dbmod = @import("db.zig");
const txnmod = @import("txn.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const WriteBatch = dbmod.WriteBatch;
const Transaction = txnmod.Transaction;

pub const nsTag: u8 = 0xFC;

pub const secondNanos: i128 = 1_000_000_000;

fn markerKey(allocator: Allocator, key: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, key.len + 1);
    out[0] = nsTag;
    @memcpy(out[1..], key);
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

pub fn setExpireAt(db: *Db, allocator: Allocator, key: []const u8, expiresAtNanos: i128) !void {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try putI128(&out, expiresAtNanos);
    try db.put(k, out.items);
}

pub fn setExpireSeconds(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128, seconds: u64) !void {
    try setExpireAt(db, allocator, key, nowNanos + @as(i128, @intCast(seconds)) * secondNanos);
}

pub fn getExpiresAt(db: *Db, allocator: Allocator, key: []const u8) !?i128 {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const raw = try db.get(allocator, k) orelse return null;
    defer allocator.free(raw);
    return try readI128(raw);
}

pub fn clearExpire(db: *Db, allocator: Allocator, key: []const u8) !void {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    try db.delete(k);
}

pub fn isDue(expiresAtNanos: i128, nowNanos: i128) bool {
    return nowNanos >= expiresAtNanos;
}

pub const TtlResult = union(enum) {
    noKey,
    noExpiry,
    seconds: u64,
};

pub fn remaining(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !TtlResult {
    const existing = try db.get(allocator, key) orelse return .noKey;
    allocator.free(existing);
    const expiresAt = try getExpiresAt(db, allocator, key) orelse return .noExpiry;
    if (isDue(expiresAt, nowNanos)) return .noKey;
    return .{ .seconds = @intCast(@divFloor(expiresAt - nowNanos, secondNanos)) };
}

pub fn expireLive(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128, seconds: u64) !bool {
    const existing = try getLive(db, allocator, key, nowNanos) orelse return false;
    allocator.free(existing);
    try setExpireSeconds(db, allocator, key, nowNanos, seconds);
    return true;
}

pub fn isExpired(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !bool {
    const expiresAt = try getExpiresAt(db, allocator, key) orelse return false;
    return isDue(expiresAt, nowNanos);
}

pub fn expireIfDue(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !bool {
    if (!try isExpired(db, allocator, key, nowNanos)) return false;
    try db.delete(key);
    try clearExpire(db, allocator, key);
    return true;
}

pub fn LiveIterator(comptime Inner: type) type {
    return struct {
        inner: Inner,
        db: *Db,
        allocator: Allocator,
        nowNanos: i128,

        const Self = @This();

        pub fn next(self: *Self) !?dbmod.Entry {
            while (try self.inner.next()) |entry| {
                if (!try isExpired(self.db, self.allocator, entry.key, self.nowNanos)) return entry;
            }
            return null;
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
        }
    };
}

pub fn liveOnly(db: *Db, allocator: Allocator, inner: anytype, nowNanos: i128) LiveIterator(@TypeOf(inner)) {
    return .{ .inner = inner, .db = db, .allocator = allocator, .nowNanos = nowNanos };
}

pub fn getLive(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !?[]u8 {
    _ = try expireIfDue(db, allocator, key, nowNanos);
    return db.get(allocator, key);
}

pub fn putWithTtl(db: *Db, allocator: Allocator, key: []const u8, value: []const u8, nowNanos: i128, seconds: u64) !void {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try putI128(&out, nowNanos + @as(i128, @intCast(seconds)) * secondNanos);
    var wb = WriteBatch.init(allocator);
    defer wb.deinit();
    try wb.put(key, value);
    try wb.put(k, out.items);
    try db.apply(&wb);
}

pub fn stagePersistentPut(db: *Db, allocator: Allocator, wb: *WriteBatch, key: []const u8, value: []const u8) !void {
    try wb.put(key, value);
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const marker = try db.get(allocator, k) orelse return;
    allocator.free(marker);
    try wb.delete(k);
}

pub fn putPersistent(db: *Db, allocator: Allocator, key: []const u8, value: []const u8) !void {
    var wb = WriteBatch.init(allocator);
    defer wb.deinit();
    try stagePersistentPut(db, allocator, &wb, key, value);
    if (wb.count() == 1) return db.put(key, value);
    try db.apply(&wb);
}

pub fn stagePersistentPutInTxn(txn: *Transaction, allocator: Allocator, key: []const u8, value: []const u8) !void {
    try txn.put(key, value);
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const marker = try txn.get(allocator, k) orelse return;
    allocator.free(marker);
    try txn.delete(k);
}

pub fn isExpiredInTxn(txn: *Transaction, allocator: Allocator, key: []const u8, nowNanos: i128) !bool {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const raw = try txn.get(allocator, k) orelse return false;
    defer allocator.free(raw);
    return isDue(try readI128(raw), nowNanos);
}

pub fn expireLiveInTxn(txn: *Transaction, allocator: Allocator, key: []const u8, nowNanos: i128, seconds: u64) !bool {
    const existing = try txn.get(allocator, key) orelse return false;
    allocator.free(existing);
    if (try isExpiredInTxn(txn, allocator, key, nowNanos)) return false;
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try putI128(&out, nowNanos + @as(i128, @intCast(seconds)) * secondNanos);
    try txn.put(k, out.items);
    return true;
}

pub fn clearExpireInTxn(txn: *Transaction, allocator: Allocator, key: []const u8) !void {
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const marker = try txn.get(allocator, k) orelse return;
    allocator.free(marker);
    try txn.delete(k);
}

pub fn remainingInTxn(txn: *Transaction, allocator: Allocator, key: []const u8, nowNanos: i128) !TtlResult {
    const existing = try txn.get(allocator, key) orelse return .noKey;
    allocator.free(existing);
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const raw = try txn.get(allocator, k) orelse return .noExpiry;
    defer allocator.free(raw);
    const expiresAt = try readI128(raw);
    if (isDue(expiresAt, nowNanos)) return .noKey;
    return .{ .seconds = @intCast(@divFloor(expiresAt - nowNanos, secondNanos)) };
}

pub fn stageDelete(db: *Db, allocator: Allocator, wb: *WriteBatch, key: []const u8) !void {
    try wb.delete(key);
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const marker = try db.get(allocator, k) orelse return;
    allocator.free(marker);
    try wb.delete(k);
}

pub fn deleteKey(db: *Db, allocator: Allocator, key: []const u8) !void {
    var wb = WriteBatch.init(allocator);
    defer wb.deinit();
    try stageDelete(db, allocator, &wb, key);
    if (wb.count() == 1) return db.delete(key);
    try db.apply(&wb);
}

pub fn stageDeleteInTxn(txn: *Transaction, allocator: Allocator, key: []const u8) !void {
    try txn.delete(key);
    const k = try markerKey(allocator, key);
    defer allocator.free(k);
    const marker = try txn.get(allocator, k) orelse return;
    allocator.free(marker);
    try txn.delete(k);
}

pub fn sweepExpired(db: *Db, allocator: Allocator, nowNanos: i128) !usize {
    var due = std.ArrayList([]u8).init(allocator);
    defer {
        for (due.items) |k| allocator.free(k);
        due.deinit();
    }
    {
        const prefix = &[_]u8{nsTag};
        var iter = try db.scanPrefix(allocator, prefix);
        defer iter.deinit();
        while (try iter.next()) |entry| {
            const expiresAt = try readI128(entry.value);
            if (isDue(expiresAt, nowNanos)) {
                try due.append(try allocator.dupe(u8, entry.key[1..]));
            }
        }
    }
    for (due.items) |userKey| {
        try db.delete(userKey);
        try clearExpire(db, allocator, userKey);
    }
    return due.items.len;
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    var pathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathBuf);
    var dbPathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const dbPath = try std.fmt.bufPrint(&dbPathBuf, "{s}/store", .{base});
    return Db.open(allocator, dbPath, .{});
}

test "remaining reports noKey, noExpiry, and counted seconds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, "missing", 0));

    try db.put("plain", "v");
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, "plain", 0));

    try setExpireSeconds(&db, allocator, "plain", 1000, 30);
    const r = try remaining(&db, allocator, "plain", 1000);
    try std.testing.expectEqual(@as(u64, 30), r.seconds);
}

test "expireIfDue removes value and marker only once due" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("session:1", "payload");
    try setExpireSeconds(&db, allocator, "session:1", 0, 5);

    try std.testing.expect(!try expireIfDue(&db, allocator, "session:1", 4 * secondNanos));
    const stillThere = (try db.get(allocator, "session:1")).?;
    allocator.free(stillThere);

    try std.testing.expect(try expireIfDue(&db, allocator, "session:1", 5 * secondNanos));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "session:1"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "session:1"));
}

test "getLive lazily expires exactly at the deadline" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "cache:x", "hot", 0, 2);

    const before = (try getLive(&db, allocator, "cache:x", 1 * secondNanos)).?;
    defer allocator.free(before);
    try std.testing.expectEqualStrings("hot", before);

    try std.testing.expectEqual(@as(?[]u8, null), try getLive(&db, allocator, "cache:x", 2 * secondNanos));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "cache:x"));
}

test "clearExpire makes a key immortal again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "note", "keep me", 0, 1);
    try clearExpire(&db, allocator, "note");

    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, "note", 100 * secondNanos));
    const v = (try getLive(&db, allocator, "note", 100 * secondNanos)).?;
    defer allocator.free(v);
    try std.testing.expectEqualStrings("keep me", v);
}

test "sweepExpired reaps every due key without touching live or unrelated keys" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "a", "1", 0, 1);
    try putWithTtl(&db, allocator, "b", "2", 0, 100);
    try putWithTtl(&db, allocator, "c", "3", 0, 1);
    try db.put("d", "forever");

    const reaped = try sweepExpired(&db, allocator, 2 * secondNanos);
    try std.testing.expectEqual(@as(usize, 2), reaped);

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "a"));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "c"));

    const b = (try db.get(allocator, "b")).?;
    defer allocator.free(b);
    try std.testing.expectEqualStrings("2", b);

    const d = (try db.get(allocator, "d")).?;
    defer allocator.free(d);
    try std.testing.expectEqualStrings("forever", d);

    try std.testing.expectEqual(@as(usize, 0), try sweepExpired(&db, allocator, 2 * secondNanos));
}

test "sweep survives a wal reopen: markers are durable, not in-memory bookkeeping" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator);
        defer db.close();
        try putWithTtl(&db, allocator, "durable-ttl", "v", 0, 5);
    }

    var db = try openTemp(&tmp, allocator);
    defer db.close();
    const r = try remaining(&db, allocator, "durable-ttl", 1 * secondNanos);
    try std.testing.expectEqual(@as(u64, 4), r.seconds);

    try std.testing.expectEqual(@as(usize, 1), try sweepExpired(&db, allocator, 10 * secondNanos));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "durable-ttl"));
}

test "setExpireAt on a nonexistent key is a real marker, not silently rejected" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try setExpireSeconds(&db, allocator, "ghost", 0, 10);
    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, "ghost", 0));
    const expiresAt = (try getExpiresAt(&db, allocator, "ghost")).?;
    try std.testing.expectEqual(@as(i128, 10 * secondNanos), expiresAt);
}

test "remaining reports noKey for a key past its deadline that was not swept yet" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "cache:y", "v", 0, 2);
    try std.testing.expectEqual(@as(u64, 1), (try remaining(&db, allocator, "cache:y", 1 * secondNanos)).seconds);
    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, "cache:y", 2 * secondNanos));
    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, "cache:y", 9 * secondNanos));
    const unswept = (try db.get(allocator, "cache:y")).?;
    allocator.free(unswept);
}

test "putPersistent over an expired, unswept key stores the new value without a ttl" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "session:2", "old", 0, 1);
    try putPersistent(&db, allocator, "session:2", "new");

    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "session:2"));
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, "session:2", 5 * secondNanos));
    const v = (try getLive(&db, allocator, "session:2", 5 * secondNanos)).?;
    defer allocator.free(v);
    try std.testing.expectEqualStrings("new", v);
    try std.testing.expectEqual(@as(usize, 0), try sweepExpired(&db, allocator, 5 * secondNanos));
}

test "putPersistent drops a live ttl in the same wal batch as the write" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator);
        defer db.close();
        try putWithTtl(&db, allocator, "k", "old", 0, 100);
        try putPersistent(&db, allocator, "k", "new");
        const k = try markerKey(allocator, "k");
        defer allocator.free(k);
        try std.testing.expectEqual(db.latestSeq("k").? + 1, db.latestSeq(k).?);
    }

    var db = try openTemp(&tmp, allocator);
    defer db.close();
    try std.testing.expectEqual(TtlResult.noExpiry, try remaining(&db, allocator, "k", 200 * secondNanos));
    const v = (try getLive(&db, allocator, "k", 200 * secondNanos)).?;
    defer allocator.free(v);
    try std.testing.expectEqualStrings("new", v);
}

test "putPersistent on a key without a ttl writes no marker tombstone" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putPersistent(&db, allocator, "plain", "v");
    const k = try markerKey(allocator, "plain");
    defer allocator.free(k);
    try std.testing.expectEqual(@as(?u64, null), db.latestSeq(k));
}

test "stagePersistentPut clears ttls of batched keys together with the batch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "a", "old", 0, 1);
    try putWithTtl(&db, allocator, "b", "keep", 0, 1);

    var wb = WriteBatch.init(allocator);
    defer wb.deinit();
    try stagePersistentPut(&db, allocator, &wb, "a", "new");
    try stagePersistentPut(&db, allocator, &wb, "c", "fresh");
    try std.testing.expectEqual(@as(usize, 3), wb.count());
    try db.apply(&wb);

    const a = (try getLive(&db, allocator, "a", 5 * secondNanos)).?;
    defer allocator.free(a);
    try std.testing.expectEqualStrings("new", a);
    const c = (try getLive(&db, allocator, "c", 5 * secondNanos)).?;
    defer allocator.free(c);
    try std.testing.expectEqualStrings("fresh", c);
    try std.testing.expectEqual(@as(?[]u8, null), try getLive(&db, allocator, "b", 5 * secondNanos));
}

test "stagePersistentPutInTxn makes the staged value live inside the txn and after commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "t", "old", 0, 1);

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try std.testing.expect(try isExpiredInTxn(&txn, allocator, "t", 5 * secondNanos));
    try stagePersistentPutInTxn(&txn, allocator, "t", "new");
    try std.testing.expect(!try isExpiredInTxn(&txn, allocator, "t", 5 * secondNanos));
    try std.testing.expect(try isExpired(&db, allocator, "t", 5 * secondNanos));
    try txn.commit();

    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "t"));
    const v = (try getLive(&db, allocator, "t", 5 * secondNanos)).?;
    defer allocator.free(v);
    try std.testing.expectEqualStrings("new", v);
}

test "expireLive refuses an expired, unswept key and reaps it instead of reviving it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "dead", "v", 0, 1);
    try std.testing.expect(!try expireLive(&db, allocator, "dead", 5 * secondNanos, 100));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "dead"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "dead"));
    try std.testing.expectEqual(TtlResult.noKey, try remaining(&db, allocator, "dead", 6 * secondNanos));

    try std.testing.expect(!try expireLive(&db, allocator, "missing", 0, 100));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "missing"));

    try db.put("alive", "v");
    try std.testing.expect(try expireLive(&db, allocator, "alive", 0, 100));
    try std.testing.expectEqual(@as(u64, 100), (try remaining(&db, allocator, "alive", 0)).seconds);
}

test "deleteKey drops a live ttl in the same wal batch as the delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator);
        defer db.close();
        try putWithTtl(&db, allocator, "k", "v", 0, 100);
        try deleteKey(&db, allocator, "k");
        const k = try markerKey(allocator, "k");
        defer allocator.free(k);
        try std.testing.expectEqual(db.latestSeq("k").? + 1, db.latestSeq(k).?);
    }

    var db = try openTemp(&tmp, allocator);
    defer db.close();
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "k"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "k"));
}

test "stageDelete adds the marker delete only for keys that have a ttl" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "timed", "v", 0, 100);
    try db.put("plain", "v");

    var wb = WriteBatch.init(allocator);
    defer wb.deinit();
    try stageDelete(&db, allocator, &wb, "timed");
    try stageDelete(&db, allocator, &wb, "plain");
    try std.testing.expectEqual(@as(usize, 3), wb.count());
    try db.apply(&wb);

    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "timed"));
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "plain"));
    const k = try markerKey(allocator, "plain");
    defer allocator.free(k);
    try std.testing.expectEqual(@as(?u64, null), db.latestSeq(k));
}

test "stageDeleteInTxn and expireLiveInTxn only touch the ttl marker on commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try putWithTtl(&db, allocator, "gone", "v", 0, 100);
    try putWithTtl(&db, allocator, "dead", "v", 0, 1);
    try db.put("alive", "v");

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try stageDeleteInTxn(&txn, allocator, "gone");
    try std.testing.expect(try expireLiveInTxn(&txn, allocator, "alive", 0, 50));
    try std.testing.expect(!try expireLiveInTxn(&txn, allocator, "gone", 0, 50));
    try std.testing.expect(!try expireLiveInTxn(&txn, allocator, "dead", 5 * secondNanos, 50));
    try std.testing.expect(!try expireLiveInTxn(&txn, allocator, "missing", 0, 50));

    try std.testing.expectEqual(@as(?i128, 100 * secondNanos), try getExpiresAt(&db, allocator, "gone"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "alive"));
    try std.testing.expectEqual(@as(?i128, 1 * secondNanos), try getExpiresAt(&db, allocator, "dead"));
    try txn.commit();

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "gone"));
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "gone"));
    try std.testing.expectEqual(@as(u64, 50), (try remaining(&db, allocator, "alive", 0)).seconds);
    try std.testing.expectEqual(@as(?i128, null), try getExpiresAt(&db, allocator, "missing"));
}
