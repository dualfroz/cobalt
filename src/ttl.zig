const std = @import("std");
const dbmod = @import("db.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;

/// Per-key expiry markers layered over the flat KV keyspace, sharing one Db
/// with tables/collections/auth (row.zig/index.zig use 'R'/'I'/'J'/'M',
/// collections.zig uses 'X', auth.zig uses 'A'; every key here starts with
/// 'T' so none of the namespaces collide):
///   "T" <key>  -> raw i128 (expiresAtNanos, big-endian)
/// The marker lives in the SAME Db as the key it guards (same WAL, same
/// flush/compaction lifecycle, same crash-durability boundary) but expiry
/// is enforced lazily: nothing here runs a background clock itself. A
/// caller must present nowNanos, either on every read (expireIfDue/getLive)
/// or through an explicit sweep (sweepExpired) - matching how session.zig's
/// SessionStore already treats "now" as an input rather than ambient state
/// (and uses the same i128 type std.time.nanoTimestamp() returns), so both
/// are trivially testable without sleeping in unit tests.
pub const nsTag: u8 = 'T';

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

/// Sets (or replaces) an absolute expiry deadline on `key`. Does not verify
/// `key` currently exists in the main keyspace - callers that need
/// existence-checked semantics (the CLI `expire` command) check db.get
/// first, same as Redis distinguishes EXPIRE from the looser PEXPIREAT.
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

/// Redis TTL(2) semantics for the CLI: `.noKey` mirrors return -2 (the key
/// itself is absent), `.noExpiry` mirrors -1 (it exists but carries no
/// expiry), `.seconds` is the whole seconds left, floored at 0 so a marker
/// that is due but not yet reaped never reports a negative remainder.
pub const TtlResult = union(enum) {
    noKey,
    noExpiry,
    seconds: u64,
};

pub fn remaining(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !TtlResult {
    const existing = try db.get(allocator, key) orelse return .noKey;
    allocator.free(existing);
    const expiresAt = try getExpiresAt(db, allocator, key) orelse return .noExpiry;
    if (nowNanos >= expiresAt) return .{ .seconds = 0 };
    return .{ .seconds = @intCast(@divFloor(expiresAt - nowNanos, secondNanos)) };
}

/// Lazily enforces expiry on read: if `key` carries a due marker, deletes
/// both the marker and the underlying key (a real delete through the normal
/// WAL/tombstone path, not just "pretend it's gone") and reports true.
pub fn expireIfDue(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !bool {
    const expiresAt = try getExpiresAt(db, allocator, key) orelse return false;
    if (!isDue(expiresAt, nowNanos)) return false;
    try db.delete(key);
    try clearExpire(db, allocator, key);
    return true;
}

/// db.get with lazy expiry applied first - the read-path counterpart of
/// putWithTtl, so a caller never observes a logically-expired value just
/// because no sweep has run yet.
pub fn getLive(db: *Db, allocator: Allocator, key: []const u8, nowNanos: i128) !?[]u8 {
    _ = try expireIfDue(db, allocator, key, nowNanos);
    return db.get(allocator, key);
}

pub fn putWithTtl(db: *Db, allocator: Allocator, key: []const u8, value: []const u8, nowNanos: i128, seconds: u64) !void {
    try db.put(key, value);
    try setExpireSeconds(db, allocator, key, nowNanos, seconds);
}

/// Active sweep: scans every marker under the 'T' namespace and reaps every
/// one that is due, deleting both the underlying key and its marker.
/// Returns the number reaped. Two passes on purpose - a RangeIterator's
/// merge heap holds live cursor positions directly into the memtable being
/// walked (only the Entry it hands back through next() is arena-copied),
/// so issuing db.delete mid-scan would mutate the very structure the
/// iterator's cursors are threaded through. Collect the due keys first,
/// mutate only after the iterator (and its cursors) are closed.
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
    // A plain db.get after the lazy expiry proves the delete was real, not
    // getLive-only bookkeeping - the tombstone is now the source of truth.
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

    // Idempotent: a second sweep at the same instant finds nothing left.
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
    // Documents the PEXPIREAT-like looseness of setExpireAt directly (the
    // CLI layer is what adds the Redis EXPIRE existence check on top).
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
