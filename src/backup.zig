const std = @import("std");
const db_mod = @import("db.zig");
const encode = @import("encode.zig");

const Allocator = std.mem.Allocator;
const Db = db_mod.Db;
const Snapshot = db_mod.Snapshot;
const WriteBatch = db_mod.WriteBatch;

// Portable logical backup format for cobalt. Dumps a consistent, point-in-time
// view of the live keyspace (as returned by Snapshot.scan - tombstones already
// resolved) into a self-describing file that can be replayed into any Db.
//
// Layout:
//   header: magic("CBLB" 4B) | version(u32) | seq(u64)
//   entry*: keyLen(u32) | valueLen(u32) | key | value | entryCrc(u32)
//           entryCrc = crc32(keyLen le bytes || valueLen le bytes || key || value)
//   footer: magic("CBLE" 4B) | entryCount(u64) | fileCrc(u32)
//           fileCrc = crc32 of every byte written before the footer magic
//           (header + all entries), rolling-accumulated while writing.
//
// Restore validates the whole file (magics, per-entry crc, trailing count,
// whole-file crc) before touching the target Db, so a corrupt or truncated
// backup never applies a partial write.

const headerMagic = "CBLB";
const footerMagic = "CBLE";
const formatVersion: u32 = 1;

pub const BackupError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    Corrupt,
    CountMismatch,
};

pub const BackupInfo = struct {
    seq: u64,
    entryCount: u64,
};

const RollingCrc = struct {
    hasher: std.hash.Crc32,

    fn init() RollingCrc {
        return .{ .hasher = std.hash.Crc32.init() };
    }

    fn feed(self: *RollingCrc, bytes: []const u8) void {
        self.hasher.update(bytes);
    }

    fn value(self: RollingCrc) u32 {
        var copy = self.hasher;
        return copy.final();
    }
};

fn writeAllCrc(writer: anytype, roll: *RollingCrc, bytes: []const u8) !void {
    try writer.writeAll(bytes);
    roll.feed(bytes);
}

fn putU32Crc(writer: anytype, roll: *RollingCrc, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, encode.endian);
    try writeAllCrc(writer, roll, &b);
}

fn putU64Crc(writer: anytype, roll: *RollingCrc, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, encode.endian);
    try writeAllCrc(writer, roll, &b);
}

/// Writes a full, consistent backup of `snapshot` to `path` (created/truncated).
/// Returns the number of entries written.
pub fn dumpToFile(allocator: Allocator, snapshot: Snapshot, path: []const u8) !u64 {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    var bufferedWriter = std.io.bufferedWriter(file.writer());
    const writer = bufferedWriter.writer();

    var roll = RollingCrc.init();
    try writeAllCrc(writer, &roll, headerMagic);
    try putU32Crc(writer, &roll, formatVersion);
    try putU64Crc(writer, &roll, snapshot.seq);

    var iter = try snapshot.scan(allocator, null, null);
    defer iter.deinit();

    var count: u64 = 0;
    var entryScratch = std.ArrayList(u8).init(allocator);
    defer entryScratch.deinit();

    while (try iter.next()) |entry| {
        entryScratch.clearRetainingCapacity();
        var lenBuf: [8]u8 = undefined;
        std.mem.writeInt(u32, lenBuf[0..4], @intCast(entry.key.len), encode.endian);
        std.mem.writeInt(u32, lenBuf[4..8], @intCast(entry.value.len), encode.endian);
        try entryScratch.appendSlice(&lenBuf);
        try entryScratch.appendSlice(entry.key);
        try entryScratch.appendSlice(entry.value);
        const entryCrc = std.hash.Crc32.hash(entryScratch.items);

        try writeAllCrc(writer, &roll, entryScratch.items);
        try putU32Crc(writer, &roll, entryCrc);
        count += 1;
    }

    try writer.writeAll(footerMagic);
    var countBuf: [8]u8 = undefined;
    std.mem.writeInt(u64, &countBuf, count, encode.endian);
    try writer.writeAll(&countBuf);

    const fileCrc = roll.value();
    var crcBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &crcBuf, fileCrc, encode.endian);
    try writer.writeAll(&crcBuf);

    try bufferedWriter.flush();
    return count;
}

const ParsedEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// One pass over a fully-loaded backup buffer: validates structure end to end
/// (magics, per-entry crc, declared count, whole-file crc) without allocating
/// per-entry copies. Returns the entries slice (positions into `data`) plus
/// backup metadata, or a BackupError describing the first problem found.
const ParsedBackup = struct {
    seq: u64,
    entries: []ParsedEntry,
};

fn parse(allocator: Allocator, data: []const u8) !ParsedBackup {
    if (data.len < headerMagic.len + 4 + 8) return BackupError.Truncated;
    if (!std.mem.eql(u8, data[0..4], headerMagic)) return BackupError.BadMagic;

    const version = encode.readU32(data, 4);
    if (version != formatVersion) return BackupError.UnsupportedVersion;
    const seq = encode.readU64(data, 8);

    var pos: usize = 16;
    var entries = std.ArrayList(ParsedEntry).init(allocator);
    errdefer entries.deinit();

    while (true) {
        if (pos + footerMagic.len <= data.len and std.mem.eql(u8, data[pos .. pos + 4], footerMagic)) {
            break;
        }
        if (pos + 8 > data.len) return BackupError.Truncated;
        const keyLen = encode.readU32(data, pos);
        const valueLen = encode.readU32(data, pos + 4);
        const entryStart = pos;
        const keyStart = pos + 8;
        const valueStart = keyStart + keyLen;
        const valueEnd = valueStart + valueLen;
        if (valueEnd + 4 > data.len) return BackupError.Truncated;

        const entryBytes = data[entryStart..valueEnd];
        const storedCrc = encode.readU32(data, valueEnd);
        const actualCrc = std.hash.Crc32.hash(entryBytes);
        if (storedCrc != actualCrc) return BackupError.Corrupt;

        try entries.append(.{ .key = data[keyStart..valueStart], .value = data[valueStart..valueEnd] });
        pos = valueEnd + 4;
    }

    if (pos + 4 + 8 + 4 > data.len) return BackupError.Truncated;
    const declaredCount = encode.readU64(data, pos + 4);
    if (declaredCount != entries.items.len) return BackupError.CountMismatch;

    const storedFileCrc = encode.readU32(data, pos + 4 + 8);
    const actualFileCrc = std.hash.Crc32.hash(data[0..pos]);
    if (storedFileCrc != actualFileCrc) return BackupError.Corrupt;

    return .{ .seq = seq, .entries = try entries.toOwnedSlice() };
}

/// Reads and structurally validates a backup file without applying it,
/// returning its metadata (seq, entry count). Useful to verify a backup
/// before trusting it for disaster recovery.
pub fn inspectFile(allocator: Allocator, path: []const u8) !BackupInfo {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 34);
    defer allocator.free(data);
    const parsed = try parse(allocator, data);
    defer allocator.free(parsed.entries);
    return .{ .seq = parsed.seq, .entryCount = parsed.entries.len };
}

/// Restores every entry from the backup at `path` into `db`, in chunks of
/// `chunkSize` applied atomically via WriteBatch. The whole file is validated
/// (magics, per-entry and whole-file crc, declared count) before any chunk is
/// applied, so a corrupt backup fails without mutating the target database.
/// Existing keys in `db` outside the backup are left untouched; keys present
/// in both are overwritten with the backup's value.
pub fn restoreFromFile(allocator: Allocator, db: *Db, path: []const u8, chunkSize: usize) !BackupInfo {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 34);
    defer allocator.free(data);

    const parsed = try parse(allocator, data);
    defer allocator.free(parsed.entries);

    var i: usize = 0;
    while (i < parsed.entries.len) {
        const end = @min(i + chunkSize, parsed.entries.len);
        var batch = WriteBatch.init(allocator);
        defer batch.deinit();
        for (parsed.entries[i..end]) |entry| {
            try batch.put(entry.key, entry.value);
        }
        try db.apply(&batch);
        i = end;
    }

    return .{ .seq = parsed.seq, .entryCount = parsed.entries.len };
}

test "backup round trip: dump then restore into a fresh db reproduces every key" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-1";
    const dstDir = "test-backup-dst-1";
    const backupPath = "test-backup-1.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();

    var keyBuf: [16]u8 = undefined;
    var valBuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "k{d:0>6}", .{i});
        const value = try std.fmt.bufPrint(&valBuf, "v{d:0>6}", .{i});
        try src.put(key, value);
    }
    // overwrite one, delete another: backup must reflect resolved state.
    try src.put("k000005", "updated");
    try src.delete("k000010");

    const snap = try src.snapshot();
    const count = try dumpToFile(allocator, snap, backupPath);
    try std.testing.expectEqual(@as(u64, 199), count);

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    const info = try restoreFromFile(allocator, &dst, backupPath, 32);
    try std.testing.expectEqual(@as(u64, 199), info.entryCount);

    i = 0;
    while (i < 200) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "k{d:0>6}", .{i});
        const got = try dst.get(allocator, key);
        if (i == 10) {
            try std.testing.expect(got == null);
            continue;
        }
        defer allocator.free(got.?);
        if (i == 5) {
            try std.testing.expectEqualStrings("updated", got.?);
        } else {
            const expected = try std.fmt.bufPrint(&valBuf, "v{d:0>6}", .{i});
            try std.testing.expectEqualStrings(expected, got.?);
        }
    }
}

test "backup of empty db round trips to zero entries" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-empty";
    const dstDir = "test-backup-dst-empty";
    const backupPath = "test-backup-empty.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    const snap = try src.snapshot();
    const count = try dumpToFile(allocator, snap, backupPath);
    try std.testing.expectEqual(@as(u64, 0), count);

    const info = try inspectFile(allocator, backupPath);
    try std.testing.expectEqual(@as(u64, 0), info.entryCount);

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    _ = try restoreFromFile(allocator, &dst, backupPath, 32);
    var iter = try dst.scan(allocator, null, null);
    defer iter.deinit();
    try std.testing.expect((try iter.next()) == null);
}

test "backup is point-in-time: writes after snapshot are excluded" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-pit";
    const backupPath = "test-backup-pit.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    try src.put("before", "1");
    const snap = try src.snapshot();
    try src.put("after", "2");

    const count = try dumpToFile(allocator, snap, backupPath);
    try std.testing.expectEqual(@as(u64, 1), count);

    const info = try inspectFile(allocator, backupPath);
    try std.testing.expectEqual(snap.seq, info.seq);
}

test "restore into db with pre-existing disjoint keys merges without touching them" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-merge";
    const dstDir = "test-backup-dst-merge";
    const backupPath = "test-backup-merge.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    try src.put("from-backup", "yes");
    const count = try dumpToFile(allocator, try src.snapshot(), backupPath);
    try std.testing.expectEqual(@as(u64, 1), count);

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    try dst.put("already-here", "kept");

    _ = try restoreFromFile(allocator, &dst, backupPath, 32);

    const kept = try dst.get(allocator, "already-here");
    defer allocator.free(kept.?);
    try std.testing.expectEqualStrings("kept", kept.?);

    const restored = try dst.get(allocator, "from-backup");
    defer allocator.free(restored.?);
    try std.testing.expectEqualStrings("yes", restored.?);
}

test "restore chunking applies every entry across multiple write batches" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-chunks";
    const dstDir = "test-backup-dst-chunks";
    const backupPath = "test-backup-chunks.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    var keyBuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 97) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "c{d:0>6}", .{i});
        try src.put(key, "x");
    }
    _ = try dumpToFile(allocator, try src.snapshot(), backupPath);

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    const info = try restoreFromFile(allocator, &dst, backupPath, 10);
    try std.testing.expectEqual(@as(u64, 97), info.entryCount);

    var found: usize = 0;
    var iter = try dst.scan(allocator, null, null);
    defer iter.deinit();
    while (try iter.next()) |_| found += 1;
    try std.testing.expectEqual(@as(usize, 97), found);
}

test "corrupted entry payload is rejected before any restore write happens" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-corrupt";
    const dstDir = "test-backup-dst-corrupt";
    const backupPath = "test-backup-corrupt.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    try src.put("intact", "value-one");
    try src.put("victim", "value-two");
    _ = try dumpToFile(allocator, try src.snapshot(), backupPath);

    {
        const file = try std.fs.cwd().openFile(backupPath, .{ .mode = .read_write });
        defer file.close();
        // flip a byte squarely inside the entry region (well past the 16 byte header).
        try file.seekTo(24);
        var byte: [1]u8 = undefined;
        _ = try file.read(&byte);
        try file.seekTo(24);
        try file.writeAll(&.{byte[0] ^ 0xFF});
    }

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    const result = restoreFromFile(allocator, &dst, backupPath, 32);
    try std.testing.expectError(BackupError.Corrupt, result);

    // nothing from the corrupt backup should have been applied: validation
    // happens over the whole in-memory buffer before the first WriteBatch.
    var iter = try dst.scan(allocator, null, null);
    defer iter.deinit();
    try std.testing.expect((try iter.next()) == null);
}

test "truncated file is rejected as Truncated, not a crash" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-trunc";
    const dstDir = "test-backup-dst-trunc";
    const backupPath = "test-backup-trunc.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(dstDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    try src.put("a", "b");
    _ = try dumpToFile(allocator, try src.snapshot(), backupPath);

    {
        const data = try std.fs.cwd().readFileAlloc(allocator, backupPath, 1 << 20);
        defer allocator.free(data);
        const truncated = data[0 .. data.len - 5];
        const file = try std.fs.cwd().createFile(backupPath, .{ .truncate = true });
        defer file.close();
        try file.writeAll(truncated);
    }

    var dst = try Db.open(allocator, dstDir, .{});
    defer dst.close();
    const result = restoreFromFile(allocator, &dst, backupPath, 32);
    try std.testing.expectError(BackupError.Truncated, result);
}

test "bad magic header is rejected without reading the rest of the file" {
    const allocator = std.testing.allocator;
    const backupPath = "test-backup-badmagic.cblb";
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    const file = try std.fs.cwd().createFile(backupPath, .{ .truncate = true });
    {
        defer file.close();
        try file.writeAll("XXXX" ++ [_]u8{0} ** 12);
    }

    const result = inspectFile(allocator, backupPath);
    try std.testing.expectError(BackupError.BadMagic, result);
}

test "unsupported version is rejected" {
    const allocator = std.testing.allocator;
    const backupPath = "test-backup-badversion.cblb";
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    const file = try std.fs.cwd().createFile(backupPath, .{ .truncate = true });
    {
        defer file.close();
        var buf: [16]u8 = undefined;
        @memcpy(buf[0..4], headerMagic);
        std.mem.writeInt(u32, buf[4..8], 99, encode.endian);
        std.mem.writeInt(u64, buf[8..16], 0, encode.endian);
        try file.writeAll(&buf);
    }

    const result = inspectFile(allocator, backupPath);
    try std.testing.expectError(BackupError.UnsupportedVersion, result);
}

test "declared entry count mismatch is caught even if per-entry crcs are valid" {
    const allocator = std.testing.allocator;
    const srcDir = "test-backup-src-countmismatch";
    const backupPath = "test-backup-countmismatch.cblb";
    std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteTree(srcDir) catch {};
    defer std.fs.cwd().deleteFile(backupPath) catch {};

    var src = try Db.open(allocator, srcDir, .{});
    defer src.close();
    try src.put("a", "1");
    try src.put("b", "2");
    _ = try dumpToFile(allocator, try src.snapshot(), backupPath);

    {
        const data = try std.fs.cwd().readFileAlloc(allocator, backupPath, 1 << 20);
        defer allocator.free(data);
        // footer is the last 4(magic)+8(count)+4(crc)=16 bytes; corrupt count only,
        // which necessarily also breaks the whole-file crc, but count is checked first.
        const countPos = data.len - 12;
        var mutated = try allocator.dupe(u8, data);
        defer allocator.free(mutated);
        std.mem.writeInt(u64, mutated[countPos..][0..8], 999, encode.endian);
        const file = try std.fs.cwd().createFile(backupPath, .{ .truncate = true });
        defer file.close();
        try file.writeAll(mutated);
    }

    const result = inspectFile(allocator, backupPath);
    try std.testing.expectError(BackupError.CountMismatch, result);
}
