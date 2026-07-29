const std = @import("std");
const encode = @import("encode.zig");
const dbmod = @import("db.zig");
const walmod = @import("wal.zig");

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Db = dbmod.Db;
const WriteBatch = dbmod.WriteBatch;

// Physical WAL-tailing replication: reads the primary's on-disk wal.log file
// directly (same binary frame format as wal.zig: [crc32 u32][seq u64][kind u8]
// [keyLen u32][valLen u32][key][value], or a batch frame marked by kind byte
// 0xB0 holding a count then per-op [kind][seq][keyLen][valLen][key][value]),
// independently of wal.zig's private replay-into-memtable path, and applies
// newly appended, crc-verified, complete frames onto a separate replica Db.
//
// This mirrors real physical log shipping (e.g. Postgres WAL streaming): it
// only sees what is still in the WAL file. Db.flush() truncates the primary's
// wal.log to empty once its memtable is durable in an SSTable (see db.zig
// flush()), so a tailer that has fallen behind a flush can no longer recover
// the truncated records from the WAL alone - poll() detects that condition
// (current file size smaller than the tailer's already-consumed offset) and
// fails loudly with error.WalTruncatedAheadOfTailer instead of silently
// resuming from zero and dropping data. The caller is expected to recover via
// fullResync(), which re-bases the replica from a live Snapshot (paying the
// same "logical snapshot, not a physical replica of on-disk levels/history"
// cost already documented for backup.zig) and restarts tailing from the
// (now known-empty) WAL, exactly mirroring a real base-backup-plus-streaming
// recovery: bulk-copy current state, then resume incremental log shipping
// from the offset the bulk copy was taken at.

const headerLen = 8 + 1 + 4 + 4;
const batchMarker: u8 = 0xB0;
const batchHeader = 8 + 1 + 4;
const opHeader = 1 + 8 + 4 + 4;
const walName = "wal.log";
const maxTailRead: usize = 256 * 1024 * 1024;

pub const ReplicateError = error{ WalTruncatedAheadOfTailer, WalGenerationChanged };

/// Reads the WAL generation stamp (see wal.zig's currentGeneration) for a
/// primary directory given only its path, for callers (WalTailer.poll,
/// Replicator construction from a persisted offset) that do not hold a live
/// *Db handle to the primary and so cannot reuse its already-open Dir.
fn readGenerationByPath(primaryDirPath: []const u8) !u64 {
    var dir = try std.fs.cwd().openDir(primaryDirPath, .{});
    defer dir.close();
    return walmod.currentGeneration(dir);
}

pub const OwnedRecord = struct {
    kind: Kind,
    seq: u64,
    key: []u8,
    value: []u8,

    pub fn deinit(self: OwnedRecord, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

fn freeAll(allocator: Allocator, records: []OwnedRecord) void {
    for (records) |record| record.deinit(allocator);
    allocator.free(records);
}

/// Tails a single WAL file from a byte offset, decoding whole, crc-verified
/// frames appended since the last poll. Never advances past an incomplete or
/// corrupt tail frame (mirrors wal.zig's own torn-write tolerance), so a
/// concurrent writer mid-append is simply not observed until its frame is
/// fully flushed and synced.
pub const WalTailer = struct {
    allocator: Allocator,
    file: std.fs.File,
    offset: u64,
    primaryDir: []u8,
    generation: u64,

    pub fn open(allocator: Allocator, primaryDirPath: []const u8, startOffset: u64, startGeneration: u64) !WalTailer {
        const path = try std.fs.path.join(allocator, &.{ primaryDirPath, walName });
        defer allocator.free(path);
        const file = try std.fs.cwd().openFile(path, .{});
        errdefer file.close();
        const dirCopy = try allocator.dupe(u8, primaryDirPath);
        return .{ .allocator = allocator, .file = file, .offset = startOffset, .primaryDir = dirCopy, .generation = startGeneration };
    }

    pub fn deinit(self: *WalTailer) void {
        self.file.close();
        self.allocator.free(self.primaryDir);
    }

    /// Returns newly observed records in append order. Caller owns the
    /// returned slice and each record's key/value (free via freeAll or by
    /// calling deinit() on each record then freeing the slice). Checks the
    /// primary's WAL generation stamp before anything else: a changed
    /// generation means the primary truncated (flushed) since the last poll,
    /// which the caller must recover from via fullResync() regardless of how
    /// the raw byte offsets happen to compare (see wal.zig's bumpGeneration
    /// doc comment for why the byte-size comparison alone is not enough).
    pub fn poll(self: *WalTailer) ![]OwnedRecord {
        const nowGeneration = try readGenerationByPath(self.primaryDir);
        if (nowGeneration != self.generation) return ReplicateError.WalGenerationChanged;

        const endPos = try self.file.getEndPos();
        if (endPos < self.offset) return ReplicateError.WalTruncatedAheadOfTailer;
        if (endPos == self.offset) return &.{};

        try self.file.seekTo(self.offset);
        const data = try self.file.readToEndAlloc(self.allocator, maxTailRead);
        defer self.allocator.free(data);

        var out = std.ArrayList(OwnedRecord).init(self.allocator);
        errdefer {
            for (out.items) |record| record.deinit(self.allocator);
            out.deinit();
        }

        var pos: usize = 0;
        while (pos + 4 + batchHeader <= data.len) {
            const storedCrc = encode.readU32(data, pos);
            const bodyStart = pos + 4;
            const bodyLen = frameBodyLen(data, bodyStart) orelse break;
            if (bodyStart + bodyLen > data.len) break;
            const body = data[bodyStart .. bodyStart + bodyLen];
            if (encode.crc(body) != storedCrc) break;

            try decodeFrame(self.allocator, body, &out);

            pos = bodyStart + bodyLen;
        }

        self.offset += pos;
        return try out.toOwnedSlice();
    }
};

fn frameBodyLen(data: []const u8, bodyStart: usize) ?usize {
    const marker = data[bodyStart + 8];
    if (marker == batchMarker) {
        if (bodyStart + batchHeader > data.len) return null;
        const opCount = encode.readU32(data, bodyStart + 9);
        var p = bodyStart + batchHeader;
        var n: u32 = 0;
        while (n < opCount) : (n += 1) {
            if (p + opHeader > data.len) return null;
            const keyLen = encode.readU32(data, p + 9);
            const valLen = encode.readU32(data, p + 13);
            const end = p + opHeader + keyLen + valLen;
            if (end > data.len) return null;
            p = end;
        }
        return p - bodyStart;
    }
    if (bodyStart + headerLen > data.len) return null;
    const keyLen = encode.readU32(data, bodyStart + 9);
    const valLen = encode.readU32(data, bodyStart + 13);
    return headerLen + keyLen + valLen;
}

fn decodeFrame(allocator: Allocator, body: []const u8, out: *std.ArrayList(OwnedRecord)) !void {
    if (body[8] == batchMarker) {
        const opCount = encode.readU32(body, 9);
        var p: usize = batchHeader;
        var n: u32 = 0;
        while (n < opCount) : (n += 1) {
            const kind: Kind = @enumFromInt(body[p]);
            const seq = encode.readU64(body, p + 1);
            const keyLen = encode.readU32(body, p + 9);
            const valLen = encode.readU32(body, p + 13);
            const keyStart = p + opHeader;
            const key = try allocator.dupe(u8, body[keyStart .. keyStart + keyLen]);
            errdefer allocator.free(key);
            const value = try allocator.dupe(u8, body[keyStart + keyLen .. keyStart + keyLen + valLen]);
            try out.append(.{ .kind = kind, .seq = seq, .key = key, .value = value });
            p = keyStart + keyLen + valLen;
        }
        return;
    }
    const seq = encode.readU64(body, 0);
    const kind: Kind = @enumFromInt(body[8]);
    const keyLen = encode.readU32(body, 9);
    const valLen = encode.readU32(body, 13);
    const key = try allocator.dupe(u8, body[headerLen .. headerLen + keyLen]);
    errdefer allocator.free(key);
    const value = try allocator.dupe(u8, body[headerLen + keyLen .. headerLen + keyLen + valLen]);
    try out.append(.{ .kind = kind, .seq = seq, .key = key, .value = value });
}

/// Ties a WalTailer to a target Db, applying newly tailed records as a single
/// WriteBatch per syncOnce(). Replicated writes get FRESH sequence numbers on
/// the target (Db.apply always assigns from its own nextSeq), so the replica
/// mirrors primary key/value state but not primary's original seq history -
/// same documented tradeoff as backup.zig's restore.
pub const Replicator = struct {
    allocator: Allocator,
    tailer: WalTailer,
    target: *Db,

    pub fn init(allocator: Allocator, primaryDirPath: []const u8, target: *Db) !Replicator {
        const gen = try readGenerationByPath(primaryDirPath);
        return initFromOffset(allocator, primaryDirPath, target, 0, gen);
    }

    pub fn initFromOffset(allocator: Allocator, primaryDirPath: []const u8, target: *Db, startOffset: u64, startGeneration: u64) !Replicator {
        const tailer = try WalTailer.open(allocator, primaryDirPath, startOffset, startGeneration);
        return .{ .allocator = allocator, .tailer = tailer, .target = target };
    }

    pub fn deinit(self: *Replicator) void {
        self.tailer.deinit();
    }

    pub fn offset(self: *const Replicator) u64 {
        return self.tailer.offset;
    }

    pub fn generation(self: *const Replicator) u64 {
        return self.tailer.generation;
    }

    /// Applies every record newly visible in the primary's WAL since the last
    /// call. Returns the number of records applied (0 if nothing new).
    /// Propagates error.WalTruncatedAheadOfTailer if the primary flushed
    /// (truncating its WAL) before this replicator consumed everything - the
    /// caller must recover via fullResync().
    pub fn syncOnce(self: *Replicator) !usize {
        const records = try self.tailer.poll();
        defer freeAll(self.allocator, records);
        if (records.len == 0) return 0;

        var batch = WriteBatch.init(self.allocator);
        defer batch.deinit();
        for (records) |record| {
            switch (record.kind) {
                .value => try batch.put(record.key, record.value),
                .tombstone => try batch.delete(record.key),
            }
        }
        try self.target.apply(&batch);
        return records.len;
    }

    /// Recovers from a fallen-behind tailer (or bootstraps a brand new
    /// replica) by copying every live key/value from a fresh primary
    /// Snapshot into the target in chunks, then re-bases the tailer at the
    /// primary's current WAL offset. Snapshot() flushes the primary first
    /// (see db.zig), so immediately after this call the primary's wal.log is
    /// known to be empty - offset 0 is therefore always the correct restart
    /// point. Requires no concurrent writer on the primary during the call
    /// (same single-writer assumption as the rest of this project - Db has
    /// no internal cross-thread synchronization).
    pub fn fullResync(self: *Replicator, primary: *Db, chunkSize: usize) !usize {
        const snap = try primary.snapshot();
        var iter = try snap.scan(self.allocator, null, null);
        defer iter.deinit();

        var batch = WriteBatch.init(self.allocator);
        defer batch.deinit();
        var applied: usize = 0;
        var staged: usize = 0;
        while (try iter.next()) |entry| {
            try batch.put(entry.key, entry.value);
            staged += 1;
            applied += 1;
            if (staged >= chunkSize) {
                try self.target.apply(&batch);
                batch.deinit();
                batch = WriteBatch.init(self.allocator);
                staged = 0;
            }
        }
        if (staged > 0) try self.target.apply(&batch);

        self.tailer.offset = 0;
        // snapshot() above flushes the primary if it had unflushed writes,
        // which bumps its WAL generation (see wal.zig) - re-baseline here so
        // the very next poll() does not immediately see a "changed"
        // generation caused by this resync itself.
        self.tailer.generation = try walmod.currentGeneration(primary.dir);
        return applied;
    }
};

const stateMagic = "CRPS";
const stateFormatVersion: u32 = 2;

/// A tail offset paired with the WAL generation it was captured against.
/// Persisting both (not just the offset) is what lets a brand-new process -
/// which never saw the in-memory generation check in WalTailer.poll() - tell
/// whether the primary truncated its WAL while this process was not running
/// at all, the same blind spot the in-memory check closes for a live one.
pub const PersistedState = struct {
    offset: u64,
    generation: u64,
};
const stateFileName = "replicate.state";
const stateTmpName = "replicate.state.tmp";
const maxStateRead: usize = 64 * 1024;

pub const StateError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    Corrupt,
    PrimaryMismatch,
};

/// Atomically persists a replicator's tail offset next to the replica's own
/// data (in replicaDirPath), so a later, brand-new `cobalt replicate --once`
/// process - which has no in-memory Replicator to resume from - can pick up
/// tailing exactly where the previous invocation left off instead of paying
/// for a full snapshot fullResync() every single time it starts. Also stores
/// primaryDirPath so a mismatched later call (pointed at a different primary
/// by mistake) is caught by loadOffset() rather than silently tailing the
/// wrong WAL from a stale offset. Written via tmp-file + rename (same pattern
/// as version.zig's writeCurrent), so a crash mid-write can never leave a
/// half-written state file where a good one used to be.
pub fn saveState(allocator: Allocator, replicaDirPath: []const u8, primaryDirPath: []const u8, offsetValue: u64, generationValue: u64) !void {
    var dir = try std.fs.cwd().openDir(replicaDirPath, .{});
    defer dir.close();

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();
    const writer = encode.ByteWriter.init(&body);
    try writer.slice(stateMagic);
    try writer.putU32(stateFormatVersion);
    try writer.putU64(offsetValue);
    try writer.putU64(generationValue);
    try writer.putU32(@intCast(primaryDirPath.len));
    try writer.slice(primaryDirPath);
    try writer.putU32(encode.crc(body.items));

    {
        const file = try dir.createFile(stateTmpName, .{ .truncate = true });
        defer file.close();
        try file.writeAll(body.items);
        try file.sync();
    }
    try dir.rename(stateTmpName, stateFileName);
}

/// Loads a previously persisted tail offset for a replica directory. Returns
/// null (not an error) when no state file has ever been written there yet -
/// callers treat that as "fresh replica, bootstrap via fullResync()" exactly
/// like before this existed. Returns StateError.PrimaryMismatch if the file
/// was written while tailing a different primary directory, so a replica
/// can never silently resume against the wrong primary from a stale offset.
pub fn loadOffset(allocator: Allocator, replicaDirPath: []const u8, primaryDirPath: []const u8) !?PersistedState {
    var dir = try std.fs.cwd().openDir(replicaDirPath, .{});
    defer dir.close();

    const data = dir.readFileAlloc(allocator, stateFileName, maxStateRead) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(data);

    const fixedLen = 4 + 4 + 8 + 8 + 4;
    if (data.len < fixedLen + 4) return StateError.Truncated;
    if (!std.mem.eql(u8, data[0..4], stateMagic)) return StateError.BadMagic;
    const version = encode.readU32(data, 4);
    if (version != stateFormatVersion) return StateError.UnsupportedVersion;
    const offsetValue = encode.readU64(data, 8);
    const generationValue = encode.readU64(data, 16);
    const pathLen = encode.readU32(data, 24);
    const pathStart = fixedLen;
    if (data.len != pathStart + pathLen + 4) return StateError.Truncated;
    const storedPath = data[pathStart .. pathStart + pathLen];
    const storedCrc = encode.readU32(data, pathStart + pathLen);
    if (encode.crc(data[0 .. pathStart + pathLen]) != storedCrc) return StateError.Corrupt;
    if (!std.mem.eql(u8, storedPath, primaryDirPath)) return StateError.PrimaryMismatch;

    return .{ .offset = offsetValue, .generation = generationValue };
}

test "replicator mirrors puts and deletes from a live primary" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    try primary.put("alpha", "one");
    try primary.put("bravo", "two");

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();

    const applied = try rep.syncOnce();
    try std.testing.expectEqual(@as(usize, 2), applied);

    const a = try replica.get(allocator, "alpha");
    defer if (a) |v| allocator.free(v);
    try std.testing.expectEqualStrings("one", a.?);
    const b = try replica.get(allocator, "bravo");
    defer if (b) |v| allocator.free(v);
    try std.testing.expectEqualStrings("two", b.?);

    try primary.delete("alpha");
    const applied2 = try rep.syncOnce();
    try std.testing.expectEqual(@as(usize, 1), applied2);

    const a2 = try replica.get(allocator, "alpha");
    try std.testing.expectEqual(@as(?[]u8, null), a2);
}

test "replicator syncOnce is idempotent between polls" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();

    try primary.put("k1", "v1");
    try std.testing.expectEqual(@as(usize, 1), try rep.syncOnce());
    try std.testing.expectEqual(@as(usize, 0), try rep.syncOnce());

    try primary.put("k2", "v2");
    try std.testing.expectEqual(@as(usize, 1), try rep.syncOnce());
    try std.testing.expectEqual(@as(usize, 0), try rep.syncOnce());

    var count: usize = 0;
    var iter = try replica.scan(allocator, null, null);
    defer iter.deinit();
    while (try iter.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "replicator applies batched writes from Db.apply as one poll" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    var writeBatch = WriteBatch.init(allocator);
    defer writeBatch.deinit();
    try writeBatch.put("x", "1");
    try writeBatch.put("y", "2");
    try writeBatch.delete("z");
    try primary.apply(&writeBatch);

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();
    const applied = try rep.syncOnce();
    try std.testing.expectEqual(@as(usize, 3), applied);

    const x = try replica.get(allocator, "x");
    defer if (x) |v| allocator.free(v);
    try std.testing.expectEqualStrings("1", x.?);
    const z = try replica.get(allocator, "z");
    try std.testing.expectEqual(@as(?[]u8, null), z);
}

test "replicator poll does not consume a torn tail frame" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();

    try primary.put("good", "data");
    try std.testing.expectEqual(@as(usize, 1), try rep.syncOnce());

    // Simulate a writer mid-append: raw bytes appended after the good frame
    // that never form a complete, crc-verified frame.
    try primary.wal.file.seekFromEnd(0);
    try primary.wal.file.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC });
    try primary.wal.sync();

    try std.testing.expectEqual(@as(usize, 0), try rep.syncOnce());

    // The writer "finishes": a real, complete frame lands after the torn
    // bytes are naturally never completed (matches wal.zig's own tolerance -
    // torn tail bytes are simply never a valid prefix of a later frame, so
    // this models a stalled partial write, not a resumed one).
    var count: usize = 0;
    var iter = try replica.scan(allocator, null, null);
    defer iter.deinit();
    while (try iter.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "replicator surfaces truncation when it falls behind a primary flush" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    try primary.put("k", "v");

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();
    // Advance the tailer's offset without applying, then flush the primary
    // (truncates wal.log to 0) so the tailer's remembered offset now points
    // past the end of the (now-empty) file.
    const staleRecords = try rep.tailer.poll();
    freeAll(allocator, staleRecords);
    try primary.flush();

    // The primary's flush() bumped its WAL generation, so the generation
    // check in poll() fires before the (now also true, but weaker) raw
    // byte-offset comparison would have.
    try std.testing.expectError(ReplicateError.WalGenerationChanged, rep.syncOnce());

    const recovered = try rep.fullResync(&primary, 500);
    try std.testing.expectEqual(@as(usize, 1), recovered);
    try std.testing.expectEqual(@as(u64, 0), rep.offset());

    const v = try replica.get(allocator, "k");
    defer if (v) |val| allocator.free(val);
    try std.testing.expectEqualStrings("v", v.?);

    // New writes after the resync are picked up normally through the
    // freshly-restarted tail at offset 0.
    try primary.put("k2", "v2");
    try std.testing.expectEqual(@as(usize, 1), try rep.syncOnce());
    const v2 = try replica.get(allocator, "k2");
    defer if (v2) |val| allocator.free(val);
    try std.testing.expectEqualStrings("v2", v2.?);
}

test "replicator fullResync bootstraps a brand new replica" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var keyBuf: [16]u8 = undefined;
        var valBuf: [16]u8 = undefined;
        const key = try std.fmt.bufPrint(&keyBuf, "key{d}", .{i});
        const val = try std.fmt.bufPrint(&valBuf, "val{d}", .{i});
        try primary.put(key, val);
    }

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();
    const applied = try rep.fullResync(&primary, 7);
    try std.testing.expectEqual(@as(usize, 50), applied);

    var count: usize = 0;
    var iter = try replica.scan(allocator, null, null);
    defer iter.deinit();
    while (try iter.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 50), count);

    // Fresh writes after the bootstrap keep tailing correctly from offset 0.
    try primary.put("late", "arrival");
    try std.testing.expectEqual(@as(usize, 1), try rep.syncOnce());
    const v = try replica.get(allocator, "late");
    defer if (v) |val| allocator.free(val);
    try std.testing.expectEqualStrings("arrival", v.?);
}

test "walTailer rejects a nonexistent primary directory" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.FileNotFound, WalTailer.open(allocator, "/nonexistent", 0, 0));
}

test "loadOffset returns null for a replica directory that never saved state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    const loaded = try loadOffset(allocator, base, "/some/primary");
    try std.testing.expectEqual(@as(?PersistedState, null), loaded);
}

test "saveState then loadOffset round-trips the offset, generation, and primary path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary", 4096, 7);
    const loaded = try loadOffset(allocator, base, "/data/primary");
    try std.testing.expectEqual(@as(u64, 4096), loaded.?.offset);
    try std.testing.expectEqual(@as(u64, 7), loaded.?.generation);
}

test "saveState overwrites a prior state file with the newest offset and generation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary", 10, 0);
    try saveState(allocator, base, "/data/primary", 20, 1);
    try saveState(allocator, base, "/data/primary", 30, 2);
    const loaded = try loadOffset(allocator, base, "/data/primary");
    try std.testing.expectEqual(@as(u64, 30), loaded.?.offset);
    try std.testing.expectEqual(@as(u64, 2), loaded.?.generation);
}

test "loadOffset rejects a state file saved for a different primary" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary-a", 123, 0);
    try std.testing.expectError(StateError.PrimaryMismatch, loadOffset(allocator, base, "/data/primary-b"));
}

test "loadOffset rejects a corrupted state file without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary", 55, 3);

    {
        const file = try tmp.dir.openFile(stateFileName, .{ .mode = .read_write });
        defer file.close();
        try file.seekTo(9);
        try file.writeAll(&[_]u8{0xFF});
    }

    try std.testing.expectError(StateError.Corrupt, loadOffset(allocator, base, "/data/primary"));
}

test "loadOffset rejects a truncated state file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary", 55, 3);

    {
        const file = try tmp.dir.openFile(stateFileName, .{ .mode = .read_write });
        defer file.close();
        try file.setEndPos(6);
    }

    try std.testing.expectError(StateError.Truncated, loadOffset(allocator, base, "/data/primary"));
}

test "loadOffset rejects a bad magic header" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    try saveState(allocator, base, "/data/primary", 55, 3);

    {
        const file = try tmp.dir.openFile(stateFileName, .{ .mode = .read_write });
        defer file.close();
        try file.seekTo(0);
        try file.writeAll("XXXX");
    }

    try std.testing.expectError(StateError.BadMagic, loadOffset(allocator, base, "/data/primary"));
}

test "loadOffset rejects a state file written in the pre-generation v1 format" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();
    const writer = encode.ByteWriter.init(&body);
    try writer.slice("CRPS");
    try writer.putU32(1);
    try writer.putU64(999);
    const primaryPath = "/data/primary";
    try writer.putU32(@intCast(primaryPath.len));
    try writer.slice(primaryPath);
    try writer.putU32(encode.crc(body.items));

    const file = try tmp.dir.createFile(stateFileName, .{ .truncate = true });
    defer file.close();
    try file.writeAll(body.items);

    try std.testing.expectError(StateError.UnsupportedVersion, loadOffset(allocator, base, "/data/primary"));
}

test "saveState and loadOffset round-trip through a real replicate directory end to end" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const primaryDir = try std.fs.path.join(allocator, &.{ base, "primary" });
    defer allocator.free(primaryDir);
    const replicaDir = try std.fs.path.join(allocator, &.{ base, "replica" });
    defer allocator.free(replicaDir);

    var primary = try Db.open(allocator, primaryDir, .{});
    defer primary.close();
    var replica = try Db.open(allocator, replicaDir, .{});
    defer replica.close();

    try primary.put("a", "1");
    try primary.put("b", "2");

    var rep = try Replicator.init(allocator, primaryDir, &replica);
    defer rep.deinit();
    _ = try rep.syncOnce();
    try saveState(allocator, replicaDir, primaryDir, rep.offset(), rep.generation());
    const savedOffset = rep.offset();
    try std.testing.expect(savedOffset > 0);

    // A brand new process would reopen the replica Db and reconstruct a
    // Replicator from the persisted offset instead of offset 0.
    var replica2 = try Db.open(allocator, replicaDir, .{});
    defer replica2.close();
    const resumed = (try loadOffset(allocator, replicaDir, primaryDir)).?;
    try std.testing.expectEqual(savedOffset, resumed.offset);
    try std.testing.expectEqual(rep.generation(), resumed.generation);

    var rep2 = try Replicator.initFromOffset(allocator, primaryDir, &replica2, resumed.offset, resumed.generation);
    defer rep2.deinit();
    try primary.put("c", "3");
    const applied = try rep2.syncOnce();
    try std.testing.expectEqual(@as(usize, 1), applied);

    const c = try replica2.get(allocator, "c");
    defer if (c) |v| allocator.free(v);
    try std.testing.expectEqualStrings("3", c.?);
    // The earlier keys were never re-applied through rep2 (it resumed past
    // them), yet they are still visible because replica2 is the same
    // on-disk replica Db that rep already wrote them into.
    const a = try replica2.get(allocator, "a");
    defer if (a) |v| allocator.free(v);
    try std.testing.expectEqualStrings("1", a.?);
}
