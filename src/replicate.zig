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

