const std = @import("std");
const encode = @import("encode.zig");

const Allocator = std.mem.Allocator;

// VersionSet/VersionEdit: append-only log of incremental changes to the
// live sstable set (fileId -> level), replacing a full-state rewrite on
// every flush/compact. Modeled on LevelDB's VersionSet: a CURRENT file
// names the active manifest log, the log holds a sequence of edit
// records, and recovery replays them into a map. The log is periodically
// rotated (a single snapshot record replaces the whole history) so it
// never grows without bound.

pub const VersionError = error{
    Corrupt,
    Truncated,
};

pub const FileEdit = struct {
    fileId: u64,
    level: u32,
};

pub const VersionEdit = struct {
    allocator: Allocator,
    added: std.ArrayList(FileEdit),
    deleted: std.ArrayList(u64),
    /// Optional counter watermarks, stamped by the caller alongside a file
    /// add/delete: the exact `Db.nextFileId`/`Db.nextSeq` value in effect
    /// right after this edit was built. Recorded so recovery can recover
    /// these counters from the manifest instead of relying solely on
    /// scanning which sstable files currently happen to be on disk - a scan
    /// alone regresses whenever a compaction fully garbage-collects a run of
    /// tombstones into zero output files (see runMerge: no output file means
    /// no fresh fileId is minted, and if the GC'd inputs held the highest
    /// seq/fileId ever used, a post-restart scan would compute a lower
    /// floor than what was really already consumed, risking seq reuse
    /// across a restart).
    nextFileId: ?u64 = null,
    nextSeq: ?u64 = null,

    pub fn init(allocator: Allocator) VersionEdit {
        return .{
            .allocator = allocator,
            .added = std.ArrayList(FileEdit).init(allocator),
            .deleted = std.ArrayList(u64).init(allocator),
        };
    }

    pub fn deinit(self: *VersionEdit) void {
        self.added.deinit();
        self.deleted.deinit();
    }

    pub fn addFile(self: *VersionEdit, fileId: u64, level: usize) !void {
        try self.added.append(.{ .fileId = fileId, .level = @intCast(level) });
    }

    pub fn deleteFile(self: *VersionEdit, fileId: u64) !void {
        try self.deleted.append(fileId);
    }

    pub fn setNextFileId(self: *VersionEdit, nextFileId: u64) void {
        self.nextFileId = nextFileId;
    }

    pub fn setNextSeq(self: *VersionEdit, nextSeq: u64) void {
        self.nextSeq = nextSeq;
    }

    pub fn isEmpty(self: *const VersionEdit) bool {
        return self.added.items.len == 0 and self.deleted.items.len == 0;
    }

    fn encode_(self: *const VersionEdit, out: *std.ArrayList(u8)) !void {
        const writer = encode.ByteWriter.init(out);
        try writer.putU32(@intCast(self.added.items.len));
        for (self.added.items) |f| {
            try writer.putU64(f.fileId);
            try writer.putU32(f.level);
        }
        try writer.putU32(@intCast(self.deleted.items.len));
        for (self.deleted.items) |id| try writer.putU64(id);
        try writer.byte(if (self.nextFileId != null) 1 else 0);
        if (self.nextFileId) |v| try writer.putU64(v);
        try writer.byte(if (self.nextSeq != null) 1 else 0);
        if (self.nextSeq) |v| try writer.putU64(v);
    }
};

/// Applies an edit's added/deleted entries onto a live fileId->level map.
pub fn applyEdit(state: *std.AutoHashMap(u64, usize), added: []const FileEdit, deleted: []const u64) !void {
    for (deleted) |id| _ = state.remove(id);
    for (added) |f| try state.put(f.fileId, f.level);
}

/// Recovered counter watermarks, threaded out of `VersionSet.open`'s replay
/// so `Db.open` can fold them into its own directory-scan-based recovery
/// (taking the max of both sources - see `VersionEdit.nextFileId`/`nextSeq`
/// doc comment for why the scan alone is not always sufficient).
pub const Counters = struct {
    nextFileId: ?u64 = null,
    nextSeq: ?u64 = null,
};

const currentName = "CURRENT";
const manifestPrefix = "MANIFEST-";

fn manifestFileName(buf: []u8, id: u64) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}{d:0>10}", .{ manifestPrefix, id });
}

pub const VersionSet = struct {
    allocator: Allocator,
    dir: std.fs.Dir,
    file: std.fs.File,
    manifestId: u64,
    /// Number of edit records appended to the current log since the last
    /// rotation (used as the rotation heuristic).
    pendingRecords: usize,
    /// Latest counter watermarks seen across every replayed (or since
    /// applied) edit - see `VersionEdit.nextFileId`/`nextSeq`. Carried
    /// forward into `rotate`'s snapshot record so they survive log rotation
    /// even though the individual edits that set them get discarded.
    counters: Counters,

    /// Opens (or bootstraps) the version set, replaying the active
    /// manifest log into a fresh fileId->level map that the caller owns.
    pub fn open(allocator: Allocator, dir: std.fs.Dir) !struct { set: VersionSet, state: std.AutoHashMap(u64, usize) } {
        var state = std.AutoHashMap(u64, usize).init(allocator);
        errdefer state.deinit();

        const currentContents = dir.readFileAlloc(allocator, currentName, 256) catch |err| switch (err) {
            error.FileNotFound => {
                const set = try bootstrap(allocator, dir);
                return .{ .set = set, .state = state };
            },
            else => return err,
        };
        defer allocator.free(currentContents);

        const trimmed = std.mem.trim(u8, currentContents, " \t\r\n");
        const id = parseManifestId(trimmed) orelse return VersionError.Corrupt;

        const file = dir.openFile(trimmed, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => {
                const set = try bootstrap(allocator, dir);
                return .{ .set = set, .state = state };
            },
            else => return err,
        };
        errdefer file.close();

        const data = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(data);

