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

        var pos: usize = 0;
        var goodEnd: usize = 0;
        var records: usize = 0;
        var counters = Counters{};
        while (pos + 8 <= data.len) {
            const storedCrc = encode.readU32(data, pos);
            const bodyStart = pos + 4;
            const bodyLen = recordBodyLen(data, bodyStart) orelse break;
            if (bodyStart + bodyLen > data.len) break;
            const body = data[bodyStart .. bodyStart + bodyLen];
            if (encode.crc(body) != storedCrc) break;

            try replayRecord(&state, &counters, body);
            records += 1;
            pos = bodyStart + bodyLen;
            goodEnd = pos;
        }

        if (goodEnd != data.len) {
            try file.setEndPos(goodEnd);
            try file.sync();
        }
        try file.seekFromEnd(0);

        return .{
            .set = .{
                .allocator = allocator,
                .dir = dir,
                .file = file,
                .manifestId = id,
                .pendingRecords = records,
                .counters = counters,
            },
            .state = state,
        };
    }

    fn bootstrap(allocator: Allocator, dir: std.fs.Dir) !VersionSet {
        var nameBuf: [64]u8 = undefined;
        const name = try manifestFileName(&nameBuf, 1);
        const file = try dir.createFile(name, .{ .read = true, .truncate = true });
        errdefer file.close();
        try writeCurrent(dir, name);
        return .{
            .allocator = allocator,
            .dir = dir,
            .file = file,
            .manifestId = 1,
            .pendingRecords = 0,
            .counters = .{},
        };
    }

    pub fn close(self: *VersionSet) void {
        self.file.close();
    }

    /// Applies `edit` to `state` and durably appends it to the manifest
    /// log. Rotates (compacts the log to a single snapshot record) once
    /// the number of pending records grows past the live file count.
    pub fn logAndApply(self: *VersionSet, edit: *const VersionEdit, state: *std.AutoHashMap(u64, usize)) !void {
        if (edit.isEmpty()) return;
        try applyEdit(state, edit.added.items, edit.deleted.items);
        if (edit.nextFileId) |v| self.counters.nextFileId = v;
        if (edit.nextSeq) |v| self.counters.nextSeq = v;
        try self.appendRecord(edit);
        self.pendingRecords += 1;

        const liveCount = state.count();
        if (self.pendingRecords > @max(liveCount, 4) * 2) {
            try self.rotate(state);
        }
    }

    fn appendRecord(self: *VersionSet, edit: *const VersionEdit) !void {
        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        try edit.encode_(&body);

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();
        const frameWriter = encode.ByteWriter.init(&frame);
        try frameWriter.putU32(encode.crc(body.items));
        try frameWriter.slice(body.items);

        try self.file.seekFromEnd(0);
        try self.file.writeAll(frame.items);
        try self.file.sync();
    }

    /// Replaces the whole log history with a single snapshot record that
    /// reproduces the current live state, then switches CURRENT to it and
    /// deletes the old log. Bounds manifest size to O(live files) instead
    /// of O(edits ever applied).
    fn rotate(self: *VersionSet, state: *const std.AutoHashMap(u64, usize)) !void {
        var snapshot = std.ArrayList(FileEdit).init(self.allocator);
        defer snapshot.deinit();
        var it = state.iterator();
        while (it.next()) |entry| {
            try snapshot.append(.{ .fileId = entry.key_ptr.*, .level = @intCast(entry.value_ptr.*) });
        }

        const newId = self.manifestId + 1;
        var nameBuf: [64]u8 = undefined;
        const newName = try manifestFileName(&nameBuf, newId);

        const newFile = try self.dir.createFile(newName, .{ .read = true, .truncate = true });
        errdefer newFile.close();

        {
            var body = std.ArrayList(u8).init(self.allocator);
            defer body.deinit();
            const writer = encode.ByteWriter.init(&body);
            try writer.putU32(@intCast(snapshot.items.len));
            for (snapshot.items) |f| {
                try writer.putU64(f.fileId);
                try writer.putU32(f.level);
            }
            try writer.putU32(0);
            // Carry the latest known counters forward into the snapshot so
            // they survive rotation even though the edits that originally
            // set them are being discarded along with the old log.
            try writer.byte(if (self.counters.nextFileId != null) 1 else 0);
            if (self.counters.nextFileId) |v| try writer.putU64(v);
            try writer.byte(if (self.counters.nextSeq != null) 1 else 0);
            if (self.counters.nextSeq) |v| try writer.putU64(v);

            var frame = std.ArrayList(u8).init(self.allocator);
            defer frame.deinit();
            const frameWriter = encode.ByteWriter.init(&frame);
            try frameWriter.putU32(encode.crc(body.items));
            try frameWriter.slice(body.items);
            try newFile.writeAll(frame.items);
            try newFile.sync();
        }

        try writeCurrent(self.dir, newName);

        var oldNameBuf: [64]u8 = undefined;
        const oldName = try manifestFileName(&oldNameBuf, self.manifestId);
        self.file.close();
        self.dir.deleteFile(oldName) catch {};

        self.file = newFile;
        self.manifestId = newId;
        self.pendingRecords = snapshot.items.len;
    }
};

fn writeCurrent(dir: std.fs.Dir, manifestName: []const u8) !void {
    const tmpName = "CURRENT.tmp";
    {
        const file = try dir.createFile(tmpName, .{ .truncate = true });
        defer file.close();
        try file.writeAll(manifestName);
        try file.sync();
    }
    try dir.rename(tmpName, currentName);
}

fn parseManifestId(name: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, name, manifestPrefix)) return null;
    return std.fmt.parseInt(u64, name[manifestPrefix.len..], 10) catch null;
}

fn recordBodyLen(data: []const u8, bodyStart: usize) ?usize {
    if (bodyStart + 4 > data.len) return null;
    const addedCount = encode.readU32(data, bodyStart);
    var p = bodyStart + 4;
    var i: u32 = 0;
    while (i < addedCount) : (i += 1) {
        if (p + 12 > data.len) return null;
        p += 12;
    }
    if (p + 4 > data.len) return null;
    const deletedCount = encode.readU32(data, p);
    p += 4;
    var j: u32 = 0;
    while (j < deletedCount) : (j += 1) {
        if (p + 8 > data.len) return null;
        p += 8;
    }
    // Trailing counter watermarks: one presence flag byte plus an optional
    // u64 each, for nextFileId then nextSeq.
    var k: u32 = 0;
    while (k < 2) : (k += 1) {
        if (p + 1 > data.len) return null;
        const present = data[p];
        p += 1;
        if (present != 0) {
            if (p + 8 > data.len) return null;
            p += 8;
        }
    }
    return p - bodyStart;
}

fn replayRecord(state: *std.AutoHashMap(u64, usize), counters: *Counters, body: []const u8) !void {
    const addedCount = encode.readU32(body, 0);
    var p: usize = 4;
    var i: u32 = 0;
    while (i < addedCount) : (i += 1) {
        const fileId = encode.readU64(body, p);
        const level = encode.readU32(body, p + 8);
        try state.put(fileId, level);
        p += 12;
    }
    const deletedCount = encode.readU32(body, p);
    p += 4;
    var j: u32 = 0;
    while (j < deletedCount) : (j += 1) {
        const fileId = encode.readU64(body, p);
        _ = state.remove(fileId);
        p += 8;
    }
    if (p < body.len) {
        const hasNextFileId = body[p];
        p += 1;
        if (hasNextFileId != 0) {
            counters.nextFileId = encode.readU64(body, p);
            p += 8;
        }
        const hasNextSeq = body[p];
        p += 1;
        if (hasNextSeq != 0) {
            counters.nextSeq = encode.readU64(body, p);
            p += 8;
        }
    }
}

test "fresh directory bootstraps an empty version set" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var opened = try VersionSet.open(allocator, tmp.dir);
    defer opened.state.deinit();
    defer opened.set.close();

    try std.testing.expectEqual(@as(usize, 0), opened.state.count());
    try std.testing.expectEqual(@as(u64, 1), opened.set.manifestId);
    try std.testing.expect(tmp.dir.access(currentName, .{}) != error.FileNotFound);
}

test "logAndApply records adds and survives reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();

        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.addFile(1, 0);
        try edit.addFile(2, 0);
        try opened.set.logAndApply(&edit, &opened.state);

        try std.testing.expectEqual(@as(usize, 2), opened.state.count());
        try std.testing.expectEqual(@as(usize, 0), opened.state.get(1).?);
    }

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(usize, 2), reopened.state.count());
    try std.testing.expectEqual(@as(usize, 0), reopened.state.get(2).?);
}

test "logAndApply replaces a deleted file with new outputs (compaction pattern)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var opened = try VersionSet.open(allocator, tmp.dir);
    defer opened.state.deinit();
    defer opened.set.close();

    var e1 = VersionEdit.init(allocator);
    defer e1.deinit();
    try e1.addFile(1, 0);
    try e1.addFile(2, 0);
    try opened.set.logAndApply(&e1, &opened.state);

    var e2 = VersionEdit.init(allocator);
    defer e2.deinit();
    try e2.deleteFile(1);
    try e2.deleteFile(2);
    try e2.addFile(3, 1);
    try opened.set.logAndApply(&e2, &opened.state);

    try std.testing.expectEqual(@as(usize, 1), opened.state.count());
    try std.testing.expectEqual(@as(usize, 1), opened.state.get(3).?);
    try std.testing.expectEqual(@as(?usize, null), opened.state.get(1));
}

test "manifest rotates once pending records outgrow live file count" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var opened = try VersionSet.open(allocator, tmp.dir);
    defer opened.state.deinit();
    defer opened.set.close();

    // Simulate steady-state leveled compaction: the live file count stays
    // fixed at 1 (each round replaces the previous output), but the edit
    // log keeps growing until it is worth rotating to a fresh snapshot.
    var fileId: u64 = 1;
    {
        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.addFile(fileId, 0);
        try opened.set.logAndApply(&edit, &opened.state);
    }

    var n: usize = 0;
    while (n < 20) : (n += 1) {
        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.deleteFile(fileId);
        fileId += 1;
        try edit.addFile(fileId, 0);
        try opened.set.logAndApply(&edit, &opened.state);
    }

    try std.testing.expect(opened.set.manifestId > 1);
    try std.testing.expectEqual(@as(usize, 1), opened.state.count());
    try std.testing.expectEqual(@as(usize, 0), opened.state.get(fileId).?);

    var nameBuf: [64]u8 = undefined;
    const oldName = try manifestFileName(&nameBuf, 1);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(oldName, .{}));
}

test "reopen after rotation still reflects live state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lastId: u64 = 0;
    var finalFileId: u64 = 1;
    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();

        {
            var edit = VersionEdit.init(allocator);
            defer edit.deinit();
            try edit.addFile(finalFileId, 0);
            try opened.set.logAndApply(&edit, &opened.state);
        }
        var n: usize = 0;
        while (n < 12) : (n += 1) {
            var edit = VersionEdit.init(allocator);
            defer edit.deinit();
            try edit.deleteFile(finalFileId);
            finalFileId += 1;
            try edit.addFile(finalFileId, 0);
            try opened.set.logAndApply(&edit, &opened.state);
        }
        lastId = opened.set.manifestId;
    }

    try std.testing.expect(lastId > 1);

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(usize, 1), reopened.state.count());
    try std.testing.expectEqual(@as(usize, 0), reopened.state.get(finalFileId).?);
    try std.testing.expectEqual(reopened.set.manifestId, lastId);
}

test "torn trailing record is ignored on recovery" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();

        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.addFile(7, 0);
        try opened.set.logAndApply(&edit, &opened.state);

        try opened.set.file.seekFromEnd(0);
        try opened.set.file.writeAll(&[_]u8{ 0xde, 0xad, 0xbe });
        try opened.set.file.sync();
    }

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(usize, 1), reopened.state.count());
    try std.testing.expectEqual(@as(usize, 0), reopened.state.get(7).?);
}

test "logAndApply persists nextFileId and nextSeq counters across reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();
        try std.testing.expectEqual(@as(?u64, null), opened.set.counters.nextFileId);

        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.addFile(1, 0);
        edit.setNextFileId(2);
        edit.setNextSeq(500);
        try opened.set.logAndApply(&edit, &opened.state);

        try std.testing.expectEqual(@as(?u64, 2), opened.set.counters.nextFileId);
        try std.testing.expectEqual(@as(?u64, 500), opened.set.counters.nextSeq);
    }

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(?u64, 2), reopened.set.counters.nextFileId);
    try std.testing.expectEqual(@as(?u64, 500), reopened.set.counters.nextSeq);
}

test "counters survive manifest rotation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lastId: u64 = 0;
    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();

        var fileId: u64 = 1;
        {
            var edit = VersionEdit.init(allocator);
            defer edit.deinit();
            try edit.addFile(fileId, 0);
            edit.setNextFileId(fileId + 1);
            edit.setNextSeq(10);
            try opened.set.logAndApply(&edit, &opened.state);
        }
        // Force rotation the same way the existing rotation test does, each
        // round bumping the seq counter so the final persisted value is
        // distinguishable from an earlier one if rotation dropped it.
        var n: usize = 0;
        while (n < 20) : (n += 1) {
            var edit = VersionEdit.init(allocator);
            defer edit.deinit();
            try edit.deleteFile(fileId);
            fileId += 1;
            try edit.addFile(fileId, 0);
            edit.setNextFileId(fileId + 1);
            edit.setNextSeq(10 + n + 1);
            try opened.set.logAndApply(&edit, &opened.state);
        }
        lastId = opened.set.manifestId;
        try std.testing.expectEqual(@as(?u64, fileId + 1), opened.set.counters.nextFileId);
        try std.testing.expectEqual(@as(?u64, 30), opened.set.counters.nextSeq);
    }
    try std.testing.expect(lastId > 1);

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(?u64, 30), reopened.set.counters.nextSeq);
}

test "missing CURRENT after previous run bootstraps fresh, empty state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var opened = try VersionSet.open(allocator, tmp.dir);
        defer opened.state.deinit();
        defer opened.set.close();
        var edit = VersionEdit.init(allocator);
        defer edit.deinit();
        try edit.addFile(1, 0);
        try opened.set.logAndApply(&edit, &opened.state);
    }

    try tmp.dir.deleteFile(currentName);

    var reopened = try VersionSet.open(allocator, tmp.dir);
    defer reopened.state.deinit();
    defer reopened.set.close();
    try std.testing.expectEqual(@as(usize, 0), reopened.state.count());
}
