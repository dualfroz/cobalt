const std = @import("std");
const encode = @import("encode.zig");
const Memtable = @import("memtable.zig").Memtable;

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Record = encode.Record;

const headerLen = 8 + 1 + 4 + 4;
const batchMarker: u8 = 0xB0;
const batchHeader = 8 + 1 + 4;
const opHeader = 1 + 8 + 4 + 4;

pub const Wal = struct {
    allocator: Allocator,
    file: std.fs.File,

    pub fn open(allocator: Allocator, dir: std.fs.Dir, name: []const u8) !Wal {
        const file = try dir.createFile(name, .{ .read = true, .truncate = false });
        return .{ .allocator = allocator, .file = file };
    }

    pub fn close(self: *Wal) void {
        self.file.close();
    }

    pub fn append(self: *Wal, kind: Kind, seq: u64, key: []const u8, value: []const u8) !void {
        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        const writer = encode.ByteWriter.init(&body);
        try writer.putU64(seq);
        try writer.byte(@intFromEnum(kind));
        try writer.putU32(@intCast(key.len));
        try writer.putU32(@intCast(value.len));
        try writer.slice(key);
        try writer.slice(value);

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();
        const frameWriter = encode.ByteWriter.init(&frame);
        try frameWriter.putU32(encode.crc(body.items));
        try frameWriter.slice(body.items);

        try self.file.seekFromEnd(0);
        try self.file.writeAll(frame.items);
    }

    pub fn appendBatch(self: *Wal, records: []const Record) !void {
        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        const writer = encode.ByteWriter.init(&body);
        try writer.putU64(0);
        try writer.byte(batchMarker);
        try writer.putU32(@intCast(records.len));
        for (records) |record| {
            try writer.byte(@intFromEnum(record.kind));
            try writer.putU64(record.seq);
            try writer.putU32(@intCast(record.key.len));
            try writer.putU32(@intCast(record.value.len));
            try writer.slice(record.key);
            try writer.slice(record.value);
        }

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();
        const frameWriter = encode.ByteWriter.init(&frame);
        try frameWriter.putU32(encode.crc(body.items));
        try frameWriter.slice(body.items);

        try self.file.seekFromEnd(0);
        try self.file.writeAll(frame.items);
    }

    pub fn sync(self: *Wal) !void {
        try self.file.sync();
    }

    pub fn reset(self: *Wal) !void {
        try self.file.setEndPos(0);
        try self.file.seekTo(0);
        try self.file.sync();
    }

    pub fn replay(self: *Wal, memtable: *Memtable) !u64 {
        try self.file.seekTo(0);
        const data = try self.file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
        defer self.allocator.free(data);

        var pos: usize = 0;
        var goodEnd: usize = 0;
        var maxSeq: u64 = 0;
        while (pos + 4 + batchHeader <= data.len) {
            const storedCrc = encode.readU32(data, pos);
            const bodyStart = pos + 4;
            const bodyLen = frameBodyLen(data, bodyStart) orelse break;
            if (bodyStart + bodyLen > data.len) break;
            const body = data[bodyStart .. bodyStart + bodyLen];
            if (encode.crc(body) != storedCrc) break;

            const frameMax = try applyFrame(memtable, body);
            if (frameMax > maxSeq) maxSeq = frameMax;

            pos = bodyStart + bodyLen;
            goodEnd = pos;
        }

        if (goodEnd != data.len) {
            try self.file.setEndPos(goodEnd);
        }
        try self.file.seekFromEnd(0);
        return maxSeq;
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

fn applyFrame(memtable: *Memtable, body: []const u8) !u64 {
    var maxSeq: u64 = 0;
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
            const key = body[keyStart .. keyStart + keyLen];
            const value = body[keyStart + keyLen .. keyStart + keyLen + valLen];
            try memtable.upsert(kind, seq, key, value);
            if (seq > maxSeq) maxSeq = seq;
            p = keyStart + keyLen + valLen;
        }
        return maxSeq;
    }
    const seq = encode.readU64(body, 0);
    const kind: Kind = @enumFromInt(body[8]);
    const keyLen = encode.readU32(body, 9);
    const valLen = encode.readU32(body, 13);
    const key = body[headerLen .. headerLen + keyLen];
    const value = body[headerLen + keyLen .. headerLen + keyLen + valLen];
    try memtable.upsert(kind, seq, key, value);
    return seq;
}

const genFileName = "wal.gen";
const genTmpName = "wal.gen.tmp";
const genMagic = "CGEN";
const genRecordLen = 4 + 8 + 4;

pub const GenerationError = error{ BadMagic, Truncated, Corrupt };

/// Reads the WAL's current generation counter from a db directory, next to
/// wal.log itself. Returns 0 (not an error) if the generation file has never
/// been written - a db that has never truncated its WAL is, by definition,
/// still on generation 0, the same value any tailer starts at.
pub fn currentGeneration(dir: std.fs.Dir) !u64 {
    var buf: [genRecordLen]u8 = undefined;
    const file = dir.openFile(genFileName, .{}) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer file.close();
    const n = try file.readAll(&buf);
    if (n != genRecordLen) return GenerationError.Truncated;
    if (!std.mem.eql(u8, buf[0..4], genMagic)) return GenerationError.BadMagic;
    const gen = encode.readU64(&buf, 4);
    const storedCrc = encode.readU32(&buf, 12);
    if (encode.crc(buf[0..12]) != storedCrc) return GenerationError.Corrupt;
    return gen;
}

/// Bumps and atomically persists the WAL generation counter. Called once per
/// truncation (see reset(), invoked from Db.flush()) so a tailer that reads
/// this stamp can tell "same WAL contents since I last looked" from "primary
/// truncated, and may have already regrown past whatever byte offset I had"
/// from an explicit marker instead of a byte-size heuristic - a pure
/// endPos-vs-offset comparison is fooled exactly when the post-truncation
/// file reaches or exceeds the old offset before the next poll.
pub fn bumpGeneration(dir: std.fs.Dir) !u64 {
    const gen = (try currentGeneration(dir)) + 1;
    var buf: [genRecordLen]u8 = undefined;
    @memcpy(buf[0..4], genMagic);
    std.mem.writeInt(u64, buf[4..12], gen, encode.endian);
    std.mem.writeInt(u32, buf[12..16], encode.crc(buf[0..12]), encode.endian);
    {
        const file = try dir.createFile(genTmpName, .{ .truncate = true });
        defer file.close();
        try file.writeAll(&buf);
        try file.sync();
    }
    try dir.rename(genTmpName, genFileName);
    return gen;
}

test "currentGeneration is 0 before any bump" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(@as(u64, 0), try currentGeneration(tmp.dir));
}

test "bumpGeneration increments and persists across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectEqual(@as(u64, 1), try bumpGeneration(tmp.dir));
    try std.testing.expectEqual(@as(u64, 2), try bumpGeneration(tmp.dir));
    try std.testing.expectEqual(@as(u64, 3), try bumpGeneration(tmp.dir));
    try std.testing.expectEqual(@as(u64, 3), try currentGeneration(tmp.dir));
}

test "currentGeneration rejects a corrupted generation file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try bumpGeneration(tmp.dir);

    const file = try tmp.dir.openFile(genFileName, .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(4);
    try file.writeAll(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

    try std.testing.expectError(GenerationError.Corrupt, currentGeneration(tmp.dir));
}

test "Wal.reset does not itself touch the generation counter" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try Wal.open(allocator, tmp.dir, "wal.log");
    defer wal.close();
    try wal.append(.value, 1, "k", "v");
    try wal.reset();

    // reset() only truncates the WAL file itself - generation bumping is a
    // separate, explicit call made by Db.flush() at the same call site, kept
    // out of Wal so tests exercising reset() in isolation (elsewhere in this
    // file) do not need a directory-wide side effect they never asked for.
    try std.testing.expectEqual(@as(u64, 0), try currentGeneration(tmp.dir));
}

test "wal append and replay" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try Wal.open(allocator, tmp.dir, "wal.log");
        defer wal.close();
        try wal.append(.value, 1, "alpha", "one");
        try wal.append(.value, 2, "bravo", "two");
        try wal.append(.tombstone, 3, "alpha", "");
        try wal.sync();
    }

    var wal = try Wal.open(allocator, tmp.dir, "wal.log");
    defer wal.close();
    var mt = try Memtable.init(allocator);
    defer mt.deinit();
    const maxSeq = try wal.replay(&mt);

    try std.testing.expectEqual(@as(u64, 3), maxSeq);
    try std.testing.expectEqual(Kind.tombstone, mt.find("alpha").?.kind);
    try std.testing.expectEqualStrings("two", mt.find("bravo").?.value);
}

test "wal batch replay applies all ops" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try Wal.open(allocator, tmp.dir, "wal.log");
        defer wal.close();
        const ops = [_]Record{
            .{ .key = "one", .value = "1", .seq = 10, .kind = .value },
            .{ .key = "two", .value = "2", .seq = 11, .kind = .value },
            .{ .key = "three", .value = "", .seq = 12, .kind = .tombstone },
        };
        try wal.appendBatch(&ops);
        try wal.sync();
    }

    var wal = try Wal.open(allocator, tmp.dir, "wal.log");
    defer wal.close();
    var mt = try Memtable.init(allocator);
    defer mt.deinit();
    const maxSeq = try wal.replay(&mt);

    try std.testing.expectEqual(@as(u64, 12), maxSeq);
    try std.testing.expectEqualStrings("1", mt.find("one").?.value);
    try std.testing.expectEqualStrings("2", mt.find("two").?.value);
    try std.testing.expectEqual(Kind.tombstone, mt.find("three").?.kind);
    try std.testing.expectEqual(@as(usize, 3), mt.count);
}

test "wal torn batch applies nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try Wal.open(allocator, tmp.dir, "wal.log");
        defer wal.close();
        try wal.append(.value, 1, "survivor", "kept");
        try wal.sync();
        const ops = [_]Record{
            .{ .key = "gone-a", .value = "x", .seq = 2, .kind = .value },
            .{ .key = "gone-b", .value = "y", .seq = 3, .kind = .value },
        };
        try wal.appendBatch(&ops);
        try wal.sync();
        try wal.file.setEndPos((try wal.file.getEndPos()) - 1);
        try wal.sync();
    }

    var wal = try Wal.open(allocator, tmp.dir, "wal.log");
    defer wal.close();
    var mt = try Memtable.init(allocator);
    defer mt.deinit();
    _ = try wal.replay(&mt);

    try std.testing.expectEqualStrings("kept", mt.find("survivor").?.value);
    try std.testing.expectEqual(@as(?encode.Record, null), mt.find("gone-a"));
    try std.testing.expectEqual(@as(?encode.Record, null), mt.find("gone-b"));
    try std.testing.expectEqual(@as(usize, 1), mt.count);
}

test "wal ignores torn tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try Wal.open(allocator, tmp.dir, "wal.log");
        defer wal.close();
        try wal.append(.value, 1, "good", "data");
        try wal.sync();
        try wal.file.seekFromEnd(0);
        try wal.file.writeAll(&[_]u8{ 0xff, 0xff, 0xff });
        try wal.sync();
    }

    var wal = try Wal.open(allocator, tmp.dir, "wal.log");
    defer wal.close();
    var mt = try Memtable.init(allocator);
    defer mt.deinit();
    _ = try wal.replay(&mt);
    try std.testing.expectEqualStrings("data", mt.find("good").?.value);
    try std.testing.expectEqual(@as(usize, 1), mt.count);
}
