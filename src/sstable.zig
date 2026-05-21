const std = @import("std");
const encode = @import("encode.zig");
const Bloom = @import("bloom.zig").Bloom;
const cache = @import("cache.zig");
const compress = @import("compress.zig");

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Record = encode.Record;
const BlockCache = cache.BlockCache;
const BlockKey = cache.BlockKey;
const Codec = compress.Codec;
const readU32 = encode.readU32;
const readU64 = encode.readU64;

pub const OwnedHit = struct {
    seq: u64,
    kind: Kind,
    value: []u8,
};

fn order(a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, a, b);
}

const magic: u32 = 0xC0BA1701;
const version: u32 = 1;
const footerLen = 4 + 4 + 8 + 4 + 8 + 4 + 8 + 8;
const recordHeader = 1 + 8 + 4 + 4;
const defaultBlockTarget = 4096;

pub const Builder = struct {
    allocator: Allocator,
    file: std.fs.File,
    offset: u64,
    blockBuf: std.ArrayList(u8),
    blockFirstKey: std.ArrayList(u8),
    indexBuf: std.ArrayList(u8),
    numEntries: u64,
    logicalBytes: u64,
    maxSeq: u64,
    bloom: Bloom,
    blockTarget: usize,

    pub fn init(allocator: Allocator, dir: std.fs.Dir, name: []const u8, expectedKeys: usize) !Builder {
        const file = try dir.createFile(name, .{ .truncate = true });
        return .{
            .allocator = allocator,
            .file = file,
            .offset = 0,
            .blockBuf = std.ArrayList(u8).init(allocator),
            .blockFirstKey = std.ArrayList(u8).init(allocator),
            .indexBuf = std.ArrayList(u8).init(allocator),
            .numEntries = 0,
            .logicalBytes = 0,
            .maxSeq = 0,
            .bloom = try Bloom.init(allocator, expectedKeys, 0.01),
            .blockTarget = defaultBlockTarget,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.blockBuf.deinit();
        self.blockFirstKey.deinit();
        self.indexBuf.deinit();
        self.bloom.deinit();
        self.file.close();
    }

    pub fn add(self: *Builder, record: Record) !void {
        if (self.blockBuf.items.len == 0) {
            self.blockFirstKey.clearRetainingCapacity();
            try self.blockFirstKey.appendSlice(record.key);
        }
        const writer = encode.ByteWriter.init(&self.blockBuf);
        try writer.byte(@intFromEnum(record.kind));
        try writer.putU64(record.seq);
        try writer.putU32(@intCast(record.key.len));
        try writer.putU32(@intCast(record.value.len));
        try writer.slice(record.key);
        try writer.slice(record.value);

        self.bloom.add(record.key);
        self.numEntries += 1;
        self.logicalBytes += recordHeader + record.key.len + record.value.len;
        if (record.seq > self.maxSeq) self.maxSeq = record.seq;

        if (self.blockBuf.items.len >= self.blockTarget) try self.flushBlock();
    }

    fn flushBlock(self: *Builder) !void {
        if (self.blockBuf.items.len == 0) return;
        const originalLen: u32 = @intCast(self.blockBuf.items.len);

        const encoded = try compress.encode(self.allocator, self.blockBuf.items);
        defer encoded.deinit(self.allocator);

        var physical = std.ArrayList(u8).init(self.allocator);
        defer physical.deinit();
        const physWriter = encode.ByteWriter.init(&physical);
        try physWriter.byte(@intFromEnum(encoded.codec));
        try physWriter.putU32(originalLen);
        try physWriter.slice(encoded.bytes);

        const physLen: u32 = @intCast(physical.items.len);
        try self.file.writeAll(physical.items);
        var crcBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &crcBuf, encode.crc(physical.items), encode.endian);
        try self.file.writeAll(&crcBuf);

        const indexWriter = encode.ByteWriter.init(&self.indexBuf);
        try indexWriter.putU64(self.offset);
        try indexWriter.putU32(physLen);
        try indexWriter.putU32(@intCast(self.blockFirstKey.items.len));
        try indexWriter.slice(self.blockFirstKey.items);

        self.offset += physLen + 4;
        self.blockBuf.clearRetainingCapacity();
    }

    pub fn finish(self: *Builder) !void {
        try self.flushBlock();

        var bloomBuf = std.ArrayList(u8).init(self.allocator);
        defer bloomBuf.deinit();
        try self.bloom.serialize(encode.ByteWriter.init(&bloomBuf));
        const bloomOffset = self.offset;
        const bloomLen: u32 = @intCast(bloomBuf.items.len);
        try self.writeBlock(bloomBuf.items);

        const indexOffset = self.offset;
        const indexLen: u32 = @intCast(self.indexBuf.items.len);
        try self.writeBlock(self.indexBuf.items);

        var footer = std.ArrayList(u8).init(self.allocator);
        defer footer.deinit();
        const fw = encode.ByteWriter.init(&footer);
        try fw.putU32(magic);
        try fw.putU32(version);
        try fw.putU64(indexOffset);
        try fw.putU32(indexLen);
        try fw.putU64(bloomOffset);
        try fw.putU32(bloomLen);
        try fw.putU64(self.numEntries);
        try fw.putU64(self.maxSeq);
        try self.file.writeAll(footer.items);
        try self.file.sync();
    }

    fn writeBlock(self: *Builder, bytes: []const u8) !void {
        try self.file.writeAll(bytes);
        var crcBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &crcBuf, encode.crc(bytes), encode.endian);
        try self.file.writeAll(&crcBuf);
        self.offset += bytes.len + 4;
    }
};

const IndexEntry = struct {
    offset: u64,
    blockLen: u32,
    firstKey: []const u8,
};

const blockPrefix = 1 + 4;

pub const Reader = struct {
    allocator: Allocator,
    buffer: []u8,
    dataBuf: []u8,
    index: []IndexEntry,
    bloom: Bloom,
    fileId: u64,
    maxSeq: u64,
    numEntries: u64,
    physicalBytes: u64,
    level: usize,
    minKey: []const u8,
    maxKey: []const u8,

    pub fn open(allocator: Allocator, dir: std.fs.Dir, name: []const u8, fileId: u64) !Reader {
        const file = try dir.openFile(name, .{});
        defer file.close();
        const buffer = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        errdefer allocator.free(buffer);
        const physicalBytes = buffer.len;

        if (buffer.len < footerLen) return error.CorruptSstable;
        const footerStart = buffer.len - footerLen;
        if (readU32(buffer, footerStart) != magic) return error.CorruptSstable;
        const indexOffset = readU64(buffer, footerStart + 8);
        const indexLen = readU32(buffer, footerStart + 16);
        const bloomOffset = readU64(buffer, footerStart + 20);
        const bloomLen = readU32(buffer, footerStart + 28);
        const numEntries = readU64(buffer, footerStart + 32);
        const maxSeq = readU64(buffer, footerStart + 40);

        const bloomData = try verifiedBlock(buffer, bloomOffset, bloomLen);
        var bloom = try Bloom.deserialize(allocator, bloomData);
        errdefer bloom.deinit();

        const indexData = try verifiedBlock(buffer, indexOffset, indexLen);

        var decoded = std.ArrayList(u8).init(allocator);
        errdefer decoded.deinit();
        var entries = std.ArrayList(IndexEntry).init(allocator);
        errdefer entries.deinit();

        var pos: usize = 0;
        while (pos < indexData.len) {
            const physOffset = readU64(indexData, pos);
            const physLen = readU32(indexData, pos + 8);
            const firstKeyLen = readU32(indexData, pos + 12);
            const keyStart = pos + 16;
            const firstKey = indexData[keyStart .. keyStart + firstKeyLen];

            const physical = try verifiedBlock(buffer, physOffset, physLen);
            if (physical.len < blockPrefix) return error.CorruptSstable;
            const codec: Codec = @enumFromInt(physical[0]);
            const originalLen = readU32(physical, 1);
            const payload = physical[blockPrefix..];
            const plainBlock = try compress.decode(allocator, codec, payload, originalLen);
            defer allocator.free(plainBlock);

            const decOffset = decoded.items.len;
            try decoded.appendSlice(plainBlock);

            try entries.append(.{ .offset = decOffset, .blockLen = @intCast(plainBlock.len), .firstKey = firstKey });
            pos = keyStart + firstKeyLen;
        }

        const dataBuf = try decoded.toOwnedSlice();
        errdefer allocator.free(dataBuf);
        const indexSlice = try entries.toOwnedSlice();
        errdefer allocator.free(indexSlice);

        var minKey: []const u8 = buffer[0..0];
        var maxKey: []const u8 = buffer[0..0];
        if (indexSlice.len > 0) {
            minKey = indexSlice[0].firstKey;
            const lastEntry = indexSlice[indexSlice.len - 1];
            const lastBlock = dataBuf[lastEntry.offset .. lastEntry.offset + lastEntry.blockLen];
            var blockPos: usize = 0;
            while (blockPos < lastBlock.len) {
                const rec = decodeRecord(lastBlock, blockPos);
                maxKey = rec.record.key;
                blockPos = rec.next;
            }
        }

        return .{
            .allocator = allocator,
            .buffer = buffer,
            .dataBuf = dataBuf,
            .index = indexSlice,
            .bloom = bloom,
            .fileId = fileId,
            .maxSeq = maxSeq,
            .numEntries = numEntries,
            .physicalBytes = physicalBytes,
            .level = 0,
            .minKey = minKey,
            .maxKey = maxKey,
        };
    }

    pub fn deinit(self: *Reader) void {
        self.allocator.free(self.index);
        self.bloom.deinit();
        self.allocator.free(self.dataBuf);
        self.allocator.free(self.buffer);
    }

    pub fn mayContain(self: *const Reader, key: []const u8) bool {
        return self.bloom.mayContain(key);
    }

    pub fn find(self: *const Reader, key: []const u8) ?Record {
        if (!self.bloom.mayContain(key)) return null;
        const blockIdx = self.findBlock(key) orelse return null;
        const block = self.blockBytes(blockIdx);
        var pos: usize = 0;
        while (pos < block.len) {
            const decoded = decodeRecord(block, pos);
            switch (order(decoded.record.key, key)) {
                .eq => return decoded.record,
                .gt => return null,
                .lt => pos = decoded.next,
            }
        }
        return null;
    }

    pub fn findAsOf(self: *const Reader, key: []const u8, maxSeq: u64) ?Record {
        const rec = self.find(key) orelse return null;
        if (rec.seq > maxSeq) return null;
        return rec;
    }

    pub fn findCachedAsOf(self: *const Reader, blockCache: *BlockCache, allocator: Allocator, key: []const u8, maxSeq: u64) !?OwnedHit {
        if (!self.bloom.mayContain(key)) return null;
        const blockIdx = self.findBlock(key) orelse return null;
        const entry = self.index[blockIdx];
        const blockKey = BlockKey{ .fileId = self.fileId, .offset = entry.offset };

        const cached = blockCache.get(blockKey);
        const block = cached orelse self.dataBuf[entry.offset .. entry.offset + entry.blockLen];
        if (cached == null) try blockCache.put(blockKey, block);

        var pos: usize = 0;
        while (pos < block.len) {
            const decoded = decodeRecord(block, pos);
            switch (order(decoded.record.key, key)) {
                .eq => {
                    if (decoded.record.seq > maxSeq) return null;
                    return OwnedHit{
                        .seq = decoded.record.seq,
                        .kind = decoded.record.kind,
                        .value = try allocator.dupe(u8, decoded.record.value),
                    };
                },
                .gt => return null,
                .lt => pos = decoded.next,
            }
        }
        return null;
    }

    pub fn cursor(self: *const Reader, start: ?[]const u8) Cursor {
        var c = Cursor{ .reader = self, .blockIdx = 0, .pos = 0, .nextPos = 0, .cur = null };
        if (self.index.len == 0) return c;
        c.blockIdx = if (start) |s| (self.findBlock(s) orelse 0) else 0;
        c.refresh();
        if (start) |s| {
            while (c.valid() and order(c.cur.?.key, s) == .lt) c.advance();
        }
        return c;
    }

    pub fn reverseCursor(self: *const Reader, allocator: Allocator, end: ?[]const u8, endInclusive: bool) !ReverseCursor {
        var c = ReverseCursor{
            .reader = self,
            .allocator = allocator,
            .positions = std.ArrayList(usize).init(allocator),
            .blockIdx = 0,
            .idx = 0,
            .exhausted = false,
            .cur = null,
        };
        if (self.index.len == 0) {
            c.exhausted = true;
            return c;
        }

        var blockIdx: usize = if (end) |e| (self.findBlock(e) orelse {
            c.exhausted = true;
            return c;
        }) else self.index.len - 1;

        try c.loadBlock(blockIdx);
        if (end) |e| {
            var chosen: ?usize = null;
            for (c.positions.items, 0..) |p, i| {
                const rec = decodeRecord(self.blockBytes(blockIdx), p);
                const within = if (endInclusive) order(rec.record.key, e) != .gt else order(rec.record.key, e) == .lt;
                if (within) chosen = i else break;
            }
            if (chosen) |i| {
                c.idx = i;
            } else {
                if (blockIdx == 0) {
                    c.exhausted = true;
                    c.cur = null;
                    return c;
                }
                blockIdx -= 1;
                try c.loadBlock(blockIdx);
                c.idx = c.positions.items.len - 1;
            }
        } else {
            c.idx = c.positions.items.len - 1;
        }
        c.setCurrent();
        return c;
    }

    fn findBlock(self: *const Reader, key: []const u8) ?usize {
        var lo: usize = 0;
        var hi: usize = self.index.len;
        var ans: ?usize = null;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (order(self.index[mid].firstKey, key) != .gt) {
                ans = mid;
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return ans;
    }

    fn blockBytes(self: *const Reader, idx: usize) []const u8 {
        const entry = self.index[idx];
        return self.dataBuf[entry.offset .. entry.offset + entry.blockLen];
    }

    pub fn blockCount(self: *const Reader) usize {
        return self.index.len;
    }
};

pub const Cursor = struct {
    reader: *const Reader,
    blockIdx: usize,
    pos: usize,
    nextPos: usize,
    cur: ?Record,

    pub fn valid(self: *const Cursor) bool {
        return self.cur != null;
    }

    pub fn record(self: *const Cursor) Record {
        return self.cur.?;
    }

    pub fn advance(self: *Cursor) void {
        self.pos = self.nextPos;
        self.refresh();
    }

    fn refresh(self: *Cursor) void {
        while (self.blockIdx < self.reader.index.len) {
            const block = self.reader.blockBytes(self.blockIdx);
            if (self.pos >= block.len) {
                self.blockIdx += 1;
                self.pos = 0;
                continue;
            }
            const decoded = decodeRecord(block, self.pos);
            self.cur = decoded.record;
            self.nextPos = decoded.next;
            return;
        }
        self.cur = null;
    }
};

pub const ReverseCursor = struct {
    reader: *const Reader,
    allocator: Allocator,
    positions: std.ArrayList(usize),
    blockIdx: usize,
    idx: usize,
    exhausted: bool,
    cur: ?Record,

    pub fn deinit(self: *ReverseCursor) void {
        self.positions.deinit();
    }

    pub fn valid(self: *const ReverseCursor) bool {
        return self.cur != null;
    }

    pub fn record(self: *const ReverseCursor) Record {
        return self.cur.?;
    }

    pub fn advance(self: *ReverseCursor) void {
        if (self.exhausted) return;
        if (self.idx == 0) {
            if (self.blockIdx == 0) {
                self.exhausted = true;
                self.cur = null;
                return;
            }
            self.loadBlock(self.blockIdx - 1) catch {
                self.exhausted = true;
                self.cur = null;
                return;
            };
            self.idx = self.positions.items.len - 1;
        } else {
            self.idx -= 1;
        }
        self.setCurrent();
    }

    fn loadBlock(self: *ReverseCursor, blockIdx: usize) !void {
        self.blockIdx = blockIdx;
        self.positions.clearRetainingCapacity();
        const block = self.reader.blockBytes(blockIdx);
        var pos: usize = 0;
        while (pos < block.len) {
            try self.positions.append(pos);
            pos = decodeRecord(block, pos).next;
        }
    }

    fn setCurrent(self: *ReverseCursor) void {
        const block = self.reader.blockBytes(self.blockIdx);
        self.cur = decodeRecord(block, self.positions.items[self.idx]).record;
    }
};

fn verifiedBlock(buffer: []const u8, offset: u64, len: u32) ![]const u8 {
    const start: usize = @intCast(offset);
    const end = start + len;
    if (end + 4 > buffer.len) return error.CorruptSstable;
    const block = buffer[start..end];
    if (encode.crc(block) != readU32(buffer, end)) return error.CorruptSstable;
    return block;
}

const Decoded = struct {
    record: Record,
    next: usize,
};

fn decodeRecord(block: []const u8, pos: usize) Decoded {
    const kind: Kind = @enumFromInt(block[pos]);
    const seq = readU64(block, pos + 1);
    const keyLen = readU32(block, pos + 9);
    const valLen = readU32(block, pos + 13);
    const keyStart = pos + recordHeader;
    const key = block[keyStart .. keyStart + keyLen];
    const valStart = keyStart + keyLen;
    const value = block[valStart .. valStart + valLen];
    return .{
        .record = .{ .key = key, .value = value, .seq = seq, .kind = kind },
        .next = valStart + valLen,
    };
}

fn buildFixture(allocator: Allocator, dir: std.fs.Dir, name: []const u8, count: usize) !void {
    var builder = try Builder.init(allocator, dir, name, count);
    defer builder.deinit();
    var buf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "k{d:0>6}", .{i});
        try builder.add(.{ .key = key, .value = "payload-value", .seq = i + 1, .kind = .value });
    }
    try builder.finish();
}

test "sstable build find" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    try std.testing.expectEqual(@as(u64, 500), reader.numEntries);
    try std.testing.expect(reader.index.len > 1);

    try std.testing.expectEqualStrings("payload-value", reader.find("k000000").?.value);
    try std.testing.expectEqualStrings("payload-value", reader.find("k000499").?.value);
    try std.testing.expectEqualStrings("payload-value", reader.find("k000250").?.value);
    try std.testing.expectEqual(@as(?Record, null), reader.find("k000500"));
    try std.testing.expectEqual(@as(?Record, null), reader.find("zzz"));
    try std.testing.expectEqual(@as(?Record, null), reader.find("aaa"));
}

test "sstable cursor ordered scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    var cur = reader.cursor(null);
    var expected: usize = 0;
    var buf: [16]u8 = undefined;
    while (cur.valid()) : (cur.advance()) {
        const key = try std.fmt.bufPrint(&buf, "k{d:0>6}", .{expected});
        try std.testing.expectEqualStrings(key, cur.record().key);
        expected += 1;
    }
    try std.testing.expectEqual(@as(usize, 500), expected);
}

test "sstable cursor seek" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    var cur = reader.cursor("k000123");
    try std.testing.expectEqualStrings("k000123", cur.record().key);
    cur.advance();
    try std.testing.expectEqualStrings("k000124", cur.record().key);

    var beyond = reader.cursor("k000600");
    try std.testing.expect(!beyond.valid());
}

test "sstable reverse cursor descends fully" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    var cur = try reader.reverseCursor(allocator, null, false);
    defer cur.deinit();
    var expected: usize = 500;
    var buf: [16]u8 = undefined;
    while (cur.valid()) : (cur.advance()) {
        expected -= 1;
        const key = try std.fmt.bufPrint(&buf, "k{d:0>6}", .{expected});
        try std.testing.expectEqualStrings(key, cur.record().key);
    }
    try std.testing.expectEqual(@as(usize, 0), expected);
}

test "sstable reverse cursor honors upper bound" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    var cur = try reader.reverseCursor(allocator, "k000100", false);
    defer cur.deinit();
    try std.testing.expectEqualStrings("k000099", cur.record().key);
    cur.advance();
    try std.testing.expectEqualStrings("k000098", cur.record().key);

    var inclusive = try reader.reverseCursor(allocator, "k000100", true);
    defer inclusive.deinit();
    try std.testing.expectEqualStrings("k000100", inclusive.record().key);

    var below = try reader.reverseCursor(allocator, "k000000", false);
    defer below.deinit();
    try std.testing.expect(!below.valid());
}
