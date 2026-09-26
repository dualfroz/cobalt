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
const version: u32 = 2;
const footerLen = 4 + 4 + 8 + 4 + 8 + 4 + 8 + 8;
const recordHeader = 1 + 8 + 4 + 4;
const defaultBlockTarget = 4096;

const restartInterval: usize = 16;

fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n and a[i] == b[i]) : (i += 1) {}
    return i;
}

pub const Builder = struct {
    allocator: Allocator,
    file: std.fs.File,
    offset: u64,
    blockBuf: std.ArrayList(u8),
    blockFirstKey: std.ArrayList(u8),
    indexBuf: std.ArrayList(u8),
    lastKey: std.ArrayList(u8),
    blockRestarts: std.ArrayList(u32),
    blockRecordCount: usize,
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
            .lastKey = std.ArrayList(u8).init(allocator),
            .blockRestarts = std.ArrayList(u32).init(allocator),
            .blockRecordCount = 0,
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
        self.lastKey.deinit();
        self.blockRestarts.deinit();
        self.bloom.deinit();
        self.file.close();
    }

    pub fn add(self: *Builder, record: Record) !void {
        if (self.blockBuf.items.len == 0) {
            self.blockFirstKey.clearRetainingCapacity();
            try self.blockFirstKey.appendSlice(record.key);
        }

        const isRestart = self.blockRecordCount % restartInterval == 0;
        const shared: u32 = if (isRestart) 0 else @intCast(commonPrefixLen(self.lastKey.items, record.key));
        const unshared = record.key[shared..];
        if (isRestart) try self.blockRestarts.append(@intCast(self.blockBuf.items.len));

        const writer = encode.ByteWriter.init(&self.blockBuf);
        try writer.byte(@intFromEnum(record.kind));
        try writer.putU64(record.seq);
        try writer.putU32(shared);
        try writer.putU32(@intCast(unshared.len));
        try writer.putU32(@intCast(record.value.len));
        try writer.slice(unshared);
        try writer.slice(record.value);

        self.lastKey.clearRetainingCapacity();
        try self.lastKey.appendSlice(record.key);
        self.blockRecordCount += 1;

        self.bloom.add(record.key);
        self.numEntries += 1;
        self.logicalBytes += recordHeader + record.key.len + record.value.len;
        if (record.seq > self.maxSeq) self.maxSeq = record.seq;

        if (self.blockBuf.items.len >= self.blockTarget) try self.flushBlock();
    }

    fn flushBlock(self: *Builder) !void {
        if (self.blockBuf.items.len == 0) return;

        const trailerWriter = encode.ByteWriter.init(&self.blockBuf);
        for (self.blockRestarts.items) |restartOffset| try trailerWriter.putU32(restartOffset);
        try trailerWriter.putU32(@intCast(self.blockRestarts.items.len));

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
        self.blockRestarts.clearRetainingCapacity();
        self.blockRecordCount = 0;
        self.lastKey.clearRetainingCapacity();
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
    restarts: []u32,
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
        if (readU32(buffer, footerStart + 4) != version) return error.UnsupportedSstableVersion;
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
        errdefer {
            for (entries.items) |e| allocator.free(e.restarts);
            entries.deinit();
        }

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
            const expanded = try expandBlock(allocator, plainBlock);
            defer allocator.free(expanded.bytes);
            errdefer allocator.free(expanded.restarts);

            const decOffset = decoded.items.len;
            try decoded.appendSlice(expanded.bytes);

            try entries.append(.{
                .offset = decOffset,
                .blockLen = @intCast(expanded.bytes.len),
                .firstKey = firstKey,
                .restarts = expanded.restarts,
            });
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
        for (self.index) |e| self.allocator.free(e.restarts);
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
        var pos: usize = Reader.seekInBlock(block, self.index[blockIdx].restarts, key);
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

        var pos: usize = Reader.seekInBlock(block, entry.restarts, key);
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
        if (start) |s| {
            c.blockIdx = self.findBlock(s) orelse 0;
            c.pos = Reader.seekInBlock(self.blockBytes(c.blockIdx), self.index[c.blockIdx].restarts, s);
        }
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

    fn seekInBlock(block: []const u8, restarts: []const u32, key: []const u8) usize {
        if (restarts.len == 0) return 0;
        var lo: usize = 0;
        var hi: usize = restarts.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const rec = decodeRecord(block, restarts[mid]);
            if (order(rec.record.key, key) != .gt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return if (lo == 0) 0 else restarts[lo - 1];
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

const ExpandedBlock = struct {
    bytes: []u8,
    restarts: []u32,
};

fn expandBlock(allocator: Allocator, physical: []const u8) !ExpandedBlock {
    if (physical.len < 4) return error.CorruptSstable;
    const numRestarts = readU32(physical, physical.len - 4);
    const restartTableBytes = @as(usize, numRestarts) * 4;
    if (restartTableBytes + 4 > physical.len) return error.CorruptSstable;
    const recordsEnd = physical.len - 4 - restartTableBytes;
    const restartTable = physical[recordsEnd .. recordsEnd + restartTableBytes];

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var flatRestarts = std.ArrayList(u32).init(allocator);
    errdefer flatRestarts.deinit();

    var prevKey = std.ArrayList(u8).init(allocator);
    defer prevKey.deinit();

    const perRecordFixed = 1 + 8 + 4 + 4 + 4;
    var pos: usize = 0;
    var restartIdx: usize = 0;
    var recordIdx: usize = 0;
    while (pos < recordsEnd) {
        if (pos + perRecordFixed > recordsEnd) return error.CorruptSstable;
        const kind = physical[pos];
        const seq = readU64(physical, pos + 1);
        const shared = readU32(physical, pos + 9);
        const unshared = readU32(physical, pos + 13);
        const valLen = readU32(physical, pos + 17);
        const keyStart = pos + perRecordFixed;
        if (shared > prevKey.items.len) return error.CorruptSstable;
        if (keyStart + @as(usize, unshared) + @as(usize, valLen) > recordsEnd) return error.CorruptSstable;

        const shouldBeRestart = recordIdx % restartInterval == 0;
        const isDeclaredRestart = restartIdx < numRestarts and readU32(restartTable, restartIdx * 4) == pos;
        if (shouldBeRestart != isDeclaredRestart) return error.CorruptSstable;
        if (shouldBeRestart) {
            if (shared != 0) return error.CorruptSstable;
            restartIdx += 1;
            try flatRestarts.append(@intCast(out.items.len));
        }

        const unsharedBytes = physical[keyStart .. keyStart + unshared];
        const valStart = keyStart + unshared;
        const value = physical[valStart .. valStart + valLen];

        const fullKey = try allocator.alloc(u8, shared + unshared);
        defer allocator.free(fullKey);
        @memcpy(fullKey[0..shared], prevKey.items[0..shared]);
        @memcpy(fullKey[shared..], unsharedBytes);

        const writer = encode.ByteWriter.init(&out);
        try writer.byte(kind);
        try writer.putU64(seq);
        try writer.putU32(@intCast(fullKey.len));
        try writer.putU32(valLen);
        try writer.slice(fullKey);
        try writer.slice(value);

        prevKey.clearRetainingCapacity();
        try prevKey.appendSlice(fullKey);

        pos = valStart + valLen;
        recordIdx += 1;
    }
    if (pos != recordsEnd) return error.CorruptSstable;
    if (restartIdx != numRestarts) return error.CorruptSstable;

    return .{ .bytes = try out.toOwnedSlice(), .restarts = try flatRestarts.toOwnedSlice() };
}

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

test "restart index lets point lookups skip straight past earlier records in a block" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 500);
    var reader = try Reader.open(allocator, tmp.dir, "test.sst", 1);
    defer reader.deinit();

    var sawMultiRestartBlock = false;
    var blockIdx: usize = 0;
    while (blockIdx < reader.index.len) : (blockIdx += 1) {
        const entry = reader.index[blockIdx];
        try std.testing.expect(entry.restarts.len >= 1);
        try std.testing.expectEqual(@as(u32, 0), entry.restarts[0]);
        if (entry.restarts.len > 1) sawMultiRestartBlock = true;

        const block = reader.blockBytes(blockIdx);
        var prevKey: []const u8 = &.{};
        for (entry.restarts) |r| {
            const rec = decodeRecord(block, r);
            if (prevKey.len > 0) try std.testing.expect(order(prevKey, rec.record.key) == .lt);
            prevKey = rec.record.key;
        }
    }
    try std.testing.expect(sawMultiRestartBlock);

    const entry0 = reader.index[0];
    try std.testing.expect(entry0.restarts.len > 2);
    const block0 = reader.blockBytes(0);
    const secondRestartOffset = entry0.restarts[1];
    const secondRestartKey = decodeRecord(block0, secondRestartOffset).record.key;
    try std.testing.expectEqual(secondRestartOffset, Reader.seekInBlock(block0, entry0.restarts, secondRestartKey));

    const firstRestartKey = decodeRecord(block0, entry0.restarts[0]).record.key;
    var midBuf: [16]u8 = undefined;
    @memcpy(midBuf[0..firstRestartKey.len], firstRestartKey);
    midBuf[firstRestartKey.len - 1] += 1;
    try std.testing.expect(order(midBuf[0..firstRestartKey.len], secondRestartKey) == .lt);
    try std.testing.expectEqual(entry0.restarts[0], Reader.seekInBlock(block0, entry0.restarts, midBuf[0..firstRestartKey.len]));

    const lastRestartKey = decodeRecord(block0, entry0.restarts[entry0.restarts.len - 1]).record.key;
    var pastBuf: [16]u8 = undefined;
    @memcpy(pastBuf[0..lastRestartKey.len], lastRestartKey);
    pastBuf[lastRestartKey.len - 1] += 1;
    try std.testing.expectEqual(entry0.restarts[entry0.restarts.len - 1], Reader.seekInBlock(block0, entry0.restarts, pastBuf[0..lastRestartKey.len]));

    try std.testing.expectEqualStrings("payload-value", reader.find(firstRestartKey).?.value);
    try std.testing.expectEqualStrings("payload-value", reader.find(secondRestartKey).?.value);
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

fn writeRawRecord(w: encode.ByteWriter, kind: Kind, seq: u64, shared: u32, unshared: []const u8, value: []const u8) !void {
    try w.byte(@intFromEnum(kind));
    try w.putU64(seq);
    try w.putU32(shared);
    try w.putU32(@intCast(unshared.len));
    try w.putU32(@intCast(value.len));
    try w.slice(unshared);
    try w.slice(value);
}

test "expandBlock reconstructs prefix-compressed records" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    try writeRawRecord(w, .value, 1, 0, "apple", "1");
    try writeRawRecord(w, .value, 2, 3, "ly", "2");
    try writeRawRecord(w, .tombstone, 3, 2, "ricot", "");
    try w.putU32(0);
    try w.putU32(1);

    const expanded = try expandBlock(allocator, buf.items);
    defer allocator.free(expanded.bytes);
    defer allocator.free(expanded.restarts);

    const d0 = decodeRecord(expanded.bytes, 0);
    try std.testing.expectEqualStrings("apple", d0.record.key);
    try std.testing.expectEqualStrings("1", d0.record.value);
    try std.testing.expectEqual(Kind.value, d0.record.kind);

    const d1 = decodeRecord(expanded.bytes, d0.next);
    try std.testing.expectEqualStrings("apply", d1.record.key);
    try std.testing.expectEqualStrings("2", d1.record.value);

    const d2 = decodeRecord(expanded.bytes, d1.next);
    try std.testing.expectEqualStrings("apricot", d2.record.key);
    try std.testing.expectEqual(Kind.tombstone, d2.record.kind);
    try std.testing.expectEqual(d2.next, expanded.bytes.len);

    try std.testing.expectEqualSlices(u32, &.{0}, expanded.restarts);
}

test "expandBlock rejects a restart declared at the wrong record" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    const record0End = 1 + 8 + 4 + 4 + 4 + 5 + 1;
    try writeRawRecord(w, .value, 1, 0, "apple", "1");
    try writeRawRecord(w, .value, 2, 3, "ly", "2");
    try w.putU32(@intCast(record0End));
    try w.putU32(1);

    try std.testing.expectError(error.CorruptSstable, expandBlock(allocator, buf.items));
}

test "expandBlock rejects a missing restart declaration" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    try writeRawRecord(w, .value, 1, 0, "apple", "1");
    try w.putU32(0);

    try std.testing.expectError(error.CorruptSstable, expandBlock(allocator, buf.items));
}

test "expandBlock rejects shared length exceeding the previous key" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    try writeRawRecord(w, .value, 1, 0, "ab", "1");
    try writeRawRecord(w, .value, 2, 5, "xyz", "2");
    try w.putU32(0);
    try w.putU32(1);

    try std.testing.expectError(error.CorruptSstable, expandBlock(allocator, buf.items));
}

test "expandBlock rejects a record stream that overruns its declared lengths" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    try w.byte(@intFromEnum(Kind.value));
    try w.putU64(1);
    try w.putU32(0);
    try w.putU32(100);
    try w.putU32(0);
    try w.putU32(0);
    try w.putU32(1);

    try std.testing.expectError(error.CorruptSstable, expandBlock(allocator, buf.items));
}

test "expandBlock rejects trailing bytes that do not form a full record" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    try writeRawRecord(w, .value, 1, 0, "apple", "1");
    try w.byte(0xff);
    try w.putU32(0);
    try w.putU32(1);

    try std.testing.expectError(error.CorruptSstable, expandBlock(allocator, buf.items));
}

test "Reader.open rejects an sstable written by an unsupported format version" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildFixture(allocator, tmp.dir, "test.sst", 10);

    {
        var file = try tmp.dir.openFile("test.sst", .{ .mode = .read_write });
        defer file.close();
        const size = try file.getEndPos();
        try file.seekTo(size - footerLen + 4);
        var bogus: [4]u8 = undefined;
        std.mem.writeInt(u32, &bogus, version + 1, encode.endian);
        try file.writeAll(&bogus);
    }

    try std.testing.expectError(error.UnsupportedSstableVersion, Reader.open(allocator, tmp.dir, "test.sst", 1));
}

test "prefix compression measurably shrinks sstables with a shared key prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const count = 3000;

    {
        var builder = try Builder.init(allocator, tmp.dir, "shared.sst", count);
        defer builder.deinit();
        var buf: [64]u8 = undefined;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = try std.fmt.bufPrint(&buf, "users\x00city\x00warsaw\x00pk{d:0>8}", .{i});
            try builder.add(.{ .key = key, .value = "v", .seq = i + 1, .kind = .value });
        }
        try builder.finish();
    }
    {
        var builder = try Builder.init(allocator, tmp.dir, "distinct.sst", count);
        defer builder.deinit();
        var buf: [64]u8 = undefined;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const scrambled = i *% 2654435761;
            const key = try std.fmt.bufPrint(&buf, "{d:0>20}", .{scrambled});
            try builder.add(.{ .key = key, .value = "v", .seq = i + 1, .kind = .value });
        }
        try builder.finish();
    }

    var sharedReader = try Reader.open(allocator, tmp.dir, "shared.sst", 1);
    defer sharedReader.deinit();
    var distinctReader = try Reader.open(allocator, tmp.dir, "distinct.sst", 2);
    defer distinctReader.deinit();

    try std.testing.expectEqual(@as(u64, count), sharedReader.numEntries);
    try std.testing.expectEqual(@as(u64, count), distinctReader.numEntries);
    try std.testing.expect(sharedReader.physicalBytes * 5 < distinctReader.physicalBytes * 4);

    try std.testing.expectEqualStrings("v", sharedReader.find("users\x00city\x00warsaw\x00pk00000000").?.value);
    try std.testing.expectEqualStrings("v", sharedReader.find("users\x00city\x00warsaw\x00pk00000150").?.value);
    try std.testing.expectEqualStrings("v", sharedReader.find("users\x00city\x00warsaw\x00pk00000299").?.value);
    try std.testing.expectEqual(@as(?Record, null), sharedReader.find("users\x00city\x00warsaw\x00pk99999999"));
}
