const std = @import("std");
const encode = @import("encode.zig");
const memtable = @import("memtable.zig");
const sstable = @import("sstable.zig");
const cache = @import("cache.zig");
const statsmod = @import("stats.zig");
const Wal = @import("wal.zig").Wal;

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Record = encode.Record;
const Memtable = memtable.Memtable;
const Reader = sstable.Reader;
const Builder = sstable.Builder;
const BlockCache = cache.BlockCache;

pub const WriteBatch = @import("batch.zig").WriteBatch;
pub const Stats = statsmod.Stats;

fn order(a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, a, b);
}

const walName = "wal.log";
const manifestName = "MANIFEST";

pub const Options = struct {
    flushThreshold: usize = 4 * 1024 * 1024,
    blockCacheBytes: usize = 8 * 1024 * 1024,
    l0CompactionTrigger: usize = 4,
    l1BaseBytes: usize = 8 * 1024 * 1024,
    levelMultiplier: usize = 10,
    sstableTargetBytes: usize = 2 * 1024 * 1024,
};

pub const Entry = struct {
    key: []const u8,
    value: []const u8,
};

pub const Db = struct {
    allocator: Allocator,
    dir: std.fs.Dir,
    dirPath: []u8,
    memtable: Memtable,
    wal: Wal,
    sstables: std.ArrayList(*Reader),
    blockCache: BlockCache,
    nextFileId: u64,
    nextSeq: u64,
    flushThreshold: usize,
    l0Trigger: usize,
    l1BaseBytes: usize,
    levelMultiplier: usize,
    sstableTargetBytes: usize,

    pub fn open(allocator: Allocator, dirPath: []const u8, options: Options) !Db {
        try std.fs.cwd().makePath(dirPath);
        var dir = try std.fs.cwd().openDir(dirPath, .{ .iterate = true });
        errdefer dir.close();

        var sstables = std.ArrayList(*Reader).init(allocator);
        errdefer {
            for (sstables.items) |reader| {
                reader.deinit();
                allocator.destroy(reader);
            }
            sstables.deinit();
        }

        var ids = std.ArrayList(u64).init(allocator);
        defer ids.deinit();
        var walker = dir.iterate();
        while (try walker.next()) |item| {
            if (item.kind != .file) continue;
            if (parseSstId(item.name)) |id| try ids.append(id);
        }
        std.mem.sort(u64, ids.items, {}, std.sort.desc(u64));

        var maxSeq: u64 = 0;
        var maxId: u64 = 0;
        for (ids.items) |id| {
            var nameBuf: [64]u8 = undefined;
            const name = try sstName(&nameBuf, id);
            const reader = try allocator.create(Reader);
            errdefer allocator.destroy(reader);
            reader.* = try Reader.open(allocator, dir, name, id);
            errdefer reader.deinit();
            try sstables.append(reader);
            if (reader.maxSeq > maxSeq) maxSeq = reader.maxSeq;
            if (id > maxId) maxId = id;
        }

        var levelMap = try loadManifest(allocator, dir);
        defer levelMap.deinit();
        for (sstables.items) |reader| {
            reader.level = levelMap.get(reader.fileId) orelse 0;
        }

        var table = try Memtable.init(allocator);
        errdefer table.deinit();
        var wal = try Wal.open(allocator, dir, walName);
        errdefer wal.close();
        const walMaxSeq = try wal.replay(&table);
        if (walMaxSeq > maxSeq) maxSeq = walMaxSeq;

        const dirPathCopy = try allocator.dupe(u8, dirPath);

        return .{
            .allocator = allocator,
            .dir = dir,
            .dirPath = dirPathCopy,
            .memtable = table,
            .wal = wal,
            .sstables = sstables,
            .blockCache = BlockCache.init(allocator, options.blockCacheBytes),
            .nextFileId = maxId + 1,
            .nextSeq = maxSeq + 1,
            .flushThreshold = options.flushThreshold,
            .l0Trigger = options.l0CompactionTrigger,
            .l1BaseBytes = options.l1BaseBytes,
            .levelMultiplier = options.levelMultiplier,
            .sstableTargetBytes = options.sstableTargetBytes,
        };
    }

    pub fn close(self: *Db) void {
        self.wal.close();
        for (self.sstables.items) |reader| {
            reader.deinit();
            self.allocator.destroy(reader);
        }
        self.sstables.deinit();
        self.blockCache.deinit();
        self.memtable.deinit();
        self.dir.close();
        self.allocator.free(self.dirPath);
    }

    pub fn put(self: *Db, key: []const u8, value: []const u8) !void {
        try self.write(.value, key, value);
    }

    pub fn delete(self: *Db, key: []const u8) !void {
        try self.write(.tombstone, key, &.{});
    }

    fn write(self: *Db, kind: Kind, key: []const u8, value: []const u8) !void {
        const seq = self.nextSeq;
        try self.wal.append(kind, seq, key, value);
        try self.wal.sync();
        try self.memtable.upsert(kind, seq, key, value);
        self.nextSeq += 1;
        if (self.memtable.byteSize >= self.flushThreshold) try self.flush();
    }

    pub fn apply(self: *Db, batch: *WriteBatch) !void {
        if (batch.ops.items.len == 0) return;
        var records = try self.allocator.alloc(Record, batch.ops.items.len);
        defer self.allocator.free(records);
        for (batch.ops.items, 0..) |op, i| {
            records[i] = .{ .key = op.key, .value = op.value, .seq = self.nextSeq + @as(u64, @intCast(i)), .kind = op.kind };
        }
        try self.wal.appendBatch(records);
        try self.wal.sync();
        for (records) |record| {
            try self.memtable.upsert(record.kind, record.seq, record.key, record.value);
        }
        self.nextSeq += records.len;
        if (self.memtable.byteSize >= self.flushThreshold) try self.flush();
    }

    pub fn get(self: *Db, allocator: Allocator, key: []const u8) !?[]u8 {
        return self.getAsOf(allocator, key, std.math.maxInt(u64));
    }

    pub fn getAsOf(self: *Db, allocator: Allocator, key: []const u8, maxSeq: u64) !?[]u8 {
        var bestSeq: ?u64 = null;
        var bestKind: Kind = .value;
        var owned: ?[]u8 = null;
        errdefer if (owned) |v| allocator.free(v);

        if (self.memtable.findAsOf(key, maxSeq)) |rec| {
            bestSeq = rec.seq;
            bestKind = rec.kind;
            owned = try allocator.dupe(u8, rec.value);
        }
        for (self.sstables.items) |reader| {
            const hit = try reader.findCachedAsOf(&self.blockCache, allocator, key, maxSeq) orelse continue;
            if (bestSeq == null or hit.seq > bestSeq.?) {
                if (owned) |v| allocator.free(v);
                bestSeq = hit.seq;
                bestKind = hit.kind;
                owned = hit.value;
            } else {
                allocator.free(hit.value);
            }
        }

        if (bestSeq == null) return null;
        if (bestKind == .tombstone) {
            if (owned) |v| allocator.free(v);
            return null;
        }
        return owned;
    }

    pub fn snapshot(self: *Db) !Snapshot {
        try self.flush();
        return .{ .db = self, .seq = if (self.nextSeq == 0) 0 else self.nextSeq - 1 };
    }

    pub fn flush(self: *Db) !void {
        if (self.memtable.count == 0) return;
        const fileId = self.nextFileId;
        var nameBuf: [64]u8 = undefined;
        const name = try sstName(&nameBuf, fileId);

        {
            var builder = try Builder.init(self.allocator, self.dir, name, self.memtable.count);
            defer builder.deinit();
            var cur = self.memtable.cursor(null);
            while (cur.valid()) : (cur.advance()) try builder.add(cur.record());
            try builder.finish();
        }

        const reader = try self.allocator.create(Reader);
        errdefer self.allocator.destroy(reader);
        reader.* = try Reader.open(self.allocator, self.dir, name, fileId);
        errdefer reader.deinit();
        reader.level = 0;
        try self.sstables.insert(0, reader);

        self.nextFileId += 1;
        self.memtable.clear();
        try self.wal.reset();
        try self.writeManifest();
        std.posix.fsync(self.dir.fd) catch {};
    }

    pub fn compact(self: *Db) !void {
        if (self.sstables.items.len <= 1) return;
        const fileId = self.nextFileId;
        var nameBuf: [64]u8 = undefined;
        const name = try sstName(&nameBuf, fileId);

        var expected: usize = 0;
        for (self.sstables.items) |reader| expected += @intCast(reader.numEntries);

        const cursors = try self.allocator.alloc(sstable.Cursor, self.sstables.items.len);
        defer self.allocator.free(cursors);
        for (self.sstables.items, 0..) |reader, i| cursors[i] = reader.cursor(null);

        {
            var builder = try Builder.init(self.allocator, self.dir, name, expected);
            defer builder.deinit();
            while (pickWinner(cursors)) |winner| {
                if (winner.kind == .value) try builder.add(winner);
            }
            try builder.finish();
        }

        const reader = try self.allocator.create(Reader);
        errdefer self.allocator.destroy(reader);
        reader.* = try Reader.open(self.allocator, self.dir, name, fileId);
        errdefer reader.deinit();

        for (self.sstables.items) |old| {
            var oldNameBuf: [64]u8 = undefined;
            const oldName = sstName(&oldNameBuf, old.fileId) catch unreachable;
            old.deinit();
            self.allocator.destroy(old);
            self.dir.deleteFile(oldName) catch {};
        }
        self.sstables.clearRetainingCapacity();
        reader.level = 0;
        try self.sstables.append(reader);
        self.nextFileId += 1;
        try self.writeManifest();
        std.posix.fsync(self.dir.fd) catch {};
    }

    pub fn maybeCompact(self: *Db) !void {
        while (true) {
            if (self.countLevel(0) >= self.l0Trigger) {
                try self.compactL0();
                continue;
            }
            var acted = false;
            var level: usize = 1;
            const bottom = self.maxDataLevel();
            while (level <= bottom) : (level += 1) {
                if (self.levelSize(level) > self.levelLimit(level)) {
                    try self.compactDown(level);
                    acted = true;
                    break;
                }
            }
            if (!acted) break;
        }
    }

    fn compactL0(self: *Db) !void {
        var inputs = std.ArrayList(*Reader).init(self.allocator);
        defer inputs.deinit();
        var lo: ?[]const u8 = null;
        var hi: ?[]const u8 = null;
        for (self.sstables.items) |reader| {
            if (reader.level != 0) continue;
            try inputs.append(reader);
            if (reader.index.len == 0) continue;
            if (lo == null or order(reader.minKey, lo.?) == .lt) lo = reader.minKey;
            if (hi == null or order(reader.maxKey, hi.?) == .gt) hi = reader.maxKey;
        }
        if (inputs.items.len == 0) return;
        if (lo) |lowBound| {
            for (self.sstables.items) |reader| {
                if (reader.level != 1 or reader.index.len == 0) continue;
                if (rangesOverlap(reader.minKey, reader.maxKey, lowBound, hi.?)) try inputs.append(reader);
            }
        }
        const dropTombstones = !self.hasDataBelow(1);
        try self.runMerge(inputs.items, 1, dropTombstones);
    }

    fn compactDown(self: *Db, level: usize) !void {
        var picked: ?*Reader = null;
        for (self.sstables.items) |reader| {
            if (reader.level != level or reader.index.len == 0) continue;
            if (picked == null or order(reader.minKey, picked.?.minKey) == .lt) picked = reader;
        }
        if (picked == null) return;
        var inputs = std.ArrayList(*Reader).init(self.allocator);
        defer inputs.deinit();
        try inputs.append(picked.?);
        const target = level + 1;
        for (self.sstables.items) |reader| {
            if (reader.level != target or reader.index.len == 0) continue;
            if (rangesOverlap(reader.minKey, reader.maxKey, picked.?.minKey, picked.?.maxKey)) try inputs.append(reader);
        }
        const dropTombstones = !self.hasDataBelow(target);
        try self.runMerge(inputs.items, target, dropTombstones);
    }

    fn runMerge(self: *Db, inputs: []*Reader, targetLevel: usize, dropTombstones: bool) !void {
        const cursors = try self.allocator.alloc(sstable.Cursor, inputs.len);
        defer self.allocator.free(cursors);
        for (inputs, 0..) |reader, i| cursors[i] = reader.cursor(null);

        var outputs = std.ArrayList(*Reader).init(self.allocator);
        errdefer {
            for (outputs.items) |produced| {
                produced.deinit();
                self.allocator.destroy(produced);
            }
            outputs.deinit();
        }

        var estimate: usize = 0;
        for (inputs) |reader| estimate += @intCast(reader.numEntries);
        if (estimate == 0) estimate = 1;

        var builder: ?Builder = null;
        var outputId: u64 = 0;
        var outputName: [64]u8 = undefined;
        errdefer if (builder) |*b| b.deinit();

        while (pickWinner(cursors)) |winner| {
            if (dropTombstones and winner.kind == .tombstone) continue;
            if (builder == null) {
                outputId = self.nextFileId;
                self.nextFileId += 1;
                const name = try sstName(&outputName, outputId);
                builder = try Builder.init(self.allocator, self.dir, name, estimate);
            }
            try builder.?.add(winner);
            if (builder.?.logicalBytes >= self.sstableTargetBytes) {
                const done = builder.?;
                builder = null;
                try self.finishOutput(done, outputId, targetLevel, &outputs);
            }
        }
        if (builder) |done| {
            builder = null;
            try self.finishOutput(done, outputId, targetLevel, &outputs);
        }

        for (inputs) |old| {
            self.removeReader(old);
            var oldNameBuf: [64]u8 = undefined;
            const oldName = sstName(&oldNameBuf, old.fileId) catch unreachable;
            old.deinit();
            self.allocator.destroy(old);
            self.dir.deleteFile(oldName) catch {};
        }
        for (outputs.items) |produced| try self.sstables.append(produced);
        outputs.deinit();

        try self.writeManifest();
        std.posix.fsync(self.dir.fd) catch {};
    }

    fn finishOutput(self: *Db, builderIn: Builder, fileId: u64, targetLevel: usize, outputs: *std.ArrayList(*Reader)) !void {
        var builder = builderIn;
        {
            errdefer builder.deinit();
            try builder.finish();
        }
        builder.deinit();

        var nameBuf: [64]u8 = undefined;
        const name = try sstName(&nameBuf, fileId);
        const reader = try self.allocator.create(Reader);
        errdefer self.allocator.destroy(reader);
        reader.* = try Reader.open(self.allocator, self.dir, name, fileId);
        errdefer reader.deinit();
        reader.level = targetLevel;
        try outputs.append(reader);
    }

    fn removeReader(self: *Db, target: *Reader) void {
        for (self.sstables.items, 0..) |reader, i| {
            if (reader == target) {
                _ = self.sstables.orderedRemove(i);
                return;
            }
        }
    }

    fn countLevel(self: *Db, level: usize) usize {
        var n: usize = 0;
        for (self.sstables.items) |reader| {
            if (reader.level == level) n += 1;
        }
        return n;
    }

    fn levelSize(self: *Db, level: usize) usize {
        var total: usize = 0;
        for (self.sstables.items) |reader| {
            if (reader.level == level) total += reader.buffer.len;
        }
        return total;
    }

    fn levelLimit(self: *Db, level: usize) usize {
        var limit = self.l1BaseBytes;
        var i: usize = 1;
        while (i < level) : (i += 1) limit *= self.levelMultiplier;
        return limit;
    }

    fn maxDataLevel(self: *Db) usize {
        var maxLevel: usize = 0;
        for (self.sstables.items) |reader| {
            if (reader.level > maxLevel) maxLevel = reader.level;
        }
        return maxLevel;
    }

    fn hasDataBelow(self: *Db, level: usize) bool {
        for (self.sstables.items) |reader| {
            if (reader.level > level and reader.numEntries > 0) return true;
        }
        return false;
    }

    fn writeManifest(self: *Db) !void {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const bodyWriter = encode.ByteWriter.init(&buf);
        try bodyWriter.putU32(@intCast(self.sstables.items.len));
        for (self.sstables.items) |reader| {
            try bodyWriter.putU64(reader.fileId);
            try bodyWriter.putU32(@intCast(reader.level));
        }

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();
        const frameWriter = encode.ByteWriter.init(&frame);
        try frameWriter.putU32(encode.crc(buf.items));
        try frameWriter.slice(buf.items);

        const tmpName = "MANIFEST.tmp";
        {
            const file = try self.dir.createFile(tmpName, .{ .truncate = true });
            defer file.close();
            try file.writeAll(frame.items);
            try file.sync();
        }
        try self.dir.rename(tmpName, manifestName);
    }

    pub fn levelOf(self: *Db, fileId: u64) ?usize {
        for (self.sstables.items) |reader| {
            if (reader.fileId == fileId) return reader.level;
        }
        return null;
    }

    pub fn latestSeq(self: *Db, key: []const u8) ?u64 {
        var best: ?u64 = null;
        if (self.memtable.find(key)) |rec| best = rec.seq;
        for (self.sstables.items) |reader| {
            const rec = reader.find(key) orelse continue;
            if (best == null or rec.seq > best.?) best = rec.seq;
        }
        return best;
    }

    pub fn stats(self: *Db) Stats {
        var result = Stats{
            .memtableEntries = self.memtable.count,
            .memtableBytes = self.memtable.byteSize,
            .sstableCount = self.sstables.items.len,
            .cacheHits = self.blockCache.stats.hits,
            .cacheMisses = self.blockCache.stats.misses,
            .nextSeq = self.nextSeq,
        };
        for (self.sstables.items) |reader| {
            result.liveEntries += reader.numEntries;
            result.physicalBytes += reader.physicalBytes;
            if (reader.level < statsmod.maxTrackedLevels) {
                result.levels[reader.level].tables += 1;
                result.levels[reader.level].entries += reader.numEntries;
                result.levels[reader.level].physicalBytes += reader.physicalBytes;
            }
        }
        return result;
    }

    pub fn scan(self: *Db, allocator: Allocator, start: ?[]const u8, end: ?[]const u8) !RangeIterator {
        return self.scanRangeAsOf(allocator, .{ .start = start, .end = end }, std.math.maxInt(u64));
    }

    pub fn scanAsOf(self: *Db, allocator: Allocator, start: ?[]const u8, end: ?[]const u8, maxSeq: u64) !RangeIterator {
        return self.scanRangeAsOf(allocator, .{ .start = start, .end = end }, maxSeq);
    }

    pub fn scanRange(self: *Db, allocator: Allocator, options: ScanOptions) !RangeIterator {
        return self.scanRangeAsOf(allocator, options, std.math.maxInt(u64));
    }

    pub fn scanRangeAsOf(self: *Db, allocator: Allocator, options: ScanOptions, maxSeq: u64) !RangeIterator {
        const cursorCount = 1 + self.sstables.items.len;
        var cursors = try allocator.alloc(SourceCursor, cursorCount);
        errdefer allocator.free(cursors);
        cursors[0] = .{ .mem = self.memtable.cursor(options.start) };
        for (self.sstables.items, 0..) |reader, i| cursors[i + 1] = .{ .sst = reader.cursor(options.start) };

        var startCopy: ?[]u8 = null;
        errdefer if (startCopy) |s| allocator.free(s);
        if (options.start) |bound| startCopy = try allocator.dupe(u8, bound);
        var endCopy: ?[]u8 = null;
        if (options.end) |bound| endCopy = try allocator.dupe(u8, bound);

        return .{
            .resultAllocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cursors = cursors,
            .start = startCopy,
            .end = endCopy,
            .startInclusive = options.startInclusive,
            .endInclusive = options.endInclusive,
            .maxSeq = maxSeq,
        };
    }

    pub fn scanPrefix(self: *Db, allocator: Allocator, prefix: []const u8) !RangeIterator {
        return self.scanPrefixAsOf(allocator, prefix, std.math.maxInt(u64));
    }

    pub fn scanPrefixAsOf(self: *Db, allocator: Allocator, prefix: []const u8, maxSeq: u64) !RangeIterator {
        const upper = try prefixUpperBound(allocator, prefix);
        defer if (upper) |u| allocator.free(u);
        return self.scanRangeAsOf(allocator, .{ .start = prefix, .end = upper }, maxSeq);
    }

    pub fn scanReverse(self: *Db, allocator: Allocator, options: ScanOptions) !ReverseRangeIterator {
        return self.scanReverseAsOf(allocator, options, std.math.maxInt(u64));
    }

    pub fn scanReverseAsOf(self: *Db, allocator: Allocator, options: ScanOptions, maxSeq: u64) !ReverseRangeIterator {
        const cursorCount = 1 + self.sstables.items.len;
        var cursors = try allocator.alloc(ReverseSource, cursorCount);
        errdefer allocator.free(cursors);
        var built: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < built) : (i += 1) cursors[i].deinit();
        }
        cursors[0] = .{ .mem = self.memtable.cursorRev(options.end, options.endInclusive) };
        built = 1;
        for (self.sstables.items, 0..) |reader, i| {
            cursors[i + 1] = .{ .sst = try reader.reverseCursor(allocator, options.end, options.endInclusive) };
            built += 1;
        }

        var startCopy: ?[]u8 = null;
        if (options.start) |bound| startCopy = try allocator.dupe(u8, bound);

        return .{
            .resultAllocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cursors = cursors,
            .start = startCopy,
            .startInclusive = options.startInclusive,
            .maxSeq = maxSeq,
        };
    }
};

pub const ScanOptions = struct {
    start: ?[]const u8 = null,
    end: ?[]const u8 = null,
    startInclusive: bool = true,
    endInclusive: bool = false,
};

fn prefixUpperBound(allocator: Allocator, prefix: []const u8) !?[]u8 {
    var end = prefix.len;
    while (end > 0 and prefix[end - 1] == 0xff) end -= 1;
    if (end == 0) return null;
    const upper = try allocator.alloc(u8, end);
    @memcpy(upper, prefix[0..end]);
    upper[end - 1] += 1;
    return upper;
}

pub const Snapshot = struct {
    db: *Db,
    seq: u64,

    pub fn get(self: Snapshot, allocator: Allocator, key: []const u8) !?[]u8 {
        return self.db.getAsOf(allocator, key, self.seq);
    }

    pub fn scan(self: Snapshot, allocator: Allocator, start: ?[]const u8, end: ?[]const u8) !RangeIterator {
        return self.db.scanAsOf(allocator, start, end, self.seq);
    }

    pub fn scanRange(self: Snapshot, allocator: Allocator, options: ScanOptions) !RangeIterator {
        return self.db.scanRangeAsOf(allocator, options, self.seq);
    }

    pub fn scanReverse(self: Snapshot, allocator: Allocator, options: ScanOptions) !ReverseRangeIterator {
        return self.db.scanReverseAsOf(allocator, options, self.seq);
    }

    pub fn scanPrefix(self: Snapshot, allocator: Allocator, prefix: []const u8) !RangeIterator {
        return self.db.scanPrefixAsOf(allocator, prefix, self.seq);
    }
};

const SourceCursor = union(enum) {
    mem: memtable.Cursor,
    sst: sstable.Cursor,

    fn valid(self: *SourceCursor) bool {
        return switch (self.*) {
            .mem => |*c| c.valid(),
            .sst => |*c| c.valid(),
        };
    }

    fn record(self: *SourceCursor) Record {
        return switch (self.*) {
            .mem => |*c| c.record(),
            .sst => |*c| c.record(),
        };
    }

    fn advance(self: *SourceCursor) void {
        switch (self.*) {
            .mem => |*c| c.advance(),
            .sst => |*c| c.advance(),
        }
    }
};

fn pickWinner(cursors: []sstable.Cursor) ?Record {
    var minKey: ?[]const u8 = null;
    for (cursors) |*c| {
        if (c.valid()) {
            const key = c.record().key;
            if (minKey == null or order(key, minKey.?) == .lt) minKey = key;
        }
    }
    if (minKey == null) return null;
    var winner: ?Record = null;
    for (cursors) |*c| {
        if (c.valid() and order(c.record().key, minKey.?) == .eq) {
            const rec = c.record();
            if (winner == null or rec.seq > winner.?.seq) winner = rec;
            c.advance();
        }
    }
    return winner.?;
}

pub const RangeIterator = struct {
    resultAllocator: Allocator,
    arena: std.heap.ArenaAllocator,
    cursors: []SourceCursor,
    start: ?[]u8,
    end: ?[]u8,
    startInclusive: bool,
    endInclusive: bool,
    maxSeq: u64,

    pub fn next(self: *RangeIterator) !?Entry {
        while (true) {
            var minKey: ?[]const u8 = null;
            for (self.cursors) |*c| {
                if (c.valid()) {
                    const key = c.record().key;
                    if (minKey == null or order(key, minKey.?) == .lt) minKey = key;
                }
            }
            if (minKey == null) return null;
            if (self.end) |bound| {
                const past = if (self.endInclusive) order(minKey.?, bound) == .gt else order(minKey.?, bound) != .lt;
                if (past) return null;
            }

            var winner: ?Record = null;
            for (self.cursors) |*c| {
                if (c.valid() and order(c.record().key, minKey.?) == .eq) {
                    const rec = c.record();
                    if (rec.seq <= self.maxSeq and (winner == null or rec.seq > winner.?.seq)) winner = rec;
                    c.advance();
                }
            }
            if (winner == null) continue;
            if (!self.startInclusive) {
                if (self.start) |bound| {
                    if (order(winner.?.key, bound) == .eq) continue;
                }
            }
            if (winner.?.kind == .tombstone) continue;

            const arena = self.arena.allocator();
            return Entry{
                .key = try arena.dupe(u8, winner.?.key),
                .value = try arena.dupe(u8, winner.?.value),
            };
        }
    }

    pub fn deinit(self: *RangeIterator) void {
        self.arena.deinit();
        if (self.start) |bound| self.resultAllocator.free(bound);
        if (self.end) |bound| self.resultAllocator.free(bound);
        self.resultAllocator.free(self.cursors);
    }
};

const ReverseSource = union(enum) {
    mem: memtable.ReverseCursor,
    sst: sstable.ReverseCursor,

    fn valid(self: *ReverseSource) bool {
        return switch (self.*) {
            .mem => |*c| c.valid(),
            .sst => |*c| c.valid(),
        };
    }

    fn record(self: *ReverseSource) Record {
        return switch (self.*) {
            .mem => |*c| c.record(),
            .sst => |*c| c.record(),
        };
    }

    fn advance(self: *ReverseSource) void {
        switch (self.*) {
            .mem => |*c| c.advance(),
            .sst => |*c| c.advance(),
        }
    }

    fn deinit(self: *ReverseSource) void {
        switch (self.*) {
            .mem => {},
            .sst => |*c| c.deinit(),
        }
    }
};

pub const ReverseRangeIterator = struct {
    resultAllocator: Allocator,
    arena: std.heap.ArenaAllocator,
    cursors: []ReverseSource,
    start: ?[]u8,
    startInclusive: bool,
    maxSeq: u64,

    pub fn next(self: *ReverseRangeIterator) !?Entry {
        while (true) {
            var maxKey: ?[]const u8 = null;
            for (self.cursors) |*c| {
                if (c.valid()) {
                    const key = c.record().key;
                    if (maxKey == null or order(key, maxKey.?) == .gt) maxKey = key;
                }
            }
            if (maxKey == null) return null;
            if (self.start) |bound| {
                const past = if (self.startInclusive) order(maxKey.?, bound) == .lt else order(maxKey.?, bound) != .gt;
                if (past) return null;
            }

            var winner: ?Record = null;
            for (self.cursors) |*c| {
                if (c.valid() and order(c.record().key, maxKey.?) == .eq) {
                    const rec = c.record();
                    if (rec.seq <= self.maxSeq and (winner == null or rec.seq > winner.?.seq)) winner = rec;
                    c.advance();
                }
            }
            if (winner == null) continue;
            if (winner.?.kind == .tombstone) continue;

            const arena = self.arena.allocator();
            return Entry{
                .key = try arena.dupe(u8, winner.?.key),
                .value = try arena.dupe(u8, winner.?.value),
            };
        }
    }

    pub fn deinit(self: *ReverseRangeIterator) void {
        self.arena.deinit();
        for (self.cursors) |*c| c.deinit();
        if (self.start) |bound| self.resultAllocator.free(bound);
        self.resultAllocator.free(self.cursors);
    }
};

fn rangesOverlap(aMin: []const u8, aMax: []const u8, bMin: []const u8, bMax: []const u8) bool {
    return order(aMin, bMax) != .gt and order(bMin, aMax) != .gt;
}

fn loadManifest(allocator: Allocator, dir: std.fs.Dir) !std.AutoHashMap(u64, usize) {
    var map = std.AutoHashMap(u64, usize).init(allocator);
    errdefer map.deinit();

    const file = dir.openFile(manifestName, .{}) catch |err| switch (err) {
        error.FileNotFound => return map,
        else => return err,
    };
    defer file.close();
    const data = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(data);
    if (data.len < 8) return map;

    const storedCrc = encode.readU32(data, 0);
    const body = data[4..];
    if (encode.crc(body) != storedCrc) return map;

    const count = encode.readU32(body, 0);
    var pos: usize = 4;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        if (pos + 12 > body.len) break;
        const fileId = encode.readU64(body, pos);
        const level = encode.readU32(body, pos + 8);
        try map.put(fileId, level);
        pos += 12;
    }
    return map;
}

fn sstName(buf: []u8, id: u64) ![]const u8 {
    return std.fmt.bufPrint(buf, "sst-{d:0>10}.cbt", .{id});
}

fn parseSstId(name: []const u8) ?u64 {
    const prefix = "sst-";
    const suffix = ".cbt";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    const digits = name[prefix.len .. name.len - suffix.len];
    return std.fmt.parseInt(u64, digits, 10) catch null;
}

