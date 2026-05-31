const std = @import("std");
const encode = @import("encode.zig");
const memtable = @import("memtable.zig");
const sstable = @import("sstable.zig");
const cache = @import("cache.zig");
const statsmod = @import("stats.zig");
const heap = @import("heap.zig");
const version = @import("version.zig");
const walmod = @import("wal.zig");
const Wal = walmod.Wal;

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Record = encode.Record;
const Memtable = memtable.Memtable;
const Reader = sstable.Reader;
const Builder = sstable.Builder;
const BlockCache = cache.BlockCache;
const VersionSet = version.VersionSet;
const VersionEdit = version.VersionEdit;

pub const WriteBatch = @import("batch.zig").WriteBatch;
pub const Stats = statsmod.Stats;

fn order(a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, a, b);
}

const walName = "wal.log";

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
    versionSet: VersionSet,
    versionState: std.AutoHashMap(u64, usize),
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

        var opened = try VersionSet.open(allocator, dir);
        errdefer opened.set.close();
        errdefer opened.state.deinit();
        for (sstables.items) |reader| {
            reader.level = opened.state.get(reader.fileId) orelse 0;
        }

        var table = try Memtable.init(allocator);
        errdefer table.deinit();
        var wal = try Wal.open(allocator, dir, walName);
        errdefer wal.close();
        const walMaxSeq = try wal.replay(&table);
        if (walMaxSeq > maxSeq) maxSeq = walMaxSeq;

        // The directory scan alone can regress: a leveled compaction that
        // fully garbage-collects a run of tombstones produces zero output
        // files (see runMerge), so no fresh fileId is minted and the
        // deleted inputs' seq/fileId watermark vanishes from disk. The
        // manifest's persisted counters (stamped on every flush/compact,
        // see VersionEdit.nextFileId/nextSeq) are the authoritative floor
        // for exactly that case; take whichever recovery source is higher
        // so this is purely additive safety, never a regression versus the
        // scan-only behaviour this project already relied on.
        const scanNextFileId = maxId + 1;
        const scanNextSeq = maxSeq + 1;
        const nextFileId = @max(scanNextFileId, opened.set.counters.nextFileId orelse 0);
        const nextSeq = @max(scanNextSeq, opened.set.counters.nextSeq orelse 0);

        const dirPathCopy = try allocator.dupe(u8, dirPath);

        return .{
            .allocator = allocator,
            .dir = dir,
            .dirPath = dirPathCopy,
            .memtable = table,
            .wal = wal,
            .sstables = sstables,
            .blockCache = BlockCache.init(allocator, options.blockCacheBytes),
            .versionSet = opened.set,
            .versionState = opened.state,
            .nextFileId = nextFileId,
            .nextSeq = nextSeq,
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
        self.versionSet.close();
        self.versionState.deinit();
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
        _ = try walmod.bumpGeneration(self.dir);

        var edit = VersionEdit.init(self.allocator);
        defer edit.deinit();
        try edit.addFile(fileId, 0);
        edit.setNextFileId(self.nextFileId);
        edit.setNextSeq(self.nextSeq);
        try self.versionSet.logAndApply(&edit, &self.versionState);
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
            var merger = try SstableMerger.init(self.allocator, cursors);
            defer merger.deinit();
            while (try merger.next()) |winner| {
                if (winner.kind == .value) try builder.add(winner);
            }
            try builder.finish();
        }

        const reader = try self.allocator.create(Reader);
        errdefer self.allocator.destroy(reader);
        reader.* = try Reader.open(self.allocator, self.dir, name, fileId);
        errdefer reader.deinit();

        var edit = VersionEdit.init(self.allocator);
        defer edit.deinit();
        for (self.sstables.items) |old| {
            try edit.deleteFile(old.fileId);
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
        try edit.addFile(fileId, 0);
        edit.setNextFileId(self.nextFileId);
        edit.setNextSeq(self.nextSeq);
        try self.versionSet.logAndApply(&edit, &self.versionState);
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

        var merger = try SstableMerger.init(self.allocator, cursors);
        defer merger.deinit();
        while (try merger.next()) |winner| {
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

        var edit = VersionEdit.init(self.allocator);
        defer edit.deinit();
        for (inputs) |old| {
            try edit.deleteFile(old.fileId);
            self.removeReader(old);
            var oldNameBuf: [64]u8 = undefined;
            const oldName = sstName(&oldNameBuf, old.fileId) catch unreachable;
            old.deinit();
            self.allocator.destroy(old);
            self.dir.deleteFile(oldName) catch {};
        }
        for (outputs.items) |produced| {
            try edit.addFile(produced.fileId, produced.level);
            try self.sstables.append(produced);
        }
        outputs.deinit();

        // Stamped even when this round produced zero output files (every
        // input was a dropped tombstone): that is exactly the case where no
        // fresh fileId gets minted and a directory scan on the next restart
        // could otherwise regress below the seq/fileId already consumed by
        // the now-deleted inputs (see the comment on VersionEdit.nextFileId
        // and Db.open's counter merge).
        edit.setNextFileId(self.nextFileId);
        edit.setNextSeq(self.nextSeq);
        try self.versionSet.logAndApply(&edit, &self.versionState);
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

        var mergeHeap = AscKeyHeap.init(allocator, {});
        errdefer mergeHeap.deinit();
        for (cursors, 0..) |*c, i| {
            if (c.valid()) try mergeHeap.push(.{ .key = c.record().key, .idx = i });
        }

        var startCopy: ?[]u8 = null;
        errdefer if (startCopy) |s| allocator.free(s);
        if (options.start) |bound| startCopy = try allocator.dupe(u8, bound);
        var endCopy: ?[]u8 = null;
        if (options.end) |bound| endCopy = try allocator.dupe(u8, bound);

        return .{
            .resultAllocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cursors = cursors,
            .heap = mergeHeap,
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

        var mergeHeap = DescKeyHeap.init(allocator, {});
        errdefer mergeHeap.deinit();
        for (cursors, 0..) |*c, i| {
            if (c.valid()) try mergeHeap.push(.{ .key = c.record().key, .idx = i });
        }

        var startCopy: ?[]u8 = null;
        if (options.start) |bound| startCopy = try allocator.dupe(u8, bound);

        return .{
            .resultAllocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cursors = cursors,
            .heap = mergeHeap,
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

/// One live position in a k-way merge: the key it currently points at
/// (a snapshot valid for the underlying source's whole lifetime, since
/// sstable/memtable cursors never overwrite already-decoded key bytes)
/// plus the index of the source cursor it belongs to.
const KeyedIndex = struct { key: []const u8, idx: usize };

fn keyIndexLess(_: void, a: KeyedIndex, b: KeyedIndex) bool {
    return order(a.key, b.key) == .lt;
}
fn keyIndexGreater(_: void, a: KeyedIndex, b: KeyedIndex) bool {
    return order(a.key, b.key) == .gt;
}

/// Ascending k-way merge heap: root always holds the smallest live key.
const AscKeyHeap = heap.MinHeap(KeyedIndex, void, keyIndexLess);
/// Descending k-way merge heap: root always holds the largest live key.
const DescKeyHeap = heap.MinHeap(KeyedIndex, void, keyIndexGreater);

/// Merges N sorted sstable cursors (compaction inputs) in ascending key
/// order using a binary heap: O(log N) per advance instead of the O(N)
/// full rescan a naive linear-scan merge needs for every emitted record.
/// Ties (same key present in several inputs) resolve to the entry with
/// the highest seq, matching last-writer-wins semantics.
const SstableMerger = struct {
    cursors: []sstable.Cursor,
    heap: AscKeyHeap,

    fn init(allocator: Allocator, cursors: []sstable.Cursor) !SstableMerger {
        var h = AscKeyHeap.init(allocator, {});
        errdefer h.deinit();
        for (cursors, 0..) |*c, i| {
            if (c.valid()) try h.push(.{ .key = c.record().key, .idx = i });
        }
        return .{ .cursors = cursors, .heap = h };
    }

    fn deinit(self: *SstableMerger) void {
        self.heap.deinit();
    }

    fn next(self: *SstableMerger) !?Record {
        const top = self.heap.peek() orelse return null;
        const minKey = top.key;
        var winner: ?Record = null;
        while (self.heap.peek()) |entry| {
            if (order(entry.key, minKey) != .eq) break;
            const popped = self.heap.pop().?;
            var c = &self.cursors[popped.idx];
            const rec = c.record();
            if (winner == null or rec.seq > winner.?.seq) winner = rec;
            c.advance();
            if (c.valid()) try self.heap.push(.{ .key = c.record().key, .idx = popped.idx });
        }
        return winner.?;
    }
};

pub const RangeIterator = struct {
    resultAllocator: Allocator,
    arena: std.heap.ArenaAllocator,
    cursors: []SourceCursor,
    heap: AscKeyHeap,
    start: ?[]u8,
    end: ?[]u8,
    startInclusive: bool,
    endInclusive: bool,
    maxSeq: u64,

    pub fn next(self: *RangeIterator) !?Entry {
        while (true) {
            const top = self.heap.peek() orelse return null;
            const minKey = top.key;
            if (self.end) |bound| {
                const past = if (self.endInclusive) order(minKey, bound) == .gt else order(minKey, bound) != .lt;
                if (past) return null;
            }

            var winner: ?Record = null;
            while (self.heap.peek()) |entry| {
                if (order(entry.key, minKey) != .eq) break;
                const popped = self.heap.pop().?;
                var c = &self.cursors[popped.idx];
                const rec = c.record();
                if (rec.seq <= self.maxSeq and (winner == null or rec.seq > winner.?.seq)) winner = rec;
                c.advance();
                if (c.valid()) try self.heap.push(.{ .key = c.record().key, .idx = popped.idx });
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
        self.heap.deinit();
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
    heap: DescKeyHeap,
    start: ?[]u8,
    startInclusive: bool,
    maxSeq: u64,

    pub fn next(self: *ReverseRangeIterator) !?Entry {
        while (true) {
            const top = self.heap.peek() orelse return null;
            const maxKey = top.key;
            if (self.start) |bound| {
                const past = if (self.startInclusive) order(maxKey, bound) == .lt else order(maxKey, bound) != .gt;
                if (past) return null;
            }

            var winner: ?Record = null;
            while (self.heap.peek()) |entry| {
                if (order(entry.key, maxKey) != .eq) break;
                const popped = self.heap.pop().?;
                var c = &self.cursors[popped.idx];
                const rec = c.record();
                if (rec.seq <= self.maxSeq and (winner == null or rec.seq > winner.?.seq)) winner = rec;
                c.advance();
                if (c.valid()) try self.heap.push(.{ .key = c.record().key, .idx = popped.idx });
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
        self.heap.deinit();
        for (self.cursors) |*c| c.deinit();
        if (self.start) |bound| self.resultAllocator.free(bound);
        self.resultAllocator.free(self.cursors);
    }
};

fn rangesOverlap(aMin: []const u8, aMax: []const u8, bMin: []const u8, bMax: []const u8) bool {
    return order(aMin, bMax) != .gt and order(bMin, aMax) != .gt;
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

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator, options: Options) !Db {
    var pathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathBuf);
    var dbPathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const dbPath = try std.fmt.bufPrint(&dbPathBuf, "{s}/store", .{base});
    return Db.open(allocator, dbPath, options);
}

test "put get delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    try db.put("apple", "red");
    try db.put("banana", "yellow");

    const apple = (try db.get(allocator, "apple")).?;
    defer allocator.free(apple);
    try std.testing.expectEqualStrings("red", apple);

    try db.put("apple", "green");
    const apple2 = (try db.get(allocator, "apple")).?;
    defer allocator.free(apple2);
    try std.testing.expectEqualStrings("green", apple2);

    try db.delete("apple");
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "apple"));

    const banana = (try db.get(allocator, "banana")).?;
    defer allocator.free(banana);
    try std.testing.expectEqualStrings("yellow", banana);
}

test "wal recovery after reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator, .{});
        defer db.close();
        try db.put("city", "warsaw");
        try db.put("river", "vistula");
        try db.delete("city");
        try std.testing.expectEqual(@as(usize, 0), db.sstables.items.len);
    }

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();
    try std.testing.expectEqual(@as(usize, 0), db.sstables.items.len);
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "city"));
    const river = (try db.get(allocator, "river")).?;
    defer allocator.free(river);
    try std.testing.expectEqualStrings("vistula", river);
}

test "flush to sstable and reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 64 });
        defer db.close();
        var buf: [16]u8 = undefined;
        var i: usize = 0;
        while (i < 200) : (i += 1) {
            const key = try std.fmt.bufPrint(&buf, "k{d:0>5}", .{i});
            try db.put(key, "value-payload");
        }
        try std.testing.expect(db.sstables.items.len > 0);
    }

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 64 });
    defer db.close();
    var buf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "k{d:0>5}", .{i});
        const got = (try db.get(allocator, key)).?;
        defer allocator.free(got);
        try std.testing.expectEqualStrings("value-payload", got);
    }
}

test "compaction dedups and drops tombstones" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 1 });
    defer db.close();

    try db.put("a", "1");
    try db.put("b", "2");
    try db.put("c", "3");
    try db.put("d", "4");
    try db.put("a", "11");
    try db.delete("c");
    try db.flush();

    try std.testing.expect(db.sstables.items.len > 1);
    try db.compact();
    try std.testing.expectEqual(@as(usize, 1), db.sstables.items.len);

    const a = (try db.get(allocator, "a")).?;
    defer allocator.free(a);
    try std.testing.expectEqualStrings("11", a);

    const b = (try db.get(allocator, "b")).?;
    defer allocator.free(b);
    try std.testing.expectEqualStrings("2", b);

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "c"));

    const d = (try db.get(allocator, "d")).?;
    defer allocator.free(d);
    try std.testing.expectEqualStrings("4", d);
}

test "scan merges memtable and sstable with tombstones" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    try db.put("a", "1");
    try db.put("b", "2");
    try db.put("c", "3");
    try db.put("d", "4");
    try db.put("e", "5");
    try db.flush();

    try db.put("c", "cNew");
    try db.delete("b");

    var iter = try db.scan(allocator, null, null);
    defer iter.deinit();

    const expectedKeys = [_][]const u8{ "a", "c", "d", "e" };
    const expectedVals = [_][]const u8{ "1", "cNew", "4", "5" };
    var idx: usize = 0;
    while (try iter.next()) |item| {
        try std.testing.expect(idx < expectedKeys.len);
        try std.testing.expectEqualStrings(expectedKeys[idx], item.key);
        try std.testing.expectEqualStrings(expectedVals[idx], item.value);
        idx += 1;
    }
    try std.testing.expectEqual(expectedKeys.len, idx);
}

test "scan honors range bounds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 32 });
    defer db.close();

    var keyBuf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 26) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "{c}", .{@as(u8, 'a') + @as(u8, @intCast(i))});
        try db.put(key, "x");
    }

    var iter = try db.scan(allocator, "d", "h");
    defer iter.deinit();
    const expected = [_][]const u8{ "d", "e", "f", "g" };
    var idx: usize = 0;
    while (try iter.next()) |item| {
        try std.testing.expect(idx < expected.len);
        try std.testing.expectEqualStrings(expected[idx], item.key);
        idx += 1;
    }
    try std.testing.expectEqual(expected.len, idx);
}

test "snapshot reads pre-overwrite value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    try db.put("color", "red");
    try db.put("shape", "circle");

    var snap = try db.snapshot();

    try db.put("color", "green");
    try db.delete("shape");
    try db.put("color", "blue");

    const snapColor = (try snap.get(allocator, "color")).?;
    defer allocator.free(snapColor);
    try std.testing.expectEqualStrings("red", snapColor);

    const snapShape = (try snap.get(allocator, "shape")).?;
    defer allocator.free(snapShape);
    try std.testing.expectEqualStrings("circle", snapShape);

    const liveColor = (try db.get(allocator, "color")).?;
    defer allocator.free(liveColor);
    try std.testing.expectEqualStrings("blue", liveColor);

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "shape"));

    var snapIter = try snap.scan(allocator, null, null);
    defer snapIter.deinit();
    var snapCount: usize = 0;
    while (try snapIter.next()) |entry| {
        if (std.mem.eql(u8, entry.key, "color")) try std.testing.expectEqualStrings("red", entry.value);
        snapCount += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), snapCount);
}

test "write batch applies all or nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var db = try openTemp(&tmp, allocator, .{});
        defer db.close();

        try db.put("existing", "keep");
        const seqBefore = db.nextSeq;

        var batch = WriteBatch.init(allocator);
        defer batch.deinit();
        try batch.put("one", "1");
        try batch.put("two", "2");
        try batch.put("three", "3");
        try batch.delete("existing");
        try db.apply(&batch);

        try std.testing.expectEqual(seqBefore + 4, db.nextSeq);

        const one = (try db.get(allocator, "one")).?;
        defer allocator.free(one);
        try std.testing.expectEqualStrings("1", one);
        const three = (try db.get(allocator, "three")).?;
        defer allocator.free(three);
        try std.testing.expectEqualStrings("3", three);
        try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "existing"));
    }

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();
    const two = (try db.get(allocator, "two")).?;
    defer allocator.free(two);
    try std.testing.expectEqualStrings("2", two);
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "existing"));
}

test "block cache serves repeated reads" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    try db.put("alpha", "one");
    try db.put("bravo", "two");
    try db.flush();

    const first = (try db.get(allocator, "alpha")).?;
    allocator.free(first);
    try std.testing.expect(db.blockCache.stats.misses >= 1);

    const hitsBefore = db.blockCache.stats.hits;
    const second = (try db.get(allocator, "alpha")).?;
    allocator.free(second);
    try std.testing.expect(db.blockCache.stats.hits > hitsBefore);
}

test "leveled compaction keeps levels disjoint and drops bottom tombstones" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{
        .flushThreshold = 512,
        .l0CompactionTrigger = 2,
        .l1BaseBytes = 4 * 1024 * 1024,
        .sstableTargetBytes = 2048,
    });
    defer db.close();

    var keyBuf: [16]u8 = undefined;
    const payload = "x" ** 120;
    var i: usize = 0;
    while (i < 60) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>4}", .{i});
        try db.put(key, payload);
    }
    try db.delete("key:0005");
    try db.delete("key:0025");
    try db.flush();

    try db.maybeCompact();

    try std.testing.expectEqual(@as(usize, 0), db.countLevel(0));
    try std.testing.expect(db.sstables.items.len >= 2);

    var live: usize = 0;
    var totalEntries: u64 = 0;
    for (db.sstables.items) |reader| {
        try std.testing.expect(reader.level >= 1);
        totalEntries += reader.numEntries;
    }

    var levelOneReaders = std.ArrayList(*Reader).init(allocator);
    defer levelOneReaders.deinit();
    for (db.sstables.items) |reader| {
        if (reader.level == 1) try levelOneReaders.append(reader);
    }
    std.mem.sort(*Reader, levelOneReaders.items, {}, lessByMinKey);
    var r: usize = 1;
    while (r < levelOneReaders.items.len) : (r += 1) {
        try std.testing.expect(order(levelOneReaders.items[r - 1].maxKey, levelOneReaders.items[r].minKey) == .lt);
    }

    i = 0;
    while (i < 60) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>4}", .{i});
        if (i == 5 or i == 25) {
            try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, key));
        } else {
            const got = (try db.get(allocator, key)).?;
            defer allocator.free(got);
            try std.testing.expectEqualStrings(payload, got);
            live += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 58), live);
    try std.testing.expectEqual(@as(u64, 58), totalEntries);
}

test "seq and fileId counters survive a compaction that garbage-collects every key" {
    // Reproduces a real recovery gap: when a bottom-level compaction merges
    // inputs that are entirely tombstones, runMerge produces zero output
    // files (see the `builder == null` guard around minting a fresh
    // fileId). If every file that ever carried a high seq/fileId gets
    // deleted in that round and nothing new gets flushed before a restart,
    // a directory-scan-only recovery would compute too low a floor and
    // risk reusing already-consumed seq numbers. The manifest's persisted
    // counters (VersionEdit.nextFileId/nextSeq, stamped unconditionally in
    // runMerge) must close that gap.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var beforeNextSeq: u64 = 0;
    var beforeNextFileId: u64 = 0;
    {
        var db = try openTemp(&tmp, allocator, .{
            .l0CompactionTrigger = 2,
            .l1BaseBytes = 4 * 1024 * 1024,
        });
        defer db.close();

        var keyBuf: [16]u8 = undefined;
        var round: usize = 0;
        while (round < 2) : (round += 1) {
            const key = try std.fmt.bufPrint(&keyBuf, "gone:{d}", .{round});
            try db.put(key, "value");
            try db.delete(key);
            try db.flush();
        }
        try std.testing.expectEqual(@as(usize, 2), db.countLevel(0));

        try db.maybeCompact();

        // The whole point: every input was a dropped tombstone, so the
        // compaction round produced no output file at all, and no new
        // fileId was ever minted for it.
        try std.testing.expectEqual(@as(usize, 0), db.sstables.items.len);

        beforeNextSeq = db.nextSeq;
        beforeNextFileId = db.nextFileId;
        try std.testing.expect(beforeNextSeq > 1);
    }

    // On disk right now: no sstable files, an empty (reset) WAL. A
    // scan-only recovery would compute nextSeq=1/nextFileId=1 here.
    var reopened = try openTemp(&tmp, allocator, .{
        .l0CompactionTrigger = 2,
        .l1BaseBytes = 4 * 1024 * 1024,
    });
    defer reopened.close();
    try std.testing.expectEqual(beforeNextSeq, reopened.nextSeq);
    try std.testing.expectEqual(beforeNextFileId, reopened.nextFileId);

    // Functional proof, not just counter equality: a fresh write after
    // reopen must not reuse a seq number already spent on the GC'd keys.
    try reopened.put("fresh", "value");
    try std.testing.expect(reopened.nextSeq > beforeNextSeq);
}

fn lessByMinKey(_: void, a: *Reader, b: *Reader) bool {
    return order(a.minKey, b.minKey) == .lt;
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

test "reverse scan yields descending order merging sources" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 48 });
    defer db.close();

    var keyBuf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 26) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "{c}", .{@as(u8, 'a') + @as(u8, @intCast(i))});
        try db.put(key, "old");
    }
    try db.put("m", "fresh");
    try db.delete("d");

    var iter = try db.scanReverse(allocator, .{});
    defer iter.deinit();
    var prev: [8]u8 = undefined;
    var prevLen: usize = 0;
    var count: usize = 0;
    var sawFreshM = false;
    var sawD = false;
    while (try iter.next()) |entry| {
        if (prevLen > 0) try std.testing.expect(order(entry.key, prev[0..prevLen]) == .lt);
        @memcpy(prev[0..entry.key.len], entry.key);
        prevLen = entry.key.len;
        if (std.mem.eql(u8, entry.key, "m")) {
            try std.testing.expectEqualStrings("fresh", entry.value);
            sawFreshM = true;
        }
        if (std.mem.eql(u8, entry.key, "d")) sawD = true;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 25), count);
    try std.testing.expect(sawFreshM);
    try std.testing.expect(!sawD);
}

test "prefix scan isolates a namespace" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 64 });
    defer db.close();

    try db.put("user:alice", "1");
    try db.put("user:bob", "2");
    try db.put("user:carol", "3");
    try db.put("post:1", "x");
    try db.put("userx", "y");
    try db.put("zzz", "z");

    var iter = try db.scanPrefix(allocator, "user:");
    defer iter.deinit();
    const expected = [_][]const u8{ "user:alice", "user:bob", "user:carol" };
    var idx: usize = 0;
    while (try iter.next()) |entry| {
        try std.testing.expect(idx < expected.len);
        try std.testing.expectEqualStrings(expected[idx], entry.key);
        idx += 1;
    }
    try std.testing.expectEqual(expected.len, idx);
}

test "scan merges a wide fan-in of uncompacted sstables with overlapping keys" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 1 });
    defer db.close();

    const sstableCount = 14;
    var round: usize = 0;
    while (round < sstableCount) : (round += 1) {
        var keyBuf: [16]u8 = undefined;
        var valBuf: [24]u8 = undefined;
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            const key = try std.fmt.bufPrint(&keyBuf, "shared:{d:0>2}", .{i});
            const value = try std.fmt.bufPrint(&valBuf, "round{d}", .{round});
            try db.put(key, value);
        }
        try db.flush();
    }
    try db.delete("shared:02");
    try db.flush();
    try std.testing.expect(db.sstables.items.len >= sstableCount + 1);

    var forward = try db.scan(allocator, null, null);
    defer forward.deinit();
    var seen: usize = 0;
    while (try forward.next()) |entry| {
        if (std.mem.eql(u8, entry.key, "shared:02")) {
            try std.testing.expect(false);
        }
        try std.testing.expectEqualStrings("round13", entry.value);
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), seen);

    var reverse = try db.scanReverse(allocator, .{});
    defer reverse.deinit();
    var revSeen: usize = 0;
    var lastKey: ?[]const u8 = null;
    while (try reverse.next()) |entry| {
        if (lastKey) |prev| try std.testing.expect(order(entry.key, prev) == .lt);
        lastKey = entry.key;
        try std.testing.expectEqualStrings("round13", entry.value);
        revSeen += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), revSeen);
}

test "inclusive and exclusive bounds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    var keyBuf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "k{d}", .{i});
        try db.put(key, "v");
    }

    {
        var iter = try db.scanRange(allocator, .{ .start = "k2", .end = "k5", .startInclusive = true, .endInclusive = true });
        defer iter.deinit();
        const expected = [_][]const u8{ "k2", "k3", "k4", "k5" };
        var idx: usize = 0;
        while (try iter.next()) |entry| {
            try std.testing.expectEqualStrings(expected[idx], entry.key);
            idx += 1;
        }
        try std.testing.expectEqual(expected.len, idx);
    }
    {
        var iter = try db.scanRange(allocator, .{ .start = "k2", .end = "k5", .startInclusive = false, .endInclusive = false });
        defer iter.deinit();
        const expected = [_][]const u8{ "k3", "k4" };
        var idx: usize = 0;
        while (try iter.next()) |entry| {
            try std.testing.expectEqualStrings(expected[idx], entry.key);
            idx += 1;
        }
        try std.testing.expectEqual(expected.len, idx);
    }
}

fn setLive(map: *std.StringHashMap([]const u8), arena: Allocator, key: []const u8, value: []const u8) !void {
    const gop = try map.getOrPut(key);
    if (!gop.found_existing) gop.key_ptr.* = try arena.dupe(u8, key);
    gop.value_ptr.* = try arena.dupe(u8, value);
}

test "scan matches sorted reference across flush restart and compaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var refArena = std.heap.ArenaAllocator.init(allocator);
    defer refArena.deinit();
    const arena = refArena.allocator();

    var live = std.StringHashMap([]const u8).init(allocator);
    defer live.deinit();

    const keyspace = 300;
    const ops = 4000;
    var prng = std.Random.DefaultPrng.init(0xC0BA17);
    const random = prng.random();

    {
        var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 2048, .sstableTargetBytes = 1024 });
        defer db.close();

        var keyBuf: [16]u8 = undefined;
        var valBuf: [24]u8 = undefined;
        var op: usize = 0;
        while (op < ops) : (op += 1) {
            const id = random.intRangeLessThan(usize, 0, keyspace);
            const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>6}", .{id});
            if (random.intRangeLessThan(usize, 0, 10) < 3) {
                try db.delete(key);
                _ = live.remove(key);
            } else {
                const value = try std.fmt.bufPrint(&valBuf, "val-{d}-{d}", .{ id, random.int(u16) });
                try db.put(key, value);
                try setLive(&live, arena, key, value);
            }
            if (random.intRangeLessThan(usize, 0, 200) == 0) try db.flush();
        }
        try db.maybeCompact();
    }

    var db = try openTemp(&tmp, allocator, .{ .flushThreshold = 2048, .sstableTargetBytes = 1024 });
    defer db.close();

    var sortedKeys = std.ArrayList([]const u8).init(allocator);
    defer sortedKeys.deinit();
    var keyIt = live.keyIterator();
    while (keyIt.next()) |key| try sortedKeys.append(key.*);
    std.mem.sort([]const u8, sortedKeys.items, {}, lessString);

    var forward = try db.scan(allocator, null, null);
    defer forward.deinit();
    var idx: usize = 0;
    while (try forward.next()) |entry| {
        try std.testing.expect(idx < sortedKeys.items.len);
        try std.testing.expectEqualStrings(sortedKeys.items[idx], entry.key);
        try std.testing.expectEqualStrings(live.get(entry.key).?, entry.value);
        idx += 1;
    }
    try std.testing.expectEqual(sortedKeys.items.len, idx);

    var reverse = try db.scanReverse(allocator, .{});
    defer reverse.deinit();
    idx = sortedKeys.items.len;
    while (try reverse.next()) |entry| {
        try std.testing.expect(idx > 0);
        idx -= 1;
        try std.testing.expectEqualStrings(sortedKeys.items[idx], entry.key);
        try std.testing.expectEqualStrings(live.get(entry.key).?, entry.value);
    }
    try std.testing.expectEqual(@as(usize, 0), idx);

    for (sortedKeys.items) |key| {
        const got = (try db.get(allocator, key)).?;
        defer allocator.free(got);
        try std.testing.expectEqualStrings(live.get(key).?, got);
    }
}

test "crash recovery honors wal durability boundary" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const total = 8;
    {
        var db = try openTemp(&tmp, allocator, .{});
        defer db.close();
        var keyBuf: [8]u8 = undefined;
        var i: usize = 0;
        while (i < total) : (i += 1) {
            const key = try std.fmt.bufPrint(&keyBuf, "wkey{d}", .{i});
            try db.put(key, "durable");
        }
        try std.testing.expectEqual(@as(usize, 0), db.sstables.items.len);
    }

    {
        const walFile = try tmp.dir.openFile("store/wal.log", .{ .mode = .read_write });
        defer walFile.close();
        const size = try walFile.getEndPos();
        try walFile.setEndPos(size - 1);
        try walFile.sync();
    }

    var db = try openTemp(&tmp, allocator, .{});
    defer db.close();

    var keyBuf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < total - 1) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "wkey{d}", .{i});
        const got = (try db.get(allocator, key)).?;
        defer allocator.free(got);
        try std.testing.expectEqualStrings("durable", got);
    }
    const lastKey = try std.fmt.bufPrint(&keyBuf, "wkey{d}", .{total - 1});
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, lastKey));
}
