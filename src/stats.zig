const std = @import("std");

pub const maxTrackedLevels = 8;

pub const LevelStat = struct {
    tables: usize = 0,
    entries: u64 = 0,
    physicalBytes: u64 = 0,
};

pub const Stats = struct {
    memtableEntries: usize = 0,
    memtableBytes: usize = 0,
    sstableCount: usize = 0,
    liveEntries: u64 = 0,
    physicalBytes: u64 = 0,
    cacheHits: u64 = 0,
    cacheMisses: u64 = 0,
    nextSeq: u64 = 0,
    levels: [maxTrackedLevels]LevelStat = [_]LevelStat{.{}} ** maxTrackedLevels,

    pub fn cacheHitRate(self: Stats) f64 {
        const total = self.cacheHits + self.cacheMisses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.cacheHits)) / @as(f64, @floatFromInt(total));
    }

    pub fn deepestLevel(self: Stats) usize {
        var deepest: usize = 0;
        for (self.levels, 0..) |level, i| {
            if (level.tables > 0) deepest = i;
        }
        return deepest;
    }

    pub fn print(self: Stats, writer: anytype) !void {
        try writer.print("memtable    entries={d} bytes={d}\n", .{ self.memtableEntries, self.memtableBytes });
        try writer.print("sstables    count={d} entries={d} physicalBytes={d}\n", .{ self.sstableCount, self.liveEntries, self.physicalBytes });
        try writer.print("nextSeq     {d}\n", .{self.nextSeq});
        try writer.print("blockCache  hits={d} misses={d} hitRate={d:.3}\n", .{ self.cacheHits, self.cacheMisses, self.cacheHitRate() });
        var i: usize = 0;
        const deepest = self.deepestLevel();
        while (i <= deepest) : (i += 1) {
            const level = self.levels[i];
            try writer.print("  L{d}        tables={d} entries={d} physicalBytes={d}\n", .{ i, level.tables, level.entries, level.physicalBytes });
        }
    }
};
