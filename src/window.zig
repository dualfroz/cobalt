const std = @import("std");
const rowmod = @import("row.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;
const Value = rowmod.Value;
const Row = rowmod.Row;

pub const WindowKind = enum {
    row_number,
    rank,
    dense_rank,
    sum,
    avg,
    count,
    count_distinct,
    min,
    max,
    lag,
    lead,
    first_value,
    last_value,
    nth_value,
};

pub const WindowSpec = struct {
    field: []const u8,
    kind: WindowKind,
    offset: u64 = 1,
    default: Value = .{ .none = {} },
};

pub const WindowError = error{
    NonNumericField,
    Overflow,
    MissingField,
    RangeNotApplicable,
} || Allocator.Error;

pub const FrameMode = enum {
    rows,
    range,
};

fn isRanking(kind: WindowKind) bool {
    return kind == .row_number or kind == .rank or kind == .dense_rank;
}

fn isOffsetLookup(kind: WindowKind) bool {
    return kind == .lag or kind == .lead;
}

fn isFrameValue(kind: WindowKind) bool {
    return kind == .first_value or kind == .last_value or kind == .nth_value;
}

pub fn specLabel(allocator: Allocator, spec: WindowSpec) Allocator.Error![]u8 {
    if (spec.field.len == 0) return allocator.dupe(u8, @tagName(spec.kind));
    return std.fmt.allocPrint(allocator, "{s}_{s}", .{ @tagName(spec.kind), spec.field });
}

const RunningAcc = struct {
    kind: WindowKind,
    field: []const u8,
    n: u64 = 0,
    sumInt: i64 = 0,
    sumFloat: f64 = 0,
    allInt: bool = true,
    minv: ?Value = null,
    maxv: ?Value = null,
    distinct: std.StringHashMapUnmanaged(void) = .{},

    fn observe(self: *RunningAcc, allocator: Allocator, row: *const Row) WindowError!void {
        switch (self.kind) {
            .count => {
                if (self.field.len == 0 or row.get(self.field) != null) self.n += 1;
            },
            .count_distinct => {
                const v = row.get(self.field) orelse return;
                const key = try rowmod.encodeValue(allocator, v);
                const res = try self.distinct.getOrPut(allocator, key);
                if (res.found_existing) allocator.free(key);
            },
            .sum, .avg => {
                const v = row.get(self.field) orelse return;
                switch (v) {
                    .int => |i| {
                        if (self.allInt) {
                            self.sumInt = std.math.add(i64, self.sumInt, i) catch return error.Overflow;
                        } else {
                            self.sumFloat += @floatFromInt(i);
                        }
                    },
                    .float => |f| {
                        if (self.allInt) {
                            self.sumFloat = @floatFromInt(self.sumInt);
                            self.allInt = false;
                        }
                        self.sumFloat += f;
                    },
                    else => return error.NonNumericField,
                }
                self.n += 1;
            },
            .min => {
                const v = row.get(self.field) orelse return;
                if (self.minv == null or rowmod.compare(v, self.minv.?) == .lt) {
                    if (self.minv) |old| old.free(allocator);
                    self.minv = try v.dupe(allocator);
                }
            },
            .max => {
                const v = row.get(self.field) orelse return;
                if (self.maxv == null or rowmod.compare(v, self.maxv.?) == .gt) {
                    if (self.maxv) |old| old.free(allocator);
                    self.maxv = try v.dupe(allocator);
                }
            },
            .row_number, .rank, .dense_rank, .lag, .lead, .first_value, .last_value, .nth_value => unreachable,
        }
    }

    fn snapshot(self: *const RunningAcc, allocator: Allocator) Allocator.Error!Value {
        return switch (self.kind) {
            .count => .{ .int = @intCast(self.n) },
            .count_distinct => .{ .int = @intCast(self.distinct.count()) },
            .sum => if (self.allInt) .{ .int = self.sumInt } else .{ .float = self.sumFloat },
            .avg => blk: {
                if (self.n == 0) break :blk .{ .none = {} };
                const total: f64 = if (self.allInt) @floatFromInt(self.sumInt) else self.sumFloat;
                break :blk .{ .float = total / @as(f64, @floatFromInt(self.n)) };
            },
            .min => if (self.minv) |v| try v.dupe(allocator) else .{ .none = {} },
            .max => if (self.maxv) |v| try v.dupe(allocator) else .{ .none = {} },
            .row_number, .rank, .dense_rank, .lag, .lead, .first_value, .last_value, .nth_value => unreachable,
        };
    }

    fn deinit(self: *RunningAcc, allocator: Allocator) void {
        if (self.minv) |v| v.free(allocator);
        if (self.maxv) |v| v.free(allocator);
        var it = self.distinct.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        self.distinct.deinit(allocator);
    }
};

fn buildPartitions(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8) Allocator.Error![][]usize {
    var order: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (order.items) |k| allocator.free(k);
        order.deinit(allocator);
    }
    var map: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(usize)) = .{};
    defer {
        var it = map.iterator();
        while (it.next()) |e| e.value_ptr.deinit(allocator);
        map.deinit(allocator);
    }

    for (rows, 0..) |*r, i| {
        var keyBuf = std.ArrayList(u8).init(allocator);
        defer keyBuf.deinit();
        for (partitionBy) |f| {
            const v = r.get(f) orelse Value{ .none = {} };
            try rowmod.appendOrdered(&keyBuf, v);
        }

        if (map.getPtr(keyBuf.items)) |list| {
            try list.append(allocator, i);
            continue;
        }
        const key = try allocator.dupe(u8, keyBuf.items);
        errdefer allocator.free(key);
        var list: std.ArrayListUnmanaged(usize) = .{};
        errdefer list.deinit(allocator);
        try list.append(allocator, i);
        try map.ensureUnusedCapacity(allocator, 1);
        try order.ensureUnusedCapacity(allocator, 1);
        map.putAssumeCapacity(key, list);
        order.appendAssumeCapacity(key);
    }

    const result = try allocator.alloc([]usize, order.items.len);
    var filled: usize = 0;
    errdefer {
        for (result[0..filled]) |p| allocator.free(p);
        allocator.free(result);
    }
    for (order.items, 0..) |key, idx| {
        const list = map.getPtr(key).?;
        result[idx] = try list.toOwnedSlice(allocator);
        filled += 1;
    }
    return result;
}

fn sortPartitionByOrder(rows: []const Row, indices: []usize, orderBy: []const querymod.OrderBy) void {
    if (orderBy.len == 0) return;
    const Ctx = struct {
        rows: []const Row,
        orderBy: []const querymod.OrderBy,

        fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            for (ctx.orderBy) |ob| {
                const av = ctx.rows[a].get(ob.field) orelse Value{ .none = {} };
                const bv = ctx.rows[b].get(ob.field) orelse Value{ .none = {} };
                const cmp = rowmod.compare(av, bv);
                if (cmp == .eq) continue;
                return if (ob.descending) cmp == .gt else cmp == .lt;
            }
            return false;
        }
    };
    std.sort.block(usize, indices, Ctx{ .rows = rows, .orderBy = orderBy }, Ctx.lessThan);
}

fn tiesWithPrev(rows: []const Row, orderBy: []const querymod.OrderBy, prevIdx: usize, curIdx: usize) bool {
    for (orderBy) |ob| {
        const av = rows[curIdx].get(ob.field) orelse Value{ .none = {} };
        const bv = rows[prevIdx].get(ob.field) orelse Value{ .none = {} };
        if (rowmod.compare(av, bv) != .eq) return false;
    }
    return true;
}

fn partitionedAndSorted(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy) Allocator.Error![][]usize {
    const partitions = try buildPartitions(allocator, rows, partitionBy);
    for (partitions) |indices| sortPartitionByOrder(rows, indices, orderBy);
    return partitions;
}

pub fn orderedIndices(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy) Allocator.Error![]usize {
    const partitions = try partitionedAndSorted(allocator, rows, partitionBy, orderBy);
    defer {
        for (partitions) |p| allocator.free(p);
        allocator.free(partitions);
    }
    const out = try allocator.alloc(usize, rows.len);
    var pos: usize = 0;
    for (partitions) |indices| {
        @memcpy(out[pos..][0..indices.len], indices);
        pos += indices.len;
    }
    return out;
}

pub fn compute(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, spec: WindowSpec, frame: FrameMode) WindowError![]Value {
    const partitions = try partitionedAndSorted(allocator, rows, partitionBy, orderBy);
    defer {
        for (partitions) |p| allocator.free(p);
        allocator.free(partitions);
    }
    return computeOneSpec(allocator, rows, partitions, orderBy, spec, frame);
}

fn computeOneSpec(allocator: Allocator, rows: []const Row, partitions: []const []usize, orderBy: []const querymod.OrderBy, spec: WindowSpec, frame: FrameMode) WindowError![]Value {
    if (!isRanking(spec.kind) and spec.kind != .count and spec.field.len == 0) return error.MissingField;
    if (frame == .range and (isRanking(spec.kind) or isOffsetLookup(spec.kind))) return error.RangeNotApplicable;

    const results = try allocator.alloc(Value, rows.len);
    for (results) |*r| r.* = .{ .none = {} };
    errdefer freeResults(allocator, results);

    for (partitions) |indices| {
        if (isRanking(spec.kind)) {
            var rank: usize = 0;
            var dense: usize = 0;
            for (indices, 0..) |idx, pos| {
                const tied = pos > 0 and (orderBy.len == 0 or tiesWithPrev(rows, orderBy, indices[pos - 1], idx));
                switch (spec.kind) {
                    .row_number => results[idx] = .{ .int = @intCast(pos + 1) },
                    .rank => {
                        if (pos == 0 or !tied) rank = pos + 1;
                        results[idx] = .{ .int = @intCast(rank) };
                    },
                    .dense_rank => {
                        if (pos == 0 or !tied) dense += 1;
                        results[idx] = .{ .int = @intCast(dense) };
                    },
                    else => unreachable,
                }
            }
            continue;
        }

        if (isOffsetLookup(spec.kind)) {
            const delta: i64 = @intCast(spec.offset);
            for (indices, 0..) |idx, pos| {
                const srcPos: i64 = @as(i64, @intCast(pos)) + (if (spec.kind == .lag) -delta else delta);
                if (srcPos >= 0 and srcPos < @as(i64, @intCast(indices.len))) {
                    const srcIdx = indices[@intCast(srcPos)];
                    const v = rows[srcIdx].get(spec.field) orelse Value{ .none = {} };
                    results[idx] = try v.dupe(allocator);
                } else {
                    results[idx] = try spec.default.dupe(allocator);
                }
            }
            continue;
        }

        if (spec.kind == .nth_value) {
            if (indices.len == 0) continue;
            const n = spec.offset;
            if (orderBy.len == 0) {
                const frameEnd: u64 = @intCast(indices.len - 1);
                const v = if (n >= 1 and n - 1 <= frameEnd)
                    rows[indices[@intCast(n - 1)]].get(spec.field) orelse Value{ .none = {} }
                else
                    spec.default;
                for (indices) |idx| results[idx] = try v.dupe(allocator);
            } else if (frame == .rows) {
                for (indices, 0..) |idx, pos| {
                    const frameEnd: u64 = @intCast(pos);
                    const v = if (n >= 1 and n - 1 <= frameEnd)
                        rows[indices[@intCast(n - 1)]].get(spec.field) orelse Value{ .none = {} }
                    else
                        spec.default;
                    results[idx] = try v.dupe(allocator);
                }
            } else {
                var pos: usize = 0;
                while (pos < indices.len) {
                    var end = pos + 1;
                    while (end < indices.len and tiesWithPrev(rows, orderBy, indices[end - 1], indices[end])) : (end += 1) {}
                    const frameEnd: u64 = @intCast(end - 1);
                    const v = if (n >= 1 and n - 1 <= frameEnd)
                        rows[indices[@intCast(n - 1)]].get(spec.field) orelse Value{ .none = {} }
                    else
                        spec.default;
                    for (indices[pos..end]) |idx| results[idx] = try v.dupe(allocator);
                    pos = end;
                }
            }
            continue;
        }

        if (isFrameValue(spec.kind)) {
            if (indices.len == 0) continue;
            if (orderBy.len == 0) {
                const firstV = rows[indices[0]].get(spec.field) orelse Value{ .none = {} };
                const lastV = rows[indices[indices.len - 1]].get(spec.field) orelse Value{ .none = {} };
                const v = if (spec.kind == .first_value) firstV else lastV;
                for (indices) |idx| results[idx] = try v.dupe(allocator);
            } else if (frame == .rows) {
                const firstV = rows[indices[0]].get(spec.field) orelse Value{ .none = {} };
                for (indices) |idx| {
                    const v = if (spec.kind == .first_value) firstV else (rows[idx].get(spec.field) orelse Value{ .none = {} });
                    results[idx] = try v.dupe(allocator);
                }
            } else {
                const firstV = rows[indices[0]].get(spec.field) orelse Value{ .none = {} };
                var pos: usize = 0;
                while (pos < indices.len) {
                    var end = pos + 1;
                    while (end < indices.len and tiesWithPrev(rows, orderBy, indices[end - 1], indices[end])) : (end += 1) {}
                    const groupLastV = rows[indices[end - 1]].get(spec.field) orelse Value{ .none = {} };
                    for (indices[pos..end]) |idx| {
                        const v = if (spec.kind == .first_value) firstV else groupLastV;
                        results[idx] = try v.dupe(allocator);
                    }
                    pos = end;
                }
            }
            continue;
        }

        var acc = RunningAcc{ .kind = spec.kind, .field = spec.field };
        defer acc.deinit(allocator);

        if (orderBy.len == 0) {
            for (indices) |idx| try acc.observe(allocator, &rows[idx]);
            for (indices) |idx| results[idx] = try acc.snapshot(allocator);
        } else if (frame == .rows) {
            for (indices) |idx| {
                try acc.observe(allocator, &rows[idx]);
                results[idx] = try acc.snapshot(allocator);
            }
        } else {
            var pos: usize = 0;
            while (pos < indices.len) {
                var end = pos + 1;
                while (end < indices.len and tiesWithPrev(rows, orderBy, indices[end - 1], indices[end])) : (end += 1) {}
                for (indices[pos..end]) |idx| try acc.observe(allocator, &rows[idx]);
                for (indices[pos..end]) |idx| results[idx] = try acc.snapshot(allocator);
                pos = end;
            }
        }
    }

    return results;
}

pub fn computeMany(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, specs: []const WindowSpec, frame: FrameMode) WindowError![][]Value {
    const partitions = try partitionedAndSorted(allocator, rows, partitionBy, orderBy);
    defer {
        for (partitions) |p| allocator.free(p);
        allocator.free(partitions);
    }

    var columns = try allocator.alloc([]Value, specs.len);
    var filledCols: usize = 0;
    errdefer {
        for (columns[0..filledCols]) |c| freeResults(allocator, c);
        allocator.free(columns);
    }
    for (specs) |spec| {
        columns[filledCols] = try computeOneSpec(allocator, rows, partitions, orderBy, spec, frame);
        filledCols += 1;
    }

    const results = try allocator.alloc([]Value, rows.len);
    var filledRows: usize = 0;
    errdefer {
        for (results[0..filledRows]) |r| freeResults(allocator, r);
        allocator.free(results);
    }
    for (0..rows.len) |rowIdx| {
        const rowValues = try allocator.alloc(Value, specs.len);
        var filledVals: usize = 0;
        errdefer {
            for (rowValues[0..filledVals]) |v| v.free(allocator);
            allocator.free(rowValues);
        }
        for (columns, 0..) |col, specIdx| {
            rowValues[specIdx] = try col[rowIdx].dupe(allocator);
            filledVals += 1;
        }
        results[rowIdx] = rowValues;
        filledRows += 1;
    }

    for (columns) |c| freeResults(allocator, c);
    allocator.free(columns);

    return results;
}

pub fn freeManyResults(allocator: Allocator, results: [][]Value) void {
    for (results) |r| freeResults(allocator, r);
    allocator.free(results);
}

pub fn freeResults(allocator: Allocator, results: []Value) void {
    for (results) |v| v.free(allocator);
    allocator.free(results);
}

fn makeRow(allocator: Allocator, fields: []const rowmod.Field) !Row {
    var r = Row.init(allocator);
    for (fields) |f| try r.set(f.name, f.value);
    return r;
}

fn threeRowsOnePartition(allocator: Allocator) !std.ArrayList(Row) {
    var rows = std.ArrayList(Row).init(allocator);
    errdefer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { team: []const u8, score: i64 }{
        .{ .team = "a", .score = 30 },
        .{ .team = "a", .score = 10 },
        .{ .team = "a", .score = 20 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "team", .value = .{ .text = d.team } },
            .{ .name = "score", .value = .{ .int = d.score } },
        }));
    }
    return rows;
}

test "row_number assigns 1..n within a single implicit partition, ordered" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }

    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .row_number }, .rows);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(i64, 3), results[0].int);
    try std.testing.expectEqual(@as(i64, 1), results[1].int);
    try std.testing.expectEqual(@as(i64, 2), results[2].int);
}

test "row_number restarts at 1 per partition" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, score: i64 }{
        .{ .city = "warsaw", .score = 5 },
        .{ .city = "krakow", .score = 9 },
        .{ .city = "warsaw", .score = 1 },
        .{ .city = "krakow", .score = 2 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "score", .value = .{ .int = d.score } },
        }));
    }

    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const results = try compute(allocator, rows.items, &partition, &order, .{ .field = "", .kind = .row_number }, .rows);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(i64, 2), results[0].int);
    try std.testing.expectEqual(@as(i64, 1), results[2].int);
    try std.testing.expectEqual(@as(i64, 2), results[1].int);
    try std.testing.expectEqual(@as(i64, 1), results[3].int);
}

test "rank skips over ties, dense_rank does not" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const scores = [_]i64{ 10, 10, 20, 30, 30, 30 };
    for (scores) |s| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "score", .value = .{ .int = s } },
        }));
    }

    const order = [_]querymod.OrderBy{.{ .field = "score" }};

    const ranks = try compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .rank }, .rows);
    defer freeResults(allocator, ranks);
    const expectedRank = [_]i64{ 1, 1, 3, 4, 4, 4 };
    for (expectedRank, 0..) |want, i| try std.testing.expectEqual(want, ranks[i].int);

    const dense = try compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .dense_rank }, .rows);
    defer freeResults(allocator, dense);
    const expectedDense = [_]i64{ 1, 1, 2, 3, 3, 3 };
    for (expectedDense, 0..) |want, i| try std.testing.expectEqual(want, dense[i].int);
}

test "rank and dense_rank without ORDER BY: whole partition ties, every row is 1" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }

    const ranks = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .rank }, .rows);
    defer freeResults(allocator, ranks);
    for (ranks) |r| try std.testing.expectEqual(@as(i64, 1), r.int);

    const dense = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .dense_rank }, .rows);
    defer freeResults(allocator, dense);
    for (dense) |r| try std.testing.expectEqual(@as(i64, 1), r.int);

    const nums = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .row_number }, .rows);
    defer freeResults(allocator, nums);
    try std.testing.expectEqual(@as(i64, 1), nums[0].int);
    try std.testing.expectEqual(@as(i64, 2), nums[1].int);
    try std.testing.expectEqual(@as(i64, 3), nums[2].int);
}

test "running sum walks cumulatively in ORDER BY order, per partition" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, day: i64, amount: i64 }{
        .{ .city = "warsaw", .day = 1, .amount = 100 },
        .{ .city = "krakow", .day = 1, .amount = 40 },
        .{ .city = "warsaw", .day = 2, .amount = 250 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }

    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const results = try compute(allocator, rows.items, &partition, &order, .{ .field = "amount", .kind = .sum }, .rows);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(i64, 100), results[0].int);
    try std.testing.expectEqual(@as(i64, 40), results[1].int);
    try std.testing.expectEqual(@as(i64, 350), results[2].int);
}

test "RANGE frame: rows tied on ORDER BY share the tie group's combined total, ROWS gives each its own" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, amount: i64 }{
        .{ .day = 1, .amount = 10 },
        .{ .day = 1, .amount = 20 },
        .{ .day = 2, .amount = 5 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const rowsResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .sum }, .rows);
    defer freeResults(allocator, rowsResult);
    try std.testing.expectEqual(@as(i64, 10), rowsResult[0].int);
    try std.testing.expectEqual(@as(i64, 30), rowsResult[1].int);
    try std.testing.expectEqual(@as(i64, 35), rowsResult[2].int);

    const rangeResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .sum }, .range);
    defer freeResults(allocator, rangeResult);
    try std.testing.expectEqual(@as(i64, 30), rangeResult[0].int);
    try std.testing.expectEqual(@as(i64, 30), rangeResult[1].int);
    try std.testing.expectEqual(@as(i64, 35), rangeResult[2].int);
}

test "RANGE frame on count/avg/min/max matches the same tie-group grouping as sum" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, amount: i64 }{
        .{ .day = 1, .amount = 30 },
        .{ .day = 1, .amount = 10 },
        .{ .day = 2, .amount = 20 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const counts = try compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .count }, .range);
    defer freeResults(allocator, counts);
    try std.testing.expectEqual(@as(i64, 2), counts[0].int);
    try std.testing.expectEqual(@as(i64, 2), counts[1].int);
    try std.testing.expectEqual(@as(i64, 3), counts[2].int);

    const mins = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .min }, .range);
    defer freeResults(allocator, mins);
    try std.testing.expectEqual(@as(i64, 10), mins[0].int);
    try std.testing.expectEqual(@as(i64, 10), mins[1].int);
    try std.testing.expectEqual(@as(i64, 10), mins[2].int);

    const maxs = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .max }, .range);
    defer freeResults(allocator, maxs);
    try std.testing.expectEqual(@as(i64, 30), maxs[0].int);
    try std.testing.expectEqual(@as(i64, 30), maxs[1].int);
    try std.testing.expectEqual(@as(i64, 30), maxs[2].int);

    const avgs = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .avg }, .range);
    defer freeResults(allocator, avgs);
    try std.testing.expectApproxEqAbs(@as(f64, 20), avgs[0].float, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f64, 20), avgs[1].float, 0.0001);
    try std.testing.expectApproxEqAbs(@as(f64, 20), avgs[2].float, 0.0001);
}

test "RANGE with no ties reduces to the same result as ROWS" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]i64{ 3, 1, 4 };
    for (data) |amount| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "amount", .value = .{ .int = amount } }}));
    }
    const order = [_]querymod.OrderBy{.{ .field = "amount" }};

    const rowsResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .sum }, .rows);
    defer freeResults(allocator, rowsResult);
    const rangeResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .sum }, .range);
    defer freeResults(allocator, rangeResult);
    for (rowsResult, rangeResult) |r, g| try std.testing.expectEqual(r.int, g.int);
}

test "RANGE with every row tied gives everyone the whole-partition total, like no ORDER BY at all" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "team" }};

    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .sum }, .range);
    defer freeResults(allocator, results);
    for (results) |r| try std.testing.expectEqual(@as(i64, 60), r.int);
}

test "frame is rejected outright for the ranking family, never silently ignored" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    try std.testing.expectError(error.RangeNotApplicable, compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .row_number }, .range));
    try std.testing.expectError(error.RangeNotApplicable, compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .rank }, .range));
    try std.testing.expectError(error.RangeNotApplicable, compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .dense_rank }, .range));
}

test "compute propagates OutOfMemory without leaking, mid-way through a RANGE tie group" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "mango", "apple" };
    for (names) |n| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "name", .value = .{ .text = n } }}));
    }
    const order = [_]querymod.OrderBy{.{ .field = "name" }};

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 4 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &order, .{ .field = "name", .kind = .min }, .range));
}

test "sum without ORDER BY gives every row the whole-partition total" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .sum }, .rows);
    defer freeResults(allocator, results);
    for (results) |r| try std.testing.expectEqual(@as(i64, 60), r.int);
}

test "avg running and count star running" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const scores = [_]i64{ 10, 20, 30 };
    for (scores) |s| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "score", .value = .{ .int = s } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};

    const avgs = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .avg }, .rows);
    defer freeResults(allocator, avgs);
    try std.testing.expectApproxEqAbs(@as(f64, 10), avgs[0].float, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 15), avgs[1].float, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 20), avgs[2].float, 1e-9);

    const counts = try compute(allocator, rows.items, &.{}, &order, .{ .field = "", .kind = .count }, .rows);
    defer freeResults(allocator, counts);
    try std.testing.expectEqual(@as(i64, 1), counts[0].int);
    try std.testing.expectEqual(@as(i64, 2), counts[1].int);
    try std.testing.expectEqual(@as(i64, 3), counts[2].int);
}

test "count_distinct runs cumulatively per partition, repeats do not grow it" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, day: i64, tag: []const u8 }{
        .{ .city = "warsaw", .day = 1, .tag = "a" },
        .{ .city = "krakow", .day = 1, .tag = "c" },
        .{ .city = "warsaw", .day = 2, .tag = "b" },
        .{ .city = "warsaw", .day = 3, .tag = "a" },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "tag", .value = .{ .text = d.tag } },
        }));
    }

    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const results = try compute(allocator, rows.items, &partition, &order, .{ .field = "tag", .kind = .count_distinct }, .rows);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(i64, 1), results[0].int);
    try std.testing.expectEqual(@as(i64, 1), results[1].int);
    try std.testing.expectEqual(@as(i64, 2), results[2].int);
    try std.testing.expectEqual(@as(i64, 2), results[3].int);
}

test "count_distinct without ORDER BY gives every row the whole-partition distinct total" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const tags = [_][]const u8{ "x", "y", "x", "z" };
    for (tags) |t| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "tag", .value = .{ .text = t } }}));
    }
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "tag", .kind = .count_distinct }, .rows);
    defer freeResults(allocator, results);
    for (results) |r| try std.testing.expectEqual(@as(i64, 3), r.int);
}

test "count_distinct RANGE frame: a tied group's members share one snapshot after the WHOLE group is observed" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, tag: []const u8 }{
        .{ .day = 1, .tag = "a" },
        .{ .day = 1, .tag = "b" },
        .{ .day = 2, .tag = "a" },
        .{ .day = 2, .tag = "c" },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "tag", .value = .{ .text = d.tag } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const rowsResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "tag", .kind = .count_distinct }, .rows);
    defer freeResults(allocator, rowsResult);
    try std.testing.expectEqual(@as(i64, 1), rowsResult[0].int);
    try std.testing.expectEqual(@as(i64, 2), rowsResult[1].int);
    try std.testing.expectEqual(@as(i64, 2), rowsResult[2].int);
    try std.testing.expectEqual(@as(i64, 3), rowsResult[3].int);

    const rangeResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "tag", .kind = .count_distinct }, .range);
    defer freeResults(allocator, rangeResult);
    try std.testing.expectEqual(@as(i64, 2), rangeResult[0].int);
    try std.testing.expectEqual(@as(i64, 2), rangeResult[1].int);
    try std.testing.expectEqual(@as(i64, 3), rangeResult[2].int);
    try std.testing.expectEqual(@as(i64, 3), rangeResult[3].int);
}

test "count_distinct requires a field like sum/avg/min/max, unlike plain count" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .count_distinct }, .rows));
}

test "count_distinct ignores rows missing the field entirely, never counts none as a value" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{.{ .name = "other", .value = .{ .int = 1 } }}));
    try rows.append(try makeRow(allocator, &.{.{ .name = "tag", .value = .{ .text = "a" } }}));
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "tag", .kind = .count_distinct }, .rows);
    defer freeResults(allocator, results);
    for (results) |r| try std.testing.expectEqual(@as(i64, 1), r.int);
}

test "count_distinct propagates OutOfMemory without leaking already-tracked distinct keys" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const tags = [_][]const u8{ "mango", "apple", "kiwi" };
    for (tags) |t| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "tag", .value = .{ .text = t } }}));
    }
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 6 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &.{}, .{ .field = "tag", .kind = .count_distinct }, .rows));
}

test "count_distinct alongside lag/lead/first_value/running sum/ranking in one computeMany call" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, tag: []const u8, amount: i64 }{
        .{ .day = 1, .tag = "a", .amount = 10 },
        .{ .day = 2, .tag = "b", .amount = 20 },
        .{ .day = 3, .tag = "a", .amount = 30 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "tag", .value = .{ .text = d.tag } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const specs = [_]WindowSpec{
        .{ .field = "tag", .kind = .count_distinct },
        .{ .field = "amount", .kind = .lag },
        .{ .field = "amount", .kind = .sum },
        .{ .field = "", .kind = .row_number },
    };
    const results = try computeMany(allocator, rows.items, &.{}, &order, &specs, .rows);
    defer freeManyResults(allocator, results);

    try std.testing.expectEqual(@as(i64, 1), results[0][0].int);
    try std.testing.expectEqual(Value{ .none = {} }, results[0][1]);
    try std.testing.expectEqual(@as(i64, 10), results[0][2].int);
    try std.testing.expectEqual(@as(i64, 1), results[0][3].int);

    try std.testing.expectEqual(@as(i64, 2), results[1][0].int);
    try std.testing.expectEqual(@as(i64, 10), results[1][1].int);
    try std.testing.expectEqual(@as(i64, 30), results[1][2].int);
    try std.testing.expectEqual(@as(i64, 2), results[1][3].int);

    try std.testing.expectEqual(@as(i64, 2), results[2][0].int);
    try std.testing.expectEqual(@as(i64, 20), results[2][1].int);
    try std.testing.expectEqual(@as(i64, 60), results[2][2].int);
    try std.testing.expectEqual(@as(i64, 3), results[2][3].int);
}

test "running min and max over a text field, independently duped per row" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};

    const mins = try compute(allocator, rows.items, &.{}, &order, .{ .field = "name", .kind = .min }, .rows);
    defer freeResults(allocator, mins);
    try std.testing.expectEqualStrings("mango", mins[0].text);
    try std.testing.expectEqualStrings("apple", mins[1].text);
    try std.testing.expectEqualStrings("apple", mins[2].text);

    const maxs = try compute(allocator, rows.items, &.{}, &order, .{ .field = "name", .kind = .max }, .rows);
    defer freeResults(allocator, maxs);
    try std.testing.expectEqualStrings("mango", maxs[0].text);
    try std.testing.expectEqualStrings("mango", maxs[1].text);
    try std.testing.expectEqualStrings("mango", maxs[2].text);
}

test "sum/avg/min/max require a field, ranking family and COUNT(*) do not" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }

    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .sum }, .rows));
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .avg }, .rows));
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .min }, .rows));
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .max }, .rows));

    const stars = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .count }, .rows);
    defer freeResults(allocator, stars);
    const nums = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .row_number }, .rows);
    defer freeResults(allocator, nums);
}

test "sum on a non-numeric field is NonNumericField, integer overflow is Overflow" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{.{ .name = "x", .value = .{ .text = "nope" } }}));
    try std.testing.expectError(error.NonNumericField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "x", .kind = .sum }, .rows));

    var overflowRows = std.ArrayList(Row).init(allocator);
    defer {
        for (overflowRows.items) |*r| r.deinit();
        overflowRows.deinit();
    }
    try overflowRows.append(try makeRow(allocator, &.{.{ .name = "x", .value = .{ .int = std.math.maxInt(i64) } }}));
    try overflowRows.append(try makeRow(allocator, &.{.{ .name = "x", .value = .{ .int = 1 } }}));
    try std.testing.expectError(error.Overflow, compute(allocator, overflowRows.items, &.{}, &.{}, .{ .field = "x", .kind = .sum }, .rows));
}

test "compute on zero rows returns an empty result, no crash" {
    const allocator = std.testing.allocator;
    const rows = [_]Row{};
    const results = try compute(allocator, &rows, &.{}, &.{}, .{ .field = "", .kind = .row_number }, .rows);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "specLabel matches aggregate.zig's kind_field / bare-kind convention" {
    const allocator = std.testing.allocator;
    const bare = try specLabel(allocator, .{ .field = "", .kind = .row_number });
    defer allocator.free(bare);
    try std.testing.expectEqualStrings("row_number", bare);

    const withField = try specLabel(allocator, .{ .field = "score", .kind = .sum });
    defer allocator.free(withField);
    try std.testing.expectEqualStrings("sum_score", withField);
}

test "compute propagates OutOfMemory without leaking, at an early allocation" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &.{}, .{ .field = "score", .kind = .sum }, .rows));
}

test "compute propagates OutOfMemory without leaking, mid-way through partitioned min/max" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi", "banana", "fig" };
    for (names) |n| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "name", .value = .{ .text = n } }}));
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 4 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &.{}, .{ .field = "name", .kind = .min }, .rows));
}

test "orderedIndices flattens partitions in first-seen order, each sorted by orderBy" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, score: i64 }{
        .{ .city = "warsaw", .score = 5 },
        .{ .city = "krakow", .score = 9 },
        .{ .city = "warsaw", .score = 1 },
        .{ .city = "krakow", .score = 2 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "score", .value = .{ .int = d.score } },
        }));
    }

    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const idx = try orderedIndices(allocator, rows.items, &partition, &order);
    defer allocator.free(idx);

    try std.testing.expectEqualSlices(usize, &.{ 2, 0, 3, 1 }, idx);
}

test "orderedIndices on zero rows returns an empty slice" {
    const allocator = std.testing.allocator;
    const rows = [_]Row{};
    const idx = try orderedIndices(allocator, &rows, &.{}, &.{});
    defer allocator.free(idx);
    try std.testing.expectEqual(@as(usize, 0), idx.len);
}

test "orderedIndices propagates OutOfMemory without leaking" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, orderedIndices(failing.allocator(), rows.items, &.{}, &.{}));
}

test "computeMany matches calling compute() once per spec, sharing one partition/order/frame" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, amount: i64 }{
        .{ .city = "warsaw", .amount = 10 },
        .{ .city = "krakow", .amount = 9 },
        .{ .city = "warsaw", .amount = 20 },
        .{ .city = "krakow", .amount = 2 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }

    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "amount" }};
    const specs = [_]WindowSpec{
        .{ .field = "amount", .kind = .sum },
        .{ .field = "amount", .kind = .avg },
        .{ .field = "", .kind = .row_number },
    };

    const many = try computeMany(allocator, rows.items, &partition, &order, &specs, .rows);
    defer freeManyResults(allocator, many);

    for (specs, 0..) |spec, specIdx| {
        const solo = try compute(allocator, rows.items, &partition, &order, spec, .rows);
        defer freeResults(allocator, solo);
        for (rows.items, 0..) |_, rowIdx| {
            try std.testing.expect(rowmod.compare(many[rowIdx][specIdx], solo[rowIdx]) == .eq);
        }
    }
}

test "computeMany keeps min/max text results independently owned per row and per spec" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi" };
    for (names) |n| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "name", .value = .{ .text = n } }}));
    }

    const specs = [_]WindowSpec{
        .{ .field = "name", .kind = .min },
        .{ .field = "name", .kind = .max },
    };
    const results = try computeMany(allocator, rows.items, &.{}, &.{}, &specs, .rows);
    defer freeManyResults(allocator, results);

    for (results) |row| {
        try std.testing.expectEqualStrings("apple", row[0].text);
        try std.testing.expectEqualStrings("mango", row[1].text);
    }
    try std.testing.expect(results[0][0].text.ptr != results[1][0].text.ptr);
}

test "computeMany with zero specs returns one empty values slice per row, no crash" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const results = try computeMany(allocator, rows.items, &.{}, &.{}, &.{}, .rows);
    defer freeManyResults(allocator, results);
    try std.testing.expectEqual(@as(usize, 3), results.len);
    for (results) |row| try std.testing.expectEqual(@as(usize, 0), row.len);
}

test "computeMany propagates OutOfMemory without leaking, at an early allocation" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const specs = [_]WindowSpec{
        .{ .field = "score", .kind = .sum },
        .{ .field = "", .kind = .row_number },
    };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, computeMany(failing.allocator(), rows.items, &.{}, &.{}, &specs, .rows));
}

test "computeMany propagates OutOfMemory without leaking, mid-way through the row-major transpose" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const specs = [_]WindowSpec{
        .{ .field = "score", .kind = .sum },
        .{ .field = "team", .kind = .min },
    };
    var failIndex: usize = 0;
    while (failIndex < 40) : (failIndex += 1) {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = failIndex });
        const result = computeMany(failing.allocator(), rows.items, &.{}, &.{}, &specs, .rows);
        if (result) |ok| {
            freeManyResults(allocator, ok);
            break;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
    } else return error.TestUnexpectedResult;
}

test "lag/lead default offset of 1: NULL (default) at the edge, adjacent value otherwise" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, amount: i64 }{
        .{ .day = 1, .amount = 10 },
        .{ .day = 2, .amount = 20 },
        .{ .day = 3, .amount = 30 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const lag = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .lag }, .rows);
    defer freeResults(allocator, lag);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lag[0]));
    try std.testing.expectEqual(@as(i64, 10), lag[1].int);
    try std.testing.expectEqual(@as(i64, 20), lag[2].int);

    const lead = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .lead }, .rows);
    defer freeResults(allocator, lead);
    try std.testing.expectEqual(@as(i64, 20), lead[0].int);
    try std.testing.expectEqual(@as(i64, 30), lead[1].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lead[2]));
}

test "lag/lead with an explicit offset skips that many physical positions" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const amounts = [_]i64{ 10, 20, 30, 40 };
    for (amounts, 0..) |a, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "amount", .value = .{ .int = a } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};

    const lag2 = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .lag, .offset = 2 }, .rows);
    defer freeResults(allocator, lag2);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lag2[0]));
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lag2[1]));
    try std.testing.expectEqual(@as(i64, 10), lag2[2].int);
    try std.testing.expectEqual(@as(i64, 20), lag2[3].int);

    const lagZero = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .lag, .offset = 0 }, .rows);
    defer freeResults(allocator, lagZero);
    for (amounts, 0..) |a, i| try std.testing.expectEqual(a, lagZero[i].int);
}

test "lag/lead use a caller-supplied default instead of NULL at the edge" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "seq", .value = .{ .int = 0 } },
        .{ .name = "amount", .value = .{ .int = 5 } },
    }));
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "seq", .value = .{ .int = 1 } },
        .{ .name = "amount", .value = .{ .int = 6 } },
    }));
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};

    const lag = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .lag, .default = .{ .int = -1 } }, .rows);
    defer freeResults(allocator, lag);
    try std.testing.expectEqual(@as(i64, -1), lag[0].int);
    try std.testing.expectEqual(@as(i64, 5), lag[1].int);
}

test "lag/lead restart per partition and treat orderBy ties as distinct physical positions" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, day: i64, amount: i64 }{
        .{ .city = "warsaw", .day = 1, .amount = 10 },
        .{ .city = "warsaw", .day = 1, .amount = 20 },
        .{ .city = "krakow", .day = 1, .amount = 99 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const lead = try compute(allocator, rows.items, &partition, &order, .{ .field = "amount", .kind = .lead }, .rows);
    defer freeResults(allocator, lead);
    try std.testing.expectEqual(@as(i64, 20), lead[0].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lead[1]));
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lead[2]));
}

test "lag/lead without ORDER BY walk first-seen input order" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const lag = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .lag }, .rows);
    defer freeResults(allocator, lag);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lag[0]));
    try std.testing.expectEqual(@as(i64, 30), lag[1].int);
    try std.testing.expectEqual(@as(i64, 10), lag[2].int);
}

test "lag/lead on a text field dupes independently per row, no shared pointers" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    const lag = try compute(allocator, rows.items, &.{}, &order, .{ .field = "name", .kind = .lag }, .rows);
    defer freeResults(allocator, lag);
    try std.testing.expectEqualStrings("mango", lag[1].text);
    try std.testing.expectEqualStrings("apple", lag[2].text);
    try std.testing.expect(lag[1].text.ptr != names[0].ptr);
}

test "lag/lead require a field, like sum/avg/min/max" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .lag }, .rows));
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .lead }, .rows));
}

test "lag/lead reject a RANGE frame outright, like the ranking family" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    try std.testing.expectError(error.RangeNotApplicable, compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .lag }, .range));
    try std.testing.expectError(error.RangeNotApplicable, compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .lead }, .range));
}

test "lag/lead propagate OutOfMemory without leaking" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi", "banana" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 4 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &order, .{ .field = "name", .kind = .lag }, .rows));
}

test "first_value/last_value without ORDER BY: whole-partition frame, constant per partition" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const first = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .first_value }, .rows);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 30), v.int);

    const last = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .last_value }, .rows);
    defer freeResults(allocator, last);
    for (last) |v| try std.testing.expectEqual(@as(i64, 20), v.int);
}

test "first_value/last_value ROWS frame: first stays the partition's first row, last degenerates to the current row" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const scores = [_]i64{ 30, 10, 20 };
    for (scores) |s| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "score", .value = .{ .int = s } }}));
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};

    const first = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .first_value }, .rows);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 10), v.int);

    const last = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .last_value }, .rows);
    defer freeResults(allocator, last);
    try std.testing.expectEqual(@as(i64, 30), last[0].int);
    try std.testing.expectEqual(@as(i64, 10), last[1].int);
    try std.testing.expectEqual(@as(i64, 20), last[2].int);
}

test "first_value/last_value RANGE frame: last_value shares the current tie group's last member" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, amount: i64 }{
        .{ .day = 1, .amount = 10 },
        .{ .day = 1, .amount = 20 },
        .{ .day = 2, .amount = 5 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const first = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .first_value }, .range);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 10), v.int);

    const last = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .last_value }, .range);
    defer freeResults(allocator, last);
    try std.testing.expectEqual(@as(i64, 20), last[0].int);
    try std.testing.expectEqual(@as(i64, 20), last[1].int);
    try std.testing.expectEqual(@as(i64, 5), last[2].int);
}

test "first_value/last_value restart per partition, RANGE tie group stays within one city" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, day: i64, amount: i64 }{
        .{ .city = "warsaw", .day = 1, .amount = 100 },
        .{ .city = "warsaw", .day = 1, .amount = 250 },
        .{ .city = "krakow", .day = 1, .amount = 40 },
        .{ .city = "krakow", .day = 1, .amount = 90 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};

    const last = try compute(allocator, rows.items, &partition, &order, .{ .field = "amount", .kind = .last_value }, .range);
    defer freeResults(allocator, last);
    try std.testing.expectEqual(@as(i64, 250), last[0].int);
    try std.testing.expectEqual(@as(i64, 250), last[1].int);
    try std.testing.expectEqual(@as(i64, 90), last[2].int);
    try std.testing.expectEqual(@as(i64, 90), last[3].int);
}

test "first_value/last_value on a text field dupes independently per row, no shared pointers" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    const first = try compute(allocator, rows.items, &.{}, &order, .{ .field = "name", .kind = .first_value }, .rows);
    defer freeResults(allocator, first);
    try std.testing.expectEqualStrings("mango", first[0].text);
    try std.testing.expectEqualStrings("mango", first[2].text);
    try std.testing.expect(first[2].text.ptr != names[0].ptr);
}

test "first_value/last_value require a field, like sum/avg/min/max" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .first_value }, .rows));
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .last_value }, .rows));
}

test "first_value/last_value accept a RANGE frame, unlike lag/lead" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const first = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .first_value }, .range);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 10), v.int);
}

test "first_value/last_value propagate OutOfMemory without leaking" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi", "banana" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 4 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &order, .{ .field = "name", .kind = .last_value }, .rows));
}

test "first_value/last_value on zero rows in a partition does not crash (empty indices guard)" {
    const allocator = std.testing.allocator;
    const rows = [_]Row{};
    const results = try compute(allocator, &rows, &.{}, &.{}, .{ .field = "x", .kind = .first_value }, .rows);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "nth_value without ORDER BY: whole-partition frame, n counts from the first-seen row" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const n1 = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 1 }, .rows);
    defer freeResults(allocator, n1);
    for (n1) |v| try std.testing.expectEqual(@as(i64, 30), v.int);

    const n3 = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 3 }, .rows);
    defer freeResults(allocator, n3);
    for (n3) |v| try std.testing.expectEqual(@as(i64, 20), v.int);

    const n4 = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 4 }, .rows);
    defer freeResults(allocator, n4);
    for (n4) |v| try std.testing.expectEqual(Value{ .none = {} }, v);
}

test "nth_value ROWS frame: position visible only once the frame has grown to include it" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const scores = [_]i64{ 30, 10, 20 };
    for (scores) |s| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "score", .value = .{ .int = s } }}));
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .nth_value, .offset = 2 }, .rows);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(Value{ .none = {} }, results[1]);
    try std.testing.expectEqual(@as(i64, 20), results[2].int);
    try std.testing.expectEqual(@as(i64, 20), results[0].int);
}

test "nth_value RANGE frame: position resolved against the current tie group's growing frame" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { day: i64, amount: i64 }{
        .{ .day = 1, .amount = 10 },
        .{ .day = 1, .amount = 20 },
        .{ .day = 2, .amount = 5 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .nth_value, .offset = 3 }, .range);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(Value{ .none = {} }, results[0]);
    try std.testing.expectEqual(Value{ .none = {} }, results[1]);
    try std.testing.expectEqual(@as(i64, 5), results[2].int);
}

test "nth_value uses a custom default instead of NULL when set" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 10, .default = .{ .int = -1 } }, .rows);
    defer freeResults(allocator, results);
    for (results) |v| try std.testing.expectEqual(@as(i64, -1), v.int);
}

test "nth_value with offset 0 never resolves (positions are 1-based)" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 0 }, .rows);
    defer freeResults(allocator, results);
    for (results) |v| try std.testing.expectEqual(Value{ .none = {} }, v);
}

test "nth_value restart per partition, RANGE tie group stays within one city" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, day: i64, amount: i64 }{
        .{ .city = "warsaw", .day = 1, .amount = 100 },
        .{ .city = "warsaw", .day = 1, .amount = 250 },
        .{ .city = "krakow", .day = 1, .amount = 40 },
        .{ .city = "krakow", .day = 1, .amount = 90 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "day", .value = .{ .int = d.day } },
            .{ .name = "amount", .value = .{ .int = d.amount } },
        }));
    }
    const partition = [_][]const u8{"city"};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const results = try compute(allocator, rows.items, &partition, &order, .{ .field = "amount", .kind = .nth_value, .offset = 2 }, .range);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(@as(i64, 250), results[0].int);
    try std.testing.expectEqual(@as(i64, 250), results[1].int);
    try std.testing.expectEqual(@as(i64, 90), results[2].int);
    try std.testing.expectEqual(@as(i64, 90), results[3].int);
}

test "nth_value on a text field dupes independently per row, no shared pointers" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "name", .kind = .nth_value, .offset = 1 }, .rows);
    defer freeResults(allocator, results);
    try std.testing.expectEqualStrings("mango", results[0].text);
    try std.testing.expectEqualStrings("mango", results[2].text);
    try std.testing.expect(results[2].text.ptr != names[0].ptr);
}

test "nth_value requires a field, like first_value/last_value" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try std.testing.expectError(error.MissingField, compute(allocator, rows.items, &.{}, &.{}, .{ .field = "", .kind = .nth_value, .offset = 1 }, .rows));
}

test "nth_value accepts a RANGE frame, unlike lag/lead" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "score" }};
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .nth_value, .offset = 1 }, .range);
    defer freeResults(allocator, results);
    for (results) |v| try std.testing.expectEqual(@as(i64, 10), v.int);
}

test "nth_value propagates OutOfMemory without leaking" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "mango", "apple", "kiwi", "banana" };
    for (names, 0..) |n, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 4 });
    try std.testing.expectError(error.OutOfMemory, compute(failing.allocator(), rows.items, &.{}, &order, .{ .field = "name", .kind = .nth_value, .offset = 2 }, .rows));
}

test "nth_value on zero rows in a partition does not crash (empty indices guard)" {
    const allocator = std.testing.allocator;
    const rows = [_]Row{};
    const results = try compute(allocator, &rows, &.{}, &.{}, .{ .field = "x", .kind = .nth_value, .offset = 1 }, .rows);
    defer freeResults(allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "computeMany mixes nth_value with lag/lead/running aggregates/ranking under one shared window" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const amounts = [_]i64{ 10, 20, 30 };
    for (amounts, 0..) |a, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "amount", .value = .{ .int = a } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    const specs = [_]WindowSpec{
        .{ .field = "amount", .kind = .nth_value, .offset = 2 },
        .{ .field = "amount", .kind = .lag },
        .{ .field = "amount", .kind = .row_number },
    };
    const results = try computeMany(allocator, rows.items, &.{}, &order, &specs, .rows);
    defer freeManyResults(allocator, results);
    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(Value{ .none = {} }, results[0][0]);
    try std.testing.expectEqual(@as(i64, 20), results[1][0].int);
    try std.testing.expectEqual(@as(i64, 20), results[2][0].int);
}

test "computeMany mixes lag/lead with running aggregates and ranking under one shared window" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const amounts = [_]i64{ 10, 20, 30 };
    for (amounts, 0..) |a, i| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "seq", .value = .{ .int = @intCast(i) } },
            .{ .name = "amount", .value = .{ .int = a } },
        }));
    }
    const order = [_]querymod.OrderBy{.{ .field = "seq" }};
    const specs = [_]WindowSpec{
        .{ .field = "amount", .kind = .lag },
        .{ .field = "amount", .kind = .lead },
        .{ .field = "amount", .kind = .sum },
        .{ .field = "", .kind = .row_number },
    };
    const many = try computeMany(allocator, rows.items, &.{}, &order, &specs, .rows);
    defer freeManyResults(allocator, many);

    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, many[0][0]));
    try std.testing.expectEqual(@as(i64, 10), many[1][0].int);
    try std.testing.expectEqual(@as(i64, 20), many[0][1].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, many[2][1]));
    try std.testing.expectEqual(@as(i64, 60), many[2][2].int);
    try std.testing.expectEqual(@as(i64, 3), many[2][3].int);
}
