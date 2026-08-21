const std = @import("std");
const rowmod = @import("row.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;
const Value = rowmod.Value;
const Row = rowmod.Row;

/// Window-function engine over already-materialized `Row` slices (the same
/// currency `aggregate.zig`/`join.zig` use): callers filter and fetch rows
/// through `Table.select`/`Table.scanAll` first, then feed the result here.
/// Unlike `aggregate.zig`'s GROUP BY (which COLLAPSES rows into one per
/// group), a window function ANNOTATES every input row with a computed
/// value while keeping all of them - SQL's `expr() OVER (PARTITION BY ...
/// ORDER BY ...)`. `compute()` returns one `Value` per row, aligned 1:1
/// with the caller's row order.
pub const WindowKind = enum {
    /// Sequential position (1-based) within the partition in `orderBy`
    /// order. Never skips or repeats, even across ties.
    row_number,
    /// 1-based rank within the partition; rows tying on every `orderBy`
    /// column share a rank, and the NEXT distinct rank skips ahead by the
    /// tie group's size (SQL's `RANK()`).
    rank,
    /// Like `rank`, but the next distinct rank is always exactly one more
    /// than the previous (SQL's `DENSE_RANK()`, no gaps).
    dense_rank,
    sum,
    avg,
    count,
    /// Running count of DISTINCT non-none values of `field` seen so far in
    /// the current frame (SQL's `COUNT(DISTINCT field) OVER (...)`).
    /// Mirrors `aggregate.zig`'s `AggKind.count_distinct` (same
    /// encode-as-hashmap-key dedup via `rowmod.encodeValue`), but as a
    /// RUNNING total instead of one final count per group: under `.rows` the
    /// distinct set only ever grows row by row within a partition, so a
    /// later row's count can never be smaller than an earlier row's. Always
    /// requires `field` (no `COUNT(*)`-style bare form, unlike plain
    /// `count`) - counting distinct values of "nothing" is not meaningful.
    count_distinct,
    min,
    max,
    /// Value of `field` `offset` rows BEFORE the current row, within the
    /// same partition, walked in `orderBy` order (SQL's `LAG()`). A row
    /// whose predecessor at that distance does not exist (falls before the
    /// start of the partition) gets `WindowSpec.default` instead.
    lag,
    /// Like `lag`, but `offset` rows AFTER the current row (SQL's `LEAD()`).
    lead,
    /// `field`'s value on the FIRST row of the current frame (SQL's
    /// `FIRST_VALUE()`). Unlike `lag`/`lead`, this DOES respect `frame`: the
    /// frame's start is always the partition's first row regardless of
    /// `FrameMode` (both variants share `UNBOUNDED PRECEDING`), so
    /// `first_value` is constant across an entire partition no matter which
    /// row is asking.
    first_value,
    /// `field`'s value on the LAST row of the current frame (SQL's
    /// `LAST_VALUE()`). This is the well-known SQL surprise: under `.rows`
    /// (`ROWS UNBOUNDED PRECEDING .. CURRENT ROW`) the frame's end IS the
    /// current row, so `last_value` degenerates to the row's own `field` -
    /// to see the partition's true final value with `orderBy` present, use
    /// `.range`, whose frame end is instead the current row's whole tie
    /// group (matching the running-aggregate family's `.range` semantics),
    /// or omit `orderBy` entirely for the whole-partition frame.
    last_value,
    /// `field`'s value on the `WindowSpec.offset`-th row (1-based) of the
    /// CURRENT frame (SQL's `NTH_VALUE(field, n)`). Shares `first_value`/
    /// `last_value`'s frame-respecting behavior (same `UNBOUNDED PRECEDING`
    /// start, same `.rows`/`.range`/no-`orderBy` frame-end split) rather than
    /// `lag`/`lead`'s fixed physical offset from the CURRENT row - `n` here
    /// counts from the frame's START, not from "here". A position that falls
    /// AFTER the current frame's end (including the well-known `.rows`
    /// degenerate case, where the frame end is the current row itself) gets
    /// `WindowSpec.default` (SQL NULL unless the caller set one), reusing
    /// `lag`/`lead`'s out-of-range convention rather than inventing a new one.
    nth_value,
};

pub const WindowSpec = struct {
    /// Ignored for `row_number`/`rank`/`dense_rank` and for `count`'s
    /// `COUNT(*)` form (pass `""`).
    field: []const u8,
    kind: WindowKind,
    /// `lag`/`lead`: how many rows back (`lag`) or forward (`lead`) within
    /// the partition's `orderBy` sequence to read from. SQL's default of 1
    /// (the immediately adjacent row). `0` is legal (reads the current row
    /// itself). `nth_value`: the 1-based position `n` within the current
    /// frame to read (SQL's `NTH_VALUE(field, n)` - `n` has no SQL default,
    /// but the struct default of `1` degenerates to `first_value`, which is
    /// a sensible fallback rather than a trap). Ignored by every other
    /// `WindowKind`.
    offset: u64 = 1,
    /// `lag`/`lead`/`nth_value`: the value stamped on a row whose target
    /// falls outside the partition (`lag`/`lead`) or outside the current
    /// frame (`nth_value`), mirroring SQL's optional third `LAG`/`LEAD`
    /// argument. Defaults to `.none` (SQL NULL when the argument is
    /// omitted). Ignored by every other `WindowKind`.
    default: Value = .{ .none = {} },
};

pub const WindowError = error{
    /// `sum`/`avg` observed a field holding a non-numeric `Value` (anything
    /// but `.int`/`.float`) - same convention as `aggregate.zig`.
    NonNumericField,
    /// The running integer sum would not fit in `i64`. Never silently
    /// wraps or drops precision by switching to float behind the caller's
    /// back.
    Overflow,
    /// `sum`/`avg`/`min`/`max` require a `field`; only the ranking family
    /// and `count`'s `COUNT(*)` form may omit one.
    MissingField,
    /// `FrameMode.range` was requested together with `row_number`/`rank`/
    /// `dense_rank`. Standard SQL does not accept a frame clause on those at
    /// all (`row_number` is always ROWS-only; `rank`/`dense_rank` already
    /// implement their own fixed tie semantics) - `compute()` rejects the
    /// combination instead of silently ignoring the requested frame.
    RangeNotApplicable,
} || Allocator.Error;

/// The frame a running-aggregate `WindowKind` (`sum`/`avg`/`count`/`min`/
/// `max`) walks when `orderBy` is non-empty - irrelevant when `orderBy` is
/// empty (both modes reduce to the same whole-partition frame then) and
/// irrelevant to the ranking family (`compute()` rejects `.range` there, see
/// `WindowError.RangeNotApplicable`). See `compute()`'s doc comment for the
/// SQL semantics each variant mirrors.
pub const FrameMode = enum {
    /// `ROWS UNBOUNDED PRECEDING .. CURRENT ROW`: a genuine running total,
    /// walked one physical row at a time regardless of ties.
    rows,
    /// `RANGE UNBOUNDED PRECEDING .. CURRENT ROW` (SQL's actual default):
    /// rows tied on every `orderBy` column share the LAST tied row's value
    /// instead of each accumulating their own individual running value.
    range,
};

fn isRanking(kind: WindowKind) bool {
    return kind == .row_number or kind == .rank or kind == .dense_rank;
}

/// `lag`/`lead`: pure positional lookups within the sorted partition. Not a
/// running aggregate (no `RunningAcc`) and not a ranking (no tie handling) -
/// its own third family, sharing `RangeNotApplicable` with the ranking
/// family below since a frame clause has no meaning for either.
fn isOffsetLookup(kind: WindowKind) bool {
    return kind == .lag or kind == .lead;
}

/// `first_value`/`last_value`/`nth_value`: like the running-aggregate
/// family, these DO respect `frame` (unlike `lag`/`lead`) - so they get
/// their own predicate rather than folding into `isOffsetLookup`.
fn isFrameValue(kind: WindowKind) bool {
    return kind == .first_value or kind == .last_value or kind == .nth_value;
}

/// The row field name a `compute()` result column is exposed under (e.g.
/// for CLI/protocol output) - bare `WindowKind` name for the ranking family
/// and for `count`'s `COUNT(*)` form (`field.len == 0`), otherwise
/// `"kind_field"`. Format-identical to `aggregate.zig`'s `specLabel`.
pub fn specLabel(allocator: Allocator, spec: WindowSpec) Allocator.Error![]u8 {
    if (spec.field.len == 0) return allocator.dupe(u8, @tagName(spec.kind));
    return std.fmt.allocPrint(allocator, "{s}_{s}", .{ @tagName(spec.kind), spec.field });
}

/// Streaming per-row accumulator for the running-aggregate family
/// (`sum`/`avg`/`count`/`min`/`max`). Mirrors `aggregate.zig`'s `AccState`
/// (same int-exact/float-fallback dual for `sum`/`avg`, same
/// compare-and-replace for `min`/`max`), minus `count_distinct` (out of
/// scope here - a running "distinct count so far" is a real SQL feature but
/// a separate piece of work). The key behavioral difference from
/// `AccState.take()`: `snapshot()` does NOT transfer ownership of
/// `minv`/`maxv` out of the accumulator, because a running window emits a
/// result after EVERY row, not once at the very end - the accumulator must
/// keep its own copy alive for the next row's snapshot too.
const RunningAcc = struct {
    kind: WindowKind,
    field: []const u8,
    n: u64 = 0,
    sumInt: i64 = 0,
    sumFloat: f64 = 0,
    allInt: bool = true,
    minv: ?Value = null,
    maxv: ?Value = null,
    /// `.count_distinct` only: encoded-`Value` bytes seen so far, one entry
    /// per distinct value - same encode-as-hashmap-key trick
    /// `aggregate.zig`'s `AccState.distinct` uses. Unlike that GROUP BY
    /// counterpart, `snapshot()` below never drains this (a running window
    /// needs the set to keep growing across the WHOLE partition walk, not
    /// just until one final result) - only `deinit` ever frees it.
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
                            // First float observed after an int-only run:
                            // migrate the exact integer sum so far into the
                            // float accumulator once, then continue in float.
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

    /// Returns the accumulator's CURRENT state as a freshly owned `Value`
    /// (a dupe for `min`/`max`, since the accumulator keeps its own copy
    /// alive for subsequent rows - see the type doc comment above).
    /// `.count_distinct` is likewise non-draining - `self.distinct.count()`
    /// is read, never emptied, so the NEXT row's snapshot still sees every
    /// value observed so far (only `deinit` ever frees the set).
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

/// Groups row indices `0..rows.len` by `partitionBy` (empty = a single
/// partition covering every row), preserving first-seen partition order -
/// the window-function analogue of `aggregate.zig`'s `GroupBy` grouping,
/// except every member index is kept instead of collapsed into one result.
/// Multi-column partition keys are built with `row.appendOrdered`
/// (concatenation-safe and unambiguous by construction), the same
/// primitive `index.zig` uses for composite index keys - a row missing one
/// of the `partitionBy` fields contributes `.none` for that column rather
/// than being excluded (unlike `aggregate.zig`'s GROUP BY, which drops rows
/// missing the group field entirely: a window function must still annotate
/// every input row with SOME result, so there is no row to drop it from).
/// Caller owns the returned slice of slices AND each inner slice
/// (`allocator.free` each inner slice, then the outer one).
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
        // `map.putAssumeCapacity`/`order.appendAssumeCapacity` below are
        // INFALLIBLE (capacity reserved just above) and back to back with
        // no fallible statement between them - a bug caught by
        // `computeMany`'s exhaustive OOM sweep test: with plain fallible
        // `map.put` then `order.append`, a failure in `order.append` AFTER
        // `map.put` already succeeded left `key`/`list` reachable from BOTH
        // this iteration's still-armed `errdefer list.deinit(allocator)`
        // AND the function-level `map` cleanup `defer` above (which iterates
        // every entry, including the one just inserted) - both would then
        // free the SAME `list` backing array. Reserving capacity for both
        // `map` and `order` up front and using the assume-capacity variants
        // means nothing fallible can happen between the two inserts, so
        // there is no window for a failure to leave `key`/`list` owned by
        // one structure while their local errdefers are still armed.
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

/// Stable in-place sort of a partition's row INDICES by `orderBy` - the
/// window-function analogue of `query.zig`'s `sortRowsBy`/`aggregate.zig`'s
/// `sortGroupsBy`, but sorting `usize` indices into `rows` rather than the
/// rows themselves (so the caller's row order and `results`' index
/// alignment are never disturbed). `orderBy.len == 0` is a no-op, leaving
/// `indices` in first-seen (input) order.
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

/// Whether `rows[curIdx]` ties `rows[prevIdx]` on every `orderBy` column -
/// the tie-group boundary `rank`/`dense_rank` need to decide whether to
/// advance. Only meaningful once `indices` has already been sorted by the
/// same `orderBy`.
fn tiesWithPrev(rows: []const Row, orderBy: []const querymod.OrderBy, prevIdx: usize, curIdx: usize) bool {
    for (orderBy) |ob| {
        const av = rows[curIdx].get(ob.field) orelse Value{ .none = {} };
        const bv = rows[prevIdx].get(ob.field) orelse Value{ .none = {} };
        if (rowmod.compare(av, bv) != .eq) return false;
    }
    return true;
}

/// `buildPartitions` followed by sorting every partition in place by
/// `orderBy` - the shared prep step `compute()` and `orderedIndices()` both
/// need, factored out so the flattened display order `orderedIndices`
/// exposes is GUARANTEED to match the partition walk `compute()` uses
/// internally (computed once, not two independently-written sorts that
/// could drift apart).
fn partitionedAndSorted(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy) Allocator.Error![][]usize {
    const partitions = try buildPartitions(allocator, rows, partitionBy);
    for (partitions) |indices| sortPartitionByOrder(rows, indices, orderBy);
    return partitions;
}

/// Returns the row-index walk order `compute()` uses internally, flattened:
/// every partition's member indices (each sorted by `orderBy`), partitions
/// concatenated in first-seen order. `compute()`'s own results stay aligned
/// to `rows`' ORIGINAL order regardless of this - this exists for callers
/// (namely `table window`'s CLI) that want to PAGE or DISPLAY results in
/// the same order the window computation itself walked, rather than raw
/// scan order, which is what plain `[start..end]` slicing of `rows` would
/// give instead. Caller owns the returned slice.
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

/// Computes one window-function result `Value` per input row, returned in
/// the SAME order as `rows` (never reorders the caller's data) - the window
/// counterpart of `aggregate.zig`'s `run`, which collapses rows into one
/// per group instead of annotating every one. `partitionBy` splits `rows`
/// into independent groups exactly like GROUP BY (first-seen order, empty
/// = a single partition covering every row); `orderBy` decides the
/// ranking/running-total walk WITHIN each partition.
///
/// Frame semantics follow standard SQL defaults, decided entirely by
/// whether `orderBy` is empty:
///   - `orderBy.len == 0`: `rank`/`dense_rank` treat the whole partition as
///     one tie (every row gets 1); `row_number` still assigns 1..n in
///     first-seen order, since it needs no ordering key to number rows.
///     The running-aggregate family uses the whole-partition frame
///     (`UNBOUNDED PRECEDING .. UNBOUNDED FOLLOWING`) - every row in the
///     partition sees the SAME final total, mirroring `SUM(x) OVER
///     (PARTITION BY p)` with no `ORDER BY` inside the `OVER` clause.
///   - `orderBy.len > 0`: `frame` picks the running-aggregate family's frame
///     along the sorted sequence. `.rows` walks one physical row at a time
///     (`ROWS UNBOUNDED PRECEDING .. CURRENT ROW`) - every row gets its own
///     individual running value, even a row tied with its predecessor.
///     `.range` (SQL's actual default, `RANGE UNBOUNDED PRECEDING ..
///     CURRENT ROW`) instead advances the accumulator by a whole tie group
///     at once and stamps every row in that group with the SAME value (the
///     group's combined total, not each member's own position within it) -
///     the same tie test `rank`/`dense_rank` already use
///     (`tiesWithPrev`), just driving accumulation instead of a rank
///     counter. `frame` is ignored (both variants agree) when `orderBy` is
///     empty, and rejected outright (`error.RangeNotApplicable`) for the
///     ranking family - see `WindowError.RangeNotApplicable`.
///
/// `lag`/`lead` (`spec.offset`/`spec.default`) ignore `frame` entirely (also
/// `error.RangeNotApplicable` under `.range`, same as the ranking family -
/// SQL does not accept a frame clause on either) and read a fixed physical
/// position `spec.offset` rows before (`lag`) or after (`lead`) each row
/// within the sorted partition sequence (first-seen order when `orderBy` is
/// empty) - unlike the running-aggregate family, a tie on `orderBy` does NOT
/// collapse two rows into one lookup target; each remains its own distinct
/// position. A row whose target position falls outside the partition gets
/// `spec.default` (SQL NULL, `.none`, unless the caller set one).
///
/// `first_value`/`last_value` DO respect `frame`, unlike `lag`/`lead`: the
/// frame's start is always the partition's first row regardless of
/// `FrameMode` (so `first_value` is constant across a whole partition), but
/// the frame's END for `last_value` follows the running-aggregate family's
/// same split - `.rows` ends the frame at the CURRENT row (so `last_value`
/// degenerates to that row's own field, SQL's well-known gotcha), `.range`
/// ends it at the current row's whole tie group, and no `orderBy` at all
/// means the whole-partition frame (so `last_value` is the last row in
/// first-seen order, same value for every row). Requires `field` like the
/// running-aggregate family (`error.MissingField` if omitted).
///
/// `nth_value` shares that same frame (start/end identical to
/// `first_value`/`last_value`) but reads the `spec.offset`-th row (1-based)
/// counted from the frame's start rather than always the first or always the
/// last; a position past the frame's current end gets `spec.default`.
///
/// Caller owns the returned slice; free each `Value` (`.free(allocator)`)
/// and the slice itself, or call `freeResults`.
pub fn compute(allocator: Allocator, rows: []const Row, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, spec: WindowSpec, frame: FrameMode) WindowError![]Value {
    const partitions = try partitionedAndSorted(allocator, rows, partitionBy, orderBy);
    defer {
        for (partitions) |p| allocator.free(p);
        allocator.free(partitions);
    }
    return computeOneSpec(allocator, rows, partitions, orderBy, spec, frame);
}

/// The single-`WindowSpec` body of `compute()`, factored out so
/// `computeMany()` can run it once per spec against partitions it already
/// built ONCE - the window-function counterpart of why `aggregate.zig`'s
/// `GroupBy` groups rows once and folds every spec into the same pass,
/// rather than re-grouping per spec. Takes already-partitioned-and-sorted
/// row indices (`partitionedAndSorted`'s output) instead of building them
/// itself.
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
            // Pure positional lookup along the sorted partition sequence -
            // no accumulator, no tie handling (a row tied with its neighbor
            // on `orderBy` is still a DISTINCT physical position for
            // `lag`/`lead`, unlike the ranking family above).
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
            // Positional lookup within the CURRENT frame (start is always
            // the partition's first row, end follows the same
            // whole-partition/.rows/.range split `first_value`/`last_value`
            // use below) - `n` counts from the frame's start, unlike
            // `lag`/`lead`'s offset from the current row. `n < 1` never
            // resolves (WindowSpec.offset defaults to 1, never 0, but a
            // caller reaching this directly - e.g. over the wire - could
            // still send 0).
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
                // Whole-partition frame: first/last row of the partition in
                // first-seen order, same value stamped on every member.
                const firstV = rows[indices[0]].get(spec.field) orelse Value{ .none = {} };
                const lastV = rows[indices[indices.len - 1]].get(spec.field) orelse Value{ .none = {} };
                const v = if (spec.kind == .first_value) firstV else lastV;
                for (indices) |idx| results[idx] = try v.dupe(allocator);
            } else if (frame == .rows) {
                // ROWS frame: start is always the partition's first row;
                // end is the CURRENT row (SQL's well-known LAST_VALUE
                // surprise under the ROWS default).
                const firstV = rows[indices[0]].get(spec.field) orelse Value{ .none = {} };
                for (indices) |idx| {
                    const v = if (spec.kind == .first_value) firstV else (rows[idx].get(spec.field) orelse Value{ .none = {} });
                    results[idx] = try v.dupe(allocator);
                }
            } else {
                // RANGE frame: end is the current row's whole tie group -
                // every row in the group shares that group's LAST member's
                // value, same tie-group walk the running-aggregate family's
                // `.range` branch uses.
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
            // Whole-partition frame: accumulate everything first, THEN
            // stamp the same final value onto every row in the partition.
            for (indices) |idx| try acc.observe(allocator, &rows[idx]);
            for (indices) |idx| results[idx] = try acc.snapshot(allocator);
        } else if (frame == .rows) {
            // ROWS frame: emit the accumulator's state after EACH row,
            // walked in sorted order, even a row tied with its predecessor.
            for (indices) |idx| {
                try acc.observe(allocator, &rows[idx]);
                results[idx] = try acc.snapshot(allocator);
            }
        } else {
            // RANGE frame: advance the accumulator by a whole tie GROUP at
            // once (same `tiesWithPrev` test the ranking family uses to
            // find its own tie boundaries), then stamp every row in that
            // group with the group's combined value - mirroring the
            // whole-partition branch above, just re-run once per group
            // instead of once for the whole partition.
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

/// Computes MULTIPLE window-function columns over the SAME shared
/// `PARTITION BY`/`ORDER BY`/`frame` in one pass - SQL's `SELECT sum(x)
/// OVER w, avg(y) OVER w, rank() OVER w FROM t WINDOW w AS (...)` (every
/// column sharing one window definition), the window-function counterpart
/// of `aggregate.zig`'s multi-`AggSpec` GROUP BY. `partitionedAndSorted` is
/// built exactly ONCE and reused for every spec - unlike calling `compute()`
/// in a loop, which would redo that O(n log n) sort per spec for no reason.
///
/// Returns one entry PER ROW (aligned 1:1 with `rows`, like `compute()`'s
/// result), each entry an independently-owned `[]Value` of length
/// `specs.len` in the SAME order as `specs` - row-major, not the
/// column-major shape the per-spec computation happens in internally,
/// because that is the shape every caller (CLI printing, wire encoding)
/// actually wants: all of one row's annotations together. Caller owns the
/// returned slice; free each inner slice (`.free(allocator)` on every
/// `Value`, then `allocator.free` the slice), or call `freeManyResults`.
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

    // Every column stays independently owned by `columns` up to this
    // point - `results` above holds its OWN dupe of every `Value` (min/max
    // may hold heap-owned text/bytes), never a shared pointer - so it is
    // always safe to free `columns` in full here, on the success path only:
    // the `errdefer` right after `columns` was allocated already covers
    // EVERY error path (early, mid-build, or during the transpose loop
    // above) using the same `filledCols`, which by now equals `specs.len` -
    // a second, unconditional `defer` registered after that `errdefer`
    // would double-free `columns` on any error occurring after it, since an
    // `errdefer` stays armed for the rest of the enclosing scope regardless
    // of what runs after it, not just the statements immediately following.
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

    // Input order: score 30, 10, 20 -> ascending rank order is row1=10
    // (input index 1), row2=20 (index 2), row3=30 (index 0). Results stay
    // aligned to INPUT row order, not the sorted walk order.
    try std.testing.expectEqual(@as(i64, 3), results[0].int); // score 30 -> 3rd
    try std.testing.expectEqual(@as(i64, 1), results[1].int); // score 10 -> 1st
    try std.testing.expectEqual(@as(i64, 2), results[2].int); // score 20 -> 2nd
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

    // warsaw: score 5 (idx0), score 1 (idx2) -> sorted asc: idx2=1st, idx0=2nd.
    try std.testing.expectEqual(@as(i64, 2), results[0].int);
    try std.testing.expectEqual(@as(i64, 1), results[2].int);
    // krakow: score 9 (idx1), score 2 (idx3) -> sorted asc: idx3=1st, idx1=2nd.
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
    // Scores: 10, 10, 20, 30, 30, 30 (already in ascending order so the
    // sort is a no-op tie-preserving identity, keeping the expected
    // positions easy to reason about).
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

    // row_number still needs no ORDER BY - just first-seen position.
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
    // warsaw, in input order: 100, 250 (already ascending by "day").
    // krakow: 40.
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

    try std.testing.expectEqual(@as(i64, 100), results[0].int); // warsaw day1: running=100
    try std.testing.expectEqual(@as(i64, 40), results[1].int); // krakow day1: running=40
    try std.testing.expectEqual(@as(i64, 350), results[2].int); // warsaw day2: running=100+250
}

test "RANGE frame: rows tied on ORDER BY share the tie group's combined total, ROWS gives each its own" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    // One partition, ordered by "day": two rows tied at day=1 (10, 20),
    // then one row at day=2 (5).
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
    // ROWS: each physical row gets its own running total, even tied ones.
    try std.testing.expectEqual(@as(i64, 10), rowsResult[0].int);
    try std.testing.expectEqual(@as(i64, 30), rowsResult[1].int);
    try std.testing.expectEqual(@as(i64, 35), rowsResult[2].int);

    const rangeResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .sum }, .range);
    defer freeResults(allocator, rangeResult);
    // RANGE: both day=1 rows share the GROUP's combined total (10+20=30),
    // not their own individual position within the tie; day=2 then adds 5.
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
    var rows = try threeRowsOnePartition(allocator); // scores 30, 10, 20, all same "team"
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_]querymod.OrderBy{.{ .field = "team" }}; // every row ties on "team"

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
    // scores 30, 10, 20 -> total 60, same value for every row.
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
    // warsaw, in "day" order: tag a, tag b, tag a (repeat) -> distinct count
    // grows 1, 2, 2 (the third row's "a" was already seen).
    // krakow: tag c -> distinct count 1.
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

    try std.testing.expectEqual(@as(i64, 1), results[0].int); // warsaw day1: {a}
    try std.testing.expectEqual(@as(i64, 1), results[1].int); // krakow day1: {c}
    try std.testing.expectEqual(@as(i64, 2), results[2].int); // warsaw day2: {a,b}
    try std.testing.expectEqual(@as(i64, 2), results[3].int); // warsaw day3: {a,b} again, "a" repeats
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
    for (results) |r| try std.testing.expectEqual(@as(i64, 3), r.int); // {x,y,z}
}

test "count_distinct RANGE frame: a tied group's members share one snapshot after the WHOLE group is observed" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    // Tied at day=1: tags "a","b" (2 distinct together, not counted one at a
    // time within the tie like ROWS would). Then day=2 adds "a" again (no
    // growth) then "c" (grows to 3).
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
    // ROWS: each physical row gets its own running distinct count.
    try std.testing.expectEqual(@as(i64, 1), rowsResult[0].int); // {a}
    try std.testing.expectEqual(@as(i64, 2), rowsResult[1].int); // {a,b}
    try std.testing.expectEqual(@as(i64, 2), rowsResult[2].int); // {a,b}, "a" repeats
    try std.testing.expectEqual(@as(i64, 3), rowsResult[3].int); // {a,b,c}

    const rangeResult = try compute(allocator, rows.items, &.{}, &order, .{ .field = "tag", .kind = .count_distinct }, .range);
    defer freeResults(allocator, rangeResult);
    // RANGE: both day=1 rows share the GROUP's combined distinct count (2),
    // not their own individual position within the tie; day=2 group adds
    // "c" (a repeats), landing on 3 for both its members.
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
    try rows.append(try makeRow(allocator, &.{.{ .name = "other", .value = .{ .int = 1 } }})); // missing "tag"
    try rows.append(try makeRow(allocator, &.{.{ .name = "tag", .value = .{ .text = "a" } }}));
    const results = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "tag", .kind = .count_distinct }, .rows);
    defer freeResults(allocator, results);
    for (results) |r| try std.testing.expectEqual(@as(i64, 1), r.int); // only "a" ever counted
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

    try std.testing.expectEqual(@as(i64, 1), results[0][0].int); // count_distinct {a}
    try std.testing.expectEqual(Value{ .none = {} }, results[0][1]); // lag: no predecessor
    try std.testing.expectEqual(@as(i64, 10), results[0][2].int); // running sum
    try std.testing.expectEqual(@as(i64, 1), results[0][3].int); // row_number

    try std.testing.expectEqual(@as(i64, 2), results[1][0].int); // {a,b}
    try std.testing.expectEqual(@as(i64, 10), results[1][1].int); // lag -> day1's amount
    try std.testing.expectEqual(@as(i64, 30), results[1][2].int);
    try std.testing.expectEqual(@as(i64, 2), results[1][3].int);

    try std.testing.expectEqual(@as(i64, 2), results[2][0].int); // {a,b}, "a" repeats
    try std.testing.expectEqual(@as(i64, 20), results[2][1].int); // lag -> day2's amount
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
    // First-seen partition order: warsaw, krakow. Within each, sort by
    // score ascending should reorder relative to input.
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

    // warsaw (first-seen) sorted asc: idx2 (score1), idx0 (score5) - then
    // krakow sorted asc: idx3 (score2), idx1 (score9).
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
    // Every row's `min` slice is its own allocation, not a shared pointer -
    // `freeManyResults` frees each independently, which the testing
    // allocator would already reject as a double free if they aliased.
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
    // Large enough to run past both columns' own computation (sum has no
    // extra allocations per row; min dupes a `Value` per row observed) and
    // into the per-row `rowValues`/`dupe` allocations the transpose loop
    // itself makes - proven by the assertion below, not by counting by hand.
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

    // offset 0 reads the current row itself.
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
    // Two rows tied on "day" within "warsaw" - lag/lead must still treat
    // them as two distinct positions (unlike the RANGE running-aggregate
    // frame, which would collapse ties into one shared value).
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
    // Stable sort keeps warsaw's two tied rows in first-seen order (10 then
    // 20), so warsaw/10's lead is warsaw/20 (not krakow, a different
    // partition entirely), and warsaw/20 (the partition's last row) is NULL.
    try std.testing.expectEqual(@as(i64, 20), lead[0].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lead[1]));
    // krakow is its own partition of one row - always NULL.
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, lead[2]));
}

test "lag/lead without ORDER BY walk first-seen input order" {
    const allocator = std.testing.allocator;
    var rows = try threeRowsOnePartition(allocator); // scores 30, 10, 20, first-seen order
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
    var rows = try threeRowsOnePartition(allocator); // scores 30, 10, 20, first-seen order
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const first = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .first_value }, .rows);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 30), v.int); // first-seen row's score

    const last = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .last_value }, .rows);
    defer freeResults(allocator, last);
    for (last) |v| try std.testing.expectEqual(@as(i64, 20), v.int); // last-seen row's score
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
    // Sorted ascending walk order: 10 (idx1), 20 (idx2), 30 (idx0).

    const first = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .first_value }, .rows);
    defer freeResults(allocator, first);
    for (first) |v| try std.testing.expectEqual(@as(i64, 10), v.int); // ROWS frame start is always the sorted partition's first row

    const last = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .last_value }, .rows);
    defer freeResults(allocator, last);
    // ROWS frame end is CURRENT ROW - last_value degenerates to the row's own field.
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
    // One partition, ordered by "day": two rows tied at day=1 (10, 20), then one row at day=2 (5).
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
    for (first) |v| try std.testing.expectEqual(@as(i64, 10), v.int); // frame start unaffected by RANGE vs ROWS

    const last = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .last_value }, .range);
    defer freeResults(allocator, last);
    // Both day=1 rows share their tie group's LAST member (20), day=2 is its own group (5).
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
    // Both rows of EACH city tie on "day" - RANGE must group them separately
    // per partition, never merging warsaw's tie group with krakow's.
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
    try std.testing.expectEqual(@as(i64, 250), last[0].int); // warsaw's tie group's last member (250)
    try std.testing.expectEqual(@as(i64, 250), last[1].int);
    try std.testing.expectEqual(@as(i64, 90), last[2].int); // krakow's OWN tie group's last member (90), not warsaw's
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
    var rows = try threeRowsOnePartition(allocator); // scores 30, 10, 20, first-seen order
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const n1 = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 1 }, .rows);
    defer freeResults(allocator, n1);
    for (n1) |v| try std.testing.expectEqual(@as(i64, 30), v.int); // same as first_value

    const n3 = try compute(allocator, rows.items, &.{}, &.{}, .{ .field = "score", .kind = .nth_value, .offset = 3 }, .rows);
    defer freeResults(allocator, n3);
    for (n3) |v| try std.testing.expectEqual(@as(i64, 20), v.int); // same as last_value (partition has 3 rows)

    // Past the whole-partition frame's end -> spec.default (SQL NULL unless set).
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
    // Sorted ascending walk order: 10 (idx1, pos0), 20 (idx2, pos1), 30 (idx0, pos2).
    // `results` stays aligned with the ORIGINAL insertion order [30, 10, 20], not
    // the sorted walk order - same convention `first_value`/`last_value`'s ROWS
    // test above uses.
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "score", .kind = .nth_value, .offset = 2 }, .rows);
    defer freeResults(allocator, results);
    // idx1 (score 10, pos0): frame is just itself (size 1) - position 2 does not
    // exist yet -> default.
    try std.testing.expectEqual(Value{ .none = {} }, results[1]);
    // idx2 (score 20, pos1): frame now covers pos0-1 (size 2) - position 2 is
    // this row's own value, 20.
    try std.testing.expectEqual(@as(i64, 20), results[2].int);
    // idx0 (score 30, pos2): frame covers pos0-2 (size 3) - position 2 is still
    // idx2's value, 20 (the frame grew, but the row AT position 2 did not change).
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
    // RANGE's frame is CUMULATIVE (UNBOUNDED PRECEDING through the current tie
    // group, same as the running-aggregate family), not limited to the current
    // group alone - position 3 only becomes reachable once the frame has grown
    // to include the day=2 group too.
    const results = try compute(allocator, rows.items, &.{}, &order, .{ .field = "amount", .kind = .nth_value, .offset = 3 }, .range);
    defer freeResults(allocator, results);
    // day=1's tie group (2 members): frame size is still only 2 - position 3
    // does not exist yet -> default for BOTH members.
    try std.testing.expectEqual(Value{ .none = {} }, results[0]);
    try std.testing.expectEqual(Value{ .none = {} }, results[1]);
    // day=2's tie group: frame now covers all 3 rows - position 3 is this row's
    // own value, 5.
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
    try std.testing.expectEqual(@as(i64, 250), results[0].int); // warsaw's 2nd member
    try std.testing.expectEqual(@as(i64, 250), results[1].int);
    try std.testing.expectEqual(@as(i64, 90), results[2].int); // krakow's OWN 2nd member, not warsaw's
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
    // nth_value(amount, 2): row 1's frame is too small (default None), rows 2-3 both see 20.
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
    try std.testing.expectEqual(@as(i64, 10), many[1][0].int); // lag
    try std.testing.expectEqual(@as(i64, 20), many[0][1].int); // lead
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, many[2][1]));
    try std.testing.expectEqual(@as(i64, 60), many[2][2].int); // running sum, final row
    try std.testing.expectEqual(@as(i64, 3), many[2][3].int); // row_number
}
