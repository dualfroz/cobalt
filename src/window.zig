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

