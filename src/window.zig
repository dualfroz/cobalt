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

