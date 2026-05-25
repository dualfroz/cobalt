const std = @import("std");
const rowmod = @import("row.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;
const Value = rowmod.Value;
const Row = rowmod.Row;
const Page = querymod.Page;
const Predicate = querymod.Predicate;

/// GROUP BY / aggregate engine over already-materialized `Row` slices (the
/// same currency `join.zig` uses): callers filter and fetch rows through
/// `Table.select`/`Table.scanAll` first, then feed them here one at a time.
/// Keeping this decoupled from `query.zig`'s `Table` (rather than adding a
/// method on it) mirrors the existing split between the storage-facing
/// `Table` and the purely row-shaped `join.zig`.
pub const AggKind = enum {
    /// Counts rows. `field.len == 0` counts every observed row
    /// (`COUNT(*)`); otherwise only rows where `field` is present
    /// (`COUNT(field)`).
    count,
    sum,
    avg,
    min,
    max,
    /// Counts distinct non-none values of `field` (SQL's
    /// `COUNT(DISTINCT field)`). Always requires a `field` - there is no
    /// bare `COUNT(DISTINCT *)` form, mirroring `sum`/`avg`/`min`/`max`.
    count_distinct,
};

pub const AggSpec = struct {
    /// Ignored for `.count` with `COUNT(*)` semantics (pass `""`).
    field: []const u8,
    kind: AggKind,
};

pub const AggregateError = error{
    /// `.sum`/`.avg` observed a field holding a non-numeric `Value`
    /// (anything but `.int`/`.float`).
    NonNumericField,
    /// The running integer sum of a `.sum`/`.avg` accumulator would not fit
    /// in `i64`. Never silently wraps or drops precision by switching to
    /// float behind the caller's back.
    Overflow,
    /// `sortGroupsBy` was asked to order by a field that names neither the
    /// GROUP BY key nor any `specLabel` of the aggregate results - the
    /// ORDER BY counterpart of `expr.parse`'s "malformed input is an error,
    /// not a guess" convention `filterHaving` already applies to HAVING.
    UnknownOrderField,
} || Allocator.Error;

/// One row of `GroupBy.finish()`'s result: `group` is the distinct group-key
/// value, `values` holds one result `Value` per input `AggSpec`, same order.
pub const GroupRow = struct {
    group: Value,
    values: []Value,

    pub fn deinit(self: *GroupRow, allocator: Allocator) void {
        self.group.free(allocator);
        for (self.values) |v| v.free(allocator);
        allocator.free(self.values);
    }
};

fn freeGroupRows(allocator: Allocator, rows: []GroupRow) void {
    for (rows) |*r| r.deinit(allocator);
    allocator.free(rows);
}

/// Trims a `GroupBy.finish()`/`run()` result to a `query.zig` `Page` window
/// (0 = unlimited, the same convention `Table.selectPage`/`join.applyPage`
/// use) - the GROUP BY counterpart of pagination for `table_aggregate`/
/// `remote-aggregate`. Grouping has already had to materialize every
/// distinct group to know how many there are, so - exactly like
/// `join.applyPage` - there is no cheaper way to honor `offset`/`limit`
/// than windowing the already-complete result; this always runs after
/// `run()` returns, never instead of it. Not a generic
/// `join.applyPage(GroupRow, ...)` call because `GroupRow.deinit` takes an
/// `allocator` argument (it owns heap payloads on `.group`/`.values`)
/// where `join.applyPage`'s `T.deinit()` takes none.
///
/// Takes ownership of `rows`: frees the backing slice, `.deinit()`s every
/// row that falls outside `[offset, offset+limit)`, and returns a freshly
/// allocated slice holding only the kept rows in their original (first-seen)
/// order. Callers own the returned slice and the rows in it exactly as they
/// would have owned `rows`.
pub fn applyPageGroups(allocator: Allocator, rows: []GroupRow, page: Page) ![]GroupRow {
    const total = rows.len;
    const start = @min(page.offset, total);
    const end = if (page.limit == 0) total else @min(start + page.limit, total);

    for (rows[0..start]) |*r| r.deinit(allocator);
    for (rows[end..total]) |*r| r.deinit(allocator);

    const kept = end - start;
    const result = allocator.alloc(GroupRow, kept) catch |err| {
        for (rows[start..end]) |*r| r.deinit(allocator);
        allocator.free(rows);
        return err;
    };
    @memcpy(result, rows[start..end]);
    allocator.free(rows);
    return result;
}

/// The row field name a `GroupRow`/global aggregate result is exposed under
/// for HAVING and CLI output purposes: bare `AggKind` name for `field.len ==
/// 0` (`COUNT(*)`), otherwise `"kind_field"`. Must stay in sync with
/// `main.zig`'s `printAggLabel`, which prints this same format directly to a
/// writer without allocating - `filterHaving`/`globalMatchesHaving` need an
/// owned string instead because it becomes a `Row` field name, so this is a
/// separate (but format-identical) helper rather than a shared one.
pub fn specLabel(allocator: Allocator, spec: AggSpec) Allocator.Error![]u8 {
    if (spec.field.len == 0) return allocator.dupe(u8, @tagName(spec.kind));
    return std.fmt.allocPrint(allocator, "{s}_{s}", .{ @tagName(spec.kind), spec.field });
}

/// Builds the synthetic probe `Row` a HAVING predicate is evaluated against:
/// one field per `spec` (named via `specLabel`) holding that spec's result
/// `Value` for this group, plus (when `groupField.len > 0`) one field named
/// `groupField` holding the group's own key - so a HAVING clause can
/// reference an aggregate result (`count`, `sum_score`, ...) or the group key
/// itself through the exact same `expr.zig` grammar `WHERE` already uses.
/// Does not take ownership of `groupValue`/`values` - `Row.set` dupes.
fn buildHavingProbe(allocator: Allocator, groupField: []const u8, groupValue: ?Value, specs: []const AggSpec, values: []const Value) !Row {
    var probe = Row.init(allocator);
    errdefer probe.deinit();
    if (groupValue) |gv| try probe.set(groupField, gv);
    for (specs, values) |spec, v| {
        const label = try specLabel(allocator, spec);
        defer allocator.free(label);
        try probe.set(label, v);
    }
    return probe;
}

/// Filters an already-grouped `run()` result by a HAVING predicate - the
/// GROUP BY counterpart of `Predicate.evaluate` on plain rows, applied AFTER
/// aggregation instead of before it (the same WHERE/HAVING split SQL makes).
/// Takes ownership of `groups` (same convention as `applyPageGroups`): every
/// group that fails `having` is `.deinit()`-ed here, the rest are moved
/// (first-seen order preserved) into a freshly allocated result slice.
/// Callers typically run this between `run()` and `applyPageGroups` - HAVING
/// narrows which groups exist before LIMIT/OFFSET windows them, exactly like
/// SQL evaluates `HAVING` before `LIMIT`.
pub fn filterHaving(allocator: Allocator, groups: []GroupRow, groupField: []const u8, specs: []const AggSpec, having: Predicate) AggregateError![]GroupRow {
    var kept: std.ArrayListUnmanaged(GroupRow) = .{};
    var i: usize = 0;
    // `groups[0..i)` is always fully accounted for by this point: each one
    // either moved into `kept` (accepted) or was already `.deinit()`-ed
    // in-loop (rejected) - touching it again here would double-free. Only
    // `groups[i..]` (the current index, mid-evaluation when this errdefer
    // fires, plus everything not yet reached) is still owned by `groups`
    // and needs disposing, the same "always dispose of the input on every
    // path" contract `applyPageGroups` upholds for its own OOM case.
    errdefer {
        for (kept.items) |*g| g.deinit(allocator);
        kept.deinit(allocator);
        for (groups[i..]) |*g| g.deinit(allocator);
        allocator.free(groups);
    }

    while (i < groups.len) : (i += 1) {
        var probe = try buildHavingProbe(allocator, groupField, groups[i].group, specs, groups[i].values);
        defer probe.deinit();
        if (having.evaluate(&probe)) {
            try kept.append(allocator, groups[i]);
        } else {
            groups[i].deinit(allocator);
        }
    }
    allocator.free(groups);
    return kept.toOwnedSlice(allocator);
}

/// HAVING for the ungrouped (`runGlobal`, CLI's `*` sentinel) aggregate path:
/// evaluates `having` against the same kind of synthetic probe row
/// `filterHaving` builds, minus any group-key field (there is no group).
/// Reports only whether the single global result should be kept - unlike
/// `filterHaving` it never frees `values`, since `runGlobal` always produces
/// exactly one result and the caller (which already owns it via
/// `freeGlobalResult`) decides whether to print it or not.
pub fn globalMatchesHaving(allocator: Allocator, specs: []const AggSpec, values: []const Value, having: Predicate) AggregateError!bool {
    var probe = try buildHavingProbe(allocator, "", null, specs, values);
    defer probe.deinit();
    return having.evaluate(&probe);
}

/// Which part of a `GroupRow` a single `OrderBy` column reads from -
/// resolved once per column by `resolveSortKeys` rather than re-matching
/// `ob.field` against `groupField`/every `specLabel` on every comparison
/// `sortGroupsBy`'s sort makes.
const SortKey = union(enum) {
    group,
    value: usize,
};

/// Resolves each `order[i].field` to either the group key itself
/// (`groupField`, e.g. `city`) or the index of the `specs` entry whose
/// `specLabel` matches (e.g. `sum_score`) - the same two-namespace lookup
/// `buildHavingProbe` exposes to a HAVING predicate, done once up front
/// instead of building a probe `Row` per comparison. An `order[i].field`
/// matching neither is `error.UnknownOrderField` rather than silently
/// sorting as if every row tied on that column. Caller owns the returned
/// slice.
fn resolveSortKeys(allocator: Allocator, groupField: []const u8, specs: []const AggSpec, order: []const querymod.OrderBy) AggregateError![]SortKey {
    var keys = try allocator.alloc(SortKey, order.len);
    errdefer allocator.free(keys);
    for (order, 0..) |ob, i| {
        if (groupField.len > 0 and std.mem.eql(u8, ob.field, groupField)) {
            keys[i] = .group;
            continue;
        }
        var found: ?usize = null;
        for (specs, 0..) |spec, j| {
            const label = try specLabel(allocator, spec);
            defer allocator.free(label);
            if (std.mem.eql(u8, label, ob.field)) {
                found = j;
                break;
            }
        }
        keys[i] = .{ .value = found orelse return error.UnknownOrderField };
    }
    return keys;
}

/// Stable in-place sort of `groups` by `order` - the GROUP BY counterpart of
/// `query.zig`'s `sortRowsBy`, applied to already-aggregated `GroupRow`s
/// instead of plain `Row`s so an ORDER BY column can name either the group
/// key (`city`) or an aggregate result (`sum_score`), the same two things a
/// HAVING predicate can reference. Columns compare left to right exactly
/// like `sortRowsBy`/SQL's `ORDER BY a, b`: the first entry decides unless
/// it ties, in which case the next breaks it. `order.len == 0` is a no-op
/// (the common case - most `table aggregate` calls have no ORDER BY).
/// Does not take ownership of `groups` - unlike `filterHaving`/
/// `applyPageGroups`, this never frees or reallocates any group, only
/// reorders the slice in place, so callers keep using their own `defer
/// freeGroupRows(...)` around the call exactly as if it were never made.
/// Typically run after `filterHaving` and before `applyPageGroups` - ORDER
/// BY sees the HAVING-narrowed set and decides what LIMIT/OFFSET's window
/// actually keeps, the same clause order SQL evaluates.
pub fn sortGroupsBy(allocator: Allocator, groups: []GroupRow, groupField: []const u8, specs: []const AggSpec, order: []const querymod.OrderBy) AggregateError!void {
    if (order.len == 0) return;
    const keys = try resolveSortKeys(allocator, groupField, specs, order);
    defer allocator.free(keys);

    const Ctx = struct {
        order: []const querymod.OrderBy,
        keys: []const SortKey,

        fn lessThan(ctx: @This(), a: GroupRow, b: GroupRow) bool {
            for (ctx.order, ctx.keys) |ob, key| {
                const av = switch (key) {
                    .group => a.group,
                    .value => |j| a.values[j],
                };
                const bv = switch (key) {
                    .group => b.group,
                    .value => |j| b.values[j],
                };
                const cmp = rowmod.compare(av, bv);
                if (cmp == .eq) continue;
                return if (ob.descending) cmp == .gt else cmp == .lt;
            }
            return false;
        }
    };
    std.sort.block(GroupRow, groups, Ctx{ .order = order, .keys = keys }, Ctx.lessThan);
}

const AccState = struct {
    kind: AggKind,
    field: []const u8,
    n: u64 = 0,
    sumInt: i64 = 0,
    sumFloat: f64 = 0,
    allInt: bool = true,
    minv: ?Value = null,
    maxv: ?Value = null,
    /// `.count_distinct` only: encoded-`Value` bytes seen so far, one entry
    /// per distinct value (owns each key, same encode-as-hashmap-key trick
    /// `GroupBy.observe` uses for the group key itself).
    distinct: std.StringHashMapUnmanaged(void) = .{},

    fn numericFieldValue(self: *const AccState, row: *const Row) ?Value {
        return row.get(self.field);
    }

    fn observe(self: *AccState, allocator: Allocator, row: *const Row) AggregateError!void {
        switch (self.kind) {
            .count => {
                if (self.field.len == 0) {
                    self.n += 1;
                } else if (row.get(self.field) != null) {
                    self.n += 1;
                }
            },
            .sum, .avg => {
                const v = self.numericFieldValue(row) orelse return;
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
            .count_distinct => {
                const v = row.get(self.field) orelse return;
                const key = try rowmod.encodeValue(allocator, v);
                const res = try self.distinct.getOrPut(allocator, key);
                if (res.found_existing) allocator.free(key);
            },
        }
    }

    /// Produces the final result `Value`, transferring ownership of any
    /// heap payload (`.min`/`.max` on text/bytes fields) out of this
    /// accumulator - a subsequent `deinit` sees `null` and frees nothing,
    /// so the same payload is never freed twice. `.count_distinct` instead
    /// frees its whole tracking set right here (the result is a plain
    /// `.int`, nothing to hand ownership of), which is why this needs
    /// `allocator` - both call sites (`GroupBy.finish`, `runGlobal`) skip a
    /// separate `deinit` call after `take()` entirely, so this is the only
    /// place that set is ever freed on the success path.
    fn take(self: *AccState, allocator: Allocator) Value {
        return switch (self.kind) {
            .count => .{ .int = @intCast(self.n) },
            .sum => if (self.allInt) .{ .int = self.sumInt } else .{ .float = self.sumFloat },
            .avg => blk: {
                if (self.n == 0) break :blk .{ .none = {} };
                const total: f64 = if (self.allInt) @floatFromInt(self.sumInt) else self.sumFloat;
                break :blk .{ .float = total / @as(f64, @floatFromInt(self.n)) };
            },
            .min => blk: {
                const v = self.minv orelse Value{ .none = {} };
                self.minv = null;
                break :blk v;
            },
            .max => blk: {
                const v = self.maxv orelse Value{ .none = {} };
                self.maxv = null;
                break :blk v;
            },
            .count_distinct => blk: {
                const result = Value{ .int = @intCast(self.distinct.count()) };
                var it = self.distinct.keyIterator();
                while (it.next()) |k| allocator.free(k.*);
                self.distinct.deinit(allocator);
                self.distinct = .{};
                break :blk result;
            },
        };
    }

    fn deinit(self: *AccState, allocator: Allocator) void {
        if (self.minv) |v| v.free(allocator);
        if (self.maxv) |v| v.free(allocator);
        var it = self.distinct.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        self.distinct.deinit(allocator);
    }
};

const Bundle = struct {
    groupValue: Value,
    accs: []AccState,

    fn deinit(self: *Bundle, allocator: Allocator) void {
        self.groupValue.free(allocator);
        for (self.accs) |*a| a.deinit(allocator);
        allocator.free(self.accs);
    }
};

/// Streaming GROUP BY accumulator: call `observe` once per candidate row
/// (already filtered by whatever `Predicate` the caller wants applied), then
/// `finish` to materialize one `GroupRow` per distinct group-key value seen,
/// in first-seen order (stable, not sorted - callers that want sorted
/// output can sort the returned slice by `.group` using `row.compare`).
pub const GroupBy = struct {
    allocator: Allocator,
    groupField: []const u8,
    specs: []const AggSpec,
    map: std.StringHashMapUnmanaged(*Bundle) = .{},
    order: std.ArrayListUnmanaged([]const u8) = .{},

    pub fn init(allocator: Allocator, groupField: []const u8, specs: []const AggSpec) GroupBy {
        return .{ .allocator = allocator, .groupField = groupField, .specs = specs };
    }

    /// Safe to call after `finish()` (which empties the internal maps) or on
    /// a `GroupBy` that was never `finish()`-ed (e.g. `observe` returned an
    /// error partway through a batch) - either way, exactly what is still
    /// owned gets freed once.
    pub fn deinit(self: *GroupBy) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.map = .{};
        self.order = .{};
    }

    /// Rows missing `groupField` entirely are excluded from every group
    /// (no "null group" bucket) - the same omission `Table.createIndex`'s
    /// backfill applies to rows missing an indexed field.
    pub fn observe(self: *GroupBy, row: *const Row) AggregateError!void {
        const groupVal = row.get(self.groupField) orelse return;
        const key = try rowmod.encodeValue(self.allocator, groupVal);

        if (self.map.get(key)) |bundle| {
            self.allocator.free(key);
            for (bundle.accs) |*a| try a.observe(self.allocator, row);
            return;
        }

        // Scoped to this block so the errdefers below only guard the
        // allocation itself: once `bundle` is handed to `self.map.put`
        // just after, ownership has moved there, and a later failure (the
        // final observe loop) must NOT free it out from under the map -
        // an errdefer spanning the whole function would do exactly that
        // and leave a dangling pointer in `self.map`.
        const bundle = blk: {
            const b = try self.allocator.create(Bundle);
            errdefer self.allocator.destroy(b);
            const accs = try self.allocator.alloc(AccState, self.specs.len);
            errdefer self.allocator.free(accs);
            for (self.specs, 0..) |spec, i| accs[i] = .{ .kind = spec.kind, .field = spec.field };
            const dupedGroup = try groupVal.dupe(self.allocator);
            b.* = .{ .groupValue = dupedGroup, .accs = accs };
            break :blk b;
        };

        try self.map.put(self.allocator, key, bundle);
        try self.order.append(self.allocator, key);
        for (bundle.accs) |*a| try a.observe(self.allocator, row);
    }

    /// Consumes the accumulated groups into an owned `[]GroupRow` and
    /// leaves `self` empty (a subsequent `deinit()` is then a no-op).
    pub fn finish(self: *GroupBy) AggregateError![]GroupRow {
        var results = try self.allocator.alloc(GroupRow, self.order.items.len);
        var filled: usize = 0;
        errdefer freeGroupRows(self.allocator, results[0..filled]);

        for (self.order.items) |key| {
            const bundle = self.map.get(key).?;
            var values = try self.allocator.alloc(Value, bundle.accs.len);
            errdefer self.allocator.free(values);
            for (bundle.accs, 0..) |*a, j| values[j] = a.take(self.allocator);
            results[filled] = .{ .group = bundle.groupValue, .values = values };
            filled += 1;
        }

        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*.accs);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.map = .{};
        self.order = .{};

        return results;
    }
};

/// Convenience wrapper: groups `rows` by `groupField`, applies `specs`, and
/// returns the finished result in one call.
pub fn run(allocator: Allocator, rows: []const Row, groupField: []const u8, specs: []const AggSpec) AggregateError![]GroupRow {
    var gb = GroupBy.init(allocator, groupField, specs);
    errdefer gb.deinit();
    for (rows) |*r| try gb.observe(r);
    return gb.finish();
}

/// A single aggregate row over all of `rows` with no grouping (SQL's
/// `SELECT COUNT(*), SUM(x) FROM t` with no `GROUP BY`) - always produces
/// exactly one result, even for zero input rows (every accumulator still
/// reports its identity result: `count` 0, `sum` 0, `avg`/`min`/`max`
/// `.none`).
pub fn runGlobal(allocator: Allocator, rows: []const Row, specs: []const AggSpec) AggregateError![]Value {
    var accs = try allocator.alloc(AccState, specs.len);
    defer allocator.free(accs);
    for (specs, 0..) |spec, i| accs[i] = .{ .kind = spec.kind, .field = spec.field };
    errdefer for (accs) |*a| a.deinit(allocator);

    for (rows) |*r| {
        for (accs) |*a| try a.observe(allocator, r);
    }

    var values = try allocator.alloc(Value, specs.len);
    for (accs, 0..) |*a, i| values[i] = a.take(allocator);
    return values;
}

pub fn freeGlobalResult(allocator: Allocator, values: []Value) void {
    for (values) |v| v.free(allocator);
    allocator.free(values);
}

fn makeRow(allocator: Allocator, fields: []const rowmod.Field) !Row {
    var r = Row.init(allocator);
    for (fields) |f| try r.set(f.name, f.value);
    return r;
}

fn findGroup(rows: []const GroupRow, group: Value) ?*const GroupRow {
    for (rows) |*r| {
        if (Value.eql(r.group, group)) return r;
    }
    return null;
}

test "count sum avg min max group by text field" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, score: i64 }{
        .{ .city = "warsaw", .score = 10 },
        .{ .city = "warsaw", .score = 30 },
        .{ .city = "krakow", .score = 5 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "score", .value = .{ .int = d.score } },
        }));
    }

    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
        .{ .field = "score", .kind = .avg },
        .{ .field = "score", .kind = .min },
        .{ .field = "score", .kind = .max },
    };
    const groups = try run(allocator, rows.items, "city", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 2), groups.len);

    const warsaw = findGroup(groups, .{ .text = "warsaw" }).?;
    try std.testing.expectEqual(@as(i64, 2), warsaw.values[0].int);
    try std.testing.expectEqual(@as(i64, 40), warsaw.values[1].int);
    try std.testing.expectApproxEqAbs(@as(f64, 20), warsaw.values[2].float, 1e-9);
    try std.testing.expectEqual(@as(i64, 10), warsaw.values[3].int);
    try std.testing.expectEqual(@as(i64, 30), warsaw.values[4].int);

    const krakow = findGroup(groups, .{ .text = "krakow" }).?;
    try std.testing.expectEqual(@as(i64, 1), krakow.values[0].int);
    try std.testing.expectEqual(@as(i64, 5), krakow.values[1].int);
}

test "sum and avg skip rows missing the field, count star still counts them" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "team", .value = .{ .text = "a" } },
        .{ .name = "points", .value = .{ .int = 7 } },
    }));
    // No "points" field on this row - must not participate in sum/avg, but
    // must still be counted by COUNT(*).
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "team", .value = .{ .text = "a" } },
    }));

    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "points", .kind = .count },
        .{ .field = "points", .kind = .sum },
        .{ .field = "points", .kind = .avg },
    };
    const groups = try run(allocator, rows.items, "team", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 1), groups.len);
    try std.testing.expectEqual(@as(i64, 2), groups[0].values[0].int); // COUNT(*)
    try std.testing.expectEqual(@as(i64, 1), groups[0].values[1].int); // COUNT(points)
    try std.testing.expectEqual(@as(i64, 7), groups[0].values[2].int); // SUM(points)
    try std.testing.expectApproxEqAbs(@as(f64, 7), groups[0].values[3].float, 1e-9); // AVG(points)
}

test "avg on a group where the field is always missing reports none" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{.{ .name = "team", .value = .{ .text = "a" } }}));

    const specs = [_]AggSpec{.{ .field = "points", .kind = .avg }};
    const groups = try run(allocator, rows.items, "team", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 1), groups.len);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, groups[0].values[0]));
}

test "sum stays exact integer until a float value forces it to switch" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .int = 3 } },
    }));
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .int = 4 } },
    }));

    const specs = [_]AggSpec{.{ .field = "x", .kind = .sum }};
    {
        const groups = try run(allocator, rows.items, "g", &specs);
        defer freeGroupRows(allocator, groups);
        // All-int input: exact int result, not a float with rounding risk.
        try std.testing.expectEqual(rowmod.ValueTag.int, @as(rowmod.ValueTag, groups[0].values[0]));
        try std.testing.expectEqual(@as(i64, 7), groups[0].values[0].int);
    }

    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .float = 0.5 } },
    }));
    {
        const groups = try run(allocator, rows.items, "g", &specs);
        defer freeGroupRows(allocator, groups);
        try std.testing.expectEqual(rowmod.ValueTag.float, @as(rowmod.ValueTag, groups[0].values[0]));
        try std.testing.expectApproxEqAbs(@as(f64, 7.5), groups[0].values[0].float, 1e-9);
    }
}

test "sum reports overflow instead of silently wrapping" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .int = std.math.maxInt(i64) } },
    }));
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .int = 1 } },
    }));

    const specs = [_]AggSpec{.{ .field = "x", .kind = .sum }};
    var gb = GroupBy.init(allocator, "g", &specs);
    defer gb.deinit();
    try gb.observe(&rows.items[0]);
    try std.testing.expectError(error.Overflow, gb.observe(&rows.items[1]));
}

test "sum on a non-numeric field errors without leaking accumulated state" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "g", .value = .{ .int = 1 } },
        .{ .name = "x", .value = .{ .text = "nope" } },
    }));

    const specs = [_]AggSpec{.{ .field = "x", .kind = .sum }};
    var gb = GroupBy.init(allocator, "g", &specs);
    defer gb.deinit();
    try std.testing.expectError(error.NonNumericField, gb.observe(&rows.items[0]));
}

test "min and max use the total order across owned text values" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const names = [_][]const u8{ "delta", "alpha", "charlie", "bravo" };
    for (names) |n| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "g", .value = .{ .int = 1 } },
            .{ .name = "name", .value = .{ .text = n } },
        }));
    }

    const specs = [_]AggSpec{
        .{ .field = "name", .kind = .min },
        .{ .field = "name", .kind = .max },
    };
    const groups = try run(allocator, rows.items, "g", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqualStrings("alpha", groups[0].values[0].text);
    try std.testing.expectEqualStrings("delta", groups[0].values[1].text);
}

test "count_distinct counts unique field values once per group, repeats collapsed" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { team: []const u8, tag: []const u8 }{
        .{ .team = "a", .tag = "red" },
        .{ .team = "a", .tag = "blue" },
        .{ .team = "a", .tag = "red" }, // repeat, must not double count
        .{ .team = "b", .tag = "green" },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "team", .value = .{ .text = d.team } },
            .{ .name = "tag", .value = .{ .text = d.tag } },
        }));
    }

    const specs = [_]AggSpec{.{ .field = "tag", .kind = .count_distinct }};
    const groups = try run(allocator, rows.items, "team", &specs);
    defer freeGroupRows(allocator, groups);

    const a = findGroup(groups, .{ .text = "a" }).?;
    try std.testing.expectEqual(@as(i64, 2), a.values[0].int);
    const b = findGroup(groups, .{ .text = "b" }).?;
    try std.testing.expectEqual(@as(i64, 1), b.values[0].int);
}

test "count_distinct ignores rows missing the field and never counts none as a value" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "team", .value = .{ .text = "a" } },
        .{ .name = "tag", .value = .{ .text = "red" } },
    }));
    // No "tag" field on this row - must not create a phantom distinct value.
    try rows.append(try makeRow(allocator, &.{
        .{ .name = "team", .value = .{ .text = "a" } },
    }));

    const specs = [_]AggSpec{.{ .field = "tag", .kind = .count_distinct }};
    const groups = try run(allocator, rows.items, "team", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 1), groups.len);
    try std.testing.expectEqual(@as(i64, 1), groups[0].values[0].int);
}

test "count_distinct on zero observed values reports zero, not none" {
    const allocator = std.testing.allocator;
    const rows: []const Row = &.{};
    const specs = [_]AggSpec{.{ .field = "tag", .kind = .count_distinct }};
    const values = try runGlobal(allocator, rows, &specs);
    defer freeGlobalResult(allocator, values);

    try std.testing.expectEqual(@as(i64, 0), values[0].int);
}

test "count_distinct propagates OutOfMemory without leaking already-tracked distinct values" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const tags = [_][]const u8{ "red", "blue", "green" };
    for (tags) |t| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "g", .value = .{ .text = "x" } },
            .{ .name = "tag", .value = .{ .text = t } },
        }));
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 6 });
    const specs = [_]AggSpec{.{ .field = "tag", .kind = .count_distinct }};
    var gb = GroupBy.init(failing.allocator(), "g", &specs);
    defer gb.deinit();

    var sawError = false;
    for (rows.items) |*r| {
        gb.observe(r) catch {
            sawError = true;
            break;
        };
    }
    try std.testing.expect(sawError);
}

test "rows missing the group field are excluded from every group" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    try rows.append(try makeRow(allocator, &.{.{ .name = "team", .value = .{ .text = "a" } }}));
    try rows.append(try makeRow(allocator, &.{})); // no "team" field at all

    const specs = [_]AggSpec{.{ .field = "", .kind = .count }};
    const groups = try run(allocator, rows.items, "team", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 1), groups.len);
    try std.testing.expectEqual(@as(i64, 1), groups[0].values[0].int);
}

test "group order is first-seen, not sorted" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const order = [_][]const u8{ "z", "a", "m" };
    for (order) |g| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "g", .value = .{ .text = g } }}));
    }

    const specs = [_]AggSpec{.{ .field = "", .kind = .count }};
    const groups = try run(allocator, rows.items, "g", &specs);
    defer freeGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 3), groups.len);
    try std.testing.expectEqualStrings("z", groups[0].group.text);
    try std.testing.expectEqualStrings("a", groups[1].group.text);
    try std.testing.expectEqualStrings("m", groups[2].group.text);
}

test "runGlobal aggregates every row into a single result with no grouping" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    var i: i64 = 1;
    while (i <= 4) : (i += 1) {
        try rows.append(try makeRow(allocator, &.{.{ .name = "x", .value = .{ .int = i } }}));
    }

    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "x", .kind = .sum },
        .{ .field = "x", .kind = .max },
    };
    const values = try runGlobal(allocator, rows.items, &specs);
    defer freeGlobalResult(allocator, values);

    try std.testing.expectEqual(@as(i64, 4), values[0].int);
    try std.testing.expectEqual(@as(i64, 10), values[1].int);
    try std.testing.expectEqual(@as(i64, 4), values[2].int);
}

test "runGlobal on zero rows still reports identity results, not an error" {
    const allocator = std.testing.allocator;
    const rows: []const Row = &.{};
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "x", .kind = .sum },
        .{ .field = "x", .kind = .max },
    };
    const values = try runGlobal(allocator, rows, &specs);
    defer freeGlobalResult(allocator, values);

    try std.testing.expectEqual(@as(i64, 0), values[0].int);
    try std.testing.expectEqual(@as(i64, 0), values[1].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, values[2]));
}

test "GroupBy propagates OutOfMemory without leaking any accumulated group" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const groupNames = [_][]const u8{ "a", "b", "c" };
    for (groupNames) |g| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "g", .value = .{ .text = g } },
            .{ .name = "x", .value = .{ .int = 1 } },
        }));
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 6 });
    const specs = [_]AggSpec{.{ .field = "x", .kind = .sum }};
    var gb = GroupBy.init(failing.allocator(), "g", &specs);
    defer gb.deinit();

    var sawError = false;
    for (rows.items) |*r| {
        gb.observe(r) catch {
            sawError = true;
            break;
        };
    }
    try std.testing.expect(sawError);
}

fn fourGroupRows(allocator: Allocator) ![]GroupRow {
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const groupNames = [_][]const u8{ "a", "b", "c", "d" };
    for (groupNames) |g| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "g", .value = .{ .text = g } }}));
    }
    const specs = [_]AggSpec{.{ .field = "", .kind = .count }};
    return run(allocator, rows.items, "g", &specs);
}

fn firstLettersOf(rows: []const GroupRow) [4]u8 {
    var out: [4]u8 = undefined;
    for (rows, 0..) |r, i| out[i] = r.group.text[0];
    return out;
}

test "applyPageGroups with offset and limit keeps a middle window in first-seen order" {
    const allocator = std.testing.allocator;
    const groups = try fourGroupRows(allocator);
    try std.testing.expectEqual(@as(usize, 4), groups.len);

    const paged = try applyPageGroups(allocator, groups, .{ .offset = 1, .limit = 2 });
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqual(@as(usize, 2), paged.len);
    try std.testing.expectEqualStrings("b", paged[0].group.text);
    try std.testing.expectEqualStrings("c", paged[1].group.text);
}

test "applyPageGroups with limit 0 returns every group, matching unpaged run" {
    const allocator = std.testing.allocator;
    const groups = try fourGroupRows(allocator);
    const paged = try applyPageGroups(allocator, groups, .{});
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqualSlices(u8, &.{ 'a', 'b', 'c', 'd' }, &firstLettersOf(paged));
}

test "applyPageGroups with offset past the end returns nothing" {
    const allocator = std.testing.allocator;
    const groups = try fourGroupRows(allocator);
    const paged = try applyPageGroups(allocator, groups, .{ .offset = 50 });
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqual(@as(usize, 0), paged.len);
}

test "applyPageGroups with limit larger than the remaining groups stops at the end" {
    const allocator = std.testing.allocator;
    const groups = try fourGroupRows(allocator);
    const paged = try applyPageGroups(allocator, groups, .{ .offset = 3, .limit = 100 });
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqualStrings("d", paged[0].group.text);
}

test "applyPageGroups propagates OutOfMemory from its own result allocation without leaking any group" {
    const allocator = std.testing.allocator;
    const groups = try fourGroupRows(allocator);
    try std.testing.expectEqual(@as(usize, 4), groups.len);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, applyPageGroups(failing.allocator(), groups, .{ .offset = 1, .limit = 2 }));
    // No explicit assertion beyond this: `testing.allocator`'s leak detector
    // at process exit is the real check - every one of the 4 `GroupRow`s (2
    // kept by the window, 2 trimmed outside it) must have been
    // `.deinit(allocator)`-ed on the error path, and the `rows` backing
    // slice itself freed, or this test fails on leak. Every `GroupRow` here
    // was built by `run()` using the real `testing.allocator`, so the error
    // path frees through that same allocator regardless of which allocator
    // `applyPageGroups` was asked to allocate its OWN result slice with -
    // the exact isolation `join.zig`'s analogous OOM test documents.
}

fn threeCityGroups(allocator: Allocator) ![]GroupRow {
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    const data = [_]struct { city: []const u8, score: i64 }{
        .{ .city = "warsaw", .score = 10 },
        .{ .city = "warsaw", .score = 30 },
        .{ .city = "krakow", .score = 5 },
        .{ .city = "gdansk", .score = 100 },
        .{ .city = "gdansk", .score = 100 },
        .{ .city = "gdansk", .score = 100 },
    };
    for (data) |d| {
        try rows.append(try makeRow(allocator, &.{
            .{ .name = "city", .value = .{ .text = d.city } },
            .{ .name = "score", .value = .{ .int = d.score } },
        }));
    }
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    return run(allocator, rows.items, "city", &specs);
}

test "filterHaving keeps only groups whose aggregate result matches the predicate" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    // warsaw: count=2 sum=40, krakow: count=1 sum=5, gdansk: count=3 sum=300
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    const having = Predicate{ .gt = .{ .field = "count", .value = .{ .int = 1 } } };
    const kept = try filterHaving(allocator, groups, "city", &specs, having);
    defer freeGroupRows(allocator, kept);

    try std.testing.expectEqual(@as(usize, 2), kept.len);
    try std.testing.expectEqualStrings("warsaw", kept[0].group.text);
    try std.testing.expectEqualStrings("gdansk", kept[1].group.text);
}

test "filterHaving can reference the underlying aggregate field name (sum_field)" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    const having = Predicate{ .gte = .{ .field = "sum_score", .value = .{ .int = 100 } } };
    const kept = try filterHaving(allocator, groups, "city", &specs, having);
    defer freeGroupRows(allocator, kept);

    try std.testing.expectEqual(@as(usize, 1), kept.len);
    try std.testing.expectEqualStrings("gdansk", kept[0].group.text);
}

test "filterHaving can also reference the group key itself, not just an aggregate result" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    const having = Predicate{ .ne = .{ .field = "city", .value = .{ .text = "krakow" } } };
    const kept = try filterHaving(allocator, groups, "city", &specs, having);
    defer freeGroupRows(allocator, kept);

    try std.testing.expectEqual(@as(usize, 2), kept.len);
    try std.testing.expectEqualStrings("warsaw", kept[0].group.text);
    try std.testing.expectEqualStrings("gdansk", kept[1].group.text);
}

test "filterHaving that rejects every group returns an empty, still-valid slice" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    const having = Predicate{ .gt = .{ .field = "count", .value = .{ .int = 1000 } } };
    const kept = try filterHaving(allocator, groups, "city", &specs, having);
    defer freeGroupRows(allocator, kept);

    try std.testing.expectEqual(@as(usize, 0), kept.len);
}

test "filterHaving composes with applyPageGroups: HAVING narrows before LIMIT/OFFSET windows" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    // Only warsaw and gdansk survive HAVING; a limit of 1 then keeps just
    // the first of those two (warsaw, first-seen), not the first of all
    // three original groups.
    const having = Predicate{ .gt = .{ .field = "count", .value = .{ .int = 1 } } };
    const filtered = try filterHaving(allocator, groups, "city", &specs, having);
    const paged = try applyPageGroups(allocator, filtered, .{ .limit = 1 });
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqualStrings("warsaw", paged[0].group.text);
}

test "filterHaving propagates OutOfMemory without leaking any group, kept or rejected" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    const having = Predicate{ .gt = .{ .field = "count", .value = .{ .int = 1 } } };

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, filterHaving(failing.allocator(), groups, "city", &specs, having));
    // Leak detector on `std.testing.allocator` at process exit is the real
    // check here (same pattern as `applyPageGroups`'s analogous OOM test):
    // every one of the 3 groups `threeCityGroups` built with the real
    // allocator must still get freed on this early failure, even though
    // `filterHaving` itself was asked to allocate its OWN bookkeeping
    // (`kept`) through the failing allocator.
}

test "globalMatchesHaving reports true or false without freeing the caller's values" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    var i: i64 = 1;
    while (i <= 5) : (i += 1) {
        try rows.append(try makeRow(allocator, &.{.{ .name = "x", .value = .{ .int = i } }}));
    }
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "x", .kind = .sum },
    };
    const values = try runGlobal(allocator, rows.items, &specs);
    defer freeGlobalResult(allocator, values);

    const passing = Predicate{ .eq = .{ .field = "count", .value = .{ .int = 5 } } };
    try std.testing.expect(try globalMatchesHaving(allocator, &specs, values, passing));

    const failing = Predicate{ .gt = .{ .field = "sum_x", .value = .{ .int = 1000 } } };
    try std.testing.expect(!try globalMatchesHaving(allocator, &specs, values, failing));
}

test "sortGroupsBy orders by the group key ascending by default" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);

    const order = [_]querymod.OrderBy{.{ .field = "city" }};
    try sortGroupsBy(allocator, groups, "city", &.{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    }, &order);

    try std.testing.expectEqualStrings("gdansk", groups[0].group.text);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqualStrings("warsaw", groups[2].group.text);
}

test "sortGroupsBy orders by the group key descending when asked" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);

    const order = [_]querymod.OrderBy{.{ .field = "city", .descending = true }};
    try sortGroupsBy(allocator, groups, "city", &.{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    }, &order);

    try std.testing.expectEqualStrings("warsaw", groups[0].group.text);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqualStrings("gdansk", groups[2].group.text);
}

test "sortGroupsBy orders by an aggregate result label, not just the group key" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };

    // warsaw sum=40, krakow sum=5, gdansk sum=300 - ascending by sum_score
    // is a completely different order than ascending by city.
    const order = [_]querymod.OrderBy{.{ .field = "sum_score" }};
    try sortGroupsBy(allocator, groups, "city", &specs, &order);

    try std.testing.expectEqualStrings("krakow", groups[0].group.text);
    try std.testing.expectEqualStrings("warsaw", groups[1].group.text);
    try std.testing.expectEqualStrings("gdansk", groups[2].group.text);
}

test "sortGroupsBy breaks ties left to right across multiple order columns" {
    const allocator = std.testing.allocator;
    var rows = std.ArrayList(Row).init(allocator);
    defer {
        for (rows.items) |*r| r.deinit();
        rows.deinit();
    }
    // Every group has count == 1 (a full tie on the first order column), so
    // only the second column (the group key itself) can decide the order -
    // built out of first-seen order d,b,a,c specifically so an
    // alphabetical result proves the second column actually ran, rather
    // than the sort coincidentally matching input order.
    const groupNames = [_][]const u8{ "d", "b", "a", "c" };
    for (groupNames) |g| {
        try rows.append(try makeRow(allocator, &.{.{ .name = "g", .value = .{ .text = g } }}));
    }
    const specs = [_]AggSpec{.{ .field = "", .kind = .count }};
    const groups = try run(allocator, rows.items, "g", &specs);
    defer freeGroupRows(allocator, groups);

    const order = [_]querymod.OrderBy{
        .{ .field = "count" },
        .{ .field = "g" },
    };
    try sortGroupsBy(allocator, groups, "g", &specs, &order);

    try std.testing.expectEqualStrings("a", groups[0].group.text);
    try std.testing.expectEqualStrings("b", groups[1].group.text);
    try std.testing.expectEqualStrings("c", groups[2].group.text);
    try std.testing.expectEqualStrings("d", groups[3].group.text);
}

test "sortGroupsBy with an empty order list leaves groups in first-seen order" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);

    try sortGroupsBy(allocator, groups, "city", &.{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    }, &.{});

    try std.testing.expectEqualStrings("warsaw", groups[0].group.text);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqualStrings("gdansk", groups[2].group.text);
}

test "sortGroupsBy rejects a field that names neither the group key nor a known aggregate label" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);

    const order = [_]querymod.OrderBy{.{ .field = "not_a_real_field" }};
    try std.testing.expectError(error.UnknownOrderField, sortGroupsBy(allocator, groups, "city", &.{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    }, &order));
}

test "sortGroupsBy composes with filterHaving and applyPageGroups: ORDER BY reorders before LIMIT/OFFSET windows" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };
    // HAVING keeps only warsaw (count=2, sum=40) and gdansk (count=3,
    // sum=300); descending sum_score then puts gdansk first even though
    // warsaw was first-seen - a limit of 1 must keep gdansk, not warsaw.
    const having = Predicate{ .gt = .{ .field = "count", .value = .{ .int = 1 } } };
    const filtered = try filterHaving(allocator, groups, "city", &specs, having);
    const order = [_]querymod.OrderBy{.{ .field = "sum_score", .descending = true }};
    try sortGroupsBy(allocator, filtered, "city", &specs, &order);
    const paged = try applyPageGroups(allocator, filtered, .{ .limit = 1 });
    defer freeGroupRows(allocator, paged);

    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqualStrings("gdansk", paged[0].group.text);
}

test "sortGroupsBy propagates OutOfMemory without leaking or freeing the caller's groups" {
    const allocator = std.testing.allocator;
    const groups = try threeCityGroups(allocator);
    defer freeGroupRows(allocator, groups);
    const specs = [_]AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "score", .kind = .sum },
    };

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const order = [_]querymod.OrderBy{.{ .field = "city" }};
    try std.testing.expectError(error.OutOfMemory, sortGroupsBy(failing.allocator(), groups, "city", &specs, &order));

    // `sortGroupsBy` never took ownership of `groups` (unlike
    // `filterHaving`), so the outer `defer freeGroupRows(allocator, ...)`
    // above must still see every group intact and still first-seen order
    // (untouched, not partially sorted) - both the leak detector on
    // `std.testing.allocator` and this ordering check are the real
    // assertions here.
    try std.testing.expectEqualStrings("warsaw", groups[0].group.text);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqualStrings("gdansk", groups[2].group.text);
}
