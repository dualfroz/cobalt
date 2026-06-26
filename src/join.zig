const std = @import("std");
const rowmod = @import("row.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;
const Row = rowmod.Row;
const Table = querymod.Table;
const Predicate = querymod.Predicate;

/// One matched pair produced by `innerJoin`: the left table's row and the
/// right table's row that satisfied `leftRow.get(leftField) ==
/// rightRow.get(rightField)`. Kept as two separate owned Rows rather than
/// merged into one flat namespace, so join output never has to invent a
/// collision rule for a field name that happens to exist on both sides.
pub const JoinedRow = struct {
    left: Row,
    right: Row,

    pub fn deinit(self: *JoinedRow) void {
        self.left.deinit();
        self.right.deinit();
    }
};

pub fn freeJoined(allocator: Allocator, rows: []JoinedRow) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

/// Independent copy of `row` via its own encode/decode round trip, so a
/// join result can outlive (and be freed separately from) the pooled
/// `Table.select` slice it was matched out of - the same row can appear in
/// more than one output pair on a one-to-many join.
fn dupeRow(allocator: Allocator, row: *const Row) !Row {
    const buf = try row.encode(allocator);
    defer allocator.free(buf);
    return try Row.decode(allocator, buf);
}

/// Inner equi-join between `left` and `right` on
/// `leftRow.get(leftField) == rightRow.get(rightField)` (compared with
/// `row.compare`, so a mismatched type - e.g. an int on one side against a
/// float on the other - never matches, exactly like `Predicate.eq`).
/// `leftPred`/`rightPred` filter each side first, evaluated exactly like
/// `Table.select` (including its own index usage). A row missing the join
/// field entirely never matches anything, on either side.
///
/// Join strategy is chosen once, not per call site: if `right` already has
/// a secondary index on `rightField`, this runs an index nested-loop join -
/// one `right.select` per surviving left row, narrowed through that index
/// exactly the way a plain `eq` query would be. Otherwise it builds an
/// in-memory hash table over the (already `rightPred`-filtered) right rows
/// keyed by the join value and probes it once per left row - a hash join,
/// so an unindexed join over two large tables still costs
/// O(leftRows + rightRows) rather than O(leftRows * rightRows).
///
/// Caller owns the returned slice and every `JoinedRow` in it; free with
/// `freeJoined`.
pub fn innerJoin(
    allocator: Allocator,
    left: *Table,
    leftField: []const u8,
    leftPred: ?Predicate,
    right: *Table,
    rightField: []const u8,
    rightPred: ?Predicate,
) ![]JoinedRow {
    const leftRows = try left.select(leftPred);
    defer querymod.freeRows(allocator, leftRows);

    var results = std.ArrayList(JoinedRow).init(allocator);
    errdefer {
        for (results.items) |*r| r.deinit();
        results.deinit();
    }

    if (right.hasIndex(rightField)) {
        for (leftRows) |*lrow| {
            const v = lrow.get(leftField) orelse continue;
            const eqPred = Predicate{ .eq = .{ .field = rightField, .value = v } };
            var combinedBuf: [2]Predicate = undefined;
            const pred: Predicate = if (rightPred) |rp| blk: {
                combinedBuf[0] = eqPred;
                combinedBuf[1] = rp;
                break :blk Predicate{ .and_ = combinedBuf[0..] };
            } else eqPred;

            const matches = try right.select(pred);
            defer querymod.freeRows(allocator, matches);
            for (matches) |*mrow| {
                var lcopy = try dupeRow(allocator, lrow);
                errdefer lcopy.deinit();
                const rcopy = try dupeRow(allocator, mrow);
                try results.append(.{ .left = lcopy, .right = rcopy });
            }
        }
        return results.toOwnedSlice();
    }

    const rightRows = try right.select(rightPred);
    defer querymod.freeRows(allocator, rightRows);

    var buckets = std.StringHashMap(std.ArrayList(usize)).init(allocator);
    defer {
        var it = buckets.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            allocator.free(entry.key_ptr.*);
        }
        buckets.deinit();
    }

    for (rightRows, 0..) |*rrow, i| {
        const v = rrow.get(rightField) orelse continue;
        const key = try rowmod.encodeValue(allocator, v);
        const gop = try buckets.getOrPut(key);
        if (gop.found_existing) {
            allocator.free(key);
        } else {
            gop.value_ptr.* = std.ArrayList(usize).init(allocator);
        }
        try gop.value_ptr.append(i);
    }

    for (leftRows) |*lrow| {
        const v = lrow.get(leftField) orelse continue;
        const key = try rowmod.encodeValue(allocator, v);
        defer allocator.free(key);
        const indices = buckets.get(key) orelse continue;
        for (indices.items) |i| {
            var lcopy = try dupeRow(allocator, lrow);
            errdefer lcopy.deinit();
            const rcopy = try dupeRow(allocator, &rightRows[i]);
            try results.append(.{ .left = lcopy, .right = rcopy });
        }
    }

    return results.toOwnedSlice();
}

/// One row produced by `leftOuterJoin`: every left row appears at least
/// once, with `right` set to `null` when nothing on the right side matched
/// (SQL LEFT OUTER JOIN semantics - the left side is never dropped, unlike
/// `innerJoin` where an unmatched left row disappears entirely).
pub const OuterJoinedRow = struct {
    left: Row,
    right: ?Row,

    pub fn deinit(self: *OuterJoinedRow) void {
        self.left.deinit();
        if (self.right) |*r| r.deinit();
    }
};

pub fn freeOuterJoined(allocator: Allocator, rows: []OuterJoinedRow) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

/// Left outer equi-join: same matching rules, strategy selection (index
/// nested-loop vs. hash join) and predicate semantics as `innerJoin`, but a
/// left row with zero matches on the right (missing join field, filtered
/// out by `rightPred`, or genuinely no equal value on the right) still
/// produces exactly one `OuterJoinedRow` with `right = null` instead of
/// vanishing from the output.
///
/// Caller owns the returned slice and every `OuterJoinedRow` in it; free
/// with `freeOuterJoined`.
pub fn leftOuterJoin(
    allocator: Allocator,
    left: *Table,
    leftField: []const u8,
    leftPred: ?Predicate,
    right: *Table,
    rightField: []const u8,
    rightPred: ?Predicate,
) ![]OuterJoinedRow {
    const leftRows = try left.select(leftPred);
    defer querymod.freeRows(allocator, leftRows);

    var results = std.ArrayList(OuterJoinedRow).init(allocator);
    errdefer {
        for (results.items) |*r| r.deinit();
        results.deinit();
    }

    if (right.hasIndex(rightField)) {
        for (leftRows) |*lrow| {
            const v = lrow.get(leftField) orelse {
                var lcopy = try dupeRow(allocator, lrow);
                errdefer lcopy.deinit();
                try results.append(.{ .left = lcopy, .right = null });
                continue;
            };
            const eqPred = Predicate{ .eq = .{ .field = rightField, .value = v } };
            var combinedBuf: [2]Predicate = undefined;
            const pred: Predicate = if (rightPred) |rp| blk: {
                combinedBuf[0] = eqPred;
                combinedBuf[1] = rp;
                break :blk Predicate{ .and_ = combinedBuf[0..] };
            } else eqPred;

            const matches = try right.select(pred);
            defer querymod.freeRows(allocator, matches);
            if (matches.len == 0) {
                var lcopy = try dupeRow(allocator, lrow);
                errdefer lcopy.deinit();
                try results.append(.{ .left = lcopy, .right = null });
                continue;
            }
            for (matches) |*mrow| {
                var lcopy = try dupeRow(allocator, lrow);
                errdefer lcopy.deinit();
                const rcopy = try dupeRow(allocator, mrow);
                try results.append(.{ .left = lcopy, .right = rcopy });
            }
        }
        return results.toOwnedSlice();
    }

    const rightRows = try right.select(rightPred);
    defer querymod.freeRows(allocator, rightRows);

    var buckets = std.StringHashMap(std.ArrayList(usize)).init(allocator);
    defer {
        var it = buckets.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            allocator.free(entry.key_ptr.*);
        }
        buckets.deinit();
    }

    for (rightRows, 0..) |*rrow, i| {
        const v = rrow.get(rightField) orelse continue;
        const key = try rowmod.encodeValue(allocator, v);
        const gop = try buckets.getOrPut(key);
        if (gop.found_existing) {
            allocator.free(key);
        } else {
            gop.value_ptr.* = std.ArrayList(usize).init(allocator);
        }
        try gop.value_ptr.append(i);
    }

    for (leftRows) |*lrow| {
        const v = lrow.get(leftField) orelse {
            var lcopy = try dupeRow(allocator, lrow);
            errdefer lcopy.deinit();
            try results.append(.{ .left = lcopy, .right = null });
            continue;
        };
        const key = try rowmod.encodeValue(allocator, v);
        defer allocator.free(key);
        const indices = buckets.get(key) orelse {
            var lcopy = try dupeRow(allocator, lrow);
            errdefer lcopy.deinit();
            try results.append(.{ .left = lcopy, .right = null });
            continue;
        };
        for (indices.items) |i| {
            var lcopy = try dupeRow(allocator, lrow);
            errdefer lcopy.deinit();
            const rcopy = try dupeRow(allocator, &rightRows[i]);
            try results.append(.{ .left = lcopy, .right = rcopy });
        }
    }

    return results.toOwnedSlice();
}

/// One row produced by `rightOuterJoin`: every right row appears at least
/// once, with `left` set to `null` when nothing on the left side matched
/// (SQL RIGHT OUTER JOIN semantics - the mirror image of `OuterJoinedRow`,
/// where it is the right side that is optional).
pub const RightOuterJoinedRow = struct {
    left: ?Row,
    right: Row,

    pub fn deinit(self: *RightOuterJoinedRow) void {
        if (self.left) |*l| l.deinit();
        self.right.deinit();
    }
};

pub fn freeRightOuterJoined(allocator: Allocator, rows: []RightOuterJoinedRow) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

/// Right outer equi-join: same matching rules and predicate semantics as
/// `innerJoin`/`leftOuterJoin`, but every `right` row appears at least once,
/// with `left = null` when nothing on the left side matched.
///
/// Implemented by delegating to `leftOuterJoin` with the two sides swapped
/// and remapping the result, rather than re-deriving the index/hash-join
/// strategy selection a third time - `leftOuterJoin(right, ..., left, ...)`
/// already produces exactly "every row of `right`, paired with an optional
/// match from `left`", which is right outer join semantics with the two
/// output fields named the other way round.
///
/// Caller owns the returned slice and every `RightOuterJoinedRow` in it;
/// free with `freeRightOuterJoined`.
pub fn rightOuterJoin(
    allocator: Allocator,
    left: *Table,
    leftField: []const u8,
    leftPred: ?Predicate,
    right: *Table,
    rightField: []const u8,
    rightPred: ?Predicate,
) ![]RightOuterJoinedRow {
    const swapped = try leftOuterJoin(allocator, right, rightField, rightPred, left, leftField, leftPred);
    defer allocator.free(swapped);

