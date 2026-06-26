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

    const results = try allocator.alloc(RightOuterJoinedRow, swapped.len);
    for (swapped, 0..) |pair, i| {
        results[i] = .{ .left = pair.right, .right = pair.left };
    }
    return results;
}

/// One row produced by `fullOuterJoin`: both `left` and `right` are
/// optional, and every row from either side that never matched on the other
/// still appears exactly once (SQL FULL OUTER JOIN semantics - the union of
/// what `leftOuterJoin` and `rightOuterJoin` each produce).
pub const FullOuterJoinedRow = struct {
    left: ?Row,
    right: ?Row,

    pub fn deinit(self: *FullOuterJoinedRow) void {
        if (self.left) |*l| l.deinit();
        if (self.right) |*r| r.deinit();
    }
};

pub fn freeFullOuterJoined(allocator: Allocator, rows: []FullOuterJoinedRow) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

/// Full outer equi-join: the union of `leftOuterJoin` (every left row,
/// matched or not) and every right row `rightOuterJoin` reports as
/// unmatched (`left == null`) - those are exactly the right-side rows a
/// plain left outer join would never produce. Built from the two existing
/// outer joins rather than a third independent matching pass, at the
/// honest cost of computing the match twice (once per direction) - the
/// same "correctness over a second matching pass" tradeoff already used by
/// `rank`/`rangeByRank` in collections.zig.
///
/// Caller owns the returned slice and every `FullOuterJoinedRow` in it;
/// free with `freeFullOuterJoined`.
pub fn fullOuterJoin(
    allocator: Allocator,
    left: *Table,
    leftField: []const u8,
    leftPred: ?Predicate,
    right: *Table,
    rightField: []const u8,
    rightPred: ?Predicate,
) ![]FullOuterJoinedRow {
    const leftSide = try leftOuterJoin(allocator, left, leftField, leftPred, right, rightField, rightPred);
    errdefer freeOuterJoined(allocator, leftSide);

    const rightSide = try rightOuterJoin(allocator, left, leftField, leftPred, right, rightField, rightPred);
    errdefer freeRightOuterJoined(allocator, rightSide);

    var unmatchedRightCount: usize = 0;
    for (rightSide) |pair| {
        if (pair.left == null) unmatchedRightCount += 1;
    }

    var results = try std.ArrayList(FullOuterJoinedRow).initCapacity(allocator, leftSide.len + unmatchedRightCount);
    errdefer {
        for (results.items) |*r| r.deinit();
        results.deinit();
    }

    for (leftSide) |pair| {
        results.appendAssumeCapacity(.{ .left = pair.left, .right = pair.right });
    }
    allocator.free(leftSide);

    for (rightSide) |pair| {
        if (pair.left) |l| {
            var lm = l;
            lm.deinit();
            var rm = pair.right;
            rm.deinit();
        } else {
            results.appendAssumeCapacity(.{ .left = null, .right = pair.right });
        }
    }
    allocator.free(rightSide);

    return results.toOwnedSlice();
}

/// Trims one of the four join result slices above to a `query.zig` `Page`
/// window (0 = unlimited, the same convention `Table.selectPage` uses) -
/// the join counterpart of pagination for `table_join`/`remote-join`.
/// Unlike `Table.selectPage`, which narrows an index scan and can stop
/// before materializing a row past the limit, a join has already had to
/// produce a full pair to know it matched at all, so there is no cheaper
/// way to honor `offset`/`limit` than windowing the already-complete
/// result - this always runs after `innerJoin`/`leftOuterJoin`/
/// `rightOuterJoin`/`fullOuterJoin` returns, never instead of it.
///
/// Takes ownership of `rows`: frees the backing slice, `.deinit()`s every
/// pair that falls outside `[offset, offset+limit)`, and returns a freshly
/// allocated slice holding only the kept pairs in their original order.
/// Callers own the returned slice and the pairs in it exactly as they
/// would have owned `rows` - free the pairs, then `allocator.free` the
/// slice (or hand ownership onward, as `server.zig`'s `table_join` handler
/// does by moving each kept pair into a `protocol.JoinPair`).
pub fn applyPage(comptime T: type, allocator: Allocator, rows: []T, page: querymod.Page) ![]T {
    const total = rows.len;
    const start = @min(page.offset, total);
    const end = if (page.limit == 0) total else @min(start + page.limit, total);

    for (rows[0..start]) |*r| r.deinit();
    for (rows[end..total]) |*r| r.deinit();

    const kept = end - start;
    const result = allocator.alloc(T, kept) catch |err| {
        for (rows[start..end]) |*r| r.deinit();
        allocator.free(rows);
        return err;
    };
    @memcpy(result, rows[start..end]);
    allocator.free(rows);
    return result;
}

const testing = std.testing;
const dbmod = @import("db.zig");

fn openTestDb(tmp: *std.testing.TmpDir) !dbmod.Db {
    const dbPath = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dbPath);
    return dbmod.Db.open(testing.allocator, dbPath, .{});
}

test "innerJoin: unindexed hash join matches on equal field value" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "bob" } }});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "item", .value = .{ .text = "widget" } } });
    try orders.put(.{ .int = 101 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "item", .value = .{ .text = "gadget" } } });
    try orders.put(.{ .int = 102 }, &.{ .{ .name = "customer_id", .value = .{ .int = 2 } }, .{ .name = "item", .value = .{ .text = "gizmo" } } });
    try orders.put(.{ .int = 103 }, &.{.{ .name = "customer_id", .value = .{ .int = 999 } }}); // no matching customer

    const joined = try innerJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 3), joined.len);

    var aliceItems = std.StringHashMap(void).init(testing.allocator);
    defer aliceItems.deinit();
    var seenBob = false;
    for (joined) |pair| {
        const name = pair.left.get("name").?.text;
        const item = pair.right.get("item").?.text;
        if (std.mem.eql(u8, name, "alice")) {
            try aliceItems.put(item, {});
        } else if (std.mem.eql(u8, name, "bob")) {
            seenBob = true;
            try testing.expectEqualStrings("gizmo", item);
        } else {
            try testing.expect(false); // unreachable: only alice/bob should ever match
        }
    }
    try testing.expect(aliceItems.contains("widget"));
    try testing.expect(aliceItems.contains("gadget"));
    try testing.expect(seenBob);
}

test "innerJoin: index nested-loop join produces identical results to hash join" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "bob" } }});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.createIndex("customer_id");
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 102 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }});

    try testing.expect(orders.hasIndex("customer_id"));

    const joined = try innerJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 3), joined.len);
}

test "innerJoin: rightPred filters matches out even when the join key matches" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "status", .value = .{ .text = "shipped" } } });
    try orders.put(.{ .int = 101 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "status", .value = .{ .text = "cancelled" } } });

    const shippedOnly = Predicate{ .eq = .{ .field = "status", .value = .{ .text = "shipped" } } };
    const joined = try innerJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", shippedOnly);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
    try testing.expectEqualStrings("shipped", joined[0].right.get("status").?.text);
}

test "innerJoin: rightPred filters matches out even through an index nested-loop join" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.createIndex("customer_id");
    try orders.put(.{ .int = 100 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "status", .value = .{ .text = "shipped" } } });
    try orders.put(.{ .int = 101 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "status", .value = .{ .text = "cancelled" } } });

    const shippedOnly = Predicate{ .eq = .{ .field = "status", .value = .{ .text = "shipped" } } };
    const joined = try innerJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", shippedOnly);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
    try testing.expectEqualStrings("shipped", joined[0].right.get("status").?.text);
}

test "innerJoin: leftPred narrows which left rows are even probed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "vip", .value = .{ .boolean = true } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "vip", .value = .{ .boolean = false } }});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }});

    const vipOnly = Predicate{ .eq = .{ .field = "vip", .value = .{ .boolean = true } } };
    const joined = try innerJoin(testing.allocator, &customers, "__pk", vipOnly, &orders, "customer_id", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
}

test "innerJoin: mismatched types never match even with equal-looking payloads" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 5 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    try right.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .float = 5.0 } }});

    const joined = try innerJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 0), joined.len);
}

test "innerJoin: rows missing the join field on either side never match" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{}); // no "k" field at all
    try left.put(.{ .int = 2 }, &.{.{ .name = "k", .value = .{ .int = 7 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    try right.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 7 } }});

    const joined = try innerJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
    try testing.expectEqual(@as(i64, 2), joined[0].left.get("__pk").?.int);
}

test "innerJoin: empty right table yields zero matches without touching left side output" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 1 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();

    const joined = try innerJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 0), joined.len);
}

test "innerJoin: one-to-many fan-out duplicates the left row for each right match" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 42 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    var i: i64 = 0;
    while (i < 5) : (i += 1) {
        try right.put(.{ .int = i }, &.{.{ .name = "k", .value = .{ .int = 42 } }});
    }

    const joined = try innerJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 5), joined.len);
    for (joined) |pair| {
        try testing.expectEqual(@as(i64, 1), pair.left.get("__pk").?.int);
    }
}

test "leftOuterJoin: unmatched left row survives with right=null instead of vanishing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "bob" } }}); // never ordered

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    const joined = try leftOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    var sawAliceMatched = false;
    var sawBobUnmatched = false;
    for (joined) |pair| {
        const name = pair.left.get("name").?.text;
        if (std.mem.eql(u8, name, "alice")) {
            try testing.expect(pair.right != null);
            sawAliceMatched = true;
        } else if (std.mem.eql(u8, name, "bob")) {
            try testing.expect(pair.right == null);
            sawBobUnmatched = true;
        }
    }
    try testing.expect(sawAliceMatched);
    try testing.expect(sawBobUnmatched);
}

test "leftOuterJoin: index nested-loop join produces identical results to hash join" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{});
    try customers.put(.{ .int = 2 }, &.{}); // no matching order either way

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.createIndex("customer_id");
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    try testing.expect(orders.hasIndex("customer_id"));

    const joined = try leftOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeOuterJoined(testing.allocator, joined);

    // customer 1 matches twice, customer 2 matches zero times but still appears once.
    try testing.expectEqual(@as(usize, 3), joined.len);
    var unmatchedCount: usize = 0;
    for (joined) |pair| {
        if (pair.right == null) unmatchedCount += 1;
    }
    try testing.expectEqual(@as(usize, 1), unmatchedCount);
}

test "leftOuterJoin: rightPred filtering out the only match still keeps the left row with right=null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{ .{ .name = "customer_id", .value = .{ .int = 1 } }, .{ .name = "status", .value = .{ .text = "cancelled" } } });

    const shippedOnly = Predicate{ .eq = .{ .field = "status", .value = .{ .text = "shipped" } } };
    const joined = try leftOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", shippedOnly);
    defer freeOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
    try testing.expect(joined[0].right == null);
}

test "leftOuterJoin: left row missing the join field entirely still appears once with right=null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{}); // no "k" field at all
    try left.put(.{ .int = 2 }, &.{.{ .name = "k", .value = .{ .int = 7 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    try right.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 7 } }});

    const joined = try leftOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    for (joined) |pair| {
        if (pair.left.get("__pk").?.int == 1) {
            try testing.expect(pair.right == null);
        } else {
            try testing.expect(pair.right != null);
        }
    }
}

test "leftOuterJoin: one-to-many fan-out on the matched side still produces one row per match" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 42 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    var i: i64 = 0;
    while (i < 5) : (i += 1) {
        try right.put(.{ .int = i }, &.{.{ .name = "k", .value = .{ .int = 42 } }});
    }

    const joined = try leftOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 5), joined.len);
    for (joined) |pair| {
        try testing.expect(pair.right != null);
    }
}

test "leftOuterJoin: empty right table yields exactly one unmatched row per left row" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 1 } }});
    try left.put(.{ .int = 2 }, &.{.{ .name = "k", .value = .{ .int = 2 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();

    const joined = try leftOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    for (joined) |pair| {
        try testing.expect(pair.right == null);
    }
}

test "rightOuterJoin: unmatched right row survives with left=null instead of vanishing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 999 } }}); // no matching customer

    const joined = try rightOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeRightOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    var sawMatched = false;
    var sawUnmatched = false;
    for (joined) |pair| {
        const customerId = pair.right.get("customer_id").?.int;
        if (customerId == 1) {
            try testing.expect(pair.left != null);
            try testing.expectEqualStrings("alice", pair.left.?.get("name").?.text);
            sawMatched = true;
        } else {
            try testing.expect(pair.left == null);
            sawUnmatched = true;
        }
    }
    try testing.expect(sawMatched);
    try testing.expect(sawUnmatched);
}

test "rightOuterJoin: index nested-loop join (index on left table) matches hash join results" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.createIndex("__pk");
    try customers.put(.{ .int = 1 }, &.{});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }}); // unmatched

    const joined = try rightOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeRightOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    var unmatchedCount: usize = 0;
    for (joined) |pair| {
        if (pair.left == null) unmatchedCount += 1;
    }
    try testing.expectEqual(@as(usize, 1), unmatchedCount);
}

test "rightOuterJoin: leftPred filtering out the only match still keeps the right row with left=null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "active", .value = .{ .boolean = false } }});

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    const activeOnly = Predicate{ .eq = .{ .field = "active", .value = .{ .boolean = true } } };
    const joined = try rightOuterJoin(testing.allocator, &customers, "__pk", activeOnly, &orders, "customer_id", null);
    defer freeRightOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 1), joined.len);
    try testing.expect(joined[0].left == null);
}

test "rightOuterJoin: empty left table yields exactly one unmatched row per right row" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    try right.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 1 } }});
    try right.put(.{ .int = 2 }, &.{.{ .name = "k", .value = .{ .int = 2 } }});

    const joined = try rightOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeRightOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    for (joined) |pair| {
        try testing.expect(pair.left == null);
    }
}

test "rightOuterJoin: one-to-many fan-out on the matched side still produces one row per match" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 42 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    var i: i64 = 0;
    while (i < 5) : (i += 1) {
        try right.put(.{ .int = i }, &.{.{ .name = "k", .value = .{ .int = 42 } }});
    }

    const joined = try rightOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeRightOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 5), joined.len);
    for (joined) |pair| {
        try testing.expect(pair.left != null);
    }
}

test "fullOuterJoin: rows unmatched on either side survive, matched pairs appear once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var customers = try Table.open(&db, testing.allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }}); // matches
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "bob" } }}); // never ordered

    var orders = try Table.open(&db, testing.allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 999 } }}); // orphan order

    const joined = try fullOuterJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
    defer freeFullOuterJoined(testing.allocator, joined);

    // alice+order100 (matched), bob+null (left-only), null+order101 (right-only).
    try testing.expectEqual(@as(usize, 3), joined.len);
    var sawMatched = false;
    var sawLeftOnly = false;
    var sawRightOnly = false;
    for (joined) |pair| {
        if (pair.left != null and pair.right != null) {
            try testing.expectEqualStrings("alice", pair.left.?.get("name").?.text);
            sawMatched = true;
        } else if (pair.left != null and pair.right == null) {
            try testing.expectEqualStrings("bob", pair.left.?.get("name").?.text);
            sawLeftOnly = true;
        } else if (pair.left == null and pair.right != null) {
            try testing.expectEqual(@as(i64, 999), pair.right.?.get("customer_id").?.int);
            sawRightOnly = true;
        } else {
            try testing.expect(false); // unreachable: both sides null never happens
        }
    }
    try testing.expect(sawMatched);
    try testing.expect(sawLeftOnly);
    try testing.expect(sawRightOnly);
}

test "fullOuterJoin: fully disjoint tables yield exactly one unmatched row per side" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    try left.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 1 } }});

    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();
    try right.put(.{ .int = 1 }, &.{.{ .name = "k", .value = .{ .int = 2 } }});

    const joined = try fullOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeFullOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 2), joined.len);
    var leftOnly: usize = 0;
    var rightOnly: usize = 0;
    for (joined) |pair| {
        if (pair.left != null and pair.right == null) leftOnly += 1;
        if (pair.left == null and pair.right != null) rightOnly += 1;
    }
    try testing.expectEqual(@as(usize, 1), leftOnly);
    try testing.expectEqual(@as(usize, 1), rightOnly);
}

test "fullOuterJoin: both tables empty yields zero rows" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    var left = try Table.open(&db, testing.allocator, "left");
    defer left.deinit();
    var right = try Table.open(&db, testing.allocator, "right");
    defer right.deinit();

    const joined = try fullOuterJoin(testing.allocator, &left, "k", null, &right, "k", null);
    defer freeFullOuterJoined(testing.allocator, joined);

    try testing.expectEqual(@as(usize, 0), joined.len);
}

fn openFourPairJoin(tmp: *std.testing.TmpDir, db: *dbmod.Db) ![]JoinedRow {
    var customers = try Table.open(db, testing.allocator, "customers");
    defer customers.deinit();
    var orders = try Table.open(db, testing.allocator, "orders");
    defer orders.deinit();

    var i: i64 = 1;
    while (i <= 4) : (i += 1) {
        try customers.put(.{ .int = i }, &.{.{ .name = "name", .value = .{ .int = i } }});
        try orders.put(.{ .int = i * 100 }, &.{.{ .name = "customer_id", .value = .{ .int = i } }});
    }
    _ = tmp;
    return innerJoin(testing.allocator, &customers, "__pk", null, &orders, "customer_id", null);
}

fn customerNames(pairs: []const JoinedRow) [4]i64 {
    var out: [4]i64 = undefined;
    for (pairs, 0..) |p, i| out[i] = p.left.get("name").?.int;
    return out;
}

test "applyPage with offset and limit keeps a middle window in order" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    const joined = try openFourPairJoin(&tmp, &db);
    try testing.expectEqual(@as(usize, 4), joined.len);

    const paged = try applyPage(JoinedRow, testing.allocator, joined, .{ .offset = 1, .limit = 2 });
    defer freeJoined(testing.allocator, paged);

    try testing.expectEqual(@as(usize, 2), paged.len);
    try testing.expectEqual(@as(i64, 2), paged[0].left.get("name").?.int);
    try testing.expectEqual(@as(i64, 3), paged[1].left.get("name").?.int);
}

test "applyPage with limit 0 returns every row, matching unlimited select" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    const joined = try openFourPairJoin(&tmp, &db);
    const paged = try applyPage(JoinedRow, testing.allocator, joined, .{});
    defer freeJoined(testing.allocator, paged);

    try testing.expectEqualSlices(i64, &.{ 1, 2, 3, 4 }, &customerNames(paged));
}

test "applyPage with offset past the end returns nothing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    const joined = try openFourPairJoin(&tmp, &db);
    const paged = try applyPage(JoinedRow, testing.allocator, joined, .{ .offset = 50 });
    defer freeJoined(testing.allocator, paged);

    try testing.expectEqual(@as(usize, 0), paged.len);
}

test "applyPage with limit larger than the remaining rows stops at the end" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    const joined = try openFourPairJoin(&tmp, &db);
    const paged = try applyPage(JoinedRow, testing.allocator, joined, .{ .offset = 3, .limit = 100 });
    defer freeJoined(testing.allocator, paged);

    try testing.expectEqual(@as(usize, 1), paged.len);
    try testing.expectEqual(@as(i64, 4), paged[0].left.get("name").?.int);
}

test "applyPage propagates OutOfMemory from its own result allocation without leaking any row" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTestDb(&tmp);
    defer db.close();

    // `joined` itself is built with the real `testing.allocator` - every
    // `Row` inside stores that same allocator (see `row.zig`'s `Row.init`),
    // so `applyPage`'s error path frees each one through it regardless of
    // which allocator `applyPage` was asked to allocate its OWN result
    // slice with below. Isolates the OOM path to exactly one call site:
    // the `allocator.alloc(T, kept)` in `applyPage` itself, not the join
    // that already succeeded.
    const joined = try openFourPairJoin(&tmp, &db);
    try testing.expectEqual(@as(usize, 4), joined.len);

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, applyPage(JoinedRow, failing.allocator(), joined, .{ .offset = 1, .limit = 2 }));
    // No explicit assertion beyond this: `testing.allocator`'s leak
    // detector at process exit is the real check - every one of the 4
    // `JoinedRow`s (2 kept by the window, 2 trimmed outside it) must have
    // been `.deinit()`-ed on the error path in `applyPage`, and the
    // `rows` backing slice itself freed, or this test fails on leak.
}
