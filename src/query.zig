const std = @import("std");
const dbmod = @import("db.zig");
const rowmod = @import("row.zig");
const idx = @import("index.zig");
const exprmod = @import("expr.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Value = rowmod.Value;
const Row = rowmod.Row;
const Field = rowmod.Field;
const IndexSet = idx.IndexSet;
const CompositeIndexSet = idx.CompositeIndexSet;
const CompositeIndexSpec = idx.CompositeIndexSpec;
const UniqueSet = idx.UniqueSet;
const ForeignKeySet = idx.ForeignKeySet;
const CheckConstraintSet = idx.CheckConstraintSet;
const ReferencedBySet = idx.ReferencedBySet;

/// Reserved field name a Table stores the primary key under, so a decoded
/// Row is self-sufficient for callers that only have the Row (e.g. results
/// of a full table scan) without needing to separately decode it from the
/// row key's escaped ordered bytes.
pub const pkField = "__pk";

pub const Condition = struct {
    field: []const u8,
    value: Value,
};

/// Paging window for `Table.selectPage`: skip the first `offset` matches,
/// return at most `limit` of them (0 = unlimited).
pub const Page = struct {
    offset: usize = 0,
    limit: usize = 0,
};

/// One column of a `Table.selectPageOrdered` sort key: order matched rows
/// by `field` (via `rowmod.compare`'s total order across value types). A
/// row missing `field` entirely sorts as `Value.none`, which `compare`
/// places before every other tag - so rows lacking the sort column
/// consistently group at the front (ascending) or back (descending)
/// instead of erroring. `selectPageOrdered` takes a `[]const OrderBy`
/// (empty = unsorted): columns after the first only break ties left by
/// the ones before them, the same lexicographic rule SQL's `ORDER BY a, b`
/// follows - the sort is stable, so a `[]const OrderBy` with a single
/// entry that leaves ties unresolved behaves exactly as before this type
/// gained multi-column support (rows keep their relative scan order:
/// ascending pk for a full scan, index order for an indexed lookup).
pub const OrderBy = struct {
    field: []const u8,
    descending: bool = false,
};

/// Which access strategy `Table.selectPage` would take for a given
/// predicate, as reported by `Table.explain`. Mirrors the three real
/// branches of `selectPage`'s decision ladder: an unindexed full scan, a
/// single-field index (`eq` narrows to one key, `lt`/`lte`/`gt`/`gte`
/// narrow to a range), or a composite index matched on a leftmost prefix
/// of its columns (`_eq` when the prefix is the whole match, `_range` when
/// the column right after the prefix also had a range bound).
pub const PlanKind = enum(u8) {
    full_scan,
    index_eq,
    index_range,
    composite_eq,
    composite_range,
};

/// `indexName` is an owned copy the caller must free with `Plan.deinit` -
/// null (and `matchedFields`/`totalFields` both 0) for `.full_scan`, which
/// names no index. For `.index_eq`/`.index_range` it is the single indexed
/// field name and `matchedFields == totalFields == 1`. For
/// `.composite_eq`/`.composite_range` it is the composite index's name and
/// `matchedFields` counts how many of the index's `totalFields` leading
/// columns the query actually pinned down (a strict prefix match still
/// narrows the scan, same leftmost-prefix rule a real multi-column B-tree
/// index gives you).
pub const Plan = struct {
    kind: PlanKind,
    indexName: ?[]const u8 = null,
    matchedFields: usize = 0,
    totalFields: usize = 0,

    pub fn deinit(self: *Plan, allocator: Allocator) void {
        if (self.indexName) |n| allocator.free(n);
        self.* = undefined;
    }
};

/// Predicate AST evaluated against a decoded Row. Leaves compare a named
/// field to a literal Value; And/Or/Not compose leaves and other predicates.
/// Predicate does not own the memory of any Value or field-name slice it
/// references - callers must keep those alive for as long as the predicate
/// tree is used.
pub const Predicate = union(enum) {
    eq: Condition,
    ne: Condition,
    lt: Condition,
    lte: Condition,
    gt: Condition,
    gte: Condition,
    like: Condition,
    /// True when `field` is absent from the row entirely, or present but
    /// holding an explicit `Value.none` - a sparse row's "never set" and a
    /// row that set the field to none are indistinguishable to a caller
    /// asking "does this row have a real value here", same as SQL NULL.
    is_null: []const u8,
    is_not_null: []const u8,
    and_: []const Predicate,
    or_: []const Predicate,
    not_: *const Predicate,

    fn isNullish(v: ?Value) bool {
        const val = v orelse return true;
        return val == .none;
    }

    pub fn evaluate(self: Predicate, row: *const Row) bool {
        return switch (self) {
            .eq => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) == .eq else false,
            .ne => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) != .eq else true,
            .lt => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) == .lt else false,
            .lte => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) != .gt else false,
            .gt => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) == .gt else false,
            .gte => |c| if (row.get(c.field)) |v| rowmod.compare(v, c.value) != .lt else false,
            .like => |c| blk: {
                const rowVal = row.get(c.field) orelse break :blk false;
                if (rowVal != .text or c.value != .text) break :blk false;
                break :blk matchLike(c.value.text, rowVal.text);
            },
            .is_null => |field| isNullish(row.get(field)),
            .is_not_null => |field| !isNullish(row.get(field)),
            .and_ => |preds| blk: {
                for (preds) |p| {
                    if (!p.evaluate(row)) break :blk false;
                }
                break :blk true;
            },
            .or_ => |preds| blk: {
                for (preds) |p| {
                    if (p.evaluate(row)) break :blk true;
                }
                break :blk false;
            },
            .not_ => |p| !p.evaluate(row),
        };
    }
};

/// SQL-style LIKE matching: `%` matches any run of characters (including
/// none), `_` matches exactly one character, every other byte in `pattern`
/// must match `text` literally. No escape character - a pattern that needs a
/// literal `%`/`_` cannot express it, same simplification `expr.zig`'s other
/// operators already make (no escaping in the predicate language at all).
/// Iterative two-pointer wildcard matcher (not recursive backtracking) so a
/// pattern like "a%a%a%a%a%a%b" against a long non-matching text stays
/// linear-ish instead of exponential: on mismatch after a `%`, only the
/// text pointer rewinds-and-retries, the pattern never re-walks from
/// scratch.
fn matchLike(pattern: []const u8, text: []const u8) bool {
    var pIdx: usize = 0;
    var tIdx: usize = 0;
    var starIdx: ?usize = null;
    var matchIdx: usize = 0;

    while (tIdx < text.len) {
        if (pIdx < pattern.len and (pattern[pIdx] == '_' or pattern[pIdx] == text[tIdx])) {
            pIdx += 1;
            tIdx += 1;
        } else if (pIdx < pattern.len and pattern[pIdx] == '%') {
            starIdx = pIdx;
            matchIdx = tIdx;
            pIdx += 1;
        } else if (starIdx) |si| {
            pIdx = si + 1;
            matchIdx += 1;
            tIdx = matchIdx;
        } else {
            return false;
        }
    }
    while (pIdx < pattern.len and pattern[pIdx] == '%') : (pIdx += 1) {}
    return pIdx == pattern.len;
}

test "matchLike handles literal, wildcard, and single-char patterns" {
    try std.testing.expect(matchLike("warsaw", "warsaw"));
    try std.testing.expect(!matchLike("warsaw", "krakow"));
    try std.testing.expect(matchLike("", ""));
    try std.testing.expect(!matchLike("a", ""));
    try std.testing.expect(matchLike("%", "anything"));
    try std.testing.expect(matchLike("%", ""));
    try std.testing.expect(matchLike("A%", "Ada"));
    try std.testing.expect(!matchLike("A%", "Boris"));
    try std.testing.expect(matchLike("%son", "Johnson"));
    try std.testing.expect(!matchLike("%son", "Sonata"));
    try std.testing.expect(matchLike("%ada%", "the ada language"));
    try std.testing.expect(matchLike("_da", "ada"));
    try std.testing.expect(!matchLike("_da", "aada"));
    try std.testing.expect(matchLike("a_a_a", "ababa"));
    try std.testing.expect(matchLike("%a%b%c%", "xaxxbxxxcx"));
    try std.testing.expect(!matchLike("%a%b%c%", "xxbxxxax"));
    try std.testing.expect(matchLike("a%%a", "aXYZa"));
}

/// A table is a named partition of a single Db's keyspace (see index.zig for
/// the exact key layout) plus a set of secondary indexes maintained on
/// write. Rows are whole-row replace semantics: `put` fully overwrites
/// whatever was stored at `pk`, syncing every registered index against the
/// old and new field values in the same call.
/// Composite indexes are capped at this many columns: generous for any
/// realistic multi-column index while keeping the planner's per-spec match
/// buffer (see `findCompositeMatch`) a fixed-size stack array.
pub const maxCompositeFields = 8;

pub const Table = struct {
    db: *Db,
    allocator: Allocator,
    name: []u8,
    indexes: IndexSet,
    composite: CompositeIndexSet,
    unique: UniqueSet,
    foreignKeys: ForeignKeySet,
    checks: CheckConstraintSet,

    pub fn open(db: *Db, allocator: Allocator, name: []const u8) !Table {
        if (!idx.validIdentifier(name)) return error.InvalidIdentifier;
        return .{
            .db = db,
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .indexes = try IndexSet.load(allocator, db, name),
            .composite = try CompositeIndexSet.load(allocator, db, name),
            .unique = try UniqueSet.load(allocator, db, name),
            .foreignKeys = try ForeignKeySet.load(allocator, db, name),
            .checks = try CheckConstraintSet.load(allocator, db, name),
        };
    }

    pub fn deinit(self: *Table) void {
        self.allocator.free(self.name);
        self.indexes.deinit();
        self.composite.deinit();
        self.unique.deinit();
        self.foreignKeys.deinit();
        self.checks.deinit();
    }

    pub fn createIndex(self: *Table, field: []const u8) !void {
        if (!idx.validIdentifier(field)) return error.InvalidIdentifier;
        if (self.indexes.has(field)) return;

        // Backfill: every existing row's current value for `field` becomes
        // an index entry before the index is advertised as usable.
        const rows = try self.scanAll();
        defer freeRows(self.allocator, rows);
        for (rows) |*r| {
            const pk = r.get(pkField) orelse continue;
            const value = r.get(field) orelse continue;
            try idx.addEntry(self.db, self.allocator, self.name, field, value, pk);
        }

        try self.indexes.add(field);
        try self.indexes.save(self.db, self.name);
    }

    /// Dropping an index also drops any UNIQUE constraint riding on it -
    /// `Table.put`'s constraint check relies on the field's index entries
    /// existing (see `createUniqueIndex`), so a unique field with no
    /// index left behind would silently stop being enforced instead of
    /// erroring, which is worse than making the drop explicit here.
    pub fn dropIndex(self: *Table, field: []const u8) !void {
        if (!self.indexes.remove(field)) return;
        try idx.dropAllEntries(self.db, self.allocator, self.name, field);
        try self.indexes.save(self.db, self.name);
        if (self.unique.remove(field)) try self.unique.save(self.db, self.name);
    }

    pub fn hasIndex(self: *const Table, field: []const u8) bool {
        return self.indexes.has(field);
    }

    pub fn hasUniqueIndex(self: *const Table, field: []const u8) bool {
        return self.unique.has(field);
    }

    /// Installs a UNIQUE constraint on `field` - SQL's `CREATE UNIQUE
    /// INDEX`. Refuses outright if the table already holds two rows with
    /// the same (non-null) value for `field`: existing data always wins
    /// over a constraint that could never have held for it, exactly like
    /// a real database refusing to add a unique index over dirty data.
    /// Backfills the plain secondary index too when it is not already
    /// present, since `put`'s duplicate check below is a `scanEq` against
    /// those very index entries rather than a full table scan - a unique
    /// field with no backing index would make every write pay for a full
    /// scan just to enforce the constraint.
    pub fn createUniqueIndex(self: *Table, field: []const u8) !void {
        if (!idx.validIdentifier(field)) return error.InvalidIdentifier;
        if (self.unique.has(field)) return;

        const rows = try self.scanAll();
        defer freeRows(self.allocator, rows);

        {
            var seen = std.StringHashMap(void).init(self.allocator);
            defer {
                var it = seen.keyIterator();
                while (it.next()) |k| self.allocator.free(k.*);
                seen.deinit();
            }
            for (rows) |*r| {
                const value = r.get(field) orelse continue;
                var encoded = std.ArrayList(u8).init(self.allocator);
                defer encoded.deinit();
                try rowmod.appendOrdered(&encoded, value);
                if (seen.contains(encoded.items)) return error.UniqueViolation;
                const owned = try self.allocator.dupe(u8, encoded.items);
                errdefer self.allocator.free(owned);
                try seen.put(owned, {});
            }
        }

        if (!self.indexes.has(field)) {
            for (rows) |*r| {
                const pk = r.get(pkField) orelse continue;
                const value = r.get(field) orelse continue;
                try idx.addEntry(self.db, self.allocator, self.name, field, value, pk);
            }
            try self.indexes.add(field);
            try self.indexes.save(self.db, self.name);
        }

        try self.unique.add(field);
        try self.unique.save(self.db, self.name);
    }

    pub fn hasForeignKey(self: *const Table, field: []const u8) bool {
        return self.foreignKeys.has(field);
    }

    /// Whether `value` names an existing row of `spec.refTable` under
    /// `spec.refField` - `query.pkField` is checked via a plain `get`
    /// (the primary key is inherently unique, no secondary index needed),
    /// anything else via `idx.scanEq` against `spec.refTable`'s own index
    /// entries (required to carry a UNIQUE constraint by
    /// `Table.createForeignKey`, so at most one owner is expected here -
    /// this only asks "does at least one exist", not "is it exactly one",
    /// since a constraint installed correctly can only ever produce zero or
    /// one).
    fn foreignKeyTargetExists(self: *Table, refTableName: []const u8, refField: []const u8, value: Value) !bool {
        if (std.mem.eql(u8, refField, pkField)) {
            var refTable = try Table.open(self.db, self.allocator, refTableName);
            defer refTable.deinit();
            var found = try refTable.get(value) orelse return false;
            found.deinit();
            return true;
        }
        const owners = try idx.scanEq(self.db, self.allocator, refTableName, refField, value);
        defer {
            for (owners) |v| v.free(self.allocator);
            self.allocator.free(owners);
        }
        return owners.len > 0;
    }

    /// Installs a FOREIGN KEY constraint: every row's (non-null) `field`
    /// value must, from this point on, name a value that exists as
    /// `refField` on `refTable` - SQL's `FOREIGN KEY (field) REFERENCES
    /// refTable(refField)`. `refField` must be either `pkField` or a field
    /// already carrying `refTable`'s own UNIQUE constraint (see
    /// `foreignKeyTargetExists`'s doc comment for why); anything else is
    /// refused with `error.ForeignKeyRequiresUniqueTarget` before touching
    /// any row, the same "refuse before mutating" shape `createUniqueIndex`
    /// uses for dirty data. Existing rows are checked against the target
    /// before the constraint is recorded - a row whose current `field`
    /// value has no matching parent aborts the whole install with
    /// `error.ForeignKeyViolation`, leaving nothing installed.
    ///
    /// Registers the reverse relationship in `refTable`'s own
    /// `ReferencedBySet` (see its doc comment) so `Table.delete` can later
    /// enforce `onDelete` against it (SQL's `ON DELETE RESTRICT` or `ON
    /// DELETE CASCADE`, see `idx.OnDelete`'s doc comment) - this used to be
    /// a documented, unfixed gap ("no registry of dependent tables exists,
    /// since tables are opened ad hoc by name and never catalogued
    /// anywhere") before `ReferencedBySet` closed it.
    ///
    /// `onDelete` only governs `Table.delete`/`Table.deleteWhere`'s plain
    /// (non-transactional) path - `txn_table.zig`'s `TableTxn.delete` reads
    /// the same `ReferencedBySet` but does not look at this field at all,
    /// so it continues to unconditionally restrict any delete that would
    /// orphan a reference even for a `cascade` constraint. That is a
    /// deliberately conservative gap, not an oversight: refusing is always
    /// a safe fallback for a feature that has not been built yet, whereas
    /// silently NOT cascading inside a transaction would leave a dangling
    /// reference behind. Only `Table.put`'s `updateRestrictedByForeignKey`
    /// check is unaffected by `onDelete` in EITHER path - there is no `ON
    /// UPDATE CASCADE` here, so a value change under a live reference is
    /// always restricted regardless of the FK's delete mode.
    ///
    /// Known gap that registry does NOT close, same documented-rather-
    /// than-fixed shape as `TableTxn`'s missing composite/unique
    /// enforcement: nothing here stops a later `refTable.dropIndex
    /// (refField)` from removing the UNIQUE constraint this foreign key
    /// depends on - doing so leaves the constraint silently checking
    /// against an unconstrained (possibly duplicate-holding) column via
    /// `scanEq`, which still answers "does at least one owner exist"
    /// correctly but no longer guarantees at most one.
    pub fn createForeignKey(self: *Table, field: []const u8, refTable: []const u8, refField: []const u8, onDelete: idx.OnDelete) !void {
        if (!idx.validIdentifier(field)) return error.InvalidIdentifier;
        if (!idx.validIdentifier(refTable)) return error.InvalidIdentifier;
        if (!idx.validIdentifier(refField)) return error.InvalidIdentifier;
        if (self.foreignKeys.has(field)) return;

        if (!std.mem.eql(u8, refField, pkField)) {
            var ref = try Table.open(self.db, self.allocator, refTable);
            defer ref.deinit();
            if (!ref.hasUniqueIndex(refField)) return error.ForeignKeyRequiresUniqueTarget;
        }

        const rows = try self.scanAll();
        defer freeRows(self.allocator, rows);
        for (rows) |*r| {
            const value = r.get(field) orelse continue;
            if (value == .none) continue;
            if (!try self.foreignKeyTargetExists(refTable, refField, value)) return error.ForeignKeyViolation;
        }

        try self.foreignKeys.add(field, refTable, refField, onDelete);
        try self.foreignKeys.save(self.db, self.name);

        // Records the reverse relationship on `refTable` so a later delete
        // against it (see `Table.delete`'s RESTRICT check) can discover
        // this constraint without a global table catalog - see
        // `ReferencedBySet`'s doc comment. Loaded, mutated, and saved
        // transiently rather than cached on a `Table` field: unlike
        // `foreignKeys`/`unique`/`checks` (always mutated through the same
        // handle that holds them), `referencedBy` is mutated as a side
        // effect of some OTHER table's `createForeignKey`/`dropForeignKey`
        // call - a `refTable` handle the CALLER already has open (the
        // ordinary "open customers, open orders, wire up the FK between
        // them" shape) would otherwise go stale the moment this runs,
        // silently under-enforcing every delete against it thereafter.
        // Works unchanged for a self-referencing FK (`refTable ==
        // self.name`) too, since it never touches `self`'s own cached
        // sets at all - it only ever reads/writes `refTable`'s on-disk
        // entry by name.
        var revSet = try ReferencedBySet.load(self.allocator, self.db, refTable);
        defer revSet.deinit();
        try revSet.add(self.name, field, refField, onDelete);
        try revSet.save(self.db, refTable);
    }

    /// Lifts a FOREIGN KEY and its reverse `ReferencedBySet` entry on
    /// whichever table it pointed at, symmetric with `createForeignKey`
    /// installing both. The target's name is copied out before
    /// `self.foreignKeys.remove` frees the spec's own strings, since the
    /// reverse cleanup below still needs it afterwards. See
    /// `createForeignKey`'s doc comment on why the reverse entry is always
    /// loaded/saved transiently rather than through a cached `Table` field.
    pub fn dropForeignKey(self: *Table, field: []const u8) !void {
        const existing = self.foreignKeys.find(field) orelse return;
        const refTable = try self.allocator.dupe(u8, existing.refTable);
        defer self.allocator.free(refTable);

        _ = self.foreignKeys.remove(field);
        try self.foreignKeys.save(self.db, self.name);

        var revSet = try ReferencedBySet.load(self.allocator, self.db, refTable);
        defer revSet.deinit();
        _ = revSet.remove(self.name, field);
        try revSet.save(self.db, refTable);
    }

    pub fn hasCheckConstraint(self: *const Table, name: []const u8) bool {
        return self.checks.has(name);
    }

    /// Installs a named CHECK constraint - SQL's `CHECK (source)` - built on
    /// the exact same predicate language `table select`/`table join` already
    /// use (`expr.zig`'s recursive-descent parser over `Predicate`). `source`
    /// is parsed once up front so a typo is rejected before anything is
    /// persisted (`error.InvalidCheckExpression` wraps any `expr.ParseError`,
    /// since a caller that only sees this constraint's name/source has no use
    /// for which specific parse error fired), then evaluated against every
    /// existing row - the same "refuse before mutating, existing data always
    /// wins" shape `createUniqueIndex`/`createForeignKey` use, so installing
    /// a CHECK that current data already violates fails outright rather than
    /// silently starting to enforce only from the next write on.
    pub fn createCheckConstraint(self: *Table, name: []const u8, source: []const u8) !void {
        if (!idx.validIdentifier(name)) return error.InvalidIdentifier;
        if (self.checks.has(name)) return;

        var parsed = exprmod.parse(self.allocator, source) catch return error.InvalidCheckExpression;
        defer parsed.deinit();

        const rows = try self.scanAll();
        defer freeRows(self.allocator, rows);
        for (rows) |*r| {
            if (!parsed.predicate.evaluate(r)) return error.CheckViolation;
        }

        try self.checks.add(name, source);
        try self.checks.save(self.db, self.name);
    }

    pub fn dropCheckConstraint(self: *Table, name: []const u8) !void {
        if (!self.checks.remove(name)) return;
        try self.checks.save(self.db, self.name);
    }

    /// Creates a multi-column secondary index named `name` over `fields`, in
    /// order - order matters, since only a leading ("leftmost") prefix of it
    /// can be used to narrow a query (see `findCompositeMatch`). Rows
    /// missing any of the fields are skipped entirely, both here and when
    /// staying in sync on `put`/`delete`, since a composite entry with a
    /// missing column would not be a well-formed tuple.
    pub fn createCompositeIndex(self: *Table, name: []const u8, fields: []const []const u8) !void {
        if (!idx.validIdentifier(name)) return error.InvalidIdentifier;
        if (fields.len < 2 or fields.len > maxCompositeFields) return error.InvalidCompositeIndex;
        for (fields) |f| if (!idx.validIdentifier(f)) return error.InvalidIdentifier;
        if (self.composite.has(name)) return;

        const rows = try self.scanAll();
        defer freeRows(self.allocator, rows);
        var values: [maxCompositeFields]Value = undefined;
        for (rows) |*r| {
            const pk = r.get(pkField) orelse continue;
            var complete = true;
            for (fields, 0..) |f, i| {
                values[i] = r.get(f) orelse {
                    complete = false;
                    break;
                };
            }
            if (!complete) continue;
            try idx.addCompositeEntry(self.db, self.allocator, self.name, name, values[0..fields.len], pk);
        }

        try self.composite.add(name, fields);
        try self.composite.save(self.db, self.name);
    }

    pub fn dropCompositeIndex(self: *Table, name: []const u8) !void {
        if (!self.composite.remove(name)) return;
        try idx.dropAllCompositeEntries(self.db, self.allocator, self.name, name);
        try self.composite.save(self.db, self.name);
    }

    pub fn hasCompositeIndex(self: *const Table, name: []const u8) bool {
        return self.composite.has(name);
    }

    /// Fully replaces the row stored at `pk` with `fields`, syncing every
    /// registered secondary index against whatever the row held before.
    pub fn put(self: *Table, pk: Value, fields: []const Field) !void {
        var old = try self.get(pk);
        defer if (old) |*o| o.deinit();

        var newRow = Row.init(self.allocator);
        defer newRow.deinit();
        try newRow.set(pkField, pk);
        for (fields) |f| try newRow.set(f.name, f.value);

        const encoded = try newRow.encode(self.allocator);
        defer self.allocator.free(encoded);
        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);

        // CHECK constraints run first, ahead of UNIQUE/FOREIGN KEY and any
        // index or row mutation - a row that fails a CHECK never gets far
        // enough to matter whether it would also have violated UNIQUE, same
        // "cheapest, purely-local check first" ordering a real database
        // uses. Re-parsed from source on every put (no cached Predicate is
        // kept on Table), the same cost `table select`/`table join` already
        // pay for their own expr text on every call.
        for (self.checks.specs.items) |spec| {
            var parsed = exprmod.parse(self.allocator, spec.source) catch return error.InvalidCheckExpression;
            defer parsed.deinit();
            if (!parsed.predicate.evaluate(&newRow)) return error.CheckViolation;
        }

        // UNIQUE constraint check runs before any index or row mutation
        // below, so a violation leaves everything untouched - the same
        // all-or-nothing shape callers already get from a plain `put`
        // either succeeding outright or failing outright. A field that
        // did not change value from the row's own previous value is
        // exempt (it already legitimately owns that value), which is why
        // updating unrelated fields on a row that already holds a unique
        // value never spuriously conflicts with itself.
        for (self.unique.fields.items) |field| {
            const newValue = newRow.get(field) orelse continue;
            const oldValue = if (old) |*o| o.get(field) else null;
            if (oldValue != null and Value.eql(oldValue.?, newValue)) continue;
            const owners = try idx.scanEq(self.db, self.allocator, self.name, field, newValue);
            defer {
                for (owners) |v| v.free(self.allocator);
                self.allocator.free(owners);
            }
            for (owners) |ownerPk| {
                if (!Value.eql(ownerPk, pk)) return error.UniqueViolation;
            }
        }

        // FOREIGN KEY check, same "before any mutation" placement as UNIQUE
        // above. Unlike UNIQUE, an unchanged value is NOT exempt: nothing in
        // this codebase stops the referenced row from having been deleted
        // out from under an already-valid reference since the last write
        // (no catalog of dependent tables exists to block that delete - see
        // `Table.createForeignKey`'s doc comment), so every put re-checks
        // every constrained field's current target rather than trusting a
        // value that merely did not change this time.
        for (self.foreignKeys.specs.items) |spec| {
            const newValue = newRow.get(spec.field) orelse continue;
            if (newValue == .none) continue;
            if (!try self.foreignKeyTargetExists(spec.refTable, spec.refField, newValue)) return error.ForeignKeyViolation;
        }

        // ON DELETE RESTRICT's update-side counterpart, see
        // `updateRestrictedByForeignKey`'s doc comment - must run before any
        // index or row mutation below, same all-or-nothing placement as
        // every other constraint check in this function.
        if (try self.updateRestrictedByForeignKey(pk, if (old) |*o| o else null, &newRow)) return error.ForeignKeyInUse;

        for (self.indexes.fields.items) |indexedField| {
            const newValue = newRow.get(indexedField);
            const oldValue = if (old) |*o| o.get(indexedField) else null;
            if (oldValue != null and (newValue == null or !Value.eql(oldValue.?, newValue.?))) {
                try idx.removeEntry(self.db, self.allocator, self.name, indexedField, oldValue.?, pk);
            }
            if (newValue) |nv| {
                if (oldValue == null or !Value.eql(oldValue.?, nv)) {
                    try idx.addEntry(self.db, self.allocator, self.name, indexedField, nv, pk);
                }
            }
        }

        for (self.composite.specs.items) |spec| {
            var oldValues: [maxCompositeFields]Value = undefined;
            var oldComplete = old != null;
            if (old) |*o| {
                for (spec.fields, 0..) |f, i| {
                    oldValues[i] = o.get(f) orelse {
                        oldComplete = false;
                        break;
                    };
                }
            }
            var newValues: [maxCompositeFields]Value = undefined;
            var newComplete = true;
            for (spec.fields, 0..) |f, i| {
                newValues[i] = newRow.get(f) orelse {
                    newComplete = false;
                    break;
                };
            }
            const unchanged = oldComplete and newComplete and valueTupleEql(oldValues[0..spec.fields.len], newValues[0..spec.fields.len]);
            if (unchanged) continue;
            if (oldComplete) try idx.removeCompositeEntry(self.db, self.allocator, self.name, spec.name, oldValues[0..spec.fields.len], pk);
            if (newComplete) try idx.addCompositeEntry(self.db, self.allocator, self.name, spec.name, newValues[0..spec.fields.len], pk);
        }

        try self.db.put(key, encoded);
    }

    pub fn get(self: *Table, pk: Value) !?Row {
        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);
        const raw = try self.db.get(self.allocator, key) orelse return null;
        defer self.allocator.free(raw);
        return try Row.decode(self.allocator, raw);
    }

    /// One (table, pk) a cascading delete has decided to remove, in the
    /// order `planCascade` discovered it - deepest dependents first, the
    /// row that was actually asked for last. Owns copies of both fields
    /// independently of whatever `Row`/`Table` produced them, since the
    /// scan that found them is long gone (and possibly a different
    /// `Table` handle entirely) by the time `delete` executes the plan.
    const CascadeAction = struct {
        table: []u8,
        pk: Value,

        fn deinit(self: *const CascadeAction, allocator: Allocator) void {
            allocator.free(self.table);
            self.pk.free(allocator);
        }
    };

    /// Cycle guard for `planCascade`: every (table, pk) already visited
    /// this call, so a cascade that loops back on itself (two tables
    /// `ON DELETE CASCADE`-ing at each other, or a longer cycle through
    /// three or more) terminates instead of recursing forever. Linear
    /// scan is fine here - a cascading delete's fan-out is bounded by how
    /// much data actually exists, and this runs once per row touched, not
    /// once per row scanned.
    const CascadeVisited = struct {
        allocator: Allocator,
        entries: std.ArrayList(CascadeAction),

        fn init(allocator: Allocator) CascadeVisited {
            return .{ .allocator = allocator, .entries = std.ArrayList(CascadeAction).init(allocator) };
        }

        fn contains(self: *const CascadeVisited, table: []const u8, pk: Value) bool {
            for (self.entries.items) |e| {
                if (std.mem.eql(u8, e.table, table) and Value.eql(e.pk, pk)) return true;
            }
            return false;
        }

        fn add(self: *CascadeVisited, table: []const u8, pk: Value) !void {
            const tableCopy = try self.allocator.dupe(u8, table);
            errdefer self.allocator.free(tableCopy);
            const pkCopy = try pk.dupe(self.allocator);
            try self.entries.append(.{ .table = tableCopy, .pk = pkCopy });
        }

        fn deinit(self: *CascadeVisited) void {
            for (self.entries.items) |e| e.deinit(self.allocator);
            self.entries.deinit();
        }
    };

    /// Recursively works out everything a delete of `pk` must remove,
    /// WITHOUT deleting anything yet, appending each decision to `plan` in
    /// dependent-before-dependency order (see `CascadeAction`'s doc
    /// comment) so `delete` can execute it leaves-first. This two-phase
    /// plan/execute split is what keeps a cascading delete all-or-nothing:
    /// a `restrict`-mode violation discovered three levels deep must abort
    /// with NOTHING mutated, exactly like the single-table check this
    /// replaced - if planning and deleting were interleaved, an earlier
    /// sibling subtree could already be gone by the time a later one fails.
    ///
    /// For every `ReferencedBySet` entry naming a table with a live row
    /// pointing at `old`'s value for the referenced field (see the
    /// previous version of this function for why the child is opened and
    /// scanned in full rather than through `idx.scanEq`, and why a
    /// self-referencing FK excludes `pk` itself from matching): `restrict`
    /// aborts the whole plan with `error.ForeignKeyInUse`; `cascade`
    /// recurses into that child row first, so it lands in `plan` ahead of
    /// `self` (a child must be gone before its parent is, or the delete
    /// order would itself violate the very constraint being enforced).
    ///
    /// `visited` is checked (and updated) BEFORE any of that per-row work,
    /// so a cycle (`planCascade(A)` reaching `planCascade(B)` reaching
    /// `planCascade(A)` again) short-circuits the re-entrant call instead
    /// of looping - the ORIGINAL call for that (table, pk) is still the one
    /// that appends it to `plan`, once its own scan finishes, so nothing is
    /// silently dropped from the plan by the cycle.
    fn planCascade(self: *Table, pk: Value, visited: *CascadeVisited, plan: *std.ArrayList(CascadeAction)) !void {
        if (visited.contains(self.name, pk)) return;
        var old = try self.get(pk) orelse return;
        defer old.deinit();
        try visited.add(self.name, pk);

        var referencedBy = try ReferencedBySet.load(self.allocator, self.db, self.name);
        defer referencedBy.deinit();
        for (referencedBy.specs.items) |spec| {
            const value = old.get(spec.refField) orelse continue;
            if (value == .none) continue;

            var child = try Table.open(self.db, self.allocator, spec.childTable);
            defer child.deinit();
            const rows = try child.scanAll();
            defer freeRows(self.allocator, rows);
            const selfReferencing = std.mem.eql(u8, spec.childTable, self.name);
            for (rows) |*r| {
                if (selfReferencing) {
                    if (r.get(pkField)) |rowPk| {
                        if (Value.eql(rowPk, pk)) continue;
                    }
                }
                const childValue = r.get(spec.childField) orelse continue;
                if (childValue == .none) continue;
                if (!Value.eql(childValue, value)) continue;

                switch (spec.onDelete) {
                    .restrict => return error.ForeignKeyInUse,
                    .cascade => {
                        const childPk = r.get(pkField) orelse continue;
                        try child.planCascade(childPk, visited, plan);
                    },
                }
            }
        }

        try plan.append(.{ .table = try self.allocator.dupe(u8, self.name), .pk = try pk.dupe(self.allocator) });
    }

    /// The actual row/index removal `delete` used to do inline before
    /// cascading existed - no FOREIGN KEY check here at all, since by the
    /// time this runs `planCascade` has already proven the entire plan is
    /// safe to execute in order. Takes `pk` rather than a decoded row
    /// because `CascadeAction` only carries the two, and re-fetching here
    /// (rather than threading the `Row` `planCascade` already read) is
    /// what lets `delete` stay tolerant of a row that no longer exists by
    /// execution time - unreachable in practice (nothing between planning
    /// and executing can delete a row out from under this single-threaded
    /// call), but cheap to make robust to rather than to assume away.
    fn executeDelete(self: *Table, pk: Value) !void {
        var old = try self.get(pk) orelse return;
        defer old.deinit();

        for (self.indexes.fields.items) |indexedField| {
            if (old.get(indexedField)) |v| {
                try idx.removeEntry(self.db, self.allocator, self.name, indexedField, v, pk);
            }
        }

        for (self.composite.specs.items) |spec| {
            var values: [maxCompositeFields]Value = undefined;
            var complete = true;
            for (spec.fields, 0..) |f, i| {
                values[i] = old.get(f) orelse {
                    complete = false;
                    break;
                };
            }
            if (complete) try idx.removeCompositeEntry(self.db, self.allocator, self.name, spec.name, values[0..spec.fields.len], pk);
        }

        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);
        try self.db.delete(key);
    }

    /// SQL's `ON DELETE RESTRICT`/`CASCADE` (see `planCascade` above) has an
    /// easy-to-miss counterpart: this codebase never leaves a child dangling
    /// when its parent ROW disappears, but until now nothing stopped a `put`
    /// from changing the parent's *value* out from under a still-live child -
    /// `refTable.dropIndex(refField)` and `updateWhere`/direct `put` changing
    /// a `refField` are exactly the "carpet pulled from under the child"
    /// cases `createForeignKey`'s own doc comment already named as open
    /// gaps. Reuses the identical scan and self-reference exclusion as
    /// `planCascade` (a value that stops existing under this pk is exactly
    /// as dangerous to a live reference as a row that stops existing
    /// entirely), but the trigger is "this pk's value for `refField` is
    /// about to change", not "this pk is about to be deleted" - so `old` may
    /// be null (a fresh insert has nothing to pull out from under anyone)
    /// and a field whose new value equals its old value is exempt, the same
    /// "unchanged is always safe" exemption `put`'s own UNIQUE check makes.
    /// Unlike `planCascade`, this ALWAYS restricts regardless of the
    /// constraint's `onDelete` mode - there is no `ON UPDATE CASCADE` here,
    /// only `ON DELETE CASCADE`, so even a `cascade`-mode FK still blocks a
    /// value change under a live reference.
    fn updateRestrictedByForeignKey(self: *Table, pk: Value, old: ?*const Row, newRow: *const Row) !bool {
        var referencedBy = try ReferencedBySet.load(self.allocator, self.db, self.name);
        defer referencedBy.deinit();
        for (referencedBy.specs.items) |spec| {
            const oldValue = if (old) |o| o.get(spec.refField) else null;
            if (oldValue == null or oldValue.? == .none) continue;
            const newValue = newRow.get(spec.refField);
            if (newValue != null and Value.eql(oldValue.?, newValue.?)) continue;

            var child = try Table.open(self.db, self.allocator, spec.childTable);
            defer child.deinit();
            const rows = try child.scanAll();
            defer freeRows(self.allocator, rows);
            const selfReferencing = std.mem.eql(u8, spec.childTable, self.name);
            for (rows) |*r| {
                if (selfReferencing) {
                    if (r.get(pkField)) |rowPk| {
                        if (Value.eql(rowPk, pk)) continue;
                    }
                }
                const childValue = r.get(spec.childField) orelse continue;
                if (childValue == .none) continue;
                if (Value.eql(childValue, oldValue.?)) return true;
            }
        }
        return false;
    }

    /// Deletes `pk`, honoring every `ON DELETE` mode registered against
    /// this table by some OTHER table's `createForeignKey` (see
    /// `idx.OnDelete`'s doc comment): a `restrict`-mode reference still
    /// pointing at this row aborts the whole call with
    /// `error.ForeignKeyInUse` and nothing is mutated; a `cascade`-mode
    /// one instead removes the referencing rows too, recursively, before
    /// this row itself goes - see `planCascade`'s doc comment for why
    /// that has to happen in two passes (plan every removal first, then
    /// execute the plan) rather than deleting as it discovers each one.
    /// A `pk` that does not exist is a silent no-op, same as before
    /// cascading existed.
    pub fn delete(self: *Table, pk: Value) !void {
        var visited = CascadeVisited.init(self.allocator);
        defer visited.deinit();
        var plan = std.ArrayList(CascadeAction).init(self.allocator);
        defer {
            for (plan.items) |a| a.deinit(self.allocator);
            plan.deinit();
        }

        try self.planCascade(pk, &visited, &plan);

        for (plan.items) |action| {
            var t = try Table.open(self.db, self.allocator, action.table);
            defer t.deinit();
            try t.executeDelete(action.pk);
        }
    }

    /// Applies `sets` on top of every row matching `pred` (or every row, if
    /// null) - SQL's `UPDATE <table> SET ... WHERE pred`. Deliberately not a
    /// bespoke in-place mutation path: each match is merged with `sets`
    /// (a `set` entry overrides a same-named existing field, or is appended
    /// if the row does not have that field yet) and written back through
    /// `put`, the exact same call an external caller doing `get` then `put`
    /// by hand would make - so every secondary/composite index touched by a
    /// changed field is maintained exactly like any other write, with zero
    /// special-casing here. Uses `selectAllMatches` rather than `selectPage`
    /// because every match must be visited regardless of any page window -
    /// there is no `LIMIT` on an `UPDATE`. Returns the number of rows
    /// updated.
    pub fn updateWhere(self: *Table, pred: ?Predicate, sets: []const Field) !usize {
        const matches = try self.selectAllMatches(pred);
        defer freeRows(self.allocator, matches);

        for (matches) |*row| {
            const pk = row.get(pkField) orelse continue;

            var merged = Row.init(self.allocator);
            defer merged.deinit();
            for (row.fields.items) |f| {
                if (std.mem.eql(u8, f.name, pkField)) continue;
                try merged.set(f.name, f.value);
            }
            for (sets) |f| try merged.set(f.name, f.value);

            try self.put(pk, merged.fields.items);
        }
        return matches.len;
    }

    /// Deletes every row matching `pred` (or every row, if null) - SQL's
    /// `DELETE FROM <table> WHERE pred`. Mirrors `updateWhere`: materializes
    /// the full match set with `selectAllMatches` (a `DELETE` has no
    /// `LIMIT` either, so partial-scan short-circuiting is wrong here same
    /// as for update) then removes each match through the existing single-row
    /// `delete`, so every secondary/composite index touched by the deleted
    /// row is maintained exactly like a caller doing `get` then `delete` by
    /// hand would - zero special-casing. Returns the number of rows deleted.
    pub fn deleteWhere(self: *Table, pred: ?Predicate) !usize {
        const matches = try self.selectAllMatches(pred);
        defer freeRows(self.allocator, matches);

        for (matches) |*row| {
            const pk = row.get(pkField) orelse continue;
            try self.delete(pk);
        }
        return matches.len;
    }

    /// Full table scan decoding every row, oldest key order. Callers own the
    /// returned slice and each Row in it (see freeRows).
    pub fn scanAll(self: *Table) ![]Row {
        const prefix = try idx.rowPrefix(self.allocator, self.name);
        defer self.allocator.free(prefix);

        var results = std.ArrayList(Row).init(self.allocator);
        errdefer {
            for (results.items) |*r| r.deinit();
            results.deinit();
        }

        var it = try self.db.scanPrefix(self.allocator, prefix);
        defer it.deinit();
        while (try it.next()) |entry| {
            const decoded = try Row.decode(self.allocator, entry.value);
            try results.append(decoded);
        }
        return results.toOwnedSlice();
    }

    /// Selects rows matching `pred` (or every row, if null). When `pred` is
    /// a single indexed condition, or an And containing one, the matching
    /// index is used to build a narrowed candidate set before the full
    /// predicate is re-checked against each candidate row - so results are
    /// always correct even though the optimization only ever inspects one
    /// conjunct's index.
    pub fn select(self: *Table, pred: ?Predicate) ![]Row {
        return self.selectPage(pred, .{});
    }

    /// Same as `select`, but skips the first `page.offset` matches and stops
    /// once `page.limit` matches have been collected (0 = unlimited, the
    /// same convention `protocol.ScanArgs` uses). Both the full-scan and
    /// index-narrowed paths stop iterating as soon as the limit is met
    /// instead of materializing the whole match set first - a real
    /// efficiency win for `LIMIT`-bounded queries against large tables, not
    /// just a post-hoc slice of an already-full result.
    pub fn selectPage(self: *Table, pred: ?Predicate, page: Page) ![]Row {
        if (pred) |p| {
            if (self.findCompositeMatch(p)) |match| {
                const cursor = try self.compositeCursorForMatch(match);
                return self.selectByIndexPage(p, cursor, page);
            }
            if (self.findIndexableLeaf(p)) |leaf| {
                const cursor = try self.cursorForLeaf(leaf);
                return self.selectByIndexPage(p, cursor, page);
            }
        }
        return self.scanFilteredPage(pred, page);
    }

    /// Same as `selectPage`, but sorts the matches by `orderBy` (when
    /// non-empty, one or more columns applied left to right - see
    /// `OrderBy`'s doc comment) before applying `page`'s offset/limit
    /// window. `selectPage`'s early-stop optimization (dropping a full scan
    /// or index cursor the moment `page.limit` matches are collected) is
    /// only correct when results come out in the strategy's natural order -
    /// sorting requires the full match set first, so an `orderBy` request
    /// materializes every match via `selectAllMatches` (still using
    /// whichever index `explain` would report, just without the early
    /// stop), sorts it, then slices the requested window with
    /// `applyRowPage`. An empty `orderBy` falls straight through to
    /// `selectPage`, keeping the early-stop behavior unchanged for the
    /// common unordered case.
    pub fn selectPageOrdered(self: *Table, pred: ?Predicate, page: Page, orderBy: []const OrderBy) ![]Row {
        if (orderBy.len == 0) return self.selectPage(pred, page);
        const all = try self.selectAllMatches(pred);
        errdefer freeRows(self.allocator, all);
        sortRowsBy(all, orderBy);
        return applyRowPage(self.allocator, all, page);
    }

    /// Collects every row matching `pred`, unpaged - the same
    /// index-vs-full-scan strategy choice `selectPage`/`explain` make,
    /// just always run to completion instead of stopping at a page limit.
    fn selectAllMatches(self: *Table, pred: ?Predicate) ![]Row {
        if (pred) |p| {
            if (self.findCompositeMatch(p)) |match| {
                const cursor = try self.compositeCursorForMatch(match);
                return self.selectByIndexPage(p, cursor, .{});
            }
            if (self.findIndexableLeaf(p)) |leaf| {
                const cursor = try self.cursorForLeaf(leaf);
                return self.selectByIndexPage(p, cursor, .{});
            }
        }
        return self.scanFilteredPage(pred, .{});
    }

    /// Reports which strategy `selectPage` would pick for `pred` without
    /// running it - the exact same decision ladder (composite match first,
    /// then a single-field indexable leaf, then a full scan), just stopping
    /// one step short of building a cursor. Exists so a caller (the CLI's
    /// `table explain`, its network/repl mirrors) can answer "would this
    /// query use an index" without materializing rows or mutating anything,
    /// which is why this takes `*const Table` unlike `selectPage`.
    pub fn explain(self: *const Table, allocator: Allocator, pred: ?Predicate) !Plan {
        if (pred) |p| {
            if (self.findCompositeMatch(p)) |match| {
                const spec = self.composite.specs.items[match.specIdx];
                const isRange = match.rangeLow != null or match.rangeHigh != null;
                return .{
                    .kind = if (isRange) .composite_range else .composite_eq,
                    .indexName = try allocator.dupe(u8, spec.name),
                    .matchedFields = match.matchedLen,
                    .totalFields = spec.fields.len,
                };
            }
            if (self.findIndexableLeaf(p)) |leaf| {
                const field = switch (leaf) {
                    .eq, .lt, .lte, .gt, .gte => |c| c.field,
                    else => unreachable,
                };
                const isRange = switch (leaf) {
                    .lt, .lte, .gt, .gte => true,
                    else => false,
                };
                return .{
                    .kind = if (isRange) .index_range else .index_eq,
                    .indexName = try allocator.dupe(u8, field),
                    .matchedFields = 1,
                    .totalFields = 1,
                };
            }
        }
        return .{ .kind = .full_scan };
    }

    fn scanFilteredPage(self: *Table, pred: ?Predicate, page: Page) ![]Row {
        const prefix = try idx.rowPrefix(self.allocator, self.name);
        defer self.allocator.free(prefix);

        var results = std.ArrayList(Row).init(self.allocator);
        errdefer {
            for (results.items) |*r| r.deinit();
            results.deinit();
        }

        var skipped: usize = 0;
        var it = try self.db.scanPrefix(self.allocator, prefix);
        defer it.deinit();
        while (try it.next()) |entry| {
            var decoded = try Row.decode(self.allocator, entry.value);
            const matches = if (pred) |p| p.evaluate(&decoded) else true;
            if (!matches) {
                decoded.deinit();
                continue;
            }
            if (skipped < page.offset) {
                skipped += 1;
                decoded.deinit();
                continue;
            }
            try results.append(decoded);
            if (page.limit != 0 and results.items.len >= page.limit) break;
        }
        return results.toOwnedSlice();
    }

    /// Streams primary keys straight from the index cursor instead of first
    /// materializing the whole candidate list (see `idx.EqCursor`/
    /// `idx.RangeCursor`): once `page.limit` rows are collected the
    /// underlying `Db` scan is simply dropped without decoding or even
    /// reading whatever index entries would have come after it, which
    /// matters when the indexed value has far more matches than the page
    /// being asked for.
    fn selectByIndexPage(self: *Table, p: Predicate, cursorIn: IndexCursor, page: Page) ![]Row {
        var cursor = cursorIn;
        defer cursor.deinit();

        var results = std.ArrayList(Row).init(self.allocator);
        errdefer {
            for (results.items) |*r| r.deinit();
            results.deinit();
        }
        var skipped: usize = 0;
        while (try cursor.next(self.allocator)) |pk| {
            defer pk.free(self.allocator);
            var r = try self.get(pk) orelse continue;
            if (!p.evaluate(&r)) {
                r.deinit();
                continue;
            }
            if (skipped < page.offset) {
                skipped += 1;
                r.deinit();
                continue;
            }
            try results.append(r);
            if (page.limit != 0 and results.items.len >= page.limit) break;
        }
        return results.toOwnedSlice();
    }

    fn findIndexableLeaf(self: *const Table, p: Predicate) ?Predicate {
        switch (p) {
            .eq, .lt, .lte, .gt, .gte => |c| {
                if (self.indexes.has(c.field)) return p;
                return null;
            },
            .and_ => |preds| {
                for (preds) |sub| {
                    if (self.findIndexableLeaf(sub)) |found| return found;
                }
                return null;
            },
            else => return null,
        }
    }

    /// Streaming counterpart of the old `pksForLeaf` (which returned a fully
    /// materialized `[]Value`): wraps whichever `idx` cursor constructor
    /// matches the leaf's comparison so `selectByIndexPage` can decode and
    /// discard candidates one at a time.
    const IndexCursor = union(enum) {
        eq: idx.EqCursor,
        range: idx.RangeCursor,
        compositeEq: idx.CompositeEqCursor,
        compositeRange: idx.CompositeRangeCursor,

        fn next(self: *IndexCursor, allocator: Allocator) !?Value {
            return switch (self.*) {
                .eq => |*c| c.next(allocator),
                .range => |*c| c.next(allocator),
                .compositeEq => |*c| c.next(allocator),
                .compositeRange => |*c| c.next(allocator),
            };
        }

        fn deinit(self: *IndexCursor) void {
            switch (self.*) {
                .eq => |*c| c.deinit(),
                .range => |*c| c.deinit(),
                .compositeEq => |*c| c.deinit(),
                .compositeRange => |*c| c.deinit(),
            }
        }
    };

    fn cursorForLeaf(self: *Table, leaf: Predicate) !IndexCursor {
        return switch (leaf) {
            .eq => |c| .{ .eq = try idx.scanEqCursor(self.db, self.allocator, self.name, c.field, c.value) },
            .lt => |c| .{ .range = try idx.scanRangeCursor(self.db, self.allocator, self.name, c.field, null, .{ .value = c.value, .inclusive = false }) },
            .lte => |c| .{ .range = try idx.scanRangeCursor(self.db, self.allocator, self.name, c.field, null, .{ .value = c.value, .inclusive = true }) },
            .gt => |c| .{ .range = try idx.scanRangeCursor(self.db, self.allocator, self.name, c.field, .{ .value = c.value, .inclusive = false }, null) },
            .gte => |c| .{ .range = try idx.scanRangeCursor(self.db, self.allocator, self.name, c.field, .{ .value = c.value, .inclusive = true }, null) },
            else => unreachable,
        };
    }

    const CompositeMatch = struct {
        specIdx: usize,
        values: [maxCompositeFields]Value,
        matchedLen: usize,
        // A range condition on the column immediately after the matched
        // eq prefix (spec.fields[matchedLen]), if the predicate has one -
        // same leftmost-prefix rule a real multi-column B-tree range scan
        // follows: only the column right after the pinned prefix can be
        // range-bound by the index, anything further is unconstrained.
        rangeLow: ?idx.Bound = null,
        rangeHigh: ?idx.Bound = null,
    };

    /// Looks for a composite index whose leading ("leftmost") columns are
    /// all pinned down by a top-level `eq` conjunct somewhere in `p` (an
    /// `and_`, in any order - unlike a real SQL planner this does not
    /// recurse into nested and_/or_, matching `findIndexableLeaf`'s scope).
    /// The match may cover a strict prefix of the index's columns, not
    /// necessarily all of them: a query naming only the first K of N
    /// indexed fields still gets a narrowed lookup, same leftmost-prefix
    /// rule a multi-column B-tree index gives you. When the column right
    /// after the matched prefix also has a top-level lt/lte/gt/gte conjunct
    /// on it, that becomes a range bound narrowing the scan further instead
    /// of leaving it unconstrained. `selectByIndexPage` re-evaluates the
    /// full predicate against every candidate row regardless, so an
    /// unmatched suffix of columns (or any other conjunct entirely) never
    /// affects correctness, only how much the index narrows the scan.
    fn findCompositeMatch(self: *const Table, p: Predicate) ?CompositeMatch {
        const preds = switch (p) {
            .and_ => |ps| ps,
            else => return null,
        };
        for (self.composite.specs.items, 0..) |spec, si| {
            var values: [maxCompositeFields]Value = undefined;
            var matched: usize = 0;
            for (spec.fields) |f| {
                const found = for (preds) |leaf| {
                    if (leaf == .eq and std.mem.eql(u8, leaf.eq.field, f)) break leaf.eq.value;
                } else null;
                const v = found orelse break;
                values[matched] = v;
                matched += 1;
            }
            if (matched == 0) continue;

            var rangeLow: ?idx.Bound = null;
            var rangeHigh: ?idx.Bound = null;
            if (matched < spec.fields.len) {
                const nextField = spec.fields[matched];
                for (preds) |leaf| {
                    switch (leaf) {
                        .gt => |c| if (std.mem.eql(u8, c.field, nextField)) {
                            rangeLow = .{ .value = c.value, .inclusive = false };
                        },
                        .gte => |c| if (std.mem.eql(u8, c.field, nextField)) {
                            rangeLow = .{ .value = c.value, .inclusive = true };
                        },
                        .lt => |c| if (std.mem.eql(u8, c.field, nextField)) {
                            rangeHigh = .{ .value = c.value, .inclusive = false };
                        },
                        .lte => |c| if (std.mem.eql(u8, c.field, nextField)) {
                            rangeHigh = .{ .value = c.value, .inclusive = true };
                        },
                        else => {},
                    }
                }
            }
            return .{ .specIdx = si, .values = values, .matchedLen = matched, .rangeLow = rangeLow, .rangeHigh = rangeHigh };
        }
        return null;
    }

    fn compositeCursorForMatch(self: *Table, match: CompositeMatch) !IndexCursor {
        const spec = self.composite.specs.items[match.specIdx];
        const eqValues = match.values[0..match.matchedLen];
        if (match.rangeLow != null or match.rangeHigh != null) {
            return .{ .compositeRange = try idx.scanCompositeRangeCursor(self.db, self.allocator, self.name, spec.name, eqValues, match.rangeLow, match.rangeHigh) };
        }
        return .{ .compositeEq = try idx.scanCompositeEqCursor(self.db, self.allocator, self.name, spec.name, eqValues) };
    }
};

fn valueTupleEql(a: []const Value, b: []const Value) bool {
    if (a.len != b.len) return false;
    for (a, b) |av, bv| {
        if (!Value.eql(av, bv)) return false;
    }
    return true;
}

pub fn freeRows(allocator: Allocator, rows: []Row) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

/// Stable in-place sort of `rows` by `order`, using `rowmod.compare`'s
/// total order across value types (see `OrderBy`'s doc comment for how a
/// missing field sorts). Columns are compared left to right: the first
/// entry decides unless it ties (`.eq`), in which case the next entry
/// breaks the tie, and so on - a plain lexicographic comparator chain, the
/// same rule SQL's `ORDER BY a, b, c` follows. `std.sort.block` rather than
/// the faster unstable `std.sort.pdq` specifically so ties that survive
/// every column preserve scan order, matching what `OrderBy`'s doc comment
/// promises callers.
fn sortRowsBy(rows: []Row, order: []const OrderBy) void {
    const Ctx = struct {
        order: []const OrderBy,

        fn lessThan(ctx: @This(), a: Row, b: Row) bool {
            for (ctx.order) |ob| {
                const av = a.get(ob.field) orelse Value{ .none = {} };
                const bv = b.get(ob.field) orelse Value{ .none = {} };
                const cmp = rowmod.compare(av, bv);
                if (cmp == .eq) continue;
                return if (ob.descending) cmp == .gt else cmp == .lt;
            }
            return false;
        }
    };
    std.sort.block(Row, rows, Ctx{ .order = order }, Ctx.lessThan);
}

/// Slices an already-materialized, unpaged match set (as `selectAllMatches`
/// returns) down to `page`'s offset/limit window, freeing every row that
/// falls outside it and the original backing allocation - the ordered
/// counterpart of the early-stop windowing `selectByIndexPage`/
/// `scanFilteredPage` do inline while scanning. `rows` must not be used
/// after this call regardless of error (see `errdefer` at the call site).
fn applyRowPage(allocator: Allocator, rows: []Row, page: Page) ![]Row {
    const start = @min(page.offset, rows.len);
    const end = if (page.limit == 0) rows.len else @min(rows.len, start + page.limit);
    for (rows[0..start]) |*r| r.deinit();
    for (rows[end..]) |*r| r.deinit();
    const kept = rows[start..end];
    const out = try allocator.alloc(Row, kept.len);
    @memcpy(out, kept);
    allocator.free(rows);
    return out;
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

test "table put get delete round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "name", .value = .{ .text = "ada" } },
        .{ .name = "age", .value = .{ .int = 36 } },
    });

    var got = (try table.get(.{ .int = 1 })).?;
    defer got.deinit();
    try std.testing.expectEqualStrings("ada", got.get("name").?.text);
    try std.testing.expectEqual(@as(i64, 36), got.get("age").?.int);
    try std.testing.expectEqual(@as(i64, 1), got.get(pkField).?.int);

    try table.delete(.{ .int = 1 });
    try std.testing.expect((try table.get(.{ .int = 1 })) == null);
}

test "table put replaces whole row" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "name", .value = .{ .text = "ada" } },
        .{ .name = "age", .value = .{ .int = 36 } },
    });
    try table.put(.{ .int = 1 }, &.{
        .{ .name = "name", .value = .{ .text = "ada" } },
    });

    var got = (try table.get(.{ .int = 1 })).?;
    defer got.deinit();
    try std.testing.expect(got.get("age") == null);
    try std.testing.expectEqualStrings("ada", got.get("name").?.text);
}

test "createIndex backfills then eq select uses index" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    try table.createIndex("city");
    try std.testing.expect(table.hasIndex("city"));

    const results = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "like predicate filters by pattern and never uses an index on that field" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    // Index the very field the like-predicate targets: `like` must still
    // fall back to a full scan (`Value.compare`-based index entries have no
    // notion of substring matching), never mistake this for an eq lookup.
    try table.createIndex("name");

