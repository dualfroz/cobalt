const std = @import("std");
const txnmod = @import("txn.zig");
const dbmod = @import("db.zig");
const rowmod = @import("row.zig");
const idx = @import("index.zig");
const querymod = @import("query.zig");
const exprmod = @import("expr.zig");

const Allocator = std.mem.Allocator;
const Transaction = txnmod.Transaction;
const Db = dbmod.Db;
const Value = rowmod.Value;
const Row = rowmod.Row;
const Field = rowmod.Field;
const IndexSet = idx.IndexSet;
const UniqueSet = idx.UniqueSet;
const ForeignKeySet = idx.ForeignKeySet;
const CheckConstraintSet = idx.CheckConstraintSet;

/// Same reserved primary-key field name query.zig's Table uses, so rows
/// written through a TableTxn and rows written through a plain Table are
/// wire-compatible: both land in the same "R\x00table\x00pk" keyspace and
/// decode identically.
pub const pkField = querymod.pkField;

/// A Table view bound to one in-flight Transaction. Where query.zig's Table
/// writes each row and its index entries directly to the Db (each `put`/
/// `delete` call is independently durable the moment it returns), TableTxn
/// stages every row write and every index-entry write into the Transaction's
/// write set instead. Nothing is visible to other readers, and nothing can
/// conflict with a concurrent writer, until the caller calls `Transaction.
/// commit()` - at which point every staged row and index mutation across
/// every TableTxn.put/delete call made against this Transaction becomes
/// visible atomically in a single WriteBatch, or none of it does (OCC
/// conflict -> error.Conflict, no partial application).
///
/// Index membership itself (which fields are indexed) is read directly from
/// the Db when a TableTxn is opened, not through the Transaction - creating
/// or dropping an index is a schema change made through query.zig's Table,
/// not through TableTxn. A TableTxn only keeps *existing* indexes in sync
/// for the rows it writes.
pub const TableTxn = struct {
    txn: *Transaction,
    allocator: Allocator,
    name: []u8,
    indexes: IndexSet,
    unique: UniqueSet,
    foreignKeys: ForeignKeySet,
    checks: CheckConstraintSet,

    pub fn open(txn: *Transaction, allocator: Allocator, name: []const u8) !TableTxn {
        if (!idx.validIdentifier(name)) return error.InvalidIdentifier;
        return .{
            .txn = txn,
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .indexes = try IndexSet.load(allocator, txn.db, name),
            .unique = try UniqueSet.load(allocator, txn.db, name),
            .foreignKeys = try ForeignKeySet.load(allocator, txn.db, name),
            .checks = try CheckConstraintSet.load(allocator, txn.db, name),
        };
    }

    pub fn deinit(self: *TableTxn) void {
        self.allocator.free(self.name);
        self.indexes.deinit();
        self.unique.deinit();
        self.foreignKeys.deinit();
        self.checks.deinit();
    }

    pub fn hasIndex(self: *const TableTxn, field: []const u8) bool {
        return self.indexes.has(field);
    }

    pub fn hasUniqueIndex(self: *const TableTxn, field: []const u8) bool {
        return self.unique.has(field);
    }

    pub fn hasForeignKey(self: *const TableTxn, field: []const u8) bool {
        return self.foreignKeys.has(field);
    }

    pub fn hasCheckConstraint(self: *const TableTxn, name: []const u8) bool {
        return self.checks.has(name);
    }

    /// Whether `value` names an existing row of `spec.refTable` under
    /// `spec.refField`, mirroring `query.zig`'s `Table.foreignKeyTargetExists`
    /// with one difference: both branches go through the bound `Transaction`
    /// instead of a plain `Db` call, so a parent row (or a unique-field FK
    /// target) staged earlier in the SAME uncommitted transaction already
    /// satisfies a child's FK check before either is durable -
    /// read-your-writes across tables, not just within one, via
    /// `Transaction.get` for the `pkField` case and `Transaction.scanPrefix`
    /// (see its doc comment) for the non-pk case.
    fn foreignKeyTargetExists(self: *TableTxn, refTableName: []const u8, refField: []const u8, value: Value) !bool {
        if (std.mem.eql(u8, refField, pkField)) {
            const key = try idx.rowKey(self.allocator, refTableName, value);
            defer self.allocator.free(key);
            const raw = try self.txn.get(self.allocator, key) orelse return false;
            self.allocator.free(raw);
            return true;
        }
        const prefix = try idx.indexValueBound(self.allocator, refTableName, refField, value);
        defer self.allocator.free(prefix);
        const entries = try self.txn.scanPrefix(self.allocator, prefix);
        defer txnmod.Transaction.freeEntries(self.allocator, entries);
        return entries.len > 0;
    }

    /// Reads through the bound Transaction, so this sees the Transaction's
    /// own uncommitted writes (read-your-writes) and registers the row key
    /// as read for OCC conflict detection at commit time.
    pub fn get(self: *TableTxn, pk: Value) !?Row {
        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);
        const raw = try self.txn.get(self.allocator, key) orelse return null;
        defer self.allocator.free(raw);
        return try Row.decode(self.allocator, raw);
    }

    /// Stages a full-row replace of `pk` plus every index-entry add/remove
    /// needed to keep currently-registered indexes consistent with the new
    /// row, all as buffered Transaction writes. None of it is visible or
    /// durable until commit.
    pub fn put(self: *TableTxn, pk: Value, fields: []const Field) !void {
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

        // CHECK constraints run first, ahead of UNIQUE/FOREIGN KEY - same
        // ordering and same "reparse on every put" cost as `query.zig`'s
        // `Table.put`. Purely local to `newRow`, so unlike UNIQUE/FOREIGN
        // KEY below this needs no `Transaction.scanPrefix` read-your-writes
        // handling at all.
        for (self.checks.specs.items) |spec| {
            var parsed = exprmod.parse(self.allocator, spec.source) catch return error.InvalidCheckExpression;
            defer parsed.deinit();
            if (!parsed.predicate.evaluate(&newRow)) return error.CheckViolation;
        }

        // UNIQUE and FOREIGN KEY checks run before any staged mutation
        // below, same all-or-nothing placement as `query.zig`'s `Table.put`:
        // a violation leaves the transaction's write set exactly as it was
        // before this call, not staged with a partial row. Both checks go
        // through `Transaction.scanPrefix`, so a UNIQUE value or FK target
        // staged by an EARLIER `put` call in this same still-open
        // transaction (a different row, possibly a different `TableTxn`
        // bound to the same `Transaction`) is caught here already, not left
        // to surface as `error.Conflict` at `commit()`.
        for (self.unique.fields.items) |field| {
            const newValue = newRow.get(field) orelse continue;
            const oldValue = if (old) |*o| o.get(field) else null;
            if (oldValue != null and Value.eql(oldValue.?, newValue)) continue;
            const prefix = try idx.indexValueBound(self.allocator, self.name, field, newValue);
            defer self.allocator.free(prefix);
            const entries = try self.txn.scanPrefix(self.allocator, prefix);
            defer txnmod.Transaction.freeEntries(self.allocator, entries);
            for (entries) |e| {
                const ownerPk = try rowmod.decodeValue(self.allocator, e.value);
                defer ownerPk.free(self.allocator);
                if (!Value.eql(ownerPk, pk)) return error.UniqueViolation;
            }
        }

        for (self.foreignKeys.specs.items) |spec| {
            const newValue = newRow.get(spec.field) orelse continue;
            if (newValue == .none) continue;
            if (!try self.foreignKeyTargetExists(spec.refTable, spec.refField, newValue)) return error.ForeignKeyViolation;
        }

        // ON DELETE RESTRICT's update-side counterpart, see
        // `updateRestrictedByForeignKey`'s doc comment - same all-or-nothing
        // placement as every other constraint check above.
        if (try self.updateRestrictedByForeignKey(pk, if (old) |*o| o else null, &newRow)) return error.ForeignKeyInUse;

        for (self.indexes.fields.items) |indexedField| {
            const newValue = newRow.get(indexedField);
            const oldValue = if (old) |*o| o.get(indexedField) else null;
            if (oldValue != null and (newValue == null or !Value.eql(oldValue.?, newValue.?))) {
                try self.stageIndexRemove(indexedField, oldValue.?, pk);
            }
            if (newValue) |nv| {
                if (oldValue == null or !Value.eql(oldValue.?, nv)) {
                    try self.stageIndexAdd(indexedField, nv, pk);
                }
            }
        }

        try self.txn.put(key, encoded);
    }

    /// Mirrors `query.zig`'s `Table.deletionRestrictedByForeignKey` (SQL's
    /// `ON DELETE RESTRICT`), reading through `self.txn.scanPrefix` instead
    /// of a plain `Db` scan - the one thing this version can do that the
    /// plain `Table` path cannot: a child row staged earlier in this SAME
    /// uncommitted transaction (via a sibling `TableTxn` on the child
    /// table, sharing this `Transaction`) already counts as a live
    /// reference, not just whatever is durably committed. `referencedBy`
    /// itself is still loaded fresh from `self.txn.db` rather than cached
    /// (schema metadata - like `indexes`/`unique`/`foreignKeys` above - is
    /// only ever mutated through `query.zig`'s `Table`, never through a
    /// `TableTxn`, but unlike those, `ReferencedBySet` is written by some
    /// OTHER table's `createForeignKey` call, so a `TableTxn` opened before
    /// that ran cannot rely on whatever it loaded at `open()` time either -
    /// see `Table.createForeignKey`'s doc comment for the same reasoning).
    fn deletionRestrictedByForeignKey(self: *TableTxn, pk: Value, old: *const Row) !bool {
        var referencedBy = try idx.ReferencedBySet.load(self.allocator, self.txn.db, self.name);
        defer referencedBy.deinit();

        for (referencedBy.specs.items) |spec| {
            const value = old.get(spec.refField) orelse continue;
            if (value == .none) continue;

            const prefix = try idx.rowPrefix(self.allocator, spec.childTable);
            defer self.allocator.free(prefix);
            const entries = try self.txn.scanPrefix(self.allocator, prefix);
            defer Transaction.freeEntries(self.allocator, entries);

            const selfReferencing = std.mem.eql(u8, spec.childTable, self.name);
            for (entries) |entry| {
                var r = try Row.decode(self.allocator, entry.value);
                defer r.deinit();
                if (selfReferencing) {
                    if (r.get(pkField)) |rowPk| {
                        if (Value.eql(rowPk, pk)) continue;
                    }
                }
                const childValue = r.get(spec.childField) orelse continue;
                if (childValue == .none) continue;
                if (Value.eql(childValue, value)) return true;
            }
        }
        return false;
    }

    /// `TableTxn.put`'s counterpart to `deletionRestrictedByForeignKey`,
    /// mirroring `query.zig`'s `Table.updateRestrictedByForeignKey` (see its
    /// doc comment for why an update needs the same RESTRICT as a delete)
    /// but reading through `self.txn.scanPrefix` like the delete-restrict
    /// version above it, so a child row staged earlier in this same
    /// uncommitted transaction already counts as a live reference. `old` may
    /// be null (a fresh insert has nothing to pull out from under anyone),
    /// and a `refField` whose new value equals its old value is exempt, the
    /// same exemption `put`'s own UNIQUE check above makes.
    fn updateRestrictedByForeignKey(self: *TableTxn, pk: Value, old: ?*const Row, newRow: *const Row) !bool {
        var referencedBy = try idx.ReferencedBySet.load(self.allocator, self.txn.db, self.name);
        defer referencedBy.deinit();

        for (referencedBy.specs.items) |spec| {
            const oldValue = if (old) |o| o.get(spec.refField) else null;
            if (oldValue == null or oldValue.? == .none) continue;
            const newValue = newRow.get(spec.refField);
            if (newValue != null and Value.eql(oldValue.?, newValue.?)) continue;

            const prefix = try idx.rowPrefix(self.allocator, spec.childTable);
            defer self.allocator.free(prefix);
            const entries = try self.txn.scanPrefix(self.allocator, prefix);
            defer Transaction.freeEntries(self.allocator, entries);

            const selfReferencing = std.mem.eql(u8, spec.childTable, self.name);
            for (entries) |entry| {
                var r = try Row.decode(self.allocator, entry.value);
                defer r.deinit();
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

    pub fn delete(self: *TableTxn, pk: Value) !void {
        var old = try self.get(pk) orelse return;
        defer old.deinit();

        if (try self.deletionRestrictedByForeignKey(pk, &old)) return error.ForeignKeyInUse;

        for (self.indexes.fields.items) |indexedField| {
            if (old.get(indexedField)) |v| {
                try self.stageIndexRemove(indexedField, v, pk);
            }
        }

        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);
        try self.txn.delete(key);
    }

    fn stageIndexAdd(self: *TableTxn, field: []const u8, value: Value, pk: Value) !void {
        const key = try idx.indexEntryKey(self.allocator, self.name, field, value, pk);
        defer self.allocator.free(key);
        const pkBytes = try rowmod.encodeValue(self.allocator, pk);
        defer self.allocator.free(pkBytes);
        try self.txn.put(key, pkBytes);
    }

    fn stageIndexRemove(self: *TableTxn, field: []const u8, value: Value, pk: Value) !void {
        const key = try idx.indexEntryKey(self.allocator, self.name, field, value, pk);
        defer self.allocator.free(key);
        try self.txn.delete(key);
    }
};

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);
    return Db.open(allocator, dbPath, .{});
}

test "TableTxn commits multiple rows atomically" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var txn = Transaction.begin(&db);
    defer txn.deinit();

    var t = try TableTxn.open(&txn, allocator, "accounts");
    defer t.deinit();

    try t.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = 100 } }});
    try t.put(.{ .int = 2 }, &.{.{ .name = "balance", .value = .{ .int = 50 } }});

    // Nothing visible outside the transaction yet.
    const probeKey = try idx.rowKey(allocator, "accounts", .{ .int = 1 });
    defer allocator.free(probeKey);
    try std.testing.expect((try db.get(allocator, probeKey)) == null);

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "accounts");
    defer plain.deinit();
    var row1 = (try plain.get(.{ .int = 1 })).?;
    defer row1.deinit();
    var row2 = (try plain.get(.{ .int = 2 })).?;
    defer row2.deinit();
    try std.testing.expectEqual(@as(i64, 100), row1.get("balance").?.int);
    try std.testing.expectEqual(@as(i64, 50), row2.get("balance").?.int);
}

test "TableTxn transfer is all-or-nothing on conflict" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "accounts");
        defer setup.deinit();
        try setup.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = 100 } }});
        try setup.put(.{ .int = 2 }, &.{.{ .name = "balance", .value = .{ .int = 50 } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "accounts");
    defer t.deinit();

    // Move 30 from account 1 to account 2, staged but not yet committed.
    var from = (try t.get(.{ .int = 1 })).?;
    defer from.deinit();
    var to = (try t.get(.{ .int = 2 })).?;
    defer to.deinit();
    try t.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = from.get("balance").?.int - 30 } }});
    try t.put(.{ .int = 2 }, &.{.{ .name = "balance", .value = .{ .int = to.get("balance").?.int + 30 } }});

    // An external writer touches account 1 before the transfer commits.
    {
        var external = try querymod.Table.open(&db, allocator, "accounts");
        defer external.deinit();
        try external.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = 999 } }});
    }

    try std.testing.expectError(error.Conflict, txn.commit());

    // Neither leg of the transfer applied: account 2 must be untouched,
    // and account 1 must show the external writer's value, not the stale
    // transfer's.
    var verify = try querymod.Table.open(&db, allocator, "accounts");
    defer verify.deinit();
    var row1 = (try verify.get(.{ .int = 1 })).?;
    defer row1.deinit();
    var row2 = (try verify.get(.{ .int = 2 })).?;
    defer row2.deinit();
    try std.testing.expectEqual(@as(i64, 999), row1.get("balance").?.int);
    try std.testing.expectEqual(@as(i64, 50), row2.get("balance").?.int);
}

test "TableTxn keeps a pre-existing index in sync across commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "users");
        defer setup.deinit();
        try setup.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
        try setup.createIndex("city");
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();
    try std.testing.expect(t.hasIndex("city"));

    try t.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});
    try t.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "users");
    defer plain.deinit();
    const warsaw = try plain.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer querymod.freeRows(allocator, warsaw);
    try std.testing.expectEqual(@as(usize, 1), warsaw.len);
    try std.testing.expectEqual(@as(i64, 2), warsaw[0].get(pkField).?.int);

    const krakow = try plain.select(.{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } });
    defer querymod.freeRows(allocator, krakow);
    try std.testing.expectEqual(@as(usize, 1), krakow.len);
    try std.testing.expectEqual(@as(i64, 1), krakow[0].get(pkField).?.int);
}

test "TableTxn delete removes row and index entries only on commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "users");
        defer setup.deinit();
        try setup.createIndex("city");
        try setup.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();
    try t.delete(.{ .int = 1 });

    // Not yet committed: still visible outside the transaction.
    {
        var outside = try querymod.Table.open(&db, allocator, "users");
        defer outside.deinit();
        var stillThere = (try outside.get(.{ .int = 1 })).?;
        stillThere.deinit();
    }

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "users");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 1 })) == null);
    const warsaw = try plain.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer querymod.freeRows(allocator, warsaw);
    try std.testing.expectEqual(@as(usize, 0), warsaw.len);
}

test "TableTxn rejects invalid table identifier" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try std.testing.expectError(error.InvalidIdentifier, TableTxn.open(&txn, allocator, ""));
}

test "TableTxn read-your-writes sees staged rows before commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();

    try t.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "ada" } }});
    var seen = (try t.get(.{ .int = 1 })).?;
    defer seen.deinit();
    try std.testing.expectEqualStrings("ada", seen.get("name").?.text);

    try t.delete(.{ .int = 1 });
    try std.testing.expect((try t.get(.{ .int = 1 })) == null);
}

test "TableTxn put enforces UNIQUE constraint against committed data" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "users");
        defer setup.deinit();
        try setup.createUniqueIndex("email");
        try setup.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@example.com" } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();
    try std.testing.expect(t.hasUniqueIndex("email"));

    try std.testing.expectError(error.UniqueViolation, t.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@example.com" } },
    }));

    // The rejected put staged nothing: committing now applies zero rows.
    try txn.commit();
    var plain = try querymod.Table.open(&db, allocator, "users");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 2 })) == null);
}

test "TableTxn put UNIQUE check exempts a row keeping its own previous value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "users");
        defer setup.deinit();
        try setup.createUniqueIndex("email");
        try setup.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@example.com" } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();

    // Updating an unrelated field on row 1 keeps its own email unchanged -
    // must not spuriously conflict with itself.
    try t.put(.{ .int = 1 }, &.{
        .{ .name = "email", .value = .{ .text = "a@example.com" } },
        .{ .name = "name", .value = .{ .text = "ada" } },
    });
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "users");
    defer plain.deinit();
    var row = (try plain.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("ada", row.get("name").?.text);
}

test "TableTxn put enforces FOREIGN KEY against committed data and rejects a dangling reference" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var customers = try querymod.Table.open(&db, allocator, "customers");
        defer customers.deinit();
        try customers.put(.{ .int = 1 }, &.{});

        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "orders");
    defer t.deinit();
    try std.testing.expect(t.hasForeignKey("customer_id"));

    // customer 1 exists (committed) -> allowed.
    try t.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    // customer 999 does not exist anywhere -> rejected.
    try std.testing.expectError(error.ForeignKeyViolation, t.put(.{ .int = 101 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 999 } },
    }));

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "orders");
    defer plain.deinit();
    var row = (try plain.get(.{ .int = 100 })).?;
    defer row.deinit();
    try std.testing.expect((try plain.get(.{ .int = 101 })) == null);
}

test "TableTxn put FOREIGN KEY on pkField sees a parent staged earlier in the same uncommitted transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        // Self-referencing table (an org chart: manager_id -> employees.pk),
        // installed while empty so no existing-row check gets in the way.
        var employees = try querymod.Table.open(&db, allocator, "employees");
        defer employees.deinit();
        try employees.createForeignKey("manager_id", "employees", pkField, .restrict);
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "employees");
    defer t.deinit();

    // Neither row is committed yet. The manager (pk=1) is only staged in
    // this same transaction's write set, but the FK check on the report
    // (pk=2) must see it via `Transaction.get`'s read-your-writes, not
    // just via the underlying Db.
    try t.put(.{ .int = 1 }, &.{});
    try t.put(.{ .int = 2 }, &.{.{ .name = "manager_id", .value = .{ .int = 1 } }});

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "employees");
    defer plain.deinit();
    var report = (try plain.get(.{ .int = 2 })).?;
    defer report.deinit();
    try std.testing.expectEqual(@as(i64, 1), report.get("manager_id").?.int);
}

test "TableTxn put FOREIGN KEY on a non-pk unique field sees a target staged earlier in the same uncommitted transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var products = try querymod.Table.open(&db, allocator, "products");
        defer products.deinit();
        try products.createUniqueIndex("sku");

        var lineItems = try querymod.Table.open(&db, allocator, "line_items");
        defer lineItems.deinit();
        try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();

    // Stage a brand-new product in the same transaction as the line item
    // that references it. `foreignKeyTargetExists`'s non-pk branch now
    // goes through `Transaction.scanPrefix`, which sees the product's
    // staged index-entry write even though neither row is committed yet -
    // same read-your-writes guarantee the pkField branch above already had.
    var products = try TableTxn.open(&txn, allocator, "products");
    defer products.deinit();
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    var lineItems = try TableTxn.open(&txn, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.put(.{ .int = 1 }, &.{
        .{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } },
    });

    // A dangling reference in the same transaction is still rejected.
    try std.testing.expectError(error.ForeignKeyViolation, lineItems.put(.{ .int = 2 }, &.{
        .{ .name = "product_sku", .value = .{ .text = "NO-SUCH-SKU" } },
    }));

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "line_items");
    defer plain.deinit();
    var row = (try plain.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("WIDGET-1", row.get("product_sku").?.text);
}

test "TableTxn put UNIQUE constraint catches a conflict staged earlier in the same uncommitted transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "users");
        defer setup.deinit();
        try setup.createUniqueIndex("email");
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "users");
    defer t.deinit();

    // First row claims the email; nothing committed yet.
    try t.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@example.com" } }});

    // A second, different row in the SAME still-open transaction tries to
    // claim the same email. Before `Transaction.scanPrefix`, the UNIQUE
    // check ran `idx.scanEq` straight against `Db` and never saw the first
    // row's staged index entry, so this put would have wrongly succeeded
    // and only failed later as a generic OCC conflict at commit (or not at
    // all, since the two rows touch disjoint keys and would not conflict).
    try std.testing.expectError(error.UniqueViolation, t.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@example.com" } },
    }));

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "users");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 2 })) == null);
    var row1 = (try plain.get(.{ .int = 1 })).?;
    defer row1.deinit();
    try std.testing.expectEqualStrings("a@example.com", row1.get("email").?.text);
}

test "TableTxn put enforces a CHECK constraint installed through query.zig's Table" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "orders");
        defer setup.deinit();
        try setup.createCheckConstraint("qty_positive", "qty gt i:0");
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "orders");
    defer t.deinit();
    try std.testing.expect(t.hasCheckConstraint("qty_positive"));

    try t.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = 5 } }});
    try std.testing.expectError(error.CheckViolation, t.put(.{ .int = 2 }, &.{
        .{ .name = "qty", .value = .{ .int = 0 } },
    }));

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "orders");
    defer plain.deinit();
    var row1 = (try plain.get(.{ .int = 1 })).?;
    defer row1.deinit();
    try std.testing.expect((try plain.get(.{ .int = 2 })) == null);
}

test "TableTxn `txn <script>` shape: a CHECK violation on the second put leaves the whole transaction uncommitted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var setup = try querymod.Table.open(&db, allocator, "orders");
        defer setup.deinit();
        try setup.createCheckConstraint("qty_positive", "qty gt i:0");
    }

