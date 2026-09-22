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

pub const pkField = querymod.pkField;

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

    pub fn get(self: *TableTxn, pk: Value) !?Row {
        const key = try idx.rowKey(self.allocator, self.name, pk);
        defer self.allocator.free(key);
        const raw = try self.txn.get(self.allocator, key) orelse return null;
        defer self.allocator.free(raw);
        return try Row.decode(self.allocator, raw);
    }

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

        for (self.checks.specs.items) |spec| {
            var parsed = exprmod.parse(self.allocator, spec.source) catch return error.InvalidCheckExpression;
            defer parsed.deinit();
            if (!parsed.predicate.evaluate(&newRow)) return error.CheckViolation;
        }

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

    var from = (try t.get(.{ .int = 1 })).?;
    defer from.deinit();
    var to = (try t.get(.{ .int = 2 })).?;
    defer to.deinit();
    try t.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = from.get("balance").?.int - 30 } }});
    try t.put(.{ .int = 2 }, &.{.{ .name = "balance", .value = .{ .int = to.get("balance").?.int + 30 } }});

    {
        var external = try querymod.Table.open(&db, allocator, "accounts");
        defer external.deinit();
        try external.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = 999 } }});
    }

    try std.testing.expectError(error.Conflict, txn.commit());

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

    try t.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
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
        var employees = try querymod.Table.open(&db, allocator, "employees");
        defer employees.deinit();
        try employees.createForeignKey("manager_id", "employees", pkField, .restrict);
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "employees");
    defer t.deinit();

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

    var products = try TableTxn.open(&txn, allocator, "products");
    defer products.deinit();
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    var lineItems = try TableTxn.open(&txn, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.put(.{ .int = 1 }, &.{
        .{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } },
    });

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

    try t.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@example.com" } }});

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

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "orders");
    defer t.deinit();

    try t.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = 5 } }});
    try std.testing.expectError(error.CheckViolation, t.put(.{ .int = 2 }, &.{
        .{ .name = "qty", .value = .{ .int = -5 } },
    }));

    var plain = try querymod.Table.open(&db, allocator, "orders");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 1 })) == null);
}

test "TableTxn delete enforces ON DELETE RESTRICT against a committed child row" {
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
        try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "customers");
    defer t.deinit();

    try std.testing.expectError(error.ForeignKeyInUse, t.delete(.{ .int = 1 }));
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "customers");
    defer plain.deinit();
    var stillThere = (try plain.get(.{ .int = 1 })).?;
    stillThere.deinit();
}

test "TableTxn delete RESTRICT sees a child row staged earlier in the same uncommitted transaction" {
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

    var ordersTxn = try TableTxn.open(&txn, allocator, "orders");
    defer ordersTxn.deinit();
    try ordersTxn.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    var customersTxn = try TableTxn.open(&txn, allocator, "customers");
    defer customersTxn.deinit();
    try std.testing.expectError(error.ForeignKeyInUse, customersTxn.delete(.{ .int = 1 }));
}

test "TableTxn delete RESTRICT does not block deleting a parent once its only child is deleted in the same transaction" {
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
        try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();

    var ordersTxn = try TableTxn.open(&txn, allocator, "orders");
    defer ordersTxn.deinit();
    try ordersTxn.delete(.{ .int = 100 });

    var customersTxn = try TableTxn.open(&txn, allocator, "customers");
    defer customersTxn.deinit();
    try customersTxn.delete(.{ .int = 1 });

    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "customers");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 1 })) == null);
}

test "TableTxn delete RESTRICT excludes the row being deleted from its own self-referencing check" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var employees = try querymod.Table.open(&db, allocator, "employees");
        defer employees.deinit();
        try employees.put(.{ .int = 1 }, &.{});
        try employees.createForeignKey("manager_id", "employees", pkField, .restrict);
        try employees.put(.{ .int = 2 }, &.{.{ .name = "manager_id", .value = .{ .int = 1 } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "employees");
    defer t.deinit();

    try std.testing.expectError(error.ForeignKeyInUse, t.delete(.{ .int = 1 }));
    try t.delete(.{ .int = 2 });
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "employees");
    defer plain.deinit();
    try std.testing.expect((try plain.get(.{ .int = 2 })) == null);
}

test "TableTxn put is restricted from changing a UNIQUE foreign key target a committed child still references" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var products = try querymod.Table.open(&db, allocator, "products");
        defer products.deinit();
        try products.createUniqueIndex("sku");
        try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

        var lineItems = try querymod.Table.open(&db, allocator, "line_items");
        defer lineItems.deinit();
        try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
        try lineItems.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } }});
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    var t = try TableTxn.open(&txn, allocator, "products");
    defer t.deinit();

    try std.testing.expectError(error.ForeignKeyInUse, t.put(.{ .int = 1 }, &.{
        .{ .name = "sku", .value = .{ .text = "WIDGET-2" } },
    }));
    try t.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "products");
    defer plain.deinit();
    var stillThere = (try plain.get(.{ .int = 1 })).?;
    defer stillThere.deinit();
    try std.testing.expectEqualStrings("WIDGET-1", stillThere.get("sku").?.text);
}

test "TableTxn put update-restrict sees a child row staged earlier in the same uncommitted transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var products = try querymod.Table.open(&db, allocator, "products");
        defer products.deinit();
        try products.createUniqueIndex("sku");
        try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

        var lineItems = try querymod.Table.open(&db, allocator, "line_items");
        defer lineItems.deinit();
        try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
    }

    var txn = Transaction.begin(&db);
    defer txn.deinit();

    var lineItemsTxn = try TableTxn.open(&txn, allocator, "line_items");
    defer lineItemsTxn.deinit();
    try lineItemsTxn.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } }});

    var productsTxn = try TableTxn.open(&txn, allocator, "products");
    defer productsTxn.deinit();
    try std.testing.expectError(error.ForeignKeyInUse, productsTxn.put(.{ .int = 1 }, &.{
        .{ .name = "sku", .value = .{ .text = "WIDGET-2" } },
    }));

    try lineItemsTxn.delete(.{ .int = 1 });
    try productsTxn.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-2" } }});
    try txn.commit();

    var plain = try querymod.Table.open(&db, allocator, "products");
    defer plain.deinit();
    var renamed = (try plain.get(.{ .int = 1 })).?;
    defer renamed.deinit();
    try std.testing.expectEqualStrings("WIDGET-2", renamed.get("sku").?.text);
}
