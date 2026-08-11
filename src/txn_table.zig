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

