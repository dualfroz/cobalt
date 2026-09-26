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

pub const pkField = "__pk";

pub const Condition = struct {
    field: []const u8,
    value: Value,
};

pub const Page = struct {
    offset: usize = 0,
    limit: usize = 0,
};

pub const OrderBy = struct {
    field: []const u8,
    descending: bool = false,
};

pub const PlanKind = enum(u8) {
    full_scan,
    index_eq,
    index_range,
    composite_eq,
    composite_range,
};

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

pub const Predicate = union(enum) {
    eq: Condition,
    ne: Condition,
    lt: Condition,
    lte: Condition,
    gt: Condition,
    gte: Condition,
    like: Condition,
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

        var revSet = try ReferencedBySet.load(self.allocator, self.db, refTable);
        defer revSet.deinit();
        try revSet.add(self.name, field, refField, onDelete);
        try revSet.save(self.db, refTable);
    }

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

        for (self.checks.specs.items) |spec| {
            var parsed = exprmod.parse(self.allocator, spec.source) catch return error.InvalidCheckExpression;
            defer parsed.deinit();
            if (!parsed.predicate.evaluate(&newRow)) return error.CheckViolation;
        }

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

    const CascadeAction = struct {
        table: []u8,
        pk: Value,

        fn deinit(self: *const CascadeAction, allocator: Allocator) void {
            allocator.free(self.table);
            self.pk.free(allocator);
        }
    };

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

    pub fn deleteWhere(self: *Table, pred: ?Predicate) !usize {
        const matches = try self.selectAllMatches(pred);
        defer freeRows(self.allocator, matches);

        for (matches) |*row| {
            const pk = row.get(pkField) orelse continue;
            try self.delete(pk);
        }
        return matches.len;
    }

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

    pub fn select(self: *Table, pred: ?Predicate) ![]Row {
        return self.selectPage(pred, .{});
    }

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

    pub fn selectPageOrdered(self: *Table, pred: ?Predicate, page: Page, orderBy: []const OrderBy) ![]Row {
        if (orderBy.len == 0) return self.selectPage(pred, page);
        const all = try self.selectAllMatches(pred);
        errdefer freeRows(self.allocator, all);
        sortRowsBy(all, orderBy);
        return applyRowPage(self.allocator, all, page);
    }

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
        rangeLow: ?idx.Bound = null,
        rangeHigh: ?idx.Bound = null,
    };

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
    try table.createIndex("name");

    try table.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada Lovelace" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "Alan Turing" } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "name", .value = .{ .text = "Grace Hopper" } }});

    {
        const results = try table.select(.{ .like = .{ .field = "name", .value = .{ .text = "A%" } } });
        defer freeRows(allocator, results);
        try std.testing.expectEqual(@as(usize, 2), results.len);
    }
    {
        const results = try table.select(.{ .like = .{ .field = "name", .value = .{ .text = "%ing" } } });
        defer freeRows(allocator, results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqualStrings("Alan Turing", results[0].get("name").?.text);
    }
    {
        const results = try table.select(.{ .like = .{ .field = "name", .value = .{ .text = "%z%" } } });
        defer freeRows(allocator, results);
        try std.testing.expectEqual(@as(usize, 0), results.len);
    }

    var plan = try table.explain(allocator, .{ .like = .{ .field = "name", .value = .{ .text = "A%" } } });
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.full_scan, plan.kind);
}

test "like combines with an indexed eq leaf inside and_ without breaking the index plan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");

    try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "name", .value = .{ .text = "Ada" } } });
    try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "name", .value = .{ .text = "Boris" } } });
    try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "name", .value = .{ .text = "Ada" } } });

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .like = .{ .field = "name", .value = .{ .text = "A%" } } },
    };
    const pred = Predicate{ .and_ = &preds };

    var plan = try table.explain(allocator, pred);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, plan.kind);
    try std.testing.expectEqualStrings("city", plan.indexName.?);

    const results = try table.select(pred);
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(i64, 1), results[0].get(pkField).?.int);
}

test "index stays in sync across update and delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");

    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    {
        const warsaw = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
        defer freeRows(allocator, warsaw);
        try std.testing.expectEqual(@as(usize, 1), warsaw.len);
    }

    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});
    {
        const warsaw = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
        defer freeRows(allocator, warsaw);
        try std.testing.expectEqual(@as(usize, 0), warsaw.len);
        const krakow = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } });
        defer freeRows(allocator, krakow);
        try std.testing.expectEqual(@as(usize, 1), krakow.len);
    }

    try table.delete(.{ .int = 1 });
    {
        const krakow = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } });
        defer freeRows(allocator, krakow);
        try std.testing.expectEqual(@as(usize, 0), krakow.len);
    }
}

test "dropIndex removes entries and falls back to full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    try table.dropIndex("city");
    try std.testing.expect(!table.hasIndex("city"));

    const results = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
}

test "range predicate uses index and respects bounds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "events");
    defer table.deinit();
    try table.createIndex("score");

    var i: i64 = 0;
    while (i < 10) : (i += 1) {
        try table.put(.{ .int = i }, &.{.{ .name = "score", .value = .{ .int = i } }});
    }

    const results = try table.select(.{ .gte = .{ .field = "score", .value = .{ .int = 7 } } });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 3), results.len);
}

test "compound and predicate narrows via one indexed conjunct" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 20 } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 40 } },
    });

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .gte = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const results = try table.select(.{ .and_ = &preds });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(i64, 2), results[0].get(pkField).?.int);
}

test "not and or predicates evaluate via full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{.{ .name = "age", .value = .{ .int = 10 } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "age", .value = .{ .int = 20 } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "age", .value = .{ .int = 30 } }});

    const orPreds = [_]Predicate{
        .{ .eq = .{ .field = "age", .value = .{ .int = 10 } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const orResults = try table.select(.{ .or_ = &orPreds });
    defer freeRows(allocator, orResults);
    try std.testing.expectEqual(@as(usize, 2), orResults.len);

    const inner = Predicate{ .eq = .{ .field = "age", .value = .{ .int = 20 } } };
    const notResult = try table.select(.{ .not_ = &inner });
    defer freeRows(allocator, notResult);
    try std.testing.expectEqual(@as(usize, 2), notResult.len);
}

test "is_null/is_not_null evaluate against missing fields, explicit none, and present values" {
    const allocator = std.testing.allocator;
    var sparse = Row.init(allocator);
    defer sparse.deinit();
    try sparse.set("age", .{ .int = 10 });

    var withNone = Row.init(allocator);
    defer withNone.deinit();
    try withNone.set("city", .{ .none = {} });

    var withCity = Row.init(allocator);
    defer withCity.deinit();
    try withCity.set("city", .{ .text = "warsaw" });

    const isNull = Predicate{ .is_null = "city" };
    const isNotNull = Predicate{ .is_not_null = "city" };

    try std.testing.expect(isNull.evaluate(&sparse));
    try std.testing.expect(!isNotNull.evaluate(&sparse));
    try std.testing.expect(isNull.evaluate(&withNone));
    try std.testing.expect(!isNotNull.evaluate(&withNone));
    try std.testing.expect(!isNull.evaluate(&withCity));
    try std.testing.expect(isNotNull.evaluate(&withCity));
}

test "is_null selects only sparse rows missing the field, over a full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "people");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "age", .value = .{ .int = 40 } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "age", .value = .{ .int = 50 } }});

    var plan = try table.explain(allocator, .{ .is_null = "city" });
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.full_scan, plan.kind);

    const missing = try table.select(.{ .is_null = "city" });
    defer freeRows(allocator, missing);
    try std.testing.expectEqual(@as(usize, 2), missing.len);

    const present = try table.select(.{ .is_not_null = "city" });
    defer freeRows(allocator, present);
    try std.testing.expectEqual(@as(usize, 1), present.len);

    try table.createIndex("age");
    const stillMissing = try table.select(.{ .is_null = "city" });
    defer freeRows(allocator, stillMissing);
    try std.testing.expectEqual(@as(usize, 2), stillMissing.len);
}

test "invalid identifiers are rejected" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try std.testing.expectError(error.InvalidIdentifier, Table.open(&db, allocator, ""));

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try std.testing.expectError(error.InvalidIdentifier, table.createIndex("bad\x00field"));
}

test "selectPage skips offset and stops at limit on a full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    var pk: i64 = 10;
    while (pk >= 1) : (pk -= 1) {
        try table.put(.{ .int = pk }, &.{});
    }

    const page = try table.selectPage(null, .{ .offset = 3, .limit = 4 });
    defer freeRows(allocator, page);
    try std.testing.expectEqual(@as(usize, 4), page.len);
    var expected: i64 = 4;
    for (page) |r| {
        try std.testing.expectEqual(expected, r.get(pkField).?.int);
        expected += 1;
    }
}

test "selectPage with limit 0 matches unlimited select" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    var pk: i64 = 1;
    while (pk <= 5) : (pk += 1) try table.put(.{ .int = pk }, &.{});

    const all = try table.select(null);
    defer freeRows(allocator, all);
    const page = try table.selectPage(null, .{});
    defer freeRows(allocator, page);
    try std.testing.expectEqual(all.len, page.len);
}

test "selectPage offset past the end returns nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{});
    try table.put(.{ .int = 2 }, &.{});

    const page = try table.selectPage(null, .{ .offset = 50 });
    defer freeRows(allocator, page);
    try std.testing.expectEqual(@as(usize, 0), page.len);
}

test "selectPage paginates through an index-narrowed predicate in pk order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");

    var pk: i64 = 1;
    while (pk <= 6) : (pk += 1) {
        try table.put(.{ .int = pk }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }
    try table.put(.{ .int = 99 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});

    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };

    const first = try table.selectPage(pred, .{ .limit = 2 });
    defer freeRows(allocator, first);
    try std.testing.expectEqual(@as(usize, 2), first.len);
    try std.testing.expectEqual(@as(i64, 1), first[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 2), first[1].get(pkField).?.int);

    const second = try table.selectPage(pred, .{ .offset = 2, .limit = 2 });
    defer freeRows(allocator, second);
    try std.testing.expectEqual(@as(usize, 2), second.len);
    try std.testing.expectEqual(@as(i64, 3), second[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 4), second[1].get(pkField).?.int);

    const rest = try table.selectPage(pred, .{ .offset = 4 });
    defer freeRows(allocator, rest);
    try std.testing.expectEqual(@as(usize, 2), rest.len);
    try std.testing.expectEqual(@as(i64, 5), rest[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 6), rest[1].get(pkField).?.int);
}

test "selectPage against a large indexed bucket stays correct with a small limit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");

    var pk: i64 = 0;
    while (pk < 500) : (pk += 1) {
        try table.put(.{ .int = pk }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }

    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };

    const page = try table.selectPage(pred, .{ .offset = 497, .limit = 10 });
    defer freeRows(allocator, page);
    try std.testing.expectEqual(@as(usize, 3), page.len);
    try std.testing.expectEqual(@as(i64, 497), page[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 498), page[1].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 499), page[2].get(pkField).?.int);
}

test "selectPageOrdered sorts a full scan ascending and descending by an int field" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    const scores = [_]i64{ 30, 10, 50, 20, 40 };
    for (scores, 1..) |score, pk| {
        try table.put(.{ .int = @intCast(pk) }, &.{.{ .name = "score", .value = .{ .int = score } }});
    }

    const asc = try table.selectPageOrdered(null, .{}, &.{.{ .field = "score" }});
    defer freeRows(allocator, asc);
    var expected = [_]i64{ 10, 20, 30, 40, 50 };
    try std.testing.expectEqual(expected.len, asc.len);
    for (asc, 0..) |r, i| try std.testing.expectEqual(expected[i], r.get("score").?.int);

    const desc = try table.selectPageOrdered(null, .{}, &.{.{ .field = "score", .descending = true }});
    defer freeRows(allocator, desc);
    std.mem.reverse(i64, &expected);
    for (desc, 0..) |r, i| try std.testing.expectEqual(expected[i], r.get("score").?.int);
}

test "selectPageOrdered applies offset/limit after sorting, not before" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    var pk: i64 = 1;
    while (pk <= 10) : (pk += 1) {
        try table.put(.{ .int = pk }, &.{.{ .name = "score", .value = .{ .int = 100 - pk } }});
    }

    const top3 = try table.selectPageOrdered(null, .{ .limit = 3 }, &.{.{ .field = "score", .descending = true }});
    defer freeRows(allocator, top3);
    try std.testing.expectEqual(@as(usize, 3), top3.len);
    try std.testing.expectEqual(@as(i64, 1), top3[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 2), top3[1].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 3), top3[2].get(pkField).?.int);

    const nextPage = try table.selectPageOrdered(null, .{ .offset = 3, .limit = 3 }, &.{.{ .field = "score", .descending = true }});
    defer freeRows(allocator, nextPage);
    try std.testing.expectEqual(@as(i64, 4), nextPage[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 6), nextPage[2].get(pkField).?.int);
}

test "selectPageOrdered sorts text fields lexically and is stable on ties" {
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

    const rows = try table.selectPageOrdered(null, .{}, &.{.{ .field = "city" }});
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 3), rows.len);
    try std.testing.expectEqualStrings("krakow", rows[0].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(pkField).?.int);
    try std.testing.expectEqualStrings("warsaw", rows[1].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 1), rows[1].get(pkField).?.int);
    try std.testing.expectEqualStrings("warsaw", rows[2].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 3), rows[2].get(pkField).?.int);
}

test "selectPageOrdered groups rows missing the sort field at the front" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "score", .value = .{ .int = 5 } }});
    try table.put(.{ .int = 2 }, &.{});
    try table.put(.{ .int = 3 }, &.{.{ .name = "score", .value = .{ .int = 1 } }});

    const rows = try table.selectPageOrdered(null, .{}, &.{.{ .field = "score" }});
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 3), rows[1].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 1), rows[2].get(pkField).?.int);
}

test "selectPageOrdered on an indexed predicate still uses the index, not a full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");
    var pk: i64 = 1;
    while (pk <= 20) : (pk += 1) {
        const city: []const u8 = if (@mod(pk, 2) == 0) "warsaw" else "krakow";
        try table.put(.{ .int = pk }, &.{
            .{ .name = "city", .value = .{ .text = city } },
            .{ .name = "score", .value = .{ .int = 100 - pk } },
        });
    }
    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };

    var plan = try table.explain(allocator, pred);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, plan.kind);

    const rows = try table.selectPageOrdered(pred, .{}, &.{.{ .field = "score" }});
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 10), rows.len);
    var lastScore: i64 = std.math.minInt(i64);
    for (rows) |r| {
        const s = r.get("score").?.int;
        try std.testing.expect(s >= lastScore);
        lastScore = s;
        try std.testing.expectEqualStrings("warsaw", r.get("city").?.text);
    }
}

test "selectPageOrdered with two columns sorts by the first, breaking ties with the second" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "people");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 30 } } });
    try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "score", .value = .{ .int = 20 } } });
    try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 10 } } });
    try table.put(.{ .int = 4 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "score", .value = .{ .int = 40 } } });

    const rows = try table.selectPageOrdered(null, .{}, &.{ .{ .field = "city" }, .{ .field = "score" } });
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 4), rows.len);
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 4), rows[1].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 3), rows[2].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 1), rows[3].get(pkField).?.int);
}

test "selectPageOrdered with two columns honors independent directions per column" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "people");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 10 } } });
    try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 20 } } });
    try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "score", .value = .{ .int = 5 } } });

    const rows = try table.selectPageOrdered(null, .{}, &.{ .{ .field = "city" }, .{ .field = "score", .descending = true } });
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(i64, 3), rows[0].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 2), rows[1].get(pkField).?.int);
    try std.testing.expectEqual(@as(i64, 1), rows[2].get(pkField).?.int);
}

test "selectPageOrdered with an empty order-by falls through to selectPage's early-stop behavior" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "people");
    defer table.deinit();
    var pk: i64 = 1;
    while (pk <= 5) : (pk += 1) {
        try table.put(.{ .int = pk }, &.{});
    }

    const ordered = try table.selectPageOrdered(null, .{ .limit = 2 }, &.{});
    defer freeRows(allocator, ordered);
    const plain = try table.selectPage(null, .{ .limit = 2 });
    defer freeRows(allocator, plain);
    try std.testing.expectEqual(plain.len, ordered.len);
    for (ordered, plain) |o, p| try std.testing.expectEqual(o.get(pkField).?.int, p.get(pkField).?.int);
}

test "createCompositeIndex backfills then full-tuple eq select uses it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 40 } },
    });
    try table.put(.{ .int = 3 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });

    try table.createCompositeIndex("city_age", &.{ "city", "age" });
    try std.testing.expect(table.hasCompositeIndex("city_age"));

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const results = try table.select(.{ .and_ = &preds });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(i64, 1), results[0].get(pkField).?.int);
}

test "composite index leftmost prefix narrows without constraining every column" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 40 } },
    });
    try table.put(.{ .int = 3 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "age", .value = .{ .int = 50 } },
    });

    const results = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 2), results.len);
}

test "composite index uses a range bound on the column after the matched prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });

    var age: i64 = 20;
    while (age < 30) : (age += 1) {
        try table.put(.{ .int = age }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "age", .value = .{ .int = age } },
        });
        try table.put(.{ .int = age + 100 }, &.{
            .{ .name = "city", .value = .{ .text = "krakow" } },
            .{ .name = "age", .value = .{ .int = age } },
        });
    }

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .gte = .{ .field = "age", .value = .{ .int = 23 } } },
        .{ .lt = .{ .field = "age", .value = .{ .int = 27 } } },
    };
    const results = try table.select(.{ .and_ = &preds });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 4), results.len);
    for (results) |r| {
        try std.testing.expectEqualStrings("warsaw", r.get("city").?.text);
        try std.testing.expect(r.get("age").?.int >= 23 and r.get("age").?.int < 27);
    }

    const openPreds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .gt = .{ .field = "age", .value = .{ .int = 27 } } },
    };
    const openResults = try table.select(.{ .and_ = &openPreds });
    defer freeRows(allocator, openResults);
    try std.testing.expectEqual(@as(usize, 2), openResults.len);
    for (openResults) |r| {
        try std.testing.expectEqualStrings("warsaw", r.get("city").?.text);
        try std.testing.expect(r.get("age").?.int > 27);
    }
}

test "composite index stays in sync across update and delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const pred = Predicate{ .and_ = &preds };

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    {
        const found = try table.select(pred);
        defer freeRows(allocator, found);
        try std.testing.expectEqual(@as(usize, 1), found.len);
    }

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 31 } },
    });
    {
        const stale = try table.select(pred);
        defer freeRows(allocator, stale);
        try std.testing.expectEqual(@as(usize, 0), stale.len);
    }

    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    {
        const wholeTable = try table.select(null);
        defer freeRows(allocator, wholeTable);
        try std.testing.expectEqual(@as(usize, 2), wholeTable.len);

        const ageless = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 31 } } },
        };
        const noMatch = try table.select(.{ .and_ = &ageless });
        defer freeRows(allocator, noMatch);
        try std.testing.expectEqual(@as(usize, 1), noMatch.len);
        try std.testing.expectEqual(@as(i64, 1), noMatch[0].get(pkField).?.int);
    }

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    try table.delete(.{ .int = 1 });
    {
        const afterDelete = try table.select(pred);
        defer freeRows(allocator, afterDelete);
        try std.testing.expectEqual(@as(usize, 0), afterDelete.len);
    }
}

test "dropCompositeIndex removes entries and falls back to full scan" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });
    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });

    try table.dropCompositeIndex("city_age");
    try std.testing.expect(!table.hasCompositeIndex("city_age"));

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const results = try table.select(.{ .and_ = &preds });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
}

test "createCompositeIndex rejects bad field counts and identifiers" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();

    try std.testing.expectError(error.InvalidCompositeIndex, table.createCompositeIndex("solo", &.{"city"}));
    try std.testing.expectError(error.InvalidIdentifier, table.createCompositeIndex("bad\x00name", &.{ "city", "age" }));
    try std.testing.expectError(error.InvalidIdentifier, table.createCompositeIndex("ok", &.{ "city", "bad\x00field" }));
}

test "composite index survives a table reopen (persisted across process restart)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var table = try Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createCompositeIndex("city_age", &.{ "city", "age" });
        try table.put(.{ .int = 1 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "age", .value = .{ .int = 30 } },
        });
    }

    var reopened = try Table.open(&db, allocator, "users");
    defer reopened.deinit();
    try std.testing.expect(reopened.hasCompositeIndex("city_age"));

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const results = try reopened.select(.{ .and_ = &preds });
    defer freeRows(allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
}

test "explain reports full_scan for a null predicate and an unindexed field" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    var noPred = try table.explain(allocator, null);
    defer noPred.deinit(allocator);
    try std.testing.expectEqual(PlanKind.full_scan, noPred.kind);
    try std.testing.expect(noPred.indexName == null);

    var unindexed = try table.explain(allocator, .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer unindexed.deinit(allocator);
    try std.testing.expectEqual(PlanKind.full_scan, unindexed.kind);
}

test "explain reports index_eq and index_range for a single-field index" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "events");
    defer table.deinit();
    try table.createIndex("score");
    try table.put(.{ .int = 1 }, &.{.{ .name = "score", .value = .{ .int = 5 } }});

    var eqPlan = try table.explain(allocator, .{ .eq = .{ .field = "score", .value = .{ .int = 5 } } });
    defer eqPlan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, eqPlan.kind);
    try std.testing.expectEqualStrings("score", eqPlan.indexName.?);
    try std.testing.expectEqual(@as(usize, 1), eqPlan.matchedFields);
    try std.testing.expectEqual(@as(usize, 1), eqPlan.totalFields);

    var rangePlan = try table.explain(allocator, .{ .gte = .{ .field = "score", .value = .{ .int = 5 } } });
    defer rangePlan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_range, rangePlan.kind);
    try std.testing.expectEqualStrings("score", rangePlan.indexName.?);
}

test "explain reports composite_eq and composite_range with matched/total field counts" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });
    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });

    const prefixPreds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
    };
    var prefixOnly = try table.explain(allocator, .{ .and_ = &prefixPreds });
    defer prefixOnly.deinit(allocator);
    try std.testing.expectEqual(PlanKind.composite_eq, prefixOnly.kind);
    try std.testing.expectEqualStrings("city_age", prefixOnly.indexName.?);
    try std.testing.expectEqual(@as(usize, 1), prefixOnly.matchedFields);
    try std.testing.expectEqual(@as(usize, 2), prefixOnly.totalFields);

    const eqPreds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    var fullEq = try table.explain(allocator, .{ .and_ = &eqPreds });
    defer fullEq.deinit(allocator);
    try std.testing.expectEqual(PlanKind.composite_eq, fullEq.kind);
    try std.testing.expectEqual(@as(usize, 2), fullEq.matchedFields);

    const rangePreds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .gte = .{ .field = "age", .value = .{ .int = 18 } } },
    };
    var rangeMatch = try table.explain(allocator, .{ .and_ = &rangePreds });
    defer rangeMatch.deinit(allocator);
    try std.testing.expectEqual(PlanKind.composite_range, rangeMatch.kind);
    try std.testing.expectEqualStrings("city_age", rangeMatch.indexName.?);
    try std.testing.expectEqual(@as(usize, 1), rangeMatch.matchedFields);
}

test "explain never mutates the table (const receiver, no rows touched)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };
    const constTable: *const Table = &table;
    var plan = try constTable.explain(allocator, pred);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, plan.kind);

    const rows = try table.select(pred);
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
}

test "updateWhere applies a set clause to every matching row and reports the count" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "active", .value = .{ .int = 0 } } });
    try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "active", .value = .{ .int = 0 } } });
    try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "active", .value = .{ .int = 0 } } });

    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };
    const updated = try table.updateWhere(pred, &.{.{ .name = "active", .value = .{ .int = 1 } }});
    try std.testing.expectEqual(@as(usize, 2), updated);

    var row1 = (try table.get(.{ .int = 1 })).?;
    defer row1.deinit();
    try std.testing.expectEqual(Value{ .int = 1 }, row1.get("active").?);
    try std.testing.expectEqualStrings("warsaw", row1.get("city").?.text);

    var row3 = (try table.get(.{ .int = 3 })).?;
    defer row3.deinit();
    try std.testing.expectEqual(Value{ .int = 0 }, row3.get("active").?);
}

test "updateWhere with a null predicate touches every row" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "counters");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "n", .value = .{ .int = 5 } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "n", .value = .{ .int = 7 } }});

    const updated = try table.updateWhere(null, &.{.{ .name = "flag", .value = .{ .text = "seen" } }});
    try std.testing.expectEqual(@as(usize, 2), updated);

    var row1 = (try table.get(.{ .int = 1 })).?;
    defer row1.deinit();
    try std.testing.expectEqualStrings("seen", row1.get("flag").?.text);
    try std.testing.expectEqual(Value{ .int = 5 }, row1.get("n").?);
}

test "updateWhere adds a brand new field a matched row never had" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    _ = try table.updateWhere(null, &.{.{ .name = "tier", .value = .{ .text = "gold" } }});

    var row = (try table.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("gold", row.get("tier").?.text);
    try std.testing.expectEqualStrings("warsaw", row.get("city").?.text);
}

test "updateWhere keeps a secondary index in sync when the indexed field changes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    const updated = try table.updateWhere(
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        &.{.{ .name = "city", .value = .{ .text = "krakow" } }},
    );
    try std.testing.expectEqual(@as(usize, 1), updated);

    const stale = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);

    const fresh = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } });
    defer freeRows(allocator, fresh);
    try std.testing.expectEqual(@as(usize, 1), fresh.len);

    const constTable: *const Table = &table;
    var plan = try constTable.explain(allocator, .{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } });
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, plan.kind);
}

test "updateWhere keeps a composite index in sync across leading and trailing column moves" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
        .{ .name = "name", .value = .{ .text = "alice" } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 31 } },
        .{ .name = "name", .value = .{ .text = "bob" } },
    });
    try table.put(.{ .int = 3 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "age", .value = .{ .int = 30 } },
        .{ .name = "name", .value = .{ .text = "carol" } },
    });
    try table.put(.{ .int = 4 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "age", .value = .{ .int = 40 } },
        .{ .name = "name", .value = .{ .text = "dave" } },
    });

    {
        const preds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
        };
        const updated = try table.updateWhere(
            .{ .and_ = &preds },
            &.{.{ .name = "age", .value = .{ .int = 45 } }},
        );
        try std.testing.expectEqual(@as(usize, 1), updated);
    }
    {
        const stalePreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
        };
        const stale = try table.select(.{ .and_ = &stalePreds });
        defer freeRows(allocator, stale);
        try std.testing.expectEqual(@as(usize, 0), stale.len);

        const freshPreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 45 } } },
        };
        const fresh = try table.select(.{ .and_ = &freshPreds });
        defer freeRows(allocator, fresh);
        try std.testing.expectEqual(@as(usize, 1), fresh.len);
        try std.testing.expectEqual(@as(i64, 1), fresh[0].get(pkField).?.int);

        const constTable: *const Table = &table;
        var plan = try constTable.explain(allocator, .{ .and_ = &freshPreds });
        defer plan.deinit(allocator);
        try std.testing.expectEqual(PlanKind.composite_eq, plan.kind);
        try std.testing.expectEqualStrings("city_age", plan.indexName.?);
        try std.testing.expectEqual(@as(usize, 2), plan.matchedFields);
    }

    {
        const preds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 31 } } },
        };
        const updated = try table.updateWhere(
            .{ .and_ = &preds },
            &.{.{ .name = "city", .value = .{ .text = "gdansk" } }},
        );
        try std.testing.expectEqual(@as(usize, 1), updated);
    }
    {
        const stalePreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 31 } } },
        };
        const stale = try table.select(.{ .and_ = &stalePreds });
        defer freeRows(allocator, stale);
        try std.testing.expectEqual(@as(usize, 0), stale.len);

        const freshPreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "gdansk" } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = 31 } } },
        };
        const fresh = try table.select(.{ .and_ = &freshPreds });
        defer freeRows(allocator, fresh);
        try std.testing.expectEqual(@as(usize, 1), fresh.len);
        try std.testing.expectEqual(@as(i64, 2), fresh[0].get(pkField).?.int);
    }

    {
        const rangePreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = "krakow" } } },
            .{ .gte = .{ .field = "age", .value = .{ .int = 30 } } },
        };
        const constTable: *const Table = &table;
        var rangePlan = try constTable.explain(allocator, .{ .and_ = &rangePreds });
        defer rangePlan.deinit(allocator);
        try std.testing.expectEqual(PlanKind.composite_range, rangePlan.kind);
        try std.testing.expectEqualStrings("city_age", rangePlan.indexName.?);

        const updated = try table.updateWhere(
            .{ .and_ = &rangePreds },
            &.{.{ .name = "name", .value = .{ .text = "updated" } }},
        );
        try std.testing.expectEqual(@as(usize, 2), updated);
    }

    const expectations = [_]struct { pk: i64, city: []const u8, age: i64, name: []const u8 }{
        .{ .pk = 1, .city = "warsaw", .age = 45, .name = "alice" },
        .{ .pk = 2, .city = "gdansk", .age = 31, .name = "bob" },
        .{ .pk = 3, .city = "krakow", .age = 30, .name = "updated" },
        .{ .pk = 4, .city = "krakow", .age = 40, .name = "updated" },
    };
    for (expectations) |exp| {
        const preds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = exp.city } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = exp.age } } },
        };
        const rows = try table.select(.{ .and_ = &preds });
        defer freeRows(allocator, rows);
        try std.testing.expectEqual(@as(usize, 1), rows.len);
        try std.testing.expectEqual(exp.pk, rows[0].get(pkField).?.int);
        try std.testing.expectEqualStrings(exp.name, rows[0].get("name").?.text);
    }

    const everyone = try table.select(null);
    defer freeRows(allocator, everyone);
    try std.testing.expectEqual(@as(usize, 4), everyone.len);
}

test "deleteWhere removes every matching row and reports the count" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    try table.put(.{ .int = 3 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});

    const pred = Predicate{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } };
    const deleted = try table.deleteWhere(pred);
    try std.testing.expectEqual(@as(usize, 2), deleted);

    try std.testing.expectEqual(@as(?Row, null), try table.get(.{ .int = 1 }));
    try std.testing.expectEqual(@as(?Row, null), try table.get(.{ .int = 2 }));

    var row3 = (try table.get(.{ .int = 3 })).?;
    defer row3.deinit();
    try std.testing.expectEqualStrings("krakow", row3.get("city").?.text);
}

test "deleteWhere with a null predicate empties the table" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "counters");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "n", .value = .{ .int = 5 } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "n", .value = .{ .int = 7 } }});

    const deleted = try table.deleteWhere(null);
    try std.testing.expectEqual(@as(usize, 2), deleted);

    const everyone = try table.select(null);
    defer freeRows(allocator, everyone);
    try std.testing.expectEqual(@as(usize, 0), everyone.len);
}

test "deleteWhere with no matches deletes nothing and leaves the table untouched" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    const deleted = try table.deleteWhere(.{ .eq = .{ .field = "city", .value = .{ .text = "gdansk" } } });
    try std.testing.expectEqual(@as(usize, 0), deleted);

    var row = (try table.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("warsaw", row.get("city").?.text);
}

test "deleteWhere removes stale secondary index entries so a fresh row can reuse the value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("city");
    try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});

    const deleted = try table.deleteWhere(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    try std.testing.expectEqual(@as(usize, 1), deleted);

    const stale = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);

    try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    const fresh = try table.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer freeRows(allocator, fresh);
    try std.testing.expectEqual(@as(usize, 1), fresh.len);
    try std.testing.expectEqual(@as(i64, 2), fresh[0].get(pkField).?.int);

    const constTable: *const Table = &table;
    var plan = try constTable.explain(allocator, .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer plan.deinit(allocator);
    try std.testing.expectEqual(PlanKind.index_eq, plan.kind);
}

test "deleteWhere removes stale composite index entries across matched equality prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createCompositeIndex("city_age", &.{ "city", "age" });

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    try table.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "age", .value = .{ .int = 31 } },
    });
    try table.put(.{ .int = 3 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });

    const preds = [_]Predicate{
        .{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } },
        .{ .eq = .{ .field = "age", .value = .{ .int = 30 } } },
    };
    const deleted = try table.deleteWhere(.{ .and_ = &preds });
    try std.testing.expectEqual(@as(usize, 1), deleted);

    const gone = try table.select(.{ .and_ = &preds });
    defer freeRows(allocator, gone);
    try std.testing.expectEqual(@as(usize, 0), gone.len);

    const survivors = [_]struct { pk: i64, city: []const u8, age: i64 }{
        .{ .pk = 2, .city = "warsaw", .age = 31 },
        .{ .pk = 3, .city = "krakow", .age = 30 },
    };
    for (survivors) |exp| {
        const survivorPreds = [_]Predicate{
            .{ .eq = .{ .field = "city", .value = .{ .text = exp.city } } },
            .{ .eq = .{ .field = "age", .value = .{ .int = exp.age } } },
        };
        const rows = try table.select(.{ .and_ = &survivorPreds });
        defer freeRows(allocator, rows);
        try std.testing.expectEqual(@as(usize, 1), rows.len);
        try std.testing.expectEqual(exp.pk, rows[0].get(pkField).?.int);

        const constTable: *const Table = &table;
        var plan = try constTable.explain(allocator, .{ .and_ = &survivorPreds });
        defer plan.deinit(allocator);
        try std.testing.expectEqual(PlanKind.composite_eq, plan.kind);
    }
}

test "createUniqueIndex backfills the plain index and rejects a colliding insert" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});

    try table.createUniqueIndex("email");
    try std.testing.expect(table.hasUniqueIndex("email"));
    try std.testing.expect(table.hasIndex("email"));

    try std.testing.expectError(error.UniqueViolation, table.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
    }));

    try table.put(.{ .int = 2 }, &.{.{ .name = "email", .value = .{ .text = "b@x.com" } }});
    const rows = try table.scanAll();
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
}

test "createUniqueIndex refuses to install over data that already has a duplicate" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "dup@x.com" } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "email", .value = .{ .text = "dup@x.com" } }});

    try std.testing.expectError(error.UniqueViolation, table.createUniqueIndex("email"));
    try std.testing.expect(!table.hasUniqueIndex("email"));
    try std.testing.expect(!table.hasIndex("email"));
}

test "createUniqueIndex over an already-indexed field reuses the index instead of duplicating entries" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createIndex("email");
    try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});

    try table.createUniqueIndex("email");
    try std.testing.expect(table.hasUniqueIndex("email"));

    try std.testing.expectError(error.UniqueViolation, table.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
    }));

    const preds = Predicate{ .eq = .{ .field = "email", .value = .{ .text = "a@x.com" } } };
    const rows = try table.select(preds);
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
}

test "unique constraint does not block updating a row's own value or an unrelated field" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
        .{ .name = "age", .value = .{ .int = 30 } },
    });
    try table.createUniqueIndex("email");

    try table.put(.{ .int = 1 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
        .{ .name = "age", .value = .{ .int = 31 } },
    });

    var row = (try table.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expectEqual(@as(i64, 31), row.get("age").?.int);
}

test "unique constraint frees a value for reuse once the owning row is deleted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createUniqueIndex("email");
    try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});
    try std.testing.expectError(error.UniqueViolation, table.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
    }));

    try table.delete(.{ .int = 1 });
    try table.put(.{ .int = 2 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});

    var row = (try table.get(.{ .int = 2 })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("a@x.com", row.get("email").?.text);
}

test "dropIndex on a unique field also drops the unique constraint" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.createUniqueIndex("email");
    try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});

    try table.dropIndex("email");
    try std.testing.expect(!table.hasUniqueIndex("email"));
    try std.testing.expect(!table.hasIndex("email"));

    try table.put(.{ .int = 2 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});
    const rows = try table.scanAll();
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
}

test "unique constraint survives a table reopen (persisted across process restart)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var table = try Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createUniqueIndex("email");
        try table.put(.{ .int = 1 }, &.{.{ .name = "email", .value = .{ .text = "a@x.com" } }});
    }

    var reopened = try Table.open(&db, allocator, "users");
    defer reopened.deinit();
    try std.testing.expect(reopened.hasUniqueIndex("email"));
    try std.testing.expectError(error.UniqueViolation, reopened.put(.{ .int = 2 }, &.{
        .{ .name = "email", .value = .{ .text = "a@x.com" } },
    }));
}

test "createUniqueIndex rejects a bad field identifier" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try std.testing.expectError(error.InvalidIdentifier, table.createUniqueIndex("bad\x00field"));
}

test "rows missing the unique field entirely never collide with each other" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var table = try Table.open(&db, allocator, "users");
    defer table.deinit();
    try table.put(.{ .int = 1 }, &.{.{ .name = "age", .value = .{ .int = 20 } }});
    try table.put(.{ .int = 2 }, &.{.{ .name = "age", .value = .{ .int = 21 } }});

    try table.createUniqueIndex("email");
    try table.put(.{ .int = 3 }, &.{.{ .name = "age", .value = .{ .int = 22 } }});
    const rows = try table.scanAll();
    defer freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 3), rows.len);
}

test "createForeignKey against the primary key rejects a dangling reference and accepts a real one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    try std.testing.expect(orders.hasForeignKey("customer_id"));

    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    try std.testing.expectError(error.ForeignKeyViolation, orders.put(.{ .int = 101 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 999 } },
    }));
}

test "createForeignKey against a UNIQUE non-pk field works, and refuses a target with no unique backing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var products = try Table.open(&db, allocator, "products");
    defer products.deinit();
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "SKU-1" } }});

    var lineItems = try Table.open(&db, allocator, "line_items");
    defer lineItems.deinit();

    try std.testing.expectError(error.ForeignKeyRequiresUniqueTarget, lineItems.createForeignKey("product_sku", "products", "sku", .restrict));

    try products.createUniqueIndex("sku");
    try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);

    try lineItems.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "SKU-1" } }});
    try std.testing.expectError(error.ForeignKeyViolation, lineItems.put(.{ .int = 2 }, &.{
        .{ .name = "product_sku", .value = .{ .text = "NOPE" } },
    }));
}

test "createForeignKey refuses to install over a child row that already dangles" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 1 }, &.{.{ .name = "customer_id", .value = .{ .int = 42 } }});

    try std.testing.expectError(error.ForeignKeyViolation, orders.createForeignKey("customer_id", "customers", pkField, .restrict));
    try std.testing.expect(!orders.hasForeignKey("customer_id"));
}

test "a row with no value for the foreign key field is exempt from the constraint" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);

    try orders.put(.{ .int = 1 }, &.{.{ .name = "note", .value = .{ .text = "guest checkout" } }});
    var row = (try orders.get(.{ .int = 1 })).?;
    defer row.deinit();
    try std.testing.expect(row.get("customer_id") == null);
}

test "dropForeignKey lifts the constraint" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);

    try std.testing.expectError(error.ForeignKeyViolation, orders.put(.{ .int = 1 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 42 } },
    }));

    try orders.dropForeignKey("customer_id");
    try std.testing.expect(!orders.hasForeignKey("customer_id"));
    try orders.put(.{ .int = 1 }, &.{.{ .name = "customer_id", .value = .{ .int = 42 } }});
}

test "deleting a parent row is restricted while a child still references it via the primary key" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    try std.testing.expectError(error.ForeignKeyInUse, customers.delete(.{ .int = 1 }));
    var stillThere = (try customers.get(.{ .int = 1 })).?;
    stillThere.deinit();

    try orders.delete(.{ .int = 100 });
    try customers.delete(.{ .int = 1 });
    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
}

test "deleteWhere on a parent table stops at the first row a child still references" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "Boris" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }});

    try std.testing.expectError(error.ForeignKeyInUse, customers.deleteWhere(null));
    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
    var stillThere = (try customers.get(.{ .int = 2 })).?;
    stillThere.deinit();
}

test "dropForeignKey lifts the delete restriction on the table it pointed at" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try std.testing.expectError(error.ForeignKeyInUse, customers.delete(.{ .int = 1 }));

    try orders.dropForeignKey("customer_id");
    try customers.delete(.{ .int = 1 });
    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
}

test "delete restriction works through a UNIQUE non-pk foreign key target too" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var products = try Table.open(&db, allocator, "products");
    defer products.deinit();
    try products.createUniqueIndex("sku");
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    var lineItems = try Table.open(&db, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
    try lineItems.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } }});

    try std.testing.expectError(error.ForeignKeyInUse, products.delete(.{ .int = 1 }));

    try lineItems.delete(.{ .int = 1 });
    try products.delete(.{ .int = 1 });
    try std.testing.expect((try products.get(.{ .int = 1 })) == null);
}

test "a self-referencing foreign key restricts deleting a manager with reports, but not a childless leaf" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var employees = try Table.open(&db, allocator, "employees");
    defer employees.deinit();
    try employees.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "CEO" } }});
    try employees.createForeignKey("manager_id", "employees", pkField, .restrict);
    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "name", .value = .{ .text = "VP" } },
        .{ .name = "manager_id", .value = .{ .int = 1 } },
    });

    try std.testing.expectError(error.ForeignKeyInUse, employees.delete(.{ .int = 1 }));
    try employees.delete(.{ .int = 2 });
    try employees.delete(.{ .int = 1 });
    try std.testing.expect((try employees.get(.{ .int = 1 })) == null);
}

test "foreign key constraint survives a table reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var customers = try Table.open(&db, allocator, "customers");
        defer customers.deinit();
        var orders = try Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    }

    var reopened = try Table.open(&db, allocator, "orders");
    defer reopened.deinit();
    try std.testing.expect(reopened.hasForeignKey("customer_id"));
    try std.testing.expectError(error.ForeignKeyViolation, reopened.put(.{ .int = 1 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 7 } },
    }));
}

test "createForeignKey rejects bad identifiers for field, refTable, and refField" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try std.testing.expectError(error.InvalidIdentifier, orders.createForeignKey("bad\x00field", "customers", pkField, .restrict));
    try std.testing.expectError(error.InvalidIdentifier, orders.createForeignKey("customer_id", "bad\x00table", pkField, .restrict));
    try std.testing.expectError(error.InvalidIdentifier, orders.createForeignKey("customer_id", "customers", "bad\x00field", .restrict));
}

test "a self-referencing foreign key enforces a tree structure against the table's own primary key" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var employees = try Table.open(&db, allocator, "employees");
    defer employees.deinit();
    try employees.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "CEO" } }});
    try employees.createForeignKey("manager_id", "employees", pkField, .restrict);

    try employees.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "CEO" } }});
    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "name", .value = .{ .text = "VP" } },
        .{ .name = "manager_id", .value = .{ .int = 1 } },
    });
    try std.testing.expectError(error.ForeignKeyViolation, employees.put(.{ .int = 3 }, &.{
        .{ .name = "name", .value = .{ .text = "Ghost report" } },
        .{ .name = "manager_id", .value = .{ .int = 999 } },
    }));
}

test "deleting a referenced parent is blocked before it can leave a child's foreign key dangling" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .restrict);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    try std.testing.expectError(error.ForeignKeyInUse, customers.delete(.{ .int = 1 }));

    try std.testing.expectEqual(@as(usize, 1), try orders.updateWhere(null, &.{
        .{ .name = "note", .value = .{ .text = "touch" } },
    }));
}

test "put is restricted from changing a UNIQUE foreign key target still referenced by a child" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var products = try Table.open(&db, allocator, "products");
    defer products.deinit();
    try products.createUniqueIndex("sku");
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    var lineItems = try Table.open(&db, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
    try lineItems.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } }});

    try std.testing.expectError(error.ForeignKeyInUse, products.put(.{ .int = 1 }, &.{
        .{ .name = "sku", .value = .{ .text = "WIDGET-2" } },
    }));
    var stillThere = (try products.get(.{ .int = 1 })).?;
    defer stillThere.deinit();
    try std.testing.expectEqualStrings("WIDGET-1", stillThere.get("sku").?.text);

    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    try lineItems.delete(.{ .int = 1 });
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-2" } }});
    var renamed = (try products.get(.{ .int = 1 })).?;
    defer renamed.deinit();
    try std.testing.expectEqualStrings("WIDGET-2", renamed.get("sku").?.text);
}

test "updateWhere is restricted from pulling a UNIQUE foreign key target out from under a child" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var products = try Table.open(&db, allocator, "products");
    defer products.deinit();
    try products.createUniqueIndex("sku");
    try products.put(.{ .int = 1 }, &.{.{ .name = "sku", .value = .{ .text = "WIDGET-1" } }});

    var lineItems = try Table.open(&db, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.createForeignKey("product_sku", "products", "sku", .restrict);
    try lineItems.put(.{ .int = 1 }, &.{.{ .name = "product_sku", .value = .{ .text = "WIDGET-1" } }});

    try std.testing.expectError(error.ForeignKeyInUse, products.updateWhere(null, &.{
        .{ .name = "sku", .value = .{ .text = "WIDGET-2" } },
    }));

    try std.testing.expectEqual(@as(usize, 1), try products.updateWhere(null, &.{
        .{ .name = "note", .value = .{ .text = "touch" } },
    }));
}

test "a self-referencing foreign key restricts renaming a UNIQUE field still targeted by a report, but not by itself" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var employees = try Table.open(&db, allocator, "employees");
    defer employees.deinit();
    try employees.createUniqueIndex("badge");
    try employees.createForeignKey("manager_badge", "employees", "badge", .restrict);
    try employees.put(.{ .int = 1 }, &.{.{ .name = "badge", .value = .{ .text = "B1" } }});
    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "badge", .value = .{ .text = "B2" } },
        .{ .name = "manager_badge", .value = .{ .text = "B1" } },
    });

    try std.testing.expectError(error.ForeignKeyInUse, employees.put(.{ .int = 1 }, &.{
        .{ .name = "badge", .value = .{ .text = "B1-NEW" } },
    }));

    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "badge", .value = .{ .text = "B2-NEW" } },
        .{ .name = "manager_badge", .value = .{ .text = "B1" } },
    });

    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "badge", .value = .{ .text = "B2-NEW" } },
    });
    try employees.put(.{ .int = 1 }, &.{.{ .name = "badge", .value = .{ .text = "B1-NEW" } }});
    var renamed = (try employees.get(.{ .int = 1 })).?;
    defer renamed.deinit();
    try std.testing.expectEqualStrings("B1-NEW", renamed.get("badge").?.text);
}

test "createCheckConstraint rejects a row that violates it and accepts one that satisfies it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createCheckConstraint("qty_positive", "qty gt i:0");
    try std.testing.expect(orders.hasCheckConstraint("qty_positive"));

    try orders.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = 5 } }});
    try std.testing.expectError(error.CheckViolation, orders.put(.{ .int = 2 }, &.{
        .{ .name = "qty", .value = .{ .int = 0 } },
    }));
    try std.testing.expectError(error.CheckViolation, orders.put(.{ .int = 3 }, &.{
        .{ .name = "qty", .value = .{ .int = -1 } },
    }));
}

test "createCheckConstraint refuses to install over existing rows that already fail it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = -5 } }});

    try std.testing.expectError(error.CheckViolation, orders.createCheckConstraint("qty_positive", "qty gt i:0"));
    try std.testing.expect(!orders.hasCheckConstraint("qty_positive"));
}

test "createCheckConstraint rejects a malformed expression before persisting anything" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try std.testing.expectError(error.InvalidCheckExpression, orders.createCheckConstraint("bad", "qty gt"));
    try std.testing.expect(!orders.hasCheckConstraint("bad"));
}

test "dropCheckConstraint lifts the constraint, and a check constraint survives a table reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var orders = try Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createCheckConstraint("qty_positive", "qty gt i:0");
    }

    var reopened = try Table.open(&db, allocator, "orders");
    defer reopened.deinit();
    try std.testing.expect(reopened.hasCheckConstraint("qty_positive"));
    try std.testing.expectError(error.CheckViolation, reopened.put(.{ .int = 1 }, &.{
        .{ .name = "qty", .value = .{ .int = 0 } },
    }));

    try reopened.dropCheckConstraint("qty_positive");
    try std.testing.expect(!reopened.hasCheckConstraint("qty_positive"));
    try reopened.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = 0 } }});
}

test "a row missing the checked field entirely is exempt (like is_null), but present-and-none is still checked" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createCheckConstraint("qty_known", "qty is_not_null");

    try std.testing.expectError(error.CheckViolation, orders.put(.{ .int = 1 }, &.{}));
}

test "multiple CHECK constraints on the same table all must pass" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createCheckConstraint("qty_positive", "qty gt i:0");
    try orders.createCheckConstraint("qty_capped", "qty lt i:1000");

    try orders.put(.{ .int = 1 }, &.{.{ .name = "qty", .value = .{ .int = 500 } }});
    try std.testing.expectError(error.CheckViolation, orders.put(.{ .int = 2 }, &.{
        .{ .name = "qty", .value = .{ .int = 1000 } },
    }));
}

test "ON DELETE CASCADE removes referencing rows instead of restricting the parent delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "Boris" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 101 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 200 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }});

    try customers.delete(.{ .int = 1 });

    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 100 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 101 })) == null);

    var otherCustomer = (try customers.get(.{ .int = 2 })).?;
    otherCustomer.deinit();
    var otherOrder = (try orders.get(.{ .int = 200 })).?;
    otherOrder.deinit();
}

test "ON DELETE CASCADE keeps secondary indexes on the cascaded rows in sync" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createIndex("status");
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 1 } },
        .{ .name = "status", .value = .{ .text = "open" } },
    });

    const before = try idx.scanEq(&db, allocator, "orders", "status", .{ .text = "open" });
    defer allocator.free(before);
    try std.testing.expectEqual(@as(usize, 1), before.len);

    try customers.delete(.{ .int = 1 });

    const after = try idx.scanEq(&db, allocator, "orders", "status", .{ .text = "open" });
    defer allocator.free(after);
    try std.testing.expectEqual(@as(usize, 0), after.len);
}

test "ON DELETE CASCADE recurses transitively across more than one hop" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    var lineItems = try Table.open(&db, allocator, "line_items");
    defer lineItems.deinit();
    try lineItems.createForeignKey("order_id", "orders", pkField, .cascade);
    try lineItems.put(.{ .int = 1000 }, &.{.{ .name = "order_id", .value = .{ .int = 100 } }});
    try lineItems.put(.{ .int = 1001 }, &.{.{ .name = "order_id", .value = .{ .int = 100 } }});

    try customers.delete(.{ .int = 1 });

    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 100 })) == null);
    try std.testing.expect((try lineItems.get(.{ .int = 1000 })) == null);
    try std.testing.expect((try lineItems.get(.{ .int = 1001 })) == null);
}

test "ON DELETE CASCADE is all-or-nothing: a RESTRICT hit anywhere in the fan-out aborts with nothing deleted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "Ada" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    var shipments = try Table.open(&db, allocator, "shipments");
    defer shipments.deinit();
    try shipments.createForeignKey("order_id", "orders", pkField, .restrict);
    try shipments.put(.{ .int = 9000 }, &.{.{ .name = "order_id", .value = .{ .int = 100 } }});

    try std.testing.expectError(error.ForeignKeyInUse, customers.delete(.{ .int = 1 }));

    var stillCustomer = (try customers.get(.{ .int = 1 })).?;
    stillCustomer.deinit();
    var stillOrder = (try orders.get(.{ .int = 100 })).?;
    stillOrder.deinit();
    var stillShipment = (try shipments.get(.{ .int = 9000 })).?;
    stillShipment.deinit();
}

test "ON DELETE CASCADE terminates on a two-table delete cycle instead of recursing forever" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var a = try Table.open(&db, allocator, "a");
    defer a.deinit();
    var b = try Table.open(&db, allocator, "b");
    defer b.deinit();

    try a.put(.{ .int = 1 }, &.{});
    try b.put(.{ .int = 1 }, &.{.{ .name = "a_id", .value = .{ .int = 1 } }});
    try a.createForeignKey("b_id", "b", pkField, .cascade);
    try a.put(.{ .int = 1 }, &.{.{ .name = "b_id", .value = .{ .int = 1 } }});
    try b.createForeignKey("a_id", "a", pkField, .cascade);

    try a.delete(.{ .int = 1 });

    try std.testing.expect((try a.get(.{ .int = 1 })) == null);
    try std.testing.expect((try b.get(.{ .int = 1 })) == null);
}

test "ON DELETE CASCADE on a self-referencing foreign key removes an entire subtree" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var employees = try Table.open(&db, allocator, "employees");
    defer employees.deinit();
    try employees.createForeignKey("manager_id", "employees", pkField, .cascade);

    try employees.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "CEO" } }});
    try employees.put(.{ .int = 2 }, &.{
        .{ .name = "name", .value = .{ .text = "VP" } },
        .{ .name = "manager_id", .value = .{ .int = 1 } },
    });
    try employees.put(.{ .int = 3 }, &.{
        .{ .name = "name", .value = .{ .text = "IC-A" } },
        .{ .name = "manager_id", .value = .{ .int = 2 } },
    });
    try employees.put(.{ .int = 4 }, &.{
        .{ .name = "name", .value = .{ .text = "IC-B" } },
        .{ .name = "manager_id", .value = .{ .int = 2 } },
    });

    try employees.delete(.{ .int = 2 });

    var ceo = (try employees.get(.{ .int = 1 })).?;
    ceo.deinit();
    try std.testing.expect((try employees.get(.{ .int = 2 })) == null);
    try std.testing.expect((try employees.get(.{ .int = 3 })) == null);
    try std.testing.expect((try employees.get(.{ .int = 4 })) == null);
}

test "deleteWhere cascades every match, not just the first" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "region", .value = .{ .text = "eu" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "region", .value = .{ .text = "eu" } }});
    try customers.put(.{ .int = 3 }, &.{.{ .name = "region", .value = .{ .text = "us" } }});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    try orders.put(.{ .int = 200 }, &.{.{ .name = "customer_id", .value = .{ .int = 2 } }});
    try orders.put(.{ .int = 300 }, &.{.{ .name = "customer_id", .value = .{ .int = 3 } }});

    const deleted = try customers.deleteWhere(.{ .eq = .{ .field = "region", .value = .{ .text = "eu" } } });
    try std.testing.expectEqual(@as(usize, 2), deleted);

    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
    try std.testing.expect((try customers.get(.{ .int = 2 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 100 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 200 })) == null);

    var stillCustomer = (try customers.get(.{ .int = 3 })).?;
    stillCustomer.deinit();
    var stillOrder = (try orders.get(.{ .int = 300 })).?;
    stillOrder.deinit();
}

test "dropForeignKey lifts a CASCADE constraint the same as a RESTRICT one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var customers = try Table.open(&db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{});

    var orders = try Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try orders.createForeignKey("customer_id", "customers", pkField, .cascade);
    try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});

    try orders.dropForeignKey("customer_id");
    try customers.delete(.{ .int = 1 });

    try std.testing.expect((try customers.get(.{ .int = 1 })) == null);
    var stillOrder = (try orders.get(.{ .int = 100 })).?;
    stillOrder.deinit();
}
