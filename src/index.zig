const std = @import("std");
const dbmod = @import("db.zig");
const row = @import("row.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Value = row.Value;

/// Keyspace layout shared by every table and index living inside a single
/// Db instance:
///   "R\x00" table "\x00" orderedPk                 -> encoded Row
///   "I\x00" table "\x00" field "\x00" orderedValue orderedPk -> encoded pk Value
///   "J\x00" table "\x00" indexName "\x00" orderedValue1 .. orderedValueN orderedPk -> encoded pk Value
///   "M\x00INDEXES\x00" table                        -> encoded list of indexed field names
///   "M\x00CINDEXES\x00" table                       -> encoded list of composite index specs
///   "M\x00UNIQUE\x00" table                         -> encoded list of UNIQUE-constrained field names
///   "M\x00FKEYS\x00" table                          -> encoded list of FOREIGN KEY specs (field, refTable, refField)
///   "M\x00CHECKS\x00" table                         -> encoded list of CHECK constraint specs (name, expr source)
///   "M\x00REFBY\x00" table                          -> encoded list of reverse FK specs (childTable, childField, refField),
///                                                       one entry per OTHER table's FOREIGN KEY that names this table+refField
///
/// All namespaces share one flat LSM keyspace (there is only one Db), so the
/// leading tag byte plus NUL separators keep tables, single-field indexes,
/// composite indexes, and metadata from ever colliding or shadowing each
/// other during a scan. A composite index entry's value columns are just N
/// single-column `row.appendOrdered` encodings concatenated in the index's
/// declared field order ahead of the primary key's - each encoding is
/// already self-delimiting (fixed width for none/boolean/int/float, a
/// 0x00 0x00 terminator for text/bytes with 0x00 bytes escaped), so the
/// concatenation compares byte-for-byte in exactly the same order as
/// comparing the value tuples component by component. That is what makes a
/// prefix scan over the leading K of N components ("leftmost prefix" rule,
/// same as a real multi-column B-tree index) a correct equality lookup on
/// just those K columns, unconstrained on the rest.
pub const rowTag: u8 = 'R';
pub const indexTag: u8 = 'I';
pub const compositeIndexTag: u8 = 'J';
pub const metaTag: u8 = 'M';
const sep: u8 = 0x00;

fn appendSegment(out: *std.ArrayList(u8), segment: []const u8) !void {
    try out.appendSlice(segment);
    try out.append(sep);
}

pub fn rowPrefix(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(rowTag);
    try appendSegment(&out, table);
    return out.toOwnedSlice();
}

pub fn rowKey(allocator: Allocator, table: []const u8, pk: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(rowTag);
    try appendSegment(&out, table);
    try row.appendOrdered(&out, pk);
    return out.toOwnedSlice();
}

pub fn indexPrefix(allocator: Allocator, table: []const u8, field: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(indexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, field);
    return out.toOwnedSlice();
}

pub fn indexEntryKey(allocator: Allocator, table: []const u8, field: []const u8, value: Value, pk: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(indexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, field);
    try row.appendOrdered(&out, value);
    try row.appendOrdered(&out, pk);
    return out.toOwnedSlice();
}

pub fn indexValueBound(allocator: Allocator, table: []const u8, field: []const u8, value: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(indexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, field);
    try row.appendOrdered(&out, value);
    return out.toOwnedSlice();
}

fn metaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "INDEXES");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

fn compositeMetaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "CINDEXES");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

fn uniqueMetaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "UNIQUE");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

fn foreignKeyMetaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "FKEYS");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

fn checkMetaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "CHECKS");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

fn referencedByMetaKey(allocator: Allocator, table: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(metaTag);
    try appendSegment(&out, "REFBY");
    try out.appendSlice(table);
    return out.toOwnedSlice();
}

pub fn compositeIndexPrefix(allocator: Allocator, table: []const u8, indexName: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(compositeIndexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, indexName);
    return out.toOwnedSlice();
}

pub fn compositeIndexEntryKey(allocator: Allocator, table: []const u8, indexName: []const u8, values: []const Value, pk: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(compositeIndexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, indexName);
    for (values) |v| try row.appendOrdered(&out, v);
    try row.appendOrdered(&out, pk);
    return out.toOwnedSlice();
}

/// Bound for a leftmost-prefix scan of a composite index: `values.len` may
/// be less than the index's full column count, in which case the scan
/// matches every entry whose leading columns equal `values` regardless of
/// what the remaining (unconstrained) columns hold - see the module-level
/// keyspace comment for why the concatenation makes this a correct prefix.
pub fn compositeIndexValueBound(allocator: Allocator, table: []const u8, indexName: []const u8, values: []const Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(compositeIndexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, indexName);
    for (values) |v| try row.appendOrdered(&out, v);
    return out.toOwnedSlice();
}

/// Bound for a composite index scan that pins `eqValues` as the leading
/// columns (leftmost prefix, same as `compositeIndexValueBound`) and then
/// appends one more ordered value for a range condition on the very next
/// column - the byte-extension argument from the module-level keyspace
/// comment applies here exactly as it does for a bare `indexValueBound`, so
/// `scanCompositeRangeCursor` can reuse the same inclusive/exclusive
/// gap trick `scanRangeCursor` uses for single-field indexes.
fn compositeIndexRangeBound(allocator: Allocator, table: []const u8, indexName: []const u8, eqValues: []const Value, extra: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(compositeIndexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, indexName);
    for (eqValues) |v| try row.appendOrdered(&out, v);
    try row.appendOrdered(&out, extra);
    return out.toOwnedSlice();
}

/// Smallest byte string strictly greater than every string with `prefix` as
/// a prefix, used as the exclusive upper bound of a prefix scan. Returns
/// null when the prefix is all 0xFF bytes (unbounded above, e.g. empty
/// table/field names never hit this in practice).
pub fn prefixUpperBound(allocator: Allocator, prefix: []const u8) !?[]u8 {
    var end = prefix.len;
    while (end > 0 and prefix[end - 1] == 0xff) end -= 1;
    if (end == 0) return null;
    const upper = try allocator.alloc(u8, end);
    @memcpy(upper, prefix[0..end]);
    upper[end - 1] += 1;
    return upper;
}

/// Whether a table name or field name is safe to embed as a NUL-delimited
/// keyspace segment: table/field identifiers may not themselves contain
/// NUL bytes or they would corrupt the segment boundaries above.
pub fn validIdentifier(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c == sep) return false;
    }
    return true;
}

/// Persisted set of field names that have a secondary index on a table.
/// Loaded once per Table.open and written back to the Db's metadata
/// namespace whenever an index is created or dropped, so indexes survive
/// process restarts without any external schema file.
pub const IndexSet = struct {
    allocator: Allocator,
    fields: std.ArrayList([]u8),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !IndexSet {
        const key = try metaKey(allocator, table);
        defer allocator.free(key);

        var set = IndexSet{ .allocator = allocator, .fields = std.ArrayList([]u8).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const count = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            if (pos + 4 > raw.len) return error.Malformed;
            const len = std.mem.readInt(u32, raw[pos..][0..4], .little);
            pos += 4;
            if (pos + len > raw.len) return error.Malformed;
            const name = try allocator.dupe(u8, raw[pos .. pos + len]);
            pos += len;
            try set.fields.append(name);
        }
        return set;
    }

    pub fn save(self: *const IndexSet, db: *Db, table: []const u8) !void {
        const key = try metaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.fields.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.fields.items) |name| {
            var lenBuf: [4]u8 = undefined;
            std.mem.writeInt(u32, &lenBuf, @intCast(name.len), .little);
            try out.appendSlice(&lenBuf);
            try out.appendSlice(name);
        }
        try db.put(key, out.items);
    }

    pub fn has(self: *const IndexSet, field: []const u8) bool {
        for (self.fields.items) |f| {
            if (std.mem.eql(u8, f, field)) return true;
        }
        return false;
    }

    pub fn add(self: *IndexSet, field: []const u8) !void {
        if (self.has(field)) return;
        const copy = try self.allocator.dupe(u8, field);
        try self.fields.append(copy);
    }

    /// Returns true if the field was present and has been removed.
    pub fn remove(self: *IndexSet, field: []const u8) bool {
        for (self.fields.items, 0..) |f, i| {
            if (std.mem.eql(u8, f, field)) {
                self.allocator.free(f);
                _ = self.fields.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *IndexSet) void {
        for (self.fields.items) |f| self.allocator.free(f);
        self.fields.deinit();
    }
};

/// Persisted set of field names carrying a UNIQUE constraint on a table -
/// same on-disk shape as `IndexSet` (own meta key, own namespace), kept as
/// a separate type because the two sets have different invariants: every
/// member of `UniqueSet` is also required to be a member of the table's
/// `IndexSet` (enforced by `Table.createUniqueIndex`/`Table.dropIndex`),
/// since `Table.put` detects a colliding value by reusing the field's
/// regular index entries via `scanEq` rather than a full table scan - a
/// unique field with no backing index would make every write pay for a
/// full scan just to check the constraint.
pub const UniqueSet = struct {
    allocator: Allocator,
    fields: std.ArrayList([]u8),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !UniqueSet {
        const key = try uniqueMetaKey(allocator, table);
        defer allocator.free(key);

        var set = UniqueSet{ .allocator = allocator, .fields = std.ArrayList([]u8).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const count = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            if (pos + 4 > raw.len) return error.Malformed;
            const len = std.mem.readInt(u32, raw[pos..][0..4], .little);
            pos += 4;
            if (pos + len > raw.len) return error.Malformed;
            const name = try allocator.dupe(u8, raw[pos .. pos + len]);
            pos += len;
            try set.fields.append(name);
        }
        return set;
    }

    pub fn save(self: *const UniqueSet, db: *Db, table: []const u8) !void {
        const key = try uniqueMetaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.fields.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.fields.items) |name| {
            var lenBuf: [4]u8 = undefined;
            std.mem.writeInt(u32, &lenBuf, @intCast(name.len), .little);
            try out.appendSlice(&lenBuf);
            try out.appendSlice(name);
        }
        try db.put(key, out.items);
    }

    pub fn has(self: *const UniqueSet, field: []const u8) bool {
        for (self.fields.items) |f| {
            if (std.mem.eql(u8, f, field)) return true;
        }
        return false;
    }

    pub fn add(self: *UniqueSet, field: []const u8) !void {
        if (self.has(field)) return;
        const copy = try self.allocator.dupe(u8, field);
        try self.fields.append(copy);
    }

    /// Returns true if the field was present and has been removed.
    pub fn remove(self: *UniqueSet, field: []const u8) bool {
        for (self.fields.items, 0..) |f, i| {
            if (std.mem.eql(u8, f, field)) {
                self.allocator.free(f);
                _ = self.fields.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *UniqueSet) void {
        for (self.fields.items) |f| self.allocator.free(f);
        self.fields.deinit();
    }
};

/// One FOREIGN KEY constraint: `field` on the owning table must, on every
/// row where it is present and non-none, name a value that exists as
/// `refField` on `refTable` (SQL's `FOREIGN KEY (field) REFERENCES
/// refTable(refField)`). `refField` is either `query.pkField` (the
/// referenced table's primary key, checked via a plain `get`) or a field
/// carrying its own UNIQUE constraint on `refTable` (checked via `scanEq`) -
/// `Table.createForeignKey` requires one of the two before installing,
/// exactly like a real database refusing a foreign key against a column
/// with no unique/primary-key backing, since otherwise "the value exists"
/// would not pin down a single unambiguous parent row.
/// SQL's `ON DELETE` clause: what a FOREIGN KEY does when the row it points
/// at is deleted. `restrict` (the SQL default, and this codebase's only
/// behavior before cascading deletes existed) refuses the delete outright
/// while a referencing row still exists; `cascade` instead deletes every
/// referencing row too, recursively (a cascaded child can itself have
/// dependents), before the parent row itself is removed. Stored as a plain
/// byte in `ForeignKeySpec`/`ReferencedBySpec` rather than a bare bool so a
/// third mode (e.g. `set_null`) can be added later without another format
/// bump.
pub const OnDelete = enum(u8) {
    restrict = 0,
    cascade = 1,
};

fn onDeleteFromByte(b: u8) !OnDelete {
    return switch (b) {
        0 => .restrict,
        1 => .cascade,
        else => error.Malformed,
    };
}

pub const ForeignKeySpec = struct {
    field: []u8,
    refTable: []u8,
    refField: []u8,
    onDelete: OnDelete,
};

/// Persisted set of FOREIGN KEY constraints on a table, at most one per
/// owning field - same on-disk shape family as `IndexSet`/`UniqueSet` (own
/// meta key, own namespace) but each entry carries two extra strings
/// (`refTable`/`refField`) plus an `onDelete` mode byte instead of being a
/// bare field name.
pub const ForeignKeySet = struct {
    allocator: Allocator,
    specs: std.ArrayList(ForeignKeySpec),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !ForeignKeySet {
        const key = try foreignKeyMetaKey(allocator, table);
        defer allocator.free(key);

        var set = ForeignKeySet{ .allocator = allocator, .specs = std.ArrayList(ForeignKeySpec).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const count = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const field = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(field);
            const refTable = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(refTable);
            const refField = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(refField);
            if (pos + 1 > raw.len) return error.Malformed;
            const onDelete = try onDeleteFromByte(raw[pos]);
            pos += 1;
            try set.specs.append(.{ .field = field, .refTable = refTable, .refField = refField, .onDelete = onDelete });
        }
        return set;
    }

    pub fn save(self: *const ForeignKeySet, db: *Db, table: []const u8) !void {
        const key = try foreignKeyMetaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.specs.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.specs.items) |spec| {
            try appendLenPrefixed(&out, spec.field);
            try appendLenPrefixed(&out, spec.refTable);
            try appendLenPrefixed(&out, spec.refField);
            try out.append(@intFromEnum(spec.onDelete));
        }
        try db.put(key, out.items);
    }

    pub fn has(self: *const ForeignKeySet, field: []const u8) bool {
        return self.find(field) != null;
    }

    pub fn find(self: *const ForeignKeySet, field: []const u8) ?ForeignKeySpec {
        for (self.specs.items) |spec| {
            if (std.mem.eql(u8, spec.field, field)) return spec;
        }
        return null;
    }

    pub fn add(self: *ForeignKeySet, field: []const u8, refTable: []const u8, refField: []const u8, onDelete: OnDelete) !void {
        if (self.has(field)) return;
        const spec = ForeignKeySpec{
            .field = try self.allocator.dupe(u8, field),
            .refTable = try self.allocator.dupe(u8, refTable),
            .refField = try self.allocator.dupe(u8, refField),
            .onDelete = onDelete,
        };
        try self.specs.append(spec);
    }

    /// Returns true if a constraint on `field` was present and has been
    /// removed.
    pub fn remove(self: *ForeignKeySet, field: []const u8) bool {
        for (self.specs.items, 0..) |spec, i| {
            if (std.mem.eql(u8, spec.field, field)) {
                self.allocator.free(spec.field);
                self.allocator.free(spec.refTable);
                self.allocator.free(spec.refField);
                _ = self.specs.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *ForeignKeySet) void {
        for (self.specs.items) |spec| {
            self.allocator.free(spec.field);
            self.allocator.free(spec.refTable);
            self.allocator.free(spec.refField);
        }
        self.specs.deinit();
    }
};

/// One named CHECK constraint: a caller-chosen `name` (used only as the key
/// under which the constraint can be dropped again, not part of the
/// keyspace layout - unlike `CompositeIndexSpec.name`, no index entries are
/// ever written for a CHECK) paired with the raw `expr.zig` predicate source
/// text it must evaluate true against. Stored as source rather than a parsed
/// tree because `index.zig` sits below `query.zig`/`expr.zig` in the
/// dependency graph and knows nothing about `Predicate` - parsing happens
/// fresh in whichever layer enforces it (`query.zig`'s `Table.put`,
/// `txn_table.zig`'s `TableTxn.put`), the same "reparse on every use" cost
/// `table select`/`table join` already pay for their own expr text.
pub const CheckConstraintSpec = struct {
    name: []u8,
    source: []u8,
};

/// Persisted set of CHECK constraints on a table, at most one per name -
/// same on-disk shape family as `ForeignKeySet` (own meta key, own
/// namespace, two length-prefixed strings per entry).
pub const CheckConstraintSet = struct {
    allocator: Allocator,
    specs: std.ArrayList(CheckConstraintSpec),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !CheckConstraintSet {
        const key = try checkMetaKey(allocator, table);
        defer allocator.free(key);

        var set = CheckConstraintSet{ .allocator = allocator, .specs = std.ArrayList(CheckConstraintSpec).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const count = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const name = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(name);
            const source = try readLenPrefixed(allocator, raw, &pos);
            try set.specs.append(.{ .name = name, .source = source });
        }
        return set;
    }

    pub fn save(self: *const CheckConstraintSet, db: *Db, table: []const u8) !void {
        const key = try checkMetaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.specs.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.specs.items) |spec| {
            try appendLenPrefixed(&out, spec.name);
            try appendLenPrefixed(&out, spec.source);
        }
        try db.put(key, out.items);
    }

    pub fn has(self: *const CheckConstraintSet, name: []const u8) bool {
        return self.find(name) != null;
    }

    pub fn find(self: *const CheckConstraintSet, name: []const u8) ?CheckConstraintSpec {
        for (self.specs.items) |spec| {
            if (std.mem.eql(u8, spec.name, name)) return spec;
        }
        return null;
    }

    pub fn add(self: *CheckConstraintSet, name: []const u8, source: []const u8) !void {
        if (self.has(name)) return;
        const spec = CheckConstraintSpec{
            .name = try self.allocator.dupe(u8, name),
            .source = try self.allocator.dupe(u8, source),
        };
        try self.specs.append(spec);
    }

    /// Returns true if a constraint named `name` was present and has been
    /// removed.
    pub fn remove(self: *CheckConstraintSet, name: []const u8) bool {
        for (self.specs.items, 0..) |spec, i| {
            if (std.mem.eql(u8, spec.name, name)) {
                self.allocator.free(spec.name);
                self.allocator.free(spec.source);
                _ = self.specs.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *CheckConstraintSet) void {
        for (self.specs.items) |spec| {
            self.allocator.free(spec.name);
            self.allocator.free(spec.source);
        }
        self.specs.deinit();
    }
};

/// One reverse FOREIGN KEY entry, recorded on the REFERENCED table rather
/// than the referencing one: some other table `childTable` has a
/// `FOREIGN KEY (childField) REFERENCES <this table>(refField)`. This is
/// the registry `Table.createForeignKey`'s doc comment calls out as
/// missing ("tables are opened ad hoc by name and never catalogued
/// anywhere") - without it, deleting a parent row has no way to discover
/// which other tables might still be pointing at it, since `ForeignKeySet`
/// is only ever stored on the referencing (child) side.
pub const ReferencedBySpec = struct {
    childTable: []u8,
    childField: []u8,
    refField: []u8,
    onDelete: OnDelete,
};

/// Persisted set of reverse FK entries on a table - same on-disk shape
/// family as `ForeignKeySet` (own meta key, own namespace, three
/// length-prefixed strings plus an `onDelete` mode byte per entry), but
/// populated by a DIFFERENT table's `createForeignKey`/`dropForeignKey`
/// call rather than by mutations against this table directly. `onDelete`
/// is duplicated here rather than looked up from the child's own
/// `ForeignKeySet` on every delete, so `Table.delete`'s cascade planner
/// (see `query.zig`'s `planCascade`) can decide restrict-vs-cascade
/// without opening and loading the child a second time just to answer
/// that. `add` is keyed by the (childTable, childField) pair - a child
/// field can only ever carry one FOREIGN KEY (enforced by
/// `ForeignKeySet.has` at the child), so at most one reverse entry per
/// pair can ever be correct; re-adding the same pair (only reachable by
/// first dropping and recreating the child's constraint, possibly with a
/// different `refField`/`onDelete`) replaces it in place instead of
/// accumulating a stale duplicate.
pub const ReferencedBySet = struct {
    allocator: Allocator,
    specs: std.ArrayList(ReferencedBySpec),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !ReferencedBySet {
        const key = try referencedByMetaKey(allocator, table);
        defer allocator.free(key);

        var set = ReferencedBySet{ .allocator = allocator, .specs = std.ArrayList(ReferencedBySpec).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const count = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const childTable = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(childTable);
            const childField = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(childField);
            const refField = try readLenPrefixed(allocator, raw, &pos);
            errdefer allocator.free(refField);
            if (pos + 1 > raw.len) return error.Malformed;
            const onDelete = try onDeleteFromByte(raw[pos]);
            pos += 1;
            try set.specs.append(.{ .childTable = childTable, .childField = childField, .refField = refField, .onDelete = onDelete });
        }
        return set;
    }

    pub fn save(self: *const ReferencedBySet, db: *Db, table: []const u8) !void {
        const key = try referencedByMetaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.specs.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.specs.items) |spec| {
            try appendLenPrefixed(&out, spec.childTable);
            try appendLenPrefixed(&out, spec.childField);
            try appendLenPrefixed(&out, spec.refField);
            try out.append(@intFromEnum(spec.onDelete));
        }
        try db.put(key, out.items);
    }

    fn indexOf(self: *const ReferencedBySet, childTable: []const u8, childField: []const u8) ?usize {
        for (self.specs.items, 0..) |spec, i| {
            if (std.mem.eql(u8, spec.childTable, childTable) and std.mem.eql(u8, spec.childField, childField)) return i;
        }
        return null;
    }

    pub fn add(self: *ReferencedBySet, childTable: []const u8, childField: []const u8, refField: []const u8, onDelete: OnDelete) !void {
        const refFieldCopy = try self.allocator.dupe(u8, refField);
        errdefer self.allocator.free(refFieldCopy);
        if (self.indexOf(childTable, childField)) |i| {
            self.allocator.free(self.specs.items[i].refField);
            self.specs.items[i].refField = refFieldCopy;
            self.specs.items[i].onDelete = onDelete;
            return;
        }
        const spec = ReferencedBySpec{
            .childTable = try self.allocator.dupe(u8, childTable),
            .childField = try self.allocator.dupe(u8, childField),
            .refField = refFieldCopy,
            .onDelete = onDelete,
        };
        try self.specs.append(spec);
    }

    /// Returns true if a reverse entry for (childTable, childField) was
    /// present and has been removed.
    pub fn remove(self: *ReferencedBySet, childTable: []const u8, childField: []const u8) bool {
        const i = self.indexOf(childTable, childField) orelse return false;
        const spec = self.specs.items[i];
        self.allocator.free(spec.childTable);
        self.allocator.free(spec.childField);
        self.allocator.free(spec.refField);
        _ = self.specs.orderedRemove(i);
        return true;
    }

    pub fn deinit(self: *ReferencedBySet) void {
        for (self.specs.items) |spec| {
            self.allocator.free(spec.childTable);
            self.allocator.free(spec.childField);
            self.allocator.free(spec.refField);
        }
        self.specs.deinit();
    }
};

fn readLenPrefixed(allocator: Allocator, raw: []const u8, pos: *usize) ![]u8 {
    if (pos.* + 4 > raw.len) return error.Malformed;
    const len = std.mem.readInt(u32, raw[pos.*..][0..4], .little);
    pos.* += 4;
    if (pos.* + len > raw.len) return error.Malformed;
    const value = try allocator.dupe(u8, raw[pos.* .. pos.* + len]);
    pos.* += len;
    return value;
}

fn appendLenPrefixed(out: *std.ArrayList(u8), value: []const u8) !void {
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, @intCast(value.len), .little);
    try out.appendSlice(&lenBuf);
    try out.appendSlice(value);
}

/// One multi-column ("composite") index: a caller-chosen name (used as the
/// keyspace discriminator, so it must be a `validIdentifier` like a table or
/// field name) plus the ordered list of fields it indexes. Field order is
/// significant - it defines both the on-disk key layout and which leading
/// ("leftmost") prefix of columns a query can use for a narrowed lookup.
pub const CompositeIndexSpec = struct {
    name: []u8,
    fields: [][]u8,

    fn free(self: *const CompositeIndexSpec, allocator: Allocator) void {
        allocator.free(self.name);
        for (self.fields) |f| allocator.free(f);
        allocator.free(self.fields);
    }
};

/// Persisted set of composite indexes on a table, the multi-column
/// counterpart to `IndexSet`. Stored under a separate metadata key
/// ("CINDEXES" vs "INDEXES") so single-field and composite indexes never
/// share or shadow each other's schema record.
pub const CompositeIndexSet = struct {
    allocator: Allocator,
    specs: std.ArrayList(CompositeIndexSpec),

    pub fn load(allocator: Allocator, db: *Db, table: []const u8) !CompositeIndexSet {
        const key = try compositeMetaKey(allocator, table);
        defer allocator.free(key);

        var set = CompositeIndexSet{ .allocator = allocator, .specs = std.ArrayList(CompositeIndexSpec).init(allocator) };
        errdefer set.deinit();

        const raw = try db.get(allocator, key) orelse return set;
        defer allocator.free(raw);

        var pos: usize = 0;
        if (pos + 4 > raw.len) return error.Malformed;
        const specCount = std.mem.readInt(u32, raw[pos..][0..4], .little);
        pos += 4;
        var i: u32 = 0;
        while (i < specCount) : (i += 1) {
            if (pos + 4 > raw.len) return error.Malformed;
            const nameLen = std.mem.readInt(u32, raw[pos..][0..4], .little);
            pos += 4;
            if (pos + nameLen > raw.len) return error.Malformed;
            const name = try allocator.dupe(u8, raw[pos .. pos + nameLen]);
            errdefer allocator.free(name);
            pos += nameLen;

            if (pos + 4 > raw.len) return error.Malformed;
            const fieldCount = std.mem.readInt(u32, raw[pos..][0..4], .little);
            pos += 4;
            const fields = try allocator.alloc([]u8, fieldCount);
            var filled: usize = 0;
            errdefer {
                for (fields[0..filled]) |f| allocator.free(f);
                allocator.free(fields);
            }
            var j: u32 = 0;
            while (j < fieldCount) : (j += 1) {
                if (pos + 4 > raw.len) return error.Malformed;
                const len = std.mem.readInt(u32, raw[pos..][0..4], .little);
                pos += 4;
                if (pos + len > raw.len) return error.Malformed;
                fields[j] = try allocator.dupe(u8, raw[pos .. pos + len]);
                filled += 1;
                pos += len;
            }
            try set.specs.append(.{ .name = name, .fields = fields });
        }
        return set;
    }

    pub fn save(self: *const CompositeIndexSet, db: *Db, table: []const u8) !void {
        const key = try compositeMetaKey(self.allocator, table);
        defer self.allocator.free(key);

        var out = std.ArrayList(u8).init(self.allocator);
        defer out.deinit();
        var countBuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &countBuf, @intCast(self.specs.items.len), .little);
        try out.appendSlice(&countBuf);
        for (self.specs.items) |spec| {
            var lenBuf: [4]u8 = undefined;
            std.mem.writeInt(u32, &lenBuf, @intCast(spec.name.len), .little);
            try out.appendSlice(&lenBuf);
            try out.appendSlice(spec.name);

            std.mem.writeInt(u32, &lenBuf, @intCast(spec.fields.len), .little);
            try out.appendSlice(&lenBuf);
            for (spec.fields) |f| {
                std.mem.writeInt(u32, &lenBuf, @intCast(f.len), .little);
                try out.appendSlice(&lenBuf);
                try out.appendSlice(f);
            }
        }
        try db.put(key, out.items);
    }

    pub fn find(self: *const CompositeIndexSet, name: []const u8) ?*const CompositeIndexSpec {
        for (self.specs.items) |*s| {
            if (std.mem.eql(u8, s.name, name)) return s;
        }
        return null;
    }

    pub fn has(self: *const CompositeIndexSet, name: []const u8) bool {
        return self.find(name) != null;
    }

    pub fn add(self: *CompositeIndexSet, name: []const u8, fields: []const []const u8) !void {
        if (self.has(name)) return;
        const nameCopy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(nameCopy);

        const fieldsCopy = try self.allocator.alloc([]u8, fields.len);
        var filled: usize = 0;
        errdefer {
            for (fieldsCopy[0..filled]) |f| self.allocator.free(f);
            self.allocator.free(fieldsCopy);
        }
        for (fields, 0..) |f, i| {
            fieldsCopy[i] = try self.allocator.dupe(u8, f);
            filled += 1;
        }
        try self.specs.append(.{ .name = nameCopy, .fields = fieldsCopy });
    }

    /// Returns true if a composite index by that name was present and has
    /// been removed.
    pub fn remove(self: *CompositeIndexSet, name: []const u8) bool {
        for (self.specs.items, 0..) |*s, i| {
            if (std.mem.eql(u8, s.name, name)) {
                s.free(self.allocator);
                _ = self.specs.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *CompositeIndexSet) void {
        for (self.specs.items) |*s| s.free(self.allocator);
        self.specs.deinit();
    }
};

/// Adds one index entry mapping `value` -> `pk` under `table.field`. The
/// entry's stored value is the plain (non order-preserving) encoding of the
/// primary key, so lookups can recover the exact original Value instead of
/// re-parsing the escaped ordered key bytes.
pub fn addEntry(db: *Db, allocator: Allocator, table: []const u8, field: []const u8, value: Value, pk: Value) !void {
    const key = try indexEntryKey(allocator, table, field, value, pk);
    defer allocator.free(key);
    const pkBytes = try row.encodeValue(allocator, pk);
    defer allocator.free(pkBytes);
    try db.put(key, pkBytes);
}

pub fn removeEntry(db: *Db, allocator: Allocator, table: []const u8, field: []const u8, value: Value, pk: Value) !void {
    const key = try indexEntryKey(allocator, table, field, value, pk);
    defer allocator.free(key);
    try db.delete(key);
}

/// Deletes every index entry for `table.field`, used when dropping an index.
pub fn dropAllEntries(db: *Db, allocator: Allocator, table: []const u8, field: []const u8) !void {
    const prefix = try indexPrefix(allocator, table, field);
    defer allocator.free(prefix);

    var keys = std.ArrayList([]u8).init(allocator);
    defer {
        for (keys.items) |k| allocator.free(k);
        keys.deinit();
    }

    var it = try db.scanPrefix(allocator, prefix);
    defer it.deinit();
    while (try it.next()) |entry| {
        try keys.append(try allocator.dupe(u8, entry.key));
    }
    for (keys.items) |k| try db.delete(k);
}

/// Adds one composite index entry mapping the full `values` tuple -> `pk`
/// under `table`'s index `indexName`. Same stored-value convention as
/// `addEntry`: the plain (non order-preserving) pk encoding.
pub fn addCompositeEntry(db: *Db, allocator: Allocator, table: []const u8, indexName: []const u8, values: []const Value, pk: Value) !void {
    const key = try compositeIndexEntryKey(allocator, table, indexName, values, pk);
    defer allocator.free(key);
    const pkBytes = try row.encodeValue(allocator, pk);
    defer allocator.free(pkBytes);
    try db.put(key, pkBytes);
}

pub fn removeCompositeEntry(db: *Db, allocator: Allocator, table: []const u8, indexName: []const u8, values: []const Value, pk: Value) !void {
    const key = try compositeIndexEntryKey(allocator, table, indexName, values, pk);
    defer allocator.free(key);
    try db.delete(key);
}

/// Deletes every entry for a composite index, used when dropping it.
pub fn dropAllCompositeEntries(db: *Db, allocator: Allocator, table: []const u8, indexName: []const u8) !void {
    const prefix = try compositeIndexPrefix(allocator, table, indexName);
    defer allocator.free(prefix);

    var keys = std.ArrayList([]u8).init(allocator);
    defer {
        for (keys.items) |k| allocator.free(k);
        keys.deinit();
    }

    var it = try db.scanPrefix(allocator, prefix);
    defer it.deinit();
    while (try it.next()) |entry| {
        try keys.append(try allocator.dupe(u8, entry.key));
    }
    for (keys.items) |k| try db.delete(k);
}

/// Lazy cursor over a leftmost-prefix equality lookup on a composite index:
/// `valuesPrefix` may cover all of the index's columns or just a leading
/// subset of them. Streaming for the same reason as `EqCursor`.
pub const CompositeEqCursor = struct {
    it: dbmod.RangeIterator,

    pub fn next(self: *CompositeEqCursor, allocator: Allocator) !?Value {
        const entry = try self.it.next() orelse return null;
        return try row.decodeValue(allocator, entry.value);
    }

    pub fn deinit(self: *CompositeEqCursor) void {
        self.it.deinit();
    }
};

pub fn scanCompositeEqCursor(db: *Db, allocator: Allocator, table: []const u8, indexName: []const u8, valuesPrefix: []const Value) !CompositeEqCursor {
    const prefix = try compositeIndexValueBound(allocator, table, indexName, valuesPrefix);
    defer allocator.free(prefix);
    return .{ .it = try db.scanPrefix(allocator, prefix) };
}

/// Eager counterpart of `scanCompositeEqCursor`, all matching primary keys.
pub fn scanCompositeEq(db: *Db, allocator: Allocator, table: []const u8, indexName: []const u8, valuesPrefix: []const Value) ![]Value {
    var cursor = try scanCompositeEqCursor(db, allocator, table, indexName, valuesPrefix);
    defer cursor.deinit();

    var results = std.ArrayList(Value).init(allocator);
    errdefer {
        for (results.items) |v| v.free(allocator);
        results.deinit();
    }
    while (try cursor.next(allocator)) |pk| try results.append(pk);
    return results.toOwnedSlice();
}

/// Lazy cursor over a range lookup on the column immediately following a
/// leftmost-prefix of equality columns on a composite index: `eqValues`
/// pins the leading columns exactly like `CompositeEqCursor`, `low`/`high`
/// bound the next column. Columns beyond that one are left unconstrained by
/// the scan, same leftmost-prefix rule as the equality-only cursor.
pub const CompositeRangeCursor = struct {
    it: dbmod.RangeIterator,

    pub fn next(self: *CompositeRangeCursor, allocator: Allocator) !?Value {
        const entry = try self.it.next() orelse return null;
        return try row.decodeValue(allocator, entry.value);
    }

    pub fn deinit(self: *CompositeRangeCursor) void {
        self.it.deinit();
    }
};

pub fn scanCompositeRangeCursor(
    db: *Db,
    allocator: Allocator,
    table: []const u8,
    indexName: []const u8,
    eqValues: []const Value,
    low: ?Bound,
    high: ?Bound,
) !CompositeRangeCursor {
    const prefix = try compositeIndexValueBound(allocator, table, indexName, eqValues);
    defer allocator.free(prefix);

    var startBuf: ?[]u8 = null;
    defer if (startBuf) |b| allocator.free(b);
    var endBuf: ?[]u8 = null;
    defer if (endBuf) |b| allocator.free(b);

    // Same inclusive/exclusive gap trick as `scanRangeCursor`: a real entry
    // key is always `compositeIndexRangeBound(eqValues, value) ++ orderedPk`,
    // a strict byte-extension of the bare per-value bound (pk encodings are
    // never empty), so a key with value == threshold always sorts after
    // `compositeIndexRangeBound(eqValues, threshold)` itself.
    const start = if (low) |b| blk: {
        const bound = try compositeIndexRangeBound(allocator, table, indexName, eqValues, b.value);
        if (b.inclusive) {
            startBuf = bound;
        } else {
            defer allocator.free(bound);
            startBuf = try prefixUpperBound(allocator, bound) orelse try allocator.dupe(u8, bound);
        }
        break :blk startBuf.?;
    } else prefix;

    const end = if (high) |b| blk: {
        const bound = try compositeIndexRangeBound(allocator, table, indexName, eqValues, b.value);
        if (b.inclusive) {
            defer allocator.free(bound);
            endBuf = try prefixUpperBound(allocator, bound) orelse try allocator.dupe(u8, bound);
        } else {
            endBuf = bound;
        }
        break :blk endBuf.?;
    } else blk: {
        endBuf = try prefixUpperBound(allocator, prefix) orelse try allocator.dupe(u8, prefix);
        break :blk endBuf.?;
    };

    return .{ .it = try db.scanRange(allocator, .{
        .start = start,
        .end = end,
        .startInclusive = true,
        .endInclusive = false,
    }) };
}

/// Lazy cursor over an equality index lookup: decodes one primary key at a
/// time from the underlying `Db.RangeIterator` instead of materializing the
/// whole match set up front. This is what lets `Table.selectPage` honour a
/// small `limit` without reading and decoding every index entry for a value
/// that may have thousands of matches.
pub const EqCursor = struct {
    it: dbmod.RangeIterator,

    pub fn next(self: *EqCursor, allocator: Allocator) !?Value {
        const entry = try self.it.next() orelse return null;
        return try row.decodeValue(allocator, entry.value);
    }

    pub fn deinit(self: *EqCursor) void {
        self.it.deinit();
    }
};

/// Point lookup, streaming: opens the underlying scan but decodes nothing
/// until `EqCursor.next` is called.
pub fn scanEqCursor(db: *Db, allocator: Allocator, table: []const u8, field: []const u8, value: Value) !EqCursor {
    const prefix = try indexValueBound(allocator, table, field, value);
    defer allocator.free(prefix);
    return .{ .it = try db.scanPrefix(allocator, prefix) };
}

/// Point lookup: all primary keys currently indexed under `value`.
pub fn scanEq(db: *Db, allocator: Allocator, table: []const u8, field: []const u8, value: Value) ![]Value {
    var cursor = try scanEqCursor(db, allocator, table, field, value);
    defer cursor.deinit();

    var results = std.ArrayList(Value).init(allocator);
    errdefer {
        for (results.items) |v| v.free(allocator);
        results.deinit();
    }
    while (try cursor.next(allocator)) |pk| try results.append(pk);
    return results.toOwnedSlice();
}

pub const Bound = struct {
    value: Value,
    inclusive: bool,
};

/// Lazy cursor over a range index lookup, same rationale as `EqCursor`.
pub const RangeCursor = struct {
    it: dbmod.RangeIterator,

    pub fn next(self: *RangeCursor, allocator: Allocator) !?Value {
        const entry = try self.it.next() orelse return null;
        return try row.decodeValue(allocator, entry.value);
    }

    pub fn deinit(self: *RangeCursor) void {
        self.it.deinit();
    }
};

/// Range lookup over `table.field`'s index, streaming: primary keys whose
/// indexed value falls within [low, high] (either side may be open/null),
/// decoded one at a time as the caller consumes the cursor.
pub fn scanRangeCursor(
    db: *Db,
    allocator: Allocator,
    table: []const u8,
    field: []const u8,
    low: ?Bound,
    high: ?Bound,
) !RangeCursor {
    const prefix = try indexPrefix(allocator, table, field);
    defer allocator.free(prefix);

    var startBuf: ?[]u8 = null;
    defer if (startBuf) |b| allocator.free(b);
    var endBuf: ?[]u8 = null;
    defer if (endBuf) |b| allocator.free(b);

    // Every real index-entry key is `indexValueBound(value) ++ orderedPk`, a
    // strict byte-extension of the bare value bound (pk encodings are never
    // empty). So a key with value == threshold always compares greater than
    // `indexValueBound(threshold)` itself - inclusive/exclusive thresholds
    // are therefore expressed by choosing which side of that gap to start
    // or stop the scan at, not by the start/endInclusive flags.
    const start = if (low) |b| blk: {
        const bound = try indexValueBound(allocator, table, field, b.value);
        if (b.inclusive) {
            startBuf = bound;
        } else {
            defer allocator.free(bound);
            startBuf = try prefixUpperBound(allocator, bound) orelse try allocator.dupe(u8, bound);
        }
        break :blk startBuf.?;
    } else prefix;

    const end = if (high) |b| blk: {
        const bound = try indexValueBound(allocator, table, field, b.value);
        if (b.inclusive) {
            defer allocator.free(bound);
            endBuf = try prefixUpperBound(allocator, bound) orelse try allocator.dupe(u8, bound);
        } else {
            endBuf = bound;
        }
        break :blk endBuf.?;
    } else blk: {
        endBuf = try prefixUpperBound(allocator, prefix) orelse try allocator.dupe(u8, prefix);
        break :blk endBuf.?;
    };

    return .{ .it = try db.scanRange(allocator, .{
        .start = start,
        .end = end,
        .startInclusive = true,
        .endInclusive = false,
    }) };
}

/// Range lookup over `table.field`'s index: all primary keys whose indexed
/// value falls within [low, high] (either side may be open/null).
pub fn scanRange(
    db: *Db,
    allocator: Allocator,
    table: []const u8,
    field: []const u8,
    low: ?Bound,
    high: ?Bound,
) ![]Value {
    var cursor = try scanRangeCursor(db, allocator, table, field, low, high);
    defer cursor.deinit();

    var results = std.ArrayList(Value).init(allocator);
    errdefer {
        for (results.items) |v| v.free(allocator);
        results.deinit();
    }
    while (try cursor.next(allocator)) |pk| try results.append(pk);
    return results.toOwnedSlice();
}

test "rowKey and indexEntryKey stay within their own namespace" {
    const allocator = std.testing.allocator;
    const rk = try rowKey(allocator, "users", .{ .int = 1 });
    defer allocator.free(rk);
    const ik = try indexEntryKey(allocator, "users", "email", .{ .text = "a@b.c" }, .{ .int = 1 });
    defer allocator.free(ik);

    try std.testing.expectEqual(@as(u8, 'R'), rk[0]);
    try std.testing.expectEqual(@as(u8, 'I'), ik[0]);
}

test "prefixUpperBound bounds a prefix scan" {
    const allocator = std.testing.allocator;
    const upper = (try prefixUpperBound(allocator, "abc")).?;
    defer allocator.free(upper);
    try std.testing.expect(std.mem.order(u8, "abc", upper) == .lt);
    try std.testing.expect(std.mem.order(u8, "abd", upper) != .lt);
}

test "IndexSet add remove save load round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try IndexSet.load(allocator, &db, "users");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.fields.items.len);

    try set.add("email");
    try set.add("age");
    try set.add("email");
    try std.testing.expectEqual(@as(usize, 2), set.fields.items.len);
    try set.save(&db, "users");

    var reloaded = try IndexSet.load(allocator, &db, "users");
    defer reloaded.deinit();
    try std.testing.expect(reloaded.has("email"));
    try std.testing.expect(reloaded.has("age"));
    try std.testing.expect(!reloaded.has("missing"));

    try std.testing.expect(reloaded.remove("email"));
    try std.testing.expect(!reloaded.remove("email"));
    try reloaded.save(&db, "users");

    var third = try IndexSet.load(allocator, &db, "users");
    defer third.deinit();
    try std.testing.expect(!third.has("email"));
    try std.testing.expect(third.has("age"));
}

test "UniqueSet add remove save load round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try UniqueSet.load(allocator, &db, "users");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.fields.items.len);

    try set.add("email");
    try set.add("ssn");
    try set.add("email");
    try std.testing.expectEqual(@as(usize, 2), set.fields.items.len);
    try set.save(&db, "users");

    var reloaded = try UniqueSet.load(allocator, &db, "users");
    defer reloaded.deinit();
    try std.testing.expect(reloaded.has("email"));
    try std.testing.expect(reloaded.has("ssn"));
    try std.testing.expect(!reloaded.has("missing"));

    try std.testing.expect(reloaded.remove("email"));
    try std.testing.expect(!reloaded.remove("email"));
    try reloaded.save(&db, "users");

    var third = try UniqueSet.load(allocator, &db, "users");
    defer third.deinit();
    try std.testing.expect(!third.has("email"));
    try std.testing.expect(third.has("ssn"));
}

test "UniqueSet and IndexSet on the same table never collide, each keeps its own membership" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var indexes = try IndexSet.load(allocator, &db, "users");
    defer indexes.deinit();
    try indexes.add("email");
    try indexes.add("city");
    try indexes.save(&db, "users");

    var unique = try UniqueSet.load(allocator, &db, "users");
    defer unique.deinit();
    try unique.add("email");
    try unique.save(&db, "users");

    // "city" is indexed but not unique, "email" is both - the two sets
    // must agree on "email" and disagree on "city" after an independent
    // reload of each, proving neither save() overwrote the other's key.
    var reloadedIndexes = try IndexSet.load(allocator, &db, "users");
    defer reloadedIndexes.deinit();
    var reloadedUnique = try UniqueSet.load(allocator, &db, "users");
    defer reloadedUnique.deinit();

    try std.testing.expect(reloadedIndexes.has("email"));
    try std.testing.expect(reloadedIndexes.has("city"));
    try std.testing.expect(reloadedUnique.has("email"));
    try std.testing.expect(!reloadedUnique.has("city"));
}

test "ForeignKeySet add remove save load round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try ForeignKeySet.load(allocator, &db, "orders");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.specs.items.len);

    try set.add("customer_id", "customers", "__pk", .cascade);
    try set.add("customer_id", "customers", "some_other_field", .restrict);
    try std.testing.expectEqual(@as(usize, 1), set.specs.items.len);
    try set.save(&db, "orders");

    var reloaded = try ForeignKeySet.load(allocator, &db, "orders");
    defer reloaded.deinit();
    try std.testing.expect(reloaded.has("customer_id"));
    try std.testing.expect(!reloaded.has("missing"));
    const spec = reloaded.find("customer_id").?;
    try std.testing.expectEqualStrings("customers", spec.refTable);
    try std.testing.expectEqualStrings("__pk", spec.refField);
    // First `add` wins (mirrors `has` guard above) - `onDelete` survives the
    // save/load round trip as the mode from that first call, not the
    // no-op second one.
    try std.testing.expectEqual(OnDelete.cascade, spec.onDelete);

    try std.testing.expect(reloaded.remove("customer_id"));
    try std.testing.expect(!reloaded.remove("customer_id"));
    try reloaded.save(&db, "orders");

    var third = try ForeignKeySet.load(allocator, &db, "orders");
    defer third.deinit();
    try std.testing.expect(!third.has("customer_id"));
}

test "ForeignKeySet.load rejects a corrupted onDelete byte instead of accepting garbage" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try ForeignKeySet.load(allocator, &db, "orders");
    defer set.deinit();
    try set.add("customer_id", "customers", "__pk", .restrict);
    try set.save(&db, "orders");

    const key = try foreignKeyMetaKey(allocator, "orders");
    defer allocator.free(key);
    const raw = try db.get(allocator, key) orelse return error.TestUnexpectedResult;
    defer allocator.free(raw);

    // Flip the trailing onDelete byte to a value neither `restrict` (0)
    // nor `cascade` (1) can ever legitimately be - same "malformed input
    // is rejected, not silently coerced" contract every other decoder in
    // this file already gives length-prefixed strings.
    const corrupted = try allocator.dupe(u8, raw);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] = 0xFF;
    try db.put(key, corrupted);

    try std.testing.expectError(error.Malformed, ForeignKeySet.load(allocator, &db, "orders"));
}

test "ReferencedBySet add replaces an existing (childTable, childField) pair instead of duplicating it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try ReferencedBySet.load(allocator, &db, "customers");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.specs.items.len);

    try set.add("orders", "customer_id", "__pk", .restrict);
    try set.add("orders", "customer_id", "__pk", .restrict);
    try std.testing.expectEqual(@as(usize, 1), set.specs.items.len);
    try set.add("line_items", "customer_id", "__pk", .cascade);
    try std.testing.expectEqual(@as(usize, 2), set.specs.items.len);
    try set.save(&db, "customers");

    var reloaded = try ReferencedBySet.load(allocator, &db, "customers");
    defer reloaded.deinit();
    try std.testing.expectEqual(@as(usize, 2), reloaded.specs.items.len);
    for (reloaded.specs.items) |spec| {
        if (std.mem.eql(u8, spec.childTable, "line_items")) {
            try std.testing.expectEqual(OnDelete.cascade, spec.onDelete);
        } else {
            try std.testing.expectEqual(OnDelete.restrict, spec.onDelete);
        }
    }

    // Re-adding the same pair under a different refField AND onDelete mode
    // replaces both in place rather than accumulating a second, now-stale
    // entry.
    try reloaded.add("orders", "customer_id", "email", .cascade);
    try std.testing.expectEqual(@as(usize, 2), reloaded.specs.items.len);
    var sawOrders = false;
    for (reloaded.specs.items) |spec| {
        if (std.mem.eql(u8, spec.childTable, "orders")) {
            sawOrders = true;
            try std.testing.expectEqualStrings("email", spec.refField);
            try std.testing.expectEqual(OnDelete.cascade, spec.onDelete);
        }
    }
    try std.testing.expect(sawOrders);

    try std.testing.expect(reloaded.remove("orders", "customer_id"));
    try std.testing.expect(!reloaded.remove("orders", "customer_id"));
    try reloaded.save(&db, "customers");

    var third = try ReferencedBySet.load(allocator, &db, "customers");
    defer third.deinit();
    try std.testing.expectEqual(@as(usize, 1), third.specs.items.len);
    try std.testing.expectEqualStrings("line_items", third.specs.items[0].childTable);
}

test "CheckConstraintSet add remove save load round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try CheckConstraintSet.load(allocator, &db, "orders");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.specs.items.len);

    try set.add("qty_positive", "qty gt 0");
    try set.add("qty_positive", "qty gt 100");
    try std.testing.expectEqual(@as(usize, 1), set.specs.items.len);
    try set.save(&db, "orders");

    var reloaded = try CheckConstraintSet.load(allocator, &db, "orders");
    defer reloaded.deinit();
    try std.testing.expect(reloaded.has("qty_positive"));
    try std.testing.expect(!reloaded.has("missing"));
    const spec = reloaded.find("qty_positive").?;
    try std.testing.expectEqualStrings("qty gt 0", spec.source);

    try std.testing.expect(reloaded.remove("qty_positive"));
    try std.testing.expect(!reloaded.remove("qty_positive"));
    try reloaded.save(&db, "orders");

    var third = try CheckConstraintSet.load(allocator, &db, "orders");
    defer third.deinit();
    try std.testing.expect(!third.has("qty_positive"));
}

test "ForeignKeySet, UniqueSet, and IndexSet on the same table never collide" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var indexes = try IndexSet.load(allocator, &db, "orders");
    defer indexes.deinit();
    try indexes.add("customer_id");
    try indexes.save(&db, "orders");

    var unique = try UniqueSet.load(allocator, &db, "orders");
    defer unique.deinit();
    try unique.add("order_number");
    try unique.save(&db, "orders");

    var fkeys = try ForeignKeySet.load(allocator, &db, "orders");
    defer fkeys.deinit();
    try fkeys.add("customer_id", "customers", "__pk", .restrict);
    try fkeys.save(&db, "orders");

    var checks = try CheckConstraintSet.load(allocator, &db, "orders");
    defer checks.deinit();
    try checks.add("qty_positive", "qty gt 0");
    try checks.save(&db, "orders");

    var reloadedIndexes = try IndexSet.load(allocator, &db, "orders");
    defer reloadedIndexes.deinit();
    var reloadedUnique = try UniqueSet.load(allocator, &db, "orders");
    defer reloadedUnique.deinit();
    var reloadedFkeys = try ForeignKeySet.load(allocator, &db, "orders");
    defer reloadedFkeys.deinit();
    var reloadedChecks = try CheckConstraintSet.load(allocator, &db, "orders");
    defer reloadedChecks.deinit();

    try std.testing.expect(reloadedIndexes.has("customer_id"));
    try std.testing.expect(reloadedUnique.has("order_number"));
    try std.testing.expect(!reloadedUnique.has("customer_id"));
    try std.testing.expect(reloadedFkeys.has("customer_id"));
    try std.testing.expect(!reloadedFkeys.has("order_number"));
    try std.testing.expect(reloadedChecks.has("qty_positive"));
    try std.testing.expect(!reloadedChecks.has("customer_id"));
}

test "addEntry scanEq removeEntry round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    try addEntry(&db, allocator, "users", "city", .{ .text = "warsaw" }, .{ .int = 1 });
    try addEntry(&db, allocator, "users", "city", .{ .text = "warsaw" }, .{ .int = 2 });
    try addEntry(&db, allocator, "users", "city", .{ .text = "krakow" }, .{ .int = 3 });

    const warsawPks = try scanEq(&db, allocator, "users", "city", .{ .text = "warsaw" });
    defer {
        for (warsawPks) |v| v.free(allocator);
        allocator.free(warsawPks);
    }
    try std.testing.expectEqual(@as(usize, 2), warsawPks.len);

    try removeEntry(&db, allocator, "users", "city", .{ .text = "warsaw" }, .{ .int = 1 });
    const afterRemove = try scanEq(&db, allocator, "users", "city", .{ .text = "warsaw" });
    defer {
        for (afterRemove) |v| v.free(allocator);
        allocator.free(afterRemove);
    }
    try std.testing.expectEqual(@as(usize, 1), afterRemove.len);
    try std.testing.expectEqual(@as(i64, 2), afterRemove[0].int);
}

test "EqCursor streams the same pks as eager scanEq and can stop early" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var i: i64 = 0;
    while (i < 20) : (i += 1) {
        try addEntry(&db, allocator, "users", "city", .{ .text = "warsaw" }, .{ .int = i });
    }

    const eager = try scanEq(&db, allocator, "users", "city", .{ .text = "warsaw" });
    defer {
        for (eager) |v| v.free(allocator);
        allocator.free(eager);
    }
    try std.testing.expectEqual(@as(usize, 20), eager.len);

    // Pull only the first three through the cursor, then drop it: this must
    // neither read nor decode the remaining seventeen entries, and the
    // testing allocator would flag a leak if the partially-consumed
    // RangeIterator's resources were not released on an early deinit.
    var cursor = try scanEqCursor(&db, allocator, "users", "city", .{ .text = "warsaw" });
    defer cursor.deinit();
    var pulled = std.ArrayList(Value).init(allocator);
    defer {
        for (pulled.items) |v| v.free(allocator);
        pulled.deinit();
    }
    var n: usize = 0;
    while (n < 3) : (n += 1) {
        const pk = (try cursor.next(allocator)).?;
        try pulled.append(pk);
    }
    try std.testing.expectEqual(@as(usize, 3), pulled.items.len);
    for (pulled.items, 0..) |v, idx2| {
        try std.testing.expectEqual(eager[idx2].int, v.int);
    }
}

test "RangeCursor streams the same pks as eager scanRange and can stop early" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var i: i64 = 0;
    while (i < 30) : (i += 1) {
        try addEntry(&db, allocator, "events", "score", .{ .int = i }, .{ .int = i });
    }

    var cursor = try scanRangeCursor(&db, allocator, "events", "score", .{ .value = .{ .int = 5 }, .inclusive = true }, null);
    defer cursor.deinit();
    const first = (try cursor.next(allocator)).?;
    defer first.free(allocator);
    const second = (try cursor.next(allocator)).?;
    defer second.free(allocator);
    try std.testing.expectEqual(@as(i64, 5), first.int);
    try std.testing.expectEqual(@as(i64, 6), second.int);
    // cursor and its underlying iterator are dropped by `defer` here without
    // consuming the other 23 matches.
}

test "scanRange respects bounds and inclusivity" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var i: i64 = 0;
    while (i < 10) : (i += 1) {
        try addEntry(&db, allocator, "events", "score", .{ .int = i }, .{ .int = i });
    }

    const all = try scanRange(&db, allocator, "events", "score", null, null);
    defer {
        for (all) |v| v.free(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 10), all.len);

    const midInclusive = try scanRange(&db, allocator, "events", "score", .{ .value = .{ .int = 3 }, .inclusive = true }, .{ .value = .{ .int = 6 }, .inclusive = true });
    defer {
        for (midInclusive) |v| v.free(allocator);
        allocator.free(midInclusive);
    }
    try std.testing.expectEqual(@as(usize, 4), midInclusive.len);
    try std.testing.expectEqual(@as(i64, 3), midInclusive[0].int);
    try std.testing.expectEqual(@as(i64, 6), midInclusive[midInclusive.len - 1].int);

    const midExclusive = try scanRange(&db, allocator, "events", "score", .{ .value = .{ .int = 3 }, .inclusive = false }, .{ .value = .{ .int = 6 }, .inclusive = false });
    defer {
        for (midExclusive) |v| v.free(allocator);
        allocator.free(midExclusive);
    }
    try std.testing.expectEqual(@as(usize, 2), midExclusive.len);
    try std.testing.expectEqual(@as(i64, 4), midExclusive[0].int);
    try std.testing.expectEqual(@as(i64, 5), midExclusive[1].int);

    const openAbove = try scanRange(&db, allocator, "events", "score", .{ .value = .{ .int = 8 }, .inclusive = true }, null);
    defer {
        for (openAbove) |v| v.free(allocator);
        allocator.free(openAbove);
    }
    try std.testing.expectEqual(@as(usize, 2), openAbove.len);
}

test "CompositeIndexSet add remove save load round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var set = try CompositeIndexSet.load(allocator, &db, "users");
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 0), set.specs.items.len);

    try set.add("city_age", &.{ "city", "age" });
    try set.add("city_age", &.{ "city", "age" }); // no-op, already present
    try std.testing.expectEqual(@as(usize, 1), set.specs.items.len);
    try set.save(&db, "users");

    var reloaded = try CompositeIndexSet.load(allocator, &db, "users");
    defer reloaded.deinit();
    try std.testing.expect(reloaded.has("city_age"));
    const spec = reloaded.find("city_age").?;
    try std.testing.expectEqual(@as(usize, 2), spec.fields.len);
    try std.testing.expectEqualStrings("city", spec.fields[0]);
    try std.testing.expectEqualStrings("age", spec.fields[1]);

    try std.testing.expect(reloaded.remove("city_age"));
    try std.testing.expect(!reloaded.remove("city_age"));
    try reloaded.save(&db, "users");

    var third = try CompositeIndexSet.load(allocator, &db, "users");
    defer third.deinit();
    try std.testing.expect(!third.has("city_age"));
}

test "single-field and composite index metadata never shadow each other" {
    // Both live under the "M" tag with table-name-suffixed keys that differ
    // only in "INDEXES" vs "CINDEXES" - this pins down that they stay two
    // genuinely distinct Db keys, not one overwriting the other.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    var single = try IndexSet.load(allocator, &db, "users");
    defer single.deinit();
    try single.add("email");
    try single.save(&db, "users");

    var composite = try CompositeIndexSet.load(allocator, &db, "users");
    defer composite.deinit();
    try composite.add("city_age", &.{ "city", "age" });
    try composite.save(&db, "users");

    var singleReloaded = try IndexSet.load(allocator, &db, "users");
    defer singleReloaded.deinit();
    try std.testing.expect(singleReloaded.has("email"));

    var compositeReloaded = try CompositeIndexSet.load(allocator, &db, "users");
    defer compositeReloaded.deinit();
    try std.testing.expect(compositeReloaded.has("city_age"));
}

test "addCompositeEntry scanCompositeEq removeCompositeEntry round trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 30 } }, .{ .int = 1 });
    try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 40 } }, .{ .int = 2 });
    try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "krakow" }, .{ .int = 30 } }, .{ .int = 3 });

    // Full-tuple match: exactly one row.
    const exact = try scanCompositeEq(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 30 } });
    defer {
        for (exact) |v| v.free(allocator);
        allocator.free(exact);
    }
    try std.testing.expectEqual(@as(usize, 1), exact.len);
    try std.testing.expectEqual(@as(i64, 1), exact[0].int);

    // Leftmost-prefix match on just the first column: both warsaw rows,
    // never the krakow one, even though it wasn't constrained on age at all.
    const prefixMatch = try scanCompositeEq(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }});
    defer {
        for (prefixMatch) |v| v.free(allocator);
        allocator.free(prefixMatch);
    }
    try std.testing.expectEqual(@as(usize, 2), prefixMatch.len);

    try removeCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 30 } }, .{ .int = 1 });
    const afterRemove = try scanCompositeEq(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }});
    defer {
        for (afterRemove) |v| v.free(allocator);
        allocator.free(afterRemove);
    }
    try std.testing.expectEqual(@as(usize, 1), afterRemove.len);
    try std.testing.expectEqual(@as(i64, 2), afterRemove[0].int);
}

test "scanCompositeRangeCursor narrows on the column after the matched prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    // Two cities, ages 20..29 in each - the composite index is (city, age).
    var age: i64 = 20;
    while (age < 30) : (age += 1) {
        try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = age } }, .{ .int = age });
        try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "krakow" }, .{ .int = age } }, .{ .int = age + 100 });
    }

    // city == "warsaw" and 23 <= age <= 26: never crosses into krakow's
    // bucket even though its ages overlap byte-for-byte with warsaw's.
    var midCursor = try scanCompositeRangeCursor(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }}, .{ .value = .{ .int = 23 }, .inclusive = true }, .{ .value = .{ .int = 26 }, .inclusive = true });
    var midInclusive = std.ArrayList(Value).init(allocator);
    defer midInclusive.deinit();
    while (try midCursor.next(allocator)) |pk| try midInclusive.append(pk);
    midCursor.deinit();
    try std.testing.expectEqual(@as(usize, 4), midInclusive.items.len);
    try std.testing.expectEqual(@as(i64, 23), midInclusive.items[0].int);
    try std.testing.expectEqual(@as(i64, 26), midInclusive.items[midInclusive.items.len - 1].int);

    // Exclusive both sides: drops the two endpoints.
    var exclusive = try scanCompositeRangeCursor(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }}, .{ .value = .{ .int = 23 }, .inclusive = false }, .{ .value = .{ .int = 26 }, .inclusive = false });
    defer exclusive.deinit();
    const first = (try exclusive.next(allocator)).?;
    defer first.free(allocator);
    const second = (try exclusive.next(allocator)).?;
    defer second.free(allocator);
    try std.testing.expectEqual(@as(i64, 24), first.int);
    try std.testing.expectEqual(@as(i64, 25), second.int);
    try std.testing.expectEqual(@as(?Value, null), try exclusive.next(allocator));

    // Open above: age >= 28 within warsaw only, never touching krakow.
    var openAbove = try scanCompositeRangeCursor(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }}, .{ .value = .{ .int = 28 }, .inclusive = true }, null);
    defer openAbove.deinit();
    const a1 = (try openAbove.next(allocator)).?;
    defer a1.free(allocator);
    const a2 = (try openAbove.next(allocator)).?;
    defer a2.free(allocator);
    try std.testing.expectEqual(@as(i64, 28), a1.int);
    try std.testing.expectEqual(@as(i64, 29), a2.int);
    try std.testing.expectEqual(@as(?Value, null), try openAbove.next(allocator));
}

test "dropAllCompositeEntries clears an index without touching another one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dbPath = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dbPath);

    var db = try Db.open(allocator, dbPath, .{});
    defer db.close();

    try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 30 } }, .{ .int = 1 });
    try addCompositeEntry(&db, allocator, "users", "other_idx", &.{ .{ .int = 1 }, .{ .int = 2 } }, .{ .int = 1 });

    try dropAllCompositeEntries(&db, allocator, "users", "city_age");

    const cityAge = try scanCompositeEq(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }});
    defer {
        for (cityAge) |v| v.free(allocator);
        allocator.free(cityAge);
    }
    try std.testing.expectEqual(@as(usize, 0), cityAge.len);

    const other = try scanCompositeEq(&db, allocator, "users", "other_idx", &.{.{ .int = 1 }});
    defer {
        for (other) |v| v.free(allocator);
        allocator.free(other);
    }
    try std.testing.expectEqual(@as(usize, 1), other.len);
}
