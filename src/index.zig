const std = @import("std");
const dbmod = @import("db.zig");
const row = @import("row.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Value = row.Value;

pub const rowTag: u8 = 0xF6;
pub const indexTag: u8 = 0xF7;
pub const compositeIndexTag: u8 = 0xF8;
pub const metaTag: u8 = 0xF9;
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

pub fn compositeIndexValueBound(allocator: Allocator, table: []const u8, indexName: []const u8, values: []const Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(compositeIndexTag);
    try appendSegment(&out, table);
    try appendSegment(&out, indexName);
    for (values) |v| try row.appendOrdered(&out, v);
    return out.toOwnedSlice();
}

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

pub fn prefixUpperBound(allocator: Allocator, prefix: []const u8) !?[]u8 {
    var end = prefix.len;
    while (end > 0 and prefix[end - 1] == 0xff) end -= 1;
    if (end == 0) return null;
    const upper = try allocator.alloc(u8, end);
    @memcpy(upper, prefix[0..end]);
    upper[end - 1] += 1;
    return upper;
}

pub fn validIdentifier(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c == sep) return false;
    }
    return true;
}

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

pub const CheckConstraintSpec = struct {
    name: []u8,
    source: []u8,
};

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

pub const ReferencedBySpec = struct {
    childTable: []u8,
    childField: []u8,
    refField: []u8,
    onDelete: OnDelete,
};

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

pub const CompositeIndexSpec = struct {
    name: []u8,
    fields: [][]u8,

    fn free(self: *const CompositeIndexSpec, allocator: Allocator) void {
        allocator.free(self.name);
        for (self.fields) |f| allocator.free(f);
        allocator.free(self.fields);
    }
};

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

pub fn scanEqCursor(db: *Db, allocator: Allocator, table: []const u8, field: []const u8, value: Value) !EqCursor {
    const prefix = try indexValueBound(allocator, table, field, value);
    defer allocator.free(prefix);
    return .{ .it = try db.scanPrefix(allocator, prefix) };
}

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

    try std.testing.expectEqual(rowTag, rk[0]);
    try std.testing.expectEqual(indexTag, ik[0]);
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
    try set.add("city_age", &.{ "city", "age" });
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

    const exact = try scanCompositeEq(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = 30 } });
    defer {
        for (exact) |v| v.free(allocator);
        allocator.free(exact);
    }
    try std.testing.expectEqual(@as(usize, 1), exact.len);
    try std.testing.expectEqual(@as(i64, 1), exact[0].int);

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

    var age: i64 = 20;
    while (age < 30) : (age += 1) {
        try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "warsaw" }, .{ .int = age } }, .{ .int = age });
        try addCompositeEntry(&db, allocator, "users", "city_age", &.{ .{ .text = "krakow" }, .{ .int = age } }, .{ .int = age + 100 });
    }

    var midCursor = try scanCompositeRangeCursor(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }}, .{ .value = .{ .int = 23 }, .inclusive = true }, .{ .value = .{ .int = 26 }, .inclusive = true });
    var midInclusive = std.ArrayList(Value).init(allocator);
    defer midInclusive.deinit();
    while (try midCursor.next(allocator)) |pk| try midInclusive.append(pk);
    midCursor.deinit();
    try std.testing.expectEqual(@as(usize, 4), midInclusive.items.len);
    try std.testing.expectEqual(@as(i64, 23), midInclusive.items[0].int);
    try std.testing.expectEqual(@as(i64, 26), midInclusive.items[midInclusive.items.len - 1].int);

    var exclusive = try scanCompositeRangeCursor(&db, allocator, "users", "city_age", &.{.{ .text = "warsaw" }}, .{ .value = .{ .int = 23 }, .inclusive = false }, .{ .value = .{ .int = 26 }, .inclusive = false });
    defer exclusive.deinit();
    const first = (try exclusive.next(allocator)).?;
    defer first.free(allocator);
    const second = (try exclusive.next(allocator)).?;
    defer second.free(allocator);
    try std.testing.expectEqual(@as(i64, 24), first.int);
    try std.testing.expectEqual(@as(i64, 25), second.int);
    try std.testing.expectEqual(@as(?Value, null), try exclusive.next(allocator));

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
