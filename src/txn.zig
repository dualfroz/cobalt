const std = @import("std");
const encode = @import("encode.zig");
const dbmod = @import("db.zig");
const WriteBatch = @import("batch.zig").WriteBatch;

const Allocator = std.mem.Allocator;
const Kind = encode.Kind;
const Db = dbmod.Db;

const BufferedWrite = struct {
    kind: Kind,
    value: []u8,
};

pub const Transaction = struct {
    db: *Db,
    allocator: Allocator,
    snapshotSeq: u64,
    reads: std.StringHashMap(void),
    writes: std.StringHashMap(BufferedWrite),
    finished: bool,

    pub fn begin(db: *Db) Transaction {
        return .{
            .db = db,
            .allocator = db.allocator,
            .snapshotSeq = if (db.nextSeq == 0) 0 else db.nextSeq - 1,
            .reads = std.StringHashMap(void).init(db.allocator),
            .writes = std.StringHashMap(BufferedWrite).init(db.allocator),
            .finished = false,
        };
    }

    pub fn deinit(self: *Transaction) void {
        var readKeys = self.reads.keyIterator();
        while (readKeys.next()) |key| self.allocator.free(key.*);
        self.reads.deinit();

        var writeEntries = self.writes.iterator();
        while (writeEntries.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.writes.deinit();
    }

    pub fn get(self: *Transaction, allocator: Allocator, key: []const u8) !?[]u8 {
        if (self.writes.get(key)) |buffered| {
            if (buffered.kind == .tombstone) return null;
            return try allocator.dupe(u8, buffered.value);
        }
        try self.recordRead(key);
        return self.db.getAsOf(allocator, key, self.snapshotSeq);
    }

    pub fn put(self: *Transaction, key: []const u8, value: []const u8) !void {
        try self.stage(.value, key, value);
    }

    pub fn delete(self: *Transaction, key: []const u8) !void {
        try self.stage(.tombstone, key, &.{});
    }

    fn stage(self: *Transaction, kind: Kind, key: []const u8, value: []const u8) !void {
        const valueCopy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(valueCopy);
        const gop = try self.writes.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.value);
            gop.value_ptr.* = .{ .kind = kind, .value = valueCopy };
            return;
        }
        gop.key_ptr.* = try self.allocator.dupe(u8, key);
        gop.value_ptr.* = .{ .kind = kind, .value = valueCopy };
    }

    fn recordRead(self: *Transaction, key: []const u8) !void {
        if (self.reads.contains(key)) return;
        const keyCopy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(keyCopy);
        try self.reads.put(keyCopy, {});
    }

    pub fn commit(self: *Transaction) !void {
        var readKeys = self.reads.keyIterator();
        while (readKeys.next()) |key| {
            if (self.db.latestSeq(key.*)) |seq| {
                if (seq > self.snapshotSeq) return error.Conflict;
            }
        }

        var batch = WriteBatch.init(self.allocator);
        defer batch.deinit();
        var writeEntries = self.writes.iterator();
        while (writeEntries.next()) |entry| {
            switch (entry.value_ptr.kind) {
                .value => try batch.put(entry.key_ptr.*, entry.value_ptr.value),
                .tombstone => try batch.delete(entry.key_ptr.*),
            }
        }
        try self.db.apply(&batch);
        self.finished = true;
    }
};

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    var pathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathBuf);
    var dbPathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const dbPath = try std.fmt.bufPrint(&dbPathBuf, "{s}/store", .{base});
    return Db.open(allocator, dbPath, .{});
}

test "transaction commits buffered writes atomically" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try txn.put("alpha", "1");
    try txn.put("bravo", "2");
    try txn.delete("alpha");

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "bravo"));

    try txn.commit();

    const bravo = (try db.get(allocator, "bravo")).?;
    defer allocator.free(bravo);
    try std.testing.expectEqualStrings("2", bravo);
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "alpha"));
}

test "transaction reads its own writes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try txn.put("k", "staged");
    const staged = (try txn.get(allocator, "k")).?;
    defer allocator.free(staged);
    try std.testing.expectEqualStrings("staged", staged);

    try txn.delete("k");
    try std.testing.expectEqual(@as(?[]u8, null), try txn.get(allocator, "k"));
}

test "conflicting commit is rejected but clean commit succeeds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("balance", "100");

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    const seen = (try txn.get(allocator, "balance")).?;
    defer allocator.free(seen);
    try std.testing.expectEqualStrings("100", seen);

    try db.put("balance", "external");

    try txn.put("balance", "150");
    try std.testing.expectError(error.Conflict, txn.commit());

    var clean = Transaction.begin(&db);
    defer clean.deinit();
    const current = (try clean.get(allocator, "balance")).?;
    defer allocator.free(current);
    try clean.put("note", "ok");
    try clean.commit();

    const note = (try db.get(allocator, "note")).?;
    defer allocator.free(note);
    try std.testing.expectEqualStrings("ok", note);
}
