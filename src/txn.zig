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

    /// One key/value pair from `scanPrefix`, owned by the caller (free with
    /// `freeEntries`).
    pub const Entry = struct {
        key: []u8,
        value: []u8,

        fn free(self: Entry, allocator: Allocator) void {
            allocator.free(self.key);
            allocator.free(self.value);
        }
    };

    pub fn freeEntries(allocator: Allocator, entries: []Entry) void {
        for (entries) |e| e.free(allocator);
        allocator.free(entries);
    }

    /// Prefix scan that reflects this transaction's own uncommitted writes,
    /// the same read-your-writes promise `get` makes for a single key
    /// extended to a whole key range: a row staged here shadows whatever the
    /// committed snapshot has under that exact key (a staged tombstone hides
    /// it entirely, a staged value replaces it), and a brand-new key staged
    /// here that falls under `prefix` shows up even though the underlying
    /// `Db` has never durably seen it. Every entry the underlying snapshot
    /// contributes is also recorded as a read for OCC purposes, same as
    /// `get` - a concurrent external write to one of those existing keys
    /// between now and `commit()` is still caught as `error.Conflict`. A
    /// concurrent external INSERT of a brand-new key under `prefix` is not
    /// caught (there is no key to register a read against before it
    /// exists) - the same phantom-read gap every OCC scheme without
    /// range-locks has, not something specific to this method.
    pub fn scanPrefix(self: *Transaction, allocator: Allocator, prefix: []const u8) ![]Entry {
        var results = std.ArrayList(Entry).init(allocator);
        errdefer {
            for (results.items) |e| e.free(allocator);
            results.deinit();
        }

        var it = try self.db.scanPrefixAsOf(allocator, prefix, self.snapshotSeq);
        defer it.deinit();
        while (try it.next()) |entry| {
            if (self.writes.contains(entry.key)) continue;
            try self.recordRead(entry.key);
            try results.append(.{ .key = try allocator.dupe(u8, entry.key), .value = try allocator.dupe(u8, entry.value) });
        }

        var writeEntries = self.writes.iterator();
        while (writeEntries.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            if (entry.value_ptr.kind == .tombstone) continue;
            try results.append(.{ .key = try allocator.dupe(u8, entry.key_ptr.*), .value = try allocator.dupe(u8, entry.value_ptr.value) });
        }

        return results.toOwnedSlice();
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

test "scanPrefix sees committed rows and a staged brand-new key under the same prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("idx:a", "1");
    try db.put("idx:b", "2");
    try db.put("other:z", "9");

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try txn.put("idx:c", "3");

    const entries = try txn.scanPrefix(allocator, "idx:");
    defer Transaction.freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 3), entries.len);

    var seenC = false;
    for (entries) |e| {
        if (std.mem.eql(u8, e.key, "idx:c")) {
            try std.testing.expectEqualStrings("3", e.value);
            seenC = true;
        }
    }
    try std.testing.expect(seenC);
}

test "scanPrefix shadows a committed key with its staged replacement and hides a staged tombstone" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("idx:a", "old-a");
    try db.put("idx:b", "old-b");

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    try txn.put("idx:a", "new-a");
    try txn.delete("idx:b");

    const entries = try txn.scanPrefix(allocator, "idx:");
    defer Transaction.freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("idx:a", entries[0].key);
    try std.testing.expectEqualStrings("new-a", entries[0].value);
}

test "scanPrefix registers committed keys as reads, so a concurrent external write under it still conflicts at commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    try db.put("idx:a", "1");

    var txn = Transaction.begin(&db);
    defer txn.deinit();
    const entries = try txn.scanPrefix(allocator, "idx:");
    Transaction.freeEntries(allocator, entries);

    try db.put("idx:a", "external-change");

    try txn.put("unrelated", "1");
    try std.testing.expectError(error.Conflict, txn.commit());
}
