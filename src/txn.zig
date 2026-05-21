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
