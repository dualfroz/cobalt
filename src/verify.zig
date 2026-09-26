const std = @import("std");
const dbmod = @import("db.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;

const verifyOptions = dbmod.Options{ .flushThreshold = 16 * 1024, .sstableTargetBytes = 8 * 1024 };

pub fn createScratchDir(allocator: Allocator, parentPath: []const u8) ![]u8 {
    var suffix: [8]u8 = undefined;
    std.crypto.random.bytes(&suffix);
    const name = try std.fmt.allocPrint(allocator, "cobalt-verify-{s}", .{std.fmt.fmtSliceHexLower(&suffix)});
    defer allocator.free(name);
    const path = try std.fs.path.join(allocator, &.{ parentPath, name });
    errdefer allocator.free(path);
    try std.fs.cwd().makeDir(path);
    return path;
}

pub fn run(allocator: Allocator, writer: anytype, parentPath: []const u8, count: usize) !bool {
    const scratchPath = try createScratchDir(allocator, parentPath);
    defer allocator.free(scratchPath);
    defer std.fs.cwd().deleteTree(scratchPath) catch {};
    try writer.print("scratch directory: {s} (removed afterwards)\n", .{scratchPath});
    return checkDurability(allocator, writer, scratchPath, count);
}

fn checkDurability(allocator: Allocator, writer: anytype, dirPath: []const u8, count: usize) !bool {
    var reference = std.ArrayList([]u8).init(allocator);
    defer {
        for (reference.items) |value| allocator.free(value);
        reference.deinit();
    }

    {
        var db = try Db.open(allocator, dirPath, verifyOptions);
        defer db.close();
        var keyBuf: [24]u8 = undefined;
        var valBuf: [32]u8 = undefined;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>10}", .{i});
            const value = try std.fmt.bufPrint(&valBuf, "value-{d:0>10}-payload", .{i});
            try db.put(key, value);
            try reference.append(try allocator.dupe(u8, value));
        }
        try db.maybeCompact();
        try writer.print("wrote {d} keys, sstables on disk: {d}\n", .{ count, db.sstables.items.len });
    }

    try writer.writeAll("process state dropped, reopening from disk...\n");

    var db = try Db.open(allocator, dirPath, verifyOptions);
    defer db.close();

    var readOk: usize = 0;
    var keyBuf: [24]u8 = undefined;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>10}", .{i});
        const got = (try db.get(allocator, key)) orelse {
            try writer.print("FAIL: missing key {s} after restart\n", .{key});
            return false;
        };
        defer allocator.free(got);
        if (!std.mem.eql(u8, got, reference.items[i])) {
            try writer.print("FAIL: value mismatch for {s}\n", .{key});
            return false;
        }
        readOk += 1;
    }

    var scanned: usize = 0;
    var prev: [24]u8 = undefined;
    var prevLen: usize = 0;
    var ordered = true;
    var iter = try db.scan(allocator, null, null);
    defer iter.deinit();
    while (try iter.next()) |entry| {
        if (prevLen > 0 and !std.mem.lessThan(u8, prev[0..prevLen], entry.key)) ordered = false;
        @memcpy(prev[0..entry.key.len], entry.key);
        prevLen = entry.key.len;
        scanned += 1;
    }

    var rev = try db.scanReverse(allocator, .{});
    defer rev.deinit();
    var reverseCount: usize = 0;
    var revPrevLen: usize = 0;
    var revPrev: [24]u8 = undefined;
    var reverseOrdered = true;
    while (try rev.next()) |entry| {
        if (revPrevLen > 0 and !std.mem.lessThan(u8, entry.key, revPrev[0..revPrevLen])) reverseOrdered = false;
        @memcpy(revPrev[0..entry.key.len], entry.key);
        revPrevLen = entry.key.len;
        reverseCount += 1;
    }

    const rangeLow = "key:0000000100";
    const rangeHigh = "key:0000000110";
    var rangeCount: usize = 0;
    if (count > 110) {
        var range = try db.scan(allocator, rangeLow, rangeHigh);
        defer range.deinit();
        while (try range.next()) |_| rangeCount += 1;
    }

    try writer.print("point reads ok:   {d}/{d}\n", .{ readOk, count });
    try writer.print("forward scan:     {d} entries, sortedOrder={}\n", .{ scanned, ordered });
    try writer.print("reverse scan:     {d} entries, descendingOrder={}\n", .{ reverseCount, reverseOrdered });
    if (count > 110) try writer.print("range [100,110):  {d} entries (expected 10)\n", .{rangeCount});

    const pass = readOk == count and scanned == count and reverseCount == count and ordered and reverseOrdered and (count <= 110 or rangeCount == 10);
    try writer.print("\nRESULT: {s}\n", .{if (pass) "PASS - all keys durable, scans consistent with reference" else "FAIL"});
    return pass;
}

test "verify runs in its own scratch directory and leaves a live store next to it untouched" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const storePath = try std.fs.path.join(allocator, &.{ root, "store" });
    defer allocator.free(storePath);

    var db = try Db.open(allocator, storePath, .{});
    defer db.close();
    try db.put("user:1", "alice");

    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();
    try std.testing.expect(try run(allocator, output.writer(), root, 150));
    try std.testing.expect(std.mem.indexOf(u8, output.items, "RESULT: PASS") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.items, "range [100,110):  10 entries") != null);

    const kept = (try db.get(allocator, "user:1")).?;
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("alice", kept);

    var names = tmp.dir.iterate();
    var entryCount: usize = 0;
    while (try names.next()) |entry| {
        try std.testing.expectEqualStrings("store", entry.name);
        entryCount += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), entryCount);
}

test "createScratchDir makes a new empty directory on every call" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const first = try createScratchDir(allocator, root);
    defer allocator.free(first);
    const second = try createScratchDir(allocator, root);
    defer allocator.free(second);

    try std.testing.expect(!std.mem.eql(u8, first, second));
    try std.testing.expectEqualStrings(root, std.fs.path.dirname(first).?);
    for ([_][]const u8{ first, second }) |path| {
        var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
        defer dir.close();
        var it = dir.iterate();
        try std.testing.expectEqual(@as(?std.fs.Dir.Entry, null), try it.next());
    }
}
