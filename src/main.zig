const std = @import("std");
const cobalt = @import("root.zig");

const usage =
    \\cobalt - LSM key/value store
    \\
    \\usage: cobalt <dir> <command> [args]
    \\
    \\commands:
    \\  put <key> <value>        store a value
    \\  get <key>                print a value or (nil)
    \\  del <key>                delete a key
    \\  scan [start] [end]       forward range scan, start inclusive, end exclusive
    \\  rscan [start] [end]      reverse range scan
    \\  prefix <prefix>          scan every key under a prefix
    \\  compact                  run full leveled compaction
    \\  stats                    print database statistics
    \\  verify <n>               write n keys, reopen, check durability and scan order
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len < 3) {
        try stderr.writeAll(usage);
        std.process.exit(2);
    }

    const dir = argv[1];
    const command = argv[2];
    const rest = argv[3..];

    if (std.mem.eql(u8, command, "verify")) {
        const count = if (rest.len >= 1) std.fmt.parseInt(usize, rest[0], 10) catch 1000 else 1000;
        try runVerify(allocator, stdout, dir, count);
        return;
    }

    var db = try cobalt.Db.open(allocator, dir, .{});
    defer db.close();

    if (std.mem.eql(u8, command, "put")) {
        if (rest.len < 2) return fail(stderr, "put needs <key> <value>");
        try db.put(rest[0], rest[1]);
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "get")) {
        if (rest.len < 1) return fail(stderr, "get needs <key>");
        if (try db.get(allocator, rest[0])) |value| {
            defer allocator.free(value);
            try stdout.print("{s}\n", .{value});
        } else {
            try stdout.writeAll("(nil)\n");
        }
    } else if (std.mem.eql(u8, command, "del")) {
        if (rest.len < 1) return fail(stderr, "del needs <key>");
        try db.delete(rest[0]);
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "scan")) {
        const start: ?[]const u8 = if (rest.len >= 1) rest[0] else null;
        const end: ?[]const u8 = if (rest.len >= 2) rest[1] else null;
        var iter = try db.scan(allocator, start, end);
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "rscan")) {
        const start: ?[]const u8 = if (rest.len >= 1) rest[0] else null;
        const end: ?[]const u8 = if (rest.len >= 2) rest[1] else null;
        var iter = try db.scanReverse(allocator, .{ .start = start, .end = end });
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "prefix")) {
        if (rest.len < 1) return fail(stderr, "prefix needs <prefix>");
        var iter = try db.scanPrefix(allocator, rest[0]);
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "compact")) {
        try db.compact();
        try stdout.print("sstables after compaction: {d}\n", .{db.sstables.items.len});
    } else if (std.mem.eql(u8, command, "stats")) {
        try db.stats().print(stdout);
    } else {
        try stderr.print("unknown command: {s}\n", .{command});
        try stderr.writeAll(usage);
        std.process.exit(2);
    }
}

fn fail(stderr: anytype, message: []const u8) !void {
    try stderr.print("error: {s}\n", .{message});
    std.process.exit(2);
}

fn runVerify(allocator: std.mem.Allocator, stdout: anytype, dir: []const u8, count: usize) !void {
    std.fs.cwd().deleteTree(dir) catch {};

    var reference = std.ArrayList([]u8).init(allocator);
    defer {
        for (reference.items) |value| allocator.free(value);
        reference.deinit();
    }

    {
        var db = try cobalt.Db.open(allocator, dir, .{ .flushThreshold = 16 * 1024, .sstableTargetBytes = 8 * 1024 });
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
        try stdout.print("wrote {d} keys, sstables on disk: {d}\n", .{ count, db.sstables.items.len });
    }

    try stdout.writeAll("process state dropped, reopening from disk...\n");

    var db = try cobalt.Db.open(allocator, dir, .{ .flushThreshold = 16 * 1024, .sstableTargetBytes = 8 * 1024 });
    defer db.close();

    var readOk: usize = 0;
    var keyBuf: [24]u8 = undefined;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>10}", .{i});
        const got = (try db.get(allocator, key)) orelse {
            try stdout.print("FAIL: missing key {s} after restart\n", .{key});
            std.process.exit(1);
        };
        defer allocator.free(got);
        if (!std.mem.eql(u8, got, reference.items[i])) {
            try stdout.print("FAIL: value mismatch for {s}\n", .{key});
            std.process.exit(1);
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

    try stdout.print("point reads ok:   {d}/{d}\n", .{ readOk, count });
    try stdout.print("forward scan:     {d} entries, sortedOrder={}\n", .{ scanned, ordered });
    try stdout.print("reverse scan:     {d} entries, descendingOrder={}\n", .{ reverseCount, reverseOrdered });
    if (count > 110) try stdout.print("range [100,110):  {d} entries (expected 10)\n", .{rangeCount});

    const pass = readOk == count and scanned == count and reverseCount == count and ordered and reverseOrdered and (count <= 110 or rangeCount == 10);
    try stdout.print("\nRESULT: {s}\n", .{if (pass) "PASS - all keys durable, scans consistent with reference" else "FAIL"});
    if (!pass) std.process.exit(1);
}
