const std = @import("std");
const cobalt = @import("root.zig");

fn throughput(ops: usize, elapsedNs: u64) f64 {
    const seconds = @as(f64, @floatFromInt(elapsedNs)) / std.time.ns_per_s;
    if (seconds == 0) return 0;
    return @as(f64, @floatFromInt(ops)) / seconds;
}

fn report(writer: anytype, label: []const u8, ops: usize, elapsedNs: u64) !void {
    const ms = @as(f64, @floatFromInt(elapsedNs)) / std.time.ns_per_ms;
    try writer.print("{s:<14} {d:>9} ops in {d:>9.2} ms  =>  {d:>12.0} ops/s\n", .{ label, ops, ms, throughput(ops, elapsedNs) });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    var opCount: usize = 100_000;
    {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();
        _ = args.next();
        if (args.next()) |arg| opCount = std.fmt.parseInt(usize, arg, 10) catch opCount;
    }

    const dataDir = "cobalt-bench-data";
    std.fs.cwd().deleteTree(dataDir) catch {};
    defer std.fs.cwd().deleteTree(dataDir) catch {};

    var db = try cobalt.Db.open(allocator, dataDir, .{ .flushThreshold = 1024 * 1024 });
    defer db.close();

    try stdout.print("== cobalt benchmark ==\n", .{});
    try stdout.print("operations: {d}, deterministic keys\n\n", .{opCount});

    var keyBuf: [32]u8 = undefined;
    var valBuf: [96]u8 = undefined;
    var timer = try std.time.Timer.start();

    var i: usize = 0;
    while (i < opCount) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>12}", .{i});
        const value = try std.fmt.bufPrint(&valBuf, "value-{d:0>12}-cobalt-lsm-payload", .{i});
        try db.put(key, value);
    }
    try report(stdout, "put", opCount, timer.read());

    const batchSize = 1000;
    timer.reset();
    var batched: usize = 0;
    while (batched < opCount) : (batched += batchSize) {
        var batch = cobalt.WriteBatch.init(allocator);
        defer batch.deinit();
        var j: usize = 0;
        while (j < batchSize and batched + j < opCount) : (j += 1) {
            const idx = opCount + batched + j;
            const key = try std.fmt.bufPrint(&keyBuf, "bat:{d:0>12}", .{idx});
            const value = try std.fmt.bufPrint(&valBuf, "value-{d:0>12}-cobalt-lsm-payload", .{idx});
            try batch.put(key, value);
        }
        try db.apply(&batch);
    }
    try report(stdout, "batch-put", opCount, timer.read());

    timer.reset();
    try db.maybeCompact();
    try report(stdout, "compact", db.sstables.items.len, timer.read());

    timer.reset();
    var found: usize = 0;
    i = 0;
    while (i < opCount) : (i += 1) {
        const key = try std.fmt.bufPrint(&keyBuf, "key:{d:0>12}", .{i});
        if (try db.get(allocator, key)) |value| {
            found += 1;
            allocator.free(value);
        }
    }
    try report(stdout, "get", opCount, timer.read());

    timer.reset();
    var scanned: usize = 0;
    {
        var iter = try db.scan(allocator, null, null);
        defer iter.deinit();
        while (try iter.next()) |_| scanned += 1;
    }
    try report(stdout, "scan-forward", scanned, timer.read());

    timer.reset();
    var reverseScanned: usize = 0;
    {
        var iter = try db.scanReverse(allocator, .{});
        defer iter.deinit();
        while (try iter.next()) |_| reverseScanned += 1;
    }
    try report(stdout, "scan-reverse", reverseScanned, timer.read());

    timer.reset();
    var prefixHits: usize = 0;
    {
        var iter = try db.scanPrefix(allocator, "key:00000000000");
        defer iter.deinit();
        while (try iter.next()) |_| prefixHits += 1;
    }
    try report(stdout, "scan-prefix", prefixHits, timer.read());

    try stdout.print("\nget hits: {d}/{d}, forward/reverse scan entries: {d}/{d}\n", .{ found, opCount, scanned, reverseScanned });

    const stats = db.stats();
    try stdout.writeAll("\n== database statistics ==\n");
    try stats.print(stdout);
    try stdout.print("compression:  {d} live entries in {d} physical bytes ({d:.1} bytes/entry)\n", .{
        stats.liveEntries,
        stats.physicalBytes,
        if (stats.liveEntries == 0) 0 else @as(f64, @floatFromInt(stats.physicalBytes)) / @as(f64, @floatFromInt(stats.liveEntries)),
    });
}
