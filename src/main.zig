const std = @import("std");
const cobalt = @import("root.zig");

const Value = cobalt.row.Value;
const Field = cobalt.row.Field;

const usage =
    \\cobalt - LSM key/value store
    \\
    \\usage: cobalt <dir> <command> [args]
    \\
    \\commands:
    \\  put <key> <value> [--ttl <seconds>]
    \\                            store a value, optionally set to expire
    \\  get <key>                print a value or (nil); a key past its ttl
    \\                            reads as (nil) and is deleted lazily on this read
    \\  del <key>                delete a key
    \\  expire <key> <seconds>   set/replace a key's ttl; error if the key does
    \\                            not currently exist (nonexistent keys have no ttl to set)
    \\  persist <key>            remove a key's ttl, making it immortal again
    \\  ttl <key>                print seconds left, -1 if no ttl, -2 if no such key
    \\  expire-sweep              actively delete every key whose ttl is due,
    \\                            not just the next one someone happens to read;
    \\                            prints how many were reaped
    \\  scan [start] [end]       forward range scan, start inclusive, end exclusive
    \\  rscan [start] [end]      reverse range scan
    \\  prefix <prefix>          scan every key under a prefix
    \\  compact                  run full leveled compaction
    \\  stats [--prom]           print database statistics (optionally as Prometheus text)
    \\  verify <n>               write n keys, reopen, check durability and scan order
    \\  serve [host:port] [--rate-limit <capacity> <per-second>]
    \\                     [--per-conn-rate-limit <capacity> <per-second>] [--auth]
    \\                     [--session-ttl <seconds>] [--session-sweep-interval <seconds>]
    \\                     [--ttl-sweep-interval <seconds>] [--coll-ttl-sweep-interval <seconds>]
    \\                            run a TCP server (default 127.0.0.1:6380),
    \\                            optionally capping requests with a shared
    \\                            token bucket and/or a private one per
    \\                            connection (both may be given together);
    \\                            --auth requires an AUTH before any op but
    \\                            ping, refuses to start if no admin user
    \\                            exists yet (see `user add`); --session-ttl
    \\                            (requires --auth) makes AUTH return a
    \\                            token valid for that many seconds - a new
    \\                            connection can present it via AUTH_TOKEN
    \\                            instead of the password, and the role it
    \\                            grants stops working once the ttl elapses
    \\                            even on a connection that never disconnects;
    \\                            --session-sweep-interval (requires
    \\                            --session-ttl) periodically drops sessions
    \\                            that expired but nobody ever presented again;
    \\                            --ttl-sweep-interval periodically reaps every
    \\                            key whose ttl is due, independent of --auth
    \\                            (like local `expire-sweep`, but automatic);
    \\                            --coll-ttl-sweep-interval does the same for
    \\                            whole collections (like local
    \\                            `coll expire-sweep`), independent of
    \\                            --ttl-sweep-interval - either, both, or
    \\                            neither may be given
    \\
    \\cobalt <host:port> remote-select <table> [expr...] [--limit N] [--offset N]
    \\                                          [--order-by field[:desc][,field[:desc]...]]
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table select` there (same expr grammar as
    \\                            local `table select`; empty expr selects
    \\                            every row) - no local Db is opened;
    \\                            --user/--pass authenticate first, needed
    \\                            only if the server was started with --auth;
    \\                            --token authenticates with a previously
    \\                            issued session token instead of a password
    \\                            (requires the server to have --session-ttl)
    \\
    \\cobalt <host:port> remote-explain <table> [expr...]
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table explain` there (same expr grammar as
    \\                            local `table select`) - no local Db is opened;
    \\                            --user/--pass or --token authenticate first,
    \\                            same as `remote-select`
    \\
    \\cobalt <host:port> remote-update <table> --set field=value[,field=value...] [expr...]
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table update` there (same --set grammar and
    \\                            expr grammar as local `table update`; empty
    \\                            expr updates every row) - no local Db is
    \\                            opened; prints the number of rows updated;
    \\                            --user/--pass or --token authenticate first,
    \\                            same as `remote-select`
    \\
    \\cobalt <host:port> remote-delete <table> [expr...]
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table delete` there (same expr grammar as
    \\                            local `table delete`; empty expr deletes
    \\                            every row) - no local Db is opened; prints
    \\                            the number of rows deleted; --user/--pass or
    \\                            --token authenticate first, same as
    \\                            `remote-select`
    \\
    \\cobalt <host:port> remote-export <table> csv|json <path>
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table export` there (same output shape as
    \\                            local `table export`), writing the result to
    \\                            <path> on THIS machine - no local Db is
    \\                            opened; prints the row count written;
    \\                            --user/--pass or --token authenticate first,
    \\                            same as `remote-select`
    \\
    \\cobalt <host:port> remote-import <table> csv|json <path>
    \\                                          [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table import` there, reading <path> on THIS
    \\                            machine and sending its bytes in one frame -
    \\                            no local Db is opened; prints the row count
    \\                            imported; --user/--pass or --token
    \\                            authenticate first, same as `remote-select`
    \\
    \\cobalt <host:port> remote-join [--left|--right|--full] <leftTable> <leftField>
    \\                                <rightTable> <rightField> [--left-expr E] [--right-expr E]
    \\                                [--limit N] [--offset N]
    \\                                [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table join` there (same 4 modes as local
    \\                            `table join`; --left-expr/--right-expr are
    \\                            the same expr grammar as `table select`,
    \\                            filtering each side before the join runs;
    \\                            --limit/--offset window the already-joined
    \\                            result, same convention as `table select`) -
    \\                            no local Db is opened; --user/--pass or
    \\                            --token authenticate first, same as
    \\                            `remote-select`
    \\
    \\cobalt <host:port> remote-aggregate <table> <groupField|*> <spec>[,<spec>...] [expr...]
    \\                                     [having <expr>] [order <field[:desc]>[,field...]]
    \\                                     [--limit N] [--offset N]
    \\                                     [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table aggregate` there (same spec grammar
    \\                            as local `table aggregate`: count |
    \\                            count:field | sum:field | avg:field |
    \\                            min:field | max:field | distinct:field,
    \\                            comma-separated;
    \\                            `*` as groupField means no GROUP BY, always
    \\                            at most one result row and --limit/--offset
    \\                            are ignored; expr filters rows before
    \\                            aggregating, same grammar as `table
    \\                            select`; an optional `having <expr>` after
    \\                            expr filters the result groups after
    \\                            aggregation, same as local `table
    \\                            aggregate`; an optional `order
    \\                            <field[:desc]>[,field...]` after having
    \\                            sorts the result groups server-side before
    \\                            --limit/--offset window them, same as
    \\                            local `table aggregate`; --limit/--offset
    \\                            window the result groups, same convention
    \\                            as `table select`) - no local Db is opened;
    \\                            --user/--pass or --token authenticate
    \\                            first, same as `remote-select`
    \\
    \\cobalt <host:port> remote-window <table> <kind[:field]>[,<kind[:field]>...] [expr...]
    \\                                  [partition <field>[,field...]]
    \\                                  [order <field[:desc]>[,field...]]
    \\                                  [--limit N] [--offset N] [--range]
    \\                                  [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and run a
    \\                            `table window` there (same spec-list
    \\                            grammar as local `table window`: row_number |
    \\                            rank | dense_rank | count | count:field |
    \\                            count_distinct:field | sum:field | avg:field |
    \\                            min:field | max:field | first_value:field |
    \\                            last_value:field | nth_value:field:n[:default] |
    \\                            lag:field[:offset[:default]] |
    \\                            lead:field[:offset[:default]],
    \\                            comma-separated for multiple
    \\                            annotation columns sharing one partition/
    \\                            order/frame; lag/lead read the field's value
    \\                            `offset` rows before/after the current row
    \\                            within the partition's order sequence
    \\                            (default offset 1, default value SQL NULL
    \\                            unless an `i:`/`f:`/`b:`/`s:`-prefixed
    \\                            `default` literal is given); first_value/
    \\                            last_value/nth_value read the current
    \\                            frame's first/last/n-th row (n is 1-based,
    \\                            required, no SQL default) - UNLIKE lag/lead,
    \\                            these respect --range - see local `table
    \\                            window`'s help for the full frame-end
    \\                            semantics; expr
    \\                            filters rows before annotation, same
    \\                            grammar as `table select`;
    \\                            an optional `partition <field>[,field...]`
    \\                            after expr splits rows into independent
    \\                            groups, same as local `table window`; an
    \\                            optional `order <field[:desc]>[,field...]`
    \\                            after partition orders rows within each
    \\                            partition for ranking/running-aggregate
    \\                            purposes; every matching row comes back
    \\                            annotated (never collapsed, unlike `table
    \\                            aggregate`); --limit/--offset window WHICH
    \\                            rows are returned, walked in the same
    \\                            partition-then-order sequence used to
    \\                            compute them, not raw scan order; --range
    \\                            switches sum/avg/count/min/max to a RANGE
    \\                            frame (rows tied on `order` share the tie
    \\                            group's combined value instead of each
    \\                            accumulating its own, SQL's actual default;
    \\                            rejected together with row_number/rank/
    \\                            dense_rank, same as local `table window`)
    \\                            - no local Db is opened; --user/--pass or
    \\                            --token authenticate first, same as
    \\                            `remote-select`
    \\
    \\cobalt <host:port> remote-publish <channel> <message...> [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and
    \\                            deliver <message> (joined from every
    \\                            trailing word) to every connection
    \\                            currently subscribed to <channel>; prints
    \\                            how many subscribers it reached (0 is a
    \\                            normal outcome for a channel nobody is
    \\                            listening to, not an error) - no local Db
    \\                            is opened
    \\
    \\cobalt <host:port> remote-subscribe <channel>[,channel...] [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and
    \\                            block, printing "subscribed as <id>" on the
    \\                            first line, then "<channel>: <message>" for
    \\                            every message published to any of the
    \\                            listed channels, until the connection
    \\                            closes (Ctrl+C, or the server shutting
    \\                            down) - the connection becomes receive-only
    \\                            once subscribed: to drop some of its
    \\                            channels without closing it, run
    \\                            `remote-unsubscribe <id> ...` from a
    \\                            different terminal
    \\
    \\cobalt <host:port> remote-unsubscribe <subscriber-id> <channel>[,channel...] [--user NAME --pass PASS] [--token TOKEN]
    \\                            connect to a running `cobalt serve` and
    \\                            drop the listed channels from
    \\                            <subscriber-id> (printed by
    \\                            `remote-subscribe` when it started); prints
    \\                            how many channels were actually removed
    \\                            (naming one the subscriber was never on is
    \\                            harmless and does not count, not an
    \\                            error); an unknown or already-disconnected
    \\                            <subscriber-id> is reported as an error,
    \\                            not silently ignored; dropping every
    \\                            channel the subscriber still has ends that
    \\                            subscription outright, same as closing its
    \\                            connection - no local Db is opened
    \\
    \\cobalt <host:port> remote-user add|passwd|role|del|list [args] [--user NAME --pass PASS] [--token TOKEN]
    \\                            same operations as `user`, but against a
    \\                            running `cobalt serve` over the network
    \\                            instead of a local Db file - requires admin
    \\                            role if the server was started with --auth
    \\                            (--user/--pass or --token authenticate first)
    \\
    \\cobalt <host:port> remote-ttl expire <key> <seconds> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-ttl persist <key> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-ttl ttl <key> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-ttl sweep [--user NAME --pass PASS] [--token TOKEN]
    \\                            same four operations as local `expire`/
    \\                            `persist`/`ttl`/`expire-sweep`, but against a
    \\                            running `cobalt serve` over the network -
    \\                            `ttl` needs only readonly role, the other
    \\                            three need readwrite, if the server was
    \\                            started with --auth
    \\
    \\cobalt <host:port> remote-coll-ttl <kind> expire <name> <seconds> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll-ttl <kind> persist <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll-ttl <kind> ttl <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll-ttl sweep [--user NAME --pass PASS] [--token TOKEN]
    \\                            same operations as local `coll <kind>
    \\                            expire|ttl|persist`/`coll expire-sweep`, but
    \\                            against a running `cobalt serve` over the
    \\                            network - `ttl` needs only readonly role,
    \\                            the other three need readwrite, if the
    \\                            server was started with --auth
    \\
    \\cobalt <host:port> remote-coll counter get|set|incrby <name> [value|delta] [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll hash set|get|del <name> <field> [value] [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll hash len|getall <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll set add|rem|ismember <name> <member> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll set card|members <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll set inter|union <name> [name...] [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll set diff <name> <other> [other...] [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll list lpush|rpush <name> <value> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll list lpop|rpop|len <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll list range <name> <start> <stop> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset add <name> <member> <score> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset score|rank <name> <member> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset incrby <name> <member> <delta> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset rem <name> <member> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset card <name> [--user NAME --pass PASS] [--token TOKEN]
    \\cobalt <host:port> remote-coll zset rangebyrank|rangebyscore <name> <lo> <hi> [--user NAME --pass PASS] [--token TOKEN]
    \\                            same operations as local `coll <kind> <op>`,
    \\                            against a running `cobalt serve` over the
    \\                            network - read-only ops (get/len/getall/
    \\                            ismember/card/members/inter/union/diff/
    \\                            range/score/rank/rangebyrank/rangebyscore)
    \\                            need only readonly role, every other op
    \\                            needs readwrite, if the server was started
    \\                            with --auth
    \\
    \\cobalt <host:port> remote-txn <script-file> [--user NAME --pass PASS] [--token TOKEN]
    \\                            same script format as local `txn`, but
    \\                            committed in one round trip against a
    \\                            running `cobalt serve` over the network -
    \\                            needs readwrite role if the server was
    \\                            started with --auth
    \\
    \\cobalt <host:port> remote-stats [--user NAME --pass PASS] [--token TOKEN]
    \\                            print a running `cobalt serve` instance's own
    \\                            request/rate-limit/auth/session counters
    \\                            together with its Db stats, as Prometheus
    \\                            text - the network counterpart of local
    \\                            `stats --prom`, since a server's own counters
    \\                            (distinct from its Db's) were otherwise only
    \\                            ever observable in-process
    \\
    \\  user add <username> <password> readonly|readwrite|admin
    \\  user passwd <username> <newpassword>
    \\  user role <username> readonly|readwrite|admin
    \\  user del <username>
    \\  user list                pre-requisite for `serve --auth`: create at
    \\                            least one admin user first
    \\  backup <file>            write a consistent point-in-time backup to <file>
    \\  restore <file>           replay a backup file into this database
    \\  backup-info <file>       validate a backup file and print its metadata
    \\
    \\  coll counter get|set|incrby <name> [value|delta]
    \\  coll hash set|get|del <name> <field> [value]
    \\  coll hash len|getall <name>
    \\  coll set add|rem|ismember <name> <member>
    \\  coll set card|members <name>
    \\  coll set inter|union <name> [name...]
    \\  coll set diff <name> <other> [other...]
    \\  coll list lpush|rpush <name> <value>
    \\  coll list lpop|rpop|len <name>
    \\  coll list range <name> <start> <stop>
    \\  coll zset add <name> <member> <score>
    \\  coll zset score|rank <name> <member>
    \\  coll zset incrby <name> <member> <delta>
    \\  coll zset rem <name> <member>
    \\  coll zset card <name>
    \\  coll zset rangebyrank|rangebyscore <name> <lo> <hi>
    \\  coll <kind> expire <name> <seconds>   whole collection expires as one unit
    \\  coll <kind> ttl <name>                seconds left, -1 no expiry, -2 no such collection
    \\  coll <kind> persist <name>            clears expiry, collection immortal again
    \\  coll expire-sweep                     reaps every due collection now, across all kinds
    \\
    \\  table put <table> <pk> [field=value ...]
    \\  table get <table> <pk>
    \\  table del <table> <pk>
    \\  table scan <table>
    \\  table select <table> [expr...] [--limit N] [--offset N]
    \\                        [--order-by field[:desc][,field[:desc]...]]
    \\    expr is a predicate: <field> eq|ne|lt|lte|gt|gte|like <value>, composed
    \\    with "and"/"or"/"not" and parentheses, e.g.
    \\    city eq s:oslo and not (age lt i:18)
    \\    like matches SQL-style wildcards against a text field: "%" is any run
    \\    of characters, "_" is exactly one, e.g. name like s:A%; it never uses
    \\    an index even when the field is indexed (always a value scan)
    \\    in and between are sugar over the operators above, so they use an
    \\    index exactly where the desugared form would:
    \\    <field> in (<value> ...) is <field> eq v1 or <field> eq v2 or ...
    \\    (a single value collapses to a bare eq, so it can use an index the
    \\    same way eq does; two or more never do, same as any other "or")
    \\    <field> between <lo> and <hi> is <field> gte <lo> and <field> lte
    \\    <hi> (inclusive both ends), e.g. age between i:18 and i:65,
    \\    city in (s:oslo s:bergen s:trondheim)
    \\    <field> is_null / <field> is_not_null take no trailing value; is_null
    \\    matches a row where the field was never set OR set to an explicit
    \\    none, e.g. city is_null and age gte i:18 (never uses an index, a
    \\    sparse row's absence is not something a B-tree entry can represent)
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
