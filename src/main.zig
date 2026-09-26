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
    \\                            store a value, optionally set to expire; without
    \\                            --ttl any earlier ttl is dropped in the same write
    \\  get <key>                print a value or (nil); a key past its ttl
    \\                            reads as (nil) and is deleted lazily on this read
    \\  del <key>                delete a key
    \\  expire <key> <seconds>   set/replace a key's ttl; error if the key does
    \\                            not currently exist or its ttl already passed
    \\  persist <key>            remove a key's ttl, making it immortal again
    \\  ttl <key>                print seconds left, -1 if no ttl, -2 if no such key
    \\                            or its ttl already passed
    \\  expire-sweep              actively delete every key whose ttl is due,
    \\                            not just the next one someone happens to read;
    \\                            prints how many were reaped
    \\  scan [start] [end]       forward range scan over user keys, start inclusive,
    \\                            end exclusive; internal entries (first byte 0xF5-0xFF:
    \\                            tables, collections, ttl markers, users) are never listed,
    \\                            and neither is a key past its ttl
    \\  rscan [start] [end]      reverse range scan over user keys
    \\  prefix <prefix>          scan every user key under a prefix
    \\  compact                  run full leveled compaction
    \\  stats [--prom]           print database statistics (optionally as Prometheus text)
    \\  verify <n>               write n keys, reopen, check durability and scan order;
    \\                            runs in a fresh scratch directory under $TMPDIR (or /tmp)
    \\                            that is removed afterwards, <dir> is never touched
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
    \\    (empty expr selects every row; --limit/--offset page the result,
    \\    limit 0 or omitted means unlimited; --order-by sorts by one or more
    \\    comma-separated fields, applied left to right (later fields only
    \\    break ties left by earlier ones), ascending by default or ":desc"
    \\    per field for descending - rows missing a sort field sort first
    \\    on it)
    \\  table explain <table> [expr...]
    \\    reports which strategy `table select` would use for the same
    \\    <table>/expr WITHOUT running the query: full scan, a single-field
    \\    index (equality or range), or a composite index (equality or range,
    \\    naming how many of its leading columns the expr actually pinned down)
    \\  table update <table> --set field=value[,field=value...] [expr...]
    \\    applies the --set field list to every row matched by expr (empty expr
    \\    updates every row); each set field overrides an existing field of the
    \\    same name or is added if the row does not have it; unmentioned fields
    \\    are left as-is; secondary/composite indexes on a changed field are
    \\    kept in sync exactly like `table put` would; prints the number of
    \\    rows updated
    \\  table delete <table> [expr...]
    \\    removes every row matched by expr (empty expr deletes every row, same
    \\    convention as `table select`/`table update`); secondary/composite
    \\    indexes on the deleted rows are kept in sync exactly like `table del`
    \\    would for a single row; prints the number of rows deleted
    \\  table index create|drop <table> <field...>  (multiple fields = composite index)
    \\    create --unique <table> <field>: single-field index that also enforces the
    \\    field holds a distinct value across every row (SQL UNIQUE); refuses to
    \\    install over data that already has a duplicate; dropping the index drops
    \\    the constraint too. Not available for composite (multi-field) indexes.
    \\  table fk create <table> <field> <refTable> <refField> [restrict|cascade]
    \\    installs a FOREIGN KEY: every <table> row's (non-null) <field> value must
    \\    name an existing <refField> on <refTable> (SQL FOREIGN KEY REFERENCES);
    \\    <refField> must be either the special primary-key name "__pk" or a field
    \\    already carrying its own --unique index on <refTable>, or the create is
    \\    refused; refuses to install over a <table> row whose current value has
    \\    no matching target; rows missing <field> entirely are exempt (nullable FK).
    \\    Last argument picks ON DELETE behavior for a `table delete`/`table_delete`
    \\    against <refTable>, default "restrict": restrict refuses the delete while
    \\    a <table> row still points at it, cascade removes those rows too (and
    \\    anything cascading from them, recursively). A `txn <script>` delete
    \\    always restricts regardless of this setting - cascade only fires through
    \\    the plain (non-transactional) delete path
    \\  table fk drop <table> <field>
    \\    removes the foreign key constraint on <field>, if any
    \\  table check create <table> <name> <expr...>
    \\    installs a named CHECK constraint (SQL CHECK): every row put into <table>
    \\    from now on must evaluate <expr> (same predicate language as `table select`)
    \\    to true, or the put is refused with CheckViolation; refuses to install over
    \\    existing rows that already fail <expr>; a malformed <expr> is refused with
    \\    InvalidCheckExpression before anything is persisted
    \\  table check drop <table> <name>
    \\    removes the named CHECK constraint, if any
    \\  table join [--left|--right|--full] <leftTable> <leftField> <rightTable> <rightField>
    \\    inner equi-join by default: prints "L <row>" / "R <row>" for every matched pair;
    \\    --left makes it a left outer join: every left row still prints once, with
    \\    "R (nil)" when it has no match on the right instead of being dropped;
    \\    --right is the mirror image: every right row prints once, "L (nil)" when unmatched;
    \\    --full is the union of both: every row on either side prints at least once;
    \\    uses an index on <rightField> (or <leftField> for --right) when one exists,
    \\    hash-joins otherwise; [--limit N] [--offset N] window the already-joined
    \\    result, same convention as `table select` (limit 0 or omitted = unlimited)
    \\    values/keys are typed: i:<int> f:<float> b:true|false s:<text>, bare text defaults to s:
    \\  table aggregate <table> <groupField|*> <spec>[,<spec>...] [expr...] [having <expr>]
    \\                   [order <field[:desc]>[,field...]] [--limit N] [--offset N]
    \\    spec is count | count:<field> | sum:<field> | avg:<field> | min:<field> | max:<field> |
    \\    distinct:<field> (COUNT DISTINCT), comma-separated for more than one in the same
    \\    pass; groupField "*" means no
    \\    grouping (a single result row over every row matching expr, same predicate
    \\    grammar as `table select`, and having/order/--limit/--offset are all ignored);
    \\    rows missing groupField are excluded from every group, rows missing a spec's
    \\    field are excluded from just that spec; --limit/--offset window the result
    \\    groups, same convention as `table select`;
    \\    an optional literal `having <expr>` after the row-filtering expr filters the
    \\    RESULT groups after aggregation (same expr grammar, evaluated before
    \\    order/--limit/--offset); its fields are the printed result labels (bare kind
    \\    name for count, else "<kind>_<field>" e.g. sum_score) plus groupField itself,
    \\    so e.g. `table aggregate orders city sum:total having sum_total gt i:1000`;
    \\    an optional literal `order <field[:desc]>[,field...]` after having (or right
    \\    after the row-filtering expr if there is no having) sorts the result groups
    \\    before --limit/--offset windows them, one or more comma-separated columns
    \\    applied left to right same as `table select`'s --order-by, each field naming
    \\    either groupField or a result label (same two names having's expr can use),
    \\    e.g. `table aggregate orders city sum:total order sum_total:desc --limit 3`
    \\    (top 3 cities by total, without needing having at all); without groupField
    \\    among the sort fields, ties on every named field keep first-seen order
    \\    (stable sort)
    \\  table window <table> <kind[:field]>[,<kind[:field]>...] [expr...] [partition <field>[,field...]]
    \\               [order <field[:desc]>[,field...]] [--limit N] [--offset N] [--range]
    \\    annotates every matching row with one or more computed window-function
    \\    columns instead of collapsing rows like `table aggregate` does; kind is
    \\    row_number | rank | dense_rank (no :field) | sum:<field> | avg:<field> |
    \\    count | count:<field> | count_distinct:<field> | min:<field> | max:<field> |
    \\    first_value:<field> | last_value:<field> | nth_value:<field>:<n>[:<default>] |
    \\    lag:<field>[:<offset>[:<default>]] | lead:<field>[:<offset>[:<default>]];
    \\    a comma-separated list (e.g. `sum:total,avg:total,rank`) computes every
    \\    column over the SAME partition/order/frame, printed in the same order
    \\    after the row's own fields;
    \\    an optional literal `partition <field>[,field...]` splits rows into
    \\    independent groups (like GROUP BY, first-seen order; omitted = one
    \\    partition covering every matching row) and an optional literal `order
    \\    <field[:desc]>[,field...]` (same syntax as `table select`'s
    \\    --order-by) decides the ranking/running-total walk within each
    \\    partition - partition must come before order if both are given;
    \\    without order, rank/dense_rank treat the whole partition as tied
    \\    (every row gets 1) and sum/avg/count/count_distinct/min/max give every
    \\    row the same whole-partition total; with order, sum/avg/count/
    \\    count_distinct/min/max become a running total walked in that order
    \\    instead, by default one physical
    \\    ROW at a time - even a row tied with its predecessor on `order` gets
    \\    its OWN individual running value; --range switches this to SQL's
    \\    actual default RANGE frame instead, where rows tied on every `order`
    \\    column share the LAST tied row's combined value rather than their own
    \\    (e.g. two rows both on day 1 both show day 1's combined total, not a
    \\    half/full split); --range has no effect without `order` (both frames
    \\    already agree there) and is rejected outright together with
    \\    row_number/rank/dense_rank (neither takes a frame clause in standard
    \\    SQL either); --limit/--offset window the printed rows in the SAME
    \\    partition-then-order walk the window computation itself uses (every
    \\    partition's rows in `order`, first-seen partition order), not raw
    \\    scan order - e.g. `table window orders row_number partition city
    \\    order amount:desc --limit 3` prints (up to) the first 3 rows of the
    \\    first-seen partition in that order, not an arbitrary scan-order slice;
    \\    lag/lead read <field>'s value <offset> rows before/after the current
    \\    row within the partition's `order` sequence (first-seen order if no
    \\    `order` given), always as a DISTINCT physical position even when tied
    \\    with a neighbor on `order` (unlike the RANGE running-aggregate frame,
    \\    which collapses ties); a row whose target falls outside the partition
    \\    gets <default> (an `i:`/`f:`/`b:`/`s:`-prefixed literal, same grammar
    \\    as put's field=value) or SQL NULL if omitted; <offset> defaults to 1
    \\    if omitted; --range is rejected outright with lag/lead, same as with
    \\    row_number/rank/dense_rank (a frame clause has no meaning for either);
    \\    first_value/last_value/nth_value read <field>'s value from the current
    \\    frame's first/last/n-th row - UNLIKE lag/lead, these DO respect --range:
    \\    first_value is always the partition's first row (same in both frames),
    \\    but last_value's frame end follows the running-aggregate split - without
    \\    --range (ROWS, ending at CURRENT ROW) last_value degenerates to the
    \\    row's own field (SQL's well-known gotcha), with --range it is instead
    \\    the LAST row of the current tie group on `order`; without `order` at
    \\    all, both give every row the whole partition's first/last value;
    \\    nth_value shares first_value/last_value's frame exactly (same start,
    \\    same ROWS/RANGE/no-order end) but reads the <n>-th row (1-based,
    \\    required - unlike lag/lead's <offset>, SQL's NTH_VALUE has no default
    \\    position) counted from the frame's START; a row whose current frame is
    \\    still smaller than <n> gets <default> (same grammar as lag/lead's, SQL
    \\    NULL if omitted) - e.g. under ROWS, nth_value:total:2 is NULL on the
    \\    first row of every partition (frame size 1) and 2nd-row's value from
    \\    then on, once the frame has grown enough to contain it
    \\  table export <table> csv|json <path>
    \\    writes every row to <path>; the column/key set is the union of every
    \\    field name across every row (primary key first, "__pk", then
    \\    first-seen order), a row missing a column just omits that cell/key
    \\    rather than writing empty/null; every value is written as a typed
    \\    string (i:/f:/b:/s:/x:/n:, same prefixes as put's field=value, plus
    \\    x: for raw bytes hex and n: for none) so re-importing reproduces the
    \\    exact original type, including floats (encoded as exact bits, not a
    \\    decimal that could round-trip lossy); prints the row count written
    \\  table import <table> csv|json <path>
    \\    reads rows written by `table export` (or any file in the same shape)
    \\    back into <table> via `table put`, so existing rows sharing a
    \\    primary key are overwritten and secondary/composite indexes stay in
    \\    sync; the "__pk" column/key is required; prints the row count read
    \\
    \\  txn <script-file>        apply a script of `put|del <table> <pk> [field=value ...]`
    \\                            lines as one atomic transaction (all-or-nothing, error.Conflict
    \\                            aborts with nothing applied); blank lines and #comments skipped
    \\
    \\  repl [--script <file>]    interactive shell over this database: put/get/del/
    \\                            scan/stats/flush/compact plus table put/get/del and
    \\                            coll <kind> <op> [args...] (counter/hash/set/list/
    \\                            zset), with begin/commit/rollback bracketing an
    \\                            interactive transaction (get mid-transaction can
    \\                            steer the next put, unlike a static `txn` script).
    \\                            Reads stdin with a prompt by default, or a file
    \\                            non-interactively with --script.
    \\
    \\  replicate <replica-dir> [--once] [--interval-ms <n>]
    \\                            tail this database's WAL and apply new writes onto
    \\                            <replica-dir> (opened/created fresh). Runs a bootstrap
    \\                            fullResync first, then loops calling syncOnce every
    \\                            interval-ms (default 200) until interrupted, or once
    \\                            and exit if --once is given. Recovers automatically
    \\                            from a fallen-behind tailer (primary flushed before
    \\                            catching up) via another fullResync.
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
        const scratchParent = std.posix.getenv("TMPDIR") orelse "/tmp";
        if (!try cobalt.verify.run(allocator, stdout, scratchParent, count)) std.process.exit(1);
        return;
    }

    if (std.mem.eql(u8, command, "remote-select")) {
        try runRemoteSelect(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-join")) {
        try runRemoteJoin(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-aggregate")) {
        try runRemoteAggregate(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-window")) {
        try runRemoteWindow(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-publish")) {
        try runRemotePublish(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-subscribe")) {
        try runRemoteSubscribe(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-unsubscribe")) {
        try runRemoteUnsubscribe(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-explain")) {
        try runRemoteExplain(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-update")) {
        try runRemoteUpdate(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-delete")) {
        try runRemoteDelete(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-export")) {
        try runRemoteExport(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-import")) {
        try runRemoteImport(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-user")) {
        try runRemoteUser(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-stats")) {
        try runRemoteStats(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-ttl")) {
        try runRemoteTtl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-coll-ttl")) {
        try runRemoteCollTtl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-coll")) {
        try runRemoteColl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-txn")) {
        try runRemoteTxn(allocator, stdout, stderr, dir, rest);
        return;
    }

    var db = try openOrExit(allocator, stderr, dir, command);
    defer db.close();

    if (std.mem.eql(u8, command, "put")) {
        if (rest.len < 2) return fail(stderr, "put needs <key> <value>");
        try requireUserKey(stderr, rest[0]);
        if (rest.len == 4 and std.mem.eql(u8, rest[2], "--ttl")) {
            const seconds = std.fmt.parseInt(u64, rest[3], 10) catch return fail(stderr, "--ttl needs a whole number of seconds");
            try cobalt.ttl.putWithTtl(&db, allocator, rest[0], rest[1], std.time.nanoTimestamp(), seconds);
        } else if (rest.len == 2) {
            try cobalt.ttl.putPersistent(&db, allocator, rest[0], rest[1]);
        } else {
            return fail(stderr, "put takes <key> <value> [--ttl <seconds>]");
        }
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "get")) {
        if (rest.len < 1) return fail(stderr, "get needs <key>");
        try requireUserKey(stderr, rest[0]);
        if (try cobalt.ttl.getLive(&db, allocator, rest[0], std.time.nanoTimestamp())) |value| {
            defer allocator.free(value);
            try stdout.print("{s}\n", .{value});
        } else {
            try stdout.writeAll("(nil)\n");
        }
    } else if (std.mem.eql(u8, command, "del")) {
        if (rest.len < 1) return fail(stderr, "del needs <key>");
        try requireUserKey(stderr, rest[0]);
        try cobalt.ttl.deleteKey(&db, allocator, rest[0]);
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "expire")) {
        if (rest.len < 2) return fail(stderr, "expire needs <key> <seconds>");
        try requireUserKey(stderr, rest[0]);
        const seconds = std.fmt.parseInt(u64, rest[1], 10) catch return fail(stderr, "expire needs a whole number of seconds");
        if (!try cobalt.ttl.expireLive(&db, allocator, rest[0], std.time.nanoTimestamp(), seconds)) return fail(stderr, "no such key");
    } else if (std.mem.eql(u8, command, "persist")) {
        if (rest.len < 1) return fail(stderr, "persist needs <key>");
        try requireUserKey(stderr, rest[0]);
        try cobalt.ttl.clearExpire(&db, allocator, rest[0]);
    } else if (std.mem.eql(u8, command, "ttl")) {
        if (rest.len < 1) return fail(stderr, "ttl needs <key>");
        try requireUserKey(stderr, rest[0]);
        switch (try cobalt.ttl.remaining(&db, allocator, rest[0], std.time.nanoTimestamp())) {
            .noKey => try stdout.writeAll("-2\n"),
            .noExpiry => try stdout.writeAll("-1\n"),
            .seconds => |s| try stdout.print("{d}\n", .{s}),
        }
    } else if (std.mem.eql(u8, command, "expire-sweep")) {
        const reaped = try cobalt.ttl.sweepExpired(&db, allocator, std.time.nanoTimestamp());
        try stdout.print("reaped: {d}\n", .{reaped});
    } else if (std.mem.eql(u8, command, "scan")) {
        const start: ?[]const u8 = if (rest.len >= 1) rest[0] else null;
        const end: ?[]const u8 = if (rest.len >= 2) rest[1] else null;
        var iter = try cobalt.keyspace.scanUser(&db, allocator, .{ .start = start, .end = end }, std.time.nanoTimestamp());
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "rscan")) {
        const start: ?[]const u8 = if (rest.len >= 1) rest[0] else null;
        const end: ?[]const u8 = if (rest.len >= 2) rest[1] else null;
        var iter = try cobalt.keyspace.scanUserReverse(&db, allocator, .{ .start = start, .end = end }, std.time.nanoTimestamp());
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "prefix")) {
        if (rest.len < 1) return fail(stderr, "prefix needs <prefix>");
        var iter = try cobalt.keyspace.scanUserPrefix(&db, allocator, rest[0], std.time.nanoTimestamp());
        defer iter.deinit();
        while (try iter.next()) |entry| try stdout.print("{s}\t{s}\n", .{ entry.key, entry.value });
    } else if (std.mem.eql(u8, command, "compact")) {
        try db.compact();
        try stdout.print("sstables after compaction: {d}\n", .{db.sstables.items.len});
    } else if (std.mem.eql(u8, command, "stats")) {
        if (rest.len >= 1 and std.mem.eql(u8, rest[0], "--prom")) {
            try cobalt.metrics.formatDbStats(stdout, "cobalt", db.stats());
        } else {
            try db.stats().print(stdout);
        }
    } else if (std.mem.eql(u8, command, "serve")) {
        const bind = if (rest.len >= 1) rest[0] else "127.0.0.1:6380";
        const serveRest = if (rest.len >= 1) rest[1..] else rest;
        try runServe(allocator, stdout, &db, bind, serveRest);
    } else if (std.mem.eql(u8, command, "backup")) {
        if (rest.len < 1) return fail(stderr, "backup needs <file>");
        const snap = try db.snapshot();
        const count = try cobalt.backup.dumpToFile(allocator, snap, rest[0]);
        try stdout.print("backup written: {d} entries, seq={d}, file={s}\n", .{ count, snap.seq, rest[0] });
    } else if (std.mem.eql(u8, command, "restore")) {
        if (rest.len < 1) return fail(stderr, "restore needs <file>");
        const info = cobalt.backup.restoreFromFile(allocator, &db, rest[0], 500) catch |err| {
            try stderr.print("restore failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("restore applied: {d} entries from seq={d}\n", .{ info.entryCount, info.seq });
    } else if (std.mem.eql(u8, command, "coll")) {
        try runColl(allocator, stdout, stderr, &db, rest);
    } else if (std.mem.eql(u8, command, "table")) {
        try runTable(allocator, stdout, stderr, &db, rest);
    } else if (std.mem.eql(u8, command, "user")) {
        try runUser(allocator, stdout, stderr, &db, rest);
    } else if (std.mem.eql(u8, command, "txn")) {
        try runTxn(allocator, stdout, stderr, &db, rest);
    } else if (std.mem.eql(u8, command, "replicate")) {
        if (rest.len < 1) return fail(stderr, "replicate needs <replica-dir>");
        try runReplicate(allocator, stdout, stderr, &db, rest[0], rest[1..]);
    } else if (std.mem.eql(u8, command, "repl")) {
        try runRepl(allocator, stdout, stderr, &db, rest);
    } else if (std.mem.eql(u8, command, "backup-info")) {
        if (rest.len < 1) return fail(stderr, "backup-info needs <file>");
        const info = cobalt.backup.inspectFile(allocator, rest[0]) catch |err| {
            try stderr.print("invalid backup: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("entries={d} seq={d}\n", .{ info.entryCount, info.seq });
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

fn requireUserKey(stderr: anytype, key: []const u8) !void {
    cobalt.keyspace.checkUserKey(key) catch return fail(stderr, "key is in the reserved internal namespace (first byte 0xF5-0xFF)");
}

fn openOrExit(allocator: std.mem.Allocator, stderr: anytype, dir: []const u8, command: []const u8) !cobalt.Db {
    return cobalt.Db.open(allocator, dir, .{}) catch |err| switch (err) {
        cobalt.OpenError.DataDirLocked => {
            try stderr.print("error: data directory '{s}' is locked by another process (a running serve, replicate or other command holds its LOCK file)\n", .{dir});
            if (std.mem.eql(u8, command, "replicate")) {
                try stderr.writeAll("replicate opens the primary directory itself and does not connect to a running server; stop the server first or embed Replicator in the serving process\n");
            }
            std.process.exit(1);
        },
        else => return err,
    };
}

fn boolFlag(v: bool) u8 {
    return if (v) 1 else 0;
}

fn runColl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, rest: []const []const u8) !void {
    if (rest.len >= 1 and std.mem.eql(u8, rest[0], "expire-sweep")) {
        const reaped = try cobalt.collttl.sweepExpired(db, allocator, std.time.nanoTimestamp());
        try stdout.print("reaped: {d}\n", .{reaped});
        return;
    }
    if (rest.len < 2) return fail(stderr, "coll needs <kind> <op> ...");
    const kind = rest[0];
    const op = rest[1];
    const args = rest[2..];

    if (std.mem.eql(u8, op, "expire") or std.mem.eql(u8, op, "ttl") or std.mem.eql(u8, op, "persist")) {
        const k = cobalt.CollectionKind.parse(kind) orelse return fail(stderr, "unknown collection kind (expected counter/hash/set/list/zset)");
        return runCollTtl(allocator, stdout, stderr, db, k, op, args);
    }

    if (args.len >= 1) {
        if (cobalt.CollectionKind.parse(kind)) |k| {
            _ = try cobalt.collttl.expireIfDue(db, allocator, k, args[0], std.time.nanoTimestamp());
        }
    }

    if (std.mem.eql(u8, kind, "counter")) {
        if (std.mem.eql(u8, op, "get")) {
            if (args.len < 1) return fail(stderr, "counter get needs <name>");
            const v = try cobalt.Counter.get(db, allocator, args[0]);
            try stdout.print("{d}\n", .{v});
        } else if (std.mem.eql(u8, op, "set")) {
            if (args.len < 2) return fail(stderr, "counter set needs <name> <value>");
            const v = std.fmt.parseInt(i64, args[1], 10) catch return fail(stderr, "invalid integer value");
            try cobalt.Counter.set(db, allocator, args[0], v);
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "incrby")) {
            if (args.len < 2) return fail(stderr, "counter incrby needs <name> <delta>");
            const delta = std.fmt.parseInt(i64, args[1], 10) catch return fail(stderr, "invalid integer delta");
            const v = try cobalt.Counter.incrBy(db, allocator, args[0], delta);
            try stdout.print("{d}\n", .{v});
        } else {
            return fail(stderr, "unknown counter operation");
        }
    } else if (std.mem.eql(u8, kind, "hash")) {
        if (std.mem.eql(u8, op, "set")) {
            if (args.len < 3) return fail(stderr, "hash set needs <name> <field> <value>");
            const created = try cobalt.Hash.set(db, allocator, args[0], args[1], args[2]);
            try stdout.print("{s}\n", .{if (created) "created" else "updated"});
        } else if (std.mem.eql(u8, op, "get")) {
            if (args.len < 2) return fail(stderr, "hash get needs <name> <field>");
            if (try cobalt.Hash.get(db, allocator, args[0], args[1])) |v| {
                defer allocator.free(v);
                try stdout.print("{s}\n", .{v});
            } else {
                try stdout.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "del")) {
            if (args.len < 2) return fail(stderr, "hash del needs <name> <field>");
            const existed = try cobalt.Hash.del(db, allocator, args[0], args[1]);
            try stdout.print("{d}\n", .{boolFlag(existed)});
        } else if (std.mem.eql(u8, op, "len")) {
            if (args.len < 1) return fail(stderr, "hash len needs <name>");
            const n = try cobalt.Hash.len(db, allocator, args[0]);
            try stdout.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "getall")) {
            if (args.len < 1) return fail(stderr, "hash getall needs <name>");
            const fields = try cobalt.Hash.getAll(db, allocator, args[0]);
            defer {
                for (fields) |f| f.free(allocator);
                allocator.free(fields);
            }
            for (fields) |f| try stdout.print("{s}\t{s}\n", .{ f.field, f.value });
        } else {
            return fail(stderr, "unknown hash operation");
        }
    } else if (std.mem.eql(u8, kind, "set")) {
        if (std.mem.eql(u8, op, "add")) {
            if (args.len < 2) return fail(stderr, "set add needs <name> <member>");
            const added = try cobalt.Set.add(db, allocator, args[0], args[1]);
            try stdout.print("{d}\n", .{boolFlag(added)});
        } else if (std.mem.eql(u8, op, "rem")) {
            if (args.len < 2) return fail(stderr, "set rem needs <name> <member>");
            const removed = try cobalt.Set.remove(db, allocator, args[0], args[1]);
            try stdout.print("{d}\n", .{boolFlag(removed)});
        } else if (std.mem.eql(u8, op, "ismember")) {
            if (args.len < 2) return fail(stderr, "set ismember needs <name> <member>");
            const is = try cobalt.Set.isMember(db, allocator, args[0], args[1]);
            try stdout.print("{d}\n", .{boolFlag(is)});
        } else if (std.mem.eql(u8, op, "card")) {
            if (args.len < 1) return fail(stderr, "set card needs <name>");
            const n = try cobalt.Set.card(db, allocator, args[0]);
            try stdout.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "members")) {
            if (args.len < 1) return fail(stderr, "set members needs <name>");
            const ms = try cobalt.Set.members(db, allocator, args[0]);
            defer {
                for (ms) |m| allocator.free(m);
                allocator.free(ms);
            }
            for (ms) |m| try stdout.print("{s}\n", .{m});
        } else if (std.mem.eql(u8, op, "inter")) {
            if (args.len < 1) return fail(stderr, "set inter needs at least one <name>");
            _ = try cobalt.collttl.expireIfDueMany(db, allocator, .set, args[1..], std.time.nanoTimestamp());
            const ms = try cobalt.Set.intersect(db, allocator, args);
            defer {
                for (ms) |m| allocator.free(m);
                allocator.free(ms);
            }
            for (ms) |m| try stdout.print("{s}\n", .{m});
        } else if (std.mem.eql(u8, op, "union")) {
            if (args.len < 1) return fail(stderr, "set union needs at least one <name>");
            _ = try cobalt.collttl.expireIfDueMany(db, allocator, .set, args[1..], std.time.nanoTimestamp());
            const ms = try cobalt.Set.unionOf(db, allocator, args);
            defer {
                for (ms) |m| allocator.free(m);
                allocator.free(ms);
            }
            for (ms) |m| try stdout.print("{s}\n", .{m});
        } else if (std.mem.eql(u8, op, "diff")) {
            if (args.len < 2) return fail(stderr, "set diff needs <name> <other...>");
            _ = try cobalt.collttl.expireIfDueMany(db, allocator, .set, args[1..], std.time.nanoTimestamp());
            const ms = try cobalt.Set.difference(db, allocator, args[0], args[1..]);
            defer {
                for (ms) |m| allocator.free(m);
                allocator.free(ms);
            }
            for (ms) |m| try stdout.print("{s}\n", .{m});
        } else {
            return fail(stderr, "unknown set operation");
        }
    } else if (std.mem.eql(u8, kind, "list")) {
        if (std.mem.eql(u8, op, "lpush")) {
            if (args.len < 2) return fail(stderr, "list lpush needs <name> <value>");
            try cobalt.List.pushLeft(db, allocator, args[0], args[1]);
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "rpush")) {
            if (args.len < 2) return fail(stderr, "list rpush needs <name> <value>");
            try cobalt.List.pushRight(db, allocator, args[0], args[1]);
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "lpop")) {
            if (args.len < 1) return fail(stderr, "list lpop needs <name>");
            if (try cobalt.List.popLeft(db, allocator, args[0])) |v| {
                defer allocator.free(v);
                try stdout.print("{s}\n", .{v});
            } else {
                try stdout.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "rpop")) {
            if (args.len < 1) return fail(stderr, "list rpop needs <name>");
            if (try cobalt.List.popRight(db, allocator, args[0])) |v| {
                defer allocator.free(v);
                try stdout.print("{s}\n", .{v});
            } else {
                try stdout.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "len")) {
            if (args.len < 1) return fail(stderr, "list len needs <name>");
            const n = try cobalt.List.len(db, allocator, args[0]);
            try stdout.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "range")) {
            if (args.len < 3) return fail(stderr, "list range needs <name> <start> <stop>");
            const start = std.fmt.parseInt(i64, args[1], 10) catch return fail(stderr, "invalid start index");
            const stop = std.fmt.parseInt(i64, args[2], 10) catch return fail(stderr, "invalid stop index");
            const vals = try cobalt.List.range(db, allocator, args[0], start, stop);
            defer {
                for (vals) |v| allocator.free(v);
                allocator.free(vals);
            }
            for (vals) |v| try stdout.print("{s}\n", .{v});
        } else {
            return fail(stderr, "unknown list operation");
        }
    } else if (std.mem.eql(u8, kind, "zset")) {
        if (std.mem.eql(u8, op, "add")) {
            if (args.len < 3) return fail(stderr, "zset add needs <name> <member> <score>");
            const score = std.fmt.parseFloat(f64, args[2]) catch return fail(stderr, "invalid score");
            try cobalt.ZSet.add(db, allocator, args[0], args[1], score);
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "score")) {
            if (args.len < 2) return fail(stderr, "zset score needs <name> <member>");
            if (try cobalt.ZSet.score(db, allocator, args[0], args[1])) |s| {
                try stdout.print("{d}\n", .{s});
            } else {
                try stdout.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "incrby")) {
            if (args.len < 3) return fail(stderr, "zset incrby needs <name> <member> <delta>");
            const delta = std.fmt.parseFloat(f64, args[2]) catch return fail(stderr, "invalid delta");
            const s = try cobalt.ZSet.incrBy(db, allocator, args[0], args[1], delta);
            try stdout.print("{d}\n", .{s});
        } else if (std.mem.eql(u8, op, "rem")) {
            if (args.len < 2) return fail(stderr, "zset rem needs <name> <member>");
            const removed = try cobalt.ZSet.remove(db, allocator, args[0], args[1]);
            try stdout.print("{d}\n", .{boolFlag(removed)});
        } else if (std.mem.eql(u8, op, "card")) {
            if (args.len < 1) return fail(stderr, "zset card needs <name>");
            const n = try cobalt.ZSet.card(db, allocator, args[0]);
            try stdout.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "rangebyrank")) {
            if (args.len < 3) return fail(stderr, "zset rangebyrank needs <name> <start> <stop>");
            const start = std.fmt.parseInt(i64, args[1], 10) catch return fail(stderr, "invalid start rank");
            const stop = std.fmt.parseInt(i64, args[2], 10) catch return fail(stderr, "invalid stop rank");
            const zms = try cobalt.ZSet.rangeByRank(db, allocator, args[0], start, stop);
            defer {
                for (zms) |zm| zm.free(allocator);
                allocator.free(zms);
            }
            for (zms) |zm| try stdout.print("{s}\t{d}\n", .{ zm.member, zm.score });
        } else if (std.mem.eql(u8, op, "rangebyscore")) {
            if (args.len < 3) return fail(stderr, "zset rangebyscore needs <name> <min> <max>");
            const min = std.fmt.parseFloat(f64, args[1]) catch return fail(stderr, "invalid min score");
            const max = std.fmt.parseFloat(f64, args[2]) catch return fail(stderr, "invalid max score");
            const zms = try cobalt.ZSet.rangeByScore(db, allocator, args[0], min, max);
            defer {
                for (zms) |zm| zm.free(allocator);
                allocator.free(zms);
            }
            for (zms) |zm| try stdout.print("{s}\t{d}\n", .{ zm.member, zm.score });
        } else if (std.mem.eql(u8, op, "rank")) {
            if (args.len < 2) return fail(stderr, "zset rank needs <name> <member>");
            if (try cobalt.ZSet.rank(db, allocator, args[0], args[1])) |r| {
                try stdout.print("{d}\n", .{r});
            } else {
                try stdout.writeAll("(nil)\n");
            }
        } else {
            return fail(stderr, "unknown zset operation");
        }
    } else {
        return fail(stderr, "unknown collection kind (expected counter/hash/set/list/zset)");
    }
}

fn runCollTtl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, k: cobalt.CollectionKind, op: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, op, "expire")) {
        if (args.len < 2) return fail(stderr, "coll <kind> expire needs <name> <seconds>");
        const seconds = std.fmt.parseInt(u64, args[1], 10) catch return fail(stderr, "expire needs a whole number of seconds");
        if (!try cobalt.collections.collectionExists(db, allocator, k, args[0])) return fail(stderr, "no such collection");
        try cobalt.collttl.setExpireSeconds(db, allocator, k, args[0], std.time.nanoTimestamp(), seconds);
        try stdout.writeAll("OK\n");
    } else if (std.mem.eql(u8, op, "persist")) {
        if (args.len < 1) return fail(stderr, "coll <kind> persist needs <name>");
        try cobalt.collttl.clearExpire(db, allocator, k, args[0]);
        try stdout.writeAll("OK\n");
    } else if (std.mem.eql(u8, op, "ttl")) {
        if (args.len < 1) return fail(stderr, "coll <kind> ttl needs <name>");
        switch (try cobalt.collttl.remaining(db, allocator, k, args[0], std.time.nanoTimestamp())) {
            .noKey => try stdout.writeAll("-2\n"),
            .noExpiry => try stdout.writeAll("-1\n"),
            .seconds => |s| try stdout.print("{d}\n", .{s}),
        }
    } else {
        return fail(stderr, "unknown coll ttl operation");
    }
}

fn parseValue(text: []const u8) !Value {
    return cobalt.row.Value.parseCli(text);
}

fn parseField(text: []const u8) !Field {
    const eq = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidField;
    const name = text[0..eq];
    if (!cobalt.index.validIdentifier(name)) return error.InvalidField;
    const value = try parseValue(text[eq + 1 ..]);
    return .{ .name = name, .value = value };
}

const PageFlags = struct { limit: u32 = 0, offset: u32 = 0 };

fn extractPageFlags(allocator: std.mem.Allocator, args: []const []const u8) !struct { page: PageFlags, rest: [][]const u8 } {
    var page = PageFlags{};
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const isLimit = std.mem.eql(u8, args[i], "--limit");
        const isOffset = std.mem.eql(u8, args[i], "--offset");
        if (isLimit or isOffset) {
            i += 1;
            if (i >= args.len) return error.InvalidPageFlag;
            const n = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidPageFlag;
            if (isLimit) page.limit = n else page.offset = n;
        } else {
            try rest.append(args[i]);
        }
    }
    return .{ .page = page, .rest = try rest.toOwnedSlice() };
}

fn extractRangeFlag(allocator: std.mem.Allocator, args: []const []const u8) !struct { range: bool, rest: [][]const u8 } {
    var range = false;
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();
    for (args) |a| {
        if (std.mem.eql(u8, a, "--range")) {
            range = true;
        } else {
            try rest.append(a);
        }
    }
    return .{ .range = range, .rest = try rest.toOwnedSlice() };
}

const SelectFlags = struct { page: PageFlags = .{}, orderBy: []const cobalt.query.OrderBy = &.{} };

fn extractSelectFlags(allocator: std.mem.Allocator, args: []const []const u8) !struct { flags: SelectFlags, rest: [][]const u8 } {
    var flags = SelectFlags{};
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const isLimit = std.mem.eql(u8, args[i], "--limit");
        const isOffset = std.mem.eql(u8, args[i], "--offset");
        const isOrderBy = std.mem.eql(u8, args[i], "--order-by");
        if (isLimit or isOffset) {
            i += 1;
            if (i >= args.len) return error.InvalidPageFlag;
            const n = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidPageFlag;
            if (isLimit) flags.page.limit = n else flags.page.offset = n;
        } else if (isOrderBy) {
            i += 1;
            if (i >= args.len) return error.InvalidPageFlag;
            allocator.free(flags.orderBy);
            flags.orderBy = try parseOrderByList(allocator, args[i]);
        } else {
            try rest.append(args[i]);
        }
    }
    return .{ .flags = flags, .rest = try rest.toOwnedSlice() };
}

fn parseOrderByFlag(text: []const u8) !cobalt.query.OrderBy {
    if (std.mem.indexOfScalar(u8, text, ':')) |colon| {
        const field = text[0..colon];
        const dir = text[colon + 1 ..];
        if (field.len == 0) return error.InvalidPageFlag;
        if (std.mem.eql(u8, dir, "desc")) return .{ .field = field, .descending = true };
        if (std.mem.eql(u8, dir, "asc")) return .{ .field = field, .descending = false };
        return error.InvalidPageFlag;
    }
    if (text.len == 0) return error.InvalidPageFlag;
    return .{ .field = text };
}

fn parseOrderByList(allocator: std.mem.Allocator, text: []const u8) ![]cobalt.query.OrderBy {
    var list = std.ArrayList(cobalt.query.OrderBy).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseOrderByFlag(segment));
    }
    return list.toOwnedSlice();
}

fn parseSetList(allocator: std.mem.Allocator, text: []const u8) ![]Field {
    var list = std.ArrayList(Field).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseField(segment));
    }
    return list.toOwnedSlice();
}

fn extractSetFlag(allocator: std.mem.Allocator, args: []const []const u8) !struct { sets: []Field, rest: [][]const u8 } {
    var sets: []Field = &.{};
    errdefer allocator.free(sets);
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--set")) {
            i += 1;
            if (i >= args.len) return error.InvalidSetFlag;
            allocator.free(sets);
            sets = parseSetList(allocator, args[i]) catch return error.InvalidSetFlag;
        } else {
            try rest.append(args[i]);
        }
    }
    if (sets.len == 0) return error.MissingSetFlag;
    return .{ .sets = sets, .rest = try rest.toOwnedSlice() };
}

fn printValue(stdout: anytype, value: Value) !void {
    switch (value) {
        .none => try stdout.writeAll("(none)"),
        .boolean => |b| try stdout.print("{}", .{b}),
        .int => |i| try stdout.print("{d}", .{i}),
        .float => |f| try stdout.print("{d}", .{f}),
        .text => |s| try stdout.writeAll(s),
        .bytes => |b| for (b) |byte| try stdout.print("{x:0>2}", .{byte}),
    }
}

fn printRow(stdout: anytype, row: cobalt.row.Row) !void {
    for (row.fields.items, 0..) |f, i| {
        if (i > 0) try stdout.writeAll("\t");
        try stdout.print("{s}=", .{f.name});
        try printValue(stdout, f.value);
    }
    try stdout.writeAll("\n");
}

fn printPlan(stdout: anytype, plan: cobalt.query.Plan) !void {
    switch (plan.kind) {
        .full_scan => try stdout.writeAll("full scan (no usable index)\n"),
        .index_eq => try stdout.print("index '{s}' (equality)\n", .{plan.indexName.?}),
        .index_range => try stdout.print("index '{s}' (range)\n", .{plan.indexName.?}),
        .composite_eq => try stdout.print("composite index '{s}' (equality, {d}/{d} columns matched)\n", .{ plan.indexName.?, plan.matchedFields, plan.totalFields }),
        .composite_range => try stdout.print("composite index '{s}' (range, {d}/{d} columns matched)\n", .{ plan.indexName.?, plan.matchedFields, plan.totalFields }),
    }
}

fn parseAggKind(name: []const u8) ?cobalt.AggKind {
    if (std.mem.eql(u8, name, "count")) return .count;
    if (std.mem.eql(u8, name, "sum")) return .sum;
    if (std.mem.eql(u8, name, "avg")) return .avg;
    if (std.mem.eql(u8, name, "min")) return .min;
    if (std.mem.eql(u8, name, "max")) return .max;
    if (std.mem.eql(u8, name, "distinct")) return .count_distinct;
    return null;
}

fn parseAggSpecs(allocator: std.mem.Allocator, text: []const u8) ![]cobalt.AggSpec {
    var specs = std.ArrayList(cobalt.AggSpec).init(allocator);
    errdefer specs.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidAggSpec;
        if (std.mem.indexOfScalar(u8, part, ':')) |colon| {
            const kind = parseAggKind(part[0..colon]) orelse return error.InvalidAggSpec;
            const field = part[colon + 1 ..];
            if (!cobalt.index.validIdentifier(field)) return error.InvalidAggSpec;
            try specs.append(.{ .field = field, .kind = kind });
        } else {
            const kind = parseAggKind(part) orelse return error.InvalidAggSpec;
            if (kind != .count) return error.InvalidAggSpec;
            try specs.append(.{ .field = "", .kind = kind });
        }
    }
    if (specs.items.len == 0) return error.InvalidAggSpec;
    return specs.toOwnedSlice();
}

fn findLiteralToken(args: []const []const u8, token: []const u8) ?usize {
    for (args, 0..) |a, i| {
        if (std.mem.eql(u8, a, token)) return i;
    }
    return null;
}

fn splitAggFilterArgs(args: []const []const u8) struct { whereArgs: []const []const u8, havingArgs: ?[]const []const u8, orderArgs: ?[]const []const u8 } {
    if (findLiteralToken(args, "having")) |hi| {
        const whereArgs = args[0..hi];
        const afterHaving = args[hi + 1 ..];
        if (findLiteralToken(afterHaving, "order")) |oi| {
            return .{ .whereArgs = whereArgs, .havingArgs = afterHaving[0..oi], .orderArgs = afterHaving[oi + 1 ..] };
        }
        return .{ .whereArgs = whereArgs, .havingArgs = afterHaving, .orderArgs = null };
    }
    if (findLiteralToken(args, "order")) |oi| {
        return .{ .whereArgs = args[0..oi], .havingArgs = null, .orderArgs = args[oi + 1 ..] };
    }
    return .{ .whereArgs = args, .havingArgs = null, .orderArgs = null };
}

fn printAggLabel(stdout: anytype, spec: cobalt.AggSpec) !void {
    if (spec.field.len == 0) {
        try stdout.writeAll(@tagName(spec.kind));
    } else {
        try stdout.print("{s}_{s}", .{ @tagName(spec.kind), spec.field });
    }
}

fn parseWindowKind(name: []const u8) ?cobalt.WindowKind {
    if (std.mem.eql(u8, name, "row_number")) return .row_number;
    if (std.mem.eql(u8, name, "rank")) return .rank;
    if (std.mem.eql(u8, name, "dense_rank")) return .dense_rank;
    if (std.mem.eql(u8, name, "sum")) return .sum;
    if (std.mem.eql(u8, name, "avg")) return .avg;
    if (std.mem.eql(u8, name, "count")) return .count;
    if (std.mem.eql(u8, name, "count_distinct")) return .count_distinct;
    if (std.mem.eql(u8, name, "min")) return .min;
    if (std.mem.eql(u8, name, "max")) return .max;
    if (std.mem.eql(u8, name, "lag")) return .lag;
    if (std.mem.eql(u8, name, "lead")) return .lead;
    if (std.mem.eql(u8, name, "first_value")) return .first_value;
    if (std.mem.eql(u8, name, "last_value")) return .last_value;
    if (std.mem.eql(u8, name, "nth_value")) return .nth_value;
    return null;
}

fn parseWindowSpec(text: []const u8) !cobalt.WindowSpec {
    var it = std.mem.splitScalar(u8, text, ':');
    const kind = parseWindowKind(it.next().?) orelse return error.InvalidWindowSpec;

    if (kind == .row_number or kind == .rank or kind == .dense_rank) {
        if (it.next() != null) return error.InvalidWindowSpec;
        return .{ .field = "", .kind = kind };
    }
    if (kind == .lag or kind == .lead) {
        const field = it.next() orelse return error.InvalidWindowSpec;
        if (!cobalt.index.validIdentifier(field)) return error.InvalidWindowSpec;
        var spec = cobalt.WindowSpec{ .field = field, .kind = kind };
        if (it.next()) |offsetText| {
            spec.offset = std.fmt.parseInt(u64, offsetText, 10) catch return error.InvalidWindowSpec;
            const rest = it.rest();
            if (rest.len > 0) spec.default = parseValue(rest) catch return error.InvalidWindowSpec;
        }
        return spec;
    }
    if (kind == .nth_value) {
        const field = it.next() orelse return error.InvalidWindowSpec;
        if (!cobalt.index.validIdentifier(field)) return error.InvalidWindowSpec;
        const nText = it.next() orelse return error.InvalidWindowSpec;
        const n = std.fmt.parseInt(u64, nText, 10) catch return error.InvalidWindowSpec;
        if (n == 0) return error.InvalidWindowSpec;
        var spec = cobalt.WindowSpec{ .field = field, .kind = kind, .offset = n };
        const rest = it.rest();
        if (rest.len > 0) spec.default = parseValue(rest) catch return error.InvalidWindowSpec;
        return spec;
    }

    const field = it.next() orelse {
        if (kind == .count) return .{ .field = "", .kind = kind };
        return error.InvalidWindowSpec;
    };
    if (it.next() != null) return error.InvalidWindowSpec;
    if (!cobalt.index.validIdentifier(field)) return error.InvalidWindowSpec;
    return .{ .field = field, .kind = kind };
}

fn parseWindowSpecs(allocator: std.mem.Allocator, text: []const u8) ![]cobalt.WindowSpec {
    var specs = std.ArrayList(cobalt.WindowSpec).init(allocator);
    errdefer specs.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidWindowSpec;
        try specs.append(try parseWindowSpec(part));
    }
    if (specs.items.len == 0) return error.InvalidWindowSpec;
    return specs.toOwnedSlice();
}

fn printWindowLabel(stdout: anytype, spec: cobalt.WindowSpec) !void {
    if (spec.field.len == 0) {
        try stdout.writeAll(@tagName(spec.kind));
    } else {
        try stdout.print("{s}_{s}", .{ @tagName(spec.kind), spec.field });
    }
}

fn splitWindowArgs(args: []const []const u8) struct { whereArgs: []const []const u8, partitionArgs: ?[]const []const u8, orderArgs: ?[]const []const u8 } {
    if (findLiteralToken(args, "partition")) |pi| {
        const whereArgs = args[0..pi];
        const afterPartition = args[pi + 1 ..];
        if (findLiteralToken(afterPartition, "order")) |oi| {
            return .{ .whereArgs = whereArgs, .partitionArgs = afterPartition[0..oi], .orderArgs = afterPartition[oi + 1 ..] };
        }
        return .{ .whereArgs = whereArgs, .partitionArgs = afterPartition, .orderArgs = null };
    }
    if (findLiteralToken(args, "order")) |oi| {
        return .{ .whereArgs = args[0..oi], .partitionArgs = null, .orderArgs = args[oi + 1 ..] };
    }
    return .{ .whereArgs = args, .partitionArgs = null, .orderArgs = null };
}

fn parsePartitionList(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |field| {
        if (!cobalt.index.validIdentifier(field)) return error.InvalidPartitionField;
        try list.append(field);
    }
    return list.toOwnedSlice();
}

fn runUser(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "user needs a subcommand (add/passwd/role/del/list)");
    const op = rest[0];
    const args = rest[1..];
    const store = cobalt.AuthStore.init(db);

    if (std.mem.eql(u8, op, "add")) {
        if (args.len < 3) return fail(stderr, "user add needs <username> <password> readonly|readwrite|admin");
        const role = cobalt.AuthRole.parse(args[2]) catch return fail(stderr, "role must be readonly, readwrite, or admin");
        store.createUser(allocator, args[0], args[1], role, cobalt.auth.recommendedRounds) catch |err| {
            return fail(stderr, @errorName(err));
        };
        try stdout.print("user '{s}' created with role {s}\n", .{ args[0], role.name() });
    } else if (std.mem.eql(u8, op, "passwd")) {
        if (args.len < 2) return fail(stderr, "user passwd needs <username> <newpassword>");
        store.setPassword(allocator, args[0], args[1], cobalt.auth.recommendedRounds) catch |err| {
            return fail(stderr, @errorName(err));
        };
        try stdout.print("password updated for '{s}'\n", .{args[0]});
    } else if (std.mem.eql(u8, op, "role")) {
        if (args.len < 2) return fail(stderr, "user role needs <username> readonly|readwrite|admin");
        const role = cobalt.AuthRole.parse(args[1]) catch return fail(stderr, "role must be readonly, readwrite, or admin");
        store.setRole(allocator, args[0], role) catch |err| {
            return fail(stderr, @errorName(err));
        };
        try stdout.print("role for '{s}' set to {s}\n", .{ args[0], role.name() });
    } else if (std.mem.eql(u8, op, "del")) {
        if (args.len < 1) return fail(stderr, "user del needs <username>");
        store.deleteUser(allocator, args[0]) catch |err| {
            return fail(stderr, @errorName(err));
        };
        try stdout.print("user '{s}' deleted\n", .{args[0]});
    } else if (std.mem.eql(u8, op, "list")) {
        const users = try store.listUsers(allocator);
        defer cobalt.auth.freeUserList(allocator, users);
        for (users) |u| try stdout.print("{s}\t{s}\n", .{ u.username, u.role.name() });
    } else {
        return fail(stderr, "unknown user operation");
    }
}

fn runTable(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "table needs a subcommand (put/get/del/delete/scan/select/index/join/aggregate/export/import)");
    const sub = rest[0];
    const args = rest[1..];

    if (std.mem.eql(u8, sub, "put")) {
        if (args.len < 2) return fail(stderr, "table put needs <table> <pk> [field=value ...]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const pk = parseValue(args[1]) catch return fail(stderr, "invalid primary key");

        var fields = std.ArrayList(Field).init(allocator);
        defer fields.deinit();
        for (args[2..]) |raw| {
            const f = parseField(raw) catch return fail(stderr, "invalid field, expected name=value");
            try fields.append(f);
        }
        table.put(pk, fields.items) catch |err| return fail(stderr, @errorName(err));
        try stdout.writeAll("OK\n");
    } else if (std.mem.eql(u8, sub, "get")) {
        if (args.len < 2) return fail(stderr, "table get needs <table> <pk>");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const pk = parseValue(args[1]) catch return fail(stderr, "invalid primary key");
        var got = try table.get(pk);
        if (got) |*row| {
            defer row.deinit();
            try printRow(stdout, row.*);
        } else {
            try stdout.writeAll("(nil)\n");
        }
    } else if (std.mem.eql(u8, sub, "del")) {
        if (args.len < 2) return fail(stderr, "table del needs <table> <pk>");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const pk = parseValue(args[1]) catch return fail(stderr, "invalid primary key");
        try table.delete(pk);
        try stdout.writeAll("OK\n");
    } else if (std.mem.eql(u8, sub, "scan")) {
        if (args.len < 1) return fail(stderr, "table scan needs <table>");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const rows = try table.scanAll();
        defer cobalt.query.freeRows(allocator, rows);
        for (rows) |r| try printRow(stdout, r);
    } else if (std.mem.eql(u8, sub, "select")) {
        if (args.len < 1) return fail(stderr, "table select needs <table> [expr...] [--limit N] [--offset N] [--order-by field[:desc][,field[:desc]...]]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();

        const sel = extractSelectFlags(allocator, args[1..]) catch return fail(stderr, "invalid --limit/--offset/--order-by value");
        defer allocator.free(sel.rest);
        defer allocator.free(sel.flags.orderBy);

        const exprText = try std.mem.join(allocator, " ", sel.rest);
        defer allocator.free(exprText);

        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        const rows = try table.selectPageOrdered(pred, .{ .offset = sel.flags.page.offset, .limit = sel.flags.page.limit }, sel.flags.orderBy);
        defer cobalt.query.freeRows(allocator, rows);
        for (rows) |r| try printRow(stdout, r);
    } else if (std.mem.eql(u8, sub, "explain")) {
        if (args.len < 1) return fail(stderr, "table explain needs <table> [expr...]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();

        const exprText = try std.mem.join(allocator, " ", args[1..]);
        defer allocator.free(exprText);

        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        var plan = try table.explain(allocator, pred);
        defer plan.deinit(allocator);
        try printPlan(stdout, plan);
    } else if (std.mem.eql(u8, sub, "update")) {
        if (args.len < 1) return fail(stderr, "table update needs <table> --set field=value[,field=value...] [expr...]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();

        const setf = extractSetFlag(allocator, args[1..]) catch |err| return fail(stderr, if (err == error.MissingSetFlag)
            "table update requires --set field=value[,field=value...]"
        else
            "invalid --set value");
        defer allocator.free(setf.sets);
        defer allocator.free(setf.rest);

        const exprText = try std.mem.join(allocator, " ", setf.rest);
        defer allocator.free(exprText);

        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        const updated = table.updateWhere(pred, setf.sets) catch |err| return fail(stderr, @errorName(err));
        try stdout.print("{d}\n", .{updated});
    } else if (std.mem.eql(u8, sub, "delete")) {
        if (args.len < 1) return fail(stderr, "table delete needs <table> [expr...]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();

        const exprText = try std.mem.join(allocator, " ", args[1..]);
        defer allocator.free(exprText);

        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        const deleted = table.deleteWhere(pred) catch |err| return fail(stderr, @errorName(err));
        try stdout.print("{d}\n", .{deleted});
    } else if (std.mem.eql(u8, sub, "index")) {
        if (args.len < 3) return fail(stderr, "table index needs create|drop <table> <field...>");
        const action = args[0];
        var positional = std.ArrayList([]const u8).init(allocator);
        defer positional.deinit();
        var unique = false;
        for (args[1..]) |a| {
            if (std.mem.eql(u8, a, "--unique")) {
                unique = true;
            } else {
                try positional.append(a);
            }
        }
        if (positional.items.len < 2) return fail(stderr, "table index needs create|drop <table> <field...>");
        var table = try cobalt.Table.open(db, allocator, positional.items[0]);
        defer table.deinit();
        const fields = positional.items[1..];
        if (std.mem.eql(u8, action, "create")) {
            if (unique) {
                if (fields.len != 1) return fail(stderr, "--unique only supports a single field, not a composite index");
                table.createUniqueIndex(fields[0]) catch |err| return fail(stderr, @errorName(err));
            } else if (fields.len == 1) {
                table.createIndex(fields[0]) catch |err| return fail(stderr, @errorName(err));
            } else {
                const name = try std.mem.join(allocator, "+", fields);
                defer allocator.free(name);
                table.createCompositeIndex(name, fields) catch |err| return fail(stderr, @errorName(err));
            }
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, action, "drop")) {
            if (fields.len == 1) {
                try table.dropIndex(fields[0]);
            } else {
                const name = try std.mem.join(allocator, "+", fields);
                defer allocator.free(name);
                try table.dropCompositeIndex(name);
            }
            try stdout.writeAll("OK\n");
        } else {
            return fail(stderr, "unknown table index action (expected create/drop)");
        }
    } else if (std.mem.eql(u8, sub, "fk")) {
        if (args.len < 2) return fail(stderr, "table fk needs create|drop <table> ...");
        const action = args[0];
        var table = try cobalt.Table.open(db, allocator, args[1]);
        defer table.deinit();
        if (std.mem.eql(u8, action, "create")) {
            if (args.len < 5) return fail(stderr, "table fk create needs <table> <field> <refTable> <refField> [restrict|cascade]");
            const onDelete: cobalt.index.OnDelete = if (args.len < 6 or std.mem.eql(u8, args[5], "restrict"))
                .restrict
            else if (std.mem.eql(u8, args[5], "cascade"))
                .cascade
            else
                return fail(stderr, "table fk create: last argument must be restrict or cascade");
            table.createForeignKey(args[2], args[3], args[4], onDelete) catch |err| return fail(stderr, @errorName(err));
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, action, "drop")) {
            if (args.len < 3) return fail(stderr, "table fk drop needs <table> <field>");
            try table.dropForeignKey(args[2]);
            try stdout.writeAll("OK\n");
        } else {
            return fail(stderr, "unknown table fk action (expected create/drop)");
        }
    } else if (std.mem.eql(u8, sub, "check")) {
        if (args.len < 2) return fail(stderr, "table check needs create|drop <table> ...");
        const action = args[0];
        var table = try cobalt.Table.open(db, allocator, args[1]);
        defer table.deinit();
        if (std.mem.eql(u8, action, "create")) {
            if (args.len < 4) return fail(stderr, "table check create needs <table> <name> <expr...>");
            const source = try std.mem.join(allocator, " ", args[3..]);
            defer allocator.free(source);
            table.createCheckConstraint(args[2], source) catch |err| return fail(stderr, @errorName(err));
            try stdout.writeAll("OK\n");
        } else if (std.mem.eql(u8, action, "drop")) {
            if (args.len < 3) return fail(stderr, "table check drop needs <table> <name>");
            try table.dropCheckConstraint(args[2]);
            try stdout.writeAll("OK\n");
        } else {
            return fail(stderr, "unknown table check action (expected create/drop)");
        }
    } else if (std.mem.eql(u8, sub, "join")) {
        const JoinMode = enum { inner, left, right, full };
        var mode: JoinMode = .inner;
        var positional = std.ArrayList([]const u8).init(allocator);
        defer positional.deinit();
        for (args) |a| {
            if (std.mem.eql(u8, a, "--left")) {
                mode = .left;
            } else if (std.mem.eql(u8, a, "--right")) {
                mode = .right;
            } else if (std.mem.eql(u8, a, "--full")) {
                mode = .full;
            } else {
                try positional.append(a);
            }
        }
        const pf = extractPageFlags(allocator, positional.items) catch return fail(stderr, "invalid --limit/--offset value");
        defer allocator.free(pf.rest);
        if (pf.rest.len < 4) return fail(stderr, "table join needs [--left|--right|--full] <leftTable> <leftField> <rightTable> <rightField> [--limit N] [--offset N]");
        const jargs = pf.rest;
        const page = cobalt.query.Page{ .offset = pf.page.offset, .limit = pf.page.limit };

        var left = try cobalt.Table.open(db, allocator, jargs[0]);
        defer left.deinit();
        var right = try cobalt.Table.open(db, allocator, jargs[2]);
        defer right.deinit();

        switch (mode) {
            .inner => {
                const joined = cobalt.join.innerJoin(allocator, &left, jargs[1], null, &right, jargs[3], null) catch |err| return fail(stderr, @errorName(err));
                const paged = cobalt.join.applyPage(cobalt.join.JoinedRow, allocator, joined, page) catch |err| return fail(stderr, @errorName(err));
                defer cobalt.join.freeJoined(allocator, paged);
                for (paged) |pair| {
                    try stdout.writeAll("L ");
                    try printRow(stdout, pair.left);
                    try stdout.writeAll("R ");
                    try printRow(stdout, pair.right);
                }
            },
            .left => {
                const joined = cobalt.join.leftOuterJoin(allocator, &left, jargs[1], null, &right, jargs[3], null) catch |err| return fail(stderr, @errorName(err));
                const paged = cobalt.join.applyPage(cobalt.join.OuterJoinedRow, allocator, joined, page) catch |err| return fail(stderr, @errorName(err));
                defer cobalt.join.freeOuterJoined(allocator, paged);
                for (paged) |pair| {
                    try stdout.writeAll("L ");
                    try printRow(stdout, pair.left);
                    if (pair.right) |r| {
                        try stdout.writeAll("R ");
                        try printRow(stdout, r);
                    } else {
                        try stdout.writeAll("R (nil)\n");
                    }
                }
            },
            .right => {
                const joined = cobalt.join.rightOuterJoin(allocator, &left, jargs[1], null, &right, jargs[3], null) catch |err| return fail(stderr, @errorName(err));
                const paged = cobalt.join.applyPage(cobalt.join.RightOuterJoinedRow, allocator, joined, page) catch |err| return fail(stderr, @errorName(err));
                defer cobalt.join.freeRightOuterJoined(allocator, paged);
                for (paged) |pair| {
                    if (pair.left) |l| {
                        try stdout.writeAll("L ");
                        try printRow(stdout, l);
                    } else {
                        try stdout.writeAll("L (nil)\n");
                    }
                    try stdout.writeAll("R ");
                    try printRow(stdout, pair.right);
                }
            },
            .full => {
                const joined = cobalt.join.fullOuterJoin(allocator, &left, jargs[1], null, &right, jargs[3], null) catch |err| return fail(stderr, @errorName(err));
                const paged = cobalt.join.applyPage(cobalt.join.FullOuterJoinedRow, allocator, joined, page) catch |err| return fail(stderr, @errorName(err));
                defer cobalt.join.freeFullOuterJoined(allocator, paged);
                for (paged) |pair| {
                    if (pair.left) |l| {
                        try stdout.writeAll("L ");
                        try printRow(stdout, l);
                    } else {
                        try stdout.writeAll("L (nil)\n");
                    }
                    if (pair.right) |r| {
                        try stdout.writeAll("R ");
                        try printRow(stdout, r);
                    } else {
                        try stdout.writeAll("R (nil)\n");
                    }
                }
            },
        }
    } else if (std.mem.eql(u8, sub, "aggregate")) {
        if (args.len < 3) return fail(stderr, "table aggregate needs <table> <groupField|*> <spec>[,<spec>...] [expr...] [having <expr>] [order <field[:desc]>[,field...]] [--limit N] [--offset N]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const groupField = args[1];

        const specs = parseAggSpecs(allocator, args[2]) catch return fail(stderr, "invalid aggregate spec (expected count | count:field | sum:field | avg:field | min:field | max:field | distinct:field, comma-separated)");
        defer allocator.free(specs);

        const flags = extractPageFlags(allocator, args[3..]) catch return fail(stderr, "invalid --limit/--offset value");
        defer allocator.free(flags.rest);

        const split = splitAggFilterArgs(flags.rest);

        const exprText = try std.mem.join(allocator, " ", split.whereArgs);
        defer allocator.free(exprText);
        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        var havingParsed: ?cobalt.expr.Parsed = null;
        defer if (havingParsed) |*p| p.deinit();
        var havingPred: ?cobalt.Predicate = null;
        if (split.havingArgs) |havingArgs| {
            const havingText = try std.mem.join(allocator, " ", havingArgs);
            defer allocator.free(havingText);
            if (havingText.len == 0) return fail(stderr, "having requires an expression");
            havingParsed = cobalt.expr.parse(allocator, havingText) catch |err| return fail(stderr, @errorName(err));
            havingPred = havingParsed.?.predicate;
        }

        var orderBy: []cobalt.query.OrderBy = &.{};
        defer allocator.free(orderBy);
        if (split.orderArgs) |orderArgs| {
            if (orderArgs.len != 1) return fail(stderr, "order requires exactly one comma-separated field list");
            orderBy = parseOrderByList(allocator, orderArgs[0]) catch return fail(stderr, "invalid order field list");
        }

        const rows = try table.select(pred);
        defer cobalt.query.freeRows(allocator, rows);

        if (std.mem.eql(u8, groupField, "*")) {
            const values = cobalt.aggregate.runGlobal(allocator, rows, specs) catch |err| return fail(stderr, @errorName(err));
            defer cobalt.aggregate.freeGlobalResult(allocator, values);
            const matches = if (havingPred) |hp|
                cobalt.aggregate.globalMatchesHaving(allocator, specs, values, hp) catch |err| return fail(stderr, @errorName(err))
            else
                true;
            if (matches) {
                for (specs, values, 0..) |spec, v, i| {
                    if (i > 0) try stdout.writeAll("\t");
                    try printAggLabel(stdout, spec);
                    try stdout.writeAll("=");
                    try printValue(stdout, v);
                }
                try stdout.writeAll("\n");
            }
        } else {
            const unpaged = cobalt.aggregate.run(allocator, rows, groupField, specs) catch |err| return fail(stderr, @errorName(err));
            const filtered = if (havingPred) |hp|
                cobalt.aggregate.filterHaving(allocator, unpaged, groupField, specs, hp) catch |err| return fail(stderr, @errorName(err))
            else
                unpaged;
            if (orderBy.len > 0) {
                cobalt.aggregate.sortGroupsBy(allocator, filtered, groupField, specs, orderBy) catch |err| return fail(stderr, @errorName(err));
            }
            const groups = cobalt.aggregate.applyPageGroups(allocator, filtered, .{ .offset = flags.page.offset, .limit = flags.page.limit }) catch |err| return fail(stderr, @errorName(err));
            defer {
                for (groups) |*g| g.deinit(allocator);
                allocator.free(groups);
            }
            for (groups) |g| {
                try stdout.writeAll("group=");
                try printValue(stdout, g.group);
                for (specs, g.values) |spec, v| {
                    try stdout.writeAll("\t");
                    try printAggLabel(stdout, spec);
                    try stdout.writeAll("=");
                    try printValue(stdout, v);
                }
                try stdout.writeAll("\n");
            }
        }
    } else if (std.mem.eql(u8, sub, "window")) {
        if (args.len < 2) return fail(stderr, "table window needs <table> <kind[:field]>[,<kind[:field]>...] [expr...] [partition <field>[,field...]] [order <field[:desc]>[,field...]] [--limit N] [--offset N] [--range]");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();

        const specs = parseWindowSpecs(allocator, args[1]) catch return fail(stderr, "invalid window spec (expected row_number | rank | dense_rank | sum:field | avg:field | count | count:field | count_distinct:field | min:field | max:field | first_value:field | last_value:field | nth_value:field:n[:default] | lag:field[:offset[:default]] | lead:field[:offset[:default]], comma-separated)");
        defer allocator.free(specs);

        const flags = extractPageFlags(allocator, args[2..]) catch return fail(stderr, "invalid --limit/--offset value");
        defer allocator.free(flags.rest);

        const rangeFlag = try extractRangeFlag(allocator, flags.rest);
        defer allocator.free(rangeFlag.rest);
        const frame: cobalt.window.FrameMode = if (rangeFlag.range) .range else .rows;

        const split = splitWindowArgs(rangeFlag.rest);

        const exprText = try std.mem.join(allocator, " ", split.whereArgs);
        defer allocator.free(exprText);
        var parsed: ?cobalt.expr.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = cobalt.expr.parse(allocator, exprText) catch |err| return fail(stderr, @errorName(err));
        }
        const pred: ?cobalt.Predicate = if (parsed) |p| p.predicate else null;

        var partitionBy: [][]const u8 = &.{};
        defer allocator.free(partitionBy);
        if (split.partitionArgs) |partitionArgs| {
            if (partitionArgs.len != 1) return fail(stderr, "partition requires exactly one comma-separated field list");
            partitionBy = parsePartitionList(allocator, partitionArgs[0]) catch return fail(stderr, "invalid partition field list");
        }

        var orderBy: []cobalt.query.OrderBy = &.{};
        defer allocator.free(orderBy);
        if (split.orderArgs) |orderArgs| {
            if (orderArgs.len != 1) return fail(stderr, "order requires exactly one comma-separated field list");
            orderBy = parseOrderByList(allocator, orderArgs[0]) catch return fail(stderr, "invalid order field list");
        }

        const rows = try table.select(pred);
        defer cobalt.query.freeRows(allocator, rows);

        const results = cobalt.window.computeMany(allocator, rows, partitionBy, orderBy, specs, frame) catch |err| return fail(stderr, @errorName(err));
        defer cobalt.window.freeManyResults(allocator, results);

        const displayOrder = cobalt.window.orderedIndices(allocator, rows, partitionBy, orderBy) catch |err| return fail(stderr, @errorName(err));
        defer allocator.free(displayOrder);

        const total = displayOrder.len;
        const start = @min(flags.page.offset, total);
        const end = if (flags.page.limit == 0) total else @min(start + flags.page.limit, total);
        var i: usize = start;
        while (i < end) : (i += 1) {
            const idx = displayOrder[i];
            for (rows[idx].fields.items, 0..) |f, j| {
                if (j > 0) try stdout.writeAll("\t");
                try stdout.print("{s}=", .{f.name});
                try printValue(stdout, f.value);
            }
            if (rows[idx].fields.items.len > 0) try stdout.writeAll("\t");
            for (specs, 0..) |spec, specIdx| {
                if (specIdx > 0) try stdout.writeAll("\t");
                try printWindowLabel(stdout, spec);
                try stdout.writeAll("=");
                try printValue(stdout, results[idx][specIdx]);
            }
            try stdout.writeAll("\n");
        }
    } else if (std.mem.eql(u8, sub, "export")) {
        if (args.len < 3) return fail(stderr, "table export needs <table> csv|json <path>");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const n = if (std.mem.eql(u8, args[1], "csv"))
            cobalt.dump.exportCsv(allocator, &table, args[2]) catch |err| return fail(stderr, @errorName(err))
        else if (std.mem.eql(u8, args[1], "json"))
            cobalt.dump.exportJson(allocator, &table, args[2]) catch |err| return fail(stderr, @errorName(err))
        else
            return fail(stderr, "table export format must be csv or json");
        try stdout.print("{d}\n", .{n});
    } else if (std.mem.eql(u8, sub, "import")) {
        if (args.len < 3) return fail(stderr, "table import needs <table> csv|json <path>");
        var table = try cobalt.Table.open(db, allocator, args[0]);
        defer table.deinit();
        const n = if (std.mem.eql(u8, args[1], "csv"))
            cobalt.dump.importCsv(allocator, &table, args[2]) catch |err| return fail(stderr, @errorName(err))
        else if (std.mem.eql(u8, args[1], "json"))
            cobalt.dump.importJson(allocator, &table, args[2]) catch |err| return fail(stderr, @errorName(err))
        else
            return fail(stderr, "table import format must be csv or json");
        try stdout.print("{d}\n", .{n});
    } else {
        return fail(stderr, "unknown table operation");
    }
}

fn runRepl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, rest: []const []const u8) !void {
    var session = cobalt.Repl.init(allocator, db);
    defer session.deinit();

    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--script")) {
        const contents = std.fs.cwd().readFileAlloc(allocator, rest[1], 16 * 1024 * 1024) catch |err| {
            try stderr.print("failed to read script '{s}': {s}\n", .{ rest[1], @errorName(err) });
            std.process.exit(1);
        };
        defer allocator.free(contents);
        var stream = std.io.fixedBufferStream(contents);
        try session.runFromReader(stream.reader(), stdout, false);
        return;
    }

    const stdinReader = std.io.getStdIn().reader();
    try session.runFromReader(stdinReader, stdout, true);
}

fn runTxn(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "txn needs <script-file>");

    const contents = std.fs.cwd().readFileAlloc(allocator, rest[0], 16 * 1024 * 1024) catch |err| {
        try stderr.print("failed to read script '{s}': {s}\n", .{ rest[0], @errorName(err) });
        std.process.exit(1);
    };
    defer allocator.free(contents);

    var txn = cobalt.Transaction.begin(db);
    defer txn.deinit();

    var tables = std.StringHashMap(cobalt.TableTxn).init(allocator);
    defer {
        var it = tables.valueIterator();
        while (it.next()) |t| t.deinit();
        tables.deinit();
    }

    var applied: usize = 0;
    var lineNo: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |rawLine| {
        lineNo += 1;
        const line = std.mem.trim(u8, rawLine, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tok = std.mem.tokenizeScalar(u8, line, ' ');
        const verb = tok.next() orelse continue;
        const tableName = tok.next() orelse {
            try stderr.print("line {d}: missing table name\n", .{lineNo});
            std.process.exit(2);
        };
        const pkText = tok.next() orelse {
            try stderr.print("line {d}: missing primary key\n", .{lineNo});
            std.process.exit(2);
        };
        const pk = parseValue(pkText) catch {
            try stderr.print("line {d}: invalid primary key '{s}'\n", .{ lineNo, pkText });
            std.process.exit(2);
        };

        const gop = try tables.getOrPut(tableName);
        if (!gop.found_existing) {
            gop.key_ptr.* = tableName;
            gop.value_ptr.* = cobalt.TableTxn.open(&txn, allocator, tableName) catch |err| {
                try stderr.print("line {d}: cannot open table '{s}': {s}\n", .{ lineNo, tableName, @errorName(err) });
                std.process.exit(2);
            };
        }
        const table = gop.value_ptr;

        if (std.mem.eql(u8, verb, "put")) {
            var fields = std.ArrayList(Field).init(allocator);
            defer fields.deinit();
            while (tok.next()) |raw| {
                const f = parseField(raw) catch {
                    try stderr.print("line {d}: invalid field '{s}'\n", .{ lineNo, raw });
                    std.process.exit(2);
                };
                try fields.append(f);
            }
            table.put(pk, fields.items) catch |err| {
                try stderr.print("line {d}: put failed: {s}\n", .{ lineNo, @errorName(err) });
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, verb, "del")) {
            table.delete(pk) catch |err| {
                try stderr.print("line {d}: del failed: {s}\n", .{ lineNo, @errorName(err) });
                std.process.exit(1);
            };
        } else {
            try stderr.print("line {d}: unknown verb '{s}' (expected put/del)\n", .{ lineNo, verb });
            std.process.exit(2);
        }
        applied += 1;
    }

    if (applied == 0) return fail(stderr, "txn script had no operations");

    txn.commit() catch |err| {
        try stderr.print("transaction failed, nothing applied: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("OK: {d} operation(s) committed atomically\n", .{applied});
}

fn runReplicate(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, db: *cobalt.Db, replicaDir: []const u8, rest: []const []const u8) !void {
    var once = false;
    var intervalMs: u64 = 200;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--once")) {
            once = true;
        } else if (std.mem.eql(u8, rest[i], "--interval-ms")) {
            i += 1;
            if (i >= rest.len) {
                try stdout.writeAll("error: --interval-ms needs a value\n");
                std.process.exit(2);
            }
            intervalMs = std.fmt.parseInt(u64, rest[i], 10) catch {
                try stdout.writeAll("error: --interval-ms needs an integer\n");
                std.process.exit(2);
            };
        } else {
            try stdout.print("error: unknown replicate flag '{s}'\n", .{rest[i]});
            std.process.exit(2);
        }
    }

    var replica = try openOrExit(allocator, stderr, replicaDir, "");
    defer replica.close();

    const resumeState = cobalt.replicate.loadOffset(allocator, replicaDir, db.dirPath) catch |err| switch (err) {
        cobalt.replicate.StateError.PrimaryMismatch => {
            try stdout.print("error: replica at '{s}' has persisted state for a different primary than '{s}' - refusing to resume against the wrong primary\n", .{ replicaDir, db.dirPath });
            std.process.exit(1);
        },
        else => return err,
    };

    var rep = if (resumeState) |state|
        try cobalt.Replicator.initFromOffset(allocator, db.dirPath, &replica, state.offset, state.generation)
    else
        try cobalt.Replicator.init(allocator, db.dirPath, &replica);
    defer rep.deinit();

    if (resumeState) |state| {
        try stdout.print("resuming tail from persisted offset={d} generation={d}\n", .{ state.offset, state.generation });
    } else {
        const bootstrapped = try rep.fullResync(db, 500);
        try stdout.print("bootstrap: {d} entries copied from snapshot\n", .{bootstrapped});
        try cobalt.replicate.saveState(allocator, replicaDir, db.dirPath, rep.offset(), rep.generation());
    }

    while (true) {
        const applied = rep.syncOnce() catch |err| switch (err) {
            cobalt.ReplicateError.WalTruncatedAheadOfTailer, cobalt.ReplicateError.WalGenerationChanged => blk: {
                const recovered = try rep.fullResync(db, 500);
                try stdout.print("resync after truncation: {d} entries\n", .{recovered});
                try cobalt.replicate.saveState(allocator, replicaDir, db.dirPath, rep.offset(), rep.generation());
                break :blk @as(usize, 0);
            },
            else => return err,
        };
        if (applied > 0) {
            try stdout.print("applied {d} record(s), tail offset={d}\n", .{ applied, rep.offset() });
            try cobalt.replicate.saveState(allocator, replicaDir, db.dirPath, rep.offset(), rep.generation());
        }
        if (once) break;
        std.time.sleep(intervalMs * std.time.ns_per_ms);
    }
}

fn parseHostPort(stdout: anytype, spec: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse {
        try stdout.print("error: address must be host:port, got '{s}'\n", .{spec});
        std.process.exit(2);
    };
    const host = spec[0..colon];
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch {
        try stdout.print("error: invalid port in '{s}'\n", .{spec});
        std.process.exit(2);
    };
    return std.net.Address.parseIp(host, port);
}

const AuthFlags = struct { username: ?[]const u8 = null, password: ?[]const u8 = null, token: ?[]const u8 = null };

fn extractAuthFlags(allocator: std.mem.Allocator, args: []const []const u8) !struct { auth: AuthFlags, rest: [][]const u8 } {
    var authFlags = AuthFlags{};
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const isUser = std.mem.eql(u8, args[i], "--user");
        const isPass = std.mem.eql(u8, args[i], "--pass");
        const isToken = std.mem.eql(u8, args[i], "--token");
        if (isUser or isPass or isToken) {
            i += 1;
            if (i >= args.len) return error.InvalidAuthFlag;
            if (isUser) authFlags.username = args[i] else if (isPass) authFlags.password = args[i] else authFlags.token = args[i];
        } else {
            try rest.append(args[i]);
        }
    }
    return .{ .auth = authFlags, .rest = try rest.toOwnedSlice() };
}

fn authenticateIfRequested(client: *cobalt.Client, stderr: anytype, authFlags: AuthFlags) !void {
    if (authFlags.token) |token| {
        client.authenticateWithToken(token) catch |err| {
            try stderr.print("error: token authentication failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (authFlags.username) |username| {
        client.authenticate(username, authFlags.password orelse "") catch |err| {
            try stderr.print("error: authentication failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        if (client.sessionToken()) |token| {
            try stderr.print("session token (use with --token): {s}\n", .{token});
        }
    }
}

fn runRemoteSelect(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-select needs <table> [expr...] [--limit N] [--offset N] [--order-by field[:desc][,field[:desc]...]]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const sel = extractSelectFlags(allocator, authFlags.rest) catch return fail(stderr, "invalid --limit/--offset/--order-by value");
    defer allocator.free(sel.rest);
    defer allocator.free(sel.flags.orderBy);

    const exprText = try std.mem.join(allocator, " ", sel.rest);
    defer allocator.free(exprText);

    const rows = client.tableSelect(allocator, rest[0], exprText, sel.flags.page.offset, sel.flags.page.limit, sel.flags.orderBy) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer cobalt.protocol.freeRows(allocator, rows);
    for (rows) |r| try printRow(stdout, r);
}

fn runRemoteExplain(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-explain needs <table> [expr...]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const exprText = try std.mem.join(allocator, " ", authFlags.rest);
    defer allocator.free(exprText);

    var plan = client.tableExplain(allocator, rest[0], exprText) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer plan.deinit(allocator);
    try printPlan(stdout, plan);
}

fn runRemoteUpdate(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-update needs <table> --set field=value[,field=value...] [expr...]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const setf = extractSetFlag(allocator, authFlags.rest) catch |err| return fail(stderr, if (err == error.MissingSetFlag)
        "remote-update requires --set field=value[,field=value...]"
    else
        "invalid --set value");
    defer allocator.free(setf.sets);
    defer allocator.free(setf.rest);

    const exprText = try std.mem.join(allocator, " ", setf.rest);
    defer allocator.free(exprText);

    const updated = client.tableUpdate(rest[0], setf.sets, exprText) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("{d}\n", .{updated});
}

fn runRemoteDelete(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-delete needs <table> [expr...]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const exprText = try std.mem.join(allocator, " ", authFlags.rest);
    defer allocator.free(exprText);

    const deleted = client.tableDelete(rest[0], exprText) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("{d}\n", .{deleted});
}

fn parseDumpFormat(stderr: anytype, text: []const u8) !cobalt.protocol.DumpFormat {
    if (std.mem.eql(u8, text, "csv")) return .csv;
    if (std.mem.eql(u8, text, "json")) return .json;
    try fail(stderr, "format must be csv or json");
    unreachable;
}

fn runRemoteExport(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-export needs <table> csv|json <path>");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const args = authFlags.rest;
    if (args.len < 2) return fail(stderr, "remote-export needs <table> csv|json <path>");
    const format = try parseDumpFormat(stderr, args[0]);

    var result = client.tableExport(allocator, rest[0], format) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer result.deinit(allocator);

    const file = std.fs.cwd().createFile(args[1], .{ .truncate = true }) catch |err| {
        try stderr.print("failed to write '{s}': {s}\n", .{ args[1], @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();
    try file.writeAll(result.content);

    try stdout.print("{d}\n", .{result.rowCount});
}

fn runRemoteImport(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-import needs <table> csv|json <path>");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const args = authFlags.rest;
    if (args.len < 2) return fail(stderr, "remote-import needs <table> csv|json <path>");
    const format = try parseDumpFormat(stderr, args[0]);

    const content = std.fs.cwd().readFileAlloc(allocator, args[1], 1 << 30) catch |err| {
        try stderr.print("failed to read '{s}': {s}\n", .{ args[1], @errorName(err) });
        std.process.exit(1);
    };
    defer allocator.free(content);

    const imported = client.tableImport(rest[0], format, content) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("{d}\n", .{imported});
}

const JoinCliMode = enum { inner, left, right, full };

fn extractJoinFlags(allocator: std.mem.Allocator, args: []const []const u8) !struct {
    mode: JoinCliMode,
    leftExpr: []const u8,
    rightExpr: []const u8,
    rest: [][]const u8,
} {
    var mode: JoinCliMode = .inner;
    var leftExpr: []const u8 = "";
    var rightExpr: []const u8 = "";
    var rest = std.ArrayList([]const u8).init(allocator);
    errdefer rest.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--left")) {
            mode = .left;
        } else if (std.mem.eql(u8, args[i], "--right")) {
            mode = .right;
        } else if (std.mem.eql(u8, args[i], "--full")) {
            mode = .full;
        } else if (std.mem.eql(u8, args[i], "--left-expr")) {
            i += 1;
            if (i >= args.len) return error.InvalidJoinFlag;
            leftExpr = args[i];
        } else if (std.mem.eql(u8, args[i], "--right-expr")) {
            i += 1;
            if (i >= args.len) return error.InvalidJoinFlag;
            rightExpr = args[i];
        } else {
            try rest.append(args[i]);
        }
    }
    return .{ .mode = mode, .leftExpr = leftExpr, .rightExpr = rightExpr, .rest = try rest.toOwnedSlice() };
}

fn runRemoteJoin(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const jf = extractJoinFlags(allocator, authFlags.rest) catch return fail(stderr, "invalid --left-expr/--right-expr value");
    defer allocator.free(jf.rest);

    const pf = extractPageFlags(allocator, jf.rest) catch return fail(stderr, "invalid --limit/--offset value");
    defer allocator.free(pf.rest);

    if (pf.rest.len < 4) return fail(stderr, "remote-join needs [--left|--right|--full] <leftTable> <leftField> <rightTable> <rightField> [--left-expr E] [--right-expr E] [--limit N] [--offset N]");

    const mode: cobalt.protocol.JoinMode = switch (jf.mode) {
        .inner => .inner,
        .left => .left,
        .right => .right,
        .full => .full,
    };

    const pairs = client.tableJoin(allocator, mode, pf.rest[0], pf.rest[1], pf.rest[2], pf.rest[3], pf.page.offset, pf.page.limit, jf.leftExpr, jf.rightExpr) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer cobalt.protocol.freeJoinPairs(allocator, pairs);

    for (pairs) |p| {
        if (p.left) |l| {
            try stdout.writeAll("L ");
            try printRow(stdout, l);
        } else {
            try stdout.writeAll("L (nil)\n");
        }
        if (p.right) |r| {
            try stdout.writeAll("R ");
            try printRow(stdout, r);
        } else {
            try stdout.writeAll("R (nil)\n");
        }
    }
}

fn runRemoteAggregate(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 3) return fail(stderr, "remote-aggregate needs <table> <groupField|*> <spec>[,<spec>...] [expr...] [having <expr>] [order <field[:desc]>[,field...]] [--limit N] [--offset N]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const table = rest[0];
    const groupField = rest[1];
    const specs = parseAggSpecs(allocator, rest[2]) catch return fail(stderr, "invalid aggregate spec (expected count | count:field | sum:field | avg:field | min:field | max:field | distinct:field, comma-separated)");
    defer allocator.free(specs);

    const authFlags = extractAuthFlags(allocator, rest[3..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const flags = extractPageFlags(allocator, authFlags.rest) catch return fail(stderr, "invalid --limit/--offset value");
    defer allocator.free(flags.rest);

    const split = splitAggFilterArgs(flags.rest);

    const exprText = try std.mem.join(allocator, " ", split.whereArgs);
    defer allocator.free(exprText);

    const havingText = if (split.havingArgs) |ha| try std.mem.join(allocator, " ", ha) else try allocator.dupe(u8, "");
    defer allocator.free(havingText);
    if (split.havingArgs != null and havingText.len == 0) return fail(stderr, "having requires an expression");

    var orderBy: []cobalt.query.OrderBy = &.{};
    defer allocator.free(orderBy);
    if (split.orderArgs) |orderArgs| {
        if (orderArgs.len != 1) return fail(stderr, "order requires exactly one comma-separated field list");
        orderBy = parseOrderByList(allocator, orderArgs[0]) catch return fail(stderr, "invalid order field list");
    }

    if (std.mem.eql(u8, groupField, "*")) {
        const values = client.tableAggregateGlobal(allocator, table, specs, havingText, exprText) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer cobalt.protocol.freeAggValues(allocator, values);
        if (values.len > 0) {
            for (specs, values, 0..) |spec, v, i| {
                if (i > 0) try stdout.writeAll("\t");
                try printAggLabel(stdout, spec);
                try stdout.writeAll("=");
                try printValue(stdout, v);
            }
            try stdout.writeAll("\n");
        }
    } else {
        const groups = client.tableAggregateGroups(allocator, table, groupField, specs, flags.page.offset, flags.page.limit, orderBy, havingText, exprText) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer cobalt.protocol.freeAggGroupRows(allocator, groups);
        for (groups) |g| {
            try stdout.writeAll("group=");
            try printValue(stdout, g.group);
            for (specs, g.values) |spec, v| {
                try stdout.writeAll("\t");
                try printAggLabel(stdout, spec);
                try stdout.writeAll("=");
                try printValue(stdout, v);
            }
            try stdout.writeAll("\n");
        }
    }
}

fn parseChannelList(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |ch| {
        if (ch.len == 0) return error.EmptyChannelName;
        try list.append(ch);
    }
    return list.toOwnedSlice();
}

fn runRemotePublish(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 2) return fail(stderr, "remote-publish needs <channel> <message...> [--user NAME --pass PASS] [--token TOKEN]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const channel = rest[0];

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    if (authFlags.rest.len == 0) return fail(stderr, "remote-publish needs a message");
    const message = try std.mem.join(allocator, " ", authFlags.rest);
    defer allocator.free(message);

    const count = client.publish(channel, message) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("{d}\n", .{count});
}

fn runRemoteSubscribe(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-subscribe needs <channel>[,channel...] [--user NAME --pass PASS] [--token TOKEN]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const channels = parseChannelList(allocator, rest[0]) catch return fail(stderr, "invalid channel list (empty channel name)");
    defer allocator.free(channels);

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const subscriberId = client.subscribe(channels) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("subscribed as {d}\n", .{subscriberId});

    while (try client.nextMessage(allocator)) |msg| {
        defer msg.deinit(allocator);
        try stdout.print("{s}: {s}\n", .{ msg.channel, msg.payload });
    }
}

fn runRemoteUnsubscribe(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 2) return fail(stderr, "remote-unsubscribe needs <subscriber-id> <channel>[,channel...] [--user NAME --pass PASS] [--token TOKEN]");
    const address = try parseHostPort(stdout, addressSpec);

    const subscriberId = std.fmt.parseInt(u64, rest[0], 10) catch return fail(stderr, "invalid <subscriber-id> (expected a non-negative integer)");

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const channels = parseChannelList(allocator, rest[1]) catch return fail(stderr, "invalid channel list (empty channel name)");
    defer allocator.free(channels);

    const authFlags = extractAuthFlags(allocator, rest[2..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const removed = client.unsubscribe(subscriberId, channels) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("{d}\n", .{removed});
}

fn runRemoteWindow(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 2) return fail(stderr, "remote-window needs <table> <kind[:field]>[,<kind[:field]>...] [expr...] [partition <field>[,field...]] [order <field[:desc]>[,field...]] [--limit N] [--offset N] [--range]");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const table = rest[0];
    const specs = parseWindowSpecs(allocator, rest[1]) catch return fail(stderr, "invalid window spec (expected row_number | rank | dense_rank | sum:field | avg:field | count | count:field | count_distinct:field | min:field | max:field | first_value:field | last_value:field | nth_value:field:n[:default] | lag:field[:offset[:default]] | lead:field[:offset[:default]], comma-separated)");
    defer allocator.free(specs);

    const authFlags = extractAuthFlags(allocator, rest[2..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const flags = extractPageFlags(allocator, authFlags.rest) catch return fail(stderr, "invalid --limit/--offset value");
    defer allocator.free(flags.rest);

    const rangeFlag = try extractRangeFlag(allocator, flags.rest);
    defer allocator.free(rangeFlag.rest);
    const frame: cobalt.window.FrameMode = if (rangeFlag.range) .range else .rows;

    const split = splitWindowArgs(rangeFlag.rest);

    const exprText = try std.mem.join(allocator, " ", split.whereArgs);
    defer allocator.free(exprText);

    var partitionBy: [][]const u8 = &.{};
    defer allocator.free(partitionBy);
    if (split.partitionArgs) |partitionArgs| {
        if (partitionArgs.len != 1) return fail(stderr, "partition requires exactly one comma-separated field list");
        partitionBy = parsePartitionList(allocator, partitionArgs[0]) catch return fail(stderr, "invalid partition field list");
    }

    var orderBy: []cobalt.query.OrderBy = &.{};
    defer allocator.free(orderBy);
    if (split.orderArgs) |orderArgs| {
        if (orderArgs.len != 1) return fail(stderr, "order requires exactly one comma-separated field list");
        orderBy = parseOrderByList(allocator, orderArgs[0]) catch return fail(stderr, "invalid order field list");
    }

    const results = client.tableWindow(allocator, table, specs, partitionBy, orderBy, flags.page.offset, flags.page.limit, exprText, frame) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer cobalt.protocol.freeWindowRows(allocator, results);

    for (results) |wr| {
        for (wr.row.fields.items, 0..) |f, j| {
            if (j > 0) try stdout.writeAll("\t");
            try stdout.print("{s}=", .{f.name});
            try printValue(stdout, f.value);
        }
        if (wr.row.fields.items.len > 0) try stdout.writeAll("\t");
        for (specs, 0..) |spec, specIdx| {
            if (specIdx > 0) try stdout.writeAll("\t");
            try printWindowLabel(stdout, spec);
            try stdout.writeAll("=");
            try printValue(stdout, wr.values[specIdx]);
        }
        try stdout.writeAll("\n");
    }
}

fn runRemoteTxn(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-txn needs <script-file> [--user NAME --pass PASS] [--token TOKEN]");
    const address = try parseHostPort(stdout, addressSpec);

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    const contents = std.fs.cwd().readFileAlloc(allocator, rest[0], 16 * 1024 * 1024) catch |err| {
        try stderr.print("failed to read script '{s}': {s}\n", .{ rest[0], @errorName(err) });
        std.process.exit(1);
    };
    defer allocator.free(contents);

    var entries = std.ArrayList(cobalt.protocol.TxnOpEntry).init(allocator);
    defer {
        for (entries.items) |e| allocator.free(e.fields);
        entries.deinit();
    }

    var lineNo: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |rawLine| {
        lineNo += 1;
        const line = std.mem.trim(u8, rawLine, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tok = std.mem.tokenizeScalar(u8, line, ' ');
        const verb = tok.next() orelse continue;
        const tableName = tok.next() orelse {
            try stderr.print("line {d}: missing table name\n", .{lineNo});
            std.process.exit(2);
        };
        const pkText = tok.next() orelse {
            try stderr.print("line {d}: missing primary key\n", .{lineNo});
            std.process.exit(2);
        };
        const pk = parseValue(pkText) catch {
            try stderr.print("line {d}: invalid primary key '{s}'\n", .{ lineNo, pkText });
            std.process.exit(2);
        };

        if (std.mem.eql(u8, verb, "put")) {
            var fields = std.ArrayList(Field).init(allocator);
            errdefer fields.deinit();
            while (tok.next()) |raw| {
                const f = parseField(raw) catch {
                    try stderr.print("line {d}: invalid field '{s}'\n", .{ lineNo, raw });
                    std.process.exit(2);
                };
                try fields.append(f);
            }
            try entries.append(.{ .verb = .put, .table = tableName, .pk = pk, .fields = try fields.toOwnedSlice() });
        } else if (std.mem.eql(u8, verb, "del")) {
            try entries.append(.{ .verb = .del, .table = tableName, .pk = pk, .fields = &.{} });
        } else {
            try stderr.print("line {d}: unknown verb '{s}' (expected put/del)\n", .{ lineNo, verb });
            std.process.exit(2);
        }
    }

    if (entries.items.len == 0) return fail(stderr, "txn script had no operations");

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const applied = client.txnOp(entries.items) catch |err| {
        try stderr.print("transaction failed, nothing applied: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    try stdout.print("OK: {d} operation(s) committed atomically\n", .{applied});
}

fn runRemoteUser(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-user needs a subcommand (add/passwd/role/del/list)");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const op = rest[0];
    const args = authFlags.rest;

    if (std.mem.eql(u8, op, "add")) {
        if (args.len < 3) return fail(stderr, "remote-user add needs <username> <password> readonly|readwrite|admin");
        const role = cobalt.AuthRole.parse(args[2]) catch return fail(stderr, "role must be readonly, readwrite, or admin");
        client.adminCreateUser(args[0], args[1], role, cobalt.auth.recommendedRounds) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("user '{s}' created with role {s}\n", .{ args[0], role.name() });
    } else if (std.mem.eql(u8, op, "passwd")) {
        if (args.len < 2) return fail(stderr, "remote-user passwd needs <username> <newpassword>");
        client.adminSetPassword(args[0], args[1], cobalt.auth.recommendedRounds) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("password updated for '{s}'\n", .{args[0]});
    } else if (std.mem.eql(u8, op, "role")) {
        if (args.len < 2) return fail(stderr, "remote-user role needs <username> readonly|readwrite|admin");
        const role = cobalt.AuthRole.parse(args[1]) catch return fail(stderr, "role must be readonly, readwrite, or admin");
        client.adminSetRole(args[0], role) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("role for '{s}' set to {s}\n", .{ args[0], role.name() });
    } else if (std.mem.eql(u8, op, "del")) {
        if (args.len < 1) return fail(stderr, "remote-user del needs <username>");
        client.adminDeleteUser(args[0]) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("user '{s}' deleted\n", .{args[0]});
    } else if (std.mem.eql(u8, op, "list")) {
        const users = client.adminListUsers(allocator) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer cobalt.auth.freeUserList(allocator, users);
        for (users) |u| try stdout.print("{s}\t{s}\n", .{ u.username, u.role.name() });
    } else {
        return fail(stderr, "unknown remote-user operation");
    }
}

fn runRemoteTtl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-ttl needs a subcommand (expire/persist/ttl/sweep)");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const op = rest[0];
    const args = authFlags.rest;

    if (std.mem.eql(u8, op, "expire")) {
        if (args.len < 2) return fail(stderr, "remote-ttl expire needs <key> <seconds>");
        const seconds = std.fmt.parseInt(u64, args[1], 10) catch return fail(stderr, "expire needs a whole number of seconds");
        client.ttlExpire(args[0], seconds) catch |err| {
            if (err == error.ServerKeyNotFound) return fail(stderr, "no such key");
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, op, "persist")) {
        if (args.len < 1) return fail(stderr, "remote-ttl persist needs <key>");
        client.ttlPersist(args[0]) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, op, "ttl")) {
        if (args.len < 1) return fail(stderr, "remote-ttl ttl needs <key>");
        const result = client.ttlQuery(args[0]) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        switch (result) {
            .noKey => try stdout.writeAll("-2\n"),
            .noExpiry => try stdout.writeAll("-1\n"),
            .seconds => |s| try stdout.print("{d}\n", .{s}),
        }
    } else if (std.mem.eql(u8, op, "sweep")) {
        const reaped = client.ttlSweep() catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("reaped: {d}\n", .{reaped});
    } else {
        return fail(stderr, "unknown remote-ttl operation");
    }
}

fn runRemoteCollTtl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 1) return fail(stderr, "remote-coll-ttl needs sweep or <kind> expire|ttl|persist <name>");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    if (std.mem.eql(u8, rest[0], "sweep")) {
        const authFlags = extractAuthFlags(allocator, rest[1..]) catch return fail(stderr, "invalid --user/--pass/--token value");
        defer allocator.free(authFlags.rest);
        try authenticateIfRequested(&client, stderr, authFlags.auth);
        const reaped = client.collTtlSweep() catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        try stdout.print("reaped: {d}\n", .{reaped});
        return;
    }

    const kind = cobalt.CollectionKind.parse(rest[0]) orelse
        return fail(stderr, "unknown collection kind (expected counter/hash/set/list/zset)");
    if (rest.len < 2) return fail(stderr, "remote-coll-ttl <kind> needs expire|ttl|persist <name>");

    const authFlags = extractAuthFlags(allocator, rest[2..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const op = rest[1];
    const args = authFlags.rest;

    if (std.mem.eql(u8, op, "expire")) {
        if (args.len < 2) return fail(stderr, "remote-coll-ttl <kind> expire needs <name> <seconds>");
        const seconds = std.fmt.parseInt(u64, args[1], 10) catch return fail(stderr, "expire needs a whole number of seconds");
        client.collTtlExpire(kind, args[0], seconds) catch |err| {
            if (err == error.ServerCollectionNotFound) return fail(stderr, "no such collection");
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, op, "persist")) {
        if (args.len < 1) return fail(stderr, "remote-coll-ttl <kind> persist needs <name>");
        client.collTtlPersist(kind, args[0]) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, op, "ttl")) {
        if (args.len < 1) return fail(stderr, "remote-coll-ttl <kind> ttl needs <name>");
        const result = client.collTtlQuery(kind, args[0]) catch |err| {
            try stderr.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        switch (result) {
            .noKey => try stdout.writeAll("-2\n"),
            .noExpiry => try stdout.writeAll("-1\n"),
            .seconds => |s| try stdout.print("{d}\n", .{s}),
        }
    } else {
        return fail(stderr, "unknown remote-coll-ttl operation");
    }
}

fn printCollReply(stdout: anytype, reply: cobalt.protocol.OwnedCollReply) !void {
    switch (reply) {
        .nil => try stdout.writeAll("(nil)\n"),
        .ok => try stdout.writeAll("OK\n"),
        .int => |v| try stdout.print("{d}\n", .{v}),
        .real => |v| try stdout.print("{d}\n", .{v}),
        .bytes => |v| try stdout.print("{s}\n", .{v}),
        .stringList => |items| for (items) |it| try stdout.print("{s}\n", .{it}),
        .pairList => |items| for (items) |p| try stdout.print("{s}\t{s}\n", .{ p.field, p.value }),
        .scorePairList => |items| for (items) |p| try stdout.print("{s}\t{d}\n", .{ p.member, p.score }),
    }
}

fn runRemoteColl(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    if (rest.len < 2) return fail(stderr, "remote-coll needs <kind> <op> ...");
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest[2..]) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);
    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const kind = rest[0];
    const op = rest[1];
    const args = authFlags.rest;

    const Call = struct { action: cobalt.protocol.CollAction, name: []const u8, callArgs: []const []const u8 };

    const call: Call = blk: {
        if (std.mem.eql(u8, kind, "counter")) {
            if (std.mem.eql(u8, op, "get")) {
                if (args.len < 1) return fail(stderr, "counter get needs <name>");
                break :blk .{ .action = .counter_get, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "set")) {
                if (args.len < 2) return fail(stderr, "counter set needs <name> <value>");
                break :blk .{ .action = .counter_set, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "incrby")) {
                if (args.len < 2) return fail(stderr, "counter incrby needs <name> <delta>");
                break :blk .{ .action = .counter_incrby, .name = args[0], .callArgs = args[1..2] };
            }
            return fail(stderr, "unknown counter operation");
        } else if (std.mem.eql(u8, kind, "hash")) {
            if (std.mem.eql(u8, op, "set")) {
                if (args.len < 3) return fail(stderr, "hash set needs <name> <field> <value>");
                break :blk .{ .action = .hash_set, .name = args[0], .callArgs = args[1..3] };
            } else if (std.mem.eql(u8, op, "get")) {
                if (args.len < 2) return fail(stderr, "hash get needs <name> <field>");
                break :blk .{ .action = .hash_get, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "del")) {
                if (args.len < 2) return fail(stderr, "hash del needs <name> <field>");
                break :blk .{ .action = .hash_del, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "len")) {
                if (args.len < 1) return fail(stderr, "hash len needs <name>");
                break :blk .{ .action = .hash_len, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "getall")) {
                if (args.len < 1) return fail(stderr, "hash getall needs <name>");
                break :blk .{ .action = .hash_getall, .name = args[0], .callArgs = &.{} };
            }
            return fail(stderr, "unknown hash operation");
        } else if (std.mem.eql(u8, kind, "set")) {
            if (std.mem.eql(u8, op, "add")) {
                if (args.len < 2) return fail(stderr, "set add needs <name> <member>");
                break :blk .{ .action = .set_add, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "rem")) {
                if (args.len < 2) return fail(stderr, "set rem needs <name> <member>");
                break :blk .{ .action = .set_rem, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "ismember")) {
                if (args.len < 2) return fail(stderr, "set ismember needs <name> <member>");
                break :blk .{ .action = .set_ismember, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "card")) {
                if (args.len < 1) return fail(stderr, "set card needs <name>");
                break :blk .{ .action = .set_card, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "members")) {
                if (args.len < 1) return fail(stderr, "set members needs <name>");
                break :blk .{ .action = .set_members, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "inter")) {
                if (args.len < 1) return fail(stderr, "set inter needs at least one <name>");
                break :blk .{ .action = .set_inter, .name = args[0], .callArgs = args[1..] };
            } else if (std.mem.eql(u8, op, "union")) {
                if (args.len < 1) return fail(stderr, "set union needs at least one <name>");
                break :blk .{ .action = .set_union, .name = args[0], .callArgs = args[1..] };
            } else if (std.mem.eql(u8, op, "diff")) {
                if (args.len < 2) return fail(stderr, "set diff needs <name> <other...>");
                break :blk .{ .action = .set_diff, .name = args[0], .callArgs = args[1..] };
            }
            return fail(stderr, "unknown set operation");
        } else if (std.mem.eql(u8, kind, "list")) {
            if (std.mem.eql(u8, op, "lpush")) {
                if (args.len < 2) return fail(stderr, "list lpush needs <name> <value>");
                break :blk .{ .action = .list_lpush, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "rpush")) {
                if (args.len < 2) return fail(stderr, "list rpush needs <name> <value>");
                break :blk .{ .action = .list_rpush, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "lpop")) {
                if (args.len < 1) return fail(stderr, "list lpop needs <name>");
                break :blk .{ .action = .list_lpop, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "rpop")) {
                if (args.len < 1) return fail(stderr, "list rpop needs <name>");
                break :blk .{ .action = .list_rpop, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "len")) {
                if (args.len < 1) return fail(stderr, "list len needs <name>");
                break :blk .{ .action = .list_len, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "range")) {
                if (args.len < 3) return fail(stderr, "list range needs <name> <start> <stop>");
                break :blk .{ .action = .list_range, .name = args[0], .callArgs = args[1..3] };
            }
            return fail(stderr, "unknown list operation");
        } else if (std.mem.eql(u8, kind, "zset")) {
            if (std.mem.eql(u8, op, "add")) {
                if (args.len < 3) return fail(stderr, "zset add needs <name> <member> <score>");
                break :blk .{ .action = .zset_add, .name = args[0], .callArgs = args[1..3] };
            } else if (std.mem.eql(u8, op, "score")) {
                if (args.len < 2) return fail(stderr, "zset score needs <name> <member>");
                break :blk .{ .action = .zset_score, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "incrby")) {
                if (args.len < 3) return fail(stderr, "zset incrby needs <name> <member> <delta>");
                break :blk .{ .action = .zset_incrby, .name = args[0], .callArgs = args[1..3] };
            } else if (std.mem.eql(u8, op, "rem")) {
                if (args.len < 2) return fail(stderr, "zset rem needs <name> <member>");
                break :blk .{ .action = .zset_rem, .name = args[0], .callArgs = args[1..2] };
            } else if (std.mem.eql(u8, op, "card")) {
                if (args.len < 1) return fail(stderr, "zset card needs <name>");
                break :blk .{ .action = .zset_card, .name = args[0], .callArgs = &.{} };
            } else if (std.mem.eql(u8, op, "rangebyrank")) {
                if (args.len < 3) return fail(stderr, "zset rangebyrank needs <name> <start> <stop>");
                break :blk .{ .action = .zset_rangebyrank, .name = args[0], .callArgs = args[1..3] };
            } else if (std.mem.eql(u8, op, "rangebyscore")) {
                if (args.len < 3) return fail(stderr, "zset rangebyscore needs <name> <min> <max>");
                break :blk .{ .action = .zset_rangebyscore, .name = args[0], .callArgs = args[1..3] };
            } else if (std.mem.eql(u8, op, "rank")) {
                if (args.len < 2) return fail(stderr, "zset rank needs <name> <member>");
                break :blk .{ .action = .zset_rank, .name = args[0], .callArgs = args[1..2] };
            }
            return fail(stderr, "unknown zset operation");
        }
        return fail(stderr, "unknown collection kind (expected counter/hash/set/list/zset)");
    };

    var reply = client.collOp(allocator, call.action, call.name, call.callArgs) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer reply.deinit(allocator);
    try printCollReply(stdout, reply);
}

fn runRemoteStats(allocator: std.mem.Allocator, stdout: anytype, stderr: anytype, addressSpec: []const u8, rest: []const []const u8) !void {
    const address = try parseHostPort(stdout, addressSpec);

    var client = cobalt.Client.connect(allocator, address) catch |err| {
        try stderr.print("error: could not connect to {s}: {s}\n", .{ addressSpec, @errorName(err) });
        std.process.exit(1);
    };
    defer client.close();

    const authFlags = extractAuthFlags(allocator, rest) catch return fail(stderr, "invalid --user/--pass/--token value");
    defer allocator.free(authFlags.rest);

    try authenticateIfRequested(&client, stderr, authFlags.auth);

    const text = client.metricsText(allocator) catch |err| {
        try stderr.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer allocator.free(text);
    try stdout.writeAll(text);
}

fn runServe(allocator: std.mem.Allocator, stdout: anytype, db: *cobalt.Db, bind: []const u8, rest: []const []const u8) !void {
    const address = try parseHostPort(stdout, bind);

    var server = try cobalt.Server.init(allocator, db, address);

    var sessionTtlSeconds: ?f64 = null;
    var sessionSweepSeconds: ?f64 = null;
    var ttlSweepSeconds: ?f64 = null;
    var collTtlSweepSeconds: ?f64 = null;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--rate-limit")) {
            if (i + 2 >= rest.len) {
                try stdout.writeAll("error: --rate-limit needs <capacity> <per-second>\n");
                std.process.exit(2);
            }
            const capacity = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid rate-limit capacity '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            const refill = std.fmt.parseFloat(f64, rest[i + 2]) catch {
                try stdout.print("error: invalid rate-limit per-second '{s}'\n", .{rest[i + 2]});
                std.process.exit(2);
            };
            server.enableRateLimit(capacity, refill);
            try stdout.print("rate limit enabled: {d} capacity, {d}/sec refill\n", .{ capacity, refill });
            i += 2;
        } else if (std.mem.eql(u8, rest[i], "--per-conn-rate-limit")) {
            if (i + 2 >= rest.len) {
                try stdout.writeAll("error: --per-conn-rate-limit needs <capacity> <per-second>\n");
                std.process.exit(2);
            }
            const capacity = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid per-conn-rate-limit capacity '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            const refill = std.fmt.parseFloat(f64, rest[i + 2]) catch {
                try stdout.print("error: invalid per-conn-rate-limit per-second '{s}'\n", .{rest[i + 2]});
                std.process.exit(2);
            };
            server.enablePerConnectionRateLimit(capacity, refill);
            try stdout.print("per-connection rate limit enabled: {d} capacity, {d}/sec refill\n", .{ capacity, refill });
            i += 2;
        } else if (std.mem.eql(u8, rest[i], "--auth")) {
            const store = cobalt.AuthStore.init(db);
            if (!(try store.hasAnyAdmin(allocator))) {
                try stdout.writeAll("error: --auth requires at least one admin user; create one first with `user add <name> <password> admin`\n");
                std.process.exit(2);
            }
            server.enableAuth(store);
            try stdout.writeAll("auth enabled: every op but ping now requires a prior AUTH\n");
        } else if (std.mem.eql(u8, rest[i], "--session-ttl")) {
            if (i + 1 >= rest.len) {
                try stdout.writeAll("error: --session-ttl needs <seconds>\n");
                std.process.exit(2);
            }
            sessionTtlSeconds = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid session-ttl '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            i += 1;
        } else if (std.mem.eql(u8, rest[i], "--session-sweep-interval")) {
            if (i + 1 >= rest.len) {
                try stdout.writeAll("error: --session-sweep-interval needs <seconds>\n");
                std.process.exit(2);
            }
            sessionSweepSeconds = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid session-sweep-interval '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            i += 1;
        } else if (std.mem.eql(u8, rest[i], "--ttl-sweep-interval")) {
            if (i + 1 >= rest.len) {
                try stdout.writeAll("error: --ttl-sweep-interval needs <seconds>\n");
                std.process.exit(2);
            }
            ttlSweepSeconds = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid ttl-sweep-interval '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            i += 1;
        } else if (std.mem.eql(u8, rest[i], "--coll-ttl-sweep-interval")) {
            if (i + 1 >= rest.len) {
                try stdout.writeAll("error: --coll-ttl-sweep-interval needs <seconds>\n");
                std.process.exit(2);
            }
            collTtlSweepSeconds = std.fmt.parseFloat(f64, rest[i + 1]) catch {
                try stdout.print("error: invalid coll-ttl-sweep-interval '{s}'\n", .{rest[i + 1]});
                std.process.exit(2);
            };
            i += 1;
        } else {
            try stdout.print("error: unknown serve flag '{s}'\n", .{rest[i]});
            std.process.exit(2);
        }
    }

    if (sessionSweepSeconds != null and sessionTtlSeconds == null) {
        try stdout.writeAll("error: --session-sweep-interval requires --session-ttl\n");
        std.process.exit(2);
    }

    var sessionStore: cobalt.SessionStore = undefined;
    if (sessionTtlSeconds) |seconds| {
        if (seconds <= 0) {
            try stdout.writeAll("error: --session-ttl must be a positive number of seconds\n");
            std.process.exit(2);
        }
        if (server.authStore == null) {
            try stdout.writeAll("error: --session-ttl requires --auth\n");
            std.process.exit(2);
        }
        sessionStore = cobalt.SessionStore.init(allocator);
        const ttlNanos: i128 = @intFromFloat(seconds * @as(f64, @floatFromInt(std.time.ns_per_s)));
        server.enableSessions(&sessionStore, ttlNanos);
        try stdout.print("sessions enabled: AUTH issues a token valid for {d}s\n", .{seconds});

        if (sessionSweepSeconds) |sweepSeconds| {
            if (sweepSeconds <= 0) {
                try stdout.writeAll("error: --session-sweep-interval must be a positive number of seconds\n");
                std.process.exit(2);
            }
            const sweepNanos: u64 = @intFromFloat(sweepSeconds * @as(f64, @floatFromInt(std.time.ns_per_s)));
            server.enableSessionSweep(sweepNanos);
            try stdout.print("session sweeper enabled: expired sessions dropped every {d}s\n", .{sweepSeconds});
        }
    }
    defer if (sessionTtlSeconds != null) sessionStore.deinit();

    if (ttlSweepSeconds) |seconds| {
        if (seconds <= 0) {
            try stdout.writeAll("error: --ttl-sweep-interval must be a positive number of seconds\n");
            std.process.exit(2);
        }
        const nanos: u64 = @intFromFloat(seconds * @as(f64, @floatFromInt(std.time.ns_per_s)));
        server.enableTtlSweep(nanos);
        try stdout.print("ttl sweeper enabled: due keys reaped every {d}s\n", .{seconds});
    }

    if (collTtlSweepSeconds) |seconds| {
        if (seconds <= 0) {
            try stdout.writeAll("error: --coll-ttl-sweep-interval must be a positive number of seconds\n");
            std.process.exit(2);
        }
        const nanos: u64 = @intFromFloat(seconds * @as(f64, @floatFromInt(std.time.ns_per_s)));
        server.enableCollTtlSweep(nanos);
        try stdout.print("collection ttl sweeper enabled: due collections reaped every {d}s\n", .{seconds});
    }

    try stdout.print("cobalt server listening on {}\n", .{server.boundAddress()});
    try server.start();
    server.wait();
}

fn expectCli(allocator: std.mem.Allocator, dir: []const u8, args: []const []const u8, expectedStdout: []const u8, expectedExit: u8) !void {
    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    try argv.appendSlice(&.{ @import("cliPaths").cobaltExe, dir });
    try argv.appendSlice(args);
    const run = try std.process.Child.run(.{ .allocator = allocator, .argv = argv.items });
    defer allocator.free(run.stdout);
    defer allocator.free(run.stderr);
    try std.testing.expectEqualStrings(expectedStdout, run.stdout);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = expectedExit }, run.term);
}

test "cli put drops any ttl, and expire and ttl treat an expired unswept key as missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const dir = try std.fs.path.join(allocator, &.{ base, "store" });
    defer allocator.free(dir);

    try expectCli(allocator, dir, &.{ "put", "dead", "old", "--ttl", "0" }, "", 0);
    try expectCli(allocator, dir, &.{ "put", "live", "old", "--ttl", "600" }, "", 0);
    try expectCli(allocator, dir, &.{ "ttl", "dead" }, "-2\n", 0);
    try expectCli(allocator, dir, &.{ "expire", "dead", "600" }, "", 2);
    try expectCli(allocator, dir, &.{ "ttl", "dead" }, "-2\n", 0);
    try expectCli(allocator, dir, &.{ "get", "dead" }, "(nil)\n", 0);

    try expectCli(allocator, dir, &.{ "put", "rewritten", "old", "--ttl", "0" }, "", 0);
    try expectCli(allocator, dir, &.{ "put", "rewritten", "new" }, "", 0);
    try expectCli(allocator, dir, &.{ "get", "rewritten" }, "new\n", 0);
    try expectCli(allocator, dir, &.{ "ttl", "rewritten" }, "-1\n", 0);

    try expectCli(allocator, dir, &.{ "put", "live", "new" }, "", 0);
    try expectCli(allocator, dir, &.{ "ttl", "live" }, "-1\n", 0);
    try expectCli(allocator, dir, &.{"expire-sweep"}, "reaped: 0\n", 0);
}
