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
        try runVerify(allocator, stdout, dir, count);
        return;
    }

    if (std.mem.eql(u8, command, "remote-select")) {
        // Reuses the <dir> slot as a host:port to connect to, exactly like
        // `verify` reuses it as the directory under test - `remote-select`
        // never opens a local Db at all.
        try runRemoteSelect(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-join")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteJoin(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-aggregate")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteAggregate(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-window")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteWindow(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-publish")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemotePublish(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-subscribe")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteSubscribe(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-unsubscribe")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteUnsubscribe(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-explain")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteExplain(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-update")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteUpdate(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-delete")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteDelete(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-export")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteExport(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-import")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteImport(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-user")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select` - never opens a local Db.
        try runRemoteUser(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-stats")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select`/`remote-user` - never opens a local Db.
        try runRemoteStats(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-ttl")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-select`/`remote-user`/`remote-stats` - never opens a
        // local Db.
        try runRemoteTtl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-coll-ttl")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-ttl` - never opens a local Db.
        try runRemoteCollTtl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-coll")) {
        // Same "<dir> slot is really host:port" convention as
        // `remote-coll-ttl` - never opens a local Db.
        try runRemoteColl(allocator, stdout, stderr, dir, rest);
        return;
    }

    if (std.mem.eql(u8, command, "remote-txn")) {
        // Same "<dir> slot is really host:port" convention as every other
        // remote-* command - never opens a local Db.
        try runRemoteTxn(allocator, stdout, stderr, dir, rest);
        return;
    }

    var db = try cobalt.Db.open(allocator, dir, .{});
    defer db.close();

    if (std.mem.eql(u8, command, "put")) {
        if (rest.len < 2) return fail(stderr, "put needs <key> <value>");
        try db.put(rest[0], rest[1]);
        if (rest.len >= 4 and std.mem.eql(u8, rest[2], "--ttl")) {
            const seconds = std.fmt.parseInt(u64, rest[3], 10) catch return fail(stderr, "--ttl needs a whole number of seconds");
            try cobalt.ttl.setExpireSeconds(&db, allocator, rest[0], std.time.nanoTimestamp(), seconds);
        } else if (rest.len > 2) {
            return fail(stderr, "put takes <key> <value> [--ttl <seconds>]");
        }
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "get")) {
        if (rest.len < 1) return fail(stderr, "get needs <key>");
        if (try cobalt.ttl.getLive(&db, allocator, rest[0], std.time.nanoTimestamp())) |value| {
            defer allocator.free(value);
            try stdout.print("{s}\n", .{value});
        } else {
            try stdout.writeAll("(nil)\n");
        }
    } else if (std.mem.eql(u8, command, "del")) {
        if (rest.len < 1) return fail(stderr, "del needs <key>");
        try db.delete(rest[0]);
        try cobalt.ttl.clearExpire(&db, allocator, rest[0]);
        try db.maybeCompact();
    } else if (std.mem.eql(u8, command, "expire")) {
        if (rest.len < 2) return fail(stderr, "expire needs <key> <seconds>");
        const seconds = std.fmt.parseInt(u64, rest[1], 10) catch return fail(stderr, "expire needs a whole number of seconds");
        const existing = try db.get(allocator, rest[0]) orelse return fail(stderr, "no such key");
        allocator.free(existing);
        try cobalt.ttl.setExpireSeconds(&db, allocator, rest[0], std.time.nanoTimestamp(), seconds);
    } else if (std.mem.eql(u8, command, "persist")) {
        if (rest.len < 1) return fail(stderr, "persist needs <key>");
        try cobalt.ttl.clearExpire(&db, allocator, rest[0]);
    } else if (std.mem.eql(u8, command, "ttl")) {
        if (rest.len < 1) return fail(stderr, "ttl needs <key>");
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
        try runReplicate(allocator, stdout, &db, rest[0], rest[1..]);
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

fn boolFlag(v: bool) u8 {
    return if (v) 1 else 0;
}

/// Dispatches `coll <kind> <op> [args...]` onto the Redis-like typed
/// collections in collections.zig (Counter/Hash/Set/List/ZSet), which until
/// now were only reachable through the library API, never a CLI.
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

    // Lazy expiry on the read/write path: every remaining op below takes the
    // collection name as args[0], so this is what keeps a bare
    // `coll hash get <name> ...` from ever reading a collection that is
    // logically already gone. `set inter|union|diff` accept further names
    // past args[0] - those get their own expireIfDueMany call right before
    // dispatch, so this single-name check only needs to cover args[0].
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
            // The blanket lazy check above only covered args[0]; args[1..]
            // are additional set names this multi-set op reads directly.
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

/// Dispatches `coll <kind> expire|ttl|persist <name> [seconds]` onto
/// collttl.zig - the whole-collection counterpart of the flat-key
/// `expire`/`ttl`/`persist` commands above. `expire` mirrors Redis-strict
/// EXPIRE by checking the collection currently exists first (same shape as
/// the flat-key `expire` handler checking db.get first).
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

/// Parses a CLI-supplied scalar into a typed row Value. `i:`/`f:`/`b:`/`s:`
/// prefixes pick int/float/bool/text explicitly; unprefixed text defaults to
/// `.text`. The returned Value borrows `text` directly (no allocation), so it
/// is only valid for as long as the argv slice (or script line) it came from.
fn parseValue(text: []const u8) !Value {
    return cobalt.row.Value.parseCli(text);
}

/// Splits `name=value` into a Field, validating the name with the same
/// identifier rule tables and indexes already enforce.
fn parseField(text: []const u8) !Field {
    const eq = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidField;
    const name = text[0..eq];
    if (!cobalt.index.validIdentifier(name)) return error.InvalidField;
    const value = try parseValue(text[eq + 1 ..]);
    return .{ .name = name, .value = value };
}

const PageFlags = struct { limit: u32 = 0, offset: u32 = 0 };

/// Pulls `--limit N` / `--offset N` out of a `table select`/`remote-select`
/// argument list wherever they appear, returning the remaining tokens
/// (destined to be joined into the expr text) alongside the parsed page
/// window. Caller owns and frees `rest`.
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

/// Pulls a lone `--range` flag (no value) out of `table window`'s/
/// `remote-window`'s trailing args, requesting `window.FrameMode.range`
/// (SQL's actual `RANGE` frame default for running aggregates) instead of
/// this CLI's `.rows` default - see `window.zig`'s `compute` doc comment
/// for the semantic difference. Kept separate from `extractPageFlags`
/// (same reason `extractSelectFlags`'s `--order-by` is kept separate:
/// `extractPageFlags` is also shared by `table join`/`table aggregate`,
/// neither of which has a frame concept to silently swallow the flag into).
/// Caller owns and frees `rest`.
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

/// `table select`/`remote-select`-only counterpart of `extractPageFlags`:
/// same `--limit`/`--offset` handling plus `--order-by
/// field[:desc][,field[:desc]...]` (one or more comma-separated columns,
/// applied left to right - later columns only break ties left by earlier
/// ones, same as SQL's `ORDER BY a, b`), kept as a SEPARATE function (not
/// folded into `extractPageFlags` itself) because `extractPageFlags` is
/// also shared by `table join`/`table aggregate` (and their remote
/// mirrors) - if `--order-by` were recognized there too, it would be
/// silently consumed and have no effect, since neither join nor aggregate
/// sorts its result. Better a flag those two commands don't recognize at
/// all than one they swallow without honoring. Caller owns and frees
/// `rest` AND `flags.orderBy` (empty slice when the flag was never given,
/// still safe to free).
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

/// Parses `--order-by`'s `field[:desc]` value, shared by `parseOrderByList`
/// (both `table select` and `remote-select` route through it) and
/// repl.zig's identically-shaped copy of the same flag. The suffix after
/// the colon must be exactly `desc` or `asc` - anything else (a typo'd
/// `:dsc`) is rejected rather than silently defaulting to ascending,
/// matching the CLI's usual "malformed input is an error, not a guess"
/// convention.
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

/// Splits `--order-by`'s comma-separated value into one or more columns,
/// each parsed by `parseOrderByFlag` - `city,age:desc` sorts by `city`
/// ascending, breaking ties by `age` descending. A leading, trailing, or
/// doubled comma yields an empty segment, rejected the same way a
/// malformed direction suffix is (not silently skipped), so `city,,age` is
/// an error rather than a silently-collapsed two-column sort. Caller owns
/// and frees the returned slice.
fn parseOrderByList(allocator: std.mem.Allocator, text: []const u8) ![]cobalt.query.OrderBy {
    var list = std.ArrayList(cobalt.query.OrderBy).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseOrderByFlag(segment));
    }
    return list.toOwnedSlice();
}

/// Splits `--set`'s comma-separated `name=value[,name=value...]` value into
/// a list of Fields, each parsed by `parseField` - the `table update`/
/// `remote-update` counterpart of `parseOrderByList`. A leading, trailing,
/// or doubled comma yields an empty segment, which `parseField`'s missing
/// `=` check rejects the same way a malformed order-by suffix is (not
/// silently skipped). Caller owns and frees the returned slice.
fn parseSetList(allocator: std.mem.Allocator, text: []const u8) ![]Field {
    var list = std.ArrayList(Field).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseField(segment));
    }
    return list.toOwnedSlice();
}

/// Pulls a single required `--set name=value[,name=value...]` flag out of a
/// `table update`/`remote-update` argument list, returning the parsed field
/// list alongside the remaining tokens (destined to be joined into the expr
/// text) - the update counterpart of `extractSelectFlags`. A missing
/// `--set` is `error.MissingSetFlag`: unlike a `WHERE` predicate (optional,
/// empty text means every row), a `SET`-less `UPDATE` names nothing to
/// change and is rejected rather than silently accepted as a no-op. Caller
/// owns and frees `rest` and the returned `sets` slice.
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

/// Prints a `query.Plan` in the same human-readable shape for `table
/// explain`, `remote-explain`, and the repl's `table explain` - one line
/// naming the strategy `selectPage` would actually take, not a guess.
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

/// Parses a comma-separated `table aggregate` spec list (e.g.
/// `count,sum:score,max:score,distinct:city`) into `AggSpec`s. Every kind
/// but bare `count` (COUNT(*)) requires a `:field` suffix, validated with
/// the same identifier rule tables/indexes already enforce. Returned
/// `field` slices borrow from `text` (itself a CLI arg living for the
/// process), so callers only need to free the returned slice itself, not
/// each field.
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

/// Splits the trailing free-text args of `table aggregate`/`remote-aggregate`
/// (after the spec list and any `--limit`/`--offset`/auth flags have already
/// been pulled out) on literal `having` and `order` tokens, in that clause
/// order (mirroring SQL's `WHERE ... GROUP BY ... HAVING ... ORDER BY ...`):
/// everything before `having` (or `order`, if `having` is absent) is the
/// WHERE-style expr filtering rows BEFORE aggregation (unchanged behavior);
/// everything between `having` and `order` (or to the end, if `order` is
/// absent) is the HAVING expr filtering result groups AFTER aggregation;
/// everything after `order` is the ORDER BY field list - a single token like
/// `--order-by`'s value (`parseOrderByList` splits it further), not a
/// free-text expr, so unlike `havingArgs` a well-formed `orderArgs` is
/// always exactly one element. Neither `having` nor `order` is a keyword
/// `expr.zig` itself understands - they only have meaning as this
/// CLI-level separator. Either or both tokens absent means "no HAVING"/"no
/// ORDER BY", the same as before ORDER BY existed for `table aggregate`.
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

/// Parses a single `table window` spec token: `<kind>`, `<kind>:<field>`,
/// - `lag`/`lead` only - `<kind>:<field>[:<offset>[:<default>]]`, or -
/// `nth_value` only - `<kind>:<field>:<n>[:<default>]`. `row_number`/
/// `rank`/`dense_rank` never take a `:field` suffix (there is nothing to
/// point them at); `count` may omit one (`COUNT(*)`) or take one;
/// `sum`/`avg`/`min`/`max`/`first_value`/`last_value`/`count_distinct`
/// always require exactly one - `count_distinct` has no `COUNT(*)`-style
/// bare form since "distinct values of nothing" is not meaningful. `lag`/`lead`
/// always require a field and additionally accept an optional integer
/// `offset` (SQL's default of 1 if omitted) and, only alongside an
/// explicit offset, an optional `default` literal in the same `i:`/`f:`/
/// `b:`/`s:`-prefixed grammar `parseValue` already uses for `put`
/// (`WindowSpec`'s SQL NULL default if omitted). `nth_value` always requires
/// a field AND a positive integer `n` (unlike `lag`/`lead`'s offset, SQL's
/// `NTH_VALUE` has no default position to fall back to) plus, optionally,
/// the same `default` literal grammar for when `n` falls outside the
/// current frame. Returned `field`/`default` text borrows from `text` (a
/// CLI arg living for the process).
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
            // `it.rest()`, NOT another `it.next()`: a typed default literal
            // (`i:-1`, `s:foo:bar`) can itself contain colons, which would
            // get wrongly re-split by a further `splitScalar` step.
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

/// Parses `table window`'s comma-separated spec list (`sum:total,avg:total,
/// row_number` - same comma-joined shape as `parseAggSpecs`, so a `table
/// window` call can now annotate every matching row with MULTIPLE computed
/// columns sharing one `PARTITION BY`/`ORDER BY`/frame, mirroring
/// `window.computeMany`) into `WindowSpec`s via `parseWindowSpec` per token.
/// Returned `field` slices borrow from `text`, same convention as
/// `parseAggSpecs`; caller owns and frees the returned slice.
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

/// Splits the trailing free-text args of `table window` (after the spec
/// token and any `--limit`/`--offset` flags have already been pulled out)
/// on literal `partition` and `order` tokens, in that clause order
/// (mirroring SQL's `OVER (PARTITION BY ... ORDER BY ...)`) - the `table
/// window` counterpart of `splitAggFilterArgs`. Everything before
/// `partition` (or `order`, if `partition` is absent) is the WHERE-style
/// expr filtering rows before annotation; everything between `partition`
/// and `order` (or to the end) is the partition field list (a single
/// comma-separated token, parsed by the caller); everything after `order`
/// is the ORDER BY field list, same shape as `splitAggFilterArgs`'s
/// `orderArgs`. Either or both tokens absent means "one implicit partition"
/// / "no ORDER BY".
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

/// Parses `table window`'s `partition <field>[,field...]` value into a
/// borrowed field-name list (same non-owning convention `parseWindowSpec`
/// uses) - a leading/trailing/doubled comma yields an empty segment,
/// rejected by `index.validIdentifier` the same way a malformed order-by
/// suffix is elsewhere, not silently skipped. Caller owns and frees the
/// returned slice (not each field - they borrow from `text`).
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

/// Dispatches `user <op> ...` onto auth.zig's Store: username/password/role
/// management for `serve --auth`, always operating on the local Db file
/// directly (never over the wire - creating the first admin has to work
/// even before any server is running, and there is no bootstrap way to
/// AUTH your way into creating the first account).
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

/// Dispatches `table <op> <table> ...` onto query.zig's Table: schemaless
/// rows with secondary indexes, until now only reachable through the library
/// API. Opens a fresh Table view per invocation (indexes are loaded from
/// their persisted metadata, so this is consistent across process restarts).
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

        // Display/page in the SAME partition-then-order walk `computeMany`
        // used internally, not raw scan order - see `table window`'s help
        // text and `window.orderedIndices`'s doc comment for why.
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

/// Runs a script of `put|del <table> <pk> [field=value ...]` lines as one
/// atomic Transaction via TableTxn: every row/index mutation across every
/// line becomes visible together on commit, or none of it does. This is the
/// only place in the CLI multi-row atomicity is reachable at all - `table
/// put` above writes one row directly to the Db per call, with no atomicity
/// across rows.
/// `repl [--script <file>]`: keeps `db` open across many commands instead
/// of the usual one-process-per-command CLI shape, so `begin`/`commit`/
/// `rollback` can bracket an interactive `cobalt.Repl` transaction - see
/// `repl.zig` for the command grammar and why that is more than `txn
/// <script-file>` with extra steps. With `--script <file>` reads from the
/// file non-interactively (no prompt, same as `txn`); otherwise reads from
/// stdin with a `cobalt>`/`cobalt(txn)>` prompt.
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

/// Dispatches `replicate <replica-dir> [--once] [--interval-ms <n>]`: opens
/// (or creates) a second Db at <replica-dir> and keeps it mirroring `db` by
/// physically tailing `db`'s wal.log (replicate.zig), recovering via a full
/// snapshot resync whenever the tailer falls behind a primary flush.
fn runReplicate(allocator: std.mem.Allocator, stdout: anytype, db: *cobalt.Db, replicaDir: []const u8, rest: []const []const u8) !void {
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

    var replica = try cobalt.Db.open(allocator, replicaDir, .{});
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
                // fullResync always re-bases the tailer to offset 0 and the
                // primary's current generation, which must be persisted
                // immediately even if nothing new was applied afterwards -
                // otherwise a later process would resume from the stale
                // pre-truncation offset/generation instead of the fresh one.
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

/// Parses a `host:port` string as used by both `serve` (bind address) and
/// `remote-select` (address to connect to). Exits with usage code 2 on a
/// malformed address rather than propagating a parse error, matching every
/// other CLI argument validation in this file.
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

/// Pulls `--user NAME` / `--pass PASS` / `--token TOKEN` out of a
/// `remote-select`/`remote-user` argument list, same shape and same "strip
/// recognized flags, keep the rest" idea as `extractPageFlags`. `--token`
/// is the CLI counterpart of `client.authenticateWithToken` - a previously
/// issued session token (see `serve --session-ttl`) used in place of a
/// username/password pair. Caller owns and frees `rest`.
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

/// Shared by `runRemoteSelect` and `runRemoteUser`: authenticates the
/// just-connected `client` using whichever credential `authFlags` carried
/// (a session token takes priority over a username/password pair - a
/// caller passing both almost certainly means "use the token, the
/// user/pass was left over from a script template"), or does nothing if
/// neither was given (server has no --auth enabled, or the op needs none).
/// A fresh password login against a server with sessions enabled gets a
/// brand new token back (`client.sessionToken()`) - printed to stderr (kept
/// out of stdout so scripts piping row/user output are not polluted) so the
/// caller can pass it to a later invocation via `--token` instead of
/// re-sending the password. Logging in with `--token` itself never mints a
/// new one (see `server.zig`'s `handleAuthToken`), so nothing is printed
/// in that branch.
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

/// Connects to a remote `cobalt serve` instance and runs `table select`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_select` opcode, so a query engine that was
/// previously CLI-local-only is now reachable over the wire with the exact
/// same expression grammar as `table select`. `--user`/`--pass` authenticate
/// first, needed only against a server started with `serve --auth`.
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

/// Connects to a remote `cobalt serve` instance and runs `table explain`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_explain` opcode, same shape as `runRemoteSelect`
/// but reporting a `query.Plan` instead of rows. `--user`/`--pass`/
/// `--token` authenticate first, needed only against a server started with
/// `serve --auth`.
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

/// Connects to a remote `cobalt serve` instance and runs `table update`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_update` opcode, same shape as `runRemoteExplain`
/// but taking a `--set` field list and printing the number of rows updated
/// instead of a plan. `--user`/`--pass`/`--token` authenticate first,
/// needed only against a server started with `serve --auth`.
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

/// Connects to a remote `cobalt serve` instance and runs `table delete`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_delete` opcode, same shape as `runRemoteExplain`
/// (no `--set` flag, since a delete has no `SET` clause) but printing the
/// number of rows deleted instead of a plan. `--user`/`--pass`/`--token`
/// authenticate first, needed only against a server started with
/// `serve --auth`.
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

/// Connects to a remote `cobalt serve` instance and runs `table export`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_export` opcode. Unlike every other remote-* op,
/// the destination `<path>` names a file on THIS machine, not the server:
/// the server renders the whole table into memory and sends the bytes
/// back in one frame, and this function is the one that actually creates
/// `<path>` and writes them - the local `table export` writes straight to
/// disk itself since it already has a `*Db` handle in-process, but a
/// remote client only ever gets bytes over the wire. `--user`/`--pass`/
/// `--token` authenticate first, needed only against a server started
/// with `serve --auth`.
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

/// Connects to a remote `cobalt serve` instance and runs `table import`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_import` opcode. Mirrors `runRemoteExport`: the
/// source `<path>` is read from THIS machine (the same way `runTxn` reads
/// a local script file), and its bytes are sent to the server in one
/// frame. `--user`/`--pass`/`--token` authenticate first, needed only
/// against a server started with `serve --auth`.
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

/// Pulls `--left`/`--right`/`--full` (mutually exclusive, last one wins,
/// same as local `table join`'s parsing loop) and `--left-expr E`/
/// `--right-expr E` out of a `remote-join` argument list, same "strip
/// recognized flags, keep the rest" shape as `extractPageFlags`/
/// `extractAuthFlags`. An expr not given defaults to the empty string,
/// meaning "select every row on that side" - the same convention
/// `tableSelect`'s empty `exprText` already uses. Caller owns and frees
/// `rest`.
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

/// Connects to a remote `cobalt serve` instance and runs `table join`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_join` opcode, mirroring `runRemoteSelect`'s shape
/// but for all four of `join.zig`'s equi-join variants instead of a plain
/// select. `--user`/`--pass`/`--token` authenticate first, needed only
/// against a server started with `serve --auth`; printing is identical to
/// the local `table join` command (`L <row>` / `R <row>`, or `L (nil)` /
/// `R (nil)` for the unmatched side of an outer join).
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

/// Connects to a remote `cobalt serve` instance and runs `table aggregate`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_aggregate` opcode, mirroring `runRemoteSelect`'s
/// shape. Same `*` sentinel as local `table aggregate` for "no GROUP BY"
/// (dispatches to `client.tableAggregateGlobal` instead of
/// `tableAggregateGroups`), same comma-separated spec grammar
/// (`parseAggSpecs`), and the same output format as the local command
/// (`printAggLabel`/`printValue`). `--limit`/`--offset` window the result
/// groups server-side (ignored for the `*` global path, same as local
/// `table aggregate`), same convention as `remote-join`.
/// `--user`/`--pass`/`--token` authenticate first, needed only against a
/// server started with `serve --auth`. An optional literal `having <expr>`
/// after the WHERE-style expr (split out by `splitAggFilterArgs`, the same
/// helper the local `table aggregate` handler uses) filters the result
/// groups server-side after aggregation, before `--limit`/`--offset` window
/// them. An optional literal `order <field[:desc]>[,field...]` after that
/// sorts the (HAVING-narrowed) result groups server-side before that same
/// window, ignored for the `*` global path exactly like `--limit`/`--offset`
/// already are - see `Client.tableAggregateGroups`/`tableAggregateGlobal`.
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
        // `values.len == 0` means the server's HAVING excluded the only
        // global result (see `Client.tableAggregateGlobal`'s doc) - print
        // nothing rather than indexing `specs` against a shorter `values`,
        // which a naive `for (specs, values, ...)` would panic on.
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

/// Connects to a remote `cobalt serve` instance and runs `table window`
/// there instead of against a local Db - the client-side counterpart of
/// `server.zig`'s `table_window` opcode, mirroring `runRemoteAggregate`'s
/// shape. Same comma-separated spec-list grammar as local `table window`
/// (`parseWindowSpecs`), same `partition <field>[,field...]`/`order
/// <field[:desc]>[,field...]` clause split (`splitWindowArgs`), and the same
/// per-row output format as the local command (row fields, then
/// `<label>=<value>`). Unlike `runRemoteAggregate`, there is no `*`
/// sentinel or global/grouped branch - a window annotation never collapses
/// rows, so there is exactly one request/response shape
/// (`Client.tableWindow`). `--limit`/`--offset` window which rows come back
/// (server-side, in `window.orderedIndices`' partition-then-order display
/// sequence, not raw scan order - see `Client.tableWindow`'s doc).
/// `--user`/`--pass`/`--token` authenticate first, needed only against a
/// server started with `serve --auth`.
/// Splits `text` on commas into channel names for `remote-subscribe` - no
/// identifier validation, unlike `parsePartitionList`, since a pub/sub
/// channel is an arbitrary string (`pubsub.zig`'s `Hub` keys purely on
/// byte equality), not a table field name.
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

/// Connects to a running `cobalt serve` and delivers a message to every
/// connection currently subscribed to `<channel>` - the client-side
/// counterpart of `server.zig`'s `publish` opcode. `<message...>` is every
/// remaining non-flag argument joined with single spaces, the same
/// "trailing free text" convention `runRemoteWindow`'s `exprText` uses, so a
/// multi-word message does not need manual quoting tricks beyond the
/// shell's own.
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

/// Connects to a running `cobalt serve`, subscribes to every channel in the
/// comma-separated `<channel>[,channel...]` list, and blocks printing
/// `<channel>: <message>` for each message that arrives until the
/// connection ends - the client-side counterpart of `server.zig`'s
/// `subscribe` opcode and `Client.nextMessage`'s doc comment on why this
/// connection never sends another request afterward. Prints "subscribed as
/// <id>" first (the id `remote-unsubscribe`, run from a different terminal
/// against a different connection, needs to ever name this subscription
/// again) - closing this process (or the connection) still ends the whole
/// subscription outright, same as before `remote-unsubscribe` existed.
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

/// Connects to a running `cobalt serve` and drops the listed channels from
/// an already-subscribed connection's set, identified by the
/// `<subscriber-id>` its `remote-subscribe` printed - the client-side
/// counterpart of `server.zig`'s `unsubscribe` opcode. Unlike
/// `remote-subscribe`, this connection is an ordinary request/response
/// round trip: it prints how many channels were actually removed and
/// exits, never blocking. `<subscriber-id>` must parse as a `u64` - a
/// malformed one is reported the same way a malformed `--limit` is
/// elsewhere in this file, before ever reaching for the network.
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

/// The network counterpart of `runTxn`: parses the exact same
/// `put|del <table> <pk> [field=value ...]` script format as the local
/// `txn <script-file>` command, but builds a list of
/// `protocol.TxnOpEntry` and commits it in one round trip through
/// `client.zig`'s `txnOp` (the `txn_op` opcode) instead of staging against
/// a local `TableTxn` directly - so a script that used to require a
/// process holding the `Db` can now run against a remote `cobalt serve`.
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
