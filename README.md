# cobalt

Cobalt is a log-structured merge-tree (LSM) key/value store written in Zig, with no
dependencies outside the standard library. It can be embedded as a library or run as a
standalone TCP server. On top of the raw ordered keyspace it provides MVCC snapshots and
optimistic transactions, key and collection expiry, Redis-style typed collections,
schema-less tables with secondary indexes, constraints and a small query language
(filters, joins, aggregates, window functions), password and token authentication with
roles, WAL-based replication, backups, Prometheus metrics, and publish/subscribe channels.

## Features

### Storage engine

- Write-ahead log with single and batched frames, CRC framing, an fsync on every append,
  and recovery that tolerates a torn tail. A generation counter is bumped every time the
  log is truncated, so tailers can detect a truncation.
- Skiplist memtable with forward and reverse cursors. It is flushed to an SSTable once it
  reaches `flushThreshold` bytes.
- SSTables with prefix-compressed keys and restart points every 16 records, a block
  index, a bloom filter per table, RLE compression for each block that it actually
  shrinks, and CRC-checked blocks. Each block's restart table is validated when the block is loaded.
- An LRU block cache shared by all readers.
- Leveled compaction: L0 is compacted once it holds `l0CompactionTrigger` tables, and
  each deeper level has a size budget of `l1BaseBytes * levelMultiplier^(n-1)`. Levels stay
  disjoint, and shadowed tombstones are dropped at the bottom level. The merge is a k-way
  heap merge where the newest sequence number wins.
- A `MANIFEST`/`CURRENT` version set that records which level each table belongs to.
  Counters are recovered from both the manifest and a directory scan.
- MVCC: every write gets a sequence number. Snapshots and `*AsOf` reads see a consistent
  view.
- Forward, reverse, range and prefix scans that merge the memtable with every SSTable.
- Atomic write batches.
- Optimistic transactions (`Transaction`) that detect read/write conflicts on commit and
  return `error.Conflict`.
- `GuardedDb`, a mutex-guarded facade for sharing one `Db` between threads.
- An exclusive `flock` on a `LOCK` file in the data directory, taken by `Db.open` and
  held until `close`. Every process that opens a directory (`serve`, `replicate`, any
  local CLI command, an embedding program) takes it, so a second opener fails with
  `error.DataDirLocked` instead of writing into a live store. The kernel drops the lock
  when the holder exits, so a crash never leaves a stale lock behind.

### Data model on top of the keyspace

Each subsystem owns a one-byte key prefix in the reserved range `0xF5`-`0xFF`, bytes that
never start a valid UTF-8 sequence. The prefixes are listed in `keyspace.zig` and checked
at compile time for collisions and for staying inside that range. User keys live below
it: raw `get`, `set`, `del`, `batch` and the TTL commands reject a key whose first byte is
`0xF5` or higher, and `scan`, `rscan` and `prefix` (CLI, `repl` and protocol) stop at
`0xF5`, so they only return user keys. The subsystems read their own namespaces directly.

- **Key TTL**: per-key expiry markers. A key past its TTL reads as missing on every read
  path (`get`, `scan`, `rscan`, `prefix` in the CLI, `repl` and protocol). It is removed
  lazily on `get`, by an explicit sweep, or by a background sweeper in the server. Semantics
  follow Redis: a plain write (`put`, protocol `set`, `batch`) drops any TTL on the key in the
  same atomic write, so a value written over an expired but not yet swept key reads back and
  never expires; `put --ttl` writes the value and its TTL together. `expire` treats a key past
  its TTL as missing (CLI and `repl` report no such key, the protocol answers `not_found`) and
  never sets a TTL on it. `ttl` prints `-1` for a key without expiry and `-2` for a missing key
  or one past its deadline, swept or not.
- **Typed collections**: counter, hash, set (including `inter`/`union`/`diff`), list
  (push/pop at both ends, `range`) and sorted set (`score`, `rank`, `incrby`,
  `rangebyrank`, `rangebyscore`). Every mutation runs as a transaction and is retried on
  conflict. A whole collection can be given a TTL as one unit.
- **Tables**: schema-less rows made of typed fields (`int`, `float`, `bool`, `text`,
  `bytes`, `none`), keyed by a typed primary key (stored as `__pk`). Supported on top of
  that:
  - single-field and composite secondary indexes; composite indexes are used for
    leftmost-prefix lookups;
  - `UNIQUE`, `FOREIGN KEY` (`restrict` or `cascade` on delete) and named `CHECK`
    constraints;
  - a predicate language: `eq ne lt lte gt gte like in between is_null is_not_null`,
    combined with `and`, `or`, `not` and parentheses;
  - `select` with multi-column `--order-by`, `--limit` and `--offset`;
  - `explain`, which shows the plan the planner picks: full scan, single-field index
    (equality or range), or composite index (equality or range);
  - bulk `update` and `delete` by predicate;
  - inner, left, right and full equi-joins (index nested-loop when the right side is
    indexed, hash join otherwise);
  - `GROUP BY` aggregates (`count`, `count:field`, `sum`, `avg`, `min`, `max`,
    `distinct`) with `having` and `order`;
  - window functions (`row_number`, `rank`, `dense_rank`, running `sum`/`avg`/`count`/
    `count_distinct`/`min`/`max`, `first_value`, `last_value`, `nth_value`, `lag`,
    `lead`) with `partition`, `order`, and ROWS or RANGE frames;
  - multi-table transactions (`TableTxn`) that keep the indexes in sync;
  - CSV and JSON export and import, with type-tagged cells so a round trip reproduces
    every value exactly.
- **Users**: accounts with role `readonly`, `readwrite` or `admin`. Passwords are stored
  only as per-user salted PBKDF2-HMAC-SHA256 hashes (100,000 rounds by default). Lookups
  of unknown users cost about as much as a wrong password.

### Server and tooling

- A TCP server with a length-prefixed binary protocol and one thread per connection.
  It supports:
  - an optional global token-bucket rate limit, a per-connection rate limit, or both;
  - optional authentication with role checks per opcode;
  - expiring session tokens that a new connection can present instead of the password;
  - background sweepers for sessions, key TTLs and collection TTLs;
  - pub/sub channels that never take the storage lock. Each subscriber gets a bounded
    mailbox (256 messages) that drops the oldest message when full.
- A client library (`Client`) that covers every opcode.
- Remote CLI commands for queries, updates, imports and exports, collections, TTL, user
  administration, transactions, stats and pub/sub.
- Point-in-time backups to a single file, with magic numbers, a CRC per entry and for the
  whole file, and an entry count. A backup is fully validated before restore writes
  anything.
- Replication: a WAL tailer applies new writes to a replica directory. It persists its
  offset, detects a truncated or regenerated primary WAL, and falls back to a full resync
  when it has fallen behind.
- Metrics: counters, gauges, histograms with quantile estimates, token-bucket and
  sliding-window limiters, and a Prometheus text exporter for both the store and the
  server.
- An interactive shell (`repl`) with `begin`/`commit`/`rollback`.
- A throughput benchmark.

## Build

Requires Zig 0.13.0.

```sh
zig build                      # library, cobalt CLI and cobalt-bench into zig-out/
zig build -Doptimize=ReleaseSafe
zig build run -- <dir> <command> [args]
zig build bench -- [operations]
```

## Upgrading

This version changes the on-disk layout of the internal namespaces: the prefixes of
tables, indexes, collections, collection and key TTL markers, and users moved to the bytes
`0xF5`-`0xFC`. A data directory written by an older build is not read correctly. Export
the data with the old build (`table export` for tables, `scan` for plain keys, and
re-create users and collections), then import it into a fresh directory with this build.
`backup`/`restore` copies raw entries and does not convert the layout.

## Tests

```sh
zig build test
```

The unit tests cover every module: crash recovery and torn WAL and manifest tails,
corrupted backups, compaction, transactions under real OS-thread concurrency, the protocol codecs, and end-to-end server
tests over real sockets (auth, sessions, rate limits, sweepers, pub/sub, every remote
opcode).

## CLI

Local commands open a data directory directly:

```
cobalt <dir> <command> [args]
```

Remote commands connect to a running `cobalt serve`. They take `host:port` in place of
the directory:

```
cobalt <host:port> remote-<command> [args] [--user NAME --pass PASS] [--token TOKEN]
```

Running `cobalt` without arguments prints the full reference. The sections below show
each group with real output.

### Keys, TTL and scans

```sh
$ cobalt ./data put user:1 alice
$ cobalt ./data put user:2 bob
$ cobalt ./data put session:9 tmp --ttl 60
$ cobalt ./data get user:1
alice
$ cobalt ./data ttl session:9
59
$ cobalt ./data ttl user:1
-1
$ cobalt ./data rscan user: user:~
user:2	bob
user:1	alice
$ cobalt ./data prefix user:
user:1	alice
user:2	bob
$ cobalt ./data del user:2
$ cobalt ./data get user:2
(nil)
```

Other commands: `expire <key> <seconds>`, `persist <key>`, `expire-sweep`,
`scan [start] [end]`, `compact`, `stats [--prom]`, `verify <n>` (writes n keys, reopens
the store and checks durability and scan order; it works in a fresh scratch directory
under `$TMPDIR` or `/tmp`, removes it afterwards and never touches `<dir>`).

### Collections

```sh
$ cobalt ./data coll counter incrby visits 5
5
$ cobalt ./data coll zset add board ada 30
OK
$ cobalt ./data coll zset add board bo 12
OK
$ cobalt ./data coll zset rangebyscore board 0 100
bo	12
ada	30
$ cobalt ./data coll list rpush q a
OK
$ cobalt ./data coll list range q 0 -1
a
$ cobalt ./data coll set add s x
1
$ cobalt ./data coll set expire s 30
OK
$ cobalt ./data coll set ttl s
29
```

Kinds and operations:

| Kind | Operations |
|------|------------|
| `counter` | `get`, `set`, `incrby` |
| `hash` | `set`, `get`, `del`, `len`, `getall` |
| `set` | `add`, `rem`, `ismember`, `card`, `members`, `inter`, `union`, `diff` |
| `list` | `lpush`, `rpush`, `lpop`, `rpop`, `len`, `range` |
| `zset` | `add`, `score`, `rank`, `incrby`, `rem`, `card`, `rangebyrank`, `rangebyscore` |

Each kind also supports `expire`, `ttl` and `persist`. `coll expire-sweep` removes every
collection whose TTL has passed.

### Tables and queries

Values are typed with a prefix: `i:` int, `f:` float, `b:` bool, `s:` text (the default).

```sh
$ cobalt ./data table put people p1 name=Ada city=oslo age=i:36
OK
$ cobalt ./data table put people p2 name=Bo city=bergen age=i:17
OK
$ cobalt ./data table put people p3 name=Cy city=oslo age=i:52
OK
$ cobalt ./data table index create people city
OK
$ cobalt ./data table select people city eq s:oslo and age gte i:18 --order-by age:desc
__pk=p3	name=Cy	city=oslo	age=52
__pk=p1	name=Ada	city=oslo	age=36
$ cobalt ./data table explain people city eq s:oslo
index 'city' (equality)
$ cobalt ./data table aggregate people city count,avg:age
group=oslo	count=2	avg_age=44
group=bergen	count=1	avg_age=17
$ cobalt ./data table window people row_number,sum:age partition city order age
__pk=p1	name=Ada	city=oslo	age=36	row_number=1	sum_age=36
__pk=p3	name=Cy	city=oslo	age=52	row_number=2	sum_age=88
__pk=p2	name=Bo	city=bergen	age=17	row_number=1	sum_age=17
$ cobalt ./data table export people csv people.csv
3
$ cat people.csv
__pk,name,city,age
s:p1,s:Ada,s:oslo,i:36
s:p2,s:Bo,s:bergen,i:17
s:p3,s:Cy,s:oslo,i:52
```

More table commands:

```
table get|del <table> <pk>
table scan <table>
table update <table> --set field=value[,field=value...] [expr...]
table delete <table> [expr...]
table index create|drop <table> <field...>
table index create --unique <table> <field>
table fk create <table> <field> <refTable> <refField> [restrict|cascade]
table fk drop <table> <field>
table check create <table> <name> <expr...>
table check drop <table> <name>
table join [--left|--right|--full] <leftTable> <leftField> <rightTable> <rightField>
table aggregate <table> <groupField|*> <spec>[,<spec>...] [expr...] [having <expr>] [order <field[:desc]>,...]
table window <table> <kind[:field]>,... [expr...] [partition <field>,...] [order <field[:desc]>,...] [--range]
table export|import <table> csv|json <path>
```

### Transactions

A `txn` script runs as one atomic commit:

```sh
$ cat move.txn
put accounts a1 balance=i:100
put accounts a2 balance=i:50
# lines starting with # are skipped
del accounts a0
$ cobalt ./data txn move.txn
OK: 3 operation(s) committed atomically
```

`repl` keeps the store open and supports interactive transactions. It reads stdin with a
prompt, or a file with `--script`:

```sh
$ printf 'begin\nput k1 v1\nget k1\ncommit\ncoll counter incrby hits 2\n' > session.txt
$ cobalt ./data repl --script session.txt
OK
OK
v1
OK
2
```

### Server, auth and remote commands

```sh
$ cobalt ./data user add admin secret admin
user 'admin' created with role admin
$ cobalt ./data user add reader pw readonly
user 'reader' created with role readonly
$ cobalt ./data serve 127.0.0.1:6380 --auth --session-ttl 600 --ttl-sweep-interval 5
auth enabled: every op but ping now requires a prior AUTH
sessions enabled: AUTH issues a token valid for 600s
ttl sweeper enabled: due keys reaped every 5s
cobalt server listening on 127.0.0.1:6380
```

From another terminal:

```sh
$ cobalt 127.0.0.1:6380 remote-select people city eq s:oslo
error: ServerUnauthorized
$ cobalt 127.0.0.1:6380 remote-select people city eq s:oslo --user reader --pass pw --limit 1
session token (use with --token): 8f5a2c4bd6cfe6dbc86d1a58d2593268b2b31529d22d98b8
__pk=p1	name=Ada	city=oslo	age=36
$ cobalt 127.0.0.1:6380 remote-update people --set age=i:37 name eq s:Ada --user reader --pass pw
error: ServerForbidden
$ cobalt 127.0.0.1:6380 remote-update people --set age=i:37 name eq s:Ada --user admin --pass secret
1
$ cobalt 127.0.0.1:6380 remote-aggregate people '*' count,max:age --token <token>
count=3	max_age=52
$ cobalt 127.0.0.1:6380 remote-stats --user reader --pass pw
cobalt_server_coll_ttl_swept_total 0
cobalt_server_conn_rate_limited_total 0
cobalt_server_forbidden_total 1
...
```

`serve` options: `--rate-limit <capacity> <per-second>`,
`--per-conn-rate-limit <capacity> <per-second>`, `--auth`, `--session-ttl <s>`,
`--session-sweep-interval <s>`, `--ttl-sweep-interval <s>`,
`--coll-ttl-sweep-interval <s>`. The default address is `127.0.0.1:6380`. `--auth`
refuses to start until at least one admin user exists.

Remote commands: `remote-select`, `remote-explain`, `remote-update`, `remote-delete`,
`remote-join`, `remote-aggregate`, `remote-window`, `remote-export`, `remote-import`
(the file is read or written on the client machine), `remote-coll`, `remote-coll-ttl`,
`remote-ttl`, `remote-txn`, `remote-user` (admin only), `remote-stats`,
`remote-publish`, `remote-subscribe`, `remote-unsubscribe`.

### Pub/sub

```sh
$ cobalt 127.0.0.1:6380 remote-subscribe news,alerts
subscribed as 0
news: build passed
alerts: disk at 91%

$ cobalt 127.0.0.1:6380 remote-publish news build passed
1
```

A subscribed connection can only receive. To drop channels from it, run
`remote-unsubscribe <id> <channel>[,channel...]` from another connection.

### Backup and replication

```sh
$ cobalt ./data backup data.bak
backup written: 23 entries, seq=27, file=data.bak
$ cobalt ./data backup-info data.bak
entries=23 seq=27
$ cobalt ./restored restore data.bak
restore applied: 23 entries from seq=27
$ cobalt ./data replicate ./replica --once
bootstrap: 4 entries copied from snapshot
```

Without `--once`, `replicate` polls the primary WAL every `--interval-ms` (default 200)
until it is interrupted.

## Wire protocol

All integers are little-endian. Requests and responses use the same frame:

```
+--------+----------------+-----------------+
| tag u8 | length u32 LE  | payload (bytes) |
+--------+----------------+-----------------+
```

On a request the tag is an opcode. On a response it is a status. A payload may be at
most 64 MiB. In the layouts below, `str` means a `u32` length followed by that many
bytes, and `rest` means all remaining payload bytes.

| Status | Name | Payload |
|--------|------|---------|
| 0 | ok | result, depends on the opcode |
| 1 | not_found | empty |
| 2 | bad_request | error message (malformed payload, invalid expression or argument) |
| 3 | io_error | error name (the storage layer failed to read or write: disk full, I/O error, permissions, a corrupt SSTable) |
| 4 | conflict | error message (transaction conflict, duplicate user) |
| 5 | internal | error name (constraint violations, out of memory, other non-I/O failures) |
| 6 | rate_limited | error message |
| 7 | unauthorized | error message (no auth yet, or the session expired) |
| 8 | forbidden | error message (role too low) |

| Op | Name | Request payload | `ok` response |
|----|------|-----------------|---------------|
| 0 | ping | empty | `PONG` |
| 1 | get | key (`rest`) | value, or status `not_found` |
| 2 | set | `str` key, value (`rest`) | empty |
| 3 | del | key (`rest`) | empty |
| 4 | scan | `u8` flags (1 = has start, 2 = has end, 4 = reverse), [`str` start], [`str` end], `u32` limit (0 = all) | entry list |
| 5 | prefix | `u32` limit, prefix (`rest`) | entry list |
| 6 | stats | empty | 8 x `u64` (memtable entries, memtable bytes, sstables, live entries, physical bytes, cache hits, cache misses, next seq), then 8 levels x 3 `u64` (tables, entries, bytes) |
| 7 | flush | empty | empty |
| 8 | compact | empty | empty |
| 9 | batch | `u32` count, then per op `u8` kind (0 = put: `str` key, `str` value; 1 = del: `str` key) | empty |
| 10 | table_select | `str` table, `u32` offset, `u32` limit, `u8` order count, per column (`u8` descending, `str` field), expression text (`rest`) | `u32` count, `str` encoded row per row |
| 11 | auth | `str` username, password (`rest`) | empty, or a session token when sessions are on |
| 12 | user_admin | `u8` action (0 create, 1 set password, 2 set role, 3 delete, 4 list), user, password, role, rounds | empty, or the user list |
| 13 | auth_token | token (`rest`) | empty |
| 14 | metrics | empty | Prometheus text for server counters and store stats |
| 15 | ttl_op | `u8` action (0 expire, 1 persist, 2 query, 3 sweep), `u64` seconds, key (`rest`) | empty, remaining TTL, or swept count |
| 16 | coll_ttl_op | same actions as `ttl_op`, plus a collection kind byte | same as `ttl_op` |
| 17 | coll_op | `u8` action (0-29, see `protocol.CollAction`), `str` name, `u32` argc, `str` per argument | tagged reply: nil, ok, int, real, bytes, string list, pair list or score pair list |
| 18 | txn_op | list of put/del row operations over one or more tables | `u32` operations committed, or status `conflict` |
| 19 | table_join | join mode, both tables and fields, per-side filters, page | list of left/right row pairs (either side may be absent) |
| 20 | table_aggregate | table, group field, specs, page, order, `having` and filter expressions | group rows, or one global row |
| 21 | table_explain | `str` table, expression text (`rest`) | the chosen plan |
| 22 | table_update | table, encoded `--set` fields, expression text | `u64` rows updated |
| 23 | table_delete | `str` table, expression text (`rest`) | `u64` rows deleted |
| 24 | table_export | `str` table, `u8` format (CSV or JSON) | `u64` row count and the file contents |
| 25 | table_import | table, format, file contents | `u64` rows imported |
| 26 | table_window | table, window specs, partition and order columns, page, frame mode, expression | rows, each with its window values |
| 27 | subscribe | `u32` count, `str` per channel | `u64` subscriber id, `u32` channel count; then one `ok` frame per message: `str` channel, message (`rest`) |
| 28 | publish | `str` channel, message (`rest`) | `u64` subscribers reached |
| 29 | unsubscribe | `u64` subscriber id, `u32` count, `str` per channel | `u32` channels removed |

An entry list is a `u32` count followed by (`str` key, `str` value) pairs. `protocol.zig`
contains the exact encoder and decoder for every opcode. `client.zig` wraps all of them.

With `--auth` enabled, `ping` always works. `auth` and `auth_token` establish a role.
Read opcodes need `readonly`, writes need `readwrite`, and `user_admin` needs `admin`.
For `ttl_op`, `coll_ttl_op` and `coll_op`, the required role depends on the action byte.

A minimal client in Python:

```python
import socket, struct

sock = socket.create_connection(("127.0.0.1", 6380))

def call(op, payload=b""):
    sock.sendall(struct.pack("<BI", op, len(payload)) + payload)
    status, length = struct.unpack("<BI", sock.recv(5, socket.MSG_WAITALL))
    return status, sock.recv(length, socket.MSG_WAITALL) if length else b""

call(0)                                                   # (0, b'PONG')
call(2, struct.pack("<I", 8) + b"greeting" + b"hello")    # (0, b'')
call(1, b"greeting")                                      # (0, b'hello')
call(1, b"missing")                                       # (1, b'')
```

## Embedding

The build script exports the library as the module `cobalt`. After
`zig fetch --save <url-or-path>`, add it in your `build.zig`:

```zig
const cobaltDep = b.dependency("cobalt", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("cobalt", cobaltDep.module("cobalt"));
```

```zig
const cobalt = @import("cobalt");

var db = try cobalt.Db.open(allocator, "data", .{});
defer db.close();

try db.put("user:1", "alice");
if (try db.get(allocator, "user:1")) |value| {
    defer allocator.free(value);
}

var txn = cobalt.Transaction.begin(&db);
defer txn.deinit();
try txn.put("balance", "100");
try txn.commit();
```

`Options` fields and defaults: `flushThreshold` 4 MiB, `blockCacheBytes` 8 MiB,
`l0CompactionTrigger` 4, `l1BaseBytes` 8 MiB, `levelMultiplier` 10,
`sstableTargetBytes` 2 MiB.

`Db.open` returns `error.DataDirLocked` while another `Db` (in this or any other process)
has the directory open. `Db` itself is the raw engine and its scans cover the whole
keyspace, internal namespaces included. To list only user keys, use
`cobalt.keyspace.scanUser`, `scanUserReverse` and `scanUserPrefix`, and
`cobalt.keyspace.checkUserKey` to validate keys that come from users.

## Project layout

| File | Responsibility |
|------|----------------|
| `build.zig`, `build.zig.zon` | build script and package manifest |
| `src/root.zig` | public library API |
| `src/main.zig` | `cobalt` command-line interface |
| `src/bench.zig` | throughput benchmark |
| `src/encode.zig` | byte encoding helpers, record and key types |
| `src/wal.zig` | write-ahead log, replay, generation counter |
| `src/memtable.zig` | skiplist memtable and cursors |
| `src/sstable.zig` | SSTable builder, reader and cursors |
| `src/bloom.zig` | bloom filter |
| `src/cache.zig` | LRU block cache |
| `src/compress.zig` | RLE block compression |
| `src/heap.zig` | binary heap used by the k-way merge |
| `src/version.zig` | manifest and version set (table to level mapping) |
| `src/batch.zig` | write batches |
| `src/stats.zig` | store statistics |
| `src/db.zig` | store facade, directory lock, flush, compaction, snapshots, iterators |
| `src/txn.zig` | optimistic MVCC transactions |
| `src/concurrent.zig` | `GuardedDb` thread-safe facade |
| `src/keyspace.zig` | registry of internal key prefixes, user-key validation and user-only scans |
| `src/ttl.zig` | per-key expiry |
| `src/collections.zig` | counter, hash, set, list and sorted set |
| `src/collttl.zig` | whole-collection expiry |
| `src/row.zig` | typed values, rows, order-preserving encoding |
| `src/index.zig` | table, index and metadata key layout; index maintenance |
| `src/query.zig` | `Table`: put/get/delete, select, planner, constraints |
| `src/expr.zig` | predicate expression parser |
| `src/join.zig` | inner and outer equi-joins |
| `src/aggregate.zig` | `GROUP BY` aggregates, `having`, ordering |
| `src/window.zig` | window functions |
| `src/txn_table.zig` | table writes inside a transaction |
| `src/dump.zig` | CSV and JSON export and import |
| `src/auth.zig` | users, roles, PBKDF2 password hashing |
| `src/session.zig` | expiring session tokens |
| `src/protocol.zig` | wire format: frames, opcodes, payload codecs |
| `src/server.zig` | TCP server, dispatch, rate limits, sweepers |
| `src/client.zig` | client library |
| `src/pubsub.zig` | pub/sub hub and subscriber mailboxes |
| `src/metrics.zig` | counters, gauges, histograms, rate limiters, Prometheus export |
| `src/backup.zig` | backup, restore, inspect |
| `src/replicate.zig` | WAL tailer and replicator |
| `src/repl.zig` | interactive shell |
| `src/verify.zig` | durability self-check in a scratch directory |

## Limitations

- `Db` has no internal locking. Inside a process, share one `Db` through `GuardedDb` or
  the server, which serialises all storage access behind a single mutex.
- The server has no TLS. Passwords and session tokens travel in plain text, so expose
  it only on trusted networks or behind a TLS terminator.
- Sessions and pub/sub messages are kept in memory only and are lost on restart.
  Undelivered messages are dropped once a subscriber's mailbox is full.
- Replication is one-way and reads the primary's WAL from a local path, not over the
  network. The replica assigns its own sequence numbers. The `replicate` command opens
  the primary directory itself, so while another process serves that directory it
  refuses to start with a lock error. In that case embed `Replicator` in the serving
  process.
- Every WAL append is fsynced. Single-key writes are therefore limited by disk sync
  latency, and batches are the fast path for bulk writes.
- Block compression is RLE only.
- Foreign key `cascade` applies only to non-transactional deletes. Deletes inside a
  transaction always use `restrict`.
- Raw `get`, `set`, `del`, `scan`, `batch`, `flush` and `compact` are available over the
  network through the protocol and `Client`, but have no `remote-*` CLI command.
- In `repl`, `scan`, `table select` and `table join` read committed state and do not see
  writes staged in an open transaction.

## License

MIT, see [LICENSE](LICENSE).
