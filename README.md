# cobalt

An embedded, log-structured merge-tree (LSM) key/value store written in Zig.

Cobalt keeps recent writes in an in-memory skiplist backed by a write-ahead
log, flushes them to immutable SSTables, and reclaims space through leveled
compaction. Reads merge the memtable and every SSTable, honouring MVCC
sequence numbers so snapshots and transactions observe a consistent view.

## Features

- Write-ahead log with single and batched frames, CRC framing, and
  torn-tail recovery.
- Skiplist memtable with forward and reverse ordered cursors.
- SSTable format with a block index, per-table bloom filter, RLE block
  compression, and CRC-checked blocks.
- LRU block cache shared across readers.
- MVCC snapshots and optimistic transactions with read/write conflict
  detection.
- Leveled compaction that keeps levels disjoint and drops shadowed
  tombstones at the bottom level.
- Forward, reverse, range, and prefix scans that merge all sources.
- Atomic write batches and a manifest describing the level of each table.

## Layout

| File | Responsibility |
|------|----------------|
| `src/encode.zig` | byte encoding helpers, record and key types |
| `src/memtable.zig` | skiplist memtable and cursors |
| `src/wal.zig` | write-ahead log and replay |
| `src/sstable.zig` | SSTable builder, reader, and cursors |
| `src/bloom.zig` | bloom filter |
| `src/cache.zig` | LRU block cache |
| `src/compress.zig` | RLE block compression |
| `src/batch.zig` | write batches |
| `src/stats.zig` | database statistics |
| `src/txn.zig` | MVCC transactions |
| `src/db.zig` | store facade, compaction, and iterators |
| `src/main.zig` | command-line interface |
| `src/bench.zig` | throughput benchmark |

## Build

```sh
zig build            # build the library, cli, and benchmark
zig build test       # run the unit tests
zig build run -- <dir> <command> [args]
zig build bench -- [operations]
```

## CLI

```sh
cobalt <dir> put <key> <value>
cobalt <dir> get <key>
cobalt <dir> del <key>
cobalt <dir> scan [start] [end]
cobalt <dir> rscan [start] [end]
cobalt <dir> prefix <prefix>
cobalt <dir> compact
cobalt <dir> stats
cobalt <dir> verify <n>
```
