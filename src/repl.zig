const std = @import("std");
const dbmod = @import("db.zig");
const txnmod = @import("txn.zig");
const rowmod = @import("row.zig");
const idx = @import("index.zig");
const querymod = @import("query.zig");
const txntablemod = @import("txn_table.zig");
const collectionsmod = @import("collections.zig");
const collttlmod = @import("collttl.zig");
const ttlmod = @import("ttl.zig");
const exprmod = @import("expr.zig");
const joinmod = @import("join.zig");
const aggregatemod = @import("aggregate.zig");
const windowmod = @import("window.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Transaction = txnmod.Transaction;
const Table = querymod.Table;
const TableTxn = txntablemod.TableTxn;
const Value = rowmod.Value;
const Field = rowmod.Field;
const Row = rowmod.Row;
const CollKind = collectionsmod.Kind;

/// Errors `Repl.dispatch` can raise on top of whatever the underlying `Db`/
/// `Transaction`/`Table` call it wraps returns (those propagate as-is, e.g.
/// `error.Conflict` from a failed commit).
pub const ReplError = error{
    UnknownCommand,
    WrongArgCount,
    NoActiveTransaction,
    TransactionAlreadyActive,
    InvalidField,
    UnknownCollectionKind,
    UnknownCollectionOp,
    InvalidArgument,
    NoSuchKey,
};

/// Interactive session bound to one already-open `*Db`. The one-shot CLI in
/// main.zig opens a fresh `Db` per process per command, and its `txn
/// <script-file>` command runs a whole transaction non-interactively from a
/// static file. `Repl` instead keeps the store open across many commands and
/// lets `begin`/`commit`/`rollback` bracket an interactive `Transaction`:
/// a `get` between `begin` and `commit` can steer what the *next* `put`
/// does (e.g. "read balance, then decide how much to add"), which a script
/// file evaluated top to bottom cannot express.
///
/// `table put/get/del` follow the active transaction automatically: with no
/// transaction open they go straight through `query.Table` (each call is
/// independently durable the moment it returns, exactly like `table put` on
/// the plain CLI); with a transaction open they route through a `TableTxn`
/// bound to it instead, so multiple `table put` calls across multiple
/// tables in the same `begin`/`commit` bracket commit atomically as one
/// `WriteBatch`, or none of them do on `error.Conflict` - the interactive
/// equivalent of `txn <script-file>`.
///
/// `scan` always reads the live, already-committed `Db` state regardless of
/// any open transaction: `Transaction` has no scan/range primitive (only
/// `get`, which resolves the transaction's own staged writes first), so a
/// staged-but-uncommitted put is invisible to `scan` until `commit` lands it
/// for real. This is a deliberate, documented limitation, not an oversight.
/// `table select`/`table join` are the same story one level up: `TableTxn`
/// only ever brackets single-row put/get/delete, so both always run against
/// `query.Table.open(self.db, ...)` directly, never through the active
/// transaction, exactly like `scan`.
pub const Repl = struct {
    db: *Db,
    allocator: Allocator,
    txn: ?Transaction = null,
    tableTxns: std.StringHashMap(TableTxn),

    pub fn init(allocator: Allocator, db: *Db) Repl {
        return .{
            .db = db,
            .allocator = allocator,
            .tableTxns = std.StringHashMap(TableTxn).init(allocator),
        };
    }

    pub fn deinit(self: *Repl) void {
        self.discardTxnState();
        self.tableTxns.deinit();
    }

    pub fn inTransaction(self: *const Repl) bool {
        return self.txn != null;
    }

    fn discardTxnState(self: *Repl) void {
        var it = self.tableTxns.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.tableTxns.clearRetainingCapacity();
        if (self.txn) |*t| {
            t.deinit();
            self.txn = null;
        }
    }

    /// Runs one line of input, writing command output or `error: <name>` to
    /// `writer`. Returns `false` on `exit`/`quit` (caller should stop
    /// reading), `true` otherwise - including after a reported error, so one
    /// bad line never kills the session.
    pub fn runLine(self: *Repl, line: []const u8, writer: anytype) !bool {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') return true;

        var tokens = std.ArrayList([]const u8).init(self.allocator);
        defer tokens.deinit();
        var it = std.mem.tokenizeAny(u8, trimmed, " \t");
        while (it.next()) |tok| try tokens.append(tok);
        if (tokens.items.len == 0) return true;

        const cmd = tokens.items[0];
        if (std.mem.eql(u8, cmd, "exit") or std.mem.eql(u8, cmd, "quit")) return false;

        self.dispatch(cmd, tokens.items[1..], writer) catch |err| {
            try writer.print("error: {s}\n", .{@errorName(err)});
        };
        return true;
    }

    /// Reads lines from `reader` until EOF, running each through `runLine`.
    /// Writes a `cobalt>`/`cobalt(txn)>` prompt before each read when
    /// `prompt` is set (interactive stdin use); script files pass `false`.
    pub fn runFromReader(self: *Repl, reader: anytype, writer: anytype, prompt: bool) !void {
        var buf: [8192]u8 = undefined;
        while (true) {
            if (prompt) {
                try writer.writeAll(if (self.inTransaction()) "cobalt(txn)> " else "cobalt> ");
            }
            const line = (try reader.readUntilDelimiterOrEof(&buf, '\n')) orelse break;
            if (!try self.runLine(line, writer)) break;
        }
    }

    fn dispatch(self: *Repl, cmd: []const u8, args: []const []const u8, writer: anytype) !void {
        if (std.mem.eql(u8, cmd, "begin")) return self.cmdBegin(args, writer);
        if (std.mem.eql(u8, cmd, "commit")) return self.cmdCommit(args, writer);
        if (std.mem.eql(u8, cmd, "rollback")) return self.cmdRollback(args, writer);
        if (std.mem.eql(u8, cmd, "put")) return self.cmdPut(args, writer);
        if (std.mem.eql(u8, cmd, "get")) return self.cmdGet(args, writer);
        if (std.mem.eql(u8, cmd, "del")) return self.cmdDel(args, writer);
        if (std.mem.eql(u8, cmd, "scan")) return self.cmdScan(args, writer);
        if (std.mem.eql(u8, cmd, "stats")) return self.cmdStats(args, writer);
        if (std.mem.eql(u8, cmd, "flush")) return self.cmdFlush(args, writer);
        if (std.mem.eql(u8, cmd, "compact")) return self.cmdCompact(args, writer);
        if (std.mem.eql(u8, cmd, "table")) return self.cmdTable(args, writer);
        if (std.mem.eql(u8, cmd, "coll")) return self.cmdColl(args, writer);
        if (std.mem.eql(u8, cmd, "expire")) return self.cmdExpire(args, writer);
        if (std.mem.eql(u8, cmd, "persist")) return self.cmdPersist(args, writer);
        if (std.mem.eql(u8, cmd, "ttl")) return self.cmdTtl(args, writer);
        if (std.mem.eql(u8, cmd, "expire-sweep")) return self.cmdExpireSweep(args, writer);
        if (std.mem.eql(u8, cmd, "help")) return self.cmdHelp(writer);
        return ReplError.UnknownCommand;
    }

