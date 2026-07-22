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

    fn cmdBegin(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        if (self.txn != null) return ReplError.TransactionAlreadyActive;
        self.txn = Transaction.begin(self.db);
        try writer.writeAll("OK\n");
    }

    fn cmdCommit(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        if (self.txn == null) return ReplError.NoActiveTransaction;
        try self.txn.?.commit();
        self.discardTxnState();
        try writer.writeAll("OK\n");
    }

    fn cmdRollback(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        if (self.txn == null) return ReplError.NoActiveTransaction;
        self.discardTxnState();
        try writer.writeAll("OK\n");
    }

    fn cmdPut(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 2) return ReplError.WrongArgCount;
        if (self.txn) |*t| {
            try t.put(args[0], args[1]);
        } else {
            try self.db.put(args[0], args[1]);
        }
        try writer.writeAll("OK\n");
    }

    fn cmdGet(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 1) return ReplError.WrongArgCount;
        const value = if (self.txn) |*t|
            try t.get(self.allocator, args[0])
        else
            try self.db.get(self.allocator, args[0]);
        defer if (value) |v| self.allocator.free(v);
        if (value) |v| {
            try writer.print("{s}\n", .{v});
        } else {
            try writer.writeAll("(nil)\n");
        }
    }

    fn cmdDel(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 1) return ReplError.WrongArgCount;
        if (self.txn) |*t| {
            try t.delete(args[0]);
        } else {
            try self.db.delete(args[0]);
        }
        try writer.writeAll("OK\n");
    }

    fn cmdScan(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len > 1) return ReplError.WrongArgCount;
        const prefix = if (args.len == 1) args[0] else "";
        var iter = try self.db.scanPrefix(self.allocator, prefix);
        defer iter.deinit();
        while (try iter.next()) |entry| {
            try writer.print("{s}\t{s}\n", .{ entry.key, entry.value });
        }
    }

    /// `expire`/`persist`/`ttl`/`expire-sweep` mirror the one-shot CLI's
    /// same-named commands (main.zig) over `ttl.zig`'s flat-key TTL layer.
    /// Like `scan` above, these always act on the live, already-committed
    /// `Db` regardless of any open transaction: a TTL marker lives under its
    /// own keyspace tag, set/cleared directly against `self.db`, never
    /// staged through `Transaction` - there is no OCC-safe way to make
    /// "expire this key in N seconds" conditional on a commit that hasn't
    /// happened yet, so (deliberately, like `coll`'s ops) this bypasses the
    /// active transaction entirely rather than pretending to participate in
    /// it.
    fn cmdExpire(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 2) return ReplError.WrongArgCount;
        const seconds = std.fmt.parseInt(u64, args[1], 10) catch return ReplError.InvalidArgument;
        const existing = try self.db.get(self.allocator, args[0]) orelse return ReplError.NoSuchKey;
        self.allocator.free(existing);
        try ttlmod.setExpireSeconds(self.db, self.allocator, args[0], std.time.nanoTimestamp(), seconds);
        try writer.writeAll("OK\n");
    }

    fn cmdPersist(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 1) return ReplError.WrongArgCount;
        try ttlmod.clearExpire(self.db, self.allocator, args[0]);
        try writer.writeAll("OK\n");
    }

    fn cmdTtl(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 1) return ReplError.WrongArgCount;
        switch (try ttlmod.remaining(self.db, self.allocator, args[0], std.time.nanoTimestamp())) {
            .noKey => try writer.writeAll("-2\n"),
            .noExpiry => try writer.writeAll("-1\n"),
            .seconds => |s| try writer.print("{d}\n", .{s}),
        }
    }

    fn cmdExpireSweep(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        const reaped = try ttlmod.sweepExpired(self.db, self.allocator, std.time.nanoTimestamp());
        try writer.print("reaped: {d}\n", .{reaped});
    }

    fn cmdStats(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        try self.db.stats().print(writer);
    }

    fn cmdFlush(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        try self.db.flush();
        try writer.writeAll("OK\n");
    }

    fn cmdCompact(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len != 0) return ReplError.WrongArgCount;
        try self.db.compact();
        try writer.writeAll("OK\n");
    }

    fn cmdTable(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 1) return ReplError.WrongArgCount;
        const op = args[0];
        const rest = args[1..];

        if (std.mem.eql(u8, op, "select")) return self.cmdTableSelect(rest, writer);
        if (std.mem.eql(u8, op, "explain")) return self.cmdTableExplain(rest, writer);
        if (std.mem.eql(u8, op, "update")) return self.cmdTableUpdate(rest, writer);
        if (std.mem.eql(u8, op, "delete")) return self.cmdTableDelete(rest, writer);
        if (std.mem.eql(u8, op, "join")) return self.cmdTableJoin(rest, writer);
        if (std.mem.eql(u8, op, "aggregate")) return self.cmdTableAggregate(rest, writer);
        if (std.mem.eql(u8, op, "window")) return self.cmdTableWindow(rest, writer);

        if (rest.len < 2) return ReplError.WrongArgCount;
        const tableName = rest[0];
        const pk = try Value.parseCli(rest[1]);

        if (std.mem.eql(u8, op, "put")) {
            var fields = std.ArrayList(Field).init(self.allocator);
            defer fields.deinit();
            for (rest[2..]) |raw| try fields.append(try parseField(raw));
            try self.tablePut(tableName, pk, fields.items);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "get")) {
            if (rest.len != 2) return ReplError.WrongArgCount;
            var row = try self.tableGet(tableName, pk) orelse {
                try writer.writeAll("(nil)\n");
                return;
            };
            defer row.deinit();
            try printRow(writer, row);
        } else if (std.mem.eql(u8, op, "del")) {
            if (rest.len != 2) return ReplError.WrongArgCount;
            try self.tableDel(tableName, pk);
            try writer.writeAll("OK\n");
        } else {
            return ReplError.UnknownCommand;
        }
    }

    /// `table select <table> [expr...] [--limit N] [--offset N] [--order-by
    /// field[:desc][,field[:desc]...]]`: interactive counterpart of the
    /// one-shot CLI's `table select` (main.zig's `runTable`) over
    /// query.zig's `Table.selectPageOrdered`, same expr grammar (expr.zig)
    /// and `--limit`/`--offset`/`--order-by` conventions.
    fn cmdTableSelect(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 1) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();

        const sel = try extractSelectFlags(self.allocator, args[1..]);
        defer self.allocator.free(sel.rest);
        defer self.allocator.free(sel.flags.orderBy);

        const exprText = try std.mem.join(self.allocator, " ", sel.rest);
        defer self.allocator.free(exprText);

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = try exprmod.parse(self.allocator, exprText);
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const rows = try table.selectPageOrdered(pred, .{ .offset = sel.flags.page.offset, .limit = sel.flags.page.limit }, sel.flags.orderBy);
        defer querymod.freeRows(self.allocator, rows);
        for (rows) |r| try printRow(writer, r);
    }

    /// `table explain <table> [expr...]`: interactive counterpart of the
    /// one-shot CLI's `table explain` (main.zig's `runTable`), reporting
    /// which strategy `table select` would use for the same predicate
    /// without running it - `query.Table.explain` over the same expr
    /// grammar `cmdTableSelect` already uses.
    fn cmdTableExplain(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 1) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();

        const exprText = try std.mem.join(self.allocator, " ", args[1..]);
        defer self.allocator.free(exprText);

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = try exprmod.parse(self.allocator, exprText);
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        var plan = try table.explain(self.allocator, pred);
        defer plan.deinit(self.allocator);
        try printPlan(writer, plan);
    }

    /// `table update <table> --set field=value[,field=value...] [expr...]`:
    /// interactive counterpart of the one-shot CLI's `table update`
    /// (main.zig's `runTable`) over `query.Table.updateWhere`, same
    /// `--set`/expr grammar. Prints the number of rows updated.
    fn cmdTableUpdate(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 1) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();

        const setf = try extractSetFlag(self.allocator, args[1..]);
        defer self.allocator.free(setf.sets);
        defer self.allocator.free(setf.rest);

        const exprText = try std.mem.join(self.allocator, " ", setf.rest);
        defer self.allocator.free(exprText);

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = try exprmod.parse(self.allocator, exprText);
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const updated = try table.updateWhere(pred, setf.sets);
        try writer.print("{d}\n", .{updated});
    }

    /// `table delete <table> [expr...]`: interactive counterpart of the
    /// one-shot CLI's `table delete` (main.zig's `runTable`) over
    /// `query.Table.deleteWhere`, same expr grammar as `cmdTableSelect`/
    /// `cmdTableExplain` (empty expr deletes every row). Prints the number
    /// of rows deleted.
    fn cmdTableDelete(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 1) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();

        const exprText = try std.mem.join(self.allocator, " ", args[1..]);
        defer self.allocator.free(exprText);

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) {
            parsed = try exprmod.parse(self.allocator, exprText);
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const deleted = try table.deleteWhere(pred);
        try writer.print("{d}\n", .{deleted});
    }

    /// `table join [--left|--right|--full] <leftTable> <leftField>
    /// <rightTable> <rightField> [--limit N] [--offset N]`: interactive
    /// counterpart of the one-shot CLI's `table join` over join.zig's four
    /// join functions. With no flag, prints inner-join pairs (`L <row>`
    /// then `R <row>`); `--left`/`--right`/`--full` print `L (nil)`/
    /// `R (nil)` for the unmatched side exactly like the CLI.
    /// `--limit`/`--offset` window the already-joined result through
    /// `join.applyPage`, same convention as `table select`'s paging (0 or
    /// omitted = unlimited). Predicates on either side are not exposed here
    /// (same deliberately minimal CLI surface as `table join` itself - the
    /// richer path is the `join.zig` library API, as its own tests cover).
    fn cmdTableJoin(self: *Repl, args: []const []const u8, writer: anytype) !void {
        const JoinMode = enum { inner, left, right, full };
        var mode: JoinMode = .inner;
        var positional = std.ArrayList([]const u8).init(self.allocator);
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
        const pf = try extractPageFlags(self.allocator, positional.items);
        defer self.allocator.free(pf.rest);
        if (pf.rest.len != 4) return ReplError.WrongArgCount;
        const jargs = pf.rest;
        const page = querymod.Page{ .offset = pf.page.offset, .limit = pf.page.limit };

        var left = try Table.open(self.db, self.allocator, jargs[0]);
        defer left.deinit();
        var right = try Table.open(self.db, self.allocator, jargs[2]);
        defer right.deinit();

        switch (mode) {
            .inner => {
                const joined = try joinmod.innerJoin(self.allocator, &left, jargs[1], null, &right, jargs[3], null);
                const paged = try joinmod.applyPage(joinmod.JoinedRow, self.allocator, joined, page);
                defer joinmod.freeJoined(self.allocator, paged);
                for (paged) |pair| {
                    try writer.writeAll("L ");
                    try printRow(writer, pair.left);
                    try writer.writeAll("R ");
                    try printRow(writer, pair.right);
                }
            },
            .left => {
                const joined = try joinmod.leftOuterJoin(self.allocator, &left, jargs[1], null, &right, jargs[3], null);
                const paged = try joinmod.applyPage(joinmod.OuterJoinedRow, self.allocator, joined, page);
                defer joinmod.freeOuterJoined(self.allocator, paged);
                for (paged) |pair| {
                    try writer.writeAll("L ");
                    try printRow(writer, pair.left);
                    if (pair.right) |r| {
                        try writer.writeAll("R ");
                        try printRow(writer, r);
                    } else {
                        try writer.writeAll("R (nil)\n");
                    }
                }
            },
            .right => {
                const joined = try joinmod.rightOuterJoin(self.allocator, &left, jargs[1], null, &right, jargs[3], null);
                const paged = try joinmod.applyPage(joinmod.RightOuterJoinedRow, self.allocator, joined, page);
                defer joinmod.freeRightOuterJoined(self.allocator, paged);
                for (paged) |pair| {
                    if (pair.left) |l| {
                        try writer.writeAll("L ");
                        try printRow(writer, l);
                    } else {
                        try writer.writeAll("L (nil)\n");
                    }
                    try writer.writeAll("R ");
                    try printRow(writer, pair.right);
                }
            },
            .full => {
                const joined = try joinmod.fullOuterJoin(self.allocator, &left, jargs[1], null, &right, jargs[3], null);
                const paged = try joinmod.applyPage(joinmod.FullOuterJoinedRow, self.allocator, joined, page);
                defer joinmod.freeFullOuterJoined(self.allocator, paged);
                for (paged) |pair| {
                    if (pair.left) |l| {
                        try writer.writeAll("L ");
                        try printRow(writer, l);
                    } else {
                        try writer.writeAll("L (nil)\n");
                    }
                    if (pair.right) |r| {
                        try writer.writeAll("R ");
                        try printRow(writer, r);
                    } else {
                        try writer.writeAll("R (nil)\n");
                    }
                }
            },
        }
    }

    /// `table aggregate <table> <groupField|*> <spec>[,<spec>...] [expr...]
    /// [--limit N] [--offset N]`: interactive counterpart of the one-shot
    /// CLI's `table aggregate` (main.zig's `runTable`) over `aggregate.zig`'s
    /// `GroupBy`/`runGlobal`. `*` as the group field means no grouping
    /// (`runGlobal`, always exactly one output line, `--limit`/`--offset`
    /// ignored - nothing to page over a single row), same sentinel the CLI
    /// uses; anything else groups by that field (`run`, one line per
    /// distinct group value, first-seen order), windowed by
    /// `aggregate.applyPageGroups` same as local `table aggregate`.
    fn cmdTableAggregate(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 2) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();
        const groupField = args[1];

        const specs = parseAggSpecs(self.allocator, args[2]) catch return ReplError.InvalidArgument;
        defer self.allocator.free(specs);

        const flags = try extractPageFlags(self.allocator, args[3..]);
        defer self.allocator.free(flags.rest);

        const exprText = try std.mem.join(self.allocator, " ", flags.rest);
        defer self.allocator.free(exprText);
        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) parsed = try exprmod.parse(self.allocator, exprText);
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const rows = try table.select(pred);
        defer querymod.freeRows(self.allocator, rows);

        if (std.mem.eql(u8, groupField, "*")) {
            const values = try aggregatemod.runGlobal(self.allocator, rows, specs);
            defer aggregatemod.freeGlobalResult(self.allocator, values);
            for (specs, values, 0..) |spec, v, i| {
                if (i > 0) try writer.writeAll("\t");
                try printAggLabel(writer, spec);
                try writer.writeAll("=");
                try printValue(writer, v);
            }
            try writer.writeAll("\n");
        } else {
            const unpaged = try aggregatemod.run(self.allocator, rows, groupField, specs);
            const groups = try aggregatemod.applyPageGroups(self.allocator, unpaged, .{ .offset = flags.page.offset, .limit = flags.page.limit });
            defer {
                for (groups) |*g| g.deinit(self.allocator);
                self.allocator.free(groups);
            }
            for (groups) |g| {
                try writer.writeAll("group=");
                try printValue(writer, g.group);
                for (specs, g.values) |spec, v| {
                    try writer.writeAll("\t");
                    try printAggLabel(writer, spec);
                    try writer.writeAll("=");
                    try printValue(writer, v);
                }
                try writer.writeAll("\n");
            }
        }
    }

    /// `table window <table> <kind[:field]>[,<kind[:field]>...] [expr...]
    /// [partition <field>[,field...]] [order <field[:desc]>[,field...]]
    /// [--limit N] [--offset N] [--range]`: interactive counterpart of the
    /// one-shot CLI's `table window` (main.zig's `runTable`) over
    /// `window.zig`'s `computeMany` - a comma-separated spec list computes
    /// multiple annotation columns sharing one partition/order/frame,
    /// mirroring `table aggregate`'s multi-spec list. Unlike
    /// `cmdTableAggregate`, a window annotation never collapses rows - every
    /// matching row is printed, annotated with the computed value(s) - so
    /// `--limit`/`--offset` window WHICH rows get
    /// printed, walked in `window.orderedIndices`' partition-then-order
    /// display sequence (matching local `table window`'s fix for the same
    /// raw-scan-order paging bug, not raw scan order). `--range` switches
    /// sum/avg/count/min/max from the default ROWS running frame to SQL's
    /// actual RANGE default (rows tied on `order` share the tie group's
    /// combined value), same as local `table window`/`remote-window`;
    /// rejected together with row_number/rank/dense_rank.
    fn cmdTableWindow(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len < 2) return ReplError.WrongArgCount;
        var table = try Table.open(self.db, self.allocator, args[0]);
        defer table.deinit();

        const specs = parseWindowSpecs(self.allocator, args[1]) catch return ReplError.InvalidArgument;
        defer self.allocator.free(specs);

        const flags = try extractPageFlags(self.allocator, args[2..]);
        defer self.allocator.free(flags.rest);

        const rangeFlag = try extractRangeFlag(self.allocator, flags.rest);
        defer self.allocator.free(rangeFlag.rest);
        const frame: windowmod.FrameMode = if (rangeFlag.range) .range else .rows;

        const split = splitWindowArgs(rangeFlag.rest);

        const exprText = try std.mem.join(self.allocator, " ", split.whereArgs);
        defer self.allocator.free(exprText);
        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (exprText.len > 0) parsed = try exprmod.parse(self.allocator, exprText);
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        var partitionBy: [][]const u8 = &.{};
        defer self.allocator.free(partitionBy);
        if (split.partitionArgs) |partitionArgs| {
            if (partitionArgs.len != 1) return ReplError.InvalidArgument;
            partitionBy = parsePartitionList(self.allocator, partitionArgs[0]) catch return ReplError.InvalidArgument;
        }

        var orderBy: []querymod.OrderBy = &.{};
        defer self.allocator.free(orderBy);
        if (split.orderArgs) |orderArgs| {
            if (orderArgs.len != 1) return ReplError.InvalidArgument;
            orderBy = parseOrderByList(self.allocator, orderArgs[0]) catch return ReplError.InvalidArgument;
        }

        const rows = try table.select(pred);
        defer querymod.freeRows(self.allocator, rows);

        const results = try windowmod.computeMany(self.allocator, rows, partitionBy, orderBy, specs, frame);
        defer windowmod.freeManyResults(self.allocator, results);

        const displayOrder = try windowmod.orderedIndices(self.allocator, rows, partitionBy, orderBy);
        defer self.allocator.free(displayOrder);

        const total = displayOrder.len;
        const start = @min(flags.page.offset, total);
        const end = if (flags.page.limit == 0) total else @min(start + flags.page.limit, total);
        var i: usize = start;
        while (i < end) : (i += 1) {
            const rowIdx = displayOrder[i];
            for (rows[rowIdx].fields.items, 0..) |f, j| {
                if (j > 0) try writer.writeAll("\t");
                try writer.print("{s}=", .{f.name});
                try printValue(writer, f.value);
            }
            if (rows[rowIdx].fields.items.len > 0) try writer.writeAll("\t");
            for (specs, 0..) |spec, specIdx| {
                if (specIdx > 0) try writer.writeAll("\t");
                try printWindowLabel(writer, spec);
                try writer.writeAll("=");
                try printValue(writer, results[rowIdx][specIdx]);
            }
            try writer.writeAll("\n");
        }
    }

    fn getOrOpenTableTxn(self: *Repl, name: []const u8) !*TableTxn {
        if (self.tableTxns.getPtr(name)) |existing| return existing;
        var opened = try TableTxn.open(&self.txn.?, self.allocator, name);
        errdefer opened.deinit();
        const nameCopy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(nameCopy);
        try self.tableTxns.put(nameCopy, opened);
        return self.tableTxns.getPtr(name).?;
    }

    fn tablePut(self: *Repl, name: []const u8, pk: Value, fields: []const Field) !void {
        if (self.txn != null) {
            const tt = try self.getOrOpenTableTxn(name);
            return tt.put(pk, fields);
        }
        var table = try Table.open(self.db, self.allocator, name);
        defer table.deinit();
        try table.put(pk, fields);
    }

    fn tableGet(self: *Repl, name: []const u8, pk: Value) !?Row {
        if (self.txn != null) {
            const tt = try self.getOrOpenTableTxn(name);
            return tt.get(pk);
        }
        var table = try Table.open(self.db, self.allocator, name);
        defer table.deinit();
        return table.get(pk);
    }

    fn tableDel(self: *Repl, name: []const u8, pk: Value) !void {
        if (self.txn != null) {
            const tt = try self.getOrOpenTableTxn(name);
            return tt.delete(pk);
        }
        var table = try Table.open(self.db, self.allocator, name);
        defer table.deinit();
        try table.delete(pk);
    }

    /// Runs `coll <kind> <op> [args...]` against the live `Db` - the
    /// interactive counterpart of the one-shot CLI's `coll` command
    /// (main.zig's `runColl`), same dispatch shape and lazy-expiry-on-
    /// access behavior (every op below reads/writes a named collection as
    /// `rest[0]`, so a collection whose TTL already elapsed is expired
    /// before the op sees it, matching the CLI). Deliberately NOT routed
    /// through the REPL's active `Transaction` the way `table`/plain
    /// `put`/`get`/`del` are: `Counter.incrBy`/`List.pushLeft`/`ZSet.add`/
    /// etc. already open and commit their OWN internal `Transaction` with
    /// OCC retry per call (see collections.zig), so there is no staged,
    /// uncommitted state here for `begin`/`commit` to bracket the way
    /// `TableTxn` brackets table writes - every `coll` op is independently
    /// durable the instant it returns, with or without an open REPL
    /// transaction, exactly like `scan` above always sees committed state
    /// only regardless of any in-flight transaction.
    fn cmdColl(self: *Repl, args: []const []const u8, writer: anytype) !void {
        if (args.len >= 1 and std.mem.eql(u8, args[0], "expire-sweep")) {
            if (args.len != 1) return ReplError.WrongArgCount;
            const reaped = try collttlmod.sweepExpired(self.db, self.allocator, std.time.nanoTimestamp());
            try writer.print("reaped: {d}\n", .{reaped});
            return;
        }
        if (args.len < 2) return ReplError.WrongArgCount;
        const kind = CollKind.parse(args[0]) orelse return ReplError.UnknownCollectionKind;
        const op = args[1];
        const rest = args[2..];

        if (std.mem.eql(u8, op, "expire") or std.mem.eql(u8, op, "ttl") or std.mem.eql(u8, op, "persist")) {
            return self.cmdCollTtl(kind, op, rest, writer);
        }

        if (rest.len >= 1) {
            _ = try collttlmod.expireIfDue(self.db, self.allocator, kind, rest[0], std.time.nanoTimestamp());
        }

        switch (kind) {
            .counter => try self.cmdCollCounter(op, rest, writer),
            .hash => try self.cmdCollHash(op, rest, writer),
            .set => try self.cmdCollSet(op, rest, writer),
            .list => try self.cmdCollList(op, rest, writer),
            .zset => try self.cmdCollZSet(op, rest, writer),
        }
    }

    /// `coll <kind> expire|ttl|persist <name>` and `coll expire-sweep`
    /// mirror the CLI's `runCollTtl`/top-of-`runColl` special case over
    /// collttl.zig - the collection-namespace counterpart of `cmdExpire`/
    /// `cmdPersist`/`cmdTtl`/`cmdExpireSweep` above, same reasoning for
    /// bypassing the active transaction (a whole collection's expiry is not
    /// staged through `Transaction` either).
    fn cmdCollTtl(self: *Repl, kind: CollKind, op: []const u8, args: []const []const u8, writer: anytype) !void {
        if (std.mem.eql(u8, op, "expire")) {
            if (args.len != 2) return ReplError.WrongArgCount;
            const seconds = std.fmt.parseInt(u64, args[1], 10) catch return ReplError.InvalidArgument;
            if (!try collectionsmod.collectionExists(self.db, self.allocator, kind, args[0])) return ReplError.NoSuchKey;
            try collttlmod.setExpireSeconds(self.db, self.allocator, kind, args[0], std.time.nanoTimestamp(), seconds);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "persist")) {
            if (args.len != 1) return ReplError.WrongArgCount;
            try collttlmod.clearExpire(self.db, self.allocator, kind, args[0]);
            try writer.writeAll("OK\n");
        } else {
            if (args.len != 1) return ReplError.WrongArgCount;
            switch (try collttlmod.remaining(self.db, self.allocator, kind, args[0], std.time.nanoTimestamp())) {
                .noKey => try writer.writeAll("-2\n"),
                .noExpiry => try writer.writeAll("-1\n"),
                .seconds => |s| try writer.print("{d}\n", .{s}),
            }
        }
    }

    fn cmdCollCounter(self: *Repl, op: []const u8, args: []const []const u8, writer: anytype) !void {
        const Counter = collectionsmod.Counter;
        if (std.mem.eql(u8, op, "get")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const v = try Counter.get(self.db, self.allocator, args[0]);
            try writer.print("{d}\n", .{v});
        } else if (std.mem.eql(u8, op, "set")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const v = std.fmt.parseInt(i64, args[1], 10) catch return ReplError.InvalidArgument;
            try Counter.set(self.db, self.allocator, args[0], v);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "incrby")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const delta = std.fmt.parseInt(i64, args[1], 10) catch return ReplError.InvalidArgument;
            const v = try Counter.incrBy(self.db, self.allocator, args[0], delta);
            try writer.print("{d}\n", .{v});
        } else {
            return ReplError.UnknownCollectionOp;
        }
    }

    fn cmdCollHash(self: *Repl, op: []const u8, args: []const []const u8, writer: anytype) !void {
        const Hash = collectionsmod.Hash;
        if (std.mem.eql(u8, op, "set")) {
            if (args.len < 3) return ReplError.WrongArgCount;
            const created = try Hash.set(self.db, self.allocator, args[0], args[1], args[2]);
            try writer.print("{s}\n", .{if (created) "created" else "updated"});
        } else if (std.mem.eql(u8, op, "get")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            if (try Hash.get(self.db, self.allocator, args[0], args[1])) |v| {
                defer self.allocator.free(v);
                try writer.print("{s}\n", .{v});
            } else {
                try writer.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "del")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const existed = try Hash.del(self.db, self.allocator, args[0], args[1]);
            try writer.print("{d}\n", .{@intFromBool(existed)});
        } else if (std.mem.eql(u8, op, "len")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const n = try Hash.len(self.db, self.allocator, args[0]);
            try writer.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "getall")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const fields = try Hash.getAll(self.db, self.allocator, args[0]);
            defer {
                for (fields) |f| f.free(self.allocator);
                self.allocator.free(fields);
            }
            for (fields) |f| try writer.print("{s}\t{s}\n", .{ f.field, f.value });
        } else {
            return ReplError.UnknownCollectionOp;
        }
    }

    fn cmdCollSet(self: *Repl, op: []const u8, args: []const []const u8, writer: anytype) !void {
        const Set = collectionsmod.Set;
        if (std.mem.eql(u8, op, "add")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const added = try Set.add(self.db, self.allocator, args[0], args[1]);
            try writer.print("{d}\n", .{@intFromBool(added)});
        } else if (std.mem.eql(u8, op, "rem")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const removed = try Set.remove(self.db, self.allocator, args[0], args[1]);
            try writer.print("{d}\n", .{@intFromBool(removed)});
        } else if (std.mem.eql(u8, op, "ismember")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const is = try Set.isMember(self.db, self.allocator, args[0], args[1]);
            try writer.print("{d}\n", .{@intFromBool(is)});
        } else if (std.mem.eql(u8, op, "card")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const n = try Set.card(self.db, self.allocator, args[0]);
            try writer.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "members")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const ms = try Set.members(self.db, self.allocator, args[0]);
            defer {
                for (ms) |m| self.allocator.free(m);
                self.allocator.free(ms);
            }
            for (ms) |m| try writer.print("{s}\n", .{m});
        } else if (std.mem.eql(u8, op, "inter") or std.mem.eql(u8, op, "union")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            _ = try collttlmod.expireIfDueMany(self.db, self.allocator, .set, args[1..], std.time.nanoTimestamp());
            const ms = if (std.mem.eql(u8, op, "inter"))
                try Set.intersect(self.db, self.allocator, args)
            else
                try Set.unionOf(self.db, self.allocator, args);
            defer {
                for (ms) |m| self.allocator.free(m);
                self.allocator.free(ms);
            }
            for (ms) |m| try writer.print("{s}\n", .{m});
        } else if (std.mem.eql(u8, op, "diff")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            _ = try collttlmod.expireIfDueMany(self.db, self.allocator, .set, args[1..], std.time.nanoTimestamp());
            const ms = try Set.difference(self.db, self.allocator, args[0], args[1..]);
            defer {
                for (ms) |m| self.allocator.free(m);
                self.allocator.free(ms);
            }
            for (ms) |m| try writer.print("{s}\n", .{m});
        } else {
            return ReplError.UnknownCollectionOp;
        }
    }

    fn cmdCollList(self: *Repl, op: []const u8, args: []const []const u8, writer: anytype) !void {
        const List = collectionsmod.List;
        if (std.mem.eql(u8, op, "lpush")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            try List.pushLeft(self.db, self.allocator, args[0], args[1]);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "rpush")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            try List.pushRight(self.db, self.allocator, args[0], args[1]);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "lpop") or std.mem.eql(u8, op, "rpop")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const popped = if (std.mem.eql(u8, op, "lpop"))
                try List.popLeft(self.db, self.allocator, args[0])
            else
                try List.popRight(self.db, self.allocator, args[0]);
            if (popped) |v| {
                defer self.allocator.free(v);
                try writer.print("{s}\n", .{v});
            } else {
                try writer.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "len")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const n = try List.len(self.db, self.allocator, args[0]);
            try writer.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "range")) {
            if (args.len < 3) return ReplError.WrongArgCount;
            const start = std.fmt.parseInt(i64, args[1], 10) catch return ReplError.InvalidArgument;
            const stop = std.fmt.parseInt(i64, args[2], 10) catch return ReplError.InvalidArgument;
            const vals = try List.range(self.db, self.allocator, args[0], start, stop);
            defer {
                for (vals) |v| self.allocator.free(v);
                self.allocator.free(vals);
            }
            for (vals) |v| try writer.print("{s}\n", .{v});
        } else {
            return ReplError.UnknownCollectionOp;
        }
    }

    fn cmdCollZSet(self: *Repl, op: []const u8, args: []const []const u8, writer: anytype) !void {
        const ZSet = collectionsmod.ZSet;
        if (std.mem.eql(u8, op, "add")) {
            if (args.len < 3) return ReplError.WrongArgCount;
            const scoreVal = std.fmt.parseFloat(f64, args[2]) catch return ReplError.InvalidArgument;
            try ZSet.add(self.db, self.allocator, args[0], args[1], scoreVal);
            try writer.writeAll("OK\n");
        } else if (std.mem.eql(u8, op, "score")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            if (try ZSet.score(self.db, self.allocator, args[0], args[1])) |s| {
                try writer.print("{d}\n", .{s});
            } else {
                try writer.writeAll("(nil)\n");
            }
        } else if (std.mem.eql(u8, op, "incrby")) {
            if (args.len < 3) return ReplError.WrongArgCount;
            const delta = std.fmt.parseFloat(f64, args[2]) catch return ReplError.InvalidArgument;
            const s = try ZSet.incrBy(self.db, self.allocator, args[0], args[1], delta);
            try writer.print("{d}\n", .{s});
        } else if (std.mem.eql(u8, op, "rem")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            const removed = try ZSet.remove(self.db, self.allocator, args[0], args[1]);
            try writer.print("{d}\n", .{@intFromBool(removed)});
        } else if (std.mem.eql(u8, op, "card")) {
            if (args.len < 1) return ReplError.WrongArgCount;
            const n = try ZSet.card(self.db, self.allocator, args[0]);
            try writer.print("{d}\n", .{n});
        } else if (std.mem.eql(u8, op, "rangebyrank") or std.mem.eql(u8, op, "rangebyscore")) {
            if (args.len < 3) return ReplError.WrongArgCount;
            const zms = if (std.mem.eql(u8, op, "rangebyrank")) blk: {
                const start = std.fmt.parseInt(i64, args[1], 10) catch return ReplError.InvalidArgument;
                const stop = std.fmt.parseInt(i64, args[2], 10) catch return ReplError.InvalidArgument;
                break :blk try ZSet.rangeByRank(self.db, self.allocator, args[0], start, stop);
            } else blk: {
                const min = std.fmt.parseFloat(f64, args[1]) catch return ReplError.InvalidArgument;
                const max = std.fmt.parseFloat(f64, args[2]) catch return ReplError.InvalidArgument;
                break :blk try ZSet.rangeByScore(self.db, self.allocator, args[0], min, max);
            };
            defer {
                for (zms) |zm| zm.free(self.allocator);
                self.allocator.free(zms);
            }
            for (zms) |zm| try writer.print("{s}\t{d}\n", .{ zm.member, zm.score });
        } else if (std.mem.eql(u8, op, "rank")) {
            if (args.len < 2) return ReplError.WrongArgCount;
            if (try ZSet.rank(self.db, self.allocator, args[0], args[1])) |r| {
                try writer.print("{d}\n", .{r});
            } else {
                try writer.writeAll("(nil)\n");
            }
        } else {
            return ReplError.UnknownCollectionOp;
        }
    }

    fn cmdHelp(self: *Repl, writer: anytype) !void {
        _ = self;
        try writer.writeAll(
            \\commands:
            \\  put <key> <value>            table put <table> <pk> [field=value ...]
            \\  get <key>                    table get <table> <pk>
            \\  del <key>                    table del <table> <pk>
            \\  scan [prefix]                begin / commit / rollback
            \\  stats / flush / compact      exit / quit
            \\  table select <table> [expr...] [--limit N] [--offset N]
            \\                        [--order-by f[:desc][,f[:desc]...]]
            \\  table join [--left|--right|--full] <lt> <lf> <rt> <rf> [--limit N] [--offset N]
            \\  table aggregate <table> <groupField|*> <spec>[,<spec>...] [expr...] [--limit N] [--offset N]
            \\  table window <table> <kind[:field]>[,<kind[:field]>...] [expr...] [partition f[,f...]]
            \\                        [order f[:desc][,f...]] [--limit N] [--offset N] [--range]
            \\  coll <kind> <op> [args...]   kind: counter/hash/set/list/zset
            \\  expire/persist/ttl <key>     coll <kind> expire/persist/ttl <name>
            \\  expire-sweep                 coll expire-sweep
            \\
        );
    }
};

const PageFlags = struct { limit: u32 = 0, offset: u32 = 0 };

/// Pulls `--limit N` / `--offset N` out of a `table select` argument list
/// wherever they appear, returning the remaining tokens (destined to be
/// joined into the expr text) alongside the parsed page window. Same shape
/// as main.zig's identically-named helper for `table select`/`remote-select`
/// on the one-shot CLI - kept as its own small copy here rather than shared,
/// since main.zig is the binary entry point and not a module repl.zig can
/// import. Caller owns and frees `rest`.
fn extractPageFlags(allocator: Allocator, args: []const []const u8) !struct { page: PageFlags, rest: [][]const u8 } {
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

/// Pulls a lone `--range` flag (no value) out of `table window`'s trailing
/// args, requesting `window.FrameMode.range` instead of the default
/// `.rows` running frame - see `window.zig`'s `compute` doc comment. Same
/// shape as main.zig's identically-named helper, kept as its own small copy
/// here for the same reason `extractPageFlags` above is. Caller owns and
/// frees `rest`.
fn extractRangeFlag(allocator: Allocator, args: []const []const u8) !struct { range: bool, rest: [][]const u8 } {
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

const SelectFlags = struct { page: PageFlags = .{}, orderBy: []const querymod.OrderBy = &.{} };

/// `table select`-only counterpart of `extractPageFlags` above, mirroring
/// main.zig's identically-shaped `extractSelectFlags`/`SelectFlags`: same
/// `--limit`/`--offset` handling plus `--order-by
/// field[:desc][,field[:desc]...]` (comma-separated, applied left to
/// right), kept SEPARATE from `extractPageFlags` rather than folded into
/// it because `extractPageFlags` is also used by `table join`/`table
/// aggregate` here, neither of which sorts its result - recognizing
/// `--order-by` there too would silently consume the flag without
/// honoring it. Caller owns and frees `rest` AND `flags.orderBy`.
fn extractSelectFlags(allocator: Allocator, args: []const []const u8) !struct { flags: SelectFlags, rest: [][]const u8 } {
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

/// Parses `--order-by`'s `field[:desc]` value - mirrors main.zig's
/// identically-shaped `parseOrderByFlag` (kept as its own copy for the same
/// reason `extractPageFlags`'s doc comment gives: repl.zig cannot import
/// main.zig, the binary entry point). `:desc`/`:asc` are the only accepted
/// suffixes; anything else is a malformed flag, not a silent default.
fn parseOrderByFlag(text: []const u8) !querymod.OrderBy {
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

/// Splits `--order-by`'s comma-separated value into one or more columns -
/// mirrors main.zig's identically-shaped `parseOrderByList` (kept as its
/// own copy for the same reason `parseOrderByFlag` above is). Caller owns
/// and frees the returned slice.
fn parseOrderByList(allocator: Allocator, text: []const u8) ![]querymod.OrderBy {
    var list = std.ArrayList(querymod.OrderBy).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseOrderByFlag(segment));
    }
    return list.toOwnedSlice();
}

/// Splits `name=value` into a Field, validating the name the same way
/// index/table identifiers already are. Values follow the CLI's `i:`/`f:`/
/// `b:`/`s:` typed-literal convention via `Value.parseCli`.
fn parseField(text: []const u8) !Field {
    const eq = std.mem.indexOfScalar(u8, text, '=') orelse return ReplError.InvalidField;
    const name = text[0..eq];
    if (!idx.validIdentifier(name)) return ReplError.InvalidField;
    const value = try Value.parseCli(text[eq + 1 ..]);
    return .{ .name = name, .value = value };
}

/// Splits `--set`'s comma-separated `name=value[,name=value...]` value into
/// a list of Fields, each parsed by `parseField` - mirrors main.zig's
/// identically-shaped `parseSetList` (kept as its own copy for the same
/// reason `parseOrderByList` above is).  Caller owns and frees the returned
/// slice.
fn parseSetList(allocator: Allocator, text: []const u8) ![]Field {
    var list = std.ArrayList(Field).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |segment| {
        try list.append(try parseField(segment));
    }
    return list.toOwnedSlice();
}

/// Pulls a single required `--set name=value[,name=value...]` flag out of a
/// `table update` argument list - mirrors main.zig's identically-shaped
/// `extractSetFlag`. Missing `--set` is `error.MissingSetFlag`: a `SET`-less
/// `UPDATE` names nothing to change. Caller owns and frees `rest` and the
/// returned `sets` slice.
fn extractSetFlag(allocator: Allocator, args: []const []const u8) !struct { sets: []Field, rest: [][]const u8 } {
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

fn parseAggKind(name: []const u8) ?aggregatemod.AggKind {
    if (std.mem.eql(u8, name, "count")) return .count;
    if (std.mem.eql(u8, name, "sum")) return .sum;
    if (std.mem.eql(u8, name, "avg")) return .avg;
    if (std.mem.eql(u8, name, "min")) return .min;
    if (std.mem.eql(u8, name, "max")) return .max;
    if (std.mem.eql(u8, name, "distinct")) return .count_distinct;
    return null;
}

/// Parses a comma-separated `table aggregate` spec list, same grammar and
/// same small standalone copy as main.zig's identically-named helper (see
/// `extractPageFlags` above for why this is not shared - main.zig is the
/// binary entry point, not a module repl.zig can import).
fn parseAggSpecs(allocator: Allocator, text: []const u8) ![]aggregatemod.AggSpec {
    var specs = std.ArrayList(aggregatemod.AggSpec).init(allocator);
    errdefer specs.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidAggSpec;
        if (std.mem.indexOfScalar(u8, part, ':')) |colon| {
            const kind = parseAggKind(part[0..colon]) orelse return error.InvalidAggSpec;
            const field = part[colon + 1 ..];
            if (!idx.validIdentifier(field)) return error.InvalidAggSpec;
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

fn printAggLabel(writer: anytype, spec: aggregatemod.AggSpec) !void {
    if (spec.field.len == 0) {
        try writer.writeAll(@tagName(spec.kind));
    } else {
        try writer.print("{s}_{s}", .{ @tagName(spec.kind), spec.field });
    }
}

fn parseWindowKind(name: []const u8) ?windowmod.WindowKind {
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

/// Parses a single `table window` spec token, same grammar (including
/// lag/lead's optional `:offset[:default]` suffix and nth_value's required
/// `:n[:default]` suffix) and same small standalone copy as main.zig's
/// identically-named helper (see `parseAggSpecs` above for why this is not
/// shared).
fn parseWindowSpec(text: []const u8) !windowmod.WindowSpec {
    var it = std.mem.splitScalar(u8, text, ':');
    const kind = parseWindowKind(it.next().?) orelse return error.InvalidWindowSpec;

    if (kind == .row_number or kind == .rank or kind == .dense_rank) {
        if (it.next() != null) return error.InvalidWindowSpec;
        return .{ .field = "", .kind = kind };
    }
    if (kind == .lag or kind == .lead) {
        const field = it.next() orelse return error.InvalidWindowSpec;
        if (!idx.validIdentifier(field)) return error.InvalidWindowSpec;
        var spec = windowmod.WindowSpec{ .field = field, .kind = kind };
        if (it.next()) |offsetText| {
            spec.offset = std.fmt.parseInt(u64, offsetText, 10) catch return error.InvalidWindowSpec;
            // `it.rest()`, NOT another `it.next()`: a typed default literal
            // (`i:-1`, `s:foo:bar`) can itself contain colons, which would
            // get wrongly re-split by a further `splitScalar` step.
            const rest = it.rest();
            if (rest.len > 0) spec.default = Value.parseCli(rest) catch return error.InvalidWindowSpec;
        }
        return spec;
    }
    if (kind == .nth_value) {
        const field = it.next() orelse return error.InvalidWindowSpec;
        if (!idx.validIdentifier(field)) return error.InvalidWindowSpec;
        const nText = it.next() orelse return error.InvalidWindowSpec;
        const n = std.fmt.parseInt(u64, nText, 10) catch return error.InvalidWindowSpec;
        if (n == 0) return error.InvalidWindowSpec;
        var spec = windowmod.WindowSpec{ .field = field, .kind = kind, .offset = n };
        const rest = it.rest();
        if (rest.len > 0) spec.default = Value.parseCli(rest) catch return error.InvalidWindowSpec;
        return spec;
    }

    const field = it.next() orelse {
        if (kind == .count) return .{ .field = "", .kind = kind };
        return error.InvalidWindowSpec;
    };
    if (it.next() != null) return error.InvalidWindowSpec;
    if (!idx.validIdentifier(field)) return error.InvalidWindowSpec;
    return .{ .field = field, .kind = kind };
}

/// Parses `table window`'s comma-separated spec list, same grammar and same
/// small standalone copy as main.zig's identically-named helper (see
/// `parseAggSpecs` above for why this is not shared) - lets one interactive
/// `table window` call annotate rows with multiple columns sharing one
/// `PARTITION BY`/`ORDER BY`/frame (`window.computeMany`).
fn parseWindowSpecs(allocator: Allocator, text: []const u8) ![]windowmod.WindowSpec {
    var specs = std.ArrayList(windowmod.WindowSpec).init(allocator);
    errdefer specs.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidWindowSpec;
        try specs.append(try parseWindowSpec(part));
    }
    if (specs.items.len == 0) return error.InvalidWindowSpec;
    return specs.toOwnedSlice();
}

fn printWindowLabel(writer: anytype, spec: windowmod.WindowSpec) !void {
    if (spec.field.len == 0) {
        try writer.writeAll(@tagName(spec.kind));
    } else {
        try writer.print("{s}_{s}", .{ @tagName(spec.kind), spec.field });
    }
}

fn findLiteralToken(args: []const []const u8, token: []const u8) ?usize {
    for (args, 0..) |a, i| {
        if (std.mem.eql(u8, a, token)) return i;
    }
    return null;
}

/// Splits the trailing free-text args of `table window` on literal
/// `partition` and `order` tokens, same grammar and same small standalone
/// copy as main.zig's identically-named helper (see `parseAggSpecs` above
/// for why this is not shared).
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

/// Parses `table window`'s `partition <field>[,field...]` value, same
/// grammar and same small standalone copy as main.zig's identically-named
/// helper. Caller owns and frees the returned slice (not each field - they
/// borrow from `text`).
fn parsePartitionList(allocator: Allocator, text: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |field| {
        if (!idx.validIdentifier(field)) return error.InvalidPartitionField;
        try list.append(field);
    }
    return list.toOwnedSlice();
}

fn printValue(writer: anytype, value: Value) !void {
    switch (value) {
        .none => try writer.writeAll("(none)"),
        .boolean => |b| try writer.print("{}", .{b}),
        .int => |i| try writer.print("{d}", .{i}),
        .float => |f| try writer.print("{d}", .{f}),
        .text => |s| try writer.writeAll(s),
        .bytes => |b| for (b) |byte| try writer.print("{x:0>2}", .{byte}),
    }
}

fn printRow(writer: anytype, row: Row) !void {
    for (row.fields.items, 0..) |f, i| {
        if (i > 0) try writer.writeAll("\t");
        try writer.print("{s}=", .{f.name});
        try printValue(writer, f.value);
    }
    try writer.writeAll("\n");
}

/// Same wording as main.zig's own `printPlan` (the two binaries do not
/// share this helper - main.zig has no repl.zig dependency and vice versa).
fn printPlan(writer: anytype, plan: querymod.Plan) !void {
    switch (plan.kind) {
        .full_scan => try writer.writeAll("full scan (no usable index)\n"),
        .index_eq => try writer.print("index '{s}' (equality)\n", .{plan.indexName.?}),
        .index_range => try writer.print("index '{s}' (range)\n", .{plan.indexName.?}),
        .composite_eq => try writer.print("composite index '{s}' (equality, {d}/{d} columns matched)\n", .{ plan.indexName.?, plan.matchedFields, plan.totalFields }),
        .composite_range => try writer.print("composite index '{s}' (range, {d}/{d} columns matched)\n", .{ plan.indexName.?, plan.matchedFields, plan.totalFields }),
    }
}

fn openTemp(tmp: *std.testing.TmpDir, allocator: Allocator) !Db {
    var pathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathBuf);
    var dbPathBuf: [std.fs.max_path_bytes]u8 = undefined;
    const dbPath = try std.fmt.bufPrint(&dbPathBuf, "{s}/store", .{base});
    return Db.open(allocator, dbPath, .{});
}

fn runScript(allocator: Allocator, repl: *Repl, script: []const u8) ![]u8 {
    var stream = std.io.fixedBufferStream(script);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try repl.runFromReader(stream.reader(), out.writer(), false);
    return out.toOwnedSlice();
}

test "plain put/get/del run immediately without a transaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "put a 1\nget a\ndel a\nget a\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\n1\nOK\n(nil)\n", out);
}

test "comments and blank lines are ignored, exit stops the loop early" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\# a comment
        \\
        \\put a 1
        \\exit
        \\get a
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\n", out);
}

test "table select filters by expr and honors --limit/--offset" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put items i:1 name=a price=i:10
        \\table put items i:2 name=b price=i:20
        \\table put items i:3 name=c price=i:30
        \\table select items price gt i:10
        \\table select items price gt i:10 --limit 1
        \\table select items price gt i:10 --offset 1
        \\table select items
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=2\tname=b\tprice=20\n" ++
            "__pk=3\tname=c\tprice=30\n" ++
            "__pk=2\tname=b\tprice=20\n" ++
            "__pk=3\tname=c\tprice=30\n" ++
            "__pk=1\tname=a\tprice=10\n" ++
            "__pk=2\tname=b\tprice=20\n" ++
            "__pk=3\tname=c\tprice=30\n",
        out,
    );
}

test "table select --order-by sorts by field, honoring :desc and combining with --limit/--offset" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    // Insert with pk NOT in price order, so a bug that sorted only within
    // the natural pk scan order (or ignored --order-by entirely) would
    // produce a visibly different sequence than asserted below.
    const out = try runScript(allocator, &repl,
        \\table put items i:1 name=b price=i:20
        \\table put items i:2 name=a price=i:30
        \\table put items i:3 name=c price=i:10
        \\table select items --order-by price
        \\table select items --order-by price:desc
        \\table select items --order-by price:desc --limit 1 --offset 1
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=3\tname=c\tprice=10\n" ++
            "__pk=1\tname=b\tprice=20\n" ++
            "__pk=2\tname=a\tprice=30\n" ++
            "__pk=2\tname=a\tprice=30\n" ++
            "__pk=1\tname=b\tprice=20\n" ++
            "__pk=3\tname=c\tprice=10\n" ++
            "__pk=1\tname=b\tprice=20\n",
        out,
    );
}

test "table select --order-by rejects a malformed direction suffix instead of defaulting to ascending" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table put items i:1 price=i:5\ntable select items --order-by price:dsc\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: InvalidPageFlag\n", out);
}

test "table select --order-by with two comma-separated columns sorts by the first, breaking ties with the second" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    // Two rows share city "warsaw" with prices NOT in insertion order, so
    // a single-column city sort alone would leave them in whatever order
    // they were inserted - only a real `price` tiebreak fixes that.
    const out = try runScript(allocator, &repl,
        \\table put items i:1 city=warsaw price=i:30
        \\table put items i:2 city=krakow price=i:5
        \\table put items i:3 city=warsaw price=i:10
        \\table select items --order-by city,price
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=2\tcity=krakow\tprice=5\n" ++
            "__pk=3\tcity=warsaw\tprice=10\n" ++
            "__pk=1\tcity=warsaw\tprice=30\n",
        out,
    );
}

test "table select --order-by rejects an empty segment from a doubled comma instead of silently collapsing it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table put items i:1 price=i:5\ntable select items --order-by city,,price\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: InvalidPageFlag\n", out);
}

test "table select reports a parse error on malformed expr without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table select items price bogus i:1\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("error: UnknownOperator\n", out);
}

test "table explain reports full_scan, an index, and a composite index, matching what table select would actually use" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    {
        var table = try Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("age");
        try table.createCompositeIndex("city_age", &.{ "city", "age" });
    }

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put users i:1 city=s:warsaw age=i:30
        \\table explain users
        \\table explain users city eq s:warsaw
        \\table explain users age eq i:30
        \\table explain users city eq s:warsaw and age eq i:30
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\n" ++
            "full scan (no usable index)\n" ++
            "full scan (no usable index)\n" ++
            "index 'age' (equality)\n" ++
            "composite index 'city_age' (equality, 2/2 columns matched)\n",
        out,
    );
}

test "table update applies --set to matching rows, prints the count, and leaves other rows untouched" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put users i:1 city=s:warsaw active=i:0
        \\table put users i:2 city=s:warsaw active=i:0
        \\table put users i:3 city=s:krakow active=i:0
        \\table update users --set active=i:1 city eq s:warsaw
        \\table select users --order-by __pk
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "2\n" ++
            "__pk=1\tcity=warsaw\tactive=1\n" ++
            "__pk=2\tcity=warsaw\tactive=1\n" ++
            "__pk=3\tcity=krakow\tactive=0\n",
        out,
    );
}

test "table update without --set is rejected as MissingSetFlag instead of silently updating nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table put users i:1 city=s:warsaw\ntable update users city eq s:warsaw\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: MissingSetFlag\n", out);
}

test "table join inner/left/right/full match main.zig's L/R printing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put customers i:1 name=alice
        \\table put customers i:2 name=bob
        \\table put orders i:100 customer_id=i:1 total=i:50
        \\table put orders i:101 customer_id=i:999 total=i:5
        \\table join customers __pk orders customer_id
        \\table join --left customers __pk orders customer_id
        \\table join --right customers __pk orders customer_id
        \\table join --full customers __pk orders customer_id
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        // plain inner join: only alice/order100 matches, bob and the orphan
        // order are absent.
        "OK\nOK\nOK\nOK\n" ++
            "L __pk=1\tname=alice\n" ++
            "R __pk=100\tcustomer_id=1\ttotal=50\n" ++
            // --left: bob survives with R (nil), the orphan order is still absent.
            "L __pk=1\tname=alice\n" ++
            "R __pk=100\tcustomer_id=1\ttotal=50\n" ++
            "L __pk=2\tname=bob\n" ++
            "R (nil)\n" ++
            // --right: the orphan order survives with L (nil), bob is absent.
            "L __pk=1\tname=alice\n" ++
            "R __pk=100\tcustomer_id=1\ttotal=50\n" ++
            "L (nil)\n" ++
            "R __pk=101\tcustomer_id=999\ttotal=5\n" ++
            // --full: both bob and the orphan order survive.
            "L __pk=1\tname=alice\n" ++
            "R __pk=100\tcustomer_id=1\ttotal=50\n" ++
            "L __pk=2\tname=bob\n" ++
            "R (nil)\n" ++
            "L (nil)\n" ++
            "R __pk=101\tcustomer_id=999\ttotal=5\n",
        out,
    );
}

test "table join respects --limit and --offset like table select does" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put customers i:1 name=alice
        \\table put customers i:2 name=bob
        \\table put customers i:3 name=carol
        \\table join --left customers __pk orders customer_id --offset 1 --limit 1
        \\table join --left customers __pk orders customer_id --offset 50
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            // --offset 1 --limit 1: skip alice, keep exactly bob.
            "L __pk=2\tname=bob\n" ++
            "R (nil)\n" ++
            // --offset 50 is past the end of a 3-row left outer join: nothing.
            "",
        out,
    );
}

test "table join needs exactly four positional args after mode flags" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table join --left customers __pk orders\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("error: WrongArgCount\n", out);
}

test "table aggregate groups by field with count/sum/avg/min/max, matching main.zig's CLI output" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table aggregate orders city count,sum:total,avg:total,min:total,max:total
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "group=warsaw\tcount=2\tsum_total=350\tavg_total=175\tmin_total=100\tmax_total=250\n" ++
            "group=krakow\tcount=1\tsum_total=40\tavg_total=40\tmin_total=40\tmax_total=40\n",
        out,
    );
}

test "table aggregate distinct:field counts unique values, collapsing repeats within a group" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw region=mazovia
        \\table put orders i:2 city=warsaw region=mazovia
        \\table put orders i:3 city=warsaw region=innerwarsaw
        \\table put orders i:4 city=krakow region=malopolska
        \\table aggregate orders city count,distinct:region
        \\table aggregate orders * distinct:region
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\nOK\n" ++
            "group=warsaw\tcount=3\tcount_distinct_region=2\n" ++
            "group=krakow\tcount=1\tcount_distinct_region=1\n" ++
            "count_distinct_region=3\n",
        out,
    );
}

test "table aggregate with * groups nothing and honors an expr filter before aggregating" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table aggregate orders * count,sum:total
        \\table aggregate orders * count,sum:total total gt i:50
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "count=3\tsum_total=390\n" ++
            "count=2\tsum_total=350\n",
        out,
    );
}

test "table aggregate rejects an invalid spec without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table aggregate orders city bogus:total\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("error: InvalidArgument\n", out);
}

test "table window row_number annotates every row without collapsing, restarting per partition in order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table window orders row_number partition city order total
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tcity=warsaw\ttotal=100\trow_number=1\n" ++
            "__pk=2\tcity=warsaw\ttotal=250\trow_number=2\n" ++
            "__pk=3\tcity=krakow\ttotal=40\trow_number=1\n",
        out,
    );
}

test "table window with a comma-separated spec list annotates every row with all columns, sharing one partition/order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table window orders row_number,sum:total partition city order total
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tcity=warsaw\ttotal=100\trow_number=1\tsum_total=100\n" ++
            "__pk=2\tcity=warsaw\ttotal=250\trow_number=2\tsum_total=350\n" ++
            "__pk=3\tcity=krakow\ttotal=40\trow_number=1\tsum_total=40\n",
        out,
    );
}

test "table window sum:field with order runs a running total along the sorted sequence" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table window orders sum:total order total
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=3\tcity=krakow\ttotal=40\tsum_total=40\n" ++
            "__pk=1\tcity=warsaw\ttotal=100\tsum_total=140\n" ++
            "__pk=2\tcity=warsaw\ttotal=250\tsum_total=390\n",
        out,
    );
}

test "table window --range shares a tied group's combined total, without it each tied row gets its own running total" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    // Two rows tied at day=1 (10, 20), then one row at day=2 (5).
    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:1 amount=i:20
        \\table put orders i:3 day=i:2 amount=i:5
        \\table window orders sum:amount order day --range
        \\table window orders sum:amount order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            // --range: both day=1 rows share the tie group's combined total.
            "__pk=1\tday=1\tamount=10\tsum_amount=30\n" ++
            "__pk=2\tday=1\tamount=20\tsum_amount=30\n" ++
            "__pk=3\tday=2\tamount=5\tsum_amount=35\n" ++
            // default (ROWS): each physical row keeps its own running total.
            "__pk=1\tday=1\tamount=10\tsum_amount=10\n" ++
            "__pk=2\tday=1\tamount=20\tsum_amount=30\n" ++
            "__pk=3\tday=2\tamount=5\tsum_amount=35\n",
        out,
    );
}

test "table window --range is rejected together with a ranking kind, not silently ignored" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 total=i:100
        \\table window orders row_number order total --range
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: RangeNotApplicable\n", out);
}

test "table window sum:field with a partition but no order stamps the same whole-partition total on every row" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table window orders sum:total partition city
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tcity=warsaw\ttotal=100\tsum_total=350\n" ++
            "__pk=2\tcity=warsaw\ttotal=250\tsum_total=350\n" ++
            "__pk=3\tcity=krakow\ttotal=40\tsum_total=40\n",
        out,
    );
}

test "table window honors --limit/--offset in partition-then-order display order, not raw scan order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 city=warsaw total=i:100
        \\table put orders i:2 city=warsaw total=i:250
        \\table put orders i:3 city=krakow total=i:40
        \\table window orders row_number order total --offset 1 --limit 1
        \\
    );
    defer allocator.free(out);
    // Sorted by total ascending: krakow/40 (rownum 1), warsaw/100 (rownum
    // 2), warsaw/250 (rownum 3) - offset 1 limit 1 must land on the SECOND
    // entry of that sorted walk, not the second row `table put` inserted.
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tcity=warsaw\ttotal=100\trow_number=2\n",
        out,
    );
}

test "table window rejects an invalid spec without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "table window orders bogus\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("error: InvalidArgument\n", out);
}

test "table window lag/lead read the adjacent row's value within order, NULL at the partition edge" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:2 amount=i:20
        \\table put orders i:3 day=i:3 amount=i:30
        \\table window orders lag:amount,lead:amount order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tlag_amount=(none)\tlead_amount=20\n" ++
            "__pk=2\tday=2\tamount=20\tlag_amount=10\tlead_amount=30\n" ++
            "__pk=3\tday=3\tamount=30\tlag_amount=20\tlead_amount=(none)\n",
        out,
    );
}

test "table window lag with an explicit offset and a caller-supplied default instead of NULL" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:2 amount=i:20
        \\table window orders lag:amount:1:i:-1 order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tlag_amount=-1\n" ++
            "__pk=2\tday=2\tamount=20\tlag_amount=10\n",
        out,
    );
}

test "table window lag/lead --range is rejected outright, like row_number" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 amount=i:10
        \\table window orders lag:amount order amount --range
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: RangeNotApplicable\n", out);
}

test "table window first_value/last_value --range: last_value shares the current tie group's last member" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:1 amount=i:20
        \\table put orders i:3 day=i:2 amount=i:5
        \\table window orders first_value:amount,last_value:amount order day --range
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tfirst_value_amount=10\tlast_value_amount=20\n" ++
            "__pk=2\tday=1\tamount=20\tfirst_value_amount=10\tlast_value_amount=20\n" ++
            "__pk=3\tday=2\tamount=5\tfirst_value_amount=10\tlast_value_amount=5\n",
        out,
    );
}

test "table window last_value without --range degenerates to the row's own field (ROWS default)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:2 amount=i:20
        \\table window orders last_value:amount order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tlast_value_amount=10\n" ++
            "__pk=2\tday=2\tamount=20\tlast_value_amount=20\n",
        out,
    );
}

test "table window nth_value --range: position resolved against the CUMULATIVE frame, not just the current tie group" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:1 amount=i:20
        \\table put orders i:3 day=i:2 amount=i:5
        \\table window orders nth_value:amount:2 order day --range
        \\
    );
    defer allocator.free(out);
    // day=1's tie group has 2 members - position 2 is its second member (20).
    // day=2's frame is UNBOUNDED PRECEDING through its own tie group, so it
    // already includes day=1's rows too - position 2 was already resolved
    // to 20 there and stays 20, even though day=2's OWN group has just 1 row.
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tnth_value_amount=20\n" ++
            "__pk=2\tday=1\tamount=20\tnth_value_amount=20\n" ++
            "__pk=3\tday=2\tamount=5\tnth_value_amount=20\n",
        out,
    );
}

test "table window nth_value ROWS default: NULL until the frame grows to reach the requested position" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table put orders i:2 day=i:2 amount=i:20
        \\table window orders nth_value:amount:2 order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\n" ++
            "__pk=1\tday=1\tamount=10\tnth_value_amount=(none)\n" ++
            "__pk=2\tday=2\tamount=20\tnth_value_amount=20\n",
        out,
    );
}

test "table window nth_value with a caller-supplied default instead of NULL" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table window orders nth_value:amount:5:i:-1 order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\n__pk=1\tday=1\tamount=10\tnth_value_amount=-1\n",
        out,
    );
}

test "table window nth_value with no field or no position reports InvalidArgument" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 amount=i:10
        \\table window orders nth_value order day
        \\table window orders nth_value:amount order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nerror: InvalidArgument\nerror: InvalidArgument\n",
        out,
    );
}

test "table window count_distinct runs a per-row distinct total, repeats do not grow it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 day=i:1 tag=s:a
        \\table put orders i:2 day=i:2 tag=s:b
        \\table put orders i:3 day=i:3 tag=s:a
        \\table window orders count_distinct:tag order day
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "OK\nOK\nOK\n" ++
            "__pk=1\tday=1\ttag=a\tcount_distinct_tag=1\n" ++
            "__pk=2\tday=2\ttag=b\tcount_distinct_tag=2\n" ++
            "__pk=3\tday=3\ttag=a\tcount_distinct_tag=2\n",
        out,
    );
}

test "table window count_distinct with no field reports InvalidArgument, unlike bare count" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl,
        \\table put orders i:1 tag=s:a
        \\table window orders count_distinct
        \\
    );
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nerror: InvalidArgument\n", out);
}

test "unknown command and wrong arg counts report errors without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "bogus\nput onlyone\nget\nput a 1\nget a\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "error: UnknownCommand\nerror: WrongArgCount\nerror: WrongArgCount\nOK\n1\n",
        out,
    );
}

test "staged writes inside a transaction are invisible until commit, then durable" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "begin\nput bal 100\nget bal\ncommit\nget bal\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nOK\n100\nOK\n100\n", out);
}

test "get mid-transaction steers the next put, applied atomically on commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();
    try db.put("bal", "100");

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "begin\nget bal\nput bal 150\ncommit\nget bal\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\n100\nOK\nOK\n150\n", out);

    const stored = (try db.get(allocator, "bal")).?;
    defer allocator.free(stored);
    try std.testing.expectEqualStrings("150", stored);
}

test "rollback discards staged writes entirely" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "begin\nput x 1\nrollback\nget x\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nOK\nOK\n(nil)\n", out);
    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "x"));
}

test "commit/rollback without an active transaction report NoActiveTransaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "commit\nrollback\nput a 1\nget a\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings(
        "error: NoActiveTransaction\nerror: NoActiveTransaction\nOK\n1\n",
        out,
    );
}

test "double begin is rejected and leaves the first transaction usable" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "begin\nput a 1\nbegin\ncommit\nget a\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nOK\nerror: TransactionAlreadyActive\nOK\n1\n", out);
}

test "table put/get/del inside a transaction stage through TableTxn atomically across two tables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(
        allocator,
        &repl,
        "begin\n" ++
            "table put accounts 1 name=alice balance=i:100\n" ++
            "table put ledger 1 note=opening\n" ++
            "table get accounts 1\n" ++
            "commit\n" ++
            "table get accounts 1\n" ++
            "table get ledger 1\n",
    );
    defer allocator.free(out);

    var lines = std.mem.splitScalar(u8, std.mem.trimRight(u8, out, "\n"), '\n');
    try std.testing.expectEqualStrings("OK", lines.next().?);
    try std.testing.expectEqualStrings("OK", lines.next().?);
    try std.testing.expectEqualStrings("OK", lines.next().?);
    const preCommitGet = lines.next().?;
    try std.testing.expect(std.mem.indexOf(u8, preCommitGet, "name=alice") != null);
    try std.testing.expectEqualStrings("OK", lines.next().?);
    const postAccounts = lines.next().?;
    try std.testing.expect(std.mem.indexOf(u8, postAccounts, "balance=100") != null);
    const postLedger = lines.next().?;
    try std.testing.expect(std.mem.indexOf(u8, postLedger, "note=opening") != null);
    try std.testing.expectEqual(@as(?[]const u8, null), lines.next());

    var directTable = try Table.open(&db, allocator, "accounts");
    defer directTable.deinit();
    var row = (try directTable.get(.{ .text = "1" })).?;
    defer row.deinit();
    try std.testing.expectEqual(@as(i64, 100), row.get("balance").?.int);
}

test "table writes made before commit are not visible to an independent Table handle" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    var stream = std.io.fixedBufferStream("begin\ntable put accounts 1 name=alice\n");
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try repl.runFromReader(stream.reader(), out.writer(), false);
    try std.testing.expectEqualStrings("OK\nOK\n", out.items);

    var outsider = try Table.open(&db, allocator, "accounts");
    defer outsider.deinit();
    try std.testing.expectEqual(@as(?Row, null), try outsider.get(.{ .text = "1" }));

    try repl.txn.?.commit();
    repl.discardTxnState();

    var again = try Table.open(&db, allocator, "accounts");
    defer again.deinit();
    var row = (try again.get(.{ .text = "1" })).?;
    defer row.deinit();
    try std.testing.expectEqualStrings("alice", row.get("name").?.text);
}

test "table put/get/del outside a transaction autocommit immediately like plain Table" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(
        allocator,
        &repl,
        "table put widgets 7 sku=s:ABC qty=i:3\ntable get widgets 7\ntable del widgets 7\ntable get widgets 7\n",
    );
    defer allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "OK\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "sku=ABC") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "qty=3") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "(nil)\n"));
}

test "malformed field is rejected before staging, transaction stays usable" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(
        allocator,
        &repl,
        "begin\ntable put accounts 1 badfieldnoequals\ntable put accounts 1 name=bob\ncommit\ntable get accounts 1\n",
    );
    defer allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "OK\nerror: InvalidField\nOK\nOK\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "name=bob") != null);
}

test "a real external conflict surfaces error.Conflict on commit and applies nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();
    try db.put("balance", "100");

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    var stream = std.io.fixedBufferStream("begin\nget balance\n");
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try repl.runFromReader(stream.reader(), out.writer(), false);

    try db.put("balance", "external");

    var stream2 = std.io.fixedBufferStream("put balance 150\ncommit\n");
    try repl.runFromReader(stream2.reader(), out.writer(), false);
    try std.testing.expect(std.mem.endsWith(u8, out.items, "OK\nerror: Conflict\n"));

    const current = (try db.get(allocator, "balance")).?;
    defer allocator.free(current);
    try std.testing.expectEqualStrings("external", current);
    try std.testing.expect(repl.inTransaction());

    var stream3 = std.io.fixedBufferStream("rollback\n");
    try repl.runFromReader(stream3.reader(), out.writer(), false);
    try std.testing.expect(!repl.inTransaction());
}

test "scan always reflects committed Db state, not an in-flight transaction's staged writes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "put k1 v1\nbegin\nput k2 v2\nscan k\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nOK\nOK\nk1\tv1\n", out);
}

test "abandoning an open transaction on deinit frees staged writes and pending TableTxn state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    const out = try runScript(allocator, &repl, "begin\nput a 1\ntable put accounts 1 name=alice\n");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("OK\nOK\nOK\n", out);
    repl.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, "a"));
    var table = try Table.open(&db, allocator, "accounts");
    defer table.deinit();
    try std.testing.expectEqual(@as(?Row, null), try table.get(.{ .text = "1" }));
}

test "flush and compact run against the live Db and stats reflects it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "put a 1\nflush\ncompact\nstats\n");
    defer allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "OK\nOK\nOK\n"));
    try std.testing.expect(out.len > "OK\nOK\nOK\n".len);
}

test "help lists commands without touching db state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    const out = try runScript(allocator, &repl, "help\n");
    defer allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "begin / commit / rollback") != null);
}

test "prompt is written before each read only when requested" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try openTemp(&tmp, allocator);
    defer db.close();

    var repl = Repl.init(allocator, &db);
    defer repl.deinit();

    var stream = std.io.fixedBufferStream("begin\nput a 1\n");
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try repl.runFromReader(stream.reader(), out.writer(), true);
    try std.testing.expectEqualStrings("cobalt> OK\ncobalt(txn)> OK\ncobalt(txn)> ", out.items);
}

