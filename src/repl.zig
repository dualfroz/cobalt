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

