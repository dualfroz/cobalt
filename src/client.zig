const std = @import("std");
const protocol = @import("protocol.zig");
const dbmod = @import("db.zig");
const rowmod = @import("row.zig");
const authmod = @import("auth.zig");
const ttlmod = @import("ttl.zig");
const collmod = @import("collections.zig");
const aggregatemod = @import("aggregate.zig");
const windowmod = @import("window.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;

pub const ClientError = error{
    ServerBadRequest,
    ServerInternal,
    ServerConflict,
    ServerRateLimited,
    ServerUnauthorized,
    ServerForbidden,
    ServerUserNotFound,
    ServerKeyNotFound,
    ServerCollectionNotFound,
    UnexpectedStatus,
};

/// Result of a remote `table export`: the row count `dump.zig`'s exporter
/// reported plus the rendered bytes, independently allocated so they
/// outlive the response frame they arrived in.
pub const RemoteExport = struct {
    rowCount: u64,
    content: []u8,

    pub fn deinit(self: RemoteExport, allocator: Allocator) void {
        allocator.free(self.content);
    }
};

fn statusToError(status: protocol.Status) ClientError {
    return switch (status) {
        .bad_request => error.ServerBadRequest,
        .internal => error.ServerInternal,
        .conflict => error.ServerConflict,
        .rate_limited => error.ServerRateLimited,
        .unauthorized => error.ServerUnauthorized,
        .forbidden => error.ServerForbidden,
        else => error.UnexpectedStatus,
    };
}

/// A blocking client for the wire protocol in `protocol.zig`. Each call
/// writes one request frame and reads exactly one response frame, so a
/// `Client` must not be shared across threads without external locking.
pub const Client = struct {
    allocator: Allocator,
    stream: std.net.Stream,
    /// The session token from the last successful `authenticate` call, if
    /// the server had `enableSessions` on (see server.zig) - null on a
    /// server without sessions, or before any successful `authenticate`.
    /// Owned by the `Client`, freed on `close()` and on every subsequent
    /// `authenticate`/`authenticateWithToken` call.
    token: ?[]u8 = null,

    pub fn connect(allocator: Allocator, address: std.net.Address) !Client {
        const stream = try std.net.tcpConnectToAddress(address);
        return .{ .allocator = allocator, .stream = stream };
    }

    pub fn close(self: *Client) void {
        if (self.token) |t| self.allocator.free(t);
        self.stream.close();
    }

    fn setToken(self: *Client, payload: []const u8) !void {
        if (self.token) |old| self.allocator.free(old);
        self.token = if (payload.len > 0) try self.allocator.dupe(u8, payload) else null;
    }

    /// The session token captured by the last successful `authenticate`,
    /// if any (see `token` above). Callers that want to reconnect later
    /// without a password should dupe this before the `Client` closes.
    pub fn sessionToken(self: *Client) ?[]const u8 {
        return self.token;
    }

    fn roundTrip(self: *Client, op: protocol.Op, payload: []const u8) !protocol.Frame {
        try protocol.writeFrame(self.stream.writer(), @intFromEnum(op), payload);
        return protocol.readFrame(self.allocator, self.stream.reader());
    }

    /// Authenticates this connection against a server that has auth
    /// enabled (see `server.zig`'s `enableAuth`). Every request on this
    /// stream after a successful call is dispatched under the role
    /// returned by the server's `auth.Store.verify`; a server without auth
    /// enabled always answers `ok` regardless of the credentials given. If
    /// the server also has sessions enabled (`enableSessions`), the
    /// response carries a fresh token captured into `sessionToken()` -
    /// otherwise `sessionToken()` reads null afterwards, same as before
    /// this call was ever made.
    pub fn authenticate(self: *Client, username: []const u8, password: []const u8) !void {
        const payload = try protocol.encodeAuth(self.allocator, username, password);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.auth, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        try self.setToken(frame.payload);
    }

    /// Authenticates this connection using a token obtained from another
    /// connection's `sessionToken()`, instead of a username/password pair
    /// (see server.zig's `auth_token` opcode) - skips the password
    /// entirely and resumes the same role until the session expires. A
    /// server without sessions enabled accepts any token unconditionally,
    /// matching `authenticate`'s behavior against a server without auth.
    pub fn authenticateWithToken(self: *Client, token: []const u8) !void {
        const payload = try protocol.encodeAuthToken(self.allocator, token);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.auth_token, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn ping(self: *Client) !void {
        var frame = try self.roundTrip(.ping, "");
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn get(self: *Client, allocator: Allocator, key: []const u8) !?[]u8 {
        var frame = try self.roundTrip(.get, key);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        return switch (status) {
            .ok => try allocator.dupe(u8, frame.payload),
            .not_found => null,
            else => statusToError(status),
        };
    }

    pub fn set(self: *Client, key: []const u8, value: []const u8) !void {
        const payload = try protocol.encodeSet(self.allocator, key, value);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.set, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn delete(self: *Client, key: []const u8) !void {
        var frame = try self.roundTrip(.del, key);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn scan(self: *Client, allocator: Allocator, args: protocol.ScanArgs) ![]protocol.OwnedEntry {
        const payload = try protocol.encodeScan(self.allocator, args);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.scan, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeEntries(allocator, frame.payload);
    }

    pub fn prefix(self: *Client, allocator: Allocator, prefixBytes: []const u8, limit: u32) ![]protocol.OwnedEntry {
        const payload = try protocol.encodePrefix(self.allocator, prefixBytes, limit);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.prefix, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeEntries(allocator, frame.payload);
    }

    pub fn stats(self: *Client) !dbmod.Stats {
        var frame = try self.roundTrip(.stats, "");
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeStats(frame.payload);
    }

    /// Fetches the server's combined Prometheus text export (its own
    /// request/rate-limit/auth/session counters from `Server.registerMetrics`
    /// plus `Db.stats()`, in the one payload `Server.handleMetrics` builds) -
    /// the network counterpart of the CLI's local-only `stats --prom`.
    /// Returned text is independently owned; free with `allocator.free`.
    pub fn metricsText(self: *Client, allocator: Allocator) ![]u8 {
        var frame = try self.roundTrip(.metrics, "");
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return allocator.dupe(u8, frame.payload);
    }

    pub fn flush(self: *Client) !void {
        var frame = try self.roundTrip(.flush, "");
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn compact(self: *Client) !void {
        var frame = try self.roundTrip(.compact, "");
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn batch(self: *Client, ops: []const protocol.BatchOp) !void {
        const payload = try protocol.encodeBatch(self.allocator, ops);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.batch, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    /// Remote `table explain`: the wire counterpart of the CLI's local
    /// `table explain`, reporting which strategy `query.Table.explain`
    /// says a matching `tableSelect` would take against the server's
    /// `*Db`, without running the query. `exprText` is the same `expr.zig`
    /// grammar as `tableSelect`'s (empty means no predicate, i.e. always a
    /// full scan). Returned `Plan` owns its `indexName` - free with
    /// `Plan.deinit`.
    pub fn tableExplain(self: *Client, allocator: Allocator, table: []const u8, exprText: []const u8) !querymod.Plan {
        const payload = try protocol.encodeTableExplain(self.allocator, table, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_explain, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodePlan(allocator, frame.payload);
    }

    /// Remote `table update`: the wire counterpart of the CLI's local
    /// `table update`, applying `sets` to every row matching `exprText`
    /// (empty means every row, the same convention `tableSelect`/
    /// `tableExplain` use) against the server's `*Db` via
    /// `query.Table.updateWhere`. Returns the number of rows updated.
    pub fn tableUpdate(self: *Client, table: []const u8, sets: []const rowmod.Field, exprText: []const u8) !u64 {
        const payload = try protocol.encodeTableUpdate(self.allocator, table, sets, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_update, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    /// Remote `table delete`: the wire counterpart of the CLI's local
    /// `table delete`, removing every row matching `exprText` (empty means
    /// every row, the same convention `tableUpdate`/`tableExplain` use)
    /// against the server's `*Db` via `query.Table.deleteWhere`. Returns the
    /// number of rows deleted.
    pub fn tableDelete(self: *Client, table: []const u8, exprText: []const u8) !u64 {
        const payload = try protocol.encodeTableDelete(self.allocator, table, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_delete, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    /// Remote `table export`: the wire counterpart of the CLI's local
    /// `table export <table> csv|json <path>`, rendering the whole table on
    /// the server and returning both the row count and the rendered bytes
    /// in one round trip. `content` is a fresh allocation independent of
    /// the response frame - free it with `RemoteExport.deinit`.
    pub fn tableExport(self: *Client, allocator: Allocator, table: []const u8, format: protocol.DumpFormat) !RemoteExport {
        const payload = try protocol.encodeTableExport(self.allocator, table, format);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_export, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        const result = try protocol.decodeExportResult(frame.payload);
        const content = try allocator.dupe(u8, result.content);
        return .{ .rowCount = result.rowCount, .content = content };
    }

    /// Remote `table import`: the wire counterpart of the CLI's local
    /// `table import <table> csv|json <path>`. `content` is data the
    /// caller already read into memory (e.g. from a local file) and sends
    /// to the server in one frame; the server runs it through `dump.zig`'s
    /// importer there. Returns the number of rows imported.
    pub fn tableImport(self: *Client, table: []const u8, format: protocol.DumpFormat, content: []const u8) !u64 {
        const payload = try protocol.encodeTableImport(self.allocator, table, format, content);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_import, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    /// Remote `table select`: `exprText` is the same `expr.zig` predicate
    /// grammar the local CLI's `table select` accepts (empty selects every
    /// row). `offset`/`limit` page the result the same way
    /// `query.Table.selectPage` does locally (0 limit = unlimited), so a
    /// large remote result does not have to come back in a single frame.
    /// `orderBy`, when non-empty, sorts server-side via
    /// `Table.selectPageOrdered` before that page window applies (one or
    /// more columns applied left to right, ties on earlier columns broken
    /// by later ones) - the network counterpart of the local CLI's `table
    /// select --order-by`. Returned rows are independently owned - free
    /// with `protocol.freeRows`.
    pub fn tableSelect(self: *Client, allocator: Allocator, table: []const u8, exprText: []const u8, offset: u32, limit: u32, orderBy: []const querymod.OrderBy) ![]rowmod.Row {
        const payload = try protocol.encodeTableSelect(self.allocator, table, exprText, offset, limit, orderBy);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_select, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeRows(allocator, frame.payload);
    }

    /// Remote `table join`: the wire counterpart of the CLI's local `table
    /// join [--left|--right|--full]`, running whichever of `join.zig`'s four
    /// equi-join variants `mode` names against the server's `*Db` instead of
    /// a locally opened one. `leftExprText`/`rightExprText` are the same
    /// `expr.zig` predicate grammar as `tableSelect`'s `exprText` (empty
    /// selects every row on that side), filtering each table before the
    /// join runs - the network counterpart of `innerJoin`'s
    /// `leftPred`/`rightPred` parameters. `offset`/`limit` window the
    /// already-joined result server-side (0/0 = unlimited), the same
    /// convention `tableSelect` uses, via `join.applyPage`. Returned pairs
    /// are independently owned - free with `protocol.freeJoinPairs`.
    pub fn tableJoin(
        self: *Client,
        allocator: Allocator,
        mode: protocol.JoinMode,
        leftTable: []const u8,
        leftField: []const u8,
        rightTable: []const u8,
        rightField: []const u8,
        offset: u32,
        limit: u32,
        leftExprText: []const u8,
        rightExprText: []const u8,
    ) ![]protocol.JoinPair {
        const payload = try protocol.encodeTableJoin(self.allocator, mode, leftTable, leftField, rightTable, rightField, offset, limit, leftExprText, rightExprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_join, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeJoinedRows(allocator, frame.payload);
    }

    /// Remote `table aggregate <table> * <specs> [expr...]` (no `GROUP BY`):
    /// the wire counterpart of the CLI's local `table aggregate` with a `*`
    /// group field, calling `aggregate.runGlobal` server-side over rows
    /// filtered by `exprText` (same `expr.zig` grammar, empty selects every
    /// row, as `tableSelect`). `havingText` (empty = no HAVING) filters the
    /// single result server-side via `aggregate.globalMatchesHaving` -
    /// returns zero values (not an error) when it excludes the only row.
    /// Otherwise always returns exactly `specs.len` values in the same order
    /// as `specs` - free with `protocol.freeAggValues`.
    pub fn tableAggregateGlobal(self: *Client, allocator: Allocator, table: []const u8, specs: []const aggregatemod.AggSpec, havingText: []const u8, exprText: []const u8) ![]rowmod.Value {
        const payload = try protocol.encodeTableAggregate(self.allocator, table, "", specs, 0, 0, &.{}, havingText, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_aggregate, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeAggGlobalResult(allocator, frame.payload);
    }

    /// Remote `table aggregate <table> <groupField> <specs> [expr...]
    /// [having <expr>] [--limit N] [--offset N]`: the wire counterpart of
    /// the CLI's local `table aggregate` with a real GROUP BY field, calling
    /// `aggregate.run` server-side, then (when `havingText` is non-empty)
    /// `aggregate.filterHaving` to narrow the groups, then windowing what
    /// remains server-side with `aggregate.applyPageGroups` (0/0 =
    /// unlimited, the same convention `tableJoin`'s `offset`/`limit` use -
    /// HAVING always runs before the window, same as SQL). `orderBy`
    /// (possibly empty) sorts the HAVING-narrowed groups server-side via
    /// `aggregate.sortGroupsBy` before that window, the same
    /// HAVING-then-ORDER-BY-then-LIMIT clause order SQL evaluates - each
    /// `orderBy[i].field` must name either `groupField` or one of `specs`'
    /// result labels (see `aggregate.specLabel`). One `GroupRow` per
    /// distinct group value kept by HAVING and the window, in `orderBy`
    /// order when non-empty, otherwise first-seen order (not sorted), same
    /// as the local library call - free with `protocol.freeAggGroupRows`.
    pub fn tableAggregateGroups(self: *Client, allocator: Allocator, table: []const u8, groupField: []const u8, specs: []const aggregatemod.AggSpec, offset: u32, limit: u32, orderBy: []const querymod.OrderBy, havingText: []const u8, exprText: []const u8) ![]aggregatemod.GroupRow {
        const payload = try protocol.encodeTableAggregate(self.allocator, table, groupField, specs, offset, limit, orderBy, havingText, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_aggregate, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeAggGroupRows(allocator, frame.payload);
    }

    /// Remote `table window <table> <kind[:field]> [expr...] [partition
    /// <field>[,field...]] [order <field[:desc]>[,field...]] [--limit N]
    /// [--offset N]`: the wire counterpart of the CLI's local `table
    /// window`, calling `window.compute` server-side over rows filtered by
    /// `exprText` (same `expr.zig` grammar, empty selects every row).
    /// Unlike `tableAggregateGroups`, this never collapses rows - every
    /// matching row keeps its own `protocol.WindowRow` - but `offset`/`limit`
    /// still window WHICH rows come back, walked in the same
    /// partition-then-order display sequence `window.orderedIndices`
    /// produces server-side (0/0 means unlimited, same convention as every
    /// other paginated opcode). Returns one `WindowRow` per surviving row, in
    /// that display order - free with `protocol.freeWindowRows`.
    pub fn tableWindow(self: *Client, allocator: Allocator, table: []const u8, specs: []const windowmod.WindowSpec, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, offset: u32, limit: u32, exprText: []const u8, windowFrame: windowmod.FrameMode) ![]protocol.WindowRow {
        const payload = try protocol.encodeTableWindow(self.allocator, table, specs, partitionBy, orderBy, offset, limit, exprText, windowFrame);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_window, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeWindowRows(allocator, frame.payload);
    }

    /// Remote `subscribe <channel>[,channel...]`: registers this connection
    /// with the server's `pubsub.Hub` and blocks until the server's ack
    /// frame comes back, so a `publish` issued on a different connection
    /// right after this returns is guaranteed to reach this subscription -
    /// see `server.zig`'s `handleSubscribe` doc comment for why the ack
    /// exists at all. After this call, `self` must only ever be used with
    /// `nextMessage` - the server never answers another request opcode on
    /// this same connection again (a real, documented protocol
    /// simplification, not an oversight: see `handleSubscribe`'s doc
    /// comment on why a subscribed connection is receive-only). Returns the
    /// `pubsub.Hub`-assigned subscriber id, the only handle a later
    /// `unsubscribe` call - necessarily made through a DIFFERENT `Client`,
    /// since this one can never send another request - can use to name this
    /// subscription.
    pub fn subscribe(self: *Client, channels: []const []const u8) !u64 {
        const payload = try protocol.encodeSubscribe(self.allocator, channels);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.subscribe, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        const ack = try protocol.decodeSubscribeAck(frame.payload);
        return ack.subscriberId;
    }

    /// Remote `unsubscribe <subscriber-id> <channel>[,channel...]`: the
    /// client-side counterpart of `server.zig`'s `unsubscribe` opcode. Sent
    /// over an ordinary connection (this one may be reused for other
    /// requests afterward, unlike the subscribe connection it targets) to
    /// drop a subset of `subscriberId`'s channels - or, if it names every
    /// channel that subscriber still has left, to end it outright (see
    /// `pubsub.Hub.unsubscribe`'s doc comment). Returns how many of
    /// `channels` were actually removed.
    pub fn unsubscribe(self: *Client, subscriberId: u64, channels: []const []const u8) !u32 {
        const payload = try protocol.encodeUnsubscribe(self.allocator, subscriberId, channels);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.unsubscribe, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeUnsubscribeResult(frame.payload);
    }

    /// Reads the next pushed message on a connection that already called
    /// `subscribe`, or `null` once the server closes the connection (the
    /// same "no more frames coming" signal `roundTrip` treats as an error
    /// everywhere else, but is the routine end of a subscription here).
    /// Blocks indefinitely otherwise - there is no polling variant, exactly
    /// like `Subscriber.waitMessage` server-side. Returns an independently
    /// owned `protocol.PubSubMessage` - free with its own `deinit`.
    pub fn nextMessage(self: *Client, allocator: Allocator) !?protocol.PubSubMessage {
        var frame = protocol.readFrame(self.allocator, self.stream.reader()) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return err,
        };
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return try protocol.decodePubSubMessage(allocator, frame.payload);
    }

    /// Remote `publish <channel> <message>`: delivers `message` to every
    /// subscriber currently registered on `channel` across every connection
    /// the server has, returning how many subscribers it reached (0 is a
    /// normal outcome for a channel nobody is listening to, not an error -
    /// see `pubsub.Hub.publish`'s doc comment). Any connection may publish,
    /// whether or not it has ever subscribed to anything itself.
    pub fn publish(self: *Client, channel: []const u8, message: []const u8) !u64 {
        const payload = try protocol.encodePublish(self.allocator, channel, message);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.publish, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodePublishResult(frame.payload);
    }

    /// Remote `txn <script>`: applies every entry in `entries` as one atomic
    /// `Transaction` commit across however many tables they touch - the wire
    /// counterpart of the CLI's local `txn <script-file>` (main.zig's
    /// `runTxn`). Returns the number of operations committed, always
    /// `entries.len` on success since a partial commit is impossible; a
    /// conflicting transaction surfaces as `error.ServerConflict` with
    /// nothing applied, matching `error.Conflict` from a local `Transaction.
    /// commit()`.
    pub fn txnOp(self: *Client, entries: []const protocol.TxnOpEntry) !u32 {
        const payload = try protocol.encodeTxnOp(self.allocator, entries);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.txn_op, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTxnResult(frame.payload);
    }

    fn userAdminRoundTrip(self: *Client, action: protocol.UserAdminAction, username: []const u8, password: []const u8, role: authmod.Role, rounds: u32) !protocol.Frame {
        const payload = try protocol.encodeUserAdmin(self.allocator, action, username, password, role, rounds);
        defer self.allocator.free(payload);
        return self.roundTrip(.user_admin, payload);
    }

    /// The wire counterpart of `auth.Store.createUser`, gated server-side
    /// behind `admin` role whenever the server has auth enabled (see
    /// `server.zig`'s `requiredRole`). `rounds` of 0 asks the server to use
    /// its own `auth.recommendedRounds` default.
    pub fn adminCreateUser(self: *Client, username: []const u8, password: []const u8, role: authmod.Role, rounds: u32) !void {
        var frame = try self.userAdminRoundTrip(.create, username, password, role, rounds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `auth.Store.setPassword`. Reports
    /// `error.ServerUserNotFound` (not the generic `UnexpectedStatus`) when
    /// the account does not exist, since that is a normal, expected outcome
    /// worth distinguishing from every other non-ok status.
    pub fn adminSetPassword(self: *Client, username: []const u8, password: []const u8, rounds: u32) !void {
        var frame = try self.userAdminRoundTrip(.set_password, username, password, .readonly, rounds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `auth.Store.setRole`.
    pub fn adminSetRole(self: *Client, username: []const u8, role: authmod.Role) !void {
        var frame = try self.userAdminRoundTrip(.set_role, username, "", role, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `auth.Store.deleteUser`.
    pub fn adminDeleteUser(self: *Client, username: []const u8) !void {
        var frame = try self.userAdminRoundTrip(.delete, username, "", .readonly, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `auth.Store.listUsers`. Returned entries are
    /// independently owned - free with `authmod.freeUserList`.
    pub fn adminListUsers(self: *Client, allocator: Allocator) ![]authmod.UserInfo {
        var frame = try self.userAdminRoundTrip(.list, "", "", .readonly, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeUserList(allocator, frame.payload);
    }

    fn ttlOpRoundTrip(self: *Client, action: protocol.TtlAction, key: []const u8, seconds: u64) !protocol.Frame {
        const payload = try protocol.encodeTtlOp(self.allocator, action, key, seconds);
        defer self.allocator.free(payload);
        return self.roundTrip(.ttl_op, payload);
    }

    /// The wire counterpart of `ttl.setExpireSeconds`, gated server-side the
    /// same way the CLI's local `expire` is: `error.ServerKeyNotFound` (not
    /// the generic `UnexpectedStatus`) when `key` does not currently exist,
    /// since that is a normal, expected outcome worth distinguishing from
    /// every other non-ok status - matching `adminSetPassword`'s treatment
    /// of an unknown username.
    pub fn ttlExpire(self: *Client, key: []const u8, seconds: u64) !void {
        var frame = try self.ttlOpRoundTrip(.expire, key, seconds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerKeyNotFound;
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `ttl.clearExpire`.
    pub fn ttlPersist(self: *Client, key: []const u8) !void {
        var frame = try self.ttlOpRoundTrip(.persist, key, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `ttl.remaining`.
    pub fn ttlQuery(self: *Client, key: []const u8) !ttlmod.TtlResult {
        var frame = try self.ttlOpRoundTrip(.query, key, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlResult(frame.payload);
    }

    /// The wire counterpart of `ttl.sweepExpired`: reaps every due key on
    /// the server and reports how many were removed.
    pub fn ttlSweep(self: *Client) !u64 {
        var frame = try self.ttlOpRoundTrip(.sweep, "", 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    fn collTtlOpRoundTrip(self: *Client, action: protocol.TtlAction, kind: collmod.Kind, name: []const u8, seconds: u64) !protocol.Frame {
        const payload = try protocol.encodeCollTtlOp(self.allocator, action, kind, name, seconds);
        defer self.allocator.free(payload);
        return self.roundTrip(.coll_ttl_op, payload);
    }

    /// The wire counterpart of `collttl.setExpireSeconds`, gated server-side
    /// the same way the CLI's local `coll <kind> expire` is:
    /// `error.ServerCollectionNotFound` (not the generic `UnexpectedStatus`)
    /// when the collection does not currently exist, matching `ttlExpire`'s
    /// treatment of an unknown flat key.
    pub fn collTtlExpire(self: *Client, kind: collmod.Kind, name: []const u8, seconds: u64) !void {
        var frame = try self.collTtlOpRoundTrip(.expire, kind, name, seconds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerCollectionNotFound;
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `collttl.clearExpire`.
    pub fn collTtlPersist(self: *Client, kind: collmod.Kind, name: []const u8) !void {
        var frame = try self.collTtlOpRoundTrip(.persist, kind, name, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    /// The wire counterpart of `collttl.remaining`.
    pub fn collTtlQuery(self: *Client, kind: collmod.Kind, name: []const u8) !ttlmod.TtlResult {
        var frame = try self.collTtlOpRoundTrip(.query, kind, name, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlResult(frame.payload);
    }

    /// The wire counterpart of `collttl.sweepExpired`: reaps every due
    /// collection of every kind on the server and reports how many were
    /// removed. The `kind` argument to `collTtlOpRoundTrip` is a
    /// placeholder here (see `protocol.encodeCollTtlOp`'s doc comment) -
    /// `.counter` is chosen arbitrarily, same convention as `ttlSweep`
    /// passing an empty key.
    pub fn collTtlSweep(self: *Client) !u64 {
        var frame = try self.collTtlOpRoundTrip(.sweep, .counter, "", 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    /// The wire counterpart of `main.zig`'s local `coll <kind> <op> ...`
    /// (backed by `collections.zig`) - one generic round trip for every
    /// `protocol.CollAction`, mirroring that opcode's own "one opcode, many
    /// actions" shape rather than exposing thirty near-identical wrapper
    /// methods here. `args` are the same CLI-text-form string arguments
    /// (values/members/indices/scores) `runColl` already parses locally, so
    /// the server decodes exactly the same numbers with exactly the same
    /// `std.fmt.parseInt`/`parseFloat` calls the local command uses. Unlike
    /// `collTtlExpire`, a missing hash field/list element/zset member is not
    /// an error here - it comes back as `OwnedCollReply.nil`, exactly like
    /// the local CLI prints `(nil)` rather than failing. Returned reply is
    /// independently owned; free with `reply.deinit(allocator)`.
    pub fn collOp(self: *Client, allocator: Allocator, action: protocol.CollAction, name: []const u8, args: []const []const u8) !protocol.OwnedCollReply {
        const payload = try protocol.encodeCollOp(self.allocator, action, name, args);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.coll_op, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeCollReply(allocator, frame.payload);
    }
};

test "statusToError maps every non-ok status to a distinct error" {
    try std.testing.expectEqual(error.ServerBadRequest, statusToError(.bad_request));
    try std.testing.expectEqual(error.ServerInternal, statusToError(.internal));
    try std.testing.expectEqual(error.ServerConflict, statusToError(.conflict));
    try std.testing.expectEqual(error.ServerRateLimited, statusToError(.rate_limited));
    try std.testing.expectEqual(error.ServerUnauthorized, statusToError(.unauthorized));
    try std.testing.expectEqual(error.ServerForbidden, statusToError(.forbidden));
    try std.testing.expectEqual(error.UnexpectedStatus, statusToError(.not_found));
}
