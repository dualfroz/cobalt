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
    ServerIoError,
    ServerConflict,
    ServerRateLimited,
    ServerUnauthorized,
    ServerForbidden,
    ServerUserNotFound,
    ServerKeyNotFound,
    ServerCollectionNotFound,
    UnexpectedStatus,
};

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
        .io_error => error.ServerIoError,
        .conflict => error.ServerConflict,
        .rate_limited => error.ServerRateLimited,
        .unauthorized => error.ServerUnauthorized,
        .forbidden => error.ServerForbidden,
        else => error.UnexpectedStatus,
    };
}

pub const Client = struct {
    allocator: Allocator,
    stream: std.net.Stream,
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

    pub fn sessionToken(self: *Client) ?[]const u8 {
        return self.token;
    }

    fn roundTrip(self: *Client, op: protocol.Op, payload: []const u8) !protocol.Frame {
        try protocol.writeFrame(self.stream.writer(), @intFromEnum(op), payload);
        return protocol.readFrame(self.allocator, self.stream.reader());
    }

    pub fn authenticate(self: *Client, username: []const u8, password: []const u8) !void {
        const payload = try protocol.encodeAuth(self.allocator, username, password);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.auth, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        try self.setToken(frame.payload);
    }

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

    pub fn tableExplain(self: *Client, allocator: Allocator, table: []const u8, exprText: []const u8) !querymod.Plan {
        const payload = try protocol.encodeTableExplain(self.allocator, table, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_explain, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodePlan(allocator, frame.payload);
    }

    pub fn tableUpdate(self: *Client, table: []const u8, sets: []const rowmod.Field, exprText: []const u8) !u64 {
        const payload = try protocol.encodeTableUpdate(self.allocator, table, sets, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_update, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    pub fn tableDelete(self: *Client, table: []const u8, exprText: []const u8) !u64 {
        const payload = try protocol.encodeTableDelete(self.allocator, table, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_delete, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

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

    pub fn tableImport(self: *Client, table: []const u8, format: protocol.DumpFormat, content: []const u8) !u64 {
        const payload = try protocol.encodeTableImport(self.allocator, table, format, content);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_import, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

    pub fn tableSelect(self: *Client, allocator: Allocator, table: []const u8, exprText: []const u8, offset: u32, limit: u32, orderBy: []const querymod.OrderBy) ![]rowmod.Row {
        const payload = try protocol.encodeTableSelect(self.allocator, table, exprText, offset, limit, orderBy);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_select, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeRows(allocator, frame.payload);
    }

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

    pub fn tableAggregateGlobal(self: *Client, allocator: Allocator, table: []const u8, specs: []const aggregatemod.AggSpec, havingText: []const u8, exprText: []const u8) ![]rowmod.Value {
        const payload = try protocol.encodeTableAggregate(self.allocator, table, "", specs, 0, 0, &.{}, havingText, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_aggregate, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeAggGlobalResult(allocator, frame.payload);
    }

    pub fn tableAggregateGroups(self: *Client, allocator: Allocator, table: []const u8, groupField: []const u8, specs: []const aggregatemod.AggSpec, offset: u32, limit: u32, orderBy: []const querymod.OrderBy, havingText: []const u8, exprText: []const u8) ![]aggregatemod.GroupRow {
        const payload = try protocol.encodeTableAggregate(self.allocator, table, groupField, specs, offset, limit, orderBy, havingText, exprText);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_aggregate, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeAggGroupRows(allocator, frame.payload);
    }

    pub fn tableWindow(self: *Client, allocator: Allocator, table: []const u8, specs: []const windowmod.WindowSpec, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, offset: u32, limit: u32, exprText: []const u8, windowFrame: windowmod.FrameMode) ![]protocol.WindowRow {
        const payload = try protocol.encodeTableWindow(self.allocator, table, specs, partitionBy, orderBy, offset, limit, exprText, windowFrame);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.table_window, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeWindowRows(allocator, frame.payload);
    }

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

    pub fn unsubscribe(self: *Client, subscriberId: u64, channels: []const []const u8) !u32 {
        const payload = try protocol.encodeUnsubscribe(self.allocator, subscriberId, channels);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.unsubscribe, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeUnsubscribeResult(frame.payload);
    }

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

    pub fn publish(self: *Client, channel: []const u8, message: []const u8) !u64 {
        const payload = try protocol.encodePublish(self.allocator, channel, message);
        defer self.allocator.free(payload);
        var frame = try self.roundTrip(.publish, payload);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodePublishResult(frame.payload);
    }

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

    pub fn adminCreateUser(self: *Client, username: []const u8, password: []const u8, role: authmod.Role, rounds: u32) !void {
        var frame = try self.userAdminRoundTrip(.create, username, password, role, rounds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn adminSetPassword(self: *Client, username: []const u8, password: []const u8, rounds: u32) !void {
        var frame = try self.userAdminRoundTrip(.set_password, username, password, .readonly, rounds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

    pub fn adminSetRole(self: *Client, username: []const u8, role: authmod.Role) !void {
        var frame = try self.userAdminRoundTrip(.set_role, username, "", role, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

    pub fn adminDeleteUser(self: *Client, username: []const u8) !void {
        var frame = try self.userAdminRoundTrip(.delete, username, "", .readonly, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerUserNotFound;
        if (status != .ok) return statusToError(status);
    }

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

    pub fn ttlExpire(self: *Client, key: []const u8, seconds: u64) !void {
        var frame = try self.ttlOpRoundTrip(.expire, key, seconds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerKeyNotFound;
        if (status != .ok) return statusToError(status);
    }

    pub fn ttlPersist(self: *Client, key: []const u8) !void {
        var frame = try self.ttlOpRoundTrip(.persist, key, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn ttlQuery(self: *Client, key: []const u8) !ttlmod.TtlResult {
        var frame = try self.ttlOpRoundTrip(.query, key, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlResult(frame.payload);
    }

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

    pub fn collTtlExpire(self: *Client, kind: collmod.Kind, name: []const u8, seconds: u64) !void {
        var frame = try self.collTtlOpRoundTrip(.expire, kind, name, seconds);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status == .not_found) return error.ServerCollectionNotFound;
        if (status != .ok) return statusToError(status);
    }

    pub fn collTtlPersist(self: *Client, kind: collmod.Kind, name: []const u8) !void {
        var frame = try self.collTtlOpRoundTrip(.persist, kind, name, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
    }

    pub fn collTtlQuery(self: *Client, kind: collmod.Kind, name: []const u8) !ttlmod.TtlResult {
        var frame = try self.collTtlOpRoundTrip(.query, kind, name, 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlResult(frame.payload);
    }

    pub fn collTtlSweep(self: *Client) !u64 {
        var frame = try self.collTtlOpRoundTrip(.sweep, .counter, "", 0);
        defer frame.deinit();
        const status = try protocol.Status.fromByte(frame.tag);
        if (status != .ok) return statusToError(status);
        return protocol.decodeTtlSweepCount(frame.payload);
    }

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
