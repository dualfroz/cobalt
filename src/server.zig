const std = @import("std");
const protocol = @import("protocol.zig");
const dbmod = @import("db.zig");
const metrics = @import("metrics.zig");
const querymod = @import("query.zig");
const exprmod = @import("expr.zig");
const authmod = @import("auth.zig");
const sessionmod = @import("session.zig");
const ttlmod = @import("ttl.zig");
const collmod = @import("collections.zig");
const collttlmod = @import("collttl.zig");
const rowmod = @import("row.zig");
const txnmod = @import("txn.zig");
const txntablemod = @import("txn_table.zig");
const joinmod = @import("join.zig");
const aggregatemod = @import("aggregate.zig");
const windowmod = @import("window.zig");
const dumpmod = @import("dump.zig");
const pubsubmod = @import("pubsub.zig");
const keyspace = @import("keyspace.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;

pub fn storageStatus(err: anyerror) protocol.Status {
    return switch (err) {
        error.InputOutput,
        error.NoSpaceLeft,
        error.DiskQuota,
        error.ReadOnlyFileSystem,
        error.AccessDenied,
        error.FileTooBig,
        error.FileNotFound,
        error.IsDir,
        error.NotOpenForWriting,
        error.NotOpenForReading,
        error.Unseekable,
        error.DeviceBusy,
        error.NoDevice,
        error.LockViolation,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.CorruptBlock,
        error.CorruptSstable,
        => .io_error,
        else => .internal,
    };
}

fn requiredRole(op: protocol.Op, payload: []const u8) authmod.Role {
    return switch (op) {
        .ping, .auth, .auth_token => .readonly,
        .get, .scan, .prefix, .stats, .table_select, .table_join, .table_aggregate, .table_window, .table_explain, .table_export, .metrics => .readonly,
        .set, .del, .batch, .flush, .compact, .table_update, .table_delete, .table_import => .readwrite,
        .user_admin => .admin,
        .ttl_op => if (payload.len > 0 and payload[0] == @intFromEnum(protocol.TtlAction.query))
            .readonly
        else
            .readwrite,
        .coll_ttl_op => if (payload.len > 0 and payload[0] == @intFromEnum(protocol.TtlAction.query))
            .readonly
        else
            .readwrite,
        .coll_op => if (payload.len > 0)
            (if ((protocol.CollAction.fromByte(payload[0]) catch null)) |a|
                (if (a.isReadOnly()) authmod.Role.readonly else .readwrite)
            else
                .readwrite)
        else
            .readwrite,
        .txn_op => .readwrite,
        .subscribe, .publish, .unsubscribe => .readonly,
    };
}

const PerConnLimitConfig = struct {
    capacity: f64,
    refillPerSecond: f64,
};

pub const Server = struct {
    allocator: Allocator,
    db: *Db,
    mutex: std.Thread.Mutex = .{},
    net: std.net.Server,
    acceptThread: ?std.Thread = null,
    active: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    limiter: ?metrics.TokenBucket = null,
    perConnLimit: ?PerConnLimitConfig = null,
    requestsTotal: metrics.MetricCounter = .{},
    rateLimitedTotal: metrics.MetricCounter = .{},
    connRateLimitedTotal: metrics.MetricCounter = .{},
    authStore: ?authmod.Store = null,
    unauthorizedTotal: metrics.MetricCounter = .{},
    forbiddenTotal: metrics.MetricCounter = .{},
    sessions: ?*sessionmod.SessionStore = null,
    sessionTtlNanos: i128 = 0,
    sessionExpiredTotal: metrics.MetricCounter = .{},
    sweepIntervalNanos: u64 = 0,
    sweeperThread: ?std.Thread = null,
    sessionsSweptTotal: metrics.MetricCounter = .{},
    ttlSweepIntervalNanos: u64 = 0,
    ttlSweeperThread: ?std.Thread = null,
    ttlSweptTotal: metrics.MetricCounter = .{},
    collTtlSweepIntervalNanos: u64 = 0,
    collTtlSweeperThread: ?std.Thread = null,
    collTtlSweptTotal: metrics.MetricCounter = .{},
    pubsub: pubsubmod.Hub = undefined,
    messagesPublishedTotal: metrics.MetricCounter = .{},

    pub fn init(allocator: Allocator, db: *Db, address: std.net.Address) !Server {
        const net = try address.listen(.{ .reuse_address = true });
        return .{ .allocator = allocator, .db = db, .net = net, .pubsub = pubsubmod.Hub.init(allocator) };
    }

    pub fn boundAddress(self: *Server) std.net.Address {
        return self.net.listen_address;
    }

    pub fn activeConnections(self: *Server) usize {
        return self.active.load(.acquire);
    }

    pub fn enableRateLimit(self: *Server, capacity: f64, refillPerSecond: f64) void {
        self.limiter = metrics.TokenBucket.init(capacity, refillPerSecond, @intCast(std.time.nanoTimestamp()));
    }

    pub fn enablePerConnectionRateLimit(self: *Server, capacity: f64, refillPerSecond: f64) void {
        self.perConnLimit = .{ .capacity = capacity, .refillPerSecond = refillPerSecond };
    }

    pub fn enableAuth(self: *Server, store: authmod.Store) void {
        self.authStore = store;
    }

    pub fn enableSessions(self: *Server, store: *sessionmod.SessionStore, ttlNanos: i128) void {
        self.sessions = store;
        self.sessionTtlNanos = ttlNanos;
    }

    pub fn enableSessionSweep(self: *Server, intervalNanos: u64) void {
        self.sweepIntervalNanos = intervalNanos;
    }

    pub fn enableTtlSweep(self: *Server, intervalNanos: u64) void {
        self.ttlSweepIntervalNanos = intervalNanos;
    }

    pub fn enableCollTtlSweep(self: *Server, intervalNanos: u64) void {
        self.collTtlSweepIntervalNanos = intervalNanos;
    }

    pub fn registerMetrics(self: *Server, reg: *metrics.Registry) !void {
        try reg.registerCounter("cobalt_server_requests_total", &self.requestsTotal);
        try reg.registerCounter("cobalt_server_rate_limited_total", &self.rateLimitedTotal);
        try reg.registerCounter("cobalt_server_conn_rate_limited_total", &self.connRateLimitedTotal);
        try reg.registerCounter("cobalt_server_unauthorized_total", &self.unauthorizedTotal);
        try reg.registerCounter("cobalt_server_forbidden_total", &self.forbiddenTotal);
        try reg.registerCounter("cobalt_server_session_expired_total", &self.sessionExpiredTotal);
        try reg.registerCounter("cobalt_server_sessions_swept_total", &self.sessionsSweptTotal);
        try reg.registerCounter("cobalt_server_ttl_swept_total", &self.ttlSweptTotal);
        try reg.registerCounter("cobalt_server_coll_ttl_swept_total", &self.collTtlSweptTotal);
        try reg.registerCounter("cobalt_server_messages_published_total", &self.messagesPublishedTotal);
    }

    pub fn start(self: *Server) !void {
        self.acceptThread = try std.Thread.spawn(.{}, acceptLoop, .{self});
        if (self.sessions != null and self.sweepIntervalNanos > 0) {
            self.sweeperThread = try std.Thread.spawn(.{}, sweepLoop, .{self});
        }
        if (self.ttlSweepIntervalNanos > 0) {
            self.ttlSweeperThread = try std.Thread.spawn(.{}, ttlSweepLoop, .{self});
        }
        if (self.collTtlSweepIntervalNanos > 0) {
            self.collTtlSweeperThread = try std.Thread.spawn(.{}, collTtlSweepLoop, .{self});
        }
    }

    pub fn wait(self: *Server) void {
        if (self.acceptThread) |t| t.join();
    }

    fn sweepLoop(self: *Server) void {
        const store = self.sessions orelse return;
        while (!self.stopping.load(.acquire)) {
            std.time.sleep(self.sweepIntervalNanos);
            if (self.stopping.load(.acquire)) return;
            const dropped = store.sweepExpired(std.time.nanoTimestamp());
            if (dropped > 0) self.sessionsSweptTotal.incrBy(@intCast(dropped));
        }
    }

    fn ttlSweepLoop(self: *Server) void {
        while (!self.stopping.load(.acquire)) {
            std.time.sleep(self.ttlSweepIntervalNanos);
            if (self.stopping.load(.acquire)) return;
            self.mutex.lock();
            const reaped = ttlmod.sweepExpired(self.db, self.allocator, std.time.nanoTimestamp()) catch {
                self.mutex.unlock();
                continue;
            };
            self.mutex.unlock();
            if (reaped > 0) self.ttlSweptTotal.incrBy(@intCast(reaped));
        }
    }

    fn collTtlSweepLoop(self: *Server) void {
        while (!self.stopping.load(.acquire)) {
            std.time.sleep(self.collTtlSweepIntervalNanos);
            if (self.stopping.load(.acquire)) return;
            self.mutex.lock();
            const reaped = collttlmod.sweepExpired(self.db, self.allocator, std.time.nanoTimestamp()) catch {
                self.mutex.unlock();
                continue;
            };
            self.mutex.unlock();
            if (reaped > 0) self.collTtlSweptTotal.incrBy(@intCast(reaped));
        }
    }

    fn acceptLoop(self: *Server) void {
        while (true) {
            const conn = self.net.accept() catch return;
            if (self.stopping.load(.acquire)) {
                conn.stream.close();
                return;
            }
            _ = self.active.fetchAdd(1, .acq_rel);
            const t = std.Thread.spawn(.{}, handleConnection, .{ self, conn }) catch {
                _ = self.active.fetchSub(1, .acq_rel);
                conn.stream.close();
                continue;
            };
            t.detach();
        }
    }

    fn handleConnection(self: *Server, conn: std.net.Server.Connection) void {
        defer conn.stream.close();
        defer _ = self.active.fetchSub(1, .acq_rel);
        var stream = conn.stream;

        var connLimiter: ?metrics.TokenBucket = if (self.perConnLimit) |cfg|
            metrics.TokenBucket.init(cfg.capacity, cfg.refillPerSecond, @intCast(std.time.nanoTimestamp()))
        else
            null;

        var connRole: ?authmod.Role = null;

        var connExpiresAtNanos: ?i128 = null;

        while (true) {
            var frame = protocol.readFrame(self.allocator, stream.reader()) catch return;
            defer frame.deinit();
            const limPtr: ?*metrics.TokenBucket = if (connLimiter) |*cl| cl else null;
            self.dispatch(&frame, stream, stream.writer(), limPtr, &connRole, &connExpiresAtNanos) catch return;
        }
    }

    fn writeErr(writer: anytype, status: protocol.Status, message: []const u8) !void {
        try protocol.writeFrame(writer, @intFromEnum(status), message);
    }

    fn writeStorageErr(writer: anytype, err: anyerror) !void {
        try protocol.writeFrame(writer, @intFromEnum(storageStatus(err)), @errorName(err));
    }

    fn writeReservedKey(writer: anytype) !void {
        try writeErr(writer, .bad_request, "key is in the reserved internal namespace (first byte 0xF5-0xFF)");
    }

    fn dispatch(self: *Server, frame: *protocol.Frame, stream: std.net.Stream, writer: anytype, connLimiter: ?*metrics.TokenBucket, connRole: *?authmod.Role, connExpiresAtNanos: *?i128) !void {
        self.requestsTotal.incr();
        if (connLimiter) |cl| {
            if (!cl.tryAcquireNow(1)) {
                self.connRateLimitedTotal.incr();
                return writeErr(writer, .rate_limited, "per-connection rate limit exceeded");
            }
        }
        if (self.limiter) |*lim| {
            if (!lim.tryAcquireNow(1)) {
                self.rateLimitedTotal.incr();
                return writeErr(writer, .rate_limited, "rate limit exceeded");
            }
        }

        const op = protocol.Op.fromByte(frame.tag) catch {
            return writeErr(writer, .bad_request, "unknown opcode");
        };

        if (self.authStore) |store| {
            if (op == .auth) return self.handleAuth(store, frame.payload, writer, connRole, connExpiresAtNanos);
            if (op == .auth_token) return self.handleAuthToken(frame.payload, writer, connRole, connExpiresAtNanos);
            if (op != .ping) {
                const role = connRole.* orelse {
                    self.unauthorizedTotal.incr();
                    return writeErr(writer, .unauthorized, "authentication required");
                };
                if (connExpiresAtNanos.*) |expiresAt| {
                    if (std.time.nanoTimestamp() >= expiresAt) {
                        connRole.* = null;
                        connExpiresAtNanos.* = null;
                        self.sessionExpiredTotal.incr();
                        self.unauthorizedTotal.incr();
                        return writeErr(writer, .unauthorized, "session expired");
                    }
                }
                if (!role.atLeast(requiredRole(op, frame.payload))) {
                    self.forbiddenTotal.incr();
                    return writeErr(writer, .forbidden, "insufficient role for this operation");
                }
            }
        }

        if (op == .subscribe) return self.handleSubscribe(frame.payload, stream);
        if (op == .publish) return self.handlePublish(frame.payload, writer);
        if (op == .unsubscribe) return self.handleUnsubscribe(frame.payload, writer);

        self.mutex.lock();
        defer self.mutex.unlock();

        switch (op) {
            .ping => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "PONG"),

            .auth => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), ""),

            .auth_token => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), ""),

            .get => {
                if (keyspace.isInternal(frame.payload)) return writeReservedKey(writer);
                const value = ttlmod.getLive(self.db, self.allocator, frame.payload, std.time.nanoTimestamp()) catch |err| {
                    return writeStorageErr(writer, err);
                };
                if (value) |v| {
                    defer self.allocator.free(v);
                    try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), v);
                } else {
                    try protocol.writeFrame(writer, @intFromEnum(protocol.Status.not_found), "");
                }
            },

            .set => {
                const args = protocol.decodeSet(frame.payload) catch {
                    return writeErr(writer, .bad_request, "malformed set payload");
                };
                if (keyspace.isInternal(args.key)) return writeReservedKey(writer);
                ttlmod.putPersistent(self.db, self.allocator, args.key, args.value) catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .del => {
                if (keyspace.isInternal(frame.payload)) return writeReservedKey(writer);
                ttlmod.deleteKey(self.db, self.allocator, frame.payload) catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .scan => try self.handleScan(frame.payload, writer),
            .prefix => try self.handlePrefix(frame.payload, writer),

            .stats => {
                const s = self.db.stats();
                const payload = protocol.encodeStats(self.allocator, s) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(payload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), payload);
            },

            .flush => {
                self.db.flush() catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .compact => {
                self.db.compact() catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .batch => try self.handleBatch(frame.payload, writer),

            .table_select => try self.handleTableSelect(frame.payload, writer),

            .table_join => try self.handleTableJoin(frame.payload, writer),

            .table_aggregate => try self.handleTableAggregate(frame.payload, writer),
            .table_window => try self.handleTableWindow(frame.payload, writer),

            .subscribe, .publish, .unsubscribe => unreachable,

            .table_explain => try self.handleTableExplain(frame.payload, writer),

            .table_update => try self.handleTableUpdate(frame.payload, writer),

            .table_delete => try self.handleTableDelete(frame.payload, writer),

            .table_export => try self.handleTableExport(frame.payload, writer),

            .table_import => try self.handleTableImport(frame.payload, writer),

            .user_admin => try self.handleUserAdmin(frame.payload, writer),

            .metrics => try self.handleMetrics(writer),

            .ttl_op => try self.handleTtlOp(frame.payload, writer),

            .coll_ttl_op => try self.handleCollTtlOp(frame.payload, writer),

            .coll_op => try self.handleCollOp(frame.payload, writer),

            .txn_op => try self.handleTxnOp(frame.payload, writer),
        }
    }

    fn handleTtlOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTtlOp(payload) catch {
            return writeErr(writer, .bad_request, "malformed ttl payload");
        };
        if (keyspace.isInternal(args.key)) return writeReservedKey(writer);
        const now = std.time.nanoTimestamp();
        switch (args.action) {
            .expire => {
                const live = ttlmod.expireLive(self.db, self.allocator, args.key, now, args.seconds) catch |err| {
                    return writeStorageErr(writer, err);
                };
                if (!live) return writeErr(writer, .not_found, "no such key");
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .persist => {
                ttlmod.clearExpire(self.db, self.allocator, args.key) catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .query => {
                const result = ttlmod.remaining(self.db, self.allocator, args.key, now) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const respPayload = protocol.encodeTtlResult(self.allocator, result) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
            .sweep => {
                const reaped = ttlmod.sweepExpired(self.db, self.allocator, now) catch |err| {
                    return writeStorageErr(writer, err);
                };
                if (reaped > 0) self.ttlSweptTotal.incrBy(@intCast(reaped));
                const respPayload = protocol.encodeTtlSweepCount(self.allocator, @intCast(reaped)) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
        }
    }

    fn handleCollTtlOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeCollTtlOp(payload) catch {
            return writeErr(writer, .bad_request, "malformed coll ttl payload");
        };
        const now = std.time.nanoTimestamp();
        switch (args.action) {
            .expire => {
                const exists = collmod.collectionExists(self.db, self.allocator, args.kind, args.name) catch |err| {
                    return writeStorageErr(writer, err);
                };
                if (!exists) return writeErr(writer, .not_found, "no such collection");
                collttlmod.setExpireSeconds(self.db, self.allocator, args.kind, args.name, now, args.seconds) catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .persist => {
                collttlmod.clearExpire(self.db, self.allocator, args.kind, args.name) catch |err| {
                    return writeStorageErr(writer, err);
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .query => {
                const result = collttlmod.remaining(self.db, self.allocator, args.kind, args.name, now) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const respPayload = protocol.encodeTtlResult(self.allocator, result) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
            .sweep => {
                const reaped = collttlmod.sweepExpired(self.db, self.allocator, now) catch |err| {
                    return writeStorageErr(writer, err);
                };
                if (reaped > 0) self.collTtlSweptTotal.incrBy(@intCast(reaped));
                const respPayload = protocol.encodeTtlSweepCount(self.allocator, @intCast(reaped)) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
        }
    }

    fn handleCollOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeCollOp(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed coll payload");
        };
        defer self.allocator.free(args.args);
        const now = std.time.nanoTimestamp();
        _ = collttlmod.expireIfDue(self.db, self.allocator, args.action.kind(), args.name, now) catch |err| {
            return writeStorageErr(writer, err);
        };
        switch (args.action) {
            .set_inter, .set_union, .set_diff => _ = collttlmod.expireIfDueMany(self.db, self.allocator, .set, args.args, now) catch |err| {
                return writeStorageErr(writer, err);
            },
            else => {},
        }
        self.dispatchCollOp(args, writer) catch |err| return switch (err) {
            error.InvalidArgCount, error.InvalidNumber => writeErr(writer, .bad_request, @errorName(err)),
            else => writeStorageErr(writer, err),
        };
    }

    fn writeCollReply(self: *Server, writer: anytype, reply: protocol.CollReply) !void {
        const respPayload = protocol.encodeCollReply(self.allocator, reply) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(respPayload);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
    }

    fn dispatchCollOp(self: *Server, args: protocol.CollOpArgs, writer: anytype) !void {
        const a = args.args;
        switch (args.action) {
            .counter_get => {
                const v = try collmod.Counter.get(self.db, self.allocator, args.name);
                try self.writeCollReply(writer, .{ .int = v });
            },
            .counter_set => {
                if (a.len < 1) return error.InvalidArgCount;
                const v = std.fmt.parseInt(i64, a[0], 10) catch return error.InvalidNumber;
                try collmod.Counter.set(self.db, self.allocator, args.name, v);
                try self.writeCollReply(writer, .ok);
            },
            .counter_incrby => {
                if (a.len < 1) return error.InvalidArgCount;
                const delta = std.fmt.parseInt(i64, a[0], 10) catch return error.InvalidNumber;
                const v = try collmod.Counter.incrBy(self.db, self.allocator, args.name, delta);
                try self.writeCollReply(writer, .{ .int = v });
            },
            .hash_set => {
                if (a.len < 2) return error.InvalidArgCount;
                const created = try collmod.Hash.set(self.db, self.allocator, args.name, a[0], a[1]);
                try self.writeCollReply(writer, .{ .int = if (created) 1 else 0 });
            },
            .hash_get => {
                if (a.len < 1) return error.InvalidArgCount;
                if (try collmod.Hash.get(self.db, self.allocator, args.name, a[0])) |v| {
                    defer self.allocator.free(v);
                    try self.writeCollReply(writer, .{ .bytes = v });
                } else {
                    try self.writeCollReply(writer, .nil);
                }
            },
            .hash_del => {
                if (a.len < 1) return error.InvalidArgCount;
                const existed = try collmod.Hash.del(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .{ .int = if (existed) 1 else 0 });
            },
            .hash_len => {
                const n = try collmod.Hash.len(self.db, self.allocator, args.name);
                try self.writeCollReply(writer, .{ .int = @intCast(n) });
            },
            .hash_getall => {
                const fields = try collmod.Hash.getAll(self.db, self.allocator, args.name);
                defer {
                    for (fields) |f| f.free(self.allocator);
                    self.allocator.free(fields);
                }
                const pairs = try self.allocator.alloc(protocol.CollPair, fields.len);
                defer self.allocator.free(pairs);
                for (fields, 0..) |f, i| pairs[i] = .{ .field = f.field, .value = f.value };
                try self.writeCollReply(writer, .{ .pairList = pairs });
            },
            .set_add => {
                if (a.len < 1) return error.InvalidArgCount;
                const added = try collmod.Set.add(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .{ .int = if (added) 1 else 0 });
            },
            .set_rem => {
                if (a.len < 1) return error.InvalidArgCount;
                const removed = try collmod.Set.remove(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .{ .int = if (removed) 1 else 0 });
            },
            .set_ismember => {
                if (a.len < 1) return error.InvalidArgCount;
                const is = try collmod.Set.isMember(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .{ .int = if (is) 1 else 0 });
            },
            .set_card => {
                const n = try collmod.Set.card(self.db, self.allocator, args.name);
                try self.writeCollReply(writer, .{ .int = @intCast(n) });
            },
            .set_members => {
                const ms = try collmod.Set.members(self.db, self.allocator, args.name);
                defer {
                    for (ms) |m| self.allocator.free(m);
                    self.allocator.free(ms);
                }
                try self.writeCollReply(writer, .{ .stringList = ms });
            },
            .set_inter, .set_union => |action| {
                const names = try self.allocator.alloc([]const u8, a.len + 1);
                defer self.allocator.free(names);
                names[0] = args.name;
                @memcpy(names[1..], a);
                const ms = if (action == .set_inter)
                    try collmod.Set.intersect(self.db, self.allocator, names)
                else
                    try collmod.Set.unionOf(self.db, self.allocator, names);
                defer {
                    for (ms) |m| self.allocator.free(m);
                    self.allocator.free(ms);
                }
                try self.writeCollReply(writer, .{ .stringList = ms });
            },
            .set_diff => {
                const ms = try collmod.Set.difference(self.db, self.allocator, args.name, a);
                defer {
                    for (ms) |m| self.allocator.free(m);
                    self.allocator.free(ms);
                }
                try self.writeCollReply(writer, .{ .stringList = ms });
            },
            .list_lpush => {
                if (a.len < 1) return error.InvalidArgCount;
                try collmod.List.pushLeft(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .ok);
            },
            .list_rpush => {
                if (a.len < 1) return error.InvalidArgCount;
                try collmod.List.pushRight(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .ok);
            },
            .list_lpop => {
                if (try collmod.List.popLeft(self.db, self.allocator, args.name)) |v| {
                    defer self.allocator.free(v);
                    try self.writeCollReply(writer, .{ .bytes = v });
                } else {
                    try self.writeCollReply(writer, .nil);
                }
            },
            .list_rpop => {
                if (try collmod.List.popRight(self.db, self.allocator, args.name)) |v| {
                    defer self.allocator.free(v);
                    try self.writeCollReply(writer, .{ .bytes = v });
                } else {
                    try self.writeCollReply(writer, .nil);
                }
            },
            .list_len => {
                const n = try collmod.List.len(self.db, self.allocator, args.name);
                try self.writeCollReply(writer, .{ .int = @intCast(n) });
            },
            .list_range => {
                if (a.len < 2) return error.InvalidArgCount;
                const rangeStart = std.fmt.parseInt(i64, a[0], 10) catch return error.InvalidNumber;
                const rangeStop = std.fmt.parseInt(i64, a[1], 10) catch return error.InvalidNumber;
                const vals = try collmod.List.range(self.db, self.allocator, args.name, rangeStart, rangeStop);
                defer {
                    for (vals) |v| self.allocator.free(v);
                    self.allocator.free(vals);
                }
                try self.writeCollReply(writer, .{ .stringList = vals });
            },
            .zset_add => {
                if (a.len < 2) return error.InvalidArgCount;
                const score = std.fmt.parseFloat(f64, a[1]) catch return error.InvalidNumber;
                try collmod.ZSet.add(self.db, self.allocator, args.name, a[0], score);
                try self.writeCollReply(writer, .ok);
            },
            .zset_score => {
                if (a.len < 1) return error.InvalidArgCount;
                if (try collmod.ZSet.score(self.db, self.allocator, args.name, a[0])) |s| {
                    try self.writeCollReply(writer, .{ .real = s });
                } else {
                    try self.writeCollReply(writer, .nil);
                }
            },
            .zset_incrby => {
                if (a.len < 2) return error.InvalidArgCount;
                const delta = std.fmt.parseFloat(f64, a[1]) catch return error.InvalidNumber;
                const s = try collmod.ZSet.incrBy(self.db, self.allocator, args.name, a[0], delta);
                try self.writeCollReply(writer, .{ .real = s });
            },
            .zset_rem => {
                if (a.len < 1) return error.InvalidArgCount;
                const removed = try collmod.ZSet.remove(self.db, self.allocator, args.name, a[0]);
                try self.writeCollReply(writer, .{ .int = if (removed) 1 else 0 });
            },
            .zset_card => {
                const n = try collmod.ZSet.card(self.db, self.allocator, args.name);
                try self.writeCollReply(writer, .{ .int = @intCast(n) });
            },
            .zset_rangebyrank, .zset_rangebyscore => |action| {
                if (a.len < 2) return error.InvalidArgCount;
                const zms = if (action == .zset_rangebyrank) blk: {
                    const rangeStart = std.fmt.parseInt(i64, a[0], 10) catch return error.InvalidNumber;
                    const rangeStop = std.fmt.parseInt(i64, a[1], 10) catch return error.InvalidNumber;
                    break :blk try collmod.ZSet.rangeByRank(self.db, self.allocator, args.name, rangeStart, rangeStop);
                } else blk: {
                    const min = std.fmt.parseFloat(f64, a[0]) catch return error.InvalidNumber;
                    const max = std.fmt.parseFloat(f64, a[1]) catch return error.InvalidNumber;
                    break :blk try collmod.ZSet.rangeByScore(self.db, self.allocator, args.name, min, max);
                };
                defer {
                    for (zms) |zm| zm.free(self.allocator);
                    self.allocator.free(zms);
                }
                const pairs = try self.allocator.alloc(protocol.CollScorePair, zms.len);
                defer self.allocator.free(pairs);
                for (zms, 0..) |zm, i| pairs[i] = .{ .member = zm.member, .score = zm.score };
                try self.writeCollReply(writer, .{ .scorePairList = pairs });
            },
            .zset_rank => {
                if (a.len < 1) return error.InvalidArgCount;
                if (try collmod.ZSet.rank(self.db, self.allocator, args.name, a[0])) |r| {
                    try self.writeCollReply(writer, .{ .int = @intCast(r) });
                } else {
                    try self.writeCollReply(writer, .nil);
                }
            },
        }
    }

    fn handleMetrics(self: *Server, writer: anytype) !void {
        var reg = metrics.Registry.init(self.allocator);
        defer reg.deinit();
        self.registerMetrics(&reg) catch |err| return writeStorageErr(writer, err);

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        reg.exportText(self.allocator, buf.writer()) catch |err| return writeStorageErr(writer, err);
        metrics.formatDbStats(buf.writer(), "cobalt", self.db.stats()) catch |err| return writeStorageErr(writer, err);

        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), buf.items);
    }

    fn handleAuth(self: *Server, store: authmod.Store, payload: []const u8, writer: anytype, connRole: *?authmod.Role, connExpiresAtNanos: *?i128) !void {
        const args = protocol.decodeAuth(payload) catch {
            return writeErr(writer, .bad_request, "malformed auth payload");
        };

        self.mutex.lock();
        const result = store.verify(self.allocator, args.username, args.password);
        self.mutex.unlock();

        const role = result catch |err| {
            self.unauthorizedTotal.incr();
            return switch (err) {
                error.InvalidCredentials, error.Malformed => writeErr(writer, .unauthorized, "invalid credentials"),
                else => writeStorageErr(writer, err),
            };
        };
        connRole.* = role;
        connExpiresAtNanos.* = null;

        if (self.sessions) |store_| {
            const now = std.time.nanoTimestamp();
            const token = store_.issue(role, self.sessionTtlNanos, now) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer self.allocator.free(token);
            connExpiresAtNanos.* = now + self.sessionTtlNanos;
            const responsePayload = protocol.encodeAuthOk(self.allocator, token) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer self.allocator.free(responsePayload);
            return protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), responsePayload);
        }
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
    }

    fn handleAuthToken(self: *Server, payload: []const u8, writer: anytype, connRole: *?authmod.Role, connExpiresAtNanos: *?i128) !void {
        const store = self.sessions orelse {
            self.unauthorizedTotal.incr();
            return writeErr(writer, .unauthorized, "session tokens are not enabled on this server");
        };
        const token = protocol.decodeAuthToken(payload);
        const session = store.validate(token, std.time.nanoTimestamp()) orelse {
            self.unauthorizedTotal.incr();
            return writeErr(writer, .unauthorized, "invalid or expired session token");
        };
        connRole.* = session.role;
        connExpiresAtNanos.* = session.expiresAtNanos;
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
    }

    fn handleScan(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeScan(payload) catch {
            return writeErr(writer, .bad_request, "malformed scan payload");
        };
        const options = dbmod.ScanOptions{ .start = args.start, .end = args.end };
        const now = std.time.nanoTimestamp();
        if (args.reverse) {
            var it = keyspace.scanUserReverse(self.db, self.allocator, options, now) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer it.deinit();
            return self.writeEntries(&it, args.limit, writer);
        }
        var it = keyspace.scanUser(self.db, self.allocator, options, now) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer it.deinit();
        return self.writeEntries(&it, args.limit, writer);
    }

    fn handlePrefix(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodePrefix(payload) catch {
            return writeErr(writer, .bad_request, "malformed prefix payload");
        };
        var it = keyspace.scanUserPrefix(self.db, self.allocator, args.prefix, std.time.nanoTimestamp()) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer it.deinit();
        return self.writeEntries(&it, args.limit, writer);
    }

    fn writeEntries(self: *Server, it: anytype, limit: u32, writer: anytype) !void {
        var entries = std.ArrayList(dbmod.Entry).init(self.allocator);
        defer entries.deinit();
        while (it.next() catch |err| return writeStorageErr(writer, err)) |e| {
            try entries.append(e);
            if (limit != 0 and entries.items.len >= limit) break;
        }

        const out = protocol.encodeEntries(self.allocator, entries.items) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleBatch(self: *Server, payload: []const u8, writer: anytype) !void {
        const ops = protocol.decodeBatch(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed batch payload");
        };
        defer self.allocator.free(ops);

        var wb = dbmod.WriteBatch.init(self.allocator);
        defer wb.deinit();
        for (ops) |op| {
            const key = switch (op) {
                .put => |kv| kv.key,
                .del => |k| k,
            };
            if (keyspace.isInternal(key)) return writeReservedKey(writer);
            switch (op) {
                .put => |kv| ttlmod.stagePersistentPut(self.db, self.allocator, &wb, kv.key, kv.value) catch |err| {
                    return writeStorageErr(writer, err);
                },
                .del => ttlmod.stageDelete(self.db, self.allocator, &wb, key) catch |err| {
                    return writeStorageErr(writer, err);
                },
            }
        }
        self.db.apply(&wb) catch |err| {
            return writeStorageErr(writer, err);
        };
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
    }

    fn handleTxnOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const entries = protocol.decodeTxnOp(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed txn_op payload");
        };
        defer self.allocator.free(entries);
        if (entries.len == 0) return writeErr(writer, .bad_request, "txn_op requires at least one operation");

        var txn = txnmod.Transaction.begin(self.db);
        defer txn.deinit();

        var tables = std.StringHashMap(txntablemod.TableTxn).init(self.allocator);
        defer {
            var it = tables.valueIterator();
            while (it.next()) |t| t.deinit();
            tables.deinit();
        }

        for (entries) |e| {
            const gop = tables.getOrPut(e.table) catch |err| {
                return writeStorageErr(writer, err);
            };
            if (!gop.found_existing) {
                gop.value_ptr.* = txntablemod.TableTxn.open(&txn, self.allocator, e.table) catch |err| {
                    return writeErr(writer, .bad_request, @errorName(err));
                };
                gop.key_ptr.* = e.table;
            }
            const table = gop.value_ptr;

            const pk = rowmod.decodeValue(self.allocator, e.pkBytes) catch {
                return writeErr(writer, .bad_request, "malformed primary key");
            };
            defer pk.free(self.allocator);

            switch (e.verb) {
                .put => {
                    var fieldsRow = rowmod.Row.decode(self.allocator, e.fieldsBytes) catch {
                        return writeErr(writer, .bad_request, "malformed fields");
                    };
                    defer fieldsRow.deinit();
                    table.put(pk, fieldsRow.fields.items) catch |err| {
                        return writeStorageErr(writer, err);
                    };
                },
                .del => {
                    table.delete(pk) catch |err| {
                        return writeStorageErr(writer, err);
                    };
                },
            }
        }

        txn.commit() catch |err| {
            return switch (err) {
                error.Conflict => writeErr(writer, .conflict, "transaction conflict"),
                else => writeStorageErr(writer, err),
            };
        };

        const out = protocol.encodeTxnResult(self.allocator, @intCast(entries.len)) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableSelect(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableSelect(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed table_select payload");
        };
        defer self.allocator.free(args.orderBy);

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const rows = table.selectPageOrdered(pred, .{ .offset = args.offset, .limit = args.limit }, args.orderBy) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer querymod.freeRows(self.allocator, rows);

        const out = protocol.encodeRows(self.allocator, rows) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableJoin(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableJoin(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_join payload");
        };

        var left = querymod.Table.open(self.db, self.allocator, args.leftTable) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer left.deinit();
        var right = querymod.Table.open(self.db, self.allocator, args.rightTable) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer right.deinit();

        var leftParsed: ?exprmod.Parsed = null;
        defer if (leftParsed) |*p| p.deinit();
        if (args.leftExprText.len > 0) {
            leftParsed = exprmod.parse(self.allocator, args.leftExprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const leftPred: ?querymod.Predicate = if (leftParsed) |p| p.predicate else null;

        var rightParsed: ?exprmod.Parsed = null;
        defer if (rightParsed) |*p| p.deinit();
        if (args.rightExprText.len > 0) {
            rightParsed = exprmod.parse(self.allocator, args.rightExprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const rightPred: ?querymod.Predicate = if (rightParsed) |p| p.predicate else null;

        var pairs = std.ArrayList(protocol.JoinPair).init(self.allocator);
        defer {
            for (pairs.items) |*p| {
                if (p.left) |*l| l.deinit();
                if (p.right) |*r| r.deinit();
            }
            pairs.deinit();
        }

        const page = querymod.Page{ .offset = args.offset, .limit = args.limit };

        switch (args.mode) {
            .inner => {
                const joined = joinmod.innerJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const paged = joinmod.applyPage(joinmod.JoinedRow, self.allocator, joined, page) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .left => {
                const joined = joinmod.leftOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const paged = joinmod.applyPage(joinmod.OuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .right => {
                const joined = joinmod.rightOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const paged = joinmod.applyPage(joinmod.RightOuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .full => {
                const joined = joinmod.fullOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeStorageErr(writer, err);
                };
                const paged = joinmod.applyPage(joinmod.FullOuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
        }

        const out = protocol.encodeJoinedRows(self.allocator, pairs.items) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableAggregate(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableAggregate(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed table_aggregate payload");
        };
        defer self.allocator.free(args.specs);
        defer self.allocator.free(args.orderBy);

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        var havingParsed: ?exprmod.Parsed = null;
        defer if (havingParsed) |*p| p.deinit();
        if (args.havingText.len > 0) {
            havingParsed = exprmod.parse(self.allocator, args.havingText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const havingPred: ?querymod.Predicate = if (havingParsed) |p| p.predicate else null;

        const rows = table.select(pred) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer querymod.freeRows(self.allocator, rows);

        if (args.groupField.len == 0) {
            const values = aggregatemod.runGlobal(self.allocator, rows, args.specs) catch |err| {
                return switch (err) {
                    error.NonNumericField, error.Overflow => writeErr(writer, .bad_request, @errorName(err)),
                    else => writeStorageErr(writer, err),
                };
            };
            defer aggregatemod.freeGlobalResult(self.allocator, values);
            const matches = if (havingPred) |hp|
                aggregatemod.globalMatchesHaving(self.allocator, args.specs, values, hp) catch |err| {
                    return writeStorageErr(writer, err);
                }
            else
                true;
            const out = protocol.encodeAggGlobalResult(self.allocator, if (matches) values else &.{}) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer self.allocator.free(out);
            try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
        } else {
            const unpaged = aggregatemod.run(self.allocator, rows, args.groupField, args.specs) catch |err| {
                return switch (err) {
                    error.NonNumericField, error.Overflow => writeErr(writer, .bad_request, @errorName(err)),
                    else => writeStorageErr(writer, err),
                };
            };
            const filtered = if (havingPred) |hp|
                aggregatemod.filterHaving(self.allocator, unpaged, args.groupField, args.specs, hp) catch |err| {
                    return writeStorageErr(writer, err);
                }
            else
                unpaged;
            if (args.orderBy.len > 0) {
                aggregatemod.sortGroupsBy(self.allocator, filtered, args.groupField, args.specs, args.orderBy) catch |err| {
                    protocol.freeAggGroupRows(self.allocator, filtered);
                    return switch (err) {
                        error.UnknownOrderField => writeErr(writer, .bad_request, @errorName(err)),
                        else => writeStorageErr(writer, err),
                    };
                };
            }
            const page = querymod.Page{ .offset = args.offset, .limit = args.limit };
            const groups = aggregatemod.applyPageGroups(self.allocator, filtered, page) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer protocol.freeAggGroupRows(self.allocator, groups);
            const out = protocol.encodeAggGroupRows(self.allocator, groups) catch |err| {
                return writeStorageErr(writer, err);
            };
            defer self.allocator.free(out);
            try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
        }
    }

    fn handleSubscribe(self: *Server, payload: []const u8, stream: std.net.Stream) !void {
        const args = protocol.decodeSubscribe(self.allocator, payload) catch {
            return writeErr(stream.writer(), .bad_request, "malformed subscribe payload");
        };
        defer args.deinit(self.allocator);
        if (args.channels.len == 0) {
            return writeErr(stream.writer(), .bad_request, "subscribe needs at least one channel");
        }

        const channelNames = try self.allocator.alloc([]const u8, args.channels.len);
        defer self.allocator.free(channelNames);
        for (args.channels, 0..) |c, i| channelNames[i] = c;

        const sub = self.pubsub.subscribe(channelNames, pubsubmod.defaultCapacity) catch {
            return writeErr(stream.writer(), .internal, "failed to register subscription");
        };

        const ack = try protocol.encodeSubscribeAck(self.allocator, sub.id, @intCast(channelNames.len));
        defer self.allocator.free(ack);
        protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Status.ok), ack) catch {
            self.pubsub.closeSubscriber(sub);
            self.pubsub.destroySubscriber(sub);
            return error.SubscriptionEnded;
        };

        const watcher = try std.Thread.spawn(.{}, watchForDisconnect, .{ &self.pubsub, sub, stream });

        while (sub.waitMessage()) |msg| {
            defer msg.deinit(self.allocator);
            const framePayload = protocol.encodePubSubMessage(self.allocator, msg.channel, msg.payload) catch break;
            defer self.allocator.free(framePayload);
            protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Status.ok), framePayload) catch break;
        }

        std.posix.shutdown(stream.handle, .both) catch {};
        watcher.join();
        self.pubsub.closeSubscriber(sub);
        self.pubsub.destroySubscriber(sub);
        return error.SubscriptionEnded;
    }

    fn watchForDisconnect(hub: *pubsubmod.Hub, sub: *pubsubmod.Subscriber, stream: std.net.Stream) void {
        var buf: [1]u8 = undefined;
        _ = stream.read(&buf) catch {};
        hub.closeSubscriber(sub);
    }

    fn handlePublish(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodePublish(payload) catch {
            return writeErr(writer, .bad_request, "malformed publish payload");
        };
        const count = self.pubsub.publish(self.allocator, args.channel, args.message) catch {
            return writeErr(writer, .internal, "failed to publish message");
        };
        if (count > 0) self.messagesPublishedTotal.incrBy(@intCast(count));
        const resp = try protocol.encodePublishResult(self.allocator, @intCast(count));
        defer self.allocator.free(resp);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), resp);
    }

    fn handleUnsubscribe(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeUnsubscribe(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed unsubscribe payload");
        };
        defer args.deinit(self.allocator);
        if (args.channels.len == 0) {
            return writeErr(writer, .bad_request, "unsubscribe needs at least one channel");
        }

        const channelNames = try self.allocator.alloc([]const u8, args.channels.len);
        defer self.allocator.free(channelNames);
        for (args.channels, 0..) |c, i| channelNames[i] = c;

        const removed = self.pubsub.unsubscribe(args.subscriberId, channelNames) catch |err| {
            return switch (err) {
                error.UnknownSubscriber => writeErr(writer, .bad_request, "unknown subscriber id"),
                else => writeStorageErr(writer, err),
            };
        };

        const resp = try protocol.encodeUnsubscribeResult(self.allocator, @intCast(removed));
        defer self.allocator.free(resp);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), resp);
    }

    fn handleTableWindow(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableWindow(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed table_window payload");
        };
        defer self.allocator.free(args.specs);
        defer self.allocator.free(args.partitionBy);
        defer self.allocator.free(args.orderBy);

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const rows = table.select(pred) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer querymod.freeRows(self.allocator, rows);

        const results = windowmod.computeMany(self.allocator, rows, args.partitionBy, args.orderBy, args.specs, args.frame) catch |err| {
            return switch (err) {
                error.NonNumericField, error.Overflow, error.MissingField, error.RangeNotApplicable => writeErr(writer, .bad_request, @errorName(err)),
                else => writeStorageErr(writer, err),
            };
        };
        defer windowmod.freeManyResults(self.allocator, results);

        const displayOrder = windowmod.orderedIndices(self.allocator, rows, args.partitionBy, args.orderBy) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(displayOrder);

        const total = displayOrder.len;
        const pageStart = @min(args.offset, total);
        const end = if (args.limit == 0) total else @min(pageStart + args.limit, total);

        var out = std.ArrayList(protocol.WindowRow).init(self.allocator);
        defer {
            for (out.items) |wr| self.allocator.free(wr.values);
            out.deinit();
        }
        var i: usize = pageStart;
        while (i < end) : (i += 1) {
            const idx = displayOrder[i];
            const values = try self.allocator.alloc(rowmod.Value, args.specs.len);
            @memcpy(values, results[idx]);
            try out.append(.{ .row = rows[idx], .values = values });
        }

        const encoded = protocol.encodeWindowRows(self.allocator, out.items) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(encoded);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), encoded);
    }

    fn handleTableExplain(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableExplain(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_explain payload");
        };

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        var plan = table.explain(self.allocator, pred) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer plan.deinit(self.allocator);

        const out = protocol.encodePlan(self.allocator, plan) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableUpdate(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableUpdate(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_update payload");
        };

        var setsRow = rowmod.Row.decode(self.allocator, args.setsBytes) catch {
            return writeErr(writer, .bad_request, "malformed table_update set fields");
        };
        defer setsRow.deinit();

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const updated = table.updateWhere(pred, setsRow.fields.items) catch |err| {
            return writeStorageErr(writer, err);
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(updated)) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableDelete(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableDelete(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_delete payload");
        };

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var parsed: ?exprmod.Parsed = null;
        defer if (parsed) |*p| p.deinit();
        if (args.exprText.len > 0) {
            parsed = exprmod.parse(self.allocator, args.exprText) catch |err| {
                return writeErr(writer, .bad_request, @errorName(err));
            };
        }
        const pred: ?querymod.Predicate = if (parsed) |p| p.predicate else null;

        const deleted = table.deleteWhere(pred) catch |err| {
            return writeStorageErr(writer, err);
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(deleted)) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableExport(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableExport(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_export payload");
        };

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const rowCount = switch (args.format) {
            .csv => dumpmod.exportCsvWriter(self.allocator, &table, buf.writer()),
            .json => dumpmod.exportJsonWriter(self.allocator, &table, buf.writer()),
        } catch |err| {
            return writeStorageErr(writer, err);
        };

        const out = protocol.encodeExportResult(self.allocator, @intCast(rowCount), buf.items) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleTableImport(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTableImport(payload) catch {
            return writeErr(writer, .bad_request, "malformed table_import payload");
        };

        var table = querymod.Table.open(self.db, self.allocator, args.table) catch |err| {
            return writeErr(writer, .bad_request, @errorName(err));
        };
        defer table.deinit();

        const imported = switch (args.format) {
            .csv => dumpmod.importCsvContent(self.allocator, &table, args.content),
            .json => dumpmod.importJsonContent(self.allocator, &table, args.content),
        } catch |err| {
            return writeStorageErr(writer, err);
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(imported)) catch |err| {
            return writeStorageErr(writer, err);
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handleUserAdmin(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeUserAdmin(payload) catch {
            return writeErr(writer, .bad_request, "malformed user_admin payload");
        };
        const store = authmod.Store.init(self.db);

        switch (args.action) {
            .create => {
                const role = authmod.Role.fromByte(args.roleByte) catch {
                    return writeErr(writer, .bad_request, "invalid role");
                };
                const rounds = if (args.rounds != 0) args.rounds else authmod.recommendedRounds;
                store.createUser(self.allocator, args.username, args.password, role, rounds) catch |err| {
                    return switch (err) {
                        error.UserExists => writeErr(writer, .conflict, "user already exists"),
                        else => writeStorageErr(writer, err),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .set_password => {
                const rounds = if (args.rounds != 0) args.rounds else authmod.recommendedRounds;
                store.setPassword(self.allocator, args.username, args.password, rounds) catch |err| {
                    return switch (err) {
                        error.UserNotFound => writeErr(writer, .not_found, "user not found"),
                        else => writeStorageErr(writer, err),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .set_role => {
                const role = authmod.Role.fromByte(args.roleByte) catch {
                    return writeErr(writer, .bad_request, "invalid role");
                };
                store.setRole(self.allocator, args.username, role) catch |err| {
                    return switch (err) {
                        error.UserNotFound => writeErr(writer, .not_found, "user not found"),
                        else => writeStorageErr(writer, err),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .delete => {
                store.deleteUser(self.allocator, args.username) catch |err| {
                    return switch (err) {
                        error.UserNotFound => writeErr(writer, .not_found, "user not found"),
                        else => writeStorageErr(writer, err),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .list => {
                const users = store.listUsers(self.allocator) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer authmod.freeUserList(self.allocator, users);
                const out = protocol.encodeUserList(self.allocator, users) catch |err| {
                    return writeStorageErr(writer, err);
                };
                defer self.allocator.free(out);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
            },
        }
    }

    pub fn stop(self: *Server) void {
        if (self.acceptThread == null) return;
        self.stopping.store(true, .release);
        const listenAddr = self.net.listen_address;
        if (std.net.tcpConnectToAddress(listenAddr)) |s| {
            s.close();
        } else |_| {}
        self.acceptThread.?.join();
        self.acceptThread = null;
        if (self.sweeperThread) |t| {
            t.join();
            self.sweeperThread = null;
        }
        if (self.ttlSweeperThread) |t| {
            t.join();
            self.ttlSweeperThread = null;
        }
        if (self.collTtlSweeperThread) |t| {
            t.join();
            self.collTtlSweeperThread = null;
        }
        self.drainConnections(500 * std.time.ns_per_ms);
        self.net.deinit();
        self.pubsub.deinit();
    }

    fn drainConnections(self: *Server, timeoutNanos: u64) void {
        const startedAt = std.time.nanoTimestamp();
        while (self.activeConnections() > 0) {
            if (std.time.nanoTimestamp() - startedAt >= timeoutNanos) return;
            std.time.sleep(1 * std.time.ns_per_ms);
        }
    }
};

fn testDb(allocator: Allocator, dir: []const u8) !Db {
    return Db.open(allocator, dir, .{});
}

fn undefinedServerForDrainTest() Server {
    var srv: Server = undefined;
    srv.active = std.atomic.Value(usize).init(0);
    srv.stopping = std.atomic.Value(bool).init(false);
    return srv;
}

test "drainConnections returns immediately when there is nothing to drain" {
    var srv = undefinedServerForDrainTest();
    const start = std.time.nanoTimestamp();
    srv.drainConnections(2 * std.time.ns_per_s);
    const elapsedNanos = std.time.nanoTimestamp() - start;
    try std.testing.expect(elapsedNanos < 200 * std.time.ns_per_ms);
}

test "drainConnections waits for a connection that finishes before the timeout" {
    var srv = undefinedServerForDrainTest();
    srv.active.store(1, .release);

    const Ctx = struct {
        srv: *Server,
        fn run(ctx: *@This()) void {
            std.time.sleep(30 * std.time.ns_per_ms);
            _ = ctx.srv.active.fetchSub(1, .acq_rel);
        }
    };
    var ctx = Ctx{ .srv = &srv };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    defer t.join();

    const start = std.time.nanoTimestamp();
    srv.drainConnections(2 * std.time.ns_per_s);
    const elapsedNanos = std.time.nanoTimestamp() - start;

    try std.testing.expectEqual(@as(usize, 0), srv.activeConnections());
    try std.testing.expect(elapsedNanos < 1 * std.time.ns_per_s);
}

test "drainConnections gives up after the timeout instead of hanging forever" {
    var srv = undefinedServerForDrainTest();
    srv.active.store(1, .release);

    const start = std.time.nanoTimestamp();
    srv.drainConnections(20 * std.time.ns_per_ms);
    const elapsedNanos = std.time.nanoTimestamp() - start;

    try std.testing.expect(elapsedNanos >= 20 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), srv.activeConnections());
}

test "server responds to ping, set, get, and delete over loopback" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.ping();
    try client.set("hello", "world");
    const got = try client.get(allocator, "hello");
    defer if (got) |g| allocator.free(g);
    try std.testing.expectEqualStrings("world", got.?);

    try client.delete("hello");
    const afterDelete = try client.get(allocator, "hello");
    try std.testing.expect(afterDelete == null);
}

test "server scan, prefix, and stats round trip real data" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("user:1", "alice");
    try client.set("user:2", "bob");
    try client.set("order:1", "widget");

    const prefixed = try client.prefix(allocator, "user:", 0);
    defer protocol.freeOwnedEntries(allocator, prefixed);
    try std.testing.expectEqual(@as(usize, 2), prefixed.len);

    const scanned = try client.scan(allocator, .{});
    defer protocol.freeOwnedEntries(allocator, scanned);
    try std.testing.expectEqual(@as(usize, 3), scanned.len);

    const s = try client.stats();
    try std.testing.expectEqual(@as(usize, 3), s.memtableEntries);
}

test "server batch applies puts and deletes atomically" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("keep", "1");
    const ops = [_]protocol.BatchOp{
        .{ .put = .{ .key = "a", .value = "1" } },
        .{ .put = .{ .key = "b", .value = "2" } },
        .{ .del = "keep" },
    };
    try client.batch(&ops);

    const a = try client.get(allocator, "a");
    defer if (a) |v| allocator.free(v);
    try std.testing.expectEqualStrings("1", a.?);

    const kept = try client.get(allocator, "keep");
    try std.testing.expect(kept == null);
}

test "server scan and prefix show only user keys and refuse raw access to internal namespaces" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    _ = try collmod.Counter.incrBy(&db, allocator, "hits", 1);
    try authmod.Store.init(&db).createUser(allocator, "root", "pw", .admin, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("session:9", "live");
    try client.set("Tsession:9", "user");
    try client.ttlExpire("session:9", 3600);

    const scanned = try client.scan(allocator, .{});
    defer protocol.freeOwnedEntries(allocator, scanned);
    try std.testing.expectEqual(@as(usize, 2), scanned.len);
    try std.testing.expectEqualStrings("Tsession:9", scanned[0].key);
    try std.testing.expectEqualStrings("session:9", scanned[1].key);

    const reversed = try client.scan(allocator, .{ .reverse = true });
    defer protocol.freeOwnedEntries(allocator, reversed);
    try std.testing.expectEqual(@as(usize, 2), reversed.len);
    try std.testing.expectEqualStrings("session:9", reversed[0].key);

    const everything = try client.prefix(allocator, "", 0);
    defer protocol.freeOwnedEntries(allocator, everything);
    try std.testing.expectEqual(@as(usize, 2), everything.len);

    const markerPrefix = try client.prefix(allocator, &[_]u8{ttlmod.nsTag}, 0);
    defer protocol.freeOwnedEntries(allocator, markerPrefix);
    try std.testing.expectEqual(@as(usize, 0), markerPrefix.len);

    const markerKey = [_]u8{ttlmod.nsTag} ++ "session:9".*;
    try std.testing.expectError(error.ServerBadRequest, client.get(allocator, &markerKey));
    try std.testing.expectError(error.ServerBadRequest, client.set(&markerKey, "forged"));
    try std.testing.expectError(error.ServerBadRequest, client.delete(&markerKey));
    try std.testing.expectError(error.ServerBadRequest, client.ttlExpire(&markerKey, 5));
    const forgedBatch = [_]protocol.BatchOp{
        .{ .put = .{ .key = "fine", .value = "1" } },
        .{ .put = .{ .key = &markerKey, .value = "forged" } },
    };
    try std.testing.expectError(error.ServerBadRequest, client.batch(&forgedBatch));
    try std.testing.expect((try client.get(allocator, "fine")) == null);

    switch (try client.ttlQuery("session:9")) {
        .seconds => |s| try std.testing.expect(s > 3500),
        else => return error.TestUnexpectedResult,
    }
}

test "server answers io_error when the storage layer fails to write" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("before", "ok");

    db.wal.file.close();
    db.wal.file = try std.fs.openFileAbsolute("/dev/full", .{ .mode = .write_only });

    try std.testing.expectError(error.ServerIoError, client.set("after", "lost"));
    const ops = [_]protocol.BatchOp{.{ .put = .{ .key = "batched", .value = "lost" } }};
    try std.testing.expectError(error.ServerIoError, client.batch(&ops));

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();
    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.del), "before");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.io_error), frame.tag);
    try std.testing.expectEqualStrings("NoSpaceLeft", frame.payload);
}

test "storageStatus maps filesystem errors to io_error and everything else to internal" {
    try std.testing.expectEqual(protocol.Status.io_error, storageStatus(error.InputOutput));
    try std.testing.expectEqual(protocol.Status.io_error, storageStatus(error.NoSpaceLeft));
    try std.testing.expectEqual(protocol.Status.io_error, storageStatus(error.CorruptSstable));
    try std.testing.expectEqual(protocol.Status.internal, storageStatus(error.OutOfMemory));
    try std.testing.expectEqual(protocol.Status.internal, storageStatus(error.UniqueViolation));
}

test "server rejects a malformed frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.set), "not a valid set payload with no length prefix boundary");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);
}

test "server serves multiple concurrent clients without corrupting state" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const WorkerCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        index: usize,
        ok: bool = false,
    };

    const worker = struct {
        fn run(ctx: *WorkerCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var buf: [32]u8 = undefined;
            const key = std.fmt.bufPrint(&buf, "k{d}", .{ctx.index}) catch return;
            client.set(key, "v") catch return;
            const got = client.get(ctx.allocator, key) catch return;
            defer if (got) |g| ctx.allocator.free(g);
            ctx.ok = got != null and std.mem.eql(u8, got.?, "v");
        }
    }.run;

    var contexts: [8]WorkerCtx = undefined;
    var threads: [8]std.Thread = undefined;
    for (0..8) |i| {
        contexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .index = i };
        threads[i] = try std.Thread.spawn(.{}, worker, .{&contexts[i]});
    }
    for (0..8) |i| threads[i].join();
    for (0..8) |i| try std.testing.expect(contexts[i].ok);
}

test "server enforces a token-bucket rate limit and rejects the overflow" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableRateLimit(3, 1);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var allowed: usize = 0;
    var rejected: usize = 0;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        client.ping() catch |err| {
            try std.testing.expectEqual(client_mod.ClientError.ServerRateLimited, err);
            rejected += 1;
            continue;
        };
        allowed += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), allowed);
    try std.testing.expectEqual(@as(usize, 3), rejected);
    try std.testing.expectEqual(@as(u64, 6), server.requestsTotal.get());
    try std.testing.expectEqual(@as(u64, 3), server.rateLimitedTotal.get());
}

test "server without an enabled rate limit never rejects" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var i: usize = 0;
    while (i < 20) : (i += 1) try client.ping();
    try std.testing.expectEqual(@as(u64, 20), server.requestsTotal.get());
    try std.testing.expectEqual(@as(u64, 0), server.rateLimitedTotal.get());
}

test "per-connection rate limit gives each connection its own budget" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enablePerConnectionRateLimit(2, 1);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var clientA = try client_mod.Client.connect(allocator, server.boundAddress());
    defer clientA.close();
    var clientB = try client_mod.Client.connect(allocator, server.boundAddress());
    defer clientB.close();

    try clientA.ping();
    try clientA.ping();
    try std.testing.expectError(client_mod.ClientError.ServerRateLimited, clientA.ping());

    try clientB.ping();
    try clientB.ping();
    try std.testing.expectError(client_mod.ClientError.ServerRateLimited, clientB.ping());

    try std.testing.expectEqual(@as(u64, 2), server.connRateLimitedTotal.get());
    try std.testing.expectEqual(@as(u64, 0), server.rateLimitedTotal.get());
}

test "per-connection and global rate limits both apply, connection budget checked first" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enablePerConnectionRateLimit(10, 1);
    server.enableRateLimit(2, 1);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.ping();
    try client.ping();
    try std.testing.expectError(client_mod.ClientError.ServerRateLimited, client.ping());

    try std.testing.expectEqual(@as(u64, 1), server.rateLimitedTotal.get());
    try std.testing.expectEqual(@as(u64, 0), server.connRateLimitedTotal.get());
}

test "server table_select executes a remote expr against real rows, using an index when available" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("city");
        try table.put(.{ .int = 1 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "age", .value = .{ .int = 20 } },
        });
        try table.put(.{ .int = 2 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "age", .value = .{ .int = 40 } },
        });
        try table.put(.{ .int = 3 }, &.{
            .{ .name = "city", .value = .{ .text = "krakow" } },
            .{ .name = "age", .value = .{ .int = 40 } },
        });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const rows = try client.tableSelect(allocator, "users", "city eq s:warsaw and age gte i:30", 0, 0, &.{});
    defer protocol.freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(querymod.pkField).?.int);

    const all = try client.tableSelect(allocator, "users", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, all);
    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "server table_explain reports index_eq, composite_eq, and full_scan over real TCP, matching what table_select would actually use" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("age");
        try table.createCompositeIndex("city_age", &.{ "city", "age" });
        try table.put(.{ .int = 1 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "age", .value = .{ .int = 30 } },
        });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var agePlan = try client.tableExplain(allocator, "users", "age eq i:30");
    defer agePlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_eq, agePlan.kind);
    try std.testing.expectEqualStrings("age", agePlan.indexName.?);

    var compositePlan = try client.tableExplain(allocator, "users", "city eq s:warsaw and age eq i:30");
    defer compositePlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.composite_eq, compositePlan.kind);
    try std.testing.expectEqualStrings("city_age", compositePlan.indexName.?);
    try std.testing.expectEqual(@as(usize, 2), compositePlan.matchedFields);
    try std.testing.expectEqual(@as(usize, 2), compositePlan.totalFields);

    var scanPlan = try client.tableExplain(allocator, "users", "city eq s:warsaw");
    defer scanPlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.full_scan, scanPlan.kind);

    const rows = try client.tableSelect(allocator, "users", "city eq s:warsaw and age eq i:30", 0, 0, &.{});
    defer protocol.freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
}

test "server table_explain rejects a malformed expr with bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const err = client.tableExplain(allocator, "users", "city bogus s:warsaw");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);

    var plan = try client.tableExplain(allocator, "users", "");
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.full_scan, plan.kind);
}

test "server table_update applies a set clause to matching rows over real TCP, keeping an index in sync" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("city");
        try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "active", .value = .{ .int = 0 } } });
        try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "active", .value = .{ .int = 0 } } });
        try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "active", .value = .{ .int = 0 } } });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const sets = [_]rowmod.Field{.{ .name = "city", .value = .{ .text = "gdansk" } }};
    const updated = try client.tableUpdate("users", &sets, "city eq s:warsaw");
    try std.testing.expectEqual(@as(u64, 2), updated);

    const stale = try client.tableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);

    const moved = try client.tableSelect(allocator, "users", "city eq s:gdansk", 0, 0, &.{});
    defer protocol.freeRows(allocator, moved);
    try std.testing.expectEqual(@as(usize, 2), moved.len);

    const untouched = try client.tableSelect(allocator, "users", "city eq s:krakow", 0, 0, &.{});
    defer protocol.freeRows(allocator, untouched);
    try std.testing.expectEqual(@as(usize, 1), untouched.len);
}

test "server table_update rejects a malformed expr with bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const sets = [_]rowmod.Field{.{ .name = "active", .value = .{ .int = 1 } }};
    const err = client.tableUpdate("users", &sets, "city bogus s:warsaw");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);

    const updated = try client.tableUpdate("users", &sets, "");
    try std.testing.expectEqual(@as(u64, 1), updated);
}

test "server rejects a malformed table_update frame (bad set fields) with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, 5, .little);
    try payload.appendSlice(&lenBuf);
    try payload.appendSlice("users");
    std.mem.writeInt(u32, &lenBuf, 4, .little);
    try payload.appendSlice(&lenBuf);
    std.mem.writeInt(u32, &lenBuf, 0xFFFFFFFF, .little);
    try payload.appendSlice(&lenBuf);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.table_update), payload.items);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

test "table_update survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    const rowCount = 30;
    {
        var accounts = try querymod.Table.open(&db, allocator, "accounts");
        defer accounts.deinit();
        try accounts.createIndex("city");
        var pk: i64 = 1;
        while (pk <= rowCount) : (pk += 1) {
            const city: []const u8 = switch (@mod(pk, 3)) {
                0 => "warsaw",
                1 => "krakow",
                else => "gdansk",
            };
            try accounts.put(.{ .int = pk }, &.{
                .{ .name = "city", .value = .{ .text = city } },
                .{ .name = "epoch", .value = .{ .int = 0 } },
            });
        }
        try db.flush();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 20;
    const reshapeThreads = 2;
    const reshapeIters = 15;
    const updaterIters = 20;

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                inline for (.{ "warsaw", "krakow", "gdansk" }) |city| {
                    const buf = std.fmt.allocPrint(ctx.allocator, "city eq s:{s}", .{city}) catch return;
                    defer ctx.allocator.free(buf);
                    const rows = client.tableSelect(ctx.allocator, "accounts", buf, 0, 0, &.{}) catch return;
                    defer protocol.freeRows(ctx.allocator, rows);
                    if (rows.len != 10) return;
                    for (rows) |row| {
                        const got = row.get("city") orelse return;
                        if (!std.mem.eql(u8, got.text, city)) return;
                    }
                }
            }
            ctx.ok = true;
        }
    }.run;

    const ReshapeCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const reshapeWorker = struct {
        fn run(ctx: *ReshapeCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < reshapeIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "update-churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const UpdaterCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const updaterWorker = struct {
        fn run(ctx: *UpdaterCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: i64 = 0;
            while (i < updaterIters) : (i += 1) {
                const target: []const u8 = if (@mod(i, 2) == 0) "krakow" else "gdansk";
                const expr = std.fmt.allocPrint(ctx.allocator, "city eq s:{s}", .{target}) catch return;
                defer ctx.allocator.free(expr);
                const sets = [_]rowmod.Field{.{ .name = "epoch", .value = .{ .int = i } }};
                const updated = client.tableUpdate("accounts", &sets, expr) catch return;
                if (updated != 10) return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var reshapeContexts: [reshapeThreads]ReshapeCtx = undefined;
    var reshapeHandles: [reshapeThreads]std.Thread = undefined;
    for (0..reshapeThreads) |i| {
        reshapeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        reshapeHandles[i] = try std.Thread.spawn(.{}, reshapeWorker, .{&reshapeContexts[i]});
    }
    var updaterContext = UpdaterCtx{ .allocator = allocator, .addr = server.boundAddress() };
    const updaterHandle = try std.Thread.spawn(.{}, updaterWorker, .{&updaterContext});

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..reshapeThreads) |i| reshapeHandles[i].join();
    updaterHandle.join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..reshapeThreads) |i| try std.testing.expect(reshapeContexts[i].ok);
    try std.testing.expect(updaterContext.ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const krakowRows = try client.tableSelect(allocator, "accounts", "city eq s:krakow", 0, 0, &.{});
    defer protocol.freeRows(allocator, krakowRows);
    try std.testing.expectEqual(@as(usize, 10), krakowRows.len);
    for (krakowRows) |row| try std.testing.expectEqual(@as(i64, 18), row.get("epoch").?.int);

    const gdanskRows = try client.tableSelect(allocator, "accounts", "city eq s:gdansk", 0, 0, &.{});
    defer protocol.freeRows(allocator, gdanskRows);
    try std.testing.expectEqual(@as(usize, 10), gdanskRows.len);
    for (gdanskRows) |row| try std.testing.expectEqual(@as(i64, 19), row.get("epoch").?.int);

    const warsawRows = try client.tableSelect(allocator, "accounts", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, warsawRows);
    try std.testing.expectEqual(@as(usize, 10), warsawRows.len);
    for (warsawRows) |row| try std.testing.expectEqual(@as(i64, 0), row.get("epoch").?.int);
}

test "table_update survives concurrent flush and compact reshaping a composite index" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    const rowCount = 30;
    {
        var accounts = try querymod.Table.open(&db, allocator, "accounts");
        defer accounts.deinit();
        try accounts.createCompositeIndex("city_age", &.{ "city", "age" });
        var pk: i64 = 1;
        while (pk <= rowCount) : (pk += 1) {
            const city: []const u8 = switch (@mod(pk, 3)) {
                0 => "warsaw",
                1 => "krakow",
                else => "gdansk",
            };
            const age: i64 = if (@mod(@divTrunc(pk - 1, 3), 2) == 0) 30 else 40;
            try accounts.put(.{ .int = pk }, &.{
                .{ .name = "city", .value = .{ .text = city } },
                .{ .name = "age", .value = .{ .int = age } },
                .{ .name = "epoch", .value = .{ .int = 0 } },
            });
        }
        try db.flush();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 20;
    const reshapeThreads = 2;
    const reshapeIters = 15;
    const updaterIters = 20;

    const Combo = struct { city: []const u8, age: i64 };
    const combos = [_]Combo{
        .{ .city = "warsaw", .age = 30 },
        .{ .city = "warsaw", .age = 40 },
        .{ .city = "krakow", .age = 30 },
        .{ .city = "krakow", .age = 40 },
        .{ .city = "gdansk", .age = 30 },
        .{ .city = "gdansk", .age = 40 },
    };

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                for (combos) |combo| {
                    const buf = std.fmt.allocPrint(ctx.allocator, "city eq s:{s} and age eq i:{d}", .{ combo.city, combo.age }) catch return;
                    defer ctx.allocator.free(buf);
                    const rows = client.tableSelect(ctx.allocator, "accounts", buf, 0, 0, &.{}) catch return;
                    defer protocol.freeRows(ctx.allocator, rows);
                    if (rows.len != 5) return;
                    for (rows) |row| {
                        const gotCity = row.get("city") orelse return;
                        if (!std.mem.eql(u8, gotCity.text, combo.city)) return;
                        const gotAge = row.get("age") orelse return;
                        if (gotAge.int != combo.age) return;
                    }
                }
            }
            ctx.ok = true;
        }
    }.run;

    const ReshapeCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const reshapeWorker = struct {
        fn run(ctx: *ReshapeCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < reshapeIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "update-composite-churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const UpdaterCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const updaterWorker = struct {
        fn run(ctx: *UpdaterCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: i64 = 0;
            while (i < updaterIters) : (i += 1) {
                const combo = if (@mod(i, 2) == 0) Combo{ .city = "krakow", .age = 30 } else Combo{ .city = "gdansk", .age = 40 };
                const expr = std.fmt.allocPrint(ctx.allocator, "city eq s:{s} and age eq i:{d}", .{ combo.city, combo.age }) catch return;
                defer ctx.allocator.free(expr);
                const sets = [_]rowmod.Field{.{ .name = "epoch", .value = .{ .int = i } }};
                const updated = client.tableUpdate("accounts", &sets, expr) catch return;
                if (updated != 5) return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var reshapeContexts: [reshapeThreads]ReshapeCtx = undefined;
    var reshapeHandles: [reshapeThreads]std.Thread = undefined;
    for (0..reshapeThreads) |i| {
        reshapeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        reshapeHandles[i] = try std.Thread.spawn(.{}, reshapeWorker, .{&reshapeContexts[i]});
    }
    var updaterContext = UpdaterCtx{ .allocator = allocator, .addr = server.boundAddress() };
    const updaterHandle = try std.Thread.spawn(.{}, updaterWorker, .{&updaterContext});

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..reshapeThreads) |i| reshapeHandles[i].join();
    updaterHandle.join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..reshapeThreads) |i| try std.testing.expect(reshapeContexts[i].ok);
    try std.testing.expect(updaterContext.ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    for (combos) |combo| {
        const expr = try std.fmt.allocPrint(allocator, "city eq s:{s} and age eq i:{d}", .{ combo.city, combo.age });
        defer allocator.free(expr);
        const rows = try client.tableSelect(allocator, "accounts", expr, 0, 0, &.{});
        defer protocol.freeRows(allocator, rows);
        try std.testing.expectEqual(@as(usize, 5), rows.len);
        const wantEpoch: i64 = if (std.mem.eql(u8, combo.city, "krakow") and combo.age == 30)
            18
        else if (std.mem.eql(u8, combo.city, "gdansk") and combo.age == 40)
            19
        else
            0;
        for (rows) |row| try std.testing.expectEqual(wantEpoch, row.get("epoch").?.int);

        var plan = try client.tableExplain(allocator, "accounts", expr);
        defer plan.deinit(allocator);
        try std.testing.expectEqual(querymod.PlanKind.composite_eq, plan.kind);
    }
}

test "server table_delete removes matching rows over real TCP, keeping an index in sync" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("city");
        try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
        try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
        try table.put(.{ .int = 3 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const deleted = try client.tableDelete("users", "city eq s:warsaw");
    try std.testing.expectEqual(@as(u64, 2), deleted);

    const gone = try client.tableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, gone);
    try std.testing.expectEqual(@as(usize, 0), gone.len);

    const untouched = try client.tableSelect(allocator, "users", "city eq s:krakow", 0, 0, &.{});
    defer protocol.freeRows(allocator, untouched);
    try std.testing.expectEqual(@as(usize, 1), untouched.len);

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.put(.{ .int = 4 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }
    const reused = try client.tableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, reused);
    try std.testing.expectEqual(@as(usize, 1), reused.len);
    try std.testing.expectEqual(@as(i64, 4), reused[0].get(querymod.pkField).?.int);
}

test "server table_delete with an empty expr removes every row" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "counters");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{.{ .name = "n", .value = .{ .int = 5 } }});
        try table.put(.{ .int = 2 }, &.{.{ .name = "n", .value = .{ .int = 7 } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const deleted = try client.tableDelete("counters", "");
    try std.testing.expectEqual(@as(u64, 2), deleted);

    const everyone = try client.tableSelect(allocator, "counters", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, everyone);
    try std.testing.expectEqual(@as(usize, 0), everyone.len);
}

test "server table_delete rejects a malformed expr with bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const err = client.tableDelete("users", "city bogus s:warsaw");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);

    const deleted = try client.tableDelete("users", "");
    try std.testing.expectEqual(@as(u64, 1), deleted);
}

test "server table_delete rejects a FOREIGN KEY RESTRICT violation over the wire and leaves the row in place" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var customers = try querymod.Table.open(&db, allocator, "customers");
        defer customers.deinit();
        try customers.put(.{ .int = 1 }, &.{});

        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createForeignKey("customer_id", "customers", querymod.pkField, .restrict);
        try orders.put(.{ .int = 100 }, &.{.{ .name = "customer_id", .value = .{ .int = 1 } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const err = client.tableDelete("customers", "");
    try std.testing.expectError(client_mod.ClientError.ServerInternal, err);

    var customers = try querymod.Table.open(&db, allocator, "customers");
    defer customers.deinit();
    var stillThere = (try customers.get(.{ .int = 1 })).?;
    defer stillThere.deinit();

    _ = try client.tableDelete("orders", "");
    const deleted = try client.tableDelete("customers", "");
    try std.testing.expectEqual(@as(u64, 1), deleted);
}

test "server rejects a malformed table_delete frame (bad table name) with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, 0xFFFFFFFF, .little);
    try payload.appendSlice(&lenBuf);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.table_delete), payload.items);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

test "server table_export renders a real table to csv and json over TCP, matching the local dump.zig output" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "age", .value = .{ .int = 30 } } });
        try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "krakow" } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var csvResult = try client.tableExport(allocator, "people", .csv);
    defer csvResult.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), csvResult.rowCount);

    var localCsv = std.ArrayList(u8).init(allocator);
    defer localCsv.deinit();
    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        const n = try dumpmod.exportCsvWriter(allocator, &table, localCsv.writer());
        try std.testing.expectEqual(@as(usize, 2), n);
    }
    try std.testing.expectEqualStrings(localCsv.items, csvResult.content);

    var jsonResult = try client.tableExport(allocator, "people", .json);
    defer jsonResult.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), jsonResult.rowCount);
    try std.testing.expect(std.mem.indexOf(u8, jsonResult.content, "warsaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, jsonResult.content, "krakow") != null);
}

test "server table_import loads csv and json content sent over TCP into a real table" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const csvImported = try client.tableImport("from_csv", .csv, "__pk,city\ni:1,s:warsaw\ni:2,s:krakow\n");
    try std.testing.expectEqual(@as(u64, 2), csvImported);

    const jsonImported = try client.tableImport("from_json", .json, "[{\"__pk\": \"i:1\", \"city\": \"s:gdansk\"}]");
    try std.testing.expectEqual(@as(u64, 1), jsonImported);

    const csvRows = try client.tableSelect(allocator, "from_csv", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, csvRows);
    try std.testing.expectEqual(@as(usize, 2), csvRows.len);

    const jsonRows = try client.tableSelect(allocator, "from_json", "city eq s:gdansk", 0, 0, &.{});
    defer protocol.freeRows(allocator, jsonRows);
    try std.testing.expectEqual(@as(usize, 1), jsonRows.len);
}

test "server table_export then table_import round trips a real table over two TCP round trips" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "source");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .float = 4.5 } } });
        try table.put(.{ .int = 2 }, &.{.{ .name = "city", .value = .{ .text = "lodz" } }});
        try table.put(.{ .int = 3 }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var exported = try client.tableExport(allocator, "source", .json);
    defer exported.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), exported.rowCount);

    const imported = try client.tableImport("dest", .json, exported.content);
    try std.testing.expectEqual(@as(u64, 3), imported);

    const warsawRows = try client.tableSelect(allocator, "dest", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, warsawRows);
    try std.testing.expectEqual(@as(usize, 1), warsawRows.len);
    try std.testing.expectEqual(@as(f64, 4.5), warsawRows[0].get("score").?.float);

    const untouched = try client.tableSelect(allocator, "dest", "city eq s:lodz", 0, 0, &.{});
    defer protocol.freeRows(allocator, untouched);
    try std.testing.expectEqual(@as(usize, 1), untouched.len);

    const allRows = try client.tableSelect(allocator, "dest", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, allRows);
    try std.testing.expectEqual(@as(usize, 3), allRows.len);
}

test "server table_export succeeds on a never-written table (schemaless tables have no declare step), table_import rejects malformed content without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    var exported = try client.tableExport(allocator, "nosuch", .csv);
    defer exported.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), exported.rowCount);

    const badImport = client.tableImport("nosuch", .json, "not json");
    try std.testing.expectError(client_mod.ClientError.ServerInternal, badImport);

    const rowCount = try client.tableImport("nosuch", .json, "[]");
    try std.testing.expectEqual(@as(u64, 0), rowCount);
}

test "server rejects a malformed table_export frame (bad format byte) with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, 6, .little);
    try payload.appendSlice(&lenBuf);
    try payload.appendSlice("people");
    try payload.append(99);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.table_export), payload.items);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

test "table_export requires only readonly role, table_import requires readwrite" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{});
    }

    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "viewer", "pass", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    try client.authenticate("viewer", "pass");

    var exported = try client.tableExport(allocator, "people", .csv);
    defer exported.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), exported.rowCount);

    try std.testing.expectError(client_mod.ClientError.ServerForbidden, client.tableImport("people", .csv, exported.content));
}

test "table_delete survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    const stableBucketRows = 10;
    const poznanRows = 10;
    {
        var accounts = try querymod.Table.open(&db, allocator, "accounts");
        defer accounts.deinit();
        try accounts.createIndex("city");
        var pk: i64 = 1;
        var i: i64 = 0;
        while (i < stableBucketRows) : (i += 1) {
            inline for (.{ "warsaw", "krakow", "gdansk" }) |city| {
                try accounts.put(.{ .int = pk }, &.{.{ .name = "city", .value = .{ .text = city } }});
                pk += 1;
            }
        }
        var seq: i64 = 0;
        while (seq < poznanRows) : (seq += 1) {
            try accounts.put(.{ .int = pk }, &.{
                .{ .name = "city", .value = .{ .text = "poznan" } },
                .{ .name = "seq", .value = .{ .int = seq } },
            });
            pk += 1;
        }
        try db.flush();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 20;
    const reshapeThreads = 2;
    const reshapeIters = 15;

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                inline for (.{ "warsaw", "krakow", "gdansk" }) |city| {
                    const buf = std.fmt.allocPrint(ctx.allocator, "city eq s:{s}", .{city}) catch return;
                    defer ctx.allocator.free(buf);
                    const rows = client.tableSelect(ctx.allocator, "accounts", buf, 0, 0, &.{}) catch return;
                    defer protocol.freeRows(ctx.allocator, rows);
                    if (rows.len != stableBucketRows) return;
                    for (rows) |row| {
                        const got = row.get("city") orelse return;
                        if (!std.mem.eql(u8, got.text, city)) return;
                    }
                }
            }
            ctx.ok = true;
        }
    }.run;

    const ReshapeCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const reshapeWorker = struct {
        fn run(ctx: *ReshapeCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < reshapeIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "delete-churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const DeleterCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const deleterWorker = struct {
        fn run(ctx: *DeleterCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var seq: i64 = 0;
            while (seq < poznanRows) : (seq += 1) {
                const expr = std.fmt.allocPrint(ctx.allocator, "city eq s:poznan and seq eq i:{d}", .{seq}) catch return;
                defer ctx.allocator.free(expr);
                const deleted = client.tableDelete("accounts", expr) catch return;
                if (deleted != 1) return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var reshapeContexts: [reshapeThreads]ReshapeCtx = undefined;
    var reshapeHandles: [reshapeThreads]std.Thread = undefined;
    for (0..reshapeThreads) |i| {
        reshapeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        reshapeHandles[i] = try std.Thread.spawn(.{}, reshapeWorker, .{&reshapeContexts[i]});
    }
    var deleterContext = DeleterCtx{ .allocator = allocator, .addr = server.boundAddress() };
    const deleterHandle = try std.Thread.spawn(.{}, deleterWorker, .{&deleterContext});

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..reshapeThreads) |i| reshapeHandles[i].join();
    deleterHandle.join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..reshapeThreads) |i| try std.testing.expect(reshapeContexts[i].ok);
    try std.testing.expect(deleterContext.ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    inline for (.{ "warsaw", "krakow", "gdansk" }) |city| {
        const buf = try std.fmt.allocPrint(allocator, "city eq s:{s}", .{city});
        defer allocator.free(buf);
        const rows = try client.tableSelect(allocator, "accounts", buf, 0, 0, &.{});
        defer protocol.freeRows(allocator, rows);
        try std.testing.expectEqual(@as(usize, stableBucketRows), rows.len);
    }

    const poznanRowsLeft = try client.tableSelect(allocator, "accounts", "city eq s:poznan", 0, 0, &.{});
    defer protocol.freeRows(allocator, poznanRowsLeft);
    try std.testing.expectEqual(@as(usize, 0), poznanRowsLeft.len);

    var plan = try client.tableExplain(allocator, "accounts", "city eq s:poznan");
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_eq, plan.kind);
}

test "server table_select pages a remote result with offset and limit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        var pk: i64 = 1;
        while (pk <= 5) : (pk += 1) try table.put(.{ .int = pk }, &.{});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const page = try client.tableSelect(allocator, "users", "", 1, 2, &.{});
    defer protocol.freeRows(allocator, page);
    try std.testing.expectEqual(@as(usize, 2), page.len);
    try std.testing.expectEqual(@as(i64, 2), page[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 3), page[1].get(querymod.pkField).?.int);

    const rest = try client.tableSelect(allocator, "users", "", 3, 0, &.{});
    defer protocol.freeRows(allocator, rest);
    try std.testing.expectEqual(@as(usize, 2), rest.len);
    try std.testing.expectEqual(@as(i64, 4), rest[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 5), rest[1].get(querymod.pkField).?.int);
}

test "server table_select orders a remote result by a field before windowing it, ascending and descending" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.createIndex("age");
        var pk: i64 = 1;
        while (pk <= 5) : (pk += 1) {
            try table.put(.{ .int = pk }, &.{.{ .name = "age", .value = .{ .int = 60 - pk * 10 } }});
        }
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const asc = try client.tableSelect(allocator, "users", "", 0, 0, &.{.{ .field = "age" }});
    defer protocol.freeRows(allocator, asc);
    try std.testing.expectEqual(@as(usize, 5), asc.len);
    try std.testing.expectEqual(@as(i64, 5), asc[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 10), asc[0].get("age").?.int);
    try std.testing.expectEqual(@as(i64, 1), asc[4].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 50), asc[4].get("age").?.int);

    const midDesc = try client.tableSelect(allocator, "users", "", 1, 2, &.{.{ .field = "age", .descending = true }});
    defer protocol.freeRows(allocator, midDesc);
    try std.testing.expectEqual(@as(usize, 2), midDesc.len);
    try std.testing.expectEqual(@as(i64, 2), midDesc[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 40), midDesc[0].get("age").?.int);
    try std.testing.expectEqual(@as(i64, 3), midDesc[1].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 30), midDesc[1].get("age").?.int);

    const midAsc = try client.tableSelect(allocator, "users", "", 1, 2, &.{.{ .field = "age" }});
    defer protocol.freeRows(allocator, midAsc);
    try std.testing.expectEqual(@as(usize, 2), midAsc.len);
    try std.testing.expectEqual(@as(i64, 4), midAsc[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 20), midAsc[0].get("age").?.int);
    try std.testing.expectEqual(@as(i64, 3), midAsc[1].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 30), midAsc[1].get("age").?.int);

    var plan = try client.tableExplain(allocator, "users", "age gte i:0");
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_range, plan.kind);
}

test "server table_select orders a remote result by two columns, sorting then breaking ties" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 30 } } });
        try table.put(.{ .int = 2 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "score", .value = .{ .int = 20 } } });
        try table.put(.{ .int = 3 }, &.{ .{ .name = "city", .value = .{ .text = "warsaw" } }, .{ .name = "score", .value = .{ .int = 10 } } });
        try table.put(.{ .int = 4 }, &.{ .{ .name = "city", .value = .{ .text = "krakow" } }, .{ .name = "score", .value = .{ .int = 40 } } });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const rows = try client.tableSelect(allocator, "people", "", 0, 0, &.{ .{ .field = "city" }, .{ .field = "score" } });
    defer protocol.freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 4), rows.len);
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 4), rows[1].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 3), rows[2].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 1), rows[3].get(querymod.pkField).?.int);
}

test "server table_select rejects a malformed expr with bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var table = try querymod.Table.open(&db, allocator, "users");
        defer table.deinit();
        try table.put(.{ .int = 1 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const err = client.tableSelect(allocator, "users", "city bogus s:warsaw", 0, 0, &.{});
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

fn seedAggregateOrders(allocator: Allocator, db: *Db) !void {
    var orders = try querymod.Table.open(db, allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 1 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "total", .value = .{ .int = 100 } },
    });
    try orders.put(.{ .int = 2 }, &.{
        .{ .name = "city", .value = .{ .text = "warsaw" } },
        .{ .name = "total", .value = .{ .int = 250 } },
    });
    try orders.put(.{ .int = 3 }, &.{
        .{ .name = "city", .value = .{ .text = "krakow" } },
        .{ .name = "total", .value = .{ .int = 40 } },
    });
}

test "server table_aggregate groups remote rows by field with count/sum, matching the local library result" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };
    const groups = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "");
    defer protocol.freeAggGroupRows(allocator, groups);

    try std.testing.expectEqual(@as(usize, 2), groups.len);
    try std.testing.expectEqualStrings("warsaw", groups[0].group.text);
    try std.testing.expectEqual(@as(i64, 2), groups[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 350), groups[0].values[1].int);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqual(@as(i64, 1), groups[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 40), groups[1].values[1].int);
}

test "server table_aggregate honors offset/limit to window the result groups server-side" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);
    var orders = try querymod.Table.open(&db, allocator, "orders");
    try orders.put(.{ .int = 4 }, &.{
        .{ .name = "city", .value = .{ .text = "gdansk" } },
        .{ .name = "total", .value = .{ .int = 5 } },
    });
    orders.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};

    const all = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "");
    defer protocol.freeAggGroupRows(allocator, all);
    try std.testing.expectEqual(@as(usize, 3), all.len);

    const paged = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 1, 1, &.{}, "", "");
    defer protocol.freeAggGroupRows(allocator, paged);
    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqualStrings(all[1].group.text, paged[0].group.text);
}

test "server table_aggregate with no groupField runs a single global aggregate and honors the expr filter" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };
    const all = try client.tableAggregateGlobal(allocator, "orders", &specs, "", "");
    defer protocol.freeAggValues(allocator, all);
    try std.testing.expectEqual(@as(i64, 3), all[0].int);
    try std.testing.expectEqual(@as(i64, 390), all[1].int);

    const filtered = try client.tableAggregateGlobal(allocator, "orders", &specs, "", "total gt i:50");
    defer protocol.freeAggValues(allocator, filtered);
    try std.testing.expectEqual(@as(i64, 2), filtered[0].int);
    try std.testing.expectEqual(@as(i64, 350), filtered[1].int);
}

test "server table_aggregate applies a HAVING clause to result groups after aggregation, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };

    const bySum = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "sum_total gt i:100", "");
    defer protocol.freeAggGroupRows(allocator, bySum);
    try std.testing.expectEqual(@as(usize, 1), bySum.len);
    try std.testing.expectEqualStrings("warsaw", bySum[0].group.text);

    const byGroup = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "city eq s:krakow", "");
    defer protocol.freeAggGroupRows(allocator, byGroup);
    try std.testing.expectEqual(@as(usize, 1), byGroup.len);
    try std.testing.expectEqualStrings("krakow", byGroup[0].group.text);

    const none = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "count gt i:1000", "");
    defer protocol.freeAggGroupRows(allocator, none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "server table_aggregate HAVING narrows groups before LIMIT/OFFSET windows them, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);
    var orders = try querymod.Table.open(&db, allocator, "orders");
    try orders.put(.{ .int = 4 }, &.{
        .{ .name = "city", .value = .{ .text = "gdansk" } },
        .{ .name = "total", .value = .{ .int = 500 } },
    });
    orders.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };
    const paged = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 1, &.{}, "sum_total gt i:100", "");
    defer protocol.freeAggGroupRows(allocator, paged);
    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqualStrings("warsaw", paged[0].group.text);

    const pagedOffset = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 1, 1, &.{}, "sum_total gt i:100", "");
    defer protocol.freeAggGroupRows(allocator, pagedOffset);
    try std.testing.expectEqual(@as(usize, 1), pagedOffset.len);
    try std.testing.expectEqualStrings("gdansk", pagedOffset[0].group.text);
}

test "server table_aggregate HAVING on the global (no groupField) path excludes the single row without erroring, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };

    const passing = try client.tableAggregateGlobal(allocator, "orders", &specs, "sum_total gt i:100", "");
    defer protocol.freeAggValues(allocator, passing);
    try std.testing.expectEqual(@as(usize, 2), passing.len);
    try std.testing.expectEqual(@as(i64, 390), passing[1].int);

    const excluded = try client.tableAggregateGlobal(allocator, "orders", &specs, "sum_total gt i:100000", "");
    defer protocol.freeAggValues(allocator, excluded);
    try std.testing.expectEqual(@as(usize, 0), excluded.len);
}

test "server table_aggregate reports a malformed HAVING expr as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};
    const err = client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "count bogus i:1", "");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_aggregate count_distinct collapses repeated field values, locally and globally, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    {
        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.put(.{ .int = 1 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "region", .value = .{ .text = "mazovia" } },
        });
        try orders.put(.{ .int = 2 }, &.{
            .{ .name = "city", .value = .{ .text = "warsaw" } },
            .{ .name = "region", .value = .{ .text = "mazovia" } },
        });
        try orders.put(.{ .int = 3 }, &.{
            .{ .name = "city", .value = .{ .text = "krakow" } },
            .{ .name = "region", .value = .{ .text = "malopolska" } },
        });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "region", .kind = .count_distinct },
    };
    const groups = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "");
    defer protocol.freeAggGroupRows(allocator, groups);
    try std.testing.expectEqual(@as(usize, 2), groups.len);
    try std.testing.expectEqualStrings("warsaw", groups[0].group.text);
    try std.testing.expectEqual(@as(i64, 2), groups[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 1), groups[0].values[1].int);
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqual(@as(i64, 1), groups[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 1), groups[1].values[1].int);

    const globalSpecs = [_]aggregatemod.AggSpec{.{ .field = "region", .kind = .count_distinct }};
    const global = try client.tableAggregateGlobal(allocator, "orders", &globalSpecs, "", "");
    defer protocol.freeAggValues(allocator, global);
    try std.testing.expectEqual(@as(i64, 2), global[0].int);
}

test "server table_aggregate reports a non-numeric sum field as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]aggregatemod.AggSpec{.{ .field = "city", .kind = .sum }};
    const err = client.tableAggregateGlobal(allocator, "orders", &specs, "", "");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_window annotates remote rows with row_number, partition-then-order matching the local library result" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const partitionBy = [_][]const u8{"city"};
    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .row_number }};
    const results = try client.tableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqualStrings("warsaw", results[0].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 100), results[0].row.get("total").?.int);
    try std.testing.expectEqual(@as(i64, 1), results[0].values[0].int);
    try std.testing.expectEqualStrings("warsaw", results[1].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 250), results[1].row.get("total").?.int);
    try std.testing.expectEqual(@as(i64, 2), results[1].values[0].int);
    try std.testing.expectEqualStrings("krakow", results[2].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 1), results[2].values[0].int);
}

test "server table_window honors offset/limit to page rows in partition-then-order display order, not raw scan order" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const partitionBy = [_][]const u8{"city"};
    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .row_number }};

    const all = try client.tableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, all);
    try std.testing.expectEqual(@as(usize, 3), all.len);

    const paged = try client.tableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 1, 1, "", .rows);
    defer protocol.freeWindowRows(allocator, paged);
    try std.testing.expectEqual(@as(usize, 1), paged.len);
    try std.testing.expectEqual(all[1].values[0].int, paged[0].values[0].int);
    try std.testing.expectEqual(all[1].row.get("total").?.int, paged[0].row.get("total").?.int);
}

test "server table_window with MULTIPLE specs returns one WindowRow.values entry per spec, in request order, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const partitionBy = [_][]const u8{"city"};
    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "", .kind = .row_number },
        .{ .field = "total", .kind = .sum },
    };
    const results = try client.tableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(@as(usize, 2), results[0].values.len);
    try std.testing.expectEqualStrings("warsaw", results[0].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 1), results[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 100), results[0].values[1].int);
    try std.testing.expectEqualStrings("warsaw", results[1].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 2), results[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 350), results[1].values[1].int);
    try std.testing.expectEqualStrings("krakow", results[2].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 1), results[2].values[0].int);
    try std.testing.expectEqual(@as(i64, 40), results[2].values[1].int);
}

test "server table_window with a partition but no order runs a whole-partition sum, matching sum:field semantics" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const partitionBy = [_][]const u8{"city"};
    const specs = [_]windowmod.WindowSpec{.{ .field = "total", .kind = .sum }};
    const results = try client.tableWindow(allocator, "orders", &specs, &partitionBy, &.{}, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    for (results) |wr| {
        const expected: i64 = if (std.mem.eql(u8, wr.row.get("city").?.text, "warsaw")) 350 else 40;
        try std.testing.expectEqual(expected, wr.values[0].int);
    }
}

test "server table_window RANGE frame groups tied rows by day, ROWS gives each row its own running total, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    {
        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.put(.{ .int = 1 }, &.{
            .{ .name = "day", .value = .{ .int = 1 } },
            .{ .name = "amount", .value = .{ .int = 10 } },
        });
        try orders.put(.{ .int = 2 }, &.{
            .{ .name = "day", .value = .{ .int = 1 } },
            .{ .name = "amount", .value = .{ .int = 20 } },
        });
        try orders.put(.{ .int = 3 }, &.{
            .{ .name = "day", .value = .{ .int = 2 } },
            .{ .name = "amount", .value = .{ .int = 5 } },
        });
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "day", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "amount", .kind = .sum }};

    const rangeResults = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .range);
    defer protocol.freeWindowRows(allocator, rangeResults);
    try std.testing.expectEqual(@as(usize, 3), rangeResults.len);
    try std.testing.expectEqual(@as(i64, 30), rangeResults[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 30), rangeResults[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 35), rangeResults[2].values[0].int);

    const rowsResults = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, rowsResults);
    try std.testing.expectEqual(@as(usize, 3), rowsResults.len);
    try std.testing.expectEqual(@as(i64, 10), rowsResults[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 30), rowsResults[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 35), rowsResults[2].values[0].int);
}

test "server table_window rejects a RANGE frame combined with row_number as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .row_number }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .range);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_window lag/lead read the adjacent row's value along order, NULL at the sequence edge, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "total", .kind = .lag },
        .{ .field = "total", .kind = .lead },
    };
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(@as(i64, 40), results[0].row.get("total").?.int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, results[0].values[0]));
    try std.testing.expectEqual(@as(i64, 100), results[0].values[1].int);
    try std.testing.expectEqual(@as(i64, 100), results[1].row.get("total").?.int);
    try std.testing.expectEqual(@as(i64, 40), results[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 250), results[1].values[1].int);
    try std.testing.expectEqual(@as(i64, 250), results[2].row.get("total").?.int);
    try std.testing.expectEqual(@as(i64, 100), results[2].values[0].int);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, results[2].values[1]));
}

test "server table_window lag with an explicit offset and a caller-supplied default, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "total", .kind = .lag, .offset = 2, .default = .{ .int = -1 } }};
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(i64, -1), results[0].values[0].int);
    try std.testing.expectEqual(@as(i64, -1), results[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 40), results[2].values[0].int);
}

test "server table_window rejects a RANGE frame combined with lag as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "total", .kind = .lead }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .range);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_window first_value/last_value read the current RANGE tie group's edges, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "total", .kind = .first_value },
        .{ .field = "total", .kind = .last_value },
    };
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .range);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    for (results) |r| try std.testing.expectEqual(@as(i64, 40), r.values[0].int);
    try std.testing.expectEqual(@as(i64, 40), results[0].values[1].int);
    try std.testing.expectEqual(@as(i64, 100), results[1].values[1].int);
    try std.testing.expectEqual(@as(i64, 250), results[2].values[1].int);
}

test "server table_window nth_value reads a fixed frame position, default at the sequence edge, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "total", .kind = .nth_value, .offset = 2, .default = .{ .int = -1 } }};
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(@as(i64, -1), results[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 100), results[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 100), results[2].values[0].int);
}

test "server table_window count_distinct runs a distinct-city total over real TCP, matching local semantics" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const orderBy = [_]querymod.OrderBy{.{ .field = "total", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "city", .kind = .count_distinct }};
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(@as(i64, 1), results[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 2), results[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 2), results[2].values[0].int);
}

test "server table_window applies the expr filter before annotating, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .count }};
    const results = try client.tableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "city eq s:warsaw", .rows);
    defer protocol.freeWindowRows(allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    for (results) |wr| try std.testing.expectEqual(@as(i64, 2), wr.values[0].int);
}

test "server table_window reports a malformed expr as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .count }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "city bogus s:warsaw", .rows);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_window reports a non-numeric sum field as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]windowmod.WindowSpec{.{ .field = "city", .kind = .sum }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "server table_window reports a sum spec with no field as bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedAggregateOrders(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .sum }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "table_aggregate survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    const rowCount = 30;
    {
        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        var pk: i64 = 1;
        while (pk <= rowCount) : (pk += 1) {
            const city: []const u8 = switch (@mod(pk, 3)) {
                0 => "warsaw",
                1 => "krakow",
                else => "gdansk",
            };
            try orders.put(.{ .int = pk }, &.{
                .{ .name = "city", .value = .{ .text = city } },
                .{ .name = "total", .value = .{ .int = pk } },
            });
        }
        try db.flush();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 20;
    const mutatorThreads = 2;
    const mutatorIters = 15;

    const expectedCount = struct {
        fn get(city: []const u8) i64 {
            return if (std.mem.eql(u8, city, "warsaw") or std.mem.eql(u8, city, "krakow") or std.mem.eql(u8, city, "gdansk")) 10 else -1;
        }
    }.get;
    const expectedSum = struct {
        fn get(city: []const u8) i64 {
            if (std.mem.eql(u8, city, "warsaw")) return 165;
            if (std.mem.eql(u8, city, "krakow")) return 145;
            if (std.mem.eql(u8, city, "gdansk")) return 155;
            return -1;
        }
    }.get;

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                const specs = [_]aggregatemod.AggSpec{
                    .{ .field = "", .kind = .count },
                    .{ .field = "total", .kind = .sum },
                };
                const groups = client.tableAggregateGroups(ctx.allocator, "orders", "city", &specs, 0, 0, &.{}, "", "") catch return;
                defer protocol.freeAggGroupRows(ctx.allocator, groups);
                if (groups.len != 3) return;
                for (groups) |g| {
                    if (g.values[0].int != expectedCount(g.group.text)) return;
                    if (g.values[1].int != expectedSum(g.group.text)) return;
                }

                const global = client.tableAggregateGlobal(ctx.allocator, "orders", &specs, "", "") catch return;
                defer protocol.freeAggValues(ctx.allocator, global);
                if (global[0].int != rowCount) return;
                if (global[1].int != 465) return;
            }
            ctx.ok = true;
        }
    }.run;

    const MutatorCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const mutatorWorker = struct {
        fn run(ctx: *MutatorCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < mutatorIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "agg-churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var mutatorContexts: [mutatorThreads]MutatorCtx = undefined;
    var mutatorHandles: [mutatorThreads]std.Thread = undefined;
    for (0..mutatorThreads) |i| {
        mutatorContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        mutatorHandles[i] = try std.Thread.spawn(.{}, mutatorWorker, .{&mutatorContexts[i]});
    }

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..mutatorThreads) |i| mutatorHandles[i].join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..mutatorThreads) |i| try std.testing.expect(mutatorContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};
    const finalGroups = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "");
    defer protocol.freeAggGroupRows(allocator, finalGroups);
    try std.testing.expectEqual(@as(usize, 3), finalGroups.len);
    for (finalGroups) |g| try std.testing.expectEqual(expectedCount(g.group.text), g.values[0].int);
}

fn seedJoinTables(allocator: Allocator, db: *Db) !void {
    var customers = try querymod.Table.open(db, allocator, "customers");
    defer customers.deinit();
    try customers.put(.{ .int = 1 }, &.{.{ .name = "name", .value = .{ .text = "alice" } }});
    try customers.put(.{ .int = 2 }, &.{.{ .name = "name", .value = .{ .text = "bob" } }});
    try customers.put(.{ .int = 3 }, &.{.{ .name = "name", .value = .{ .text = "carol" } }});

    var orders = try querymod.Table.open(db, allocator, "orders");
    defer orders.deinit();
    try orders.put(.{ .int = 101 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 1 } },
        .{ .name = "total", .value = .{ .int = 50 } },
    });
    try orders.put(.{ .int = 102 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 1 } },
        .{ .name = "total", .value = .{ .int = 30 } },
    });
    try orders.put(.{ .int = 103 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 999 } },
        .{ .name = "total", .value = .{ .int = 999 } },
    });
}

test "server table_join runs a remote inner join, using an index when available" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedJoinTables(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const noIndex = try client.tableJoin(allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, noIndex);
    try std.testing.expectEqual(@as(usize, 2), noIndex.len);
    for (noIndex) |p| {
        try std.testing.expect(p.left != null);
        try std.testing.expect(p.right != null);
        try std.testing.expectEqualStrings("alice", p.left.?.get("name").?.text);
    }

    {
        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createIndex("customer_id");
    }
    const withIndex = try client.tableJoin(allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, withIndex);
    try std.testing.expectEqual(@as(usize, 2), withIndex.len);
}

test "server table_join runs left, right, and full outer variants with predicates" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedJoinTables(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const left = try client.tableJoin(allocator, .left, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, left);
    try std.testing.expectEqual(@as(usize, 4), left.len);
    var carolUnmatched = false;
    for (left) |p| {
        if (p.left) |l| {
            if (std.mem.eql(u8, l.get("name").?.text, "carol")) {
                try std.testing.expect(p.right == null);
                carolUnmatched = true;
            }
        }
    }
    try std.testing.expect(carolUnmatched);

    const right = try client.tableJoin(allocator, .right, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, right);
    try std.testing.expectEqual(@as(usize, 3), right.len);
    var orphanOrderUnmatched = false;
    for (right) |p| {
        if (p.left == null) orphanOrderUnmatched = true;
    }
    try std.testing.expect(orphanOrderUnmatched);

    const full = try client.tableJoin(allocator, .full, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, full);
    try std.testing.expectEqual(@as(usize, 5), full.len);

    const filtered = try client.tableJoin(allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "total gt i:40");
    defer protocol.freeJoinPairs(allocator, filtered);
    try std.testing.expectEqual(@as(usize, 1), filtered.len);
    try std.testing.expectEqual(@as(i64, 50), filtered[0].right.?.get("total").?.int);
}

test "server table_join windows a real TCP result through offset and limit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedJoinTables(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const unpaged = try client.tableJoin(allocator, .left, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, unpaged);
    try std.testing.expectEqual(@as(usize, 4), unpaged.len);

    const windowed = try client.tableJoin(allocator, .left, "customers", querymod.pkField, "orders", "customer_id", 1, 2, "", "");
    defer protocol.freeJoinPairs(allocator, windowed);
    try std.testing.expectEqual(@as(usize, 2), windowed.len);
    try std.testing.expectEqual(@as(i64, 30), windowed[0].right.?.get("total").?.int);
    try std.testing.expectEqualStrings("bob", windowed[1].left.?.get("name").?.text);
    try std.testing.expect(windowed[1].right == null);

    const pastEnd = try client.tableJoin(allocator, .left, "customers", querymod.pkField, "orders", "customer_id", 50, 0, "", "");
    defer protocol.freeJoinPairs(allocator, pastEnd);
    try std.testing.expectEqual(@as(usize, 0), pastEnd.len);
}

test "server table_join rejects a malformed expr with bad_request, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    try seedJoinTables(allocator, &db);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const err = client.tableJoin(allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "name bogus s:alice", "");
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

test "table_select survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    const rowCount = 30;
    {
        var table = try querymod.Table.open(&db, allocator, "people");
        defer table.deinit();
        var pk: i64 = 1;
        while (pk <= rowCount) : (pk += 1) {
            const city: []const u8 = switch (@mod(pk, 3)) {
                0 => "warsaw",
                1 => "krakow",
                else => "gdansk",
            };
            try table.put(.{ .int = pk }, &.{
                .{ .name = "city", .value = .{ .text = city } },
                .{ .name = "age", .value = .{ .int = pk * 2 } },
            });
        }
        try db.flush();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 40;
    const mutatorThreads = 2;
    const mutatorIters = 15;

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const cityOrderBy = [_]querymod.OrderBy{
        .{ .field = "city" },
        .{ .field = "age", .descending = true },
    };

    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                const warsawRows = client.tableSelect(ctx.allocator, "people", "city eq s:warsaw", 0, 0, &.{}) catch return;
                defer protocol.freeRows(ctx.allocator, warsawRows);
                if (warsawRows.len != rowCount / 3) return;

                const allRows = client.tableSelect(ctx.allocator, "people", "", 0, 0, &.{}) catch return;
                defer protocol.freeRows(ctx.allocator, allRows);
                if (allRows.len != rowCount) return;
                for (allRows) |row| {
                    const pk = row.get(querymod.pkField) orelse return;
                    const age = row.get("age") orelse return;
                    if (age.int != pk.int * 2) return;
                }

                const ordered = client.tableSelect(ctx.allocator, "people", "", 0, 0, &cityOrderBy) catch return;
                defer protocol.freeRows(ctx.allocator, ordered);
                if (ordered.len != rowCount) return;
                var prevCity: ?[]const u8 = null;
                var prevAge: i64 = std.math.maxInt(i64);
                for (ordered) |row| {
                    const city = (row.get("city") orelse return).text;
                    const age = (row.get("age") orelse return).int;
                    if (prevCity) |pc| {
                        const cmp = std.mem.order(u8, pc, city);
                        if (cmp == .gt) return;
                        if (cmp == .eq and age > prevAge) return;
                        if (cmp != .eq) prevAge = std.math.maxInt(i64);
                    }
                    prevCity = city;
                    prevAge = age;
                }
            }
            ctx.ok = true;
        }
    }.run;

    const MutatorCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const mutatorWorker = struct {
        fn run(ctx: *MutatorCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < mutatorIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var mutatorContexts: [mutatorThreads]MutatorCtx = undefined;
    var mutatorHandles: [mutatorThreads]std.Thread = undefined;
    for (0..mutatorThreads) |i| {
        mutatorContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        mutatorHandles[i] = try std.Thread.spawn(.{}, mutatorWorker, .{&mutatorContexts[i]});
    }

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..mutatorThreads) |i| mutatorHandles[i].join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..mutatorThreads) |i| try std.testing.expect(mutatorContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const finalAll = try client.tableSelect(allocator, "people", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, finalAll);
    try std.testing.expectEqual(@as(usize, rowCount), finalAll.len);
    const finalWarsaw = try client.tableSelect(allocator, "people", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, finalWarsaw);
    try std.testing.expectEqual(@as(usize, rowCount / 3), finalWarsaw.len);

    const finalOrdered = try client.tableSelect(allocator, "people", "", 0, 0, &cityOrderBy);
    defer protocol.freeRows(allocator, finalOrdered);
    try std.testing.expectEqual(@as(usize, rowCount), finalOrdered.len);
    try std.testing.expectEqualStrings("gdansk", finalOrdered[0].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 29), finalOrdered[0].get(querymod.pkField).?.int);
    try std.testing.expectEqualStrings("gdansk", finalOrdered[9].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 2), finalOrdered[9].get(querymod.pkField).?.int);
    try std.testing.expectEqualStrings("krakow", finalOrdered[10].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 28), finalOrdered[10].get(querymod.pkField).?.int);
    try std.testing.expectEqualStrings("krakow", finalOrdered[19].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 1), finalOrdered[19].get(querymod.pkField).?.int);
    try std.testing.expectEqualStrings("warsaw", finalOrdered[20].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 30), finalOrdered[20].get(querymod.pkField).?.int);
    try std.testing.expectEqualStrings("warsaw", finalOrdered[29].get("city").?.text);
    try std.testing.expectEqual(@as(i64, 3), finalOrdered[29].get(querymod.pkField).?.int);
}

fn seedJoinConcurrencyTables(allocator: Allocator, db: *Db) !void {
    var customers = try querymod.Table.open(db, allocator, "customers");
    defer customers.deinit();
    var pk: i64 = 1;
    while (pk <= 10) : (pk += 1) {
        var buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "cust{d}", .{pk});
        try customers.put(.{ .int = pk }, &.{.{ .name = "name", .value = .{ .text = name } }});
    }

    var orders = try querymod.Table.open(db, allocator, "orders");
    defer orders.deinit();
    pk = 1;
    while (pk <= 8) : (pk += 1) {
        try orders.put(.{ .int = pk }, &.{
            .{ .name = "customer_id", .value = .{ .int = pk } },
            .{ .name = "total", .value = .{ .int = pk * 10 } },
        });
    }
    try orders.put(.{ .int = 9 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 999 } },
        .{ .name = "total", .value = .{ .int = 900 } },
    });
    try orders.put(.{ .int = 10 }, &.{
        .{ .name = "customer_id", .value = .{ .int = 998 } },
        .{ .name = "total", .value = .{ .int = 800 } },
    });
}

test "table_join survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();
    try seedJoinConcurrencyTables(allocator, &db);
    try db.flush();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const readerThreads = 4;
    const readerIters = 20;
    const mutatorThreads = 2;
    const mutatorIters = 15;
    const matchedCount = 8;
    const customerCount = 10;

    const ReaderCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };
    const readerWorker = struct {
        fn run(ctx: *ReaderCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readerIters) : (i += 1) {
                const inner = client.tableJoin(ctx.allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "") catch return;
                defer protocol.freeJoinPairs(ctx.allocator, inner);
                if (inner.len != matchedCount) return;
                for (inner) |pair| {
                    const left = pair.left orelse return;
                    const right = pair.right orelse return;
                    const pk = left.get(querymod.pkField) orelse return;
                    const total = right.get("total") orelse return;
                    if (total.int != pk.int * 10) return;
                }

                const left = client.tableJoin(ctx.allocator, .left, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "") catch return;
                defer protocol.freeJoinPairs(ctx.allocator, left);
                if (left.len != customerCount) return;

                const right = client.tableJoin(ctx.allocator, .right, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "") catch return;
                defer protocol.freeJoinPairs(ctx.allocator, right);
                if (right.len != matchedCount + 2) return;

                const full = client.tableJoin(ctx.allocator, .full, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "") catch return;
                defer protocol.freeJoinPairs(ctx.allocator, full);
                if (full.len != customerCount + 2) return;
            }
            ctx.ok = true;
        }
    }.run;

    const MutatorCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };
    const mutatorWorker = struct {
        fn run(ctx: *MutatorCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < mutatorIters) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "join-churn-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "x") catch return;
                client.flush() catch return;
                client.compact() catch return;
            }
            ctx.ok = true;
        }
    }.run;

    var readerContexts: [readerThreads]ReaderCtx = undefined;
    var readerHandles: [readerThreads]std.Thread = undefined;
    for (0..readerThreads) |i| {
        readerContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readerHandles[i] = try std.Thread.spawn(.{}, readerWorker, .{&readerContexts[i]});
    }
    var mutatorContexts: [mutatorThreads]MutatorCtx = undefined;
    var mutatorHandles: [mutatorThreads]std.Thread = undefined;
    for (0..mutatorThreads) |i| {
        mutatorContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        mutatorHandles[i] = try std.Thread.spawn(.{}, mutatorWorker, .{&mutatorContexts[i]});
    }

    for (0..readerThreads) |i| readerHandles[i].join();
    for (0..mutatorThreads) |i| mutatorHandles[i].join();
    for (0..readerThreads) |i| try std.testing.expect(readerContexts[i].ok);
    for (0..mutatorThreads) |i| try std.testing.expect(mutatorContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const finalInner = try client.tableJoin(allocator, .inner, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, finalInner);
    try std.testing.expectEqual(@as(usize, matchedCount), finalInner.len);
    const finalFull = try client.tableJoin(allocator, .full, "customers", querymod.pkField, "orders", "customer_id", 0, 0, "", "");
    defer protocol.freeJoinPairs(allocator, finalFull);
    try std.testing.expectEqual(@as(usize, customerCount + 2), finalFull.len);
}

test "server without enableAuth accepts any auth attempt and every op" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.authenticate("nobody", "wrong");
    try client.set("k", "v");
}

test "server with auth enabled rejects unauthenticated requests, ping excepted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.ping();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.get(allocator, "k"));
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.set("k", "v"));
    try std.testing.expectEqual(@as(u64, 2), server.unauthorizedTotal.get());
}

test "server rejects a bad password and accepts the correct one, then serves requests" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.authenticate("alice", "wrong"));
    try client.authenticate("alice", "hunter2");

    try client.set("k", "v");
    const got = try client.get(allocator, "k");
    defer if (got) |g| allocator.free(g);
    try std.testing.expectEqualStrings("v", got.?);
}

test "server enforces readonly role: reads succeed, writes are forbidden" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "viewer", "pass", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.authenticate("viewer", "pass");
    const got = try client.get(allocator, "missing");
    try std.testing.expect(got == null);
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, client.set("k", "v"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, client.delete("k"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, client.compact());
    const txnEntries = [_]protocol.TxnOpEntry{
        .{ .verb = .put, .table = "accounts", .pk = .{ .int = 1 } },
    };
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, client.txnOp(&txnEntries));
    try std.testing.expectEqual(@as(u64, 4), server.forbiddenTotal.get());
}

test "server without enableSessions returns no token from authenticate" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.authenticate("alice", "hunter2");
    try std.testing.expect(client.sessionToken() == null);
}

test "a session token from one connection authenticates a brand new connection without a password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    var sessions = sessionmod.SessionStore.init(allocator);
    defer sessions.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    server.enableSessions(&sessions, 60 * std.time.ns_per_s);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var first = try client_mod.Client.connect(allocator, server.boundAddress());
    try first.authenticate("alice", "hunter2");
    const token = try allocator.dupe(u8, first.sessionToken().?);
    defer allocator.free(token);
    first.close();

    var second = try client_mod.Client.connect(allocator, server.boundAddress());
    defer second.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, second.get(allocator, "k"));
    try second.authenticateWithToken(token);
    try second.set("k", "v");
    const got = try second.get(allocator, "k");
    defer if (got) |g| allocator.free(g);
    try std.testing.expectEqualStrings("v", got.?);
}

test "auth_token is rejected as unauthorized when sessions are not enabled" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.authenticateWithToken("whatever"));
}

test "an unknown or garbage session token is rejected" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    var sessions = sessionmod.SessionStore.init(allocator);
    defer sessions.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    server.enableSessions(&sessions, 60 * std.time.ns_per_s);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.authenticateWithToken("not-a-real-token"));
}

test "an expired session forces re-authentication even on the same open connection" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    var sessions = sessionmod.SessionStore.init(allocator);
    defer sessions.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    server.enableSessions(&sessions, 500 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.authenticate("alice", "hunter2");
    try client.set("k", "v");

    std.time.sleep(700 * std.time.ns_per_ms);
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, client.get(allocator, "k"));
    try std.testing.expectEqual(@as(u64, 1), server.sessionExpiredTotal.get());

    try client.authenticate("alice", "hunter2");
    const got = try client.get(allocator, "k");
    defer if (got) |g| allocator.free(g);
    try std.testing.expectEqualStrings("v", got.?);
}

test "each connection authenticates independently under auth enforcement" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var clientA = try client_mod.Client.connect(allocator, server.boundAddress());
    defer clientA.close();
    var clientB = try client_mod.Client.connect(allocator, server.boundAddress());
    defer clientB.close();

    try clientA.authenticate("alice", "hunter2");
    try clientA.set("shared", "1");

    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, clientB.get(allocator, "shared"));
}

test "server without auth enabled allows user_admin to create and list users" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.adminCreateUser("alice", "hunter2", .readwrite, 16);
    const users = try client.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, users);
    try std.testing.expectEqual(@as(usize, 1), users.len);
    try std.testing.expectEqualStrings("alice", users[0].username);
    try std.testing.expectEqual(authmod.Role.readwrite, users[0].role);

    var second = try client_mod.Client.connect(allocator, server.boundAddress());
    defer second.close();
    try second.authenticate("alice", "hunter2");
}

test "user_admin requires admin role once auth is enabled" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "root", "toor", .admin, 16);
    try store.createUser(allocator, "viewer", "pass", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var viewer = try client_mod.Client.connect(allocator, server.boundAddress());
    defer viewer.close();
    try viewer.authenticate("viewer", "pass");
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, viewer.adminCreateUser("nobody", "x", .readonly, 16));

    var admin = try client_mod.Client.connect(allocator, server.boundAddress());
    defer admin.close();
    try admin.authenticate("root", "toor");
    try admin.adminCreateUser("bob", "b-pass", .readwrite, 16);

    const users = try admin.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, users);
    try std.testing.expectEqual(@as(usize, 3), users.len);
}

test "user_admin set_password, set_role, and delete round trip over the wire, enforced by real auth" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "root", "toor", .admin, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var admin = try client_mod.Client.connect(allocator, server.boundAddress());
    defer admin.close();
    try admin.authenticate("root", "toor");

    try admin.adminCreateUser("alice", "old-pass", .readonly, 16);

    var probe = try client_mod.Client.connect(allocator, server.boundAddress());
    defer probe.close();
    try probe.authenticate("alice", "old-pass");

    try admin.adminSetPassword("alice", "new-pass", 16);
    var probe2 = try client_mod.Client.connect(allocator, server.boundAddress());
    defer probe2.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, probe2.authenticate("alice", "old-pass"));
    try probe2.authenticate("alice", "new-pass");

    try admin.adminSetRole("alice", .admin);
    const users = try admin.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, users);
    var sawAlice = false;
    for (users) |u| {
        if (std.mem.eql(u8, u.username, "alice")) {
            try std.testing.expectEqual(authmod.Role.admin, u.role);
            sawAlice = true;
        }
    }
    try std.testing.expect(sawAlice);

    try admin.adminDeleteUser("alice");
    var probe3 = try client_mod.Client.connect(allocator, server.boundAddress());
    defer probe3.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, probe3.authenticate("alice", "new-pass"));
}

test "user_admin reports conflict on duplicate create and not-found on missing user" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.adminCreateUser("alice", "hunter2", .readonly, 16);
    try std.testing.expectError(client_mod.ClientError.ServerConflict, client.adminCreateUser("alice", "other", .admin, 16));
    try std.testing.expectError(client_mod.ClientError.ServerUserNotFound, client.adminSetPassword("ghost", "x", 16));
    try std.testing.expectError(client_mod.ClientError.ServerUserNotFound, client.adminSetRole("ghost", .admin));
    try std.testing.expectError(client_mod.ClientError.ServerUserNotFound, client.adminDeleteUser("ghost"));
}

test "server rejects a malformed user_admin frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.user_admin), "\x00");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);
}

test "server metrics register into an external Prometheus registry" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableRateLimit(1, 1000);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    try client.ping();
    client.ping() catch {};

    var reg = metrics.Registry.init(allocator);
    defer reg.deinit();
    try server.registerMetrics(&reg);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try reg.exportText(allocator, buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_requests_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_rate_limited_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_conn_rate_limited_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_unauthorized_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_forbidden_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_session_expired_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_sessions_swept_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "cobalt_server_ttl_swept_total 0\n") != null);
}

test "client.metricsText fetches the server's own counters and db stats over the wire in one payload" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("a", "1");
    try client.set("b", "2");
    try client.ping();

    const text = try client.metricsText(allocator);
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_server_requests_total 4\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_server_rate_limited_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_memtable_entries 2\n") != null);
}

test "server gates the metrics opcode behind readonly role like every other read op" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "reader", "pw", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var unauthed = try client_mod.Client.connect(allocator, server.boundAddress());
    defer unauthed.close();
    try std.testing.expectError(error.ServerUnauthorized, unauthed.metricsText(allocator));

    var reader = try client_mod.Client.connect(allocator, server.boundAddress());
    defer reader.close();
    try reader.authenticate("reader", "pw");
    const text = try reader.metricsText(allocator);
    allocator.free(text);
}

test "enableSessionSweep periodically drops expired sessions nobody ever presents again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    var sessions = sessionmod.SessionStore.init(allocator);
    defer sessions.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    server.enableSessions(&sessions, 100 * std.time.ns_per_ms);
    server.enableSessionSweep(50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    try client.authenticate("alice", "hunter2");
    client.close();

    try std.testing.expectEqual(@as(usize, 1), sessions.count());

    std.time.sleep(400 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(usize, 0), sessions.count());
    try std.testing.expect(server.sessionsSweptTotal.get() >= 1);
}

test "a server with sessions enabled but no sweep interval never sweeps" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    var sessions = sessionmod.SessionStore.init(allocator);
    defer sessions.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    server.enableSessions(&sessions, 50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    try client.authenticate("alice", "hunter2");
    client.close();

    std.time.sleep(200 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(usize, 1), sessions.count());
    try std.testing.expectEqual(@as(u64, 0), server.sessionsSweptTotal.get());
}

test "ttl_op over the wire: expire, query, persist, and sweep round trip against a real server" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("plain", "v");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.ttlQuery("plain"));

    try std.testing.expectError(client_mod.ClientError.ServerKeyNotFound, client.ttlExpire("ghost", 60));

    try client.ttlExpire("plain", 60);
    const withTtl = try client.ttlQuery("plain");
    try std.testing.expect(withTtl.seconds == 59 or withTtl.seconds == 60);

    try client.ttlPersist("plain");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.ttlQuery("plain"));

    try client.set("doomed", "x");
    try client.ttlExpire("doomed", 0);
    std.time.sleep(5 * std.time.ns_per_ms);
    const reaped = try client.ttlSweep();
    try std.testing.expectEqual(@as(u64, 1), reaped);
    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "doomed"));

    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("never-existed"));
}

test "del and batched del over the wire drop the key's ttl marker together with the key" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("single", "v");
    try client.ttlExpire("single", 3600);
    try client.set("batched", "v");
    try client.ttlExpire("batched", 3600);

    try client.delete("single");
    const ops = [_]protocol.BatchOp{.{ .del = "batched" }};
    try client.batch(&ops);

    for ([_][]const u8{ "single", "batched" }) |key| {
        try std.testing.expectEqual(@as(?[]u8, null), try db.get(allocator, key));
        try std.testing.expectEqual(@as(?i128, null), try ttlmod.getExpiresAt(&db, allocator, key));
    }
}

test "get, scan and prefix over the wire treat a key past its ttl as missing, like the cli" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("gone", "stale");
    try client.ttlExpire("gone", 0);
    try client.set("kept", "fresh");
    try client.ttlExpire("kept", 60);
    try client.set("plain", "forever");
    std.time.sleep(5 * std.time.ns_per_ms);

    const scanned = try client.scan(allocator, .{});
    defer protocol.freeOwnedEntries(allocator, scanned);
    try std.testing.expectEqual(@as(usize, 2), scanned.len);
    try std.testing.expectEqualStrings("kept", scanned[0].key);
    try std.testing.expectEqualStrings("plain", scanned[1].key);

    const reversed = try client.scan(allocator, .{ .reverse = true });
    defer protocol.freeOwnedEntries(allocator, reversed);
    try std.testing.expectEqual(@as(usize, 2), reversed.len);
    try std.testing.expectEqualStrings("plain", reversed[0].key);
    try std.testing.expectEqualStrings("kept", reversed[1].key);

    const limited = try client.scan(allocator, .{ .limit = 1 });
    defer protocol.freeOwnedEntries(allocator, limited);
    try std.testing.expectEqual(@as(usize, 1), limited.len);
    try std.testing.expectEqualStrings("kept", limited[0].key);

    const prefixed = try client.prefix(allocator, "g", 0);
    defer protocol.freeOwnedEntries(allocator, prefixed);
    try std.testing.expectEqual(@as(usize, 0), prefixed.len);

    const everything = try client.prefix(allocator, "", 0);
    defer protocol.freeOwnedEntries(allocator, everything);
    try std.testing.expectEqual(@as(usize, 2), everything.len);

    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "gone"));
    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("gone"));

    const kept = (try client.get(allocator, "kept")).?;
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("fresh", kept);
}

test "set and batch over the wire drop any ttl, and expire and ttl treat an expired unswept key as missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    for ([_][]const u8{ "dead", "rewritten", "batched" }) |key| {
        try client.set(key, "old");
        try client.ttlExpire(key, 0);
    }
    try client.set("live", "old");
    try client.ttlExpire("live", 600);

    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("dead"));
    try std.testing.expectError(client_mod.ClientError.ServerKeyNotFound, client.ttlExpire("dead", 600));
    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("dead"));
    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "dead"));

    try client.set("rewritten", "new");
    try client.set("live", "new");
    const ops = [_]protocol.BatchOp{
        .{ .put = .{ .key = "batched", .value = "new" } },
        .{ .put = .{ .key = "plain", .value = "new" } },
    };
    try client.batch(&ops);

    for ([_][]const u8{ "rewritten", "live", "batched", "plain" }) |key| {
        try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.ttlQuery(key));
        const value = (try client.get(allocator, key)).?;
        defer allocator.free(value);
        try std.testing.expectEqualStrings("new", value);
    }
    try std.testing.expectEqual(@as(u64, 0), try client.ttlSweep());
}

test "ttl_op gates query as readonly and expire as readwrite" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "reader", "pw", .readonly, 16);
    try store.createUser(allocator, "writer", "pw", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var writer = try client_mod.Client.connect(allocator, server.boundAddress());
    defer writer.close();
    try writer.authenticate("writer", "pw");
    try writer.set("k", "v");

    var reader = try client_mod.Client.connect(allocator, server.boundAddress());
    defer reader.close();
    try reader.authenticate("reader", "pw");

    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try reader.ttlQuery("k"));

    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlExpire("k", 30));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlPersist("k"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlSweep());

    try writer.ttlExpire("k", 30);
    try writer.ttlPersist("k");
    _ = try writer.ttlSweep();
}

test "server rejects a malformed ttl_op frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ttl_op), "\x09");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);
}

test "enableTtlSweep periodically reaps due keys nobody ever reads again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableTtlSweep(50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("a", "1");
    try client.ttlExpire("a", 0);

    std.time.sleep(300 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "a"));
    try std.testing.expect(server.ttlSweptTotal.get() >= 1);
}

test "a server with no ttl sweep interval never runs the ttl sweeper" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("a", "1");
    try client.ttlExpire("a", 0);
    std.time.sleep(100 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(u64, 0), server.ttlSweptTotal.get());
    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("a"));
}

test "coll_ttl_op over the wire: expire, query, persist, and sweep round trip against a real server" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    _ = try collmod.Hash.set(&db, allocator, "profile", "name", "ada");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.collTtlQuery(.hash, "profile"));

    try std.testing.expectError(client_mod.ClientError.ServerCollectionNotFound, client.collTtlExpire(.hash, "ghost", 60));

    try client.collTtlExpire(.hash, "profile", 60);
    const withTtl = try client.collTtlQuery(.hash, "profile");
    try std.testing.expect(withTtl.seconds == 59 or withTtl.seconds == 60);

    try client.collTtlPersist(.hash, "profile");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.collTtlQuery(.hash, "profile"));

    _ = try collmod.Hash.set(&db, allocator, "doomed", "k", "v");
    try client.collTtlExpire(.hash, "doomed", 0);
    std.time.sleep(5 * std.time.ns_per_ms);
    const reaped = try client.collTtlSweep();
    try std.testing.expectEqual(@as(u64, 1), reaped);
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "doomed"));

    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.collTtlQuery(.set, "never-existed"));
}

test "coll_ttl_op gates query as readonly and expire as readwrite" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    _ = try collmod.Hash.set(&db, allocator, "k", "f", "v");

    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "reader", "pw", .readonly, 16);
    try store.createUser(allocator, "writer", "pw", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var writer = try client_mod.Client.connect(allocator, server.boundAddress());
    defer writer.close();
    try writer.authenticate("writer", "pw");

    var reader = try client_mod.Client.connect(allocator, server.boundAddress());
    defer reader.close();
    try reader.authenticate("reader", "pw");

    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try reader.collTtlQuery(.hash, "k"));

    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlExpire(.hash, "k", 30));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlPersist(.hash, "k"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlSweep());

    try writer.collTtlExpire(.hash, "k", 30);
    try writer.collTtlPersist(.hash, "k");
    _ = try writer.collTtlSweep();
}

test "server rejects a malformed coll_ttl_op frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.coll_ttl_op), "\x02");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);
}

test "enableCollTtlSweep periodically reaps due collections nobody ever touches again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableCollTtlSweep(50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    _ = try collmod.ZSet.add(&db, allocator, "board", "alice", 10);
    try client.collTtlExpire(.zset, "board", 0);

    std.time.sleep(300 * std.time.ns_per_ms);

    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .zset, "board"));
    try std.testing.expect(server.collTtlSweptTotal.get() >= 1);
}

test "a server with no coll ttl sweep interval never runs the coll ttl sweeper" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    _ = try collmod.Set.add(&db, allocator, "tags", "zig");
    try client.collTtlExpire(.set, "tags", 0);
    std.time.sleep(100 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(u64, 0), server.collTtlSweptTotal.get());
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "tags"));
}

test "a server with the flat ttl sweeper and the coll ttl sweeper enabled at once runs both independently" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableTtlSweep(50 * std.time.ns_per_ms);
    server.enableCollTtlSweep(50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try client.set("flatkey", "1");
    try client.ttlExpire("flatkey", 0);
    _ = try collmod.Hash.set(&db, allocator, "session:1", "user", "ada");
    try client.collTtlExpire(.hash, "session:1", 0);

    var waited: u64 = 0;
    while (waited < 3000 and (server.ttlSweptTotal.get() == 0 or server.collTtlSweptTotal.get() == 0)) {
        std.time.sleep(50 * std.time.ns_per_ms);
        waited += 50;
    }

    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "flatkey"));
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "session:1"));
    try std.testing.expect(server.ttlSweptTotal.get() >= 1);
    try std.testing.expect(server.collTtlSweptTotal.get() >= 1);

    try std.testing.expectEqual(@as(u64, 1), server.ttlSweptTotal.get());
    try std.testing.expectEqual(@as(u64, 1), server.collTtlSweptTotal.get());
}

test "coll_op over the wire exercises all five collection kinds against a real server" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    {
        var got = try client.collOp(allocator, .counter_get, "visits", &.{});
        defer got.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 0), got.int);

        var setReply = try client.collOp(allocator, .counter_set, "visits", &[_][]const u8{"10"});
        defer setReply.deinit(allocator);
        try std.testing.expect(setReply == .ok);

        var incrReply = try client.collOp(allocator, .counter_incrby, "visits", &[_][]const u8{"5"});
        defer incrReply.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 15), incrReply.int);
    }

    {
        var created = try client.collOp(allocator, .hash_set, "profile", &[_][]const u8{ "name", "ada" });
        defer created.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), created.int);

        var updated = try client.collOp(allocator, .hash_set, "profile", &[_][]const u8{ "name", "grace" });
        defer updated.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 0), updated.int);

        _ = try client.collOp(allocator, .hash_set, "profile", &[_][]const u8{ "age", "36" });

        var got = try client.collOp(allocator, .hash_get, "profile", &[_][]const u8{"name"});
        defer got.deinit(allocator);
        try std.testing.expectEqualStrings("grace", got.bytes);

        var missing = try client.collOp(allocator, .hash_get, "profile", &[_][]const u8{"ghost"});
        defer missing.deinit(allocator);
        try std.testing.expect(missing == .nil);

        var lenReply = try client.collOp(allocator, .hash_len, "profile", &.{});
        defer lenReply.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 2), lenReply.int);

        var delReply = try client.collOp(allocator, .hash_del, "profile", &[_][]const u8{"age"});
        defer delReply.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), delReply.int);

        var all = try client.collOp(allocator, .hash_getall, "profile", &.{});
        defer all.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), all.pairList.len);
        try std.testing.expectEqualStrings("name", all.pairList[0].field);
        try std.testing.expectEqualStrings("grace", all.pairList[0].value);
    }

    {
        _ = try client.collOp(allocator, .set_add, "a", &[_][]const u8{"x"});
        _ = try client.collOp(allocator, .set_add, "a", &[_][]const u8{"y"});
        _ = try client.collOp(allocator, .set_add, "b", &[_][]const u8{"y"});
        _ = try client.collOp(allocator, .set_add, "b", &[_][]const u8{"z"});

        var isMem = try client.collOp(allocator, .set_ismember, "a", &[_][]const u8{"x"});
        defer isMem.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), isMem.int);

        var card = try client.collOp(allocator, .set_card, "a", &.{});
        defer card.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 2), card.int);

        var inter = try client.collOp(allocator, .set_inter, "a", &[_][]const u8{"b"});
        defer inter.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), inter.stringList.len);
        try std.testing.expectEqualStrings("y", inter.stringList[0]);

        var uni = try client.collOp(allocator, .set_union, "a", &[_][]const u8{"b"});
        defer uni.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 3), uni.stringList.len);

        var diff = try client.collOp(allocator, .set_diff, "a", &[_][]const u8{"b"});
        defer diff.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), diff.stringList.len);
        try std.testing.expectEqualStrings("x", diff.stringList[0]);

        var rem = try client.collOp(allocator, .set_rem, "a", &[_][]const u8{"x"});
        defer rem.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), rem.int);
    }

    {
        _ = try client.collOp(allocator, .list_rpush, "queue", &[_][]const u8{"one"});
        _ = try client.collOp(allocator, .list_rpush, "queue", &[_][]const u8{"two"});
        _ = try client.collOp(allocator, .list_lpush, "queue", &[_][]const u8{"zero"});

        var ranged = try client.collOp(allocator, .list_range, "queue", &[_][]const u8{ "0", "-1" });
        defer ranged.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 3), ranged.stringList.len);
        try std.testing.expectEqualStrings("zero", ranged.stringList[0]);
        try std.testing.expectEqualStrings("two", ranged.stringList[2]);

        var popped = try client.collOp(allocator, .list_lpop, "queue", &.{});
        defer popped.deinit(allocator);
        try std.testing.expectEqualStrings("zero", popped.bytes);

        var lenReply = try client.collOp(allocator, .list_len, "queue", &.{});
        defer lenReply.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 2), lenReply.int);

        var emptyPop = try client.collOp(allocator, .list_rpop, "never-existed", &.{});
        defer emptyPop.deinit(allocator);
        try std.testing.expect(emptyPop == .nil);
    }

    {
        _ = try client.collOp(allocator, .zset_add, "board", &[_][]const u8{ "alice", "10.5" });
        _ = try client.collOp(allocator, .zset_add, "board", &[_][]const u8{ "bob", "20" });

        var score = try client.collOp(allocator, .zset_score, "board", &[_][]const u8{"alice"});
        defer score.deinit(allocator);
        try std.testing.expectEqual(@as(f64, 10.5), score.real);

        var incr = try client.collOp(allocator, .zset_incrby, "board", &[_][]const u8{ "alice", "1.5" });
        defer incr.deinit(allocator);
        try std.testing.expectEqual(@as(f64, 12.0), incr.real);

        var rank = try client.collOp(allocator, .zset_rank, "board", &[_][]const u8{"alice"});
        defer rank.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 0), rank.int);

        var byRank = try client.collOp(allocator, .zset_rangebyrank, "board", &[_][]const u8{ "0", "-1" });
        defer byRank.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), byRank.scorePairList.len);
        try std.testing.expectEqualStrings("alice", byRank.scorePairList[0].member);
        try std.testing.expectEqualStrings("bob", byRank.scorePairList[1].member);

        var byScore = try client.collOp(allocator, .zset_rangebyscore, "board", &[_][]const u8{ "15", "25" });
        defer byScore.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), byScore.scorePairList.len);
        try std.testing.expectEqualStrings("bob", byScore.scorePairList[0].member);

        var card = try client.collOp(allocator, .zset_card, "board", &.{});
        defer card.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 2), card.int);

        var removed = try client.collOp(allocator, .zset_rem, "board", &[_][]const u8{"bob"});
        defer removed.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), removed.int);
    }
}

test "coll_op survives many real concurrent connections hammering the same counter" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const threadCount = 8;
    const perThread = 50;

    const IncrCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };

    const incrWorker = struct {
        fn run(ctx: *IncrCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < perThread) : (i += 1) {
                var reply = client.collOp(ctx.allocator, .counter_incrby, "shared-counter", &[_][]const u8{"1"}) catch return;
                reply.deinit(ctx.allocator);
            }
            ctx.ok = true;
        }
    }.run;

    var incrContexts: [threadCount]IncrCtx = undefined;
    var incrThreads: [threadCount]std.Thread = undefined;
    for (0..threadCount) |i| {
        incrContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        incrThreads[i] = try std.Thread.spawn(.{}, incrWorker, .{&incrContexts[i]});
    }
    for (0..threadCount) |i| incrThreads[i].join();
    for (0..threadCount) |i| try std.testing.expect(incrContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    var total = try client.collOp(allocator, .counter_get, "shared-counter", &.{});
    defer total.deinit(allocator);
    try std.testing.expectEqual(@as(i64, threadCount * perThread), total.int);
}

test "coll_op survives many real concurrent connections adding disjoint members to the same set" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const threadCount = 8;
    const perThread = 50;

    const AddCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };

    const addWorker = struct {
        fn run(ctx: *AddCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < perThread) : (i += 1) {
                var buf: [32]u8 = undefined;
                const member = std.fmt.bufPrint(&buf, "t{d}-m{d}", .{ ctx.thread, i }) catch return;
                var reply = client.collOp(ctx.allocator, .set_add, "shared-set", &[_][]const u8{member}) catch return;
                reply.deinit(ctx.allocator);
            }
            ctx.ok = true;
        }
    }.run;

    var addContexts: [threadCount]AddCtx = undefined;
    var addThreads: [threadCount]std.Thread = undefined;
    for (0..threadCount) |i| {
        addContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        addThreads[i] = try std.Thread.spawn(.{}, addWorker, .{&addContexts[i]});
    }
    for (0..threadCount) |i| addThreads[i].join();
    for (0..threadCount) |i| try std.testing.expect(addContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    var card = try client.collOp(allocator, .set_card, "shared-set", &.{});
    defer card.deinit(allocator);
    try std.testing.expectEqual(@as(i64, threadCount * perThread), card.int);

    for (0..threadCount) |t| {
        var buf: [32]u8 = undefined;
        const member = try std.fmt.bufPrint(&buf, "t{d}-m0", .{t});
        var isMem = try client.collOp(allocator, .set_ismember, "shared-set", &[_][]const u8{member});
        defer isMem.deinit(allocator);
        try std.testing.expectEqual(@as(i64, 1), isMem.int);
    }
}

test "coll_op applies the same lazy-expiry check as coll_ttl_op before every dispatch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    _ = try collmod.Hash.set(&db, allocator, "session", "user", "ada");
    try client.collTtlExpire(.hash, "session", 0);
    std.time.sleep(5 * std.time.ns_per_ms);

    var got = try client.collOp(allocator, .hash_get, "session", &[_][]const u8{"user"});
    defer got.deinit(allocator);
    try std.testing.expect(got == .nil);
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "session"));
}

test "coll_op set_inter/union/diff lazily expire every extra set name, not just the first" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    _ = try collmod.Set.add(&db, allocator, "a", "x");
    _ = try collmod.Set.add(&db, allocator, "b", "x");
    try client.collTtlExpire(.set, "b", 0);
    std.time.sleep(5 * std.time.ns_per_ms);

    var inter = try client.collOp(allocator, .set_inter, "a", &[_][]const u8{"b"});
    defer inter.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), inter.stringList.len);
}

test "coll_op gates a read action as readonly and a write action as readwrite" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    _ = try collmod.Hash.set(&db, allocator, "k", "f", "v");

    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "reader", "pw", .readonly, 16);
    try store.createUser(allocator, "writer", "pw", .readwrite, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var writer = try client_mod.Client.connect(allocator, server.boundAddress());
    defer writer.close();
    try writer.authenticate("writer", "pw");

    var reader = try client_mod.Client.connect(allocator, server.boundAddress());
    defer reader.close();
    try reader.authenticate("reader", "pw");

    var got = try reader.collOp(allocator, .hash_get, "k", &[_][]const u8{"f"});
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("v", got.bytes);

    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collOp(allocator, .hash_set, "k", &[_][]const u8{ "f", "v2" }));

    var setReply = try writer.collOp(allocator, .hash_set, "k", &[_][]const u8{ "f", "v2" });
    defer setReply.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 0), setReply.int);
}

test "server rejects a malformed coll_op frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.coll_op), "\x00");
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);
}

test "server answers coll_op with bad_request when an action gets too few arguments" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, client.collOp(allocator, .counter_set, "n", &.{}));
}

test "ttl_op survives many real concurrent connections racing writes against sweeps" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const writerCount = 6;
    const perWriter = 40;
    const sweeperCount = 3;
    const sweepsPerSweeper = 200;

    const WriteCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };

    const writeWorker = struct {
        fn run(ctx: *WriteCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < perWriter) : (i += 1) {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "ttl-conc-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.set(key, "v") catch return;
                client.ttlExpire(key, 0) catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const SweepCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        reaped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        ok: bool = false,
    };

    const sweepWorker = struct {
        fn run(ctx: *SweepCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < sweepsPerSweeper) : (i += 1) {
                const n = client.ttlSweep() catch return;
                _ = ctx.reaped.fetchAdd(n, .monotonic);
            }
            ctx.ok = true;
        }
    }.run;

    var writeContexts: [writerCount]WriteCtx = undefined;
    var writeThreads: [writerCount]std.Thread = undefined;
    var sweepContexts: [sweeperCount]SweepCtx = undefined;
    var sweepThreads: [sweeperCount]std.Thread = undefined;

    for (0..sweeperCount) |i| {
        sweepContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        sweepThreads[i] = try std.Thread.spawn(.{}, sweepWorker, .{&sweepContexts[i]});
    }
    for (0..writerCount) |i| {
        writeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        writeThreads[i] = try std.Thread.spawn(.{}, writeWorker, .{&writeContexts[i]});
    }
    for (0..writerCount) |i| writeThreads[i].join();
    for (0..sweeperCount) |i| sweepThreads[i].join();
    for (0..writerCount) |i| try std.testing.expect(writeContexts[i].ok);
    for (0..sweeperCount) |i| try std.testing.expect(sweepContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const finalReaped = try client.ttlSweep();

    var total: u64 = finalReaped;
    for (0..sweeperCount) |i| total += sweepContexts[i].reaped.load(.monotonic);
    try std.testing.expectEqual(@as(u64, writerCount * perWriter), total);

    for (0..writerCount) |t| {
        var buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "ttl-conc-{d}-0", .{t});
        try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, key));
        try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery(key));
    }
}

test "coll_ttl_op survives many real concurrent connections racing writes against sweeps" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const writerCount = 6;
    const perWriter = 40;
    const sweeperCount = 3;
    const sweepsPerSweeper = 200;

    const WriteCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };

    const writeWorker = struct {
        fn run(ctx: *WriteCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < perWriter) : (i += 1) {
                var buf: [32]u8 = undefined;
                const name = std.fmt.bufPrint(&buf, "ttlcoll-conc-{d}-{d}", .{ ctx.thread, i }) catch return;
                var reply = client.collOp(ctx.allocator, .counter_incrby, name, &[_][]const u8{"1"}) catch return;
                reply.deinit(ctx.allocator);
                client.collTtlExpire(.counter, name, 0) catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const SweepCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        reaped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        ok: bool = false,
    };

    const sweepWorker = struct {
        fn run(ctx: *SweepCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < sweepsPerSweeper) : (i += 1) {
                const n = client.collTtlSweep() catch return;
                _ = ctx.reaped.fetchAdd(n, .monotonic);
            }
            ctx.ok = true;
        }
    }.run;

    var writeContexts: [writerCount]WriteCtx = undefined;
    var writeThreads: [writerCount]std.Thread = undefined;
    var sweepContexts: [sweeperCount]SweepCtx = undefined;
    var sweepThreads: [sweeperCount]std.Thread = undefined;

    for (0..sweeperCount) |i| {
        sweepContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        sweepThreads[i] = try std.Thread.spawn(.{}, sweepWorker, .{&sweepContexts[i]});
    }
    for (0..writerCount) |i| {
        writeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        writeThreads[i] = try std.Thread.spawn(.{}, writeWorker, .{&writeContexts[i]});
    }
    for (0..writerCount) |i| writeThreads[i].join();
    for (0..sweeperCount) |i| sweepThreads[i].join();
    for (0..writerCount) |i| try std.testing.expect(writeContexts[i].ok);
    for (0..sweeperCount) |i| try std.testing.expect(sweepContexts[i].ok);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const finalReaped = try client.collTtlSweep();

    var total: u64 = finalReaped;
    for (0..sweeperCount) |i| total += sweepContexts[i].reaped.load(.monotonic);
    try std.testing.expectEqual(@as(u64, writerCount * perWriter), total);

    for (0..writerCount) |t| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "ttlcoll-conc-{d}-0", .{t});
        try std.testing.expect(!try collmod.collectionExists(&db, allocator, .counter, name));
        try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.collTtlQuery(.counter, name));
    }
}

test "user_admin survives many real concurrent connections racing to create the same username" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const threadCount = 8;

    const CreateCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        created: bool = false,
        conflicted: bool = false,
        ok: bool = false,
    };

    const createWorker = struct {
        fn run(ctx: *CreateCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var buf: [16]u8 = undefined;
            const password = std.fmt.bufPrint(&buf, "pw-{d}", .{ctx.thread}) catch return;
            if (client.adminCreateUser("shared-user", password, .readwrite, 4)) |_| {
                ctx.created = true;
            } else |err| {
                if (err != client_mod.ClientError.ServerConflict) return;
                ctx.conflicted = true;
            }
            ctx.ok = true;
        }
    }.run;

    var contexts: [threadCount]CreateCtx = undefined;
    var threads: [threadCount]std.Thread = undefined;
    for (0..threadCount) |i| {
        contexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        threads[i] = try std.Thread.spawn(.{}, createWorker, .{&contexts[i]});
    }
    for (0..threadCount) |i| threads[i].join();

    var createdCount: usize = 0;
    var conflictedCount: usize = 0;
    for (0..threadCount) |i| {
        try std.testing.expect(contexts[i].ok);
        if (contexts[i].created) createdCount += 1;
        if (contexts[i].conflicted) conflictedCount += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), createdCount);
    try std.testing.expectEqual(@as(usize, threadCount - 1), conflictedCount);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const users = try client.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, users);
    try std.testing.expectEqual(@as(usize, 1), users.len);
    try std.testing.expectEqualStrings("shared-user", users[0].username);
}

test "user_admin survives many real concurrent connections mutating and listing the same account" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");

    var setup = try client_mod.Client.connect(allocator, server.boundAddress());
    defer setup.close();
    try setup.adminCreateUser("shared-admin", "init-pw", .readonly, 4);

    const writerCount = 6;
    const perWriter = 40;
    const readerCount = 3;
    const readsPerReader = 200;

    const WriteCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: usize,
        ok: bool = false,
    };

    const writeWorker = struct {
        fn run(ctx: *WriteCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < perWriter) : (i += 1) {
                var buf: [32]u8 = undefined;
                const password = std.fmt.bufPrint(&buf, "pw-{d}-{d}", .{ ctx.thread, i }) catch return;
                client.adminSetPassword("shared-admin", password, 4) catch return;
                const role: authmod.Role = if (i % 2 == 0) .readwrite else .readonly;
                client.adminSetRole("shared-admin", role) catch return;
            }
            ctx.ok = true;
        }
    }.run;

    const ReadCtx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        ok: bool = false,
    };

    const readWorker = struct {
        fn run(ctx: *ReadCtx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var i: usize = 0;
            while (i < readsPerReader) : (i += 1) {
                const users = client.adminListUsers(ctx.allocator) catch return;
                defer authmod.freeUserList(ctx.allocator, users);
                if (users.len != 1) return;
                if (!std.mem.eql(u8, users[0].username, "shared-admin")) return;
            }
            ctx.ok = true;
        }
    }.run;

    var writeContexts: [writerCount]WriteCtx = undefined;
    var writeThreads: [writerCount]std.Thread = undefined;
    var readContexts: [readerCount]ReadCtx = undefined;
    var readThreads: [readerCount]std.Thread = undefined;

    for (0..readerCount) |i| {
        readContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress() };
        readThreads[i] = try std.Thread.spawn(.{}, readWorker, .{&readContexts[i]});
    }
    for (0..writerCount) |i| {
        writeContexts[i] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = i };
        writeThreads[i] = try std.Thread.spawn(.{}, writeWorker, .{&writeContexts[i]});
    }
    for (0..writerCount) |i| writeThreads[i].join();
    for (0..readerCount) |i| readThreads[i].join();
    for (0..writerCount) |i| try std.testing.expect(writeContexts[i].ok);
    for (0..readerCount) |i| try std.testing.expect(readContexts[i].ok);

    try setup.adminSetPassword("shared-admin", "final-known-pw", 4);
    try setup.adminSetRole("shared-admin", .admin);

    const store = authmod.Store.init(&db);
    const role = try store.verify(allocator, "shared-admin", "final-known-pw");
    try std.testing.expectEqual(authmod.Role.admin, role);

    const finalUsers = try setup.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, finalUsers);
    try std.testing.expectEqual(@as(usize, 1), finalUsers.len);
    try std.testing.expectEqual(authmod.Role.admin, finalUsers[0].role);
}

test "server txn_op commits put and del atomically across two tables, keeping an index in sync" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var accounts = try querymod.Table.open(&db, allocator, "accounts");
        defer accounts.deinit();
        try accounts.put(.{ .int = 1 }, &.{.{ .name = "balance", .value = .{ .int = 100 } }});
        try accounts.put(.{ .int = 2 }, &.{.{ .name = "balance", .value = .{ .int = 5 } }});

        var people = try querymod.Table.open(&db, allocator, "people");
        defer people.deinit();
        try people.createIndex("city");
        try people.put(.{ .int = 10 }, &.{.{ .name = "city", .value = .{ .text = "warsaw" } }});
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const peopleFields = [_]rowmod.Field{.{ .name = "city", .value = .{ .text = "warsaw" } }};
    const entries = [_]protocol.TxnOpEntry{
        .{ .verb = .put, .table = "accounts", .pk = .{ .int = 2 }, .fields = &.{.{ .name = "balance", .value = .{ .int = 999 } }} },
        .{ .verb = .put, .table = "people", .pk = .{ .int = 11 }, .fields = &peopleFields },
        .{ .verb = .del, .table = "accounts", .pk = .{ .int = 1 } },
    };
    const applied = try client.txnOp(&entries);
    try std.testing.expectEqual(@as(u32, 3), applied);

    var accounts = try querymod.Table.open(&db, allocator, "accounts");
    defer accounts.deinit();
    try std.testing.expect((try accounts.get(.{ .int = 1 })) == null);
    var row2 = (try accounts.get(.{ .int = 2 })).?;
    defer row2.deinit();
    try std.testing.expectEqual(@as(i64, 999), row2.get("balance").?.int);

    var people = try querymod.Table.open(&db, allocator, "people");
    defer people.deinit();
    const warsaw = try people.select(.{ .eq = .{ .field = "city", .value = .{ .text = "warsaw" } } });
    defer querymod.freeRows(allocator, warsaw);
    try std.testing.expectEqual(@as(usize, 2), warsaw.len);
}

test "server txn_op rejects a CHECK constraint violation over the wire and commits nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createCheckConstraint("qty_positive", "qty gt i:0");
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const entries = [_]protocol.TxnOpEntry{
        .{ .verb = .put, .table = "orders", .pk = .{ .int = 1 }, .fields = &.{.{ .name = "qty", .value = .{ .int = 5 } }} },
        .{ .verb = .put, .table = "orders", .pk = .{ .int = 2 }, .fields = &.{.{ .name = "qty", .value = .{ .int = -1 } }} },
    };
    try std.testing.expectError(client_mod.ClientError.ServerInternal, client.txnOp(&entries));

    var orders = try querymod.Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try std.testing.expect((try orders.get(.{ .int = 1 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 2 })) == null);
}

test "server txn_op rejects an ON DELETE RESTRICT violation over the wire, seeing a child staged earlier in the same batch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var customers = try querymod.Table.open(&db, allocator, "customers");
        defer customers.deinit();
        try customers.put(.{ .int = 1 }, &.{});

        var orders = try querymod.Table.open(&db, allocator, "orders");
        defer orders.deinit();
        try orders.createForeignKey("customer_id", "customers", querymod.pkField, .restrict);
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    const entries = [_]protocol.TxnOpEntry{
        .{ .verb = .put, .table = "orders", .pk = .{ .int = 100 }, .fields = &.{.{ .name = "customer_id", .value = .{ .int = 1 } }} },
        .{ .verb = .del, .table = "customers", .pk = .{ .int = 1 } },
    };
    try std.testing.expectError(client_mod.ClientError.ServerInternal, client.txnOp(&entries));

    var orders = try querymod.Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try std.testing.expect((try orders.get(.{ .int = 100 })) == null);

    var customers = try querymod.Table.open(&db, allocator, "customers");
    defer customers.deinit();
    var stillThere = (try customers.get(.{ .int = 1 })).?;
    stillThere.deinit();
}

test "server txn_op rejects an empty operation list with bad_request" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, client.txnOp(&.{}));
}

test "server rejects a malformed txn_op frame with bad_request without crashing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const stream = try std.net.tcpConnectToAddress(server.boundAddress());
    defer stream.close();

    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, 1, .little);
    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.txn_op), &payload);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

test "server txn_op survives many real concurrent connections writing disjoint rows across two tables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    {
        var widgets = try querymod.Table.open(&db, allocator, "widgets");
        defer widgets.deinit();
        try widgets.createIndex("owner");
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    const threadCount = 6;
    const perThread = 40;

    const Ctx = struct {
        allocator: Allocator,
        addr: std.net.Address,
        thread: i64,
        ok: bool = false,
    };

    const worker = struct {
        fn run(ctx: *Ctx) void {
            var client = client_mod.Client.connect(ctx.allocator, ctx.addr) catch return;
            defer client.close();
            var buf: [32]u8 = undefined;
            var i: i64 = 0;
            while (i < perThread) : (i += 1) {
                const ownerTag = std.fmt.bufPrint(&buf, "owner-{d}", .{ctx.thread}) catch return;
                const widgetPk: i64 = ctx.thread * 1_000_000 + i;
                const entries = [_]protocol.TxnOpEntry{
                    .{ .verb = .put, .table = "widgets", .pk = .{ .int = widgetPk }, .fields = &.{.{ .name = "owner", .value = .{ .text = ownerTag } }} },
                    .{ .verb = .put, .table = "tags", .pk = .{ .int = widgetPk }, .fields = &.{.{ .name = "seq", .value = .{ .int = i } }} },
                };
                const applied = client.txnOp(&entries) catch return;
                if (applied != 2) return;
            }
            ctx.ok = true;
        }
    }.run;

    var contexts: [threadCount]Ctx = undefined;
    var threads: [threadCount]std.Thread = undefined;
    for (0..threadCount) |t| {
        contexts[t] = .{ .allocator = allocator, .addr = server.boundAddress(), .thread = @intCast(t) };
        threads[t] = try std.Thread.spawn(.{}, worker, .{&contexts[t]});
    }
    for (0..threadCount) |t| threads[t].join();
    for (0..threadCount) |t| try std.testing.expect(contexts[t].ok);

    var widgets = try querymod.Table.open(&db, allocator, "widgets");
    defer widgets.deinit();
    var tags = try querymod.Table.open(&db, allocator, "tags");
    defer tags.deinit();

    var total: usize = 0;
    for (0..threadCount) |t| {
        var buf: [32]u8 = undefined;
        const ownerTag = try std.fmt.bufPrint(&buf, "owner-{d}", .{t});
        const owned = try widgets.select(.{ .eq = .{ .field = "owner", .value = .{ .text = ownerTag } } });
        defer querymod.freeRows(allocator, owned);
        try std.testing.expectEqual(@as(usize, perThread), owned.len);
        total += owned.len;
    }
    try std.testing.expectEqual(@as(usize, threadCount * perThread), total);

    const allTags = try tags.select(null);
    defer querymod.freeRows(allocator, allTags);
    try std.testing.expectEqual(@as(usize, threadCount * perThread), allTags.len);
}

test "server delivers a published message to a subscriber over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    defer sub.close();
    _ = try sub.subscribe(&.{"weather"});

    var pub_ = try client_mod.Client.connect(allocator, server.boundAddress());
    defer pub_.close();
    const delivered = try pub_.publish("weather", "sunny");
    try std.testing.expectEqual(@as(u64, 1), delivered);

    const msg = (try sub.nextMessage(allocator)).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("weather", msg.channel);
    try std.testing.expectEqualStrings("sunny", msg.payload);
    try std.testing.expectEqual(@as(u64, 1), server.messagesPublishedTotal.get());
}

test "server delivers to a subscriber's own copy per channel it named, every subscriber on a channel reached" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var subA = try client_mod.Client.connect(allocator, server.boundAddress());
    defer subA.close();
    _ = try subA.subscribe(&.{ "orders", "alerts" });

    var subB = try client_mod.Client.connect(allocator, server.boundAddress());
    defer subB.close();
    _ = try subB.subscribe(&.{"orders"});

    var pub_ = try client_mod.Client.connect(allocator, server.boundAddress());
    defer pub_.close();
    try std.testing.expectEqual(@as(u64, 2), try pub_.publish("orders", "order-1"));
    try std.testing.expectEqual(@as(u64, 1), try pub_.publish("alerts", "disk-full"));

    const aFirst = (try subA.nextMessage(allocator)).?;
    defer aFirst.deinit(allocator);
    try std.testing.expectEqualStrings("orders", aFirst.channel);
    try std.testing.expectEqualStrings("order-1", aFirst.payload);
    const aSecond = (try subA.nextMessage(allocator)).?;
    defer aSecond.deinit(allocator);
    try std.testing.expectEqualStrings("alerts", aSecond.channel);
    try std.testing.expectEqualStrings("disk-full", aSecond.payload);

    const bOnly = (try subB.nextMessage(allocator)).?;
    defer bOnly.deinit(allocator);
    try std.testing.expectEqualStrings("orders", bOnly.channel);
    try std.testing.expectEqualStrings("order-1", bOnly.payload);
}

test "server publish to a channel with no subscribers returns 0 without crashing, over real TCP" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectEqual(@as(u64, 0), try client.publish("nobody-home", "hello"));
    try client.ping();
}

test "server rejects an empty subscribe channel list as bad_request, connection stays diagnosable" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, client.subscribe(&.{}));
}

test "closing a subscriber's connection unregisters it - a later publish no longer reaches it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    _ = try sub.subscribe(&.{"ch"});
    try std.testing.expectEqual(@as(usize, 1), server.pubsub.channelSubscriberCount("ch"));
    sub.close();

    const startedAt = std.time.nanoTimestamp();
    while (server.pubsub.channelSubscriberCount("ch") != 0) {
        if (std.time.nanoTimestamp() - startedAt > 2 * std.time.ns_per_s) break;
        std.time.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 0), server.pubsub.channelSubscriberCount("ch"));

    var pub_ = try client_mod.Client.connect(allocator, server.boundAddress());
    defer pub_.close();
    try std.testing.expectEqual(@as(u64, 0), try pub_.publish("ch", "too-late"));
}

test "server with auth enabled requires authentication before subscribe or publish, readonly role suffices" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "viewer", "hunter2", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var anon = try client_mod.Client.connect(allocator, server.boundAddress());
    defer anon.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, anon.subscribe(&.{"ch"}));
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, anon.publish("ch", "x"));

    var viewer = try client_mod.Client.connect(allocator, server.boundAddress());
    defer viewer.close();
    try viewer.authenticate("viewer", "hunter2");
    _ = try viewer.subscribe(&.{"ch"});

    var writer_ = try client_mod.Client.connect(allocator, server.boundAddress());
    defer writer_.close();
    try writer_.authenticate("viewer", "hunter2");
    try std.testing.expectEqual(@as(u64, 1), try writer_.publish("ch", "hi"));

    const msg = (try viewer.nextMessage(allocator)).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("hi", msg.payload);
}

test "server unsubscribe over real TCP drops one channel while the other keeps flowing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    defer sub.close();
    const subId = try sub.subscribe(&.{ "orders", "alerts" });

    var ctrl = try client_mod.Client.connect(allocator, server.boundAddress());
    defer ctrl.close();
    const removed = try ctrl.unsubscribe(subId, &.{"orders"});
    try std.testing.expectEqual(@as(u32, 1), removed);
    try ctrl.ping();

    var pub_ = try client_mod.Client.connect(allocator, server.boundAddress());
    defer pub_.close();
    try std.testing.expectEqual(@as(u64, 0), try pub_.publish("orders", "too-late"));
    try std.testing.expectEqual(@as(u64, 1), try pub_.publish("alerts", "fire"));

    const msg = (try sub.nextMessage(allocator)).?;
    defer msg.deinit(allocator);
    try std.testing.expectEqualStrings("alerts", msg.channel);
    try std.testing.expectEqualStrings("fire", msg.payload);
}

test "server unsubscribe from every remaining channel ends the subscription like a disconnect" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    defer sub.close();
    const subId = try sub.subscribe(&.{"ch"});

    var ctrl = try client_mod.Client.connect(allocator, server.boundAddress());
    defer ctrl.close();
    try std.testing.expectEqual(@as(u32, 1), try ctrl.unsubscribe(subId, &.{"ch"}));

    try std.testing.expect((try sub.nextMessage(allocator)) == null);

    const startedAt = std.time.nanoTimestamp();
    while (server.pubsub.channelSubscriberCount("ch") != 0) {
        if (std.time.nanoTimestamp() - startedAt > 2 * std.time.ns_per_s) break;
        std.time.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 0), server.pubsub.channelSubscriberCount("ch"));
}

test "server rejects unsubscribe with an unknown subscriber id as bad_request" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();

    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, client.unsubscribe(999999, &.{"ch"}));
    try client.ping();
}

test "server rejects an empty unsubscribe channel list as bad_request" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    defer sub.close();
    const subId = try sub.subscribe(&.{"ch"});

    var ctrl = try client_mod.Client.connect(allocator, server.boundAddress());
    defer ctrl.close();
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, ctrl.unsubscribe(subId, &.{}));
}

test "server with auth enabled requires authentication before unsubscribe, readonly role suffices" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try testDb(allocator, path);
    defer db.close();
    const store = authmod.Store.init(&db);
    try store.createUser(allocator, "viewer", "hunter2", .readonly, 16);

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try Server.init(allocator, &db, address);
    server.enableAuth(store);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var sub = try client_mod.Client.connect(allocator, server.boundAddress());
    defer sub.close();
    try sub.authenticate("viewer", "hunter2");
    const subId = try sub.subscribe(&.{"ch"});

    var anon = try client_mod.Client.connect(allocator, server.boundAddress());
    defer anon.close();
    try std.testing.expectError(client_mod.ClientError.ServerUnauthorized, anon.unsubscribe(subId, &.{"ch"}));

    var ctrl = try client_mod.Client.connect(allocator, server.boundAddress());
    defer ctrl.close();
    try ctrl.authenticate("viewer", "hunter2");
    try std.testing.expectEqual(@as(u32, 1), try ctrl.unsubscribe(subId, &.{"ch"}));
}
