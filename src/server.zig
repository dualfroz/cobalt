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

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;

/// Which role a given opcode needs at minimum when auth is enabled. `ping`
/// and `auth` itself are handled before this is ever consulted (see
/// `dispatch`) - every other read op needs `readonly`, every mutation
/// needs `readwrite`, and `user_admin` (remote user management: create,
/// change password, change role, delete, list) needs `admin` - the one
/// opcode reserved for administrative server operations. Bootstrapping the
/// very first admin account still has to happen CLI-only over a local Db
/// handle (see `main.zig`'s `user add` and `serve --auth`'s refusal to
/// start without one), since a fresh server has no admin to authenticate
/// this opcode with in the first place.
///
/// `ttl_op` bundles four actions (see `protocol.TtlAction`) behind one
/// opcode, unlike every other entry here which is a single action - so it
/// is the one case that needs to peek at the payload's first byte (the
/// action tag) rather than deciding purely from `op`. `query` is read-only;
/// `expire`/`persist`/`sweep` all mutate the store and need `readwrite`. A
/// payload too short to carry an action byte falls back to `readwrite` (the
/// stricter requirement) - the actual decode in `handleTtlOp` will reject it
/// as malformed either way, so this only affects which error status a
/// bad frame gets before it is ever decoded.
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
        // Same action-byte peek as `.ttl_op` above, and for the same
        // reason: `coll_ttl_op` bundles the same four actions, just
        // against a whole collection instead of one flat key.
        .coll_ttl_op => if (payload.len > 0 and payload[0] == @intFromEnum(protocol.TtlAction.query))
            .readonly
        else
            .readwrite,
        // `coll_op` bundles thirty collection actions behind one opcode
        // (see `protocol.CollAction`) - same action-byte peek as `ttl_op`/
        // `coll_ttl_op`, but the read/write split is looked up from
        // `CollAction.isReadOnly` instead of a single fixed action value,
        // since unlike the four TTL actions this opcode's actions are not
        // all one enum-comparison away from each other.
        .coll_op => if (payload.len > 0)
            (if ((protocol.CollAction.fromByte(payload[0]) catch null)) |a|
                (if (a.isReadOnly()) authmod.Role.readonly else .readwrite)
            else
                .readwrite)
        else
            .readwrite,
        // `txn_op` is always a write (every entry is a put or a delete),
        // unlike `ttl_op`/`coll_ttl_op`/`coll_op` above it has no read-only
        // action to peek for, so it needs no payload inspection at all.
        .txn_op => .readwrite,
        // Pub/sub never touches `Db` at all (see `pubsub.zig`'s `Hub` doc
        // comment) - all three are gated `readonly` purely so a server with
        // auth enabled still requires SOME authenticated connection before
        // any of them works, matching every other opcode's default
        // posture, rather than because any of them reads storage.
        // `unsubscribe` in particular is always sent from a DIFFERENT
        // connection than the one that subscribed (see
        // `protocol.encodeUnsubscribe`'s doc comment) - it needs no
        // stronger role than `subscribe`/`publish` just because it arrives
        // over its own connection.
        .subscribe, .publish, .unsubscribe => .readonly,
    };
}

const PerConnLimitConfig = struct {
    capacity: f64,
    refillPerSecond: f64,
};

/// A TCP server that exposes a single `Db` over the binary protocol in
/// `protocol.zig`. One accept loop thread hands each connection off to
/// its own detached worker thread; every worker serialises its access to
/// `db` through `mutex` since `Db` itself keeps no internal locking.
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
    /// Channel registry for `subscribe`/`publish` - see `pubsub.zig`'s doc
    /// comment on `Hub` for why this is entirely separate from `mutex`/`db`
    /// above (a live subscriber must never be able to block a store read or
    /// write, or vice versa).
    pubsub: pubsubmod.Hub = undefined,
    messagesPublishedTotal: metrics.MetricCounter = .{},

    pub fn init(allocator: Allocator, db: *Db, address: std.net.Address) !Server {
        const net = try address.listen(.{ .reuse_address = true });
        return .{ .allocator = allocator, .db = db, .net = net, .pubsub = pubsubmod.Hub.init(allocator) };
    }

    pub fn boundAddress(self: *Server) std.net.Address {
        return self.net.listen_address;
    }

    /// Number of connections currently being served. Exposed for tests
    /// that need to wait for a handler to finish without racing on
    /// thread teardown.
    pub fn activeConnections(self: *Server) usize {
        return self.active.load(.acquire);
    }

    /// Turns on a token-bucket rate limit shared across every connection:
    /// each dispatched request consumes one token before it is allowed to
    /// touch `db.mutex` at all, so an overload is rejected cheaply instead
    /// of queuing behind real storage work. Disabled (unlimited) by
    /// default; call once before `start()`.
    pub fn enableRateLimit(self: *Server, capacity: f64, refillPerSecond: f64) void {
        self.limiter = metrics.TokenBucket.init(capacity, refillPerSecond, @intCast(std.time.nanoTimestamp()));
    }

    /// Gives every accepted connection its own private token bucket,
    /// independent of every other connection's budget and of the shared
    /// `limiter` above. A fresh bucket is created per connection in
    /// `handleConnection` (not shared state, so no locking is needed beyond
    /// what TokenBucket already does internally) - one noisy client cannot
    /// starve another client's share of the server, which a single global
    /// bucket cannot express. Both limits can be enabled together: a
    /// request must clear the per-connection budget before it is even
    /// checked against the global one. Disabled by default; call once
    /// before `start()`.
    pub fn enablePerConnectionRateLimit(self: *Server, capacity: f64, refillPerSecond: f64) void {
        self.perConnLimit = .{ .capacity = capacity, .refillPerSecond = refillPerSecond };
    }

    /// Turns on username/password authentication and role enforcement for
    /// every connection: after this call, every opcode except `ping` and
    /// `auth` itself requires a prior successful `auth` on that connection
    /// (`unauthorized` otherwise), and the authenticated role must meet
    /// `requiredRole(op)` (`forbidden` otherwise). `store` is not owned by
    /// the server - the caller keeps managing the underlying `Db` user
    /// records (creating the first admin, etc.) through `store` directly.
    /// Disabled (no auth required, matching every prior version of this
    /// server) by default; call once before `start()`.
    pub fn enableAuth(self: *Server, store: authmod.Store) void {
        self.authStore = store;
    }

    /// Layers expiring session tokens on top of password auth (requires
    /// `enableAuth` to also be called - sessions are only ever minted from
    /// a successful password check, never a substitute for one). Once
    /// enabled: a successful `auth` response carries a fresh token in its
    /// payload (empty payload otherwise, unchanged from before this
    /// existed) valid for `ttlNanos`; a NEW connection can skip the
    /// password entirely by sending that token as `auth_token` instead;
    /// and - the actual behavior change from plain password auth - a
    /// connection's authenticated role stops being honored the moment its
    /// session's expiry passes, even if the TCP connection itself has
    /// stayed open the whole time (`dispatch` re-checks the wall clock on
    /// every request, not just at `auth` time). `store` is not owned by
    /// the server, exactly like `enableAuth`'s `authmod.Store` - the
    /// caller keeps it alive and can inspect/revoke sessions directly.
    pub fn enableSessions(self: *Server, store: *sessionmod.SessionStore, ttlNanos: i128) void {
        self.sessions = store;
        self.sessionTtlNanos = ttlNanos;
    }

    /// Runs `SessionStore.sweepExpired` on a background thread every
    /// `intervalNanos`, starting once `start()` is called. Without this, a
    /// session nobody ever presents again (the client that held it simply
    /// vanished) sits in `sessions` forever - `validate()` only ever cleans
    /// up a token someone actually tries to use. Requires `enableSessions`
    /// to have been called first (checked in `start()`, not here, since
    /// callers are free to call these two in either order before `start`).
    pub fn enableSessionSweep(self: *Server, intervalNanos: u64) void {
        self.sweepIntervalNanos = intervalNanos;
    }

    /// Runs `ttl.sweepExpired` on a background thread every `intervalNanos`,
    /// starting once `start()` is called - independent of `enableAuth`/
    /// `enableSessions`/`enableSessionSweep` above, since key TTLs (set via
    /// the `ttl_op` opcode or the CLI's local `put --ttl`/`expire`) are a
    /// property of the `Db` itself, not of authentication. Without this, a
    /// key whose TTL elapsed but that nobody ever reads again (so
    /// `ttl.getLive`'s lazy expiry never fires) sits in the store forever -
    /// exactly the same gap `enableSessionSweep` closes for session tokens.
    /// Call once before `start()`.
    pub fn enableTtlSweep(self: *Server, intervalNanos: u64) void {
        self.ttlSweepIntervalNanos = intervalNanos;
    }

    /// Runs `collttl.sweepExpired` on a background thread every
    /// `intervalNanos`, starting once `start()` is called - the whole-
    /// collection counterpart of `enableTtlSweep` above, independent of it
    /// (a server can enable one, both, or neither). Without this, a
    /// collection whose TTL elapsed but that nobody ever touches again (so
    /// `coll_ttl_op`'s lazy `expireIfDue` never fires, matching the CLI's
    /// local `coll` dispatcher) sits in the store forever. Call once before
    /// `start()`.
    pub fn enableCollTtlSweep(self: *Server, intervalNanos: u64) void {
        self.collTtlSweepIntervalNanos = intervalNanos;
    }

    /// Registers this server's request counters into `reg` under fixed
    /// names, so they show up alongside any other Prometheus metrics an
    /// embedding application already exports.
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

    /// Blocks until the accept loop exits (only happens via `stop()` or
    /// an unrecoverable accept error). Used by long-running foreground
    /// servers such as the CLI's `serve` command.
    pub fn wait(self: *Server) void {
        if (self.acceptThread) |t| t.join();
    }

    /// Background loop started by `start()` when `enableSessionSweep` set a
    /// nonzero interval and sessions are enabled. Sleeps the full interval
    /// between sweeps (a sweep is pure housekeeping, never load-bearing for
    /// correctness - `validate()` already refuses an expired token on its
    /// own), and checks `stopping` both before and after each sleep so
    /// `stop()` never has to wait more than one interval to join it.
    fn sweepLoop(self: *Server) void {
        const store = self.sessions orelse return;
        while (!self.stopping.load(.acquire)) {
            std.time.sleep(self.sweepIntervalNanos);
            if (self.stopping.load(.acquire)) return;
            const dropped = store.sweepExpired(std.time.nanoTimestamp());
            if (dropped > 0) self.sessionsSweptTotal.incrBy(@intCast(dropped));
        }
    }

    /// Background loop started by `start()` when `enableTtlSweep` set a
    /// nonzero interval. Unlike `sweepLoop` above, `ttl.sweepExpired` reads
    /// and mutates the same `Db` every request handler touches, so this
    /// loop must take `self.mutex` around the call exactly like `dispatch`
    /// does for every opcode - `Db` itself keeps no internal locking (see
    /// the doc comment on `Server`). A failed sweep (e.g. a transient I/O
    /// error) is skipped rather than crashing the server; the next tick
    /// tries again.
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

    /// Background loop started by `start()` when `enableCollTtlSweep` set a
    /// nonzero interval - the whole-collection counterpart of `ttlSweepLoop`
    /// above, same shape (own thread, takes `self.mutex` around the actual
    /// `Db` access, skips a failed sweep rather than crashing).
    /// `collttl.sweepExpired` walks every kind's marker namespace in one
    /// prefix scan, so one thread covers Counter/Hash/Set/List/ZSet at once
    /// rather than needing one sweeper per kind.
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

        // A private bucket for this one connection, if enabled. It lives on
        // this worker's own stack and is only ever touched by this thread,
        // so unlike `self.limiter` it needs no cross-thread synchronization
        // even though TokenBucket carries its own mutex regardless.
        var connLimiter: ?metrics.TokenBucket = if (self.perConnLimit) |cfg|
            metrics.TokenBucket.init(cfg.capacity, cfg.refillPerSecond, @intCast(std.time.nanoTimestamp()))
        else
            null;

        // Which role (if any) this one connection has authenticated as.
        // Lives on this worker's stack, exactly like `connLimiter` above -
        // a fresh, private slot per connection, never shared.
        var connRole: ?authmod.Role = null;

        // When sessions are enabled (see `enableSessions`), the nanosecond
        // timestamp at which `connRole` above stops being honored - set
        // whenever `auth`/`auth_token` succeeds, re-checked on every
        // request in `dispatch`. Stays null (never expires on its own) for
        // a server with auth but no session store, matching the original
        // "authenticated for as long as the connection is open" behavior.
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
                // A role survives only as long as its session does, when
                // sessions are enabled: a session that expired since the
                // last request on this same connection is treated exactly
                // like never having authenticated at all, forcing a fresh
                // `auth`/`auth_token` before anything else proceeds.
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

        // `subscribe`/`publish` never touch `db` - handled here, before
        // `self.mutex` is ever taken, so neither one can be blocked behind
        // (or block) a store read/write. `subscribe` in particular can hold
        // this stack frame open for the entire remaining lifetime of the
        // connection (see `handleSubscribe`'s doc comment), which would
        // starve every other connection forever if it happened under
        // `self.mutex`.
        if (op == .subscribe) return self.handleSubscribe(frame.payload, stream);
        if (op == .publish) return self.handlePublish(frame.payload, writer);
        if (op == .unsubscribe) return self.handleUnsubscribe(frame.payload, writer);

        self.mutex.lock();
        defer self.mutex.unlock();

        switch (op) {
            .ping => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "PONG"),

            // Only reachable when `self.authStore == null` - a server with
            // auth enabled answers `auth` requests in `handleAuth` above,
            // before this switch is ever entered. A server with auth
            // disabled has nothing to check credentials against, so it
            // always accepts, matching every other opcode's "auth is
            // simply not enforced" behavior on this server.
            .auth => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), ""),

            // Only reachable when `self.authStore == null`, for the exact
            // same reason as `.auth` above: a server without auth enabled
            // has no notion of a session either, so it accepts any token
            // unconditionally rather than ever consulting a session store.
            .auth_token => try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), ""),

            .get => {
                const value = self.db.get(self.allocator, frame.payload) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
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
                self.db.put(args.key, args.value) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .del => {
                self.db.delete(frame.payload) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .scan => try self.handleScan(frame.payload, writer),
            .prefix => try self.handlePrefix(frame.payload, writer),

            .stats => {
                const s = self.db.stats();
                const payload = protocol.encodeStats(self.allocator, s) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(payload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), payload);
            },

            .flush => {
                self.db.flush() catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .compact => {
                self.db.compact() catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .batch => try self.handleBatch(frame.payload, writer),

            .table_select => try self.handleTableSelect(frame.payload, writer),

            .table_join => try self.handleTableJoin(frame.payload, writer),

            .table_aggregate => try self.handleTableAggregate(frame.payload, writer),
            .table_window => try self.handleTableWindow(frame.payload, writer),

            // All three already handled and returned from above, before
            // `self.mutex` was ever taken - never reached here.
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

    /// Answers the `ttl_op` opcode: the network counterpart of the CLI's
    /// local `expire`/`persist`/`ttl`/`expire-sweep` (main.zig), all backed
    /// by the same `ttl.zig` functions the local commands call directly -
    /// `query`/`sweep` were previously reachable only from a process that
    /// had the `Db` open itself. `expire` mirrors the CLI's Redis-EXPIRE-
    /// strict existence check (main.zig checks `db.get` before calling
    /// `ttl.setExpireSeconds`; here the same check happens before the same
    /// call) and answers `not_found` rather than `ok` when the key does not
    /// currently exist, instead of the looser PEXPIREAT-like
    /// `ttl.setExpireAt` that would silently accept it.
    fn handleTtlOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeTtlOp(payload) catch {
            return writeErr(writer, .bad_request, "malformed ttl payload");
        };
        const now = std.time.nanoTimestamp();
        switch (args.action) {
            .expire => {
                const existing = self.db.get(self.allocator, args.key) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                if (existing == null) return writeErr(writer, .not_found, "no such key");
                self.allocator.free(existing.?);
                ttlmod.setExpireSeconds(self.db, self.allocator, args.key, now, args.seconds) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .persist => {
                ttlmod.clearExpire(self.db, self.allocator, args.key) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .query => {
                const result = ttlmod.remaining(self.db, self.allocator, args.key, now) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                const respPayload = protocol.encodeTtlResult(self.allocator, result) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
            .sweep => {
                const reaped = ttlmod.sweepExpired(self.db, self.allocator, now) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                if (reaped > 0) self.ttlSweptTotal.incrBy(@intCast(reaped));
                const respPayload = protocol.encodeTtlSweepCount(self.allocator, @intCast(reaped)) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
        }
    }

    /// Answers the `coll_ttl_op` opcode: the network counterpart of the
    /// CLI's local `coll <kind> expire|ttl|persist <name>`/`coll
    /// expire-sweep` (main.zig), all backed by the same `collttl.zig`
    /// functions the local commands call directly - same shape as
    /// `handleTtlOp` above, but `expire`'s existence check is
    /// `collections.collectionExists` (a whole namespace) instead of
    /// `db.get` (one key), matching the CLI's own `coll <kind> expire`
    /// check.
    fn handleCollTtlOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeCollTtlOp(payload) catch {
            return writeErr(writer, .bad_request, "malformed coll ttl payload");
        };
        const now = std.time.nanoTimestamp();
        switch (args.action) {
            .expire => {
                const exists = collmod.collectionExists(self.db, self.allocator, args.kind, args.name) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                if (!exists) return writeErr(writer, .not_found, "no such collection");
                collttlmod.setExpireSeconds(self.db, self.allocator, args.kind, args.name, now, args.seconds) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .persist => {
                collttlmod.clearExpire(self.db, self.allocator, args.kind, args.name) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },
            .query => {
                const result = collttlmod.remaining(self.db, self.allocator, args.kind, args.name, now) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                const respPayload = protocol.encodeTtlResult(self.allocator, result) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
            .sweep => {
                const reaped = collttlmod.sweepExpired(self.db, self.allocator, now) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                if (reaped > 0) self.collTtlSweptTotal.incrBy(@intCast(reaped));
                const respPayload = protocol.encodeTtlSweepCount(self.allocator, @intCast(reaped)) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(respPayload);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
            },
        }
    }

    /// Answers the `coll_op` opcode: the network counterpart of the CLI's
    /// local `coll <kind> <op> ...` (main.zig's `runColl`, backed by
    /// `collections.zig`) - collections were previously reachable only from
    /// a process holding the `Db` directly, the same gap `ttl_op`/
    /// `coll_ttl_op` already closed for TTL management. Applies the same
    /// lazy-expiry check `runColl` performs locally before every dispatch
    /// (`collttl.expireIfDue` on the target name, plus `expireIfDueMany` on
    /// the extra names of the three multi-set actions) so a collection
    /// whose TTL is already due never appears alive over the wire either.
    /// The actual per-action work lives in `dispatchCollOp` below; this
    /// function only handles decode and the shared expiry check.
    fn handleCollOp(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodeCollOp(self.allocator, payload) catch {
            return writeErr(writer, .bad_request, "malformed coll payload");
        };
        defer self.allocator.free(args.args);
        const now = std.time.nanoTimestamp();
        _ = collttlmod.expireIfDue(self.db, self.allocator, args.action.kind(), args.name, now) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        switch (args.action) {
            .set_inter, .set_union, .set_diff => _ = collttlmod.expireIfDueMany(self.db, self.allocator, .set, args.args, now) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            },
            else => {},
        }
        // Thirty actions each wrapping their own `db` call in a `catch |err|
        // return writeErr(...)` (the pattern every other handler in this
        // file uses) would triple the size of this function for no benefit
        // over one shared boundary: `dispatchCollOp` uses plain `try` and
        // two sentinel errors for malformed arguments, and this one catch
        // maps both cases to the right status - the same information either
        // way, just not repeated thirty times.
        self.dispatchCollOp(args, writer) catch |err| return switch (err) {
            error.InvalidArgCount, error.InvalidNumber => writeErr(writer, .bad_request, @errorName(err)),
            else => writeErr(writer, .internal, @errorName(err)),
        };
    }

    fn writeCollReply(self: *Server, writer: anytype, reply: protocol.CollReply) !void {
        const respPayload = protocol.encodeCollReply(self.allocator, reply) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(respPayload);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), respPayload);
    }

    /// One arm per `protocol.CollAction`, each translating straight from
    /// `args.args` (the CLI-text-form string arguments) into the matching
    /// `collections.zig` call and back into a `protocol.CollReply` - the
    /// exact same translation `main.zig`'s `runColl` already does for the
    /// local CLI, just producing a wire reply instead of a printed line.
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

    /// Answers the `metrics` opcode: the network counterpart of the CLI's
    /// `stats --prom` (which only ever renders `Db.stats()` locally) plus
    /// this server's own request/rate-limit/auth/session counters from
    /// `registerMetrics` - until now those counters were only ever
    /// observable in-process, by a test holding a direct `*Server`
    /// pointer. The registry is built fresh per request and thrown away
    /// immediately after rendering: there is nothing to keep alive between
    /// calls, since every counter it reads lives on `self` regardless.
    fn handleMetrics(self: *Server, writer: anytype) !void {
        var reg = metrics.Registry.init(self.allocator);
        defer reg.deinit();
        self.registerMetrics(&reg) catch |err| return writeErr(writer, .internal, @errorName(err));

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        reg.exportText(self.allocator, buf.writer()) catch |err| return writeErr(writer, .internal, @errorName(err));
        metrics.formatDbStats(buf.writer(), "cobalt", self.db.stats()) catch |err| return writeErr(writer, .internal, @errorName(err));

        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), buf.items);
    }

    /// Verifies credentials against `store` and, on success, stamps the
    /// resulting role into this connection's `connRole` slot so every
    /// subsequent request on the same connection is dispatched under it.
    /// Locks `self.mutex` only around the actual `Db` read `verify`
    /// performs, same as every other handler here.
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
                else => writeErr(writer, .internal, @errorName(err)),
            };
        };
        connRole.* = role;
        connExpiresAtNanos.* = null;

        if (self.sessions) |store_| {
            const now = std.time.nanoTimestamp();
            const token = store_.issue(role, self.sessionTtlNanos, now) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer self.allocator.free(token);
            connExpiresAtNanos.* = now + self.sessionTtlNanos;
            const responsePayload = protocol.encodeAuthOk(self.allocator, token) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer self.allocator.free(responsePayload);
            return protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), responsePayload);
        }
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
    }

    /// Authenticates a connection from a previously issued session token
    /// instead of a username/password pair (see `enableSessions`). Only
    /// reachable when `self.sessions` is set, since `dispatch` only routes
    /// `auth_token` here while `self.authStore` is also set.
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
        var entries = std.ArrayList(dbmod.Entry).init(self.allocator);
        defer entries.deinit();

        if (args.reverse) {
            var it = self.db.scanReverse(self.allocator, .{ .start = args.start, .end = args.end }) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer it.deinit();
            while (try it.next()) |e| {
                try entries.append(e);
                if (args.limit != 0 and entries.items.len >= args.limit) break;
            }
        } else {
            var it = self.db.scanRange(self.allocator, .{ .start = args.start, .end = args.end }) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer it.deinit();
            while (try it.next()) |e| {
                try entries.append(e);
                if (args.limit != 0 and entries.items.len >= args.limit) break;
            }
        }

        const out = protocol.encodeEntries(self.allocator, entries.items) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    fn handlePrefix(self: *Server, payload: []const u8, writer: anytype) !void {
        const args = protocol.decodePrefix(payload) catch {
            return writeErr(writer, .bad_request, "malformed prefix payload");
        };
        var it = self.db.scanPrefix(self.allocator, args.prefix) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer it.deinit();

        var entries = std.ArrayList(dbmod.Entry).init(self.allocator);
        defer entries.deinit();
        while (try it.next()) |e| {
            try entries.append(e);
            if (args.limit != 0 and entries.items.len >= args.limit) break;
        }

        const out = protocol.encodeEntries(self.allocator, entries.items) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
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
            switch (op) {
                .put => |kv| try wb.put(kv.key, kv.value),
                .del => |key| try wb.delete(key),
            }
        }
        self.db.apply(&wb) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
    }

    /// Executes a `txn_op` request: the network counterpart of the CLI's
    /// local `txn <script-file>` (main.zig's `runTxn`), applying every
    /// put/delete in `entries` as one atomic `Transaction` commit across
    /// however many tables they touch. Runs entirely inside `dispatch`'s
    /// single `self.mutex` acquisition, like every other opcode - which
    /// means, unlike a raw multi-thread `Transaction` against an unguarded
    /// `*Db` (see `concurrent.zig`'s `GuardedDb` doc comment), no other
    /// connection's request can ever interleave between this transaction's
    /// begin and its commit. `txn.commit()`'s OCC conflict check stays in
    /// place and still maps to `Status.conflict` below, but under this
    /// server's locking discipline nothing can actually trigger it for a
    /// request that arrives, stages, and commits within one dispatch call -
    /// the same reason `concurrent.zig`'s `TableTransferWorker` test treats
    /// a real `error.Conflict` under `GuardedDb.acquire()` as a bug, not an
    /// expected outcome.
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
                return writeErr(writer, .internal, @errorName(err));
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
                        return writeErr(writer, .internal, @errorName(err));
                    };
                },
                .del => {
                    table.delete(pk) catch |err| {
                        return writeErr(writer, .internal, @errorName(err));
                    };
                },
            }
        }

        txn.commit() catch |err| {
            return switch (err) {
                error.Conflict => writeErr(writer, .conflict, "transaction conflict"),
                else => writeErr(writer, .internal, @errorName(err)),
            };
        };

        const out = protocol.encodeTxnResult(self.allocator, @intCast(entries.len)) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table select <table> [expr]` remotely: opens the named
    /// table over the same `*Db` the rest of the server serves (so it sees
    /// exactly the indexes/rows a local CLI `table` command would), parses
    /// the expression text with the same `expr.zig` grammar the CLI uses
    /// (empty text means "every row", matching `Table.select(null)`), and
    /// wire-encodes the resulting rows. `args.orderBy`, when present, is
    /// forwarded to `Table.selectPageOrdered` so the offset/limit window
    /// applies AFTER sorting, exactly like the local `table select
    /// --order-by` CLI path - `null` falls through to the plain
    /// `selectPage` early-stop behavior instead. A bad table name or
    /// malformed expression is a client mistake (`bad_request`), not a
    /// server fault.
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
            return writeErr(writer, .internal, @errorName(err));
        };
        defer querymod.freeRows(self.allocator, rows);

        const out = protocol.encodeRows(self.allocator, rows) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_join` request against `join.zig`'s four equi-join
    /// variants, chosen by `args.mode` - the network counterpart of the
    /// CLI's local `table join [--left|--right|--full]`. Each variant
    /// produces its own result type (`JoinedRow`/`OuterJoinedRow`/
    /// `RightOuterJoinedRow`/`FullOuterJoinedRow`), but every one of them is
    /// just two optional `Row`s under the hood, so this flattens whichever
    /// one came back into `protocol.JoinPair` before encoding - one wire
    /// format for all four modes, exactly like `coll_op` bundles thirty
    /// collection actions behind one opcode instead of thirty. Ownership of
    /// each row is moved (by value) from the mode-specific slice into
    /// `pairs`, then that mode-specific slice is freed as a raw allocation
    /// (not through `join.freeJoined`/`freeOuterJoined`/etc, which would
    /// double-deinit rows already moved into `pairs`) - `pairs`'s own defer
    /// is what actually frees the row contents, once encoding is done.
    /// `args.offset`/`args.limit` window the mode-specific slice through
    /// `join.applyPage` right after it comes back, before the flatten -
    /// `applyPage` already frees the pre-page slice and hands back a fresh
    /// one, so the pattern below frees `paged`, never `joined` directly.
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
                    return writeErr(writer, .internal, @errorName(err));
                };
                const paged = joinmod.applyPage(joinmod.JoinedRow, self.allocator, joined, page) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .left => {
                const joined = joinmod.leftOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                const paged = joinmod.applyPage(joinmod.OuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .right => {
                const joined = joinmod.rightOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                const paged = joinmod.applyPage(joinmod.RightOuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
            .full => {
                const joined = joinmod.fullOuterJoin(self.allocator, &left, args.leftField, leftPred, &right, args.rightField, rightPred) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                const paged = joinmod.applyPage(joinmod.FullOuterJoinedRow, self.allocator, joined, page) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(paged);
                for (paged) |p| try pairs.append(.{ .left = p.left, .right = p.right });
            },
        }

        const out = protocol.encodeJoinedRows(self.allocator, pairs.items) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_aggregate` request: opens the named table over the
    /// same `*Db` the rest of the server serves, filters rows with the same
    /// `expr.zig` grammar `table_select`/`table_join` already use (empty
    /// text selects every row), then hands the filtered rows to
    /// `aggregate.zig` - `runGlobal` when `args.groupField` is empty (the
    /// network counterpart of the CLI's `*` sentinel for "no GROUP BY"),
    /// `run` otherwise. When `args.havingText` is non-empty, it is parsed
    /// with the same `expr.zig` grammar and applied AFTER aggregation but
    /// BEFORE paging - `globalMatchesHaving` on the `runGlobal` path (an
    /// excluded single result comes back as zero values, not an error) or
    /// `filterHaving` on the grouped path - then, on the grouped path only,
    /// a non-empty `args.orderBy` sorts the HAVING-narrowed groups via
    /// `aggregate.sortGroupsBy` (an unknown order field is `bad_request`,
    /// same treatment as a malformed HAVING expr) - then windowed by
    /// `args.offset`/`args.limit` through `aggregate.applyPageGroups` (0/0 =
    /// unlimited, ignored for the `runGlobal` path since that always
    /// produces at most one result row, same as `args.orderBy`). Two distinct wire shapes come back
    /// (`encodeAggGlobalResult` vs `encodeAggGroupRows`) because the client
    /// already knows which one it asked for (it is the one that chose
    /// `groupField`), so no extra discriminator byte is needed on the wire -
    /// the client just decodes with whichever matches its own request, the
    /// same reasoning `Client.tableAggregateGlobal`/`tableAggregateGroups`
    /// document. A bad table name, malformed expr, or a spec referencing a
    /// non-numeric field (`error.NonNumericField`/`error.Overflow` from
    /// `aggregate.zig`) is a client mistake (`bad_request`), not a server
    /// fault.
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
            return writeErr(writer, .internal, @errorName(err));
        };
        defer querymod.freeRows(self.allocator, rows);

        if (args.groupField.len == 0) {
            const values = aggregatemod.runGlobal(self.allocator, rows, args.specs) catch |err| {
                return switch (err) {
                    error.NonNumericField, error.Overflow => writeErr(writer, .bad_request, @errorName(err)),
                    else => writeErr(writer, .internal, @errorName(err)),
                };
            };
            defer aggregatemod.freeGlobalResult(self.allocator, values);
            const matches = if (havingPred) |hp|
                aggregatemod.globalMatchesHaving(self.allocator, args.specs, values, hp) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                }
            else
                true;
            const out = protocol.encodeAggGlobalResult(self.allocator, if (matches) values else &.{}) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer self.allocator.free(out);
            try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
        } else {
            const unpaged = aggregatemod.run(self.allocator, rows, args.groupField, args.specs) catch |err| {
                return switch (err) {
                    error.NonNumericField, error.Overflow => writeErr(writer, .bad_request, @errorName(err)),
                    else => writeErr(writer, .internal, @errorName(err)),
                };
            };
            const filtered = if (havingPred) |hp|
                aggregatemod.filterHaving(self.allocator, unpaged, args.groupField, args.specs, hp) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                }
            else
                unpaged;
            if (args.orderBy.len > 0) {
                aggregatemod.sortGroupsBy(self.allocator, filtered, args.groupField, args.specs, args.orderBy) catch |err| {
                    protocol.freeAggGroupRows(self.allocator, filtered);
                    return switch (err) {
                        error.UnknownOrderField => writeErr(writer, .bad_request, @errorName(err)),
                        else => writeErr(writer, .internal, @errorName(err)),
                    };
                };
            }
            const page = querymod.Page{ .offset = args.offset, .limit = args.limit };
            const groups = aggregatemod.applyPageGroups(self.allocator, filtered, page) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer protocol.freeAggGroupRows(self.allocator, groups);
            const out = protocol.encodeAggGroupRows(self.allocator, groups) catch |err| {
                return writeErr(writer, .internal, @errorName(err));
            };
            defer self.allocator.free(out);
            try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
        }
    }

    /// Executes a `table_window` request: opens the named table, filters
    /// rows with the same `expr.zig` grammar every other `table_*` opcode
    /// uses (empty text selects every row), then hands the filtered rows to
    /// `window.compute` for the single `args.spec` annotation, along with
    /// `args.frame` (ROWS or RANGE - see `window.zig`'s `FrameMode` doc
    /// comment) - unlike `table_aggregate`, this NEVER collapses rows, so
    /// `results[i]` stays aligned 1:1 with `rows[i]` regardless of paging (a
    /// `NonNumericField`/`Overflow`/`MissingField`/`RangeNotApplicable` from
    /// `window.zig` is a client mistake, `bad_request`, same treatment as
    /// `table_aggregate`).
    /// `args.offset`/`args.limit` then window which rows get PRINTED, walked
    /// in `window.orderedIndices`' partition-then-order sequence (the same
    /// display order local `table window` uses, not raw scan order) rather
    /// than slicing `rows`/`results` directly - the exact bug local `table
    /// window` hit and fixed (see `window.zig`'s `orderedIndices` doc
    /// comment) before this network path existed, so it is built paginated
    /// the correct way from the start instead of repeating that mistake.
    /// Each surviving row is paired with its already-computed value into a
    /// `protocol.WindowRow` and sent back via `encodeWindowRows` - the
    /// client prints them in the order received, no further sorting needed.
    /// A `subscribe` request never returns in the normal sense: once the
    /// connection is registered in `self.pubsub`, this function owns the
    /// rest of the connection's lifetime (both directions of the socket)
    /// until the client disconnects, then propagates `error.SubscriptionEnded`
    /// so `handleConnection`'s `catch return` unwinds cleanly - the same
    /// "any error just ends the connection" contract every other opcode
    /// already relies on for a plain disconnect mid-frame.
    ///
    /// Design: a `subscribe` connection becomes receive-only after the ack.
    /// A dedicated watcher thread does exactly one blocking read attempt on
    /// `stream` - whatever it gets back (a byte the client sent, or an
    /// error/EOF from a disconnect) closes the subscription, since there is
    /// no way to both keep reading further commands AND push messages on
    /// one TCP connection without either a second concurrent writer (a
    /// write race against the push loop below) or re-entering this same
    /// read/dispatch loop (a read race against the watcher). Unlike a
    /// protocol like Redis's, which multiplexes further commands
    /// (UNSUBSCRIBE, PING) onto the same subscribed connection, this
    /// connection itself never reads another request - but `unsubscribe`
    /// (see `handleUnsubscribe`) reaches the SAME `sub` from a completely
    /// different connection, keyed by the id this function's ack carries
    /// (`sub.id`), so dropping a subset of channels still does not require
    /// closing the connection outright; only dropping every remaining
    /// channel does (`pubsub.Hub.unsubscribe`'s doc comment). Once the push loop ends (for any reason - the
    /// watcher closed `sub`, or a write here failed because the peer is
    /// gone), `std.posix.shutdown` unblocks the watcher's still-pending read
    /// (rather than relying on `conn.stream.close()` racing a live read on
    /// the same fd from another thread, which is a well-known way to
    /// recycle a file descriptor into an unrelated, concurrently-accepted
    /// connection) before joining it - so by the time this returns, no
    /// other thread still touches `stream` or `sub`.
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

    /// The watcher half of `handleSubscribe`: blocks on exactly one read
    /// attempt, then closes `sub` regardless of the outcome (data, EOF, or
    /// an error - all three mean "stop pushing to this connection"). Runs
    /// on its own thread so `handleSubscribe`'s push loop can block
    /// independently on `sub.waitMessage()` - see that function's doc
    /// comment for why this is a single read, not a loop.
    fn watchForDisconnect(hub: *pubsubmod.Hub, sub: *pubsubmod.Subscriber, stream: std.net.Stream) void {
        var buf: [1]u8 = undefined;
        _ = stream.read(&buf) catch {};
        hub.closeSubscriber(sub);
    }

    /// Executes a `publish` request: any connection may call this
    /// regardless of whether it has ever subscribed to anything (see
    /// `protocol.encodePublish`'s doc comment). Delivery is fire-and-forget
    /// from this handler's point of view - `pubsub.Hub.publish` never
    /// blocks on a slow subscriber, so this returns as soon as every
    /// currently-registered subscriber's mailbox has been handed its own
    /// copy (or dropped one, under `Subscriber.push`'s backpressure policy).
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

    /// Executes an `unsubscribe` request: unlike `subscribe`, this is a
    /// plain request/response opcode that returns like any other - it never
    /// touches the connection that originally subscribed, because that
    /// connection became receive-only the moment its ack arrived (see
    /// `handleSubscribe`'s doc comment) and this one is always a separate
    /// connection entirely (see `protocol.encodeUnsubscribe`'s doc
    /// comment). `pubsub.Hub.unsubscribe`'s `error.UnknownSubscriber` (a
    /// stale id, a typo, or a subscriber that already disconnected on its
    /// own - all indistinguishable from here, see that function's doc
    /// comment) is the caller's mistake, `bad_request`, the same treatment
    /// `table_window` gives a `MissingField` from a bad field name.
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
                else => writeErr(writer, .internal, @errorName(err)),
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
            return writeErr(writer, .internal, @errorName(err));
        };
        defer querymod.freeRows(self.allocator, rows);

        const results = windowmod.computeMany(self.allocator, rows, args.partitionBy, args.orderBy, args.specs, args.frame) catch |err| {
            return switch (err) {
                error.NonNumericField, error.Overflow, error.MissingField, error.RangeNotApplicable => writeErr(writer, .bad_request, @errorName(err)),
                else => writeErr(writer, .internal, @errorName(err)),
            };
        };
        defer windowmod.freeManyResults(self.allocator, results);

        const displayOrder = windowmod.orderedIndices(self.allocator, rows, args.partitionBy, args.orderBy) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(displayOrder);

        const total = displayOrder.len;
        const pageStart = @min(args.offset, total);
        const end = if (args.limit == 0) total else @min(pageStart + args.limit, total);

        // `out`'s WindowRow.values arrays hold SHALLOW copies borrowed from
        // `results` (safe: `encodeWindowRows` below only reads them to
        // serialize, never frees them) - `results` stays the true owner,
        // freed by the `defer` above; only the borrowing arrays themselves
        // get freed here, same "shallow copy into a throwaway wire-shape
        // struct, one true owner frees the contents" pattern
        // `handleTableAggregate`'s `GroupRow`-to-wire path already relies on.
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
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(encoded);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), encoded);
    }

    /// Executes a `table_explain` request: opens the named table over the
    /// same `*Db` the rest of the server serves, parses the expr text with
    /// the same grammar `table_select`/`table_join`/`table_aggregate`
    /// already use, then reports which strategy `querymod.Table.explain`
    /// says a matching `table select`/`table_select` would take - without
    /// running the query or touching any row. A bad table name or malformed
    /// expression is a client mistake (`bad_request`), not a server fault.
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
            return writeErr(writer, .internal, @errorName(err));
        };
        defer plan.deinit(self.allocator);

        const out = protocol.encodePlan(self.allocator, plan) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_update` request: the network counterpart of the
    /// CLI's local `table update <table> --set ... [expr...]`, running
    /// `query.Table.updateWhere` against the server's `*Db`. The wire
    /// `sets` field list arrives pre-encoded with `Row.encode` (the same
    /// trick `decodeTxnOp`'s `fieldsBytes` uses), so it is decoded into a
    /// real `Row` here before `updateWhere` ever sees it. The response is a
    /// bare row count reusing `encodeTtlSweepCount`'s u64 wire shape - the
    /// same "no new response type, an existing shape already fits"
    /// precedent `coll_ttl_op` set for `ttl_op`'s result encoding.
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
            return writeErr(writer, .internal, @errorName(err));
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(updated)) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_delete` request: the network counterpart of the
    /// CLI's local `table delete <table> [expr...]`, running
    /// `query.Table.deleteWhere` against the server's `*Db`. Same wire shape
    /// as `table_explain` (table + exprText, no `SET` clause) and same
    /// response shape as `table_update` (a bare row count reusing
    /// `encodeTtlSweepCount`'s u64 wire shape).
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
            return writeErr(writer, .internal, @errorName(err));
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(deleted)) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_export` request: the network counterpart of the
    /// CLI's local `table export <table> csv|json <path>`, rendering the
    /// whole table through `dump.zig`'s `exportCsvWriter`/`exportJsonWriter`
    /// (the same functions the local path calls, just pointed at an
    /// in-memory `ArrayList` writer instead of a file, since there is no
    /// filesystem path to write to on the server side of a request) and
    /// sending the row count plus the rendered bytes back in one frame.
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
            return writeErr(writer, .internal, @errorName(err));
        };

        const out = protocol.encodeExportResult(self.allocator, @intCast(rowCount), buf.items) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `table_import` request: the network counterpart of the
    /// CLI's local `table import <table> csv|json <path>`, feeding the
    /// wire-carried `content` bytes straight into `dump.zig`'s
    /// `importCsvContent`/`importJsonContent` (the same functions the local
    /// path calls after reading a file into memory - the client already did
    /// that reading, so the server only ever sees bytes, never a path)
    /// against the server's `*Db`. The response is a bare row count, the
    /// same u64 wire shape `table_update`/`table_delete` already use.
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
            return writeErr(writer, .internal, @errorName(err));
        };

        const out = protocol.encodeTtlSweepCount(self.allocator, @intCast(imported)) catch |err| {
            return writeErr(writer, .internal, @errorName(err));
        };
        defer self.allocator.free(out);
        try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
    }

    /// Executes a `user_admin` request (create/set_password/set_role/delete/
    /// list) against a fresh `authmod.Store` over the same `*Db` the rest of
    /// the server serves. Deliberately does NOT consult `self.authStore` -
    /// that field only controls whether *login enforcement* is turned on
    /// for this server, not whether the user table exists, so remote user
    /// management works the same way whether or not `--auth` is active.
    /// `requiredRole` already gates this opcode behind `admin` whenever
    /// auth enforcement IS enabled; a server with auth disabled enforces
    /// nothing on any opcode, this one included, matching every other op's
    /// documented behavior.
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
                        else => writeErr(writer, .internal, @errorName(err)),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .set_password => {
                const rounds = if (args.rounds != 0) args.rounds else authmod.recommendedRounds;
                store.setPassword(self.allocator, args.username, args.password, rounds) catch |err| {
                    return switch (err) {
                        error.UserNotFound => writeErr(writer, .not_found, "user not found"),
                        else => writeErr(writer, .internal, @errorName(err)),
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
                        else => writeErr(writer, .internal, @errorName(err)),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .delete => {
                store.deleteUser(self.allocator, args.username) catch |err| {
                    return switch (err) {
                        error.UserNotFound => writeErr(writer, .not_found, "user not found"),
                        else => writeErr(writer, .internal, @errorName(err)),
                    };
                };
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), "");
            },

            .list => {
                const users = store.listUsers(self.allocator) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer authmod.freeUserList(self.allocator, users);
                const out = protocol.encodeUserList(self.allocator, users) catch |err| {
                    return writeErr(writer, .internal, @errorName(err));
                };
                defer self.allocator.free(out);
                try protocol.writeFrame(writer, @intFromEnum(protocol.Status.ok), out);
            },
        }
    }

    /// Stops accepting new connections and waits for the accept loop to
    /// exit. Closing the listening socket while another thread is
    /// blocked inside `accept()` on that same fd is a race the standard
    /// library treats as a bug (it asserts on EBADF), so instead we flip
    /// `stopping` and connect a throwaway client to our own listen
    /// address: that wakes the pending `accept()` with a real, briefly
    /// alive connection, which the loop then discards and exits on. Only
    /// once the accept thread has rejoined is it safe to close the
    /// listening socket itself.
    ///
    /// Already-accepted connections are `.detach()`ed worker threads this
    /// struct holds no `std.Thread` handle for, so they cannot be `join`ed
    /// directly - `drainConnections` below waits on the `active` counter
    /// instead. This used to be entirely the caller's problem ("leave them
    /// to finish on their own, call `activeConnections()` first if you need
    /// to wait"), but every real caller in this codebase - every test in
    /// this file included - called `stop()` and then immediately tore down
    /// the `Db`/allocator the detached worker's `dispatch()` still reads
    /// from, with nothing enforcing that the worker had actually noticed
    /// its connection closed and returned first. Most of the time the
    /// worker's blocking read already sees EOF and exits before the caller
    /// gets around to teardown, so the race stayed invisible for a long
    /// time; occasionally it does not, and a worker thread touches a freed
    /// `Db`/`Allocator.VTable`, corrupting the heap in a way that only
    /// surfaces later as an unrelated test's leak/double-free abort - this
    /// is exactly the flaky `zig build test` failure the gate re-run in
    /// this session caught (roughly 1 run in 4-6, always attributed to
    /// whichever unrelated test happened to run next). Waiting here by
    /// default, bounded so a genuinely long-lived idle connection (still
    /// blocked in `stream.reader()` with nothing sent and no EOF) cannot
    /// hang shutdown forever, closes that gap for every caller instead of
    /// relying on each one to remember `activeConnections()`.
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
        // Best-effort, same as `drainConnections` above: a subscriber
        // connection that never disconnects (client vanished without
        // closing its socket) is still `active` past the drain timeout, so
        // its `Subscriber` is never `destroySubscriber`'d and leaks for the
        // remaining life of the process - this `deinit` only frees `Hub`'s
        // own channel map, which by then holds no dangling entries for any
        // subscriber that WAS properly torn down.
        self.pubsub.deinit();
    }

    /// Polls `activeConnections()` until it reaches zero or `timeoutNanos`
    /// elapses, whichever comes first. See the doc comment on `stop()` for
    /// why this exists and why it is bounded rather than unconditional.
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

// `drainConnections` only ever touches `self.active`/`self.stopping`, so it
// can be exercised on a `Server` value that was never `init()`ed with a
// real `Db`/socket - every other field stays `undefined` and is never
// read. This isolates the drain/timeout contract itself from the (much
// harder to force deterministically) real-socket race it exists to close.
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
    // Returned once the worker actually finished, not after burning the
    // full 2-second timeout - proves this is a real wait-for-drain, not a
    // fixed sleep in disguise.
    try std.testing.expect(elapsedNanos < 1 * std.time.ns_per_s);
}

test "drainConnections gives up after the timeout instead of hanging forever" {
    var srv = undefinedServerForDrainTest();
    srv.active.store(1, .release); // never decremented by anyone

    const start = std.time.nanoTimestamp();
    srv.drainConnections(20 * std.time.ns_per_ms);
    const elapsedNanos = std.time.nanoTimestamp() - start;

    try std.testing.expect(elapsedNanos >= 20 * std.time.ns_per_ms);
    // Still stuck at 1 - drainConnections gave up, it did not (and cannot)
    // force the phantom connection closed itself.
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
    // Slow refill (1 token/sec): the whole burst below completes in well
    // under a second of wall-clock time, so refill contributes nowhere
    // near a full token and the outcome is deterministic.
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

    // Exhaust A's private budget first: B must be unaffected because each
    // connection got its own bucket, not a bucket shared across the server.
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

    // The global bucket was the one that actually ran out, not the
    // per-connection one (which had plenty of headroom left).
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

    // Single-field index eq on `age`.
    var agePlan = try client.tableExplain(allocator, "users", "age eq i:30");
    defer agePlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_eq, agePlan.kind);
    try std.testing.expectEqualStrings("age", agePlan.indexName.?);

    // Composite index, full prefix matched by equality on both columns.
    var compositePlan = try client.tableExplain(allocator, "users", "city eq s:warsaw and age eq i:30");
    defer compositePlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.composite_eq, compositePlan.kind);
    try std.testing.expectEqualStrings("city_age", compositePlan.indexName.?);
    try std.testing.expectEqual(@as(usize, 2), compositePlan.matchedFields);
    try std.testing.expectEqual(@as(usize, 2), compositePlan.totalFields);

    // No predicate on an indexed field anywhere -> full scan.
    var scanPlan = try client.tableExplain(allocator, "users", "city eq s:warsaw");
    defer scanPlan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.full_scan, scanPlan.kind);

    // Cross-check: what table_explain reports for the composite query is
    // exactly what table_select actually finds when it runs it - the whole
    // point of an explain feature is not lying about what execution does.
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

    // The connection survives a bad_request and can still serve a good
    // request right after - same expectation `table_select`'s malformed-expr
    // test above holds for its own opcode.
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

    // The old index entry is gone for both moved rows...
    const stale = try client.tableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);

    // ...a fresh one under the new value finds them, and the row not
    // matched by the predicate (pk 3, krakow) was left untouched.
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

    // The connection survives a bad_request and can still serve a good
    // request right after - same expectation `table_explain`'s malformed
    // test above holds for its own opcode.
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

    // A well-formed table name ("users"), then a "set fields" byte string
    // that decodeTableUpdate happily hands back as opaque bytes but
    // Row.decode rejects (a field count of 0xFFFFFFFF with nothing behind
    // it) - the decode failure `handleTableUpdate` itself must catch,
    // unlike `decodeTableUpdate`'s own malformed-frame check above it.
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

    // The connection must still be usable afterward.
    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

// `table_update` shares the same underlying-sstable-reshaping hazard as
// `table_select`/`table_join`/`table_aggregate` above, but with a sharper
// edge: `updateWhere` both READS (via `selectAllMatches`) and WRITES (via
// `put`) in the same request, while those three only read. `self.mutex` in
// `Server.dispatch` still serializes every request end-to-end including
// `flush`/`compact`, so no single request can observe a torn sstable set -
// what this test actually proves is that real structural reshaping,
// interleaved via real OS threads through the real TCP/dispatch path, never
// desyncs `updateWhere`'s read-then-write from the index it must keep in
// sync, and that a single updater thread's own sequence of writes lands
// exactly where expected once every other thread has stopped.
//
// Thirty rows split evenly three ways by `@mod(pk, 3)` (same helper as the
// `table_aggregate` concurrency test above) so the "city" index always
// holds exactly 10 rows per bucket - that count must never move, because
// this test's single updater thread only ever touches the "epoch" field,
// never "city" itself, so index population is an invariant a reader can
// check at every single snapshot, not just at the end.
test "table_update survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    // Small target size so a handful of `flush`/`compact` calls do real
    // structural work instead of needing megabytes of data first - same
    // trick as the `table_select`/`table_join`/`table_aggregate`
    // concurrency tests above.
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

    // Final sanity check on a fresh connection: the updater alternated
    // krakow/gdansk, so the last krakow write was iteration 18 (last even
    // below 20) and the last gdansk write was iteration 19 (last odd) -
    // warsaw was never touched by any predicate and must still read 0.
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

// Same shape as the test above, but the index guarding the concurrent
// reads/updates is a COMPOSITE one (`city_age`, two columns) instead of a
// single-column `city` index - `updateWhere` reached through
// `composite_eq` was only proven correct single-threaded so far (see
// query.zig's "updateWhere keeps a composite index in sync" test); this
// proves the same code path survives real `flush`/`compact` reshaping the
// underlying sstables while other connections read and write through it.
test "table_update survives concurrent flush and compact reshaping a composite index" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Db.open(allocator, path, .{ .sstableTargetBytes = 512 });
    defer db.close();

    // 30 rows: 3 cities x 2 age bands x 5 rows each. Every (city, age) pair
    // is a full-tuple equality match against `city_age`, so
    // `Table.selectPage`/`updateWhere` both reach it through `composite_eq`
    // (see query.zig's "createCompositeIndex backfills then full-tuple eq
    // select" test for the same match shape single-threaded).
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
                // Alternates between two full-tuple matches on the composite
                // index, never touching `city`/`age` themselves, so the
                // (5, 5, 5, 5, 5, 5) population split is a checkable
                // invariant on every single reader iteration in flight.
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

    // Final sanity check on a fresh connection: the updater alternated
    // krakow/30 and gdansk/40, so the last krakow/30 write was iteration 18
    // (last even below 20) and the last gdansk/40 write was iteration 19
    // (last odd) - the other four (city, age) combos were never touched by
    // any predicate and must still read epoch 0.
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

        // The composite index must still be the strategy actually used
        // after all this churn, not a fallback to a full scan.
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

    // The index entries for both deleted rows are gone, not just the rows -
    // a stale entry here would surface as a phantom in a later select.
    const gone = try client.tableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, gone);
    try std.testing.expectEqual(@as(usize, 0), gone.len);

    // The row not matched by the predicate (pk 3, krakow) was left untouched.
    const untouched = try client.tableSelect(allocator, "users", "city eq s:krakow", 0, 0, &.{});
    defer protocol.freeRows(allocator, untouched);
    try std.testing.expectEqual(@as(usize, 1), untouched.len);

    // A fresh row can reuse the "warsaw" value without colliding with a
    // leftover index entry from the deleted rows.
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

    // The connection survives a bad_request and can still serve a good
    // request right after - same expectation `table_update`'s malformed
    // test above holds for its own opcode.
    const deleted = try client.tableDelete("users", "");
    try std.testing.expectEqual(@as(u64, 1), deleted);
}

// `handleTableDelete` calls `Table.deleteWhere` directly (see its own
// source), the exact function `Table.delete`'s ON DELETE RESTRICT check
// (query.zig, backed by `ReferencedBySet`) is wired into - so this was
// never a separate opcode to teach about FOREIGN KEY, only a round trip to
// prove the wire path actually reaches it, the same "real dispatch, not
// just the in-process unit test" shape the CHECK/FK/UNIQUE `txn_op` tests
// elsewhere in this file already are.
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

    // Once the referencing order is gone, the same request succeeds.
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

    // A length prefix (0xFFFFFFFF) claiming far more table-name bytes than
    // the payload actually carries - `decodeTableDelete`'s own malformed-frame
    // check must catch this before `Table.open` is ever reached.
    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, 0xFFFFFFFF, .little);
    try payload.appendSlice(&lenBuf);

    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.table_delete), payload.items);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    // The connection must still be usable afterward.
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
    // Every row's primary key shows up somewhere in the rendered JSON -
    // enough to prove the server actually rendered real content instead
    // of an empty/placeholder body, without re-parsing JSON here too.
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

    // `table` is just a keyspace prefix, never declared ahead of time (see
    // `query.Table.open`), so exporting one nothing has ever put a row into
    // is a valid zero-row export, not an error.
    var exported = try client.tableExport(allocator, "nosuch", .csv);
    defer exported.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), exported.rowCount);

    const badImport = client.tableImport("nosuch", .json, "not json");
    try std.testing.expectError(client_mod.ClientError.ServerInternal, badImport);

    // The connection survives an internal error and can still serve a
    // good request right after.
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

    // A well-formed table name ("people") followed by a format byte
    // outside the DumpFormat enum (99) - `decodeTableExport` itself must
    // reject this before `Table.open` is ever reached.
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

    // The connection must still be usable afterward.
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

// `table_delete` shares the same underlying-sstable-reshaping hazard as
// `table_update` above (see that test's header comment for the full
// rationale), but where `updateWhere` reads-then-writes each matched row in
// place, `deleteWhere` reads-then-REMOVES it - a sharper edge again, since a
// removed row's index entries must never resurface even if a `flush`/
// `compact` reshapes the underlying sstables mid-scan. Three buckets
// (warsaw/krakow/gdansk) stay untouched for the whole test and are the
// reader threads' stable invariant (always exactly 10 rows each); a fourth
// bucket (poznan) is what the deleter thread progressively drains one row
// at a time via a "seq" field unrelated to the "city" index, so every
// delete is a distinct, real structural change rather than a no-op repeat.
test "table_delete survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    // Small target size so a handful of `flush`/`compact` calls do real
    // structural work instead of needing megabytes of data first - same
    // trick as `table_update`'s own concurrency test above.
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

    // Final sanity check on a fresh connection: the three stable buckets are
    // still exactly 10 rows each, poznan is completely gone (not just its
    // index entries - real rows too), and no phantom entry survives under
    // the "poznan" index bucket for a later put to collide with.
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

// `table_explain` reports which strategy `selectPage` would use, but
// `table_select`'s own `--order-by` is the one place the network protocol
// carries a sort key: `handleTableSelect` forwards `args.orderBy` into
// `Table.selectPageOrdered`, which must sort BEFORE windowing by
// offset/limit (see query.zig's "applies offset/limit after sorting"
// test). This exercises that ordering end to end over a real socket,
// including on a field that has an index (`age`) - `selectAllMatches`
// still narrows through the index, it just cannot early-stop while a sort
// is pending, and the wire round trip must not lose that.
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
        // pk order deliberately not age order: pk 1 has the highest age
        // (50), pk 5 the lowest (10) - a bug that sorted only within pk
        // scan order would fail every assertion below.
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

    // Descending, windowed to the middle page (offset 1, limit 2). Age
    // decreases as pk increases here, so descending-by-age happens to land
    // on the same row order as ascending pk (pk1..5 = ages 50,40,30,20,10)
    // - the offset/limit window (pk 2, pk 3) is still only correct if the
    // full 5-row set was sorted first and THEN windowed, not windowed off
    // the raw scan and left unsorted (which would coincidentally return
    // the same two rows here, but in the ascending-age windowed case below
    // would not).
    const midDesc = try client.tableSelect(allocator, "users", "", 1, 2, &.{.{ .field = "age", .descending = true }});
    defer protocol.freeRows(allocator, midDesc);
    try std.testing.expectEqual(@as(usize, 2), midDesc.len);
    try std.testing.expectEqual(@as(i64, 2), midDesc[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 40), midDesc[0].get("age").?.int);
    try std.testing.expectEqual(@as(i64, 3), midDesc[1].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 30), midDesc[1].get("age").?.int);

    // Ascending, same window (offset 1, limit 2): ascending-by-age order is
    // pk 5,4,3,2,1 (ages 10,20,30,40,50), so offset 1..3 is pk 4 then pk 3
    // - a DIFFERENT pair than the descending window above, which a
    // window-before-sort bug (paging the raw pk scan, then sorting only
    // the already-cut window) would fail to distinguish.
    const midAsc = try client.tableSelect(allocator, "users", "", 1, 2, &.{.{ .field = "age" }});
    defer protocol.freeRows(allocator, midAsc);
    try std.testing.expectEqual(@as(usize, 2), midAsc.len);
    try std.testing.expectEqual(@as(i64, 4), midAsc[0].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 20), midAsc[0].get("age").?.int);
    try std.testing.expectEqual(@as(i64, 3), midAsc[1].get(querymod.pkField).?.int);
    try std.testing.expectEqual(@as(i64, 30), midAsc[1].get("age").?.int);

    // Cross-check: table_explain reports the `age` index is used for the
    // predicate that would narrow this query, same as the ordered path's
    // `selectAllMatches` internally reuses.
    var plan = try client.tableExplain(allocator, "users", "age gte i:0");
    defer plan.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_range, plan.kind);
}

// A second, INDEPENDENT `orderBy` column exercises a path the single-column
// test above cannot: `handleTableSelect` decoding a wire count > 1 and
// `sortRowsBy`'s tie-breaking chain, both new with multi-column support.
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
        // Two cities, scores deliberately NOT already grouped by city in
        // scan order, so a single-column `city` sort alone would leave
        // each city's rows unsorted by `score` - only a real tiebreak
        // fixes that.
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
    try std.testing.expectEqual(@as(i64, 2), rows[0].get(querymod.pkField).?.int); // krakow/20
    try std.testing.expectEqual(@as(i64, 4), rows[1].get(querymod.pkField).?.int); // krakow/40
    try std.testing.expectEqual(@as(i64, 3), rows[2].get(querymod.pkField).?.int); // warsaw/10
    try std.testing.expectEqual(@as(i64, 1), rows[3].get(querymod.pkField).?.int); // warsaw/30
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

    // Unpaged baseline: 3 distinct cities in first-seen order (warsaw twice
    // seeded first, then krakow, then gdansk added above).
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
    try seedAggregateOrders(allocator, &db); // warsaw: count=2 sum=350, krakow: count=1 sum=40

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

    // Referencing the printed aggregate label (sum_total): only warsaw's
    // group sum clears 100.
    const bySum = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "sum_total gt i:100", "");
    defer protocol.freeAggGroupRows(allocator, bySum);
    try std.testing.expectEqual(@as(usize, 1), bySum.len);
    try std.testing.expectEqualStrings("warsaw", bySum[0].group.text);

    // Referencing the group key itself (city), not just an aggregate result.
    const byGroup = try client.tableAggregateGroups(allocator, "orders", "city", &specs, 0, 0, &.{}, "city eq s:krakow", "");
    defer protocol.freeAggGroupRows(allocator, byGroup);
    try std.testing.expectEqual(@as(usize, 1), byGroup.len);
    try std.testing.expectEqualStrings("krakow", byGroup[0].group.text);

    // A HAVING clause that excludes every group comes back as zero groups,
    // not an error.
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
    // Groups in first-seen order: warsaw(count=2 sum=350), krakow(count=1
    // sum=40), gdansk(count=1 sum=500). HAVING count gt 0 keeps all three,
    // but HAVING sum_total gt i:100 keeps only warsaw and gdansk (in that
    // order) - a limit of 1 must then return warsaw, not krakow (which
    // would be first if the window applied before HAVING).

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
    try seedAggregateOrders(allocator, &db); // global: count=3 sum=390

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
        // Both warsaw rows share the same region on purpose - the whole
        // point of this test is that COUNT(DISTINCT region) collapses them
        // to 1, unlike plain COUNT which would report 2.
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
    try std.testing.expectEqual(@as(i64, 2), groups[0].values[0].int); // COUNT(*)
    try std.testing.expectEqual(@as(i64, 1), groups[0].values[1].int); // COUNT(DISTINCT region)
    try std.testing.expectEqualStrings("krakow", groups[1].group.text);
    try std.testing.expectEqual(@as(i64, 1), groups[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 1), groups[1].values[1].int);

    const globalSpecs = [_]aggregatemod.AggSpec{.{ .field = "region", .kind = .count_distinct }};
    const global = try client.tableAggregateGlobal(allocator, "orders", &globalSpecs, "", "");
    defer protocol.freeAggValues(allocator, global);
    try std.testing.expectEqual(@as(i64, 2), global[0].int); // mazovia + malopolska
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

    // First-seen partition order (warsaw at pk1, krakow at pk3), sorted by
    // total within each partition: warsaw 100 then 250, krakow 40 alone.
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
    // warsaw: total 100 then 250 (running sum), krakow: total 40 alone.
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
        // Two rows tied at day=1 (10, 20), then one row at day=2 (5).
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
    // Both day=1 rows share the tie group's combined total (10+20=30).
    try std.testing.expectEqual(@as(i64, 30), rangeResults[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 30), rangeResults[1].values[0].int);
    try std.testing.expectEqual(@as(i64, 35), rangeResults[2].values[0].int);

    const rowsResults = try client.tableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer protocol.freeWindowRows(allocator, rowsResults);
    try std.testing.expectEqual(@as(usize, 3), rowsResults.len);
    // ROWS: each physical row gets its own running total, even tied ones.
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

    // Sorted by total ascending: krakow/40, warsaw/100, warsaw/250.
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

    // Sorted: krakow/40, warsaw/100, warsaw/250 - lag offset 2 reaches back
    // two physical positions, so only the LAST row has a real source (40);
    // the first two fall outside the sequence and get the -1 default.
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

    // Sorted by total ascending: krakow/40, warsaw/100, warsaw/250 - no ties,
    // so RANGE reduces to one tie group per row (same as ROWS): first_value
    // is always the partition's first row (40, frame start is unaffected by
    // ties), but last_value is each row's OWN value since it is its own
    // singleton tie group.
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

    // Sorted: krakow/40, warsaw/100, warsaw/250. Position 2 (n=2) needs a
    // frame of at least size 2 - the first row's ROWS frame is still just
    // itself (size 1), so it falls back to the caller's default (-1); the
    // remaining two rows both see position 2's value, 100.
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

    // Sorted by total ascending: krakow/40, warsaw/100, warsaw/250 - distinct
    // "city" running count grows 1 (krakow), 2 (warsaw joins), then stays 2
    // (warsaw repeats).
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

    // The CLI's `parseWindowSpec` would reject this before ever sending it,
    // but nothing on the wire itself stops a client from asking for it -
    // `window.computeMany`'s `MissingField` must come back as
    // `bad_request`, not an internal server error.
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .sum }};
    const err = client.tableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, err);
}

// `table_aggregate` shares the exact same underlying-sstable-reshaping
// hazard as `table_select`/`table_join` above (see the `table_select`
// concurrency test's header comment): `flush`/`compact` swap `Db.sstables`
// out from under any in-flight reader while `Server.dispatch`'s `self.mutex`
// is what keeps an aggregate's full-table scan (and the grouping/windowing
// on top of it in `aggregate.zig`) from tearing. Thirty rows split evenly
// three ways by `@mod(pk, 3)` so every group lands on an independently
// checkable count and sum: pk%3==0 -> "warsaw" (pks 3,6,..,30, count 10, sum
// 165), pk%3==1 -> "krakow" (pks 1,4,..,28, count 10, sum 145), pk%3==2 ->
// "gdansk" (pks 2,5,..,29, count 10, sum 155) - global count 30, sum 465.
test "table_aggregate survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    // Small target size so a handful of `flush`/`compact` calls do real
    // structural work instead of needing megabytes of data first - same
    // trick as the `table_select`/`table_join` concurrency tests above.
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

    // Final sanity check on a fresh connection: after all the concurrent
    // churn, the aggregate results are still exactly what they were before
    // the server ever started - the churn wrote only unrelated
    // `agg-churn-*` keys and reshaped physical sstable layout, never touched
    // `orders` values.
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

    // rightExprText filters the orders side before the join runs, same as
    // `innerJoin`'s `rightPred` - narrowing to `total gt i:40` drops one of
    // alice's two orders.
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

    // Unpaged left outer join order: (alice,101) (alice,102) (bob,nil) (carol,nil).
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

// `table_select` is the only networked table opcode - rows can only be
// written locally (CLI `table put`), never over the wire - so this cannot
// reuse the coll_op "many writers, one shared counter" shape. What it CAN
// share with a live server is the sstable storage underneath: `flush` and
// `compact` (both real networked opcodes) mutate `Db.sstables` in place,
// closing and destroying old `Reader`s and swapping in new ones while
// `compact` in particular collapses the whole list down to a single file.
// A `table_select` cursor concurrently mid-scan over those same readers is
// exactly the use-after-free/torn-read shape a missing lock around
// `Server.dispatch` would produce - `self.mutex` must serialize every
// request regardless of which opcode it is, not just same-opcode traffic.
test "table_select survives concurrent flush and compact reshaping the underlying sstables" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    // A small target size so a handful of `flush`/`compact` calls do real
    // structural work instead of needing megabytes of data first.
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
    // A multi-element order-by (city ascending, then age descending as a
    // tiebreak within each city) - `handleTableSelect` decodes a wire
    // orderBy count > 1 into `Table.selectPageOrdered`, which cannot
    // early-stop mid-scan the way an unordered `selectPage` can, so it reads
    // more of the table before sorting. This proves that path survives real
    // `flush`/`compact` reshaping the underlying sstables mid-scan, not just
    // the single-column order-by already covered by
    // "orders a remote result by a field before windowing it" above.
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

    // Final sanity check on a fresh connection: after all the concurrent
    // churn, the table data itself must be byte-for-byte what was written
    // before the server ever started - `flush`/`compact` change physical
    // layout, never live values.
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const finalAll = try client.tableSelect(allocator, "people", "", 0, 0, &.{});
    defer protocol.freeRows(allocator, finalAll);
    try std.testing.expectEqual(@as(usize, rowCount), finalAll.len);
    const finalWarsaw = try client.tableSelect(allocator, "people", "city eq s:warsaw", 0, 0, &.{});
    defer protocol.freeRows(allocator, finalWarsaw);
    try std.testing.expectEqual(@as(usize, rowCount / 3), finalWarsaw.len);

    // Precise check of the multi-column order-by: city groups sorted
    // alphabetically (gdansk < krakow < warsaw), each group internally by
    // age (== pk*2) descending. pk%3 maps 2->gdansk, 1->krakow, 0->warsaw,
    // so each group's highest pk (== highest age) leads that group.
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

// `table_join` shares the exact same underlying-sstable-reshaping hazard as
// `table_select` above (see that test's header comment) - `flush`/`compact`
// swap `Db.sstables` out from under any in-flight reader while
// `Server.dispatch`'s `self.mutex` is what keeps a join's two-table scan
// from tearing. Ten customers / ten orders, deliberately NOT 1:1: two
// customers (9, 10) never appear in `orders`, and two orders (9, 10) carry a
// `customer_id` nobody has, so inner/left/right/full each land on a
// different, independently-checkable pair count instead of degenerating to
// the same number.
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

    // Small target size so a handful of `flush`/`compact` calls do real
    // structural work instead of needing megabytes of data first - same
    // trick as the `table_select` concurrency test above.
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

    // Final sanity check on a fresh connection: all four join shapes are
    // still exactly what they were before the server ever started - the
    // concurrent churn wrote only unrelated `join-churn-*` keys and
    // reshaped physical sstable layout, never touched `customers`/`orders`
    // values.
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

    // A fully independent second connection, never given the password.
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

    // The very same connection re-authenticates and keeps working - the
    // socket itself was never the thing that expired, only the session.
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

    // clientB never authenticated - a separate socket does not inherit
    // clientA's role even though it hits the exact same server/store.
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

    // The account just created over the wire really works for real auth.
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

    // The freshly created account really authenticates against the live,
    // enforced auth store - not just written to a table nobody checks.
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

    // Server's own request counter: 2 sets + 1 ping + this very metrics
    // request itself, all counted in `requestsTotal` before dispatch even
    // looks at the opcode.
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_server_requests_total 4\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cobalt_server_rate_limited_total 0\n") != null);
    // Db stats rendered by the same `formatDbStats` `stats --prom` uses
    // locally, appended after the server's own counters in one response.
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
    // A short-lived session that nobody will ever present again: without
    // the sweeper, this sits in `sessions` forever since `validate()` only
    // cleans up a token someone actually tries to use.
    server.enableSessions(&sessions, 100 * std.time.ns_per_ms);
    server.enableSessionSweep(50 * std.time.ns_per_ms);
    try server.start();
    defer server.stop();

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    try client.authenticate("alice", "hunter2");
    client.close();

    try std.testing.expectEqual(@as(usize, 1), sessions.count());

    // Long enough for the session to expire (100ms) and for at least one
    // sweep tick (every 50ms) to have run past that point.
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

    // The session expired a while ago, but with no sweeper running it is
    // still sitting in the store's map until something calls `validate` on
    // it - `count()` still sees it, unlike the sweeper test above.
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

    // A key with no ttl at all reads back .noExpiry, not .noKey.
    try client.set("plain", "v");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.ttlQuery("plain"));

    // expire on a key that does not exist is a real, distinct failure.
    try std.testing.expectError(client_mod.ClientError.ServerKeyNotFound, client.ttlExpire("ghost", 60));

    // expire on an existing key sets a marker the query action can see.
    // Real wall-clock time (both `expire` and `query` stamp their own
    // `std.time.nanoTimestamp()` server-side) can shave a second off by
    // the time the second round trip lands, so accept 59 or 60 rather
    // than pinning an exact value.
    try client.ttlExpire("plain", 60);
    const withTtl = try client.ttlQuery("plain");
    try std.testing.expect(withTtl.seconds == 59 or withTtl.seconds == 60);

    // persist removes the marker again, back to .noExpiry.
    try client.ttlPersist("plain");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.ttlQuery("plain"));

    // sweep over a key that is already due for expiry reaps exactly it,
    // and a real subsequent get proves the delete was real, not marker-only.
    try client.set("doomed", "x");
    try client.ttlExpire("doomed", 0);
    std.time.sleep(5 * std.time.ns_per_ms);
    const reaped = try client.ttlSweep();
    try std.testing.expectEqual(@as(u64, 1), reaped);
    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "doomed"));

    // querying a key that was never there at all (not merely expired) is
    // .noKey, distinct from .noExpiry.
    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery("never-existed"));
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

    // query is readonly: a readonly connection can run it.
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try reader.ttlQuery("k"));

    // expire/persist/sweep all mutate: forbidden for a readonly connection.
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlExpire("k", 30));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlPersist("k"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.ttlSweep());

    // The readwrite connection can do all four.
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

    // Long enough for the key to be due and for at least one sweep tick
    // (every 50ms) to run past that point - nobody ever reads "a" again,
    // so without the background sweeper it would sit there forever (only
    // `ttl.getLive`'s lazy path or an explicit sweep would ever catch it).
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

    // Nothing swept it in the background, but the key IS logically due -
    // client.get goes straight through db.get (not the lazy ttl path), so
    // the underlying value is still physically present until something
    // sweeps it.
    try std.testing.expectEqual(@as(u64, 0), server.ttlSweptTotal.get());
    const v = (try client.get(allocator, "a")).?;
    allocator.free(v);
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

    // A hash with no ttl at all reads back .noExpiry, not .noKey - the
    // collection itself has to actually exist server-side first, created
    // directly through `db` here for brevity (the `coll_op` opcode below
    // is this same test file's own coverage for reaching it remotely).
    _ = try collmod.Hash.set(&db, allocator, "profile", "name", "ada");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.collTtlQuery(.hash, "profile"));

    // expire on a collection that does not exist is a real, distinct failure.
    try std.testing.expectError(client_mod.ClientError.ServerCollectionNotFound, client.collTtlExpire(.hash, "ghost", 60));

    // expire on an existing collection sets a marker the query action can
    // see. Real wall-clock time can shave a second off by the time the
    // second round trip lands, so accept 59 or 60 rather than an exact value.
    try client.collTtlExpire(.hash, "profile", 60);
    const withTtl = try client.collTtlQuery(.hash, "profile");
    try std.testing.expect(withTtl.seconds == 59 or withTtl.seconds == 60);

    // persist removes the marker again, back to .noExpiry.
    try client.collTtlPersist(.hash, "profile");
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try client.collTtlQuery(.hash, "profile"));

    // sweep over a collection that is already due for expiry reaps exactly
    // it, and the whole hash (not just one field) is really gone afterwards.
    _ = try collmod.Hash.set(&db, allocator, "doomed", "k", "v");
    try client.collTtlExpire(.hash, "doomed", 0);
    std.time.sleep(5 * std.time.ns_per_ms);
    const reaped = try client.collTtlSweep();
    try std.testing.expectEqual(@as(u64, 1), reaped);
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "doomed"));

    // querying a collection that was never there at all (not merely
    // expired) is .noKey, distinct from .noExpiry.
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

    // query is readonly: a readonly connection can run it.
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try reader.collTtlQuery(.hash, "k"));

    // expire/persist/sweep all mutate: forbidden for a readonly connection.
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlExpire(.hash, "k", 30));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlPersist(.hash, "k"));
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collTtlSweep());

    // The readwrite connection can do all four.
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

    // A single byte is enough for an action but not the kind byte that
    // must follow it, so `decodeCollTtlOp` fails on the second `takeByte`.
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

    // Long enough for the collection to be due and for at least one sweep
    // tick (every 50ms) to run past that point - nobody ever reads "board"
    // again, so without the background sweeper it would sit there forever.
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

    // Nothing swept it in the background, but the collection IS logically
    // due - it is still physically present until something sweeps it.
    try std.testing.expectEqual(@as(u64, 0), server.collTtlSweptTotal.get());
    try std.testing.expect(try collmod.collectionExists(&db, allocator, .set, "tags"));
}

test "a server with the flat ttl sweeper and the coll ttl sweeper enabled at once runs both independently" {
    // Every prior session's notes on both sweepers flagged the same gap:
    // `enableTtlSweep` and `enableCollTtlSweep` start two structurally
    // independent background threads on the same `Server` (separate
    // fields, separate `std.Thread.spawn` calls, separate join calls in
    // `stop()`), but nothing had ever exercised them running at the same
    // time. This proves three things at once: a flat key due for
    // expiry and a whole collection due for expiry both get reaped by
    // their OWN sweeper without either one starving or double-counting
    // the other's target, and `stop()` cleanly joins both sweeper threads
    // (the exact bug class caught and fixed in session #28, where a
    // missing join on one sweeper thread left it alive past `db.close()`
    // and segfaulted the next test).
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

    // Poll rather than sleep a single fixed window: two background
    // sweeper threads plus the accept/connection threads contending for
    // `self.mutex` on a loaded host can occasionally push either sweeper's
    // tick past a fixed 300ms, which is not a correctness bug in the
    // sweeper - it is exactly the kind of host-load flakiness this
    // project's own frostbyte sessions document repeatedly. Waiting up to
    // 3s in 50ms increments keeps the assertion meaningful (still fails
    // for real if a sweeper never runs) without being a coin flip on a
    // busy machine.
    var waited: u64 = 0;
    while (waited < 3000 and (server.ttlSweptTotal.get() == 0 or server.collTtlSweptTotal.get() == 0)) {
        std.time.sleep(50 * std.time.ns_per_ms);
        waited += 50;
    }

    try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, "flatkey"));
    try std.testing.expect(!try collmod.collectionExists(&db, allocator, .hash, "session:1"));
    try std.testing.expect(server.ttlSweptTotal.get() >= 1);
    try std.testing.expect(server.collTtlSweptTotal.get() >= 1);

    // Neither sweeper's counter absorbed the other's reap: exactly one
    // flat key was due and exactly one collection was due, so each
    // counter reads exactly 1, not a shared/blended total.
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

    // Counter: get on a name nobody ever touched defaults to 0, set
    // pins an exact value, incrby accumulates - the same three-step
    // shape `collections.test.counter incrBy accumulates` already
    // covers locally, now round-tripped over the wire.
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

    // Hash: set reports created vs updated as 1/0, get returns the
    // value or nil, del removes a field, len/getall reflect what remains.
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

    // Set: add/rem/ismember/card/members plus the three multi-set ops,
    // where `name` is the first set and the extra `args` are the rest -
    // the same split `runColl` uses locally for `args[0]` vs `args[1..]`.
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

    // List: push both ends, pop both ends, range with a redis-style
    // negative index, len reflecting what remains.
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

    // ZSet: add/incrby/score/rank/card/rangebyrank/rangebyscore, with a
    // real fractional score to exercise the f64 wire encoding end to end.
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

// Closes the gap every `coll_op` session note since #30 has flagged and
// deferred: every existing `coll_op` test drives ONE connection at a
// time, so nothing has ever proven that many independent TCP connections
// hammering `coll_op` against the SAME named collection concurrently are
// safe - `Server.dispatch` takes `self.mutex` once per request exactly
// like every other opcode, but that claim had never been exercised here
// with real OS threads and real sockets the way `concurrent.zig`'s
// `GuardedDb` tests already exercise `Db`/`TableTxn` directly.
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
    // Every increment is a separate request from a separate connection, so
    // a missing lock around `runColl`'s read-modify-write would show up
    // here as a total strictly less than threadCount*perThread (lost
    // updates), not as a crash - the mutex in `Server.dispatch` must make
    // this land on the exact total every single run.
    try std.testing.expectEqual(@as(i64, threadCount * perThread), total.int);
}

// Same shape as the counter test above but for a structural collection
// (`Set`) instead of a single scalar: many connections each add their OWN
// disjoint members to one shared set, so a race would show up as a
// missing member (an add silently lost to a concurrent writer) rather
// than a wrong total, which is a different failure mode than incrBy's
// lost-update and worth its own proof.
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

    // Spot-check a member from every thread, not just the aggregate count -
    // a bug that dropped exactly one member per thread but "gained" one
    // duplicate elsewhere could still pass the cardinality check above.
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

    // The lazy check in `handleCollOp` reaps "session" before hash_get
    // ever runs, so the field reads back as gone, not as its old value.
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

    // "b" is due but is only referenced through `args`, never `name` - if
    // the handler only checked `name` (like it does for every single-name
    // action), "b" would still look alive here and `intersect` would see
    // its stale "x" member. It must come back empty instead.
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

    // hash_get is read-only: a readonly connection can run it.
    var got = try reader.collOp(allocator, .hash_get, "k", &[_][]const u8{"f"});
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("v", got.bytes);

    // hash_set mutates: forbidden for a readonly connection.
    try std.testing.expectError(client_mod.ClientError.ServerForbidden, reader.collOp(allocator, .hash_set, "k", &[_][]const u8{ "f", "v2" }));

    // The readwrite connection can do it. "f" already exists, so hash_set
    // reports it as updated (0), not created (1) - same int-flag shape as
    // set_add/set_rem/hash_del elsewhere in this opcode, not `.ok`.
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

    // A single action byte is not enough to decode the length-prefixed
    // name that must follow it.
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

    // counter_set needs a value argument - a well-formed frame that omits
    // it should come back as a clean bad_request, not an internal error or
    // a crash from indexing into an empty args slice.
    try std.testing.expectError(client_mod.ClientError.ServerBadRequest, client.collOp(allocator, .counter_set, "n", &.{}));
}

// Same ksztalt of proof as the two `coll_op` concurrency tests above
// (many real OS threads, each its own TCP connection, hammering shared
// server state) but for `ttl_op` instead - the next direction flagged at
// the end of session solo #32 (cobalt-postep.md). `ttl_op` has no shared
// mutable VALUE the way a counter or set does (each writer's key is its
// own, disjoint from every other writer's), so the race worth proving
// here is different: writer connections racing `set`+`expire` against
// sweeper connections racing `sweep`, all against the SAME `Db.sstables`/
// memtable underneath. `ttl.sweepExpired` reads its own prefix scan and
// deletes what it found within a single `handleTtlOp` call, which the
// `self.mutex` in `Server.dispatch` executes atomically end-to-end, so a
// key can never be swept twice and no swept count can double-count - the
// grand total across every sweep response plus one final mop-up sweep
// must land on exactly the number of keys written, with zero lost and
// zero duplicated, no matter how the OS interleaves the connections.
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

    // Any key that lost the race against every sweeper (written after the
    // last sweep call landed) is mopped up by one final sweep here.
    const finalReaped = try client.ttlSweep();

    var total: u64 = finalReaped;
    for (0..sweeperCount) |i| total += sweepContexts[i].reaped.load(.monotonic);
    try std.testing.expectEqual(@as(u64, writerCount * perWriter), total);

    // Spot-check one key from every writer thread: all must be truly gone
    // (not just marker-cleared), proving the sweeps were real deletes.
    for (0..writerCount) |t| {
        var buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "ttl-conc-{d}-0", .{t});
        try std.testing.expectEqual(@as(?[]u8, null), try client.get(allocator, key));
        try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.ttlQuery(key));
    }
}

// Mirrors the `ttl_op` concurrency test above but against `coll_ttl_op`
// and a real collection (`Counter`) instead of a flat key - the sibling
// gap the same end-of-#32 note called out explicitly ("ttl_op dziala na
// plaskim keyspace... analogiczny test... jest wykonalny, ale odlozony").
// `collttl.sweepExpired` (collttl.zig) shares the exact same
// scan-then-delete-within-one-call shape as `ttl.sweepExpired`, so the
// same exactly-once accounting argument applies.
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

    // Spot-check one collection from every writer thread: the WHOLE
    // counter namespace must be gone, not merely its TTL marker.
    for (0..writerCount) |t| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "ttlcoll-conc-{d}-0", .{t});
        try std.testing.expect(!try collmod.collectionExists(&db, allocator, .counter, name));
        try std.testing.expectEqual(ttlmod.TtlResult.noKey, try client.collTtlQuery(.counter, name));
    }
}

// `coll_op`/`ttl_op`/`coll_ttl_op`/`table_select` above all have their own
// concurrency proof now (#31/#32/#33's end-of-session notes tracked this
// gap explicitly); `user_admin` was the one opcode still missing one. Its
// shared mutable state is `auth.Store` (auth.zig), itself just a thin
// get/put layer over the same `*Db` - `createUser` is a plain
// check-then-write (`db.get` then `db.put`, no compare-and-swap), so a
// missing lock around it would let two concurrent `create` calls for the
// SAME username both observe "absent" and both write, silently doubling
// the account (or worse, interleaving two different `UserRecord.encode()`
// outputs into one key). `self.mutex` in `Server.dispatch` is the only
// thing standing between that and reality here, same as every other
// opcode's concurrency test in this file.
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
    // A missing lock around the check-then-write in `createUser` would let
    // more than one racer observe "absent" and both succeed, so this must
    // land on EXACTLY one winner - not "at least one".
    try std.testing.expectEqual(@as(usize, 1), createdCount);
    try std.testing.expectEqual(@as(usize, threadCount - 1), conflictedCount);

    var client = try client_mod.Client.connect(allocator, server.boundAddress());
    defer client.close();
    const users = try client.adminListUsers(allocator);
    defer authmod.freeUserList(allocator, users);
    // Guards against the OTHER failure mode a lost lock could produce: the
    // two racing `db.put` calls interleaving their encoded bytes into one
    // corrupted record instead of cleanly overwriting each other, which
    // would still leave exactly one key but might fail to decode, or a
    // duplicate row under the same key if compaction ever saw two
    // physically distinct writes land as one logically doubled entry.
    try std.testing.expectEqual(@as(usize, 1), users.len);
    try std.testing.expectEqualStrings("shared-user", users[0].username);
}

// Same shared-mutex proof as the create-race test above, but for the
// read-modify-write shape (`setPassword`/`setRole`, each its own
// `mustGet` then `db.put`) rather than the check-then-write shape of
// `create`, plus a concurrent reader (`list`) racing the writers - the
// third distinct access pattern `user_admin` exposes over the wire.
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
                // Any decode failure inside the server (a torn/corrupted
                // record) surfaces here as `error.ServerInternal`, not a
                // silently wrong answer, since `handleUserAdmin` maps every
                // `UserRecord.decode` error straight to an `internal`
                // status frame.
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

    // A final, deterministic write from the main thread after every racer
    // has joined, then verified through `auth.Store.verify` directly
    // (bypassing the network entirely) against the SAME `*Db` the server
    // just hammered concurrently: this proves the record surviving on disk
    // is not merely "decodable" (the readers above already checked that)
    // but functionally intact - the exact salt/rounds/hash triple that
    // `setPassword` wrote is still paired correctly with the role
    // `setRole` wrote after it, not a torn mix of two different racers'
    // writes.
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

// `txn_op` is the network counterpart of the local CLI's `txn <script>`
// (main.zig's `runTxn`) - until now atomic multi-row/multi-table commits
// were reachable only from a process holding the `Db` directly, the same
// gap `table_select`/`coll_op`/`ttl_op` already closed for their own
// subsystems. This round trip exercises both verbs across two tables in
// one commit, including a pre-existing secondary index, to prove the field
// list and primary key survive the wire encoding (`Row.encode`/
// `rowmod.encodeValue`) intact enough for `TableTxn.put`'s index
// maintenance to run correctly on the decoded side, not just for the raw
// bytes to round-trip in isolation the way protocol.zig's own unit tests
// already check.
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

// Closes a gap left open by the CHECK constraint's introduction alongside
// UNIQUE/FOREIGN KEY: `TableTxn.put` enforces all three identically (see
// txn_table.zig), and this server's only write path (`handleTxnOp`) already
// runs every entry through `TableTxn.put` - so a remote `txn_op` rejecting a
// CHECK violation was already true the moment `TableTxn.put` gained the
// check, never separately wired. This test is the same kind of "prove the
// wire path actually exercises it, not just the in-process unit test" round
// trip the FK/UNIQUE `txn_op` test above already is.
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

    // Whole transaction is atomic across both entries: the earlier,
    // individually-valid row 1 must not have been committed either.
    var orders = try querymod.Table.open(&db, allocator, "orders");
    defer orders.deinit();
    try std.testing.expect((try orders.get(.{ .int = 1 })) == null);
    try std.testing.expect((try orders.get(.{ .int = 2 })) == null);
}

// `handleTxnOp` runs every entry through `TableTxn.put`/`TableTxn.delete`
// (see txn_table.zig), which now enforce ON DELETE RESTRICT exactly like
// CHECK/UNIQUE/FOREIGN KEY on put above - never separately wired for this
// opcode either. The interesting case a plain `table_delete` test cannot
// cover: both the child insert AND the restricted parent delete are only
// staged within this ONE `txn_op` batch, never durable on their own -
// `TableTxn.delete`'s RESTRICT check has to see the child through
// `Transaction.scanPrefix`'s same-transaction visibility (see
// txn_table.zig's own unit test for this), not a plain Db scan, or this
// would wrongly let the delete through.
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

    // Nothing committed: neither the staged order nor the rejected delete.
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

    // A u32 entry count of 1 promises one full entry, but the payload ends
    // right after it - not even a verb byte follows.
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, 1, .little);
    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.txn_op), &payload);
    var frame = try protocol.readFrame(allocator, stream.reader());
    defer frame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.bad_request), frame.tag);

    // The connection must still be usable afterward - a malformed frame is
    // a client mistake, not a fatal error for the server.
    try protocol.writeFrame(stream.writer(), @intFromEnum(protocol.Op.ping), "");
    var pingFrame = try protocol.readFrame(allocator, stream.reader());
    defer pingFrame.deinit();
    try std.testing.expectEqual(@intFromEnum(protocol.Status.ok), pingFrame.tag);
}

// Proves the `txn_op` code path (decode -> `Transaction`/`TableTxn` ->
// index maintenance -> commit, all under `Server.dispatch`'s single
// `self.mutex`) holds up under real concurrent OS threads each on their
// own real TCP connection - the same rigor `coll_op`'s/`table_select`'s
// own concurrency tests apply, but for the table+index layer instead of
// the flat keyspace or the Redis-like collections, which is a genuinely
// different code path (this is the first concurrency test to drive
// `TableTxn`/index maintenance through a live socket at all;
// `concurrent.zig`'s own `TableTxn` concurrency test bypasses the network
// entirely via `GuardedDb`). Each worker writes into two disjoint rows per
// round (its own row in `widgets`, indexed by `owner`, and a companion row
// in `tags`) so a lost or duplicated write from bad interleaving would
// show up as a wrong row count or a wrong index membership, not just a
// wrong number.
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
        // Every widget this thread wrote must show up under its own index
        // entry, exactly `perThread` of them - not fewer (a lost write)
        // and not more (a duplicated one).
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
    // A no-receiver publish is not a mutation of anything - `ping` still
    // works on the same connection right after, proving `publish` never
    // left the connection or the server in some half-dispatched state.
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

    // The watcher thread's disconnect detection runs asynchronously - poll
    // with a bounded timeout instead of a fixed sleep, the same style
    // `drainConnections` already uses elsewhere in this file.
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

    // The subscribe connection itself never answers another request (see
    // `handleSubscribe`'s doc comment) - unsubscribe always goes over its
    // own, separate connection.
    var ctrl = try client_mod.Client.connect(allocator, server.boundAddress());
    defer ctrl.close();
    const removed = try ctrl.unsubscribe(subId, &.{"orders"});
    try std.testing.expectEqual(@as(u32, 1), removed);
    // `ctrl` is an ordinary connection - it must still answer further
    // requests normally after an unsubscribe, proving `handleUnsubscribe`
    // returns like any other opcode rather than hijacking the connection.
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

