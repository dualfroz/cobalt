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

