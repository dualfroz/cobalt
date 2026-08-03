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

