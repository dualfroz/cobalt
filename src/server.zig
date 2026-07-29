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

