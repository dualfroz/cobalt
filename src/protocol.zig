const std = @import("std");
const encode = @import("encode.zig");
const dbmod = @import("db.zig");
const rowmod = @import("row.zig");
const authmod = @import("auth.zig");
const ttlmod = @import("ttl.zig");
const collmod = @import("collections.zig");
const aggregatemod = @import("aggregate.zig");
const windowmod = @import("window.zig");
const querymod = @import("query.zig");

const Allocator = std.mem.Allocator;

/// Guard against a corrupt or hostile length prefix causing an unbounded
/// allocation before a single byte of the frame body has been validated.
pub const maxFrameBytes: u32 = 64 * 1024 * 1024;

pub const Op = enum(u8) {
    ping = 0,
    get = 1,
    set = 2,
    del = 3,
    scan = 4,
    prefix = 5,
    stats = 6,
    flush = 7,
    compact = 8,
    batch = 9,
    table_select = 10,
    auth = 11,
    user_admin = 12,
    auth_token = 13,
    metrics = 14,
    ttl_op = 15,
    coll_ttl_op = 16,
    coll_op = 17,
    txn_op = 18,
    table_join = 19,
    table_aggregate = 20,
    table_explain = 21,
    table_update = 22,
    table_delete = 23,
    table_export = 24,
    table_import = 25,
    table_window = 26,
    subscribe = 27,
    publish = 28,
    unsubscribe = 29,

    pub fn fromByte(b: u8) !Op {
        return std.meta.intToEnum(Op, b) catch error.UnknownOp;
    }
};

pub const Status = enum(u8) {
    ok = 0,
    not_found = 1,
    bad_request = 2,
    io_error = 3,
    conflict = 4,
    internal = 5,
    rate_limited = 6,
    unauthorized = 7,
    forbidden = 8,

    pub fn fromByte(b: u8) !Status {
        return std.meta.intToEnum(Status, b) catch error.UnknownStatus;
    }
};

pub const ProtoError = error{
    UnknownOp,
    UnknownStatus,
    FrameTooLarge,
    Malformed,
};

/// A frame is the unit exchanged over the wire in both directions: a
/// single tag byte (an `Op` on the request side, a `Status` on the
/// response side) followed by a little-endian u32 payload length and the
/// payload itself.
pub const Frame = struct {
    tag: u8,
    payload: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Frame) void {
        self.allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn writeFrame(writer: anytype, tag: u8, payload: []const u8) !void {
    if (payload.len > maxFrameBytes) return error.FrameTooLarge;
    var header: [5]u8 = undefined;
    header[0] = tag;
    std.mem.writeInt(u32, header[1..5], @intCast(payload.len), encode.endian);
    try writer.writeAll(&header);
    if (payload.len > 0) try writer.writeAll(payload);
}

pub fn readFrame(allocator: Allocator, reader: anytype) !Frame {
    var header: [5]u8 = undefined;
    try reader.readNoEof(&header);
    const tag = header[0];
    const len = std.mem.readInt(u32, header[1..5], encode.endian);
    if (len > maxFrameBytes) return error.FrameTooLarge;
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    if (len > 0) try reader.readNoEof(payload);
    return .{ .tag = tag, .payload = payload, .allocator = allocator };
}

/// Bounds-checked cursor over a decoded payload. Every read returns
/// `error.Malformed` instead of panicking when the peer sent a short or
/// truncated buffer, since payload bytes come from an untrusted socket.
pub const Cursor = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn takeByte(self: *Cursor) !u8 {
        if (self.pos + 1 > self.data.len) return error.Malformed;
        const v = self.data[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn takeU32(self: *Cursor) !u32 {
        if (self.pos + 4 > self.data.len) return error.Malformed;
        const v = encode.readU32(self.data, self.pos);
        self.pos += 4;
        return v;
    }

    pub fn takeU64(self: *Cursor) !u64 {
        if (self.pos + 8 > self.data.len) return error.Malformed;
        const v = encode.readU64(self.data, self.pos);
        self.pos += 8;
        return v;
    }

    pub fn takeBytes(self: *Cursor, n: usize) ![]const u8 {
        if (self.pos + n > self.data.len) return error.Malformed;
        const v = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return v;
    }

    pub fn takeLenPrefixed(self: *Cursor) ![]const u8 {
        const n = try self.takeU32();
        return self.takeBytes(n);
    }

    pub fn atEnd(self: *Cursor) bool {
        return self.pos == self.data.len;
    }
};

fn putLenPrefixed(writer: encode.ByteWriter, v: []const u8) !void {
    try writer.putU32(@intCast(v.len));
    try writer.slice(v);
}

// --- set ---

pub fn encodeSet(allocator: Allocator, key: []const u8, value: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, key);
    try w.slice(value);
    return buf.toOwnedSlice();
}

pub const SetArgs = struct { key: []const u8, value: []const u8 };

pub fn decodeSet(payload: []const u8) !SetArgs {
    var c = Cursor{ .data = payload };
    const key = try c.takeLenPrefixed();
    const value = c.data[c.pos..];
    return .{ .key = key, .value = value };
}

// --- auth ---

pub fn encodeAuth(allocator: Allocator, username: []const u8, password: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, username);
    try w.slice(password);
    return buf.toOwnedSlice();
}

pub const AuthArgs = struct { username: []const u8, password: []const u8 };

pub fn decodeAuth(payload: []const u8) !AuthArgs {
    var c = Cursor{ .data = payload };
    const username = try c.takeLenPrefixed();
    const password = c.data[c.pos..];
    return .{ .username = username, .password = password };
}

/// A successful `auth` response's payload: empty when the server has no
/// session store wired up (see server.zig's `enableSessions`), or the raw
/// session token bytes when it does. There is no separate decode function
/// on the client side - `frame.payload` itself IS the token (or empty),
/// no framing needed for a single opaque blob.
pub fn encodeAuthOk(allocator: Allocator, token: ?[]const u8) ![]u8 {
    return allocator.dupe(u8, token orelse "");
}

// --- auth_token ---

/// Reconnects a fresh connection to a role without presenting the
/// password again, by presenting a token previously handed out in an
/// `auth` response (see `session.zig`'s `SessionStore.issue`). The
/// payload is nothing but the opaque token bytes - no framing needed for
/// a single blob, exactly like `encodeAuthOk`.
pub fn encodeAuthToken(allocator: Allocator, token: []const u8) ![]u8 {
    return allocator.dupe(u8, token);
}

pub fn decodeAuthToken(payload: []const u8) []const u8 {
    return payload;
}

// --- user_admin ---

/// Remote counterpart of the CLI's local `user add|passwd|role|del|list`,
/// carried as one opcode so `server.zig`'s `requiredRole` can gate all five
/// actions behind a single `admin`-only check instead of five separate
/// opcodes. `role`/`rounds` are only meaningful for the actions that use
/// them (`create` reads both, `set_role` reads only `role`, `set_password`
/// reads only `rounds`); callers send 0 for the fields an action ignores.
pub const UserAdminAction = enum(u8) {
    create = 0,
    set_password = 1,
    set_role = 2,
    delete = 3,
    list = 4,

    pub fn fromByte(b: u8) !UserAdminAction {
        return std.meta.intToEnum(UserAdminAction, b) catch error.Malformed;
    }
};

pub fn encodeUserAdmin(allocator: Allocator, action: UserAdminAction, username: []const u8, password: []const u8, role: authmod.Role, rounds: u32) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(action));
    try w.byte(@intFromEnum(role));
    try w.putU32(rounds);
    try putLenPrefixed(w, username);
    try w.slice(password);
    return buf.toOwnedSlice();
}

pub const UserAdminArgs = struct {
    action: UserAdminAction,
    roleByte: u8,
    rounds: u32,
    username: []const u8,
    password: []const u8,
};

pub fn decodeUserAdmin(payload: []const u8) !UserAdminArgs {
    var c = Cursor{ .data = payload };
    const action = try UserAdminAction.fromByte(try c.takeByte());
    const roleByte = try c.takeByte();
    const rounds = try c.takeU32();
    const username = try c.takeLenPrefixed();
    const password = c.data[c.pos..];
    return .{ .action = action, .roleByte = roleByte, .rounds = rounds, .username = username, .password = password };
}

/// Encodes the response of a `list` user_admin request: every username
/// paired with its role byte. Reuses `authmod.UserInfo`/`freeUserList`
/// rather than inventing a parallel type, the same way `encodeStats` reuses
/// `dbmod.Stats` and `encodeRows` reuses `rowmod.Row`.
pub fn encodeUserList(allocator: Allocator, users: []const authmod.UserInfo) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(users.len));
    for (users) |u| {
        try putLenPrefixed(w, u.username);
        try w.byte(@intFromEnum(u.role));
    }
    return buf.toOwnedSlice();
}

/// Decodes a user list response into independently owned entries - free
/// with `authmod.freeUserList`.
pub fn decodeUserList(allocator: Allocator, payload: []const u8) ![]authmod.UserInfo {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(authmod.UserInfo).initCapacity(allocator, count);
    errdefer {
        for (list.items) |u| u.deinit(allocator);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const uname = try c.takeLenPrefixed();
        const role = authmod.Role.fromByte(try c.takeByte()) catch return error.Malformed;
        const owned = try allocator.dupe(u8, uname);
        list.appendAssumeCapacity(.{ .username = owned, .role = role });
    }
    return list.toOwnedSlice();
}

// --- ttl_op ---

/// Remote counterpart of the CLI's local `expire`/`persist`/`ttl`/
/// `expire-sweep` (main.zig, backed by `ttl.zig`), carried as one opcode the
/// same way `user_admin` bundles five user-management actions under one
/// opcode - see server.zig's `requiredRole`, which (unlike `user_admin`'s
/// blanket `admin` gate) inspects this action byte: `query` is read-only
/// and needs only `readonly`; `expire`/`persist`/`sweep` all mutate (sweep
/// deletes every due key) and need `readwrite`, matching every other write
/// opcode.
pub const TtlAction = enum(u8) {
    expire = 0,
    persist = 1,
    query = 2,
    sweep = 3,

    pub fn fromByte(b: u8) !TtlAction {
        return std.meta.intToEnum(TtlAction, b) catch error.Malformed;
    }
};

/// `seconds` is only meaningful for `expire` - callers send 0 for the other
/// three actions, same "unused fields carry a zero" convention as
/// `encodeUserAdmin`'s `role`/`rounds`. `key` is empty for `sweep`, which
/// operates on every due key in the store rather than one specific key.
pub fn encodeTtlOp(allocator: Allocator, action: TtlAction, key: []const u8, seconds: u64) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(action));
    try w.putU64(seconds);
    try w.slice(key);
    return buf.toOwnedSlice();
}

pub const TtlOpArgs = struct { action: TtlAction, seconds: u64, key: []const u8 };

pub fn decodeTtlOp(payload: []const u8) !TtlOpArgs {
    var c = Cursor{ .data = payload };
    const action = try TtlAction.fromByte(try c.takeByte());
    const seconds = try c.takeU64();
    const key = c.data[c.pos..];
    return .{ .action = action, .seconds = seconds, .key = key };
}

/// Encodes the response to a `query` ttl_op: reuses `ttlmod.TtlResult`
/// rather than inventing a parallel type, the same way `encodeStats` reuses
/// `dbmod.Stats` and `encodeUserList` reuses `authmod.UserInfo`.
pub fn encodeTtlResult(allocator: Allocator, result: ttlmod.TtlResult) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    switch (result) {
        .noKey => try w.byte(0),
        .noExpiry => try w.byte(1),
        .seconds => |s| {
            try w.byte(2);
            try w.putU64(s);
        },
    }
    return buf.toOwnedSlice();
}

pub fn decodeTtlResult(payload: []const u8) !ttlmod.TtlResult {
    var c = Cursor{ .data = payload };
    const kind = try c.takeByte();
    return switch (kind) {
        0 => .noKey,
        1 => .noExpiry,
        2 => .{ .seconds = try c.takeU64() },
        else => error.Malformed,
    };
}

/// Encodes the response to a `sweep` ttl_op: how many due keys were reaped.
pub fn encodeTtlSweepCount(allocator: Allocator, count: u64) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(count);
    return buf.toOwnedSlice();
}

pub fn decodeTtlSweepCount(payload: []const u8) !u64 {
    var c = Cursor{ .data = payload };
    return c.takeU64();
}

// --- coll_ttl_op ---

/// Remote counterpart of the CLI's local `coll <kind> expire|ttl|persist
/// <name>`/`coll expire-sweep` (main.zig, backed by `collttl.zig`), same
/// bundling shape as `ttl_op` above but for a whole typed collection
/// (Counter/Hash/Set/List/ZSet) instead of one flat key - so the payload
/// carries an extra `Kind` tag byte the flat version does not need.
/// Reuses `TtlAction` directly rather than a parallel enum: the four
/// actions (expire/persist/query/sweep) mean exactly the same thing here,
/// just against `collttl.zig` instead of `ttl.zig`.
pub fn encodeCollTtlOp(allocator: Allocator, action: TtlAction, kind: collmod.Kind, name: []const u8, seconds: u64) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(action));
    // `sweep` operates across every kind at once (collttl.sweepExpired
    // scans the whole marker namespace, not one kind's slice of it), so
    // the kind byte is meaningless for that action - callers pass any
    // valid `Kind` and `decodeCollTtlOp` still decodes it, but
    // `handleCollTtlOp` never reads it for `.sweep`. Same "unused field
    // still round-trips" convention as `encodeTtlOp`'s zeroed `seconds`
    // on non-`expire` actions.
    try w.byte(kind.tagByte());
    try w.putU64(seconds);
    try w.slice(name);
    return buf.toOwnedSlice();
}

pub const CollTtlOpArgs = struct { action: TtlAction, kind: collmod.Kind, seconds: u64, name: []const u8 };

pub fn decodeCollTtlOp(payload: []const u8) !CollTtlOpArgs {
    var c = Cursor{ .data = payload };
    const action = try TtlAction.fromByte(try c.takeByte());
    const kind = collmod.Kind.fromTagByte(try c.takeByte()) orelse return error.Malformed;
    const seconds = try c.takeU64();
    const name = c.data[c.pos..];
    return .{ .action = action, .kind = kind, .seconds = seconds, .name = name };
}

// --- coll_op ---

/// Remote counterpart of the CLI's local `coll <kind> <op> ...` (main.zig's
/// `runColl`, backed by `collections.zig`) - until now the Redis-like
/// collections (Counter/Hash/Set/List/ZSet) were reachable only from a
/// process that had the `Db` open directly, the same gap `ttl_op`/
/// `coll_ttl_op` already closed for TTL management. One opcode bundles
/// every collection operation (the same "one opcode, many actions" shape
/// as `user_admin` and `ttl_op`) rather than one opcode per op, since the
/// five kinds share almost nothing about their argument count or type.
/// The payload carries only the action tag, the collection name, and a
/// variable list of string arguments in the exact CLI text form `runColl`
/// already parses locally (values/members/indices/scores) - so
/// `handleCollOp` (server.zig) can reuse the very same
/// `std.fmt.parseInt`/`parseFloat` calls instead of inventing a second
/// binary number encoding just for this opcode.
pub const CollAction = enum(u8) {
    counter_get = 0,
    counter_set = 1,
    counter_incrby = 2,
    hash_set = 3,
    hash_get = 4,
    hash_del = 5,
    hash_len = 6,
    hash_getall = 7,
    set_add = 8,
    set_rem = 9,
    set_ismember = 10,
    set_card = 11,
    set_members = 12,
    // `set_inter`/`set_union`/`set_diff`: `name` is the first set, `args`
    // are every remaining set name - the same split `runColl` already uses
    // (`args[0]` vs `args[1..]`) for these three multi-set operations.
    set_inter = 13,
    set_union = 14,
    set_diff = 15,
    list_lpush = 16,
    list_rpush = 17,
    list_lpop = 18,
    list_rpop = 19,
    list_len = 20,
    list_range = 21,
    zset_add = 22,
    zset_score = 23,
    zset_incrby = 24,
    zset_rem = 25,
    zset_card = 26,
    zset_rangebyrank = 27,
    zset_rangebyscore = 28,
    zset_rank = 29,

    pub fn fromByte(b: u8) !CollAction {
        return std.meta.intToEnum(CollAction, b) catch error.Malformed;
    }

    /// Which `collections.Kind` namespace this action's lazy TTL check
    /// (`collttl.expireIfDue`, called on `name` before every dispatch in
    /// `handleCollOp`) and `requiredRole` gating both need - grouped by the
    /// action's numeric range rather than a second explicit table, since
    /// the enum above is itself laid out kind-by-kind.
    pub fn kind(self: CollAction) collmod.Kind {
        return switch (self) {
            .counter_get, .counter_set, .counter_incrby => .counter,
            .hash_set, .hash_get, .hash_del, .hash_len, .hash_getall => .hash,
            .set_add, .set_rem, .set_ismember, .set_card, .set_members, .set_inter, .set_union, .set_diff => .set,
            .list_lpush, .list_rpush, .list_lpop, .list_rpop, .list_len, .list_range => .list,
            .zset_add, .zset_score, .zset_incrby, .zset_rem, .zset_card, .zset_rangebyrank, .zset_rangebyscore, .zset_rank => .zset,
        };
    }

    /// True for actions that only read - see `server.zig`'s `requiredRole`,
    /// which needs this to decide `readonly` vs `readwrite` from the action
    /// byte alone, the same action-byte peek `ttl_op`/`coll_ttl_op` already
    /// use for their own bundled actions.
    pub fn isReadOnly(self: CollAction) bool {
        return switch (self) {
            .counter_get, .hash_get, .hash_len, .hash_getall, .set_ismember, .set_card, .set_members, .set_inter, .set_union, .set_diff, .list_len, .list_range, .zset_score, .zset_card, .zset_rangebyrank, .zset_rangebyscore, .zset_rank => true,
            else => false,
        };
    }
};

pub fn encodeCollOp(allocator: Allocator, action: CollAction, name: []const u8, args: []const []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(action));
    try putLenPrefixed(w, name);
    try w.putU32(@intCast(args.len));
    for (args) |a| try putLenPrefixed(w, a);
    return buf.toOwnedSlice();
}

pub const CollOpArgs = struct {
    action: CollAction,
    name: []const u8,
    args: [][]const u8,
};

/// `name` and every entry of `args` are borrowed slices into `payload`,
/// valid only as long as the frame that carried them is alive - the same
/// convention `decodeBatch`/`decodeTableSelect` use. Only the `args`
/// pointer array itself is owned by the caller (free with
/// `allocator.free`); never its contents.
pub fn decodeCollOp(allocator: Allocator, payload: []const u8) !CollOpArgs {
    var c = Cursor{ .data = payload };
    const action = try CollAction.fromByte(try c.takeByte());
    const name = try c.takeLenPrefixed();
    const count = try c.takeU32();
    var list = try std.ArrayList([]const u8).initCapacity(allocator, count);
    errdefer list.deinit();
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        list.appendAssumeCapacity(try c.takeLenPrefixed());
    }
    return .{ .action = action, .name = name, .args = try list.toOwnedSlice() };
}

/// One reply shape covers every `coll_op` action, tagged by the first byte -
/// the response-side counterpart of the request-side `CollAction`. `.nil`
/// is the wire form of the CLI's `(nil)` (a hash field/list pop/zset score
/// that does not exist); `.ok` is a bare acknowledgement (counter set,
/// hash set/del as a flag would double up with `.int`, so those still use
/// `.int` with 0/1 - see `encodeCollReply`).
pub const CollReplyTag = enum(u8) {
    nil = 0,
    ok = 1,
    int = 2,
    real = 3,
    bytes = 4,
    stringList = 5,
    pairList = 6,
    scorePairList = 7,
};

pub const CollPair = struct { field: []const u8, value: []const u8 };
pub const CollScorePair = struct { member: []const u8, score: f64 };

pub const CollReply = union(enum) {
    nil,
    ok,
    int: i64,
    real: f64,
    bytes: []const u8,
    stringList: []const []const u8,
    pairList: []const CollPair,
    scorePairList: []const CollScorePair,
};

pub fn encodeCollReply(allocator: Allocator, reply: CollReply) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    switch (reply) {
        .nil => try w.byte(@intFromEnum(CollReplyTag.nil)),
        .ok => try w.byte(@intFromEnum(CollReplyTag.ok)),
        .int => |v| {
            try w.byte(@intFromEnum(CollReplyTag.int));
            try w.putU64(@bitCast(v));
        },
        .real => |v| {
            try w.byte(@intFromEnum(CollReplyTag.real));
            try w.putU64(@bitCast(v));
        },
        .bytes => |v| {
            try w.byte(@intFromEnum(CollReplyTag.bytes));
            try w.slice(v);
        },
        .stringList => |items| {
            try w.byte(@intFromEnum(CollReplyTag.stringList));
            try w.putU32(@intCast(items.len));
            for (items) |it| try putLenPrefixed(w, it);
        },
        .pairList => |items| {
            try w.byte(@intFromEnum(CollReplyTag.pairList));
            try w.putU32(@intCast(items.len));
            for (items) |p| {
                try putLenPrefixed(w, p.field);
                try putLenPrefixed(w, p.value);
            }
        },
        .scorePairList => |items| {
            try w.byte(@intFromEnum(CollReplyTag.scorePairList));
            try w.putU32(@intCast(items.len));
            for (items) |p| {
                try putLenPrefixed(w, p.member);
                try w.putU64(@bitCast(p.score));
            }
        },
    }
    return buf.toOwnedSlice();
}

pub const OwnedCollPair = struct { field: []u8, value: []u8 };
pub const OwnedCollScorePair = struct { member: []u8, score: f64 };

/// Decoded, independently owned counterpart of `CollReply` - every byte
/// slice is a fresh allocation the caller must free via `deinit`, unlike
/// `CollOpArgs` above which stays borrowed (that side is consumed
/// immediately inside `dispatch` before the frame is freed; this side
/// crosses back out to a `Client` caller that keeps it around).
pub const OwnedCollReply = union(enum) {
    nil,
    ok,
    int: i64,
    real: f64,
    bytes: []u8,
    stringList: [][]u8,
    pairList: []OwnedCollPair,
    scorePairList: []OwnedCollScorePair,

    pub fn deinit(self: *OwnedCollReply, allocator: Allocator) void {
        switch (self.*) {
            .bytes => |b| allocator.free(b),
            .stringList => |items| {
                for (items) |it| allocator.free(it);
                allocator.free(items);
            },
            .pairList => |items| {
                for (items) |p| {
                    allocator.free(p.field);
                    allocator.free(p.value);
                }
                allocator.free(items);
            },
            .scorePairList => |items| {
                for (items) |p| allocator.free(p.member);
                allocator.free(items);
            },
            .nil, .ok, .int, .real => {},
        }
        self.* = undefined;
    }
};

pub fn decodeCollReply(allocator: Allocator, payload: []const u8) !OwnedCollReply {
    var c = Cursor{ .data = payload };
    const tag = std.meta.intToEnum(CollReplyTag, try c.takeByte()) catch return error.Malformed;
    return switch (tag) {
        .nil => .nil,
        .ok => .ok,
        .int => .{ .int = @bitCast(try c.takeU64()) },
        .real => .{ .real = @bitCast(try c.takeU64()) },
        .bytes => .{ .bytes = try allocator.dupe(u8, c.data[c.pos..]) },
        .stringList => blk: {
            const count = try c.takeU32();
            var list = try std.ArrayList([]u8).initCapacity(allocator, count);
            errdefer {
                for (list.items) |it| allocator.free(it);
                list.deinit();
            }
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const raw = try c.takeLenPrefixed();
                list.appendAssumeCapacity(try allocator.dupe(u8, raw));
            }
            break :blk .{ .stringList = try list.toOwnedSlice() };
        },
        .pairList => blk: {
            const count = try c.takeU32();
            var list = try std.ArrayList(OwnedCollPair).initCapacity(allocator, count);
            errdefer {
                for (list.items) |p| {
                    allocator.free(p.field);
                    allocator.free(p.value);
                }
                list.deinit();
            }
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const field = try c.takeLenPrefixed();
                const value = try c.takeLenPrefixed();
                list.appendAssumeCapacity(.{ .field = try allocator.dupe(u8, field), .value = try allocator.dupe(u8, value) });
            }
            break :blk .{ .pairList = try list.toOwnedSlice() };
        },
        .scorePairList => blk: {
            const count = try c.takeU32();
            var list = try std.ArrayList(OwnedCollScorePair).initCapacity(allocator, count);
            errdefer {
                for (list.items) |p| allocator.free(p.member);
                list.deinit();
            }
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const member = try c.takeLenPrefixed();
                const score: f64 = @bitCast(try c.takeU64());
                list.appendAssumeCapacity(.{ .member = try allocator.dupe(u8, member), .score = score });
            }
            break :blk .{ .scorePairList = try list.toOwnedSlice() };
        },
    };
}

// --- txn_op ---

/// Remote counterpart of the CLI's local `txn <script-file>` (main.zig's
/// `runTxn`, backed by `txn.zig`/`txn_table.zig`): a batch of put/delete row
/// operations, possibly spanning several tables, applied as one atomic
/// `Transaction` commit - the same "every op succeeds together or none of
/// them do" guarantee the local CLI gives, now reachable from a process that
/// only has a `Client`, not a `*Db`. Unlike `coll_op`/`ttl_op` (one action
/// against one key/collection per request) this opcode carries a LIST of
/// entries, since a transaction script is inherently a batch.
pub const TxnVerb = enum(u8) {
    put = 0,
    del = 1,

    pub fn fromByte(b: u8) !TxnVerb {
        return std.meta.intToEnum(TxnVerb, b) catch error.Malformed;
    }
};

/// One staged operation as the caller supplies it. `fields` is ignored for
/// `.del` (callers pass `&.{}`) - same "unused argument still there, just
/// empty" convention as `encodeUserAdmin`'s zeroed `role`/`rounds` on
/// actions that do not need them.
pub const TxnOpEntry = struct {
    verb: TxnVerb,
    table: []const u8,
    pk: rowmod.Value,
    fields: []const rowmod.Field = &.{},
};

pub fn encodeTxnOp(allocator: Allocator, entries: []const TxnOpEntry) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(entries.len));
    for (entries) |e| {
        try w.byte(@intFromEnum(e.verb));
        try putLenPrefixed(w, e.table);

        const pkBytes = try rowmod.encodeValue(allocator, e.pk);
        defer allocator.free(pkBytes);
        try putLenPrefixed(w, pkBytes);

        // Reuses `Row.encode` for the field list exactly the way
        // `encodeRows` does for a whole result set, instead of inventing a
        // second name+value framing just for this opcode.
        var fieldsRow = rowmod.Row.init(allocator);
        defer fieldsRow.deinit();
        for (e.fields) |f| try fieldsRow.set(f.name, f.value);
        const fieldsBytes = try fieldsRow.encode(allocator);
        defer allocator.free(fieldsBytes);
        try putLenPrefixed(w, fieldsBytes);
    }
    return buf.toOwnedSlice();
}

/// Decoded entry with every slice borrowed from the frame `payload` that
/// carried it - same convention as `decodeCollOp`/`decodeTableSelect`, valid
/// only as long as that payload is alive. `pkBytes`/`fieldsBytes` still need
/// `rowmod.decodeValue`/`rowmod.Row.decode` to become a real `Value`/field
/// list; kept undecoded here so a malformed table name or verb byte fails
/// fast without touching row-decoding at all.
pub const DecodedTxnOpEntry = struct {
    verb: TxnVerb,
    table: []const u8,
    pkBytes: []const u8,
    fieldsBytes: []const u8,
};

pub fn decodeTxnOp(allocator: Allocator, payload: []const u8) ![]DecodedTxnOpEntry {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(DecodedTxnOpEntry).initCapacity(allocator, count);
    errdefer list.deinit();
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const verb = try TxnVerb.fromByte(try c.takeByte());
        const table = try c.takeLenPrefixed();
        const pkBytes = try c.takeLenPrefixed();
        const fieldsBytes = try c.takeLenPrefixed();
        list.appendAssumeCapacity(.{ .verb = verb, .table = table, .pkBytes = pkBytes, .fieldsBytes = fieldsBytes });
    }
    return list.toOwnedSlice();
}

/// Encodes the response to a successful `txn_op`: how many operations were
/// committed - always every entry in the request, since a partial commit is
/// impossible (`error.Conflict` aborts the whole transaction instead, and
/// surfaces as `Status.conflict` with no payload, the same shape as
/// `user_admin`'s `UserExists` conflict).
pub fn encodeTxnResult(allocator: Allocator, applied: u32) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(applied);
    return buf.toOwnedSlice();
}

pub fn decodeTxnResult(payload: []const u8) !u32 {
    var c = Cursor{ .data = payload };
    return c.takeU32();
}

// --- scan / prefix ---

pub const ScanArgs = struct {
    start: ?[]const u8 = null,
    end: ?[]const u8 = null,
    limit: u32 = 0,
    reverse: bool = false,
};

const scanFlagHasStart: u8 = 1 << 0;
const scanFlagHasEnd: u8 = 1 << 1;
const scanFlagReverse: u8 = 1 << 2;

pub fn encodeScan(allocator: Allocator, args: ScanArgs) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    var flags: u8 = 0;
    if (args.start != null) flags |= scanFlagHasStart;
    if (args.end != null) flags |= scanFlagHasEnd;
    if (args.reverse) flags |= scanFlagReverse;
    try w.byte(flags);
    if (args.start) |s| try putLenPrefixed(w, s);
    if (args.end) |e| try putLenPrefixed(w, e);
    try w.putU32(args.limit);
    return buf.toOwnedSlice();
}

pub fn decodeScan(payload: []const u8) !ScanArgs {
    var c = Cursor{ .data = payload };
    const flags = try c.takeByte();
    var args = ScanArgs{};
    if (flags & scanFlagHasStart != 0) args.start = try c.takeLenPrefixed();
    if (flags & scanFlagHasEnd != 0) args.end = try c.takeLenPrefixed();
    args.reverse = flags & scanFlagReverse != 0;
    args.limit = try c.takeU32();
    return args;
}

pub fn encodePrefix(allocator: Allocator, prefix: []const u8, limit: u32) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(limit);
    try w.slice(prefix);
    return buf.toOwnedSlice();
}

pub const PrefixArgs = struct { prefix: []const u8, limit: u32 };

pub fn decodePrefix(payload: []const u8) !PrefixArgs {
    var c = Cursor{ .data = payload };
    const limit = try c.takeU32();
    const prefix = c.data[c.pos..];
    return .{ .prefix = prefix, .limit = limit };
}

// --- entry lists (scan / prefix responses) ---

pub fn encodeEntries(allocator: Allocator, entries: []const dbmod.Entry) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(entries.len));
    for (entries) |e| {
        try putLenPrefixed(w, e.key);
        try putLenPrefixed(w, e.value);
    }
    return buf.toOwnedSlice();
}

pub const OwnedEntry = struct {
    key: []u8,
    value: []u8,

    pub fn deinit(self: *OwnedEntry, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// Copies every key and value out of `payload` so the caller can free
/// the frame that carried them and keep the entries alive independently.
pub fn decodeEntries(allocator: Allocator, payload: []const u8) ![]OwnedEntry {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(OwnedEntry).initCapacity(allocator, count);
    errdefer {
        for (list.items) |*e| e.deinit(allocator);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const key = try c.takeLenPrefixed();
        const value = try c.takeLenPrefixed();
        const ownedKey = try allocator.dupe(u8, key);
        errdefer allocator.free(ownedKey);
        const ownedValue = try allocator.dupe(u8, value);
        list.appendAssumeCapacity(.{ .key = ownedKey, .value = ownedValue });
    }
    return list.toOwnedSlice();
}

pub fn freeOwnedEntries(allocator: Allocator, entries: []OwnedEntry) void {
    for (entries) |*e| e.deinit(allocator);
    allocator.free(entries);
}

// --- batch ---

pub const BatchOp = union(enum) {
    put: struct { key: []const u8, value: []const u8 },
    del: []const u8,
};

const batchKindPut: u8 = 0;
const batchKindDel: u8 = 1;

pub fn encodeBatch(allocator: Allocator, ops: []const BatchOp) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(ops.len));
    for (ops) |op| {
        switch (op) {
            .put => |kv| {
                try w.byte(batchKindPut);
                try putLenPrefixed(w, kv.key);
                try putLenPrefixed(w, kv.value);
            },
            .del => |key| {
                try w.byte(batchKindDel);
                try putLenPrefixed(w, key);
            },
        }
    }
    return buf.toOwnedSlice();
}

pub const DecodedBatchOp = union(enum) {
    put: struct { key: []const u8, value: []const u8 },
    del: []const u8,
};

pub fn decodeBatch(allocator: Allocator, payload: []const u8) ![]DecodedBatchOp {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(DecodedBatchOp).initCapacity(allocator, count);
    errdefer list.deinit();
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const kind = try c.takeByte();
        switch (kind) {
            batchKindPut => {
                const key = try c.takeLenPrefixed();
                const value = try c.takeLenPrefixed();
                list.appendAssumeCapacity(.{ .put = .{ .key = key, .value = value } });
            },
            batchKindDel => {
                const key = try c.takeLenPrefixed();
                list.appendAssumeCapacity(.{ .del = key });
            },
            else => return error.Malformed,
        }
    }
    return list.toOwnedSlice();
}

// --- table select ---

/// Wire request for a remote `table select`: a table name, the raw text of
/// an `expr.zig` predicate expression (empty text selects every row, the
/// same convention `query.Table.select(null)` uses locally), an
/// offset/limit page window using the same "0 = unlimited" convention as
/// `ScanArgs.limit` above - so a large remote result can be paged instead
/// of always coming back in one frame bounded only by `maxFrameBytes` - and
/// a `query.OrderBy` sort key list (possibly empty) applied server-side via
/// `Table.selectPageOrdered` before that page window. The order-by count
/// byte (and each field name/direction pair behind it) sit BEFORE
/// `exprText` rather than after it, because `exprText` is decoded as
/// "everything left in the payload" - anything meant to survive decoding
/// has to come first. A single byte bounds the count to 255 columns, far
/// more than any real query needs.
pub fn encodeTableSelect(allocator: Allocator, table: []const u8, exprText: []const u8, offset: u32, limit: u32, orderBy: []const querymod.OrderBy) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.putU32(offset);
    try w.putU32(limit);
    try w.byte(@intCast(orderBy.len));
    for (orderBy) |ob| {
        try w.byte(if (ob.descending) 1 else 0);
        try putLenPrefixed(w, ob.field);
    }
    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableSelectArgs = struct {
    table: []const u8,
    exprText: []const u8,
    offset: u32 = 0,
    limit: u32 = 0,
    orderBy: []const querymod.OrderBy = &.{},
};

/// `table`, `exprText`, and every `orderBy[i].field` are borrowed slices
/// into `payload` - the same convention `decodeCollOp` uses. Only the
/// `orderBy` array itself is owned by the caller (free with
/// `allocator.free`); never its contents.
pub fn decodeTableSelect(allocator: Allocator, payload: []const u8) !TableSelectArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const offset = try c.takeU32();
    const limit = try c.takeU32();
    const count = try c.takeByte();
    var list = try std.ArrayList(querymod.OrderBy).initCapacity(allocator, count);
    errdefer list.deinit();
    var i: u8 = 0;
    while (i < count) : (i += 1) {
        const descending = try c.takeByte();
        const field = try c.takeLenPrefixed();
        list.appendAssumeCapacity(.{ .field = field, .descending = descending != 0 });
    }
    const exprText = c.data[c.pos..];
    return .{ .table = table, .exprText = exprText, .offset = offset, .limit = limit, .orderBy = try list.toOwnedSlice() };
}

/// Encodes a `table select` result set as a length-prefixed list of rows,
/// each row itself encoded with `Row.encode` (the same self-describing
/// field format a Table stores on disk).
pub fn encodeRows(allocator: Allocator, rows: []const rowmod.Row) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(rows.len));
    for (rows) |*r| {
        const encoded = try r.encode(allocator);
        defer allocator.free(encoded);
        try putLenPrefixed(w, encoded);
    }
    return buf.toOwnedSlice();
}

/// Decodes a `table select` result set into independently owned Rows -
/// callers must free each with `Row.deinit` (see `freeRows` below).
pub fn decodeRows(allocator: Allocator, payload: []const u8) ![]rowmod.Row {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(rowmod.Row).initCapacity(allocator, count);
    errdefer {
        for (list.items) |*r| r.deinit();
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const raw = try c.takeLenPrefixed();
        const row = rowmod.Row.decode(allocator, raw) catch return error.Malformed;
        list.appendAssumeCapacity(row);
    }
    return list.toOwnedSlice();
}

pub fn freeRows(allocator: Allocator, rows: []rowmod.Row) void {
    for (rows) |*r| r.deinit();
    allocator.free(rows);
}

// --- table join ---

/// Which of `join.zig`'s four equi-join variants a `table_join` request
/// wants - the wire counterpart of the CLI's `table join`
/// `[--left|--right|--full]` flags (no flag means `.inner`).
pub const JoinMode = enum(u8) {
    inner = 0,
    left = 1,
    right = 2,
    full = 3,

    pub fn fromByte(b: u8) !JoinMode {
        return std.meta.intToEnum(JoinMode, b) catch error.UnknownJoinMode;
    }
};

/// Wire request for a remote `table join`: which variant (`mode`), the two
/// tables and the fields they are joined on, and an optional `expr.zig`
/// predicate text for each side - the same `leftPred`/`rightPred` filter
/// `join.innerJoin` and its outer variants already take, evaluated exactly
/// like `table_select`'s `exprText` (empty selects every row on that side).
pub fn encodeTableJoin(
    allocator: Allocator,
    mode: JoinMode,
    leftTable: []const u8,
    leftField: []const u8,
    rightTable: []const u8,
    rightField: []const u8,
    offset: u32,
    limit: u32,
    leftExprText: []const u8,
    rightExprText: []const u8,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(mode));
    try putLenPrefixed(w, leftTable);
    try putLenPrefixed(w, leftField);
    try putLenPrefixed(w, rightTable);
    try putLenPrefixed(w, rightField);
    try w.putU32(offset);
    try w.putU32(limit);
    try putLenPrefixed(w, leftExprText);
    try w.slice(rightExprText);
    return buf.toOwnedSlice();
}

pub const TableJoinArgs = struct {
    mode: JoinMode,
    leftTable: []const u8,
    leftField: []const u8,
    rightTable: []const u8,
    rightField: []const u8,
    offset: u32 = 0,
    limit: u32 = 0,
    leftExprText: []const u8,
    rightExprText: []const u8,
};

pub fn decodeTableJoin(payload: []const u8) !TableJoinArgs {
    var c = Cursor{ .data = payload };
    const mode = try JoinMode.fromByte(try c.takeByte());
    const leftTable = try c.takeLenPrefixed();
    const leftField = try c.takeLenPrefixed();
    const rightTable = try c.takeLenPrefixed();
    const rightField = try c.takeLenPrefixed();
    const offset = try c.takeU32();
    const limit = try c.takeU32();
    const leftExprText = try c.takeLenPrefixed();
    const rightExprText = c.data[c.pos..];
    return .{
        .mode = mode,
        .leftTable = leftTable,
        .leftField = leftField,
        .rightTable = rightTable,
        .rightField = rightField,
        .offset = offset,
        .limit = limit,
        .leftExprText = leftExprText,
        .rightExprText = rightExprText,
    };
}

/// One row pair from any of `join.zig`'s four variants, flattened to a
/// single wire shape: `innerJoin` never leaves either side null,
/// `leftOuterJoin`/`rightOuterJoin` leave exactly one side nullable, and
/// `fullOuterJoin` allows either - rather than four near-identical wire
/// encodings, every variant's result is converted to this one shape before
/// `encodeJoinedRows`, and the CLI decides what "(nil)" means from which
/// `--left`/`--right`/`--full` flag it sent, exactly like the local `table
/// join` printer already does per `JoinMode`.
pub const JoinPair = struct { left: ?rowmod.Row, right: ?rowmod.Row };

fn putOptionalRow(allocator: Allocator, w: encode.ByteWriter, row: ?rowmod.Row) !void {
    if (row) |*r| {
        try w.byte(1);
        const encoded = try r.encode(allocator);
        defer allocator.free(encoded);
        try putLenPrefixed(w, encoded);
    } else {
        try w.byte(0);
    }
}

pub fn encodeJoinedRows(allocator: Allocator, pairs: []const JoinPair) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(pairs.len));
    for (pairs) |p| {
        try putOptionalRow(allocator, w, p.left);
        try putOptionalRow(allocator, w, p.right);
    }
    return buf.toOwnedSlice();
}

fn takeOptionalRow(allocator: Allocator, c: *Cursor) !?rowmod.Row {
    const present = try c.takeByte();
    if (present == 0) return null;
    const raw = try c.takeLenPrefixed();
    return rowmod.Row.decode(allocator, raw) catch return error.Malformed;
}

/// Decodes a `table_join` result set into independently owned `JoinPair`s -
/// callers must free each present side with `Row.deinit` (see
/// `freeJoinPairs` below).
pub fn decodeJoinedRows(allocator: Allocator, payload: []const u8) ![]JoinPair {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(JoinPair).initCapacity(allocator, count);
    errdefer {
        for (list.items) |*p| {
            if (p.left) |*l| l.deinit();
            if (p.right) |*r| r.deinit();
        }
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const left = try takeOptionalRow(allocator, &c);
        const right = try takeOptionalRow(allocator, &c);
        list.appendAssumeCapacity(.{ .left = left, .right = right });
    }
    return list.toOwnedSlice();
}

pub fn freeJoinPairs(allocator: Allocator, pairs: []JoinPair) void {
    for (pairs) |*p| {
        if (p.left) |*l| l.deinit();
        if (p.right) |*r| r.deinit();
    }
    allocator.free(pairs);
}

// --- table aggregate ---

/// Wire request for a remote `table aggregate`: a table name, an optional
/// GROUP BY field (empty means no grouping - the network counterpart of the
/// CLI's `*` sentinel for `table aggregate <table> *`, chosen client-side so
/// the wire itself needs no separate mode byte), the list of
/// `aggregate.zig` specs to compute, and an `expr.zig` predicate text
/// filtering rows BEFORE aggregation runs - the same empty-means-every-row
/// convention `table_select`'s `exprText` already uses.
/// `offset`/`limit` window the result GROUPS (not the input rows) when
/// `groupField` is non-empty, the same `join.applyPage`/`Table.selectPage`
/// convention as `table_join`'s wire format - 0/0 means unlimited. Ignored
/// server-side when `groupField` is empty (`runGlobal` always produces
/// exactly one result row, nothing to page).
/// `orderBy` is a `query.OrderBy` sort key list (possibly empty) applied
/// server-side to the result GROUPS via `aggregate.sortGroupsBy`, after
/// HAVING narrows them and before `offset`/`limit` window them - same
/// convention and wire shape (count byte + descending byte + length-prefixed
/// field name, per column) as `encodeTableSelect`'s `orderBy`. Each
/// `orderBy[i].field` must name either `groupField` or one of `specs`'
/// `specLabel`s (validated server-side by `sortGroupsBy`, not here).
/// Meaningless (and ignored server-side) for the ungrouped `groupField.len
/// == 0` path, same as `offset`/`limit` already are - `runGlobal` always
/// produces exactly one result row, nothing to order.
///
/// `havingText` is a second, independent `expr.zig` predicate text
/// (empty means no HAVING) filtering the result GROUPS AFTER aggregation,
/// evaluated server-side before `offset`/`limit` window them - the wire
/// counterpart of the CLI's `having <expr>` suffix. Encoded length-prefixed
/// (not "rest of payload" like `exprText`) precisely because `exprText`
/// still needs to occupy that final slot.
pub fn encodeTableAggregate(allocator: Allocator, table: []const u8, groupField: []const u8, specs: []const aggregatemod.AggSpec, offset: u32, limit: u32, orderBy: []const querymod.OrderBy, havingText: []const u8, exprText: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try putLenPrefixed(w, groupField);
    try w.putU32(@intCast(specs.len));
    for (specs) |spec| {
        try w.byte(@intFromEnum(spec.kind));
        try putLenPrefixed(w, spec.field);
    }
    try w.putU32(offset);
    try w.putU32(limit);
    try w.byte(@intCast(orderBy.len));
    for (orderBy) |ob| {
        try w.byte(if (ob.descending) 1 else 0);
        try putLenPrefixed(w, ob.field);
    }
    try putLenPrefixed(w, havingText);
    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableAggregateArgs = struct {
    table: []const u8,
    groupField: []const u8,
    /// Borrows `field` slices from the decoded payload but owns the slice
    /// itself - caller frees with `allocator.free(args.specs)`, same shape
    /// as `decodeBatch`'s returned list.
    specs: []aggregatemod.AggSpec,
    offset: u32 = 0,
    limit: u32 = 0,
    /// Empty means no ORDER BY - see `encodeTableAggregate`'s doc. Borrows
    /// `field` slices from the decoded payload but owns the slice itself,
    /// same convention as `specs`/`TableSelectArgs.orderBy`.
    orderBy: []const querymod.OrderBy = &.{},
    /// Empty means no HAVING clause - see `encodeTableAggregate`'s doc.
    havingText: []const u8,
    exprText: []const u8,
};

pub fn decodeTableAggregate(allocator: Allocator, payload: []const u8) !TableAggregateArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const groupField = try c.takeLenPrefixed();
    const count = try c.takeU32();
    var specs = try std.ArrayList(aggregatemod.AggSpec).initCapacity(allocator, count);
    errdefer specs.deinit();
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const kindByte = try c.takeByte();
        const kind = std.meta.intToEnum(aggregatemod.AggKind, kindByte) catch return error.Malformed;
        const field = try c.takeLenPrefixed();
        specs.appendAssumeCapacity(.{ .kind = kind, .field = field });
    }
    const offset = try c.takeU32();
    const limit = try c.takeU32();
    const orderCount = try c.takeByte();
    var orderBy = try std.ArrayList(querymod.OrderBy).initCapacity(allocator, orderCount);
    errdefer orderBy.deinit();
    var j: u8 = 0;
    while (j < orderCount) : (j += 1) {
        const descending = try c.takeByte();
        const field = try c.takeLenPrefixed();
        orderBy.appendAssumeCapacity(.{ .field = field, .descending = descending != 0 });
    }
    const havingText = try c.takeLenPrefixed();
    const exprText = c.data[c.pos..];
    return .{ .table = table, .groupField = groupField, .specs = try specs.toOwnedSlice(), .offset = offset, .limit = limit, .orderBy = try orderBy.toOwnedSlice(), .havingText = havingText, .exprText = exprText };
}

fn putEncodedValue(allocator: Allocator, w: encode.ByteWriter, value: rowmod.Value) !void {
    const encoded = try rowmod.encodeValue(allocator, value);
    defer allocator.free(encoded);
    try putLenPrefixed(w, encoded);
}

fn takeDecodedValue(allocator: Allocator, c: *Cursor) !rowmod.Value {
    const raw = try c.takeLenPrefixed();
    return rowmod.decodeValue(allocator, raw) catch return error.Malformed;
}

/// Encodes a `runGlobal` (no `GROUP BY`) result: exactly `specs.len` values,
/// same order as the request's specs.
pub fn encodeAggGlobalResult(allocator: Allocator, values: []const rowmod.Value) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(values.len));
    for (values) |v| try putEncodedValue(allocator, w, v);
    return buf.toOwnedSlice();
}

/// Decodes a `runGlobal` result into independently owned `Value`s - callers
/// must free with `freeAggValues`.
pub fn decodeAggGlobalResult(allocator: Allocator, payload: []const u8) ![]rowmod.Value {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(rowmod.Value).initCapacity(allocator, count);
    errdefer {
        for (list.items) |v| v.free(allocator);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) list.appendAssumeCapacity(try takeDecodedValue(allocator, &c));
    return list.toOwnedSlice();
}

pub fn freeAggValues(allocator: Allocator, values: []rowmod.Value) void {
    for (values) |v| v.free(allocator);
    allocator.free(values);
}

/// Encodes a grouped `run` result: one entry per `GroupRow` (the group-key
/// value, then exactly `specs.len` result values), in the same first-seen
/// order `GroupBy.finish()` produced them.
pub fn encodeAggGroupRows(allocator: Allocator, groups: []const aggregatemod.GroupRow) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(groups.len));
    for (groups) |g| {
        try putEncodedValue(allocator, w, g.group);
        try w.putU32(@intCast(g.values.len));
        for (g.values) |v| try putEncodedValue(allocator, w, v);
    }
    return buf.toOwnedSlice();
}

/// Decodes a grouped `run` result into independently owned `GroupRow`s -
/// callers must free each with `GroupRow.deinit`, then the slice itself
/// (see `freeAggGroupRows`).
pub fn decodeAggGroupRows(allocator: Allocator, payload: []const u8) ![]aggregatemod.GroupRow {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(aggregatemod.GroupRow).initCapacity(allocator, count);
    errdefer {
        for (list.items) |*g| g.deinit(allocator);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const group = try takeDecodedValue(allocator, &c);
        // Armed for the rest of THIS iteration's block only - Zig disarms an
        // errdefer once the block it was declared in exits normally, and
        // `appendAssumeCapacity` below is that block's last statement, so a
        // later iteration's failure can never reach back and double-free an
        // already-appended `group` (the exact class of bug `aggregate.zig`'s
        // `GroupBy.observe` hit and fixed - see its comment for the details).
        errdefer group.free(allocator);
        const valueCount = try c.takeU32();
        var values = try allocator.alloc(rowmod.Value, valueCount);
        errdefer allocator.free(values);
        var filled: u32 = 0;
        errdefer for (values[0..filled]) |v| v.free(allocator);
        var j: u32 = 0;
        while (j < valueCount) : (j += 1) {
            values[j] = try takeDecodedValue(allocator, &c);
            filled += 1;
        }
        list.appendAssumeCapacity(.{ .group = group, .values = values });
    }
    return list.toOwnedSlice();
}

pub fn freeAggGroupRows(allocator: Allocator, groups: []aggregatemod.GroupRow) void {
    for (groups) |*g| g.deinit(allocator);
    allocator.free(groups);
}

// --- table window ---

/// Wire request for a remote `table window`: a table name, the LIST of
/// `window.zig` `WindowSpec`s to compute (one or more columns sharing the
/// same `PARTITION BY`/`ORDER BY`/`frame` - `window.computeMany`'s shape,
/// mirroring `table_aggregate`'s `specs` list), the `PARTITION BY`/`ORDER
/// BY` field lists (either possibly empty, same "no partition"/"no order"
/// meaning as local `table window`'s `partitionBy`/`orderBy`), `offset`/
/// `limit` windowing the PRINTED rows in the same partition-then-order walk
/// `window.orderedIndices` produces (not raw scan order, not `computeMany`'s
/// per-row results, which stay aligned 1:1 with every matching row
/// regardless of paging - see `handleTableWindow`'s doc), and an `expr.zig`
/// predicate text filtering rows BEFORE annotation (same
/// empty-means-every-row convention every other `table_*` opcode's
/// `exprText` already uses). `orderBy` reuses `querymod.OrderBy`'s wire
/// shape (descending byte + length-prefixed field name) exactly like
/// `encodeTableAggregate`'s. `specs` is a byte count followed by
/// `(kind byte, length-prefixed field)` pairs, same shape `partitionBy`
/// already uses for its own count-prefixed field list. `frame` is a single
/// byte (`@intFromEnum(windowmod.FrameMode)`) written right before
/// `exprText` - after every other fixed-size field but before the
/// unbounded, unprefixed trailing text, same placement
/// `encodeTableAggregate`'s `havingText` uses relative to ITS trailing
/// `exprText`.
/// Writes a `WindowSpec`'s `offset`/`default` fields, shared by `lag`/`lead`
/// (offset = rows back/forward from the current row) and `nth_value`
/// (offset = 1-based position within the frame) - both pairs share the same
/// wire shape, so one writer covers all three `WindowKind`s. `default` uses
/// the tag+payload shape `row.zig`'s `encodeValue` does, but written
/// directly (not through `putEncodedValue`, which allocates a throwaway
/// buffer via `rowmod.encodeValue` only to copy it right back out) since a
/// `WindowSpec.default` is always a small scalar or short borrowed string,
/// never worth a heap round trip.
fn putLagLeadExtra(w: encode.ByteWriter, offset: u64, default: rowmod.Value) !void {
    try w.putU64(offset);
    try w.byte(@intFromEnum(@as(rowmod.ValueTag, default)));
    switch (default) {
        .none => {},
        .boolean => |v| try w.byte(if (v) 1 else 0),
        .int => |v| try w.putU64(@bitCast(v)),
        .float => |v| try w.putU64(@bitCast(v)),
        .text, .bytes => |s| try putLenPrefixed(w, s),
    }
}

/// Reads back what `putLagLeadExtra` wrote. `.text`/`.bytes` are returned as
/// slices BORROWED from `c`'s backing payload (never allocated) - the same
/// convention `WindowSpec.field`/`TableWindowArgs.partitionBy` already use,
/// safe because the payload buffer outlives the whole request handler.
fn takeLagLeadExtra(c: *Cursor) !struct { offset: u64, default: rowmod.Value } {
    const offset = try c.takeU64();
    const tagByte = try c.takeByte();
    const tag = std.meta.intToEnum(rowmod.ValueTag, tagByte) catch return error.Malformed;
    const default: rowmod.Value = switch (tag) {
        .none => .{ .none = {} },
        .boolean => .{ .boolean = (try c.takeByte()) != 0 },
        .int => .{ .int = @bitCast(try c.takeU64()) },
        .float => .{ .float = @bitCast(try c.takeU64()) },
        .text => .{ .text = try c.takeLenPrefixed() },
        .bytes => .{ .bytes = try c.takeLenPrefixed() },
    };
    return .{ .offset = offset, .default = default };
}

pub fn encodeTableWindow(allocator: Allocator, table: []const u8, specs: []const windowmod.WindowSpec, partitionBy: []const []const u8, orderBy: []const querymod.OrderBy, offset: u32, limit: u32, exprText: []const u8, frame: windowmod.FrameMode) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.byte(@intCast(specs.len));
    for (specs) |spec| {
        try w.byte(@intFromEnum(spec.kind));
        try putLenPrefixed(w, spec.field);
        if (spec.kind == .lag or spec.kind == .lead or spec.kind == .nth_value) try putLagLeadExtra(w, spec.offset, spec.default);
    }
    try w.byte(@intCast(partitionBy.len));
    for (partitionBy) |field| try putLenPrefixed(w, field);
    try w.byte(@intCast(orderBy.len));
    for (orderBy) |ob| {
        try w.byte(if (ob.descending) 1 else 0);
        try putLenPrefixed(w, ob.field);
    }
    try w.putU32(offset);
    try w.putU32(limit);
    try w.byte(@intFromEnum(frame));
    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableWindowArgs = struct {
    table: []const u8,
    /// Borrows field-name slices from the decoded payload but owns the
    /// slice itself, same convention as `partitionBy`/`orderBy` below.
    /// Always non-empty for a well-formed request (`decodeTableWindow`
    /// itself does not enforce this - `handleTableWindow` rejects an empty
    /// list as `bad_request`, same as `table_aggregate`'s empty-specs
    /// check).
    specs: []const windowmod.WindowSpec = &.{},
    /// Borrows field-name slices from the decoded payload but owns the
    /// slice itself, same convention as `TableAggregateArgs.orderBy`. Empty
    /// means "one implicit partition" (the whole result set), same as local
    /// `table window`'s default.
    partitionBy: []const []const u8 = &.{},
    orderBy: []const querymod.OrderBy = &.{},
    offset: u32 = 0,
    limit: u32 = 0,
    frame: windowmod.FrameMode = .rows,
    exprText: []const u8,
};

pub fn decodeTableWindow(allocator: Allocator, payload: []const u8) !TableWindowArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const specCount = try c.takeByte();
    var specs = try std.ArrayList(windowmod.WindowSpec).initCapacity(allocator, specCount);
    errdefer specs.deinit();
    var s: u8 = 0;
    while (s < specCount) : (s += 1) {
        const kindByte = try c.takeByte();
        const kind = std.meta.intToEnum(windowmod.WindowKind, kindByte) catch return error.Malformed;
        const field = try c.takeLenPrefixed();
        if (kind == .lag or kind == .lead or kind == .nth_value) {
            const extra = try takeLagLeadExtra(&c);
            specs.appendAssumeCapacity(.{ .kind = kind, .field = field, .offset = extra.offset, .default = extra.default });
        } else {
            specs.appendAssumeCapacity(.{ .kind = kind, .field = field });
        }
    }
    const partitionCount = try c.takeByte();
    var partitionBy = try std.ArrayList([]const u8).initCapacity(allocator, partitionCount);
    errdefer partitionBy.deinit();
    var i: u8 = 0;
    while (i < partitionCount) : (i += 1) partitionBy.appendAssumeCapacity(try c.takeLenPrefixed());
    const orderCount = try c.takeByte();
    var orderBy = try std.ArrayList(querymod.OrderBy).initCapacity(allocator, orderCount);
    errdefer orderBy.deinit();
    var j: u8 = 0;
    while (j < orderCount) : (j += 1) {
        const descending = try c.takeByte();
        const obField = try c.takeLenPrefixed();
        orderBy.appendAssumeCapacity(.{ .field = obField, .descending = descending != 0 });
    }
    const offset = try c.takeU32();
    const limit = try c.takeU32();
    const frameByte = try c.takeByte();
    const frame = std.meta.intToEnum(windowmod.FrameMode, frameByte) catch return error.Malformed;
    const exprText = c.data[c.pos..];
    return .{
        .table = table,
        .specs = try specs.toOwnedSlice(),
        .partitionBy = try partitionBy.toOwnedSlice(),
        .orderBy = try orderBy.toOwnedSlice(),
        .offset = offset,
        .limit = limit,
        .frame = frame,
        .exprText = exprText,
    };
}

/// One annotated row from a `table_window` result: the original row
/// (unmodified, same fields the request matched) paired with one computed
/// window value PER requested spec, in the same order as the request's
/// `specs` list - the network shape of what local `table window` prints per
/// row (`printRow` fields, then `<label>=<value>` per spec). Already in the
/// server-paginated partition-then-order display order (see
/// `handleTableWindow`), so the client prints these in order with no
/// further sorting.
pub const WindowRow = struct { row: rowmod.Row, values: []rowmod.Value };

pub fn encodeWindowRows(allocator: Allocator, rows: []const WindowRow) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(rows.len));
    for (rows) |wr| {
        const encoded = try wr.row.encode(allocator);
        defer allocator.free(encoded);
        try putLenPrefixed(w, encoded);
        try w.putU32(@intCast(wr.values.len));
        for (wr.values) |v| try putEncodedValue(allocator, w, v);
    }
    return buf.toOwnedSlice();
}

/// Decodes a `table_window` result into independently owned `WindowRow`s -
/// callers must free each (`.row.deinit()`, each `.values[i].free(allocator)`
/// then `allocator.free(.values)`), then the slice itself (see
/// `freeWindowRows`).
pub fn decodeWindowRows(allocator: Allocator, payload: []const u8) ![]WindowRow {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList(WindowRow).initCapacity(allocator, count);
    errdefer {
        for (list.items) |*wr| {
            wr.row.deinit();
            for (wr.values) |v| v.free(allocator);
            allocator.free(wr.values);
        }
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const raw = try c.takeLenPrefixed();
        var row = rowmod.Row.decode(allocator, raw) catch return error.Malformed;
        errdefer row.deinit();
        const valueCount = try c.takeU32();
        var values = try allocator.alloc(rowmod.Value, valueCount);
        errdefer allocator.free(values);
        var filled: u32 = 0;
        errdefer for (values[0..filled]) |v| v.free(allocator);
        var j: u32 = 0;
        while (j < valueCount) : (j += 1) {
            values[j] = try takeDecodedValue(allocator, &c);
            filled += 1;
        }
        list.appendAssumeCapacity(.{ .row = row, .values = values });
    }
    return list.toOwnedSlice();
}

pub fn freeWindowRows(allocator: Allocator, rows: []WindowRow) void {
    for (rows) |*wr| {
        wr.row.deinit();
        for (wr.values) |v| v.free(allocator);
        allocator.free(wr.values);
    }
    allocator.free(rows);
}

// --- pubsub ---

/// Wire request for `subscribe`: the list of channel names to listen on (at
/// least one - `server.zig`'s `handleSubscribe` rejects an empty list as
/// malformed rather than opening a subscription that can never receive
/// anything). Unlike every other opcode in this file, a `subscribe` request
/// does not get a single reply frame back: after the initial acknowledgment
/// (see `encodeSubscribeAck`), the connection becomes a one-way stream of
/// `encodePubSubMessage` frames until it closes - see `pubsub.zig`'s doc
/// comment on `Hub` and `server.zig`'s `handleSubscribe`.
pub fn encodeSubscribe(allocator: Allocator, channels: []const []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(channels.len));
    for (channels) |c| try putLenPrefixed(w, c);
    return buf.toOwnedSlice();
}

pub const SubscribeArgs = struct {
    channels: [][]u8,

    pub fn deinit(self: SubscribeArgs, allocator: Allocator) void {
        for (self.channels) |c| allocator.free(c);
        allocator.free(self.channels);
    }
};

