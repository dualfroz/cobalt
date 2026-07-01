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

