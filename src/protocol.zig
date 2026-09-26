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

pub fn encodeAuthOk(allocator: Allocator, token: ?[]const u8) ![]u8 {
    return allocator.dupe(u8, token orelse "");
}

pub fn encodeAuthToken(allocator: Allocator, token: []const u8) ![]u8 {
    return allocator.dupe(u8, token);
}

pub fn decodeAuthToken(payload: []const u8) []const u8 {
    return payload;
}

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

pub const TtlAction = enum(u8) {
    expire = 0,
    persist = 1,
    query = 2,
    sweep = 3,

    pub fn fromByte(b: u8) !TtlAction {
        return std.meta.intToEnum(TtlAction, b) catch error.Malformed;
    }
};

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

pub fn encodeCollTtlOp(allocator: Allocator, action: TtlAction, kind: collmod.Kind, name: []const u8, seconds: u64) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(action));
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

    pub fn kind(self: CollAction) collmod.Kind {
        return switch (self) {
            .counter_get, .counter_set, .counter_incrby => .counter,
            .hash_set, .hash_get, .hash_del, .hash_len, .hash_getall => .hash,
            .set_add, .set_rem, .set_ismember, .set_card, .set_members, .set_inter, .set_union, .set_diff => .set,
            .list_lpush, .list_rpush, .list_lpop, .list_rpop, .list_len, .list_range => .list,
            .zset_add, .zset_score, .zset_incrby, .zset_rem, .zset_card, .zset_rangebyrank, .zset_rangebyscore, .zset_rank => .zset,
        };
    }

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

pub const TxnVerb = enum(u8) {
    put = 0,
    del = 1,

    pub fn fromByte(b: u8) !TxnVerb {
        return std.meta.intToEnum(TxnVerb, b) catch error.Malformed;
    }
};

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

        var fieldsRow = rowmod.Row.init(allocator);
        defer fieldsRow.deinit();
        for (e.fields) |f| try fieldsRow.set(f.name, f.value);
        const fieldsBytes = try fieldsRow.encode(allocator);
        defer allocator.free(fieldsBytes);
        try putLenPrefixed(w, fieldsBytes);
    }
    return buf.toOwnedSlice();
}

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

pub const JoinMode = enum(u8) {
    inner = 0,
    left = 1,
    right = 2,
    full = 3,

    pub fn fromByte(b: u8) !JoinMode {
        return std.meta.intToEnum(JoinMode, b) catch error.UnknownJoinMode;
    }
};

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
    specs: []aggregatemod.AggSpec,
    offset: u32 = 0,
    limit: u32 = 0,
    orderBy: []const querymod.OrderBy = &.{},
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

pub fn encodeAggGlobalResult(allocator: Allocator, values: []const rowmod.Value) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(@intCast(values.len));
    for (values) |v| try putEncodedValue(allocator, w, v);
    return buf.toOwnedSlice();
}

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
    specs: []const windowmod.WindowSpec = &.{},
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

pub fn decodeSubscribe(allocator: Allocator, payload: []const u8) !SubscribeArgs {
    var c = Cursor{ .data = payload };
    const count = try c.takeU32();
    var list = try std.ArrayList([]u8).initCapacity(allocator, count);
    errdefer {
        for (list.items) |ch| allocator.free(ch);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const name = try c.takeLenPrefixed();
        const owned = try allocator.dupe(u8, name);
        list.appendAssumeCapacity(owned);
    }
    return .{ .channels = try list.toOwnedSlice() };
}

pub fn encodeSubscribeAck(allocator: Allocator, subscriberId: u64, channelCount: u32) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(subscriberId);
    try w.putU32(channelCount);
    return buf.toOwnedSlice();
}

pub const SubscribeAck = struct { subscriberId: u64, channelCount: u32 };

pub fn decodeSubscribeAck(payload: []const u8) !SubscribeAck {
    var c = Cursor{ .data = payload };
    const subscriberId = try c.takeU64();
    const channelCount = try c.takeU32();
    return .{ .subscriberId = subscriberId, .channelCount = channelCount };
}

pub fn encodePublish(allocator: Allocator, channel: []const u8, message: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, channel);
    try w.slice(message);
    return buf.toOwnedSlice();
}

pub const PublishArgs = struct { channel: []const u8, message: []const u8 };

pub fn decodePublish(payload: []const u8) !PublishArgs {
    var c = Cursor{ .data = payload };
    const channel = try c.takeLenPrefixed();
    const message = c.data[c.pos..];
    return .{ .channel = channel, .message = message };
}

pub fn encodePublishResult(allocator: Allocator, subscriberCount: u64) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(subscriberCount);
    return buf.toOwnedSlice();
}

pub fn decodePublishResult(payload: []const u8) !u64 {
    var c = Cursor{ .data = payload };
    return c.takeU64();
}

pub fn encodeUnsubscribe(allocator: Allocator, subscriberId: u64, channels: []const []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(subscriberId);
    try w.putU32(@intCast(channels.len));
    for (channels) |c| try putLenPrefixed(w, c);
    return buf.toOwnedSlice();
}

pub const UnsubscribeArgs = struct {
    subscriberId: u64,
    channels: [][]u8,

    pub fn deinit(self: UnsubscribeArgs, allocator: Allocator) void {
        for (self.channels) |c| allocator.free(c);
        allocator.free(self.channels);
    }
};

pub fn decodeUnsubscribe(allocator: Allocator, payload: []const u8) !UnsubscribeArgs {
    var c = Cursor{ .data = payload };
    const subscriberId = try c.takeU64();
    const count = try c.takeU32();
    var list = try std.ArrayList([]u8).initCapacity(allocator, count);
    errdefer {
        for (list.items) |ch| allocator.free(ch);
        list.deinit();
    }
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const name = try c.takeLenPrefixed();
        const owned = try allocator.dupe(u8, name);
        list.appendAssumeCapacity(owned);
    }
    return .{ .subscriberId = subscriberId, .channels = try list.toOwnedSlice() };
}

pub fn encodeUnsubscribeResult(allocator: Allocator, removedCount: u32) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(removedCount);
    return buf.toOwnedSlice();
}

pub fn decodeUnsubscribeResult(payload: []const u8) !u32 {
    var c = Cursor{ .data = payload };
    return c.takeU32();
}

pub const PubSubMessage = struct {
    channel: []u8,
    payload: []u8,

    pub fn deinit(self: PubSubMessage, allocator: Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.payload);
    }
};

pub fn encodePubSubMessage(allocator: Allocator, channel: []const u8, payload: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, channel);
    try w.slice(payload);
    return buf.toOwnedSlice();
}

pub fn decodePubSubMessage(allocator: Allocator, payload: []const u8) !PubSubMessage {
    var c = Cursor{ .data = payload };
    const channel = try c.takeLenPrefixed();
    const message = c.data[c.pos..];
    const channelCopy = try allocator.dupe(u8, channel);
    errdefer allocator.free(channelCopy);
    const payloadCopy = try allocator.dupe(u8, message);
    return .{ .channel = channelCopy, .payload = payloadCopy };
}

pub fn encodeTableExplain(allocator: Allocator, table: []const u8, exprText: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableExplainArgs = struct { table: []const u8, exprText: []const u8 };

pub fn decodeTableExplain(payload: []const u8) !TableExplainArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const exprText = c.data[c.pos..];
    return .{ .table = table, .exprText = exprText };
}

pub fn encodePlan(allocator: Allocator, plan: querymod.Plan) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(plan.kind));
    try putLenPrefixed(w, plan.indexName orelse "");
    try w.putU32(@intCast(plan.matchedFields));
    try w.putU32(@intCast(plan.totalFields));
    return buf.toOwnedSlice();
}

pub fn decodePlan(allocator: Allocator, payload: []const u8) !querymod.Plan {
    var c = Cursor{ .data = payload };
    const kindByte = try c.takeByte();
    const kind = std.meta.intToEnum(querymod.PlanKind, kindByte) catch return error.Malformed;
    const rawName = try c.takeLenPrefixed();
    const indexName = if (rawName.len == 0) null else try allocator.dupe(u8, rawName);
    errdefer if (indexName) |n| allocator.free(n);
    const matchedFields = try c.takeU32();
    const totalFields = try c.takeU32();
    return .{ .kind = kind, .indexName = indexName, .matchedFields = matchedFields, .totalFields = totalFields };
}

pub fn encodeTableUpdate(allocator: Allocator, table: []const u8, sets: []const rowmod.Field, exprText: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);

    var setsRow = rowmod.Row.init(allocator);
    defer setsRow.deinit();
    for (sets) |f| try setsRow.set(f.name, f.value);
    const setsBytes = try setsRow.encode(allocator);
    defer allocator.free(setsBytes);
    try putLenPrefixed(w, setsBytes);

    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableUpdateArgs = struct { table: []const u8, setsBytes: []const u8, exprText: []const u8 };

pub fn decodeTableUpdate(payload: []const u8) !TableUpdateArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const setsBytes = try c.takeLenPrefixed();
    const exprText = c.data[c.pos..];
    return .{ .table = table, .setsBytes = setsBytes, .exprText = exprText };
}

pub fn encodeTableDelete(allocator: Allocator, table: []const u8, exprText: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.slice(exprText);
    return buf.toOwnedSlice();
}

pub const TableDeleteArgs = struct { table: []const u8, exprText: []const u8 };

pub fn decodeTableDelete(payload: []const u8) !TableDeleteArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const exprText = c.data[c.pos..];
    return .{ .table = table, .exprText = exprText };
}

pub const DumpFormat = enum(u8) {
    csv = 0,
    json = 1,
};

pub fn encodeTableExport(allocator: Allocator, table: []const u8, format: DumpFormat) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.byte(@intFromEnum(format));
    return buf.toOwnedSlice();
}

pub const TableExportArgs = struct { table: []const u8, format: DumpFormat };

pub fn decodeTableExport(payload: []const u8) !TableExportArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const formatByte = try c.takeByte();
    const format = std.meta.intToEnum(DumpFormat, formatByte) catch return error.Malformed;
    return .{ .table = table, .format = format };
}

pub fn encodeExportResult(allocator: Allocator, rowCount: u64, content: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(rowCount);
    try w.slice(content);
    return buf.toOwnedSlice();
}

pub const ExportResult = struct { rowCount: u64, content: []const u8 };

pub fn decodeExportResult(payload: []const u8) !ExportResult {
    var c = Cursor{ .data = payload };
    const rowCount = try c.takeU64();
    const content = payload[c.pos..];
    return .{ .rowCount = rowCount, .content = content };
}

pub fn encodeTableImport(allocator: Allocator, table: []const u8, format: DumpFormat, content: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, table);
    try w.byte(@intFromEnum(format));
    try w.slice(content);
    return buf.toOwnedSlice();
}

pub const TableImportArgs = struct { table: []const u8, format: DumpFormat, content: []const u8 };

pub fn decodeTableImport(payload: []const u8) !TableImportArgs {
    var c = Cursor{ .data = payload };
    const table = try c.takeLenPrefixed();
    const formatByte = try c.takeByte();
    const format = std.meta.intToEnum(DumpFormat, formatByte) catch return error.Malformed;
    const content = payload[c.pos..];
    return .{ .table = table, .format = format, .content = content };
}

pub fn encodeStats(allocator: Allocator, stats: dbmod.Stats) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(@intCast(stats.memtableEntries));
    try w.putU64(@intCast(stats.memtableBytes));
    try w.putU64(@intCast(stats.sstableCount));
    try w.putU64(stats.liveEntries);
    try w.putU64(stats.physicalBytes);
    try w.putU64(stats.cacheHits);
    try w.putU64(stats.cacheMisses);
    try w.putU64(stats.nextSeq);
    for (stats.levels) |level| {
        try w.putU64(@intCast(level.tables));
        try w.putU64(level.entries);
        try w.putU64(level.physicalBytes);
    }
    return buf.toOwnedSlice();
}

pub fn decodeStats(payload: []const u8) !dbmod.Stats {
    var c = Cursor{ .data = payload };
    var stats = dbmod.Stats{};
    stats.memtableEntries = @intCast(try c.takeU64());
    stats.memtableBytes = @intCast(try c.takeU64());
    stats.sstableCount = @intCast(try c.takeU64());
    stats.liveEntries = try c.takeU64();
    stats.physicalBytes = try c.takeU64();
    stats.cacheHits = try c.takeU64();
    stats.cacheMisses = try c.takeU64();
    stats.nextSeq = try c.takeU64();
    var i: usize = 0;
    while (i < stats.levels.len) : (i += 1) {
        stats.levels[i] = .{
            .tables = @intCast(try c.takeU64()),
            .entries = try c.takeU64(),
            .physicalBytes = try c.takeU64(),
        };
    }
    return stats;
}

test "frame round trip through an in-memory buffer" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try writeFrame(buf.writer(), @intFromEnum(Op.get), "hello");
    var stream = std.io.fixedBufferStream(buf.items);
    var frame = try readFrame(allocator, stream.reader());
    defer frame.deinit();

    try std.testing.expectEqual(@intFromEnum(Op.get), frame.tag);
    try std.testing.expectEqualStrings("hello", frame.payload);
}

test "frame with empty payload round trips" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try writeFrame(buf.writer(), @intFromEnum(Op.ping), "");
    var stream = std.io.fixedBufferStream(buf.items);
    var frame = try readFrame(allocator, stream.reader());
    defer frame.deinit();

    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

test "readFrame rejects a length prefix beyond the frame guard" {
    const allocator = std.testing.allocator;
    var header: [5]u8 = undefined;
    header[0] = 0;
    std.mem.writeInt(u32, header[1..5], maxFrameBytes + 1, encode.endian);
    var stream = std.io.fixedBufferStream(&header);
    try std.testing.expectError(error.FrameTooLarge, readFrame(allocator, stream.reader()));
}

test "readFrame rejects a truncated body" {
    const allocator = std.testing.allocator;
    var header: [5]u8 = undefined;
    header[0] = 0;
    std.mem.writeInt(u32, header[1..5], 10, encode.endian);
    var stream = std.io.fixedBufferStream(&header);
    try std.testing.expectError(error.EndOfStream, readFrame(allocator, stream.reader()));
}

test "Op.fromByte rejects unknown opcodes" {
    try std.testing.expectError(error.UnknownOp, Op.fromByte(200));
    try std.testing.expectEqual(Op.batch, try Op.fromByte(9));
    try std.testing.expectEqual(Op.table_select, try Op.fromByte(10));
    try std.testing.expectEqual(Op.auth, try Op.fromByte(11));
    try std.testing.expectEqual(Op.user_admin, try Op.fromByte(12));
    try std.testing.expectEqual(Op.auth_token, try Op.fromByte(13));
    try std.testing.expectEqual(Op.metrics, try Op.fromByte(14));
    try std.testing.expectEqual(Op.ttl_op, try Op.fromByte(15));
    try std.testing.expectEqual(Op.coll_ttl_op, try Op.fromByte(16));
    try std.testing.expectEqual(Op.coll_op, try Op.fromByte(17));
    try std.testing.expectEqual(Op.txn_op, try Op.fromByte(18));
    try std.testing.expectEqual(Op.table_join, try Op.fromByte(19));
    try std.testing.expectEqual(Op.table_aggregate, try Op.fromByte(20));
    try std.testing.expectEqual(Op.table_explain, try Op.fromByte(21));
    try std.testing.expectEqual(Op.table_update, try Op.fromByte(22));
    try std.testing.expectEqual(Op.table_delete, try Op.fromByte(23));
    try std.testing.expectEqual(Op.table_export, try Op.fromByte(24));
    try std.testing.expectEqual(Op.table_import, try Op.fromByte(25));
    try std.testing.expectEqual(Op.table_window, try Op.fromByte(26));
    try std.testing.expectEqual(Op.subscribe, try Op.fromByte(27));
    try std.testing.expectEqual(Op.publish, try Op.fromByte(28));
    try std.testing.expectEqual(Op.unsubscribe, try Op.fromByte(29));
}

test "Status.fromByte rejects unknown status codes" {
    try std.testing.expectError(error.UnknownStatus, Status.fromByte(200));
    try std.testing.expectEqual(Status.internal, try Status.fromByte(5));
    try std.testing.expectEqual(Status.rate_limited, try Status.fromByte(6));
    try std.testing.expectEqual(Status.unauthorized, try Status.fromByte(7));
    try std.testing.expectEqual(Status.forbidden, try Status.fromByte(8));
}

test "auth payload encodes and decodes username and password" {
    const allocator = std.testing.allocator;
    const payload = try encodeAuth(allocator, "alice", "hunter2");
    defer allocator.free(payload);
    const args = try decodeAuth(payload);
    try std.testing.expectEqualStrings("alice", args.username);
    try std.testing.expectEqualStrings("hunter2", args.password);
}

test "auth payload handles an empty password" {
    const allocator = std.testing.allocator;
    const payload = try encodeAuth(allocator, "alice", "");
    defer allocator.free(payload);
    const args = try decodeAuth(payload);
    try std.testing.expectEqualStrings("alice", args.username);
    try std.testing.expectEqualStrings("", args.password);
}

test "encodeAuthOk with no token round trips to an empty payload" {
    const allocator = std.testing.allocator;
    const payload = try encodeAuthOk(allocator, null);
    defer allocator.free(payload);
    try std.testing.expectEqual(@as(usize, 0), payload.len);
}

test "encodeAuthOk with a token round trips exactly" {
    const allocator = std.testing.allocator;
    const payload = try encodeAuthOk(allocator, "deadbeef");
    defer allocator.free(payload);
    try std.testing.expectEqualStrings("deadbeef", payload);
}

test "auth_token payload round trips the opaque token bytes" {
    const allocator = std.testing.allocator;
    const payload = try encodeAuthToken(allocator, "abc123token");
    defer allocator.free(payload);
    try std.testing.expectEqualStrings("abc123token", decodeAuthToken(payload));
}

test "set payload encodes and decodes key and value" {
    const allocator = std.testing.allocator;
    const payload = try encodeSet(allocator, "k", "value-bytes");
    defer allocator.free(payload);
    const args = try decodeSet(payload);
    try std.testing.expectEqualStrings("k", args.key);
    try std.testing.expectEqualStrings("value-bytes", args.value);
}

test "set payload handles an empty value" {
    const allocator = std.testing.allocator;
    const payload = try encodeSet(allocator, "k", "");
    defer allocator.free(payload);
    const args = try decodeSet(payload);
    try std.testing.expectEqualStrings("k", args.key);
    try std.testing.expectEqualStrings("", args.value);
}

test "scan args round trip with both bounds" {
    const allocator = std.testing.allocator;
    const payload = try encodeScan(allocator, .{ .start = "a", .end = "z", .limit = 42, .reverse = true });
    defer allocator.free(payload);
    const args = try decodeScan(payload);
    try std.testing.expectEqualStrings("a", args.start.?);
    try std.testing.expectEqualStrings("z", args.end.?);
    try std.testing.expectEqual(@as(u32, 42), args.limit);
    try std.testing.expect(args.reverse);
}

test "scan args round trip with no bounds" {
    const allocator = std.testing.allocator;
    const payload = try encodeScan(allocator, .{});
    defer allocator.free(payload);
    const args = try decodeScan(payload);
    try std.testing.expect(args.start == null);
    try std.testing.expect(args.end == null);
    try std.testing.expect(!args.reverse);
}

test "prefix args round trip" {
    const allocator = std.testing.allocator;
    const payload = try encodePrefix(allocator, "user:", 7);
    defer allocator.free(payload);
    const args = try decodePrefix(payload);
    try std.testing.expectEqualStrings("user:", args.prefix);
    try std.testing.expectEqual(@as(u32, 7), args.limit);
}

test "entries round trip and are independently owned" {
    const allocator = std.testing.allocator;
    const entries = [_]dbmod.Entry{
        .{ .key = "a", .value = "1" },
        .{ .key = "b", .value = "2" },
    };
    const payload = try encodeEntries(allocator, &entries);
    defer allocator.free(payload);

    const owned = try decodeEntries(allocator, payload);
    defer freeOwnedEntries(allocator, owned);

    try std.testing.expectEqual(@as(usize, 2), owned.len);
    try std.testing.expectEqualStrings("a", owned[0].key);
    try std.testing.expectEqualStrings("1", owned[0].value);
    try std.testing.expectEqualStrings("b", owned[1].key);
    try std.testing.expectEqualStrings("2", owned[1].value);
}

test "empty entry list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeEntries(allocator, &[_]dbmod.Entry{});
    defer allocator.free(payload);
    const owned = try decodeEntries(allocator, payload);
    defer freeOwnedEntries(allocator, owned);
    try std.testing.expectEqual(@as(usize, 0), owned.len);
}

test "batch ops round trip put and delete" {
    const allocator = std.testing.allocator;
    const ops = [_]BatchOp{
        .{ .put = .{ .key = "a", .value = "1" } },
        .{ .del = "b" },
    };
    const payload = try encodeBatch(allocator, &ops);
    defer allocator.free(payload);

    const decoded = try decodeBatch(allocator, payload);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("a", decoded[0].put.key);
    try std.testing.expectEqualStrings("1", decoded[0].put.value);
    try std.testing.expectEqualStrings("b", decoded[1].del);
}

test "decodeBatch rejects an unknown op kind" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(1);
    try w.byte(9);
    try std.testing.expectError(error.Malformed, decodeBatch(allocator, buf.items));
}

test "stats round trip preserves all fields including per-level detail" {
    const allocator = std.testing.allocator;
    var stats = dbmod.Stats{};
    stats.memtableEntries = 3;
    stats.memtableBytes = 128;
    stats.sstableCount = 2;
    stats.liveEntries = 100;
    stats.physicalBytes = 4096;
    stats.cacheHits = 10;
    stats.cacheMisses = 4;
    stats.nextSeq = 55;
    stats.levels[0] = .{ .tables = 1, .entries = 50, .physicalBytes = 2048 };
    stats.levels[3] = .{ .tables = 2, .entries = 50, .physicalBytes = 2048 };

    const payload = try encodeStats(allocator, stats);
    defer allocator.free(payload);
    const decoded = try decodeStats(payload);

    try std.testing.expectEqual(stats.memtableEntries, decoded.memtableEntries);
    try std.testing.expectEqual(stats.nextSeq, decoded.nextSeq);
    try std.testing.expectEqual(stats.levels[0].tables, decoded.levels[0].tables);
    try std.testing.expectEqual(stats.levels[3].entries, decoded.levels[3].entries);
    try std.testing.expectEqual(@as(f64, decoded.cacheHitRate()), decoded.cacheHitRate());
}

test "table select args round trip with a non-empty expr" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "city eq s:warsaw", 0, 0, &.{});
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("city eq s:warsaw", args.exprText);
    try std.testing.expectEqual(@as(u32, 0), args.offset);
    try std.testing.expectEqual(@as(u32, 0), args.limit);
    try std.testing.expectEqual(@as(usize, 0), args.orderBy.len);
}

test "table select args round trip with an empty expr means select all" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "", 0, 0, &.{});
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("", args.exprText);
}

test "table select args round trip with a page window" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "age gt i:10", 5, 3, &.{});
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("age gt i:10", args.exprText);
    try std.testing.expectEqual(@as(u32, 5), args.offset);
    try std.testing.expectEqual(@as(u32, 3), args.limit);
}

test "table select args round trip with an ascending order-by" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "", 0, 0, &.{.{ .field = "age" }});
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqual(@as(usize, 1), args.orderBy.len);
    try std.testing.expectEqualStrings("age", args.orderBy[0].field);
    try std.testing.expectEqual(false, args.orderBy[0].descending);
}

test "table select args round trip with a descending order-by, page, and expr all together" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "city eq s:warsaw", 2, 5, &.{.{ .field = "score", .descending = true }});
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("city eq s:warsaw", args.exprText);
    try std.testing.expectEqual(@as(u32, 2), args.offset);
    try std.testing.expectEqual(@as(u32, 5), args.limit);
    try std.testing.expectEqualStrings("score", args.orderBy[0].field);
    try std.testing.expectEqual(true, args.orderBy[0].descending);
}

test "table select args round trip with two order-by columns in given order" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "", 0, 0, &.{ .{ .field = "city" }, .{ .field = "score", .descending = true } });
    defer allocator.free(payload);
    const args = try decodeTableSelect(allocator, payload);
    defer allocator.free(args.orderBy);
    try std.testing.expectEqual(@as(usize, 2), args.orderBy.len);
    try std.testing.expectEqualStrings("city", args.orderBy[0].field);
    try std.testing.expectEqual(false, args.orderBy[0].descending);
    try std.testing.expectEqualStrings("score", args.orderBy[1].field);
    try std.testing.expectEqual(true, args.orderBy[1].descending);
}

test "decodeTableSelect rejects an order-by count claiming more columns than were actually encoded" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableSelect(allocator, "users", "", 0, 0, &.{.{ .field = "age" }});
    defer allocator.free(payload);
    const countBytePos = 4 + 5 + 4 + 4;
    try std.testing.expectEqual(@as(u8, 1), payload[countBytePos]);
    var corrupted = try allocator.dupe(u8, payload);
    defer allocator.free(corrupted);
    corrupted[countBytePos] = 200;
    try std.testing.expectError(error.Malformed, decodeTableSelect(allocator, corrupted));
}

test "rows round trip through encode and decode" {
    const allocator = std.testing.allocator;
    var rows = [_]rowmod.Row{ rowmod.Row.init(allocator), rowmod.Row.init(allocator) };
    defer for (&rows) |*r| r.deinit();
    try rows[0].set("name", .{ .text = "ada" });
    try rows[0].set("age", .{ .int = 36 });
    try rows[1].set("name", .{ .text = "bob" });
    try rows[1].set("age", .{ .int = 24 });

    const payload = try encodeRows(allocator, &rows);
    defer allocator.free(payload);

    const decoded = try decodeRows(allocator, payload);
    defer freeRows(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("ada", decoded[0].get("name").?.text);
    try std.testing.expectEqual(@as(i64, 36), decoded[0].get("age").?.int);
    try std.testing.expectEqualStrings("bob", decoded[1].get("name").?.text);
    try std.testing.expectEqual(@as(i64, 24), decoded[1].get("age").?.int);
}

test "empty row list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeRows(allocator, &[_]rowmod.Row{});
    defer allocator.free(payload);
    const decoded = try decodeRows(allocator, payload);
    defer freeRows(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "JoinMode.fromByte rejects an unknown mode" {
    try std.testing.expectError(error.UnknownJoinMode, JoinMode.fromByte(9));
}

test "table_join args round trip mode, tables, fields, and both expr texts" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableJoin(allocator, .left, "customers", "__pk", "orders", "customer_id", 0, 0, "age gt i:10", "total gt i:0");
    defer allocator.free(payload);
    const args = try decodeTableJoin(payload);
    try std.testing.expectEqual(JoinMode.left, args.mode);
    try std.testing.expectEqualStrings("customers", args.leftTable);
    try std.testing.expectEqualStrings("__pk", args.leftField);
    try std.testing.expectEqualStrings("orders", args.rightTable);
    try std.testing.expectEqualStrings("customer_id", args.rightField);
    try std.testing.expectEqual(@as(u32, 0), args.offset);
    try std.testing.expectEqual(@as(u32, 0), args.limit);
    try std.testing.expectEqualStrings("age gt i:10", args.leftExprText);
    try std.testing.expectEqualStrings("total gt i:0", args.rightExprText);
}

test "table_join args round trip with both expr texts empty" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableJoin(allocator, .inner, "a", "x", "b", "y", 0, 0, "", "");
    defer allocator.free(payload);
    const args = try decodeTableJoin(payload);
    try std.testing.expectEqual(JoinMode.inner, args.mode);
    try std.testing.expectEqualStrings("", args.leftExprText);
    try std.testing.expectEqualStrings("", args.rightExprText);
}

test "table_join args round trip a nonzero offset and limit" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableJoin(allocator, .full, "a", "x", "b", "y", 3, 7, "", "");
    defer allocator.free(payload);
    const args = try decodeTableJoin(payload);
    try std.testing.expectEqual(@as(u32, 3), args.offset);
    try std.testing.expectEqual(@as(u32, 7), args.limit);
}

test "join pairs round trip a fully matched pair (inner-join shape)" {
    const allocator = std.testing.allocator;
    var left = rowmod.Row.init(allocator);
    defer left.deinit();
    try left.set("name", .{ .text = "ada" });
    var right = rowmod.Row.init(allocator);
    defer right.deinit();
    try right.set("total", .{ .int = 42 });

    const pairs = [_]JoinPair{.{ .left = left, .right = right }};
    const payload = try encodeJoinedRows(allocator, &pairs);
    defer allocator.free(payload);

    const decoded = try decodeJoinedRows(allocator, payload);
    defer freeJoinPairs(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("ada", decoded[0].left.?.get("name").?.text);
    try std.testing.expectEqual(@as(i64, 42), decoded[0].right.?.get("total").?.int);
}

test "join pairs round trip a nil left side and a nil right side" {
    const allocator = std.testing.allocator;
    var right = rowmod.Row.init(allocator);
    defer right.deinit();
    try right.set("total", .{ .int = 7 });
    var left = rowmod.Row.init(allocator);
    defer left.deinit();
    try left.set("name", .{ .text = "carol" });

    const pairs = [_]JoinPair{
        .{ .left = null, .right = right },
        .{ .left = left, .right = null },
    };
    const payload = try encodeJoinedRows(allocator, &pairs);
    defer allocator.free(payload);

    const decoded = try decodeJoinedRows(allocator, payload);
    defer freeJoinPairs(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expect(decoded[0].left == null);
    try std.testing.expectEqual(@as(i64, 7), decoded[0].right.?.get("total").?.int);
    try std.testing.expectEqualStrings("carol", decoded[1].left.?.get("name").?.text);
    try std.testing.expect(decoded[1].right == null);
}

test "empty join pair list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeJoinedRows(allocator, &[_]JoinPair{});
    defer allocator.free(payload);
    const decoded = try decodeJoinedRows(allocator, payload);
    defer freeJoinPairs(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "table_aggregate args round trip a groupField, several specs, and an expr" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
        .{ .field = "total", .kind = .max },
        .{ .field = "city", .kind = .count_distinct },
    };
    const payload = try encodeTableAggregate(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "total gt i:10");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqualStrings("orders", args.table);
    try std.testing.expectEqualStrings("city", args.groupField);
    try std.testing.expectEqual(@as(u32, 0), args.offset);
    try std.testing.expectEqual(@as(u32, 0), args.limit);
    try std.testing.expectEqualStrings("", args.havingText);
    try std.testing.expectEqualStrings("total gt i:10", args.exprText);
    try std.testing.expectEqual(@as(usize, 4), args.specs.len);
    try std.testing.expectEqual(aggregatemod.AggKind.count, args.specs[0].kind);
    try std.testing.expectEqualStrings("", args.specs[0].field);
    try std.testing.expectEqual(aggregatemod.AggKind.sum, args.specs[1].kind);
    try std.testing.expectEqualStrings("total", args.specs[1].field);
    try std.testing.expectEqual(aggregatemod.AggKind.max, args.specs[2].kind);
    try std.testing.expectEqual(aggregatemod.AggKind.count_distinct, args.specs[3].kind);
    try std.testing.expectEqualStrings("city", args.specs[3].field);
}

test "table_aggregate args round trip an empty groupField (global, no grouping) and empty expr" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};
    const payload = try encodeTableAggregate(allocator, "orders", "", &specs, 0, 0, &.{}, "", "");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqualStrings("", args.groupField);
    try std.testing.expectEqualStrings("", args.exprText);
    try std.testing.expectEqual(@as(usize, 1), args.specs.len);
}

test "table_aggregate args round trip a nonzero offset and limit" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};
    const payload = try encodeTableAggregate(allocator, "orders", "city", &specs, 2, 5, &.{}, "", "");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(u32, 2), args.offset);
    try std.testing.expectEqual(@as(u32, 5), args.limit);
}

test "table_aggregate args round trip a non-empty havingText alongside a non-empty exprText" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };
    const payload = try encodeTableAggregate(allocator, "orders", "city", &specs, 0, 0, &.{}, "sum_total gt i:1000", "total gt i:10");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqualStrings("sum_total gt i:1000", args.havingText);
    try std.testing.expectEqualStrings("total gt i:10", args.exprText);
}

test "table_aggregate args round trip a multi-column orderBy alongside havingText and exprText" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{
        .{ .field = "", .kind = .count },
        .{ .field = "total", .kind = .sum },
    };
    const orderBy = [_]querymod.OrderBy{
        .{ .field = "sum_total", .descending = true },
        .{ .field = "city" },
    };
    const payload = try encodeTableAggregate(allocator, "orders", "city", &specs, 0, 0, &orderBy, "sum_total gt i:100", "total gt i:10");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 2), args.orderBy.len);
    try std.testing.expectEqualStrings("sum_total", args.orderBy[0].field);
    try std.testing.expect(args.orderBy[0].descending);
    try std.testing.expectEqualStrings("city", args.orderBy[1].field);
    try std.testing.expect(!args.orderBy[1].descending);
    try std.testing.expectEqualStrings("sum_total gt i:100", args.havingText);
    try std.testing.expectEqualStrings("total gt i:10", args.exprText);
}

test "table_aggregate args round trip an empty orderBy the same as before this feature existed" {
    const allocator = std.testing.allocator;
    const specs = [_]aggregatemod.AggSpec{.{ .field = "", .kind = .count }};
    const payload = try encodeTableAggregate(allocator, "orders", "city", &specs, 0, 0, &.{}, "", "");
    defer allocator.free(payload);
    const args = try decodeTableAggregate(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 0), args.orderBy.len);
}

test "decodeTableAggregate rejects an unknown agg kind byte instead of corrupting a spec" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "orders");
    try putLenPrefixed(w, "city");
    try w.putU32(1);
    try w.byte(200);
    try putLenPrefixed(w, "total");

    try std.testing.expectError(error.Malformed, decodeTableAggregate(allocator, buf.items));
}

test "agg global result round trips count/sum/max values, including a none from an empty avg" {
    const allocator = std.testing.allocator;
    const values = [_]rowmod.Value{
        .{ .int = 4 },
        .{ .float = 10.5 },
        .{ .none = {} },
        .{ .text = "warsaw" },
    };
    const payload = try encodeAggGlobalResult(allocator, &values);
    defer allocator.free(payload);

    const decoded = try decodeAggGlobalResult(allocator, payload);
    defer freeAggValues(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 4), decoded.len);
    try std.testing.expectEqual(@as(i64, 4), decoded[0].int);
    try std.testing.expectApproxEqAbs(@as(f64, 10.5), decoded[1].float, 1e-9);
    try std.testing.expectEqual(rowmod.ValueTag.none, @as(rowmod.ValueTag, decoded[2]));
    try std.testing.expectEqualStrings("warsaw", decoded[3].text);
}

test "empty agg global result round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeAggGlobalResult(allocator, &[_]rowmod.Value{});
    defer allocator.free(payload);
    const decoded = try decodeAggGlobalResult(allocator, payload);
    defer freeAggValues(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "agg group rows round trip several groups with several values each" {
    const allocator = std.testing.allocator;
    const groups = [_]aggregatemod.GroupRow{
        .{ .group = .{ .text = "warsaw" }, .values = @constCast(&[_]rowmod.Value{ .{ .int = 2 }, .{ .int = 350 } }) },
        .{ .group = .{ .text = "krakow" }, .values = @constCast(&[_]rowmod.Value{ .{ .int = 1 }, .{ .int = 40 } }) },
    };
    const payload = try encodeAggGroupRows(allocator, &groups);
    defer allocator.free(payload);

    const decoded = try decodeAggGroupRows(allocator, payload);
    defer freeAggGroupRows(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("warsaw", decoded[0].group.text);
    try std.testing.expectEqual(@as(i64, 2), decoded[0].values[0].int);
    try std.testing.expectEqual(@as(i64, 350), decoded[0].values[1].int);
    try std.testing.expectEqualStrings("krakow", decoded[1].group.text);
    try std.testing.expectEqual(@as(i64, 40), decoded[1].values[1].int);
}

test "empty agg group rows list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeAggGroupRows(allocator, &[_]aggregatemod.GroupRow{});
    defer allocator.free(payload);
    const decoded = try decodeAggGroupRows(allocator, payload);
    defer freeAggGroupRows(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "decodeAggGroupRows rejects a corrupted second group without leaking the first" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);

    var goodGroup = rowmod.Row.init(allocator);
    defer goodGroup.deinit();
    const goodGroupValue = try rowmod.encodeValue(allocator, .{ .text = "warsaw" });
    defer allocator.free(goodGroupValue);
    const goodMemberValue = try rowmod.encodeValue(allocator, .{ .int = 1 });
    defer allocator.free(goodMemberValue);

    try w.putU32(2);
    try putLenPrefixed(w, goodGroupValue);
    try w.putU32(1);
    try putLenPrefixed(w, goodMemberValue);
    try putLenPrefixed(w, &[_]u8{99});

    try std.testing.expectError(error.Malformed, decodeAggGroupRows(allocator, buf.items));
}

test "table_explain args round trip a table and an expr" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableExplain(allocator, "users", "city eq s:warsaw");
    defer allocator.free(payload);
    const args = try decodeTableExplain(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("city eq s:warsaw", args.exprText);
}

test "table_explain args round trip an empty expr" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableExplain(allocator, "users", "");
    defer allocator.free(payload);
    const args = try decodeTableExplain(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("", args.exprText);
}

test "table_update args round trip a table, set fields, and an expr" {
    const allocator = std.testing.allocator;
    const sets = [_]rowmod.Field{
        .{ .name = "active", .value = .{ .int = 1 } },
        .{ .name = "city", .value = .{ .text = "krakow" } },
    };
    const payload = try encodeTableUpdate(allocator, "users", &sets, "city eq s:warsaw");
    defer allocator.free(payload);
    const args = try decodeTableUpdate(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("city eq s:warsaw", args.exprText);

    var decoded = try rowmod.Row.decode(allocator, args.setsBytes);
    defer decoded.deinit();
    try std.testing.expectEqual(rowmod.Value{ .int = 1 }, decoded.get("active").?);
    try std.testing.expectEqualStrings("krakow", decoded.get("city").?.text);
}

test "table_update args round trip an empty expr, updating every row" {
    const allocator = std.testing.allocator;
    const sets = [_]rowmod.Field{.{ .name = "seen", .value = .{ .int = 1 } }};
    const payload = try encodeTableUpdate(allocator, "users", &sets, "");
    defer allocator.free(payload);
    const args = try decodeTableUpdate(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("", args.exprText);

    var decoded = try rowmod.Row.decode(allocator, args.setsBytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.count());
}

test "table_delete args round trip a table and an expr" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableDelete(allocator, "users", "city eq s:warsaw");
    defer allocator.free(payload);
    const args = try decodeTableDelete(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("city eq s:warsaw", args.exprText);
}

test "table_delete args round trip an empty expr, deleting every row" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableDelete(allocator, "users", "");
    defer allocator.free(payload);
    const args = try decodeTableDelete(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqualStrings("", args.exprText);
}

test "table_export args round trip a table and each format" {
    const allocator = std.testing.allocator;

    const csvPayload = try encodeTableExport(allocator, "users", .csv);
    defer allocator.free(csvPayload);
    const csvArgs = try decodeTableExport(csvPayload);
    try std.testing.expectEqualStrings("users", csvArgs.table);
    try std.testing.expectEqual(DumpFormat.csv, csvArgs.format);

    const jsonPayload = try encodeTableExport(allocator, "users", .json);
    defer allocator.free(jsonPayload);
    const jsonArgs = try decodeTableExport(jsonPayload);
    try std.testing.expectEqualStrings("users", jsonArgs.table);
    try std.testing.expectEqual(DumpFormat.json, jsonArgs.format);
}

test "table_export rejects a format byte outside the DumpFormat enum" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "users");
    try w.byte(99);
    try std.testing.expectError(error.Malformed, decodeTableExport(buf.items));
}

test "export result round trips a row count and content bytes" {
    const allocator = std.testing.allocator;
    const payload = try encodeExportResult(allocator, 3, "__pk\ni:1\ni:2\ni:3\n");
    defer allocator.free(payload);
    const result = try decodeExportResult(payload);
    try std.testing.expectEqual(@as(u64, 3), result.rowCount);
    try std.testing.expectEqualStrings("__pk\ni:1\ni:2\ni:3\n", result.content);
}

test "export result round trips a zero row count with empty content" {
    const allocator = std.testing.allocator;
    const payload = try encodeExportResult(allocator, 0, "");
    defer allocator.free(payload);
    const result = try decodeExportResult(payload);
    try std.testing.expectEqual(@as(u64, 0), result.rowCount);
    try std.testing.expectEqualStrings("", result.content);
}

test "table_import args round trip a table, format, and content" {
    const allocator = std.testing.allocator;
    const payload = try encodeTableImport(allocator, "users", .json, "[{\"__pk\": \"i:1\"}]");
    defer allocator.free(payload);
    const args = try decodeTableImport(payload);
    try std.testing.expectEqualStrings("users", args.table);
    try std.testing.expectEqual(DumpFormat.json, args.format);
    try std.testing.expectEqualStrings("[{\"__pk\": \"i:1\"}]", args.content);
}

test "table_import rejects a format byte outside the DumpFormat enum" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "users");
    try w.byte(7);
    try w.slice("ignored");
    try std.testing.expectError(error.Malformed, decodeTableImport(buf.items));
}

test "Plan round trips full_scan with a null indexName" {
    const allocator = std.testing.allocator;
    const payload = try encodePlan(allocator, .{ .kind = .full_scan });
    defer allocator.free(payload);
    var decoded = try decodePlan(allocator, payload);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.full_scan, decoded.kind);
    try std.testing.expect(decoded.indexName == null);
    try std.testing.expectEqual(@as(usize, 0), decoded.matchedFields);
    try std.testing.expectEqual(@as(usize, 0), decoded.totalFields);
}

test "Plan round trips index_range with an indexName and field counts" {
    const allocator = std.testing.allocator;
    const payload = try encodePlan(allocator, .{ .kind = .index_range, .indexName = "score", .matchedFields = 1, .totalFields = 1 });
    defer allocator.free(payload);
    var decoded = try decodePlan(allocator, payload);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.index_range, decoded.kind);
    try std.testing.expectEqualStrings("score", decoded.indexName.?);
    try std.testing.expectEqual(@as(usize, 1), decoded.matchedFields);
    try std.testing.expectEqual(@as(usize, 1), decoded.totalFields);
}

test "Plan round trips composite_eq with a strict prefix match" {
    const allocator = std.testing.allocator;
    const payload = try encodePlan(allocator, .{ .kind = .composite_eq, .indexName = "city_age", .matchedFields = 1, .totalFields = 2 });
    defer allocator.free(payload);
    var decoded = try decodePlan(allocator, payload);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(querymod.PlanKind.composite_eq, decoded.kind);
    try std.testing.expectEqualStrings("city_age", decoded.indexName.?);
    try std.testing.expectEqual(@as(usize, 1), decoded.matchedFields);
    try std.testing.expectEqual(@as(usize, 2), decoded.totalFields);
}

test "decodePlan rejects an unknown PlanKind byte instead of corrupting a plan" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(200);
    try putLenPrefixed(w, "");
    try w.putU32(0);
    try w.putU32(0);

    try std.testing.expectError(error.Malformed, decodePlan(allocator, buf.items));
}

test "decodeRows rejects a corrupted row payload without leaking prior rows" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    var goodRow = rowmod.Row.init(allocator);
    defer goodRow.deinit();
    try goodRow.set("a", .{ .int = 1 });
    const encoded = try goodRow.encode(allocator);
    defer allocator.free(encoded);

    try w.putU32(2);
    try putLenPrefixed(w, encoded);
    try putLenPrefixed(w, &.{ 9, 9, 9 });

    try std.testing.expectError(error.Malformed, decodeRows(allocator, buf.items));
}

test "Cursor.takeLenPrefixed rejects a length that overruns the buffer" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(100);
    try w.slice("short");
    var c = Cursor{ .data = buf.items };
    try std.testing.expectError(error.Malformed, c.takeLenPrefixed());
}

test "UserAdminAction.fromByte rejects an unknown action" {
    try std.testing.expectError(error.Malformed, UserAdminAction.fromByte(200));
    try std.testing.expectEqual(UserAdminAction.list, try UserAdminAction.fromByte(4));
}

test "user_admin create payload round trips role and rounds" {
    const allocator = std.testing.allocator;
    const payload = try encodeUserAdmin(allocator, .create, "alice", "hunter2", .admin, 100_000);
    defer allocator.free(payload);
    const args = try decodeUserAdmin(payload);
    try std.testing.expectEqual(UserAdminAction.create, args.action);
    try std.testing.expectEqualStrings("alice", args.username);
    try std.testing.expectEqualStrings("hunter2", args.password);
    try std.testing.expectEqual(@intFromEnum(authmod.Role.admin), args.roleByte);
    try std.testing.expectEqual(@as(u32, 100_000), args.rounds);
}

test "user_admin delete payload carries only the username" {
    const allocator = std.testing.allocator;
    const payload = try encodeUserAdmin(allocator, .delete, "bob", "", .readonly, 0);
    defer allocator.free(payload);
    const args = try decodeUserAdmin(payload);
    try std.testing.expectEqual(UserAdminAction.delete, args.action);
    try std.testing.expectEqualStrings("bob", args.username);
    try std.testing.expectEqualStrings("", args.password);
}

test "user_admin list payload round trips with an empty username" {
    const allocator = std.testing.allocator;
    const payload = try encodeUserAdmin(allocator, .list, "", "", .readonly, 0);
    defer allocator.free(payload);
    const args = try decodeUserAdmin(payload);
    try std.testing.expectEqual(UserAdminAction.list, args.action);
    try std.testing.expectEqualStrings("", args.username);
}

test "user list round trips every username with its role" {
    const allocator = std.testing.allocator;
    const users = [_]authmod.UserInfo{
        .{ .username = @constCast("alice"), .role = .readonly },
        .{ .username = @constCast("root"), .role = .admin },
    };
    const payload = try encodeUserList(allocator, &users);
    defer allocator.free(payload);

    const decoded = try decodeUserList(allocator, payload);
    defer authmod.freeUserList(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("alice", decoded[0].username);
    try std.testing.expectEqual(authmod.Role.readonly, decoded[0].role);
    try std.testing.expectEqualStrings("root", decoded[1].username);
    try std.testing.expectEqual(authmod.Role.admin, decoded[1].role);
}

test "empty user list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeUserList(allocator, &[_]authmod.UserInfo{});
    defer allocator.free(payload);
    const decoded = try decodeUserList(allocator, payload);
    defer authmod.freeUserList(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "decodeUserList rejects an unknown role byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(1);
    try putLenPrefixed(w, "ghost");
    try w.byte(200);
    try std.testing.expectError(error.Malformed, decodeUserList(allocator, buf.items));
}

test "TtlAction.fromByte rejects an unknown action" {
    try std.testing.expectError(error.Malformed, TtlAction.fromByte(200));
    try std.testing.expectEqual(TtlAction.sweep, try TtlAction.fromByte(3));
}

test "ttl_op expire payload round trips key and seconds" {
    const allocator = std.testing.allocator;
    const payload = try encodeTtlOp(allocator, .expire, "session:1", 30);
    defer allocator.free(payload);
    const args = try decodeTtlOp(payload);
    try std.testing.expectEqual(TtlAction.expire, args.action);
    try std.testing.expectEqualStrings("session:1", args.key);
    try std.testing.expectEqual(@as(u64, 30), args.seconds);
}

test "ttl_op sweep payload carries an empty key and zero seconds" {
    const allocator = std.testing.allocator;
    const payload = try encodeTtlOp(allocator, .sweep, "", 0);
    defer allocator.free(payload);
    const args = try decodeTtlOp(payload);
    try std.testing.expectEqual(TtlAction.sweep, args.action);
    try std.testing.expectEqualStrings("", args.key);
    try std.testing.expectEqual(@as(u64, 0), args.seconds);
}

test "ttl result round trips noKey, noExpiry, and seconds" {
    const allocator = std.testing.allocator;

    const noKeyPayload = try encodeTtlResult(allocator, .noKey);
    defer allocator.free(noKeyPayload);
    try std.testing.expectEqual(ttlmod.TtlResult.noKey, try decodeTtlResult(noKeyPayload));

    const noExpiryPayload = try encodeTtlResult(allocator, .noExpiry);
    defer allocator.free(noExpiryPayload);
    try std.testing.expectEqual(ttlmod.TtlResult.noExpiry, try decodeTtlResult(noExpiryPayload));

    const secondsPayload = try encodeTtlResult(allocator, .{ .seconds = 42 });
    defer allocator.free(secondsPayload);
    const decoded = try decodeTtlResult(secondsPayload);
    try std.testing.expectEqual(@as(u64, 42), decoded.seconds);
}

test "decodeTtlResult rejects an unknown kind byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(200);
    try std.testing.expectError(error.Malformed, decodeTtlResult(buf.items));
}

test "ttl sweep count round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeTtlSweepCount(allocator, 7);
    defer allocator.free(payload);
    try std.testing.expectEqual(@as(u64, 7), try decodeTtlSweepCount(payload));
}

test "coll_ttl_op expire payload round trips action, kind, name and seconds" {
    const allocator = std.testing.allocator;
    const payload = try encodeCollTtlOp(allocator, .expire, .hash, "profile", 30);
    defer allocator.free(payload);
    const args = try decodeCollTtlOp(payload);
    try std.testing.expectEqual(TtlAction.expire, args.action);
    try std.testing.expectEqual(collmod.Kind.hash, args.kind);
    try std.testing.expectEqualStrings("profile", args.name);
    try std.testing.expectEqual(@as(u64, 30), args.seconds);
}

test "coll_ttl_op round trips every kind's tag byte" {
    const allocator = std.testing.allocator;
    const kinds = [_]collmod.Kind{ .counter, .hash, .set, .list, .zset };
    for (kinds) |k| {
        const payload = try encodeCollTtlOp(allocator, .query, k, "n", 0);
        defer allocator.free(payload);
        const args = try decodeCollTtlOp(payload);
        try std.testing.expectEqual(k, args.kind);
    }
}

test "coll_ttl_op sweep payload carries an empty name and zero seconds" {
    const allocator = std.testing.allocator;
    const payload = try encodeCollTtlOp(allocator, .sweep, .counter, "", 0);
    defer allocator.free(payload);
    const args = try decodeCollTtlOp(payload);
    try std.testing.expectEqual(TtlAction.sweep, args.action);
    try std.testing.expectEqualStrings("", args.name);
    try std.testing.expectEqual(@as(u64, 0), args.seconds);
}

test "decodeCollTtlOp rejects an unknown kind byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(@intFromEnum(TtlAction.query));
    try w.byte('?');
    try w.putU64(0);
    try std.testing.expectError(error.Malformed, decodeCollTtlOp(buf.items));
}

test "decodeCollTtlOp rejects an unknown action byte before the kind byte is even read" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(200);
    try w.byte('H');
    try w.putU64(0);
    try std.testing.expectError(error.Malformed, decodeCollTtlOp(buf.items));
}

test "CollAction.fromByte rejects an unknown action" {
    try std.testing.expectError(error.Malformed, CollAction.fromByte(200));
    try std.testing.expectEqual(CollAction.zset_rank, try CollAction.fromByte(29));
}

test "CollAction.kind groups every action under its collection kind" {
    try std.testing.expectEqual(collmod.Kind.counter, CollAction.counter_incrby.kind());
    try std.testing.expectEqual(collmod.Kind.hash, CollAction.hash_getall.kind());
    try std.testing.expectEqual(collmod.Kind.set, CollAction.set_diff.kind());
    try std.testing.expectEqual(collmod.Kind.list, CollAction.list_range.kind());
    try std.testing.expectEqual(collmod.Kind.zset, CollAction.zset_rangebyscore.kind());
}

test "CollAction.isReadOnly separates reads from writes" {
    try std.testing.expect(CollAction.counter_get.isReadOnly());
    try std.testing.expect(!CollAction.counter_set.isReadOnly());
    try std.testing.expect(CollAction.zset_rank.isReadOnly());
    try std.testing.expect(!CollAction.zset_add.isReadOnly());
    try std.testing.expect(CollAction.set_inter.isReadOnly());
    try std.testing.expect(!CollAction.list_lpush.isReadOnly());
}

test "coll_op payload round trips action, name, and a variable arg list" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "alice", "10" };
    const payload = try encodeCollOp(allocator, .zset_add, "leaderboard", &args);
    defer allocator.free(payload);
    const decoded = try decodeCollOp(allocator, payload);
    defer allocator.free(decoded.args);
    try std.testing.expectEqual(CollAction.zset_add, decoded.action);
    try std.testing.expectEqualStrings("leaderboard", decoded.name);
    try std.testing.expectEqual(@as(usize, 2), decoded.args.len);
    try std.testing.expectEqualStrings("alice", decoded.args[0]);
    try std.testing.expectEqualStrings("10", decoded.args[1]);
}

test "coll_op payload round trips a zero-arg action" {
    const allocator = std.testing.allocator;
    const payload = try encodeCollOp(allocator, .hash_getall, "profile", &.{});
    defer allocator.free(payload);
    const decoded = try decodeCollOp(allocator, payload);
    defer allocator.free(decoded.args);
    try std.testing.expectEqual(CollAction.hash_getall, decoded.action);
    try std.testing.expectEqualStrings("profile", decoded.name);
    try std.testing.expectEqual(@as(usize, 0), decoded.args.len);
}

test "decodeCollOp rejects an unknown action byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(250);
    try putLenPrefixed(w, "x");
    try w.putU32(0);
    try std.testing.expectError(error.Malformed, decodeCollOp(allocator, buf.items));
}

test "coll reply round trips nil and ok" {
    const allocator = std.testing.allocator;

    const nilPayload = try encodeCollReply(allocator, .nil);
    defer allocator.free(nilPayload);
    var nilReply = try decodeCollReply(allocator, nilPayload);
    defer nilReply.deinit(allocator);
    try std.testing.expect(nilReply == .nil);

    const okPayload = try encodeCollReply(allocator, .ok);
    defer allocator.free(okPayload);
    var okReply = try decodeCollReply(allocator, okPayload);
    defer okReply.deinit(allocator);
    try std.testing.expect(okReply == .ok);
}

test "coll reply round trips int and real" {
    const allocator = std.testing.allocator;

    const intPayload = try encodeCollReply(allocator, .{ .int = -42 });
    defer allocator.free(intPayload);
    var intReply = try decodeCollReply(allocator, intPayload);
    defer intReply.deinit(allocator);
    try std.testing.expectEqual(@as(i64, -42), intReply.int);

    const realPayload = try encodeCollReply(allocator, .{ .real = 3.5 });
    defer allocator.free(realPayload);
    var realReply = try decodeCollReply(allocator, realPayload);
    defer realReply.deinit(allocator);
    try std.testing.expectEqual(@as(f64, 3.5), realReply.real);
}

test "coll reply round trips raw bytes independently of the source payload" {
    const allocator = std.testing.allocator;
    const payload = try encodeCollReply(allocator, .{ .bytes = "hello" });
    defer allocator.free(payload);
    var reply = try decodeCollReply(allocator, payload);
    defer reply.deinit(allocator);
    try std.testing.expectEqualStrings("hello", reply.bytes);
}

test "coll reply round trips a string list, including empty" {
    const allocator = std.testing.allocator;
    const items = [_][]const u8{ "a", "bb", "ccc" };
    const payload = try encodeCollReply(allocator, .{ .stringList = &items });
    defer allocator.free(payload);
    var reply = try decodeCollReply(allocator, payload);
    defer reply.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), reply.stringList.len);
    try std.testing.expectEqualStrings("bb", reply.stringList[1]);

    const emptyPayload = try encodeCollReply(allocator, .{ .stringList = &.{} });
    defer allocator.free(emptyPayload);
    var emptyReply = try decodeCollReply(allocator, emptyPayload);
    defer emptyReply.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), emptyReply.stringList.len);
}

test "coll reply round trips a pair list (hash getall shape)" {
    const allocator = std.testing.allocator;
    const pairs = [_]CollPair{
        .{ .field = "name", .value = "ada" },
        .{ .field = "age", .value = "36" },
    };
    const payload = try encodeCollReply(allocator, .{ .pairList = &pairs });
    defer allocator.free(payload);
    var reply = try decodeCollReply(allocator, payload);
    defer reply.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), reply.pairList.len);
    try std.testing.expectEqualStrings("name", reply.pairList[0].field);
    try std.testing.expectEqualStrings("ada", reply.pairList[0].value);
    try std.testing.expectEqualStrings("age", reply.pairList[1].field);
    try std.testing.expectEqualStrings("36", reply.pairList[1].value);
}

test "coll reply round trips a score pair list (zset range shape), including negative scores" {
    const allocator = std.testing.allocator;
    const pairs = [_]CollScorePair{
        .{ .member = "bob", .score = -1.5 },
        .{ .member = "ada", .score = 10.25 },
    };
    const payload = try encodeCollReply(allocator, .{ .scorePairList = &pairs });
    defer allocator.free(payload);
    var reply = try decodeCollReply(allocator, payload);
    defer reply.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), reply.scorePairList.len);
    try std.testing.expectEqualStrings("bob", reply.scorePairList[0].member);
    try std.testing.expectEqual(@as(f64, -1.5), reply.scorePairList[0].score);
    try std.testing.expectEqualStrings("ada", reply.scorePairList[1].member);
    try std.testing.expectEqual(@as(f64, 10.25), reply.scorePairList[1].score);
}

test "decodeCollReply rejects an unknown tag byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.byte(250);
    try std.testing.expectError(error.Malformed, decodeCollReply(allocator, buf.items));
}

test "txn_op entries round trip put and del across two tables" {
    const allocator = std.testing.allocator;
    const putFields = [_]rowmod.Field{
        .{ .name = "balance", .value = .{ .int = 100 } },
        .{ .name = "city", .value = .{ .text = "warsaw" } },
    };
    const entries = [_]TxnOpEntry{
        .{ .verb = .put, .table = "accounts", .pk = .{ .int = 1 }, .fields = &putFields },
        .{ .verb = .del, .table = "sessions", .pk = .{ .text = "abc" } },
    };
    const payload = try encodeTxnOp(allocator, &entries);
    defer allocator.free(payload);

    const decoded = try decodeTxnOp(allocator, payload);
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);

    try std.testing.expectEqual(TxnVerb.put, decoded[0].verb);
    try std.testing.expectEqualStrings("accounts", decoded[0].table);
    const pk0 = try rowmod.decodeValue(allocator, decoded[0].pkBytes);
    try std.testing.expectEqual(@as(i64, 1), pk0.int);
    var fields0 = try rowmod.Row.decode(allocator, decoded[0].fieldsBytes);
    defer fields0.deinit();
    try std.testing.expectEqual(@as(i64, 100), fields0.get("balance").?.int);
    try std.testing.expectEqualStrings("warsaw", fields0.get("city").?.text);

    try std.testing.expectEqual(TxnVerb.del, decoded[1].verb);
    try std.testing.expectEqualStrings("sessions", decoded[1].table);
    var pk1 = try rowmod.decodeValue(allocator, decoded[1].pkBytes);
    defer pk1.free(allocator);
    try std.testing.expectEqualStrings("abc", pk1.text);
    var fields1 = try rowmod.Row.decode(allocator, decoded[1].fieldsBytes);
    defer fields1.deinit();
    try std.testing.expectEqual(@as(usize, 0), fields1.count());
}

test "empty txn_op entry list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeTxnOp(allocator, &[_]TxnOpEntry{});
    defer allocator.free(payload);
    const decoded = try decodeTxnOp(allocator, payload);
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "decodeTxnOp rejects an unknown verb byte" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(1);
    try w.byte(9);
    try std.testing.expectError(error.Malformed, decodeTxnOp(allocator, buf.items));
}

test "txn_op result round trips the applied count" {
    const allocator = std.testing.allocator;
    const payload = try encodeTxnResult(allocator, 7);
    defer allocator.free(payload);
    try std.testing.expectEqual(@as(u32, 7), try decodeTxnResult(payload));
}

test "table_window args round trip a ranking spec with a partition, an order-by, and an expr" {
    const allocator = std.testing.allocator;
    const orderBy = [_]querymod.OrderBy{.{ .field = "day", .descending = false }};
    const partitionBy = [_][]const u8{"city"};
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .row_number }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "total gt i:10", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqualStrings("orders", args.table);
    try std.testing.expectEqual(@as(usize, 1), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.row_number, args.specs[0].kind);
    try std.testing.expectEqualStrings("", args.specs[0].field);
    try std.testing.expectEqual(@as(usize, 1), args.partitionBy.len);
    try std.testing.expectEqualStrings("city", args.partitionBy[0]);
    try std.testing.expectEqual(@as(usize, 1), args.orderBy.len);
    try std.testing.expectEqualStrings("day", args.orderBy[0].field);
    try std.testing.expect(!args.orderBy[0].descending);
    try std.testing.expectEqualStrings("total gt i:10", args.exprText);
}

test "table_window args round trip a sum spec with no partition, no order-by, and an empty expr" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{.{ .field = "total", .kind = .sum }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 1), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.sum, args.specs[0].kind);
    try std.testing.expectEqualStrings("total", args.specs[0].field);
    try std.testing.expectEqual(@as(usize, 0), args.partitionBy.len);
    try std.testing.expectEqual(@as(usize, 0), args.orderBy.len);
    try std.testing.expectEqualStrings("", args.exprText);
}

test "table_window args round trip a count_distinct spec alongside sum, no extra wire bytes needed" {
    const allocator = std.testing.allocator;
    const orderBy = [_]querymod.OrderBy{.{ .field = "day" }};
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "tag", .kind = .count_distinct },
        .{ .field = "amount", .kind = .sum },
    };
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &orderBy, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 2), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.count_distinct, args.specs[0].kind);
    try std.testing.expectEqualStrings("tag", args.specs[0].field);
    try std.testing.expectEqual(windowmod.WindowKind.sum, args.specs[1].kind);
}

test "table_window args round trip first_value/last_value specs alongside a partition/order/RANGE frame" {
    const allocator = std.testing.allocator;
    const orderBy = [_]querymod.OrderBy{.{ .field = "day" }};
    const partitionBy = [_][]const u8{"city"};
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "amount", .kind = .first_value },
        .{ .field = "amount", .kind = .last_value },
    };
    const payload = try encodeTableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "", .range);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 2), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.first_value, args.specs[0].kind);
    try std.testing.expectEqualStrings("amount", args.specs[0].field);
    try std.testing.expectEqual(windowmod.WindowKind.last_value, args.specs[1].kind);
    try std.testing.expectEqualStrings("amount", args.specs[1].field);
    try std.testing.expectEqual(windowmod.FrameMode.range, args.frame);
}

test "table_window args round trip MULTIPLE specs sharing one partition/order/frame" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "total", .kind = .sum },
        .{ .field = "total", .kind = .avg },
        .{ .field = "", .kind = .rank },
    };
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 3), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.sum, args.specs[0].kind);
    try std.testing.expectEqualStrings("total", args.specs[0].field);
    try std.testing.expectEqual(windowmod.WindowKind.avg, args.specs[1].kind);
    try std.testing.expectEqualStrings("total", args.specs[1].field);
    try std.testing.expectEqual(windowmod.WindowKind.rank, args.specs[2].kind);
    try std.testing.expectEqualStrings("", args.specs[2].field);
}

test "table_window args round trip a nonzero offset and limit" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{.{ .field = "", .kind = .rank }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 2, 5, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(u32, 2), args.offset);
    try std.testing.expectEqual(@as(u32, 5), args.limit);
}

test "table_window args round trip a RANGE frame, and default to ROWS when the byte is 0" {
    const allocator = std.testing.allocator;
    const order = [_]querymod.OrderBy{.{ .field = "day", .descending = false }};
    const specs = [_]windowmod.WindowSpec{.{ .field = "amount", .kind = .sum }};

    const rangePayload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &order, 0, 0, "", .range);
    defer allocator.free(rangePayload);
    const rangeArgs = try decodeTableWindow(allocator, rangePayload);
    defer allocator.free(rangeArgs.specs);
    defer allocator.free(rangeArgs.partitionBy);
    defer allocator.free(rangeArgs.orderBy);
    try std.testing.expectEqual(windowmod.FrameMode.range, rangeArgs.frame);

    const rowsPayload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &order, 0, 0, "", .rows);
    defer allocator.free(rowsPayload);
    const rowsArgs = try decodeTableWindow(allocator, rowsPayload);
    defer allocator.free(rowsArgs.specs);
    defer allocator.free(rowsArgs.partitionBy);
    defer allocator.free(rowsArgs.orderBy);
    try std.testing.expectEqual(windowmod.FrameMode.rows, rowsArgs.frame);
}

test "decodeTableWindow rejects an unknown frame byte instead of silently defaulting to ROWS" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "orders");
    try w.byte(1);
    try w.byte(@intFromEnum(windowmod.WindowKind.sum));
    try putLenPrefixed(w, "total");
    try w.byte(0);
    try w.byte(0);
    try w.putU32(0);
    try w.putU32(0);
    try w.byte(200);

    try std.testing.expectError(error.Malformed, decodeTableWindow(allocator, buf.items));
}

test "table_window args round trip a multi-column partition and multi-column descending order-by" {
    const allocator = std.testing.allocator;
    const partitionBy = [_][]const u8{ "city", "region" };
    const orderBy = [_]querymod.OrderBy{
        .{ .field = "day", .descending = true },
        .{ .field = "amount", .descending = false },
    };
    const specs = [_]windowmod.WindowSpec{.{ .field = "amount", .kind = .max }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &partitionBy, &orderBy, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 2), args.partitionBy.len);
    try std.testing.expectEqualStrings("city", args.partitionBy[0]);
    try std.testing.expectEqualStrings("region", args.partitionBy[1]);
    try std.testing.expectEqual(@as(usize, 2), args.orderBy.len);
    try std.testing.expect(args.orderBy[0].descending);
    try std.testing.expect(!args.orderBy[1].descending);
}

test "decodeTableWindow rejects an unknown window kind byte instead of corrupting a spec" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "orders");
    try w.byte(1);
    try w.byte(200);
    try putLenPrefixed(w, "total");
    try w.byte(0);
    try w.byte(0);
    try w.putU32(0);
    try w.putU32(0);

    try std.testing.expectError(error.Malformed, decodeTableWindow(allocator, buf.items));
}

test "window rows round trip through encode and decode" {
    const allocator = std.testing.allocator;
    var rows = [_]rowmod.Row{ rowmod.Row.init(allocator), rowmod.Row.init(allocator) };
    defer for (&rows) |*r| r.deinit();
    try rows[0].set("city", .{ .text = "warsaw" });
    try rows[1].set("city", .{ .text = "krakow" });

    var values0 = [_]rowmod.Value{.{ .int = 1 }};
    var values1 = [_]rowmod.Value{.{ .int = 2 }};
    const windowRows = [_]WindowRow{
        .{ .row = rows[0], .values = &values0 },
        .{ .row = rows[1], .values = &values1 },
    };
    const payload = try encodeWindowRows(allocator, &windowRows);
    defer allocator.free(payload);

    const decoded = try decodeWindowRows(allocator, payload);
    defer freeWindowRows(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("warsaw", decoded[0].row.get("city").?.text);
    try std.testing.expectEqual(@as(usize, 1), decoded[0].values.len);
    try std.testing.expectEqual(@as(i64, 1), decoded[0].values[0].int);
    try std.testing.expectEqualStrings("krakow", decoded[1].row.get("city").?.text);
    try std.testing.expectEqual(@as(i64, 2), decoded[1].values[0].int);
}

test "window rows round trip MULTIPLE values per row, same order as the request's specs" {
    const allocator = std.testing.allocator;
    var rows = [_]rowmod.Row{rowmod.Row.init(allocator)};
    defer for (&rows) |*r| r.deinit();
    try rows[0].set("city", .{ .text = "warsaw" });

    var values0 = [_]rowmod.Value{ .{ .int = 30 }, .{ .float = 15.0 }, .{ .int = 1 } };
    const windowRows = [_]WindowRow{.{ .row = rows[0], .values = &values0 }};
    const payload = try encodeWindowRows(allocator, &windowRows);
    defer allocator.free(payload);

    const decoded = try decodeWindowRows(allocator, payload);
    defer freeWindowRows(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqual(@as(usize, 3), decoded[0].values.len);
    try std.testing.expectEqual(@as(i64, 30), decoded[0].values[0].int);
    try std.testing.expectEqual(@as(f64, 15.0), decoded[0].values[1].float);
    try std.testing.expectEqual(@as(i64, 1), decoded[0].values[2].int);
}

test "empty window row list round trips" {
    const allocator = std.testing.allocator;
    const payload = try encodeWindowRows(allocator, &[_]WindowRow{});
    defer allocator.free(payload);
    const decoded = try decodeWindowRows(allocator, payload);
    defer freeWindowRows(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "subscribe args round trip a multi-channel list" {
    const allocator = std.testing.allocator;
    const payload = try encodeSubscribe(allocator, &.{ "orders", "alerts" });
    defer allocator.free(payload);

    const args = try decodeSubscribe(allocator, payload);
    defer args.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), args.channels.len);
    try std.testing.expectEqualStrings("orders", args.channels[0]);
    try std.testing.expectEqualStrings("alerts", args.channels[1]);
}

test "subscribe args round trip an empty channel list" {
    const allocator = std.testing.allocator;
    const payload = try encodeSubscribe(allocator, &.{});
    defer allocator.free(payload);

    const args = try decodeSubscribe(allocator, payload);
    defer args.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), args.channels.len);
}

test "decodeSubscribe rejects a truncated channel count" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.Malformed, decodeSubscribe(allocator, &.{ 0, 0 }));
}

test "decodeSubscribe rejects a channel count larger than the payload can hold" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU32(5);
    try std.testing.expectError(error.Malformed, decodeSubscribe(allocator, buf.items));
}

test "subscribe ack round trips a subscriber id and channel count" {
    const allocator = std.testing.allocator;
    const payload = try encodeSubscribeAck(allocator, 42, 3);
    defer allocator.free(payload);
    const ack = try decodeSubscribeAck(payload);
    try std.testing.expectEqual(@as(u64, 42), ack.subscriberId);
    try std.testing.expectEqual(@as(u32, 3), ack.channelCount);
}

test "unsubscribe args round trip a subscriber id and multi-channel list" {
    const allocator = std.testing.allocator;
    const payload = try encodeUnsubscribe(allocator, 7, &.{ "orders", "alerts" });
    defer allocator.free(payload);

    const args = try decodeUnsubscribe(allocator, payload);
    defer args.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), args.subscriberId);
    try std.testing.expectEqual(@as(usize, 2), args.channels.len);
    try std.testing.expectEqualStrings("orders", args.channels[0]);
    try std.testing.expectEqualStrings("alerts", args.channels[1]);
}

test "unsubscribe args round trip an empty channel list" {
    const allocator = std.testing.allocator;
    const payload = try encodeUnsubscribe(allocator, 1, &.{});
    defer allocator.free(payload);

    const args = try decodeUnsubscribe(allocator, payload);
    defer args.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), args.channels.len);
}

test "decodeUnsubscribe rejects a truncated channel count" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.Malformed, decodeUnsubscribe(allocator, &.{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 }));
}

test "decodeUnsubscribe rejects a channel count larger than the payload can hold" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try w.putU64(1);
    try w.putU32(5);
    try std.testing.expectError(error.Malformed, decodeUnsubscribe(allocator, buf.items));
}

test "unsubscribe result round trips a removed count, including zero" {
    const allocator = std.testing.allocator;
    const zero = try encodeUnsubscribeResult(allocator, 0);
    defer allocator.free(zero);
    try std.testing.expectEqual(@as(u32, 0), try decodeUnsubscribeResult(zero));

    const some = try encodeUnsubscribeResult(allocator, 2);
    defer allocator.free(some);
    try std.testing.expectEqual(@as(u32, 2), try decodeUnsubscribeResult(some));
}

test "publish args round trip a channel and a binary-safe message" {
    const allocator = std.testing.allocator;
    const message = [_]u8{ 0, 1, 2, 0, 255 };
    const payload = try encodePublish(allocator, "orders", &message);
    defer allocator.free(payload);

    const args = try decodePublish(payload);
    try std.testing.expectEqualStrings("orders", args.channel);
    try std.testing.expectEqualSlices(u8, &message, args.message);
}

test "publish result round trips a subscriber count, including zero" {
    const allocator = std.testing.allocator;
    const payload = try encodePublishResult(allocator, 0);
    defer allocator.free(payload);
    try std.testing.expectEqual(@as(u64, 0), try decodePublishResult(payload));

    const payload2 = try encodePublishResult(allocator, 7);
    defer allocator.free(payload2);
    try std.testing.expectEqual(@as(u64, 7), try decodePublishResult(payload2));
}

test "pubsub message round trips channel and payload as independent owned copies" {
    const allocator = std.testing.allocator;
    const payload = try encodePubSubMessage(allocator, "alerts", "disk full");
    defer allocator.free(payload);

    const decoded = try decodePubSubMessage(allocator, payload);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("alerts", decoded.channel);
    try std.testing.expectEqualStrings("disk full", decoded.payload);
}

test "pubsub message round trips an empty payload" {
    const allocator = std.testing.allocator;
    const payload = try encodePubSubMessage(allocator, "ch", "");
    defer allocator.free(payload);

    const decoded = try decodePubSubMessage(allocator, payload);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("ch", decoded.channel);
    try std.testing.expectEqual(@as(usize, 0), decoded.payload.len);
}

test "table_window args round trip a lag spec with a nonzero offset and an int default" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{.{ .field = "amount", .kind = .lag, .offset = 3, .default = .{ .int = -1 } }};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &order, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 1), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.lag, args.specs[0].kind);
    try std.testing.expectEqualStrings("amount", args.specs[0].field);
    try std.testing.expectEqual(@as(u64, 3), args.specs[0].offset);
    try std.testing.expectEqual(@as(i64, -1), args.specs[0].default.int);
}

test "table_window args round trip a lead spec with its default text and default offset of 1" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{.{ .field = "status", .kind = .lead, .default = .{ .text = "none-yet" } }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(windowmod.WindowKind.lead, args.specs[0].kind);
    try std.testing.expectEqual(@as(u64, 1), args.specs[0].offset);
    try std.testing.expectEqualStrings("none-yet", args.specs[0].default.text);
}

test "table_window args round trip lag/lead alongside a plain sum spec in the same request" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "amount", .kind = .sum },
        .{ .field = "amount", .kind = .lag, .offset = 2 },
        .{ .field = "amount", .kind = .lead },
    };
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 3), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.sum, args.specs[0].kind);
    try std.testing.expectEqual(windowmod.WindowKind.lag, args.specs[1].kind);
    try std.testing.expectEqual(@as(u64, 2), args.specs[1].offset);
    try std.testing.expectEqual(windowmod.WindowKind.lead, args.specs[2].kind);
    try std.testing.expectEqual(@as(u64, 1), args.specs[2].offset);
}

test "table_window args round trip an nth_value spec with its position and a custom default" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{.{ .field = "amount", .kind = .nth_value, .offset = 2, .default = .{ .int = -1 } }};
    const order = [_]querymod.OrderBy{.{ .field = "day" }};
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &order, 0, 0, "", .range);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 1), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.nth_value, args.specs[0].kind);
    try std.testing.expectEqualStrings("amount", args.specs[0].field);
    try std.testing.expectEqual(@as(u64, 2), args.specs[0].offset);
    try std.testing.expectEqual(@as(i64, -1), args.specs[0].default.int);
}

test "table_window args round trip nth_value alongside lag/lead/sum in the same request" {
    const allocator = std.testing.allocator;
    const specs = [_]windowmod.WindowSpec{
        .{ .field = "amount", .kind = .sum },
        .{ .field = "amount", .kind = .nth_value, .offset = 3 },
        .{ .field = "amount", .kind = .lag },
    };
    const payload = try encodeTableWindow(allocator, "orders", &specs, &.{}, &.{}, 0, 0, "", .rows);
    defer allocator.free(payload);
    const args = try decodeTableWindow(allocator, payload);
    defer allocator.free(args.specs);
    defer allocator.free(args.partitionBy);
    defer allocator.free(args.orderBy);

    try std.testing.expectEqual(@as(usize, 3), args.specs.len);
    try std.testing.expectEqual(windowmod.WindowKind.sum, args.specs[0].kind);
    try std.testing.expectEqual(windowmod.WindowKind.nth_value, args.specs[1].kind);
    try std.testing.expectEqual(@as(u64, 3), args.specs[1].offset);
    try std.testing.expectEqual(windowmod.WindowKind.lag, args.specs[2].kind);
}

test "decodeTableWindow rejects a truncated nth_value default value instead of misreading trailing bytes" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "orders");
    try w.byte(1);
    try w.byte(@intFromEnum(windowmod.WindowKind.nth_value));
    try putLenPrefixed(w, "amount");
    try w.putU64(2);
    try w.byte(@intFromEnum(rowmod.ValueTag.int));

    try std.testing.expectError(error.Malformed, decodeTableWindow(allocator, buf.items));
}

test "decodeTableWindow rejects a truncated lag/lead default value instead of misreading trailing bytes" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = encode.ByteWriter.init(&buf);
    try putLenPrefixed(w, "orders");
    try w.byte(1);
    try w.byte(@intFromEnum(windowmod.WindowKind.lag));
    try putLenPrefixed(w, "amount");
    try w.putU64(1);
    try w.byte(@intFromEnum(rowmod.ValueTag.text));

    try std.testing.expectError(error.Malformed, decodeTableWindow(allocator, buf.items));
}
