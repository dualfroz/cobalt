const std = @import("std");
const dbmod = @import("db.zig");

const Allocator = std.mem.Allocator;
const Db = dbmod.Db;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Username/password authentication and coarse-grained role authorization,
/// layered over the same Db as tables/indexes/collections under its own
/// namespace tag 'A' (row.zig/index.zig use 'R'/'I'/'M', collections.zig
/// uses 'X', so no keyspace ever collides):
///   "A" "U\0" username -> UserRecord{role, rounds, salt[16], hash[32]}
/// Passwords are never stored: only a per-user salted PBKDF2-HMAC-SHA256
/// hash, using `std.crypto.pwhash.pbkdf2` - the same primitive the standard
/// library itself ships for exactly this purpose, not a hand-rolled one.
pub const nsTag: u8 = 'A';
const userPrefixBytes = [_]u8{ nsTag, 'U', 0 };
const saltLen = 16;
const hashLen = 32;
const recordLen = 1 + 4 + saltLen + hashLen;

pub const AuthError = error{
    UserNotFound,
    UserExists,
    InvalidCredentials,
    Malformed,
};

/// Roles form a total order, not a set of independent flags: readwrite
/// implies readonly, admin implies both. `atLeast` is the only check any
/// caller (server.zig's dispatch) ever needs.
pub const Role = enum(u8) {
    readonly = 0,
    readwrite = 1,
    admin = 2,

    pub fn fromByte(b: u8) !Role {
        return std.meta.intToEnum(Role, b) catch error.Malformed;
    }

    pub fn parse(text: []const u8) !Role {
        if (std.mem.eql(u8, text, "readonly")) return .readonly;
        if (std.mem.eql(u8, text, "readwrite")) return .readwrite;
        if (std.mem.eql(u8, text, "admin")) return .admin;
        return error.Malformed;
    }

    pub fn name(self: Role) []const u8 {
        return switch (self) {
            .readonly => "readonly",
            .readwrite => "readwrite",
            .admin => "admin",
        };
    }

    pub fn atLeast(self: Role, min: Role) bool {
        return @intFromEnum(self) >= @intFromEnum(min);
    }
};

/// Recommended real-world cost factor for interactive login (OWASP's floor
/// for PBKDF2-HMAC-SHA256 as of 2023). A constant rather than a value
/// baked into `hashPassword` so tests can pass a tiny round count and stay
/// fast, while `main.zig` and any other real caller default to this.
pub const recommendedRounds: u32 = 100_000;

fn userKey(allocator: Allocator, username: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, userPrefixBytes.len + username.len);
    @memcpy(out[0..userPrefixBytes.len], &userPrefixBytes);
    @memcpy(out[userPrefixBytes.len..], username);
    return out;
}

const UserRecord = struct {
    role: Role,
    rounds: u32,
    salt: [saltLen]u8,
    hash: [hashLen]u8,

    fn encode(self: UserRecord) [recordLen]u8 {
        var out: [recordLen]u8 = undefined;
        out[0] = @intFromEnum(self.role);
        std.mem.writeInt(u32, out[1..5], self.rounds, .little);
        @memcpy(out[5 .. 5 + saltLen], &self.salt);
        @memcpy(out[5 + saltLen .. recordLen], &self.hash);
        return out;
    }

    fn decode(data: []const u8) !UserRecord {
        if (data.len != recordLen) return error.Malformed;
        var rec: UserRecord = undefined;
        rec.role = try Role.fromByte(data[0]);
        rec.rounds = std.mem.readInt(u32, data[1..5], .little);
        @memcpy(&rec.salt, data[5 .. 5 + saltLen]);
        @memcpy(&rec.hash, data[5 + saltLen .. recordLen]);
        return rec;
    }
};

fn randomSalt() [saltLen]u8 {
    var salt: [saltLen]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

fn hashPassword(password: []const u8, salt: [saltLen]u8, rounds: u32) ![hashLen]u8 {
    var out: [hashLen]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&out, password, &salt, rounds, Hmac256);
    return out;
}

/// Fixed salt/rounds used to cost a lookup against a username that does not
/// exist, so `verify` spends roughly the same CPU whether the account is
/// missing or the password was merely wrong - closing the most obvious
/// timing side channel for username enumeration over the network (the
/// key comparison itself still only runs on the "user exists" path, since
/// there is nothing real to compare against otherwise).
const dummySalt = [_]u8{0} ** saltLen;
const dummyRounds: u32 = 4096;

pub const UserInfo = struct {
    username: []u8,
    role: Role,

    pub fn deinit(self: UserInfo, allocator: Allocator) void {
        allocator.free(self.username);
    }
};

pub fn freeUserList(allocator: Allocator, users: []UserInfo) void {
    for (users) |u| u.deinit(allocator);
    allocator.free(users);
}

/// Username/password/role management layered over a `*Db`. Every method
/// touches only keys under `userPrefixBytes`; unrelated data in the same
/// Db (tables, collections, raw KV) is never read or written. Not
/// synchronized on its own, same as every other module built over Db -
/// server.zig serializes access with its own connection-handling mutex.
pub const Store = struct {
    db: *Db,

    pub fn init(db: *Db) Store {
        return .{ .db = db };
    }

    pub fn createUser(self: Store, allocator: Allocator, username: []const u8, password: []const u8, role: Role, rounds: u32) !void {
        const key = try userKey(allocator, username);
        defer allocator.free(key);
        if (try self.db.get(allocator, key)) |existing| {
            allocator.free(existing);
            return error.UserExists;
        }
        const salt = randomSalt();
        const record = UserRecord{
            .role = role,
            .rounds = rounds,
            .salt = salt,
            .hash = try hashPassword(password, salt, rounds),
        };
        const encoded = record.encode();
        try self.db.put(key, &encoded);
    }

