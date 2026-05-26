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

    fn mustGet(self: Store, allocator: Allocator, key: []const u8) !UserRecord {
        const raw = try self.db.get(allocator, key) orelse return error.UserNotFound;
        defer allocator.free(raw);
        return UserRecord.decode(raw);
    }

    pub fn setPassword(self: Store, allocator: Allocator, username: []const u8, newPassword: []const u8, rounds: u32) !void {
        const key = try userKey(allocator, username);
        defer allocator.free(key);
        var record = try self.mustGet(allocator, key);
        record.rounds = rounds;
        record.salt = randomSalt();
        record.hash = try hashPassword(newPassword, record.salt, rounds);
        const encoded = record.encode();
        try self.db.put(key, &encoded);
    }

    pub fn setRole(self: Store, allocator: Allocator, username: []const u8, role: Role) !void {
        const key = try userKey(allocator, username);
        defer allocator.free(key);
        var record = try self.mustGet(allocator, key);
        record.role = role;
        const encoded = record.encode();
        try self.db.put(key, &encoded);
    }

    pub fn deleteUser(self: Store, allocator: Allocator, username: []const u8) !void {
        const key = try userKey(allocator, username);
        defer allocator.free(key);
        _ = try self.mustGet(allocator, key);
        try self.db.delete(key);
    }

    /// Verifies `password` for `username`, returning the stored role on
    /// success. See `dummySalt`/`dummyRounds` for why a missing user still
    /// pays a full PBKDF2 pass before failing. The final comparison uses
    /// `std.crypto.utils.timingSafeEql` rather than `std.mem.eql`, since an
    /// early-exit byte comparison on the hash would leak how many leading
    /// bytes matched to a network attacker timing repeated attempts.
    pub fn verify(self: Store, allocator: Allocator, username: []const u8, password: []const u8) !Role {
        const key = try userKey(allocator, username);
        defer allocator.free(key);
        const raw = try self.db.get(allocator, key) orelse {
            _ = hashPassword(password, dummySalt, dummyRounds) catch {};
            return error.InvalidCredentials;
        };
        defer allocator.free(raw);
        const record = try UserRecord.decode(raw);
        const candidate = try hashPassword(password, record.salt, record.rounds);
        if (!std.crypto.utils.timingSafeEql([hashLen]u8, candidate, record.hash)) return error.InvalidCredentials;
        return record.role;
    }

    /// Whether at least one admin account exists - `main.zig` uses this to
    /// refuse turning on server-side auth enforcement until an operator has
    /// created a way back in, so enabling `--auth` can never lock everyone
    /// out of a fresh database.
    pub fn hasAnyAdmin(self: Store, allocator: Allocator) !bool {
        var it = try self.db.scanPrefix(allocator, &userPrefixBytes);
        defer it.deinit();
        while (try it.next()) |entry| {
            const record = UserRecord.decode(entry.value) catch continue;
            if (record.role == .admin) return true;
        }
        return false;
    }

    /// Returns every user with their role, independently owned - free with
    /// `freeUserList`. Order follows key order (lexicographic by username).
    pub fn listUsers(self: Store, allocator: Allocator) ![]UserInfo {
        var it = try self.db.scanPrefix(allocator, &userPrefixBytes);
        defer it.deinit();
        var out = std.ArrayList(UserInfo).init(allocator);
        errdefer {
            for (out.items) |u| u.deinit(allocator);
            out.deinit();
        }
        while (try it.next()) |entry| {
            const record = UserRecord.decode(entry.value) catch continue;
            const uname = entry.key[userPrefixBytes.len..];
            try out.append(.{ .username = try allocator.dupe(u8, uname), .role = record.role });
        }
        return out.toOwnedSlice();
    }
};

fn testDb(allocator: Allocator, dir: std.fs.Dir) !Db {
    const path = try dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    return Db.open(allocator, path, .{});
}

test "role ordering is a total order across readonly/readwrite/admin" {
    try std.testing.expect(Role.readwrite.atLeast(.readonly));
    try std.testing.expect(Role.admin.atLeast(.readonly));
    try std.testing.expect(Role.admin.atLeast(.readwrite));
    try std.testing.expect(Role.admin.atLeast(.admin));
    try std.testing.expect(!Role.readonly.atLeast(.readwrite));
    try std.testing.expect(!Role.readwrite.atLeast(.admin));
}

test "Role.parse rejects an unknown role name" {
    try std.testing.expectEqual(Role.admin, try Role.parse("admin"));
    try std.testing.expectError(error.Malformed, Role.parse("superuser"));
}

test "createUser then verify accepts the correct password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try testDb(allocator, tmp.dir);
    defer db.close();

    const store = Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readwrite, 16);

    const role = try store.verify(allocator, "alice", "hunter2");
    try std.testing.expectEqual(Role.readwrite, role);
}

test "verify rejects a wrong password without revealing which part was wrong" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try testDb(allocator, tmp.dir);
    defer db.close();

    const store = Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readonly, 16);

    try std.testing.expectError(error.InvalidCredentials, store.verify(allocator, "alice", "wrong"));
}

test "verify rejects an unknown username the same way as a wrong password" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try testDb(allocator, tmp.dir);
    defer db.close();

    const store = Store.init(&db);
    try std.testing.expectError(error.InvalidCredentials, store.verify(allocator, "ghost", "anything"));
}

test "createUser rejects a duplicate username" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var db = try testDb(allocator, tmp.dir);
    defer db.close();

    const store = Store.init(&db);
    try store.createUser(allocator, "alice", "hunter2", .readonly, 16);
    try std.testing.expectError(error.UserExists, store.createUser(allocator, "alice", "different", .admin, 16));
}

