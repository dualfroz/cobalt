const std = @import("std");
const authmod = @import("auth.zig");

const Allocator = std.mem.Allocator;

/// Random session tokens with expiration, independent of any one TCP
/// connection - the layer that replaces "authenticated for as long as this
/// socket stays open" (server.zig's `connRole`) with "authenticated until
/// this token expires or is revoked". A client that authenticates once,
/// gets a token back, and disconnects can reconnect later and resume the
/// same role by presenting the token (`auth_token` opcode in protocol.zig)
/// instead of the password again - and the token stops working on its own
/// after its TTL elapses even if the same connection stays open the whole
/// time, unlike plain password auth which never expires mid-connection.
pub const tokenBytes = 24;
pub const tokenHexLen = tokenBytes * 2;

fn generateTokenHex() [tokenHexLen]u8 {
    var raw: [tokenBytes]u8 = undefined;
    std.crypto.random.bytes(&raw);
    return std.fmt.bytesToHex(raw, .lower);
}

pub const Session = struct {
    role: authmod.Role,
    expiresAtNanos: i128,
};

/// In-memory only (never persisted to Db - a session is a login artifact,
/// not application data): thread-safe via its own mutex since `server.zig`
/// dispatches requests from one worker thread per connection and any of
/// them may issue, validate, or revoke a token concurrently.
pub const SessionStore = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    sessions: std.StringHashMapUnmanaged(Session) = .{},

    pub fn init(allocator: Allocator) SessionStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SessionStore) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.sessions.deinit(self.allocator);
    }

    /// Issues a fresh random token bound to `role`, valid until
    /// `nowNanos + ttlNanos`. Caller owns the returned slice.
    pub fn issue(self: *SessionStore, role: authmod.Role, ttlNanos: i128, nowNanos: i128) ![]u8 {
        const hex = generateTokenHex();
        const keyOwned = try self.allocator.dupe(u8, &hex);
        errdefer self.allocator.free(keyOwned);
        const returned = try self.allocator.dupe(u8, &hex);
        errdefer self.allocator.free(returned);

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sessions.put(self.allocator, keyOwned, .{ .role = role, .expiresAtNanos = nowNanos + ttlNanos });
        return returned;
    }

    /// Returns the session bound to `token` (role and expiry) if it exists
    /// and has not expired as of `nowNanos`. An expired session is deleted
    /// right here (lazy cleanup) rather than left around for
    /// `sweepExpired` to eventually find - a token that has expired must
    /// never again validate as live, so the deletion happens on the same
    /// lookup that discovers it. Returning the expiry (not just the role)
    /// lets a caller such as `server.zig` re-check the same session later
    /// against a fresh clock without a second store lookup.
    pub fn validate(self: *SessionStore, token: []const u8, nowNanos: i128) ?Session {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.sessions.getEntry(token) orelse return null;
        if (entry.value_ptr.expiresAtNanos <= nowNanos) {
            const key = entry.key_ptr.*;
            _ = self.sessions.remove(token);
            self.allocator.free(key);
            return null;
        }
        return entry.value_ptr.*;
    }

    /// Explicit logout: removes a token before it would naturally expire.
    /// Returns whether a session was actually present.
    pub fn revoke(self: *SessionStore, token: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const kv = self.sessions.fetchRemove(token) orelse return false;
        self.allocator.free(kv.key);
        return true;
    }

    /// Removes every session expired as of `nowNanos`, returning how many
    /// were dropped. `validate` already deletes an expired session the
    /// moment someone tries to use it, but a token nobody ever presents
    /// again would otherwise sit in memory forever - this is the
    /// housekeeping sweep a long-lived server can run periodically.
    pub fn sweepExpired(self: *SessionStore, nowNanos: i128) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var doomed = std.ArrayList([]const u8).init(self.allocator);
        defer doomed.deinit();
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expiresAtNanos <= nowNanos) {
                doomed.append(entry.key_ptr.*) catch continue;
            }
        }
        for (doomed.items) |key| {
            _ = self.sessions.remove(key);
            self.allocator.free(key);
        }
        return doomed.items.len;
    }

    pub fn count(self: *SessionStore) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }
};

test "issue then validate returns the bound role before expiry" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();

    const token = try store.issue(.readwrite, 1_000_000_000, 0);
    defer std.testing.allocator.free(token);

    try std.testing.expectEqual(@as(usize, tokenHexLen), token.len);
    try std.testing.expectEqual(authmod.Role.readwrite, store.validate(token, 500_000_000).?.role);
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "validate returns null once past expiry and removes the session" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();

    const token = try store.issue(.admin, 1_000, 0);
    defer std.testing.allocator.free(token);

    try std.testing.expect(store.validate(token, 1_000) == null);
    try std.testing.expectEqual(@as(usize, 0), store.count());
    // A second lookup of the same (already-removed) token still misses cleanly.
    try std.testing.expect(store.validate(token, 1_000) == null);
}

test "unknown token never validates" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expect(store.validate("does-not-exist", 0) == null);
}

test "revoke removes a session before its natural expiry" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();

    const token = try store.issue(.readonly, 1_000_000_000, 0);
    defer std.testing.allocator.free(token);

    try std.testing.expect(store.revoke(token));
    try std.testing.expect(store.validate(token, 0) == null);
    // Revoking an already-gone token is a clean no-op, not an error.
    try std.testing.expect(!store.revoke(token));
}

test "two tokens for different roles are independent" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();

    const a = try store.issue(.readonly, 1_000_000_000, 0);
    defer std.testing.allocator.free(a);
    const b = try store.issue(.admin, 1_000_000_000, 0);
    defer std.testing.allocator.free(b);

    try std.testing.expect(!std.mem.eql(u8, a, b));
    try std.testing.expectEqual(authmod.Role.readonly, store.validate(a, 0).?.role);
    try std.testing.expectEqual(authmod.Role.admin, store.validate(b, 0).?.role);

    try std.testing.expect(store.revoke(a));
    try std.testing.expect(store.validate(a, 0) == null);
    // Revoking `a` must never touch `b`'s still-live session.
    try std.testing.expectEqual(authmod.Role.admin, store.validate(b, 0).?.role);
}

test "sweepExpired drops only expired sessions and reports the count" {
    var store = SessionStore.init(std.testing.allocator);
    defer store.deinit();

    const stale1 = try store.issue(.readonly, 100, 0);
    defer std.testing.allocator.free(stale1);
    const stale2 = try store.issue(.readwrite, 100, 0);
    defer std.testing.allocator.free(stale2);
    const fresh = try store.issue(.admin, 1_000_000_000, 0);
    defer std.testing.allocator.free(fresh);

    try std.testing.expectEqual(@as(usize, 3), store.count());
    try std.testing.expectEqual(@as(usize, 2), store.sweepExpired(200));
    try std.testing.expectEqual(@as(usize, 1), store.count());
    try std.testing.expectEqual(authmod.Role.admin, store.validate(fresh, 200).?.role);

    // A second sweep at the same time has nothing left to remove.
    try std.testing.expectEqual(@as(usize, 0), store.sweepExpired(200));
}

test "generateTokenHex produces distinct, fully hex-encoded tokens" {
    const a = generateTokenHex();
    const b = generateTokenHex();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    for (a) |c| try std.testing.expect(std.ascii.isHex(c));
}
