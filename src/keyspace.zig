const std = @import("std");
const auth = @import("auth.zig");
const index = @import("index.zig");
const collections = @import("collections.zig");
const collttl = @import("collttl.zig");
const ttl = @import("ttl.zig");

/// Single source of truth for every top-level byte tag a module uses to
/// namespace its own keys in the flat `Db` keyspace (auth.zig/index.zig/
/// collections.zig/collttl.zig/ttl.zig each own one plain byte as the
/// first byte of every key they write, and rely on every OTHER module
/// picking a different one - the entire scheme is "gentleman's agreement
/// by comment" with nothing that actually enforces it).
///
/// Session #29 hit the failure mode this closes: collttl.zig originally
/// reused ttl.zig's tag 'T' (only byte-disjoint via an extra marker byte,
/// not prefix-disjoint), so ttl.zig's `sweepExpired` prefix-scan over "T"
/// silently matched collttl.zig's markers too, corrupting sweep counts and
/// leaving collections un-swept. It was caught by a flaky-looking test
/// failure, not by anything structural - nothing stopped a *third* module
/// from making the same mistake tomorrow.
///
/// Each entry below points at the module's own `pub const ...Tag`
/// definition instead of retyping the byte, so this list is derived FROM
/// the real definitions and cannot silently drift out of sync with them.
/// `assertAllDistinct` runs at comptime (see the `comptime` block below,
/// pulled in transitively by every build via root.zig) - a future module
/// that picks an already-taken byte fails the BUILD, not a test someone
/// has to remember to write.
pub const Entry = struct { owner: []const u8, tag: u8 };

pub const registry = [_]Entry{
    .{ .owner = "auth", .tag = auth.nsTag },
    .{ .owner = "index.row", .tag = index.rowTag },
    .{ .owner = "index.index", .tag = index.indexTag },
    .{ .owner = "index.compositeIndex", .tag = index.compositeIndexTag },
    .{ .owner = "index.meta", .tag = index.metaTag },
    .{ .owner = "collections", .tag = collections.nsTag },
    .{ .owner = "collttl", .tag = collttl.nsTag },
    .{ .owner = "ttl", .tag = ttl.nsTag },
};

fn assertAllDistinct() void {
    @setEvalBranchQuota(10_000);
    for (registry, 0..) |a, i| {
        for (registry[i + 1 ..]) |b| {
            if (a.tag == b.tag) {
                @compileError("keyspace tag collision: '" ++ &[_]u8{a.tag} ++ "' claimed by both '" ++ a.owner ++ "' and '" ++ b.owner ++ "' - pick a different top-level byte for one of them");
            }
        }
    }
}

comptime {
    assertAllDistinct();
}

/// `true` iff no other registered owner already claims `tag` - the check a
/// brand new module should run against its OWN candidate byte before
/// wiring it into `registry` above, so the collision surfaces while
/// picking the byte instead of after writing a whole module around it.
pub fn isFree(tag: u8) bool {
    for (registry) |e| {
        if (e.tag == tag) return false;
    }
    return true;
}

test "registry has no duplicate top-level tags (runtime mirror of the comptime check)" {
    for (registry, 0..) |a, i| {
        for (registry[i + 1 ..]) |b| {
            try std.testing.expect(a.tag != b.tag);
        }
    }
}

test "registry pins the exact set of tags currently in use" {
    var seen = std.AutoHashMap(u8, void).init(std.testing.allocator);
    defer seen.deinit();
    for (registry) |e| try seen.put(e.tag, {});
    // A change here (tag added, removed, or reassigned) must be a
    // deliberate edit to this file's `registry` literal, not something
    // that happened to fall out of touching an unrelated module.
    try std.testing.expectEqual(@as(usize, 8), seen.count());
    inline for (.{ 'A', 'R', 'I', 'J', 'M', 'X', 'Y', 'T' }) |expected| {
        try std.testing.expect(seen.contains(expected));
    }
}

test "isFree reports the registered tags as taken and an unused byte as free" {
    try std.testing.expect(!isFree('A'));
    try std.testing.expect(!isFree('T'));
    try std.testing.expect(!isFree('Y'));
    try std.testing.expect(isFree('Z'));
    try std.testing.expect(isFree(0));
}
