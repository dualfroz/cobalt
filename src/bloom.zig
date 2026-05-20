const std = @import("std");
const encode = @import("encode.zig");

const Allocator = std.mem.Allocator;

pub const Bloom = struct {
    allocator: Allocator,
    bits: []u8,
    bitCount: u64,
    hashCount: u32,

    pub fn init(allocator: Allocator, expectedKeys: usize, falsePositive: f64) !Bloom {
        const n: f64 = @floatFromInt(@max(expectedKeys, 1));
        const ln2 = @log(@as(f64, 2.0));
        const m = @ceil(-(n * @log(falsePositive)) / (ln2 * ln2));
        var bitCount: u64 = @intFromFloat(m);
        if (bitCount < 64) bitCount = 64;
        var hashCount: u32 = @intFromFloat(@round((m / n) * ln2));
        if (hashCount < 1) hashCount = 1;
        if (hashCount > 16) hashCount = 16;

        const byteLen: usize = @intCast((bitCount + 7) / 8);
        const bits = try allocator.alloc(u8, byteLen);
        @memset(bits, 0);
        return .{
            .allocator = allocator,
            .bits = bits,
            .bitCount = bitCount,
            .hashCount = hashCount,
        };
    }

    pub fn deinit(self: *Bloom) void {
        self.allocator.free(self.bits);
    }

    pub fn add(self: *Bloom, key: []const u8) void {
        const h1 = std.hash.Wyhash.hash(0x9e3779b97f4a7c15, key);
        const h2 = std.hash.Wyhash.hash(0xc2b2ae3d27d4eb4f, key);
        var i: u32 = 0;
        while (i < self.hashCount) : (i += 1) {
            const combined = h1 +% (@as(u64, i) *% h2);
            const bit = combined % self.bitCount;
            self.bits[@intCast(bit / 8)] |= @as(u8, 1) << @intCast(bit % 8);
        }
    }

    pub fn mayContain(self: *const Bloom, key: []const u8) bool {
        const h1 = std.hash.Wyhash.hash(0x9e3779b97f4a7c15, key);
        const h2 = std.hash.Wyhash.hash(0xc2b2ae3d27d4eb4f, key);
        var i: u32 = 0;
        while (i < self.hashCount) : (i += 1) {
            const combined = h1 +% (@as(u64, i) *% h2);
            const bit = combined % self.bitCount;
            const set = (self.bits[@intCast(bit / 8)] >> @intCast(bit % 8)) & 1;
            if (set == 0) return false;
        }
        return true;
    }

    pub fn serialize(self: *const Bloom, writer: encode.ByteWriter) !void {
        try writer.putU32(self.hashCount);
        try writer.putU64(self.bitCount);
        try writer.slice(self.bits);
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Bloom {
        const hashCount = encode.readU32(data, 0);
        const bitCount = encode.readU64(data, 4);
        const bits = try allocator.dupe(u8, data[12..]);
        return .{
            .allocator = allocator,
            .bits = bits,
            .bitCount = bitCount,
            .hashCount = hashCount,
        };
    }
};
