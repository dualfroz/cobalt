const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Codec = enum(u8) {
    none = 0,
    rle = 1,
};

const maxRun = 130;
const maxLiteral = 128;

pub fn rleCompress(allocator: Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < input.len) {
        var runLen: usize = 1;
        while (i + runLen < input.len and input[i + runLen] == input[i] and runLen < maxRun) : (runLen += 1) {}

        if (runLen >= 3) {
            try out.append(0x80 | @as(u8, @intCast(runLen - 3)));
            try out.append(input[i]);
            i += runLen;
            continue;
        }

        const litStart = i;
        var litLen: usize = 0;
        while (i < input.len and litLen < maxLiteral) {
            var ahead: usize = 1;
            while (i + ahead < input.len and input[i + ahead] == input[i] and ahead < 3) : (ahead += 1) {}
            if (ahead >= 3) break;
            i += 1;
            litLen += 1;
        }
        try out.append(@as(u8, @intCast(litLen - 1)));
        try out.appendSlice(input[litStart .. litStart + litLen]);
    }

    return out.toOwnedSlice();
}

pub fn rleDecompress(allocator: Allocator, input: []const u8, expectedLen: usize) ![]u8 {
    var out = try allocator.alloc(u8, expectedLen);
    errdefer allocator.free(out);

    var written: usize = 0;
    var i: usize = 0;
    while (i < input.len) {
        const control = input[i];
        i += 1;
        if (control & 0x80 != 0) {
            const runLen: usize = @as(usize, control & 0x7f) + 3;
            if (i >= input.len) return error.CorruptBlock;
            const byte = input[i];
            i += 1;
            if (written + runLen > expectedLen) return error.CorruptBlock;
            @memset(out[written .. written + runLen], byte);
            written += runLen;
        } else {
            const litLen: usize = @as(usize, control) + 1;
            if (i + litLen > input.len) return error.CorruptBlock;
            if (written + litLen > expectedLen) return error.CorruptBlock;
            @memcpy(out[written .. written + litLen], input[i .. i + litLen]);
            written += litLen;
            i += litLen;
        }
    }
    if (written != expectedLen) return error.CorruptBlock;
    return out;
}

pub const Encoded = struct {
    codec: Codec,
    bytes: []u8,

    pub fn deinit(self: Encoded, allocator: Allocator) void {
        allocator.free(self.bytes);
    }
};

pub fn encode(allocator: Allocator, input: []const u8) !Encoded {
    const compressed = try rleCompress(allocator, input);
    if (compressed.len < input.len) {
        return .{ .codec = .rle, .bytes = compressed };
    }
    allocator.free(compressed);
    return .{ .codec = .none, .bytes = try allocator.dupe(u8, input) };
}

pub fn decode(allocator: Allocator, codec: Codec, payload: []const u8, originalLen: usize) ![]u8 {
    return switch (codec) {
        .none => allocator.dupe(u8, payload),
        .rle => rleDecompress(allocator, payload, originalLen),
    };
}

fn expectRoundtrip(allocator: Allocator, input: []const u8) !void {
    const compressed = try rleCompress(allocator, input);
    defer allocator.free(compressed);
    const restored = try rleDecompress(allocator, compressed, input.len);
    defer allocator.free(restored);
    try std.testing.expectEqualSlices(u8, input, restored);
}

test "rle roundtrip on runs literals and mixed" {
    const allocator = std.testing.allocator;
    try expectRoundtrip(allocator, "");
    try expectRoundtrip(allocator, "a");
    try expectRoundtrip(allocator, "aaaaaaaaaa");
    try expectRoundtrip(allocator, "abcdefghij");
    try expectRoundtrip(allocator, "aaabbbcccdddeeefff");
    try expectRoundtrip(allocator, "aaaaaXbbbbbYcccccZ");
    try expectRoundtrip(allocator, &[_]u8{0} ** 300);
    try expectRoundtrip(allocator, &[_]u8{0xff} ** 300);
}

test "rle roundtrip on random data" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1234abcd);
    const random = prng.random();
    var buf: [4096]u8 = undefined;
    var trial: usize = 0;
    while (trial < 40) : (trial += 1) {
        const len = random.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*byte| byte.* = random.intRangeAtMost(u8, 0, 5);
        try expectRoundtrip(allocator, buf[0..len]);
    }
}

test "rle compresses repetitive payload" {
    const allocator = std.testing.allocator;
    const payload = "x" ** 1000;
    const compressed = try rleCompress(allocator, payload);
    defer allocator.free(compressed);
    try std.testing.expect(compressed.len < payload.len / 10);
}

test "encode picks smaller representation" {
    const allocator = std.testing.allocator;

    const compressible = "y" ** 500;
    const enc1 = try encode(allocator, compressible);
    defer enc1.deinit(allocator);
    try std.testing.expectEqual(Codec.rle, enc1.codec);
    const back1 = try decode(allocator, enc1.codec, enc1.bytes, compressible.len);
    defer allocator.free(back1);
    try std.testing.expectEqualSlices(u8, compressible, back1);

    var incompressible: [256]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xfeed);
    prng.random().bytes(&incompressible);
    const enc2 = try encode(allocator, &incompressible);
    defer enc2.deinit(allocator);
    try std.testing.expectEqual(Codec.none, enc2.codec);
    const back2 = try decode(allocator, enc2.codec, enc2.bytes, incompressible.len);
    defer allocator.free(back2);
    try std.testing.expectEqualSlices(u8, &incompressible, back2);
}

test "decompress rejects truncated stream" {
    const allocator = std.testing.allocator;
    const payload = "z" ** 200;
    const compressed = try rleCompress(allocator, payload);
    defer allocator.free(compressed);
    try std.testing.expectError(error.CorruptBlock, rleDecompress(allocator, compressed[0 .. compressed.len - 1], payload.len));
}
