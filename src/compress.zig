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
