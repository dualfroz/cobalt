const std = @import("std");

pub const endian = std.builtin.Endian.little;

pub const Kind = enum(u8) {
    value = 0,
    tombstone = 1,
};

pub const Record = struct {
    key: []const u8,
    value: []const u8,
    seq: u64,
    kind: Kind,
};

pub const ByteWriter = struct {
    buf: *std.ArrayList(u8),

    pub fn init(buf: *std.ArrayList(u8)) ByteWriter {
        return .{ .buf = buf };
    }

    pub fn byte(self: ByteWriter, v: u8) !void {
        try self.buf.append(v);
    }

    pub fn putU32(self: ByteWriter, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, endian);
        try self.buf.appendSlice(&b);
    }

    pub fn putU64(self: ByteWriter, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, endian);
        try self.buf.appendSlice(&b);
    }

    pub fn slice(self: ByteWriter, v: []const u8) !void {
        try self.buf.appendSlice(v);
    }
};

pub fn readU32(data: []const u8, pos: usize) u32 {
    return std.mem.readInt(u32, data[pos..][0..4], endian);
}

pub fn readU64(data: []const u8, pos: usize) u64 {
    return std.mem.readInt(u64, data[pos..][0..8], endian);
}

pub fn crc(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}
