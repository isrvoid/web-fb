// MIT License
// Copyright (c) 2023 Johannes Teichrieb
// GitHub, Gmail: isrvoid

// Aims to be fast and correct for RFC 6455 compliant peers.
const std = @import("std");
const os = std.os;
const mem = std.mem;
const assert = std.debug.assert;

buf: []u8,
fd: os.socket_t,
mkey: [4]u8 = undefined,
start_i: usize = undefined,
end_i: usize = 0,
read_i: usize = 0,
reading_header: bool = true,
is_binary: bool = undefined,
is_open: bool = true,
is_closing: bool = false,

const WebSocket = @This();
const CloseStatus = enum(u16) {
    going_away = 1001,
    protocol_error = 1002,
    policy_violation = 1008,
    message_too_big = 1009,
};
fn ValBytes(comptime T: type) type {
    return extern union {
        val: T,
        a: [@sizeOf(T)]u8,
    };
}
const LenBytes = ValBytes(u64);
const len7_max = 125;

// receive_buf.len is max receivable payload length
pub fn init(socket: os.socket_t, receive_buf: []u8) WebSocket {
    assert(receive_buf.len >= len7_max and receive_buf.len < 1 << 63);
    return .{ .fd = socket, .buf = receive_buf };
}

// check isOpen() after null result; deplete periodically from a single thread
// non-blocking; result is only valid until the next call
pub fn recvNext(self: *WebSocket) !?[]const u8 {
    assert(self.is_open);
    if (self.reading_header and !try self.readHeader()) return null;
    if (self.read_i < self.end_i and !try self.recv(self.end_i)) return null;
    defer self.postFrameCleanup();
    return self.unmask();
}

pub inline fn isOpen(self: *const WebSocket) bool {
    return self.is_open;
}

// type of last message returned by recvNext(); 'false' for text
pub inline fn isBinary(self: *const WebSocket) bool {
    return self.is_binary;
}

pub fn send(self: *WebSocket, data: []const u8) !void {
    return self.sendWithH0(data, 0x82);
}

pub fn sendText(self: *WebSocket, data: []const u8) !void {
    return self.sendWithH0(data, 0x81);
}

pub fn closeStep(self: *WebSocket) !bool {
    if (self.is_open) {
        try self.beginCloseWithStatus(.going_away);
        return false;
    }
    assert(self.is_closing);
    const len = os.recv(self.fd, self.buf, 0) catch |err| return if (err == error.WouldBlock) false else err;
    if (len != 0) return false;
    os.close(self.fd);
    self.is_closing = false;
    return true;
}

fn sendWithH0(self: *WebSocket, data: []const u8, comptime h0: u8) !void {
    const header: []const u8 = res: {
        if (data.len <= len7_max) break :res &[2]u8{ h0, @truncate(u8, data.len) };

        const len = LenBytes{ .val = mem.nativeToBig(u64, data.len) };
        if (data.len < 1 << 16) break :res &[2]u8{ h0, 0x7e } ++ len.a[6..8];
        break :res &[2]u8{ h0, 0x7f } ++ len.a;
    };
    // TODO lock
    _ = try os.send(self.fd, header, 0);
    _ = try os.send(self.fd, data, 0);
}

fn readHeader(self: *WebSocket) !bool {
    // not meant to be transparent; refer to RFC 6455
    const header_i = self.end_i;
    if (self.read_i < header_i + 2 and !try self.recv(header_i + 2)) return false;
    const h0 = self.buf[header_i];
    const h1 = self.buf[header_i + 1];
    const opcode = h0 & 0x0f;
    const is_peer_closing = opcode == 0x8;
    const is_not_masked = h1 & 0x80 == 0; // catch mask early to remove it as a length variable
    if (is_peer_closing or is_not_masked) {
        // peer closing status is probable guess (spec-compliant; avoids parsing)
        try self.beginCloseWithStatus(if (is_peer_closing) .going_away else .protocol_error);
        return false;
    }
    const len7 = h1 & 0x7f;
    const num_ext_bytes = @as(u32, @boolToInt(len7 == 0x7e)) * 2 + @as(u32, @boolToInt(len7 == 0x7f)) * 8;
    const header_len = 2 + num_ext_bytes + 4;
    if (self.read_i < header_i + header_len and !try self.recv(header_i + header_len)) return false;
    // not supported (non spec compliant): fragmented messages, ping, pong
    const is_other_error = h0 != 0x82 and h0 != 0x81;
    if (is_other_error) {
        const is_fragmented = h0 & 0x80 == 0 and (opcode == 0x1 or opcode == 0x2);
        const is_ping = opcode == 0x9 or opcode == 0xa;
        const close_status: CloseStatus = if (is_fragmented or is_ping) .policy_violation else .protocol_error;
        try self.beginCloseWithStatus(close_status);
        return false;
    }
    self.is_binary = opcode == 0x2;

    const len: usize = res: {
        if (len7 <= len7_max) break :res len7;

        var lb = LenBytes{ .val = 0 };
        const ext_len_bytes = self.buf[header_i + 2 .. header_i + 2 + num_ext_bytes];
        if (comptime @import("builtin").cpu.arch.endian() == .Little) {
            for (ext_len_bytes, 0..) |v, i|
                lb.a[num_ext_bytes - 1 - i] = v;
        } else { // big endian
            mem.copy(u8, lb.a[8 - num_ext_bytes .. 8], ext_len_bytes);
        }
        const len = lb.val;

        // assert in init() makes len > buf.len also cover length64 MSB != 0
        // encoding with minimal number of bytes is not enforced (no protocol error)
        if (len > self.buf.len) {
            const close_status: CloseStatus = if (len & 1 << 63 != 0) .protocol_error else .message_too_big;
            try self.beginCloseWithStatus(close_status);
            return false;
        }
        break :res @truncate(usize, len);
    };

    const header_end_i = header_i + header_len;
    mem.copy(u8, &self.mkey, self.buf[header_end_i - 4 .. header_end_i]);
    const data_fits_in_place = header_end_i <= self.buf.len - len; // '-' prevents wrapping on 32-bit arch
    if (data_fits_in_place) {
        self.start_i = header_end_i;
        self.end_i = header_end_i + len;
    } else {
        mem.copy(u8, self.buf, self.buf[header_end_i..self.read_i]);
        self.read_i -= header_end_i;
        self.start_i = 0;
        self.end_i = len;
    }
    self.reading_header = false;
    return true;
}

fn postFrameCleanup(self: *WebSocket) void {
    const max_header_len = 14;
    if (self.end_i == self.read_i) {
        self.end_i = 0;
        self.read_i = 0;
    } else if (self.buf.len - self.end_i < max_header_len) { // ensure next header fits into buffer
        mem.copy(u8, self.buf, self.buf[self.end_i..self.read_i]);
        self.read_i -= self.end_i;
        self.end_i = 0;
    }
    self.reading_header = true;
}

fn unmask(self: *WebSocket) []u8 {
    var res = self.buf[self.start_i..self.end_i];
    if (self.end_i - self.start_i < 32) {
        for (res, 0..) |*v, i|
            v.* ^= self.mkey[i % 4];
    } else {
        const start = @ptrToInt(self.buf.ptr + self.start_i);
        const end = @ptrToInt(self.buf.ptr + self.end_i);
        const aligned_end = end & ~@as(usize, 3);
        const past_aligned = start % 4;
        const al_inc = @as(usize, @boolToInt(past_aligned != 0)) * 4 - past_aligned;
        const aligned_start = start + al_inc;
        const key = ValBytes(u32){ .a = .{ self.mkey[al_inc], self.mkey[al_inc+1 & 3], self.mkey[al_inc+2 & 3], self.mkey[al_inc+3 & 3] } };
        var i = start;
        while (i < aligned_start) : (i += 1)
            @intToPtr(*u8, i).* ^= key.a[i % 4];
        while (i < aligned_end) : (i += 4)
            @intToPtr(*u32, i).* ^= key.val;
        while (i < end) : (i += 1)
            @intToPtr(*u8, i).* ^= key.a[i % 4];
    }
    return res;
}

fn recv(self: *WebSocket, min_read_i: usize) !bool {
    assert(min_read_i > self.read_i and min_read_i <= self.buf.len);
    const max_read_i = @min(min_read_i + 0x100, self.buf.len); // limit size of potential data move
    const n = os.recv(self.fd, self.buf[self.read_i..max_read_i], 0) catch |err| return if (err == error.WouldBlock) false else err;
    if (n == 0) { // out-of-spec peer shutdown
        self.is_open = false;
        os.close(self.fd);
        return false;
    }
    self.read_i += n;
    return self.read_i >= min_read_i;
}

fn beginCloseWithStatus(self: *WebSocket, status: CloseStatus) !void {
    try self.sendClose(status);
    self.is_closing = true;
    self.is_open = false;
    try os.shutdown(self.fd, .send);
}

fn sendClose(self: *const WebSocket, status: CloseStatus) !void {
    const status_val = @enumToInt(status);
    const frame = [4]u8{ 0x88, 0x02, @truncate(u8, status_val >> 8), @truncate(u8, status_val) };
    _ = try os.send(self.fd, &frame, 0);
}
