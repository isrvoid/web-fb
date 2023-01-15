const std = @import("std");
const os = std.os;
const mem = std.mem;

const IpAddress = std.net.Ip4Address;
const socket_t = std.os.socket_t;

const DebugLog = struct {
    f: std.fs.File = undefined,

    const Self = @This();
    const is_disabled = @import("builtin").mode != .Debug;

    fn init(self: *Self, file_path: []const u8) !void {
        if (comptime is_disabled) return;
        self.f = try std.fs.createFileAbsolute(file_path, .{});
    }

    fn deinit(self: *Self) void {
        if (is_disabled) return;
        self.f.close();
    }

    fn logSend(self: *Self, buf: []const u8) void {
        if (is_disabled) return;
        const writer = self.f.writer();
        self.writeSeparator("SEND");
        writer.writeAll(buf) catch {};
    }

    fn logSendFile(self: *Self, header: []const u8, path: []const u8) void {
        if (is_disabled) return;
        const writer = self.f.writer();
        self.writeSeparator("SEND");
        writer.writeAll(header) catch {};
        writer.writeAll("content of: ") catch {};
        writer.writeAll(path) catch {};
        writer.writeByte('\n') catch {};
    }

    fn logRecv(self: *Self, buf: []const u8) void {
        if (is_disabled) return;
        const writer = self.f.writer();
        self.writeSeparator("RECV");
        writer.writeAll(buf) catch {};
    }

    fn logClientConnected(self: *Self) void {
        if (is_disabled) return;
        self.writeSeparator("CONNECTED " ++ "-" ** 20);
    }

    fn writeSeparator(self: *Self, comptime msg: []const u8) void {
        if (is_disabled) return;
        self.f.writer().writeAll("-" ** 50 ++ " " ++ msg ++ "\n") catch {};
    }
};

var debug_log = DebugLog{};

pub fn main() !void {
    const sfd = try initSocket(8080);
    defer os.close(sfd);
    try debug_log.init("/tmp/requestLog.txt");
    defer debug_log.deinit();
    var request_buf: [0x400]u8 = undefined;
    outer: while (true) {
        const cfd = try waitForConnection(sfd);
        debug_log.logClientConnected();
        while (true) {
            const raw_request = try waitForRequest(cfd, &request_buf);
            debug_log.logRecv(if (raw_request.len > 0) raw_request else "end-of-file (0 length)\n");
            if (raw_request.len == 0) { // peer has closed
                os.close(cfd);
                continue :outer;
            }
            const request = res: {
                const request_ = parseRequest(raw_request);
                if (request_ == null) {
                    try sendErrorResponse(cfd, .bad_request);
                    continue;
                }
                break :res request_.?;
            };
            switch (request.method) {
                .GET => {
                    if (request.is_upgrade_request) {
                        if (try handleUpgradeRequest(cfd, request.raw_websocket_key.?)) {
                            handOverWsConnection(cfd);
                            continue :outer;
                        }
                    } else try handleGetFileRequest(cfd, request);
                },
                else => try sendErrorResponse(cfd, .not_implemented),
            }
        }
    }
}

// Why not use an available WebSocket implementation?
// If we ignore the extensions, WebSocket is a simple protocol. The header has just a few control bits.
// Projects with hundreds of lines of code and multiple files have extra stuff not needed here.
// web-fb uses binary messages of known length. The code should span few ten lines (tests excluded).

const WebSocket = struct {
    buf: []u8,
    fd: socket_t,
    mkey: [4]u8 = undefined,
    start_i: usize = undefined,
    end_i: usize = 0,
    read_i: usize = 0,
    reading_header: bool = true,
    is_binary: bool = undefined,
    recv_type: MessageType = undefined,
    is_open: bool = true,

    const Self = @This();

    const CloseStatus = enum(u16) {
        going_away = 1001,
        protocol_error = 1002,
        policy_violation = 1008,
        message_too_big = 1009,
    };
    const MessageType = enum {
        data,
        ping,
        pong,
    };
    const max_control_data_len = 125;

    // receive_buf.len is max receivable payload length
    fn init(socket: socket_t, receive_buf: []u8) WebSocket {
        // for now only supports receiving up to 0xffff (extended length 16)
        std.debug.assert(receive_buf.len >= max_control_data_len and receive_buf.len <= 1 << 16);
        return .{ .fd = socket, .buf = receive_buf };
    }

    // check is_open after null result; deplete periodically from a single thread
    // non-blocking; result is only valid until the next call
    fn recvNext(self: *Self) !?[]const u8 {
        // not meant to be transparent; refer to RFC 6455
        // aims to be fastest and correct for compliant peers
        // if the peer violates spec (protocol errors), closing status code might be questionable
        std.debug.assert(self.is_open);
        if (self.reading_header and !try self.readHeader()) return null;
        if (self.read_i < self.end_i and !try self.recv(self.end_i)) return null;

        defer self.postFrameCleanup();
        const data = self.unmask();
        switch (self.recv_type) {
            .data => return data,
            .ping => {
                try self.sendPong(data);
                return null;
            },
            .pong => return null, // spec allows unsolicited PONG
        }
    }

    fn send(_: *Self, _: []const u8) !void {
        // FIXME
    }

    fn sendPong(self: *Self, data: []const u8) !void {
        std.debug.assert(data.len <= max_control_data_len);
        const header = [2]u8{ 0x8a, @truncate(u7, data.len) };
        // TODO lock
        _ = try os.send(self.fd, &header, 0);
        _ = try os.send(self.fd, data, 0);
    }

    fn readHeader(self: *Self) !bool {
        //const initial_read = @min(0x100, buf.len); FIXME
        // TODO maybe move (trailing) truncated message; reallocate header
        if (self.read_i < self.end_i + 2 and !try self.recv(self.end_i + 2)) return false;

        const h0 = self.buf[0];
        const h1 = self.buf[1];
        const opcode = h0 & 0x0f;
        const is_peer_closing = opcode == 8;
        if (is_peer_closing) {
            try self.close(.going_away); // status is probable guess (spec-compliant; avoids parsing)
            return false;
        }
        // TODO length first?
        // fragmented messages are not supported (non spec compliant)
        const is_closing_bulk = h0 & 0xf7 != 0x81 and h0 & 0xf7 != 0x82 or h1 & 0x80 == 0 or h1 == 0xff;
        if (is_closing_bulk) {
            const is_fin = h0 & 0x80 != 0;
            const is_text_or_binary = opcode == 1 or opcode == 2;
            // non protocol_error status might be incorrect for spec violating peers (not that important)
            const close_status: WebSocket.CloseStatus = if (!is_fin and is_text_or_binary) .policy_violation
                else if (h1 == 0xff) .message_too_big else .protocol_error;
            try self.close(close_status);
            return false;
        }
        // only remaining close reason is length (message too big and protocol errors)
        // TODO hanle or ignore length protocol error
        // TODO set members
        // TODO realloc if the message doesn't fit; move head, if received length matches message
        // there is a case where the header doesn't fit - can special treatment be avoided?
        return true;
    }

    fn unmask(self: *Self) []u8 {
        // FIXME
        return self.buf[self.start_i..self.end_i];
    }

    fn postFrameCleanup(_: *Self) void {
        // FIXME
    }

    fn recv(self: *Self, min_i: usize) !bool {
        std.debug.assert(min_i > self.read_i);
        const n = os.recv(self.fd, self.buf[self.read_i..], os.linux.MSG.DONTWAIT) catch |err| return if (err == std.os.RecvFromError.WouldBlock) false else err;
        if (n == 0) { // out-of-spec peer shutdown
            self.is_open = false;
            os.close(self.fd);
            return false;
        }
        self.read_i += n;
        return self.read_i >= min_i;
    }

    fn close(self: *Self, status: WebSocket.CloseStatus) !void {
        try self.sendClose(status);
        self.is_open = false;
        try os.shutdown(self.fd, .send);
        while (try os.recv(self.fd, self.buf, 0) != 0) {}
        os.close(self.fd);
    }

    fn sendClose(self: *const Self, status: WebSocket.CloseStatus) !void {
        const status_val = @enumToInt(status);
        const frame = [4]u8{ 0x88, 0x02, @truncate(u8, status_val >> 8), @truncate(u8, status_val) };
        _ = try os.send(self.fd, &frame, 0);
    }
};

fn handOverWsConnection(socket: socket_t) void {
    // FIXME push the socket somewhere else and return; this is just for debugging
    var buf: [0x1000]u8 = undefined;
    var ws = WebSocket.init(socket, &buf);
    while (ws.is_open) {
        // FIXME
        while (ws.recvNext() catch unreachable) |msg| {
            _ = msg;
        }
        std.time.sleep(1e6);
    }
}

fn handleGetFileRequest(socket: socket_t, request: Request) !void {
    const close_after = ".wasm"; // last file before expected upgrade request
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const is_default_target = request.raw_target.len == 1 and request.raw_target[0] == '/';
    const path_ = sanitizedPath(if (is_default_target) "/index.html" else request.raw_target, &path_buf);
    if (path_) |path| {
        const should_close = mem.endsWith(u8, path, close_after);
        try sendFileResponse(socket, path, should_close);
    } else try sendErrorResponse(socket, .not_found);
}

fn handleUpgradeRequest(socket: socket_t, raw_key: []const u8) !bool {
    const fixed_append = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(raw_key);
    sha.update(fixed_append);
    var hash: [20]u8 = undefined;
    sha.final(&hash);
    var hash64: [28]u8 = undefined;
    const encoder = std.base64.standard.Encoder;
    try sendUpgradeResponse(socket, encoder.encode(&hash64, &hash));
    return true;
}

fn sendUpgradeResponse(socket: socket_t, hash_str: []const u8) !void {
    var buf: [0x100]u8 = undefined;
    const fmt = "HTTP/1.1 " ++ statusString(.switching_protocols)
        ++ "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n";
    const s = std.fmt.bufPrint(&buf, fmt, .{hash_str}) catch unreachable;
    _ = try os.send(socket, s, 0);
    debug_log.logSend(s);
}

fn initSocket(port: u16) !socket_t {
    const sfd = try os.socket(os.AF.INET, os.SOCK.STREAM | os.SOCK.CLOEXEC, 0);
    const address = IpAddress.init(.{ 0, 0, 0, 0 }, port);
    try os.bind(sfd, @ptrCast(*const os.sockaddr, &address), @sizeOf(IpAddress));
    const backlog = 10;
    try os.listen(sfd, backlog);
    return sfd;
}

fn waitForConnection(sfd: socket_t) !socket_t {
    var peer_address: IpAddress = undefined;
    var peer_address_size: os.socklen_t = @sizeOf(IpAddress);
    const cfd = try os.accept(sfd, @ptrCast(*os.sockaddr, &peer_address), &peer_address_size, os.SOCK.CLOEXEC);
    if (peer_address_size != @sizeOf(IpAddress)) return error.PeerAddressSize;
    logAddress("peer connected: {s}", &peer_address);
    return cfd;
}

fn waitForRequest(socket: socket_t, buf: []u8) ![]u8 {
    const n = try os.recv(socket, buf, 0);
    if (n == buf.len) return error.BufferFull;
    return buf[0..n];
}

const Request = struct {
    method: std.http.Method,
    raw_target: []const u8,
    is_upgrade_request: bool,
    raw_websocket_key: ?[]const u8,
};

fn parseRequest(content: []const u8) ?Request {
    var result: Request = undefined;
    var line_it = HeaderLineIterator{.request = content};
    const request_line = line_it.next() orelse return null;
    if (!parseRequestLine(request_line, &result)) return null;
    if (!parseUpgradeFields(line_it, &result)) return null;
    return result;
}

fn parseRequestLine(line: []const u8, result_out: *Request) bool {
    const method_end_i = mem.indexOfScalar(u8, line, ' ') orelse return false;
    const target_end_i = mem.lastIndexOfScalar(u8, line, ' ').?;
    if (!mem.eql(u8, "HTTP/1.1", line[target_end_i + 1 ..])) return false;

    result_out.method = res: {
        const token = line[0..method_end_i];
        inline for (@typeInfo(std.http.Method).Enum.fields) |field|
            if (mem.eql(u8, token, field.name))
                break :res @intToEnum(std.http.Method, field.value);
        return false;
    };
    result_out.raw_target = line[method_end_i + 1 .. target_end_i];
    return true;
}

fn parseUpgradeFields(fields_start: HeaderLineIterator, result_out: *Request) bool {
    result_out.is_upgrade_request = false;
    result_out.raw_websocket_key = null;
    var it = fields_start;
    var line_ = it.next();
    while (line_ != null) : (line_ = it.next()) {
        const line = line_.?;
        if (isUpgradeField(line))
            result_out.is_upgrade_request = true;

        var key: []const u8 = undefined;
        if (isWebsocketKeyField(line, &key))
            result_out.raw_websocket_key = key;
    }
    return result_out.is_upgrade_request == (result_out.raw_websocket_key != null);
}

fn isUpgradeField(line: []const u8) bool {
    const name = "upgrade:";
    const val = "websocket";
    const min_len = name.len + val.len;
    if (line.len < min_len) return false;
    if (!std.ascii.eqlIgnoreCase(name, line[0..name.len])) return false;
    return mem.eql(u8, val, mem.trim(u8, line[name.len..], &std.ascii.whitespace));
}

fn isWebsocketKeyField(line: []const u8, key_out: *[]const u8) bool {
    const name = "sec-websocket-key:";
    const min_len = name.len + 1;
    if (line.len < min_len) return false;
    if (std.ascii.toLower(line[16]) != 'y') return false; // discard same prefix quicker
    if (!std.ascii.eqlIgnoreCase(name, line[0..name.len])) return false;
    const val = mem.trim(u8, line[name.len..], &std.ascii.whitespace);
    key_out.* = val;
    return val.len > 0;
}

const HeaderLineIterator = struct {
    request: []const u8,
    last_end_i: usize = 0,

    const Self = @This();

    fn next(self: *Self) ?[]const u8 {
        const tail = self.request[self.last_end_i..];
        const ending_i = indexOfHeaderLineEnding(tail) orelse return null;
        if (ending_i == 0) return null;
        self.last_end_i += ending_i + 2;
        return tail[0..ending_i];
    }

    fn indexOfHeaderLineEnding(s: []const u8) ?usize {
        var p = s.ptr;
        const p_end = s.ptr + s.len - 1;
        while (@ptrToInt(p) < @ptrToInt(p_end)) : (p += 1)
            if (p[0] == '\r' and p[1] == '\n')
                return @ptrToInt(p) - @ptrToInt(s.ptr);

        return null;
    }
};

test "header line iterator" {
    const expect = std.testing.expect;
    const expectEqs = std.testing.expectEqualStrings;
    var it: HeaderLineIterator = undefined;
    // invalid
    it = HeaderLineIterator{.request = ""};
    try expect(null == it.next());
    it = HeaderLineIterator{.request = "\n"};
    try expect(null == it.next());
    it = HeaderLineIterator{.request = "foo"};
    try expect(null == it.next());
    // valid
    it = HeaderLineIterator{.request = "foo\r\n"};
    try expectEqs("foo", it.next().?);
    it = HeaderLineIterator{.request = "a\r\nBar: x\r\n"};
    try expectEqs("a", it.next().?);
    try expectEqs("Bar: x", it.next().?);
    // invalid end
    it = HeaderLineIterator{.request = "foo\r\n"};
    _ = it.next();
    try expect(null == it.next());
    // single end
    it = HeaderLineIterator{.request = "\r\n"};
    try expect(null == it.next());
    // header end
    it = HeaderLineIterator{.request = "Foo:\r\n\r\n"};
    _ = it.next();
    try expect(null == it.next());
    try expect(null == it.next());
}

fn sendErrorResponse(socket: socket_t, comptime status: std.http.Status) !void {
    var buf: [0x100]u8 = undefined;
    const s = writeErrorResponse(status, &buf);
    _ = try os.send(socket, s, 0);
    debug_log.logSend(s);
}

fn logAddress(comptime fmt: []const u8, a: *const IpAddress) void {
    var buf: [32]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    a.format("", .{}, stream.writer()) catch unreachable;
    std.log.info(fmt, .{stream.getWritten()});
}

inline fn statusString(comptime status: std.http.Status) [:0]const u8 {
    comptime return std.fmt.comptimePrint("{d} {s}", .{ @enumToInt(status), status.phrase().? })[0..];
}

fn writeErrorResponse(comptime stat: std.http.Status, buf: []u8) []u8 {
    const status = statusString(stat);
    const header_fmt = "HTTP/1.1 " ++ status ++ "\r\nContent-Type: text/html\r\nConnection: close\r\n"
        ++ "Content-Length: {d}\r\n\r\n";
    const body = "<html>\n<head><title>" ++ status ++ "</title></head>\n"
        ++ "<body>\n<h1>" ++ status ++ "</h1>\n<hr/>\n</body>\n</html>\n";
    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();
    std.fmt.format(writer, header_fmt, .{body.len}) catch unreachable;
    writer.writeAll(body) catch unreachable;
    return stream.getWritten();
}

fn sendFileResponse(socket: socket_t, path: []const u8, close_connection: bool) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content_len: usize = try file.getEndPos();
    var header_buf: [0x100]u8 = undefined;
    const header = writeHeader(content_len, contentType(path), close_connection, &header_buf);
    _ = try os.send(socket, header, 0);
    try sendFile(socket, file, content_len);
    debug_log.logSendFile(header, path);
}

fn contentType(path: []const u8) ContentType {
    if (mem.endsWith(u8, path, ".html")) return .html;
    if (mem.endsWith(u8, path, ".js")) return .javascript;
    if (mem.endsWith(u8, path, ".wasm")) return .webassembly;
    if (mem.endsWith(u8, path, ".txt")) return .text;
    return .binary;
}

const ContentType = enum {
    html,
    javascript,
    webassembly,
    text,
    binary,
};

fn sendFile(socket: socket_t, file: std.fs.File, len: usize) !void {
    var buf: [1 << 12]u8 = undefined;
    var file_i: usize = 0;
    while (file_i < len) {
        const buf_i = try file.read(&buf);
        file_i += buf_i;
        if (buf_i == 0) return error.FileTruncated; // file changed during response (shouldn't happen)
        _ = try os.send(socket, buf[0..buf_i], 0);
    }
}

fn writeHeader(content_len: usize, content_type: ContentType, close_connection: bool, buf: []u8) []u8 {
    const fmt = "HTTP/1.1 " ++ statusString(.ok) ++ "\r\nContent-Type: {s}\r\nConnection: {s}\r\n"
        ++ "Content-Length: {d}\r\n\r\n";
    const sType = switch (content_type) {
        .html => "text/html",
        .javascript => "text/javascript",
        .webassembly => "application/wasm",
        .text => "text/plain",
        .binary => "application/octet-stream",
    };
    const sConn = if (close_connection) "close" else "keep-alive\r\nKeep-Alive: timeout=5";
    var stream = std.io.fixedBufferStream(buf);
    std.fmt.format(stream.writer(), fmt, .{ sType, sConn, content_len }) catch unreachable;
    return stream.getWritten();
}

const web_root = "web-root/";

fn sanitizedPath(raw: []const u8, result_buf: *[std.fs.MAX_PATH_BYTES]u8) ?[]u8 {
    if (raw.len == 0 or raw[0] != '/') return null;
    // target starts with '/', otherwise relative() could return ".." and escape web_root directory
    std.debug.assert(raw[0] == '/');
    var sanitized_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const sanitized = res: {
        var fba = std.heap.FixedBufferAllocator.init(sanitized_buf[web_root.len..]);
        var s = std.fs.path.relative(fba.allocator(), "/", raw) catch unreachable;
        s.ptr -= web_root.len;
        s.len += web_root.len;
        s[0..web_root.len].* = web_root.*;
        break :res s;
    };
    return std.fs.realpath(sanitized, result_buf) catch null;
}
