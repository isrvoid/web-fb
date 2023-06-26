const std = @import("std");
const mem = std.mem;
const os = std.os;
const IpAddress = std.net.Ip4Address;
const socket_t = std.os.socket_t;

const Content = @import("content.zig").Content;

var debug_log = DebugLog{};

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

request_buf: []u8,
sfd: socket_t,
cfd: socket_t = undefined,
is_peer_connected: bool = false,
content: Content,

const Server = @This();

pub fn init(port: u16, content: Content, request_buf: []u8) !Server {
    try debug_log.init("/tmp/webfb_debug_log.txt");
    return Server{ .sfd = try initSocket(port), .content = content, .request_buf = request_buf };
}

pub fn deinit(self: *Server) void {
    if (self.is_peer_connected)
        os.close(self.cfd);
    os.close(self.sfd);
    debug_log.deinit();
}

pub fn step(self: *Server) !?socket_t {
    if (!self.is_peer_connected) {
        self.cfd = res: {
            const fd = try maybeAcceptConnection(self.sfd);
            if (fd == null) return null;
            break :res fd.?;
        };
        debug_log.logClientConnected();
        self.is_peer_connected = true;
    }
    const cfd = self.cfd;
    const raw_request = res: {
        const req = try maybeReceiveRequest(cfd, self.request_buf);
        if (req == null) return null;
        break :res req.?;
    };
    debug_log.logRecv(if (raw_request.len > 0) raw_request else "end-of-file (0 length)\n");
    if (raw_request.len == 0) { // peer has closed
        os.close(cfd);
        self.is_peer_connected = false;
        return null;
    }
    const request = parseRequest(raw_request) catch {
        try sendErrorResponse(cfd, .bad_request);
        return null;
    };
    switch (request.method) {
        .GET => {
            if (request.is_upgrade_request) {
                if (try handleUpgradeRequest(cfd, request.websocket_key.?)) {
                    self.is_peer_connected = false;
                    return cfd;
                }
            } else try handleFileRequest(cfd, request, self.content);
        },
        else => try sendErrorResponse(cfd, .not_implemented),
    }
    return null;
}

fn handleFileRequest(socket: socket_t, request: Request, content: Content) !void {
    const close_after = ".wasm"; // last file before expected upgrade request
    var url_buf: [0x400]u8 = undefined;
    const path = res: {
        const url = try sanitizeUrl(request.url, &url_buf);
        const is_default_url = url.len == 0;
        break :res if (is_default_url) "index.html" else url;
    };
    const should_close = mem.endsWith(u8, path, close_after);
    sendFileResponse(socket, content, path, should_close) catch |err|
        if (err == error.FileNotFound) try sendErrorResponse(socket, .not_found) else return err;
}

fn handleUpgradeRequest(socket: socket_t, ws_key: []const u8) !bool {
    const fixed_append = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(ws_key);
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
    try os.bind(sfd, @ptrCast(&address), @sizeOf(IpAddress));
    const backlog = 10;
    try os.listen(sfd, backlog);
    return sfd;
}

fn maybeAcceptConnection(sfd: socket_t) !?socket_t {
    var peer_address: IpAddress = undefined;
    var peer_address_size: os.socklen_t = @sizeOf(IpAddress);
    const cfd = os.accept(sfd, @ptrCast(&peer_address), &peer_address_size, os.SOCK.NONBLOCK) catch |err|
        return if (err == error.WouldBlock) null else err;
    if (peer_address_size != @sizeOf(IpAddress)) return error.PeerAddressSize;
    logAddress("peer connected: {s}", &peer_address);
    return cfd;
}

fn maybeReceiveRequest(socket: socket_t, buf: []u8) !?[]u8 {
    const n = os.recv(socket, buf, 0) catch |err| return if (err == error.WouldBlock) null else err;
    if (n == buf.len) return error.BufferFull;
    return buf[0..n];
}

const Request = struct {
    method: std.http.Method,
    url: []const u8,
    is_upgrade_request: bool,
    websocket_key: ?[]const u8,
};

fn parseRequest(a: []const u8) !Request {
    var result: Request = undefined;
    var line_it = HeaderLineIterator{ .request = a };
    const request_line = line_it.next().?; // FIXME receive end of the header in step()
    try parseRequestLine(request_line, &result);
    try parseUpgradeFields(line_it, &result);
    return result;
}

fn parseRequestLine(line: []const u8, out: *Request) !void {
    const method_end_i = mem.indexOfScalar(u8, line, ' ') orelse return error.RequestLine;
    const url_end_i = mem.lastIndexOfScalar(u8, line, ' ').?;
    const url_start_i = method_end_i + 1;
    if (url_start_i >= url_end_i) return error.RequestLineUrl;
    out.url = line[url_start_i..url_end_i];

    const http_start_i = url_end_i + 1;
    if (!mem.eql(u8, "HTTP/1.1", line[http_start_i..])) return error.RequestLineHttp;

    out.method = res: {
        const token = line[0..method_end_i];
        inline for (@typeInfo(std.http.Method).Enum.fields) |field|
            if (mem.eql(u8, token, field.name))
                break :res @enumFromInt(field.value);
        return error.RequestLineMethod;
    };
}

fn parseUpgradeFields(fields_start: HeaderLineIterator, out: *Request) !void {
    out.is_upgrade_request = false;
    out.websocket_key = null;
    var it = fields_start;
    while (it.next()) |line| {
        if (isUpgradeField(line))
            out.is_upgrade_request = true;

        var key: []const u8 = undefined;
        if (isWebsocketKeyField(line, &key))
            out.websocket_key = key;
    }
    if (out.is_upgrade_request != (out.websocket_key != null)) return error.UpgradeRequestFields;
}

fn isUpgradeField(line: []const u8) bool {
    const name = "upgrade:";
    const val = "websocket";
    const min_len = name.len + val.len;
    if (line.len < min_len) return false;
    if (!std.ascii.eqlIgnoreCase(name, line[0..name.len])) return false;
    return mem.eql(u8, val, trim(line[name.len..]));
}

fn isWebsocketKeyField(line: []const u8, key_out: *[]const u8) bool {
    const name = "sec-websocket-key:";
    const min_len = name.len + 1;
    if (line.len < min_len) return false;
    if (std.ascii.toLower(line[16]) != 'y') return false; // discard same prefix quicker
    if (!std.ascii.eqlIgnoreCase(name, line[0..name.len])) return false;
    key_out.* = trim(line[name.len..]);
    return key_out.len > 0;
}

inline fn trim(s: []const u8) []const u8 {
    return mem.trim(u8, s, &std.ascii.whitespace);
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
        while (@intFromPtr(p) < @intFromPtr(p_end)) : (p += 1)
            if (p[0] == '\r' and p[1] == '\n')
                return @intFromPtr(p) - @intFromPtr(s.ptr);

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

fn logAddress(comptime fmt: []const u8, addr: *const IpAddress) void {
    var buf: [32]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    addr.format("", .{}, stream.writer()) catch unreachable;
    std.log.info(fmt, .{stream.getWritten()});
}

inline fn statusString(comptime status: std.http.Status) [:0]const u8 {
    comptime return std.fmt.comptimePrint("{d} {s}", .{ @intFromEnum(status), status.phrase().? })[0..];
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

fn sendFileResponse(socket: socket_t, content: Content, path: []const u8, close_connection: bool) !void {
    const prop = try content.open(path);
    defer content.close();
    var header_buf: [0x100]u8 = undefined;
    const header = writeHeader(prop.len, prop.cont_type, close_connection, &header_buf);
    _ = try os.send(socket, header, 0);
    var chunk = try content.nextChunk();
    while (chunk.len != 0) : (chunk = try content.nextChunk())
        _ = try os.send(socket, chunk, 0);
    debug_log.logSendFile(header, path);
}

fn writeHeader(content_len: usize, content_type: Content.Type, close_connection: bool, buf: []u8) []u8 {
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

// sanitized URL has no ".." (can't escape); leading '/' is omitted
fn sanitizeUrl(url: []const u8, buf: []u8) ![]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    return (try std.fs.path.resolvePosix(fba.allocator(), &[2][]const u8{ "/", url }))[1..];
}
