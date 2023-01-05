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

var debug_log: DebugLog = .{};

pub fn main() !void {
    const sfd = try initSocket(8080);
    defer os.closeSocket(sfd);
    try debug_log.init("/tmp/requestLog.txt");
    defer debug_log.deinit();
    var request_buf: [512]u8 = undefined;
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    while (true) {
        const cfd = try waitForConnection(sfd);
        debug_log.logClientConnected();
        while (true) {
            const raw_request = try waitForRequest(cfd, &request_buf);
            debug_log.logRecv(if (raw_request.len > 0) raw_request else "end-of-file (0 length)\n");
            if (raw_request.len == 0) break; // end-of-file (peer orderly shutdown)
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
                    const is_default_target = request.raw_target.len == 1 and request.raw_target[0] == '/';
                    const path_ = sanitizedPath(if (is_default_target) "/index.html" else request.raw_target, &path_buf);
                    if (path_) |path|
                        try sendFileResponse(cfd, path)
                    else
                        try sendErrorResponse(cfd, .not_found);
                },
                else => try sendErrorResponse(cfd, .not_implemented),
            }
        }
        std.log.info("client disconnected", .{});
    }
}

fn initSocket(port: u16) !socket_t {
    const fd = try os.socket(os.AF.INET, os.SOCK.STREAM | os.SOCK.CLOEXEC, 0);
    const address = IpAddress.init(.{ 0, 0, 0, 0 }, port);
    try os.bind(fd, @ptrCast(*const os.sockaddr, &address), @sizeOf(IpAddress));
    const backlog = 10;
    try os.listen(fd, backlog);
    return fd;
}

fn waitForConnection(sfd: socket_t) !socket_t {
    var peer_address: IpAddress = undefined;
    var peer_address_size: os.socklen_t = @sizeOf(IpAddress);
    const cfd = try os.accept(sfd, @ptrCast(*os.sockaddr, &peer_address), &peer_address_size, os.SOCK.CLOEXEC);
    if (peer_address_size != @sizeOf(IpAddress)) return error.PeerAddressSize;
    logAddress("client connected: {s}", &peer_address);
    return cfd;
}

fn waitForRequest(fd: socket_t, buf: []u8) ![]u8 {
    const n = try os.recv(fd, buf, 0);
    if (n == buf.len) return error.BufferFull;
    return buf[0..n];
}

const Request = struct {
    method: std.http.Method,
    raw_target: []const u8,
};

fn parseRequest(content: []const u8) ?Request {
    const line_end_i = indexOfHeaderLineEnding(content) orelse return null;
    const line = content[0..line_end_i];
    const method_end_i = mem.indexOfScalar(u8, line, ' ') orelse return null;
    const target_end_i = mem.lastIndexOfScalar(u8, line, ' ').?;
    if (!mem.eql(u8, "HTTP/1.1", line[target_end_i + 1 ..])) return null;

    const method = res: {
        const token = line[0..method_end_i];
        inline for (@typeInfo(std.http.Method).Enum.fields) |field|
            if (mem.eql(u8, token, field.name))
                break :res @intToEnum(std.http.Method, field.value);
        return null;
    };
    return .{ .method = method, .raw_target = line[method_end_i + 1 .. target_end_i] };
}

fn indexOfHeaderLineEnding(s: []const u8) ?usize {
    var p = s.ptr;
    const p_end = s.ptr + s.len - 1;
    while (@ptrToInt(p) < @ptrToInt(p_end)) : (p += 1)
        if (p[0] == '\r' and p[1] == '\n')
            return @ptrToInt(p) - @ptrToInt(s.ptr);

    return null;
}

fn sendErrorResponse(fd: socket_t, comptime status: std.http.Status) !void {
    var buf: [256]u8 = undefined;
    const s = writeErrorResponse(status, &buf);
    const n = try os.send(fd, s, 0);
    if (n != s.len) return error.SendTruncated;
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

fn writeErrorResponse(comptime se: std.http.Status, buf: []u8) []u8 {
    const status = statusString(se);
    const header_fmt = "HTTP/1.1 " ++ status ++ "\r\n" ++ "Content-Type: text/html\r\n"
        ++ "Content-Length: {d}\r\n" ++ "\r\n";
    const body = "<html>\n<head><title>" ++ status ++ "</title></head>\n" ++ "<body>\n<h1>"
        ++ status ++ "</h1>\n<hr/>\n</body>\n</html>\n";
    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();
    std.fmt.format(writer, header_fmt, .{body.len}) catch unreachable;
    writer.writeAll(body) catch unreachable;
    return stream.getWritten();
}

fn sendFileResponse(socket: socket_t, path: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content_len: usize = try file.getEndPos();
    var header_buf: [256]u8 = undefined;
    const header = writeHeader(content_len, contentType(path), &header_buf);
    var n = try os.send(socket, header, 0);
    if (n != header.len) return error.SendTruncated;
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
        if (buf_i == 0) return error.FileTruncated; // file changed during response (shouldn't happen)
        file_i += buf_i;
        var send_i: usize = 0;
        while (send_i < buf_i) {
            const n = try os.send(socket, buf[send_i..buf_i], 0);
            send_i += n;
        }
    }
}

fn writeHeader(content_len: usize, content_type: ContentType, buf: []u8) []u8 {
    const fmt = "HTTP/1.1 " ++ statusString(.ok) ++ "\r\nContent-Type: {s}\r\n"
        ++ "Keep-Alive: timeout=120, max=1000\r\nConnection: keep-alive\r\n"
        ++ "Content-Length: {d}\r\n\r\n";
    const sType = switch (content_type) {
        .html => "text/html",
        .javascript => "text/javascript",
        .webassembly => "application/wasm",
        .text => "text/plain",
        .binary => "application/octet-stream",
    };
    var stream = std.io.fixedBufferStream(buf);
    std.fmt.format(stream.writer(), fmt, .{ sType, content_len }) catch unreachable;
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
