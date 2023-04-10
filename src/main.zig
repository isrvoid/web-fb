const std = @import("std");

const Server = @import("Server.zig");

pub fn main() !void {
    var request_buf: [0x400]u8 = undefined;
    var dir_cont = @import("content.zig").DirContent{ .dir = "web-root" };
    var server = try Server.init(8080, dir_cont.content(), &request_buf);
    defer server.deinit();
    while (true) {
        const res = try server.step();
        if (res) |socket|
            try echoAndClose(socket);

        std.time.sleep(1e6);
    }
}

// test dummy
fn echoAndClose(socket: std.os.socket_t) !void {
    const timeMs = std.time.milliTimestamp;
    var buf: [0x1000]u8 = undefined;
    var ws = @import("WebSocket.zig").init(socket, &buf);
    const echo_duration_ms = 1000;
    const time_end = timeMs() + echo_duration_ms;
    while (ws.isOpen() and timeMs() < time_end) {
        while (try ws.recvNext()) |msg| {
            if (!ws.isBinary())
                try ws.sendText(msg);
        }
        std.time.sleep(1e6);
    }
    if (ws.isOpen())
        while (!try ws.closeStep())
            std.time.sleep(1e6);
}

test "force inclusion" {
    _ = Server;
}
