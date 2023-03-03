const std = @import("std");
const page_size = std.mem.page_size;

const frame_width = 800;
const frame_height = 480;

export fn initTempPage() void {
    temp_page = std.heap.page_allocator.create([page_size]u8) catch @panic("alloc failed");
}

export fn tempPageAdr() u32 {
    return @ptrToInt(temp_page);
}
var temp_page: *[page_size]u8 = undefined;

export fn init() void {
    const pa = std.heap.page_allocator;
    send_buf = pa.create([page_size]u8) catch @panic("alloc failed");
    recv_buf = pa.create([page_size]u8) catch @panic("alloc failed");
    frame_buf = pa.alloc(u32, frame_width * frame_height) catch @panic("alloc failed");
    fill(0xff000000);
}
var frame_buf: []u32 = undefined;
var recv_buf: *[page_size]u8 = undefined;
var send_buf: *[page_size]u8 = undefined;

export fn writeBufferAdrLen() i32 {
    const p = @ptrCast(*[6]u32, @alignCast(4, temp_page));
    p[0] = @ptrToInt(frame_buf.ptr);
    p[1] = frame_width * frame_height * 4;
    p[2] = @ptrToInt(recv_buf);
    p[3] = recv_buf.len;
    p[4] = @ptrToInt(send_buf);
    p[5] = send_buf.len;
    return p.len;
}

export fn frameWidth() u32 {
    return frame_width;
}

export fn frameHeight() u32 {
    return frame_height;
}

fn fill(v: u32) void {
    for (frame_buf) |*e|
        e.* = v;
}

export fn update(_: u32) void {
    const val: u32 = 0xff000000 | buf_change_idx % 64 << 10;
    fill(val);
    buf_change_idx +%= 1;
}

var buf_change_idx: u32 = 0;

export fn popShouldRender() bool {
    return true;
}

export fn pushReceived(_: u32) void {}
export fn setConnected(_: bool) void {}
export fn setInputPosition(_: i32, _: i32) void {}
export fn setInputPressed(_: bool) void {}
export fn setWheelDelta(_: i32) void {}
export fn setWheelPressed(_: bool) void {}
