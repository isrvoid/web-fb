const std = @import("std");

export fn init() void {
    frame_buf = std.heap.page_allocator.alloc(u32, image_width * image_height) catch unreachable;
    fill(0xff000000);
}

var frame_buf: []u32 = undefined;
const image_width = 800;
const image_height = 480;

export fn bufferAddress() u32 {
    return @intCast(u32, @ptrToInt(frame_buf.ptr));
}

export fn bufferSize() u32 {
    return image_width * image_height * 4;
}

export fn imageWidth() u32 {
    return image_width;
}

export fn imageHeight() u32 {
    return image_height;
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

export fn popShouldDraw() bool {
    return true;
}

export fn setInputPosition(_: i32, _: i32) void {}
export fn setInputPressed(_: bool) void {}
