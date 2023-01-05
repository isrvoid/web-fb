const std = @import("std");

extern fn print(i32) void;

const buffer = @intToPtr([*]align(4) u8, buffer_offset);

export fn init() void {
    // TODO maybe reserve memory
    fill(0xff000000);
}

const buffer_offset = 1 << 12;
const image_width = 320;
const image_height = 240;

export fn bufferOffset() u32 {
    return buffer_offset;
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
    const buf = @ptrCast([*]u32, buffer)[0 .. image_width * image_height];
    for (buf) |*e|
        e.* = v;
}

// TODO remove
export fn testTransitionStep() void {
    const buf = @ptrCast([*]u32, buffer)[0 .. image_width * image_height];
    const val: u32 = 0xff000000 | buf_change_idx % 64 << 10;
    for (buf) |*e|
        e.* = val;

    buf_change_idx +%= 1;
}

var buf_change_idx: u32 = 0;
