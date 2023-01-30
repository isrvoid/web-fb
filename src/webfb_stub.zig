const std = @import("std");

const buffer = @intToPtr([*]align(4) u8, buffer_adr);

export fn init() void {
    const num_pages_required = (buffer_adr + bufferSize()) / std.mem.page_size + 1;
    const num_pages = @wasmMemorySize(0);
    if (num_pages < num_pages_required)
        if (@wasmMemoryGrow(0, num_pages_required - num_pages) == -1)
            @panic("Failed to increase memory");

    fill(0xff000000);
}

const buffer_adr = std.mem.page_size * 16; // global_base set to page 8 in build.zig
const image_width = 800;
const image_height = 480;

export fn bufferAddress() u32 {
    return buffer_adr;
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
