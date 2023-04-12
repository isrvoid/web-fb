const std = @import("std");

pub const Content = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        open: *const fn (*anyopaque, path: []const u8) anyerror!Properties,
        close: *const fn (*anyopaque) void,
        nextChunk: *const fn (*anyopaque) anyerror![]const u8,
    };

    pub const Type = enum {
        html,
        javascript,
        webassembly,
        text,
        binary,
    };

    const Properties = struct {
        cont_type: Type,
        len: usize,
    };

    pub fn open(self: Content, path: []const u8) !Properties {
        return self.vtable.open(self.ptr, path);
    }

    pub fn close(self: Content) void {
        return self.vtable.close(self.ptr);
    }

    pub fn nextChunk(self: Content) ![]const u8 {
        return self.vtable.nextChunk(self.ptr);
    }
};

pub const DirContent = struct {
    dir: []const u8,
    buf: [0x1000]u8 = undefined,
    file: std.fs.File = undefined,
    is_open: bool = false,

    const Self = @This();

    pub fn content(self: *Self) Content {
        return .{
            .ptr = self,
            .vtable = &.{
                .open = open,
                .close = close,
                .nextChunk = nextChunk,
            },
        };
    }

    pub fn open(ctx: *anyopaque, sub_path: []const u8) !Content.Properties {
        const self = @ptrCast(*Self, @alignCast(@alignOf(Self), ctx));
        std.debug.assert(!self.is_open);
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&path_buf);
        const path = try std.fs.path.join(fba.allocator(), &[2][]const u8{ self.dir, sub_path });
        self.file = try std.fs.cwd().openFile(path, .{});
        const len = @intCast(usize, try self.file.getEndPos());
        self.is_open = true;
        return .{ .cont_type = contentType(path), .len = len };
    }

    pub fn close(ctx: *anyopaque) void {
        const self = @ptrCast(*Self, @alignCast(@alignOf(Self), ctx));
        std.debug.assert(self.is_open);
        self.file.close();
        self.is_open = false;
    }

    pub fn nextChunk(ctx: *anyopaque) ![]const u8 {
        const self = @ptrCast(*Self, @alignCast(@alignOf(Self), ctx));
        const n = try self.file.read(&self.buf);
        return self.buf[0..n];
    }

    fn contentType(path: []const u8) Content.Type {
        const endsWith = std.mem.endsWith;
        if (endsWith(u8, path, ".html")) return .html;
        if (endsWith(u8, path, ".js")) return .javascript;
        if (endsWith(u8, path, ".wasm")) return .webassembly;
        if (endsWith(u8, path, ".txt")) return .text;
        return .binary;
    }
};

pub const ListContent = struct {
    entries: []const Entry,
    read_i: usize = undefined,
    current: []const u8 = undefined,

    pub const Entry = struct {
        name: []const u8,
        cont: []const u8,
        cont_type: Content.Type,
    };
    const max_chunk_size = 0x1000;
    const Self = @This();

    pub fn content(self: *Self) Content {
        return .{
            .ptr = self,
            .vtable = &.{
                .open = open,
                .close = close,
                .nextChunk = nextChunk,
            },
        };
    }

    pub fn open(ctx: *anyopaque, name: []const u8) !Content.Properties {
        const self = @ptrCast(*Self, @alignCast(@alignOf(Self), ctx));
        for (self.entries) |e| {
            if (std.mem.eql(u8, name, e.name)) {
                self.read_i = 0;
                self.current = e.cont;
                return .{ .cont_type = e.cont_type, .len = e.cont.len };
            }
        }
        return error.FileNotFound;
    }

    pub fn close(_: *anyopaque) void {}

    pub fn nextChunk(ctx: *anyopaque) ![]const u8 {
        const self = @ptrCast(*Self, @alignCast(@alignOf(Self), ctx));
        const chunk_end = @min(self.read_i + max_chunk_size, self.current.len);
        defer self.read_i = chunk_end;
        return self.current[self.read_i..chunk_end];
    }
};
