const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("webfb", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const wasm_lib = b.addSharedLibrary("webfb", "src/webfb_wasm.zig", .unversioned);
    const wasm_target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "wasm32-freestanding" }) catch unreachable;
    wasm_lib.setTarget(wasm_target);
    wasm_lib.setBuildMode(.ReleaseFast);
    wasm_lib.rdynamic = true;
    wasm_lib.strip = true;
    const wasm_page_size = 1 << 16;
    wasm_lib.global_base = 8 * wasm_page_size;
    wasm_lib.override_dest_dir = .{ .custom = "../web-root" };
    wasm_lib.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}
