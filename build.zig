const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("cobalt", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "cobalt",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "cobalt",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const runCmd = b.addRunArtifact(exe);
    runCmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        runCmd.addArgs(args);
    }

    const runStep = b.step("run", "Run the cobalt CLI");
    runStep.dependOn(&runCmd.step);

    const bench = b.addExecutable(.{
        .name = "cobalt-bench",
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(bench);

    const benchCmd = b.addRunArtifact(bench);
    benchCmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        benchCmd.addArgs(args);
    }

    const benchStep = b.step("bench", "Run the throughput benchmark");
    benchStep.dependOn(&benchCmd.step);

    const libUnitTests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const runLibUnitTests = b.addRunArtifact(libUnitTests);

    const exeUnitTests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cliPaths = b.addOptions();
    cliPaths.addOptionPath("cobaltExe", exe.getEmittedBin());
    exeUnitTests.root_module.addOptions("cliPaths", cliPaths);
    const runExeUnitTests = b.addRunArtifact(exeUnitTests);

    const testStep = b.step("test", "Run unit tests");
    testStep.dependOn(&runLibUnitTests.step);
    testStep.dependOn(&runExeUnitTests.step);
}
