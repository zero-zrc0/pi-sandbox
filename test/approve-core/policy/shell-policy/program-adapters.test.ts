import path from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeExternalProgram, resolveProgramExecutable } from "#approve-core/policy/shell-policy/program-adapters";

function adapted(program: string, argv: readonly string[]) {
  return analyzeExternalProgram({
    operationId: "call:op",
    unitId: "call:u0",
    shell: "bash",
    program,
    argv,
    cwd: process.cwd(),
    extent: { start: 0, end: 20 },
    environmentStable: true,
  });
}

function expectCompleteReadOnly(program: string, argv: readonly string[]): void {
  expect(adapted(program, argv).operation).toMatchObject({
    effects: { status: "known", value: ["file.read", "process.spawn"] },
    fileTargets: { status: "known", value: [{ path: process.cwd(), effect: "file.read" }] },
    networkTargets: { status: "known", value: [] },
    dynamicExecution: { status: "known", value: false },
    complete: true,
  });
}

function expectUnresolved(program: string, argv: readonly string[]): void {
  expect(adapted(program, argv).operation).toMatchObject({
    effects: { status: "unknown" },
    complete: false,
  });
}

describe("external program adapters", () => {
  it("resolves only a real executable identity from an unchanged command environment", () => {
    expect(resolveProgramExecutable(process.execPath, process.cwd()).status).toBe("known");
    expect(resolveProgramExecutable("git", process.cwd(), { environmentStable: false })).toMatchObject({
      status: "unknown",
      reason: "command-environment-changed",
    });
  });

  it("recognizes git status as a complete read-only operation", () => {
    const result = adapted("git", ["status"]);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["file.read", "process.spawn"] },
      fileTargets: { status: "known", value: [{ path: process.cwd(), effect: "file.read" }] },
      networkTargets: { status: "known", value: [] },
      complete: true,
    });
  });

  it.each([
    ["--pre", ["--pre", "cat"]],
    ["--pre=value", ["--pre=value"]],
  ])("keeps rg %s incomplete because it can spawn a preprocessor", (_label, argv) => {
    const result = adapted("rg", argv);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["process.spawn"] },
      dynamicExecution: { status: "known", value: true },
      complete: false,
    });
  });

  it("treats option-like text after -- as a path, not an rg option", () => {
    const result = adapted("rg", ["needle", "--", "--pre"]);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["file.read", "process.spawn"] },
      fileTargets: { status: "known", value: [{ path: expect.stringMatching(/[\\/]--pre$/), effect: "file.read" }] },
      complete: true,
    });
  });

  it("marks npm lifecycle commands as writes, network, and dynamic execution", () => {
    expect(adapted("npm", ["install"]).operation).toMatchObject({
      effects: { status: "known", value: ["file.create", "file.write", "network", "process.spawn"] },
      dynamicExecution: { status: "known", value: true },
      complete: false,
    });
    expect(adapted("npm", ["run", "build"]).operation).toMatchObject({
      effects: { status: "known", value: ["process.spawn"] },
      dynamicExecution: { status: "known", value: true },
      complete: false,
    });
  });

  it.each([
    { label: "git status --short", program: "git", argv: ["status", "--short"] },
    { label: "git log --oneline -n 5", program: "git", argv: ["log", "--oneline", "-n", "5"] },
    { label: "git branch --show-current", program: "git", argv: ["branch", "--show-current"] },
    { label: "git rev-parse --show-toplevel", program: "git", argv: ["rev-parse", "--show-toplevel"] },
  ])("recognizes $label as a complete read-only operation", ({ program, argv }) => {
    expectCompleteReadOnly(program, argv);
  });

  it.each([
    ["status --output=x", ["status", "--output=x"]],
    ["log -p", ["log", "-p"]],
    ["-c core.pager=cat status", ["-c", "core.pager=cat", "status"]],
    ["status somefile", ["status", "somefile"]],
    ["log --pretty=oneline", ["log", "--pretty=oneline"]],
  ])("keeps git %s unresolved", (_label, argv) => {
    expectUnresolved("git", argv);
  });

  it("recognizes rg with read-only options as a complete read", () => {
    expectCompleteReadOnly("rg", ["-n", "-i", "--glob", "*.ts", "--", "needle"]);
  });

  it("recognizes rg read-only options with attached values", () => {
    const result = adapted("rg", ["-A3", "-ePATTERN", "--color=never", "--", "needle"]);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["file.read", "process.spawn"] },
      fileTargets: {
        status: "known",
        value: [{ path: path.resolve(process.cwd(), "needle"), effect: "file.read" }],
      },
      complete: true,
    });
  });

  it("keeps resolving rg positional paths after the pattern against the working directory", () => {
    const result = adapted("rg", ["-n", "needle", "src"]);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["file.read", "process.spawn"] },
      fileTargets: {
        status: "known",
        value: [{ path: path.resolve(process.cwd(), "src"), effect: "file.read" }],
      },
      complete: true,
    });
  });

  it("treats every positional as a path when -e supplies the pattern", () => {
    const result = adapted("rg", ["-e", "needle", "src"]);

    expect(result.operation).toMatchObject({
      effects: { status: "known", value: ["file.read", "process.spawn"] },
      fileTargets: {
        status: "known",
        value: [{ path: path.resolve(process.cwd(), "src"), effect: "file.read" }],
      },
      complete: true,
    });
  });

  it.each([
    ["-f/--file option", ["-f", "patterns", "needle"]],
    ["stdin marker", ["-", "needle"]],
    ["unknown option", ["--sort-files", "needle"]],
  ])("keeps rg with an unsupported %s incomplete", (_label, argv) => {
    expectUnresolved("rg", argv);
  });
});
