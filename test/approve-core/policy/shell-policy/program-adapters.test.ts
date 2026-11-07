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
});
