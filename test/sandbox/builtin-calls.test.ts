import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { runtimeEnvironment } from "./fixtures/harness";
import { describe, expect, it } from "vitest";
import { createInvalidationHarness, outcomeText, useInvalidationCleanup } from "./fixtures/invalidation-harness";

useInvalidationCleanup();

describe("complete SDK builtin calls", () => {
  it("serializes two edits of the same file before either reaches a helper", async () => {
    const harness = await createInvalidationHarness();
    const target = join(harness.layout.workspace, "shared.txt");
    writeFileSync(target, "alpha beta");
    let started = 0;
    let entered!: () => void; const firstEntered = new Promise<void>(resolve => { entered = resolve; });
    let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
    const execute = harness.controller.execute.bind(harness.controller);
    harness.controller.execute = async input => {
      started++;
      if (started === 1) { entered(); await held; }
      return execute(input);
    };
    const first = harness.runCall("edit", "first-edit", { path: "@shared.txt", edits: [{ oldText: "alpha", newText: "gamma" }] });
    await firstEntered;
    const second = harness.runCall("edit", "second-edit", { path: target, edits: [{ oldText: "beta", newText: "delta" }] });
    try {
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(started).toBe(1);
    } finally { release(); }
    await Promise.all([first, second]);
    expect(readFileSync(target, "utf8")).toBe("gamma delta");
    expect(harness.records.map(record => record.state)).toEqual(["completed", "completed"]);
  }, 20_000);

  it("preserves the SDK error while recording a started execution failure", async () => {
    const harness = await createInvalidationHarness();
    const message = await outcomeText(harness.runCall("read", "missing-sdk-file", { path: "missing.txt" }));
    expect(message).toMatch(/ENOENT|no such file/i);
    expect(harness.records).toHaveLength(1);
    expect(harness.records[0]).toMatchObject({ state: "failed", started: true, code: "execution-failed" });
  });

  it("runs the SDK ls implementation in the complete-call process", async () => {
    const harness = await createInvalidationHarness();
    writeFileSync(join(harness.layout.workspace, "listed.txt"), "listed");
    const message = await outcomeText(harness.runCall("ls", "sdk-ls", { path: "." }));
    expect(message).toContain("listed.txt");
    expect(harness.records).toHaveLength(1);
    expect(harness.records[0]).toMatchObject({ state: "completed", toolName: "ls" });
  });

  it.each(["grep", "find"] as const)("runs the SDK %s implementation with its installed binary", async name => {
    const bin = join(getAgentDir(), "bin");
    if (name === "find") expect(existsSync(join(bin, process.platform === "win32" ? "fd.exe" : "fd")), "install the SDK fd prerequisite before this behavior check").toBe(true);
    const environment = runtimeEnvironment();
    const harness = await createInvalidationHarness({ environment: { ...environment, PATH: `${bin}${delimiter}${environment.PATH ?? ""}` } });
    writeFileSync(join(harness.layout.workspace, "found.txt"), "needle\n");
    const message = await outcomeText(harness.runCall(name, `sdk-${name}`, { path: ".", pattern: name === "grep" ? "needle" : "*.txt" }));
    expect(message, message).toContain("found.txt");
    expect(harness.records[0]).toMatchObject({ state: "completed", toolName: name });
  }, 20_000);

  it.skipIf(process.platform !== "win32")("runs the SDK PowerShell implementation in the complete-call process", async () => {
    const systemRoot = process.env.SystemRoot!;
    const harness = await createInvalidationHarness({ environment: { SystemRoot: systemRoot,
      PATH: join(systemRoot, "System32", "WindowsPowerShell", "v1.0") } });
    const message = await outcomeText(harness.runCall("powershell", "sdk-powershell", { command: "Write-Output 'controlled-powershell'" }));
    expect(message).toContain("controlled-powershell");
    expect(harness.records[0]).toMatchObject({ state: "completed", toolName: "powershell" });
  }, 20_000);
});
