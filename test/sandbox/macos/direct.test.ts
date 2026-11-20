import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExecutionOperation, ExecutionRequest } from "#sandbox/types";

const seatbelt = vi.hoisted(() => ({
  buildSeatbeltProfile: vi.fn(() => ({ ok: true as const, profile: "test-profile" })),
  probeMacOSSeatbelt: vi.fn(() => ({ status: "candidate-present" as const, executable: "/usr/bin/sandbox-exec" as const,
    defaultDenyProbePassed: true as const, nativeMatrixVerified: false as const })),
  MACOS_SANDBOX_EXEC_PATH: "/usr/bin/sandbox-exec",
}));
vi.mock("../../../src/sandbox/backend/macos/seatbelt", () => seatbelt);

import { EXECUTION_INSTALL_ROOT } from "#sandbox/platform";
import { createMacOSDirectBackend } from "#sandbox/backend/macos/direct";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  seatbelt.buildSeatbeltProfile.mockClear();
  seatbelt.probeMacOSSeatbelt.mockClear();
});

function makeRequest(operation: ExecutionOperation, workingDirectory?: string): ExecutionRequest {
  const cwd = workingDirectory ?? mkdtempSync(join(tmpdir(), "pi-sandbox-macos-direct-"));
  if (!roots.includes(cwd)) roots.push(cwd);
  return {
    plan: { version: 3, filesystem: [], network: { kind: "none" }, metadataRead: "all", digest: "test-plan" },
    requestId: "request-1",
    toolCallId: "call-1",
    actionDigest: "action",
    sessionId: "session",
    toolName: operation.kind === "builtin-tool" ? operation.name : operation.kind,
    mode: "default",
    policyRevision: "policy",
    configRevision: "config",
    backendId: "macos-seatbelt",
    start: { cwd, operation, environment: { HOME: cwd, PATH: "/usr/bin:/bin" }, deadlineAt: Date.now() + 10_000 },
  };
}

describe("macOS host-native launch preparation", () => {
  it("runs builtin tools as the target Node worker under Seatbelt", async () => {
    const driver = createMacOSDirectBackend({ installRoot: EXECUTION_INSTALL_ROOT, hostEnvironment: {} });
    const request = makeRequest({ kind: "builtin-tool", name: "read", arguments: { path: "sample.txt" } });

    const result = await driver.prepare(request);

    expect(result).toMatchObject({ executable: "/usr/bin/sandbox-exec", outputMode: "worker" });
    if ("ok" in result) throw new Error(result.reason);
    expect(result.args.slice(0, 3)).toEqual(["-p", "test-profile", realpathSync(process.execPath)]);
    expect(result.args[3]).toMatch(/builtin-worker\.bundle\.mjs$/u);
    expect(JSON.parse(result.input ?? "{}")).toMatchObject({ kind: "builtin-tool", toolCallId: "call-1" });
    expect(seatbelt.buildSeatbeltProfile).toHaveBeenCalledWith(expect.objectContaining({
      plan: request.plan,
      cwd: request.start.cwd,
    }));
  });

  it("keeps direct shell operations on the selected shell process", async () => {
    const driver = createMacOSDirectBackend({ installRoot: EXECUTION_INSTALL_ROOT, hostEnvironment: {} });
    const request = makeRequest({ kind: "shell", shell: "/bin/sh", command: "printf direct-shell" });

    const result = await driver.prepare(request);

    expect(result).toMatchObject({ executable: "/usr/bin/sandbox-exec", outputMode: "stream" });
    if ("ok" in result) throw new Error(result.reason);
    expect(result.args.slice(0, 4)).toEqual(["-p", "test-profile", "/bin/sh", "-c"]);
  });

  it("runs internal file operations through a worker that stays inside Seatbelt", async () => {
    const driver = createMacOSDirectBackend({ installRoot: EXECUTION_INSTALL_ROOT, hostEnvironment: {} });
    const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-macos-direct-"));
    roots.push(cwd);
    const request = makeRequest({ kind: "read-file", path: join(cwd, "sample.txt") }, cwd);

    const result = await driver.prepare(request);

    expect(result).toMatchObject({ executable: "/usr/bin/sandbox-exec", outputMode: "capture" });
    if ("ok" in result) throw new Error(result.reason);
    expect(result.args[3]).toMatch(/operation-worker\.mjs$/u);
    expect(result.readyMarker).toBe("\x1ePI-MACOS-OPERATION-READY\x1f");
  });
});
