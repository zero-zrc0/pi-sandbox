import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import type { BackendCapabilities } from "#sandbox/types";
import type { HelperProbeResult } from "#sandbox/lifecycle";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";
import { prepareMacOSHelperProcess } from "#sandbox/backend/macos/index";

const harness = vi.hoisted(() => ({
  options: undefined as unknown,
  result: undefined as unknown,
}));

// The probe only needs the controller's construction options and its probe
// verdict; a stub keeps this a pure unit test of platform branching.
vi.mock("#sandbox/lifecycle", () => ({
  ExecutionController: class {
    constructor(options: unknown) { harness.options = options; }
    async probe(): Promise<unknown> { return harness.result; }
    async dispose(): Promise<void> {}
  },
}));

interface CapturedControllerOptions {
  readonly installation: {
    readonly installRoot: string;
    readonly executable: string;
    readonly args?: readonly string[];
    readonly expectedProtocolVersion?: number;
    readonly expectedBackendId?: string;
  };
  readonly helperCwd: string;
  readonly workspace?: string;
  readonly helperEnvironment: Readonly<Record<string, string>>;
  readonly prepareHelperProcess?: unknown;
  readonly probeTimeoutMs?: number;
}

const workspaceRoot = "/tmp/pi-sandbox-probe-workspace";
const darwinRuntime = {
  directory: "/Users/test/Library/Application Support/pi-sandbox/runtimes/darwin-arm64",
  storageRoot: "/Users/test/Library/Application Support/pi-sandbox",
  source: "manual" as const,
  manifest: {
    schemaVersion: 1 as const,
    version: "1.0.1",
    stable: true as const,
    platform: "darwin",
    arch: "arm64",
    protocolVersion: 2,
    minPluginVersion: "0.0.0",
    maxPluginVersionExclusive: "999999.999.999",
    backendId: "macos-seatbelt",
    files: [],
  },
  files: {},
};
const linuxRuntime = {
  ...darwinRuntime,
  directory: "/tmp/pi-sandbox-linux-runtime",
  manifest: {
    ...darwinRuntime.manifest,
    platform: "linux",
    backendId: "linux-bwrap-landlock-seccomp",
  },
};

function capabilities(overrides: Partial<BackendCapabilities> = {}): BackendCapabilities {
  return {
    filesystem: { read: true, write: true, granularity: "file", protectedPaths: true, environment: true },
    network: "none",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
    ...overrides,
  };
}

function probeResult(overrides: Partial<BackendCapabilities> = {}, id = "macos-seatbelt"): HelperProbeResult {
  return {
    status: "available",
    backend: { id, version: "1.0.0" },
    capabilities: capabilities(overrides),
    protocolVersion: 2,
  };
}

function capture(): CapturedControllerOptions {
  return harness.options as CapturedControllerOptions;
}

function probe(runtime: typeof darwinRuntime | typeof linuxRuntime, signal = new AbortController().signal) {
  return probeSandboxRuntime({ runtime, workspaceRoot, signal });
}

describe("probeSandboxRuntime", () => {
  it("probes the macOS helper through the Seatbelt wrapper without runtime directories", async () => {
    harness.result = probeResult();

    expect(await probe(darwinRuntime)).toEqual({ available: true });

    const options = capture();
    expect(options.installation.args?.[0]).toBe(
      fileURLToPath(new URL("../../src/sandbox/backend/macos/helper.mjs", import.meta.url)),
    );
    expect(options.installation.expectedBackendId).toBe("macos-seatbelt");
    expect(options.installation.expectedProtocolVersion).toBe(2);
    expect(options.prepareHelperProcess).toBe(prepareMacOSHelperProcess);
    expect(options.helperEnvironment).toMatchObject({
      HOME: process.env.HOME,
      PI_SANDBOX_WORKSPACE_ROOT: workspaceRoot,
    });
    expect(options.helperEnvironment).not.toHaveProperty("PI_SANDBOX_RUNTIME_DIR");
    expect(options.helperEnvironment).not.toHaveProperty("PI_SANDBOX_RUNTIME_ROOT");
    expect(options.workspace).toBe(workspaceRoot);
  });

  it("reports an unusable macOS system runtime with the probe reason", async () => {
    harness.result = { status: "missing", reason: "helper executable is missing: /usr/bin/sandbox-exec" };

    expect(await probe(darwinRuntime)).toEqual({
      available: false,
      reason: "helper executable is missing: /usr/bin/sandbox-exec",
    });
  });

  it("rejects a macOS backend that is not strictly no-network and complete", async () => {
    harness.result = probeResult({ network: "domains", streamOutput: false });

    expect(await probe(darwinRuntime)).toEqual({
      available: false,
      reason: "runtime lacks required capabilities: no-network default, streamed output",
    });
  });

  it("keeps the linux capability gate and runtime environment unchanged", async () => {
    harness.result = probeResult({ network: "domains", streamOutput: false }, "linux-bwrap-landlock-seccomp");

    expect(await probe(linuxRuntime)).toEqual({ available: true });

    const options = capture();
    expect(options.installation.args?.[0]).toBe(
      fileURLToPath(new URL("../../src/sandbox/backend/linux/helper.mjs", import.meta.url)),
    );
    expect(options.installation.expectedBackendId).toBe("linux-bwrap-landlock-seccomp");
    expect(options.prepareHelperProcess).toBeUndefined();
    expect(options.helperEnvironment).toMatchObject({
      PI_SANDBOX_RUNTIME_DIR: linuxRuntime.directory,
      PI_SANDBOX_RUNTIME_ROOT: linuxRuntime.storageRoot,
      PI_SANDBOX_WORKSPACE_ROOT: workspaceRoot,
    });
  });

  it("still requires controlled network egress on linux", async () => {
    harness.result = probeResult({ network: "none" }, "linux-bwrap-landlock-seccomp");

    expect(await probe(linuxRuntime)).toEqual({
      available: false,
      reason: "runtime lacks required capabilities: controlled network egress",
    });
  });

  it("returns unavailable when the probe is cancelled", async () => {
    harness.result = probeResult();
    const controller = new AbortController();
    controller.abort();

    expect(await probe(darwinRuntime, controller.signal)).toEqual({
      available: false,
      reason: "runtime probe was cancelled",
    });
  });
});
