import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { BackendCapabilities } from "#sandbox/types";
import type { BackendProbeResult } from "#sandbox/lifecycle";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";

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
  readonly directBackend?: { readonly id: string; readonly version: string };
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
    protocolVersion: 3,
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
    filesystem: { read: true, write: true, granularity: "file", protectedPaths: true, environment: true, metadataRead: "all" },
    network: "none",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
    ...overrides,
  };
}

function probeResult(overrides: Partial<BackendCapabilities> = {}, id = "macos-seatbelt"): BackendProbeResult {
  return {
    status: "available",
    backend: { id, version: "1.0.0" },
    capabilities: capabilities(overrides),
  };
}

function capture(): CapturedControllerOptions {
  return harness.options as CapturedControllerOptions;
}

function probe(runtime: typeof darwinRuntime | typeof linuxRuntime, signal = new AbortController().signal) {
  return probeSandboxRuntime({ runtime, workspaceRoot, signal });
}

describe("probeSandboxRuntime", () => {
  it("probes the host-native macOS backend without runtime directories", async () => {
    harness.result = probeResult();

    expect(await probe(darwinRuntime)).toEqual({ available: true });

    const options = capture();
    expect(options.directBackend).toMatchObject({ id: "macos-seatbelt", version: "1.0.0" });
  });

  it("reports an unusable macOS system runtime with the probe reason", async () => {
    harness.result = { status: "unavailable", reason: "sandbox-exec is unavailable" };

    expect(await probe(darwinRuntime)).toEqual({
      available: false,
      reason: "sandbox-exec is unavailable",
    });
  });

  it("rejects a macOS backend that is not strictly no-network and complete", async () => {
    harness.result = probeResult({ network: "domains", streamOutput: false });

    expect(await probe(darwinRuntime)).toEqual({
      available: false,
      reason: "runtime lacks required capabilities: no-network default, streamed output",
    });
  });

  it("probes the host-native Linux backend with the runtime environment", async () => {
    harness.result = probeResult({ network: "domains", streamOutput: false }, "linux-bwrap-landlock-seccomp");

    expect(await probe(linuxRuntime)).toEqual({ available: true });

    const options = capture();
    expect(options.directBackend).toMatchObject({ id: "linux-bwrap-landlock-seccomp", version: "1.1.0" });
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
