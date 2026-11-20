import { describe, expect, it } from "vitest";

import { shellSandboxCapability } from "#sandbox/capability";
import type { RequiredCapabilities } from "#sandbox/backend/capabilities";
import type { BackendProbeResult } from "#sandbox/lifecycle";
import type { BackendCapabilities } from "#sandbox/types";
import { makeInvocation } from "./fixtures/harness";

const requirements: RequiredCapabilities = {
  read: true,
  write: true,
  fileGranularity: true,
  protectedPaths: true,
  environment: true,
  metadataRead: "all",
  network: "domains",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: true,
};

const capabilities: BackendCapabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "file",
    protectedPaths: true,
    environment: true,
    metadataRead: "all",
  },
  network: "domains",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: true,
};

function binding() {
  const invocation = makeInvocation({
    cwd: "C:\\work\\project",
    toolName: "bash",
    args: { command: "echo ok" },
  });
  if (invocation.executionBinding.status !== "bound") {
    throw new Error("fixture invocation is not bound");
  }
  return {
    actionDigest: invocation.digest,
    executionBinding: invocation.executionBinding,
  };
}

describe("assessment capability adapter", () => {
  it("maps a complete probe to an available host-named boundary", () => {
    const proof = binding();
    const result = shellSandboxCapability({
      probe: {
        status: "available",
        backend: { id: "fixture-direct", version: "1.0.0" },
        capabilities,
      },
      requirements,
      boundary: "windows-restricted-token",
      ...proof,
    });
    expect(result).toMatchObject({
      available: true,
      enforcesAllLimits: true,
      boundary: "windows-restricted-token",
      actionDigest: proof.actionDigest,
      executionBinding: proof.executionBinding,
    });
  });

  it("does not upgrade an unavailable or coarse backend", () => {
    const proof = binding();
    const coarse = shellSandboxCapability({
      probe: {
        status: "available",
        backend: { id: "fixture-direct", version: "1.0.0" },
        capabilities: { ...capabilities, processTree: false },
      },
      requirements,
      boundary: "fixture-direct",
      ...proof,
    });
    expect(coarse).toMatchObject({
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
    });
    expect(coarse.reason).toContain("process-tree");

    const missing: BackendProbeResult = {
      status: "unavailable",
      reason: "native backend is unavailable",
    };
    expect(
      shellSandboxCapability({
        probe: missing,
        requirements,
        boundary: "windows-restricted-token",
        ...proof,
      }),
    ).toMatchObject({
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
      reason: missing.reason,
    });
  });

  it("refuses to record an unnamed boundary", () => {
    const proof = binding();
    expect(
      shellSandboxCapability({
        probe: {
          status: "available",
          backend: { id: "fixture-direct", version: "1.0.0" },
          capabilities,
        },
        requirements,
        boundary: " ",
        ...proof,
      }),
    ).toMatchObject({
      available: false,
      boundary: "none",
    });
  });
});
