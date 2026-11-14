import { describe, expect, it } from "vitest";
import { CODEMODE_RUNTIME_LIMITS } from "#sandbox/codemode/limits";

describe("Codemode Runtime limits", () => {
  it("freezes finite process, nested-call, and model-request capacity", () => {
    expect(CODEMODE_RUNTIME_LIMITS).toMatchObject({
      defaultMaxActiveRuntimes: 2,
      maxConfiguredActiveRuntimes: 8,
      maxQueuedRuntimes: 8,
      runtimeQueueWaitMs: 60_000,
      maxNestedCallsPerRuntime: 100_000,
      maxConcurrentNestedCallsPerRuntime: 64,
      maxConcurrentModelCallsPerRuntime: 4,
    });
  });

  it("keeps two logical messages within each bounded transport queue", () => {
    expect(CODEMODE_RUNTIME_LIMITS).toMatchObject({
      protocolVersion: 1,
      maxFrameBytes: 16 * 1024 * 1024,
      fragmentBytes: 8 * 1024 * 1024,
      maxLogicalMessageBytes: 128 * 1024 * 1024,
      maxQueuedMessageBytes: 2 * CODEMODE_RUNTIME_LIMITS.maxLogicalMessageBytes,
      maxDiagnosticBytes: 16 * 1024,
      quickJsMemoryBytes: 256 * 1024 * 1024,
    });
  });
});
