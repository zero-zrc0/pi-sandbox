import { describe, expect, it } from "vitest";

import { sandboxToolFailureReason } from "#sandbox/pi";
import { SANDBOX_TOOL_TIMEOUT_MS } from "#sandbox/sandbox-tools";

/**
 * The documented per-call cap is 60 s, but the same `execution-timeout` code
 * also carries the native start timeout and a pre-start deadline refusal. Only
 * the plan-deadline reason may be reworded (design §6.4).
 */
describe("sandbox tool failure wording (design §6.4)", () => {
  it("names the restricted-mode per-call cap when the plan deadline expires", () => {
    expect(sandboxToolFailureReason({ code: "execution-timeout", reason: "execution deadline expired" }))
      .toBe(`sandbox tool timed out after ${SANDBOX_TOOL_TIMEOUT_MS / 1000}s`);
    expect(SANDBOX_TOOL_TIMEOUT_MS / 1000).toBe(60);
  });

  it.each([
    "start timed out",
    "plan deadline expired before the native process started",
  ])("keeps another execution-timeout reason intact: %s", (reason) => {
    expect(sandboxToolFailureReason({ code: "execution-timeout", reason })).toBe(reason);
  });

  it("keeps other failure codes intact", () => {
    expect(sandboxToolFailureReason({ code: "execution-failed", reason: "sandbox protocol failure" }))
      .toBe("sandbox protocol failure");
    expect(sandboxToolFailureReason({ code: "execution-cancelled", reason: "request was aborted" }))
      .toBe("request was aborted");
  });
});
