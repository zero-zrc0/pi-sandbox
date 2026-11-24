import { describe, expect, it } from "vitest";
import { formatPiSandboxError } from "../src/error-format";

describe("formatPiSandboxError", () => {
  it("returns the message as-is without adding a prefix", () => {
    expect(formatPiSandboxError("permission:protected-control-path: C:\\x\\.git\\config"))
      .toBe("permission:protected-control-path: C:\\x\\.git\\config");
  });

  it("strips the legacy marker but keeps the detail", () => {
    expect(formatPiSandboxError("[pi-sandbox-error] : sandbox-bypass:protected-target: C:\\x"))
      .toBe("sandbox-bypass:protected-target: C:\\x");
  });

  it("normalizes Error values and empty text", () => {
    expect(formatPiSandboxError(new Error("boom"))).toBe("boom");
    expect(formatPiSandboxError("   ")).toBe("Unknown error");
  });
});
