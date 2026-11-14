import { describe, expect, it } from "vitest";
import { allTruth, anyTruth, notTruth } from "#approve-core/policy/shell-policy/truth";

describe("shell policy three-valued logic", () => {
  it("keeps unknown under negation", () => {
    expect(notTruth("unknown")).toBe("unknown");
  });

  it("lets false dominate all and true dominate any", () => {
    expect(allTruth(["unknown", "false"])).toBe("false");
    expect(anyTruth(["unknown", "true"])).toBe("true");
  });

  it("returns unknown when no decisive value exists", () => {
    expect(allTruth(["true", "unknown"])).toBe("unknown");
    expect(anyTruth(["false", "unknown"])).toBe("unknown");
  });
});
