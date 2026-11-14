import { describe, expect, it } from "vitest";
import { mergeEffectProofs, proof } from "#approve-core/utils/access-intent/effect";

describe("mergeEffectProofs", () => {
  it("keeps a matching effect and prefers the more diagnostic source", () => {
    const merged = mergeEffectProofs(proof("read", "global-declared"), proof("read", "builtin-core"));
    expect(merged.effect).toBe("read");
    expect(merged.source).toBe("builtin-core");
  });

  it("is symmetric in argument order", () => {
    const a = proof("read", "syntax");
    const b = proof("read", "project-declared");
    expect(mergeEffectProofs(a, b)).toEqual(mergeEffectProofs(b, a));
  });

  it("keeps a retraction detail over a bare source of the same rank", () => {
    const withDetail = proof("unproven", "declaration-retracted", "option:-i");
    const without = proof("unproven", "declaration-retracted");
    expect(mergeEffectProofs(withDetail, without).detail).toBe("option:-i");
  });

  it("collapses disagreeing effects to unproven regardless of sources", () => {
    for (const [a, b] of [
      [proof("read", "syntax"), proof("write", "syntax")],
      [proof("read", "builtin-core"), proof("write", "global-declared")],
    ] as const) {
      expect(mergeEffectProofs(a, b).effect).toBe("unproven");
    }
  });
});
