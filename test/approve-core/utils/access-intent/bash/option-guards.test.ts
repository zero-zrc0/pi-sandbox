import { describe, expect, it } from "vitest";
import { hasGuardedOption } from "#approve-core/utils/access-intent/bash/option-guards";

describe("option guards", () => {
  it("recognizes abbreviated and attached long options", () => {
    expect(hasGuardedOption([{ value: "--out=file", computed: false, mayLeadWithDash: true }], ["--output"])).toBe(true);
    expect(hasGuardedOption([{ value: "--other", computed: false, mayLeadWithDash: true }], ["--output"])).toBe(false);
  });

  it("recognizes guarded short options inside clusters", () => {
    expect(hasGuardedOption([{ value: "-nro", computed: false, mayLeadWithDash: true }], ["-o"])).toBe(true);
    expect(hasGuardedOption([{ value: "-nr", computed: false, mayLeadWithDash: true }], ["-o"])).toBe(false);
  });

  it("treats a computed dash-leading argument as uncertain", () => {
    expect(hasGuardedOption([{ value: "$option", computed: true, mayLeadWithDash: true }], ["--output"])).toBe(true);
    expect(hasGuardedOption([{ value: "file$part", computed: true, mayLeadWithDash: false }], ["--output"])).toBe(false);
  });

  it("matches single-dash long words and attached suffixes", () => {
    expect(hasGuardedOption([{ value: "-fprint0", computed: false, mayLeadWithDash: true }], ["-fprint"])).toBe(true);
    expect(hasGuardedOption([{ value: "--", computed: false, mayLeadWithDash: true }], ["--output"])).toBe(false);
  });
});
