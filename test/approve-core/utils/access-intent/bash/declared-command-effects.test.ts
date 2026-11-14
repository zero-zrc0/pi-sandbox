import { describe, expect, it } from "vitest";
import { declaredCommandEffect } from "#approve-core/utils/access-intent/bash/declared-command-effects";
import type { CommandWord } from "#approve-core/utils/access-intent/bash/wrapper-analysis";

function words(...values: string[]): CommandWord[] {
  return values.map((value) => ({ value, computed: false, mayLeadWithDash: value.startsWith("-") }));
}

describe("declared command effects", () => {
  it("uses project declarations in preference to global entries", () => {
    const declarations = {
      global: { tool: { effects: ["read"] as const } },
      project: { tool: { effects: ["write"] as const } },
    };
    expect(declaredCommandEffect(words("tool", "file"), declarations)).toEqual({ effect: "write", source: "project-declared" });
  });

  it("selects nested subcommand declarations by leading literal words", () => {
    const declarations = { global: { tool: { effects: ["read"] as const, subcommands: { put: { subcommands: { file: ["write"] as const } } } } } };
    expect(declaredCommandEffect(words("tool", "put", "file", "target"), declarations)?.effect).toBe("write");
    expect(declaredCommandEffect(words("tool", "status"), declarations)?.effect).toBe("read");
  });

  it("withdraws nested effects when any selected level guards an option", () => {
    const declarations = { global: { tool: { unlessOption: ["--output"], subcommands: { show: { effects: ["read"] as const } } } } };
    expect(declaredCommandEffect(words("tool", "show", "--out=file"), declarations)).toEqual({ effect: "unknown", source: "declaration-retracted" });
  });

  it("ignores declarations for core commands and wrappers", () => {
    const declarations = { project: { sort: { effects: ["read"] as const }, sudo: { effects: ["read"] as const } } };
    expect(declaredCommandEffect(words("sort", "-o", "output"), declarations)).toBeUndefined();
    expect(declaredCommandEffect(words("sudo", "tool"), declarations)).toBeUndefined();
  });

  it("accepts a single-effect shorthand for a subcommand", () => {
    const declarations = { global: { tool: { subcommands: { show: "read" as const } } } };
    expect(declaredCommandEffect(words("tool", "show", "file"), declarations)?.effect).toBe("read");
  });

  it("treats repeated identical directions as one declared effect", () => {
    const declarations = { global: { tool: { effects: ["read", "read"] as const } } };
    expect(declaredCommandEffect(words("tool", "file"), declarations)).toEqual({ effect: "read", source: "global-declared" });
  });

  it("does not choose one direction when both read and write are declared", () => {
    const declarations = { project: { tool: { effects: ["read", "write"] as const } } };
    expect(declaredCommandEffect(words("tool", "file"), declarations)).toEqual({ effect: "unknown", source: "project-declared" });
  });
});
