import { describe, expect, it } from "vitest";
import { expandHome, splitHomePrefix } from "#approve-core/utils/path/expand-home";

const HOME = "/home/user";

describe("splitHomePrefix", () => {
  it("splits supported prefixes without touching the rest", () => {
    expect(splitHomePrefix("~", HOME)).toEqual({ prefix: HOME, rest: "" });
    expect(splitHomePrefix("~/a/b", HOME)).toEqual({ prefix: HOME, rest: "/a/b" });
    expect(splitHomePrefix("~\\x", HOME)).toEqual({ prefix: HOME, rest: "\\x" });
    expect(splitHomePrefix("$HOME", HOME)).toEqual({ prefix: HOME, rest: "" });
    expect(splitHomePrefix("$HOME/y", HOME)).toEqual({ prefix: HOME, rest: "/y" });
    expect(splitHomePrefix("${HOME}", HOME)).toEqual({ prefix: HOME, rest: "" });
    expect(splitHomePrefix("${HOME}/z", HOME)).toEqual({ prefix: HOME, rest: "/z" });
  });

  it("refuses unsupported forms", () => {
    for (const literal of ["~user", "$HOMEDIR", "${HOME:-/x}", "~x/y", "abc~/y", ""]) {
      expect(splitHomePrefix(literal, HOME)).toBeUndefined();
    }
  });
});

describe("expandHome", () => {
  it("expands supported prefixes", () => {
    expect(expandHome("~", HOME)).toBe(HOME);
    expect(expandHome("~/x", HOME)).toBe(`${HOME}/x`);
    expect(expandHome("$HOME/x", HOME)).toBe(`${HOME}/x`);
    expect(expandHome("${HOME}/x y", HOME)).toBe(`${HOME}/x y`);
  });

  it("keeps the rest unnormalized", () => {
    expect(expandHome("~/a/../b", HOME)).toBe(`${HOME}/a/../b`);
  });

  it("does not double separators when home ends with one", () => {
    expect(expandHome("~/x", `${HOME}/`)).toBe(`${HOME}/x`);
  });

  it("passes through unsupported forms", () => {
    expect(expandHome("~user/x", HOME)).toBe("~user/x");
    expect(expandHome("${HOME:-/x}", HOME)).toBe("${HOME:-/x}");
  });
});
