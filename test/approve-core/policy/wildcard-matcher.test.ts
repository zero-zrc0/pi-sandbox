import { describe, expect, it } from "vitest";
import {
  compileWildcard,
  wildcardMatch,
} from "#approve-core/policy/wildcard-matcher";

const WIN32 = { caseInsensitive: true, separatorEquivalence: true } as const;

describe("wildcard characters", () => {
  it("matches any run including empty and newlines with *", () => {
    expect(wildcardMatch("*", "")).toBe(true);
    expect(wildcardMatch("*", "a\nb")).toBe(true);
    expect(wildcardMatch("a*b", "ab")).toBe(true);
    expect(wildcardMatch("a*b", "a\nb")).toBe(true);
  });

  it("matches exactly one character including newline with ?", () => {
    expect(wildcardMatch("a?b", "axb")).toBe(true);
    expect(wildcardMatch("a?b", "a\nb")).toBe(true);
    expect(wildcardMatch("a?b", "ab")).toBe(false);
    expect(wildcardMatch("a?b", "axxb")).toBe(false);
  });

  it("treats other regex characters literally", () => {
    expect(wildcardMatch("a.b", "a.b")).toBe(true);
    expect(wildcardMatch("a.b", "axb")).toBe(false);
    expect(wildcardMatch("a+b(c)", "a+b(c)")).toBe(true);
    expect(wildcardMatch("$HOME/x", "$HOME/x")).toBe(true);
  });

  it("requires the whole value to match", () => {
    expect(wildcardMatch("git", "git status")).toBe(false);
    expect(wildcardMatch("git status", "git status")).toBe(true);
    expect(wildcardMatch("git", "git\n")).toBe(false);
  });
});

describe("optional trailing space and star", () => {
  it("makes the space and trailing arguments optional", () => {
    expect(wildcardMatch("git *", "git")).toBe(true);
    expect(wildcardMatch("git *", "git status")).toBe(true);
    expect(wildcardMatch("git *", "git status --short")).toBe(true);
    expect(wildcardMatch("git *", "gitx")).toBe(false);
  });

  it("does not treat a star without a preceding space as optional", () => {
    expect(wildcardMatch("git*", "git")).toBe(true);
    expect(wildcardMatch("git*", "gitz")).toBe(true);
    expect(wildcardMatch("git*", "gi")).toBe(false);
  });
});

describe("path-surface folding", () => {
  it("keeps case and separators significant without folding", () => {
    expect(wildcardMatch("C:\\Temp\\*", "c:/temp/x")).toBe(false);
    expect(wildcardMatch("/a/b", "/A/B")).toBe(false);
  });

  it("folds case and separators on both pattern and value", () => {
    expect(wildcardMatch("C:\\Temp\\*", "c:/temp/x", WIN32)).toBe(true);
    expect(wildcardMatch("C:/Temp/*", "C:\\TEMP\\x", WIN32)).toBe(true);
    expect(wildcardMatch("*.LOG", "run.log", WIN32)).toBe(true);
  });

  it("reports the original pattern rather than the compiled source", () => {
    expect(compileWildcard("git *").pattern).toBe("git *");
  });
});
