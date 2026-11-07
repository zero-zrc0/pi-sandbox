import { describe, expect, it } from "vitest";
import {
  pathFlavorForPlatform,
  POSIX_PATH_FLAVOR as POSIX,
  WIN32_PATH_FLAVOR as WIN32,
} from "#approve-core/utils/path/path-flavor";

describe("path flavor selection", () => {
  it("provides exactly two languages selected by explicit platform", () => {
    expect(pathFlavorForPlatform("win32").kind).toBe("win32");
    expect(pathFlavorForPlatform("darwin").kind).toBe("posix");
    expect(pathFlavorForPlatform("linux").kind).toBe("posix");
  });
});

describe("folding and lexical values", () => {
  it("folds case only on win32", () => {
    expect(WIN32.fold("C:\\A\\B")).toBe("c:\\a\\b");
    expect(POSIX.fold("/A/B")).toBe("/A/B");
  });

  it("computes lexical comparable values relative to a base", () => {
    expect(WIN32.lexicalValue("c:\\root", "C:/root/sub/../x")).toBe("c:\\root\\x");
    expect(POSIX.lexicalValue("/root", "/root/./a")).toBe("/root/a");
  });
});

describe("separator recognition", () => {
  it("recognizes only / on posix", () => {
    expect(POSIX.lastSeparatorIndex("a/b\\c")).toBe(1);
    expect(POSIX.separators).toEqual(["/"]);
  });

  it("recognizes both separators on win32, last index uses the same set", () => {
    expect(WIN32.lastSeparatorIndex("a/b\\c/d")).toBe(5);
    expect(WIN32.separators).toEqual(["/", "\\"]);
  });
});

describe("wildcard options", () => {
  it("enables folding options on win32 only", () => {
    expect(WIN32.wildcard).toEqual({ caseInsensitive: true, separatorEquivalence: true });
    expect(POSIX.wildcard).toEqual({ caseInsensitive: false, separatorEquivalence: false });
  });
});

describe("containment", () => {
  it("treats the directory itself and true children as inside", () => {
    expect(POSIX.contains("/a/b", "/a/b")).toBe(true);
    expect(POSIX.contains("/a/b", "/a/b/c")).toBe(true);
    expect(WIN32.contains("C:\\x", "c:\\x\\y")).toBe(true);
  });

  it("rejects .. escapes", () => {
    expect(POSIX.contains("/a/b", "/a/b/../c")).toBe(false);
    expect(POSIX.contains("/a/b", "/a")).toBe(false);
  });

  it("rejects empty operands", () => {
    expect(POSIX.contains("", "/a")).toBe(false);
    expect(POSIX.contains("/a", "")).toBe(false);
  });

  it("rejects absolute relative results across win32 drives", () => {
    expect(WIN32.contains("C:\\a", "D:\\a\\b")).toBe(false);
  });
});

describe("file URL decoding", () => {
  it("decodes posix URLs", () => {
    expect(POSIX.decodeFileUrl("file:///home/u/a%20b")).toEqual({ ok: true, path: "/home/u/a b" });
  });

  it("decodes win32 drive URLs to uppercase backslash spellings", () => {
    expect(WIN32.decodeFileUrl("file:///c:/x/y")).toEqual({ ok: true, path: "C:\\x\\y" });
  });

  it("accepts localhost authority", () => {
    expect(POSIX.decodeFileUrl("file://localhost/etc/hosts")).toEqual({ ok: true, path: "/etc/hosts" });
  });

  it("rejects remote hosts and bad escapes", () => {
    expect(POSIX.decodeFileUrl("file://example.com/x").ok).toBe(false);
    expect(POSIX.decodeFileUrl("file:///a%2").ok).toBe(false);
  });

  it("rejects relative targets for posix", () => {
    expect(POSIX.decodeFileUrl("file://rel/x").ok).toBe(false);
  });
});
