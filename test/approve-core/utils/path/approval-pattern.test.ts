import { describe, expect, it } from "vitest";
import { sessionApprovalPatterns } from "#approve-core/utils/path/approval-pattern";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";

function patterns(value: string, dirs: readonly string[], flavor: typeof POSIX = POSIX) {
  const dirSet = new Set(dirs);
  return sessionApprovalPatterns(value, { flavor, isConfirmedDir: (p) => dirSet.has(p) });
}

describe("sessionApprovalPatterns", () => {
  it("emits the directory itself plus a separator-faithful wildcard", () => {
    expect(patterns("/a/b", ["/a/b"])).toEqual(["/a/b", "/a/b/*"]);
    expect(patterns("C:\\a\\b", ["C:\\a\\b"], WIN32)).toEqual(["C:\\a\\b", "C:\\a\\b\\*"]);
  });

  it("does not cover sibling directories that share a name prefix", () => {
    const result = patterns("/a/b", ["/a/b"]);
    expect(result[1]).not.toBe("/a/b*");
  });

  it("appends * once for directories already carrying a trailing separator", () => {
    expect(patterns("/a/b/", ["/a/b"])).toEqual(["/a/b", "/a/b/*"]);
  });

  it("emits a parent-scope wildcard for files and missing entries", () => {
    expect(patterns("/a/b/file.ts", [])).toEqual(["/a/b/*"]);
    expect(patterns("/a/missing", [])).toEqual(["/a/*"]);
  });

  it("scopes separator-less relative values to the current directory", () => {
    expect(patterns("file.ts", [])).toEqual(["*"]);
    expect(patterns("dir", ["dir"])).toEqual(["dir", "dir/*"]);
  });

  it("handles the root parent", () => {
    expect(patterns("/file", [])).toEqual(["/*"]);
  });
});
