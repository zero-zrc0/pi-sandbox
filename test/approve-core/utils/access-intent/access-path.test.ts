import { describe, expect, it } from "vitest";
import { accessPathForNativeTool, accessPathFromLiteral } from "#approve-core/utils/access-intent/access-path";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";

function normalizer() {
  return new PathNormalizer(POSIX, "/work", {
    home: "/home/user",
    realpathSync: () => {
      const error = new Error("missing") as Error & { code: string };
      error.code = "ENOENT";
      throw error;
    },
  });
}

describe("accessPathFromLiteral", () => {
  it("builds the full path value object through the session normalizer", () => {
    const value = accessPathFromLiteral(normalizer(), "src/x.ts", "/work");
    expect(value.display).toBe("/work/src/x.ts");
    expect(value.matchValues).toEqual(["/work/src/x.ts", "src/x.ts"]);
    expect(value.boundary).toBe("/work/src/x.ts");
  });

  it("defaults the base to the session cwd", () => {
    const value = accessPathFromLiteral(normalizer(), "x.ts");
    expect(value.display).toBe("/work/x.ts");
    expect(value.matchValues).toEqual(["/work/x.ts", "x.ts"]);
  });
});

describe("accessPathForNativeTool", () => {
  it("resolves the actual target the tool opens", () => {
    const value = accessPathForNativeTool(normalizer(), "read", "@relative.txt");
    expect(value.display).toBe("/work/relative.txt");
    expect(value.matchValues).toContain("relative.txt");
  });
});
