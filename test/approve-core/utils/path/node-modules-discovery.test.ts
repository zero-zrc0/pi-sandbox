import { describe, expect, it } from "vitest";
import { findGlobalNodeModules } from "#approve-core/utils/path/node-modules-discovery";

const MODULE_URL = "file:///repo/sub/node_modules/pkg/index.js";

describe("findGlobalNodeModules", () => {
  it("finds the ancestor node_modules without running npm", () => {
    let npmRuns = 0;
    const result = findGlobalNodeModules(MODULE_URL, {
      exists: (p) => p === "/repo/sub/node_modules",
      runNpmRoot: () => {
        npmRuns += 1;
        return { status: 0, stdout: "/global\n" };
      },
    });
    expect(result).toBe("/repo/sub/node_modules");
    expect(npmRuns).toBe(0);
  });

  it("falls back to npm root -g once when no ancestor matches", () => {
    let npmRuns = 0;
    const result = findGlobalNodeModules(MODULE_URL, {
      exists: (p) => p === "/global/node_modules",
      runNpmRoot: () => {
        npmRuns += 1;
        return { status: 0, stdout: " /global/node_modules \n" };
      },
    });
    expect(result).toBe("/global/node_modules");
    expect(npmRuns).toBe(1);
  });

  it("degrades on invalid URLs, npm failure, empty output and missing directories", () => {
    expect(findGlobalNodeModules("not a url", { exists: () => false })).toBeUndefined();
    expect(
      findGlobalNodeModules(MODULE_URL, {
        exists: () => false,
        runNpmRoot: () => ({ status: 1, stdout: "/x" }),
      }),
    ).toBeUndefined();
    expect(
      findGlobalNodeModules(MODULE_URL, {
        exists: () => false,
        runNpmRoot: () => ({ status: 0, stdout: "  \n" }),
      }),
    ).toBeUndefined();
    expect(
      findGlobalNodeModules(MODULE_URL, {
        exists: () => false,
        runNpmRoot: () => ({ status: 0, stdout: "/missing\n" }),
      }),
    ).toBeUndefined();
    expect(
      findGlobalNodeModules(MODULE_URL, {
        exists: () => false,
        runNpmRoot: () => {
          throw new Error("timeout");
        },
      }),
    ).toBeUndefined();
  });
});
