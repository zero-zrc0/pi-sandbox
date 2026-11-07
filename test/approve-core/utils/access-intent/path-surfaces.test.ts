import { describe, expect, it } from "vitest";
import {
  builtinToolIdentityEffect,
  directionalSurface,
  isMisfoldedDirectionSurface,
  splitPathSurface,
} from "#approve-core/utils/access-intent/path-surfaces";

describe("splitPathSurface", () => {
  it("splits only the two legal families", () => {
    expect(splitPathSurface("path")).toEqual({ family: "path", direction: undefined });
    expect(splitPathSurface("path_read")).toEqual({ family: "path", direction: "read" });
    expect(splitPathSurface("external_directory_write")).toEqual({
      family: "external_directory",
      direction: "write",
    });
    expect(splitPathSurface("bash")).toBeUndefined();
  });

  it("does not misclassify other names that merely end in a direction suffix", () => {
    expect(isMisfoldedDirectionSurface("pathutil_read")).toBe(true);
    expect(isMisfoldedDirectionSurface("path_read")).toBe(false);
    expect(isMisfoldedDirectionSurface("path")).toBe(false);
  });

  it("builds directional surface names", () => {
    expect(directionalSurface("path", "write")).toBe("path_write");
    expect(directionalSurface("external_directory", "read")).toBe("external_directory_read");
  });
});

describe("builtinToolIdentityEffect", () => {
  it("proves read or write for the respective tools only", () => {
    expect(builtinToolIdentityEffect("read")).toBe("read");
    expect(builtinToolIdentityEffect("find")).toBe("read");
    expect(builtinToolIdentityEffect("grep")).toBe("read");
    expect(builtinToolIdentityEffect("ls")).toBe("read");
    expect(builtinToolIdentityEffect("write")).toBe("write");
    expect(builtinToolIdentityEffect("edit")).toBe("unproven");
    expect(builtinToolIdentityEffect("anything_else")).toBe("unproven");
  });
});
