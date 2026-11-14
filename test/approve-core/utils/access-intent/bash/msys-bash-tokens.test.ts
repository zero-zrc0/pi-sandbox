import { describe, expect, it } from "vitest";
import {
  classifyBashToken,
  resolveMsysToken,
} from "#approve-core/utils/access-intent/bash/msys-bash-tokens";

describe("classifyBashToken on win32", () => {
  it("recognizes the four safe devices before drive mounts", () => {
    for (const device of ["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"]) {
      expect(classifyBashToken(device, "win32")).toBe("device");
    }
    expect(classifyBashToken("/dev/other", "win32")).toBe("posix-absolute");
  });

  it("classifies single-letter mounts", () => {
    expect(classifyBashToken("/c", "win32")).toBe("drive-mount");
    expect(classifyBashToken("/c/", "win32")).toBe("drive-mount");
    expect(classifyBashToken("/c/x", "win32")).toBe("drive-mount");
    expect(classifyBashToken("/cd/x", "win32")).toBe("posix-absolute");
  });

  it("classifies other absolute and plain tokens", () => {
    expect(classifyBashToken("/usr/bin", "win32")).toBe("posix-absolute");
    expect(classifyBashToken("foo", "win32")).toBe("plain");
    expect(classifyBashToken("C:\\x", "win32")).toBe("plain");
  });
});

describe("classifyBashToken on posix", () => {
  it("treats every token as plain", () => {
    expect(classifyBashToken("/dev/null", "posix")).toBe("plain");
    expect(classifyBashToken("/c/x", "posix")).toBe("plain");
  });
});

describe("resolveMsysToken", () => {
  it("converts drive mounts to uppercase backslash paths", () => {
    expect(resolveMsysToken("/c/x", "win32")).toBe("C:\\x");
    expect(resolveMsysToken("/c", "win32")).toBe("C:\\");
    expect(resolveMsysToken("/c/", "win32")).toBe("C:\\");
  });

  it("keeps devices and posix-absolute literals", () => {
    expect(resolveMsysToken("/dev/null", "win32")).toBe("/dev/null");
    expect(resolveMsysToken("/usr/bin", "win32")).toBe("/usr/bin");
  });

  it("passes plain tokens through on both platforms", () => {
    expect(resolveMsysToken("x", "win32")).toBe("x");
    expect(resolveMsysToken("x", "posix")).toBe("x");
  });
});
