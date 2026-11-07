import { describe, expect, it } from "vitest";
import { isOutsideCanonicalCwd } from "#approve-core/utils/path/path-containment";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";

describe("isOutsideCanonicalCwd", () => {
  it("treats only out-of-tree canonical paths as external", () => {
    expect(isOutsideCanonicalCwd("/work/a", "/work", POSIX)).toBe(false);
    expect(isOutsideCanonicalCwd("/work", "/work", POSIX)).toBe(false);
    expect(isOutsideCanonicalCwd("/other/a", "/work", POSIX)).toBe(true);
  });

  it("never treats the four safe devices as external", () => {
    for (const device of ["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"]) {
      expect(isOutsideCanonicalCwd(device, "/work", POSIX)).toBe(false);
    }
    // The exemption does not extend to every /dev path.
    expect(isOutsideCanonicalCwd("/dev/tty", "/work", POSIX)).toBe(true);
  });

  it("is not external for empty operands", () => {
    expect(isOutsideCanonicalCwd("", "/work", POSIX)).toBe(false);
    expect(isOutsideCanonicalCwd("/work", "", POSIX)).toBe(false);
  });

  it("applies win32 folding", () => {
    expect(isOutsideCanonicalCwd("c:\\work\\a", "C:\\Work", WIN32)).toBe(false);
    expect(isOutsideCanonicalCwd("C:\\other", "C:\\Work", WIN32)).toBe(true);
  });
});
