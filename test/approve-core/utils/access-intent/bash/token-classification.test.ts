import { describe, expect, it } from "vitest";
import { classifyPathToken } from "../../../../../src/approve-core/utils/access-intent/bash/token-classification";

describe("path token classification", () => {
  it("distinguishes external paths from ordinary bare operands", () => {
    expect(classifyPathToken("../secret", "posix")).toEqual({ bare: true, path: true, external: true });
    expect(classifyPathToken("HEAD..main", "posix")).toEqual({ bare: true, path: false, external: false });
  });

  it("rejects URI schemes while retaining Windows drive paths", () => {
    expect(classifyPathToken("mailto:user@example.com", "posix").bare).toBe(false);
    expect(classifyPathToken("C:\\data\\file", "win32").external).toBe(true);
  });

  it("recognizes platform separators and preserves the root path", () => {
    expect(classifyPathToken("/", "posix")).toEqual({ bare: true, path: true, external: true });
    expect(classifyPathToken("folder\\file", "posix").path).toBe(false);
    expect(classifyPathToken("folder\\file", "win32").path).toBe(true);
    expect(classifyPathToken("C:relative", "win32")).toEqual({ bare: true, path: true, external: false });
  });

  it("applies shared exclusions without discarding glob characters", () => {
    for (const value of ["", "--flag", "NAME=value", "https://example.test/x", "@scope/name"]) {
      expect(classifyPathToken(value, "posix").bare).toBe(false);
    }
    expect(classifyPathToken("@/src/*.ts", "posix")).toEqual({ bare: true, path: true, external: false });
    expect(classifyPathToken("../*.ts", "posix")).toEqual({ bare: true, path: true, external: true });
  });
});
