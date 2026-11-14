import { describe, expect, it } from "vitest";
import { isInfrastructureRead } from "#approve-core/utils/path/pi-infrastructure-read";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";

const base = {
  flavor: POSIX,
  cwd: "/proj",
  home: "/home/user",
  configuredPaths: [] as readonly string[],
  exclusions: [] as readonly string[],
};

describe("isInfrastructureRead", () => {
  it("allows the project-local npm and git directories", () => {
    expect(isInfrastructureRead("/proj/.pi/npm/pkg", base)).toBe(true);
    expect(isInfrastructureRead("/proj/.pi/git/hooks", { ...base, cwd: "/proj" })).toBe(true);
    expect(isInfrastructureRead("/other/.pi/npm", base)).toBe(false);
  });

  it("allows configured paths with home expansion", () => {
    const options = { ...base, configuredPaths: ["~/.pi/cache"] };
    expect(isInfrastructureRead("/home/user/.pi/cache/x", options)).toBe(true);
    expect(isInfrastructureRead("/home/other/.pi/cache/x", options)).toBe(false);
  });

  it("matches configured globs across separators, consistent with policy wildcards", () => {
    const options = { ...base, configuredPaths: ["/etc/pi/*"] };
    expect(isInfrastructureRead("/etc/pi/one", options)).toBe(true);
    expect(isInfrastructureRead("/etc/pi/one/two", options)).toBe(true);
    expect(isInfrastructureRead("/etc/pi2/one", options)).toBe(false);
  });

  it("matches single-character globs", () => {
    const options = { ...base, configuredPaths: ["/opt/pi-?"] };
    expect(isInfrastructureRead("/opt/pi-a", options)).toBe(true);
    expect(isInfrastructureRead("/opt/pi-ab", options)).toBe(false);
  });

  it("lets exclusions win over every allowance", () => {
    const options = {
      ...base,
      configuredPaths: ["/etc/pi"],
      exclusions: ["/etc/pi/secrets"],
    };
    expect(isInfrastructureRead("/etc/pi/secrets/key", options)).toBe(false);
    expect(isInfrastructureRead("/etc/pi/other", options)).toBe(true);
  });

  it("uses win32 folding for matching", () => {
    const options = {
      ...base,
      flavor: WIN32,
      cwd: "C:\\Proj",
      configuredPaths: ["C:\\Etc\\Pi"],
    };
    expect(isInfrastructureRead("c:\\etc\\pi\\x", options)).toBe(true);
    expect(isInfrastructureRead("C:\\Etc\\Pi2\\x", options)).toBe(false);
  });

  it("rejects empty paths", () => {
    expect(isInfrastructureRead("", base)).toBe(false);
  });
});
