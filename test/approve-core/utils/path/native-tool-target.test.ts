import { describe, expect, it } from "vitest";
import {
  convertNativeDriveMount,
  resolveNativeToolTarget,
} from "#approve-core/utils/path/native-tool-target";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";

function options(overrides: {
  flavor?: typeof POSIX;
  cwd?: string;
  readFallbacks?: boolean;
  existing?: readonly string[];
  home?: string;
}) {
  const existing = new Set(overrides.existing ?? []);
  return {
    cwd: overrides.cwd ?? "/work",
    flavor: overrides.flavor ?? POSIX,
    readFallbacks: overrides.readFallbacks ?? false,
    exists: (p: string) => existing.has(p),
    home: overrides.home ?? "/home/user",
  };
}

describe("convertNativeDriveMount", () => {
  it("converts the three supported shapes", () => {
    expect(convertNativeDriveMount("/c/x")).toBe("C:\\x");
    expect(convertNativeDriveMount("/mnt/c/x")).toBe("C:\\x");
    expect(convertNativeDriveMount("/cygdrive/c/x")).toBe("C:\\x");
    expect(convertNativeDriveMount("/c")).toBeUndefined();
  });

  it("leaves UNC and backslash inputs unchanged", () => {
    expect(convertNativeDriveMount("\\\\host\\share")).toBeUndefined();
    expect(convertNativeDriveMount("c:\\x")).toBeUndefined();
  });
});

describe("resolveNativeToolTarget", () => {
  it("resolves relative inputs against the cwd without rewriting", () => {
    const result = resolveNativeToolTarget("a/b", options({}));
    expect(result.target).toBe("/work/a/b");
    expect(result.rewritten).toBe(false);
    expect(result.relativeSpelling).toBe("a/b");
  });

  it("keeps the relative spelling for compatibility", () => {
    const result = resolveNativeToolTarget("file.txt", options({}));
    expect(result.relativeSpelling).toBe("file.txt");
  });

  it("strips one leading @ without counting it as rewriting", () => {
    const result = resolveNativeToolTarget("@/x", options({}));
    expect(result.target).toBe("/x");
    expect(result.rewritten).toBe(false);
  });

  it("replaces Unicode whitespace and marks rewriting", () => {
    const result = resolveNativeToolTarget("/x\u00A0y", options({}));
    expect(result.target).toBe("/x y");
    expect(result.rewritten).toBe(true);
  });

  it("expands ~ but not $HOME", () => {
    expect(resolveNativeToolTarget("~/x", options({})).target).toBe("/home/user/x");
    expect(resolveNativeToolTarget("~", options({})).target).toBe("/home/user");
    const homeLiteral = resolveNativeToolTarget("$HOME/x", options({}));
    expect(homeLiteral.target).toBe("/work/$HOME/x");
  });

  it("converts win32 drive mounts and marks rewriting", () => {
    const result = resolveNativeToolTarget("/c/x", options({ flavor: WIN32, cwd: "C:\\work" }));
    expect(result.target).toBe("C:\\x");
    expect(result.rewritten).toBe(true);
  });

  it("decodes file URLs and marks rewriting", () => {
    const result = resolveNativeToolTarget("file:///a%20b", options({}));
    expect(result.target).toBe("/a b");
    expect(result.rewritten).toBe(true);
  });

  it("keeps the current spelling when file URL decoding fails", () => {
    const result = resolveNativeToolTarget("file://host/x", options({}));
    // No decoding is applied; the spelling then resolves like any relative path.
    expect(result.relativeSpelling).toBe("file://host/x");
  });

  it("applies read fallbacks in order and picks the first existing variant", () => {
    const nfd = "e\u0301".normalize("NFD");
    const composed = resolveNativeToolTarget(nfd.normalize("NFC"), options({
      readFallbacks: true,
      existing: [`/work/${nfd}`],
    }));
    expect(composed.target).toBe(`/work/${nfd}`);
    expect(composed.rewritten).toBe(true);

    const curly = "/it\u2019s";
    const curlyResult = resolveNativeToolTarget("/it's", options({
      readFallbacks: true,
      existing: [curly],
    }));
    expect(curlyResult.target).toBe(curly);
    expect(curlyResult.rewritten).toBe(true);
  });

  it("does not probe existence for non-read tools", () => {
    let probes = 0;
    const opts = options({ readFallbacks: false });
    resolveNativeToolTarget("missing", { ...opts, exists: () => { probes += 1; return false; } });
    expect(probes).toBe(0);
  });
});
