import { describe, expect, it } from "vitest";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";

interface Deps {
  realpathMap?: Record<string, string>;
  existing?: readonly string[];
  entries?: Record<string, unknown>;
  additionalLocalPaths?: readonly string[];
}

function makeNormalizer(flavor: typeof POSIX, cwd: string, deps: Deps = {}) {
  const realpathMap = deps.realpathMap ?? {};
  const existing = new Set(deps.existing ?? []);
  return new PathNormalizer(flavor, cwd, {
    home: "/home/user",
    additionalLocalPaths: deps.additionalLocalPaths,
    realpathSync: (p) => {
      if (p in realpathMap) return realpathMap[p];
      const error = new Error("missing") as Error & { code: string };
      error.code = "ENOENT";
      throw error;
    },
    existsSync: (p) => existing.has(p),
    lstatSync: (p) => (existing.has(p) ? { isDirectory: () => false } : undefined),
    statSync: (p) => (existing.has(p) ? { isDirectory: () => false } : undefined),
  });
}

describe("cleanLiteral", () => {
  it("trims, unquotes at most once per end, drops @ and expands home", () => {
    const n = makeNormalizer(POSIX, "/work");
    expect(n.cleanLiteral("  /a/b  ")).toBe("/a/b");
    expect(n.cleanLiteral("\"/a/b\"")).toBe("/a/b");
    expect(n.cleanLiteral("'/a/b'")).toBe("/a/b");
    expect(n.cleanLiteral("\"/a/b'")).toBe("/a/b");
    expect(n.cleanLiteral("''/a/b''")).toBe("'/a/b'");
    expect(n.cleanLiteral("@/a")).toBe("/a");
    expect(n.cleanLiteral("~/x")).toBe("/home/user/x");
  });
});

describe("normalPath", () => {
  it("produces display, match aliases and boundary for absolute paths", () => {
    const n = makeNormalizer(POSIX, "/work", { realpathMap: { "/work": "/real/work" } });
    const value = n.normalPath("/work/src/x.ts");
    expect(value.display).toBe("/work/src/x.ts");
    expect(value.matchValues).toEqual(["/work/src/x.ts", "src/x.ts", "/real/work/src/x.ts"]);
    expect(value.boundary).toBe("/real/work/src/x.ts");
    expect(value.redirectNote).toBe("/real/work/src/x.ts");
  });

  it("does not add an empty alias for the cwd itself", () => {
    const n = makeNormalizer(POSIX, "/work");
    expect(n.normalPath("/work").matchValues).toEqual(["/work"]);
  });

  it("adds no project-relative alias outside the cwd", () => {
    const n = makeNormalizer(POSIX, "/work");
    expect(n.normalPath("/other/x").matchValues).toEqual(["/other/x"]);
  });

  it("resolves relative literals against an explicit base", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.normalPath("x.ts", "/work/src");
    expect(value.display).toBe("/work/src/x.ts");
    expect(value.matchValues).toContain("x.ts");
  });

  it("keeps unknown-base relative paths literal", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.normalPath("x.ts");
    expect(value.display).toBe("x.ts");
    expect(value.matchValues).toEqual(["x.ts"]);
    expect(value.boundary).toBe("");
  });

  it("keeps wildcards literal-only", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.normalPath("src/*");
    expect(value.matchValues).toEqual(["src/*"]);
    expect(value.boundary).toBe("");
  });

  it("produces empty values for empty literals", () => {
    const n = makeNormalizer(POSIX, "/work");
    expect(n.normalPath("")).toEqual({ display: "", matchValues: [], boundary: "" });
  });
});

describe("bashTokenPath", () => {
  it("keeps safe devices literal in every representation on win32", () => {
    const n = makeNormalizer(WIN32, "C:\\work");
    const value = n.bashTokenPath("/dev/null");
    expect(value.display).toBe("/dev/null");
    expect(value.matchValues).toEqual(["/dev/null"]);
    expect(value.boundary).toBe("/dev/null");
  });

  it("converts drive mounts on win32", () => {
    const n = makeNormalizer(WIN32, "C:\\work");
    expect(n.bashTokenPath("/c/x").display).toBe("C:\\x");
  });

  it("keeps posix-absolute literals on win32", () => {
    const n = makeNormalizer(WIN32, "C:\\work");
    const value = n.bashTokenPath("/usr/bin");
    expect(value.matchValues).toEqual(["/usr/bin"]);
    expect(value.boundary).toBe("");
  });

  it("treats /dev/null as a plain token on posix", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.bashTokenPath("/dev/null");
    expect(value.display).toBe("/dev/null");
    expect(value.matchValues).toContain("/dev/null");
  });
});

describe("nativeToolPath", () => {
  it("uses the tool's own target and records rewriting", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.nativeToolPath("read", "a.txt");
    expect(value.display).toBe("/work/a.txt");
    expect(value.matchValues).toEqual(["/work/a.txt", "a.txt"]);
  });

  it("provides a redirect note when the tool rewrote the spelling", () => {
    const n = makeNormalizer(POSIX, "/work");
    const value = n.nativeToolPath("read", "/x\u00A0y");
    expect(value.display).toBe("/x y");
    expect(value.redirectNote).toBe("/x y");
  });
});

describe("cd interpretation and offsets", () => {
  it("interprets win32 drive mounts as absolute and devices as unknown", () => {
    const n = makeNormalizer(WIN32, "C:\\work");
    expect(n.interpretCd("/c/x").kind).toBe("absolute");
    expect(n.interpretCd("/dev/null").kind).toBe("unknown");
    expect(n.interpretCd("/usr").kind).toBe("unknown");
    expect(n.interpretCd("C:\\x").kind).toBe("absolute");
    expect(n.interpretCd("sub").kind).toBe("relative");
  });

  it("joins cd offsets", () => {
    const n = makeNormalizer(POSIX, "/work");
    expect(n.resolveCdOffset("/work", "sub")).toBe("/work/sub");
    expect(n.resolveCdOffset("/work", "")).toBe("/work");
  });
});

describe("out-of-cwd judgment", () => {
  it("judges against the canonical cwd and exempts safe devices", () => {
    const n = makeNormalizer(POSIX, "/work", {
      realpathMap: { "/work": "/real/work", "/elsewhere": "/elsewhere" },
    });
    expect(n.isOutside("/work/a")).toBe(false);
    expect(n.isOutside("/elsewhere/x")).toBe(true);
    expect(n.isOutside("/dev/null")).toBe(false);
    expect(n.isOutside("/dev/other")).toBe(true);
  });

  it("treats the session workspace as local alongside the project cwd", () => {
    const n = makeNormalizer(POSIX, "/work", {
      additionalLocalPaths: ["/session-workspace"],
      realpathMap: { "/work": "/real/work", "/session-workspace": "/agent/workspaces/session" },
    });
    expect(n.isOutside("/session-workspace/scripts/task.sh")).toBe(false);
    expect(n.isOutside("/outside/secret.txt")).toBe(true);
  });

  it("is not external when the location cannot be proven", () => {
    const n = new PathNormalizer(POSIX, "/work", {
      home: "/home/user",
      realpathSync: () => {
        throw new Error("denied");
      },
    });
    expect(n.isOutside("/anywhere")).toBe(false);
  });
});

describe("existence probes", () => {
  it("distinguishes entry (lstat) from following-link existence", () => {
    const n = makeNormalizer(POSIX, "/work", { existing: ["/work/link", "/work/file"] });
    expect(n.entryExists("/work/link")).toBe(true);
    expect(n.entryExists("/work/missing")).toBe(false);
    expect(n.exists("/work/file")).toBe(true);
    expect(n.exists("/work/missing")).toBe(false);
  });

  it("treats probe errors as non-existence and non-directories", () => {
    const n = new PathNormalizer(POSIX, "/work", {
      home: "/home/user",
      existsSync: () => {
        throw new Error("boom");
      },
      statSync: () => {
        throw new Error("boom");
      },
    });
    expect(n.exists("/x")).toBe(false);
    expect(n.isDirectory("/x")).toBe(false);
  });
});
