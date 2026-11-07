import { describe, expect, it } from "vitest";
import {
  matchesNpmDeclaration,
  npmOriginKey,
  proveNpmSource,
  type NpmSourceProof,
} from "#approve-core/utils/tool-access/npm-source";

const POSIX_ORIGIN = ["npm:@scope/pkg@1.2.3", "user", "package", "dist/tool.js"].join("\u0000");

const POSIX_SOURCE_INFO = {
  path: "/home/u/.pi/node_modules/@scope/pkg/dist/tool.js",
  source: "npm:@scope/pkg@1.2.3",
  scope: "user",
  origin: "package",
  baseDir: "/home/u/.pi/node_modules/@scope/pkg",
};

function toolWith(sourceInfo: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "pkg-tool",
    origin: POSIX_ORIGIN,
    revision: "1",
    description: "package tool",
    parameters: { type: "object" },
    sourceInfo,
    ...extra,
  };
}

function unprovenReason(proof: NpmSourceProof): string {
  if (proof.kind !== "unproven") throw new Error(`expected unproven, got ${proof.kind}`);
  return proof.reason;
}

describe("npmOriginKey", () => {
  it("joins the source, scope, origin and package-relative entry with NUL", () => {
    expect(npmOriginKey("npm:pkg@1.2.3", "project", "package", "dist/tool.js"))
      .toBe("npm:pkg@1.2.3\u0000project\u0000package\u0000dist/tool.js");
  });
});

describe("proveNpmSource", () => {
  it("proves a scoped npm package with an exact version", () => {
    const proof = proveNpmSource(toolWith(POSIX_SOURCE_INFO));

    expect(proof).toEqual({
      kind: "proven",
      packageName: "@scope/pkg",
      version: "1.2.3",
      originKey: POSIX_ORIGIN,
    });
    expect(Object.isFrozen(proof)).toBe(true);
  });

  it("proves an unscoped package without a version and omits the version field", () => {
    const originKey = npmOriginKey("npm:my-tool", "project", "package", "dist/index.js");
    const proof = proveNpmSource(toolWith({
      path: "/repo/.pi/node_modules/my-tool/dist/index.js",
      source: "npm:my-tool",
      scope: "project",
      origin: "package",
      baseDir: "/repo/.pi/node_modules/my-tool",
    }, { origin: originKey }));

    expect(proof).toEqual({ kind: "proven", packageName: "my-tool", originKey });
    expect(proof).not.toHaveProperty("version");
  });

  it("keeps a version range verbatim", () => {
    const originKey = ["npm:@scope/pkg@^1.0.0", "user", "package", "dist/tool.js"].join("\u0000");
    expect(proveNpmSource(toolWith(
      { ...POSIX_SOURCE_INFO, source: "npm:@scope/pkg@^1.0.0" },
      { origin: originKey },
    ))).toMatchObject({ kind: "proven", packageName: "@scope/pkg", version: "^1.0.0" });
  });

  it("normalizes a Windows entry to forward slashes", () => {
    const originKey = npmOriginKey("npm:pkg@2.0.0", "user", "package", "dist/tool.js");
    const proof = proveNpmSource(toolWith({
      path: "C:\\Users\\u\\.pi\\node_modules\\pkg\\dist\\tool.js",
      source: "npm:pkg@2.0.0",
      scope: "user",
      origin: "package",
      baseDir: "C:\\Users\\u\\.pi\\node_modules\\pkg",
    }, { origin: originKey }));

    expect(proof).toEqual({ kind: "proven", packageName: "pkg", version: "2.0.0", originKey });
  });

  it("requires the entry path to be strictly inside the package baseDir", () => {
    expect(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, path: POSIX_SOURCE_INFO.baseDir })))
      .toMatchObject({ kind: "unproven", reason: "entry-outside-package" });
    expect(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, path: `${POSIX_SOURCE_INFO.baseDir}/../pkg-evil/x.js` })))
      .toMatchObject({ kind: "unproven", reason: "entry-outside-package" });
    expect(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, path: "/home/u/.pi/node_modules/pkg-other/x.js" })))
      .toMatchObject({ kind: "unproven", reason: "entry-outside-package" });
  });

  it("rejects an entry on another Windows drive", () => {
    expect(proveNpmSource(toolWith({
      path: "D:\\other\\x.js",
      source: "npm:pkg",
      scope: "user",
      origin: "package",
      baseDir: "C:\\repo\\node_modules\\pkg",
    }))).toMatchObject({ kind: "unproven", reason: "entry-outside-package" });
  });

  it("rejects a relative source path or base directory", () => {
    expect(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, path: "dist/tool.js" })))
      .toMatchObject({ kind: "unproven", reason: "invalid-source-path" });
    expect(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, baseDir: "node_modules/@scope/pkg" })))
      .toMatchObject({ kind: "unproven", reason: "invalid-source-path" });
  });

  it("proves not-npm for a non-package origin", () => {
    expect(proveNpmSource(toolWith({
      path: "/repo/ext/tool.ts",
      source: "npm:foo",
      scope: "project",
      origin: "top-level",
    }))).toEqual({ kind: "not-npm" });
  });

  it("proves not-npm when a package came from a non-npm source", () => {
    expect(proveNpmSource(toolWith({
      path: "/repo/ext/tool.ts",
      source: "git:github.com/acme/tools",
      scope: "project",
      origin: "package",
      baseDir: "/repo/ext",
    }))).toEqual({ kind: "not-npm" });
    expect(proveNpmSource(toolWith({
      path: "/repo/ext/tool.ts",
      source: "local:./tools",
      scope: "project",
      origin: "package",
      baseDir: "/repo/ext",
    }))).toEqual({ kind: "not-npm" });
  });

  it("does not guess a package from the installation path or tool name", () => {
    expect(proveNpmSource(toolWith({
      path: "/repo/node_modules/looks-like-npm/dist/tool.js",
      source: "local",
      scope: "project",
      origin: "top-level",
    }))).toEqual({ kind: "not-npm" });
  });

  it("rejects a missing or non-record sourceInfo", () => {
    expect(unprovenReason(proveNpmSource({ name: "pkg-tool" }))).toBe("missing-source-info");
    expect(unprovenReason(proveNpmSource(toolWith(undefined)))).toBe("missing-source-info");
    expect(unprovenReason(proveNpmSource(toolWith("npm:@scope/pkg")))).toBe("missing-source-info");
    expect(unprovenReason(proveNpmSource(null))).toBe("missing-source-info");
  });

  it("reads only own data properties and never triggers getters", () => {
    const getterTool = Object.defineProperty({ name: "pkg-tool" }, "sourceInfo", {
      get: () => POSIX_SOURCE_INFO,
      enumerable: true,
      configurable: true,
    });
    expect(unprovenReason(proveNpmSource(getterTool))).toBe("missing-source-info");

    const inheritedTool = Object.create({ sourceInfo: POSIX_SOURCE_INFO }) as Record<string, unknown>;
    expect(unprovenReason(proveNpmSource(inheritedTool))).toBe("missing-source-info");

    const getterField = {
      sourceInfo: Object.defineProperties({}, {
        path: { get: () => POSIX_SOURCE_INFO.path, enumerable: true },
        source: { value: POSIX_SOURCE_INFO.source, enumerable: true },
        scope: { value: POSIX_SOURCE_INFO.scope, enumerable: true },
        origin: { value: POSIX_SOURCE_INFO.origin, enumerable: true },
        baseDir: { value: POSIX_SOURCE_INFO.baseDir, enumerable: true },
      }),
    };
    expect(unprovenReason(proveNpmSource(getterField))).toBe("invalid-source-info");
  });

  it("rejects missing or empty required source fields", () => {
    expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, path: undefined }))))
      .toBe("invalid-source-info");
    expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, source: "  " }))))
      .toBe("invalid-source-info");
    expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, scope: "" }))))
      .toBe("invalid-source-info");
    expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, origin: "" }))))
      .toBe("invalid-source-info");
  });

  it("rejects a missing or empty baseDir", () => {
    const { baseDir: _omitted, ...withoutBaseDir } = POSIX_SOURCE_INFO;
    expect(unprovenReason(proveNpmSource(toolWith(withoutBaseDir)))).toBe("missing-base-dir");
    expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, baseDir: "  " }))))
      .toBe("missing-base-dir");
  });

  it("rejects an npm spec whose package name is not precise", () => {
    for (const source of ["npm:", "npm:@scope", "npm:@scope/", "npm:foo bar", "npm:foo//bar"]) {
      expect(unprovenReason(proveNpmSource(toolWith({ ...POSIX_SOURCE_INFO, source }))))
        .toBe("unparseable-npm-spec");
    }
  });

  it("rejects a captured origin that does not match the proven origin key", () => {
    expect(proveNpmSource(toolWith(POSIX_SOURCE_INFO, { origin: "npm:other-pkg" })))
      .toMatchObject({ kind: "unproven", reason: "origin-mismatch" });
  });

  it("accepts a captured origin nested in a definition", () => {
    const tool = {
      definition: { identity: { name: "pkg-tool", origin: POSIX_ORIGIN, revision: "1" } },
      sourceInfo: POSIX_SOURCE_INFO,
    };
    expect(proveNpmSource(tool)).toMatchObject({ kind: "proven", originKey: POSIX_ORIGIN });
  });

  it("gives two tools from the same package distinct origin keys per entry", () => {
    const first = proveNpmSource(toolWith(POSIX_SOURCE_INFO));
    const second = proveNpmSource(toolWith(
      { ...POSIX_SOURCE_INFO, path: `${POSIX_SOURCE_INFO.baseDir}/dist/other.js` },
      { origin: ["npm:@scope/pkg@1.2.3", "user", "package", "dist/other.js"].join("\u0000") },
    ));

    expect(first.kind).toBe("proven");
    expect(second.kind).toBe("proven");
    expect((first as { originKey: string }).originKey).not.toBe((second as { originKey: string }).originKey);
  });
});

describe("matchesNpmDeclaration", () => {
  const proof = proveNpmSource(toolWith(POSIX_SOURCE_INFO));

  it("matches the package when no entry is declared", () => {
    expect(matchesNpmDeclaration({ package: "@scope/pkg" }, proof)).toBe(true);
  });

  it("matches an exact normalized entry", () => {
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "dist/tool.js" }, proof)).toBe(true);
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "./dist/tool.js" }, proof)).toBe(true);
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "dist\\tool.js" }, proof)).toBe(true);
  });

  it("does not match a different package or entry", () => {
    expect(matchesNpmDeclaration({ package: "other-pkg" }, proof)).toBe(false);
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "dist/other.js" }, proof)).toBe(false);
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "tool.js" }, proof)).toBe(false);
    expect(matchesNpmDeclaration({ package: "@scope/pkg", entry: "../dist/tool.js" }, proof)).toBe(false);
  });

  it("never matches a not-npm or unproven proof", () => {
    const notNpm: NpmSourceProof = { kind: "not-npm" };
    const unprovenProof: NpmSourceProof = { kind: "unproven", reason: "missing-base-dir" };
    expect(matchesNpmDeclaration({ package: "@scope/pkg" }, notNpm)).toBe(false);
    expect(matchesNpmDeclaration({ package: "@scope/pkg" }, unprovenProof)).toBe(false);
  });
});
