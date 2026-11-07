import { describe, expect, it } from "vitest";
import {
  bashCommandIntent,
  buildAccessIntent,
  fixedValuesIntent,
  pathValuesIntent,
  rawToolIntent,
} from "#approve-core/utils/access-intent/access-intent";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";

describe("intent builders", () => {
  it("carries the agent only between calls, never inferred from input", () => {
    expect(rawToolIntent("read", { path: "/a", agent: "sneaky" })).toEqual({
      kind: "raw-tool",
      toolName: "read",
      input: { path: "/a", agent: "sneaky" },
    });
    expect(pathValuesIntent("path", [], "reviewer").agent).toBe("reviewer");
    expect(fixedValuesIntent("mcp", ["gh_pr"]).agent).toBeUndefined();
    expect(bashCommandIntent("git status", ["git status"]).surface).toBe("bash");
  });
});

describe("buildAccessIntent", () => {
  const normalizer = () =>
    new PathNormalizer(POSIX, "/work", {
      home: "/home/user",
      realpathSync: () => {
        const error = new Error("missing") as Error & { code: string };
        error.code = "ENOENT";
        throw error;
      },
    });

  it("builds path-value intents for builtin path tools", () => {
    const intent = buildAccessIntent("read", { path: "src/x.ts" }, { normalizer: normalizer() });
    expect(intent.kind).toBe("path-values");
    if (intent.kind !== "path-values") return;
    expect(intent.surface).toBe("read");
    expect(intent.paths[0].display).toBe("/work/src/x.ts");
  });

  it("builds bash-command intents with equivalent spellings", () => {
    const intent = buildAccessIntent("bash", { command: "# c\nmake test" }, { normalizer: normalizer() });
    expect(intent).toMatchObject({
      kind: "bash-command",
      surface: "bash",
      original: "# c\nmake test",
      spellings: ["make test", "# c\nmake test"],
    });
  });

  it("builds fixed-value intents for MCP surfaces without rebuilding proxy inputs", () => {
    const intent = buildAccessIntent("mcp", { tool: "gh:pr" }, { normalizer: normalizer() });
    expect(intent.kind).toBe("fixed-values");
    if (intent.kind !== "fixed-values") return;
    expect(intent.surface).toBe("mcp");
    expect(intent.values).toContain("gh_pr");
    expect(intent.values.at(-1)).toBe("mcp");
  });

  it("keeps raw-tool intents for everything else", () => {
    const intent = buildAccessIntent("deploy", { region: "eu" }, { normalizer: normalizer() });
    expect(intent).toEqual({ kind: "raw-tool", toolName: "deploy", input: { region: "eu" } });
  });

  it("never throws on malformed inputs", () => {
    expect(() => buildAccessIntent("read", 42, { normalizer: normalizer() })).not.toThrow();
    expect(() => buildAccessIntent("bash", null, { normalizer: normalizer() })).not.toThrow();
  });
});
