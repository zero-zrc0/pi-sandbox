import { describe, expect, it } from "vitest";
import {
  generateMcpProxyCandidates,
  generatePiMcpCandidates,
  parseQualifiedToolName,
  toolCallCandidates,
  MCP_CALL_CANDIDATE,
  MCP_CONNECT_CANDIDATE,
  MCP_DESCRIBE_CANDIDATE,
  MCP_LIST_CANDIDATE,
  MCP_SEARCH_CANDIDATE,
  MCP_STATUS_CANDIDATE,
  sanitizeMcpName,
} from "#approve-core/utils/access-intent/mcp-targets";

describe("parseQualifiedToolName", () => {
  it("splits at the first colon and keeps later colons in the tool", () => {
    expect(parseQualifiedToolName("github:create_issue")).toEqual({
      server: "github",
      tool: "create_issue",
      raw: "github:create_issue",
    });
    expect(parseQualifiedToolName("a:b:c")).toEqual({ server: "a", tool: "b:c", raw: "a:b:c" });
    expect(parseQualifiedToolName("nocolon")).toBeUndefined();
    expect(parseQualifiedToolName(":tool")).toBeUndefined();
    expect(parseQualifiedToolName("server:")).toBeUndefined();
  });
});

describe("toolCallCandidates", () => {
  it("combines explicit server with underscore and colon forms plus raw parts", () => {
    expect(toolCallCandidates("create_issue", "github", [])).toEqual([
      "github_create_issue",
      "github:create_issue",
      "github",
      "create_issue",
      "create_issue",
      MCP_CALL_CANDIDATE,
    ].filter((value, index, all) => all.indexOf(value) === index));
  });

  it("prefers the explicit server over the qualified name server", () => {
    const candidates = toolCallCandidates("gitlab:create", "github", []);
    expect(candidates).toContain("github_create");
    expect(candidates).not.toContain("gitlab_create");
  });

  it("avoids a doubled prefix when the tool already starts with `<server>_`", () => {
    const candidates = toolCallCandidates("github_create", "github", []);
    expect(candidates.filter((c) => c === "github_create")).toHaveLength(1);
    expect(candidates).not.toContain("github_github_create");
  });

  it("uses the longest configured server prefix match when no server is explicit", () => {
    const candidates = toolCallCandidates("github_tools_scan", undefined, ["github", "github_tools"]);
    expect(candidates).toEqual(["github_tools_scan", "github_tools", MCP_CALL_CANDIDATE]);
  });

  it("falls back to a configured `_<server>` suffix match", () => {
    const candidates = toolCallCandidates("scan_github", undefined, ["github"]);
    expect(candidates).toContain("github_scan_github");
    expect(candidates).toContain("github:scan_github");
    expect(candidates).toContain("github");
  });

  it("keeps the bare tool and raw reference when nothing matches", () => {
    const candidates = toolCallCandidates("plain_tool", undefined, []);
    expect(candidates).toEqual(["plain_tool", MCP_CALL_CANDIDATE]);
  });
});

describe("generateMcpProxyCandidates", () => {
  it("selects exactly one operation category by priority", () => {
    expect(generateMcpProxyCandidates({ tool: "gh:x" }, []).at(-1)).toBe(MCP_CALL_CANDIDATE);
    expect(generateMcpProxyCandidates({ connect: "fs", server: "srv" }, []).at(-1)).toBe(MCP_CONNECT_CANDIDATE);
    expect(generateMcpProxyCandidates({ describe: "gh:x" }, []).at(-1)).toBe(MCP_DESCRIBE_CANDIDATE);
    expect(generateMcpProxyCandidates({ search: "issu" }, []).at(-1)).toBe(MCP_SEARCH_CANDIDATE);
    expect(generateMcpProxyCandidates({ server: "gh" }, []).at(-1)).toBe(MCP_LIST_CANDIDATE);
    expect(generateMcpProxyCandidates({}, []).at(-1)).toBe(MCP_STATUS_CANDIDATE);
  });

  it("ignores empty values and dedupes", () => {
    const candidates = generateMcpProxyCandidates({ server: "  ", tool: "a:b" }, []);
    expect(candidates.filter((c) => c.trim().length === 0)).toHaveLength(0);
    expect(new Set(candidates).size).toBe(candidates.length);
  });

  it("describe uses the tool target shape with the describe category", () => {
    const call = generateMcpProxyCandidates({ tool: "gh:x" }, []);
    const describe = generateMcpProxyCandidates({ describe: "gh:x" }, []);
    expect(describe.slice(0, -1)).toEqual(call.slice(0, -1));
    expect(describe.at(-1)).toBe(MCP_DESCRIBE_CANDIDATE);
  });
});

describe("generatePiMcpCandidates", () => {
  it("prefers the longest sanitized config server match", () => {
    const candidates = generatePiMcpCandidates("mcp__my.server__tool", "my.server", "tool", ["my_server", "other"]);
    expect(candidates).toContain("my_server_tool");
    expect(candidates).toContain("my_server:tool");
    expect(candidates).toContain("my_server");
    expect(candidates).toContain("tool");
    expect(candidates).toContain("mcp__my.server__tool");
    expect(candidates.at(-1)).toBe(MCP_CALL_CANDIDATE);
  });

  it("emits original and sanitized spellings without duplicates", () => {
    const candidates = generatePiMcpCandidates("mcp__plain__t", "plain", "t", ["plain"]);
    expect(candidates.filter((c) => c === "plain_t")).toHaveLength(1);
    expect(candidates.filter((c) => c === "plain:t")).toHaveLength(1);
  });

  it("sanitizes by replacing non-alphanumeric characters with underscores", () => {
    expect(sanitizeMcpName("my-server.v2")).toBe("my_server_v2");
  });
});
