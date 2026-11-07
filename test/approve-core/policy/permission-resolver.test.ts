import { describe, expect, it } from "vitest";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";

function harness(permission: unknown) {
  const normalizer = new PathNormalizer(POSIX, "/work", {
    realpathSync: (path) => path,
    existsSync: () => false,
  });
  const session = new SessionRuleStore({ flavor: POSIX });
  const manager = new PermissionManager({
    flavor: POSIX,
    session,
    loadPolicy: () => ({ stamp: "s1", scopes: { global: { permission } } }),
  });
  const resolver = new PermissionResolver({ manager, normalizer });
  return { manager, resolver, session, normalizer };
}

describe("raw tool resolution", () => {
  it("checks ordinary tools on their own surface", () => {
    const { resolver } = harness({ tool: "allow" });
    expect(resolver.check({ toolName: "tool", input: {} })).toMatchObject({
      state: "allow",
      toolName: "tool",
      target: "*",
    });
  });

  it("resolves builtin path tool inputs into path values", () => {
    const { resolver } = harness({ read: { "/work/*": "allow" } });
    expect(resolver.check({ toolName: "read", input: { path: "a.txt" } })).toMatchObject({
      state: "allow",
      target: "/work/a.txt",
      matchedPattern: "/work/*",
    });
  });

  it("resolves shell calls into command intents", () => {
    const { resolver } = harness({ bash: { "git *": "deny" } });
    expect(resolver.check({ toolName: "bash", input: { command: "git status" } })).toMatchObject({
      state: "deny",
      command: "git status",
    });
  });

  it("reads MCP server names dynamically when resolving Pi MCP tools", () => {
    const { manager, normalizer } = harness({ mcp: { "my.server_tool": "allow" } });
    let servers = ["old.server"];
    const resolver = new PermissionResolver({
      manager,
      normalizer,
      mcpConfigServers: () => servers,
    });

    const before = resolver.buildIntent("my_server__tool", {});
    expect(before.kind).toBe("fixed-values");
    if (before.kind !== "fixed-values") throw new Error("expected MCP candidates");
    expect(before.values).not.toContain("my.server_tool");
    servers = ["my.server"];
    const after = resolver.buildIntent("my_server__tool", {});
    expect(after.kind).toBe("fixed-values");
    if (after.kind !== "fixed-values") throw new Error("expected MCP candidates");
    expect(after.values).toContain("my.server_tool");
  });
});

describe("path resolution", () => {
  it("uses the session cwd for relative literals", () => {
    const { resolver } = harness({ path_read: { "/work/*": "allow" } });
    expect(resolver.checkPath("path_read", "a.txt")).toMatchObject({
      state: "allow",
      target: "/work/a.txt",
      source: "special",
    });
  });

  it("honors an independent base directory", () => {
    const { resolver } = harness({ path_read: { "/work/sub/*": "allow" } });
    expect(resolver.checkPath("path_read", "a.log", { baseDir: "/work/sub" })).toMatchObject({
      state: "allow",
      target: "/work/sub/a.log",
    });
  });

  it("does not rebuild already resolved path values", () => {
    const { resolver } = harness({ path_read: { "rel-only": "deny" } });
    const result = resolver.checkPathValues("path_read", [{
      display: "rel-only",
      matchValues: ["rel-only"],
      boundary: "",
    }]);
    expect(result).toMatchObject({ state: "deny", target: "rel-only" });
  });

  it("reports the tool name on path checks when given", () => {
    const { resolver } = harness({ path_read: "allow" });
    expect(resolver.checkPath("path_read", "/work/a", { toolName: "read" }).toolName).toBe("read");
  });
});

describe("session attachment", () => {
  it("applies session approvals without the caller passing them", () => {
    const { resolver, session } = harness({ bash: "ask" });
    session.approve("bash", "git *");
    expect(resolver.check({ toolName: "bash", input: { command: "git status" } })).toMatchObject({
      state: "allow",
      source: "session",
    });
  });
});
