import { describe, expect, it } from "vitest";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { PermissionService } from "#approve-core/policy/permissions-service";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";

function harness(
  permission: unknown,
  options: {
    units?: (command: string) => readonly string[] | undefined;
    maxRegistrations?: number;
  } = {},
) {
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
  const service = new PermissionService({
    manager,
    resolver,
    normalizer,
    session,
    ...(options.units === undefined ? {} : { bash: { units: options.units } }),
    ...(options.maxRegistrations === undefined
      ? {}
      : { maxRegistrations: options.maxRegistrations }),
  });
  return { service, manager, resolver, session, normalizer };
}

describe("bash queries", () => {
  it("falls back to the whole string when the parser is cold", () => {
    const { service } = harness({ bash: { "*": "allow", "git status && rm *": "deny" } });
    expect(service.checkBash("git status && rm -rf /")).toMatchObject({
      state: "deny",
      command: "git status && rm -rf /",
    });
  });

  it("decomposes the command when the parser is warm", () => {
    const { service } = harness(
      { bash: { "git *": "allow", "rm *": "deny" } },
      { units: () => ["git status", "rm -rf /"] },
    );
    const result = service.checkBash("git status && rm -rf /");
    expect(result.state).toBe("deny");
    expect(result.command).toBe("rm -rf /");
  });

  it("takes the most restrictive unit and keeps the first on ties", () => {
    const { service } = harness(
      { bash: { "git *": "ask", "npm *": "ask" } },
      { units: () => ["git status", "npm test"] },
    );
    expect(service.checkBash("git status && npm test")).toMatchObject({
      state: "ask",
      command: "git status",
    });
  });

  it("falls back to the whole string for an empty unit list", () => {
    const { service } = harness(
      { bash: "deny" },
      { units: () => [] },
    );
    expect(service.checkBash("ls").state).toBe("deny");
  });
});

describe("path and tool queries", () => {
  it("shares the gate path normalizer", () => {
    const { service, normalizer } = harness({ path_read: { "/work/*": "allow" } });
    expect(service.pathNormalizer).toBe(normalizer);
    expect(service.checkPath("path_read", "a.txt")).toMatchObject({
      state: "allow",
      target: "/work/a.txt",
    });
  });

  it("checks MCP tools with fixed name candidates", () => {
    const { service } = harness({ mcp: "allow" });
    expect(service.checkMcp("mcp__gh__issues")).toMatchObject({
      toolName: "mcp__gh__issues",
      state: "allow",
      source: "mcp",
    });
  });

  it("forwards tool-level and fully-denied queries", () => {
    const { service } = harness({ tool: "deny" });
    expect(service.toolState("tool")).toBe("deny");
    expect(service.isToolFullyDenied("tool")).toBe(true);
  });

  it("uses the requested agent rules when agent policy stamps match", () => {
    const session = new SessionRuleStore({ flavor: POSIX });
    const normalizer = new PathNormalizer(POSIX, "/work", {
      realpathSync: path => path,
      existsSync: () => false,
    });
    const policies = {
      writer: { stamp: "same-mtime", scopes: { global: { permission: { tool: "allow" } }, agent: { permission: { tool: "allow" } } } },
      planner: { stamp: "same-mtime", scopes: { global: { permission: { tool: "allow" } }, agent: { permission: { tool: "deny" } } } },
    } as const;
    const manager = new PermissionManager({
      flavor: POSIX,
      session,
      loadPolicy: (agent?: string) => policies[agent === "planner" ? "planner" : "writer"],
    });
    const resolver = new PermissionResolver({ manager, normalizer });
    const service = new PermissionService({ manager, resolver, normalizer, session });

    expect(service.toolState("tool", "writer")).toBe("allow");
    expect(service.toolState("tool", "planner")).toBe("deny");
  });

  it("forwards ordinary tool checks", () => {
    const { service } = harness({ tool: "allow" });
    expect(service.checkTool("tool", {}).state).toBe("allow");
  });
});

describe("session access", () => {
  it("approves through the shared store and reflects the grant", () => {
    const { service } = harness({ bash: "ask" });
    service.approve("bash", "git *");
    expect(service.checkBash("git status").state).toBe("allow");
    service.clearSession();
    expect(service.checkBash("git status").state).toBe("ask");
  });
});

describe("formatter registry", () => {
  it("registers, resolves and disposes by name", () => {
    const { service } = harness({});
    const formatter = { render: () => "x" };
    const registration = service.registerFormatter("read", formatter);
    expect(registration).toBeDefined();
    expect(service.resolveFormatter("read")).toBe(formatter);
    expect(service.formatterNames()).toEqual(["read"]);
    registration!.dispose();
    expect(service.resolveFormatter("read")).toBeUndefined();
    expect(service.formatterNames()).toEqual([]);
  });

  it("rejects a duplicate registration", () => {
    const { service } = harness({});
    const first = service.registerFormatter("read", { id: 1 });
    expect(service.registerFormatter("read", { id: 2 })).toBeUndefined();
    expect(service.resolveFormatter("read")).toEqual({ id: 1 });
    first!.dispose();
    expect(service.registerFormatter("read", { id: 3 })).toBeDefined();
  });

  it("keeps a later registration when an old disposer runs", () => {
    const { service } = harness({});
    const first = service.registerFormatter("read", { id: 1 })!;
    first.dispose();
    const second = service.registerFormatter("read", { id: 2 })!;
    first.dispose();
    expect(service.resolveFormatter("read")).toEqual({ id: 2 });
    second.dispose();
  });

  it("rejects names beyond the bound", () => {
    const { service } = harness({}, { maxRegistrations: 1 });
    expect(service.registerFormatter("a", {})).toBeDefined();
    expect(service.registerFormatter("b", {})).toBeUndefined();
  });

  it("keeps access extractors in their own registry", () => {
    const { service } = harness({});
    const extractor = { extract: () => "a.txt" };
    expect(service.registerAccessExtractor("custom", extractor)).toBeDefined();
    expect(service.resolveAccessExtractor("custom")).toBe(extractor);
    expect(service.resolveFormatter("custom")).toBeUndefined();
    expect(service.accessExtractorNames()).toEqual(["custom"]);
  });

  it("exposes the extractor registry as the access-intent lookup seam", () => {
    const { service } = harness({});
    const extractor = { origin: "local" as const, extract: () => "a.txt" };
    service.registerAccessExtractor("custom", extractor);
    service.registerAccessExtractor("broken", { extract: () => "x" });
    const lookup = service.extractorLookup();
    expect(lookup.lookup("custom")).toBe(extractor);
    expect(lookup.lookup("broken")).toBeUndefined();
    expect(lookup.lookup("missing")).toBeUndefined();
  });
});
