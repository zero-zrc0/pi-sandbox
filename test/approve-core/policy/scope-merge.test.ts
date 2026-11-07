import { describe, expect, it } from "vitest";
import {
  mergeScopePermissions,
  SCOPE_PRIORITY,
} from "#approve-core/policy/scope-merge";
import { originOf } from "#approve-core/policy/permission-merge";

function entries(result: ReturnType<typeof mergeScopePermissions>, surface: string) {
  return (result.surfaces.get(surface)?.entries ?? []).map((entry) => [
    entry.pattern,
    entry.action,
  ]);
}

describe("scope priority", () => {
  it("folds scopes from global to project-agent regardless of input key order", () => {
    expect(SCOPE_PRIORITY).toEqual(["global", "project", "agent", "project-agent"]);
    const result = mergeScopePermissions({
      "project-agent": { permission: { bash: { "git *": "deny" } } },
      agent: { permission: { bash: { "git *": "ask" } } },
      project: { permission: { bash: { "git *": "allow" } } },
      global: { permission: { bash: { "git *": "deny" } } },
    });
    expect(entries(result, "bash")).toEqual([["git *", "deny"]]);
    expect(originOf(result, "bash", "git *")).toBe("project-agent");
  });
});

describe("pattern merging", () => {
  it("merges objects pattern by pattern and keeps lower origins", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: { "git *": "allow", "npm *": "ask" } } },
      project: { permission: { bash: { "git push": "deny" } } },
    });
    expect(entries(result, "bash")).toEqual([
      ["git *", "allow"],
      ["npm *", "ask"],
      ["git push", "deny"],
    ]);
    expect(originOf(result, "bash", "git *")).toBe("global");
    expect(originOf(result, "bash", "git push")).toBe("project");
  });

  it("lets a higher scope overwrite the same pattern in place of the lower one", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: { "git *": "deny" } } },
      project: { permission: { bash: { "git *": "allow" } } },
    });
    expect(entries(result, "bash")).toEqual([["git *", "allow"]]);
    expect(originOf(result, "bash", "git *")).toBe("project");
  });

  it("keeps the lower position when a higher scope overrides the same pattern", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: { "git *": "deny", "git push *": "allow" } } },
      project: { permission: { bash: { "git *": "ask" } } },
    });
    expect(entries(result, "bash")).toEqual([
      ["git *", "ask"],
      ["git push *", "allow"],
    ]);
  });

  it("replaces the whole surface when a higher scope uses a catch-all string", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: { "git *": "allow", "npm *": "allow" } } },
      project: { permission: { bash: "deny" } },
    });
    expect(entries(result, "bash")).toEqual([["*", "deny"]]);
    expect(originOf(result, "bash", "*")).toBe("project");
    expect(originOf(result, "bash", "git *")).toBeUndefined();
  });

  it("replaces the whole surface when a lower scope used a catch-all string", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: "allow" } },
      project: { permission: { bash: { "git *": "deny" } } },
    });
    expect(entries(result, "bash")).toEqual([["git *", "deny"]]);
  });

  it("keeps surfaces that a higher scope does not mention", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: "allow", skill: { deploy: "deny" } } },
      project: { permission: { bash: "ask" } },
    });
    expect(entries(result, "skill")).toEqual([["deploy", "deny"]]);
    expect(originOf(result, "skill", "deploy")).toBe("global");
  });
});

describe("family expansion before merging", () => {
  it("expands each scope before the merge", () => {
    const result = mergeScopePermissions({
      global: { permission: { path: { "*": "allow" } } },
      project: { permission: { path_write: { "/tmp/*": "deny" } } },
    });
    expect(entries(result, "path_read")).toEqual([["*", "allow"]]);
    expect(entries(result, "path_write")).toEqual([
      ["*", "allow"],
      ["/tmp/*", "deny"],
    ]);
    expect(originOf(result, "path_write", "*")).toBe("global");
    expect(originOf(result, "path_write", "/tmp/*")).toBe("project");
  });

  it("keeps a bare family catch-all as a catch-all surface value", () => {
    const result = mergeScopePermissions({
      global: { permission: { path: "allow" } },
      project: { permission: { path_write: { "/tmp/*": "deny" } } },
    });
    expect(entries(result, "path_write")).toEqual([["/tmp/*", "deny"]]);
  });
});

describe("universal default", () => {
  it("takes the highest scope universal default and records its origin", () => {
    const result = mergeScopePermissions({
      global: { permission: { "*": "deny" } },
      project: { permission: { "*": "allow" } },
    });
    expect(result.universal).toEqual({ action: "allow", origin: "project" });
  });

  it("keeps a lower universal default when a higher scope has none", () => {
    const result = mergeScopePermissions({
      global: { permission: { "*": "allow" } },
      project: { permission: { bash: "ask" } },
    });
    expect(result.universal).toEqual({ action: "allow", origin: "global" });
  });
});

describe("invalid scopes", () => {
  it("reports invalid scopes without dropping their entries", () => {
    const result = mergeScopePermissions({
      global: { permission: { bash: "allow" } },
      project: { permission: { bash: "ask" }, invalid: true },
      agent: { invalid: true },
    });
    expect(result.invalidScopes).toEqual(["project", "agent"]);
    expect(entries(result, "bash")).toEqual([["*", "ask"]]);
  });
});
