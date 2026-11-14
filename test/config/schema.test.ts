import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  APPROVAL_CHAIN_JSON_SCHEMA_ID,
  APPROVAL_CHAIN_JSON_SCHEMA_TITLE,
  LEGACY_CONFIG_SOURCES,
  MAX_NODE_ID_LENGTH,
  PERMISSION_MODES,
  approvalChainConfigSchema,
  approvalNodesSchema,
  buildApprovalChainJsonSchema,
  parseApprovalChainConfig,
  parseRuntimeConfig,
  runtimeConfigSchema,
  toNodeEntries,
} from "#config/schema";

type JsonSchema = Record<string, unknown>;

function keyOf(schema: unknown, key: string): JsonSchema {
  const record = schema as JsonSchema;
  return record[key] as JsonSchema;
}

function schemaAt(root: unknown, path: readonly string[]): JsonSchema {
  let current = root as JsonSchema;
  for (const segment of path) current = keyOf(current, segment);
  return current;
}

function rejects(value: unknown, schema: z.ZodType = approvalChainConfigSchema): boolean {
  return !schema.safeParse(value).success;
}

function paths(value: unknown, schema: z.ZodType = approvalChainConfigSchema): readonly string[] {
  const result = schema.safeParse(value);
  if (result.success) return [];
  return result.error.issues.map((issue) => issue.path.map(String).join("."));
}

const minimalChain = {};

function node(id: string, declaration: Record<string, unknown>): Record<string, unknown> {
  return { approval: { nodes: { [id]: declaration } } };
}

describe("runtime configuration schema", () => {
  it("accepts an empty runtime configuration without inventing values", () => {
    expect(runtimeConfigSchema.parse({})).toEqual({});
    expect(parseRuntimeConfig({})).toEqual({ ok: true, config: {} });
  });

  it("accepts every optional runtime field", () => {
    const config = {
      $schema: "https://example.test/config.schema.json",
      debugLog: true,
      permissionReviewLog: false,
      yoloMode: true,
      doublePressToConfirm: true,
      forwardingTimeoutMs: 3000,
      promptTimeoutMs: 60000,
      promptMaxRows: 12,
      promptFieldMaxWidth: 80,
      reviewLogFieldMaxWidth: 120,
      toolInputPreviewMaxLength: 200,
      toolTextSummaryMaxLength: 80,
      promptNotifications: ["bell", "osc9", "osc777"],
      piInfrastructureReadPaths: ["~/.pi/cache"],
      authorizerChain: ["builtin/rules", "model"],
      permission: { bash: { "git status": "allow" }, path_write: "ask" },
      shellTools: { shell: { commandArgument: "command", workdirArgument: "cwd" } },
      commandEffects: { tool: { effects: "write" } },
      permissionDialogKeys: { approve: "y" },
    };
    expect(runtimeConfigSchema.safeParse(config).success).toBe(true);
  });

  it("rejects unknown runtime fields and a legacy selector outside the runtime table", () => {
    expect(parseRuntimeConfig({ unknownField: true })).toEqual({
      ok: false,
      issues: [{ path: "unknownField", code: "unknown-key", message: 'unexpected field: unknownField' }],
    });
    expect(rejects({ strategy: "model" }, runtimeConfigSchema)).toBe(true);
  });

  it("rejects malformed runtime field shapes", () => {
    const invalid = [
      { debugLog: "yes" },
      { forwardingTimeoutMs: 0 },
      { promptMaxRows: 1.5 },
      { toolInputPreviewMaxLength: -1 },
      { promptNotifications: ["ding"] },
      { promptNotifications: "bell" },
      { piInfrastructureReadPaths: [""] },
      { piInfrastructureReadPaths: [1] },
      { authorizerChain: [""] },
      { permision: {} },
      { shellTools: { shell: { commandArgument: "" } } },
      { shellTools: { shell: { commandArgument: "command", extra: 1 } } },
      { commandEffects: { "a/b": { effects: "read" } } },
      { permission: { "": "allow" } },
    ];
    for (const value of invalid) expect(rejects(value, runtimeConfigSchema)).toBe(true);
  });

  it("keeps the deprecated preview caps accepted", () => {
    expect(runtimeConfigSchema.safeParse({ toolInputPreviewMaxLength: 100, toolTextSummaryMaxLength: 40 }).success).toBe(true);
  });
});

describe("formal approval-chain defaults", () => {
  it("parses an empty document into the documented default configuration", () => {
    expect(approvalChainConfigSchema.parse(minimalChain)).toEqual({
      mode: "default",
      approver: { timeoutMs: 15000, decisionContextAcquisition: "llm" },
      toolBindings: [],
      toolRules: [],
      learning: { enabled: false },
      execution: {},
      experimental: { sandboxEnabled: false },
      approval: { nodes: {} },
    });
    expect(parseApprovalChainConfig(minimalChain)).toEqual({
      ok: true,
      config: approvalChainConfigSchema.parse(minimalChain),
    });
  });

  it("exposes the four permission modes", () => {
    expect(PERMISSION_MODES).toEqual(["read-only", "default", "auto-review", "full-access"]);
    for (const mode of PERMISSION_MODES) {
      expect(approvalChainConfigSchema.parse({ mode }).mode).toBe(mode);
    }
    for (const mode of ["readonly", "full access", "yolo"]) {
      expect(rejects({ mode })).toBe(true);
    }
  });

  it("rejects the removed legacy selectors", () => {
    for (const value of [{ yoloMode: true }, { authorizerChain: ["model"] }, { strategy: "model" }]) {
      expect(rejects(value)).toBe(true);
      const result = approvalChainConfigSchema.safeParse(value);
      expect(result.success).toBe(false);
      if (result.success) continue;
      expect(result.error.issues.map((issue) => issue.code)).toContain("unrecognized_keys");
    }
  });

  it("still accepts the deprecated preview caps after merge", () => {
    expect(parseApprovalChainConfig({ toolInputPreviewMaxLength: 10, toolTextSummaryMaxLength: 10 }).ok).toBe(true);
  });

  it.each([true, false])("ignores the removed MCP sandbox setting when loading legacy configuration (%s)", mcpSandbox => {
    const result = parseApprovalChainConfig({ experimental: { mcpSandbox } });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.config.experimental).toEqual({ sandboxEnabled: false });
  });
});

describe("approval nodes", () => {
  it("accepts a node map and preserves declaration order in node entries", () => {
    const config = approvalChainConfigSchema.parse({
      approval: {
        nodes: {
          "user:first": { path: "./first.ts", enabled: false, priority: -3, options: { label: "first" } },
          "user:second": { path: "./second.ts" },
        },
      },
    });
    expect(Object.keys(config.approval.nodes)).toEqual(["user:first", "user:second"]);
    expect(toNodeEntries(config.approval.nodes)).toEqual([
      { id: "user:first", path: "./first.ts", enabled: false, priority: -3, options: { label: "first" } },
      { id: "user:second", path: "./second.ts" },
    ]);
  });

  it("carries an optional display description through node entries", () => {
    const config = approvalChainConfigSchema.parse({
      approval: {
        nodes: {
          "user:described": { path: "./x.ts", description: "Reviews database migrations." },
        },
      },
    });
    expect(toNodeEntries(config.approval.nodes)).toEqual([
      { id: "user:described", path: "./x.ts", description: "Reviews database migrations." },
    ]);
    expect(parseApprovalChainConfig(node("user:a", { path: "./x.ts", description: "" })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { path: "./x.ts", description: 7 })).ok).toBe(false);
  });

  it("accepts a node id of exactly the maximum length and rejects a longer one", () => {
    const longest = "n".repeat(MAX_NODE_ID_LENGTH);
    expect(MAX_NODE_ID_LENGTH).toBe(200);
    expect(parseApprovalChainConfig(node(longest, { path: "./x.ts" })).ok).toBe(true);
    expect(parseApprovalChainConfig(node("n".repeat(MAX_NODE_ID_LENGTH + 1), { path: "./x.ts" })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("", { path: "./x.ts" })).ok).toBe(false);
  });

  it("rejects node fields outside the frozen four", () => {
    expect(parseApprovalChainConfig(node("user:a", { id: "user:a", path: "./x.ts" })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { path: "./x.ts", unknown: true })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { path: "" })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { enabled: "yes" })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { priority: 1.5 })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { priority: 2 ** 60 })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { options: [] })).ok).toBe(false);
    expect(parseApprovalChainConfig(node("user:a", { options: { bad: undefined } })).ok).toBe(false);
  });

  it("reports the offending node field path", () => {
    const result = parseApprovalChainConfig(node("user:a", { id: "user:a", path: "./x.ts" }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((issue) => issue.path)).toContain('approval.nodes["user:a"].id');
    expect(result.issues.map((issue) => issue.code)).toContain("unknown-key");
  });

  it("accepts a node declaration with no fields", () => {
    expect(parseApprovalChainConfig(node("user:bare", {})).ok).toBe(true);
  });
});

describe("approval-chain sections", () => {
  it("keeps the runtime fields the formal model retains", () => {
    const config = {
      $schema: "./config.schema.json",
      debugLog: true,
      permissionReviewLog: true,
      doublePressToConfirm: false,
      forwardingTimeoutMs: 1000,
      promptTimeoutMs: 2000,
      promptMaxRows: 8,
      promptFieldMaxWidth: 40,
      reviewLogFieldMaxWidth: 160,
      promptNotifications: ["bell"],
      piInfrastructureReadPaths: ["~/.pi/cache"],
      permission: { bash: "ask" },
      shellTools: { shell: { commandArgument: "command" } },
      commandEffects: { tool: { effects: ["read", "write"], unlessOption: ["--dry-run"] } },
    };
    expect(parseApprovalChainConfig(config).ok).toBe(true);
  });

  it("treats dialog keys as a display preference, never as a permission failure", () => {
    for (const permissionDialogKeys of [
      { approve: "A" },
      { approve: "j" },
      { approve: "+" },
      { approve: "yy" },
      { unknownAction: "x" },
    ]) {
      expect(parseApprovalChainConfig({ permissionDialogKeys }).ok).toBe(true);
    }
    // A wrongly typed value is a schema violation, not an unbindable character.
    expect(parseApprovalChainConfig({ permissionDialogKeys: { approve: 1 } }).ok).toBe(false);
    expect(parseApprovalChainConfig({ permissionDialogKeys: [] }).ok).toBe(false);
  });

  it("rejects malformed command effects and shell tools in the formal model", () => {
    expect(parseApprovalChainConfig({ commandEffects: { "a/b": { effects: "read" } } }).ok).toBe(false);
    expect(parseApprovalChainConfig({ commandEffects: { tool: { effects: "execute" } } }).ok).toBe(false);
    expect(parseApprovalChainConfig({ shellTools: { shell: { commandArgument: "" } } }).ok).toBe(false);
  });

  it("accepts a complete section set", () => {
    const config = {
      mode: "auto-review",
      approver: { provider: "anthropic", model: "claude", surfaces: ["bash"], instructions: "be careful" },
      toolBindings: [{
        tool: "read_file",
        profile: "file-reader",
        locations: [{ pointer: "/path", access: "read" }],
        origin: "builtin",
      }],
      learning: { enabled: true },
      execution: { network: { mode: "none" } },
      experimental: { sandboxEnabled: false },
      approval: { nodes: {} },
    };
    expect(parseApprovalChainConfig(config).ok).toBe(true);
    expect(approvalChainConfigSchema.parse(config).mode).toBe("auto-review");
  });

  it("rejects invalid sections instead of repairing them", () => {
    const invalid = [
      { approver: { provider: "only-provider" } },
      { toolBindings: [{ tool: "x" }] },
      { learning: { enabled: "true" } },
      { learning: { enabled: true, extra: 1 } },
      { learning: [] },
      { execution: { sources: [] } },
      { execution: { network: { mode: "allowlist", allow: [] } } },
      { execution: { unknown: true } },
      { experimental: { mcpSandbox: "yes" } },
      { experimental: { unknown: true } },
      { approval: { nodes: [] } },
      { approval: { nodes: {}, extra: 1 } },
      { approval: [] },
    ];
    for (const value of invalid) expect(rejects(value)).toBe(true);
  });

  it("validates migration markers against version 1 and the legacy source categories", () => {
    expect(LEGACY_CONFIG_SOURCES).toEqual([
      "legacy-global-policy", "legacy-project-policy", "legacy-extension-config",
    ]);
    for (const from of LEGACY_CONFIG_SOURCES) {
      expect(parseApprovalChainConfig({ migration: { version: 1, from } }).ok).toBe(true);
    }
    for (const migration of [
      { version: 2, from: "legacy-global-policy" },
      { version: 1, from: "npm-script" },
      { version: 1 },
      { from: "legacy-global-policy" },
      { version: 1, from: "legacy-global-policy", extra: true },
    ]) {
      expect(parseApprovalChainConfig({ migration }).ok).toBe(false);
    }
  });

  it("does not treat frontmatter-shaped permission text as authorization", () => {
    expect(parseApprovalChainConfig({ permission: [] as unknown }).ok).toBe(false);
  });
});

describe("approval-chain JSON schema", () => {
  const schema = buildApprovalChainJsonSchema();

  it("is a draft 2020-12 schema with publishing metadata", () => {
    expect(schema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(schema["$id"]).toBe(APPROVAL_CHAIN_JSON_SCHEMA_ID);
    expect(schema.title).toBe(APPROVAL_CHAIN_JSON_SCHEMA_TITLE);
    expect(schema.type).toBe("object");
    expect(schema.additionalProperties).toBe(false);
  });

  it("declares exactly the spec's fields in declaration order", () => {
    expect(Object.keys(keyOf(schema, "properties"))).toEqual([
      "$schema",
      "debugLog",
      "permissionReviewLog",
      "doublePressToConfirm",
      "forwardingTimeoutMs",
      "promptTimeoutMs",
      "promptMaxRows",
      "promptFieldMaxWidth",
      "reviewLogFieldMaxWidth",
      "toolInputPreviewMaxLength",
      "toolTextSummaryMaxLength",
      "promptNotifications",
      "piInfrastructureReadPaths",
      "permission",
      "shellTools",
      "commandEffects",
      "permissionDialogKeys",
      "mode",
      "approver",
      "toolBindings",
      "toolRules",
      "learning",
      "execution",
      "experimental",
      "approval",
      "shellPolicy",
      "migration",
    ]);
    expect(schema.required).toBeUndefined();
  });

  it("matches the runtime defaults", () => {
    const properties = keyOf(schema, "properties");
    expect(keyOf(properties, "mode").default).toBe("default");
    expect(keyOf(properties, "toolBindings").default).toEqual([]);
    expect(keyOf(properties, "toolRules").default).toEqual([]);
    expect(keyOf(properties, "learning").default).toEqual({});
    expect(keyOf(properties, "execution").default).toEqual({});
    expect(keyOf(properties, "approval").default).toEqual({});
    expect(keyOf(properties, "approver").default).toEqual({});
    expect(schemaAt(schema, ["properties", "mode"]).enum).toEqual([...PERMISSION_MODES]);
    expect(schemaAt(schema, ["properties", "approver", "properties", "timeoutMs"]).default).toBe(15000);
    expect(schemaAt(schema, ["properties", "approver", "properties", "decisionContextAcquisition"]).default).toBe("llm");
    expect(schemaAt(schema, ["properties", "learning", "properties", "enabled"]).default).toBe(false);
    expect(schemaAt(schema, ["properties", "execution", "properties"])).not.toHaveProperty("sources");
    expect(schemaAt(schema, ["properties", "approval", "properties", "nodes"]).default).toEqual({});
    const parsed = approvalChainConfigSchema.parse(minimalChain);
    expect(parsed.mode).toBe(keyOf(properties, "mode").default);
    expect(parsed.approver.timeoutMs).toBe(schemaAt(schema, ["properties", "approver", "properties", "timeoutMs"]).default);
    expect(parsed.learning.enabled).toBe(schemaAt(schema, ["properties", "learning", "properties", "enabled"]).default);
    expect(parsed.execution).toEqual({});
    expect(parsed.approval.nodes).toEqual(schemaAt(schema, ["properties", "approval", "properties", "nodes"]).default);
  });

  it("publishes the frozen node declaration fields", () => {
    const declaration = schemaAt(schema, ["properties", "approval", "properties", "nodes", "additionalProperties"]);
    expect(Object.keys(keyOf(declaration, "properties"))).toEqual(["path", "enabled", "priority", "kind", "options", "description"]);
    expect(declaration.additionalProperties).toBe(false);
    expect(declaration.required).toBeUndefined();
    expect(schemaAt(schema, ["properties", "approval", "properties", "nodes"]).propertyNames)
      .toMatchObject({ type: "string", minLength: 1, maxLength: MAX_NODE_ID_LENGTH });
  });

  it("leaves the permission surface rule to the runtime direction check", () => {
    const permission = keyOf(keyOf(schema, "properties"), "permission");
    expect(permission.propertyNames).toEqual({ type: "string", minLength: 1 });
    expect(keyOf(permission, "propertyNames").enum).toBeUndefined();
    expect(keyOf(permission, "propertyNames").pattern).toBeUndefined();
    expect(approvalChainConfigSchema.safeParse({
      permission: {
        "*": "ask",
        path: "ask",
        path_read: "allow",
        path_write: "deny",
        external_directory: "ask",
        external_directory_read: "allow",
        external_directory_write: "deny",
        bash: "ask",
        mcp: "allow",
        skill: "deny",
        read: "allow",
        custom_tool: { "*": "ask" },
      },
    }).success).toBe(true);
    expect(approvalChainConfigSchema.safeParse({ permission: { path_reed: "allow" } }).success).toBe(false);
    expect(approvalChainConfigSchema.safeParse({ permission: { external_directory_reed: "allow" } }).success).toBe(false);
  });

  it("is deterministic and matches the committed artifact", () => {
    expect(buildApprovalChainJsonSchema()).toEqual(buildApprovalChainJsonSchema());
    // The artifact is generated with LF; tolerate a CRLF worktree checkout so
    // the drift guard tests the schema, not the checkout's line endings.
    const committed = readFileSync(new URL("../../schemas/permissions.schema.json", import.meta.url), "utf8")
      .replace(/\r\n/g, "\n");
    expect(committed).toBe(`${JSON.stringify(buildApprovalChainJsonSchema(), null, 2)}\n`);
  });
});

describe("parse results", () => {
  it("reports every failing field path for a mixed-invalid document", () => {
    const result = parseApprovalChainConfig({ mode: "yolo", approval: { nodes: { "user:a": { path: "" } } } });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const paths = result.issues.map((issue) => issue.path);
    expect(paths).toContain("mode");
    expect(paths).toContain('approval.nodes["user:a"].path');
  });

  it("returns the parsed model on success", () => {
    const result = parseApprovalChainConfig({ mode: "read-only" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.mode).toBe("read-only");
  });

  it("treats a non-object document as invalid", () => {
    for (const value of [null, "x", 1, []]) {
      expect(parseApprovalChainConfig(value).ok).toBe(false);
    }
  });

  it("reports an unknown top-level field as an unknown-key issue", () => {
    expect(parseApprovalChainConfig({ extra: 1 })).toEqual({
      ok: false,
      issues: [{ path: "extra", code: "unknown-key", message: "unexpected field: extra" }],
    });
  });

  it("nodes schema is the same declaration used by the formal schema", () => {
    expect(approvalNodesSchema.parse({})).toEqual({});
    expect(approvalNodesSchema.safeParse({ "user:a": { path: "./a.ts" } }).success).toBe(true);
  });
});

