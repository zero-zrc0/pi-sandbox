/**
 * Published configuration schemas (specs/config-schema.md sections 3, 4 and 11).
 *
 * Two schemas live here. `runtimeConfigSchema` is the legacy extension runtime
 * configuration: every field is optional and it still accepts the old
 * `yoloMode`/`authorizerChain` selectors so an existing file can be migrated.
 * `approvalChainConfigSchema` is the formal model: the same runtime fields
 * minus those selectors, plus mode, approver, tool bindings, learning,
 * shared execution settings and approval nodes. Both are zod declarations, so the
 * published JSON Schema is generated from the same source as runtime
 * validation — there is no hand-written second model.
 *
 * Defaults are applied by the schemas themselves: parsing an empty document
 * yields the documented default configuration.
 */
import { z } from "zod";
import {
  jsonObjectSchema,
  nonEmptyStringListSchema,
  nonEmptyStringSchema,
  permissionConfigSchema,
  positiveIntegerSchema,
  safeIntegerSchema,
  issuesFromZodError,
  type ConfigParseResult,
} from "#config/config-schema";
import { approverConfigSchema } from "#config/approver-schema";
import { commandEffectsSchema } from "#config/command-effects-config";
import { permissionDialogKeysSchema } from "#config/dialog-keys";
import { executionConfigSchema } from "#config/execution-source-schema";
import { shellPolicySchema } from "#config/shell-policy-schema";
import { toolBindingsSchema } from "#config/tool-binding-schema";
import { PERMISSION_MODES, type PermissionModeName } from "#config/permission-mode";

export { PERMISSION_MODES, type PermissionModeName } from "#config/permission-mode";

/** Longest accepted approval node id, in characters. */
export const MAX_NODE_ID_LENGTH = 200;

/** Terminal notifications the prompt may emit. */
export const PROMPT_NOTIFICATIONS = Object.freeze(["bell", "osc9", "osc777"] as const);

/** Legacy configuration files a migration marker may name. */
export const LEGACY_CONFIG_SOURCES = Object.freeze([
  "legacy-global-policy",
  "legacy-project-policy",
  "legacy-extension-config",
] as const);

export type LegacyConfigSource = (typeof LEGACY_CONFIG_SOURCES)[number];

/* ------------------------------------------------------------------ */
/* Runtime fields shared by both schemas (section 3)                   */
/* ------------------------------------------------------------------ */

/** Named shell arguments: which input parameter carries the command and the workdir. */
export const shellToolSchema = z.strictObject({
  commandArgument: nonEmptyStringSchema,
  workdirArgument: nonEmptyStringSchema.optional(),
});

export const shellToolsSchema = z.record(z.string().min(1), shellToolSchema);

export type ShellTool = z.infer<typeof shellToolSchema>;
export type ShellTools = z.infer<typeof shellToolsSchema>;

/**
 * The runtime field table, declared once and reused by both schemas so the two
 * models cannot drift. Declaration order is the published JSON Schema order.
 */
const runtimeFieldSchemas = {
  $schema: z.string().optional(),
  debugLog: z.boolean().optional(),
  permissionReviewLog: z.boolean().optional(),
  yoloMode: z.boolean().optional(),
  doublePressToConfirm: z.boolean().optional(),
  forwardingTimeoutMs: positiveIntegerSchema.optional(),
  promptTimeoutMs: positiveIntegerSchema.optional(),
  promptMaxRows: positiveIntegerSchema.optional(),
  promptFieldMaxWidth: positiveIntegerSchema.optional(),
  reviewLogFieldMaxWidth: positiveIntegerSchema.optional(),
  // Deprecated preview caps: still accepted, no runtime effect.
  toolInputPreviewMaxLength: positiveIntegerSchema.optional(),
  toolTextSummaryMaxLength: positiveIntegerSchema.optional(),
  promptNotifications: z.array(z.enum(PROMPT_NOTIFICATIONS)).optional(),
  piInfrastructureReadPaths: nonEmptyStringListSchema.optional(),
  authorizerChain: nonEmptyStringListSchema.optional(),
  permission: permissionConfigSchema.optional(),
  shellTools: shellToolsSchema.optional(),
  commandEffects: commandEffectsSchema.optional(),
  permissionDialogKeys: permissionDialogKeysSchema.optional(),
} as const;

/** Legacy extension runtime configuration: all fields optional, no defaults. */
export const runtimeConfigSchema = z.strictObject(runtimeFieldSchemas);

export type RuntimeConfig = z.infer<typeof runtimeConfigSchema>;

/** The runtime fields carried over into the formal model. */
const { yoloMode: _removedYoloMode, authorizerChain: _removedAuthorizerChain, ...formalRuntimeFields } =
  runtimeFieldSchemas;

/* ------------------------------------------------------------------ */
/* Approval nodes (section 4)                                          */
/* ------------------------------------------------------------------ */

/**
 * One user approval node. The map key is the node id; an entry may never carry
 * its own id field.
 */
export const approvalNodeDeclarationSchema = z.strictObject({
  path: nonEmptyStringSchema.optional(),
  enabled: z.boolean().optional(),
  priority: safeIntegerSchema.optional(),
  options: jsonObjectSchema.optional(),
  description: nonEmptyStringSchema.optional(),
});

export type ApprovalNodeDeclaration = z.infer<typeof approvalNodeDeclarationSchema>;

export const approvalNodeIdSchema = z.string().min(1).max(MAX_NODE_ID_LENGTH);

/** Node declaration map; object key order is the declaration order. */
export const approvalNodesSchema = z.record(approvalNodeIdSchema, approvalNodeDeclarationSchema);

export type ApprovalNodes = z.infer<typeof approvalNodesSchema>;

export type ApprovalNodeOptions = z.infer<typeof jsonObjectSchema>;

/** A node entry: the declaration with its map key promoted to `id`. */
export interface ApprovalNodeEntry {
  readonly id: string;
  readonly path?: string;
  readonly enabled?: boolean;
  readonly priority?: number;
  readonly options?: ApprovalNodeOptions;
  readonly description?: string;
}

/**
 * Convert the declared node map into ordered entries. Object key order is the
 * declaration order, so no separate ordering field is needed.
 */
export function toNodeEntries(
  nodes: Readonly<Record<string, ApprovalNodeDeclaration>>,
): readonly ApprovalNodeEntry[] {
  return Object.entries(nodes).map(([id, declaration]) =>
    Object.freeze({
      id,
      ...(declaration.path === undefined ? {} : { path: declaration.path }),
      ...(declaration.enabled === undefined ? {} : { enabled: declaration.enabled }),
      ...(declaration.priority === undefined ? {} : { priority: declaration.priority }),
      ...(declaration.options === undefined ? {} : { options: declaration.options }),
      ...(declaration.description === undefined ? {} : { description: declaration.description }),
    }),
  );
}

/* ------------------------------------------------------------------ */
/* Formal approval-chain model (section 4)                             */
/* ------------------------------------------------------------------ */

export const learningConfigSchema = z.strictObject({
  enabled: z.boolean().default(false),
});

export const experimentalConfigSchema = z.strictObject({
  mcpSandbox: z.boolean().default(false),
});

export const approvalConfigSchema = z.strictObject({
  nodes: approvalNodesSchema.default({}),
});

export type LearningConfig = z.infer<typeof learningConfigSchema>;
export type ExperimentalConfig = z.infer<typeof experimentalConfigSchema>;
export type ApprovalConfig = z.infer<typeof approvalConfigSchema>;

/** Optional marker describing where a migrated file came from. */
export const configMigrationSchema = z.strictObject({
  version: z.literal(1),
  from: z.enum(LEGACY_CONFIG_SOURCES),
});

export type ConfigMigration = z.infer<typeof configMigrationSchema>;

/**
 * The formal approval-chain configuration. Removed legacy selectors
 * (`yoloMode`, `authorizerChain`, `strategy`) are unknown fields here and are
 * therefore rejected; the deprecated preview caps stay accepted.
 */
export const approvalChainConfigSchema = z.strictObject({
  ...formalRuntimeFields,
  mode: z.enum(PERMISSION_MODES).default("default"),
  approver: approverConfigSchema.prefault({}),
  toolBindings: toolBindingsSchema.default([]),
  learning: learningConfigSchema.prefault({}),
  execution: executionConfigSchema.prefault({}),
  experimental: experimentalConfigSchema.prefault({}),
  approval: approvalConfigSchema.prefault({}),
  shellPolicy: shellPolicySchema.optional(),
  migration: configMigrationSchema.optional(),
});

export type ApprovalChainConfig = z.infer<typeof approvalChainConfigSchema>;

/* ------------------------------------------------------------------ */
/* Parsing and publication (section 11)                                */
/* ------------------------------------------------------------------ */

/** Parse one runtime configuration scope. */
export function parseRuntimeConfig(value: unknown): ConfigParseResult<RuntimeConfig> {
  const result = runtimeConfigSchema.safeParse(value);
  return result.success
    ? { ok: true, config: result.data }
    : { ok: false, issues: issuesFromZodError(result.error) };
}

/** Parse one formal approval-chain configuration scope. */
export function parseApprovalChainConfig(value: unknown): ConfigParseResult<ApprovalChainConfig> {
  const result = approvalChainConfigSchema.safeParse(value);
  return result.success
    ? { ok: true, config: result.data }
    : { ok: false, issues: issuesFromZodError(result.error) };
}

export const APPROVAL_CHAIN_JSON_SCHEMA_ID = "urn:pi-sandbox:schema:approval-chain:1";
export const APPROVAL_CHAIN_JSON_SCHEMA_TITLE = "Pi permission approval-chain configuration";
export const APPROVAL_CHAIN_JSON_SCHEMA_DESCRIPTION =
  "Configuration accepted by the pi-sandbox approval chain, in its editor-facing input form.";

/**
 * Publish the formal configuration as a draft 2020-12 JSON Schema. The input
 * form is used so defaulted fields stay optional for editors; `$schema`,
 * `$id`, title and description are publishing metadata only.
 */
export function buildApprovalChainJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(approvalChainConfigSchema, {
    target: "draft-2020-12",
    io: "input",
  }) as Record<string, unknown>;
  const { $schema, ...rest } = generated;
  return {
    $schema,
    $id: APPROVAL_CHAIN_JSON_SCHEMA_ID,
    title: APPROVAL_CHAIN_JSON_SCHEMA_TITLE,
    description: APPROVAL_CHAIN_JSON_SCHEMA_DESCRIPTION,
    ...rest,
  };
}
