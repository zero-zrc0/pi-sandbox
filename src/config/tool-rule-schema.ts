/**
 * Tool admission rule configuration (design §5, specs/config-schema.md §7).
 *
 * `toolRules` replaces the unwired `toolBindings` declaration list. One rule
 * names a tool (wildcard), optionally argument wildcards, a decision, and — for
 * `allow` — the file-access profile that builds approval facts plus, for
 * sandbox-hosted tools, the module location.
 *
 * Validation lives here so the config loader, the published JSON Schema and the
 * runtime evaluator reject exactly the same documents.
 */
import { z } from "zod";
import { nonEmptyStringSchema } from "./config-schema";
import {
  NPM_PACKAGE_NAME_PATTERN,
  TOOL_BINDING_ACCESSES,
  TOOL_BINDING_PROFILES,
  TOOL_BINDING_WHEN_ABSENT,
  isValidJsonPointer,
  type ToolBindingDeclaration,
} from "./tool-binding-schema";

/** Longest accepted rule id, in characters (audit references it verbatim). */
export const MAX_TOOL_RULE_ID_LENGTH = 200;

/** The two decisions a rule may declare; absence of a rule means `ask`. */
export const TOOL_RULE_DECISIONS = ["allow", "deny"] as const;

/** A rule id: 1-200 characters, stable in audit records. */
export const toolRuleIdSchema = z.string().min(1).max(MAX_TOOL_RULE_ID_LENGTH);

/** A wildcard pattern (`*` / `**` / `?`); validated structurally, matched later. */
export const toolRuleGlobSchema = nonEmptyStringSchema;

/** One argument matcher: JSON Pointer → wildcard. */
export const toolRuleArgumentsSchema = z.record(
  z.string().refine(isValidJsonPointer, "expected a valid JSON Pointer"),
  toolRuleGlobSchema,
);

/** One declared file location, reusing the binding vocabulary. */
export const toolRuleLocationSchema = z.strictObject({
  pointer: z.string().refine(isValidJsonPointer, "expected a valid JSON Pointer"),
  access: z.enum(TOOL_BINDING_ACCESSES),
  whenAbsent: z.enum(TOOL_BINDING_WHEN_ABSENT).optional(),
});

/**
 * A sandbox-hosted tool module: an npm package entry, a local path, or both
 * forms are rejected. `config` is opaque JSON handed to the module.
 */
export const toolRuleSandboxSchema = z
  .strictObject({
    package: z.string().regex(NPM_PACKAGE_NAME_PATTERN, "expected a lowercase npm package name").optional(),
    entry: nonEmptyStringSchema.optional(),
    path: nonEmptyStringSchema.optional(),
    /** Tool metadata the host registers; the module is never imported for it. */
    description: z.string().optional(),
    parameters: z.record(z.string(), z.unknown()).optional(),
    config: z.unknown().optional(),
  })
  .refine(
    (value) => value.package !== undefined || value.path !== undefined,
    "a sandbox tool needs a package or a path",
  )
  .refine(
    (value) => value.entry === undefined || value.package !== undefined,
    "an entry belongs to the package form",
  );

/** One admission rule. Unknown fields are rejected. */
export const toolRuleSchema = z
  .strictObject({
    id: toolRuleIdSchema,
    match: z.strictObject({
      tool: toolRuleGlobSchema,
      args: toolRuleArgumentsSchema.optional(),
    }),
    decision: z.enum(TOOL_RULE_DECISIONS),
    profile: z.enum(TOOL_BINDING_PROFILES).optional(),
    locations: z.array(toolRuleLocationSchema).min(1).optional(),
    sandbox: toolRuleSandboxSchema.optional(),
  })
  .refine(
    (value) => value.decision === "allow" || (value.profile === undefined && value.locations === undefined && value.sandbox === undefined),
    "profile, locations and sandbox are only valid on an allow rule",
  )
  .refine(
    (value) => value.locations === undefined || value.profile !== undefined,
    "declared locations need a profile",
  )
  .refine(
    (value) => value.locations === undefined || value.locations.length > 0,
    "locations must not be empty",
  )
  .refine(
    (value) => value.sandbox === undefined || (!value.match.tool.includes("*") && !value.match.tool.includes("?")),
    "a sandbox tool needs a concrete tool name",
  );

/** The `toolRules` scope: an ordered list of rules. */
export const toolRulesSchema = z.array(toolRuleSchema);

export type ToolRuleLocationDeclaration = z.infer<typeof toolRuleLocationSchema>;
export type ToolRuleSandboxDeclaration = z.infer<typeof toolRuleSandboxSchema>;
export type ToolRuleDeclaration = z.infer<typeof toolRuleSchema>;

/**
 * Deprecated `toolBindings` → `toolRules` migration (design §5.5).
 *
 * Each declaration becomes one tool-level `allow` rule. The origin/package
 * identity form is intentionally not carried over: a rule matches by tool name,
 * which is exactly the authority the old declaration exercised.
 */
export function migrateToolBindings(
  bindings: readonly ToolBindingDeclaration[],
): readonly ToolRuleDeclaration[] {
  return bindings.map((binding, index) => ({
    id: `toolBindings:${binding.tool}:${index}`.slice(0, MAX_TOOL_RULE_ID_LENGTH),
    match: { tool: binding.tool },
    decision: "allow" as const,
    profile: binding.profile,
    locations: binding.locations.map((location) => ({
      pointer: location.pointer,
      access: location.access,
      ...(location.whenAbsent === undefined ? {} : { whenAbsent: location.whenAbsent }),
    })),
  }));
}
