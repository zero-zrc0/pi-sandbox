/**
 * Shared configuration schema foundation.
 *
 * Every configuration declaration in this package is a zod schema, so the same
 * declaration drives both runtime validation and the published JSON Schema.
 * This module holds the validation primitives every configuration file shares
 * and the permission map, whose shape predates the rest of the model.
 *
 * Validation philosophy: machine-readable categories stay stable, strings keep
 * the text the user wrote, and issue paths are stable dotted field paths so the
 * loaders can report exactly which key failed.
 */
import { z } from "zod";

/** Longest accepted deny reason, in characters. */
export const MAX_DENY_REASON_LENGTH = 500;

/** Named permission surfaces the engine understands; other tool names use the catch-all. */
export const NAMED_PERMISSION_SURFACES = Object.freeze([
  "*",
  "path",
  "path_read",
  "path_write",
  "external_directory",
  "external_directory_read",
  "external_directory_write",
  "bash",
  "mcp",
  "skill",
] as const);

/**
 * The four legal direction surfaces. A name that starts with `path_` or
 * `external_directory_` but is not one of these is rejected, so a misspelled
 * direction cannot silently degrade into a tool catch-all.
 */
export const DIRECTIONAL_PERMISSION_SURFACE_NAMES = Object.freeze([
  "path_read",
  "path_write",
  "external_directory_read",
  "external_directory_write",
] as const);

/* ------------------------------------------------------------------ */
/* Validation primitives                                               */
/* ------------------------------------------------------------------ */

/**
 * A string with at least one non-whitespace character. The parsed value keeps
 * the original text: never assume it has been trimmed.
 */
export const nonEmptyStringSchema = z
  .string()
  .min(1)
  .refine((value) => value.trim().length > 0, "expected a non-empty string");

/** A finite positive integer. */
export const positiveIntegerSchema = z.number().int().positive();

/** A safe integer of either sign. */
export const safeIntegerSchema = z.number().int();

/** A finite number inside the closed unit interval. */
export const ratioSchema = z.number().min(0).max(1);

/** A JSON value: the leaf type of object-shaped configuration options. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * A JSON value. Declared recursively rather than derived from `z.json()` so the
 * published JSON Schema names its recursive definition instead of an internal
 * placeholder.
 */
const jsonValueSchema: z.ZodType<JsonValue> = z
  .lazy(() =>
    z.union([
      z.null(),
      z.boolean(),
      z.number(),
      z.string(),
      z.array(jsonValueSchema),
      z.record(z.string(), jsonValueSchema),
    ]),
  )
  .meta({ id: "JsonValue" });

/** A JSON object: string keys mapped to JSON values. */
export const jsonObjectSchema = z.record(z.string(), jsonValueSchema);

/** An environment variable name that is portable across the supported platforms. */
export const environmentVariableNameSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "expected a portable environment variable name");

/** A list whose items are each a non-empty string. The list itself may be empty. */
export const nonEmptyStringListSchema = z.array(nonEmptyStringSchema);

/* ------------------------------------------------------------------ */
/* Issue reporting                                                     */
/* ------------------------------------------------------------------ */

/**
 * Machine-readable problem kinds a configuration file can report. `invalid`
 * covers a wrong type or value, `unknown-key` a rejected extra field, and
 * `invalid-key` a rejected map key (surface, pattern or record key).
 */
export type ConfigIssueCode = "invalid" | "unknown-key" | "invalid-key";

/** One configuration problem, addressed by a stable dotted field path. */
export interface ConfigIssue {
  /** Dotted field path; `""` is the document root. */
  readonly path: string;
  readonly code: ConfigIssueCode;
  readonly message: string;
}

/** Parse outcome for one configuration scope. */
export type ConfigParseResult<T> =
  | { readonly ok: true; readonly config: T }
  | { readonly ok: false; readonly issues: readonly ConfigIssue[] };

const IDENTIFIER_SEGMENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;

/** Render a zod issue path as `a.b[0].c`, quoting non-identifier keys. */
export function formatConfigIssuePath(path: readonly PropertyKey[]): string {
  let rendered = "";
  for (const segment of path) {
    if (typeof segment === "number") {
      rendered += `[${segment}]`;
      continue;
    }
    const name = String(segment);
    if (IDENTIFIER_SEGMENT.test(name)) rendered += rendered.length === 0 ? name : `.${name}`;
    else rendered += `[${JSON.stringify(name)}]`;
  }
  return rendered;
}

type RawIssue = z.ZodError["issues"][number];

function issueDepth(issues: readonly ConfigIssue[]): number {
  let deepest = 0;
  for (const issue of issues) if (issue.path.length > deepest) deepest = issue.path.length;
  return deepest;
}

/**
 * Most specific branch of a failed union: a catch-all action string fails at
 * the surface itself, while a pattern map fails deeper. Reporting the deeper
 * branch keeps the loader's field path useful instead of blaming the surface.
 */
function expandUnion(issue: RawIssue & { readonly code: "invalid_union" }, path: readonly PropertyKey[]): ConfigIssue[] {
  const rawBranches = "errors" in issue && Array.isArray(issue.errors) ? issue.errors : [];
  const branches = rawBranches.map((branch) => branch.flatMap((child) => expandRawIssue(child, path)));
  let best = branches[0] ?? [];
  for (const branch of branches.slice(1)) {
    if (issueDepth(branch) > issueDepth(best)) best = branch;
  }
  // A discriminated union with an unknown discriminant reports no branches; the
  // union issue itself still names the offending field.
  if (best.length === 0) return [{ path: formatConfigIssuePath(path), code: "invalid", message: issue.message }];
  return best;
}

function expandRawIssue(issue: RawIssue, base: readonly PropertyKey[]): ConfigIssue[] {
  const path = [...base, ...issue.path];
  if (issue.code === "invalid_union") return expandUnion(issue, path);
  if (issue.code === "unrecognized_keys") {
    return issue.keys.map((key) => ({
      path: formatConfigIssuePath([...path, key]),
      code: "unknown-key" as const,
      message: `unexpected field: ${key}`,
    }));
  }
  if (issue.code === "invalid_key") {
    return [{ path: formatConfigIssuePath(path), code: "invalid-key", message: issue.message }];
  }
  return [{ path: formatConfigIssuePath(path), code: "invalid", message: issue.message }];
}

/**
 * Convert a zod error into configuration issues. Rejected extra fields are
 * reported one issue per key, because the loaders surface them individually.
 */
export function issuesFromZodError(error: z.ZodError): readonly ConfigIssue[] {
  return error.issues.flatMap((issue) => expandRawIssue(issue, []));
}

/* ------------------------------------------------------------------ */
/* Permission configuration                                            */
/* ------------------------------------------------------------------ */

/** The three permission actions. */
export const permissionStateSchema = z.enum(["allow", "ask", "deny"]);

export type PermissionState = z.infer<typeof permissionStateSchema>;

/** A deny that carries a short user-facing reason. */
export const denyWithReasonSchema = z.strictObject({
  action: z.literal("deny"),
  reason: z.string().max(MAX_DENY_REASON_LENGTH).optional(),
});

export type DenyWithReason = z.infer<typeof denyWithReasonSchema>;

/** A pattern value is an action or a deny-with-reason object. */
export const patternValueSchema = z.union([permissionStateSchema, denyWithReasonSchema]);

export type PatternValue = z.infer<typeof patternValueSchema>;

/** A pattern key is non-empty; the empty pattern is rejected, an empty map is not. */
const patternKeySchema = z.string().min(1);

/** A surface's pattern map. An empty map is legal and produces no rules. */
const patternMapSchema = z.record(patternKeySchema, patternValueSchema);

/** A surface value is a catch-all action string or a pattern map. */
export const surfaceValueSchema = z.union([permissionStateSchema, patternMapSchema]);

export type SurfaceValue = z.infer<typeof surfaceValueSchema>;

function isMisspelledDirectionalSurface(name: string): boolean {
  const directional = (DIRECTIONAL_PERMISSION_SURFACE_NAMES as readonly string[]).includes(name);
  return !directional && (name.startsWith("path_") || name.startsWith("external_directory_"));
}

const surfaceKeySchema = z
  .string()
  .min(1)
  .refine((name) => !isMisspelledDirectionalSurface(name), "expected a known direction surface");

/**
 * A scope's flat permission map: surface → catch-all action or pattern map.
 *
 * The map is open by design — an unknown tool name is a legal catch-all surface
 * — but empty surface keys and misspelled direction names are rejected.
 */
export const permissionConfigSchema = z.record(surfaceKeySchema, surfaceValueSchema);

export type FlatPermissionConfig = z.infer<typeof permissionConfigSchema>;
