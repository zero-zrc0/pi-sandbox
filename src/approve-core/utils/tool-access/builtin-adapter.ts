/**
 * Builtin read/write/edit adapters (specs/tool-access.md §3).
 *
 * A tool is builtin only when both its name and its host origin look builtin:
 * a bare name match must never bind an arbitrary tool. The captured schema has
 * to match the frozen shape exactly; any drift, extra input key, empty path or
 * URL returns incomplete rather than a partial verified report.
 */
import {
  normalizeToolAccessFacts,
  type ToolAccess,
  type ToolAccessFactsResult,
} from "./access-facts";
import type { ToolDefinition } from "./tool-definition";

const BUILTIN_SOURCE = "builtin";
const BUILTIN_TOOL_NAMES = ["read", "write", "edit"] as const;
type BuiltinToolName = (typeof BUILTIN_TOOL_NAMES)[number];

type SchemaType = "string" | "number" | "array";

const BUILTIN_SCHEMAS: Readonly<Record<BuiltinToolName, {
  readonly properties: Readonly<Record<string, SchemaType>>;
  readonly required: readonly string[];
}>> = {
  read: {
    properties: { path: "string", offset: "number", limit: "number" },
    required: ["path"],
  },
  write: {
    properties: { path: "string", content: "string" },
    required: ["path", "content"],
  },
  edit: {
    properties: { path: "string", edits: "array" },
    required: ["path", "edits"],
  },
};

const EDIT_ITEM_PROPERTIES: Readonly<Record<string, SchemaType>> = { oldText: "string", newText: "string" };

interface AccessExtraction {
  readonly ok: true;
  readonly accesses: readonly ToolAccess[];
}

interface ExtractionFailure {
  readonly ok: false;
  readonly reason: string;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function isBuiltinToolName(value: unknown): value is BuiltinToolName {
  return typeof value === "string" && (BUILTIN_TOOL_NAMES as readonly string[]).includes(value);
}

/**
 * Host builtin origins are colon-separated identifiers that contain a
 * `builtin` segment ("builtin", "builtin:read", "pi:builtin"). NUL-joined npm
 * origin keys and arbitrary plugin origins never qualify.
 */
function isHostBuiltinOrigin(origin: string): boolean {
  if (origin.includes("\u0000")) return false;
  return origin.trim().split(":").includes("builtin");
}

/** True only when both the tool name and its host origin are builtin. */
export function isBuiltinToolIdentity(tool: ToolDefinition): boolean {
  const raw: unknown = tool;
  if (!isPlainRecord(raw)) return false;
  const identity = raw.identity;
  if (!isPlainRecord(identity)) return false;
  if (!isBuiltinToolName(identity.name)) return false;
  if (typeof identity.origin !== "string") return false;
  return isHostBuiltinOrigin(identity.origin);
}

function frozenUnbound(): ToolAccessFactsResult {
  return Object.freeze({
    status: "unbound" as const,
    source: BUILTIN_SOURCE,
    complete: false,
    unknownEffects: Object.freeze([]) as readonly string[],
    accesses: Object.freeze([]) as readonly ToolAccess[],
  });
}

function incompleteFacts(tool: ToolDefinition, reason: string): ToolAccessFactsResult {
  return normalizeToolAccessFacts({ accesses: [], complete: false, unknownEffects: [reason] }, tool, BUILTIN_SOURCE);
}

function verifiedFacts(tool: ToolDefinition, accesses: readonly ToolAccess[]): ToolAccessFactsResult {
  return normalizeToolAccessFacts({ accesses, complete: true, unknownEffects: [] }, tool, BUILTIN_SOURCE);
}

function sameSortedStrings(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

function editsSchemaProblem(propertySchema: Record<string, unknown>): string | undefined {
  const items = propertySchema.items;
  if (!isPlainRecord(items) || items.type !== "object") return "schema-item-drift";
  const properties = items.properties;
  if (!isPlainRecord(properties)) return "schema-item-drift";
  if (!sameSortedStrings(Object.keys(properties), Object.keys(EDIT_ITEM_PROPERTIES))) return "schema-item-drift";
  for (const [key, expectedType] of Object.entries(EDIT_ITEM_PROPERTIES)) {
    const property = properties[key];
    if (!isPlainRecord(property) || property.type !== expectedType) return "schema-item-drift";
  }
  const required = items.required;
  if (!Array.isArray(required) || required.some((item) => typeof item !== "string")) return "schema-item-drift";
  if (!sameSortedStrings(required, Object.keys(EDIT_ITEM_PROPERTIES))) return "schema-item-drift";
  return undefined;
}

/**
 * The captured schema must be an object whose required/properties sets match
 * the frozen builtin shape exactly, including the edit item schema.
 */
function builtinSchemaProblem(name: BuiltinToolName, parameters: unknown): string | undefined {
  if (!isPlainRecord(parameters)) return "schema-unavailable";
  if (parameters.type !== "object") return "schema-type-drift";
  const properties = parameters.properties;
  if (!isPlainRecord(properties)) return "schema-properties-drift";
  const shape = BUILTIN_SCHEMAS[name];
  if (!sameSortedStrings(Object.keys(properties), Object.keys(shape.properties))) return "schema-properties-drift";
  const required = parameters.required;
  if (!Array.isArray(required) || required.some((item) => typeof item !== "string")) return "schema-required-drift";
  if (!sameSortedStrings(required, shape.required)) return "schema-required-drift";
  for (const [key, expectedType] of Object.entries(shape.properties)) {
    const propertySchema = properties[key];
    if (!isPlainRecord(propertySchema) || propertySchema.type !== expectedType) return "schema-property-drift";
    if (key === "edits") {
      const problem = editsSchemaProblem(propertySchema);
      if (problem !== undefined) return problem;
    }
  }
  return undefined;
}

/**
 * URL schemes are recognized exactly like access-facts: two or more scheme
 * characters before `:` (a single letter is a Windows drive, not a scheme).
 */
function looksLikeUrl(path: string): boolean {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(path);
  return match !== null && (match[1] as string).length > 1;
}

function isAbsolutePath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(path) || path.startsWith("/") || path.startsWith("\\");
}

/** Simple join: facts only need a stable cwd-relative path, not resolution. */
function resolveFactPath(cwd: string, path: string): string {
  if (isAbsolutePath(path)) return path;
  const base = typeof cwd === "string" ? cwd.trim() : "";
  if (base.length === 0) return path;
  const separator = base.includes("\\") ? "\\" : "/";
  const relative = separator === "\\" ? path.replace(/\//gu, "\\") : path;
  return base.endsWith("/") || base.endsWith("\\") ? `${base}${relative}` : `${base}${separator}${relative}`;
}

function checkedPath(raw: unknown): { readonly ok: true; readonly path: string } | { readonly ok: false } {
  if (typeof raw !== "string") return { ok: false };
  const path = raw.trim();
  if (path.length === 0 || looksLikeUrl(path)) return { ok: false };
  return { ok: true, path };
}

function readAccesses(input: Record<string, unknown>, cwd: string): AccessExtraction | ExtractionFailure {
  if (!hasOnlyKeys(input, ["path", "offset", "limit"])) return { ok: false, reason: "unknown-input-field" };
  const path = checkedPath(input.path);
  if (!path.ok) return { ok: false, reason: "invalid-path" };
  for (const key of ["offset", "limit"]) {
    const value = input[key];
    if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
      return { ok: false, reason: "invalid-input-value" };
    }
  }
  return { ok: true, accesses: [{ path: resolveFactPath(cwd, path.path), access: "read", operation: "read" }] };
}

function writeAccesses(input: Record<string, unknown>, cwd: string): AccessExtraction | ExtractionFailure {
  if (!hasOnlyKeys(input, ["path", "content"])) return { ok: false, reason: "unknown-input-field" };
  const path = checkedPath(input.path);
  if (!path.ok) return { ok: false, reason: "invalid-path" };
  if (typeof input.content !== "string") return { ok: false, reason: "invalid-input-value" };
  return { ok: true, accesses: [{ path: resolveFactPath(cwd, path.path), access: "write", operation: "write" }] };
}

function editAccesses(input: Record<string, unknown>, cwd: string): AccessExtraction | ExtractionFailure {
  if (!hasOnlyKeys(input, ["path", "edits"])) return { ok: false, reason: "unknown-input-field" };
  const path = checkedPath(input.path);
  if (!path.ok) return { ok: false, reason: "invalid-path" };
  const edits = input.edits;
  if (!Array.isArray(edits) || edits.length === 0) return { ok: false, reason: "invalid-edits" };
  for (const edit of edits) {
    if (!isPlainRecord(edit) || !hasOnlyKeys(edit, ["oldText", "newText"])) return { ok: false, reason: "invalid-edits" };
    if (typeof edit.oldText !== "string" || typeof edit.newText !== "string") {
      return { ok: false, reason: "invalid-edits" };
    }
  }
  const resolved = resolveFactPath(cwd, path.path);
  // One edit target needs both directions, exactly like the persisted match.
  return {
    ok: true,
    accesses: [
      { path: resolved, access: "read", operation: "read" },
      { path: resolved, access: "write", operation: "write" },
    ],
  };
}

function extractAccesses(
  name: BuiltinToolName,
  input: unknown,
  cwd: string,
): AccessExtraction | ExtractionFailure {
  if (!isPlainRecord(input)) return { ok: false, reason: "invalid-input" };
  if (name === "read") return readAccesses(input, cwd);
  if (name === "write") return writeAccesses(input, cwd);
  return editAccesses(input, cwd);
}

/** Extract the file access facts proven by one builtin tool call. */
export function extractBuiltinToolAccess(
  tool: ToolDefinition,
  input: unknown,
  cwd: string,
): ToolAccessFactsResult {
  if (!isBuiltinToolIdentity(tool)) return frozenUnbound();
  const name = (tool.identity.name as string) as BuiltinToolName;
  const schemaProblem = builtinSchemaProblem(name, tool.parameters);
  if (schemaProblem !== undefined) return incompleteFacts(tool, schemaProblem);
  const extraction = extractAccesses(name, input, cwd);
  if (!extraction.ok) return incompleteFacts(tool, extraction.reason);
  return verifiedFacts(tool, extraction.accesses);
}
