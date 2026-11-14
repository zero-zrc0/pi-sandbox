/**
 * Prompt summaries for the six built-in path tools (specs/human-review.md §3).
 *
 * Display-only: a summary states which file or pattern a call touches and how
 * much it changes, never the text being written or replaced. Bounding and
 * pluralization primitives come from `tool-input-preview`.
 */
import {
  DEFAULT_PREVIEW_LIMITS,
  countLabel,
  countLines,
  inlinePreview,
  type PreviewLimits,
} from "./tool-input-preview";

/** Options bag for callers that build summaries from injected caps. */
export interface BuiltinSummaryOptions {
  readonly limits?: Partial<PreviewLimits>;
}

/** The built-in tools that get a structured path-tool summary. */
export type BuiltinToolName = "read" | "write" | "edit" | "find" | "grep" | "ls";

type InputRecord = Readonly<Record<string, unknown>>;

function isPlainObject(value: unknown): value is InputRecord {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Inputs that are not plain objects are treated as an empty input object. */
function asInputRecord(input: unknown): InputRecord {
  return isPlainObject(input) ? input : {};
}

function nonBlankString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** `path` first, then `file_path`; both must be non-blank strings. */
export function toolInputPath(input: unknown): string | undefined {
  const record = asInputRecord(input);
  return nonBlankString(record.path) ?? nonBlankString(record.file_path);
}

export function summarizeRead(
  input: unknown,
  _limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  const record = asInputRecord(input);
  const path = toolInputPath(record);
  if (path === undefined) return undefined;

  const fragments = [`read ${path}`];
  if (isFiniteNumber(record.offset)) fragments.push(`offset ${record.offset}`);
  if (isFiniteNumber(record.limit)) fragments.push(`limit ${record.limit}`);
  return fragments.join(", ");
}

export function summarizeWrite(
  input: unknown,
  _limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  const record = asInputRecord(input);
  const path = toolInputPath(record);
  if (path === undefined) return undefined;

  const content = typeof record.content === "string" ? record.content : "";
  return `write ${path}: ${countLabel(countLines(content), "line", "lines")}, ${countLabel(
    content.length,
    "character",
    "characters",
  )}`;
}

interface EditReplacement {
  readonly oldText: string;
  readonly newText: string;
}

function isEditReplacement(value: unknown): value is EditReplacement {
  return isPlainObject(value) && typeof value.oldText === "string" && typeof value.newText === "string";
}

/**
 * Valid replacements: the valid items of a non-empty `edits` array, otherwise
 * the top-level `oldText`/`newText` pair when both are strings.
 */
function editReplacements(record: InputRecord): readonly EditReplacement[] {
  const edits = record.edits;
  if (Array.isArray(edits) && edits.length > 0) return edits.filter(isEditReplacement);
  if (typeof record.oldText === "string" && typeof record.newText === "string") {
    return [{ oldText: record.oldText, newText: record.newText }];
  }
  return [];
}

export function summarizeEdit(
  input: unknown,
  _limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  const record = asInputRecord(input);
  const path = toolInputPath(record);
  if (path === undefined) return undefined;

  const replacements = editReplacements(record);
  if (replacements.length === 0) return `edit ${path}`;

  const first = replacements[0];
  const summary =
    `edit ${path}: ${countLabel(replacements.length, "replacement", "replacements")}, ` +
    `first edit replaces ${countLabel(countLines(first.oldText), "line", "lines")} ` +
    `with ${countLabel(countLines(first.newText), "line", "lines")}`;
  const remaining = replacements.length - 1;
  return remaining > 0 ? `${summary}, ${countLabel(remaining, "more edit", "more edits")}` : summary;
}

function inlineField(value: unknown, limit: number): string | undefined {
  return typeof value === "string" ? inlinePreview(value, limit) : undefined;
}

/** find/grep share the pattern, glob, path fragment order. */
function summarizeSearch(
  prefix: "find" | "grep",
  input: unknown,
  limits: PreviewLimits,
): string | undefined {
  const record = asInputRecord(input);
  const fragments: string[] = [];

  const pattern = inlineField(record.pattern, limits.textSummary);
  if (pattern !== undefined) fragments.push(`pattern "${pattern}"`);
  const glob = inlineField(record.glob, limits.textSummary);
  if (glob !== undefined) fragments.push(`glob "${glob}"`);

  const path = toolInputPath(record);
  fragments.push(path === undefined ? "in the current working directory" : `path ${path}`);
  return `${prefix} ${fragments.join(", ")}`;
}

export function summarizeFind(
  input: unknown,
  limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  return summarizeSearch("find", input, limits);
}

export function summarizeGrep(
  input: unknown,
  limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  return summarizeSearch("grep", input, limits);
}

export function summarizeLs(
  input: unknown,
  _limits: PreviewLimits = DEFAULT_PREVIEW_LIMITS,
): string | undefined {
  const path = toolInputPath(input);
  return path === undefined ? "ls in the current working directory" : `ls path ${path}`;
}

/** Dispatcher table for callers that only have a resolved tool name. */
export const BUILTIN_TOOL_SUMMARIES: Readonly<
  Record<BuiltinToolName, (input: unknown, limits?: PreviewLimits) => string | undefined>
> = {
  read: summarizeRead,
  write: summarizeWrite,
  edit: summarizeEdit,
  find: summarizeFind,
  grep: summarizeGrep,
  ls: summarizeLs,
};

/**
 * Dispatch a trimmed, exactly lowercase built-in name. Aliases, casing
 * variants, MCP proxy calls, Bash and extension tools yield no summary.
 */
export function summarizeBuiltinToolInput(
  toolName: string,
  input: unknown,
  limits?: PreviewLimits,
): string | undefined {
  if (typeof toolName !== "string") return undefined;
  const name = toolName.trim();
  if (!Object.hasOwn(BUILTIN_TOOL_SUMMARIES, name)) return undefined;
  return BUILTIN_TOOL_SUMMARIES[name as BuiltinToolName](input, limits);
}
