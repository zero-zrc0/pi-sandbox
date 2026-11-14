/**
 * Display-only preview primitives for human review (specs/human-review.md §2).
 *
 * Every helper here bounds what a human reads; none of them changes the call
 * that is being approved. Caps are fixed at construction time and the old
 * runtime preview configuration intentionally does not apply.
 */

/** Character caps for previews. Fixed defaults; constructors may inject tests. */
export interface PreviewLimits {
  /** Whole prompt input preview cap. */
  readonly promptInput: number;
  /** One inline field (pattern, glob) cap. */
  readonly textSummary: number;
  /** Whole MCP argument summary cap. */
  readonly mcpSummary: number;
  /** One MCP string argument cap. */
  readonly mcpValue: number;
}

export const DEFAULT_PREVIEW_LIMITS: PreviewLimits = Object.freeze({
  promptInput: 200,
  textSummary: 80,
  mcpSummary: 160,
  mcpValue: 60,
});

/** Marker appended after a truncated preview. */
export const PREVIEW_ELLIPSIS = "…";

/** Marker replacing a value whose key looks like a credential. */
export const REDACTED_VALUE = "[redacted]";

const MAX_MASK_DEPTH = 10;

const SENSITIVE_KEY_NEEDLES: readonly string[] = [
  "privatekey",
  "sessionkey",
  "accesskey",
  "clientsecret",
  "apikey",
  "password",
  "passwd",
  "secret",
  "token",
  "credential",
  "authorization",
  "cookie",
];

/**
 * Resolve caller overrides over the fixed defaults. Only finite positive
 * integers are honored, so a malformed limit can never widen a preview.
 */
export function resolvePreviewLimits(overrides?: Partial<PreviewLimits>): PreviewLimits {
  const pick = (value: unknown, fallback: number): number =>
    typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : fallback;
  return Object.freeze({
    promptInput: pick(overrides?.promptInput, DEFAULT_PREVIEW_LIMITS.promptInput),
    textSummary: pick(overrides?.textSummary, DEFAULT_PREVIEW_LIMITS.textSummary),
    mcpSummary: pick(overrides?.mcpSummary, DEFAULT_PREVIEW_LIMITS.mcpSummary),
    mcpValue: pick(overrides?.mcpValue, DEFAULT_PREVIEW_LIMITS.mcpValue),
  });
}

/** Keep at most `limit` characters, adding the ellipsis only after truncation. */
export function truncateWithEllipsis(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}${PREVIEW_ELLIPSIS}`;
}

/** An empty string has no lines; CRLF, CR and LF all end a line. */
export function countLines(text: string): number {
  if (text.length === 0) return 0;
  return text.split(/\r\n|\r|\n/u).length;
}

/** Quantity text is singular only for exactly one. */
export function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Collapse every whitespace run to one space and trim the ends. */
export function collapseWhitespace(text: string): string {
  return text.replace(/\s+/gu, " ").trim();
}

/** One-line field preview: blank text has no preview at all. */
export function inlinePreview(text: string, limit: number): string | undefined {
  const collapsed = collapseWhitespace(text);
  if (collapsed.length === 0) return undefined;
  return truncateWithEllipsis(collapsed, limit);
}

/** JSON text for a value, or undefined when the value is not serializable. */
export function safeStringify(value: unknown): string | undefined {
  try {
    const text = JSON.stringify(value);
    return typeof text === "string" ? text : undefined;
  } catch {
    return undefined;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isEmptyPlainObject(value: unknown): boolean {
  return isPlainObject(value) && Object.keys(value).length === 0;
}

/**
 * Prompt-facing JSON preview. Unserializable values, null and empty objects
 * produce no preview; anything else is collapsed to one line and bounded.
 */
export function jsonPreview(value: unknown, limit: number): string | undefined {
  if (value === null) return undefined;
  if (isEmptyPlainObject(value)) return undefined;
  const text = safeStringify(value);
  if (text === undefined) return undefined;
  return inlinePreview(text, limit);
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_.\s]/gu, "");
}

/** Credential-looking keys are matched after separator and case normalization. */
export function isSensitiveKey(key: string): boolean {
  if (typeof key !== "string" || key.trim().length === 0) return false;
  const normalized = normalizeKey(key);
  return SENSITIVE_KEY_NEEDLES.some((needle) => normalized.includes(needle));
}

function maskValue(value: unknown, depth: number, ancestors: Set<object>): unknown {
  if (typeof value !== "object" || value === null) return value;
  if (depth > MAX_MASK_DEPTH) return REDACTED_VALUE;
  if (ancestors.has(value)) return REDACTED_VALUE;

  if (Array.isArray(value)) {
    ancestors.add(value);
    try {
      return value.map((item) => maskValue(item, depth + 1, ancestors));
    } finally {
      ancestors.delete(value);
    }
  }

  if (!isPlainObject(value)) return value;

  ancestors.add(value);
  try {
    const masked: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      masked[key] = isSensitiveKey(key) ? REDACTED_VALUE : maskValue(value[key], depth + 1, ancestors);
    }
    return masked;
  } finally {
    ancestors.delete(value);
  }
}

/** Deep copy with credential-valued keys replaced before any serialization. */
export function maskSensitiveKeys(value: unknown): unknown {
  return maskValue(value, 0, new Set<object>());
}

/** Review-log JSON preview: mask first, then serialize and bound. */
export function logJsonPreview(value: unknown, limit: number): string | undefined {
  return jsonPreview(maskSensitiveKeys(value), limit);
}
