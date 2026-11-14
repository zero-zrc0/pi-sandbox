/**
 * Sensitive-content rejection for project-rule learning.
 *
 * Learning refuses the whole action instead of persisting a redacted guess:
 * credentials must never reach rules, evidence quotes, identities, paths or
 * audit reasons. The limits mirror the project rule model's structural caps.
 */

export type SensitiveScanResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly kind: "sensitive" | "unlearnable";
      readonly category?: string;
      readonly reason?: string;
    };

/** Generic marker used in place of sensitive text; never the original value. */
export const SENSITIVE_REASON_PLACEHOLDER = "[redacted: sensitive content]";

const MAX_DEPTH = 16;
const MAX_CONTAINER_ENTRIES = 512;
const MAX_STRING_LENGTH = 4096;

const NON_JSON_REASON = "non-json";
const DEPTH_REASON = "depth-limit";
const ENTRY_REASON = "entry-limit";
const STRING_LENGTH_REASON = "string-length-limit";

/**
 * Key categories are matched after lowercasing and removing `-`, `_`, `.` and
 * whitespace, so `API_KEY`, `api-key` and `apiKey` all normalize alike.
 */
const SENSITIVE_KEY_CATEGORIES: ReadonlyArray<readonly [needle: string, category: string]> = [
  ["privatekey", "private-key"],
  ["sessionkey", "session-key"],
  ["accesskey", "access-key"],
  ["clientsecret", "client-secret"],
  ["apikey", "api-key"],
  ["password", "password"],
  ["passwd", "password"],
  ["bearer", "bearer"],
  ["secret", "secret"],
  ["token", "token"],
  ["credential", "credential"],
  ["authorization", "authorization"],
  ["cookie", "cookie"],
];

const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/i;
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/;
/** A lone JWT header segment still identifies a serialized credential. */
const JWT_HEADER_SEGMENT_RE = /eyJ[A-Za-z0-9_-]{10,}/;
const AUTHORIZATION_HEADER_RE = /\bauthorization\s*[:=]\s*\S+/i;
const BEARER_OR_BASIC_RE = /(?:^|[\s"'(,;=])(bearer|basic)\s+([A-Za-z0-9._~+/=-]+)/i;
const COOKIE_HEADER_RE = /\b(?:cookie|set-cookie)\s*[:=]\s*\S+/i;
const URL_CREDENTIALS_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s\/:@]+:[^\s\/@]+@/i;
const KEY_ASSIGNMENT_RE = /(?:^|[\s"'(&?;,=])([A-Za-z0-9_.-]+)\s*[:=]\s*(?=\S)/g;
const COMMAND_OPTION_RE = /(?:^|\s)--?([A-Za-z0-9_-]+)(?:=|\s+)(?=\S)/g;

const SERVICE_TOKEN_PATTERNS: readonly RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}\b/,
  /\bnpm_[A-Za-z0-9]{30,}\b/,
  /\bSK[0-9a-fA-F]{32}\b/,
];
/** Azure storage connection strings carry shared keys as plain assignments. */
const AZURE_CONNECTION_RE = /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{20,}/i;

function sensitive(category: string): SensitiveScanResult {
  return { ok: false, kind: "sensitive", category };
}

function unlearnable(reason: string): SensitiveScanResult {
  return { ok: false, kind: "unlearnable", reason };
}

function isPlainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_.\s]/g, "");
}

function detectSensitiveKeyCategory(key: string): string | undefined {
  const normalized = normalizeKey(key);
  for (const [needle, category] of SENSITIVE_KEY_CATEGORIES) {
    if (normalized.includes(needle)) return category;
  }
  return undefined;
}

/** Bearer credentials are opaque even when purely alphabetic; Basic needs token shape. */
function looksLikeCredentialToken(token: string): boolean {
  if (token.length < 12) return false;
  return /[0-9]/.test(token) || (/[a-z]/.test(token) && /[A-Z]/.test(token)) || /[+/=]/.test(token);
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/**
 * Long opaque values (base64/hex-like) are rejected. Hex digests stay below the
 * entropy threshold so stored SHA-256 digests are not mistaken for secrets.
 */
function looksHighEntropy(text: string): boolean {
  if (text.length < 32) return false;
  if (!/^[A-Za-z0-9+=_-]+$/.test(text)) return false;
  if (!/[A-Za-z]/.test(text) || !/[0-9]/.test(text)) return false;
  return shannonEntropy(text) >= 4.2;
}

function looksLikeSensitiveText(text: string): string | undefined {
  if (text.length === 0) return undefined;
  if (PRIVATE_KEY_RE.test(text)) return "private-key";
  if (JWT_RE.test(text)) return "jwt";
  if (JWT_HEADER_SEGMENT_RE.test(text)) return "jwt";
  if (AUTHORIZATION_HEADER_RE.test(text)) return "authorization";

  const bearer = BEARER_OR_BASIC_RE.exec(text);
  if (bearer !== null) {
    const scheme = bearer[1].toLowerCase();
    const token = bearer[2];
    if (scheme === "bearer" ? token.length >= 16 : looksLikeCredentialToken(token)) return "bearer";
  }

  if (COOKIE_HEADER_RE.test(text)) return "cookie";
  if (URL_CREDENTIALS_RE.test(text)) return "url-credentials";

  for (const match of text.matchAll(KEY_ASSIGNMENT_RE)) {
    const category = detectSensitiveKeyCategory(match[1]);
    if (category !== undefined) return category;
  }
  for (const match of text.matchAll(COMMAND_OPTION_RE)) {
    const category = detectSensitiveKeyCategory(match[1]);
    if (category !== undefined) return category;
  }

  for (const pattern of SERVICE_TOKEN_PATTERNS) {
    if (pattern.test(text)) return "service-token";
  }
  if (AZURE_CONNECTION_RE.test(text)) return "service-token";
  if (looksHighEntropy(text)) return "high-entropy";
  return undefined;
}

/**
 * Text detection is shared by structured argument values, evidence quotes,
 * tool identities, paths and audit reasons.
 */
export function isSensitiveText(text: string): boolean {
  return looksLikeSensitiveText(text) !== undefined;
}

/** Sensitive reasons are replaced wholesale so no fragment of the value leaks. */
export function redactSensitiveReason(text: string): string {
  return isSensitiveText(text) ? SENSITIVE_REASON_PLACEHOLDER : text;
}

/** Scan one JSON-ish value without ever returning the matched text. */
export function scanStructuredArguments(value: unknown): SensitiveScanResult {
  try {
    return scanValue(value, 1, new Set<object>());
  } catch {
    // Unreadable values fail closed: they are not learnable either.
    return unlearnable(NON_JSON_REASON);
  }
}

function scanValue(value: unknown, depth: number, ancestors: Set<object>): SensitiveScanResult {
  if (value === null) return { ok: true };
  switch (typeof value) {
    case "string": {
      if (value.length > MAX_STRING_LENGTH) return unlearnable(STRING_LENGTH_REASON);
      const category = looksLikeSensitiveText(value);
      return category === undefined ? { ok: true } : sensitive(category);
    }
    case "number":
      return Number.isFinite(value) ? { ok: true } : unlearnable(NON_JSON_REASON);
    case "boolean":
      return { ok: true };
    case "object":
      return scanContainer(value, depth, ancestors);
    default:
      return unlearnable(NON_JSON_REASON);
  }
}

function scanContainer(value: object, depth: number, ancestors: Set<object>): SensitiveScanResult {
  if (ancestors.has(value)) return unlearnable(NON_JSON_REASON);
  if (depth > MAX_DEPTH) return unlearnable(DEPTH_REASON);

  if (Array.isArray(value)) {
    if (value.length > MAX_CONTAINER_ENTRIES) return unlearnable(ENTRY_REASON);
    ancestors.add(value);
    try {
      for (const item of value) {
        const result = scanValue(item, depth + 1, ancestors);
        if (!result.ok) return result;
      }
      return { ok: true };
    } finally {
      ancestors.delete(value);
    }
  }

  if (!isPlainObject(value)) return unlearnable(NON_JSON_REASON);
  if (Object.getOwnPropertySymbols(value).length > 0) return unlearnable(NON_JSON_REASON);
  const keys = Object.keys(value);
  if (keys.length > MAX_CONTAINER_ENTRIES) return unlearnable(ENTRY_REASON);

  ancestors.add(value);
  try {
    for (const key of keys) {
      const keyCategory = detectSensitiveKeyCategory(key);
      if (keyCategory !== undefined) return sensitive(keyCategory);
      const result = scanValue((value as Record<string, unknown>)[key], depth + 1, ancestors);
      if (!result.ok) return result;
    }
    return { ok: true };
  } finally {
    ancestors.delete(value);
  }
}
