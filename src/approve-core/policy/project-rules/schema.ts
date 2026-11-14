/**
 * Project rule file validation.
 *
 * The file is the only persisted project-rule artifact, so every nested
 * object is closed: unknown fields reject, limits are re-checked, and
 * sensitive content never reaches a returned model. A successful result is
 * deeply frozen.
 */
import {
  EXACT_ACTION_CONTRACT_VERSION,
  PROJECT_RULES_LIMITS,
  PROJECT_RULES_SCHEMA_VERSION,
  RULE_ID_PATTERN,
  canonicalJson,
  type ProjectIdentity,
  type ProjectRulesFile,
  type RuleEffect,
  type RuleScope,
  type RuleStatus,
  type ScopeAccess,
  type StoredProjectRule,
} from "./types";
import { isSensitiveText, scanStructuredArguments } from "./sensitive";

export type ProjectRulesProblemKind =
  | "not-object"
  | "unknown-version"
  | "schema-invalid"
  | "identity-mismatch"
  | "duplicate-rule-id"
  | "duplicate-tombstone-id"
  | "revocation-mismatch"
  | "limit-exceeded"
  | "sensitive-content";

export interface ProjectRulesProblem {
  readonly kind: ProjectRulesProblemKind;
  /** Dotted path of the offending field for structural problems. */
  readonly path?: string;
  readonly detail?: string;
  readonly category?: string;
}

export type ProjectRulesValidation =
  | { readonly ok: true; readonly file: ProjectRulesFile }
  | { readonly ok: false; readonly problem: ProjectRulesProblem };

const RULE_EFFECTS = new Set<RuleEffect>(["allow", "deny"]);
const RULE_STATUSES = new Set<RuleStatus>(["active", "needs_review", "revoked"]);
const SCOPE_ACCESSES = new Set<ScopeAccess>(["read", "write", "execute", "network", "other"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function invalid(path: string, detail: string): ProjectRulesProblem {
  return { kind: "schema-invalid", path, detail };
}

function limit(path: string, detail: string): ProjectRulesProblem {
  return { kind: "limit-exceeded", path, detail };
}

function sensitive(path: string, category?: string): ProjectRulesProblem {
  return category === undefined
    ? { kind: "sensitive-content", path }
    : { kind: "sensitive-content", path, category };
}

/** Closed-object check: every required key present, no other key allowed. */
function closedObject(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): ProjectRulesProblem | undefined {
  if (!isObject(value)) return invalid(path, "object expected");
  for (const key of required) {
    if (!(key in value)) return invalid(`${path}.${key}`, "missing field");
  }
  for (const key of Object.keys(value)) {
    if (!required.includes(key) && !optional.includes(key)) return invalid(`${path}.${key}`, "unknown field");
  }
  return undefined;
}

/** Textual fields that the sensitive detector also covers. */
function checkText(value: unknown, path: string): ProjectRulesProblem | undefined {
  if (!nonEmptyString(value)) return invalid(path, "non-empty string expected");
  return isSensitiveText(value) ? sensitive(path) : undefined;
}

function checkArguments(value: unknown, path: string): ProjectRulesProblem | undefined {
  if (!isObject(value)) return invalid(path, "JSON object expected");
  const scan = scanStructuredArguments(value);
  if (!scan.ok) {
    if (scan.kind === "sensitive") return sensitive(path, scan.category);
    return scan.reason === "non-json" ? invalid(path, "non-json value") : limit(path, scan.reason ?? "unlearnable");
  }
  let bytes: number;
  try {
    bytes = Buffer.byteLength(canonicalJson(value), "utf8");
  } catch {
    return invalid(path, "not serializable");
  }
  return bytes > PROJECT_RULES_LIMITS.maxRuleArgumentBytes
    ? limit(path, "arguments exceed the per-rule byte limit")
    : undefined;
}

function checkTool(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["name", "origin", "definitionRevision"]);
  if (closed) return closed;
  const tool = value as Record<string, unknown>;
  for (const key of ["name", "origin", "definitionRevision"]) {
    const problem = checkText(tool[key], `${path}.${key}`);
    if (problem) return problem;
  }
  return undefined;
}

function checkScope(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["surface", "target", "access"]);
  if (closed) return closed;
  const scope = value as Record<string, unknown>;
  for (const key of ["surface", "target"]) {
    const problem = checkText(scope[key], `${path}.${key}`);
    if (problem) return problem;
  }
  return SCOPE_ACCESSES.has(scope.access as ScopeAccess) ? undefined : invalid(`${path}.access`, "unknown access");
}

function checkMatch(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, [
    "contractVersion",
    "type",
    "tool",
    "definitionDigest",
    "arguments",
    "argumentsDigest",
    "cwd",
    "environmentDigest",
    "requiredScopes",
  ]);
  if (closed) return closed;
  const match = value as Record<string, unknown>;
  if (match.contractVersion !== EXACT_ACTION_CONTRACT_VERSION) return invalid(`${path}.contractVersion`, "unknown contract version");
  if (match.type !== "exact_action") return invalid(`${path}.type`, "exact_action expected");

  const toolProblem = checkTool(match.tool, `${path}.tool`);
  if (toolProblem) return toolProblem;
  if (!nonEmptyString(match.definitionDigest)) return invalid(`${path}.definitionDigest`, "non-empty string expected");
  if (isSensitiveText(match.definitionDigest)) return sensitive(`${path}.definitionDigest`);

  const argumentsProblem = checkArguments(match.arguments, `${path}.arguments`);
  if (argumentsProblem) return argumentsProblem;
  if (!nonEmptyString(match.argumentsDigest)) return invalid(`${path}.argumentsDigest`, "non-empty string expected");

  const cwdProblem = checkText(match.cwd, `${path}.cwd`);
  if (cwdProblem) return cwdProblem;
  if (!nonEmptyString(match.environmentDigest)) return invalid(`${path}.environmentDigest`, "non-empty string expected");

  if (!Array.isArray(match.requiredScopes) || match.requiredScopes.length === 0) {
    return invalid(`${path}.requiredScopes`, "at least one scope expected");
  }
  for (const [index, scope] of match.requiredScopes.entries()) {
    const scopeProblem = checkScope(scope, `${path}.requiredScopes.${index}`);
    if (scopeProblem) return scopeProblem;
  }
  return undefined;
}

function checkProvenance(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["sessionId", "sourceEntryId", "quote", "actor"], ["confidence", "judge"]);
  if (closed) return closed;
  const provenance = value as Record<string, unknown>;
  for (const key of ["sessionId", "sourceEntryId", "actor"]) {
    const problem = checkText(provenance[key], `${path}.${key}`);
    if (problem) return problem;
  }
  if (provenance.judge !== undefined) {
    const problem = checkText(provenance.judge, `${path}.judge`);
    if (problem) return problem;
  }
  const quote = provenance.quote;
  if (!nonEmptyString(quote)) return invalid(`${path}.quote`, "non-empty string expected");
  if (quote.length > PROJECT_RULES_LIMITS.maxQuoteChars) return limit(`${path}.quote`, "quote exceeds the character limit");
  if (isSensitiveText(quote)) return sensitive(`${path}.quote`);
  if (provenance.confidence !== undefined) {
    const confidence = provenance.confidence;
    if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      return invalid(`${path}.confidence`, "finite confidence in [0,1] expected");
    }
    if (confidence < PROJECT_RULES_LIMITS.minConfidence) return invalid(`${path}.confidence`, "confidence below the model minimum");
  }
  return undefined;
}

function checkRevocation(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["revokedAt", "actor"], ["reason"]);
  if (closed) return closed;
  const revocation = value as Record<string, unknown>;
  if (!isTimestamp(revocation.revokedAt)) return invalid(`${path}.revokedAt`, "timestamp expected");
  const actorProblem = checkText(revocation.actor, `${path}.actor`);
  if (actorProblem) return actorProblem;
  if (revocation.reason !== undefined) {
    if (typeof revocation.reason !== "string") return invalid(`${path}.reason`, "string expected");
    if (isSensitiveText(revocation.reason)) return sensitive(`${path}.reason`);
  }
  return undefined;
}

function checkStoredRule(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["id", "effect", "status", "match", "provenance", "createdAt", "updatedAt"], ["revocation"]);
  if (closed) return closed;
  const rule = value as Record<string, unknown>;
  if (typeof rule.id !== "string" || !RULE_ID_PATTERN.test(rule.id)) return invalid(`${path}.id`, "rule ID expected");
  if (!RULE_EFFECTS.has(rule.effect as RuleEffect)) return invalid(`${path}.effect`, "allow or deny expected");
  if (!RULE_STATUSES.has(rule.status as RuleStatus)) return invalid(`${path}.status`, "known status expected");
  if (!isTimestamp(rule.createdAt)) return invalid(`${path}.createdAt`, "timestamp expected");
  if (!isTimestamp(rule.updatedAt)) return invalid(`${path}.updatedAt`, "timestamp expected");

  const matchProblem = checkMatch(rule.match, `${path}.match`);
  if (matchProblem) return matchProblem;
  const provenanceProblem = checkProvenance(rule.provenance, `${path}.provenance`);
  if (provenanceProblem) return provenanceProblem;

  const revoked = rule.status === "revoked";
  if (revoked && rule.revocation === undefined) return { kind: "revocation-mismatch", path, detail: "revoked rule needs a revocation" };
  if (!revoked && rule.revocation !== undefined) return { kind: "revocation-mismatch", path, detail: "only revoked rules carry a revocation" };
  if (rule.revocation !== undefined) {
    const revocationProblem = checkRevocation(rule.revocation, `${path}.revocation`);
    if (revocationProblem) return revocationProblem;
  }
  return undefined;
}

function checkTombstone(value: unknown, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["ruleId", "effect", "matchDigest", "revokedAt", "revision"]);
  if (closed) return closed;
  const tombstone = value as Record<string, unknown>;
  if (typeof tombstone.ruleId !== "string" || !RULE_ID_PATTERN.test(tombstone.ruleId)) return invalid(`${path}.ruleId`, "rule ID expected");
  if (!RULE_EFFECTS.has(tombstone.effect as RuleEffect)) return invalid(`${path}.effect`, "allow or deny expected");
  if (!nonEmptyString(tombstone.matchDigest)) return invalid(`${path}.matchDigest`, "non-empty string expected");
  if (!isTimestamp(tombstone.revokedAt)) return invalid(`${path}.revokedAt`, "timestamp expected");
  return nonNegativeInteger(tombstone.revision) ? undefined : invalid(`${path}.revision`, "non-negative integer expected");
}

function checkIdentity(value: unknown, expected: ProjectIdentity, path: string): ProjectRulesProblem | undefined {
  const closed = closedObject(value, path, ["rootPath", "displayName", "slug", "identityHash"]);
  if (closed) return closed;
  const identity = value as Record<string, unknown>;
  for (const key of ["rootPath", "displayName", "slug", "identityHash"]) {
    if (!nonEmptyString(identity[key])) return invalid(`${path}.${key}`, "non-empty string expected");
  }
  if (identity.rootPath !== expected.rootPath || identity.displayName !== expected.displayName ||
    identity.slug !== expected.slug || identity.identityHash !== expected.identityHash) {
    return { kind: "identity-mismatch", path };
  }
  return undefined;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

/**
 * Validate one persisted project rule file against the current project
 * identity. `expectedIdentity` is the identity the caller resolved for this
 * project; a file bound to another project is rejected, not re-bound.
 */
export function validateProjectRulesFile(value: unknown, expectedIdentity: ProjectIdentity): ProjectRulesValidation {
  if (!isObject(value)) return { ok: false, problem: { kind: "not-object" } };

  if (value.schemaVersion !== PROJECT_RULES_SCHEMA_VERSION) {
    return { ok: false, problem: { kind: "unknown-version" } };
  }
  const closed = closedObject(value, "file", ["schemaVersion", "revision", "identity", "rules", "tombstones"]);
  if (closed) return { ok: false, problem: closed };

  if (!nonNegativeInteger(value.revision)) return { ok: false, problem: invalid("file.revision", "non-negative integer expected") };

  const identityProblem = checkIdentity(value.identity, expectedIdentity, "file.identity");
  if (identityProblem) return { ok: false, problem: identityProblem };

  if (!Array.isArray(value.rules)) return { ok: false, problem: invalid("file.rules", "array expected") };
  if (!Array.isArray(value.tombstones)) return { ok: false, problem: invalid("file.tombstones", "array expected") };

  let bytes: number;
  try {
    bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  } catch {
    return { ok: false, problem: invalid("file", "not serializable") };
  }
  if (bytes > PROJECT_RULES_LIMITS.maxFileBytes) return { ok: false, problem: limit("file", "file exceeds the byte limit") };
  if (value.rules.length > PROJECT_RULES_LIMITS.maxRules) return { ok: false, problem: limit("file.rules", "too many rules") };
  if (value.tombstones.length > PROJECT_RULES_LIMITS.maxTombstones) return { ok: false, problem: limit("file.tombstones", "too many tombstones") };

  const ruleIds = new Set<string>();
  const rules: StoredProjectRule[] = [];
  for (const [index, candidate] of value.rules.entries()) {
    const problem = checkStoredRule(candidate, `file.rules.${index}`);
    if (problem) return { ok: false, problem };
    const rule = candidate as StoredProjectRule;
    if (ruleIds.has(rule.id)) return { ok: false, problem: { kind: "duplicate-rule-id", path: `file.rules.${index}.id` } };
    ruleIds.add(rule.id);
    rules.push(rule);
  }

  const tombstoneIds = new Set<string>();
  const tombstones: ProjectRulesFile["tombstones"][number][] = [];
  for (const [index, candidate] of value.tombstones.entries()) {
    const problem = checkTombstone(candidate, `file.tombstones.${index}`);
    if (problem) return { ok: false, problem };
    const tombstone = candidate as ProjectRulesFile["tombstones"][number];
    if (tombstoneIds.has(tombstone.ruleId)) {
      return { ok: false, problem: { kind: "duplicate-tombstone-id", path: `file.tombstones.${index}.ruleId` } };
    }
    tombstoneIds.add(tombstone.ruleId);
    const target = rules.find((rule) => rule.id === tombstone.ruleId);
    if (!target || target.status !== "revoked" || target.effect !== tombstone.effect) {
      return { ok: false, problem: { kind: "revocation-mismatch", path: `file.tombstones.${index}.ruleId` } };
    }
    tombstones.push(tombstone);
  }

  const file: ProjectRulesFile = {
    schemaVersion: PROJECT_RULES_SCHEMA_VERSION,
    revision: value.revision,
    identity: value.identity as ProjectIdentity,
    rules,
    tombstones,
  };
  return { ok: true, file: deepFreeze(file) };
}

/** Rule scopes are persisted sorted; this keeps the on-disk shape stable. */
export function sortedRuleScopes(scopes: readonly RuleScope[]): RuleScope[] {
  return [...scopes].sort((left, right) => {
    const leftKey = `${left.surface}\0${left.target}\0${left.access}`;
    const rightKey = `${right.surface}\0${right.target}\0${right.access}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}
