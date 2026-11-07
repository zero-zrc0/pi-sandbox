/**
 * Project rule model vocabulary.
 *
 * A project rule file stores exact-action allow/deny rules for one project
 * identity. The types here are the frozen persisted shape; validation and
 * construction live in `schema.ts`, `match.ts` and the evidence modules.
 */
import { createHash } from "node:crypto";

export const PROJECT_RULES_SCHEMA_VERSION = 1 as const;
export const EXACT_ACTION_CONTRACT_VERSION = 1 as const;

export const PROJECT_RULES_LIMITS = Object.freeze({
  /** Rules and tombstones each cap one file. */
  maxRules: 512,
  maxTombstones: 512,
  /** Serialized file bytes, and the effective arguments of one rule. */
  maxFileBytes: 1024 * 1024,
  maxRuleArgumentBytes: 32 * 1024,
  /** One verbatim user quote. */
  maxQuoteChars: 500,
  /** One learning request. */
  maxCandidates: 64,
  maxLearningInputsPerField: 32,
  maxActiveBatches: 8,
  /** Model-proposed create/revoke confidence. */
  minConfidence: 0.9,
});

export const RULE_ID_PATTERN = /^rule-[0-9a-f]{16,64}$/;
export const DEFAULT_RULE_ID_HEX = 24;
export const IDENTITY_HASH_HEX = 16;

export type RuleEffect = "allow" | "deny";
export type RuleStatus = "active" | "needs_review" | "revoked";
export type ScopeAccess = "read" | "write" | "execute" | "network" | "other";

/** One scope of the current action; IDs are host-local and never persisted. */
export interface ActionScope {
  readonly id: string;
  readonly surface: string;
  readonly target: string;
  readonly access: ScopeAccess;
}

/** The persisted scope shape: a sorted surface/target/access triple. */
export interface RuleScope {
  readonly surface: string;
  readonly target: string;
  readonly access: ScopeAccess;
}

export interface RuleToolIdentity {
  readonly name: string;
  readonly origin: string;
  readonly definitionRevision: string;
}

export interface ExactActionMatch {
  readonly contractVersion: typeof EXACT_ACTION_CONTRACT_VERSION;
  readonly type: "exact_action";
  readonly tool: RuleToolIdentity;
  /** Digest over the captured tool definition; never the definition itself. */
  readonly definitionDigest: string;
  /** Full effective arguments, frozen as JSON. */
  readonly arguments: unknown;
  readonly argumentsDigest: string;
  /** Best-effort canonical working directory at capture time. */
  readonly cwd: string;
  /** Digest only: environment values are never persisted. */
  readonly environmentDigest: string;
  readonly requiredScopes: readonly RuleScope[];
}

export interface RuleProvenance {
  readonly sessionId: string;
  /** The frozen authorization entry the user wrote. */
  readonly sourceEntryId: string;
  readonly quote: string;
  /** Model-proposed confidence, when the rule came from a judge. */
  readonly confidence?: number;
  /** Judge identity, when a model approved the action. */
  readonly judge?: string;
  readonly actor: string;
}

export interface RuleRevocation {
  readonly revokedAt: string;
  readonly actor: string;
  readonly reason?: string;
}

export interface StoredProjectRule {
  readonly id: string;
  readonly effect: RuleEffect;
  readonly status: RuleStatus;
  readonly match: ExactActionMatch;
  readonly provenance: RuleProvenance;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly revocation?: RuleRevocation;
}

export interface RuleTombstone {
  readonly ruleId: string;
  readonly effect: RuleEffect;
  readonly matchDigest: string;
  readonly revokedAt: string;
  /** File revision the revocation was committed in. */
  readonly revision: number;
}

/** The normalized project identity that the file is bound to. */
export interface ProjectIdentity {
  readonly rootPath: string;
  readonly displayName: string;
  readonly slug: string;
  readonly identityHash: string;
}

export interface ProjectRulesFile {
  readonly schemaVersion: typeof PROJECT_RULES_SCHEMA_VERSION;
  readonly revision: number;
  readonly identity: ProjectIdentity;
  readonly rules: readonly StoredProjectRule[];
  readonly tombstones: readonly RuleTombstone[];
}

/** The current action, as the host proves it. */
export interface ExactAction {
  readonly requestId: string;
  readonly tool: RuleToolIdentity;
  readonly definitionDigest: string;
  readonly arguments: unknown;
  readonly argumentsDigest: string;
  readonly cwd: string;
  readonly environmentDigest: string;
  readonly scopes: readonly ActionScope[];
  /** True when policy already holds a hard deny for this action. */
  readonly hardDeny?: boolean;
}

export interface RuleMatchHit {
  readonly kind: "match";
  readonly match: ExactActionMatch;
  readonly coveredScopeIds: readonly string[];
}

export type RuleMatchResult =
  | { readonly kind: "no-match" }
  | { readonly kind: "definition-changed" }
  | { readonly kind: "environment-changed" }
  | RuleMatchHit;

/** Frozen authorization entries a model proposal may cite. */
export type AuthorizationSource =
  | "user"
  | "tool"
  | "assistant"
  | "system"
  | "summary"
  | "reviewer"
  | "extension"
  | "log"
  | "context";

export interface AuthorizationEntry {
  readonly id: string;
  readonly source: AuthorizationSource;
  readonly text: string;
}

/** The model-proposed evidence a create or revoke must prove. */
export interface EvidenceProposal {
  readonly sourceEntryId: string;
  readonly quote: string;
  readonly confidence: number;
  readonly judge: string;
  readonly sessionId: string;
  readonly actor: string;
}

/** Deterministic canonical JSON used by every digest in this domain. */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  return "null";
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Host-generated rule ID; the model can never choose it. */
export function ruleIdFor(input: {
  readonly effect: RuleEffect;
  readonly matchDigest: string;
  readonly sourceEntryId: string;
  readonly sessionId: string;
}): string {
  const digest = sha256Hex(canonicalJson([
    "project-rule",
    input.effect,
    input.matchDigest,
    input.sourceEntryId,
    input.sessionId,
  ]));
  return `rule-${digest.slice(0, DEFAULT_RULE_ID_HEX)}`;
}

export function isRuleId(value: unknown): value is string {
  return typeof value === "string" && RULE_ID_PATTERN.test(value);
}

/** Deterministic sort for scope triples; same triple keeps separate entries. */
export function sortRuleScopes(scopes: readonly RuleScope[]): RuleScope[] {
  return [...scopes].sort((left, right) => {
    const leftKey = `${left.surface}\0${left.target}\0${left.access}`;
    const rightKey = `${right.surface}\0${right.target}\0${right.access}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}
