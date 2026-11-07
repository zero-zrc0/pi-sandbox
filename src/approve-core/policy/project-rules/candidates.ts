/**
 * In-memory learning-candidate collector.
 *
 * Model-proposed `create`/`revoke` candidates are partitioned by review
 * attempt plus request id, so interleaved reviews never read each other's
 * staging. The collector is memory-only and is a safety seam: `parse` never
 * throws, never writes files and never changes a verdict. Callers explicitly
 * take or discard staged data after the review lifecycle decides.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { PROJECT_RULES_LIMITS } from "./types";

export type LearningField = "create" | "revoke";

export interface LearningCandidate {
  readonly attemptId: string;
  readonly requestId: string;
  readonly field: LearningField;
  readonly index: number;
  readonly value: Readonly<Record<string, unknown>>;
}

export interface LearningRejection {
  readonly attemptId: string;
  readonly requestId: string;
  readonly field?: LearningField;
  readonly index?: number;
  readonly reason: string;
}

export interface StagedLearningData {
  readonly candidates: readonly LearningCandidate[];
  readonly rejections: readonly LearningRejection[];
}

export interface LearningCandidateCollectorOptions {
  readonly maxActiveBuckets?: number;
  readonly maxCandidatesPerRequest?: number;
  readonly maxInputsPerField?: number;
  readonly maxRejections?: number;
}

/** Stable rejection reasons; callers may log or audit them as-is. */
export const LEARNING_REJECTION_REASONS = Object.freeze({
  unknownField: "unknown-field",
  fieldNotArray: "field-not-array",
  invalidCandidate: "invalid-candidate",
  candidateLimit: "candidate-limit",
  bucketCapacity: "bucket-capacity",
} as const);

const {
  unknownField: UNKNOWN_FIELD,
  fieldNotArray: FIELD_NOT_ARRAY,
  invalidCandidate: INVALID_CANDIDATE,
  candidateLimit: CANDIDATE_LIMIT,
  bucketCapacity: BUCKET_CAPACITY,
} = LEARNING_REJECTION_REASONS;

const DEFAULT_MAX_ACTIVE_BUCKETS = PROJECT_RULES_LIMITS.maxActiveBatches;
const DEFAULT_MAX_CANDIDATES_PER_REQUEST = PROJECT_RULES_LIMITS.maxCandidates;
const DEFAULT_MAX_INPUTS_PER_FIELD = PROJECT_RULES_LIMITS.maxLearningInputsPerField;
const DEFAULT_MAX_REJECTIONS = 64;
const MAX_JSON_DEPTH = 64;

const LEARNING_FIELDS: readonly LearningField[] = ["create", "revoke"];

const INVALID_JSON = Symbol("invalid-json");

/** Shared immutable view: every empty result is the same safe object. */
const EMPTY_VIEW: StagedLearningData = Object.freeze({
  candidates: Object.freeze([]) as readonly LearningCandidate[],
  rejections: Object.freeze([]) as readonly LearningRejection[],
});

interface RequestBucket {
  readonly candidates: LearningCandidate[];
  readonly rejections: LearningRejection[];
}

interface RejectionDetails {
  readonly field?: LearningField;
  readonly index?: number;
  readonly reason: string;
}

interface ParseContext {
  readonly attemptId?: string;
  readonly requestId: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function positiveSafeInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function frozenView(
  candidates: LearningCandidate[],
  rejections: LearningRejection[],
): StagedLearningData {
  return Object.freeze({
    candidates: Object.freeze(candidates),
    rejections: Object.freeze(rejections),
  });
}

/**
 * Freeze one candidate value as JSON data. Anything that cannot round-trip
 * through JSON (functions, non-finite numbers, accessors, class instances,
 * cycles, symbol keys) is not learnable and is rejected.
 */
function freezeCandidateValue(value: unknown): Readonly<Record<string, unknown>> | undefined {
  try {
    if (!isPlainObject(value)) return undefined;
    const frozen = freezeJsonNode(value, 1, new Set<object>());
    return frozen === INVALID_JSON ? undefined : (frozen as Readonly<Record<string, unknown>>);
  } catch {
    return undefined;
  }
}

function freezeJsonNode(value: unknown, depth: number, ancestors: Set<object>): unknown {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      return Number.isFinite(value) ? value : INVALID_JSON;
    case "object":
      return freezeJsonContainer(value as object, depth, ancestors);
    default:
      // undefined, function, symbol and bigint are not JSON values.
      return INVALID_JSON;
  }
}

function freezeJsonContainer(value: object, depth: number, ancestors: Set<object>): unknown {
  if (depth > MAX_JSON_DEPTH) return INVALID_JSON;
  // Ancestors (not a global seen set) reject cycles while allowing shared refs.
  if (ancestors.has(value)) return INVALID_JSON;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        // Descriptors avoid invoking accessors and reject sparse holes.
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !("value" in descriptor)) return INVALID_JSON;
        const item = freezeJsonNode(descriptor.value, depth + 1, ancestors);
        if (item === INVALID_JSON) return INVALID_JSON;
        items.push(item);
      }
      return Object.freeze(items);
    }
    if (!isPlainObject(value)) return INVALID_JSON;
    if (Object.getOwnPropertySymbols(value).length > 0) return INVALID_JSON;
    const frozenObject: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) return INVALID_JSON;
      const item = freezeJsonNode(descriptor.value, depth + 1, ancestors);
      if (item === INVALID_JSON) return INVALID_JSON;
      // defineProperty keeps a data property named `__proto__` from mutating the prototype.
      Object.defineProperty(frozenObject, key, {
        value: item,
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    return Object.freeze(frozenObject);
  } finally {
    ancestors.delete(value);
  }
}

export class LearningCandidateCollector {
  readonly #attemptStorage = new AsyncLocalStorage<string>();
  readonly #buckets = new Map<string, Map<string, RequestBucket>>();
  readonly #limits: Readonly<Required<LearningCandidateCollectorOptions>>;
  #attemptCounter = 0;

  constructor(options?: LearningCandidateCollectorOptions) {
    const source: LearningCandidateCollectorOptions =
      options !== null && typeof options === "object" ? options : {};
    this.#limits = Object.freeze({
      maxActiveBuckets: positiveSafeInteger(source.maxActiveBuckets, DEFAULT_MAX_ACTIVE_BUCKETS),
      maxCandidatesPerRequest: positiveSafeInteger(
        source.maxCandidatesPerRequest,
        DEFAULT_MAX_CANDIDATES_PER_REQUEST,
      ),
      maxInputsPerField: positiveSafeInteger(source.maxInputsPerField, DEFAULT_MAX_INPUTS_PER_FIELD),
      maxRejections: positiveSafeInteger(source.maxRejections, DEFAULT_MAX_REJECTIONS),
    });
  }

  /** Run `work` with an implicit attempt id; nested calls keep their own id. */
  runAttempt<T>(work: (attemptId: string) => T): T {
    this.#attemptCounter += 1;
    const attemptId = `attempt-${this.#attemptCounter}`;
    return this.#attemptStorage.run(attemptId, () => work(attemptId));
  }

  currentAttemptId(): string | undefined {
    return this.#attemptStorage.getStore();
  }

  /**
   * Validate one model payload and stage its valid candidates.
   *
   * Unknown-only payloads are ignored. Once a `create` or `revoke` key proves
   * the payload meant to learn, unknown fields become rejections instead of
   * candidates. Only the newly staged data is returned, frozen.
   */
  parse(input: unknown, context?: ParseContext): StagedLearningData {
    try {
      return this.#parse(input, context);
    } catch {
      // Untrusted payloads must never escape this seam as an exception.
      return EMPTY_VIEW;
    }
  }

  /** Extract and delete the given request buckets of one attempt. */
  take(attemptId: string, requestIds: readonly string[]): StagedLearningData {
    if (!isNonEmptyString(attemptId) || !Array.isArray(requestIds)) return EMPTY_VIEW;
    const byAttempt = this.#buckets.get(attemptId);
    if (byAttempt === undefined) return EMPTY_VIEW;

    const candidates: LearningCandidate[] = [];
    const rejections: LearningRejection[] = [];
    const seen = new Set<string>();
    for (const requestId of requestIds) {
      if (!isNonEmptyString(requestId) || seen.has(requestId)) continue;
      seen.add(requestId);
      const bucket = byAttempt.get(requestId);
      if (bucket === undefined) continue;
      candidates.push(...bucket.candidates);
      rejections.push(...bucket.rejections);
      byAttempt.delete(requestId);
    }
    if (byAttempt.size === 0) this.#buckets.delete(attemptId);
    if (candidates.length === 0 && rejections.length === 0) return EMPTY_VIEW;
    return frozenView(candidates, rejections);
  }

  hasStagedData(attemptId?: string): boolean {
    if (attemptId !== undefined) {
      if (!isNonEmptyString(attemptId)) return false;
      const byAttempt = this.#buckets.get(attemptId);
      return byAttempt !== undefined && byAttempt.size > 0;
    }
    return this.#bucketCount() > 0;
  }

  discard(attemptId: string, requestId: string): void {
    if (!isNonEmptyString(attemptId) || !isNonEmptyString(requestId)) return;
    const byAttempt = this.#buckets.get(attemptId);
    if (byAttempt === undefined) return;
    byAttempt.delete(requestId);
    if (byAttempt.size === 0) this.#buckets.delete(attemptId);
  }

  discardAttempt(attemptId: string): void {
    if (!isNonEmptyString(attemptId)) return;
    this.#buckets.delete(attemptId);
  }

  clear(): void {
    this.#buckets.clear();
  }

  pendingRequestCount(attemptId?: string): number {
    if (attemptId !== undefined) {
      if (!isNonEmptyString(attemptId)) return 0;
      return this.#buckets.get(attemptId)?.size ?? 0;
    }
    return this.#bucketCount();
  }

  #parse(input: unknown, context?: ParseContext): StagedLearningData {
    const attemptId = this.#resolveAttemptId(context);
    const requestId = context?.requestId;
    if (attemptId === undefined || !isNonEmptyString(requestId)) return EMPTY_VIEW;
    if (!isPlainObject(input)) return EMPTY_VIEW;

    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Object.keys(descriptors);
    const keySet = new Set(keys);
    // Accessor-backed input cannot be read as data-own properties; ignore it.
    for (const key of keys) {
      const descriptor = descriptors[key]!;
      if (!("value" in descriptor)) return EMPTY_VIEW;
    }

    const hasLegalKey = keySet.has("create") || keySet.has("revoke");
    if (!hasLegalKey) return EMPTY_VIEW;
    const symbols = Object.getOwnPropertySymbols(input);

    const existing = this.#findBucket(attemptId, requestId);
    if (existing === undefined && this.#bucketCount() >= this.#limits.maxActiveBuckets) {
      return Object.freeze({
        candidates: Object.freeze([]) as readonly LearningCandidate[],
        rejections: Object.freeze([
          Object.freeze({ attemptId, requestId, reason: BUCKET_CAPACITY }),
        ]) as readonly LearningRejection[],
      });
    }

    // Request caps are cumulative: repeated parses of one request share them.
    const baseCandidateCount = existing?.candidates.length ?? 0;
    const baseRejectionCount = existing?.rejections.length ?? 0;
    const candidates: LearningCandidate[] = [];
    const rejections: LearningRejection[] = [];

    // Reject unknown fields only after a legal key proved the learning intent.
    for (const key of keys) {
      if (key === "create" || key === "revoke") continue;
      this.#reject(rejections, baseRejectionCount, attemptId, requestId, { reason: UNKNOWN_FIELD });
    }
    for (const _symbol of symbols) {
      this.#reject(rejections, baseRejectionCount, attemptId, requestId, { reason: UNKNOWN_FIELD });
    }

    for (const field of LEARNING_FIELDS) {
      if (!keySet.has(field)) continue;
      const fieldDescriptor = descriptors[field]!;
      const fieldValue: unknown = "value" in fieldDescriptor ? fieldDescriptor.value : undefined;
      if (!Array.isArray(fieldValue)) {
        this.#reject(rejections, baseRejectionCount, attemptId, requestId, {
          field,
          reason: FIELD_NOT_ARRAY,
        });
        continue;
      }
      const itemCount = Math.min(fieldValue.length, this.#limits.maxInputsPerField);
      for (let index = 0; index < itemCount; index += 1) {
        if (baseCandidateCount + candidates.length >= this.#limits.maxCandidatesPerRequest) {
          this.#reject(rejections, baseRejectionCount, attemptId, requestId, {
            field,
            index,
            reason: CANDIDATE_LIMIT,
          });
          continue;
        }
        // Descriptors keep hostile payload getters from executing here.
        const itemDescriptor = Object.getOwnPropertyDescriptor(fieldValue, String(index));
        const item: unknown =
          itemDescriptor !== undefined && "value" in itemDescriptor ? itemDescriptor.value : undefined;
        const value = freezeCandidateValue(item);
        if (value === undefined) {
          this.#reject(rejections, baseRejectionCount, attemptId, requestId, {
            field,
            index,
            reason: INVALID_CANDIDATE,
          });
          continue;
        }
        candidates.push(Object.freeze({ attemptId, requestId, field, index, value }));
      }
    }

    if (candidates.length === 0 && rejections.length === 0) return EMPTY_VIEW;

    const bucket = existing ?? this.#createBucket(attemptId, requestId);
    bucket.candidates.push(...candidates);
    bucket.rejections.push(...rejections);
    return frozenView(candidates, rejections);
  }

  #resolveAttemptId(context?: ParseContext): string | undefined {
    if (context !== undefined && context !== null && context.attemptId !== undefined) {
      // An unusable explicit attempt must not silently fall back to the context.
      return isNonEmptyString(context.attemptId) ? context.attemptId : undefined;
    }
    const implicit = this.#attemptStorage.getStore();
    return isNonEmptyString(implicit) ? implicit : undefined;
  }

  #reject(
    rejections: LearningRejection[],
    baseCount: number,
    attemptId: string,
    requestId: string,
    details: RejectionDetails,
  ): void {
    if (baseCount + rejections.length >= this.#limits.maxRejections) return;
    rejections.push(Object.freeze({ attemptId, requestId, ...details }));
  }

  #findBucket(attemptId: string, requestId: string): RequestBucket | undefined {
    return this.#buckets.get(attemptId)?.get(requestId);
  }

  #createBucket(attemptId: string, requestId: string): RequestBucket {
    const bucket: RequestBucket = { candidates: [], rejections: [] };
    const byAttempt = this.#buckets.get(attemptId);
    if (byAttempt === undefined) this.#buckets.set(attemptId, new Map([[requestId, bucket]]));
    else byAttempt.set(requestId, bucket);
    return bucket;
  }

  #bucketCount(): number {
    let total = 0;
    for (const byAttempt of this.#buckets.values()) total += byAttempt.size;
    return total;
  }
}
