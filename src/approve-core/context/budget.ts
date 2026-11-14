/**
 * Reviewer-context token budget and evidence selection
 * (specs/reviewer-context.md §7, §9).
 *
 * The estimates here are conservative local capacity checks; they never claim
 * to equal provider usage. The decision budget derives the hard cap and the
 * packing target, the provider check proves a request fits a context window,
 * and the selection keeps a history that cannot fit by dropping whole
 * droppable groups newest-first instead of truncating arbitrary entries.
 */
import type { ApprovalEvidence } from "./types";
import { REVIEW_BUDGET_LIMITS } from "./types";

/** Hard cap and packing target of one model decision budget. */
export interface DecisionBudget {
  readonly max: number;
  readonly target: number;
}

/** A cap override is honoured only as a legal positive safe integer (§9). */
function isLegalConfiguredMax(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/** Decide the hard cap and the 80% packing target (§9). */
export function decisionBudget(configuredMaxTokens?: number | null): DecisionBudget {
  const max = isLegalConfiguredMax(configuredMaxTokens)
    ? configuredMaxTokens
    : REVIEW_BUDGET_LIMITS.decisionDefaultTokens;
  const packed = Math.floor(max * REVIEW_BUDGET_LIMITS.decisionPackingRatio);
  // The packing target never rises above the configured cap; a cap too small to
  // honour the 500-token floor simply keeps the whole cap as the target.
  const target = Math.min(max, Math.max(REVIEW_BUDGET_LIMITS.decisionMinimumTargetTokens, packed));
  return { max, target };
}

/**
 * Code-point ranges charged as one token: CJK punctuation, kana, unified and
 * compatibility ideographs (including extensions A and B+), fullwidth forms and
 * Hangul (§9). Every other code point is a quarter token.
 */
const CJK_RANGES: readonly (readonly [number, number])[] = [
  [0x1100, 0x11ff], // Hangul Jamo
  [0x3000, 0x303f], // CJK Symbols and Punctuation
  [0x3040, 0x30ff], // Hiragana and Katakana
  [0x3130, 0x318f], // Hangul Compatibility Jamo
  [0x3400, 0x4dbf], // CJK Unified Ideographs Extension A
  [0x4e00, 0x9fff], // CJK Unified Ideographs
  [0xa960, 0xa97f], // Hangul Jamo Extended-A
  [0xac00, 0xd7af], // Hangul Syllables
  [0xf900, 0xfaff], // CJK Compatibility Ideographs
  [0xff00, 0xffef], // Halfwidth and Fullwidth Forms
  [0x20000, 0x2fa1f], // CJK Unified Ideographs Extension B and later
];

function isCjkCodePoint(codePoint: number): boolean {
  return CJK_RANGES.some(([start, end]) => codePoint >= start && codePoint <= end);
}

/** Conservative local token estimate for one text (§9). */
export function estimateTextTokens(text: string): number {
  return Math.ceil(estimateTextTokenQuarters(text) / 4);
}

/** Exact quarter-token weight before the request-level round-up. */
export function estimateTextTokenQuarters(text: string): number {
  if (typeof text !== "string") throw new TypeError("estimateTextTokenQuarters expects a string");
  let quarters = 0;
  for (const character of text) {
    const codePoint = character.codePointAt(0) ?? 0;
    quarters += isCjkCodePoint(codePoint) ? 4 : 1;
  }
  return quarters;
}

/** Measure text after one exact JSON string-content escaping layer. */
export function estimateJsonStringContentTokenQuarters(text: string): number {
  const encoded = JSON.stringify(text);
  if (typeof encoded !== "string") throw new Error("request-not-serializable");
  return estimateTextTokenQuarters(encoded.slice(1, -1));
}

/** Measure the complete rendered JSON of a request value (§9). */
export function measureRequestTokens(value: unknown): number {
  return Math.ceil(measureRequestTokenQuarters(value) / 4);
}

/** Measure a complete rendered JSON request before the final round-up. */
export function measureRequestTokenQuarters(value: unknown): number {
  let rendered: string | undefined;
  try {
    rendered = JSON.stringify(value);
  } catch {
    throw new Error("request-not-serializable");
  }
  if (typeof rendered !== "string") throw new Error("request-not-serializable");
  return estimateTextTokenQuarters(rendered);
}

/** Everything a provider budget check needs about one request (§9). */
export interface ProviderBudgetInput {
  /** The complete request context; measured as its rendered JSON. */
  readonly context: unknown;
  /** Output tokens the reviewer wants to reserve. */
  readonly outputTokens: number;
  /** The model's own output limit. */
  readonly maxOutputTokens: number;
  readonly contextWindowTokens: number;
  /** Room kept for provider framing; unusable values count as zero. */
  readonly framingMarginTokens?: number;
  /** Injected estimator seam; defaults to `estimateTextTokens`. */
  readonly estimateTokens?: (text: string) => number;
}

export type ProviderBudgetFailure =
  | "invalid-context-window"
  | "invalid-output-limit"
  | "invalid-output-budget"
  | "context-not-serializable"
  | "context-window-exceeded"
  | "invalid-estimator";

export type ProviderBudgetResult =
  | { readonly ok: true; readonly outputTokens: number; readonly inputTokens: number }
  | { readonly ok: false; readonly reason: ProviderBudgetFailure };

/** True for a finite number greater than zero. */
function isPositiveFinite(value: number): boolean {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

/** Prove one request fits `input + output + framingMargin <= window` (§9). */
export function checkProviderBudget(input: ProviderBudgetInput): ProviderBudgetResult {
  if (!isPositiveFinite(input.contextWindowTokens)) {
    return { ok: false, reason: "invalid-context-window" };
  }
  if (!isPositiveFinite(input.maxOutputTokens)) {
    return { ok: false, reason: "invalid-output-limit" };
  }
  if (!isPositiveFinite(input.outputTokens)) {
    return { ok: false, reason: "invalid-output-budget" };
  }
  const estimator = input.estimateTokens;
  if (estimator !== undefined && typeof estimator !== "function") {
    return { ok: false, reason: "invalid-estimator" };
  }
  const estimate = estimator ?? estimateTextTokens;
  const actualOutputTokens = Math.min(input.outputTokens, input.maxOutputTokens);
  let rendered: string | undefined;
  try {
    rendered = JSON.stringify(input.context);
  } catch {
    return { ok: false, reason: "context-not-serializable" };
  }
  if (typeof rendered !== "string") return { ok: false, reason: "context-not-serializable" };
  const marginInput = input.framingMarginTokens;
  const margin =
    typeof marginInput === "number" && Number.isFinite(marginInput) && marginInput >= 0 ? marginInput : 0;
  const inputTokens = estimate(rendered);
  if (inputTokens + actualOutputTokens + margin > input.contextWindowTokens) {
    return { ok: false, reason: "context-window-exceeded" };
  }
  return { ok: true, outputTokens: actualOutputTokens, inputTokens };
}

/**
 * History evidence that the budget may consider (§6). Authorization is
 * rendered in its own request section, so user-sourced evidence is excluded
 * here instead of being duplicated or rewritten by the budget.
 */
export function historySelectableEvidence(
  evidence: readonly ApprovalEvidence[],
): readonly ApprovalEvidence[] {
  return Object.freeze(evidence.filter((item) => item.source !== "user"));
}

/** Per-tool-call component counts; entries without a tool identity are ignored. */
interface ToolPartCounts {
  readonly calls: ReadonlyMap<string, number>;
  readonly results: ReadonlyMap<string, number>;
}

function countToolParts(evidence: readonly ApprovalEvidence[]): ToolPartCounts {
  const calls = new Map<string, number>();
  const results = new Map<string, number>();
  for (const item of evidence) {
    if (item.toolCallId === undefined) continue;
    const counts = item.toolPart === "call" ? calls : item.toolPart === "result" ? results : undefined;
    if (counts === undefined) continue;
    counts.set(item.toolCallId, (counts.get(item.toolCallId) ?? 0) + 1);
  }
  return { calls, results };
}

/**
 * True when any tool call id has more results than calls in this evidence (§7).
 * The caller must rebuild a Full selection instead of sending an orphan result.
 */
export function hasUnpairedToolResults(evidence: readonly ApprovalEvidence[]): boolean {
  const { calls, results } = countToolParts(evidence);
  for (const [toolCallId, resultCount] of results) {
    if (resultCount > (calls.get(toolCallId) ?? 0)) return true;
  }
  return false;
}

/** A history the budget selected: the evidence kept and whether anything was omitted. */
export interface BudgetedEvidence {
  readonly evidence: readonly ApprovalEvidence[];
  readonly omitted: boolean;
}

export interface IncrementalEvidenceCosts {
  readonly limitQuarterTokens: number;
  readonly baseQuarterTokens: { readonly all: number; readonly omitted: number };
  readonly entryQuarterTokens: readonly number[];
  readonly separatorQuarterTokens: number;
  readonly emptyPlaceholderQuarterTokens: number;
}

function selectableGroups(evidence: readonly ApprovalEvidence[]): {
  readonly droppable: ReadonlySet<number>;
  readonly groups: readonly (readonly number[])[];
} {
  const droppable = new Set<number>();
  const groups: number[][] = [];
  let openGroup: number[] | undefined;
  const { calls, results } = countToolParts(evidence);
  const isCompletePairAt = (index: number): boolean => {
    const call = evidence[index];
    const result = evidence[index + 1];
    if (call?.toolPart !== "call" || result?.toolPart !== "result") return false;
    const toolCallId = call.toolCallId;
    return (
      toolCallId !== undefined &&
      toolCallId === result.toolCallId &&
      calls.get(toolCallId) === 1 &&
      results.get(toolCallId) === 1
    );
  };
  for (let index = 0; index < evidence.length; index += 1) {
    const item = evidence[index]!;
    if (item.source === "assistant") {
      openGroup = [index];
      groups.push(openGroup);
      droppable.add(index);
      continue;
    }
    if (isCompletePairAt(index)) {
      const pairIndices = [index, index + 1];
      if (openGroup === undefined) groups.push(pairIndices);
      else openGroup.push(...pairIndices);
      droppable.add(index);
      droppable.add(index + 1);
      index += 1;
      continue;
    }
    openGroup = undefined;
  }
  return { droppable, groups };
}

/** Select whole history groups from exact additive quarter-token costs. */
export function selectBudgetedEvidenceByCost(
  evidence: readonly ApprovalEvidence[],
  costs: IncrementalEvidenceCosts,
): BudgetedEvidence | undefined {
  if (
    costs.entryQuarterTokens.length !== evidence.length ||
    !Number.isFinite(costs.limitQuarterTokens) ||
    !Number.isFinite(costs.separatorQuarterTokens) ||
    !Number.isFinite(costs.emptyPlaceholderQuarterTokens) ||
    costs.entryQuarterTokens.some((cost) => !Number.isFinite(cost))
  ) return undefined;

  const { droppable, groups } = selectableGroups(evidence);
  if (groups.length === 0) return undefined;
  let selectedCount = 0;
  let selectedCost = 0;
  const selected = new Set<number>();
  for (const index of evidence.keys()) {
    if (droppable.has(index)) continue;
    selected.add(index);
    selectedCount += 1;
    selectedCost += costs.entryQuarterTokens[index]!;
  }
  const totalCost = (count: number, entries: number, omitted: boolean): number => {
    const base = costs.baseQuarterTokens[omitted ? "omitted" : "all"];
    if (count === 0) return base;
    return base - costs.emptyPlaceholderQuarterTokens + entries + costs.separatorQuarterTokens * (count - 1);
  };
  if (totalCost(selectedCount, selectedCost, true) > costs.limitQuarterTokens) return undefined;

  for (const group of [...groups].reverse()) {
    let groupCost = 0;
    for (const index of group) groupCost += costs.entryQuarterTokens[index]!;
    const candidateCount = selectedCount + group.length;
    if (totalCost(candidateCount, selectedCost + groupCost, true) > costs.limitQuarterTokens) continue;
    for (const index of group) selected.add(index);
    selectedCount = candidateCount;
    selectedCost += groupCost;
  }
  return { evidence: evidence.filter((_, index) => selected.has(index)), omitted: true };
}

/**
 * Keep the largest useful history that fits (§7).
 *
 * The full list wins as-is. Otherwise only whole droppable groups are removed,
 * newest first, while every mandatory entry is kept; a history is never
 * truncated mid-pair and `omitted` is always reported when the full list did
 * not fit without the omission flag.
 */
export function selectBudgetedEvidence(
  evidence: readonly ApprovalEvidence[],
  fits: (candidate: readonly ApprovalEvidence[], omitted: boolean) => boolean,
): BudgetedEvidence | undefined {
  if (fits(evidence, false)) return { evidence, omitted: false };

  const { droppable, groups } = selectableGroups(evidence);
  if (groups.length === 0) return undefined;

  const mandatory = evidence.filter((_, index) => !droppable.has(index));
  if (!fits(mandatory, true)) return undefined;

  const selected = new Set<number>();
  for (const index of evidence.keys()) {
    if (!droppable.has(index)) selected.add(index);
  }
  for (const group of [...groups].reverse()) {
    const candidateIndices = [...selected, ...group].sort((left, right) => left - right);
    const candidate = candidateIndices.map((index) => evidence[index]!);
    if (!fits(candidate, true)) continue;
    for (const index of group) selected.add(index);
  }
  return { evidence: evidence.filter((_, index) => selected.has(index)), omitted: true };
}
