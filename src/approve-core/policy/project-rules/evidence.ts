/**
 * User evidence verification for project-rule learning.
 *
 * A model proposal may cite only a verbatim quote of a frozen user
 * authorization entry. This module decides whether that quote really proves the
 * requested persistent create/revoke (specs/project-rule-model.md §8-§11):
 *
 * - the cited entry exists, is sourced from the user and contains the quote
 *   verbatim; paraphrases, transcript attributions and cloned quotes fail;
 * - statements are classified lexically (ephemeral / persistent / allow / deny /
 *   revoke / broad / read / write / execute) and negations are scoped to the
 *   same statement unit, so "不要撤销" never counts as a revoke;
 * - create evidence needs persistent, non-ephemeral authorization whose
 *   operation direction covers every ask access of the current action and whose
 *   target binding follows one of the three accepted proofs;
 * - revoke evidence needs an explicit revoke in quote and context plus one of
 *   the three target proofs over active rules.
 *
 * Everything here is pure: no I/O, no clock, no mocks and no thrown errors. A
 * rejection is always a stable `reason` string so callers (the Phase 9 learning
 * transaction) can branch on it.
 */
import { matchExactAction } from "./match";
import { isSensitiveText } from "./sensitive";
import {
  PROJECT_RULES_LIMITS,
  type AuthorizationEntry,
  type EvidenceProposal,
  type ExactAction,
  type RuleEffect,
  type ScopeAccess,
  type StoredProjectRule,
} from "./types";

const MAX_QUOTE_CHARS = PROJECT_RULES_LIMITS.maxQuoteChars;
const MIN_CONFIDENCE = PROJECT_RULES_LIMITS.minConfidence;

// ---------------------------------------------------------------------------
// Statement splitting
// ---------------------------------------------------------------------------

export interface StatementSpan {
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

const HARD_STATEMENT_SEPARATORS = new Set(["。", "！", "？", "；", "!", "?", ";"]);

function trimmedSpan(text: string, from: number, to: number): StatementSpan | undefined {
  let start = from;
  let end = to;
  while (start < end && /\s/.test(text[start] as string)) start += 1;
  while (end > start && /\s/.test(text[end - 1] as string)) end -= 1;
  if (start >= end) return undefined;
  return { text: text.slice(start, end), start, end };
}

/**
 * Split text into statement units. A unit ends at a Chinese/ASCII question
 * mark, exclamation mark, semicolon or full stop, at an ASCII period that is
 * followed by end-of-text or whitespace (so `3.14` stays whole), or at any line
 * break. Offsets index into the original text and exclude surrounding
 * whitespace.
 */
export function splitStatements(text: string): readonly { readonly text: string; readonly start: number; readonly end: number }[] {
  const spans: StatementSpan[] = [];
  let unitStart = 0;
  const flush = (to: number): void => {
    const span = trimmedSpan(text, unitStart, to);
    if (span !== undefined) spans.push(span);
  };
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index] as string;
    if (character === "\r" || character === "\n") {
      flush(index);
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      unitStart = index + 1;
      continue;
    }
    if (HARD_STATEMENT_SEPARATORS.has(character)) {
      flush(index + 1);
      unitStart = index + 1;
      continue;
    }
    if (character === ".") {
      const next = index + 1 < text.length ? (text[index + 1] as string) : "";
      if (next === "" || /\s/.test(next)) {
        flush(index + 1);
        unitStart = index + 1;
      }
    }
  }
  flush(text.length);
  return spans;
}

// ---------------------------------------------------------------------------
// Statement classification (spec §9)
// ---------------------------------------------------------------------------

export interface StatementClassification {
  readonly ephemeral: boolean;
  readonly persistent: boolean;
  readonly allow: boolean;
  readonly deny: boolean;
  readonly revoke: boolean;
  readonly negatedRevoke: boolean;
  readonly broad: boolean;
  readonly reads: boolean;
  readonly writes: boolean;
  readonly executes: boolean;
}

const ALLOW_VERB_RE =
  /\ballow(?:s|ed|ing)?\b|\bpermit(?:s|ted|ting)?\b|\bapprov(?:e|es|ed|ing)\b|\bauthoriz(?:e|es|ed|ing)\b|允许|准许|同意|授权|批准|放行|可以/i;
const DENY_VERB_RE =
  /\bden(?:y|ies|ied)\b|\bforbid(?:s|den)?\b|\bdisallow(?:s|ed)?\b|\bprohibit(?:s|ed)?\b|not\s+allowed|never\s+allow(?:ed)?|don'?t\s+allow|do\s+not\s+allow|must\s+not|may\s+not|禁止|严禁|不许|不准|不准许|不允许|不可以|不得|不能|不可/i;
const REVOKE_VERB_RE =
  /撤销|撤消|撤回|撤掉|废除|作废|(?:(?:删除|删掉|移除|去掉|取消|忘记|忘掉|停用|禁用)[^。！？!?;\n]{0,10}(?:规则|rule|策略))|\brevok(?:e|es|ed|ing)\b|\b(?:remove|delete|forget|drop)\s+(?:this|the|that|a)\s+rule\b/i;
const EPHEMERAL_RE =
  /(?:仅|只|就)?这(?:一)?次|本次|当前会话|本会话|这次会话|本次会话|当前对话|本次对话|临时|暂时|短期内|一次性|只此一次|下不为例|不要记住|别记住|不用记住|无需记住|无须记住|不要记录|别记录|不要保存|别保存|不要存|别存|just\s+this\s+once|this\s+once|only\s+this\s+time|this\s+time\s+only|one[\s-]?off|one\s+time\s+only|for\s+now|temporarily|temporary|this\s+session|current\s+session|just\s+for\s+now|don'?t\s+remember|do\s+not\s+remember|don'?t\s+save|no\s+need\s+to\s+remember/i;
const PERSISTENT_RE =
  /以后|今后|从此|将来|后续|长期|永远|永久|一直|始终|每次|每回|记住|记下|记录下|记录下来|存下来|(?:\b(?:always|permanently?|remember)\b|\bfrom\s+now\s+on\b|\bevery\s+time\b|\beach\s+time\b|\b(?:in\s+the\s+)?future\b|\bgoing\s+forward\b|\bhenceforth\b|\bpersist(?:s|ed|ing|ently)?\b)/i;
const BROAD_RE = /\ball\b|\bany\b|\beverything\b|\banything\b|\bwhatever\b|\bwhichever\b|所有|任何|一切|全部|每个|每回|任意|随便/i;
const READ_VERB_RE =
  /\bread(?:s|ing)?\b|\bview(?:s|ing)?\b|\blist(?:s|ing)?\b|\bshow(?:s|ing)?\b|\bopen(?:s|ing)?\b|\binspect(?:s|ing)?\b|\blook(?:s|ing)?\b|\bcat\b|读取|读|查看|查阅|浏览|列出|打开|看/i;
const WRITE_VERB_RE =
  /\bwrit(?:e|es|ten|ing)\b|\bedit(?:s|ing)?\b|\bcreat(?:e|es|ing)\b|\bdelet(?:e|es|ing)\b|\bmov(?:e|es|ing)\b|\bcop(?:y|ies|ying)\b|\brenam(?:e|es|ing)\b|\bmodif(?:y|ies|ying)\b|\bupdat(?:e|es|ing)\b|\bappend(?:s|ing)?\b|\boverwrit(?:e|es|ing)\b|\bremov(?:e|es|ing)\b|\bsav(?:e|es|ing)\b|\bchmod\b|\bmkdir\b|\btouch\b|写入|写|编辑|修改|创建|新建|删除|删掉|删|移动|复制|拷贝|重命名|改名|追加|覆盖|保存/i;
const EXECUTE_VERB_RE =
  /\brun(?:s|ning)?\b|\bexecut(?:e|es|ed|ing)\b|\bexec\b|\binvok(?:e|es|ed|ing)\b|\blaunch(?:es|ed|ing)?\b|\bspawn(?:s|ed|ing)?\b|\bstart(?:s|ed|ing)?\b|运行|执行|调用|启动|跑/i;

/**
 * Negation that dominates a verb when it ends right before the verb inside the
 * same statement unit ("不要撤销", "don't revoke", "不允许").
 */
const NEGATION_BEFORE_RE =
  /(?:不要|不用|不必|无需|无须|不是|并非|不算|不曾|不再|不能|不可|不得|不准|不许|不可以|无法|未能|别|勿|没|未|不|禁止|避免|don'?t|dont|doesn'?t|does\s+not|do\s+not|did\s+not|didn'?t|not|never|no\s+need\s+to|without|avoid|shouldn'?t|should\s+not|wouldn'?t|would\s+not|can'?t|cannot|won'?t|will\s+not|mustn'?t|must\s+not|needn'?t|no)\s*$/i;

function matchIndexes(text: string, pattern: RegExp): number[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const scanner = new RegExp(pattern.source, flags);
  const indexes: number[] = [];
  let match = scanner.exec(text);
  while (match !== null) {
    indexes.push(match.index);
    if (match[0].length === 0) scanner.lastIndex += 1;
    match = scanner.exec(text);
  }
  return indexes;
}

function precededByNegation(text: string, index: number): boolean {
  return NEGATION_BEFORE_RE.test(text.slice(Math.max(0, index - 16), index));
}

/**
 * Lexical classification of one statement unit. Negation only dominates the
 * verb it directly precedes inside the same unit, so "不要撤销" yields
 * `negatedRevoke` instead of `revoke`, and a negated allow counts as a deny.
 * Write authorization implies read; read never implies write and unspecified
 * operations stay false so they cannot widen the host scope.
 */
export function classifyStatement(text: string): StatementClassification {
  const allowMatches = matchIndexes(text, ALLOW_VERB_RE);
  const allow = allowMatches.some((index) => !precededByNegation(text, index));
  const negatedAllow = allowMatches.some((index) => precededByNegation(text, index));
  const deny = DENY_VERB_RE.test(text) || negatedAllow;

  const revokeMatches = matchIndexes(text, REVOKE_VERB_RE);
  const revoke = revokeMatches.some((index) => !precededByNegation(text, index));
  const negatedRevoke = revokeMatches.some((index) => precededByNegation(text, index));

  const persistentMatches = matchIndexes(text, PERSISTENT_RE);
  const persistent = persistentMatches.some((index) => !precededByNegation(text, index));
  const ephemeral = EPHEMERAL_RE.test(text);
  const broad = BROAD_RE.test(text);
  const writes = WRITE_VERB_RE.test(text);
  const reads = READ_VERB_RE.test(text) || writes;
  const executes = EXECUTE_VERB_RE.test(text);

  return { ephemeral, persistent, allow, deny, revoke, negatedRevoke, broad, reads, writes, executes };
}

function mergeClassifications(classifications: readonly StatementClassification[]): StatementClassification {
  const merged = {
    ephemeral: false,
    persistent: false,
    allow: false,
    deny: false,
    revoke: false,
    negatedRevoke: false,
    broad: false,
    reads: false,
    writes: false,
    executes: false,
  };
  for (const classification of classifications) {
    merged.ephemeral ||= classification.ephemeral;
    merged.persistent ||= classification.persistent;
    merged.allow ||= classification.allow;
    merged.deny ||= classification.deny;
    merged.revoke ||= classification.revoke;
    merged.negatedRevoke ||= classification.negatedRevoke;
    merged.broad ||= classification.broad;
    merged.reads ||= classification.reads;
    merged.writes ||= classification.writes;
    merged.executes ||= classification.executes;
  }
  merged.reads ||= merged.writes;
  return merged;
}

// ---------------------------------------------------------------------------
// Shared evidence seams
// ---------------------------------------------------------------------------

export type EvidenceFailure = {
  readonly ok: false;
  readonly reason:
    | "invalid-evidence"
    | "unknown-entry"
    | "not-user-source"
    | "quote-not-verbatim"
    | "quote-ambiguous"
    | "sensitive"
    | "ephemeral"
    | "no-persistent"
    | "contradictory"
    | "operation-unprovable"
    | "target-unprovable"
    | "unrelated-context";
};

type FailureReason = EvidenceFailure["reason"];

function failure(reason: FailureReason): EvidenceFailure {
  return { ok: false, reason };
}

/** Stable precondition shared by create and revoke evidence (§8, §1). */
function basicEvidenceProblem(proposal: EvidenceProposal): FailureReason | undefined {
  if (proposal.sourceEntryId.trim().length === 0) return "invalid-evidence";
  if (proposal.quote.trim().length === 0) return "invalid-evidence";
  if (proposal.quote.length > MAX_QUOTE_CHARS) return "invalid-evidence";
  if (!Number.isFinite(proposal.confidence)) return "invalid-evidence";
  if (proposal.confidence < MIN_CONFIDENCE || proposal.confidence > 1) return "invalid-evidence";
  return undefined;
}

function findEntry(
  authorization: readonly AuthorizationEntry[],
  sourceEntryId: string,
): AuthorizationEntry | undefined {
  return authorization.find((entry) => entry.id === sourceEntryId);
}

/** The "complete user text" is every user-sourced entry, in frozen order. */
function userTextOf(authorization: readonly AuthorizationEntry[]): string {
  return authorization
    .filter((entry) => entry.source === "user")
    .map((entry) => entry.text)
    .join("\n");
}

function countOccurrences(text: string, needle: string): number {
  let count = 0;
  let index = text.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = text.indexOf(needle, index + 1);
  }
  return count;
}

interface TextSpan {
  readonly start: number;
  readonly end: number;
}

const QUOTE_PAIRS: readonly (readonly [string, string])[] = [
  ["“", "”"],
  ["‘", "’"],
  ["「", "」"],
  ["『", "』"],
  ["`", "`"],
  ['"', '"'],
];

/** Interior ranges of quoted/backticked text; an unclosed opener is ignored. */
function quotedInteriorSpans(text: string): TextSpan[] {
  const spans: TextSpan[] = [];
  for (let index = 0; index < text.length; index += 1) {
    for (const [open, close] of QUOTE_PAIRS) {
      if ((text[index] as string) !== open) continue;
      const closeIndex = text.indexOf(close, index + 1);
      if (closeIndex === -1) break;
      spans.push({ start: index + 1, end: closeIndex });
      index = closeIndex;
      break;
    }
  }
  return spans;
}

/**
 * Entry text that presents a non-user source as the authorization source
 * ("assistant said", "工具返回", "日志显示") is transcript, not direct consent.
 */
const ATTRIBUTION_RE =
  /(?:assistant|tool|tools|system|log|logs|summary|reviewer|extension|model|agent|terminal\s+output|previous\s+(?:message|reply|context)|according\s+to|助手|助理|工具|系统|日志|总结|模型|代理|上文|上面|刚才(?:的)?(?:回复|消息)|之前(?:的)?(?:回复|消息))[^。！？!?;\n]{0,24}(?:said|says|say|reported|reports|noted|notes|confirmed|confirms|stated|states|suggested|suggests|indicated|indicates|allowed|allows|说|表示|认为|显示|返回|同意|允许|可以|确认|提到|指出)/i;

/**
 * A quote must occur at least once outside a quoted/backticked paraphrase and
 * outside an attribution to another source in the same statement unit.
 */
function isDirectUserQuote(entryText: string, quote: string): boolean {
  if (ATTRIBUTION_RE.test(quote)) return false;
  const quotedSpans = quotedInteriorSpans(entryText);
  const statements = splitStatements(entryText);
  let index = entryText.indexOf(quote);
  while (index !== -1) {
    const quoted = quotedSpans.some((span) => index >= span.start && index + quote.length <= span.end);
    const statement = statements.find((span) => index >= span.start && index < span.end);
    const attributed = statement !== undefined && ATTRIBUTION_RE.test(entryText.slice(statement.start, index));
    if (!quoted && !attributed) return true;
    index = entryText.indexOf(quote, index + 1);
  }
  return false;
}

function intersectsStatement(statement: StatementSpan, start: number, end: number): boolean {
  return statement.start < end && statement.end > start;
}

// ---------------------------------------------------------------------------
// Target binding helpers (spec §10)
// ---------------------------------------------------------------------------

const PATH_TOKEN_RE = /[^\s，。；;！？、,?!()\[\]{}<>"'`“”‘’]+/gu;

/** Path-like tokens; whole command targets ("npm test") are not path-like. */
function extractPathLikeTokens(text: string): string[] {
  const tokens: string[] = [];
  for (const match of text.matchAll(PATH_TOKEN_RE)) {
    const raw = (match[0] as string).replace(/[.:;!?]+$/u, "");
    if (raw.length < 3) continue;
    if (raw.includes("/") || raw.includes("\\") || /\.[A-Za-z0-9]{1,8}$/u.test(raw)) tokens.push(raw);
  }
  return tokens;
}

function mentionsTarget(text: string, target: string): boolean {
  if (!text.includes(target)) return false;
  const pathLike = target.includes("/") || target.includes("\\") || /\.[A-Za-z0-9]{1,8}$/u.test(target);
  if (!pathLike) return true;
  return extractPathLikeTokens(text).includes(target);
}

function actionTargetsOf(action: ExactAction): readonly string[] {
  return [...new Set(action.scopes.map((scope) => scope.target))];
}

function targetSetKey(action: ExactAction): string {
  return canonicalTargetKey(actionTargetsOf(action));
}

function canonicalTargetKey(targets: readonly string[]): string {
  return JSON.stringify([...targets].sort());
}

function effectiveBatch(action: ExactAction, batch: readonly ExactAction[]): readonly ExactAction[] {
  return batch.some((candidate) => candidate.requestId === action.requestId) ? batch : [action, ...batch];
}

function actionHasNonReadAccess(action: ExactAction): boolean {
  return action.scopes.some((scope) => scope.access !== "read");
}

function requestedAccesses(action: ExactAction): readonly ScopeAccess[] {
  return [...new Set(action.scopes.map((scope) => scope.access))];
}

const INSPECT_ONLY_RE =
  /(?:只能|仅能|只可|仅可|只许|只允许)(?:查看|读取|读|看|浏览|列出|检查)|只读|仅读|read[- ]?only|inspect[- ]only|only\s+(?:view|read|list|inspect|look)|just\s+(?:view|read|list|inspect|look)|nothing\s+but\s+(?:view|read)|don'?t\s+(?:edit|modify|write|change)|do\s+not\s+(?:edit|modify|write|change)|不能(?:编辑|修改|写入|写|改)/i;

const POINTER_RE =
  /这个|当前|同?一动作|同一操作|该动作|该操作|这条|那条|该规则|此规则|该条|此条|this\s+(?:action|one|rule)|current\s+(?:action|one|rule)|same\s+(?:action|one|rule)|(?:\bthis\b|\bcurrent\b|\bsame\b|\bthat\b|\bit\b)/i;

const RULE_REFERENCE_RE = /rule-[0-9a-f]{16,64}|\brule\b|规则/i;

function hasPathLikeToken(text: string): boolean {
  return extractPathLikeTokens(text).length > 0;
}

function hasIndependentSubject(text: string): boolean {
  return hasPathLikeToken(text) || RULE_REFERENCE_RE.test(text);
}

function coversAccess(classification: StatementClassification, access: ScopeAccess): boolean {
  switch (access) {
    case "read":
      return classification.reads;
    case "write":
      return classification.writes;
    case "execute":
      return classification.executes;
    case "network":
    case "other":
      // The classifier cannot prove network/other direction, so unspecified
      // operations never widen the host scope.
      return false;
  }
}

// ---------------------------------------------------------------------------
// Create evidence (spec §10)
// ---------------------------------------------------------------------------

export interface CreateEvidenceRequest {
  readonly action: ExactAction;
  readonly batch: readonly ExactAction[];
  readonly authorization: readonly AuthorizationEntry[];
  readonly proposal: EvidenceProposal;
  readonly effect: RuleEffect;
}

export type CreateEvidenceResult =
  | { readonly ok: true; readonly context: string; readonly classification: StatementClassification }
  | EvidenceFailure;

function classifyOtherUnits(
  otherStatements: readonly StatementSpan[],
  actionTargets: readonly string[],
  effect: RuleEffect,
  nonReadAccess: boolean,
): FailureReason | undefined {
  for (const statement of otherStatements) {
    const classification = classifyStatement(statement.text);
    const mentionsActionTarget = actionTargets.some((target) => mentionsTarget(statement.text, target));
    // An independent persistent grant about another target makes the current
    // quote's target ambiguous; it is unrelated context, not consent for this
    // action.
    if (classification.persistent && !mentionsActionTarget && hasPathLikeToken(statement.text)) {
      return "unrelated-context";
    }
    if (!hasIndependentSubject(statement.text)) {
      if (classification.ephemeral) return "ephemeral";
      if (effect === "allow" && (classification.deny || classification.revoke)) return "contradictory";
    }
    if (mentionsActionTarget) {
      if (classification.ephemeral) return "ephemeral";
      if (effect === "allow" && (classification.deny || classification.revoke)) return "contradictory";
    }
    // A read-only/one-time/negative authorization limits an allow that needs a
    // non-read direction. It applies to the current target and to generic
    // qualifiers that do not name an unrelated target.
    const mentionsOtherTargetOnly = hasPathLikeToken(statement.text) && !mentionsActionTarget;
    if (effect === "allow" && nonReadAccess && !mentionsOtherTargetOnly &&
      INSPECT_ONLY_RE.test(statement.text) && !classification.writes) {
      return "operation-unprovable";
    }
  }
  return undefined;
}

function bindsExplicitTargets(
  request: CreateEvidenceRequest,
  actionTargets: readonly string[],
  contextText: string,
): boolean {
  const actionKey = targetSetKey(request.action);
  const sameTargetSet = effectiveBatch(request.action, request.batch)
    .filter((candidate) => canonicalTargetKey(actionTargetsOf(candidate)) === actionKey);
  if (sameTargetSet.length !== 1) return false;
  if (!actionTargets.every((target) => mentionsTarget(contextText, target))) return false;
  if (!actionTargets.every((target) => mentionsTarget(request.proposal.quote, target))) return false;
  // Precise reference: no unknown path target may be named by the quote or its
  // context.
  const allowed = new Set(actionTargets);
  for (const token of extractPathLikeTokens(request.proposal.quote)) {
    if (!allowed.has(token)) return false;
  }
  for (const token of extractPathLikeTokens(contextText)) {
    if (!allowed.has(token)) return false;
  }
  return true;
}

function bindsBroadPersistent(
  request: CreateEvidenceRequest,
  contextText: string,
  contextClassification: StatementClassification,
  otherStatements: readonly StatementSpan[],
  actionTargets: readonly string[],
): boolean {
  if (!contextClassification.broad) return false;
  if (hasPathLikeToken(request.proposal.quote)) return false;
  if (hasPathLikeToken(contextText)) return false;
  if (actionTargets.some((target) => mentionsTarget(contextText, target))) return false;
  if (INSPECT_ONLY_RE.test(contextText) && actionHasNonReadAccess(request.action)) return false;
  for (const statement of otherStatements) {
    if (hasPathLikeToken(statement.text)) return false;
    if (actionTargets.some((target) => mentionsTarget(statement.text, target))) return false;
    if (INSPECT_ONLY_RE.test(statement.text) && actionHasNonReadAccess(request.action)) return false;
  }
  return true;
}

function bindsSingleActionPointer(
  request: CreateEvidenceRequest,
  contextText: string,
  actionTargets: readonly string[],
): boolean {
  if (effectiveBatch(request.action, request.batch).length !== 1) return false;
  if (!POINTER_RE.test(contextText)) return false;
  const allowed = new Set(actionTargets);
  for (const token of extractPathLikeTokens(contextText)) {
    if (!allowed.has(token)) return false;
  }
  if (INSPECT_ONLY_RE.test(contextText) && actionHasNonReadAccess(request.action)) return false;
  return true;
}

/**
 * Verify that a model-proposed quote proves a persistent create of `effect`
 * for `action`. Returns the authorization context and its classification on
 * success; failures never throw.
 */
export function verifyCreateEvidence(request: CreateEvidenceRequest): CreateEvidenceResult {
  const proposal = request.proposal;
  const basicProblem = basicEvidenceProblem(proposal);
  if (basicProblem !== undefined) return failure(basicProblem);
  if (isSensitiveText(proposal.quote)) return failure("sensitive");

  const entry = findEntry(request.authorization, proposal.sourceEntryId);
  if (entry === undefined) return failure("unknown-entry");
  if (entry.source !== "user") return failure("not-user-source");
  if (!entry.text.includes(proposal.quote)) return failure("quote-not-verbatim");
  if (!isDirectUserQuote(entry.text, proposal.quote)) return failure("not-user-source");
  if (countOccurrences(userTextOf(request.authorization), proposal.quote) !== 1) return failure("quote-ambiguous");

  const entryStatements = splitStatements(entry.text);
  const quoteStart = entry.text.indexOf(proposal.quote);
  const quoteEnd = quoteStart + proposal.quote.length;
  const contextStatements = entryStatements.filter((statement) => intersectsStatement(statement, quoteStart, quoteEnd));
  const contextText = contextStatements.map((statement) => statement.text).join("\n");
  const quoteClassification = classifyStatement(proposal.quote);
  const contextClassification = mergeClassifications(contextStatements.map((statement) => classifyStatement(statement.text)));

  if (quoteClassification.ephemeral || contextClassification.ephemeral) return failure("ephemeral");
  if (!quoteClassification.persistent || !contextClassification.persistent) return failure("no-persistent");

  if (request.effect === "allow") {
    if (!quoteClassification.allow) return failure("contradictory");
    if (quoteClassification.deny || quoteClassification.revoke ||
      contextClassification.deny || contextClassification.revoke) {
      return failure("contradictory");
    }
  } else {
    if (!quoteClassification.deny) return failure("contradictory");
    if (quoteClassification.allow && quoteClassification.deny) return failure("contradictory");
  }

  // §9 keeps other statement units for limited-condition checks only. We scan
  // the cited entry's own units so an unrelated grant from another user message
  // cannot poison this evidence; cross-entry duplicates already fail above.
  const otherStatements = entryStatements.filter((statement) => !intersectsStatement(statement, quoteStart, quoteEnd));
  const actionTargets = actionTargetsOf(request.action);
  const nonReadAccess = actionHasNonReadAccess(request.action);
  const otherProblem = classifyOtherUnits(otherStatements, actionTargets, request.effect, nonReadAccess);
  if (otherProblem !== undefined) return failure(otherProblem);

  if (request.action.scopes.length === 0) return failure("target-unprovable");
  const missingAccess = requestedAccesses(request.action)
    .filter((access) => !coversAccess(contextClassification, access));
  if (missingAccess.length > 0) return failure("operation-unprovable");
  // An inspect-only qualifier in the authorization unit itself limits an allow
  // that needs a non-read direction ("以后允许所有编辑，但只能查看").
  if (request.effect === "allow" && nonReadAccess && INSPECT_ONLY_RE.test(contextText)) {
    return failure("operation-unprovable");
  }

  if (bindsExplicitTargets(request, actionTargets, contextText)) {
    return { ok: true, context: contextText, classification: contextClassification };
  }
  if (bindsBroadPersistent(request, contextText, contextClassification, otherStatements, actionTargets)) {
    return { ok: true, context: contextText, classification: contextClassification };
  }
  if (bindsSingleActionPointer(request, contextText, actionTargets)) {
    return { ok: true, context: contextText, classification: contextClassification };
  }
  return failure("target-unprovable");
}

// ---------------------------------------------------------------------------
// Revoke evidence (spec §11)
// ---------------------------------------------------------------------------

export interface RevokeEvidenceRequest {
  readonly action: ExactAction;
  readonly batch: readonly ExactAction[];
  readonly authorization: readonly AuthorizationEntry[];
  readonly proposal: EvidenceProposal;
  readonly rules: readonly StoredProjectRule[];
  readonly targetRuleId?: string;
}

export type RevokeEvidenceResult =
  | { readonly ok: true; readonly targetRuleId: string; readonly context: string }
  | EvidenceFailure;

function activeRulesOf(rules: readonly StoredProjectRule[]): readonly StoredProjectRule[] {
  return rules.filter((rule) => rule.status === "active" && rule.revocation === undefined);
}

/**
 * Verify that a model-proposed quote proves revoking exactly one active rule.
 * The revoked rule is proven by the exact rule ID in the revoke unit, by a
 * complete path that only one active rule owns, or by a "this rule" pointer
 * when exactly one active rule matches the current action.
 */
export function verifyRevokeEvidence(request: RevokeEvidenceRequest): RevokeEvidenceResult {
  const proposal = request.proposal;
  const basicProblem = basicEvidenceProblem(proposal);
  if (basicProblem !== undefined) return failure(basicProblem);
  if (isSensitiveText(proposal.quote)) return failure("sensitive");

  const entry = findEntry(request.authorization, proposal.sourceEntryId);
  if (entry === undefined) return failure("unknown-entry");
  if (entry.source !== "user") return failure("not-user-source");
  if (!entry.text.includes(proposal.quote)) return failure("quote-not-verbatim");
  if (!isDirectUserQuote(entry.text, proposal.quote)) return failure("not-user-source");
  if (countOccurrences(userTextOf(request.authorization), proposal.quote) !== 1) return failure("quote-ambiguous");

  const entryStatements = splitStatements(entry.text);
  const quoteStart = entry.text.indexOf(proposal.quote);
  const quoteEnd = quoteStart + proposal.quote.length;
  const contextStatements = entryStatements.filter((statement) => intersectsStatement(statement, quoteStart, quoteEnd));
  const contextText = contextStatements.map((statement) => statement.text).join("\n");
  const quoteClassification = classifyStatement(proposal.quote);
  const contextClassification = mergeClassifications(contextStatements.map((statement) => classifyStatement(statement.text)));

  if (quoteClassification.ephemeral || contextClassification.ephemeral) return failure("ephemeral");
  if (quoteClassification.negatedRevoke || contextClassification.negatedRevoke) return failure("contradictory");
  if (!quoteClassification.revoke || !contextClassification.revoke) return failure("contradictory");

  const activeRules = activeRulesOf(request.rules);
  if (request.targetRuleId !== undefined && !activeRules.some((rule) => rule.id === request.targetRuleId)) {
    return failure("target-unprovable");
  }

  let targetRule: StoredProjectRule | undefined;
  const explicitRuleIds = activeRules.filter((rule) => contextText.includes(rule.id));
  if (explicitRuleIds.length > 1) return failure("target-unprovable");
  if (explicitRuleIds.length === 1) targetRule = explicitRuleIds[0];

  if (targetRule === undefined) {
    const pathMatches = activeRules.filter((rule) =>
      rule.match.requiredScopes.some((scope) => mentionsTarget(contextText, scope.target)));
    if (pathMatches.length > 1) return failure("target-unprovable");
    if (pathMatches.length === 1) targetRule = pathMatches[0];
  }

  if (targetRule === undefined && POINTER_RE.test(contextText)) {
    const matchingRules = activeRules.filter((rule) => matchExactAction(rule, request.action).kind === "match");
    if (matchingRules.length === 1) {
      // "这条规则" is only unambiguous when no conflicting path is named.
      const candidate = matchingRules[0];
      const candidateTargets = new Set(candidate.match.requiredScopes.map((scope) => scope.target));
      if (extractPathLikeTokens(contextText).every((token) => candidateTargets.has(token))) targetRule = candidate;
    }
  }

  if (targetRule === undefined) return failure("target-unprovable");
  if (request.targetRuleId !== undefined && request.targetRuleId !== targetRule.id) {
    return failure("target-unprovable");
  }
  return { ok: true, targetRuleId: targetRule.id, context: contextText };
}
