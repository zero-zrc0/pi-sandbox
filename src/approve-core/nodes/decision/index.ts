/**
 * The decision node — the one front node that decides (v4 §9.2).
 *
 * It replaces the separate rules / assessment / shell-policy / mode decision
 * nodes: the facts are projected once per call, the responsibility chain runs
 * over them, and exactly one batch of unit decisions is submitted. No later
 * front node can overwrite those decisions, which is why the old
 * "don't override an explicit ask" heuristics are gone — the ordering and the
 * composition rules now carry that meaning.
 *
 * What it does not do: it does not analyze the step (the structure-analysis node
 * already did), does not execute anything, and does not resolve asks (the model
 * and human nodes still do that).
 *
 * Sources and where their opinion went:
 *
 * | source | chain kind |
 * |---|---|
 * | mode | `mode-base`, plus `mode-override` for the configured `uncertain`/`unmatched` attitudes |
 * | explicit rules | `explicit-rules-restrict` / `explicit-rules-grant` |
 * | shell policy (`builtin/powershell`, `builtin/external-command`) | restriction / grant over the per-unit policy opinion |
 * | tool assessment | `block` → restriction, `run` → grant, `review`/`defer` → no opinion |
 * | danger families | `danger-intent` |
 * | sensitive paths | `sensitive-paths` |
 * | nothing | `fallback` |
 *
 * Assessment `review`/`defer` deliberately carry no opinion. The mode records
 * `unknown`; the configured sandbox receipt or final fallback resolves it.
 */
import type { CallState, UnitDecision, UnitReview } from "#approve-core/contracts";
import type { ChainNode, SessionReviewPort, StepContext } from "#approve-core/runtime";
import type { PermissionMode } from "../../../contracts";
import type { ShellPolicy } from "#config/shell-policy-schema";
import type { ShellPolicyPathVariables } from "#approve-core/policy/shell-policy/evaluate";
import type { ShellExecutionPermissions } from "#config/execution-source-schema";
import type { Rule, RuleEvaluator } from "#approve-core/policy/rule";
import type { PathFlavor } from "#approve-core/utils/path/path-flavor";
import type { BashProgramProvider } from "#approve-core/nodes/analysis";
import type { AssessmentResolver } from "#approve-core/nodes/assessment";
import { deriveAccessFacts } from "#approve-core/nodes/mode";
import { shellPolicyUnitDecisions, type BashProgramAnalysis } from "#approve-core/nodes/shell-policy";
import { decideCall } from "#approve-core/chain/decide";
import { createDefaultChainHandlers } from "#approve-core/chain/defaults";
import { createFallbackHandler } from "#approve-core/chain/handlers/fallback";
import { createModeBaseHandler } from "#approve-core/chain/handlers/mode-base";
import {
  createModeOverrideHandler,
  createOpinionGrantHandler,
  createOpinionRestrictionHandler,
  ASSESSMENT_GRANT_PRIORITY,
  ASSESSMENT_RESTRICTION_PRIORITY,
  SHELL_POLICY_GRANT_PRIORITY,
  SHELL_POLICY_RESTRICTION_PRIORITY,
  type UnitOpinion,
} from "#approve-core/chain/handlers/opinions";
import { createSandboxDefaultRunHandler } from "#approve-core/chain/handlers/sandbox-default-run";
import { chainCallDigest, createSandboxReceipt } from "#approve-core/chain/receipt";
import type { ChainCallFacts, ChainChannel, ChainUnitFacts, UnitAccessFact } from "#approve-core/chain/facts";
import type { Handler } from "#approve-core/chain/run";
import { projectRuleFacts } from "#approve-core/chain/facts/rules";
import { projectSensitiveFacts } from "#approve-core/chain/facts/sensitive";
import { projectShellFacts } from "#approve-core/chain/facts/shell";

export const DECISION_NODE_ID = "builtin/decision";

export interface DecisionNodeOptions {
  readonly mode: PermissionMode;
  readonly cwd?: string;
  readonly platform?: NodeJS.Platform;
  readonly rules: readonly Rule[];
  readonly evaluator?: RuleEvaluator;
  readonly flavor?: PathFlavor;
  readonly mcpTargets?: (call: CallState) => readonly string[];
  readonly resolveAssessment?: AssessmentResolver;
  readonly shellPolicy?: ShellPolicy;
  readonly shellPathVariables?: ShellPolicyPathVariables;
  readonly additionalLocalPaths?: readonly string[];
  readonly enabledShellNodes?: readonly string[];
  readonly shellGrants?: ShellExecutionPermissions;
  readonly getBashProgram?: BashProgramProvider;
  readonly workspaceRoot?: string;
  readonly workspaceBulkDeleteAction?: "deny" | "ask";
  /**
   * Links the host appends after the built-ins: user approval nodes (P2) and
   * the C2 sandbox default run (P3). A user link must never outrank a built-in
   * deny, which `orderHandlers` plus the deny short-circuit enforce.
   */
  readonly userNodes?: readonly UserNodeLink[];
  readonly extraHandlers?: readonly Handler[];
  /**
   * The host's session memory. Its deny is stored as a review that can reject an
   * allow; approve resolves asks. Absent in `full-access`.
   */
  readonly sessionReviews?: SessionReviewPort;
  /**
   * C2: what the execution layer can confine. Present only when the host holds a
   * live sandbox session; the mode's `shellPolicy.modes.<mode>.defaultPolicy`
   * still has to opt in, and the per-call receipt is issued and validated here
   * from these claims plus the frozen call digest.
   */
  readonly sandboxRun?: SandboxRunCapability;
}

export interface SandboxRunCapability {
  readonly backend: string;
  readonly available: boolean;
  readonly networkPolicy: "none" | "proxied";
  readonly planRevision: string;
  readonly sessionId: string;
  readonly workspaceRoot: string;
}

function clip(text: string, limit: number): string {
  return text.length <= limit ? text : `${text.slice(0, limit - 3)}...`;
}

/**
 * The fixed front decision node. Its position is the caller's responsibility:
 * the host binds it after `builtin/identity`, so user priority cannot move it.
 */
export function createDecisionNode(options: DecisionNodeOptions): ChainNode {
  const platform = options.platform ?? process.platform;
  const cwd = options.cwd ?? process.cwd();
  return Object.freeze({
    apiVersion: "1" as const,
    id: DECISION_NODE_ID,
    evaluate: async (context: StepContext) => {
      const decisions: UnitDecision[] = [];
      const reviews: UnitReview[] = [];
      const userOpinions = await evaluateUserNodes(options.userNodes ?? [], context);
      for (const call of context.state.calls) {
        if (call.units.some((unit) => unit.decision === "deny")) continue;
        const evaluated = await decideOneCall(call, context, options, {
          platform,
          cwd,
          workspaceRoot: options.workspaceRoot ?? cwd,
        }, userOpinions);
        decisions.push(...evaluated.decisions);
        reviews.push(...evaluated.reviews);
      }
      return { decisions, ...(reviews.length === 0 ? {} : { reviews }) };
    },
  });
}

/**
 * A user approval node as a chain link (v4 §4).
 *
 * The node keeps the `apiVersion: "1"` shape it always had; what changes is
 * that its result is read as an opinion instead of final state. `kind` decides
 * which half of that opinion the chain may use: `restriction` keeps the
 * deny/ask half, `grant` keeps the allow half. A legacy declaration is a
 * restriction, which is the safe half.
 */
export interface UserNodeLink {
  readonly node: ChainNode;
  readonly kind: "restriction" | "grant";
  /** The configured priority; only its order is used (links land in 70–990). */
  readonly priority: number;
  readonly timeoutMs?: number;
}

const USER_LINK_FIRST_PRIORITY = 70;
const USER_LINK_LAST_PRIORITY = 990;
const DEFAULT_USER_NODE_TIMEOUT_MS = 30_000;

/** Per-node, per-call, per-unit opinions of every user link. */
type UserOpinions = ReadonlyMap<string, ReadonlyMap<string, ReadonlyMap<string, UnitOpinion>>>;

/**
 * Run every user node once for the step, then keep only its opinions. A node
 * that throws or times out fails closed: its opinion becomes an ask for every
 * call, and the other links still run (v4 §4), so one broken plugin cannot
 * approve or deny anything.
 */
async function evaluateUserNodes(
  links: readonly UserNodeLink[],
  context: StepContext,
): Promise<UserOpinions> {
  const opinions = new Map<string, Map<string, Map<string, UnitOpinion>>>();
  const ordered = [...links].sort((left, right) => left.priority - right.priority);
  for (const link of ordered) {
    const byCall = new Map<string, Map<string, UnitOpinion>>();
    opinions.set(link.node.id, byCall);
    try {
      const result = await withTimeout(
        link.node.evaluate(context, { log: () => undefined }),
        link.timeoutMs ?? DEFAULT_USER_NODE_TIMEOUT_MS,
      );
      for (const decision of result.decisions) {
        if (decision.decision === "escalate") continue;
        const byUnit = byCall.get(decision.toolCallId) ?? new Map<string, UnitOpinion>();
        byCall.set(decision.toolCallId, byUnit);
        const previous = byUnit.get(decision.unitId);
        if (previous === undefined || rank(decision.decision) > rank(previous.decision)) {
          byUnit.set(decision.unitId, {
            decision: decision.decision,
            reason: decision.reason,
            ...(decision.askFor === undefined ? {} : { askFor: decision.askFor }),
          });
        }
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : "threw";
      for (const call of context.state.calls) {
        const byUnit = new Map<string, UnitOpinion>();
        for (const unit of call.units) {
          byUnit.set(unit.unitId, {
            decision: "ask",
            reason: `user-handler-fault:${link.node.id}:${reason}`,
          });
        }
        byCall.set(call.toolCallId, byUnit);
      }
    }
  }
  return opinions;
}

async function withTimeout<T>(work: Promise<T> | T, timeoutMs: number): Promise<T> {
  const value = Promise.resolve(work);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return value;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("user-handler-timeout")), timeoutMs);
    });
    return await Promise.race([value, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

interface DerivedContext {
  readonly platform: NodeJS.Platform;
  readonly cwd: string;
  readonly workspaceRoot: string;
}

async function decideOneCall(
  call: CallState,
  context: StepContext,
  options: DecisionNodeOptions,
  derived: DerivedContext,
  userOpinions: UserOpinions,
): Promise<{ readonly decisions: readonly UnitDecision[]; readonly reviews: readonly UnitReview[] }> {
  const shell = await projectShellFacts({
    call,
    ...(context.bashPrograms?.[call.toolCallId] === undefined
      ? {}
      : { bashView: context.bashPrograms[call.toolCallId] }),
    ...(context.powershellPrograms?.[call.toolCallId] === undefined
      ? {}
      : { powershellView: context.powershellPrograms[call.toolCallId] }),
    options: {
      platform: derived.platform,
      cwd: derived.cwd,
      workspaceRoot: derived.workspaceRoot,
      ...(options.shellPolicy === undefined ? {} : { shellPolicy: options.shellPolicy }),
      ...(options.shellPathVariables === undefined
        ? {}
        : { shellPathVariables: options.shellPathVariables }),
      ...(options.additionalLocalPaths === undefined
        ? {}
        : { additionalLocalPaths: options.additionalLocalPaths }),
      ...(options.enabledShellNodes === undefined
        ? {}
        : { enabledShellNodes: options.enabledShellNodes }),
      ...(options.shellGrants === undefined ? {} : { shellGrants: options.shellGrants }),
      ...(options.workspaceBulkDeleteAction === undefined
        ? {}
        : { workspaceBulkDeleteAction: options.workspaceBulkDeleteAction }),
    },
  });

  const accessByUnit = shell?.access ?? await legacyAccessByUnit(call, options, derived);
  const dangers = shell?.dangers ?? [];
  const ruleFacts = await projectRuleFacts({
    call,
    context,
    options: {
      rules: options.rules,
      ...(options.evaluator === undefined ? {} : { evaluator: options.evaluator }),
      ...(options.flavor === undefined ? {} : { flavor: options.flavor }),
      ...(options.mcpTargets === undefined ? {} : { mcpTargets: options.mcpTargets }),
      ...(options.getBashProgram === undefined
        ? {}
        : { getBashProgram: options.getBashProgram }),
    },
  });

  const units: ChainUnitFacts[] = call.units.map((unit) => {
    const access = accessByUnit.get(unit.unitId) ?? UNKNOWN_ONLY;
    const unitDangers = dangers.filter((hit) =>
      hit.unitIds.length === 0 || hit.unitIds.includes(unit.unitId));
    const rule = ruleFacts.get(unit.unitId);
    return {
      unitId: unit.unitId,
      toolName: call.toolName,
      access,
      dangers: unitDangers,
      ...(rule === undefined ? {} : { rule }),
      sensitive: projectSensitiveFacts({
        call,
        access,
        cwd: derived.cwd,
        platform: derived.platform,
      }),
    };
  });

  const callFacts: ChainCallFacts = {
    toolCallId: call.toolCallId,
    toolName: call.toolName,
    units,
    ...(call.hostExecutionRequest === undefined
      ? {}
      : { hostExecutionRequest: call.hostExecutionRequest }),
  };

  const policyOpinions = shellPolicyOpinions(call, context, options, derived.platform, shell?.bashAnalysis);
  const modeOverrides = modeOverrideOpinions(options.mode, units, policyOpinions, options);
  const channel: ChainChannel = call.hostExecutionRequest === undefined ? "normal" : "elevation";
  const assessment = await assessmentOpinions(call, context, options);
  const sessionReview = await sessionReviewForCall(call, options);
  const sandboxHandler = await sandboxDefaultRunHandler(callFacts, call, context, options);

  const result = await decideCall(callFacts, {
    mode: options.mode,
    channel,
    handlers: buildHandlers(
      policyOpinions,
      modeOverrides,
      assessment,
      options,
      call,
      userOpinions,
      sandboxHandler,
    ),
    signal: context.signal,
  });

  if (result.fault !== undefined) {
    // The runtime turns this into its step-level fault fallback, which is the
    // existing fail-closed behavior for a broken node.
    throw new Error(`chain-fault:${result.fault.handlerId}:${result.fault.reason}`);
  }

  const decisions = result.units.map((unit) => {
    const verdict = unit.verdict;
    const decision = verdict.state === "none" || verdict.state === "unknown" ? "ask" : verdict.state;
    return {
      toolCallId: call.toolCallId,
      unitId: unit.unitId,
      decision,
      ...(decision === "ask" && verdict.askFor !== undefined
        ? { askFor: verdict.askFor }
        : {}),
      reason: clip(verdict.reason.length > 0 ? verdict.reason : "chain:no-opinion", 2_000),
    };
  });
  const reviews = sessionReview === undefined || result.units.some((unit) => unit.verdict.state === "deny")
    ? []
    : result.units.flatMap((unit): UnitReview[] => {
        if (sessionReview.decision === "deny") {
          return [{
            toolCallId: call.toolCallId,
            unitId: unit.unitId,
            decision: "deny",
            reason: sessionReview.reason,
          }];
        }
        if (unit.verdict.state !== "ask" || unit.verdict.askFor === "escalate") return [];
        return [{
          toolCallId: call.toolCallId,
          unitId: unit.unitId,
          decision: "approve",
          reason: sessionReview.reason,
        }];
      });
  return { decisions, reviews };
}

const UNKNOWN_ONLY: readonly UnitAccessFact[] = Object.freeze([Object.freeze({ kind: "unknown" })]);

/** Path tools and shell calls without a parsed view fall back to the old derivation. */
async function legacyAccessByUnit(
  call: CallState,
  options: DecisionNodeOptions,
  derived: DerivedContext,
): Promise<ReadonlyMap<string, readonly UnitAccessFact[]>> {
  const facts = await deriveAccessFacts(call, {
    cwd: derived.cwd,
    platform: derived.platform,
    ...(options.getBashProgram === undefined ? {} : { getBashProgram: options.getBashProgram }),
    ...(options.shellGrants === undefined ? {} : { shellGrants: options.shellGrants }),
    ...(options.additionalLocalPaths === undefined ? {} : { additionalLocalPaths: options.additionalLocalPaths }),
  });
  return new Map(call.units.map((unit) => [unit.unitId, facts]));
}

/** The configured shell policy, as one opinion per unit (deny > ask > allow). */
function shellPolicyOpinions(
  call: CallState,
  context: StepContext,
  options: DecisionNodeOptions,
  platform: NodeJS.Platform,
  bashAnalysis?: BashProgramAnalysis,
): ReadonlyMap<string, UnitOpinion> {
  const enabled = options.enabledShellNodes ?? [];
  const opinions = new Map<string, UnitOpinion>();
  const nodeOptions = {
    policy: options.shellPolicy,
    mode: options.mode,
    ...(options.shellPathVariables === undefined
      ? {}
      : { pathVariables: options.shellPathVariables }),
    platform,
  };
  const merge = (decisions: readonly UnitDecision[]): void => {
    for (const decision of decisions) {
      if (decision.decision === "escalate") continue;
      const previous = opinions.get(decision.unitId);
      if (previous === undefined || rank(decision.decision) > rank(previous.decision)) {
        opinions.set(decision.unitId, { decision: decision.decision, reason: decision.reason });
      }
    }
  };
  if (enabled.includes("builtin/powershell") && call.toolName === "powershell") {
    merge(shellPolicyUnitDecisions({
      node: "builtin/powershell",
      call,
      context,
      view: context.powershellPrograms?.[call.toolCallId],
      bashView: undefined,
      options: nodeOptions,
    }));
  }
  if (enabled.includes("builtin/external-command")) {
    merge(shellPolicyUnitDecisions({
      node: "builtin/external-command",
      call,
      context,
      view: context.powershellPrograms?.[call.toolCallId],
      bashView: context.bashPrograms?.[call.toolCallId],
      ...(bashAnalysis === undefined ? {} : { bashAnalysis }),
      options: nodeOptions,
    }));
  }
  return opinions;
}

function rank(decision: UnitDecision["decision"]): number {
  return decision === "deny" ? 2 : decision === "ask" ? 1 : 0;
}

/**
 * The mode's configured `uncertain`/`unmatched` attitude. `uncertain` means the
 * facts do not prove the effect; `unmatched` means no shell-policy rule covered
 * the unit, which is the same situation the mode node used the unit history for.
 */
function modeOverrideOpinions(
  mode: PermissionMode,
  units: readonly ChainUnitFacts[],
  policyOpinions: ReadonlyMap<string, UnitOpinion>,
  options: DecisionNodeOptions,
): ReadonlyMap<string, UnitOpinion> {
  const modePolicy = mode === "full-access" ? undefined : options.shellPolicy?.modes?.[mode];
  const overrides = new Map<string, UnitOpinion>();
  if (modePolicy === undefined) return overrides;
  for (const unit of units) {
    const uncertain = unit.access.some((fact) => fact.kind === "unknown");
    const policy = policyOpinions.get(unit.unitId);
    const unmatched = policy === undefined || policy.reason.endsWith(":unmatched");
    const configured = uncertain ? modePolicy.uncertain : unmatched ? modePolicy.unmatched : undefined;
    if (configured === undefined) continue;
    overrides.set(unit.unitId, {
      decision: configured,
      reason: `shell-policy:mode:${mode}:${uncertain ? "uncertain" : "unmatched"}`,
    });
  }
  return overrides;
}

/**
 * The tool assessment's opinion. `block` tightens, `run` widens, and the
 * "I cannot prove it" routes carry no opinion at all.
 */
async function assessmentOpinions(
  call: CallState,
  context: StepContext,
  options: DecisionNodeOptions,
): Promise<ReadonlyMap<string, UnitOpinion>> {
  const opinions = new Map<string, UnitOpinion>();
  if (options.resolveAssessment === undefined) return opinions;
  let assessment;
  try {
    assessment = await options.resolveAssessment(call, context);
  } catch {
    // An assessment that cannot answer is not evidence of safety.
    opinions.set("*", { decision: "ask", reason: "assessment:fault" });
    return opinions;
  }
  if (assessment === null) return opinions;
  const reason = clip(`assessment:${assessment.route}:${assessment.cause}:${assessment.reason}`, 2_000);
  if (assessment.route === "block") opinions.set("*", { decision: "deny", reason });
  if (assessment.route === "run" && !isStrictApproval(options)) {
    opinions.set("*", { decision: "allow", reason });
  }
  return opinions;
}

function isStrictApproval(options: DecisionNodeOptions): boolean {
  return (options.mode === "default" || options.mode === "auto-review") &&
    options.shellPolicy?.modes?.[options.mode]?.defaultPolicy === "ask";
}

function buildHandlers(
  policyOpinions: ReadonlyMap<string, UnitOpinion>,
  modeOverrides: ReadonlyMap<string, UnitOpinion>,
  assessment: ReadonlyMap<string, UnitOpinion>,
  options: DecisionNodeOptions,
  call: CallState,
  userOpinions: UserOpinions,
  sandboxHandler: Handler | undefined,
): readonly Handler[] {
  const strictApproval = isStrictApproval(options);
  return [
    createModeBaseHandler({ strictApproval }),
    createModeOverrideHandler({ overrides: modeOverrides }),
    ...createDefaultChainHandlers().filter((handler) =>
      handler.id !== "builtin/mode-base" && handler.id !== "builtin/fallback"),
    createOpinionRestrictionHandler({
      id: "builtin/shell-policy-restrict",
      priority: SHELL_POLICY_RESTRICTION_PRIORITY,
      opinions: policyOpinions,
    }),
    createOpinionGrantHandler({
      id: "builtin/shell-policy-grant",
      priority: SHELL_POLICY_GRANT_PRIORITY,
      opinions: policyOpinions,
    }),
    createOpinionRestrictionHandler({
      id: "builtin/assessment-restrict",
      priority: ASSESSMENT_RESTRICTION_PRIORITY,
      opinions: assessment,
    }),
    createOpinionGrantHandler({
      id: "builtin/assessment-grant",
      priority: ASSESSMENT_GRANT_PRIORITY,
      opinions: assessment,
    }),
    ...(sandboxHandler === undefined ? [] : [sandboxHandler]),
    ...userHandlers(options.userNodes ?? [], call, userOpinions),
    createFallbackHandler(),
    ...(options.extraHandlers ?? []),
  ];
}

/**
 * The host's session memory, read once per call. A memory failure never decides
 * a call: an exception or a missing answer is "no opinion", and the chain's own
 * fallback keeps the ask.
 */
async function sessionReviewForCall(
  call: CallState,
  options: DecisionNodeOptions,
): Promise<Awaited<ReturnType<SessionReviewPort>> | undefined> {
  if (options.mode === "full-access") return undefined;
  const port = options.sessionReviews;
  if (port === undefined) return undefined;
  let decision;
  try {
    decision = await port({
      toolCallId: call.toolCallId,
      toolName: call.toolName,
      arguments: call.arguments,
    });
  } catch {
    return undefined;
  }
  return decision;
}

/** How long a C2 receipt stays valid; it is issued and checked in one decision. */
const SANDBOX_RECEIPT_TTL_MS = 60_000;

/**
 * C2 (`sandbox-default-run`, priority 60): when strict approval is off and the
 * host reports a working backend, the chain binds this call to a sandbox receipt
 * that may resolve a clean unknown. Existing asks and denies remain unchanged.
 */
async function sandboxDefaultRunHandler(
  call: ChainCallFacts,
  sourceCall: CallState,
  context: StepContext,
  options: DecisionNodeOptions,
): Promise<Handler | undefined> {
  const capability = options.sandboxRun;
  if (capability === undefined || !capability.available) return undefined;
  if (options.mode !== "default" && options.mode !== "auto-review") return undefined;
  const modePolicy = options.shellPolicy?.modes?.[options.mode];
  if (modePolicy?.defaultPolicy === "ask") return undefined;
  if (call.toolName === "bash") {
    try {
      const program = await options.getBashProgram?.(sourceCall);
      if (program === undefined || !program.parsed || program.parseUnresolved) return undefined;
    } catch {
      return undefined;
    }
  } else if (call.toolName === "powershell") {
    const view = context.powershellPrograms?.[call.toolCallId];
    if (view === undefined || view.callDigest !== sourceCall.digest ||
      view.commandText !== sourceCall.arguments.command || !view.result.ok ||
      view.result.summary.completeness !== "complete") return undefined;
  } else {
    return undefined;
  }
  const issuedAtMs = Date.now();
  const receipt = createSandboxReceipt({
    sessionId: capability.sessionId,
    backend: capability.backend,
    planRevision: capability.planRevision,
    callDigest: chainCallDigest(call),
    issuedAtMs,
    expiresAtMs: issuedAtMs + SANDBOX_RECEIPT_TTL_MS,
    workspaceRoot: capability.workspaceRoot,
    networkPolicy: capability.networkPolicy,
  });
  return createSandboxDefaultRunHandler({
    receipt,
    nowMs: () => Date.now(),
    sessionId: capability.sessionId,
    workspaceRoot: capability.workspaceRoot,
  });
}

/**
 * The user links for one call, in the configured order. They land in the
 * documented 70–990 band, after every built-in restriction, so a user grant can
 * resolve unknown; they cannot remove an ask, and a built-in deny has already
 * short-circuited.
 */
function userHandlers(
  links: readonly UserNodeLink[],
  call: CallState,
  userOpinions: UserOpinions,
): readonly Handler[] {
  const ordered = [...links].sort((left, right) => left.priority - right.priority);
  return ordered.map((link, index) => {
    const priority = Math.min(USER_LINK_LAST_PRIORITY, USER_LINK_FIRST_PRIORITY + index);
    const opinions = userOpinions.get(link.node.id)?.get(call.toolCallId) ?? new Map<string, UnitOpinion>();
    return link.kind === "grant"
      ? createOpinionGrantHandler({ id: link.node.id, priority, opinions })
      : createOpinionRestrictionHandler({ id: link.node.id, priority, opinions });
  });
}







