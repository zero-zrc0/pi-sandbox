import type { ExecutionRequest } from "../../elevation";
import { approvalText, resolveApprovalLanguage, type ApprovalText } from "./approval-i18n";
﻿/**
 * Pi host integration (specs/host-integration.md §5, §6, §7, §9).
 *
 * This module owns one extension instance: it opens a session record per Pi
 * session, keeps that session's reviewer memory, reviewer context store,
 * step runner, mode reminder and publication generation, and answers every Pi
 * `tool_call` through the frozen approval chain. Everything external is
 * injected — the config publication factory, the analysis and chain ports, the
 * model registry, the sandbox guard, the human selector and the audit sink — so
 * the host can be driven by the Pi event surface alone and the migrated core
 * (which needs the later wiring phase to load) is never imported as a value.
 *
 * Failure policy: an unavailable config, an ambiguous step, a changed evidence
 * snapshot or a chain/host error always blocks the call. Only a final host
 * allow lets the call through; audit, learning and observer failures never
 * change a decision that was already reached.
 */
import type {
  ExtensionAPI,
  ExtensionContext,
  ExtensionToolContext,
  KeybindingsManager,
  SessionEntry,
  SessionProjection,
  Theme,
  ToolCallEvent,
  ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { formatPiSandboxError } from "../../error-format";
import {
  DynamicBorder,
  getLanguageFromPath,
  highlightCode,
} from "@earendil-works/pi-coding-agent";
import { Box, Container, Spacer, Text } from "@earendil-works/pi-tui";
import type {
  BashProgramProvider,
  BashProgramRequest,
  PowerShellProgramProvider,
  PowerShellProgramRequest,
} from "#approve-core/nodes/analysis";
import type {
  BashProgramFactsView,
  CaptureStepResult,
  CallSummary,
  StepCapture,
  StepCaptureInput,
  UnitPreparation,
} from "#approve-core/contracts";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type {
  HumanApprover,
  HumanRequest,
  HumanResponse,
  NodeBinding,
  RunStepChainInput,
  RunStepChainResult,
  SessionReviewPort,
  StepContext,
} from "#approve-core/runtime";
import type { LlmApproverNodeDependencies } from "#approve-core/nodes/llm-approver/types";
import type {
  ReviewerContextStore,
  ReviewerLearningLifecycle,
  ReviewerMode,
  ReviewerSessionFacts,
  ReviewerSessionMemory,
  ReviewCaptureResult,
  ReviewToolEvent,
} from "#approve-core/context";
import { createReviewerContextStore } from "#approve-core/context/store";
import { createReviewerSessionMemory } from "#approve-core/context/session-memory";
import { reviewDigest } from "#approve-core/context/types";
import { createModeReminder, modeReminderText, type ModeReminder } from "./mode-reminder";
import { getActiveAgentName } from "./active-agent";
import { createPermissionRequestId } from "./permission-request-id";
import {
  createAskSessionMemory,
  type AskSessionMemory,
} from "#approve-core/policy/tool-rules";
import {
  createSessionCommandGrants,
  suggestSessionCommandGrants,
  type SessionCommandGrants,
} from "#approve-core/policy/session-command-grants";
import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import { collectStepBashFacts } from "./bash-facts";
import { collectStepPowerShellFacts } from "./powershell-facts";
import { createStepFacts } from "./step-facts";
import { existsSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import {
  buildEditDiff,
  fallbackPreview,
  type DiffLine,
} from "./write-diff";
import {
  createStepRunner,
  type StepHandle,
  type StepOutcome,
  type StepRunner,
  type StepRunnerLearningPort,
} from "./step-runner";

// ---------------------------------------------------------------------------
// Public vocabulary
// ---------------------------------------------------------------------------

/** The permission mode, structurally identical to the reviewer mode. */
export type PermissionMode = ReviewerMode;

/** The dedicated answer type of a controlled-execution review. */
export type ReviewAnswer =
  | { readonly block: true; readonly reason: string; readonly permissionDenied?: boolean }
  | { readonly kind: "host-execution"; readonly reason: string }
  | undefined;

export interface SandboxReviewInput {
  readonly ask?: boolean;
  readonly requestedPath?: string;
  readonly resolvedPath?: string;
}

/** One installed publication generation of the approval chain. */
export interface PermissionPublication {
  readonly generation: number;
  readonly nodes: readonly NodeBinding[];
  readonly mode: PermissionMode;
  readonly rulesRevision: number;
  readonly intentRevision: number;
  readonly learningEnabled: boolean;
  commit?(): boolean;
  dispose(): void | Promise<void>;
}

/** Per-session seam the publication factory assembles the chain against. */
export interface PublicationSession {
  readonly sessionId: string;
  readonly context: ReviewerContextStore;
  readonly learning?: ReviewerLearningLifecycle;
  readonly resolveSession: LlmApproverNodeDependencies["resolveSession"];
  readonly verifyFacts: LlmApproverNodeDependencies["verifyFacts"];
}

export interface PublicationFactoryInput {
  readonly generation: number;
  readonly previous: PermissionPublication | undefined;
  readonly ctx: ExtensionContext;
  readonly session: PublicationSession;
  readonly configuration?: unknown;
}

export interface PreparedPublicationConfiguration {
  readonly configuration: unknown;
  commit(): boolean;
}

export interface PublicationFactoryPort {
  publish(input: PublicationFactoryInput): Promise<PermissionPublication>;
  prepareReload?(
    ctx: ExtensionContext,
    sessionId: string,
  ): PreparedPublicationConfiguration | undefined | Promise<PreparedPublicationConfiguration | undefined>;
  didReload?(ctx: ExtensionContext, sessionId: string): void;
}

/** Per-step structure analysis (units) and the shared Bash program provider. */
export interface AnalysisPort {
  analyze(
    capture: StepCapture,
    input: { readonly cwd: string; readonly generation: number; readonly signal?: AbortSignal },
  ): Promise<readonly UnitPreparation[]>;
  bashPrograms?(
    capture: StepCapture,
    input: { readonly cwd: string; readonly generation: number; readonly signal?: AbortSignal },
  ): BashProgramProvider | undefined;
  powershellPrograms?(
    capture: StepCapture,
    input: { readonly cwd: string; readonly generation: number; readonly signal?: AbortSignal },
  ): PowerShellProgramProvider | undefined;
}

/** Sandbox channel: approval review inside the controlled-execution guard. */
export interface SandboxPort {
  guard(
    event: ToolCallEvent,
    ctx: ExtensionContext,
    review: (input?: SandboxReviewInput) => Promise<ReviewAnswer>,
  ): Promise<ReviewAnswer>;
  selectFileTargets?(calls: StepCapture["directCalls"], ctx: ExtensionContext): Readonly<Record<string, HumanPromptTarget>>;
  invalidate?(sessionId: string): void;
  configurationChanged?(sessionId: string): void;
  /**
   * True when `currentInput` differs from the model's recorded
   * `originalInput` only by a rewrite the host itself performed (the
   * temporary-path mapping); such a disagreement is not tampering.
   */
  sanctionedArgumentRewrite?(
    toolName: string,
    originalInput: unknown,
    currentInput: unknown,
    ctx: ExtensionContext,
  ): boolean;
}

export interface MemoryPort {
  create(input: { readonly host: ReviewerHostSessionLike; readonly now: () => number }): ReviewerSessionMemory;
}

export interface ContextStorePort {
  create(now: () => number): ReviewerContextStore;
}

export interface LearningPort {
  create(input: {
    readonly sessionId: string;
    readonly now: () => number;
  }): {
    /** The accept-side lifecycle the model nodes consume. */
    readonly model?: ReviewerLearningLifecycle;
    /** The finalize/discard-side lifecycle the step runner consumes. */
    readonly stepRunner?: StepRunnerLearningPort;
    dispose(): void;
  };
}

/** The subset of the Pi session a reviewer memory reads. */
export interface ReviewerHostSessionLike {
  getSessionId(): string;
  getLeafId(): string | null;
  getEntry(id: string): SessionEntry | undefined;
  getBranch(fromId?: string): SessionEntry[];
  getEntries(): SessionEntry[];
  buildSessionProjection?(): SessionProjection;
}

/** The injected frozen-capture constructor (`captureStep` in the wiring phase). */
export type CaptureStepPort = (input: StepCaptureInput) => CaptureStepResult;

/** The injected chain runner (`runStepChain` in the wiring phase). */
export type RunChainPort = (input: RunStepChainInput) => Promise<RunStepChainResult>;

export type AuditEvent =
  | { readonly kind: "publication"; readonly sessionId: string; readonly generation: number; readonly mode: PermissionMode }
  | { readonly kind: "invalidate"; readonly sessionId: string; readonly reason: string }
  | {
      readonly kind: "step";
      readonly sessionId: string;
      readonly requestId: string;
      readonly stepKey: string;
      readonly captureDigest: string;
      readonly generation: number;
      readonly toolCallId: string;
      readonly toolName: string;
      readonly decision: StepOutcome["decision"];
      readonly reason?: string;
    }
  | {
      readonly kind: "execution";
      readonly sessionId: string;
      readonly phase: "start" | "end";
      readonly toolCallId: string;
      readonly toolName: string;
      readonly parentToolCallId?: string;
      readonly isError?: boolean;
    }
  | {
      readonly kind: "mode-reminder";
      readonly sessionId: string;
      readonly revision: number;
      readonly mode: PermissionMode;
      readonly sent: boolean;
    }
  | {
      readonly kind: "human";
      readonly sessionId: string;
      readonly toolCallId: string;
      readonly askFor: "allow" | "escalate";
      readonly decision: "approve" | "deny" | "cancel";
      readonly escalation: boolean;
    }
  | {
      /** An `ask` decision reused from the session memory (design §5.6). */
      readonly kind: "session-decision";
      readonly sessionId: string;
      readonly toolCallId: string;
      readonly toolName: string;
      readonly decision: "allow" | "deny";
      /** Request id of the human prompt that recorded the decision. */
      readonly requestId: string;
    }
  | {
      readonly kind: "chain-node";
      readonly sessionId: string;
      readonly generation: number;
      readonly stepKey: string;
      readonly nodeId: string;
      readonly outcome: "applied" | "noop" | "fault" | "timeout" | "cancelled";
      readonly reason?: string;
    }
  | {
      readonly kind: "unit-change";
      readonly sessionId: string;
      readonly generation: number;
      readonly stepKey: string;
      readonly changes: readonly {
        readonly toolCallId: string;
        readonly unitId: string;
        readonly nodeId: string;
        readonly decision: "allow" | "ask" | "deny" | "escalate";
        readonly reason: string;
      }[];
    }
  | { readonly kind: "error"; readonly sessionId: string; readonly area: string; readonly detail: string };

export interface AuditSinkPort {
  write(event: AuditEvent): void;
}

export interface HumanSelectionPort {
  select(request: HumanRequest, ctx: ExtensionContext): Promise<HumanResponse | undefined>;
}

export interface SessionPathApproval {
  readonly surface: "path_read" | "path_write";
  readonly scope: string;
  remember(decision: "allow" | "deny"): void;
}

export interface SessionPathApprovalRequest {
  readonly sessionId: string;
  readonly toolName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly selectedFilePath?: string;
  readonly cwd: string;
}

export interface PermissionExtensionOptions {
  readonly publications: PublicationFactoryPort;
  readonly analysis: AnalysisPort;
  readonly captureStep: CaptureStepPort;
  readonly runChain: RunChainPort;
  readonly audit?: AuditSinkPort;
  readonly clock?: () => number;
  readonly memory?: MemoryPort;
  readonly contextStore?: ContextStorePort;
  readonly learning?: LearningPort;
  readonly sandbox?: SandboxPort;
  readonly bypassToolName?: string;
  /** Complete human adapter override; wins over the selector. */
  readonly human?: HumanApprover;
  /** Interactive selector seam; `undefined` means "no selection" (cancel). */
  readonly selectHuman?: HumanSelectionPort["select"];
  /** Describes and records a directory-scoped human choice for a file tool. */
  readonly sessionPathApproval?: (
    request: SessionPathApprovalRequest,
  ) => SessionPathApproval | undefined;
  /** Default local prompt timeout for the built-in human selector. */
  readonly promptTimeoutMs?: number;
}

export interface HostSessionState {
  readonly sessionId: string;
  readonly generation: number;
  readonly publication: "ready" | "unavailable";
  readonly activeSteps: number;
  readonly pendingCalls: number;
  readonly settledCalls: number;
  readonly mode: PermissionMode | undefined;
}

export interface HostState {
  readonly sessions: readonly HostSessionState[];
}

export interface PermissionExtension {
  install(api: ExtensionAPI): void;
  reload(ctx: ExtensionContext): Promise<boolean>;
  setSessionMode(sessionId: string, mode: PermissionMode | null): void;
  reviewSandboxBypass(
    input: SandboxBypassReviewInput,
    ctx: ExtensionToolContext,
  ): Promise<SandboxBypassReviewAnswer>;
  state(): HostState;
  dispose(): Promise<void>;
}

/** The type `src/sandbox/bypass.ts` imports from `#approve-core/host`. */
export interface SandboxBypassReviewInput {
  readonly toolCallId: string;
  readonly targetToolName: string;
  readonly arguments: unknown;
  readonly reason: string;
  readonly elevation: import("../../elevation").ToolElevation;
}

/**
 * The bypass-channel answer: `undefined` approves the elevation (the bypass
 * tool then executes the target at the requested tier), and a block refuses it.
 */
export type SandboxBypassReviewAnswer =
  | { readonly block: true; readonly reason: string }
  | undefined;

// ---------------------------------------------------------------------------
// Constants and small helpers
// ---------------------------------------------------------------------------

const DEFAULT_OWNER = "default";
const DEFAULT_PROMPT_TIMEOUT_MS = 5 * 60_000;
const MAX_AUDIT_REASON = 2_000;

const CANCEL_OPTION = "Cancel - do not approve";
const APPROVE_OPTION = "Approve this call once";
const DENY_OPTION = "Deny this call";

function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function serializeArguments(value: unknown): string {
  try {
    const text = JSON.stringify(value);
    if (typeof text !== "string") return "{}";
    return text.length <= 400 ? text : `${text.slice(0, 397)}...`;
  } catch {
    return "{}";
  }
}

function summarizeReasons(summary: CallSummary, fallback: string): string {
  const reasons = [...new Set(summary.reasons
    .map((reason) => reason.reason)
    .filter((reason) => typeof reason === "string" && reason.length > 0))];
  return reasons.length === 0 ? fallback : reasons.join("; ");
}

function toolResultText(result: unknown): { readonly text: string; readonly isError: boolean } {
  const record = typeof result === "object" && result !== null ? result as Record<string, unknown> : {};
  const content = record.content;
  let text = "";
  if (typeof content === "string") {
    text = content;
  } else if (Array.isArray(content)) {
    text = content
      .map((part) => (typeof part === "object" && part !== null && (part as { type?: unknown }).type === "text"
        ? String((part as { text?: unknown }).text ?? "")
        : ""))
      .filter((part) => part.length > 0)
      .join("\n");
  }
  if (text === "") {
    try {
      text = JSON.stringify(record.isError === true ? { isError: true } : summaryOfObject(record));
    } catch {
      text = "";
    }
  }
  return { text: text.slice(0, 4_096), isError: record.isError === true };
}

function summaryOfObject(record: Record<string, unknown>): unknown {
  const keys = Object.keys(record).slice(0, 16);
  return Object.fromEntries(keys.map((key) => [key, typeof record[key] === "string" ? record[key] : "…"]));
}

function installHost(ctx: ExtensionContext): ReviewerHostSessionLike {
  const manager = ctx.sessionManager;
  return {
    getSessionId: () => manager.getSessionId(),
    getLeafId: () => manager.getLeafId(),
    getEntry: (id) => manager.getEntry(id),
    getBranch: (fromId) => manager.getBranch(fromId),
    getEntries: () => manager.getEntries(),
    buildSessionProjection: () => manager.buildSessionProjection(),
  };
}

function defaultMemoryPort(): MemoryPort {
  return { create: ({ host, now }) => createReviewerSessionMemory({ host, now }) };
}

function defaultContextStorePort(): ContextStorePort {
  return { create: (now) => createReviewerContextStore({ now }) };
}

// ---------------------------------------------------------------------------
// Human request facts (§9)
// ---------------------------------------------------------------------------

interface HumanPromptTarget {
  readonly requestedPath: string;
  readonly resolvedPath: string;
}

type HumanPromptRequest = HumanRequest & { readonly selectedFileTarget?: HumanPromptTarget };
export interface HumanPromptFacts {
  readonly escalation: boolean;
  readonly askFor: "allow" | "escalate";
  readonly toolName: string;
  readonly toolCallId: string;
  readonly reason: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly targetPaths: readonly string[];
  readonly title: string;
  readonly options: readonly string[];
  readonly approveOption: string;
  readonly denyOption: string;
  readonly cancelOption: string;
}

/**
 * Facts the default human selector renders. An escalation request names the
 * reason, the tool and the final arguments in its title; a normal request never
 * claims to be an escalation.
 */
export function humanPromptFacts(request: HumanPromptRequest): HumanPromptFacts {
  const toolName = nonEmpty(request.call.toolName) ?? "tool";
  const askFor = request.summary.askFor === "escalate" ? "escalate" : "allow";
  const escalation = askFor === "escalate";
  const tier = request.call.hostExecutionRequest?.elevation.tier;
  const reason = summarizeReasons(request.summary, escalation
    ? tier === undefined ? "ordinary approvals cannot grant Host execution" : `one-time ${tier} elevation was requested`
    : "no reason was recorded");
  const args = serializeArguments(request.call.arguments);
  const targetPaths = request.selectedFileTarget === undefined
    ? []
    : formatHumanTargetPaths(request.selectedFileTarget, approvalText[resolveApprovalLanguage()]);
  const title = tier === "host"
    ? `Host execution request for ${toolName} (outside the OS sandbox). Reason: ${reason}. Final arguments: ${args}`
    : tier === "default"
      ? `Default sandbox elevation request for ${toolName}. Reason: ${reason}. Final arguments: ${args}`
      : escalation
        ? `Ordinary ${toolName} call cannot receive Host execution. Reason: ${reason}. Arguments: ${args}`
        : `Approve ${toolName} call? Reason: ${reason}. Arguments: ${args}`;
  return {
    escalation,
    askFor,
    toolName,
    toolCallId: request.call.toolCallId,
    reason,
    arguments: request.call.arguments,
    targetPaths,
    title,
    options: [CANCEL_OPTION, APPROVE_OPTION, DENY_OPTION],
    approveOption: APPROVE_OPTION,
    denyOption: DENY_OPTION,
    cancelOption: CANCEL_OPTION,
  };
}

function formatHumanTargetPaths(target: HumanPromptTarget, text: ApprovalText): readonly string[] {
  if (target.requestedPath === target.resolvedPath) return [`${text.path}  ${target.requestedPath}`];
  return [
    `${text.requestedPath}  ${target.requestedPath}`,
    `${text.resolvedPath}  ${target.resolvedPath}`,
  ];
}
function formatHumanArguments(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? "[unserializable arguments]";
  } catch {
    return "[unserializable arguments]";
  }
}

function conciseArgs(value: unknown): string[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return [String(value)];
  }
  const record = value as Record<string, unknown>;
  const lines: string[] = [];
  for (const [key, val] of Object.entries(record)) {
    if (typeof val === "string") {
      const parts = val.replace(/\r\n/g, "\n").split("\n");
      if (parts.length === 1) lines.push(`${key}: ${val}`);
      else lines.push(`${key}:`, ...parts.map((part) => `  ${part}`));
    } else if (typeof val === "number" || typeof val === "boolean") {
      lines.push(`${key}: ${val}`);
    } else if (val === null || val === undefined) {
      lines.push(`${key}: (none)`);
    } else {
      try {
        lines.push(`${key}: ${JSON.stringify(val)}`);
      } catch {
        lines.push(`${key}: [unserializable]`);
      }
    }
  }
  return lines.length > 0 ? lines : [formatHumanArguments(value)];
}

function plainPreviewLines(value: unknown): DiffLine[] {
  return conciseArgs(value).map((text) => ({ kind: "plain" as const, text }));
}

function highlightedFileLines(content: string, filePath: string, text: ApprovalText): DiffLine[] {
  if (content === "") return [{ kind: "plain", text: text.emptyFile }];
  const normalized = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = fallbackPreview(normalized);
  const highlighted = highlightCode(normalized, getLanguageFromPath(filePath));
  return lines.map((line, index) => ({
    kind: "syntax" as const,
    lineNumber: line.lineNumber,
    text: highlighted[index] ?? line.text,
  }));
}

function buildApprovalPreview(request: HumanRequest, cwd: string, text: ApprovalText): DiffLine[] {
  const toolName = request.call.toolName;
  const args = request.call.arguments as Record<string, unknown> | undefined;
  if (toolName === "write" && args !== undefined) {
    const path = typeof args.path === "string" ? args.path : "";
    const content = typeof args.content === "string" ? args.content : "";
    return highlightedFileLines(content, isAbsolute(path) ? path : resolve(cwd, path), text);
  }
  if (toolName === "edit" && args !== undefined) {
    const edits = Array.isArray(args.edits) ? (args.edits as unknown[]) : undefined;
    if (edits !== undefined && edits.length > 0) {
      const lines: DiffLine[] = [];
      for (const entry of edits) {
        if (typeof entry !== "object" || entry === null) continue;
        const record = entry as Record<string, unknown>;
        const oldText = typeof record.oldText === "string" ? record.oldText : "";
        const newText = typeof record.newText === "string" ? record.newText : "";
        lines.push(...buildEditDiff(oldText, newText));
      }
      if (lines.length > 0) return lines;
    }
    const oldText = typeof args.oldText === "string" ? args.oldText : "";
    const newText = typeof args.newText === "string" ? args.newText : "";
    if (oldText !== "" || newText !== "") return buildEditDiff(oldText, newText);
  }
  // read / powershell / bash / others: show concise name + args, no JSON, no diff color.
  return plainPreviewLines(request.call.arguments);
}

function humanEscalationReason(request: HumanRequest, text: ApprovalText): string {
  const requestedReason = request.call.hostExecutionRequest?.reason.trim();
  if (requestedReason) return requestedReason;
  const reasons = request.summary.reasons.map((entry) => entry.reason);
  if (reasons.some(reason => reason.includes("external-delete-needs-approval"))) {
    return text === approvalText.zh ? "删除目标位于当前工作目录之外" : "The deletion target is outside the working directory";
  }
  if (reasons.some((reason) => reason.includes("external-write-needs-approval"))) {
    return text === approvalText.zh ? "写入目标位于当前工作目录之外" : "The write target is outside the working directory";
  }
  return reasons.find((reason) => reason.trim().length > 0)?.trim() ?? "";
}

function renderHumanTitle(request: HumanPromptRequest, cwd: string, highlight: (value: string) => string, text: ApprovalText): string {
  const escalation = request.call.hostExecutionRequest !== undefined ||
    (request.summary.askFor === "escalate" && request.summary.reasons.some(entry =>
      /external-(?:write|delete)-needs-approval|one-time-host-execution/.test(entry.reason)));
  const reason = escalation ? humanEscalationReason(request, text) : "";
  const args = request.call.arguments as Record<string, unknown> | undefined;
  const path = args !== undefined && typeof args.path === "string" ? args.path : "";
  const fileTool = request.call.toolName === "write" || request.call.toolName === "edit";
  const absolutePath = request.selectedFileTarget?.resolvedPath ?? (path === "" ? "" : isAbsolute(path) ? path : resolve(cwd, path));
  const targetPaths = request.selectedFileTarget === undefined
    ? []
    : formatHumanTargetPaths(request.selectedFileTarget, text);
  const elevation = request.call.hostExecutionRequest?.elevation;
  const tier = elevation?.tier;
  const scope = elevation?.scope.map(entry => `${text === approvalText.zh ? entry.access === "write" ? "写入" : "读取" : entry.access} ${entry.path}`).join(`\n${text.scope}  `);
  const requestTitle = text.request(request.call.toolName, tier === undefined ? undefined : highlight(text.elevation(tier)));
  const hostBoundary = tier === "host" ? text.hostBoundary : "";
  const ordinaryHostNotice = escalation && elevation === undefined ? text.ordinaryHostUnavailable : "";
  let operation = "";
  if (request.call.toolName === "write") {
    operation = absolutePath !== "" && existsSync(absolutePath) ? text.overwriteFile : text.createFile;
  } else if (request.call.toolName === "edit") {
    operation = text.editFile;
  }
  return [
    requestTitle,
    hostBoundary,
    ordinaryHostNotice,
    fileTool ? `${text.operation}  ${operation} · ${path === "" ? "" : basename(path)}` : "",
    ...targetPaths,
    scope !== undefined
      ? `${text.scope}  ${scope}`
      : targetPaths.length === 0 && path !== ""
        ? `${text.path}  ${absolutePath}`
        : "",
    reason.length > 0 ? `${text.reason}  ${reason}` : "",
  ].filter((part) => part.length > 0).join("\n");
}

function approvalPreviewTitle(request: HumanRequest, text: ApprovalText): string {
  if (request.call.toolName === "write") return text.fileContent;
  if (request.call.toolName === "edit") return text.edits;
  return text.arguments;
}

class ApprovalPreviewRule extends Container {
  constructor(private readonly theme: Theme) {
    super();
  }

  override render(width: number): string[] {
    return [this.theme.fg("muted", "┄".repeat(Math.max(1, width)))];
  }
}

class HumanApprovalSelectorComponent extends Container {
  private selectedIndex = -1;
  private readonly listContainer = new Container();

  constructor(
    titleLines: readonly string[],
    previewLines: readonly DiffLine[],
    previewTitle: string,
    private readonly options: readonly string[],
    private readonly theme: Theme,
    private readonly keybindings: KeybindingsManager,
    private readonly onSelect: (option: string) => void,
    private readonly onCancel: () => void,
    argumentLines: readonly DiffLine[] = [],
    text: ApprovalText = approvalText.en,
  ) {
    super();
    this.addChild(new DynamicBorder());
    this.addChild(new Spacer(1));
    const [heading, ...details] = titleLines;
    if (heading !== undefined) this.addChild(new Text(this.theme.fg("accent", this.theme.bold(heading)), 0, 0));
    if (details.length > 0) this.addChild(new Spacer(1));
    for (const line of details) {
      const split = line.indexOf("  ");
      const value = split < 0 ? this.theme.fg("warning", line)
        : this.theme.fg("muted", line.slice(0, split) + "  ") + this.theme.fg("text", line.slice(split + 2));
      this.addChild(new Text(value, 0, 0));
    }
    if (argumentLines.length > 0) this.addPreview(argumentLines, text.arguments);
    this.addPreview(previewLines, previewTitle);
    this.addChild(new Spacer(1));
    this.addChild(new ApprovalPreviewRule(this.theme));
    this.addChild(new Spacer(1));
    this.addChild(this.listContainer);
    this.updateList();
    this.addChild(new Spacer(1));
    this.addChild(new Text(this.theme.fg("muted", text.help), 0, 0));
    this.addChild(new Spacer(1));
    this.addChild(new DynamicBorder());
  }

  private addPreview(lines: readonly DiffLine[], title: string): void {
    this.addChild(new Spacer(1));
    const box = new Box(1, 1, value => this.parameterBackground(value));
    box.addChild(new Text(this.theme.fg("muted", title), 0, 0));
    box.addChild(new Spacer(1));
    for (const line of lines) {
      const prefix = line.lineNumber === undefined ? "" : String(line.lineNumber).padStart(4, " ") + " │ ";
      const color = line.kind === "add" ? "success" : line.kind === "remove" ? "error" : "text";
      box.addChild(new Text(this.theme.fg("muted", prefix) + this.theme.fg(color, line.text), 0, 0));
    }
    this.addChild(box);
  }

  private parameterBackground(text: string): string {
    const light = this.theme.appearance === "light";
    const color = this.theme.getColorMode?.() === "truecolor"
      ? light ? "\u001b[48;2;233;234;236m" : "\u001b[48;2;37;39;43m"
      : light ? "\u001b[48;5;254m" : "\u001b[48;5;236m";
    return color + text.replace(/\u001b\[(0|49)m/g, (match, code) => code === "0" ? match + color : color) + "\u001b[49m";
  }

  private updateList(): void {
    this.listContainer.clear();
    for (let i = 0; i < this.options.length; i++) {
      const active = i === this.selectedIndex;
      const label = this.options[i]!;
      const line = this.theme.fg(active ? "accent" : "text", active ? this.theme.bold(label) : label);
      this.listContainer.addChild(new Text(line, 0, 0, active ? value => this.parameterBackground(value) : undefined));
    }
  }

  handleInput(data: string): void {
    if (this.keybindings.matches(data, "tui.select.up") || data === "k") {
      this.selectedIndex = this.selectedIndex <= 0 ? this.options.length - 1 : this.selectedIndex - 1;
      this.updateList();
    } else if (this.keybindings.matches(data, "tui.select.down") || data === "j") {
      this.selectedIndex = (this.selectedIndex + 1) % this.options.length;
      this.updateList();
    } else if ((this.keybindings.matches(data, "tui.select.confirm") || data === "\n") && this.selectedIndex >= 0) {
      this.onSelect(this.options[this.selectedIndex]!);
    } else if (this.keybindings.matches(data, "tui.select.cancel")) {
      this.onCancel();
    }
  }
}
/**
 * Host-side node order (§6.7): builtin front nodes first, then the published
 * custom nodes in priority order (declaration order breaks ties), then the
 * model/post nodes. Positions and priorities come from the publication factory;
 * this function only fixes the deterministic order the chain runs in.
 */
export function orderPublishedNodes(nodes: readonly NodeBinding[]): readonly NodeBinding[] {
  const front: NodeBinding[] = [];
  const user: { readonly binding: NodeBinding; readonly index: number }[] = [];
  const post: NodeBinding[] = [];
  nodes.forEach((binding, index) => {
    if (binding.position === "front") front.push(binding);
    else if (binding.position === "user") user.push({ binding, index });
    else post.push(binding);
  });
  user.sort((left, right) => {
    const byPriority = (left.binding.priority ?? 0) - (right.binding.priority ?? 0);
    return byPriority === 0 ? left.index - right.index : byPriority;
  });
  return Object.freeze([...front, ...user.map((entry) => entry.binding),
    ...post.filter(binding => binding.node.id !== "builtin/human"),
    ...post.filter(binding => binding.node.id === "builtin/human")]);
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

interface PreparedStep {
  readonly stepKey: string;
  readonly captureDigest: string;
  readonly capture: StepCapture;
  readonly generation: number;
  readonly publication: PermissionPublication;
  readonly handle: StepHandle;
  readonly calls: readonly string[];
}

type PreparationResult =
  | { readonly kind: "prepared"; readonly value: PreparedStep }
  | { readonly kind: "settled" }
  | { readonly kind: "failed"; readonly reason: string };

interface PreparingStep {
  readonly stepKey: string;
  readonly captureDigest: string;
  readonly capture: StepCapture;
  readonly generation: number;
  readonly invalidationRevision: number;
  readonly owner: string;
  readonly mode: PermissionMode;
  readonly publication: PermissionPublication;
  readonly captured: Extract<ReviewCaptureResult, { readonly ok: true }>;
  readonly selectedFileTargets?: Readonly<Record<string, HumanPromptTarget>>;
  /** The session memory link, present only on the approval path. */
  readonly sessionReviews?: SessionReviewPort;
  readonly controller: AbortController;
  readonly promise: Promise<PreparationResult>;
  cancel(reason: string): void;
}

interface PinnedPublication {
  readonly publication: PermissionPublication;
  readonly generation: number;
  readonly owner: string;
  readonly mode: PermissionMode;
  readonly sessionFacts: ReviewerSessionFacts;
}

interface HostSession {
  readonly id: string;
  readonly memory: ReviewerSessionMemory;
  /** Session-scoped `ask` decisions an explicit human choice recorded (§5.6). */
  readonly askDecisions: AskSessionMemory;
  /** Command families an explicit "Allow for this session" remembered. */
  readonly commandGrants: SessionCommandGrants;
  readonly context: ReviewerContextStore;
  readonly learning: {
    readonly model?: ReviewerLearningLifecycle;
    readonly stepRunner?: StepRunnerLearningPort;
    dispose(): void;
  };
  readonly runner: StepRunner;
  readonly reminder: ModeReminder;
  publication: PermissionPublication | undefined;
  modeOverride: PermissionMode | undefined;
  generation: number;
  invalidationRevision: number;
  currentRefs: number;
  reload: Promise<unknown>;
  readonly retired: Map<number, { publication: PermissionPublication; refs: number }>;
  readonly prepared: Map<string, PreparedStep>;
  readonly preparing: Map<string, PreparingStep>;
  readonly preparedByCall: Map<string, PreparedStep>;
  readonly reviewPaths: Map<string, HumanPromptTarget>;
  readonly handledToolCallIds: Set<string>;
  readonly pinned: Map<string, PinnedPublication>;
  ctx: ExtensionContext | undefined;
  disposed: boolean;
}

function isToolCallResult(value: unknown): value is ToolCallEventResult {
  return typeof value === "object" && value !== null;
}

function effectiveMode(session: HostSession): PermissionMode | undefined {
  return session.modeOverride ?? session.publication?.mode;
}

/** Shell tools whose approved command families can be remembered. */
const SHELL_SESSION_TOOLS: ReadonlySet<string> = new Set(["bash", "shell"]);

/**
 * Parse one shell command into units for the session family memory. A command
 * the parser did not fully understand, or that produced no units, yields
 * `undefined` so the family memory never guesses.
 */
async function sessionCommandUnits(
  command: string,
  cwd: string,
): Promise<readonly BashCommand[] | undefined> {
  try {
    const program = await BashProgram.parse(
      command,
      new PathNormalizer(pathFlavorForPlatform(process.platform), cwd),
    );
    if (!program.parsed || program.parseUnresolved) return undefined;
    const units = program.commands();
    if (units.length === 0) return undefined;
    if (units.some((unit) => unit.parseUnresolved === true || unit.salvaged === true)) return undefined;
    return units;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export function createPermissionExtension(options: PermissionExtensionOptions): PermissionExtension {
  const text = approvalText[resolveApprovalLanguage()];
  const now = options.clock ?? Date.now;
  const promptTimeoutMs = options.promptTimeoutMs ?? DEFAULT_PROMPT_TIMEOUT_MS;
  const memoryPort = options.memory ?? defaultMemoryPort();
  const contextPort = options.contextStore ?? defaultContextStorePort();
  const stepFacts = createStepFacts({ capture: options.captureStep });
  const auditSink = options.audit;
  const sessions = new Map<string, HostSession>();
  const auditNotified = new Set<string>();
  let pi: ExtensionAPI | undefined;
  let disposed = false;

  function audit(event: AuditEvent): void {
    if (auditSink === undefined) return;
    try {
      auditSink.write(event);
    } catch {
      // A failed audit write is reported at most once per session and must
      // never change an approval result.
      if (auditNotified.has(event.sessionId)) return;
      auditNotified.add(event.sessionId);
      const session = sessions.get(event.sessionId);
      try {
        session?.ctx?.ui?.notify(
          formatPiSandboxError("permission: the audit log could not be written; approval results are unaffected"),
          "warning",
        );
      } catch {
        // Notifying is best effort too.
      }
    }
  }

  function auditError(sessionId: string, area: string, error: unknown): void {
    const detail = error instanceof Error ? error.message : String(error);
    audit({ kind: "error", sessionId, area, detail: detail.slice(0, MAX_AUDIT_REASON) });
  }

  function sendMessage(
    message: { readonly customType: string; readonly content: string; readonly display: boolean },
    opts?: { readonly triggerTurn?: boolean; readonly deliverAs?: "steer" | "followUp" | "nextTurn" },
  ): void {
    try {
      pi?.sendMessage(message, opts);
    } catch {
      // A reminder is informational; its failure never changes a decision.
    }
  }

  function appendEntry(customType: string, data?: unknown): void {
    try {
      pi?.appendEntry(customType, data);
    } catch {
      // Persisted reminder state is best effort.
    }
  }

  function currentBranch(session: HostSession): readonly SessionEntry[] {
    try {
      return session.ctx?.sessionManager.getBranch() ?? [];
    } catch {
      return [];
    }
  }

  function createSession(ctx: ExtensionContext): HostSession {
    const id = ctx.sessionManager.getSessionId();
    const memory = memoryPort.create({ host: installHost(ctx), now });
    const context = contextPort.create(now);
    const learning = options.learning?.create({ sessionId: id, now }) ?? { dispose: () => undefined };
    const session: HostSession = {
      id,
      memory,
      askDecisions: createAskSessionMemory(),
      commandGrants: createSessionCommandGrants(),
      context,
      learning,
      runner: createStepRunner({
        currentGeneration: () => session.publication?.generation,
        runChain: options.runChain,
        now,
        ...(learning.stepRunner === undefined ? {} : { learning: learning.stepRunner }),
        onAudit: (event) => {
          if (event.kind === "node") {
            audit({
              kind: "chain-node",
              sessionId: session.id,
              generation: event.generation,
              stepKey: event.stepKey,
              nodeId: event.entry.nodeId,
              outcome: event.entry.outcome,
              ...(event.entry.reason === undefined ? {} : { reason: event.entry.reason }),
            });
          } else if (event.kind === "unit-change") {
            audit({
              kind: "unit-change",
              sessionId: session.id,
              generation: event.generation,
              stepKey: event.stepKey,
              changes: event.changes.map((change) => ({
                toolCallId: change.toolCallId,
                unitId: change.unitId,
                nodeId: change.nodeId,
                decision: change.decision,
                reason: change.reason,
              })),
            });
          }
        },
      }),
      reminder: createModeReminder({
        api: {
          sendMessage,
          appendEntry,
          getBranch: () => currentBranch(session),
        },
        now,
      }),
      publication: undefined,
      modeOverride: undefined,
      generation: 0,
      invalidationRevision: 0,
      currentRefs: 0,
      reload: Promise.resolve(),
      retired: new Map(),
      prepared: new Map(),
      preparing: new Map(),
      preparedByCall: new Map(),
      reviewPaths: new Map(),
      handledToolCallIds: new Set(),
      pinned: new Map(),
      ctx,
      disposed: false,
    };
    session.reminder.restore(currentBranch(session));
    return session;
  }

  function ensureSession(ctx: ExtensionContext): HostSession | undefined {
    if (disposed) return undefined;
    const id = ctx.sessionManager.getSessionId();
    const existing = sessions.get(id);
    if (existing !== undefined) {
      existing.ctx = ctx;
      return existing.disposed ? undefined : existing;
    }
    const created = createSession(ctx);
    sessions.set(id, created);
    return created;
  }

  function sessionUnavailableReason(ctx: ExtensionContext): string {
    if (disposed) return "permission:session-unavailable:extension-disposed";
    const session = sessions.get(ctx.sessionManager.getSessionId());
    if (session?.disposed) return "permission:session-unavailable:session-disposed";
    return "permission:session-unavailable:unknown";
  }

  // -------------------------------------------------------------------------
  // Publication lifecycle (§5)
  // -------------------------------------------------------------------------

  function disposePublication(session: HostSession, publication: PermissionPublication, area: string): void {
    try {
      const result = publication.dispose();
      if (result instanceof Promise) void result.catch((error) => auditError(session.id, area, error));
    } catch (error) {
      auditError(session.id, area, error);
    }
  }

  function retire(session: HostSession, publication: PermissionPublication): void {
    // Move the live references of the old current publication into the retired
    // table: the new publication starts with no references, so a later retire
    // can never inherit them and leak the old generation.
    const refs = session.currentRefs;
    session.currentRefs = 0;
    if (refs === 0) {
      disposePublication(session, publication, "publication-retire");
      return;
    }
    session.retired.set(publication.generation, { publication, refs });
  }

  function acquirePublication(session: HostSession, publication: PermissionPublication): boolean {
    if (session.disposed) return false;
    if (session.publication === publication) {
      session.currentRefs += 1;
      return true;
    }
    const entry = session.retired.get(publication.generation);
    if (entry === undefined) return false;
    session.retired.set(publication.generation, { publication, refs: entry.refs + 1 });
    return true;
  }

  function releasePublication(session: HostSession, publication: PermissionPublication): void {
    if (session.publication === publication) {
      session.currentRefs = Math.max(0, session.currentRefs - 1);
      return;
    }
    const entry = session.retired.get(publication.generation);
    if (entry === undefined) return;
    const refs = entry.refs - 1;
    if (refs > 0) {
      session.retired.set(publication.generation, { publication, refs });
      return;
    }
    session.retired.delete(publication.generation);
    disposePublication(session, publication, "publication-release");
  }

  function ensurePublication(
    ctx: ExtensionContext,
    session: HostSession,
    force: boolean,
  ): Promise<PermissionPublication | undefined> {
    const task = session.reload.then(async (): Promise<PermissionPublication | undefined> => {
      if (session.disposed) return session.publication;
      if (!force && session.publication !== undefined) return session.publication;
      const generation = session.generation + 1;
      const sessionPort: PublicationSession = {
        sessionId: session.id,
        context: session.context,
        ...(session.learning.model === undefined ? {} : { learning: session.learning.model }),
        resolveSession: (step: StepContext) => resolveSessionFor(session, step),
        verifyFacts: (input) => verifyFactsFor(session, input),
      };
      let prepared: PreparedPublicationConfiguration | undefined;
      if (force && options.publications.prepareReload !== undefined) {
        try {
          prepared = await options.publications.prepareReload(ctx, session.id);
        } catch (error) {
          auditError(session.id, "publication-prepare", error);
          return session.publication;
        }
        if (prepared === undefined) {
          auditError(session.id, "publication-prepare", "reload candidate is unavailable");
          return session.publication;
        }
      }
      let next: PermissionPublication;
      try {
        next = await options.publications.publish({
          generation,
          previous: session.publication,
          ctx,
          session: sessionPort,
          ...(prepared === undefined ? {} : { configuration: prepared.configuration }),
        });
      } catch (error) {
        auditError(session.id, "publication", error);
        return session.publication;
      }
      if (session.disposed) {
        disposePublication(session, next, "publication-shutdown");
        return session.publication;
      }
      if (!Number.isSafeInteger(next.generation) || next.generation !== generation) {
        auditError(session.id, "publication", "publication returned an unexpected generation");
        disposePublication(session, next, "publication-invalid");
        return session.publication;
      }
      if (prepared !== undefined && !prepared.commit()) {
        auditError(session.id, "publication-commit", "reload candidate was superseded");
        disposePublication(session, next, "publication-superseded");
        return session.publication;
      }
      if (next.commit !== undefined && !next.commit()) {
        auditError(session.id, "publication-commit", "publication candidate was superseded");
        disposePublication(session, next, "publication-superseded");
        return session.publication;
      }
      const previous = session.publication;
      const previousMode = effectiveMode(session);
      // Retire first: it moves the old live references aside and resets the
      // current count, so the new publication starts unreferenced.
      if (previous !== undefined) retire(session, previous);
      session.publication = next;
      session.generation = generation;
      const mode = effectiveMode(session) ?? next.mode;
      if (previousMode === undefined || previousMode !== mode) {
        const revision = session.reminder.noteModeChange(mode);
        audit({ kind: "mode-reminder", sessionId: session.id, revision, mode, sent: false });
      }
      audit({ kind: "publication", sessionId: session.id, generation, mode });
      if (force) {
        try {
          options.sandbox?.configurationChanged?.(session.id);
        } catch (error) {
          auditError(session.id, "sandbox-configuration", error);
        }
        try {
          options.publications.didReload?.(ctx, session.id);
        } catch (error) {
          auditError(session.id, "publication-notify", error);
        }
      }
      return next;
    });
    session.reload = task.then(() => undefined, () => undefined);
    return task;
  }

  // -------------------------------------------------------------------------
  // Session facts for the reviewer nodes (§6.6, §7)
  // -------------------------------------------------------------------------

  function resolveOwner(session: HostSession): string {
    const ctx = session.ctx;
    if (ctx === undefined) return DEFAULT_OWNER;
    const name = getActiveAgentName(ctx);
    return nonEmpty(name) ?? DEFAULT_OWNER;
  }

  function resolveSessionFor(session: HostSession, step: StepContext): ReviewerSessionFacts | undefined {
    if (session.disposed) return undefined;
    const pin = session.pinned.get(step.state.stepKey);
    if (pin === undefined) return undefined;
    const owner = resolveOwner(session);
    if (owner !== pin.owner) return undefined;
    return session.memory.isCurrent(owner, pin.sessionFacts.view, pin.sessionFacts.revisions)
      ? pin.sessionFacts : undefined;
  }

  function verifyFactsFor(
    session: HostSession,
    input: Parameters<NonNullable<LlmApproverNodeDependencies["verifyFacts"]>>[0],
  ): boolean {
    if (session.disposed) return false;
    const owner = resolveOwner(session);
    if (input.owner !== owner) return false;
    const pins = [...session.pinned.values()].filter((pin) =>
      pin.mode === input.mode &&
      pin.publication.rulesRevision === input.revisions.projectRules &&
      pin.publication.intentRevision === input.revisions.intent &&
      pin.sessionFacts.view.captureSeq === input.view.captureSeq &&
      pin.sessionFacts.view.historyVersion === input.view.historyVersion &&
      session.memory.isCurrent(owner, pin.sessionFacts.view, input.revisions));
    if (pins.length === 0) return false;
    for (const call of input.calls) {
      if (call.call.digest !== call.actionDigest) return false;
      if (call.call.toolCallId !== call.toolCallId) return false;
    }
    return true;
  }

  // -------------------------------------------------------------------------
  // Human fallback (§9)
  // -------------------------------------------------------------------------

  function makeHuman(ctx: ExtensionContext, session: HostSession, selectedFileTargets?: Readonly<Record<string, HumanPromptTarget>>): HumanApprover {
    if (options.human !== undefined) return options.human;
    return async (request: HumanRequest): Promise<HumanResponse> => {
      const unavailable: HumanResponse = { decision: "cancel", reason: "permission:human-unavailable" };
      const selectedFileTarget = selectedFileTargets?.[request.call.toolCallId] ?? session.reviewPaths.get(request.call.toolCallId);
      const promptRequest: HumanPromptRequest = selectedFileTarget === undefined
        ? request
        : { ...request, selectedFileTarget };
      const facts = humanPromptFacts(promptRequest);
      const emit = (decision: HumanResponse["decision"]): void => {
        audit({
          kind: "human",
          sessionId: session.id,
          toolCallId: facts.toolCallId,
          askFor: facts.askFor,
          decision,
          escalation: facts.escalation,
        });
      };
      if (options.selectHuman !== undefined) {
        let response: HumanResponse | undefined;
        try {
          response = await options.selectHuman(promptRequest, ctx);
        } catch {
          response = undefined;
        }
        if (
          response === undefined ||
          (response.decision !== "approve" && response.decision !== "deny" && response.decision !== "cancel")
        ) {
          emit("cancel");
          return unavailable;
        }
        emit(response.decision);
        return response;
      }
      if (!ctx.hasUI) {
        emit("cancel");
        return unavailable;
      }
      if (request.signal.aborted) {
        emit("cancel");
        return { decision: "cancel", reason: "permission:human-cancelled" };
      }
      const escalation = request.summary?.askFor === "escalate"
        || request.call?.hostExecutionRequest !== undefined;
      const toolName = typeof request.call?.toolName === "string" ? request.call.toolName : "";
      const args = request.call?.arguments;
      let pathApproval: SessionPathApproval | undefined;
      if (args !== undefined && options.sessionPathApproval !== undefined) {
        try {
          pathApproval = options.sessionPathApproval({
            sessionId: session.id,
            toolName,
            arguments: args,
            ...(selectedFileTarget === undefined ? {} : { selectedFilePath: selectedFileTarget.resolvedPath }),
            cwd: ctx.cwd,
          });
        } catch {
          pathApproval = undefined;
        }
      }
      const sessionChoices = !escalation;
      const scopeSuffix = pathApproval === undefined ? "" : `: ${pathApproval.scope}`;
      const allowSessionChoice = `${text.allowSession}${scopeSuffix}`;
      const denySessionChoice = `${text.denySession}${scopeSuffix}`;
      const choices = sessionChoices
        ? [text.approveOnce, text.deny, allowSessionChoice, denySessionChoice]
        : [text.approveOnce, text.deny];
      const rememberSession = async (decision: "allow" | "deny"): Promise<void> => {
        if (toolName.length === 0) return;
        try {
          session.askDecisions.remember(toolName, request.call?.arguments, decision, createPermissionRequestId());
        } catch {
          // Remembering is advisory and never changes the decision itself.
        }
        try {
          pathApproval?.remember(decision);
        } catch {
          // A path-scope update never changes this call's human decision.
        }
        if (!SHELL_SESSION_TOOLS.has(toolName)) return;
        const command = request.call?.arguments?.command;
        if (typeof command !== "string" || command.trim().length === 0) return;
        const units = await sessionCommandUnits(command, ctx.cwd);
        if (units === undefined) return;
        try {
          if (decision === "allow") {
            const grants = suggestSessionCommandGrants(units);
            if (grants.length > 0) session.commandGrants.remember(grants);
          } else {
            // A session deny must also retire an earlier family allow.
            session.commandGrants.forget(units);
          }
        } catch {
          // Family memory is advisory and never changes the decision itself.
        }
      };
      let timeout: ReturnType<typeof setTimeout> | undefined;
      let cancelPrompt: (() => void) | undefined;
      let picked: string | undefined;
      try {
        picked = await ctx.ui.custom<string | undefined>((tui, theme, keybindings, done) => {
          tui.setClearOnShrink(true);
          let settled = false;
          const finish = (value?: string): void => {
            if (settled) return;
            settled = true;
            if (timeout !== undefined) clearTimeout(timeout);
            if (cancelPrompt !== undefined) request.signal.removeEventListener("abort", cancelPrompt);
            done(value);
          };
          cancelPrompt = () => finish(undefined);
          request.signal.addEventListener("abort", cancelPrompt, { once: true });
          timeout = setTimeout(() => finish(undefined), promptTimeoutMs);
          if (request.signal.aborted) finish(undefined);
          const title = renderHumanTitle(promptRequest, ctx.cwd, (value) =>
            theme.fg("warning", theme.bold(value)) + (theme.getFgAnsi?.("accent") ?? ""), text);
          const preview = buildApprovalPreview(request, ctx.cwd, text);
          return new HumanApprovalSelectorComponent(
            title.split("\n"),
            preview,
            approvalPreviewTitle(request, text),
            choices,
            theme,
            keybindings,
            (option) => finish(option),
            () => finish(undefined),
            request.call.toolName === "write" || approvalPreviewTitle(request, text) === text.arguments ? [] : plainPreviewLines(request.call.arguments),
            text,
          );
        });
      } catch {
        emit("cancel");
        return unavailable;
      } finally {
        if (timeout !== undefined) clearTimeout(timeout);
        if (cancelPrompt !== undefined) request.signal.removeEventListener("abort", cancelPrompt);
      }
      if (picked === text.approveOnce) {
        emit("approve");
        return { decision: "approve", reason: "permission:human-approved" };
      }
      if (picked === allowSessionChoice) {
        await rememberSession("allow");
        emit("approve");
        return { decision: "approve", reason: "permission:human-approved-session" };
      }
      if (picked === text.deny) {
        emit("deny");
        return { decision: "deny", reason: "permission:human-denied" };
      }
      if (picked === denySessionChoice) {
        await rememberSession("deny");
        emit("deny");
        return { decision: "deny", reason: "permission:human-denied-session" };
      }
      emit("cancel");
      return { decision: "cancel", reason: "permission:human-cancelled" };
    };
  }

  // -------------------------------------------------------------------------
  // Outcome mapping (§6 result mapping)
  // -------------------------------------------------------------------------

  function answerFor(outcome: StepOutcome, allowHostExecution: boolean, executionRequest?: ExecutionRequest): ReviewAnswer {
    if (outcome.decision === "allow") return undefined;
    if (outcome.decision === "blocked") return { block: true, reason: `permission:${outcome.reason}` };
    const reasons = [...new Set(outcome.result.reasons
      .map((reason) => reason.reason)
      .filter((reason) => typeof reason === "string" && reason.length > 0))];
    const reviewDenials = [...new Set(outcome.result.reasons
      .filter((reason) => reason.review?.decision === "deny")
      .map((reason) => reason.review?.reason)
      .filter((reason) => typeof reason === "string" && reason.length > 0))];
    const detail = reasons.length === 0 ? "denied by the approval chain" : reasons.join("; ");
    if (outcome.decision === "deny") {
      if (reviewDenials.length > 0) {
        return { block: true, reason: reviewDenials.join("; ") };
      }
      const permissionDenied = reasons.length > 0 && reasons.every(reason =>
        /^mode:read-only:(write|network)-forbidden$/.test(reason));
      return { block: true, reason: `permission:denied: ${detail}`, ...(permissionDenied ? { permissionDenied: true } : {}) };
    }
    const sandboxReview = executionRequest === undefined && outcome.result.reasons.some(entry =>
      /^risk:.*:needs-confirmation:/.test(entry.reason)) && outcome.result.reasons.every(entry =>
      entry.decision === "allow" || /^risk:.*:needs-confirmation:/.test(entry.reason));
    if (sandboxReview) return undefined;
    return allowHostExecution
      ? { kind: "host-execution", reason: `permission:host-execution: ${detail}` }
      : { block: true, reason: "permission:ordinary-host-execution-forbidden; request_tool_elevation is available for supported built-in tools" };
  }

  // -------------------------------------------------------------------------
  // Tool call processing (§6)
  // -------------------------------------------------------------------------

  function recordToolEvent(session: HostSession, event: ReviewToolEvent): void {
    try {
      session.memory.recordToolEvent(event);
    } catch {
      // The memory is a reviewer aid; a failure never changes the decision.
    }
  }

  /**
   * The session memory returns a scoped review result for this frozen call.
   * Ordinary calls get `undefined`; a matching answer is recorded separately
   * from the rule verdict and cannot bypass a deny.
   *
   * The port must never throw and never decide on a memory failure: the audit
   * write and the memory record are the only side effects, and a failure there
   * is swallowed the same way `recordToolEvent` swallows one.
   */
  function createSessionReviewPort(
    session: HostSession,
    ctx: ExtensionContext,
    event: ToolCallEvent,
    input: {
      readonly recordCallInMemory?: boolean;
      readonly hostExecutionRequest?: ExecutionRequest;
    },
  ): SessionReviewPort {
    const parentToolCallId = nonEmpty((event as { parentToolCallId?: unknown }).parentToolCallId);
    const recordCall = (): void => {
      if (input.recordCallInMemory === false) return;
      recordToolEvent(session, {
        kind: "call",
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: event.input,
        ...(parentToolCallId === undefined ? {} : { parentToolCallId }),
      });
    };
    return async (request) => {
      if (request.toolCallId !== event.toolCallId) return undefined;
      const remembered = session.askDecisions.lookup(event.toolName, event.input);
      if (remembered !== undefined) {
        recordCall();
        audit({
          kind: "session-decision",
          sessionId: session.id,
          toolCallId: event.toolCallId,
          toolName: event.toolName,
          decision: remembered.decision,
          requestId: remembered.requestId,
        });
        return {
          decision: remembered.decision === "allow" ? "approve" : "deny",
          reason: remembered.decision === "allow"
            ? "session:remembered-allow"
            : "session:remembered-deny",
        };
      }
      if (
        input.hostExecutionRequest === undefined &&
        session.commandGrants.size > 0 &&
        SHELL_SESSION_TOOLS.has(event.toolName)
      ) {
        const command = (event.input as Readonly<Record<string, unknown>>).command;
        if (typeof command === "string" && command.trim().length > 0) {
          const units = await sessionCommandUnits(command, ctx.cwd);
          if (units !== undefined && session.commandGrants.matches(command, units)) {
            recordCall();
            audit({
              kind: "session-decision",
              sessionId: session.id,
              toolCallId: event.toolCallId,
              toolName: event.toolName,
            decision: "allow",
              requestId: createPermissionRequestId(),
            });
            return { decision: "approve", reason: "session:command-family" };
          }
        }
      }
      return undefined;
    };
  }

  function invalidateHost(session: HostSession, reason: string): void {
    session.invalidationRevision += 1;
    for (const preparing of session.preparing.values()) {
      preparing.cancel("permission:evidence-changed");
    }
    session.runner.invalidate();
    session.prepared.clear();
    session.preparing.clear();
    session.preparedByCall.clear();
    session.handledToolCallIds.clear();
    session.pinned.clear();
    try {
      options.sandbox?.invalidate?.(session.id);
    } catch (error) {
      auditError(session.id, "sandbox-invalidate", error);
    }
    audit({ kind: "invalidate", sessionId: session.id, reason });
  }

  function capturedCallMatches(
    capture: StepCapture,
    event: ToolCallEvent,
    parentToolCallId: string | undefined,
    hostExecutionRequest: ExecutionRequest | undefined,
  ): boolean {
    const call = capture.directCalls.find((item) => item.toolCallId === event.toolCallId);
    try {
      return call !== undefined && call.toolName === event.toolName &&
        call.parentToolCallId === parentToolCallId &&
        call.argumentsDigest === reviewDigest(event.input) &&
        reviewDigest(call.hostExecutionRequest ?? null) === reviewDigest(hostExecutionRequest ?? null);
    } catch {
      return false;
    }
  }

  function preparationIsCurrent(session: HostSession, preparing: PreparingStep): boolean {
    return !session.disposed && !preparing.controller.signal.aborted &&
      session.invalidationRevision === preparing.invalidationRevision &&
      resolveOwner(session) === preparing.owner &&
      session.preparing.get(preparing.stepKey) === preparing;
  }

  function startPreparation(
    session: HostSession,
    ctx: ExtensionContext,
    input: {
      readonly capture: StepCapture;
      readonly captured: Extract<ReviewCaptureResult, { readonly ok: true }>;
      readonly owner: string;
      readonly mode: PermissionMode;
      readonly publication: PermissionPublication;
      readonly selectedFileTargets?: Readonly<Record<string, HumanPromptTarget>>;
      /** The session memory link; absent on non-approval paths. */
      readonly sessionReviews?: SessionReviewPort;
    },
  ): PreparingStep {
    let resolveWork!: (result: PreparationResult) => void;
    let resolveCancelled!: (result: PreparationResult) => void;
    const work = new Promise<PreparationResult>((resolve) => { resolveWork = resolve; });
    const cancelled = new Promise<PreparationResult>((resolve) => { resolveCancelled = resolve; });
    const controller = new AbortController();
    let cancelledOnce = false;
    let preparing!: PreparingStep;
    preparing = {
      stepKey: input.capture.stepKey,
      captureDigest: input.capture.digest,
      capture: input.capture,
      generation: input.publication.generation,
      invalidationRevision: session.invalidationRevision,
      owner: input.owner,
      mode: input.mode,
      publication: input.publication,
      captured: input.captured,
      ...(input.selectedFileTargets === undefined ? {} : { selectedFileTargets: input.selectedFileTargets }),
      ...(input.sessionReviews === undefined ? {} : { sessionReviews: input.sessionReviews }),
      controller,
      promise: Promise.race([work, cancelled]),
      cancel(reason) {
        if (cancelledOnce) return;
        cancelledOnce = true;
        controller.abort();
        resolveCancelled({ kind: "failed", reason });
        if (session.preparing.get(preparing.stepKey) === preparing) {
          session.preparing.delete(preparing.stepKey);
        }
      },
    };
    session.preparing.set(preparing.stepKey, preparing);
    if (!acquirePublication(session, preparing.publication)) {
      resolveWork({ kind: "failed", reason: "generation-stale" });
      session.preparing.delete(preparing.stepKey);
      return preparing;
    }
    void performPreparation(session, ctx, preparing).then(resolveWork, (error: unknown) => {
      auditError(session.id, "preparation", error);
      resolveWork({ kind: "failed", reason: "chain-failed" });
    });
    return preparing;
  }

  async function performPreparation(
    session: HostSession,
    ctx: ExtensionContext,
    preparing: PreparingStep,
  ): Promise<PreparationResult> {
    let transferred = false;
    let pin: PinnedPublication | undefined;
    let signal: AbortSignal;
    const fail = (reason: string): PreparationResult => ({ kind: "failed", reason });
    try {
      signal = ctx.signal === undefined
        ? preparing.controller.signal
        : AbortSignal.any([ctx.signal, preparing.controller.signal]);
      let units: readonly UnitPreparation[];
      try {
        units = await options.analysis.analyze(preparing.capture, {
          cwd: ctx.cwd,
          generation: preparing.generation,
          signal,
        });
      } catch (error) {
        if (preparing.controller.signal.aborted) return fail("evidence-changed");
        auditError(session.id, "analysis", error);
        return fail("analysis-failed");
      }
      if (!preparationIsCurrent(session, preparing)) return fail("evidence-changed");
      if (units.length === 0) return fail("analysis-failed");

      if (!session.memory.isCurrent(preparing.owner, preparing.captured.view, preparing.captured.revisions)) {
        return fail("evidence-changed");
      }
      const sessionFacts: ReviewerSessionFacts = {
        view: preparing.captured.view,
        revisions: {
          ...preparing.captured.revisions,
          projectRules: preparing.publication.rulesRevision,
          intent: preparing.publication.intentRevision,
        },
        mode: preparing.mode,
      };

      let bashPrograms: Readonly<Record<string, BashProgramFactsView>> | undefined;
      if (options.analysis.bashPrograms !== undefined) {
        try {
          const provider = options.analysis.bashPrograms(preparing.capture, {
            cwd: ctx.cwd,
            generation: preparing.generation,
            signal,
          });
          if (provider !== undefined) {
            bashPrograms = await collectStepBashFacts({
              calls: preparing.capture.directCalls as readonly BashProgramRequest[],
              provider,
            });
          }
        } catch (error) {
          if (preparing.controller.signal.aborted) return fail("evidence-changed");
          auditError(session.id, "bash-facts", error);
          bashPrograms = undefined;
        }
      }
      if (!preparationIsCurrent(session, preparing)) return fail("evidence-changed");

      let powershellPrograms: Readonly<Record<string, PowerShellProgramFactsView>> | undefined;
      if (options.analysis.powershellPrograms !== undefined) {
        try {
          const provider = options.analysis.powershellPrograms(preparing.capture, {
            cwd: ctx.cwd,
            generation: preparing.generation,
            signal,
          });
          if (provider !== undefined) {
            powershellPrograms = await collectStepPowerShellFacts({
              calls: preparing.capture.directCalls as readonly PowerShellProgramRequest[],
              provider,
              cwd: ctx.cwd,
            });
          }
        } catch (error) {
          if (preparing.controller.signal.aborted) return fail("evidence-changed");
          auditError(session.id, "powershell-facts", error);
          powershellPrograms = undefined;
        }
      }

      if (!preparationIsCurrent(session, preparing) ||
          !session.memory.isCurrent(preparing.owner, preparing.captured.view, preparing.captured.revisions)) {
        return fail("evidence-changed");
      }

      pin = {
        publication: preparing.publication,
        generation: preparing.generation,
        owner: preparing.owner,
        mode: preparing.mode,
        sessionFacts,
      };
      session.pinned.set(preparing.stepKey, pin);
      let begun;
      try {
        begun = session.runner.begin({
          capture: preparing.capture,
          units,
          nodes: orderPublishedNodes(preparing.publication.nodes),
          generation: preparing.generation,
          mode: preparing.mode,
          sessionFacts,
          ...(bashPrograms === undefined ? {} : { bashPrograms }),
          ...(powershellPrograms === undefined ? {} : { powershellPrograms }),
          ...(preparing.selectedFileTargets === undefined ? {} : { selectedFilePaths: Object.fromEntries(
            Object.entries(preparing.selectedFileTargets).map(([id, target]) => [id, target.resolvedPath]),
          ) }),
          signal,
          human: makeHuman(ctx, session, preparing.selectedFileTargets),
          ...(preparing.sessionReviews === undefined
            ? {}
            : { sessionReviews: preparing.sessionReviews }),
          onFinal: () => undefined,
        });
      } catch (error) {
        auditError(session.id, "begin", error);
        return fail("chain-failed");
      }
      if (!begun.ok) return fail(begun.reason);

      const prepared: PreparedStep = {
        stepKey: preparing.stepKey,
        captureDigest: preparing.captureDigest,
        capture: preparing.capture,
        generation: preparing.generation,
        publication: preparing.publication,
        handle: begun.handle,
        calls: preparing.capture.directCalls.map((call) => call.toolCallId),
      };
      session.prepared.set(preparing.stepKey, prepared);
      for (const call of prepared.calls) session.preparedByCall.set(call, prepared);
      if (session.preparing.get(preparing.stepKey) === preparing) {
        session.preparing.delete(preparing.stepKey);
      }
      transferred = true;
      void begun.handle.done
        .then(() => undefined, () => undefined)
        .then(() => {
          if (session.prepared.get(prepared.stepKey) === prepared) {
            session.prepared.delete(prepared.stepKey);
          }
          for (const call of prepared.calls) {
            if (session.preparedByCall.get(call) === prepared) session.preparedByCall.delete(call);
          }
          if (session.pinned.get(prepared.stepKey) === pin) session.pinned.delete(prepared.stepKey);
          releasePublication(session, prepared.publication);
        });
      return { kind: "prepared", value: prepared };
    } finally {
      if (!transferred) {
        if (pin !== undefined && session.pinned.get(preparing.stepKey) === pin) {
          session.pinned.delete(preparing.stepKey);
        }
        releasePublication(session, preparing.publication);
      }
      if (session.preparing.get(preparing.stepKey) === preparing) {
        session.preparing.delete(preparing.stepKey);
      }
    }
  }

  async function resolveApproval(
    session: HostSession,
    ctx: ExtensionContext,
    event: ToolCallEvent,
    input: {
      readonly hostExecutionRequest?: ExecutionRequest;
      readonly allowHostExecution: boolean;
      readonly recordCallInMemory?: boolean;
    },
  ): Promise<ReviewAnswer> {
    const requestId = createPermissionRequestId();
    session.ctx = ctx;
    if (session.publication === undefined) {
      await ensurePublication(ctx, session, false);
    }
    const publication = session.publication;
    if (publication === undefined) return { block: true, reason: "permission:config-unavailable" };
    const mode = effectiveMode(session) ?? publication.mode;
    const parentToolCallId = nonEmpty((event as { parentToolCallId?: unknown }).parentToolCallId);
    const fixed = session.preparedByCall.get(event.toolCallId);
    if (fixed !== undefined) {
      if (input.recordCallInMemory !== false) {
        recordToolEvent(session, {
          kind: "call",
          sessionId: session.id,
          toolCallId: event.toolCallId,
          toolName: event.toolName,
          input: event.input,
          ...(parentToolCallId === undefined ? {} : { parentToolCallId }),
        });
      }
      if (!capturedCallMatches(fixed.capture, event, parentToolCallId, input.hostExecutionRequest)) {
        return { block: true, reason: "permission:capture-mismatch: the call changed after its approval was captured; the approval no longer covers it" };
      }
      const outcome = await fixed.handle.join(event.toolCallId);
      auditStep(session, requestId, fixed, event, outcome);
      return answerFor(outcome, input.allowHostExecution, input.hostExecutionRequest);
    }

    // Session denies remain effective when the sandbox baseline allows a call.
    // Session approvals apply only to unresolved asks in the decision node.
    const sessionReviews = effectiveMode(session) !== "full-access"
      ? createSessionReviewPort(session, ctx, event, input)
      : undefined;

    const owner = resolveOwner(session);
    if (input.recordCallInMemory !== false) {
      recordToolEvent(session, {
        kind: "call",
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: event.input,
        ...(parentToolCallId === undefined ? {} : { parentToolCallId }),
      });
    }
    const captured = session.memory.capture(owner);
    if (!captured.ok) {
      return { block: true, reason: "permission:session-unavailable:memory-" + captured.reason };
    }
    const registeredTools = safeToolNames();
    const facts = stepFacts.capture({
      event: {
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: event.input,
        ...(parentToolCallId === undefined ? {} : { parentToolCallId }),
        ...(input.hostExecutionRequest === undefined ? {} : { hostExecutionRequest: input.hostExecutionRequest }),
      },
      ...(captured.view.manifest === undefined ? {} : { manifest: captured.view.manifest }),
      ...(registeredTools === undefined ? {} : { registeredTools }),
      ...(options.sandbox?.sanctionedArgumentRewrite === undefined ? {} : {
        sanctionedArgumentRewrite: (manifestCall) => options.sandbox!.sanctionedArgumentRewrite!(
          manifestCall.toolName, manifestCall.arguments, event.input, ctx),
      }),
    });
    if (!facts.ok) {
      const detail = facts.reason === "incomplete"
        ? "the approval capture for this call is incomplete; retry the call"
        : facts.reason === "capture-failed"
          ? "the approval chain could not freeze this call for review; retry the call"
          : "this call no longer matches the arguments the model recorded (or the tool is not registered); the approval chain refuses to review a changed call";
      return { block: true, reason: `permission:step-facts:${facts.reason}: ${detail}` };
    }
    const capture = facts.capture;
    if (!capturedCallMatches(capture, event, parentToolCallId, input.hostExecutionRequest)) {
      return { block: true, reason: "permission:capture-mismatch: the call changed after its approval was captured; the approval no longer covers it" };
    }

    const deliver = async (result: PreparationResult): Promise<ReviewAnswer> => {
      if (result.kind === "prepared") {
        const prepared = result.value;
        const outcome = await prepared.handle.join(event.toolCallId);
        auditStep(session, requestId, prepared, event, outcome);
        return answerFor(outcome, input.allowHostExecution, input.hostExecutionRequest);
      }
      if (result.kind === "failed" && result.reason === "duplicate-step" &&
          input.recordCallInMemory !== false && session.runner.hasCall(event.toolCallId)) {
        const outcome = await session.runner.join({
          toolCallId: event.toolCallId,
          captureDigest: capture.digest,
          ...(ctx.signal === undefined ? {} : { signal: ctx.signal }),
        });
        auditStep(session, requestId, {
          stepKey: capture.stepKey,
          captureDigest: capture.digest,
          generation: publication.generation,
        }, event, outcome);
        return answerFor(outcome, input.allowHostExecution, input.hostExecutionRequest);
      }
      const reason = result.kind === "settled" ? "duplicate-step" : result.reason;
      return { block: true, reason: reason.startsWith("permission:") ? reason : "permission:" + reason };
    };

    const prepared = session.prepared.get(capture.stepKey);
    if (prepared !== undefined) {
      if (prepared.captureDigest !== capture.digest) {
        return { block: true, reason: "permission:capture-mismatch: the call changed after its approval was captured; the approval no longer covers it" };
      }
      if (prepared.generation !== publication.generation) {
        return { block: true, reason: "permission:generation-stale" };
      }
      return deliver({ kind: "prepared", value: prepared });
    }

    const existing = session.preparing.get(capture.stepKey);
    if (existing !== undefined) {
      if (existing.captureDigest !== capture.digest) {
        return { block: true, reason: "permission:capture-mismatch: the call changed after its approval was captured; the approval no longer covers it" };
      }
      if (existing.generation !== publication.generation) {
        return { block: true, reason: "permission:generation-stale" };
      }
      return deliver(await existing.promise);
    }

    const preparing = startPreparation(session, ctx, {
      capture,
      captured,
      owner,
      mode,
      publication,
      ...(input.hostExecutionRequest !== undefined || options.sandbox?.selectFileTargets === undefined ? {} : {
        selectedFileTargets: options.sandbox.selectFileTargets(capture.directCalls, ctx),
      }),
      ...(sessionReviews === undefined ? {} : { sessionReviews }),
    });
    return deliver(await preparing.promise);
  }

  function safeToolNames(): readonly string[] | undefined {
    if (pi === undefined) return undefined;
    try {
      return (pi.getAllTools() ?? []).map((tool) => tool.name);
    } catch {
      return undefined;
    }
  }

  function auditStep(
    session: HostSession,
    requestId: string,
    prepared: Pick<PreparedStep, "stepKey" | "captureDigest" | "generation">,
    event: ToolCallEvent,
    outcome: StepOutcome,
  ): void {
    audit({
      kind: "step",
      sessionId: session.id,
      requestId,
      stepKey: prepared.stepKey,
      captureDigest: prepared.captureDigest,
      generation: prepared.generation,
      toolCallId: event.toolCallId,
      toolName: event.toolName,
      decision: outcome.decision,
      ...(outcome.decision === "blocked" ? { reason: outcome.reason } : {}),
    });
  }

  function toToolCallResult(answer: ReviewAnswer): ToolCallEventResult | undefined {
    if (answer === undefined) return undefined;
    if ("kind" in answer && answer.kind === "host-execution") {
      return { block: true, reason: "permission:host-execution-unavailable" };
    }
    return { block: true, reason: formatPiSandboxError(answer.reason) };
  }

  async function handleToolCall(event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> {
    if (options.bypassToolName !== undefined && event.toolName === options.bypassToolName) {
      const session = ensureSession(ctx);
      if (session === undefined) return { block: true, reason: sessionUnavailableReason(ctx) };
      const owner = resolveOwner(session);
      if (!session.memory.initialized) {
        const initialized = session.memory.capture(owner);
        if (!initialized.ok) {
          return { block: true, reason: `permission:session-unavailable:memory-${initialized.reason}` };
        }
      }
      const parentToolCallId = nonEmpty((event as { parentToolCallId?: unknown }).parentToolCallId);
      recordToolEvent(session, {
        kind: "call",
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: event.input,
        ...(parentToolCallId === undefined ? {} : { parentToolCallId }),
      });
      return undefined;
    }
    const session = ensureSession(ctx);
    if (session === undefined) return { block: true, reason: sessionUnavailableReason(ctx) };
    if (session.publication === undefined) {
      await ensurePublication(ctx, session, false);
    }
    if (session.publication === undefined) {
      return { block: true, reason: "permission:config-unavailable" };
    }
    if (session.handledToolCallIds.has(event.toolCallId)) {
      return { block: true, reason: "permission:duplicate-call" };
    }
    session.handledToolCallIds.add(event.toolCallId);
    const review = (input?: SandboxReviewInput) => {
      const selectedFileTarget = typeof input?.requestedPath === "string" && typeof input.resolvedPath === "string"
        ? { requestedPath: input.requestedPath, resolvedPath: input.resolvedPath }
        : undefined;
      if (selectedFileTarget !== undefined) session.reviewPaths.set(event.toolCallId, selectedFileTarget);
      return resolveApproval(session, ctx, event, { allowHostExecution: false }).finally(() => {
        if (selectedFileTarget !== undefined && session.reviewPaths.get(event.toolCallId) === selectedFileTarget) {
          session.reviewPaths.delete(event.toolCallId);
        }
      });
    };
    try {
      if (options.sandbox !== undefined) {
        const answer = await options.sandbox.guard(event, ctx, review);
        return toToolCallResult(answer);
      }
      const answer = await review();
      return toToolCallResult(answer);
    } catch (error) {
      auditError(session.id, "tool-call", error);
      return { block: true, reason: "permission:internal-error" };
    }
  }

  // -------------------------------------------------------------------------
  // Sandbox bypass channel (§6)
  // -------------------------------------------------------------------------

  async function reviewSandboxBypass(
    input: SandboxBypassReviewInput,
    ctx: ExtensionToolContext,
  ): Promise<SandboxBypassReviewAnswer> {
    const session = ensureSession(ctx);
    if (session === undefined) return { block: true, reason: sessionUnavailableReason(ctx) };
    const event = {
      type: "tool_call",
      toolCallId: input.toolCallId,
      toolName: input.targetToolName,
      input: input.arguments,
    } as unknown as ToolCallEvent;
    const answer = await resolveApproval(session, ctx, event, {
      hostExecutionRequest: { reason: input.reason, elevation: input.elevation },
      allowHostExecution: true,
      recordCallInMemory: false,
    });
    if (answer === undefined) return undefined;
    // In the dedicated bypass channel an escalation result means "the elevation
    // is approved": the sandbox bypass tool executes the target on the host.
    if ("kind" in answer && answer.kind === "host-execution") return undefined;
    return { block: true, reason: answer.reason };
  }

  // -------------------------------------------------------------------------
  // Pi event wiring (§7)
  // -------------------------------------------------------------------------

  function install(api: ExtensionAPI): void {
    pi = api;
    api.on("session_start", async (_event, ctx) => {
      const session = ensureSession(ctx);
      if (session === undefined) return;
      await ensurePublication(ctx, session, false);
    });
    api.on("tool_call", async (event, ctx) => {
      const result = await handleToolCall(event, ctx);
      return result?.block === true
        ? { ...result, reason: formatPiSandboxError(result.reason) }
        : result;
    });
    api.on("tool_execution_start", (event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      recordToolEvent(session, {
        kind: "call",
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: event.args,
        ...(event.parentToolCallId === undefined ? {} : { parentToolCallId: event.parentToolCallId }),
      });
      audit({
        kind: "execution",
        sessionId: session.id,
        phase: "start",
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        ...(event.parentToolCallId === undefined ? {} : { parentToolCallId: event.parentToolCallId }),
      });
    });
    api.on("tool_execution_end", (event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      const result = toolResultText(event.result);
      recordToolEvent(session, {
        kind: "result",
        sessionId: session.id,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        text: result.text,
        isError: event.isError === true || result.isError,
      });
      audit({
        kind: "execution",
        sessionId: session.id,
        phase: "end",
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        ...(event.parentToolCallId === undefined ? {} : { parentToolCallId: event.parentToolCallId }),
        isError: event.isError === true,
      });
      // A finished call no longer pins its step association; the step itself
      // stays alive until its own run settles.
      if (session.preparedByCall.get(event.toolCallId) !== undefined) {
        session.preparedByCall.delete(event.toolCallId);
      }
    });
    api.on("input", (event, ctx) => {
      const session = ensureSession(ctx);
      if (session === undefined) return;
      if (event.source !== "extension") {
        if (event.streamingBehavior === undefined) {
          try {
            session.memory.noteUserInput(event.text);
          } catch {
            // The memory failure only makes later captures fail closed.
          }
          invalidateHost(session, "user-input");
        }
        const mode = effectiveMode(session) ?? "default";
        const state = session.reminder.handleInput({
          mode,
          source: event.source,
          ...(event.streamingBehavior === undefined ? {} : { streamingBehavior: event.streamingBehavior }),
        });
        audit({
          kind: "mode-reminder",
          sessionId: session.id,
          revision: session.reminder.state().revision,
          mode,
          sent: state,
        });
      }
    });
    api.on("before_agent_start", async (_event, ctx) => {
      const session = ensureSession(ctx);
      if (session === undefined) return;
      invalidateHost(session, "before-agent-start");
      // "Best effort": only load a publication when there is none. External
      // config changes arrive through resources_discover; a reload here would
      // create a new generation before every agent run.
      await ensurePublication(ctx, session, session.publication === undefined);
    });
    api.on("resources_discover", async (event, ctx) => {
      if (event.reason !== "reload") return;
      const session = ensureSession(ctx);
      if (session === undefined) return;
      await ensurePublication(ctx, session, true);
    });
    api.on("mcp_servers_change", (_event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      invalidateHost(session, "mcp-servers-change");
    });
    api.on("session_tree", (_event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      try {
        session.memory.noteNavigation();
      } catch {
        // A later capture fails closed on its own.
      }
      invalidateHost(session, "session-tree");
    });
    api.on("session_compact", (_event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      try {
        session.memory.requestHistoryRebuild();
      } catch {
        // A later capture fails closed on its own.
      }
      invalidateHost(session, "session-compact");
    });
    api.on("agent_end", (_event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      session.reminder.agentEnd(currentBranch(session));
    });
    api.on("session_shutdown", async (_event, ctx) => {
      const session = sessions.get(ctx.sessionManager.getSessionId());
      if (session === undefined) return;
      await disposeSession(session);
    });
  }

  async function disposeSession(session: HostSession): Promise<void> {
    if (session.disposed) return;
    session.disposed = true;
    session.invalidationRevision += 1;
    for (const preparing of session.preparing.values()) {
      preparing.cancel("permission:session-unavailable:session-disposed");
    }
    session.preparing.clear();
    try {
      await session.reload;
    } catch {
      // A failed publication never blocks shutdown.
    }
    try {
      session.runner.dispose();
    } catch (error) {
      auditError(session.id, "runner-dispose", error);
    }
    try {
      session.context.dispose();
    } catch (error) {
      auditError(session.id, "context-dispose", error);
    }
    try {
      session.memory.dispose();
    } catch (error) {
      auditError(session.id, "memory-dispose", error);
    }
    session.commandGrants.clear();
    try {
      session.learning.dispose();
    } catch (error) {
      auditError(session.id, "learning-dispose", error);
    }
    const current = session.publication;
    session.publication = undefined;
    if (current !== undefined) {
      const refs = session.currentRefs;
      session.currentRefs = 0;
      if (refs === 0) disposePublication(session, current, "publication-shutdown");
      else session.retired.set(current.generation, { publication: current, refs });
    }
    for (const [generation, entry] of [...session.retired]) {
      if (entry.refs === 0) {
        session.retired.delete(generation);
        disposePublication(session, entry.publication, "publication-shutdown");
      }
    }
    session.prepared.clear();
    session.preparedByCall.clear();
    session.pinned.clear();
    sessions.delete(session.id);
  }

  function state(): HostState {
    return {
      sessions: [...sessions.values()].map((session) => {
        const counters = session.runner.state();
        return {
          sessionId: session.id,
          generation: session.generation,
          publication: session.publication === undefined ? "unavailable" : "ready",
          activeSteps: counters.activeSteps,
          pendingCalls: counters.pendingCalls,
          settledCalls: counters.settledCalls,
          mode: effectiveMode(session),
        };
      }),
    };
  }

  async function dispose(): Promise<void> {
    disposed = true;
    for (const session of [...sessions.values()]) await disposeSession(session);
  }

  function setSessionMode(sessionId: string, mode: PermissionMode | null): void {
    const session = sessions.get(sessionId);
    if (session === undefined || session.disposed) return;
    const previous = effectiveMode(session);
    session.modeOverride = mode ?? undefined;
    const current = effectiveMode(session);
    if (current === undefined || previous === current) return;
    const revision = session.reminder.noteModeChange(current);
    audit({ kind: "mode-reminder", sessionId, revision, mode: current, sent: false });
  }

  return {
    install,
    async reload(ctx) {
      const session = ensureSession(ctx);
      if (session === undefined) return false;
      const previous = session.publication;
      const current = await ensurePublication(ctx, session, true);
      return current !== undefined && current !== previous;
    },
    setSessionMode,
    reviewSandboxBypass,
    state,
    dispose,
  };
}

/** Render the hidden mode reminder text for hosts that only need the wording. */
export { modeReminderText };

