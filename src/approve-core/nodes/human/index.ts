/**
 * Human review surface (specs/human-review.md §1) and the module entry point.
 *
 * The adapter is the last fallback of the approval chain: it shows at most one
 * prompt per still-ask call, races that prompt against abort and a local
 * timeout, and maps only explicit host choices to approve or deny. Every
 * unavailable path (no UI, throw, timeout, missing or unknown answer) ends in a
 * cancellation, never an approval. Preview formatting lives in the sibling
 * modules; this file owns the prompt, the default TUI selector and the audit
 * records.
 */

import { matchesKey, truncateToWidth, type Component } from "@earendil-works/pi-tui";
import type { CallSummary, CallState } from "#approve-core/contracts";
import type { HumanApprover, HumanRequest, HumanResponse } from "#approve-core/runtime";
import {
  createPromptToolInputFormatter,
  type ToolInputFormatterLookup,
} from "./tool-input-prompt-formatters";
import type { PreviewLimits } from "./tool-input-preview";

export * from "./tool-input-preview";
export * from "./builtin-tool-input-formatters";
export * from "./tool-input-prompt-formatters";
export * from "./tool-preview-formatter";

/** Default local prompt timeout: five minutes. */
export const DEFAULT_HUMAN_TIMEOUT_MS = 300_000;

/** Default machine-readable reason category for human decisions. */
export const DEFAULT_HUMAN_REASON_PREFIX = "permission:human";

export const HUMAN_CANCEL_OPTION = "Cancel - do not approve";
export const HUMAN_APPROVE_OPTION = "Approve this call once";
export const HUMAN_DENY_OPTION = "Deny this call";

// ---------------------------------------------------------------------------
// Request facts and prompt view
// ---------------------------------------------------------------------------

/** What the prompt renders for one request. */
export interface HumanPromptView {
  readonly title: string;
  readonly options: readonly string[];
  readonly approveOption: string;
  readonly denyOption: string;
  readonly cancelOption: string;
}

/** Prompt facts plus the request identity used for audit. */
export interface HumanRequestFacts extends HumanPromptView {
  readonly escalation: boolean;
  readonly askFor: "allow" | "escalate";
  readonly toolName: string;
  readonly toolCallId: string;
  readonly reason: string;
  readonly arguments: Readonly<Record<string, unknown>>;
}

/** Default describer: names the tool, the recorded reasons and the options. */
export function describeHumanRequest(request: HumanRequest): HumanRequestFacts {
  const facts = requestAuditFacts(request, 0);
  const tier = request.call.hostExecutionRequest?.elevation.tier;
  const reason = summarizeReasons(
    request.summary,
    facts.escalation
      ? tier === undefined ? "ordinary approvals cannot grant Host execution" : `one-time ${tier} elevation was requested`
      : "no reason was recorded",
  );
  const title = tier === "host"
    ? `Host execution request for ${facts.toolName} (outside the OS sandbox). Reason: ${reason}`
    : tier === "default"
      ? `Default sandbox elevation request for ${facts.toolName}. Reason: ${reason}`
      : facts.escalation
        ? `Ordinary ${facts.toolName} call cannot receive Host execution. Reason: ${reason}`
        : `Approve ${facts.toolName} call? Reason: ${reason}`;
  return Object.freeze({
    escalation: facts.escalation,
    askFor: facts.askFor,
    toolName: facts.toolName,
    toolCallId: facts.toolCallId,
    reason,
    arguments: readArguments(request),
    title,
    options: Object.freeze([HUMAN_CANCEL_OPTION, HUMAN_APPROVE_OPTION, HUMAN_DENY_OPTION]),
    approveOption: HUMAN_APPROVE_OPTION,
    denyOption: HUMAN_DENY_OPTION,
    cancelOption: HUMAN_CANCEL_OPTION,
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** Identity attached to every human audit record. */
export interface HumanAuditFacts {
  readonly generation: number;
  readonly stepKey: string;
  readonly toolCallId: string;
  readonly toolName: string;
  readonly askFor: "allow" | "escalate";
  readonly escalation: boolean;
}

export type HumanAuditEvent =
  | ({ readonly kind: "prompt" } & HumanAuditFacts)
  | ({
      readonly kind: "answered";
      readonly decision: HumanResponse["decision"];
      readonly reason: string;
    } & HumanAuditFacts)
  | ({
      readonly kind: "unavailable";
      readonly decision: "cancel";
      readonly reason: string;
    } & HumanAuditFacts);

export interface HumanAuditPort {
  record(event: HumanAuditEvent): void;
}

// ---------------------------------------------------------------------------
// Default prompt component (interval highlight only after the first move)
// ---------------------------------------------------------------------------

export interface HumanSelectorComponentInput {
  readonly title: string;
  readonly options: readonly string[];
  readonly onSelect: (option: string) => void;
  readonly onCancel: () => void;
}

export interface HumanSelectorComponent extends Component {
  readonly selectedIndex: number;
  render(width: number): string[];
  handleInput(data: string): void;
}

class ApprovalSelector implements HumanSelectorComponent {
  private index = -1;
  private settled = false;

  constructor(private readonly input: HumanSelectorComponentInput) {}

  get selectedIndex(): number {
    return this.index;
  }

  invalidate(): void {
    // No cached rendering state.
  }

  handleInput(data: string): void {
    if (this.settled) return;
    const last = this.input.options.length - 1;
    if (matchesKey(data, "down")) {
      this.index = this.index < 0 ? 0 : Math.min(this.index + 1, last);
      return;
    }
    if (matchesKey(data, "up")) {
      this.index = this.index < 0 ? last : Math.max(this.index - 1, 0);
      return;
    }
    if (matchesKey(data, "enter")) {
      if (this.index < 0) return;
      const option = this.input.options[this.index];
      if (option === undefined) return;
      this.settled = true;
      this.input.onSelect(option);
      return;
    }
    if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c")) {
      this.settled = true;
      this.input.onCancel();
    }
  }

  render(width: number): string[] {
    const lines: string[] = [truncateToWidth(this.input.title, width, "")];
    this.input.options.forEach((option, index) => {
      const prefix = index === this.index ? "→ " : "  ";
      lines.push(truncateToWidth(`${prefix}${option}`, width, ""));
    });
    return lines;
  }
}

/** Default TUI selector component: no highlight until the user moves. */
export function createHumanSelectorComponent(input: HumanSelectorComponentInput): HumanSelectorComponent {
  return new ApprovalSelector(input);
}

// ---------------------------------------------------------------------------
// Default prompt port (TUI custom component, RPC selector, no UI)
// ---------------------------------------------------------------------------

export interface HumanPromptSelectOptions {
  readonly signal?: AbortSignal;
  readonly timeout?: number;
}

/** The narrow host surface a default prompt needs. */
export interface HumanPromptHost {
  readonly mode?: string;
  readonly hasUI: boolean;
  readonly ui: {
    select(
      title: string,
      options: readonly string[],
      opts?: HumanPromptSelectOptions,
    ): Promise<string | undefined>;
    custom?(
      factory: (
        tui: unknown,
        theme: unknown,
        keybindings: unknown,
        done: (result: unknown) => void,
      ) => Component,
    ): Promise<unknown>;
  };
}

export type HumanPromptPort = (view: HumanPromptView, request: HumanRequest) => Promise<unknown>;

export interface HumanPromptOptions {
  /** Host dialog timeout; the adapter keeps its own independent timeout. */
  readonly timeoutMs?: number;
}

/**
 * Default prompt port. TUI mode renders the selector component so Enter cannot
 * confirm before the user moved; every other UI mode uses the host dialog. A
 * throwing or missing UI yields no selection.
 */
export function createHumanPrompt(host: HumanPromptHost, options: HumanPromptOptions = {}): HumanPromptPort {
  return async (view, request) => {
    if (!host.hasUI) return undefined;
    if (host.mode === "tui" && typeof host.ui.custom === "function") {
      try {
        const result = await host.ui.custom((_tui, _theme, _keybindings, done) =>
          createHumanSelectorComponent({
            title: view.title,
            options: view.options,
            onSelect: (option) => done(option),
            onCancel: () => done(undefined),
          }));
        return typeof result === "string" ? result : undefined;
      } catch {
        return undefined;
      }
    }
    try {
      return await host.ui.select(view.title, [...view.options], {
        signal: request.signal,
        timeout: options.timeoutMs,
      });
    } catch {
      return undefined;
    }
  };
}

// ---------------------------------------------------------------------------
// Human approver adapter (§1)
// ---------------------------------------------------------------------------

export type HumanPromptDescriber = (request: HumanRequest) => HumanPromptView;
export type HumanInputPreview = (toolName: string, input: unknown) => string | undefined;

export interface HumanApproverOptions {
  /** Shows one prompt for one request. */
  readonly prompt: HumanPromptPort;
  /** Current publication generation, recorded in the audit. */
  readonly generation: () => number;
  readonly timeoutMs?: number;
  /** Default serial: one prompt at a time, matching a single UI. */
  readonly concurrency?: "serial" | "parallel";
  /** Machine-readable reason category; defaults to `permission:human`. */
  readonly reasonPrefix?: string;
  readonly audit?: HumanAuditPort;
  readonly describe?: HumanPromptDescriber;
  readonly formatInput?: HumanInputPreview;
  readonly limits?: Partial<PreviewLimits>;
  readonly formatters?: ToolInputFormatterLookup;
  readonly setTimer?: (callback: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
}

type PromptOutcome =
  | { readonly kind: "choice"; readonly value: unknown }
  | { readonly kind: "aborted" }
  | { readonly kind: "timeout" }
  | { readonly kind: "unavailable" };

/**
 * Create the human approver. All prompts run through one settlement path: the
 * first of prompt answer, abort and timeout wins, and the timer plus the abort
 * listener are removed before the answer is returned.
 */
export function createHumanApprover(options: HumanApproverOptions): HumanApprover {
  const timeoutMs = resolveTimeout(options.timeoutMs);
  const reasonPrefix = resolveReasonPrefix(options.reasonPrefix);
  const describe = options.describe ?? describeHumanRequest;
  const formatInput = options.formatInput
    ?? createPromptToolInputFormatter({ limits: options.limits, formatters: options.formatters }).preview;
  const setTimer = options.setTimer ?? ((callback: () => void, ms: number) => setTimeout(callback, ms));
  const clearTimer = options.clearTimer ?? ((handle: unknown) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  });

  const record = (event: HumanAuditEvent): void => {
    if (options.audit === undefined) return;
    try {
      options.audit.record(event);
    } catch {
      // An audit failure must never change the decision.
    }
  };

  const readGeneration = (): number => {
    try {
      const generation = options.generation();
      return typeof generation === "number" && Number.isSafeInteger(generation) ? generation : 0;
    } catch {
      return 0;
    }
  };

  async function reviewOnce(request: HumanRequest): Promise<HumanResponse> {
    const facts = requestAuditFacts(request, readGeneration());
    const unavailable = (reason: string): HumanResponse => {
      record({ kind: "unavailable", ...facts, decision: "cancel", reason });
      return Object.freeze({ decision: "cancel", reason });
    };
    if (request.signal.aborted) return unavailable(`${reasonPrefix}:aborted`);

    let view: HumanPromptView;
    try {
      view = describe(request);
    } catch {
      return unavailable(`${reasonPrefix}:unavailable`);
    }
    const preview = readInputPreview(request);
    const titled: HumanPromptView = Object.freeze({
      ...view,
      title: preview === undefined ? view.title : `${view.title} with input ${preview}`,
    });

    record({ kind: "prompt", ...facts });
    const outcome = await showPrompt(titled, request);
    if (outcome.kind === "aborted") return unavailable(`${reasonPrefix}:aborted`);
    if (outcome.kind === "timeout") return unavailable(`${reasonPrefix}:timeout`);
    if (outcome.kind === "unavailable") return unavailable(`${reasonPrefix}:unavailable`);
    if (outcome.kind === "choice" && outcome.value === undefined) {
      // A dialog dismissed without a choice is an unavailable prompt.
      return unavailable(`${reasonPrefix}:unavailable`);
    }

    const choice = outcome.value;
    const answered = (decision: HumanResponse["decision"], reason: string): HumanResponse => {
      record({ kind: "answered", ...facts, decision, reason });
      return Object.freeze({ decision, reason });
    };
    if (choice === view.approveOption) return answered("approve", `${reasonPrefix}:approved`);
    if (choice === view.denyOption) return answered("deny", `${reasonPrefix}:denied`);
    if (choice === view.cancelOption) return answered("cancel", `${reasonPrefix}:cancelled`);
    // Unknown or malformed choice: its own diagnostic, still a cancellation.
    return answered("cancel", `${reasonPrefix}:invalid-selection`);
  }

  function readInputPreview(request: HumanRequest): string | undefined {
    try {
      const preview = formatInput(readToolName(request), readArguments(request));
      if (typeof preview !== "string") return undefined;
      const trimmed = preview.trim();
      return trimmed.length === 0 ? undefined : trimmed;
    } catch {
      // Preview failures must not block the approval prompt.
      return undefined;
    }
  }

  function showPrompt(view: HumanPromptView, request: HumanRequest): Promise<PromptOutcome> {
    return new Promise<PromptOutcome>((resolve) => {
      let settled = false;
      let timer: unknown;
      const settle = (outcome: PromptOutcome): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimer(timer);
        request.signal.removeEventListener("abort", onAbort);
        resolve(outcome);
      };
      const onAbort = (): void => settle({ kind: "aborted" });

      if (request.signal.aborted) {
        settle({ kind: "aborted" });
        return;
      }
      request.signal.addEventListener("abort", onAbort, { once: true });
      timer = setTimer(() => settle({ kind: "timeout" }), timeoutMs);

      let pending: Promise<unknown>;
      try {
        pending = Promise.resolve(options.prompt(view, request));
      } catch {
        settle({ kind: "unavailable" });
        return;
      }
      pending.then(
        (value) => settle({ kind: "choice", value }),
        () => settle({ kind: "unavailable" }),
      );
    });
  }

  let tail: Promise<unknown> = Promise.resolve();
  const select = (request: HumanRequest): Promise<HumanResponse> => {
    // A request that arrives aborted is cancelled directly, without waiting
    // behind a prompt the UI is already showing.
    if (request.signal.aborted) return reviewOnce(request);
    const task = (): Promise<HumanResponse> => reviewOnce(request);
    if (options.concurrency === "parallel") return task();
    const queued = tail.then(task);
    tail = queued.then(() => undefined, () => undefined);
    return queued;
  };
  return select;
}

// ---------------------------------------------------------------------------
// Selection port bridge (Phase 12 HumanSelectionPort shape)
// ---------------------------------------------------------------------------

export interface HumanSelectionPortOptions extends HumanPromptOptions {
  readonly reasonPrefix?: string;
  readonly setTimer?: (callback: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
}

/**
 * Bridge to the host selector seam. It deliberately reports "no selection" for
 * every unavailable outcome so the caller's fallback keeps the final say; it
 * never returns an approval it did not receive.
 */
export function createHumanSelectionPort(
  host: HumanPromptHost,
  options: HumanSelectionPortOptions = {},
): (request: HumanRequest) => Promise<HumanResponse | undefined> {
  const prompt = createHumanPrompt(host, { timeoutMs: options.timeoutMs });
  const reasonPrefix = resolveReasonPrefix(options.reasonPrefix);
  const timeoutMs = resolveTimeout(options.timeoutMs);
  const setTimer = options.setTimer ?? ((callback: () => void, ms: number) => setTimeout(callback, ms));
  const clearTimer = options.clearTimer ?? ((handle: unknown) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  });

  return async (request: HumanRequest): Promise<HumanResponse | undefined> => {
    if (request.signal.aborted) return undefined;
    let view: HumanPromptView;
    try {
      view = describeHumanRequest(request);
    } catch {
      return undefined;
    }

    const outcome = await new Promise<PromptOutcome>((resolve) => {
      let settled = false;
      let timer: unknown;
      const settle = (result: PromptOutcome): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimer(timer);
        request.signal.removeEventListener("abort", onAbort);
        resolve(result);
      };
      const onAbort = (): void => settle({ kind: "aborted" });
      request.signal.addEventListener("abort", onAbort, { once: true });
      timer = setTimer(() => settle({ kind: "timeout" }), timeoutMs);
      let pending: Promise<unknown>;
      try {
        pending = Promise.resolve(prompt(view, request));
      } catch {
        settle({ kind: "unavailable" });
        return;
      }
      pending.then(
        (value) => settle({ kind: "choice", value }),
        () => settle({ kind: "unavailable" }),
      );
    });
    if (outcome.kind !== "choice") return undefined;
    if (outcome.value === view.approveOption) return { decision: "approve", reason: `${reasonPrefix}:approved` };
    if (outcome.value === view.denyOption) return { decision: "deny", reason: `${reasonPrefix}:denied` };
    if (outcome.value === view.cancelOption) return { decision: "cancel", reason: `${reasonPrefix}:cancelled` };
    return undefined;
  };
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function resolveTimeout(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : DEFAULT_HUMAN_TIMEOUT_MS;
}

function resolveReasonPrefix(value: unknown): string {
  return nonEmpty(value) ?? DEFAULT_HUMAN_REASON_PREFIX;
}

function readToolName(request: HumanRequest): string {
  return nonEmpty(request.call?.toolName) ?? "tool";
}

function readArguments(request: HumanRequest): Readonly<Record<string, unknown>> {
  const args = (request.call as CallState | undefined)?.arguments;
  return typeof args === "object" && args !== null ? args : {};
}

function summarizeReasons(summary: CallSummary | undefined, fallback: string): string {
  const reasons = Array.isArray(summary?.reasons)
    ? summary.reasons
      .map((entry) => entry?.reason)
      .filter((reason): reason is string => typeof reason === "string" && reason.length > 0)
    : [];
  return reasons.length === 0 ? fallback : reasons.join("; ");
}

function requestAuditFacts(request: HumanRequest, generation: number): HumanAuditFacts {
  const escalation = request.summary?.askFor === "escalate"
    || request.call?.hostExecutionRequest !== undefined;
  return {
    generation,
    stepKey: typeof request.capture?.stepKey === "string" ? request.capture.stepKey : "",
    toolCallId: typeof request.call?.toolCallId === "string" ? request.call.toolCallId : "",
    toolName: readToolName(request),
    askFor: escalation ? "escalate" : "allow",
    escalation,
  };
}
