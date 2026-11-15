import { AsyncLocalStorage } from "node:async_hooks";
import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { TSchema } from "typebox";

import {
  createBashToolDefinition,
  createPowerShellToolDefinition,
  createReadToolDefinition,
  createGrepToolDefinition,
  createFindToolDefinition,
  createLsToolDefinition,
  withFileMutationQueue,
  createEditToolDefinition,
  createWriteToolDefinition,
  type ExtensionAPI,
  type ExtensionToolContext,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";

import type { PermissionMode } from "../contracts";
import { formatPiSandboxError } from "../error-format";
import { freezeJson, jsonDigest, type JsonObject } from "../json";
import { builtinToolPath } from "./builtin-path";
import {
  bindOwnedToolExecution,
  type ScopeVerification,
  type ToolInvocationBindingStore,
} from "#sandbox/execution-binding";
import type {
  InvocationRequester,
  ToolInvocationFacts,
} from "../invocation";
import type { PermissionScope } from "../action";
import { compileExecutionPlan, filterExecutionEnvironment, selectExecutionEnvironment } from "#sandbox/plan";
import {
  DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST,
  BUILTIN_TOOL_NAMES,
  type BuiltinToolName,
  DEFAULT_EXECUTION_DEADLINE_MS,
  MCP_EXECUTION_COVERAGE,
  type CancellationCode,
  type ExecutionCoverage,
  type ExecutionModeDescription,
  type ExecutionOperation,
  type ExecutionOutcome,
  type FilesystemGrantInput,
  type NetworkDestination,
  type NetworkScope,
  describeExecutionMode,
} from "#sandbox/types";
import { correlationKey } from "#sandbox/keys";
import { resolveHostPathIdentity } from "#sandbox/path";
import type { ExecutionController } from "#sandbox/lifecycle";
import {
  createExecutionValidityGuard,
  type ValidityRefusal,
} from "#sandbox/validity";
import {
  ControlledOperationError,
  type OperationRunOptions,
} from "#sandbox/operations";
import { isPathWithin, isSamePath, normalizeHostPath } from "#sandbox/path";
import type { PlanApprovedScope, PlanBaselineScope } from "#sandbox/plan";
import { intersectNetworkScopes } from "#sandbox/network-scope";
import {
  sandboxToolDefinitionFields,
  SANDBOX_TOOL_TIMEOUT_MS,
  type SandboxToolSpec,
} from "#sandbox/sandbox-tools";

export type ControlledToolName = BuiltinToolName;

export const DEFAULT_CONTROLLED_TOOLS: readonly ControlledToolName[] = BUILTIN_TOOL_NAMES;
export const UNCONTROLLED_BUILTIN_TOOLS: readonly string[] = Object.freeze([]);

const UNSUPPORTED_EXECUTION_CATEGORIES: readonly string[] = Object.freeze([
  "extension-direct-fs-spawn",
  "local-mcp-server-already-started",
  "remote-mcp-remote-side-effects",
]);

export interface PiExecutionHostBinding {
  /** Current public Pi `getAllTools()` snapshot, read at execute time. */
  getAllTools(): readonly unknown[];
  readRequester(ctx: ExtensionToolContext): InvocationRequester;
  readEnvironment(ctx: ExtensionToolContext): unknown;
  verifyScope(
    invocation: ToolInvocationFacts,
    ctx: ExtensionToolContext,
    approvedRevision: string,
  ): ScopeVerification | Promise<ScopeVerification>;
  readCurrentScopeRevision(ctx: ExtensionToolContext): string | undefined;
}

export interface PiExecutionPlanOptions {
  readonly mode: PermissionMode;
  readonly baseline: PlanBaselineScope;
  readonly oneCallDefault?: (invocation: ToolInvocationFacts) => PlanBaselineScope | undefined;
  /** Trusted shell grants added only to Bash and PowerShell operations. */
  readonly shellBaseline?: PlanBaselineScope;
  readonly networkCeiling?: NetworkScope;
  /** Host-approved extension. Defaults to the action's matching allow scopes. */
  readonly approvedScope?: (invocation: ToolInvocationFacts) => PlanApprovedScope;
  readonly configRevision: string;
  readonly backendId: string;
  readonly deadlineMs?: number;
  /** Explicit helper environment. Defaults to the allowlisted action environment. */
  readonly environment?: Readonly<Record<string, string>>;
  readonly environmentAllowlist?: readonly string[];
  readonly protectedPaths?: readonly string[];
  readonly protectedControlNames?: readonly string[];
  /** Host-approved shell interpreter recorded in shell plans. */
  readonly shell?: string;
  /** Host-owned canonicalizer for symlink/reparse-safe targets. */
  readonly resolvePath?: (path: string) => string | null;
  /** Read the live config revision so a capture from an older config cannot run. */
  readonly readConfigRevision?: () => string;
  readonly now?: () => number;
}

export function effectiveBaselineForOperation(
  baseline: PlanBaselineScope,
  shellBaseline: PlanBaselineScope | undefined,
  operation: ExecutionOperation,
): PlanBaselineScope {
  const isShell = operation.kind === "shell" ||
    (operation.kind === "builtin-tool" && (operation.name === "bash" || operation.name === "powershell"));
  if (!isShell || shellBaseline === undefined) return baseline;
  return Object.freeze({
    filesystem: Object.freeze([...baseline.filesystem, ...shellBaseline.filesystem]),
    network: intersectNetworkScopes(baseline.network, shellBaseline.network),
  });
}

export interface PiExecutionAdapterOptions {
  readonly controller: ExecutionController;
  readonly bindings: ToolInvocationBindingStore;
  readonly host: PiExecutionHostBinding;
  readonly owner: string;
  readonly bindingId: string;
  readonly plan: PiExecutionPlanOptions;
  /** Details returned when 04 blocks a call before the controlled executor. */
  readonly failureDetails?: unknown;
  readonly tools?: readonly ControlledToolName[];
  /**
   * Declared sandbox-hosted third-party tools (design §6). Each becomes one
   * controlled definition that runs the module in a one-shot worker.
   */
  readonly sandboxTools?: readonly SandboxToolSpec[];
  /**
   * Host-declared tools with their own trusted executor. This is an explicit
   * opt-in, never a default: restricted mode blocks everything else.
   */
  readonly ownsAdditionalTool?: (name: string) => boolean;
  /** Definition cwd fallback; Pi passes the live `ctx.cwd` at execute time. */
  readonly cwd?: string;
  /**
   * Upper bound on tool calls this adapter keeps outstanding at once. A call
   * counts from the moment its approval is taken until its own `finally`,
   * including the time it spends queued. When the bound is reached the adapter
   * refuses the next call instead of dropping an existing registration, so no
   * live call can lose its owner.
   */
  readonly maxOutstandingCalls?: number;
}

export interface PiExecutionAdapter {
  readonly definitions: readonly AnyToolDefinition[];
  readonly coverage: ExecutionCoverage;
  readonly mode: ExecutionModeDescription;
  /** Register controlled definitions and block every uncontrolled tool. */
  install(api: Pick<ExtensionAPI, "registerTool" | "on">): void;
  /** Drop captured approvals and cancel this session's executions. */
  clearSession(sessionId: string): Promise<void>;
  /** Drop captures and invalidate unstarted plans after a config change. */
  updateConfiguration(): Promise<void>;
  dispose(): Promise<void>;
  /**
   * Outstanding work this adapter still owns: sessions with a live lease,
   * captured approvals and in-flight tool calls. Each count falls back to zero
   * once nothing references it, which is how a host checks that capacity is
   * bounded without reading internal collections.
   */
  outstandingWork(): {
    readonly leasedSessions: number;
    readonly capturedExecutions: number;
    readonly activeCalls: number;
  };
}

/**
 * Pi's `ToolDefinition` renderers are contravariant in the parameter type, so a
 * heterogeneous list cannot be typed with the default schema parameter.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyToolDefinition = ToolDefinition<any, any, any>;

/**
 * One live claim on a session's identity.
 *
 * Identity is an object reference, not a counter: a counter that returns to a
 * previous value would let an old continuation look current again after its
 * session was cleared and reused. An invalidated lease is removed from the
 * index and can never be reinstalled, while a new approval for the same
 * session id is handed a different object.
 */
interface SessionLease {
  readonly sessionId: string;
  /** Set once and permanently. Continuations holding this lease are dead. */
  invalid: boolean;
  /** Pending verifications, captures and active calls still pointing here. */
  claims: number;
}

/**
 * The adapter state a call was approved against. Everything a later
 * continuation must re-check is captured here, before the first await, so an
 * invalidation cannot be revived by reading fresh values afterwards.
 */
interface CallIdentity {
  readonly adapterGeneration: number;
  readonly sessionId: string;
  readonly lease: SessionLease;
  readonly configRevision: string;
}

interface CapturedExecution extends CallIdentity {
  readonly invocation: ToolInvocationFacts;
  readonly policyRevision: string;
  readonly deadlineAt: number;
  /** Context of the original call: the only handle to the live policy owner. */
  readonly ctx: ExtensionToolContext;
}

interface ActiveCall extends CapturedExecution {
  readonly signal: AbortSignal;
}

/**
 * One in-flight tool call, cancellable while no helper is running.
 * The entry keeps the session claim so the call stays an outstanding,
 * capacity-consuming owner until its own `finally` releases it.
 */
interface ActiveCallEntry {
  readonly sessionId: string;
  readonly lease: SessionLease;
  readonly controller: AbortController;
}

const MAX_CAPTURED_EXECUTIONS = 64;
const MAX_ACTIVE_CALLS = 64;
/**
 * Upper bound on the passes {@link stableFacts} makes before declaring the
 * host unable to report one consistent set of revisions.
 */
const VALIDATION_SNAPSHOT_ATTEMPTS = 4;

function sessionIdOf(ctx: ExtensionToolContext): string | null {
  try {
    const sessionId = ctx.sessionManager.getSessionId();
    return typeof sessionId === "string" && sessionId.trim()
      ? sessionId.trim()
      : null;
  } catch {
    return null;
  }
}

/** Parse only simple `host` or `host:port` allow-scope targets. */
function networkDestination(target: string): NetworkDestination | null {
  const trimmed = target.trim().toLowerCase();
  if (!trimmed || trimmed === "*" || trimmed.includes("/")) return null;
  const match = /^([^:\s]+)(?::(\d{1,5}))?$/u.exec(trimmed);
  if (!match) return null;
  const host = match[1]!;
  if (!match[2]) return { host };
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) return null;
  return { host, port };
}

/**
 * A scope names a concrete target; its granularity follows the filesystem so a
 * directory target is not planned as a regular file.
 */
function pathGranularity(path: string): "file" | "directory" {
  try {
    return statSync(path).isDirectory() ? "directory" : "file";
  } catch {
    return "file";
  }
}

/**
 * Conservative default: only allow scopes of the exact action become approved
 * extensions. A host that knows real directory granularity must pass its own
 * `approvedScope`; this default never widens a scope.
 */
function approvedScopeFromInvocation(
  invocation: ToolInvocationFacts,
): PlanApprovedScope {
  const filesystem: FilesystemGrantInput[] = [];
  const network: NetworkDestination[] = [];
  for (const scope of invocation.action.scopes as readonly PermissionScope[]) {
    if (scope.state !== "allow") continue;
    if (scope.access === "read" || scope.access === "write") {
      const path = normalizeHostPath(scope.target);
      if (!path) continue;
      filesystem.push({
        path,
        access: scope.access,
        granularity: pathGranularity(path),
      });
      continue;
    }
    if (scope.access === "network") {
      const destination = networkDestination(scope.target);
      if (destination) network.push(destination);
    }
  }
  return {
    filesystem,
    ...(network.length === 0 ? {} : { network }),
  };
}

/**
 * Bind one controlled operation to the frozen approved action. This is a
 * second check after 04: a host must not be able to compile a plan whose
 * operation differs from the arguments that were approved.
 */
export function operationMatchesApprovedAction(
  invocation: ToolInvocationFacts,
  operation: ExecutionOperation,
): string | null {
  if (operation.kind === "builtin-tool") {
    return operation.name === invocation.action.tool.name &&
      jsonDigest(operation.arguments) === jsonDigest(invocation.action.effectiveArguments)
      ? null : "builtin tool or arguments differ from the approved invocation";
  }
  const args = invocation.action.effectiveArguments as Record<string, unknown>;
  const cwd = invocation.action.cwd;
  const toolName = invocation.action.tool.name;
  const expectedPath = (value: unknown): string | null => {
    if (typeof value !== "string" || !value.trim()) return null;
    return normalizeHostPath(resolve(cwd, value));
  };
  switch (toolName) {
    case "bash": {
      if (operation.kind !== "shell") return "bash approval requires a shell operation";
      return operation.command === args.command
        ? null
        : "shell command differs from the approved arguments";
    }
    case "read": {
      if (operation.kind !== "read-file" && operation.kind !== "access-file") {
        return "read approval requires a file read operation";
      }
      const path = expectedPath(args.path);
      if (!path) return "approved read path is invalid";
      return isSamePath(path, operation.path)
        ? null
        : "operation path differs from the approved read path";
    }
    case "write": {
      const path = expectedPath(args.path);
      if (!path) return "approved write path is invalid";
      if (operation.kind === "access-dir") {
        // The only directory this check may look at is the one holding the
        // approved file; anything else would be an unrelated directory probe.
        const directory = normalizeHostPath(dirname(path));
        return directory &&
          isSamePath(directory, operation.path) &&
          isSamePath(path, operation.forFile)
          ? null
          : "access-dir does not match the approved write target";
      }
      if (operation.kind === "mkdir") {
        const directory = normalizeHostPath(dirname(path));
        return directory && isSamePath(directory, operation.path)
          ? null
          : "mkdir path differs from the approved write path";
      }
      if (operation.kind !== "write-file") {
        return "write approval requires a file write operation";
      }
      if (!isSamePath(path, operation.path)) {
        return "operation path differs from the approved write path";
      }
      return operation.content === args.content
        ? null
        : "operation content differs from the approved write content";
    }
    case "edit": {
      if (
        operation.kind !== "read-file" &&
        operation.kind !== "access-file" &&
        operation.kind !== "write-file"
      ) {
        return "edit approval requires a file read/write operation";
      }
      const path = expectedPath(args.path);
      if (!path) return "approved edit path is invalid";
      return isSamePath(path, operation.path)
        ? null
        : "operation path differs from the approved edit path";
    }
    default:
      return null;
  }
}

function deadlineFor(
  captured: CapturedExecution,
  operation: ExecutionOperation,
  timeoutMs: number | undefined,
  now: number,
): number {
  const operationTimeout =
    timeoutMs ?? (operation.kind === "shell" ? operation.timeoutMs : undefined);
  const timeoutDeadline =
    operationTimeout === undefined ? Number.POSITIVE_INFINITY : now + operationTimeout;
  return Math.min(captured.deadlineAt, timeoutDeadline);
}

/**
 * User-facing reason for a failed sandbox tool outcome (design §6.4).
 *
 * Only the plan deadline is the documented per-call cap (`ABORT_REASONS` in
 * lifecycle.ts). The same `execution-timeout` code also carries the helper start
 * timeout (a literal "start timed out") and a deadline that expired before the
 * helper started (`callRefusal` below), which must keep their own text, so the
 * mapping is keyed on the exact reason.
 */
export function sandboxToolFailureReason(
  outcome: { readonly code: string; readonly reason: string },
): string {
  return outcome.code === "execution-timeout" && outcome.reason === "execution deadline expired"
    ? `sandbox tool timed out after ${SANDBOX_TOOL_TIMEOUT_MS / 1000}s`
    : outcome.reason;
}

/**
 * Create Pi-owned tool definitions backed by the trusted-helper executor and
 * reuse 04's final invocation binding. Full access registers nothing: this
 * module never claims a sandbox for that mode.
 */
export function createPiExecutionAdapter(
  options: PiExecutionAdapterOptions,
): PiExecutionAdapter {
  const mode = describeExecutionMode(options.plan.mode);
  const tools = Object.freeze([...(options.tools ?? DEFAULT_CONTROLLED_TOOLS)]);
  const uncontrolledBuiltins = Object.freeze(
    options.plan.mode === "full-access"
      ? [...UNCONTROLLED_BUILTIN_TOOLS, ...DEFAULT_CONTROLLED_TOOLS]
      : [
          ...UNCONTROLLED_BUILTIN_TOOLS,
          ...DEFAULT_CONTROLLED_TOOLS.filter((name) => !tools.includes(name)),
        ],
  );
  const coverage: ExecutionCoverage = Object.freeze({
    sandboxed: options.plan.mode !== "full-access",
    boundary: mode.boundary,
    controlled: options.plan.mode === "full-access" ? [] : tools,
    uncontrolledBuiltins,
    unsupported: UNSUPPORTED_EXECUTION_CATEGORIES,
    mcp: MCP_EXECUTION_COVERAGE,
  });

  if (options.plan.mode === "full-access") {
    return {
      definitions: [],
      coverage,
      mode,
      install: () => undefined,
      clearSession: async () => undefined,
      updateConfiguration: () => options.controller.updateConfiguration(),
      dispose: () => options.controller.dispose(),
      // Full access registers nothing and captures nothing, so this adapter
      // never owns outstanding work.
      outstandingWork: () => ({
        leasedSessions: 0,
        capturedExecutions: 0,
        activeCalls: 0,
      }),
    };
  }

  const modeWithSandbox = options.plan.mode;
  const now = options.plan.now ?? Date.now;
  const deadlineMs =
    options.plan.deadlineMs ?? DEFAULT_EXECUTION_DEADLINE_MS;
  const allowlist =
    options.plan.environmentAllowlist ?? DEFAULT_HELPER_ENVIRONMENT_ALLOWLIST;
  const readConfigRevision = (): string =>
    options.plan.readConfigRevision?.() ?? options.plan.configRevision;
  const resolvePath = options.plan.resolvePath ?? resolveHostPathIdentity;
  const maxOutstandingCalls = options.maxOutstandingCalls ?? MAX_ACTIVE_CALLS;
  if (
    !Number.isInteger(maxOutstandingCalls) ||
    maxOutstandingCalls < 1 ||
    maxOutstandingCalls > MAX_ACTIVE_CALLS
  ) {
    throw new Error("maxOutstandingCalls must be an integer within the module bound");
  }
  let adapterGeneration = 0;
  let disposed = false;
  const sessionLeases = new Map<string, SessionLease>();
  const captured = new Map<string, CapturedExecution>();
  const activeCalls = new Map<string, ActiveCallEntry>();
  const callStorage = new AsyncLocalStorage<ActiveCall>();

  function identityIsLive(identity: CallIdentity): boolean {
    return (
      !disposed &&
      identity.adapterGeneration === adapterGeneration &&
      !identity.lease.invalid &&
      sessionLeases.get(identity.sessionId) === identity.lease
    );
  }

  /**
   * Takes a claim on the session's current lease, issuing a new one when the
   * session has no live claim left. Callers must hand the claim to the next
   * stage or release it; the index only holds leases someone still references.
   */
  function acquireLease(sessionId: string): SessionLease | null {
    if (disposed) return null;
    let lease = sessionLeases.get(sessionId);
    if (!lease || lease.invalid) {
      lease = { sessionId, invalid: false, claims: 0 };
      sessionLeases.set(sessionId, lease);
    }
    lease.claims += 1;
    return lease;
  }

  function releaseLease(lease: SessionLease): void {
    lease.claims -= 1;
    if (lease.claims > 0) return;
    // Never drop a replacement lease for the same session id.
    if (sessionLeases.get(lease.sessionId) === lease) {
      sessionLeases.delete(lease.sessionId);
    }
  }

  /**
   * Marks the session's current lease dead and removes it from the index.
   * Clearing a session nobody has claimed is a no-op, so repeated idle clears
   * cannot accumulate history.
   */
  function invalidateLease(sessionId: string): void {
    const lease = sessionLeases.get(sessionId);
    if (!lease) return;
    lease.invalid = true;
    sessionLeases.delete(sessionId);
  }

  /** Snapshot the live state. Call this before any await, never after one. */
  function captureIdentity(sessionId: string): CallIdentity | null {
    const lease = acquireLease(sessionId);
    if (!lease) return null;
    const capturedAdapterGeneration = adapterGeneration;
    let configRevision: string;
    try {
      configRevision = readConfigRevision();
    } catch {
      releaseLease(lease);
      return null;
    }
    const identity = {
      adapterGeneration: capturedAdapterGeneration,
      sessionId,
      lease,
      configRevision,
    };
    if (identityIsLive(identity)) return identity;
    releaseLease(lease);
    return null;
  }

  /** The same policy owner 04 reads; missing or throwing blocks execution. */
  function livePolicyRevision(call: CapturedExecution): string | null {
    try {
      const value = options.host.readCurrentScopeRevision(call.ctx);
      return typeof value === "string" && value.trim() ? value : null;
    } catch {
      return null;
    }
  }

  /**
   * Reads every live validity fact until two consecutive passes agree.
   *
   * One pass cannot prove stability: a reader is allowed to advance another
   * revision as its own observable effect, so the value read before that call
   * is already stale. Two identical passes prove nothing moved during them.
   * Hosts that keep moving a revision on every read never stabilise, and this
   * returns `null` after a bounded number of passes instead of looping.
   */
  function stableFacts(
    sessionId: string,
    readPolicy: () => string | null,
  ): {
    readonly policyRevision: string;
    readonly configRevision: string;
  } | null {
    let previous: {
      readonly adapterGeneration: number;
      readonly lease: SessionLease;
      readonly policyRevision: string;
      readonly configRevision: string;
    } | null = null;
    for (let attempt = 0; attempt < VALIDATION_SNAPSHOT_ATTEMPTS; attempt += 1) {
      const seenAdapterGeneration = adapterGeneration;
      const seenLease = sessionLeases.get(sessionId);
      if (disposed || !seenLease || seenLease.invalid) return null;
      const policyRevision = readPolicy();
      if (policyRevision === null) return null;
      let configRevision: string;
      try {
        configRevision = readConfigRevision();
      } catch {
        return null;
      }
      const current = {
        adapterGeneration: seenAdapterGeneration,
        lease: seenLease,
        policyRevision,
        configRevision,
      };
      if (
        previous !== null &&
        previous.adapterGeneration === current.adapterGeneration &&
        previous.lease === current.lease &&
        previous.policyRevision === current.policyRevision &&
        previous.configRevision === current.configRevision
      ) {
        return current;
      }
      previous = current;
    }
    return null;
  }

  /**
   * Why this call may no longer execute, or `null` while it still may.
   * Every fact that can expire between two operations of one call is re-read
   * as one stable snapshot, both before compiling and before the helper starts.
   */
  function callRefusal(
    call: CapturedExecution,
    deadlineAt?: number,
  ): ValidityRefusal | null {
    if (!identityIsLive(call)) {
      return {
        code: "plan-invalidated",
        reason: "session or configuration was invalidated after approval",
      };
    }
    const facts = stableFacts(call.sessionId, () => livePolicyRevision(call));
    if (facts === null) {
      return {
        code: "plan-invalidated",
        reason:
          "the current policy and configuration revisions could not be read as one stable snapshot",
      };
    }
    if (facts.policyRevision !== call.policyRevision) {
      return {
        code: "plan-invalidated",
        reason: "policy revision changed after approval",
      };
    }
    if (facts.configRevision !== call.configRevision) {
      return {
        code: "plan-invalidated",
        reason: "configuration changed after approval",
      };
    }
    if (!identityIsLive(call)) {
      return {
        code: "plan-invalidated",
        reason: "session or configuration changed during validation",
      };
    }
    if (deadlineAt !== undefined && deadlineAt <= now()) {
      return {
        code: "execution-timeout",
        reason: "plan deadline expired before the helper started",
      };
    }
    return null;
  }

  function assertCallLive(call: CapturedExecution): void {
    const refusal = callRefusal(call);
    if (refusal) {
      throw new ControlledOperationError(refusal.code, refusal.reason);
    }
  }

  function invalidateActiveCalls(
    code: CancellationCode,
    matches: (sessionId: string) => boolean,
  ): void {
    for (const entry of activeCalls.values()) {
      if (!matches(entry.sessionId)) continue;
      // The entry stays registered: the call is still real outstanding work
      // until it settles. The code travels as the abort reason so the
      // execution record keeps the real cause instead of reporting a session
      // clear as a user cancel.
      entry.controller.abort(code);
    }
  }

  /**
   * Registers the call, refusing when the key is taken or the bound is reached.
   * Evicting a registration instead of refusing would silently drop the owner
   * of live work and let capacity grow without limit.
   */
  function registerActiveCall(key: string, entry: ActiveCallEntry): boolean {
    if (activeCalls.has(key)) return false;
    if (activeCalls.size >= maxOutstandingCalls) return false;
    activeCalls.set(key, entry);
    return true;
  }

  function clearCaptured(matches: (key: string) => boolean): void {
    for (const [key, entry] of [...captured]) {
      if (!matches(key)) continue;
      captured.delete(key);
      releaseLease(entry.lease);
    }
  }
  function captureKey(sessionId: string, toolCallId: string): string {
    return correlationKey(sessionId, toolCallId);
  }

  /** Drops a capture and hands back the session claim it was holding. */
  function releaseCaptured(key: string): void {
    const existing = captured.get(key);
    if (!existing) return;
    captured.delete(key);
    releaseLease(existing.lease);
  }

  function remember(
    invocation: ToolInvocationFacts,
    revision: string,
    identity: CallIdentity,
    ctx: ExtensionToolContext,
  ): void {
    const key = captureKey(identity.sessionId, invocation.action.toolCallId);
    releaseCaptured(key);
    captured.set(key, {
      ...identity,
      invocation,
      policyRevision: revision,
      deadlineAt: now() + deadlineMs,
      ctx,
    });
    // The claim taken for the verification now belongs to this capture.
    while (captured.size > MAX_CAPTURED_EXECUTIONS) {
      const oldest = captured.keys().next().value;
      if (typeof oldest !== "string" || oldest === key) break;
      releaseCaptured(oldest);
    }
  }

  function take(
    sessionId: string,
    toolCallId: string,
  ): CapturedExecution | undefined {
    const key = captureKey(sessionId, toolCallId);
    const entry = captured.get(key);
    if (!entry) return undefined;
    captured.delete(key);
    if (!identityIsLive(entry) || entry.deadlineAt <= now()) {
      releaseLease(entry.lease);
      return undefined;
    }
    // The capture's claim transfers to the active-call registration below.
    return entry;
  }

  async function runOperation(
    call: ActiveCall,
    operation: ExecutionOperation,
    runOptions: OperationRunOptions,
  ): Promise<ExecutionOutcome> {
    if (runOptions.cwd !== undefined) {
      const approvedCwd = normalizeHostPath(call.invocation.action.cwd);
      const requestedCwd = normalizeHostPath(runOptions.cwd);
      if (!approvedCwd || !requestedCwd || !isSamePath(approvedCwd, requestedCwd)) {
        throw new ControlledOperationError(
          "invalid-plan",
          "tool cwd changed after approval",
        );
      }
    }
    if (runOptions.signal?.aborted || call.signal.aborted) {
      throw new ControlledOperationError("aborted", "request was aborted");
    }
    assertCallLive(call);
    const mismatch = operationMatchesApprovedAction(call.invocation, operation);
    if (mismatch) {
      throw new ControlledOperationError(
        "action-changed-before-execution",
        mismatch,
      );
    }
    const current = now();
    const deadlineAt = deadlineFor(
      call,
      operation,
      runOptions.timeoutMs,
      current,
    );
    if (deadlineAt <= current) {
      throw new ControlledOperationError(
        "sandbox-deadline-exceeded",
        "plan deadline has passed",
      );
    }
    const environment =
      options.plan.environment ??
      selectExecutionEnvironment(call.invocation.action.environment, allowlist);
    const environmentCheck = filterExecutionEnvironment(environment, allowlist);
    if (!environmentCheck.ok) {
      throw new ControlledOperationError(
        "environment-not-allowed",
        environmentCheck.reason,
      );
    }
    const requestedApproval = options.plan.approvedScope?.(call.invocation) ?? approvedScopeFromInvocation(call.invocation);
    const oneCallDefault = options.plan.oneCallDefault?.(call.invocation);
    const baseline = effectiveBaselineForOperation(oneCallDefault ?? options.plan.baseline, options.plan.shellBaseline, operation);
    const approved = {
      ...requestedApproval,
      filesystem: requestedApproval.filesystem.filter(grant => !baseline.filesystem.some(baselineGrant =>
        baselineGrant.access === grant.access && (baselineGrant.granularity === "directory"
          ? isPathWithin(baselineGrant.path, grant.path) : isSamePath(baselineGrant.path, grant.path)))),
    };
    if (operation.kind === "builtin-tool" && operation.name === "write") {
      const path = builtinToolPath(operation.name, String(operation.arguments.path), call.invocation.action.cwd);
      const parent = dirname(path);
      if (!existsSync(parent) && ![...baseline.filesystem, ...approved.filesystem].some(grant =>
        grant.access === "write" && grant.granularity === "directory" && isPathWithin(grant.path, parent))) {
        throw new ControlledOperationError("scope-expansion", "creating the target parent requires an approved directory grant");
      }
    }
    const compiled = compileExecutionPlan({
      invocation: call.invocation,
      operation,
      mode: oneCallDefault === undefined ? modeWithSandbox : "default",
      owner: options.owner,
      bindingId: options.bindingId,
      baseline,
      ...(options.plan.networkCeiling === undefined ? {} : { networkCeiling: options.plan.networkCeiling }),
      approved,
      backendId: options.plan.backendId,
      policyRevision: call.policyRevision,
      configRevision: call.configRevision,
      deadlineAt,
      now: current,
      environment: environmentCheck.environment,
      environmentAllowlist: allowlist,
      ...(options.plan.protectedPaths === undefined ? {} : { protectedPaths: options.plan.protectedPaths }),
      expectedToolRevision: call.invocation.action.tool.revision,
      ...(options.plan.shell === undefined ? {} : { shell: options.plan.shell }),
      resolvePath,
      ...(options.plan.protectedControlNames === undefined
        ? {}
        : { protectedControlNames: options.plan.protectedControlNames }),
    });
    if (!compiled.ok) {
      throw new ControlledOperationError(compiled.code, compiled.reason);
    }
    // Compilation ran host-owned callbacks (approved-scope derivation and path
    // identity resolution) that can re-enter and invalidate this call.
    assertCallLive(call);
    if (call.signal.aborted || runOptions.signal?.aborted) {
      throw new ControlledOperationError("aborted", "request was aborted");
    }
    const signal = runOptions.signal ?? call.signal;
    const executeInput = {
      plan: compiled.plan,
      ...(signal === undefined ? {} : { signal }),
      // The checks above only describe the moment they ran. This task may then
      // wait in the queue and in the handshake, so the controller re-reads the
      // same facts after each wait it owns: once before a process exists and
      // once before the business start is sent.
      validity: createExecutionValidityGuard(() => callRefusal(call, deadlineAt)),
      ...(runOptions.onOutput === undefined
        ? {}
        : { onOutput: runOptions.onOutput }),
    };
    return options.controller.execute(executeInput);
  }

  const cwd = options.cwd ?? process.cwd();

  function controlledDefinition<TParams extends TSchema, TDetails, TState>(
    original: ToolDefinition<TParams, TDetails, TState>,
  ): ToolDefinition<TParams, TDetails, TState> {
    const execute = original.execute;
    const wrapper: ToolDefinition<TParams, TDetails, TState> = {
      ...original,
      execute: async (toolCallId, params, signal, onUpdate, ctx) => {
        const sessionId = sessionIdOf(ctx);
        if (!sessionId) {
          throw new ControlledOperationError(
            "requester-unavailable",
            "requester session is unavailable",
          );
        }
        const entry = take(sessionId, toolCallId);
        if (!entry) {
          throw new ControlledOperationError(
            "approved-action-unavailable",
            "no captured approval matches this tool call",
          );
        }
        if (signal?.aborted) {
          releaseLease(entry.lease);
          throw new ControlledOperationError("aborted", "request was aborted");
        }
        try {
          assertCallLive(entry);
        } catch (error) {
          releaseLease(entry.lease);
          throw error;
        }
        // The call owns a cancellation source of its own: an invalidation can
        // arrive while no helper is running, between two SDK sub-operations.
        const callController = new AbortController();
        const forwardAbort = () => callController.abort();
        if (signal) signal.addEventListener("abort", forwardAbort, { once: true });
        const key = captureKey(sessionId, toolCallId);
        const owner: ActiveCallEntry = {
          sessionId,
          lease: entry.lease,
          controller: callController,
        };
        if (!registerActiveCall(key, owner)) {
          if (signal) signal.removeEventListener("abort", forwardAbort);
          releaseLease(entry.lease);
          throw new ControlledOperationError(
            "sandbox-queue-full",
            activeCalls.has(key)
              ? "a controlled call with the same session and tool call id is already outstanding"
              : "this adapter has no room left for another outstanding controlled call",
          );
        }
        try {
          return await callStorage.run(
            { ...entry, signal: callController.signal },
            () => execute.call(original, toolCallId, params, signal, onUpdate, ctx),
          );
        } finally {
          if (signal) signal.removeEventListener("abort", forwardAbort);
          // Release only this registration: a later call may already own the
          // same key, and an invalidation must not have dropped the owner.
          if (activeCalls.get(key) === owner) activeCalls.delete(key);
          releaseLease(owner.lease);
        }
      },
    };
    const bound = bindOwnedToolExecution(wrapper, {
      owner: options.owner,
      bindingId: options.bindingId,
      failureDetails: options.failureDetails as TDetails,
      bindings: options.bindings,
      getAllTools: () => options.host.getAllTools(),
      readRequester: (ctx) => options.host.readRequester(ctx),
      readEnvironment: (ctx) => options.host.readEnvironment(ctx),
      verifyScope: async (invocation, ctx, approvedRevision) => {
        // Capture the identity before the first await. Reading the live config
        // or session state afterwards would adopt whatever an invalidation had
        // already replaced.
        const identity = captureIdentity(invocation.requester.sessionId);
        if (!identity) return { allowed: false as const };
        let claimed = false;
        try {
          const result = await options.host.verifyScope(
            invocation,
            ctx,
            approvedRevision,
          );
          if (!identityIsLive(identity)) {
            // A session or configuration invalidation raced this verification.
            // It must not recreate the capture it just dropped.
            return { allowed: false as const };
          }
          if (
            result &&
            result.allowed === true &&
            typeof result.revision === "string" &&
            result.revision.trim()
          ) {
            remember(invocation, result.revision, identity, ctx);
            // The capture now holds the claim this verification took.
            claimed = true;
          }
          return result;
        } finally {
          if (!claimed) releaseLease(identity.lease);
        }
      },
      readCurrentScopeRevision: (ctx) =>
        options.host.readCurrentScopeRevision(ctx),
    });
    return bound;
  }

  const factories: Record<ControlledToolName, () => AnyToolDefinition> = {
    bash: () => createBashToolDefinition(cwd),
    powershell: () => createPowerShellToolDefinition(cwd),
    read: () => createReadToolDefinition(cwd),
    write: () => createWriteToolDefinition(cwd),
    edit: () => createEditToolDefinition(cwd),
    grep: () => createGrepToolDefinition(cwd),
    find: () => createFindToolDefinition(cwd),
    ls: () => createLsToolDefinition(cwd),
  };

  function builtinDefinition(name: ControlledToolName): AnyToolDefinition {
    const original = factories[name]();
    return controlledDefinition({ ...original, execute: async (id, args, signal, onUpdate, ctx) => {
      const run = async () => {
        const call = callStorage.getStore();
        if (!call) throw new ControlledOperationError("approved-action-unavailable", "builtin ran outside a bound call");
        let pending = "";
        const context = freezeJson({
          sessionId: ctx.sessionManager.getSessionId(),
          ...(options.plan.backendId === "windows-mxc" && (name === "write" || name === "edit")
            ? { mutationQueuePath: builtinToolPath(name, (args as { path: string }).path, ctx.cwd) } : {}),
          ...(ctx.sessionManager.getSessionFile() === undefined ? {} : { sessionFile: ctx.sessionManager.getSessionFile() }),
          ...(ctx.model === undefined ? {} : { model: { id: ctx.model.id, provider: ctx.model.provider, input: ctx.model.input,
            ...(ctx.model.inputLimits === undefined ? {} : { inputLimits: ctx.model.inputLimits }) } }),
        }) as JsonObject;
        const timeout = (args as { timeout?: unknown }).timeout;
        const outcome = await runOperation(call, { kind: "builtin-tool", name, arguments: freezeJson(args) as JsonObject, context }, {
          signal: call.signal, cwd: ctx.cwd,
          ...(options.plan.backendId === "windows-mxc" && (name === "bash" || name === "powershell") &&
            typeof timeout === "number" && Number.isFinite(timeout) && timeout > 0
            ? { timeoutMs: Math.ceil(timeout * 1000) } : {}),
          onOutput: chunk => {
            if (chunk.stream !== "stdout") return;
            pending += chunk.data;
            let end: number;
            while ((end = pending.indexOf("\n")) >= 0) {
              const line = pending.slice(0, end); pending = pending.slice(end + 1);
              if (line) onUpdate?.(JSON.parse(line));
            }
          },
        });
        if (outcome.state !== "completed" && !(outcome.code === "execution-failed" && outcome.dataBase64)) {
          throw new ControlledOperationError(outcome.code, outcome.reason);
        }
        if (!outcome.dataBase64) throw new ControlledOperationError("sandbox-protocol-error", "builtin result is missing");
        const envelope = JSON.parse(Buffer.from(outcome.dataBase64, "base64").toString("utf8"));
        if (typeof envelope.error === "string") throw new Error(formatPiSandboxError(envelope.error));
        if (!envelope.result || !Array.isArray(envelope.result.content)) throw new ControlledOperationError("sandbox-protocol-error", "builtin result is invalid");
        if (outcome.state !== "completed" && envelope.result.isError !== true) throw new ControlledOperationError(outcome.code, outcome.reason);
        return envelope.result;
      };
      if (name === "write" || name === "edit") {
        const path = resolveHostPathIdentity(builtinToolPath(name, (args as { path: string }).path, ctx.cwd));
        if (!path) throw new ControlledOperationError("invalid-plan", "mutation target cannot be resolved");
        return withFileMutationQueue(process.platform === "win32" ? path.toLowerCase() : path, run);
      }
      return run();
    } });
  }

  /**
   * One declared sandbox tool (design §6): the worker loads the module by path
   * and returns the module's own result envelope, so nothing is imported here.
   */
  function sandboxToolDefinition(spec: SandboxToolSpec): AnyToolDefinition {
    const fields = sandboxToolDefinitionFields(spec);
    return controlledDefinition({
      ...fields,
      execute: async (
        _id: string,
        args: unknown,
        signal: AbortSignal | undefined,
        onUpdate: ((update: unknown) => void) | undefined,
        ctx: ExtensionToolContext,
      ) => {
        const call = callStorage.getStore();
        if (!call) throw new ControlledOperationError("approved-action-unavailable", "sandbox tool ran outside a bound call");
        let pending = "";
        const outcome = await runOperation(call, {
          kind: "sandbox-tool",
          name: spec.name,
          modulePath: spec.modulePath,
          stateDirectory: spec.stateDirectory,
          arguments: freezeJson(args) as JsonObject,
          ...(spec.config === undefined ? {} : { config: spec.config }),
          context: freezeJson({
            sessionId: ctx.sessionManager.getSessionId(),
            ...(ctx.sessionManager.getSessionFile() === undefined ? {} : { sessionFile: ctx.sessionManager.getSessionFile() }),
          }) as JsonObject,
        }, {
          signal: call.signal,
          cwd: ctx.cwd,
          timeoutMs: SANDBOX_TOOL_TIMEOUT_MS,
          onOutput: chunk => {
            if (chunk.stream !== "stdout") return;
            pending += chunk.data;
            let end: number;
            while ((end = pending.indexOf("\n")) >= 0) {
              const line = pending.slice(0, end);
              pending = pending.slice(end + 1);
              if (line) onUpdate?.(JSON.parse(line));
            }
          },
        });
        if (outcome.state !== "completed" && !(outcome.code === "execution-failed" && outcome.dataBase64)) {
          throw new ControlledOperationError(outcome.code, sandboxToolFailureReason(outcome));
        }
        if (!outcome.dataBase64) throw new ControlledOperationError("sandbox-protocol-error", "sandbox tool result is missing");
        const envelope = JSON.parse(Buffer.from(outcome.dataBase64, "base64").toString("utf8"));
        if (typeof envelope.error === "string") throw new Error(formatPiSandboxError(envelope.error));
        if (!envelope.result || !Array.isArray(envelope.result.content)) {
          throw new ControlledOperationError("sandbox-protocol-error", "sandbox tool result is invalid");
        }
        return envelope.result;
      },
    } as unknown as Parameters<typeof controlledDefinition>[0]) as AnyToolDefinition;
  }

  const definitions = Object.freeze([
    ...tools.map((name) => builtinDefinition(name)),
    ...(options.sandboxTools ?? []).map((spec) => sandboxToolDefinition(spec)),
  ]);

  return {
    definitions,
    coverage,
    mode,
    install(api) {
      for (const definition of definitions) api.registerTool(definition);
      // Restricted mode is allowlist-only: a tool without controlled
      // operations would execute in the Pi Node process. A host may explicitly
      // vouch for another executor, but silence is never permission.
      api.on("tool_call", (event) => {
        if (tools.includes(event.toolName as ControlledToolName)) return undefined;
        if (options.ownsAdditionalTool?.(event.toolName) === true) return undefined;
        return {
          block: true,
          reason: `[sandbox-uncontrolled] ${event.toolName} has no controlled operations in ${modeWithSandbox} mode`,
        };
      });
    },
    async clearSession(sessionId) {
      // Invalidate synchronously before any await: a continuation that is
      // already running must see its own lease dead, and a later approval that
      // reuses this session id is handed a different object.
      invalidateLease(sessionId);
      const prefix = correlationKey(sessionId, "");
      clearCaptured((key) => key.startsWith(prefix));
      invalidateActiveCalls("session-disposed", (activeSession) => activeSession === sessionId);
      options.bindings.clearSession(sessionId);
      await options.controller.cancelSession(sessionId, "session disposed");
    },
    async updateConfiguration() {
      // The generation is shared by every session, so one increment retires
      // all leases at once. Leases that nobody references any more are already
      // absent from the index.
      adapterGeneration += 1;
      clearCaptured(() => true);
      invalidateActiveCalls("plan-invalidated", () => true);
      await options.controller.updateConfiguration();
    },
    async dispose() {
      disposed = true;
      clearCaptured(() => true);
      invalidateActiveCalls("session-disposed", () => true);
      for (const sessionId of [...sessionLeases.keys()]) invalidateLease(sessionId);
      sessionLeases.clear();
      await options.controller.dispose();
    },
    outstandingWork() {
      return {
        leasedSessions: sessionLeases.size,
        capturedExecutions: captured.size,
        activeCalls: activeCalls.size,
      };
    },
  };
}
