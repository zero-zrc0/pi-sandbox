import type {
  AgentToolResult,
  ExtensionToolContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { formatPiSandboxError } from "../error-format";

import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
  toolInvocationDigestMatches,
  type InvocationRequester,
  type ToolInvocationFacts,
} from "../invocation";

interface PendingBinding {
  readonly requesterSessionId: string;
  readonly toolCallId: string;
  readonly invocation: ToolInvocationFacts;
  readonly scopeRevision: string;
}

export interface AuthorizedToolInvocation {
  readonly invocation: ToolInvocationFacts;
  /** Policy revision used when the final permission scope was approved. */
  readonly scopeRevision: string;
}

/** The scope resolver returns the current revision it evaluated. */
export type ScopeVerification =
  | { readonly allowed: true; readonly revision: string }
  | { readonly allowed: false; readonly revision?: string };

type CurrentInvocationCapture =
  | { readonly ok: true; readonly invocation: ToolInvocationFacts }
  | { readonly ok: false; readonly reason: "unavailable" | "invalid" };

/** One-shot store between a successful gate decision and an owned execute. */
export class ToolInvocationBindingStore {
  private readonly pending = new Map<string, PendingBinding>();

  /** Record only a complete, digest-valid action with a plugin-owned executor. */
  authorize(invocation: ToolInvocationFacts, scopeRevision: string): boolean {
    if (!toolInvocationDigestMatches(invocation)) return false;
    if (typeof scopeRevision !== "string" || !scopeRevision.trim()) return false;
    const binding = invocation.executionBinding;
    if (
      binding.status !== "bound" ||
      binding.toolName !== invocation.action.tool.name ||
      binding.revision !== invocation.action.tool.revision
    ) {
      return false;
    }
    const key = bindingKey(
      invocation.requester.sessionId,
      invocation.action.toolCallId,
    );
    if (this.pending.has(key)) return false;
    this.pending.set(key, {
      requesterSessionId: invocation.requester.sessionId,
      toolCallId: invocation.action.toolCallId,
      invocation,
      scopeRevision,
    });
    return true;
  }

  /** Consume a matching authorization once. */
  take(
    requesterSessionId: string,
    toolCallId: string,
  ): AuthorizedToolInvocation | undefined {
    const key = bindingKey(requesterSessionId, toolCallId);
    const entry = this.pending.get(key);
    if (!entry) return undefined;
    this.pending.delete(key);
    return {
      invocation: entry.invocation,
      scopeRevision: entry.scopeRevision,
    };
  }

  /** Drop every unused authorization owned by a session. */
  clearSession(requesterSessionId: string): void {
    for (const [key, entry] of this.pending) {
      if (entry.requesterSessionId === requesterSessionId) {
        this.pending.delete(key);
      }
    }
  }
}

export interface OwnedToolExecutionOptions<TDetails> {
  readonly owner: string;
  readonly bindingId: string;
  /** A tool-specific result detail value for fail-closed blocked calls. */
  readonly failureDetails: TDetails;
  readonly bindings: ToolInvocationBindingStore;
  /** Current public Pi `getAllTools()` snapshot, read at execute time. */
  getAllTools(): readonly unknown[];
  /** Current requester and environment facts, read at execute time. */
  readRequester(ctx: ExtensionToolContext): InvocationRequester;
  readEnvironment(ctx: ExtensionToolContext): unknown;
  /**
   * Re-resolve the exact pending scope under current policy. After any async
   * lookup, return the revision actually evaluated; changed policy blocks.
   */
  verifyScope(
    invocation: ToolInvocationFacts,
    ctx: ExtensionToolContext,
    approvedRevision: string,
  ): ScopeVerification | Promise<ScopeVerification>;
  /**
   * Synchronously read the live revision from the same policy owner as
   * `verifyScope`. Missing values or throws block execution.
   */
  readCurrentScopeRevision(ctx: ExtensionToolContext): string | undefined;
  readonly executeAuthorized?: (
    invocation: ToolInvocationFacts,
    execute: () => Promise<AgentToolResult<TDetails>>,
  ) => Promise<AgentToolResult<TDetails>>;
}

/**
 * Wrap a tool definition owned by this plugin. Its original `execute` is
 * reached only after the final parameters, requester, cwd, environment,
 * registered definition, and pending permission scope still match the action
 * approved earlier. This cannot wrap a definition owned by another extension.
 */
export function bindOwnedToolExecution<
  TParams extends TSchema,
  TDetails,
  TState,
>(
  definition: ToolDefinition<TParams, TDetails, TState>,
  options: OwnedToolExecutionOptions<TDetails>,
): ToolDefinition<TParams, TDetails, TState> {
  const execute = definition.execute;
  const toolName = definition.name;
  const parameters = definition.parameters;
  // Keep the trusted readers fixed; each callback must still read live facts.
  const {
    owner,
    bindingId,
    failureDetails,
    bindings,
    getAllTools,
    readRequester,
    readEnvironment,
    verifyScope,
    readCurrentScopeRevision,
  } = options;
  return {
    ...definition,
    execute: async (toolCallId, params, signal, onUpdate, ctx) => {
      const requesterSessionId = readSessionId(ctx);
      if (!requesterSessionId) {
        return executionError("requester-unavailable", failureDetails);
      }
      const authorization = bindings.take(requesterSessionId, toolCallId);
      if (
        !authorization ||
        !toolInvocationDigestMatches(authorization.invocation)
      ) {
        return executionError("approved-action-unavailable", failureDetails);
      }
      const approved = authorization.invocation;
      const binding = approved.executionBinding;
      if (
        binding.status !== "bound" ||
        binding.owner !== owner ||
        binding.bindingId !== bindingId ||
        binding.toolName !== toolName ||
        binding.revision !== approved.action.tool.revision
      ) {
        return executionError("execute-binding-changed", failureDetails);
      }

      const captureCurrentInvocation = (): CurrentInvocationCapture => {
        try {
          const seed = captureToolInvocationSeed({
            event: {
              type: "tool_call",
              toolName,
              toolCallId,
              ...(approved.action.parentToolCallId === undefined
                ? {}
                : { parentToolCallId: approved.action.parentToolCallId }),
              input: params,
            },
            registeredTools: getAllTools(),
            cwd: ctx.cwd,
            requester: readRequester(ctx),
            environment: readEnvironment(ctx),
          });
          if (!seed.ok) return { ok: false, reason: "unavailable" };
          const captured = finalizeToolInvocation(seed.seed, {
            requestId: approved.action.requestId,
            scopes: approved.action.scopes,
            executionBinding: binding,
          });
          return captured.ok
            ? { ok: true, invocation: captured.invocation }
            : { ok: false, reason: "invalid" };
        } catch {
          return { ok: false, reason: "unavailable" };
        }
      };

      const initial = captureCurrentInvocation();
      if (!initial.ok) {
        return executionError(
          initial.reason === "invalid"
            ? "action-facts-invalid"
            : "action-facts-unavailable",
          failureDetails,
        );
      }
      if (initial.invocation.digest !== approved.digest) {
        return executionError(
          "action-changed-before-execution",
          failureDetails,
        );
      }
      let verifiedScopeRevision: string;
      try {
        const scopeVerification = await verifyScope(
          approved,
          ctx,
          authorization.scopeRevision,
        );
        if (!scopeVerification || scopeVerification.allowed !== true) {
          return executionError("permission-scope-changed", failureDetails);
        }
        if (scopeVerification.revision !== authorization.scopeRevision) {
          return executionError(
            "permission-policy-revision-changed",
            failureDetails,
          );
        }
        verifiedScopeRevision = scopeVerification.revision;
      } catch {
        return executionError("permission-scope-unavailable", failureDetails);
      }

      // The scope check can wait while Pi's mutable tool-call data changes.
      // Re-read current host facts after that final await and pass the
      // immutable approved parameters to the owned executor.
      if (signal?.aborted) {
        return executionError("execution-cancelled-before-start", failureDetails);
      }
      const current = captureCurrentInvocation();
      if (!current.ok) {
        return executionError(
          current.reason === "invalid"
            ? "action-facts-invalid"
            : "action-facts-unavailable",
          failureDetails,
        );
      }
      if (current.invocation.digest !== approved.digest) {
        return executionError(
          "action-changed-before-execution",
          failureDetails,
        );
      }
      const currentRequesterSessionId = readSessionId(ctx);
      if (
        !currentRequesterSessionId ||
        currentRequesterSessionId !== requesterSessionId
      ) {
        return executionError(
          "requester-changed-before-execution",
          failureDetails,
        );
      }

      const approvedArguments = approved.action.effectiveArguments;
      if (!Value.Check(parameters, approvedArguments)) {
        return executionError("approved-action-invalid", failureDetails);
      }
      if (signal?.aborted) {
        return executionError("execution-cancelled-before-start", failureDetails);
      }

      let currentScopeRevision: string | undefined;
      try {
        currentScopeRevision = readCurrentScopeRevision(ctx);
      } catch {
        return executionError(
          "permission-policy-revision-unavailable",
          failureDetails,
        );
      }
      if (
        typeof currentScopeRevision !== "string" ||
        !currentScopeRevision.trim()
      ) {
        return executionError(
          "permission-policy-revision-unavailable",
          failureDetails,
        );
      }
      if (
        currentScopeRevision !== authorization.scopeRevision ||
        currentScopeRevision !== verifiedScopeRevision
      ) {
        return executionError(
          "permission-policy-revision-changed",
          failureDetails,
        );
      }

      const executeApproved = () => execute.call(
        definition,
        toolCallId,
        approvedArguments,
        signal,
        onUpdate,
        ctx,
      );
      return options.executeAuthorized === undefined
        ? executeApproved()
        : options.executeAuthorized(approved, executeApproved);
    },
  };
}

function readSessionId(ctx: ExtensionToolContext): string | null {
  try {
    const sessionId = ctx.sessionManager.getSessionId();
    return typeof sessionId === "string" && sessionId.trim()
      ? sessionId.trim()
      : null;
  } catch {
    return null;
  }
}

function bindingKey(requesterSessionId: string, toolCallId: string): string {
  return JSON.stringify([requesterSessionId, toolCallId]);
}

function executionError<TDetails>(
  reason: string,
  details: TDetails,
): AgentToolResult<TDetails> {
  return {
    content: [
      { type: "text", text: formatPiSandboxError(`Permission binding blocked execution: ${reason}`) },
    ],
    isError: true,
    details,
  };
}
