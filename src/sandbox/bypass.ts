import type {
  ExtensionAPI,
  ExtensionContext,
  ExtensionToolContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Type, type Static, type TSchema } from "typebox";
import { Value } from "typebox/value";
import { freezeJson, jsonDigest, type JsonObject } from "../json";
import type { PermissionMode } from "../contracts";
import type { SandboxBypassReviewInput } from "#approve-core/host";

export const SANDBOX_BYPASS_TOOL_NAME = "request_sandbox_bypass";

type Block = { readonly block: true; readonly reason: string };
type ToolInfo = ReturnType<ExtensionAPI["getAllTools"]>[number];
type CallableTool = ExtensionToolContext["tools"][number];
type HostToolDefinition = ToolDefinition<any, any, any>;

interface PreparedRequest {
  readonly targetToolCallId: string;
  readonly sessionId: string;
  readonly targetToolName: string;
  readonly arguments: JsonObject;
  readonly reason: string;
  readonly schema: TSchema;
  readonly sourcePath: string;
  readonly exposure: ToolInfo["exposure"];
  readonly hostTool: HostToolDefinition;
  readonly hostExecute: HostToolDefinition["execute"];
  readonly mode: PermissionMode;
  readonly policyRevision: string;
}

export interface SandboxBypassOptions {
  readonly mode: (ctx: ExtensionContext) => PermissionMode;
  readonly policyRevision: (ctx: ExtensionContext) => string;
  readonly resolveHostTool: (
    name: string,
    schema: TSchema,
  ) => HostToolDefinition | undefined;
  readonly recordExecution: (input: {
    readonly sessionId: string;
    readonly toolCallId: string;
    readonly targetToolName: string;
    readonly actionDigest: string;
    readonly state: "completed" | "failed";
    readonly impact: "known" | "unknown";
    readonly code?: string;
  }) => void;
}

const parameters = Type.Object({
  reason: Type.String(),
  toolName: Type.String(),
  arguments: Type.Record(Type.String(), Type.Any()),
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function copyJsonObject(value: unknown): JsonObject | undefined {
  try {
    const copy = freezeJson(value);
    return isRecord(copy) ? copy as JsonObject : undefined;
  } catch {
    return undefined;
  }
}

function findUniqueTool(api: ExtensionAPI, name: string): ToolInfo | undefined {
  const matches = api.getAllTools().filter((tool) => tool.name === name);
  return matches.length === 1 ? matches[0] : undefined;
}

export function createSandboxBypass(options: SandboxBypassOptions) {
  let api: ExtensionAPI | undefined;
  let reviewer: ((input: SandboxBypassReviewInput, ctx: ExtensionToolContext) => Promise<Block | undefined>) | undefined;
  const usedCalls = new Map<string, Set<string>>();

  function recordExecution(input: Parameters<SandboxBypassOptions["recordExecution"]>[0]): void {
    try {
      options.recordExecution(input);
    } catch {
      return;
    }
  }

  function prepareRequest(
    toolCallId: string,
    inputValue: unknown,
    ctx: ExtensionToolContext,
  ): PreparedRequest | Block {
    if (api === undefined) return { block: true, reason: "sandbox-bypass:tool-registry-unavailable" };
    const mode = options.mode(ctx);
    const policyRevision = options.policyRevision(ctx);
    if (mode === "read-only") {
      return { block: true, reason: "sandbox-bypass:disabled-in-read-only" };
    }
    const input = isRecord(inputValue) ? inputValue : undefined;
    if (
      input === undefined || typeof input.reason !== "string" || input.reason.trim().length === 0 ||
      typeof input.toolName !== "string" || input.toolName.trim().length === 0
    ) {
      return { block: true, reason: "sandbox-bypass:invalid-request" };
    }
    if (input.toolName === SANDBOX_BYPASS_TOOL_NAME) {
      return { block: true, reason: "sandbox-bypass:self-target-forbidden" };
    }
    const sessionId = ctx.sessionManager.getSessionId();
    if (usedCalls.get(sessionId)?.has(toolCallId)) {
      return { block: true, reason: "sandbox-bypass:duplicate-request" };
    }
    const target = findUniqueTool(api, input.toolName);
    if (target === undefined) {
      return { block: true, reason: `sandbox-bypass:unknown-tool:${input.toolName}` };
    }
    const args = copyJsonObject(input.arguments);
    if (args === undefined || typeof target.sourceInfo.path !== "string") {
      return { block: true, reason: "sandbox-bypass:invalid-arguments" };
    }
    try {
      if (!Value.Check(target.parameters, args)) {
        return { block: true, reason: `sandbox-bypass:arguments-do-not-match:${input.toolName}` };
      }
    } catch {
      return { block: true, reason: `sandbox-bypass:invalid-tool-schema:${input.toolName}` };
    }

    const hostTool = options.resolveHostTool(input.toolName, target.parameters);
    if (hostTool === undefined) {
      return { block: true, reason: `sandbox-bypass:target-executor-unavailable:${input.toolName}` };
    }
    const request: PreparedRequest = {
      sessionId,
      targetToolCallId: `${toolCallId}:sandbox-bypass-target`,
      targetToolName: input.toolName,
      arguments: args,
      reason: input.reason,
      schema: target.parameters,
      sourcePath: target.sourceInfo.path,
      exposure: target.exposure,
      hostTool,
      hostExecute: hostTool.execute,
      mode,
      policyRevision,
    };
    const sessionCalls = usedCalls.get(sessionId) ?? new Set<string>();
    sessionCalls.add(toolCallId);
    usedCalls.set(sessionId, sessionCalls);
    return request;
  }

  async function execute(
    toolCallId: string,
    _input: Static<typeof parameters>,
    signal: AbortSignal | undefined,
    onUpdate: Parameters<HostToolDefinition["execute"]>[3],
    ctx: ExtensionToolContext,
  ) {
    const sessionId = ctx.sessionManager.getSessionId();
    const prepared = prepareRequest(toolCallId, _input, ctx);
    if ("block" in prepared) {
      throw new Error(prepared.reason);
    }
    const request = prepared;
    if (api === undefined) throw new Error("sandbox-bypass:tool-registry-unavailable");
    if (request.sessionId !== sessionId) {
      throw new Error("sandbox-bypass:session-changed");
    }
    const targetInfo = findUniqueTool(api, request.targetToolName);
    if (
      targetInfo === undefined || targetInfo.parameters !== request.schema ||
      targetInfo.sourceInfo.path !== request.sourcePath || targetInfo.exposure !== request.exposure ||
      !Value.Check(targetInfo.parameters, request.arguments)
    ) {
      throw new Error("sandbox-bypass:target-registration-changed");
    }

    const hostTool = options.resolveHostTool(request.targetToolName, request.schema);
    if (hostTool !== request.hostTool || hostTool?.execute !== request.hostExecute) {
      throw new Error(`sandbox-bypass:target-executor-unavailable:${request.targetToolName}`);
    }
    if (signal?.aborted) {
      throw new Error("sandbox-bypass:cancelled-before-review");
    }

    const invoke = () => request.hostExecute.call(
      request.hostTool,
      request.targetToolCallId,
      request.arguments as never,
      signal,
      onUpdate,
      ctx,
    );

    if (reviewer === undefined) throw new Error("sandbox-bypass:reviewer-unavailable");
    const review = await reviewer({
      toolCallId: request.targetToolCallId,
      targetToolName: request.targetToolName,
      arguments: request.arguments,
      reason: request.reason,
    }, ctx);
    if (review !== undefined) throw new Error(review.reason);
    if (
      options.mode(ctx) === "read-only" || options.mode(ctx) !== request.mode ||
      options.policyRevision(ctx) !== request.policyRevision ||
      ctx.sessionManager.getSessionId() !== request.sessionId
    ) {
      throw new Error("sandbox-bypass:approval-invalidated-by-policy-change");
    }
    const currentTarget = findUniqueTool(api, request.targetToolName);
    const currentHostTool = options.resolveHostTool(request.targetToolName, request.schema);
    if (
      currentTarget === undefined || currentTarget.parameters !== request.schema ||
      currentTarget.sourceInfo.path !== request.sourcePath || currentTarget.exposure !== request.exposure ||
      currentHostTool !== request.hostTool || currentHostTool?.execute !== request.hostExecute
    ) {
      throw new Error("sandbox-bypass:target-registration-changed");
    }
    if (signal?.aborted || ctx.signal?.aborted) throw new Error("sandbox-bypass:cancelled-before-execution");

    const actionDigest = jsonDigest({
      sessionId: request.sessionId,
      requestToolCallId: toolCallId,
      toolCallId: request.targetToolCallId,
      toolName: request.targetToolName,
      arguments: request.arguments,
      sourcePath: request.sourcePath,
      policyRevision: request.policyRevision,
    });
    let result: Awaited<ReturnType<CallableTool["execute"]>>;
    try {
      result = await invoke();
    } catch (error) {
      recordExecution({
        sessionId: ctx.sessionManager.getSessionId(),
        toolCallId: request.targetToolCallId,
        targetToolName: request.targetToolName,
        actionDigest,
        state: "failed",
        impact: "unknown",
        code: "execution-failed",
      });
      throw error;
    }
    recordExecution({
      sessionId: ctx.sessionManager.getSessionId(),
      toolCallId: request.targetToolCallId,
      targetToolName: request.targetToolName,
      actionDigest,
      state: result.isError === true ? "failed" : "completed",
      impact: "known",
      ...(result.isError === true ? { code: "execution-failed" } : {}),
    });
    return result;
  }

  return {
    tool: {
      name: SANDBOX_BYPASS_TOOL_NAME,
      label: "Request one-time host execution",
      description:
        "Request approval to run one registered tool once on the host with the supplied complete arguments. " +
        "State why host execution is needed.",
      parameters,
      executionMode: "sequential" as const,
      execute,
    },
    install(apiValue: ExtensionAPI) {
      api = apiValue;
      api.registerTool(this.tool);
    },
    setReviewer(value: typeof reviewer) {
      reviewer = value;
    },
    clearSession(sessionId: string) {
      usedCalls.delete(sessionId);
    },
    syncMode(mode: PermissionMode, _sessionId?: string) {
      if (api === undefined) return;
      const active = api.getActiveTools();
      const next = mode === "read-only"
        ? active.filter((name) => name !== SANDBOX_BYPASS_TOOL_NAME)
        : active.includes(SANDBOX_BYPASS_TOOL_NAME)
          ? active
          : [...active, SANDBOX_BYPASS_TOOL_NAME];
      if (next.length !== active.length || next.some((name, index) => name !== active[index])) {
        api.setActiveTools(next);
      }
    },
  };
}
