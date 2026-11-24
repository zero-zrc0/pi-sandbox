import type {
  ExtensionAPI,
  ExtensionContext,
  ExtensionToolContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Type, type Static, type TSchema } from "typebox";
import { Value } from "typebox/value";
import { freezeJson, jsonDigest, type JsonObject } from "../json";
import { formatPiSandboxError } from "../error-format";
import type { PermissionMode } from "../contracts";
import type { ToolElevation } from "../elevation";
import type { SandboxBypassReviewInput } from "#approve-core/host";

export const SANDBOX_BYPASS_TOOL_NAME = "request_tool_elevation";

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
  readonly cwd: string;
  readonly elevation: ToolElevation;
}

export interface SandboxBypassOptions {
  readonly mode: (ctx: ExtensionContext) => PermissionMode;
  readonly policyRevision: (ctx: ExtensionContext) => string;
  readonly resolveHostTool: (
    name: string,
    schema: TSchema,
  ) => HostToolDefinition | undefined;
  readonly prepareElevation: (name: string, args: JsonObject, tier: ToolElevation["tier"], ctx: ExtensionToolContext) =>
    ToolElevation | Block | undefined;
  readonly validateElevation: (name: string, args: JsonObject, elevation: ToolElevation, ctx: ExtensionToolContext) => boolean;
  readonly executeDefault: (input: SandboxBypassReviewInput, signal: AbortSignal | undefined,
    onUpdate: Parameters<HostToolDefinition["execute"]>[3], ctx: ExtensionToolContext) => ReturnType<HostToolDefinition["execute"]>;
  readonly recordExecution: (input: {
    readonly sessionId: string;
    readonly toolCallId: string;
    readonly targetToolName: string;
    readonly actionDigest: string;
    readonly executionMode: "host" | "sandbox";
    readonly state: "completed" | "failed";
    readonly impact: "known" | "unknown";
    readonly code?: string;
  }) => void;
}

const parameters = Type.Object({
  reason: Type.String(),
  toolName: Type.String(),
  arguments: Type.Record(Type.String(), Type.Any()),
  tier: Type.Union([Type.Literal("default"), Type.Literal("host")]),
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
    if (mode === "full-access") return { block: true, reason: "sandbox-bypass:elevation-not-needed" };
    const input = isRecord(inputValue) ? inputValue : undefined;
    if (
      input === undefined || typeof input.reason !== "string" || input.reason.trim().length === 0 ||
      typeof input.toolName !== "string" || input.toolName.trim().length === 0 ||
      (input.tier !== "default" && input.tier !== "host")
    ) {
      return { block: true, reason: "sandbox-bypass:invalid-request: supply reason, toolName, the target's exact complete arguments, and tier (default or host)" };
    }
    if (input.toolName === SANDBOX_BYPASS_TOOL_NAME) {
      return { block: true, reason: "sandbox-bypass:self-target-forbidden" };
    }
    const sessionId = ctx.sessionManager.getSessionId();
    if (usedCalls.get(sessionId)?.has(toolCallId)) {
      return { block: true, reason: "sandbox-bypass:duplicate-request: this call already used its one elevation request" };
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
        return { block: true, reason: `sandbox-bypass:arguments-do-not-match:${input.toolName}: pass the target tool's exact complete arguments unchanged` };
      }
    } catch {
      return { block: true, reason: `sandbox-bypass:invalid-tool-schema:${input.toolName}` };
    }

    const hostTool = options.resolveHostTool(input.toolName, target.parameters);
    if (hostTool === undefined) {
      return { block: true, reason: `sandbox-bypass:target-executor-unavailable:${input.toolName}` };
    }
    const preparedElevation = options.prepareElevation(input.toolName, args, input.tier, ctx);
    if (preparedElevation === undefined) {
      return { block: true, reason: `sandbox-bypass:elevation-unavailable:${input.tier}:${input.toolName}: the elevation could not be prepared for this tool and tier` };
    }
    if ("block" in preparedElevation) return preparedElevation;
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
      cwd: ctx.cwd,
      elevation: freezeJson(preparedElevation) as unknown as ToolElevation,
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
      throw new Error(formatPiSandboxError(prepared.reason));
    }
    const request = prepared;
    if (api === undefined) throw new Error(formatPiSandboxError("sandbox-bypass:tool-registry-unavailable"));
    if (request.sessionId !== sessionId) {
      throw new Error(formatPiSandboxError("sandbox-bypass:session-changed"));
    }
    const targetInfo = findUniqueTool(api, request.targetToolName);
    if (
      targetInfo === undefined || targetInfo.parameters !== request.schema ||
      targetInfo.sourceInfo.path !== request.sourcePath || targetInfo.exposure !== request.exposure ||
      !Value.Check(targetInfo.parameters, request.arguments)
    ) {
      throw new Error(formatPiSandboxError("sandbox-bypass:target-registration-changed"));
    }

    const hostTool = options.resolveHostTool(request.targetToolName, request.schema);
    if (hostTool !== request.hostTool || hostTool?.execute !== request.hostExecute) {
      throw new Error(formatPiSandboxError(`sandbox-bypass:target-executor-unavailable:${request.targetToolName}`));
    }
    if (signal?.aborted) {
      throw new Error(formatPiSandboxError("sandbox-bypass:cancelled-before-review"));
    }

    const reviewInput: SandboxBypassReviewInput = {
      toolCallId: request.targetToolCallId,
      targetToolName: request.targetToolName,
      arguments: request.arguments,
      reason: request.reason,
      elevation: request.elevation,
    };
    const invoke = () => request.elevation.tier === "default"
      ? options.executeDefault(reviewInput, signal, onUpdate, ctx)
      : request.hostExecute.call(
      request.hostTool,
      request.targetToolCallId,
      request.arguments as never,
      signal,
      onUpdate,
      ctx,
    );

    if (reviewer === undefined) throw new Error(formatPiSandboxError("sandbox-bypass:reviewer-unavailable"));
    const review = await reviewer(reviewInput, ctx);
    if (review !== undefined) throw new Error(formatPiSandboxError(review.reason));
    if (
      ctx.cwd !== request.cwd || options.mode(ctx) !== request.mode ||
      options.policyRevision(ctx) !== request.policyRevision ||
      ctx.sessionManager.getSessionId() !== request.sessionId
    ) {
      throw new Error(formatPiSandboxError("sandbox-bypass:approval-invalidated-by-policy-change: the permission configuration changed after approval; request elevation again"));
    }
    const currentTarget = findUniqueTool(api, request.targetToolName);
    const currentHostTool = options.resolveHostTool(request.targetToolName, request.schema);
    if (
      currentTarget === undefined || currentTarget.parameters !== request.schema ||
      currentTarget.sourceInfo.path !== request.sourcePath || currentTarget.exposure !== request.exposure ||
      currentHostTool !== request.hostTool || currentHostTool?.execute !== request.hostExecute
    ) {
      throw new Error(formatPiSandboxError("sandbox-bypass:target-registration-changed"));
    }
    if (signal?.aborted || ctx.signal?.aborted) throw new Error(formatPiSandboxError("sandbox-bypass:cancelled-before-execution"));
    if (!options.validateElevation(request.targetToolName, request.arguments, request.elevation, ctx)) {
      throw new Error(formatPiSandboxError("sandbox-bypass:target-scope-changed: the approved target's access needs changed after approval; request elevation again"));
    }

    const actionDigest = jsonDigest({
      sessionId: request.sessionId,
      requestToolCallId: toolCallId,
      toolCallId: request.targetToolCallId,
      toolName: request.targetToolName,
      arguments: request.arguments,
      sourcePath: request.sourcePath,
      policyRevision: request.policyRevision,
      elevation: request.elevation,
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
        executionMode: request.elevation.tier === "host" ? "host" : "sandbox",
        state: "failed",
        impact: "unknown",
        code: "execution-failed",
      });
      throw new Error(formatPiSandboxError(error));
    }
    recordExecution({
      sessionId: ctx.sessionManager.getSessionId(),
      toolCallId: request.targetToolCallId,
      targetToolName: request.targetToolName,
      actionDigest,
      executionMode: request.elevation.tier === "host" ? "host" : "sandbox",
      state: result.isError === true ? "failed" : "completed",
      impact: "known",
      ...(result.isError === true ? { code: "execution-failed" } : {}),
    });
    return result;
  }

  return {
    tool: {
      name: SANDBOX_BYPASS_TOOL_NAME,
      label: "Request one-time tool elevation",
      description:
        "Request one-time elevation for a supported built-in tool by supplying its exact complete arguments, a reason, and the tier you choose. " +
        "File tools accept Default for a one-time sandboxed file access; shell tools (bash, powershell) accept Host only, which runs the exact command once outside the OS sandbox after approval. " +
        "Choose Host only when the action needs access outside the sandbox. " +
        "Default never falls back to Host. Use the least access needed. " +
        "Explicit policy denies and risk denies remain final.",
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
    syncMode(mode: PermissionMode, _sessionId?: string, sandboxEnabled = true) {
      if (api === undefined) return;
      const active = api.getActiveTools();
      const next = mode === "full-access" || !sandboxEnabled
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
