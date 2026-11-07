import type {
  ExtensionAPI,
  ExtensionToolContext,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSandboxBypass, SANDBOX_BYPASS_TOOL_NAME } from "../../src/sandbox/bypass";

const TARGET = "bypass_test_plugin";
const targetParameters = Type.Object({ marker: Type.String() });
const result = { content: [{ type: "text" as const, text: "host-result" }], details: {} };

function tool(
  name: string,
  exposure: "direct" | "hidden" = "direct",
  execute = vi.fn(async () => result),
): ToolDefinition<any, any, any> {
  return {
    name,
    label: name,
    description: name,
    parameters: targetParameters,
    exposure,
    execute,
  };
}

function setup(options: {
  mode?: "read-only" | "default" | "auto-review" | "full-access";
  controlled?: boolean;
  exposure?: "direct" | "hidden";
} = {}) {
  let mode = options.mode ?? "default";
  let policyRevision = "policy-1";
  let sessionId = "bypass-session";
  const controlled = options.controlled ?? true;
  let activeTools = [SANDBOX_BYPASS_TOOL_NAME];
  const definitions: ToolDefinition<any, any, any>[] = [];
  const targetExecute = vi.fn(async () => result);
  const targetDefinition = tool(TARGET, options.exposure, targetExecute);
  definitions.push(targetDefinition);
  const api = {
    registerTool: (definition: ToolDefinition<any, any, any>) => definitions.push(definition),
    getAllTools: () => definitions.map((definition) => ({
      name: definition.name,
      description: definition.description,
      parameters: definition.parameters,
      exposure: definition.exposure ?? "direct",
      sourceInfo: { path: definition.name === TARGET && controlled ? "src/index.ts" : `${definition.name}.ts` },
    })),
    getActiveTools: () => [...activeTools],
    setActiveTools: (names: string[]) => { activeTools = [...names]; },
    appendEntry: vi.fn(),
  } as unknown as ExtensionAPI;
  const recorded = vi.fn();
  const bypass = createSandboxBypass({
    mode: () => mode,
    policyRevision: () => policyRevision,
    resolveHostTool: (name, schema) =>
      controlled && name === TARGET && schema === targetParameters
        ? targetDefinition
        : undefined,
    recordExecution: recorded,
  });
  bypass.install(api);

  const callableTarget = {
    name: TARGET,
    parameters: targetParameters,
    execute: async (toolCallId: string, args: Record<string, unknown>) =>
      targetDefinition.execute(toolCallId, args, undefined, undefined, context),
  };
  const context = {
    sessionManager: { getSessionId: () => sessionId },
    get tools() { return activeTools.includes(TARGET) ? [callableTarget] : []; },
  } as unknown as ExtensionToolContext;
  const requestInput = (argumentsValue: Record<string, unknown> = { marker: "fixed" }) => ({
    reason: "Need the plugin host capability for this one call.",
    toolName: TARGET,
    arguments: argumentsValue,
  });
  const execute = (toolCallId = "bypass-call", signal?: AbortSignal, input = requestInput()) => bypass.tool.execute(
    toolCallId,
    input as never,
    signal,
    undefined,
    context,
  );

  return {
    api,
    bypass,
    context,
    execute,
    recorded,
    setMode: (value: typeof mode) => { mode = value; },
    setPolicyRevision: (value: string) => { policyRevision = value; },
    setSessionId: (value: string) => { sessionId = value; },
    targetExecute,
    getActiveTools: () => [...activeTools],
    requestInput,
  };
}

afterEach(() => vi.restoreAllMocks());

describe("one-time sandbox bypass tool", () => {
  it("validates, freezes and executes a registered plugin once after review", async () => {
    const test = setup();
    expect(test.bypass.tool.description).toContain("Request approval to run one registered tool once on the host");
    const original = test.requestInput();
    test.bypass.setReviewer(async (input) => {
      expect(input.targetToolName).toBe(TARGET);
      expect(input.arguments).toEqual({ marker: "fixed" });
      expect(input.reason).toContain("one call");
      original.arguments.marker = "mutated after preflight";
      return undefined;
    });

    const output = await test.execute("bypass-call", undefined, original);
    expect(output).toBe(result);
    expect(test.targetExecute).toHaveBeenCalledTimes(1);
    expect(test.targetExecute).toHaveBeenCalledWith(
      "bypass-call:sandbox-bypass-target",
      { marker: "fixed" },
      undefined,
      undefined,
      test.context,
    );
    expect(test.getActiveTools()).toEqual([SANDBOX_BYPASS_TOOL_NAME]);
    expect(test.recorded).toHaveBeenCalledWith(expect.objectContaining({
      targetToolName: TARGET,
      state: "completed",
      impact: "known",
    }));
  });

  it("executes an explicitly supplied registered target without a prior sandbox denial", async () => {
    const explicit = setup();
    explicit.bypass.setReviewer(async () => undefined);
    await expect(explicit.execute()).resolves.toBe(result);
    expect(explicit.targetExecute).toHaveBeenCalledTimes(1);

    const untrusted = setup({ controlled: false });
    const reviewer = vi.fn(async () => undefined);
    untrusted.bypass.setReviewer(reviewer);
    await expect(untrusted.execute()).rejects.toThrow("sandbox-bypass:target-executor-unavailable");
    expect(reviewer).not.toHaveBeenCalled();

    const differentArguments = setup();
    differentArguments.bypass.setReviewer(async (input) => {
      expect(input.arguments).toEqual({ marker: "changed" });
      return undefined;
    });
    await expect(differentArguments.execute("changed-call", undefined, differentArguments.requestInput({ marker: "changed" })))
      .resolves.toBe(result);
  });

  it("rejects unknown, self-targeted, and schema-invalid requests before review", async () => {
    const test = setup();
    await expect(test.execute("unknown-call", undefined, { ...test.requestInput(), toolName: "missing-tool" }))
      .rejects.toThrow("sandbox-bypass:unknown-tool");
    await expect(test.execute("self-call", undefined, {
      reason: "self",
      toolName: SANDBOX_BYPASS_TOOL_NAME,
      arguments: {},
    })).rejects.toThrow("sandbox-bypass:self-target-forbidden");
    await expect(test.execute("schema-call", undefined, test.requestInput({ marker: 42 })))
      .rejects.toThrow("sandbox-bypass:arguments-do-not-match");
    expect(test.targetExecute).not.toHaveBeenCalled();
  });

  it("does not execute after a denied or invalidated approval", async () => {
    const denied = setup();
    denied.bypass.setReviewer(async () => ({ block: true, reason: "approval-chain:denied" }));
    await expect(denied.execute()).rejects.toThrow("approval-chain:denied");
    expect(denied.targetExecute).not.toHaveBeenCalled();

    const invalidated = setup();
    invalidated.bypass.setReviewer(async () => {
      invalidated.setPolicyRevision("policy-2");
      return undefined;
    });
    await expect(invalidated.execute()).rejects.toThrow("approval-invalidated-by-policy-change");
    expect(invalidated.targetExecute).not.toHaveBeenCalled();

    const failedReview = setup();
    failedReview.bypass.setReviewer(async () => { throw new Error("reviewer-timeout"); });
    await expect(failedReview.execute()).rejects.toThrow("reviewer-timeout");
    expect(failedReview.targetExecute).not.toHaveBeenCalled();
  });

  it("binds an explicit request to its session and rejects cancellation", async () => {
    const wrongSession = setup();
    wrongSession.bypass.setReviewer(async () => {
      wrongSession.setSessionId("other-session");
      return undefined;
    });
    await expect(wrongSession.execute()).rejects.toThrow("approval-invalidated-by-policy-change");
    expect(wrongSession.targetExecute).not.toHaveBeenCalled();
    wrongSession.bypass.clearSession("bypass-session");
    expect(wrongSession.getActiveTools()).toEqual([SANDBOX_BYPASS_TOOL_NAME]);

    const cancelled = setup();
    cancelled.bypass.setReviewer(async () => undefined);
    const abort = new AbortController();
    abort.abort();
    await expect(cancelled.execute("bypass-call", abort.signal)).rejects.toThrow("cancelled-before-review");
    expect(cancelled.targetExecute).not.toHaveBeenCalled();
  });

  it("records thrown target outcomes as unknown without retrying", async () => {
    const test = setup();
    test.bypass.setReviewer(async () => undefined);
    test.targetExecute.mockRejectedValueOnce(new Error("target-result-unknown"));

    await expect(test.execute()).rejects.toThrow("target-result-unknown");

    expect(test.targetExecute).toHaveBeenCalledTimes(1);
    expect(test.recorded).toHaveBeenCalledWith(expect.objectContaining({
      state: "failed",
      impact: "unknown",
    }));
  });

  it("returns a completed target result when execution recording fails", async () => {
    const test = setup();
    test.bypass.setReviewer(async () => undefined);
    test.recorded.mockImplementation(() => { throw new Error("audit-unavailable"); });

    await expect(test.execute()).resolves.toBe(result);

    expect(test.targetExecute).toHaveBeenCalledTimes(1);
  });

  it("hides the request tool in read-only mode and restores it afterward", async () => {
    const test = setup();
    test.setMode("read-only");
    test.bypass.syncMode("read-only");
    expect(test.getActiveTools()).toEqual([]);
    await expect(test.execute()).rejects.toThrow("sandbox-bypass:disabled-in-read-only");
    test.bypass.syncMode("default");
    test.setMode("default");
    expect(test.getActiveTools()).toContain(SANDBOX_BYPASS_TOOL_NAME);
  });

  it("uses the original executor for controlled tools, including hidden built-ins", async () => {
    const test = setup({ controlled: true, exposure: "hidden" });
    test.bypass.setReviewer(async () => undefined);
    await expect(test.execute()).resolves.toBe(result);
    expect(test.targetExecute).toHaveBeenCalledTimes(1);
  });
});
