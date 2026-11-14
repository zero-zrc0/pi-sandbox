import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createReadToolDefinition,
  createExtensionRuntime,
  ExtensionRunner,
  ModelRegistry,
  ModelRuntime,
  SessionManager,
  type ExtensionToolContext,
} from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
} from "../../src/invocation";
import {
  bindOwnedToolExecution,
  type OwnedToolExecutionOptions,
  ToolInvocationBindingStore,
} from "#sandbox/execution-binding";
import type { InvocationRequester } from "../../src/invocation";

let tempDir = "";

afterEach(() => {
  if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  tempDir = "";
});

async function makeRuntime(cwd: string) {
  tempDir = mkdtempSync(join(tmpdir(), "a04-tool-binding-"));
  const modelRuntime = await ModelRuntime.create({
    authPath: join(tempDir, "auth.json"),
    modelsPath: null,
    modelsStorePath: join(tempDir, "models.json"),
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
  const sessionManager = SessionManager.inMemory(cwd, { id: "session-9" });
  const runner = new ExtensionRunner(
    [],
    createExtensionRuntime(),
    cwd,
    sessionManager,
    new ModelRegistry(modelRuntime),
  );
  return runner;
}

function makeOwnedReadDefinition() {
  const definition = {
    ...createReadToolDefinition("C:/workspace", {
      operations: {
        readFile: async () => Buffer.from("file data"),
        access: async () => undefined,
      },
    }),
    name: "owned_read",
  };
  const toolInfo = {
    name: definition.name,
    description: definition.description,
    parameters: definition.parameters,
    sourceInfo: {
      path: "<inline:a04-test>",
      source: "a04-test",
      scope: "temporary",
      origin: "top-level",
    },
  };
  const operations = {
    readFile: vi.fn(async () => Buffer.from("file data")),
    access: vi.fn(async () => undefined),
  };
  return { definition, toolInfo, operations };
}

function makeInvocation(
  definition: ReturnType<typeof makeOwnedReadDefinition>,
  input: { path: string },
) {
  const seed = captureToolInvocationSeed({
    event: {
      type: "tool_call",
      toolName: definition.definition.name,
      toolCallId: "call-1",
      input,
    },
    registeredTools: [definition.toolInfo],
    cwd: "C:/workspace",
    requester: { sessionId: "session-9", agentName: null },
    environment: { APP_ENV: "test" },
  });
  if (!seed.ok) throw new Error("expected complete invocation seed");
  const captured = finalizeToolInvocation(seed.seed, {
    requestId: "request-1",
    scopes: [
      {
        id: "scope-1",
        surface: definition.definition.name,
        target: input.path,
        access: "read",
        state: "ask",
        source: "tool",
      },
    ],
    executionBinding: {
      status: "bound",
      owner: "a04-test",
      toolName: definition.definition.name,
      revision: seed.seed.tool.revision,
      bindingId: "owned-read-binding",
    },
  });
  if (!captured.ok) throw new Error("expected complete invocation");
  return captured.invocation;
}

interface ReadExecutionHarnessOptions {
  readonly scopeRevision?: string;
  readonly getAllTools?: OwnedToolExecutionOptions<undefined>["getAllTools"];
  readonly readRequester?: OwnedToolExecutionOptions<undefined>["readRequester"];
  readonly readEnvironment?: OwnedToolExecutionOptions<undefined>["readEnvironment"];
  readonly readCurrentScopeRevision?: () => string | undefined;
  readonly verifyScope?: OwnedToolExecutionOptions<undefined>["verifyScope"];
  readonly wrapContext?: (
    context: ExtensionToolContext,
  ) => ExtensionToolContext;
}

async function makeReadExecutionHarness(options: ReadExecutionHarnessOptions = {}) {
  const factoryTool = makeOwnedReadDefinition();
  const invocation = makeInvocation(factoryTool, { path: "safe.txt" });
  const bindings = new ToolInvocationBindingStore();
  const scopeRevision = options.scopeRevision ?? "policy-1";
  if (!bindings.authorize(invocation, scopeRevision)) {
    throw new Error("expected the complete owned invocation to be authorized");
  }

  const runner = await makeRuntime("C:/workspace");
  const baseContext = runner.createToolContext("call-1", undefined);
  const context = options.wrapContext?.(baseContext) ?? baseContext;
  const readFile = vi.fn(async () => Buffer.from("file data"));
  const definition = {
    ...createReadToolDefinition("C:/workspace", {
      operations: { readFile, access: async () => undefined },
    }),
    name: "owned_read",
  };
  const defaultRequester: InvocationRequester = {
    sessionId: "session-9",
    agentName: null,
  };
  const executionOptions = {
    owner: "a04-test",
    bindingId: "owned-read-binding",
    failureDetails: undefined,
    bindings,
    getAllTools: options.getAllTools ?? (() => [factoryTool.toolInfo]),
    readRequester: options.readRequester ?? (() => defaultRequester),
    readEnvironment: options.readEnvironment ?? (() => ({ APP_ENV: "test" })),
    verifyScope:
      options.verifyScope ??
      (() => ({ allowed: true, revision: scopeRevision })),
    readCurrentScopeRevision:
      options.readCurrentScopeRevision ?? (() => scopeRevision),
  };
  const wrapped = bindOwnedToolExecution(definition, executionOptions);
  return { factoryTool, invocation, bindings, runner, context, readFile, definition, wrapped };
}

describe("owned tool execute binding", () => {
  it("rechecks final inputs before invoking Pi operations", async () => {
    const factoryTool = makeOwnedReadDefinition();
    const invocation = makeInvocation(factoryTool, { path: "safe.txt" });
    const bindings = new ToolInvocationBindingStore();
    expect(bindings.authorize(invocation, "policy-1")).toBe(true);

    const runner = await makeRuntime("C:/workspace");
    const context = runner.createToolContext("call-1", undefined);
    const readFile = vi.fn(async () => Buffer.from("file data"));
    const readCurrentScopeRevision = vi.fn(() => "policy-1");
    const operations = { ...factoryTool.operations, readFile };
    const originalDefinition = createReadToolDefinition("C:/workspace", {
      operations,
    });
    const definition = { ...originalDefinition, name: "owned_read" };
    const toolInfo = { ...factoryTool.toolInfo, parameters: definition.parameters };
    const wrapped = bindOwnedToolExecution(definition, {
      owner: "a04-test",
      bindingId: "owned-read-binding",
      failureDetails: undefined,
      bindings,
      getAllTools: () => [toolInfo],
      readRequester: () => ({ sessionId: "session-9", agentName: null }),
      readEnvironment: () => ({ APP_ENV: "test" }),
      readCurrentScopeRevision,
      verifyScope: () => ({ allowed: true, revision: "policy-1" }),
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );

    expect(readFile).toHaveBeenCalledOnce();
    expect(readCurrentScopeRevision).toHaveBeenCalledOnce();
    expect(result.isError).not.toBe(true);
  });

  it("blocks a changed final argument before the owned operation runs", async () => {
    const factoryTool = makeOwnedReadDefinition();
    const invocation = makeInvocation(factoryTool, { path: "safe.txt" });
    const bindings = new ToolInvocationBindingStore();
    expect(bindings.authorize(invocation, "policy-1")).toBe(true);

    const runner = await makeRuntime("C:/workspace");
    const context = runner.createToolContext("call-1", undefined);
    const readFile = vi.fn(async () => Buffer.from("file data"));
    const definition = {
      ...createReadToolDefinition("C:/workspace", {
        operations: { readFile, access: async () => undefined },
      }),
      name: "owned_read",
    };
    const wrapped = bindOwnedToolExecution(definition, {
      owner: "a04-test",
      bindingId: "owned-read-binding",
      failureDetails: undefined,
      bindings,
      getAllTools: () => [factoryTool.toolInfo],
      readRequester: () => ({ sessionId: "session-9", agentName: null }),
      readEnvironment: () => ({ APP_ENV: "test" }),
      readCurrentScopeRevision: () => "policy-1",
      verifyScope: () => ({ allowed: true, revision: "policy-1" }),
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "changed.txt" },
      undefined,
      undefined,
      context,
    );

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks arguments changed while the final scope check is waiting", async () => {
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const params = { path: "safe.txt" };
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      params,
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    params.path = "unapproved.txt";
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
    params.path = "safe.txt";
    const retry = await wrapped.execute(
      "call-1",
      params,
      undefined,
      undefined,
      context,
    );
    expect(retry.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when the policy revision changes during final scope verification", async () => {
    let currentPolicyRevision = "policy-1";
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    currentPolicyRevision = "policy-2";
    releaseScopeCheck({ allowed: true, revision: currentPolicyRevision });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks a policy change after scope verification resolves but before execution resumes", async () => {
    let currentPolicyRevision = "policy-1";
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const readCurrentScopeRevision = vi.fn(() => currentPolicyRevision);
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      readCurrentScopeRevision,
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    currentPolicyRevision = "policy-2";
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readCurrentScopeRevision).toHaveBeenCalledOnce();
    expect(readFile).not.toHaveBeenCalled();
  });

  it("defers when the current scope revision is missing", async () => {
    const readCurrentScopeRevision = vi.fn(() => undefined);
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      readCurrentScopeRevision,
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );

    expect(result.isError).toBe(true);
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          text: expect.stringContaining("permission-policy-revision-unavailable"),
        }),
      ]),
    );
    expect(readCurrentScopeRevision).toHaveBeenCalledOnce();
    expect(readFile).not.toHaveBeenCalled();

    const retry = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    expect(retry.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("defers when reading the current scope revision throws", async () => {
    const readCurrentScopeRevision = vi.fn(() => {
      throw new Error("policy store unavailable");
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      readCurrentScopeRevision,
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );

    expect(result.isError).toBe(true);
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          text: expect.stringContaining("permission-policy-revision-unavailable"),
        }),
      ]),
    );
    expect(readCurrentScopeRevision).toHaveBeenCalledOnce();
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when execution is cancelled while final scope verification waits", async () => {
    const controller = new AbortController();
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      controller.signal,
      undefined,
      context,
    );
    await scopeStarted;
    controller.abort();
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when the requester changes while final scope verification waits", async () => {
    let requester = { sessionId: "session-9", agentName: null as string | null };
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      readRequester: () => requester,
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    requester = { sessionId: "session-10", agentName: "child-agent" };
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when the Pi session changes while final scope verification waits", async () => {
    let sessionId = "session-9";
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });
    vi.spyOn(context.sessionManager, "getSessionId").mockImplementation(
      () => sessionId,
    );

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    sessionId = "session-10";
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when the execution environment changes while scope verification waits", async () => {
    let environment: Record<string, string> = { APP_ENV: "test" };
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      readEnvironment: () => environment,
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    environment = { APP_ENV: "production" };
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("keeps the environment reader bound while final scope verification waits", async () => {
    const factoryTool = makeOwnedReadDefinition();
    const invocation = makeInvocation(factoryTool, { path: "safe.txt" });
    const bindings = new ToolInvocationBindingStore();
    expect(bindings.authorize(invocation, "policy-1")).toBe(true);

    const runner = await makeRuntime("C:/workspace");
    const context = runner.createToolContext("call-1", undefined);
    const readFile = vi.fn(async () => Buffer.from("file data"));
    const definition = {
      ...createReadToolDefinition("C:/workspace", {
        operations: { readFile, access: async () => undefined },
      }),
      name: "owned_read",
    };
    let environment: Record<string, string> = { APP_ENV: "test" };
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const options = {
      owner: "a04-test",
      bindingId: "owned-read-binding",
      failureDetails: undefined,
      bindings,
      getAllTools: () => [factoryTool.toolInfo],
      readRequester: () => ({ sessionId: "session-9", agentName: null }),
      readEnvironment: () => environment,
      readCurrentScopeRevision: () => "policy-1",
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    } satisfies OwnedToolExecutionOptions<undefined>;
    const wrapped = bindOwnedToolExecution(definition, options);

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    environment = { APP_ENV: "production" };
    options.readEnvironment = () => ({ APP_ENV: "test" });
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks a changed tool definition after scope verification waits", async () => {
    const factoryTool = makeOwnedReadDefinition();
    let registeredTools: readonly unknown[] = [factoryTool.toolInfo];
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      getAllTools: () => registeredTools,
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    registeredTools = [
      {
        ...factoryTool.toolInfo,
        description: "A revised read tool definition.",
      },
    ];
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when cwd changes while final scope verification waits", async () => {
    let currentCwd = "C:/workspace";
    let releaseScopeCheck!: (result: {
      allowed: true;
      revision: string;
    }) => void;
    let scopeCheckStarted!: () => void;
    const scopeStarted = new Promise<void>((resolve) => {
      scopeCheckStarted = resolve;
    });
    const scopeCheck = new Promise<{
      allowed: true;
      revision: string;
    }>((resolve) => {
      releaseScopeCheck = resolve;
    });
    const { wrapped, context, readFile } = await makeReadExecutionHarness({
      wrapContext: (baseContext) =>
        new Proxy(baseContext, {
          get(target, property, receiver) {
            return property === "cwd"
              ? currentCwd
              : Reflect.get(target, property, receiver);
          },
        }),
      verifyScope: () => {
        scopeCheckStarted();
        return scopeCheck;
      },
    });

    const execution = wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );
    await scopeStarted;
    currentCwd = "C:/other-workspace";
    releaseScopeCheck({ allowed: true, revision: "policy-1" });
    const result = await execution;

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });

  it("blocks when the pending permission scope no longer verifies", async () => {
    const factoryTool = makeOwnedReadDefinition();
    const invocation = makeInvocation(factoryTool, { path: "safe.txt" });
    const bindings = new ToolInvocationBindingStore();
    expect(bindings.authorize(invocation, "policy-1")).toBe(true);

    const runner = await makeRuntime("C:/workspace");
    const context = runner.createToolContext("call-1", undefined);
    const readFile = vi.fn(async () => Buffer.from("file data"));
    const definition = {
      ...createReadToolDefinition("C:/workspace", {
        operations: { readFile, access: async () => undefined },
      }),
      name: "owned_read",
    };
    const verifyScope = vi.fn().mockReturnValue({
      allowed: false,
      revision: "policy-1",
    });
    const wrapped = bindOwnedToolExecution(definition, {
      owner: "a04-test",
      bindingId: "owned-read-binding",
      failureDetails: undefined,
      bindings,
      getAllTools: () => [factoryTool.toolInfo],
      readRequester: () => ({ sessionId: "session-9", agentName: null }),
      readEnvironment: () => ({ APP_ENV: "test" }),
      readCurrentScopeRevision: () => "policy-1",
      verifyScope,
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );

    expect(result.isError).toBe(true);
    expect(verifyScope).toHaveBeenCalledOnce();
    expect(readFile).not.toHaveBeenCalled();
  });

  it("does not execute a tool without a plugin-owned final binding", async () => {
    const tool = makeOwnedReadDefinition();
    const seed = captureToolInvocationSeed({
      event: {
        type: "tool_call",
        toolName: tool.definition.name,
        toolCallId: "call-1",
        input: { path: "safe.txt" },
      },
      registeredTools: [tool.toolInfo],
      cwd: "C:/workspace",
      requester: { sessionId: "session-9", agentName: null },
      environment: { APP_ENV: "test" },
    });
    if (!seed.ok) throw new Error("expected complete invocation seed");
    const captured = finalizeToolInvocation(seed.seed, {
      requestId: "request-1",
      scopes: [],
      executionBinding: {
        status: "unavailable",
        reason: "host-tool-execute-is-not-interceptable",
      },
    });
    if (!captured.ok) throw new Error("expected complete action");

    const bindings = new ToolInvocationBindingStore();
    expect(bindings.authorize(captured.invocation, "policy-1")).toBe(false);

    const runner = await makeRuntime("C:/workspace");
    const context = runner.createToolContext("call-1", undefined);
    const readFile = vi.fn(async () => Buffer.from("file data"));
    const definition = {
      ...createReadToolDefinition("C:/workspace", {
        operations: { readFile, access: async () => undefined },
      }),
      name: "owned_read",
    };
    const wrapped = bindOwnedToolExecution(definition, {
      owner: "a04-test",
      bindingId: "owned-read-binding",
      failureDetails: undefined,
      bindings,
      getAllTools: () => [tool.toolInfo],
      readRequester: () => ({ sessionId: "session-9", agentName: null }),
      readEnvironment: () => ({ APP_ENV: "test" }),
      readCurrentScopeRevision: () => "policy-1",
      verifyScope: () => ({ allowed: true, revision: "policy-1" }),
    });

    const result = await wrapped.execute(
      "call-1",
      { path: "safe.txt" },
      undefined,
      undefined,
      context,
    );

    expect(result.isError).toBe(true);
    expect(readFile).not.toHaveBeenCalled();
  });
});
