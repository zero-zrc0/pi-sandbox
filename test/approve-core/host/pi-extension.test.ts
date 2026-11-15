/**
 * Phase 12 host integration (specs/host-integration.md §5, §6, §7, §9).
 *
 * The tests drive the extension through its injected ports and the Pi host
 * event surface only: a fake host API records handler registrations, fake
 * publications/analysis/chain ports model deferred work, and an in-memory
 * reviewer session reader keeps evidence snapshots explicit. Every expected
 * outcome is a worked example from the spec; blocked means the call is denied.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import type {
  ExtensionAPI,
  ExtensionContext,
  SessionEntry,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import {
  createPermissionExtension,
  humanPromptFacts,
  type AnalysisPort,
  type AuditEvent,
  type AuditSinkPort,
  type CaptureStepPort,
  type ContextStorePort,
  type LearningPort,
  type MemoryPort,
  type PermissionExtension,
  type PermissionPublication,
  type PublicationFactoryInput,
  type PublicationFactoryPort,
  type RunChainPort,
  type SandboxPort,
} from "#approve-core/host/pi-extension";
import type {
  CaptureStepResult,
  EffectiveNodeConfiguration,
  FinalCallResult,
  StepCapture,
  StepCaptureInput,
  UnitPreparation,
} from "#approve-core/contracts";
import type { NodeBinding, RunStepChainInput, RunStepChainResult } from "#approve-core/runtime";
import { createApprovalNodeHost } from "#approve-core/node-loader/manager";
import type { ApprovalNodeLoadPlan } from "../../../src/sdk";
import type {
  ReviewerContextStore,
  ReviewerLearningLifecycle,
  ReviewerSessionMemory,
  ReviewToolEvent,
  ReviewView,
  LearningFinalizeInput,
} from "#approve-core/context";
import { reviewDigest } from "#approve-core/context/types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CWD = "E:\\work\\project";
const SESSION_ID = "session-1";
const OWNER = "default";

function makeSession(): { readonly id: string; readonly entries: SessionEntry[] } {
  return { id: SESSION_ID, entries: [] };
}

function makeContext(
  session: { readonly id: string },
  overrides: Partial<ExtensionContext> = {},
): ExtensionContext {
  return {
    cwd: CWD,
    mode: "tui",
    hasUI: true,
    signal: undefined,
    sessionManager: {
      getSessionId: () => session.id,
      getCwd: () => CWD,
      getLeafId: () => null,
      getLeafEntry: () => undefined,
      getEntry: () => undefined,
      getBranch: () => [],
      getEntries: () => [],
      buildSessionProjection: () => ({ entries: [], messages: [], thinkingLevel: "off", model: null }),
    },
    ui: {
      select: async () => undefined,
      confirm: async () => false,
      input: async () => undefined,
      notify: () => undefined,
      setStatus: () => undefined,
      setWidget: () => undefined,
      custom: async () => undefined,
    },
    getSystemPrompt: () => "",
    isIdle: () => true,
    isProjectTrusted: () => false,
    modelRegistry: {},
    model: undefined,
    scopedModels: [],
    abort: () => undefined,
    hasPendingMessages: () => false,
    shutdown: () => undefined,
    getContextUsage: () => undefined,
    compact: () => undefined,
    ...overrides,
  } as unknown as ExtensionContext;
}

interface FakeMemory {
  readonly memory: ReviewerSessionMemory;
  readonly events: ReviewToolEvent[];
  readonly revisions: { owner: number; navigation: number; authorization: number };
  setManifest(manifest: ReviewView["manifest"]): void;
  bumpAuthorization(): void;
}

function makeFakeMemory(): FakeMemory {
  const revisions = { owner: 1, navigation: 1, authorization: 1 };
  const events: ReviewToolEvent[] = [];
  let captureSeq = 1;
  let manifest: ReviewView["manifest"];
  const view = (owner: string): ReviewView => ({
    owner,
    sessionId: SESSION_ID,
    historyVersion: 1,
    captureSeq,
    leafId: "",
    branchRootId: "",
    ...(manifest === undefined ? {} : { manifest }),
    transcript: [],
    authorization: [],
    degraded: true,
  });
  const memory = {
    initialized: true,
    disposed: false,
    degraded: true,
    state: () => ({
      initialized: true,
      disposed: false,
      degraded: true,
      failure: undefined,
      view: view(OWNER),
      historyVersion: 1,
      captureSeq,
      pendingEvents: 0,
    }),
    capture: (owner: string) => ({ ok: true as const, view: view(owner), revisions: { ...revisions } }),
    noteUserInput: () => {
      revisions.authorization += 1;
    },
    noteNavigation: () => {
      revisions.navigation += 1;
    },
    requestHistoryRebuild: () => {
      revisions.navigation += 1;
    },
    recordToolEvent: (event: ReviewToolEvent) => {
      events.push(event);
    },
    dispose: () => undefined,
  } as unknown as ReviewerSessionMemory;
  return {
    memory,
    events,
    revisions,
    setManifest: (value) => {
      manifest = value;
    },
    bumpAuthorization: () => {
      revisions.authorization += 1;
    },
  };
}

type Handler = (event: unknown, ctx: ExtensionContext) => unknown;

interface FakeApi {
  readonly api: ExtensionAPI;
  handlers(event: string): readonly Handler[];
  appendEntries(): readonly { customType: string; data: unknown }[];
  messages(): readonly { customType: string; content: string; display: boolean; deliverAs?: string }[];
  fire(event: string, payload: unknown, ctx: ExtensionContext): Promise<unknown>;
}

function makeApi(tools: readonly { name: string }[] = [], registryFailure = false): FakeApi {
  const registered = new Map<string, Handler[]>();
  const entries: { customType: string; data: unknown }[] = [];
  const messages: { customType: string; content: string; display: boolean; deliverAs?: string }[] = [];
  const api = {
    on(event: string, handler: Handler) {
      const list = registered.get(event) ?? [];
      list.push(handler);
      registered.set(event, list);
      return () => undefined;
    },
    getAllTools: () => {
      if (registryFailure) throw new Error("tool registry unavailable");
      return tools;
    },
    getActiveTools: () => tools.map((tool) => tool.name),
    setActiveTools: () => undefined,
    appendEntry: (customType: string, data: unknown) => {
      entries.push({ customType, data });
    },
    sendMessage: (
      message: { customType: string; content: string; display: boolean },
      opts?: { deliverAs?: "steer" | "followUp" | "nextTurn" },
    ) => {
      messages.push({
        customType: message.customType,
        content: message.content,
        display: message.display,
        ...(opts?.deliverAs === undefined ? {} : { deliverAs: opts.deliverAs }),
      });
    },
    sendUserMessage: () => undefined,
  } as unknown as ExtensionAPI;
  return {
    api,
    handlers: (event) => registered.get(event) ?? [],
    appendEntries: () => entries,
    messages: () => messages,
    async fire(event, payload, ctx) {
      let result: unknown;
      for (const handler of registered.get(event) ?? []) result = await handler(payload, ctx);
      return result;
    },
  };
}

function makeCapture(input: StepCaptureInput): StepCapture {
  return {
    stepKey: input.stepKey,
    sessionId: input.sessionId,
    sourceEntryId: input.sourceEntryId,
    manifestRevision: input.manifestRevision,
    complete: true,
    directCalls: input.directCalls.map((call) => ({
      toolCallId: call.toolCallId as string,
      ...(call.parentToolCallId === undefined ? {} : { parentToolCallId: call.parentToolCallId }),
      toolName: call.toolName as string,
      arguments: call.arguments as Readonly<Record<string, unknown>>,
      argumentsDigest: call.argumentsDigest as string,
      ...(call.hostExecutionRequest === undefined ? {} : { hostExecutionRequest: call.hostExecutionRequest }),
      digest: `call:${call.toolCallId as string}`,
    })),
    digest: `digest:${input.stepKey}:${input.directCalls.length}`,
  } as unknown as StepCapture;
}

const capturePort: CaptureStepPort = (input) => ({ ok: true, capture: makeCapture(input) }) satisfies CaptureStepResult;

function makeUnits(capture: StepCapture): UnitPreparation[] {
  return capture.directCalls.map((call) => ({
    toolCallId: call.toolCallId,
    unitId: `${call.toolCallId}:whole`,
    actionDigest: call.digest,
    reason: "review this call",
  }));
}

interface FakeChain {
  readonly calls: RunStepChainInput[];
  readonly port: RunChainPort;
  resolve(value: RunStepChainResult): void;
}

function makeChain(onInput?: (input: RunStepChainInput) => void): FakeChain {
  const calls: RunStepChainInput[] = [];
  const resolvers: ((value: RunStepChainResult) => void)[] = [];
  return {
    calls,
    port: async (input) => {
      calls.push(input);
      onInput?.(input);
      return new Promise<RunStepChainResult>((resolve) => {
        resolvers.push(resolve);
      });
    },
    resolve: (value) => resolvers.shift()?.(value),
  };
}

function makeResult(
  capture: StepCapture,
  toolCallId: string,
  decision: "allow" | "deny" | "escalate",
  generation: number,
  reason = "worked-example reason",
): FinalCallResult {
  const publishedAt = Date.now();
  return {
    stepKey: capture.stepKey,
    sessionId: capture.sessionId,
    toolCallId,
    revision: 2,
    generation,
    decision,
    reasons: decision === "allow" ? [] : [{ unitId: `${toolCallId}:whole`, decision, askFor: decision === "escalate" ? "escalate" : undefined, reason }],
    publishedAt,
    expiresAt: publishedAt + 300_000,
  } as unknown as FinalCallResult;
}

function chainState(
  capture: StepCapture,
  decisions: readonly { toolCallId: string; decision: "allow" | "deny" | "escalate" | "ask" }[],
): unknown {
  return {
    stepKey: capture.stepKey,
    sessionId: capture.sessionId,
    sourceEntryId: capture.sourceEntryId,
    captureDigest: capture.digest,
    revision: 2,
    calls: capture.directCalls.map((call) => {
      const decision = decisions.find((entry) => entry.toolCallId === call.toolCallId)?.decision ?? "ask";
      return {
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        arguments: call.arguments,
        argumentsDigest: call.argumentsDigest,
        digest: call.digest,
        units: [{
          unitId: `${call.toolCallId}:whole`,
          decision,
          reason: "worked-example unit",
          source: "structure-analysis",
          history: [],
        }],
      };
    }),
    digest: "state-digest",
  };
}

function chainResult(
  capture: StepCapture,
  toolCallId: string,
  decision: "allow" | "deny" | "escalate",
  generation: number,
  reason?: string,
): RunStepChainResult {
  return {
    ok: true,
    state: chainState(capture, [{ toolCallId, decision }]) as never,
    results: [makeResult(capture, toolCallId, decision, generation, reason)],
    pendingToolCallIds: [],
    runs: [],
    faults: [],
    status: "completed",
  } as unknown as RunStepChainResult;
}

function chainResults(
  capture: StepCapture,
  decisions: readonly { toolCallId: string; decision: "allow" | "deny" | "escalate"; reason?: string }[],
  generation: number,
): RunStepChainResult {
  return {
    ok: true,
    state: chainState(capture, decisions) as never,
    results: decisions.map((entry) => makeResult(capture, entry.toolCallId, entry.decision, generation, entry.reason)),
    pendingToolCallIds: [],
    runs: [],
    faults: [],
    status: "completed",
  } as unknown as RunStepChainResult;
}

function makePublication(
  generation: number,
  mode: PermissionPublication["mode"] = "default",
  nodes: readonly NodeBinding[] = [],
): PermissionPublication {
  return {
    generation,
    nodes,
    mode,
    rulesRevision: 7,
    intentRevision: 9,
    learningEnabled: false,
    dispose: () => undefined,
  };
}

interface PublicationsHarness {
  readonly port: PublicationFactoryPort;
  readonly inputs: PublicationFactoryInput[];
  readonly disposed: number[];
}

function makePublications(
  modes: readonly PermissionPublication["mode"][] = ["default"],
  nodes: readonly NodeBinding[] = [],
): PublicationsHarness {
  const inputs: PublicationFactoryInput[] = [];
  const disposed: number[] = [];
  let index = 0;
  return {
    inputs,
    disposed,
    port: {
      async publish(input) {
        inputs.push(input);
        const mode = modes[Math.min(index, modes.length - 1)]!;
        index += 1;
        return {
          ...makePublication(input.generation, mode, nodes),
          dispose: () => { disposed.push(input.generation); },
        };
      },
    },
  };
}

function makeAnalysis(onAnalyze?: (capture: StepCapture) => void): AnalysisPort & { readonly calls: StepCapture[] } {
  const calls: StepCapture[] = [];
  return {
    calls,
    async analyze(capture) {
      calls.push(capture);
      onAnalyze?.(capture);
      return makeUnits(capture);
    },
  };
}

const contextStore: ContextStorePort = {
  create: () => ({
    disposed: false,
    begin: () => ({ ok: false as const, reason: "disposed" as const }),
    commit: () => ({ ok: false as const, reason: "disposed" as const }),
    invalidate: () => undefined,
    state: () => [],
    dispose: () => undefined,
  }) as unknown as ReviewerContextStore,
};

async function waitFor(predicate: () => boolean, label: string): Promise<void> {
  for (let index = 0; index < 200; index += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${label}`);
}
interface Harness {
  readonly extension: PermissionExtension;
  readonly api: FakeApi;
  readonly chain: FakeChain;
  readonly publications: PublicationsHarness;
  readonly analysis: AnalysisPort & { readonly calls: StepCapture[] };
  readonly audit: AuditEvent[];
  readonly memory: FakeMemory;
  readonly ctx: ExtensionContext;
  fire(event: string, payload: unknown): Promise<unknown>;
  toolCall(toolCallId?: string, toolName?: string, input?: Record<string, unknown>): Promise<{ block?: boolean; reason?: string; kind?: string } | undefined>;
}

function nodeBinding(
  id: string,
  position: "front" | "user" | "post",
  priority: number | null,
): NodeBinding {
  return {
    node: {
      apiVersion: "1",
      id,
      evaluate: () => ({ decisions: [] }),
    },
    position,
    priority,
  } as unknown as NodeBinding;
}

async function harness(options: {
  readonly modes?: readonly PermissionPublication["mode"][];
  readonly tools?: readonly { name: string }[];
  readonly onAnalyze?: (capture: StepCapture) => void;
  readonly publications?: PublicationFactoryPort;
  readonly sandbox?: SandboxPort;
  readonly bypassToolName?: string;
  readonly nodes?: readonly NodeBinding[];
  readonly learning?: LearningPort;
  readonly auditSink?: AuditSinkPort;
  readonly uiNotify?: () => void;
  readonly toolRegistryFailure?: boolean;
  readonly onChainInput?: (input: RunStepChainInput) => void;
  readonly bashPrograms?: AnalysisPort["bashPrograms"];
  readonly runChain?: RunChainPort;
  readonly captureStep?: CaptureStepPort;
} = {}): Promise<Harness> {
  const session = makeSession();
  const ctx = makeContext(session);
  if (options.uiNotify !== undefined) {
    (ctx.ui as unknown as { notify: () => void }).notify = () => options.uiNotify?.();
  }
  const memory = makeFakeMemory();
  const analysis = makeAnalysis(options.onAnalyze);
  if (options.bashPrograms !== undefined) Object.assign(analysis, { bashPrograms: options.bashPrograms });
  const publications = makePublications(options.modes ?? ["default"], options.nodes ?? []);
  const chain = makeChain(options.onChainInput);
  const audit: AuditEvent[] = [];
  const api = makeApi(options.tools ?? [{ name: "bash" }, { name: "write" }], options.toolRegistryFailure === true);
  const extension = createPermissionExtension({
    publications: options.publications ?? publications.port,
    analysis,
    captureStep: options.captureStep ?? capturePort,
    runChain: options.runChain ?? chain.port,
    memory: { create: () => memory.memory } satisfies MemoryPort,
    contextStore,
    ...(options.sandbox === undefined ? {} : { sandbox: options.sandbox }),
    ...(options.bypassToolName === undefined ? {} : { bypassToolName: options.bypassToolName }),
    ...(options.learning === undefined ? {} : { learning: options.learning }),
    audit: {
      write: (event) => {
        audit.push(event);
        options.auditSink?.write(event);
      },
    },
  });
  extension.install(api.api);
  await api.fire("session_start", { type: "session_start", reason: "startup" }, ctx);
  return {
    extension,
    api,
    chain,
    publications,
    analysis,
    audit,
    memory,
    ctx,
    fire: (event, payload) => api.fire(event, payload, ctx),
    async toolCall(toolCallId = "call-1", toolName = "bash", input = { command: "ls" }) {
      const event = { type: "tool_call", toolCallId, toolName, input } as unknown as ToolCallEvent;
      return (await api.fire("tool_call", event, ctx)) as
        | { block?: boolean; reason?: string; kind?: string }
        | undefined;
    },
  };
}

// ---------------------------------------------------------------------------
// §5 publication lifecycle
// ---------------------------------------------------------------------------

describe("host publication lifecycle (§5)", () => {
  it("publishes one generation on session_start and audits it", async () => {
    const h = await harness();
    expect(h.publications.inputs).toHaveLength(1);
    expect(h.publications.inputs[0]?.generation).toBe(1);
    expect(h.extension.state().sessions[0]?.generation).toBe(1);
    expect(h.extension.state().sessions[0]?.publication).toBe("ready");
    expect(h.audit.some((event) => event.kind === "publication" && event.generation === 1)).toBe(true);
  });

  it("applies a session mode to future steps without publishing a new generation", async () => {
    const chainInputs: RunStepChainInput[] = [];
    const h = await harness({ onChainInput: (input) => chainInputs.push(input) });
    const generation = h.extension.state().sessions[0]?.generation;

    h.extension.setSessionMode(SESSION_ID, "read-only");
    const call = h.toolCall("call-session-mode");
    await waitFor(() => h.chain.calls.length === 1, "session-mode chain run");

    expect(h.extension.state().sessions[0]?.mode).toBe("read-only");
    expect(h.extension.state().sessions[0]?.generation).toBe(generation);
    expect(h.publications.inputs).toHaveLength(1);
    expect(chainInputs[0]?.mode).toBe("read-only");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-session-mode", "allow", generation!));
    expect(await call).toBeUndefined();
  });

  it("keeps the previous publication when a reload fails and stays unavailable on a first failure", async () => {
    const session = makeSession();
    const ctx = makeContext(session);
    const disposed: number[] = [];
    const configurationChanges: string[] = [];
    let fail = false;
    const port: PublicationFactoryPort = {
      async publish(input) {
        if (fail) throw new Error("config unavailable");
        return { ...makePublication(input.generation), dispose: () => { disposed.push(input.generation); } };
      },
    };
    const api = makeApi();
    const extension = createPermissionExtension({
      publications: port,
      analysis: makeAnalysis(),
      captureStep: capturePort,
      runChain: makeChain().port,
      memory: { create: () => makeFakeMemory().memory },
      contextStore,
      sandbox: {
        guard: async (_event, _ctx, review) => review(),
        configurationChanged: (sessionId) => configurationChanges.push(sessionId),
      },
      audit: { write: () => undefined },
    });
    extension.install(api.api);
    fail = true;
    await api.fire("session_start", { type: "session_start", reason: "startup" }, ctx);
    expect(extension.state().sessions[0]?.generation).toBe(0);
    expect(extension.state().sessions[0]?.publication).toBe("unavailable");

    fail = false;
    await api.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" }, ctx);
    expect(extension.state().sessions[0]?.generation).toBe(1);
    expect(configurationChanges).toEqual([SESSION_ID]);

    fail = true;
    await api.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" }, ctx);
    expect(extension.state().sessions[0]?.generation).toBe(1);
    expect(configurationChanges).toEqual([SESSION_ID]);
    expect(disposed).toHaveLength(0);
  });

  it("commits a reload configuration only after its publication succeeds", async () => {
    const session = makeSession();
    const ctx = makeContext(session);
    let candidateValue = "initial";
    let activeValue: string | undefined;
    let fail = false;
    const publishedValues: unknown[] = [];
    const committedValues: string[] = [];
    const configurationChanges: string[] = [];
    const reloadNotifications: string[] = [];
    const port: PublicationFactoryPort = {
      prepareReload() {
        const value = candidateValue;
        return {
          configuration: value,
          commit() {
            activeValue = value;
            committedValues.push(value);
            return true;
          },
        };
      },
      didReload: (_ctx, sessionId) => reloadNotifications.push(sessionId),
      async publish(input) {
        publishedValues.push(input.configuration);
        if (input.generation > 1) expect(activeValue).toBe("initial");
        if (fail) throw new Error("publication failed");
        return makePublication(input.generation);
      },
    };
    const api = makeApi();
    const extension = createPermissionExtension({
      publications: port,
      analysis: makeAnalysis(),
      captureStep: capturePort,
      runChain: makeChain().port,
      memory: { create: () => makeFakeMemory().memory },
      contextStore,
      sandbox: {
        guard: async (_event, _ctx, review) => review(),
        configurationChanged: (sessionId) => configurationChanges.push(sessionId),
      },
      audit: { write: () => undefined },
    });
    extension.install(api.api);
    await api.fire("session_start", { type: "session_start", reason: "startup" }, ctx);
    activeValue = "initial";
    expect(activeValue).toBe("initial");

    candidateValue = "reloaded";
    fail = true;
    expect(await extension.reload(ctx)).toBe(false);
    expect(activeValue).toBe("initial");
    expect(committedValues).toEqual([]);
    expect(configurationChanges).toEqual([]);
    expect(reloadNotifications).toEqual([]);

    fail = false;
    expect(await extension.reload(ctx)).toBe(true);
    expect(activeValue).toBe("reloaded");
    expect(committedValues).toEqual(["reloaded"]);
    expect(configurationChanges).toEqual([SESSION_ID]);
    expect(reloadNotifications).toEqual([SESSION_ID]);
    expect(publishedValues).toEqual([undefined, "reloaded", "reloaded"]);
  });

  it("discards a superseded node candidate and releases its actual generation", async () => {
    const node = {
      id: "user/check",
      source: "global" as const,
      position: "user" as const,
      order: 0,
      enabled: true,
      path: "check.js",
      priority: 0,
    };
    const nodeConfig: EffectiveNodeConfiguration = { nodes: [node], warnings: [], digest: "config-digest" };
    const plan: ApprovalNodeLoadPlan = {
      effectiveNodes: [node],
      nodeConfig,
      configDigest: "config-digest",
      globalConfigDir: join(tmpdir(), "pi-node-global"),
      projectConfigDir: join(tmpdir(), "pi-node-project"),
      projectTrusted: false,
    };
    const permissions = {
      checkPermission: () => ({ state: "ask" as const, origin: "unavailable" }),
      getToolPermission: () => "ask" as const,
    };
    const disposedModules: number[] = [];
    const configurationChanges: string[] = [];
    const loadedPublications: { outer: number; actual: number }[] = [];
    let moduleId = 0;
    let supersedeNextCandidate = false;
    let extension!: PermissionExtension;
    const nodeHost = createApprovalNodeHost({
      importModule: async () => {
        const id = ++moduleId;
        return {
          apiVersion: "1",
          createNode: () => ({ apiVersion: "1", id: "user/check", evaluate: () => ({ decisions: [] }) }),
          dispose: () => { disposedModules.push(id); },
        };
      },
    });
    const publications: PublicationFactoryPort = {
      prepareReload() {
        const mode = extension.state().sessions[0]?.mode;
        return { configuration: mode, commit: () => extension.state().sessions[0]?.mode === mode };
      },
      async publish(input) {
        const candidate = await nodeHost.prepare({ plan, permissions });
        loadedPublications.push({ outer: input.generation, actual: candidate.publication.generation });
        if (supersedeNextCandidate) {
          supersedeNextCandidate = false;
          extension.setSessionMode(SESSION_ID, "read-only");
        }
        let committed = false;
        let disposed = false;
        return {
          ...makePublication(input.generation),
          commit() {
            committed = candidate.commit();
            return committed;
          },
          async dispose() {
            if (disposed) return;
            disposed = true;
            if (committed) await nodeHost.release(candidate.publication.generation);
            else await candidate.dispose();
          },
        };
      },
    };
    const h = await harness({
      publications,
      sandbox: {
        guard: async (_event, _ctx, review) => review(),
        configurationChanged: (sessionId) => configurationChanges.push(sessionId),
      },
    });
    extension = h.extension;

    supersedeNextCandidate = true;
    expect(await extension.reload(h.ctx)).toBe(false);
    expect(extension.state().sessions[0]?.generation).toBe(1);
    expect(nodeHost.current()?.generation).toBe(1);
    expect(disposedModules).toEqual([2]);
    expect(configurationChanges).toEqual([]);

    expect(await extension.reload(h.ctx)).toBe(true);
    expect(disposedModules).toEqual([2, 1]);
    expect(await extension.reload(h.ctx)).toBe(true);
    expect(configurationChanges).toEqual([SESSION_ID, SESSION_ID]);
    expect(loadedPublications).toEqual([
      { outer: 1, actual: 1 },
      { outer: 2, actual: 2 },
      { outer: 2, actual: 2 },
      { outer: 3, actual: 3 },
    ]);
    expect(disposedModules).toEqual([2, 1, 3]);

    await extension.dispose();
    await nodeHost.dispose();
    expect(disposedModules).toEqual([2, 1, 3, 4]);
  });

  it("never installs a publication that resolves after shutdown and releases it", async () => {
    const session = makeSession();
    const ctx = makeContext(session);
    const disposed: number[] = [];
    let release: (() => void) | undefined;
    const port: PublicationFactoryPort = {
      publish: (input) =>
        new Promise<PermissionPublication>((resolve) => {
          release = () => resolve({
            ...makePublication(input.generation),
            dispose: () => { disposed.push(input.generation); },
          });
        }),
    };
    const api = makeApi();
    const extension = createPermissionExtension({
      publications: port,
      analysis: makeAnalysis(),
      captureStep: capturePort,
      runChain: makeChain().port,
      memory: { create: () => makeFakeMemory().memory },
      contextStore,
      audit: { write: () => undefined },
    });
    extension.install(api.api);
    const starting = api.fire("session_start", { type: "session_start", reason: "startup" }, ctx);
    await waitFor(() => release !== undefined, "deferred publication start");
    const shutdown = api.fire("session_shutdown", { type: "session_shutdown", reason: "new" }, ctx);
    release?.();
    await Promise.all([starting, shutdown]);
    expect(extension.state().sessions).toHaveLength(0);
    expect(disposed).toEqual([1]);
  });

  it("serializes reloads and a reload only affects future steps", async () => {
    const h = await harness();
    const call = h.toolCall("call-1");
    await waitFor(() => h.chain.calls.length === 1, "first chain run");
    expect(h.chain.calls[0]?.generation).toBe(1);
    await Promise.all([
      h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" }),
      h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" }),
    ]);
    expect(h.publications.inputs.map((input) => input.generation)).toEqual([1, 2, 3]);

    // The old step is fenced: its late allow is never published.
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-1", "allow", 1));
    expect(await call).toEqual({ block: true, reason: expect.stringContaining("permission:generation-stale") });

    // A step started afterwards uses the current publication.
    const next = h.toolCall("call-2");
    await waitFor(() => h.chain.calls.length === 2, "reloaded chain run");
    expect(h.chain.calls[1]?.generation).toBe(3);
    h.chain.resolve(chainResult(h.chain.calls[1]!.capture, "call-2", "allow", 3));
    expect(await next).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §6 tool call processing
// ---------------------------------------------------------------------------

describe("host tool call processing (§6)", () => {
  it("blocks every call when no publication is available", async () => {
    const session = makeSession();
    const ctx = makeContext(session);
    const api = makeApi();
    const extension = createPermissionExtension({
      publications: { publish: async () => { throw new Error("no config"); } },
      analysis: makeAnalysis(),
      captureStep: capturePort,
      runChain: makeChain().port,
      memory: { create: () => makeFakeMemory().memory },
      contextStore,
      audit: { write: () => undefined },
    });
    extension.install(api.api);
    await api.fire("session_start", { type: "session_start", reason: "startup" }, ctx);
    const answer = await api.fire("tool_call", { type: "tool_call", toolCallId: "call-1", toolName: "bash", input: { command: "ls" } } as unknown as ToolCallEvent, ctx);
    expect(answer).toEqual({ block: true, reason: expect.stringContaining("permission:config-unavailable") });
  });

  it("passes an allow result through and blocks a deny with the aggregated reasons", async () => {
    const allowed = await harness();
    const allowCall = allowed.toolCall("call-1");
    await waitFor(() => allowed.chain.calls.length === 1, "allow chain run");
    allowed.chain.resolve(chainResult(allowed.chain.calls[0]!.capture, "call-1", "allow", 1));
    expect(await allowCall).toBeUndefined();

    const denied = await harness();
    const denyCall = denied.toolCall("call-2");
    await waitFor(() => denied.chain.calls.length === 1, "deny chain run");
    denied.chain.resolve(chainResult(denied.chain.calls[0]!.capture, "call-2", "deny", 1));
    const answer = await denyCall;
    expect(answer?.block).toBe(true);
    expect(answer?.reason).toContain("worked-example reason");
  });

  it("maps an escalation result to a block when no sandbox channel exists", async () => {
    const h = await harness();
    const call = h.toolCall("call-3");
    await waitFor(() => h.chain.calls.length === 1, "escalation chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-3", "escalate", 1));
    expect(await call).toMatchObject({
      block: true,
      reason: expect.stringContaining("ordinary-host-execution-forbidden"),
    });
  });

  it("blocks instead of mixing evidence when the session changes during analysis", async () => {
    let h!: Harness;
    h = await harness({ onAnalyze: () => h.memory.bumpAuthorization() });
    const answer = await h.toolCall("call-4");
    expect(answer).toEqual({ block: true, reason: expect.stringContaining("permission:evidence-changed") });
    expect(h.chain.calls).toHaveLength(0);
  });

  it("shares analysis and one step run between concurrent calls of a complete manifest", async () => {
    const h = await harness({ tools: [{ name: "bash" }] });
    h.memory.setManifest({
      stepKey: "step-entry-1",
      sourceEntryId: "entry-1",
      revision: 0,
      complete: true,
      directCalls: [
        { toolCallId: "call-a", toolName: "bash", arguments: { command: "ls" }, argumentsDigest: reviewDigest({ command: "ls" }) },
        { toolCallId: "call-b", toolName: "bash", arguments: { command: "pwd" }, argumentsDigest: reviewDigest({ command: "pwd" }) },
      ],
    });
    const analyze = h.analysis.analyze.bind(h.analysis);
    const releases: (() => void)[] = [];
    let analysisCount = 0;
    let providerCount = 0;
    h.analysis.analyze = async (capture, input) => {
      analysisCount += 1;
      await new Promise<void>((resolve) => releases.push(resolve));
      return analyze(capture, input);
    };
    h.analysis.bashPrograms = () => {
      providerCount += 1;
      return async () => undefined;
    };
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await waitFor(() => releases.length === 1, "first manifest analysis");
    const second = h.toolCall("call-b", "bash", { command: "pwd" });
    expect(analysisCount).toBe(1);
    expect(h.chain.calls).toHaveLength(0);
    releases[0]!();
    await waitFor(() => h.chain.calls.length === 1, "manifest chain run");
    expect(h.analysis.calls).toHaveLength(1);
    expect(providerCount).toBe(1);
    await Promise.resolve();
    h.chain.resolve(chainResults(h.chain.calls[0]!.capture, [
      { toolCallId: "call-a", decision: "allow" },
      { toolCallId: "call-b", decision: "deny", reason: "second call denied" },
    ], 1));
    expect(await first).toBeUndefined();
    const secondAnswer = await second;
    expect(secondAnswer?.block).toBe(true);
    expect(secondAnswer?.reason).toContain("second call denied");
    expect(h.chain.calls).toHaveLength(1);
  });

  it("holds one publication reference across shared preparation during reload", async () => {
    const h = await harness({ tools: [{ name: "bash" }] });
    h.memory.setManifest({
      stepKey: "step-reload-preparing",
      sourceEntryId: "entry-reload-preparing",
      revision: 0,
      complete: true,
      directCalls: [
        { toolCallId: "call-a", toolName: "bash", arguments: { command: "ls" }, argumentsDigest: reviewDigest({ command: "ls" }) },
        { toolCallId: "call-b", toolName: "bash", arguments: { command: "pwd" }, argumentsDigest: reviewDigest({ command: "pwd" }) },
      ],
    });
    const analyze = h.analysis.analyze.bind(h.analysis);
    let release!: () => void;
    let analysisCount = 0;
    h.analysis.analyze = async (capture, input) => {
      analysisCount += 1;
      await new Promise<void>((resolve) => { release = resolve; });
      return analyze(capture, input);
    };
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await waitFor(() => release !== undefined, "deferred preparation");
    const second = h.toolCall("call-b", "bash", { command: "pwd" });
    expect(analysisCount).toBe(1);

    await h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" });
    expect(h.publications.disposed).toEqual([]);
    release();
    expect(await first).toEqual({ block: true, reason: expect.stringContaining("permission:generation-stale") });
    expect(await second).toEqual({ block: true, reason: expect.stringContaining("permission:generation-stale") });
    await waitFor(() => h.publications.disposed.includes(1), "preparation reference release");
    expect(h.publications.disposed).toEqual([1]);
    expect(h.chain.calls).toHaveLength(0);
  });

  it("cancels waiters and keeps a replacement preparation when old analysis finishes late", async () => {
    const h = await harness({ tools: [{ name: "bash" }] });
    h.memory.setManifest({
      stepKey: "step-retry-preparing",
      sourceEntryId: "entry-retry-preparing",
      revision: 0,
      complete: true,
      directCalls: [
        { toolCallId: "call-a", toolName: "bash", arguments: { command: "ls" }, argumentsDigest: reviewDigest({ command: "ls" }) },
        { toolCallId: "call-b", toolName: "bash", arguments: { command: "pwd" }, argumentsDigest: reviewDigest({ command: "pwd" }) },
        { toolCallId: "call-c", toolName: "bash", arguments: { command: "git status" }, argumentsDigest: reviewDigest({ command: "git status" }) },
      ],
    });
    const analyze = h.analysis.analyze.bind(h.analysis);
    const releases: (() => void)[] = [];
    const signals: AbortSignal[] = [];
    h.analysis.analyze = async (capture, input) => {
      signals.push(input.signal!);
      await new Promise<void>((resolve) => releases.push(resolve));
      return analyze(capture, input);
    };
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await waitFor(() => releases.length === 1, "first retry preparation");
    await h.fire("input", { type: "input", text: "new task", source: "interactive" });
    expect(signals[0]?.aborted).toBe(true);
    expect(await first).toEqual({ block: true, reason: expect.stringContaining("permission:evidence-changed") });

    const retry = h.toolCall("call-a", "bash", { command: "ls" });
    await waitFor(() => releases.length === 2, "replacement preparation");
    releases[0]!();
    await Promise.resolve();
    const sibling = h.toolCall("call-b", "bash", { command: "pwd" });
    expect(releases).toHaveLength(2);
    releases[1]!();
    await waitFor(() => h.chain.calls.length === 1, "replacement chain run");
    h.chain.resolve(chainResults(h.chain.calls[0]!.capture, [
      { toolCallId: "call-a", decision: "allow" },
      { toolCallId: "call-b", decision: "allow" },
      { toolCallId: "call-c", decision: "deny" },
    ], 1));
    expect(await retry).toBeUndefined();
    expect(await sibling).toBeUndefined();
    expect(h.analysis.calls).toHaveLength(2);
    expect(h.chain.calls).toHaveLength(1);
  });

  it("uses each settled manifest call outcome and blocks a repeated call id", async () => {
    const h = await harness({ tools: [{ name: "write" }] });
    const firstInput = { path: "E:/AGENT/pi-test-file.txt", content: "ok" };
    const secondInput = { path: "C:/Users/86152/AppData/Local/Temp/pi-test-file-external.txt", content: "ok" };
    h.memory.setManifest({
      stepKey: "step-sequential",
      sourceEntryId: "entry-sequential",
      revision: 0,
      complete: true,
      directCalls: [
        { toolCallId: "call-first", toolName: "write", arguments: firstInput, argumentsDigest: reviewDigest(firstInput) },
        { toolCallId: "call-second", toolName: "write", arguments: secondInput, argumentsDigest: reviewDigest(secondInput) },
      ],
    });

    const first = h.toolCall("call-first", "write", firstInput);
    await waitFor(() => h.chain.calls.length === 1, "sequential manifest chain run");
    await waitFor(() => h.analysis.calls[0]?.directCalls.length === 2, "complete manifest analysis");
    h.chain.resolve(chainResults(h.chain.calls[0]!.capture, [
      { toolCallId: "call-first", decision: "allow" },
      { toolCallId: "call-second", decision: "deny", reason: "outside write denied" },
    ], 1));
    expect(await first).toBeUndefined();

    const second = await h.toolCall("call-second", "write", secondInput);
    expect(second?.reason).toContain("outside write denied");
    expect(h.chain.calls).toHaveLength(1);

    expect(await h.toolCall("call-first", "write", firstInput)).toEqual({
      block: true,
      reason: expect.stringContaining("permission:duplicate-call"),
    });
    expect(h.chain.calls).toHaveLength(1);
  });

  it("rejects a changed call while its shared step is pending", async () => {
    const h = await harness();
    h.memory.setManifest({
      stepKey: "step-changed",
      sourceEntryId: "entry-changed",
      revision: 0,
      complete: true,
      directCalls: [
        { toolCallId: "call-a", toolName: "bash", arguments: { command: "ls" }, argumentsDigest: reviewDigest({ command: "ls" }) },
        { toolCallId: "call-b", toolName: "bash", arguments: { command: "pwd" }, argumentsDigest: reviewDigest({ command: "pwd" }) },
      ],
    });
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await waitFor(() => h.chain.calls.length === 1, "pending chain");
    const changed = h.toolCall("call-b", "bash", { command: "changed" });
    const renamed = h.toolCall("call-b", "write", { command: "pwd" });
    const nested = h.fire("tool_call", { type: "tool_call", toolCallId: "call-b", toolName: "bash", input: { command: "pwd" }, parentToolCallId: "parent" });
    h.chain.resolve(chainResults(h.chain.calls[0]!.capture, [
      { toolCallId: "call-a", decision: "allow" },
      { toolCallId: "call-b", decision: "allow" },
    ], 1));
    expect(await changed).toEqual({ block: true, reason: expect.stringContaining("permission:capture-mismatch") });
    expect(await renamed).toEqual({ block: true, reason: expect.stringContaining("permission:duplicate-call") });
    expect(await nested).toEqual({ block: true, reason: expect.stringContaining("permission:duplicate-call") });
    expect(await first).toBeUndefined();
  });

  it("rejects a step invalidated while bash facts are collecting", async () => {
    let release!: () => void;
    let started = false;
    const h = await harness({ bashPrograms: () => async () => {
      started = true;
      await new Promise<void>((resolve) => { release = resolve; });
      return undefined;
    } });
    const call = h.toolCall("call-delayed");
    await waitFor(() => started, "bash facts");
    await h.fire("mcp_servers_change", { type: "mcp_servers_change" });
    release();
    let settled = false;
    void call.then(() => { settled = true; });
    await waitFor(() => settled || h.chain.calls.length > 0, "invalidated result or chain");
    if (h.chain.calls.length > 0) h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-delayed", "allow", 1));
    expect(await call).toEqual({ block: true, reason: expect.stringContaining("permission:evidence-changed") });
    expect(h.chain.calls).toHaveLength(0);
  });

  it("asks the injected human selector and maps no selection to a cancel", async () => {
    const h = await harness();
    const call = h.toolCall("call-5");
    await waitFor(() => h.chain.calls.length === 1, "human chain run");
    const human = h.chain.calls[0]?.human;
    expect(human).toBeTypeOf("function");
    const response = await human!({
      capture: h.chain.calls[0]!.capture,
      call: {
        toolCallId: "call-5",
        toolName: "bash",
        arguments: { command: "ls" },
        argumentsDigest: "d",
        digest: "c",
        units: [],
      } as never,
      summary: { toolCallId: "call-5", decision: "ask", askFor: "allow", reasons: [], pendingUnitIds: [] } as never,
      state: {} as never,
      signal: new AbortController().signal,
    });
    expect(response.decision).toBe("cancel");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-5", "allow", 1));
    expect(await call).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §6 sandbox bypass channel
// ---------------------------------------------------------------------------

describe("host sandbox bypass channel (§6)", () => {
  it("does not reuse an approval when the host execution reason changes", async () => {
    const h = await harness();
    const request = {
      toolCallId: "call-bypass-changed",
      targetToolName: "write",
      arguments: { path: "a.txt", content: "x" },
      reason: "first",
      elevation: { tier: "host" as const, scope: [{ path: "a.txt", access: "write" as const }] },
    };
    const first = h.extension.reviewSandboxBypass(request, h.ctx as never);
    await waitFor(() => h.chain.calls.length === 1, "bypass chain run");
    const changed = h.extension.reviewSandboxBypass({ ...request, reason: "second" }, h.ctx as never);
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, request.toolCallId, "escalate", 1));
    expect(await changed).toEqual({ block: true, reason: "permission:capture-mismatch" });
    expect(await first).toBeUndefined();
  });

  it("answers an escalation in the dedicated bypass channel with a host-execution result", async () => {
    const h = await harness();
    const answerPromise = h.extension.reviewSandboxBypass(
      {
        toolCallId: "call-6",
        targetToolName: "write",
        arguments: { path: "a.txt", content: "x" },
        reason: "need host access",
        elevation: { tier: "host", scope: [{ path: "a.txt", access: "write" }] },
      },
      h.ctx as never,
    );
    await waitFor(() => h.chain.calls.length === 1, "bypass chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-6", "escalate", 1, "need host access"));
    const answer = await answerPromise;
    expect(answer).toBeUndefined();
  });

  it("refuses a bypass elevation when the approval chain denies it", async () => {
    const h = await harness();
    const answerPromise = h.extension.reviewSandboxBypass(
      {
        toolCallId: "call-6d",
        targetToolName: "write",
        arguments: { path: "a.txt", content: "x" },
        reason: "need host access",
        elevation: { tier: "host", scope: [{ path: "a.txt", access: "write" }] },
      },
      h.ctx as never,
    );
    await waitFor(() => h.chain.calls.length === 1, "bypass deny chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-6d", "deny", 1, "denied by the reviewer"));
    const answer = await answerPromise;
    expect(answer).toEqual({ block: true, reason: "permission:denied: denied by the reviewer" });
  });
});

// ---------------------------------------------------------------------------
// §6 sandbox guard channel
// ---------------------------------------------------------------------------

describe("host sandbox guard channel (§6)", () => {
  it("leaves the configured bypass tool to its dedicated review channel", async () => {
    let guarded = 0;
    const h = await harness({
      bypassToolName: "request_sandbox_bypass",
      sandbox: {
        guard: async () => {
          guarded += 1;
          return undefined;
        },
      },
    });

    expect(await h.toolCall("call-bypass", "request_sandbox_bypass", {})).toBeUndefined();
    expect(guarded).toBe(0);
    expect(h.chain.calls).toHaveLength(0);
  });

  it("routes the approval review through the injected sandbox guard", async () => {
    const seen: string[] = [];
    const h = await harness({
      sandbox: {
        guard: async (event, _ctx, review) => {
          seen.push(event.toolCallId);
          return review();
        },
      },
    });
    const call = h.toolCall("call-g");
    await waitFor(() => h.chain.calls.length === 1, "guard chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-g", "allow", 1));
    expect(await call).toBeUndefined();
    expect(seen).toEqual(["call-g"]);
  });

  it("honours a sandbox guard block without running the approval chain", async () => {
    const h = await harness({
      sandbox: { guard: async () => ({ block: true, reason: "sandbox:unmanaged-tool" }) },
    });
    expect(await h.toolCall("call-h")).toEqual({ block: true, reason: expect.stringContaining("sandbox:unmanaged-tool") });
    expect(h.chain.calls).toHaveLength(0);
  });

  it("notifies the sandbox host about invalidation and configuration reloads", async () => {
    const invalidated: string[] = [];
    const changed: string[] = [];
    const h = await harness({
      sandbox: {
        guard: async (_event, _ctx, review) => review(),
        invalidate: (sessionId) => invalidated.push(sessionId),
        configurationChanged: (sessionId) => changed.push(sessionId),
      },
    });
    await h.fire("input", { type: "input", text: "switch task", source: "interactive" });
    await h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" });
    expect(invalidated).toEqual([SESSION_ID]);
    expect(changed).toEqual([SESSION_ID]);
  });
});

// ---------------------------------------------------------------------------
// §7 session events
// ---------------------------------------------------------------------------

describe("host session events (§7)", () => {
  it("invalidates settled results after a non-extension user input and sends the mode reminder", async () => {
    const h = await harness();
    const first = h.toolCall("call-7");
    await waitFor(() => h.chain.calls.length === 1, "settle chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-7", "allow", 1));
    expect(await first).toBeUndefined();
    expect(h.extension.state().sessions[0]?.settledCalls).toBe(1);

    await h.fire("input", { type: "input", text: "use the other file", source: "interactive" });
    expect(h.extension.state().sessions[0]?.settledCalls).toBe(0);
    const reminders = h.api.messages().filter((message) => message.customType === "permission:mode-reminder");
    expect(reminders).toHaveLength(1);
    expect(reminders[0]?.display).toBe(false);
    expect(h.audit.some((event) => event.kind === "mode-reminder")).toBe(true);
  });

  it("never sends a mode reminder for extension input", async () => {
    const h = await harness();
    await h.fire("input", { type: "input", text: "extension note", source: "extension" });
    expect(h.api.messages()).toHaveLength(0);
  });

  it("invalidates host results on compaction, navigation and MCP server changes", async () => {
    const h = await harness();
    await h.fire("session_compact", { type: "session_compact", compactionEntry: {}, fromExtension: false, reason: "manual", willRetry: false });
    await h.fire("session_tree", { type: "session_tree", newLeafId: "leaf-2", oldLeafId: null });
    await h.fire("mcp_servers_change", { type: "mcp_servers_change", servers: [] });
    const invalidations = h.audit.filter((event) => event.kind === "invalidate");
    expect(invalidations.length).toBeGreaterThanOrEqual(3);
    expect(h.memory.revisions.navigation).toBeGreaterThan(1);
  });

  it("disposes session resources and the current publication on shutdown", async () => {
    const h = await harness();
    await h.fire("session_shutdown", { type: "session_shutdown", reason: "quit" });
    expect(h.extension.state().sessions).toHaveLength(0);
    expect(h.publications.disposed).toEqual([1]);
  });
});

// ---------------------------------------------------------------------------
// §9 default human selector facts
// ---------------------------------------------------------------------------

describe("default human selector facts (§9)", () => {
  it("keeps a human-approved recursive deletion in the sandbox", async () => {
    const h = await harness({
      sandbox: { guard: async (_event, _ctx, review) => review({ ask: true }) },
      runChain: async input => chainResult(input.capture, input.capture.directCalls[0]!.toolCallId,
        "escalate", input.generation, "risk:workspace-bulk-delete:needs-confirmation:recursive-delete"),
    });
    expect(await h.toolCall("delete-build", "bash", { command: "rm -rf build" })).toBeUndefined();
  });
  function request(escalation: boolean) {
    return {
      capture: { directCalls: [{ toolName: "write", arguments: { path: "a.txt", content: "secret" } }] } as never,
      call: { toolCallId: "call-9", toolName: "write", arguments: { path: "a.txt", content: "secret" } } as never,
      summary: {
        toolCallId: "call-9",
        decision: "ask",
        askFor: escalation ? "escalate" : "allow",
        reasons: [{ unitId: "u", decision: "ask", reason: escalation ? "sandbox blocked the write" : "write outside workspace" }],
        pendingUnitIds: [],
      } as never,
      state: {} as never,
      signal: new AbortController().signal,
    };
  }

  it("shows the reason, tool and final arguments for an escalation request", () => {
    const facts = humanPromptFacts(request(true));
    expect(facts.escalation).toBe(true);
    expect(facts.title).toContain("sandbox blocked the write");
    expect(facts.title).toContain("write");
    expect(facts.title).toContain("a.txt");
  });

  it("does not disguise a normal request as an escalation", () => {
    const facts = humanPromptFacts(request(false));
    expect(facts.escalation).toBe(false);
    expect(facts.title.toLowerCase()).not.toContain("host execution");
    expect(facts.title.toLowerCase()).not.toContain("escalat");
  });
});

// ---------------------------------------------------------------------------
// Spec-conformance fixes (retired generations, learning seam, audit, ordering)
// ---------------------------------------------------------------------------

interface FakeLearningPort {
  readonly port: LearningPort;
  readonly model: ReviewerLearningLifecycle;
  readonly finalized: LearningFinalizeInput[];
  readonly discarded: string[];
  readonly disposeCount: () => number;
}

function makeLearningPort(): FakeLearningPort {
  const finalized: LearningFinalizeInput[] = [];
  const discarded: string[] = [];
  let disposed = 0;
  const model = {
    beginAttempt: () => "attempt-1",
    stage: () => 0,
    accept: () => undefined,
    discardAttempt: () => undefined,
  } as unknown as ReviewerLearningLifecycle;
  return {
    model,
    finalized,
    discarded,
    disposeCount: () => disposed,
    port: {
      create: () => ({
        model,
        stepRunner: {
          finalize: (input) => {
            finalized.push(input);
            return { ok: false as const, reason: "no-pending" };
          },
          discard: (toolCallId) => {
            discarded.push(toolCallId);
          },
        },
        dispose: () => {
          disposed += 1;
        },
      }),
    },
  };
}

describe("host spec-conformance fixes", () => {
  it("disposes a superseded publication once the step holding it ends", async () => {
    const h = await harness();
    const call = h.toolCall("call-retire");
    await waitFor(() => h.chain.calls.length === 1, "first chain run");
    await h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" });
    await h.fire("resources_discover", { type: "resources_discover", cwd: CWD, reason: "reload" });
    // The step still pins generation 1, so the second retired generation is
    // disposed at once while generation 1 waits for the step to end.
    expect(h.publications.disposed).toEqual([2]);

    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-retire", "allow", 1));
    expect(await call).toEqual({ block: true, reason: expect.stringContaining("permission:generation-stale") });
    await waitFor(() => h.publications.disposed.includes(1), "retired generation release");
    expect(new Set(h.publications.disposed)).toEqual(new Set([1, 2]));
  });

  it("passes the model lifecycle to the publication and the runner lifecycle to the step runner", async () => {
    const learning = makeLearningPort();
    const h = await harness({ learning: learning.port });
    expect(h.publications.inputs[0]?.session.learning).toBe(learning.model);

    const call = h.toolCall("call-learn");
    await waitFor(() => h.chain.calls.length === 1, "learning chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-learn", "allow", 1));
    expect(await call).toBeUndefined();
    await waitFor(() => learning.finalized.length === 1, "learning finalize");
    expect(learning.finalized[0]?.stepKey).toBe("call:call-learn");
    expect(learning.finalized[0]?.calls.map((entry) => entry.decision)).toEqual(["allow"]);
  });

  it("audits accepted unit decisions with the step identity", async () => {
    const h = await harness({
      onChainInput: (input) => {
        input.host?.unitsAccepted?.([
          {
            toolCallId: "call-unit",
            unitId: "call-unit:whole",
            nodeId: "builtin/rules",
            revision: 2,
            decision: "deny",
            reason: "rules:bash:deny:pattern:value",
          },
        ] as never);
      },
    });
    const call = h.toolCall("call-unit");
    await waitFor(() => h.chain.calls.length === 1, "unit audit chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-unit", "allow", 1));
    expect(await call).toBeUndefined();
    const unitAudit = h.audit.find((event) => event.kind === "unit-change");
    expect(unitAudit).toEqual(expect.objectContaining({
      sessionId: SESSION_ID,
      generation: 1,
      stepKey: "call:call-unit",
      changes: [
        expect.objectContaining({
          toolCallId: "call-unit",
          unitId: "call-unit:whole",
          nodeId: "builtin/rules",
          decision: "deny",
        }),
      ],
    }));
  });

  it("warns at most once per session when the audit sink fails and keeps decisions", async () => {
    let notifications = 0;
    const h = await harness({
      uiNotify: () => {
        notifications += 1;
      },
      auditSink: {
        write: () => {
          throw new Error("audit log is read-only");
        },
      },
    });
    await h.fire("input", { type: "input", text: "first", source: "interactive" });
    await h.fire("input", { type: "input", text: "second", source: "interactive" });
    expect(notifications).toBe(1);

    const call = h.toolCall("call-audit");
    await waitFor(() => h.chain.calls.length === 1, "audit failure chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-audit", "allow", 1));
    expect(await call).toBeUndefined();
  });

  it("invalidates prior results before an agent run without forcing a new publication", async () => {
    const h = await harness();
    const call = h.toolCall("call-agent");
    await waitFor(() => h.chain.calls.length === 1, "agent start chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-agent", "allow", 1));
    expect(await call).toBeUndefined();
    expect(h.extension.state().sessions[0]?.settledCalls).toBe(1);

    await h.fire("before_agent_start", {
      type: "before_agent_start",
      systemPrompt: "",
      systemPromptOptions: {},
      messageType: "user",
      prompt: "next task",
    });
    expect(h.extension.state().sessions[0]?.settledCalls).toBe(0);
    expect(h.publications.inputs).toHaveLength(1);
  });

  it("orders published nodes as front, custom by priority, then post", async () => {
    const h = await harness({
      nodes: [
        nodeBinding("post-node", "post", null),
        nodeBinding("custom-b", "user", 2),
        nodeBinding("front-node", "front", null),
        nodeBinding("custom-a", "user", 1),
      ],
    });
    const call = h.toolCall("call-order");
    await waitFor(() => h.chain.calls.length === 1, "ordered chain run");
    expect(h.chain.calls[0]?.nodes.map((binding) => binding.node.id)).toEqual([
      "front-node",
      "custom-a",
      "custom-b",
      "post-node",
    ]);
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-order", "allow", 1));
    expect(await call).toBeUndefined();
  });

  it.each(["approve", "defer", "deny"] as const)("runs the auto reviewer before the human fallback for a Host request: %s", async verdict => {
    const { runStepChain } = await import("#approve-core/runtime");
    const { mapCallReview, captureStep } = await import("#approve-core/contracts");
    const events: string[] = [];
    const reviewer = nodeBinding("builtin/decision-approver", "post", null);
    const human = nodeBinding("builtin/human", "post", null);
    const makeReview = (binding: NodeBinding, decision: "approve" | "deny" | "defer"): NodeBinding => ({ ...binding,
      node: { ...binding.node, evaluate: async step => {
        if (!step.state.calls.some(call => call.units.some(unit =>
          unit.decision === "ask" && unit.review === undefined))) return { decisions: [] };
        events.push(binding.node.id);
        const mapped = mapCallReview(step.state, { id: binding.node.id, priority: null }, {
          toolCallId: step.state.calls[0]!.toolCallId, decision, reason: "safe exact Host call",
        });
        if (!mapped.ok) throw Error(mapped.reason);
        return mapped.submission.result;
      } },
    });
    const h = await harness({ modes: ["auto-review"], nodes: [makeReview(human, "deny"), makeReview(reviewer, verdict)],
      captureStep,
      runChain: input => runStepChain(input),
    });
    const answer = await h.extension.reviewSandboxBypass({ toolCallId: "auto-host", targetToolName: "write",
      arguments: { path: "notes.txt", content: "safe" }, reason: "save output",
      elevation: { tier: "host", scope: [{ path: "E:\\output\\notes.txt", access: "write" }] },
    }, h.ctx as never);
    appendFileSync("temp-review.txt", JSON.stringify({ event: "host-review-order-reproduction",
      mode: h.extension.state().sessions[0]?.mode, enabledNodes: [reviewer.node.id, human.node.id],
      transport: "deterministic-test-double", reviewerVerdict: verdict, executedNodes: events,
      finalVerdict: answer === undefined ? "approved" : "blocked" }) + "\n");
    if (verdict === "approve") expect(answer).toBeUndefined();
    else expect(answer).toMatchObject({ block: true });
    expect(events).toEqual(verdict === "defer" ? [reviewer.node.id, human.node.id] : [reviewer.node.id]);
  });

  it("does not reject calls when the host tool registry cannot be read", async () => {
    const h = await harness({ toolRegistryFailure: true });
    const call = h.toolCall("call-registry");
    await waitFor(() => h.chain.calls.length === 1, "registry-failure chain run");
    h.chain.resolve(chainResult(h.chain.calls[0]!.capture, "call-registry", "allow", 1));
    expect(await call).toBeUndefined();
  });
});



// ---------------------------------------------------------------------------
// Ask decisions remembered for the session (design §5.6)
// ---------------------------------------------------------------------------

describe("session-scoped ask decisions (§5.6)", () => {
  beforeEach(() => vi.stubEnv("LC_ALL", "zh-CN"));
  afterEach(() => vi.unstubAllEnvs());
  const DOWN = "\u001b[B";
  const ENTER = "\r";
  const ESCAPE = "\u001b";
  const theme = { fg: (_color: string, text: string) => text, bg: (_color: string, text: string) => text, bold: (text: string) => text };
  const keybindings = {
    matches: (data: string, action: string) =>
      (action === "tui.select.down" && data === DOWN) ||
      (action === "tui.select.confirm" && data === ENTER) ||
      (action === "tui.select.cancel" && data === ESCAPE),
  };

  /** One prompt driver: each captured component is settled by the caller. */
  function promptDriver(ctx: ExtensionContext, themeValue: unknown = theme) {
    const pending: { readonly input: (data: string) => void; readonly render: (width: number) => string[]; readonly mouse: (event: import("@earendil-works/pi-tui").TuiMouseEvent) => unknown }[] = [];
    (ctx.ui as unknown as { custom: unknown }).custom = async (factory: unknown) => {
      const create = factory as (
        tui: unknown,
        themeValue: unknown,
        bindings: unknown,
        done: (value: unknown) => void,
      ) => { handleInput(data: string): void; render(width: number): string[]; handleMouse(event: import("@earendil-works/pi-tui").TuiMouseEvent): unknown };
      return new Promise((resolve) => {
        const component = create({ setClearOnShrink: () => undefined }, themeValue, keybindings, resolve);
        pending.push({ input: (data) => component.handleInput(data), render: (width) => component.render(width), mouse: (event) => component.handleMouse(event) });
      });
    };
    return {
      pending,
      /** Select one option by its position, requiring an explicit move first. */
      async choose(index: number): Promise<void> {
        await waitFor(() => pending.length > 0, "human prompt");
        const prompt = pending.shift()!;
        for (let step = 0; step <= index; step += 1) prompt.input(DOWN);
        prompt.input(ENTER);
      },
      async cancel(): Promise<void> {
        await waitFor(() => pending.length > 0, "human prompt");
        pending.shift()!.input(ESCAPE);
      },
    };
  }

  function approvalChain(calls: StepCapture[], reason?: string): RunChainPort {
    return async (input) => {
      calls.push(input.capture);
      const call = input.capture.directCalls[0]!;
      // The chain receives a scoped review result; the stub publishes its final outcome.
      const review = await input.sessionReviews?.({
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        arguments: call.arguments,
      });
      if (review !== undefined) {
        return chainResult(input.capture, call.toolCallId,
          review.decision === "approve" ? "allow" : "deny", input.generation, review.reason);
      }
      const response = await input.human!({
        capture: input.capture,
        call: {
          toolCallId: call.toolCallId,
          toolName: call.toolName,
          arguments: call.arguments,
          ...(call.hostExecutionRequest === undefined ? {} : { hostExecutionRequest: call.hostExecutionRequest }),
        } as never,
        summary: {
          toolCallId: call.toolCallId,
          decision: "ask",
          askFor: call.hostExecutionRequest === undefined && reason === undefined ? "allow" : "escalate",
          reasons: reason === undefined ? [] : [{ unitId: "u", decision: "ask", reason }],
          pendingUnitIds: [],
        } as never,
        state: {} as never,
        signal: input.signal ?? new AbortController().signal,
      });
      const decision = response.decision === "approve"
        ? call.hostExecutionRequest === undefined ? "allow" as const : "escalate" as const
        : "deny" as const;
      return chainResult(input.capture, call.toolCallId, decision, input.generation);
    };
  }

  async function askHarness() {
    const chains: StepCapture[] = [];
    const h = await harness({
      sandbox: { guard: async (_event, _ctx, review) => review({ ask: true }) },
      runChain: approvalChain(chains),
    });
    return { h, chains, driver: promptDriver(h.ctx) };
  }

  it.each(["zh", "en"])("shows external deletion correctly and restores the %s title color", async language => {
    const { initTheme } = await import("@earendil-works/pi-coding-agent");
    initTheme(undefined, false);
    vi.stubEnv("LC_ALL", language === "zh" ? "zh-CN" : "en-US");
    const h = await harness({
      tools: [{ name: "powershell" }],
      sandbox: { guard: async (_event, _ctx, review) => review({ ask: true }) },
      runChain: approvalChain([], "mode:default:external-delete-needs-approval"),
    });
    const colors: Record<string, string> = { accent: "\u001b[34m", warning: "\u001b[33m" };
    const styledTheme = { ...theme,
      fg: (color: string, value: string) => (colors[color] ?? "") + value + "\u001b[39m",
      getFgAnsi: (color: string) => colors[color] ?? "",
    };
    const driver = promptDriver(h.ctx, styledTheme);
    const call = h.toolCall("delete-external", "powershell", { command: "Remove-Item -LiteralPath E:\\outside\\file.txt" });
    await waitFor(() => driver.pending.length > 0, "deletion prompt");
    const output = driver.pending[0]!.render(100).join("\n");
    const plain = output.replace(/\u001b\[[0-9;]*m/g, "");
    expect(plain).toContain(language === "zh" ? "删除目标位于当前工作目录之外" : "The deletion target is outside the working directory");
    expect(plain).not.toContain(language === "zh" ? "写入目标" : "The write target");
    expect(output).toContain(language === "zh"
      ? "普通审批不能授予宿主权限"
      : "An ordinary approval cannot run this call with Host permissions");
    await driver.cancel();
    await call;
  });

  it("shows the requested Host tier, scope and sandbox boundary", async () => {
    vi.stubEnv("LC_ALL", "en-US");
    const { h, driver } = await askHarness();
    const review = h.extension.reviewSandboxBypass({
      toolCallId: "explicit-host-review",
      targetToolName: "write",
      arguments: { path: "/tmp/external.txt", content: "approved" },
      reason: "write the requested output",
      elevation: { tier: "host", scope: [{ path: "/tmp/external.txt", access: "write" }] },
    }, h.ctx as never);
    await waitFor(() => driver.pending.length > 0, "explicit Host review prompt");
    const output = driver.pending[0]!.render(100).join("\n").replace(/\u001b\[[0-9;]*m/g, "");

    expect(output).toContain("elevation host");
    expect(output).toContain("outside the OS sandbox");
    expect(output).toContain("write /tmp/external.txt");
    await driver.cancel();
    expect(await review).toMatchObject({ block: true });
  });

  it("renders tool arguments and choices in the approval panel", async () => {
    const { initTheme } = await import("@earendil-works/pi-coding-agent");
    initTheme(undefined, false);
    const { h, driver } = await askHarness();
    const call = h.toolCall("render", "bash", { command: "first()\nsecond()" });
    await waitFor(() => driver.pending.length > 0, "human prompt");
    const output = driver.pending[0]!.render(60).join("\n");
    expect(output).toContain("工具 bash 请求执行");
    expect(output).toContain("调用参数");
    expect(output).toContain("first()");
    expect(output).toContain("second()");
    expect(output).toContain("仅允许本次");
    expect(output).toContain("↑↓ 选择");
    expect(output.indexOf("调用参数")).toBeLessThan(output.indexOf("仅允许本次"));
    const narrow = driver.pending[0]!.render(32);
    const { visibleWidth } = await import("@earendil-works/pi-tui");
    expect(narrow.every(line => visibleWidth(line) <= 32)).toBe(true);
    expect(output).not.toContain("红=删除");
    await driver.cancel();
    await call;
  });

  it.each([["zh", "default"], ["zh", "host"], ["en", "default"], ["en", "host"]] as const)("shows %s %s elevation with its exact scope and one-time choices", async (language, tier) => {
    vi.stubEnv("LC_ALL", language === "zh" ? "zh-CN" : "fr-FR");
    const { initTheme } = await import("@earendil-works/pi-coding-agent");
    initTheme(undefined, false);
    const h = await harness({ runChain: approvalChain([]) });
    const liveTheme = process.env.PI_SANDBOX_APPROVAL_PREVIEW
      ? (await import(new URL("modes/interactive/theme/theme.js", import.meta.resolve("@earendil-works/pi-coding-agent")).href)).theme
      : theme;
    const driver = promptDriver(h.ctx, liveTheme);
    h.extension.setSessionMode(SESSION_ID, "read-only");
    const content = Array.from({ length: 20 }, (_, i) => `notes line ${i}`).join("\n");
    const call = h.extension.reviewSandboxBypass({ toolCallId: `elevation-${tier}`, targetToolName: "write",
      arguments: { path: "notes.md", content }, reason: language === "zh" ? "保存本次修改" : "Save the current changes",
      elevation: { tier, scope: [{ path: "E:\\project\\notes.md", access: "write" }] },
    }, h.ctx as never);
    await waitFor(() => driver.pending.length > 0, "elevation prompt");
    const prompt = driver.pending[0]!;
    const rawOutput = prompt.render(76).join("\n");
    const output = rawOutput.replace(/\u001b\[[0-9;]*m/g, "");
    expect(output).toContain(language === "zh" ? `工具 write 请求提权 ${tier} 执行` : `write requests elevation ${tier} execution`);
    expect(output).not.toContain("→");
    expect(output).toContain(`${language === "zh" ? "写入" : "write"} E:\\project\\notes.md`);
    expect(output).toContain(language === "zh" ? "保存本次修改" : "Save the current changes");
    expect(output).toContain(language === "zh" ? "文件内容" : "File content");
    expect(output).not.toContain("path:");
    expect(output).not.toContain("content:");
    expect(output).toContain("notes line 19");
    expect(output).toContain(language === "zh" ? "仅允许本次" : "Approve once");
    expect(output).not.toContain(language === "zh" ? "本会话允许" : "Allow for this session");
    if (language === "en") expect(output).not.toMatch(/[\p{Script=Han}]/u);
    else {
      expect(output).not.toContain("Call Arguments");
      expect(output).not.toContain("Approve once");
    }
    expect(output).not.toContain("本次调用将脱离沙箱执行");
    expect(output).not.toContain("This call will run outside the sandbox");
    expect(output).not.toContain("点击展开");
    expect(output).not.toContain("Click to expand");
    const { visibleWidth } = await import("@earendil-works/pi-tui");
    expect(prompt.render(32).every(line => visibleWidth(line) <= 32)).toBe(true);
    if (process.env.PI_SANDBOX_APPROVAL_PREVIEW) {
      mkdirSync(process.env.PI_SANDBOX_APPROVAL_PREVIEW, { recursive: true });
      writeFileSync(join(process.env.PI_SANDBOX_APPROVAL_PREVIEW, `${language}-${tier}.txt`), rawOutput, "utf8");
    }
    await driver.cancel();
    expect(await call).toMatchObject({ block: true });
  });

  it("shows every command argument line without collapse controls", async () => {
    const { initTheme } = await import("@earendil-works/pi-coding-agent");
    initTheme(undefined, false);
    const { h, driver } = await askHarness();
    const call = h.toolCall("mouse", "bash", { command: Array.from({ length: 50 }, (_, i) => `line-${i}`).join("\n") });
    await waitFor(() => driver.pending.length > 0, "human prompt");
    const prompt = driver.pending[0]!;
    const output = prompt.render(80).join("\n");
    expect(output).toContain("line-0");
    expect(output).toContain("line-49");
    expect(output).not.toContain("点击展开");
    expect(output).not.toContain("点击收起");
    await driver.cancel();
    await call;
  });

  it("reuses a session allow for the same tool and arguments without prompting", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    // Option 2 in the default prompt is "Allow for this session".
    await driver.choose(2);
    expect(await first).toBeUndefined();
    expect(chains).toHaveLength(1);

    const second = h.toolCall("call-b", "bash", { command: "ls" });
    expect(await second).toBeUndefined();
    // The remembered allow reaches the chain as a grant link.
    expect(chains).toHaveLength(2);
    expect(driver.pending).toHaveLength(0);
    expect(h.audit).toEqual(expect.arrayContaining([expect.objectContaining({
      kind: "session-decision",
      toolCallId: "call-b",
      toolName: "bash",
      decision: "allow",
    })]));
  });

  it("asks again when the arguments change", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await driver.choose(2);
    await first;

    const second = h.toolCall("call-b", "bash", { command: "pwd" });
    await driver.choose(0); // Approve once, not for the session.
    await second;
    expect(chains).toHaveLength(2);

    // A one-time approval is not remembered.
    const third = h.toolCall("call-c", "bash", { command: "pwd" });
    await driver.choose(0);
    await third;
    expect(chains).toHaveLength(3);
  });

  it("reuses a session command family for a new argument shape without prompting", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "git status" });
    await driver.choose(2);
    expect(await first).toBeUndefined();
    expect(chains).toHaveLength(1);

    const second = h.toolCall("call-b", "bash", { command: "git status --short" });
    expect(await second).toBeUndefined();
    // The family grant is a chain link: the second call enters the chain.
    expect(chains).toHaveLength(2);
    expect(driver.pending).toHaveLength(0);
  });

  it("asks again when any unit of a chain falls outside the remembered family", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "git status" });
    await driver.choose(2);
    await first;

    const second = h.toolCall("call-b", "bash", { command: "git status && git log" });
    await driver.choose(0);
    await second;
    expect(chains).toHaveLength(2);
  });

  it("retires a remembered family after a session deny", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "git status" });
    await driver.choose(2);
    await first;

    // A chain with one uncovered unit still prompts; denying it for the
    // session also retires the family grant the covered unit rode on.
    const denied = h.toolCall("call-b", "bash", { command: "git status && git log" });
    await driver.choose(3); // Deny for this session.
    expect(await denied).toMatchObject({ block: true, reason: expect.stringContaining("permission:denied") });
    expect(chains).toHaveLength(2);

    const variant = h.toolCall("call-c", "bash", { command: "git status --short" });
    await driver.choose(0);
    await variant;
    expect(chains).toHaveLength(3);
  });

  it("remembers a session deny and blocks later identical calls without prompting", async () => {
    const { h, chains, driver } = await askHarness();
    const first = h.toolCall("call-a", "write", { path: "a.txt", content: "x" });
    // Options: 0 approve once, 1 deny, 2 allow session, 3 deny session.
    await driver.choose(3);
    expect(await first).toMatchObject({ block: true, reason: expect.stringContaining("permission:denied") });

    const second = h.toolCall("call-b", "write", { path: "a.txt", content: "x" });
    // The remembered deny is a chain restriction now, so the block carries its
    // chain reason instead of the old host short-circuit reason.
    expect(await second).toEqual({ block: true, reason: expect.stringContaining("permission:denied: session:remembered-deny") });
    expect(chains).toHaveLength(2);
    expect(driver.pending).toHaveLength(0);
  });

  it("checks a remembered deny when the current mode would otherwise allow the sandbox call", async () => {
    const chains: StepCapture[] = [];
    let ask = true;
    const askChain = approvalChain(chains);
    const h = await harness({
      sandbox: { guard: async (_event, _ctx, review) => review(ask ? { ask: true } : undefined) },
      runChain: async input => {
        const call = input.capture.directCalls[0]!;
        if (call.toolCallId === "call-a") return askChain(input);
        chains.push(input.capture);
        const review = await input.sessionReviews?.({
          toolCallId: call.toolCallId,
          toolName: call.toolName,
          arguments: call.arguments,
        });
        return chainResult(
          input.capture,
          call.toolCallId,
          review?.decision === "deny" ? "deny" : "allow",
          input.generation,
          review?.reason,
        );
      },
    });
    const driver = promptDriver(h.ctx);

    const first = h.toolCall("call-a", "bash", { command: "cd sub" });
    await driver.choose(3);
    expect(await first).toMatchObject({ block: true });

    ask = false;
    const second = h.toolCall("call-b", "bash", { command: "cd sub" });
    expect(await second).toEqual({ block: true, reason: expect.stringContaining("permission:denied: session:remembered-deny") });
    expect(driver.pending).toHaveLength(0);
    expect(chains).toHaveLength(2);
  });

  it("does not carry a decision into another session", async () => {
    const { h, driver } = await askHarness();
    const first = h.toolCall("call-a", "bash", { command: "ls" });
    await driver.choose(2);
    await first;

    const other = makeContext({ id: "session-2" });
    const otherDriver = promptDriver(other);
    const fireOn = async (payload: unknown): Promise<unknown> => {
      let result: unknown;
      for (const handler of h.api.handlers("tool_call")) result = await handler(payload, other);
      return result;
    };
    const pending = fireOn({
      type: "tool_call",
      toolCallId: "call-other",
      toolName: "bash",
      input: { command: "ls" },
    });
    await waitFor(() => otherDriver.pending.length > 0, "prompt in the second session");
    otherDriver.pending.shift()!.input(ESCAPE);
    expect(await pending).toMatchObject({ block: true, reason: expect.stringContaining("permission:denied") });
  });
});


