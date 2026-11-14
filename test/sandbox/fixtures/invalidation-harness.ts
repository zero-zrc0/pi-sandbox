import { join } from "node:path";

import type { ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import { afterEach } from "vitest";

import {
  createPiExecutionAdapter,
  type AnyToolDefinition,
  type ControlledToolName,
  type PiExecutionAdapter,
  type PiExecutionPlanOptions,
} from "#sandbox/pi";
import type { ExecutionController } from "#sandbox/lifecycle";
import type { ExecutionRecord } from "#sandbox/types";
import { ToolInvocationBindingStore } from "#sandbox/execution-binding";
import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
} from "../../../src/invocation";
import {
  createTestLayout,
  fixtureEnvironment,
  makeController,
  removeTestLayout,
  type TestLayout,
} from "./harness";

const OWNER = "plan-11-validity-owner";
const BINDING_ID = "plan-11-validity-binding";
export const SESSION_ID = "plan-11-validity-session";

const layouts: TestLayout[] = [];
const adapters: PiExecutionAdapter[] = [];

/**
 * Call once at the top level of a test file that uses the rig. Each file owns
 * its hook, so a shared module cannot bind cleanup to only one of them.
 */
export function useInvalidationCleanup(): void {
  afterEach(async () => {
    for (const adapter of adapters.splice(0)) await adapter.dispose();
    for (const layout of layouts.splice(0)) removeTestLayout(layout);
  });
}

export interface InvalidationHarnessOptions {
  readonly environment?: Readonly<Record<string, string>>;
  readonly scenario?: string;
  readonly policy?: () => string;
  /** Stop inside `host.verifyScope` for matching calls until released. */
  readonly holdVerification?: (toolCallId: string) => boolean;
  readonly onRecord?: (record: ExecutionRecord) => void;
  readonly maxConcurrent?: number;
  readonly configRevision?: string;
  readonly readConfigRevision?: () => string;
  readonly approvedScope?: PiExecutionPlanOptions["approvedScope"];
  readonly maxOutstandingCalls?: number;
  /** Approval budget for the whole tool call, in milliseconds. */
  readonly deadlineMs?: number;
  /** Extra helper environment, e.g. a business marker file. */
  readonly helperEnvironmentExtra?: Readonly<Record<string, string>>;
}

export interface InvalidationHarness {
  readonly layout: TestLayout;
  readonly adapter: PiExecutionAdapter;
  readonly controller: ExecutionController;
  readonly records: ExecutionRecord[];
  readonly helperPidFile: string;
  /** Resolves once the adapter has entered `host.verifyScope`. */
  readonly verificationEntered: Promise<void>;
  releaseVerification: () => void;
  /** Start a real tool call; the promise stays pending while verification is held. */
  pendingCall: (
    toolName: ControlledToolName,
    toolCallId: string,
    input: Record<string, unknown>,
    sessionId?: string,
  ) => Promise<unknown>;
  /** Run a real tool call through to completion. */
  runCall: (
    toolName: ControlledToolName,
    toolCallId: string,
    input: Record<string, unknown>,
    sessionId?: string,
  ) => Promise<unknown>;
}

export async function createInvalidationHarness(
  options: InvalidationHarnessOptions = {},
): Promise<InvalidationHarness> {
  const layout = createTestLayout("plan11-validity");
  layouts.push(layout);
  const helperPidFile = join(layout.root, "helper.pid");
  const records: ExecutionRecord[] = [];
  const scenario = options.scenario ?? "ok";
  const controller = makeController({
    layout,
    scenario,
    maxConcurrent: options.maxConcurrent ?? 2,
    helperEnvironment: fixtureEnvironment(scenario, {
      FIXTURE_SELF_PID_FILE: helperPidFile,
      ...(options.helperEnvironmentExtra ?? {}),
    }),
    onRecord: (record) => {
      records.push(record);
      options.onRecord?.(record);
    },
  });
  const bindings = new ToolInvocationBindingStore();
  const policy = options.policy ?? (() => "r1");
  let definitions: readonly AnyToolDefinition[] = [];

  let releaseHeld!: () => void;
  const held = new Promise<void>((resolve) => (releaseHeld = resolve));
  let markEntered!: () => void;
  const verificationEntered = new Promise<void>((resolve) => (markEntered = resolve));

  const registeredTools = () =>
    definitions.map((definition) => ({
      name: definition.name,
      description: definition.description,
      parameters: definition.parameters,
      sourceInfo: {
        path: "<plan11-test>",
        source: "plan11-test",
        scope: "temporary",
        origin: "top-level",
      },
    }));

  const adapter = createPiExecutionAdapter({
    controller,
    bindings,
    owner: OWNER,
    bindingId: BINDING_ID,
    cwd: layout.workspace,
    ...(options.maxOutstandingCalls === undefined
      ? {}
      : { maxOutstandingCalls: options.maxOutstandingCalls }),
    host: {
      getAllTools: registeredTools,
      readRequester: (ctx) => ({
        sessionId: ctx.sessionManager.getSessionId(),
        agentName: null,
      }),
      readEnvironment: () => options.environment ?? {},
      readCurrentScopeRevision: () => policy(),
      verifyScope: async (invocation) => {
        markEntered();
        if (options.holdVerification?.(invocation.action.toolCallId)) await held;
        return { allowed: true, revision: policy() };
      },
    },
    plan: {
      mode: "default",
      baseline: {
        filesystem: [
          { path: layout.workspace, access: "read", granularity: "directory" },
          { path: layout.workspace, access: "write", granularity: "directory" },
        ],
        network: { kind: "none" },
      },
      configRevision: options.configRevision ?? "c1",
      backendId: "fixture-helper",
      ...(options.deadlineMs === undefined ? {} : { deadlineMs: options.deadlineMs }),
      ...(options.readConfigRevision === undefined
        ? {}
        : { readConfigRevision: options.readConfigRevision }),
      ...(options.approvedScope === undefined ? {} : { approvedScope: options.approvedScope }),
    },
  });
  definitions = adapter.definitions;
  adapters.push(adapter);

  function definitionFor(toolName: ControlledToolName): AnyToolDefinition {
    const definition = definitions.find((candidate) => candidate.name === toolName);
    if (!definition) throw new Error(`the rig registered no ${toolName}`);
    return definition;
  }

  function contextFor(sessionId: string): ExtensionToolContext {
    return {
      cwd: layout.workspace,
      sessionManager: {
        getSessionId: () => sessionId,
        getSessionFile: () => undefined,
      },
    } as unknown as ExtensionToolContext;
  }

  function pendingCall(
    toolName: ControlledToolName,
    toolCallId: string,
    input: Record<string, unknown>,
    sessionId = SESSION_ID,
  ): Promise<unknown> {
    const definition = definitionFor(toolName);
    const seed = captureToolInvocationSeed({
      event: { type: "tool_call", toolName, toolCallId, input },
      registeredTools: registeredTools(),
      cwd: layout.workspace,
      requester: { sessionId, agentName: null },
      environment: options.environment ?? {},
    });
    if (!seed.ok) throw new Error(`seed failed: ${seed.reason}`);
    const finalized = finalizeToolInvocation(seed.seed, {
      requestId: `request-${toolCallId}`,
      scopes: [],
      executionBinding: {
        status: "bound",
        owner: OWNER,
        toolName,
        revision: seed.seed.tool.revision,
        bindingId: BINDING_ID,
      },
    });
    if (!finalized.ok) throw new Error(`finalize failed: ${finalized.reason}`);
    if (!bindings.authorize(finalized.invocation, policy())) {
      throw new Error("the binding store rejected the approval");
    }
    const execute = definition.execute as (
      toolCallId: string,
      params: unknown,
      signal: AbortSignal | undefined,
      onUpdate: undefined,
      ctx: ExtensionToolContext,
    ) => Promise<unknown>;
    return execute(toolCallId, input, undefined, undefined, contextFor(sessionId));
  }

  async function runCall(
    toolName: ControlledToolName,
    toolCallId: string,
    input: Record<string, unknown>,
    sessionId = SESSION_ID,
  ): Promise<unknown> {
    const pending = pendingCall(toolName, toolCallId, input, sessionId);
    releaseHeld();
    return pending;
  }

  return {
    layout,
    adapter,
    controller,
    records,
    helperPidFile,
    verificationEntered,
    releaseVerification: () => releaseHeld(),
    pendingCall,
    runCall,
  };
}

function resultText(value: unknown): string {
  const content = (value as { content?: { type: string; text?: string }[] }).content;
  return (content ?? []).map((part) => part.text ?? "").join(" ");
}

/**
 * A refusal can reach the test either as an error tool result (Pi's own agent
 * loop) or as a rejection (calling the definition directly). Both mean the
 * same thing here: the operation never started.
 */
export async function outcomeText(promise: Promise<unknown>): Promise<string> {
  try {
    return resultText(await promise);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}
