import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  type AgentSession,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import {
  fauxAssistantMessage,
  fauxProvider,
  fauxToolCall,
} from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";

import type { PermissionScope } from "../../src/action";
import type { DirectBackendDriver } from "#sandbox/backend/direct";
import {
  createPiExecutionAdapter,
  type PiExecutionHostBinding,
} from "#sandbox/pi";
import type { ExecutionController } from "#sandbox/lifecycle";
import type { ExecutionRecord } from "#sandbox/types";
import { ToolInvocationBindingStore } from "#sandbox/execution-binding";
import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
} from "../../src/invocation";
import {
  createTestLayout,
  makeController,
  removeTestLayout,
  runtimeEnvironment,
  testExecutionEnvironment,
  type TestLayout,
} from "./fixtures/harness";
import { createTestDirectBackend } from "./fixtures/direct-backend";

const OWNER = "plan-11-pi-owner";
const BINDING_ID = "plan-11-pi-binding";
const SESSION_ID = "plan-11-pi-session";
const POLICY_REVISION = "plan11-pi-policy-r1";
const CONFIG_REVISION = "plan11-pi-config-r1";

interface ToolCallFacts {
  readonly toolName: string;
  readonly input: Record<string, unknown>;
}

interface HarnessOptions {
  /** When false the gate never authorizes, exercising the fail-closed path. */
  readonly authorize: boolean;
  readonly mode?: "default" | "full-access";
  /** Allow scopes to bind with the approval; defaults to a bash execute scope. */
  readonly scopes?: (facts: ToolCallFacts) => readonly PermissionScope[];
  /** Override the fake backend to exercise a failure mode. */
  readonly directBackend?: DirectBackendDriver;
  /** The active tool names offered to the faux model. */
  readonly activeTools?: readonly string[];
  readonly readConfigRevision?: () => string;
  readonly ownsAdditionalTool?: (name: string) => boolean;
  readonly shell?: string;
  readonly resolvePath?: (path: string) => string | null;
  /** Approval budget for every operation of one captured call. */
  readonly deadlineMs?: number;
  readonly now?: () => number;
  /** Observes each execution record, e.g. to advance a fake clock mid-call. */
  readonly onRecord?: (record: ExecutionRecord) => void;
}

type FauxProvider = ReturnType<typeof fauxProvider>;

interface PiHostHarness {
  readonly layout: TestLayout;
  readonly bindings: ToolInvocationBindingStore;
  readonly adapter: ReturnType<typeof createPiExecutionAdapter>;
  readonly session: AgentSession;
  readonly faux: FauxProvider;
  readonly records: ExecutionRecord[];
}

const activeSessions: AgentSession[] = [];
const activeControllers: ExecutionController[] = [];
const activeLayouts: TestLayout[] = [];

afterEach(async () => {
  for (const session of activeSessions.splice(0)) session.dispose();
  await Promise.all(
    activeControllers.splice(0).map((controller) => controller.dispose()),
  );
  for (const layout of activeLayouts.splice(0)) removeTestLayout(layout);
});

function bashScopes(): readonly PermissionScope[] {
  return [
    {
      id: "plan11-pi-bash-scope",
      surface: "bash",
      target: "execute",
      access: "other",
      state: "allow",
      source: "tool",
    },
  ];
}

function fileScope(
  toolName: string,
  access: "read" | "write",
  target: string,
): readonly PermissionScope[] {
  return [
    {
      id: `plan11-pi-${access}-scope`,
      surface: toolName,
      target,
      access,
      state: "allow",
      source: "tool",
    },
  ];
}

async function createPiHostHarness(
  options: HarnessOptions,
): Promise<PiHostHarness> {
  const layout = createTestLayout("plan11-pi-host");
  activeLayouts.push(layout);
  const cwd = layout.workspace;
  const agentDir = layout.agent;
  const environment = runtimeEnvironment();
  const records: ExecutionRecord[] = [];
  const controller = makeController({
    layout,
    scenario: "ok",
    environment: testExecutionEnvironment(),
    onRecord: (record) => {
      records.push(record);
      options.onRecord?.(record);
    },
    ...(options.directBackend === undefined ? {} : { directBackend: options.directBackend }),
  });
  activeControllers.push(controller);

  const bindings = new ToolInvocationBindingStore();
  let session: AgentSession | undefined;

  const host: PiExecutionHostBinding = {
    getAllTools: () => session?.getAllTools() ?? [],
    readRequester: (ctx) => ({
      sessionId: ctx.sessionManager.getSessionId(),
      agentName: null,
    }),
    readEnvironment: () => environment,
    verifyScope: () => ({ allowed: true, revision: POLICY_REVISION }),
    readCurrentScopeRevision: () => POLICY_REVISION,
  };

  const adapter = createPiExecutionAdapter({
    controller,
    bindings,
    host,
    owner: OWNER,
    bindingId: BINDING_ID,
    ...(options.ownsAdditionalTool === undefined
      ? {}
      : { ownsAdditionalTool: options.ownsAdditionalTool }),
    plan: {
      mode: options.mode ?? "default",
      baseline: {
        filesystem: [
          { path: cwd, access: "read", granularity: "directory" },
          { path: cwd, access: "write", granularity: "directory" },
        ],
        network: { kind: "none" },
      },
      configRevision: CONFIG_REVISION,
      backendId: "fixture-direct",
      ...(options.readConfigRevision === undefined
        ? {}
        : { readConfigRevision: options.readConfigRevision }),
      ...(options.shell === undefined ? {} : { shell: options.shell }),
      ...(options.deadlineMs === undefined ? {} : { deadlineMs: options.deadlineMs }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.resolvePath === undefined
        ? {}
        : { resolvePath: options.resolvePath }),
    },
  });

  const extensionFactory = (pi: ExtensionAPI): void => {
    adapter.install(pi);
    pi.on("tool_call", (event, ctx) => {
      if (!options.authorize) return undefined;
      const facts: ToolCallFacts = {
        toolName: event.toolName,
        input: event.input as Record<string, unknown>,
      };
      const captured = captureToolInvocationSeed({
        event,
        registeredTools: session?.getAllTools() ?? [],
        cwd: ctx.cwd,
        requester: {
          sessionId: ctx.sessionManager.getSessionId(),
          agentName: null,
        },
        environment,
      });
      if (!captured.ok) {
        throw new Error(`host capture failed: ${captured.reason}`);
      }
      const finalized = finalizeToolInvocation(captured.seed, {
        requestId: `plan11-pi-request-${event.toolCallId}`,
        scopes: options.scopes?.(facts) ?? bashScopes(),
        executionBinding: {
          status: "bound",
          owner: OWNER,
          toolName: event.toolName,
          revision: captured.seed.tool.revision,
          bindingId: BINDING_ID,
        },
      });
      if (!finalized.ok) {
        throw new Error(`host finalize failed: ${finalized.reason}`);
      }
      if (!bindings.authorize(finalized.invocation, POLICY_REVISION)) {
        throw new Error("host could not authorize the approval");
      }
      return undefined;
    });
  };

  const faux = fauxProvider({
    api: "openai-completions",
    provider: "plan11-pi-faux",
    models: [{ id: "plan11-pi-model", name: "Plan 11 host test model" }],
  });
  const modelRuntime = await ModelRuntime.create({
    authPath: join(agentDir, "auth.json"),
    modelsPath: null,
    modelsStorePath: join(agentDir, "models.json"),
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
  modelRuntime.registerNativeProvider(faux.provider);
  const model = modelRuntime.getModel(faux.provider.id, "plan11-pi-model");
  if (!model) throw new Error("faux model was not registered with Pi");

  const settingsManager = SettingsManager.create(cwd, agentDir);
  const resourceLoader = new DefaultResourceLoader({
    cwd,
    agentDir,
    settingsManager,
    extensionFactories: [extensionFactory],
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
  });
  await resourceLoader.reload();

  const created = await createAgentSession({
    cwd,
    agentDir,
    model,
    modelRuntime,
    settingsManager,
    resourceLoader,
    sessionManager: SessionManager.inMemory(cwd, { id: SESSION_ID }),
    tools: [...(options.activeTools ?? ["bash", "read", "write", "edit"])],
    thinkingLevel: "off",
  });
  session = created.session;
  activeSessions.push(session);

  return { layout, bindings, adapter, session, faux, records };
}

type ToolResultMessage = Extract<
  AgentSession["messages"][number],
  { role: "toolResult" }
>;

function toolResultFor(
  session: AgentSession,
  toolName: string,
): ToolResultMessage {
  const message = session.messages.find(
    (candidate): candidate is ToolResultMessage =>
      candidate.role === "toolResult" && candidate.toolName === toolName,
  );
  if (!message) {
    throw new Error(`no tool result was recorded for ${toolName}`);
  }
  return message;
}

function resultText(message: ToolResultMessage): string {
  return message.content
    .map((part) => (part.type === "text" ? part.text : ""))
    .join(" ");
}

describe("public Pi controlled execution host", () => {
  it("takes over the builtin bash definition and executes through the native backend", async () => {
    const harness = await createPiHostHarness({ authorize: true });
    const { session, faux, layout } = harness;

    const bashInfo = session
      .getAllTools()
      .find((tool) => tool.name === "bash");
    expect(bashInfo).toBeDefined();
    expect(bashInfo?.sourceInfo.source).not.toBe("builtin");
    for (const name of ["bash", "read", "write", "edit"]) {
      const info = session.getAllTools().find((tool) => tool.name === name);
      expect(info?.sourceInfo.source, name).not.toBe("builtin");
    }

    const command = `"${process.execPath}" -e "require('node:fs').writeFileSync('host-executed.txt','host')"`;
    faux.setResponses([
      fauxAssistantMessage(
        [fauxToolCall("bash", { command }, { id: "plan11-pi-bash-call" })],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Run the controlled bash command.");

    const result = toolResultFor(session, "bash");
    expect(result.isError).not.toBe(true);
    expect(
      readFileSync(join(layout.workspace, "host-executed.txt"), "utf8"),
    ).toBe("host");
  });

  it("writes a file only through the negotiated native backend", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.workspace, "controlled.txt"),
        ),
    });
    const { session, faux, layout } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            { path: "controlled.txt", content: "from-native" },
            { id: "plan11-pi-write-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Write the controlled file.");

    expect(toolResultFor(session, "write").isError).not.toBe(true);
    expect(readFileSync(join(layout.workspace, "controlled.txt"), "utf8")).toBe(
      "from-native",
    );
  });

  it("writes to an existing external parent with only an exact file approval", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.root, "external", "report.txt"),
        ),
    });
    const { session, faux, layout } = harness;
    const external = join(layout.root, "external");
    mkdirSync(external, { recursive: true });

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            {
              path: join(external, "report.txt"),
              content: "into-existing-parent",
            },
            { id: "plan11-pi-external-write" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Write into the existing external directory.");

    const result = toolResultFor(session, "write");
    expect(resultText(result)).not.toContain("scope-expansion");
    expect(result.isError).not.toBe(true);
    expect(readFileSync(join(external, "report.txt"), "utf8")).toBe(
      "into-existing-parent",
    );
  });

  it("refuses to create an unapproved parent for an exact file approval", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.root, "external", "absent", "report.txt"),
        ),
    });
    const { session, faux, layout } = harness;
    const external = join(layout.root, "external");
    const absent = join(external, "absent");
    mkdirSync(external, { recursive: true });

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            {
              path: join(absent, "report.txt"),
              content: "must-not-create",
            },
            { id: "plan11-pi-missing-parent-write" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Write into a parent that does not exist.");

    const result = toolResultFor(session, "write");
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("scope-expansion");
    expect(existsSync(absent)).toBe(false);
    expect(existsSync(join(absent, "report.txt"))).toBe(false);
  });

  it("reads an existing file through the native worker", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "read",
          join(harness.layout.workspace, "seed.txt"),
        ),
    });
    const { session, faux, layout } = harness;
    writeFileSync(join(layout.workspace, "seed.txt"), "seed-content", "utf8");

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "read",
            { path: "seed.txt" },
            { id: "plan11-pi-read-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Read the seed file.");

    const result = toolResultFor(session, "read");
    expect(result.isError).not.toBe(true);
    expect(resultText(result)).toContain("seed-content");
  });

  it("preserves SDK path variant resolution inside the baseline workspace", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "read",
          join(harness.layout.workspace, "note's.txt"),
        ),
    });
    const { session, faux, layout } = harness;
    // Only the curly-quote variant exists; Pi's default resolver would probe
    // the host filesystem, find it and read an unapproved path.
    writeFileSync(join(layout.workspace, "note\u2019s.txt"), "variant-secret", "utf8");

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "read",
            { path: "note's.txt" },
            { id: "plan11-pi-variant-read" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Read the file whose host variant exists.");

    const result = toolResultFor(session, "read");
    expect(result.isError).not.toBe(true);
    expect(resultText(result)).toContain("variant-secret");
  });

  it("preserves SDK image results in the builtin process", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "read",
          join(harness.layout.workspace, "picture.png"),
        ),
    });
    const { session, faux, layout } = harness;
    writeFileSync(
      join(layout.workspace, "picture.png"),
      Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==", "base64"),
    );

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "read",
            { path: "picture.png" },
            { id: "plan11-pi-image-read" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Read the image file.");

    const result = toolResultFor(session, "read");
    expect(result.isError).not.toBe(true);
    expect(result.content.some(part => part.type === "image")).toBe(true);
  });

  it("preserves SDK shell truncation and output-file details", async () => {
    const harness = await createPiHostHarness({ authorize: true });
    const { session, faux } = harness;
    const before = new Set(
      readdirSync(tmpdir()).filter((name) => name.startsWith("pi-bash-")),
    );

    const command =
      `"${process.execPath}" -e "let s='';for(let i=0;i<3000;i++)s+=` +
      `'line '+i+String.fromCharCode(10);process.stdout.write(s)"`;
    faux.setResponses([
      fauxAssistantMessage(
        [fauxToolCall("bash", { command }, { id: "plan11-pi-big-output" })],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Run a command with oversized output.");

    const result = toolResultFor(session, "bash");
    expect(result.isError).not.toBe(true);
    expect(resultText(result)).toContain("Full output:");
    const created = readdirSync(tmpdir())
      .filter((name) => name.startsWith("pi-bash-") && !before.has(name))
      .sort();
    expect(created).toHaveLength(1);
    for (const name of created) rmSync(join(tmpdir(), name));
  });

  it("executes a complete builtin within one approval budget", async () => {
    let elapsed = 0;
    const harness = await createPiHostHarness({
      authorize: true,
      deadlineMs: 10_000,
      now: () => Date.now() + elapsed,
      onRecord: () => {
        // The captured budget is spent once the first operation settles.
        elapsed = 20_000;
      },
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.workspace, "budget.txt"),
        ),
    });
    const { session, faux, layout } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            { path: "budget.txt", content: "second-step" },
            { id: "plan11-pi-budget-write" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Write after the shared budget expired.");

    const result = toolResultFor(session, "write");
    expect(result.isError).not.toBe(true);
    expect(existsSync(join(layout.workspace, "budget.txt"))).toBe(true);
    // One SDK call produces one execution record.
    expect(harness.records).toHaveLength(1);
    expect(harness.records[0]?.started).toBe(true);
  });

  it("edits a file through the native worker with the real Pi edit definition", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: () => [],
    });
    const { session, faux, layout } = harness;
    const target = join(layout.workspace, "editable.txt");
    writeFileSync(target, "alpha beta", "utf8");

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "edit",
            {
              path: "editable.txt",
              edits: [{ oldText: "alpha", newText: "gamma" }],
            },
            { id: "plan11-pi-edit-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Edit the controlled file.");

    expect(toolResultFor(session, "edit").isError).not.toBe(true);
    expect(readFileSync(target, "utf8")).toBe("gamma beta");
  });

  it("blocks an unapproved builtin instead of running it in the Pi host", async () => {
    const harness = await createPiHostHarness({
      authorize: false,
      activeTools: ["ls"],
    });
    const { session, faux } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [fauxToolCall("ls", { path: "." }, { id: "plan11-pi-ls-call" })],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("List the directory with the uncontrolled builtin.");

    const result = toolResultFor(session, "ls");
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("approved-action-unavailable");
  });

  it("does not execute an approval captured under an older configuration", async () => {
    let reads = 0;
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.workspace, "stale.txt"),
        ),
      readConfigRevision: () =>
        reads++ === 0 ? "plan11-config-r1" : "plan11-config-r2",
    });
    const { session, faux, layout } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            { path: "stale.txt", content: "stale" },
            { id: "plan11-pi-stale-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Write after a configuration switch.");

    const result = toolResultFor(session, "write");
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("plan-invalidated");
    expect(existsSync(join(layout.workspace, "stale.txt"))).toBe(false);
  });

  it("does not bypass a builtin binding through additional tool ownership", async () => {
    const harness = await createPiHostHarness({
      authorize: false,
      activeTools: ["ls"],
      ownsAdditionalTool: name => name === "ls",
    });
    const { session, faux } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [fauxToolCall("ls", { path: "." }, { id: "plan11-pi-ls-allowed" })],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("List with a host-vouched tool.");

    expect(toolResultFor(session, "ls").isError).toBe(true);
  });

  it("fails closed when no approval was captured and never starts a native process", async () => {
    const harness = await createPiHostHarness({ authorize: false });
    const { session, faux, layout } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            { path: "blocked.txt", content: "blocked" },
            { id: "plan11-pi-blocked-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Attempt the unapproved write.");

    const result = toolResultFor(session, "write");
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("approved-action-unavailable");
    expect(existsSync(join(layout.workspace, "blocked.txt"))).toBe(false);
  });

  it("reports an unavailable native backend without starting a process", async () => {
    const harness = await createPiHostHarness({
      authorize: true,
      scopes: (facts) =>
        fileScope(
          facts.toolName,
          "write",
          join(harness.layout.workspace, "never.txt"),
        ),
      directBackend: createTestDirectBackend({ scenario: "unavailable" }),
    });
    const { session, faux, layout } = harness;

    faux.setResponses([
      fauxAssistantMessage(
        [
          fauxToolCall(
            "write",
            { path: "never.txt", content: "never" },
            { id: "plan11-pi-missing-call" },
          ),
        ],
        { stopReason: "toolUse" },
      ),
      fauxAssistantMessage("finished"),
    ]);

    await session.prompt("Attempt a write with an unavailable native backend.");

    const result = toolResultFor(session, "write");
    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("sandbox-unavailable");
    expect(existsSync(join(layout.workspace, "never.txt"))).toBe(false);
  });

  it("registers nothing and keeps builtin tools for full access", async () => {
    const harness = await createPiHostHarness({
      authorize: false,
      mode: "full-access",
    });
    const { session, adapter } = harness;

    expect(adapter.definitions).toHaveLength(0);
    expect(adapter.coverage.sandboxed).toBe(false);
    expect(adapter.coverage.boundary).toBe("none");
    expect(adapter.coverage.controlled).toEqual([]);
    expect(adapter.coverage.uncontrolledBuiltins).toEqual(
      expect.arrayContaining(["bash", "read", "write", "edit"]),
    );
    expect(adapter.coverage.mcp.localStarted.controlled).toBe(false);
    expect(adapter.coverage.mcp.remote.boundary).toBe("local-transport-only");

    const bashInfo = session
      .getAllTools()
      .find((tool) => tool.name === "bash");
    expect(bashInfo?.sourceInfo.source).toBe("builtin");
    expect(session.getToolDefinition("bash")).toBeDefined();
  });
});
