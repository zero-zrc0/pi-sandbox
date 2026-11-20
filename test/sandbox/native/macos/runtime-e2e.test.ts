import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SessionManager, type ExtensionAPI, type ExtensionContext, type ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { resolveConfigPaths } from "#config/config-paths";
import { createApprovalChainConfigOwner } from "#config/owner";
import { createControlledExecution } from "#sandbox/production";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";
import { SandboxRuntimeManager } from "#sandbox/runtime-manager";
import { probeMacOSSeatbelt } from "#sandbox/backend/macos/index";
import type { AnyToolDefinition } from "#sandbox/pi";

const operationWorkerPath = fileURLToPath(new URL("../../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url));
const extensionSource = fileURLToPath(new URL("../../../../src/index.ts", import.meta.url));
const seatbelt = process.platform === "darwin" ? probeMacOSSeatbelt() : undefined;
const nativeReady = process.platform === "darwin" && existsSync(operationWorkerPath) && seatbelt?.status === "candidate-present";

/**
 * End-to-end macOS route: the real runtime manager prepares the system
 * Seatbelt runtime, the real production wiring builds the controller, and a
 * `write` whose argument spells `$TMPDIR` lands in the session workspace
 * temporary directory instead of a literal `$TMPDIR` directory.
 */
describe.skipIf(!nativeReady)("native macOS runtime end to end", () => {
  let root: string;
  let workspace: string;
  let agentDir: string;
  let manager: SandboxRuntimeManager;
  let execution: ReturnType<typeof createControlledExecution>;
  const definitions = new Map<string, AnyToolDefinition>();
  const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
  let ctx: ExtensionToolContext;

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "pi-sandbox-macos-e2e-")));
    workspace = join(root, "workspace");
    agentDir = join(root, "agent");
    for (const directory of [workspace, agentDir, join(agentDir, "extensions", "pi-sandbox")]) {
      mkdirSync(directory, { recursive: true });
    }
    const paths = resolveConfigPaths({ agentDir, cwd: workspace, extensionRoot: dirname(dirname(extensionSource)) });
    writeFileSync(paths.globalConfigFile, JSON.stringify({ mode: "default", experimental: { sandboxEnabled: true } }));
    const owner = createApprovalChainConfigOwner({ paths, cwd: workspace, projectTrusted: true });
    const packageVersion = (JSON.parse(readFileSync(fileURLToPath(new URL("../../../../package.json", import.meta.url)), "utf8")) as { version: string }).version;
    manager = new SandboxRuntimeManager({
      pluginRoot: join(agentDir, "extensions", "pi-sandbox"),
      agentDir,
      catalog: { schemaVersion: 1, runtimes: [] },
      platform: "darwin",
      arch: process.arch === "arm64" ? "arm64" : "x64",
      pluginVersion: packageVersion,
      protocolVersion: 3,
      probe: (runtime, input) => probeSandboxRuntime({ runtime, ...input }),
    });
    const state = await manager.prepare({ workspaceRoot: workspace });
    expect(state).toMatchObject({ status: "ready", runtime: { manifest: { backendId: "macos-seatbelt" } } });

    const api = {
      registerTool: (definition: AnyToolDefinition) => { definitions.set(definition.name, definition); },
      registerToolRenderer: () => undefined,
      registerCommand: () => undefined,
      getAllTools: () => [...definitions.values()].map(definition => ({ name: definition.name,
        description: definition.description, parameters: definition.parameters,
        ...(definition.namespace ? { namespace: definition.namespace } : {}),
        sourceInfo: { path: extensionSource, source: "local", scope: "user", origin: "top-level" } })),
      getMcpServers: () => [], getActiveTools: () => [], setActiveTools: () => undefined,
      appendEntry: () => undefined,
      on: (event: string, handler: (...args: unknown[]) => unknown) => {
        handlers.set(event, [...(handlers.get(event) ?? []), handler]);
        return () => undefined;
      },
    } as unknown as ExtensionAPI;
    execution = createControlledExecution({
      agentDir,
      registrationPath: extensionSource,
      snapshot: (snapshotCtx: ExtensionContext) => owner.snapshot({ sessionId: snapshotCtx.sessionManager.getSessionId() }),
      runtime: () => manager.state(),
      mcp: { loadConfig: () => ({ servers: [], errors: [] }) },
    });
    execution.install(api);
    ctx = { cwd: workspace, isProjectTrusted: () => true,
      sessionManager: SessionManager.inMemory(workspace, { id: "macos-e2e-session" }),
    } as unknown as ExtensionToolContext;
  }, 60_000);

  afterAll(async () => {
    for (const handler of handlers.get("session_shutdown") ?? []) {
      await handler({ type: "session_shutdown", reason: "quit" }, ctx);
    }
    await manager?.disable();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  it("writes a $TMPDIR path into the session workspace temporary directory", async () => {
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "macos-e2e-temp-write",
      input: { path: "$TMPDIR/notes.txt", content: "sandboxed temporary" } };
    const review = async () => undefined;

    expect(await execution.guard(event, ctx, review)).toBeUndefined();
    expect(event.input.path).not.toBe("$TMPDIR/notes.txt");

    const result = await definitions.get("write")!.execute(
      event.toolCallId, event.input, undefined, undefined, ctx as never,
    );
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    const workspaceTemporary = join(execution.sessionWorkspace(ctx), "tmp", "notes.txt");
    expect(readFileSync(workspaceTemporary, "utf8")).toBe("sandboxed temporary");
    expect(existsSync(join(workspace, "$TMPDIR"))).toBe(false);
  }, 60_000);
});
