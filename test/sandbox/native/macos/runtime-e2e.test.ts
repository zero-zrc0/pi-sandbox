import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SessionManager, type ExtensionAPI, type ExtensionContext, type ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { resolveConfigPaths } from "#config/config-paths";
import { createApprovalChainConfigOwner } from "#config/owner";
import { createControlledExecution } from "#sandbox/production";
import { probeSandboxRuntime } from "#sandbox/runtime-probe";
import { SandboxRuntimeManager } from "#sandbox/runtime-manager";
import { probeMacOSSeatbelt } from "#sandbox/backend/macos/index";
import type { AnyToolDefinition } from "#sandbox/pi";

const operationWorkerPath = fileURLToPath(new URL("../../../../src/sandbox/backend/macos/operation-worker.mjs", import.meta.url));
const extensionSource = fileURLToPath(new URL("../../../../src/index.ts", import.meta.url));
const seatbelt = process.platform === "darwin" ? await probeMacOSSeatbelt() : undefined;
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
  let homeDir: string;
  let configPath: string;
  let owner: ReturnType<typeof createApprovalChainConfigOwner>;
  let manager: SandboxRuntimeManager;
  let execution: ReturnType<typeof createControlledExecution>;
  const definitions = new Map<string, AnyToolDefinition>();
  const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
  let ctx: ExtensionToolContext;

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "pi-sandbox-macos-e2e-")));
    workspace = join(root, "workspace");
    agentDir = join(root, "agent");
    homeDir = join(root, "home");
    for (const directory of [workspace, agentDir, homeDir, join(agentDir, "extensions", "pi-sandbox")]) {
      mkdirSync(directory, { recursive: true });
    }
    vi.stubEnv("HOME", homeDir);
    const paths = resolveConfigPaths({ agentDir, cwd: workspace, extensionRoot: dirname(dirname(extensionSource)) });
    configPath = paths.globalConfigFile;
    writeFileSync(paths.globalConfigFile, JSON.stringify({ mode: "default", experimental: { sandboxEnabled: true } }));
    owner = createApprovalChainConfigOwner({ paths, cwd: workspace, projectTrusted: true });
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
    vi.unstubAllEnvs();
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

  it("reads skills, blocks control writes, and applies denyPaths in native execution", async () => {
    const files = [
      { root: ".agents", relative: join("skills", "demo", "SKILL.md"), content: "skill content" },
      { root: ".codex", relative: "config.toml", content: "model = 'test'" },
    ];
    for (const file of files) {
      const path = join(homeDir, file.root, file.relative);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, file.content);
    }

    for (const [index, file] of files.entries()) {
      const path = join(homeDir, file.root, file.relative);
      const read = { type: "tool_call" as const, toolName: "read", toolCallId: `macos-control-read-${index}`, input: { path } };
      expect(await execution.guard(read, ctx, async () => undefined)).toBeUndefined();
      const result = await definitions.get("read")!.execute(read.toolCallId, read.input, undefined, undefined, ctx as never);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain(file.content);

      const write = { type: "tool_call" as const, toolName: "write", toolCallId: `macos-control-write-${index}`,
        input: { path, content: "must not replace control data" } };
      expect(await execution.guard(write, ctx, async () => undefined)).toMatchObject({ block: true,
        reason: expect.stringContaining("protected-control-path") });
      expect(readFileSync(path, "utf8")).toBe(file.content);
    }

    const deniedPath = join(homeDir, ".agents", "skills", "demo", "SKILL.md");
    writeFileSync(configPath, JSON.stringify({ mode: "default", experimental: { sandboxEnabled: true },
      execution: { denyPaths: [deniedPath] } }));
    owner.reload();
    const deniedRead = { type: "tool_call" as const, toolName: "read", toolCallId: "macos-control-deny-path", input: { path: deniedPath } };
    expect(await execution.guard(deniedRead, ctx, async () => undefined)).toBeUndefined();
    const deniedResult = await definitions.get("read")!.execute(deniedRead.toolCallId, deniedRead.input, undefined, undefined, ctx as never);
    expect(deniedResult.isError, JSON.stringify(deniedResult)).toBe(true);
    expect(JSON.stringify(deniedResult)).not.toContain("skill content");
  }, 60_000);
});
