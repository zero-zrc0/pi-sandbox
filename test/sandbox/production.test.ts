import { EventEmitter } from "node:events";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createConnection, createServer as createTcpServer } from "node:net";
import { createSocket } from "node:dgram";
import { networkInterfaces } from "node:os";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionManager, type ExtensionAPI, type ExtensionContext, type ExtensionToolContext, type RegisteredMcpServer } from "@earendil-works/pi-coding-agent";
import { resolveConfigPaths } from "#config/config-paths";
import { createApprovalChainConfigOwner } from "#config/owner";
import { createControlledExecution } from "#sandbox/production";
import { createSandboxBypass } from "#sandbox/bypass";
import { sessionWorkspacePath } from "#sandbox/session-workspace";
import { ExecutionController } from "#sandbox/lifecycle";
import type { SandboxRuntimeState } from "#sandbox/runtime-manager";
import type { RuntimeFileEntry, RuntimeFileRole } from "#sandbox/runtime-catalog";
import type { ResolvedRuntimeFiles } from "#sandbox/runtime-store";
import { runWithApprovedCodemode } from "#sandbox/codemode/approval-scope";
import type { AnyToolDefinition } from "#sandbox/pi";
import { createTestLayout, makeController, removeTestLayout, waitFor, waitForProcessGone } from "./fixtures/harness";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import { prepareWindowsRuntimeExecutable } from "#sandbox/runtime-windows-integrity";
import { findSystemBubblewrap } from "../../src/sandbox/backend/linux/bwrap-selection.mjs";

const cleanup: (() => Promise<void>)[] = [];
const privateAddress = Object.values(networkInterfaces()).flat().find(address => address?.family === "IPv4" && !address.internal)?.address;
afterEach(async () => { for (const close of cleanup.splice(0)) await close(); });

function setup(
  mode: "default" | "auto-review" | "read-only" | "full-access" = "default",
  native = false,
  scenario = "ok",
  sandboxEnabled = true,
) {
  const layout = createTestLayout("controlled-production");
  const source = fileURLToPath(new URL("../../src/index.ts", import.meta.url));
  const definitions = new Map<string, AnyToolDefinition>();
  const sources = new Map<string, string>();
  const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
  const records: unknown[] = [];
  const controllers: ReturnType<typeof makeController>[] = [];
  const registeredServers: RegisteredMcpServer[] = [];
  const ctx = { cwd: layout.workspace, isProjectTrusted: () => true,
    sessionManager: SessionManager.inMemory(layout.workspace, { id: "controlled-session" }),
  } as unknown as ExtensionToolContext;
  const paths = resolveConfigPaths({ agentDir: layout.agent, cwd: layout.workspace, extensionRoot: dirname(dirname(source)) });
  const owner = createApprovalChainConfigOwner({ paths, cwd: layout.workspace, projectTrusted: true });
  // Production keeps one config owner per session (src/index.ts runtimeFor).
  // Most cases share the single owner; the cross-session sandbox-tool case
  // registers a second one so its rule table really differs.
  const sessionOwners = new Map<string, ReturnType<typeof createApprovalChainConfigOwner>>([
    [ctx.sessionManager.getSessionId(), owner],
  ]);
  if (mode !== "default" || sandboxEnabled) {
    mkdirSync(join(layout.agent, "extensions", "pi-sandbox"), { recursive: true });
    writeFileSync(paths.globalConfigFile, JSON.stringify({ mode, experimental: { sandboxEnabled } }));
  }
  const runtimePlatform = process.platform === "win32" ? "win32" : process.platform === "linux" ? "linux" : "darwin";
  const runtimeArch = process.arch === "arm64" ? "arm64" : "x64";
  const backendId = runtimePlatform === "linux" ? "linux-bwrap-landlock-seccomp" : runtimePlatform === "win32" ? "windows-mxc" : "unsupported-platform";
  const runtimeRoot = join(dirname(dirname(source)), "runtimes");
  mkdirSync(runtimeRoot, { recursive: true });
  const runtimeDirectory = mkdtempSync(join(runtimeRoot, "test-runtime-"));
  const runtimeFiles: Partial<Record<RuntimeFileRole, string>> = {};
  const runtimeManifestFiles: RuntimeFileEntry[] = [];
  const installRuntimeFile = (role: RuntimeFileRole, sourcePath: string, targetName: string, executable: boolean) => {
    if (!existsSync(sourcePath)) return;
    const targetPath = join(runtimeDirectory, targetName);
    copyFileSync(sourcePath, targetPath);
    if (native && role === "windowsExecutable") prepareWindowsRuntimeExecutable(targetPath);
    runtimeFiles[role] = targetPath;
    runtimeManifestFiles.push({
      role,
      path: targetName,
      sha256: createHash("sha256").update(readFileSync(targetPath)).digest("hex"),
      executable,
    });
  };
  if (runtimePlatform === "win32") {
    const module = join(dirname(dirname(source)), "src/sandbox/backend/windows/mxc");
    installRuntimeFile("windowsExecutable", join(module, "pi-sandbox-windows-mxc.exe"), "pi-sandbox-windows-mxc.exe", true);
    installRuntimeFile("mxcManifest", join(module, "mxc-runtime.json"), "mxc-runtime.json", false);
  } else if (runtimePlatform === "linux") {
    const module = join(dirname(dirname(source)), "src/sandbox/backend/linux");
    installRuntimeFile("linuxLauncher", join(module, "linux-sandbox"), "linux-sandbox", true);
    installRuntimeFile("egressBridge", join(module, "linux-egress-bridge"), "linux-egress-bridge", true);
    installRuntimeFile("bubblewrap", "/usr/bin/bwrap", "bwrap", true);
    if (runtimeFiles.bubblewrap) {
      const licensePath = join(runtimeDirectory, "bwrap.LICENSE");
      writeFileSync(licensePath, "test license");
      runtimeFiles.bubblewrapLicense = licensePath;
      runtimeManifestFiles.push({ role: "bubblewrapLicense", path: "bwrap.LICENSE",
        sha256: createHash("sha256").update(readFileSync(licensePath)).digest("hex"), executable: false });
    }
  }
  const requiredRuntimeFileCount = runtimePlatform === "linux" ? 4 : runtimePlatform === "win32" ? 2 : 0;
  const bubblewrapVersion = runtimePlatform === "linux"
    ? /^bubblewrap (\d+\.\d+\.\d+)/u.exec(spawnSync(runtimeFiles.bubblewrap!, ["--version"], { encoding: "utf8" }).stdout ?? "")?.[1]
    : undefined;
  if (runtimeManifestFiles.length === requiredRuntimeFileCount && requiredRuntimeFileCount > 0 &&
      (runtimePlatform !== "linux" || bubblewrapVersion !== undefined)) {
    writeFileSync(join(runtimeDirectory, "runtime.json"), JSON.stringify({
      schemaVersion: 1,
      version: "1.0.0",
      stable: true,
      platform: runtimePlatform,
      arch: runtimeArch,
      protocolVersion: 2,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId,
      files: runtimeManifestFiles,
      ...(runtimePlatform === "linux" ? { components: { bubblewrapVersion, bubblewrapSourceCommit: "a".repeat(40) } } : {}),
    }));
  }
  const runtime = {
    directory: runtimeDirectory,
    source: "manual",
    manifest: {
      schemaVersion: 1,
      version: "1.0.0",
      stable: true,
      platform: runtimePlatform,
      arch: runtimeArch,
      protocolVersion: 2,
      minPluginVersion: "1.0.0",
      maxPluginVersionExclusive: "2.0.0",
      backendId,
      files: runtimeManifestFiles,
      ...(runtimePlatform === "linux" ? { components: { bubblewrapVersion: "0.13.2", bubblewrapSourceCommit: "a".repeat(40) } } : {}),
    },
    files: runtimeFiles,
  } as unknown as ResolvedRuntimeFiles;
  const runtimeState: SandboxRuntimeState = backendId === "unsupported-platform"
    ? { status: "unavailable", reason: "unsupported test platform" }
    : { status: "ready", runtime };
  const api = {
    events: new EventEmitter(),
    registerTool: (definition: AnyToolDefinition) => { definitions.set(definition.name, definition); sources.set(definition.name, source); },
    registerToolRenderer: () => undefined, registerCommand: () => undefined,
    getAllTools: () => [...definitions.values()].map(definition => ({ name: definition.name,
      description: definition.description, parameters: definition.parameters,
      ...(definition.namespace ? { namespace: definition.namespace } : {}), sourceInfo: {
        path: sources.get(definition.name), source: "local", scope: "user", origin: "top-level",
      } })),
    getMcpServers: () => registeredServers, getActiveTools: () => [], setActiveTools: () => undefined,
    appendEntry: (_type: string, value: unknown) => records.push(value),
    on: (event: string, handler: (...args: unknown[]) => unknown) => { handlers.set(event, [...(handlers.get(event) ?? []), handler]); return () => undefined; },
  } as unknown as ExtensionAPI;
  const execution = createControlledExecution({
    agentDir: layout.agent,
    runtime: () => runtimeState,
    snapshot: (snapshotCtx: ExtensionContext) => {
      const id = snapshotCtx.sessionManager.getSessionId();
      return (sessionOwners.get(id) ?? owner).snapshot({ sessionId: id });
    },
    ...(native ? {} : { controller: (_ctx: ExtensionContext, onRecord: (record: import("#sandbox/types").ExecutionRecord) => void) => {
      const controller = makeController({ layout, onRecord, scenario }); controllers.push(controller); return controller;
    } }),
    mcp: { loadConfig: () => ({ servers: [], errors: [] }) },
  });
  execution.install(api);
  cleanup.push(async () => {
    for (const handler of handlers.get("session_shutdown") ?? []) await handler({ type: "session_shutdown", reason: "quit" }, ctx);
    rmSync(runtimeDirectory, { recursive: true, force: true });
    removeTestLayout(layout);
  });
  const emit = async (name: string, eventContext: ExtensionToolContext = ctx, event: unknown = { type: name }) => {
    for (const handler of handlers.get(name) ?? []) await handler(event, eventContext);
  };
  return { layout, paths, ctx, owner, sessionOwners, execution, definitions, sources, records, controllers, registeredServers, api, emit };
}

describe("production controlled execution boundary", () => {
  it.skipIf(process.platform !== "linux")("protects the same system bubblewrap binary that the helper selects", async () => {
    const systemBinaryDirectory = mkdtempSync(join(tmpdir(), "pi-sandbox-system-bwrap-"));
    const systemBinary = join(systemBinaryDirectory, "bwrap");
    writeFileSync(systemBinary, "#!/bin/sh\nexit 0\n");
    chmodSync(systemBinary, 0o755);
    const previousPath = process.env.PATH;
    let capturedProtectedPaths: readonly string[] | undefined;
    const execute = vi.spyOn(ExecutionController.prototype, "execute").mockImplementation(async input => {
      capturedProtectedPaths = input.plan.protectedPaths;
      throw new Error("captured execution plan");
    });
    process.env.PATH = systemBinaryDirectory;

    try {
      const rig = setup("read-only");
      const selectedSystemBinary = findSystemBubblewrap(process.env.PATH, rig.ctx.cwd);
      expect(selectedSystemBinary).toBe(systemBinary);
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "protected-system-bwrap",
        input: { path: "notes.txt", content: "approved" } };
      const elevation = rig.execution.prepareElevation("write", event.input, "default", rig.ctx);
      if ("block" in elevation) throw new Error(elevation.reason);

      await expect(rig.execution.executeDefault({ toolCallId: "protected-system-bwrap-execution", targetToolName: "write",
        arguments: event.input, reason: "save notes", elevation }, undefined, undefined, rig.ctx)).rejects.toThrow("captured execution plan");

      expect(capturedProtectedPaths).toContain(selectedSystemBinary);
    } finally {
      execute.mockRestore();
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
      rmSync(systemBinaryDirectory, { recursive: true, force: true });
    }
  });

  it.each(["project", "session-workspace"] as const)(
    "runs an explicit Default write to the %s directory in read-only mode without changing the session mode",
    async directory => {
    const rig = setup("read-only");
    const workspace = rig.execution.sessionWorkspace(rig.ctx);
    const target = join(directory === "project" ? rig.layout.workspace : workspace, "notes.txt");
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "readonly-write",
      input: { path: target, content: "approved" } };
    const elevation = rig.execution.prepareElevation("write", event.input, "default", rig.ctx);
    if ("block" in elevation) throw new Error(elevation.reason);
    expect(elevation).toMatchObject({ tier: "default", scope: [
      { path: rig.layout.workspace, access: "write" },
      { path: workspace, access: "write" },
    ] });
    const result = await rig.execution.executeDefault({ toolCallId: "default-target", targetToolName: "write",
      arguments: event.input, reason: "save notes", elevation }, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true);
    expect(readFileSync(target, "utf8")).toBe("approved");
    expect(rig.owner.snapshot({ sessionId: rig.ctx.sessionManager.getSessionId() }).config.mode).toBe("read-only");
    expect(rig.records).toContainEqual(expect.objectContaining({ executionMode: "sandbox", state: "completed" }));
  });

  it(
    "compiles read-only Default elevation into directory-level project and session workspace grants", async () => {
      const rig = setup("read-only", true);
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "capture-native-default-elevation",
        input: { path: "elevated.txt", content: "one-time default" } };
      const elevation = rig.execution.prepareElevation("write", event.input, "default", rig.ctx);
      if ("block" in elevation) throw new Error(elevation.reason);
      let capturedPlan: import("#sandbox/types").ExecutionPlan | undefined;
      const execute = vi.spyOn(ExecutionController.prototype, "execute").mockImplementation(async input => {
        capturedPlan = input.plan;
        throw new Error("captured execution plan");
      });

      try {
        await expect(rig.execution.executeDefault({ toolCallId: "capture-default-target", targetToolName: "write",
          arguments: event.input, reason: "save file", elevation }, undefined, undefined, rig.ctx))
          .rejects.toThrow("captured execution plan");
      } finally {
        execute.mockRestore();
      }

      expect(capturedPlan?.filesystem).toContainEqual(expect.objectContaining({
        path: rig.layout.workspace,
        access: "write",
        granularity: "directory",
        source: "approved-extension",
      }));
      expect(capturedPlan?.filesystem).toContainEqual(expect.objectContaining({
        path: rig.execution.sessionWorkspace(rig.ctx),
        access: "write",
        granularity: "directory",
        source: "approved-extension",
      }));
      expect(capturedPlan?.filesystem).not.toContainEqual(expect.objectContaining({
        path: join(rig.layout.workspace, "elevated.txt"), access: "write", granularity: "file",
      }));
    },
  );

  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))
    .each(["project", "session-workspace"] as const)(
    "writes through native Default elevation to the %s directory while the session stays read-only", async directory => {
      const rig = setup("read-only", true);
      const workspace = rig.execution.sessionWorkspace(rig.ctx);
      const root = directory === "project" ? rig.layout.workspace : workspace;
      const target = join(root, "elevated.txt");
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "native-readonly-elevation",
        input: { path: target, content: "one-time default" } };
      const elevation = rig.execution.prepareElevation("write", event.input, "default", rig.ctx);
      if ("block" in elevation) throw new Error(elevation.reason);
      const result = await rig.execution.executeDefault({ toolCallId: "native-default-target", targetToolName: "write",
        arguments: event.input, reason: "save file", elevation }, undefined, undefined, rig.ctx);
      expect(result.isError).not.toBe(true);
      expect(readFileSync(target, "utf8")).toBe("one-time default");
      const next = { ...event, toolCallId: "ordinary-after-elevation", input: { path: join(root, "ordinary.txt"), content: "must remain blocked" } };
      expect(await rig.execution.guard(next, rig.ctx, async () => undefined)).toMatchObject({
        block: true,
        reason: expect.stringContaining(directory === "project" ? 'tier "default"' : "session-workspace-write-forbidden"),
      });
      expect(existsSync(join(root, "ordinary.txt"))).toBe(false);
      expect(rig.owner.snapshot({ sessionId: rig.ctx.sessionManager.getSessionId() }).config.mode).toBe("read-only");
    },
  );

  it("keeps sandbox resources until the approval host commits a reload", async () => {
    const rig = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "reload-lifecycle",
      input: { path: "reload.txt", content: "approved" },
    };
    await rig.execution.guard(event, rig.ctx, async () => undefined);
    const controller = rig.controllers[0]!;
    const dispose = vi.spyOn(controller, "dispose");

    await rig.emit("resources_discover", rig.ctx, { type: "resources_discover", reason: "reload" });

    expect(dispose).not.toHaveBeenCalled();
    rig.execution.configurationChanged("controlled-session");
    await waitFor(() => dispose.mock.calls.length === 1);
    expect(dispose).toHaveBeenCalledTimes(1);
  });

  it("blocks ordinary approvals from routing managed calls to Host", async () => {
    const rig = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "ordinary-host-forbidden",
      input: { path: "host-escalated.txt", content: "must remain blocked" },
    };
    const review = vi.fn(async () => ({
      kind: "host-execution" as const,
      reason: "ordinary approval cannot issue Host",
    }));

    expect(await rig.execution.guard(event, rig.ctx, review)).toMatchObject({
      block: true,
      reason: expect.stringContaining("ordinary-host-execution-forbidden"),
    });
    expect(review).toHaveBeenCalledTimes(1);
    expect(existsSync(join(rig.layout.workspace, "host-escalated.txt"))).toBe(false);
  });

  it("blocks out-of-scope file calls with the exact path and requested tier", async () => {
    const rig = setup("read-only");
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "readonly-write-requires-default",
      input: { path: "readonly.txt", content: "must remain blocked" },
    };
    const review = vi.fn(async () => undefined);

    expect(await rig.execution.guard(event, rig.ctx, review)).toMatchObject({
      block: true,
      reason: expect.stringContaining("tier \"default\""),
    });
    expect(review).not.toHaveBeenCalled();
    expect(existsSync(join(rig.layout.workspace, "readonly.txt"))).toBe(false);

    const externalPath = join(rig.layout.agent, "external-input.txt");
    const external = await rig.execution.guard({
      type: "tool_call" as const,
      toolName: "read",
      toolCallId: "external-read-requires-host",
      input: { path: externalPath },
    }, rig.ctx, review);
    expect(external).toMatchObject({
      block: true,
      reason: expect.stringContaining(externalPath),
    });
    expect(external?.reason).toContain('tier "host"');
    expect(review).not.toHaveBeenCalled();
    expect(rig.execution.prepareElevation("read", { path: externalPath }, "default", rig.ctx)).toMatchObject({
      block: true,
      reason: expect.stringContaining("default-scope-exceeds-project-and-session-workspace"),
    });
    expect(rig.execution.prepareElevation("read", { path: externalPath }, "host", rig.ctx)).toMatchObject({
      tier: "host",
      scope: [{ path: externalPath, access: "read" }],
    });
  });

  it("keeps ordinary session workspace writes read-only and grants directory scopes only for explicit elevation", async () => {
    const rig = setup("read-only");
    const workspace = rig.execution.sessionWorkspace(rig.ctx);
    const target = join(workspace, "forbidden.txt");
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "readonly-session-workspace-write",
      input: { path: target, content: "must remain blocked" },
    };
    const ordinaryReview = vi.fn(async () => undefined);

    expect(await rig.execution.guard(event, rig.ctx, ordinaryReview)).toMatchObject({
      block: true,
      reason: expect.stringContaining("session-workspace-write-forbidden"),
    });
    expect(ordinaryReview).not.toHaveBeenCalled();
    expect(rig.execution.prepareElevation("write", event.input, "default", rig.ctx)).toMatchObject({
      tier: "default",
      scope: [
        { path: rig.layout.workspace, access: "write" },
        { path: workspace, access: "write" },
      ],
    });
    expect(rig.execution.prepareElevation("write", event.input, "host", rig.ctx)).toMatchObject({
      tier: "host",
      scope: [{ path: target, access: "write" }],
    });
    expect(existsSync(target)).toBe(false);
  });

  it("executes an external Host file request only after the elevation reviewer approves", async () => {
    const rig = setup("read-only");
    const target = join(rig.layout.agent, "approved-host.txt");
    const ordinaryReview = vi.fn(async () => undefined);
    const ordinary = await rig.execution.guard({
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "ordinary-external-write",
      input: { path: target, content: "ordinary must not write" },
    }, rig.ctx, ordinaryReview);
    expect(ordinary).toMatchObject({ block: true, reason: expect.stringContaining('tier "host"') });
    expect(ordinaryReview).not.toHaveBeenCalled();
    expect(existsSync(target)).toBe(false);

    const bypass = createSandboxBypass({
      mode: ctx => rig.owner.snapshot({ sessionId: ctx.sessionManager.getSessionId() }).config.mode,
      policyRevision: ctx => rig.execution.configurationRevision(ctx),
      resolveHostTool: (name, schema) => rig.execution.resolveHostTool(name, schema),
      prepareElevation: (name, args, tier, ctx) => rig.execution.prepareElevation(name, args, tier, ctx),
      validateElevation: (name, args, elevation, ctx) => rig.execution.validateElevation(name, args, elevation, ctx),
      executeDefault: (input, signal, onUpdate, ctx) => rig.execution.executeDefault(input, signal, onUpdate, ctx),
      recordExecution: event => rig.records.push(event),
    });
    bypass.install(rig.api);
    bypass.setReviewer(async input => {
      expect(input.elevation.tier).toBe("host");
      return undefined;
    });

    try {
      const result = await bypass.tool.execute("approved-host-request", {
        reason: "write the requested external output",
        toolName: "write",
        arguments: { path: target, content: "host approved" },
        tier: "host",
      }, undefined, undefined, rig.ctx);
      expect(result.isError).not.toBe(true);
      expect(readFileSync(target, "utf8")).toBe("host approved");
      expect(rig.records).toContainEqual(expect.objectContaining({ executionMode: "host", state: "completed" }));
      expect(rig.owner.snapshot({ sessionId: rig.ctx.sessionManager.getSessionId() }).config.mode).toBe("read-only");
    } finally {
      rmSync(target, { force: true });
    }
  });

  it.each(["default", "auto-review"] as const)("gives each session a persistent, writable workspace and matching temporary environment in %s mode", async mode => {
    const rig = setup(mode);
    const sessionId = rig.ctx.sessionManager.getSessionId();
    const workspace = rig.execution.sessionWorkspace(rig.ctx);
    expect(workspace).toBe(sessionWorkspacePath(rig.layout.agent, sessionId));
    expect(existsSync(join(workspace, "tmp"))).toBe(true);

    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "session-workspace-write",
      input: { path: join(workspace, "artifact.txt"), content: "persisted" },
    };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    let capturedPlan: import("#sandbox/types").ExecutionPlan | undefined;
    const execute = vi.spyOn(ExecutionController.prototype, "execute").mockImplementation(async input => {
      capturedPlan = input.plan;
      throw new Error("captured execution plan");
    });
    try {
      await expect(rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx))
        .rejects.toThrow("captured execution plan");
    } finally {
      execute.mockRestore();
    }

    expect(capturedPlan?.filesystem).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: workspace, access: "read", source: "baseline" }),
      expect.objectContaining({ path: workspace, access: "write", source: "baseline" }),
    ]));
    expect(capturedPlan?.environment).toMatchObject({
      PI_SANDBOX_WORK_DIR: workspace,
      TEMP: join(workspace, "tmp"),
      TMP: join(workspace, "tmp"),
      TMPDIR: join(workspace, "tmp"),
    });

    const forkContext = {
      ...rig.ctx,
      sessionManager: SessionManager.inMemory(rig.layout.workspace, { id: "controlled-session-fork" }),
    } as ExtensionToolContext;
    expect(rig.execution.sessionWorkspace(forkContext)).not.toBe(workspace);
    writeFileSync(join(workspace, "retained.txt"), "retained");
    await rig.emit("session_shutdown", rig.ctx);
    expect(existsSync(join(workspace, "retained.txt"))).toBe(true);
    expect(rig.execution.sessionWorkspace(rig.ctx)).toBe(workspace);
  });

  it("canonicalizes project roots before checking file scope", async () => {
    const rig = setup("default");
    const projectAlias = join(rig.layout.root, "workspace-alias");
    symlinkSync(rig.layout.workspace, projectAlias, process.platform === "win32" ? "junction" : "dir");
    const aliasContext = { ...rig.ctx, cwd: projectAlias } as ExtensionToolContext;
    const inProject = { type: "tool_call" as const, toolName: "write", toolCallId: "symlink-project-write",
      input: { path: "through-alias.txt", content: "in project" } };
    expect(await rig.execution.guard(inProject, aliasContext, async () => undefined)).toBeUndefined();

    const externalDirectory = join(rig.layout.agent, "external-directory");
    mkdirSync(externalDirectory);
    symlinkSync(externalDirectory, join(rig.layout.workspace, "external-link"), process.platform === "win32" ? "junction" : "dir");
    const outsideTarget = join(projectAlias, "external-link", "outside.txt");
    expect(await rig.execution.guard({ ...inProject, toolCallId: "symlink-outside-write",
      input: { path: outsideTarget, content: "outside project" } }, aliasContext, async () => undefined)).toMatchObject({
      block: true,
      reason: expect.stringContaining('tier "host"'),
    });
    expect(existsSync(join(externalDirectory, "outside.txt"))).toBe(false);
  });

  it("refuses a symlinked session workspace", () => {
    const rig = setup();
    const workspace = sessionWorkspacePath(rig.layout.agent, rig.ctx.sessionManager.getSessionId());
    const parent = dirname(workspace);
    mkdirSync(parent, { recursive: true });
    symlinkSync(rig.layout.workspace, workspace, process.platform === "win32" ? "junction" : "dir");

    expect(() => rig.execution.sessionWorkspace(rig.ctx)).toThrow("session-workspace:expected-real-directory");
  });

  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "isolates concurrent Windows host instances by their network leases", async () => {
      const first = createServer((_request, response) => response.end("instance-one"));
      const second = createServer((_request, response) => response.end("instance-two"));
      await Promise.all([new Promise<void>(resolve => first.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => second.listen(0, "127.0.0.1", resolve))]);
      const firstPort = (first.address() as { port: number }).port;
      const secondPort = (second.address() as { port: number }).port;
      const rigs = [setup("default", true), setup("default", true)];
      const events = rigs.map((rig, index) => {
        const ownPort = index === 0 ? firstPort : secondPort;
        const otherPort = index === 0 ? secondPort : firstPort;
        mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
        writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
          mode: "allowlist", allow: [{ host: "127.0.0.1", port: ownPort }],
        } } }));
        const command = `$curl=Join-Path $env:SystemRoot 'System32\\curl.exe'; & $curl --silent --fail --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${ownPort}/'; & $curl --silent --fail --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${otherPort}/'; if ($LASTEXITCODE -eq 0) { 'unexpected-other' } else { 'other-blocked' }`;
        return { type: "tool_call" as const, toolName: "powershell", toolCallId: `network-instance-${index}`, input: { command } };
      });
      try {
        const reviews = await Promise.all(rigs.map((rig, index) => rig.execution.guard(events[index]!, rig.ctx, async () => undefined)));
        expect(reviews).toEqual([undefined, undefined]);
        const results = await Promise.all(rigs.map((rig, index) => rig.definitions.get("powershell")!.execute(events[index]!.toolCallId, events[index]!.input, undefined, undefined, rig.ctx)));
        for (const [index, result] of results.entries()) {
          expect(result.isError, JSON.stringify(result)).not.toBe(true);
          expect(JSON.stringify(result)).toContain(index === 0 ? "instance-one" : "instance-two");
          expect(JSON.stringify(result)).toContain("other-blocked");
          expect(JSON.stringify(result)).not.toContain("unexpected-other");
        }
      } finally {
        first.closeAllConnections(); second.closeAllConnections();
        await Promise.all([new Promise<void>(resolve => first.close(() => resolve())), new Promise<void>(resolve => second.close(() => resolve()))]);
      }
    }, 35_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each(["configuration tightening", "cancellation", "timeout"])(
    "revokes a live Windows proxy connection on %s", async action => {
      let opened = false; let closed = false;
      const server = createServer((_request, response) => {
        opened = true; response.writeHead(200, { "Content-Type": "text/plain" }); response.write("open");
        response.on("close", () => { closed = true; });
      });
      await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as { port: number }).port;
      const rig = setup("default", true);
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      const config = rig.paths.globalConfigFile;
      writeFileSync(config, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] } } }));
      const command = `$curl=Join-Path $env:SystemRoot 'System32\\curl.exe'; & $curl --silent --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${port}/'; Start-Sleep -Seconds 30`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "network-reload", input: { command, ...(action === "timeout" ? { timeout: 8 } : {}) } };
      const abort = new AbortController();
      try {
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const running = rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, abort.signal, undefined, rig.ctx).catch(error => error);
        await waitFor(() => opened, 20_000);
        if (action === "configuration tightening") {
          writeFileSync(config, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: "none" } } }));
          rig.execution.configurationChanged("controlled-session");
        } else if (action === "cancellation") abort.abort();
        await running;
        await waitFor(() => closed, 10_000);
        expect(rig.records).toEqual([expect.objectContaining({ state: "cancelled", started: true,
          ...(action === "timeout" ? { code: "execution-timeout" } : action === "cancellation" ? { code: "execution-cancelled" } : {}) })]);
      } finally { abort.abort(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    }, 35_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each([
    { host: "::1", family: "InterNetworkV6" },
    ...(privateAddress ? [{ host: privateAddress, family: "InterNetwork" }] : []),
  ])("blocks direct $family traffic in the real Windows destination policy", async ({ host, family }) => {
    const server = createTcpServer(socket => socket.end());
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
    const port = (server.address() as { port: number }).port;
    const control = createConnection(port, host); await once(control, "connect"); control.destroy();
    const rig = setup("default", true);
    mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
      mode: "allowlist", allow: [{ host: "example.com", port: 443 }],
    } } }));
    const command = `try { $c=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::${family}); $c.Connect('${host}',${port}); 'unexpected-direct'; $c.Dispose() } catch { 'direct-blocked' }`;
    try {
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: `native-${family}`, input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain("direct-blocked");
      expect(JSON.stringify(result)).not.toContain("unexpected-direct");
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  }, 25_000);

  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "blocks UDP delivery in the real Windows destination policy", async () => {
      const server = createSocket("udp4"); server.bind(0, "127.0.0.1"); await once(server, "listening");
      const port = server.address().port;
      let received = 0; server.on("message", () => { received++; });
      const control = createSocket("udp4"); control.send(Buffer.from("control"), port, "127.0.0.1");
      await waitFor(() => received === 1); control.close(); received = 0;
      const rig = setup("default", true);
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
        mode: "allowlist", allow: [{ host: "example.com", port: 443 }],
      } } }));
      const command = `try { $u=[Net.Sockets.UdpClient]::new(); $u.Send([byte[]](1,2,3),3,'127.0.0.1',${port}) | Out-Null; $u.Dispose() } catch {}; 'udp-attempted'`;
      try {
        const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-udp", input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(result.isError, JSON.stringify(result)).not.toBe(true);
        expect(JSON.stringify(result)).toContain("udp-attempted");
        await new Promise(resolve => setTimeout(resolve, 500));
        expect(received).toBe(0);
      } finally { server.close(); }
    }, 25_000,
  );
  it.skipIf(process.platform !== "linux" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url))))(
    "enforces destination egress for a real Linux Bash tool", async () => {
      const allowed = createServer((_request, response) => response.end("linux-proxy-allowed"));
      const denied = createServer((_request, response) => response.end("linux-proxy-denied"));
      await Promise.all([new Promise<void>(resolve => allowed.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => denied.listen(0, "127.0.0.1", resolve))]);
      const allowedPort = (allowed.address() as { port: number }).port;
      const deniedPort = (denied.address() as { port: number }).port;
      const rig = setup("default", true);
      const previousTemp = process.env.TEMP;
      process.env.TEMP = rig.layout.agent;
      cleanup.push(async () => { if (previousTemp === undefined) delete process.env.TEMP; else process.env.TEMP = previousTemp; });
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
        mode: "allowlist", allow: [{ host: "127.0.0.1", port: allowedPort }],
      } } }));
      const command = `/usr/bin/curl -fsS --noproxy '' --proxy "$HTTP_PROXY" http://127.0.0.1:${allowedPort}/; /usr/bin/curl -fsS --noproxy '' --proxy "$HTTP_PROXY" http://127.0.0.1:${deniedPort}/ >/dev/null 2>&1 && echo unexpected-proxy || echo proxy-blocked; /usr/bin/curl -fsS -m 2 --noproxy '*' http://127.0.0.1:${allowedPort}/ >/dev/null 2>&1 && echo unexpected-direct || echo direct-blocked`;
      try {
        const event = { type: "tool_call" as const, toolName: "bash", toolCallId: "linux-native-network", input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("bash")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(result.isError, JSON.stringify(result)).not.toBe(true);
        expect(JSON.stringify(result)).toContain("linux-proxy-allowed");
        expect(JSON.stringify(result)).toContain("proxy-blocked");
        expect(JSON.stringify(result)).toContain("direct-blocked");
        expect(JSON.stringify(result)).not.toContain("unexpected-");
      } finally {
        allowed.closeAllConnections(); denied.closeAllConnections();
        await Promise.all([new Promise<void>(resolve => allowed.close(() => resolve())), new Promise<void>(resolve => denied.close(() => resolve()))]);
      }
    }, 25_000,
  );
  it.skipIf(process.platform !== "linux" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url)))).each(["none", "all"] as const)(
    "enforces %s for a real Linux Bash tool", async kind => {
      const server = createServer((_request, response) => response.end("linux-direct-ok"));
      await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as { port: number }).port;
      const rig = setup("default", true);
      const previousTemp = process.env.TEMP; process.env.TEMP = rig.layout.agent;
      cleanup.push(async () => { if (previousTemp === undefined) delete process.env.TEMP; else process.env.TEMP = previousTemp; });
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: kind } } }));
      const command = `/usr/bin/curl -fsS -m 2 --noproxy '*' http://127.0.0.1:${port}/ && echo direct-connected || echo direct-blocked; test -z "$HTTP_PROXY" || echo injected-proxy`;
      try {
        const event = { type: "tool_call" as const, toolName: "bash", toolCallId: `linux-native-${kind}`, input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("bash")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(result.isError, JSON.stringify(result)).not.toBe(true);
        expect(JSON.stringify(result)).toContain(kind === "all" ? "direct-connected" : "direct-blocked");
        expect(JSON.stringify(result)).not.toContain("injected-proxy");
      } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each(["none", "all"] as const)(
    "enforces %s for a real PowerShell tool", async kind => {
      const server = createServer((_request, response) => response.end("reachable"));
      await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as { port: number }).port;
      const rig = setup("default", true);
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: kind } } }));
      const command = `try { $c=[Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1',${port}); 'direct-connected'; $c.Dispose() } catch { 'direct-blocked' }; if ($env:HTTP_PROXY) { 'injected-proxy' }`;
      try {
        const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: `native-network-${kind}`, input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(result.isError, JSON.stringify(result)).not.toBe(true);
        expect(JSON.stringify(result)).toContain(kind === "all" ? "direct-connected" : "direct-blocked");
        expect(JSON.stringify(result)).not.toContain("injected-proxy");
      } finally {
        server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
      }
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "enforces destination egress for a real PowerShell tool", async () => {
      const allowed = createServer((_request, response) => response.end("proxy-allowed"));
      const denied = createServer((_request, response) => response.end("proxy-denied"));
      await Promise.all([new Promise<void>(resolve => allowed.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => denied.listen(0, "127.0.0.1", resolve))]);
      const allowedPort = (allowed.address() as { port: number }).port;
      const deniedPort = (denied.address() as { port: number }).port;
      const rig = setup("default", true);
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
        mode: "allowlist", allow: [{ host: "127.0.0.1", port: allowedPort }],
      } } }));
      const command = `$ErrorActionPreference='Stop'; $curl=Join-Path $env:SystemRoot 'System32\\curl.exe'; & $curl --silent --show-error --fail --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${allowedPort}/'; if ($LASTEXITCODE -ne 0) { throw 'proxy request failed' }; & $curl --silent --fail --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${deniedPort}/'; if ($LASTEXITCODE -eq 0) { 'unexpected-proxy' } else { 'proxy-blocked' }; try { $c=[Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1',${allowedPort}); 'unexpected-direct'; $c.Dispose() } catch { 'direct-blocked' }`;
      try {
        const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-network", input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(result.isError, JSON.stringify(result)).not.toBe(true);
        expect(JSON.stringify(result)).toContain("proxy-allowed");
        expect(JSON.stringify(result)).toContain("proxy-blocked");
        expect(JSON.stringify(result)).toContain("direct-blocked");
        expect(JSON.stringify(result)).not.toContain("unexpected-");
      } finally {
        allowed.closeAllConnections(); denied.closeAllConnections();
        await Promise.all([new Promise<void>(resolve => allowed.close(() => resolve())), new Promise<void>(resolve => denied.close(() => resolve()))]);
      }
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !privateAddress || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "uses the controlled proxy automatically for PowerShell web requests", async () => {
      const allowed = createServer((_request, response) => response.end("allowed"));
      const denied = createServer((_request, response) => response.end("denied"));
      await Promise.all([new Promise<void>(resolve => allowed.listen(0, privateAddress, resolve)), new Promise<void>(resolve => denied.listen(0, privateAddress, resolve))]);
      const allowedPort = (allowed.address() as { port: number }).port;
      const deniedPort = (denied.address() as { port: number }).port;
      const rig = setup("default", true);
      mkdirSync(join(rig.layout.agent, "extensions", "pi-sandbox"), { recursive: true });
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: {
        mode: "allowlist", allow: [{ host: privateAddress!, port: allowedPort }],
      } } }));
      const command = `try { 'allowed-' + (Invoke-WebRequest -Uri 'http://${privateAddress}:${allowedPort}/' -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 'allowed-failed' }; try { (Invoke-WebRequest -Uri 'http://${privateAddress}:${deniedPort}/' -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 'denied-blocked' }`;
      try {
        const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "automatic-proxy", input: { command } };
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
        expect(JSON.stringify(result)).toContain('"allowed-200\\r\\ndenied-blocked');
      } finally {
        allowed.closeAllConnections(); denied.closeAllConnections();
        await Promise.all([new Promise<void>(resolve => allowed.close(() => resolve())), new Promise<void>(resolve => denied.close(() => resolve()))]);
      }
    }, 25_000,
  );
  it.each(["default", "read-only", "full-access"] as const)("disables the incompatible platform shell in %s mode", async mode => {
    const rig = setup(mode);
    const disabled = process.platform === "win32" ? "bash" : "powershell";
    const enabled = process.platform === "win32" ? "powershell" : "bash";
    expect(rig.definitions.get(disabled)!.exposure).toBe("hidden");
    expect(rig.definitions.get(enabled)!.exposure).not.toBe("hidden");
    const event = { type: "tool_call" as const, toolName: disabled, toolCallId: "disabled-shell", input: { command: "echo test" } };
    const review = vi.fn(async () => undefined);
    expect(await rig.execution.guard(event, rig.ctx, review)).toMatchObject({ block: true, reason: expect.stringContaining("sandbox-capability-unsupported") });
    expect(review).not.toHaveBeenCalled();
    await expect(rig.definitions.get(disabled)!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx)).rejects.toThrow("sandbox-capability-unsupported");
    expect(rig.controllers).toHaveLength(0);
    expect(rig.records).toEqual([]);
  });
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each([
    { name: "grep", binary: "rg.exe", input: { path: ".", pattern: "needle" }, expected: "needle" },
    { name: "find", binary: "fd.exe", input: { path: ".", pattern: "*.txt" }, expected: "sample.txt" },
  ] as const)("runs $name from a custom Pi agent directory", async ({ name, binary, input, expected }) => {
    const previousAgent = process.env.PI_CODING_AGENT_DIR;
    const previousPath = process.env.PATH;
    const source = join(process.env.USERPROFILE!, ".pi", "agent", "bin", binary);
    expect(existsSync(source)).toBe(true);
    const rig = setup("default", true);
    const agent = join(rig.layout.root, "custom-agent");
    mkdirSync(join(agent, "bin"), { recursive: true });
    copyFileSync(source, join(agent, "bin", binary));
    writeFileSync(join(rig.layout.workspace, "sample.txt"), "needle");
    process.env.PI_CODING_AGENT_DIR = agent;
    process.env.PATH = "";
    try {
      const event = { type: "tool_call" as const, toolName: name, toolCallId: `native-custom-${name}`, input };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get(name)!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain(expected);
    } finally {
      if (previousAgent === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = previousAgent;
      if (previousPath === undefined) delete process.env.PATH; else process.env.PATH = previousPath;
    }
  }, 25_000);
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "runs a real builtin through the production Windows backend", async () => {
      const rig = setup("default", true);
      writeFileSync(join(rig.layout.workspace, "approved.txt"), "production-native-read");
      const event = { type: "tool_call" as const, toolName: "read", toolCallId: "native-read", input: { path: "approved.txt" } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("read")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain("production-native-read");
      expect(rig.records).toEqual([expect.objectContaining({ state: "completed", started: true, toolName: "read" })]);
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "writes an approved file through the production Windows backend", async () => {
      const rig = setup("default", true);
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "native-write", input: { path: "approved.txt", content: "production-native-write" } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(readFileSync(join(rig.layout.workspace, "approved.txt"), "utf8")).toBe("production-native-write");
      expect(rig.records).toEqual([expect.objectContaining({ state: "completed", started: true, toolName: "write" })]);
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "overwrites an existing approved file through the production Windows backend", async () => {
      const rig = setup("default", true);
      const target = join(rig.layout.workspace, "approved.txt");
      writeFileSync(target, "original");
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "native-overwrite", input: { path: "approved.txt", content: "updated" } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(readFileSync(target, "utf8")).toBe("updated");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "overwrites an existing file addressed with the Pi @ prefix", async () => {
      const rig = setup("default", true);
      const target = join(rig.layout.workspace, "approved.txt");
      writeFileSync(target, "original");
      const event = { type: "tool_call" as const, toolName: "write", toolCallId: "native-prefixed-overwrite", input: { path: "@approved.txt", content: "updated" } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(readFileSync(target, "utf8")).toBe("updated");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "serializes concurrent edits to the same file through the production Windows backend", async () => {
      const rig = setup("default", true);
      const target = join(rig.layout.workspace, "concurrent.txt");
      writeFileSync(target, "left right");
      const events = [
        { type: "tool_call" as const, toolName: "edit", toolCallId: "edit-left", input: { path: "concurrent.txt", edits: [{ oldText: "left", newText: "LEFT" }] } },
        { type: "tool_call" as const, toolName: "edit", toolCallId: "edit-right", input: { path: "concurrent.txt", edits: [{ oldText: "right", newText: "RIGHT" }] } },
      ];
      for (const event of events) expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const results = await Promise.all(events.map(event => rig.definitions.get("edit")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx)));
      expect(results.map(result => result.isError)).not.toContain(true);
      expect(readFileSync(target, "utf8")).toBe("LEFT RIGHT");
    }, 30_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "does not allow editing a protected file through the production Windows backend", async () => {
      const rig = setup("default", true);
      const control = join(rig.layout.workspace, ".git");
      mkdirSync(control);
      const target = join(control, "config");
      writeFileSync(target, "original");
      const event = { type: "tool_call" as const, toolName: "edit", toolCallId: "protected-edit", input: { path: target, edits: [{ oldText: "original", newText: "changed" }] } };
      const denied = await rig.execution.guard(event, rig.ctx, async () => undefined);
      if (!denied) {
        try { await rig.definitions.get("edit")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx); } catch { /* Rejection is expected. */ }
      }
      expect(readFileSync(target, "utf8")).toBe("original");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "allows workspace writes while denying protected control paths", async () => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const protectedFile = join(rig.layout.workspace, ".git", "config");
      writeFileSync(protectedFile, "original");
      const allowedFile = join(rig.layout.workspace, "allowed.txt");
      const safeProtected = protectedFile.replaceAll("'", "''");
      const protectedDir = join(rig.layout.workspace, ".git").replaceAll("'", "''");
      const movedDir = join(rig.layout.workspace, "git-moved").replaceAll("'", "''");
      const command = `[IO.File]::WriteAllText('${allowedFile.replaceAll("'", "''")}','allowed'); try { [IO.File]::WriteAllText('${safeProtected}','changed'); 'writable' } catch { 'denied' }; try { [IO.File]::Delete('${safeProtected}'); 'deleted' } catch { 'delete-denied' }; try { [IO.Directory]::Move('${protectedDir}','${movedDir}'); 'moved' } catch { 'move-denied' }`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-protected", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(readFileSync(allowedFile, "utf8")).toBe("allowed");
      expect(readFileSync(protectedFile, "utf8")).toBe("original");
      expect(JSON.stringify(result)).toContain("denied");
      expect(JSON.stringify(result)).toContain("delete-denied");
      expect(JSON.stringify(result)).toContain("move-denied");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each(["existing", "created"])(
    "does not implicitly protect nested control directories: %s", async state => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const nested = join(rig.layout.workspace, "nested");
      mkdirSync(nested);
      const target = join(nested, ".git", "config");
      if (state === "existing") { mkdirSync(join(nested, ".git")); writeFileSync(target, "original"); }
      const command = `try { ${state === "created" ? `[IO.Directory]::CreateDirectory('${join(nested, ".git").replaceAll("'", "''")}') | Out-Null; ` : ""}[IO.File]::WriteAllText('${target.replaceAll("'", "''")}','changed'); 'writable' } catch { 'denied' }`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-nested-protected", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(readFileSync(target, "utf8")).toBe("changed");
      expect(JSON.stringify(result)).toContain("writable");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "denies writes to a protected file's alternate data stream", async () => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const file = join(rig.layout.workspace, ".git", "config");
      const stream = `${file}:mxc-test`;
      writeFileSync(file, "original");
      writeFileSync(stream, "original-stream");
      expect(readFileSync(stream, "utf8")).toBe("original-stream");
      const command = `try { [IO.File]::WriteAllText('${stream.replaceAll("'", "''")}','changed'); 'writable' } catch { 'denied' }`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-protected-stream", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain("denied");
      expect(readFileSync(stream, "utf8")).toBe("original-stream");
      expect(readFileSync(file, "utf8")).toBe("original");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "cancels a running PowerShell process through the production Windows backend", async () => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const command = "Write-Output ('pid=' + $PID); Start-Sleep -Seconds 30";
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-cancel", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const abort = new AbortController();
      let pid = 0;
      let finished = false;
      let outcome: unknown;
      const running = rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, abort.signal, update => {
        const match = /pid=(\d+)/u.exec(JSON.stringify(update));
        if (match) pid = Number(match[1]);
      }, rig.ctx).catch(error => error).then(result => { outcome = result; finished = true; return result; });
      try {
        await waitFor(() => pid > 0 || finished, 20_000);
        expect(pid, JSON.stringify(outcome)).toBeGreaterThan(0);
        expect(() => process.kill(pid, 0)).not.toThrow();
        abort.abort();
        await running;
        await waitFor(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
        expect(rig.records).toEqual([expect.objectContaining({ state: "cancelled", code: "execution-cancelled", started: true })]);
      } finally { abort.abort(); await running; }
    }, 35_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "times out a PowerShell process tree through the production Windows backend", async () => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const command = "$exe=$env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; $p=[Diagnostics.Process]::Start($exe,'-NoProfile -Command Start-Sleep -Seconds 60'); Write-Output ('rootpid=' + $PID); Write-Output ('childpid=' + $p.Id); Start-Sleep -Seconds 60";
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-timeout", input: { command, timeout: 20 } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      let rootPid = 0;
      let childPid = 0;
      let observedLive = false;
      let outcome: unknown;
      const abort = new AbortController();
      const watchdog = setTimeout(() => abort.abort(), 35_000);
      try {
        outcome = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, abort.signal, update => {
          const output = JSON.stringify(update);
          rootPid = Number(/rootpid=(\d+)/u.exec(output)?.[1] ?? rootPid);
          childPid = Number(/childpid=(\d+)/u.exec(output)?.[1] ?? childPid);
          if (rootPid && childPid) {
            try { process.kill(rootPid, 0); process.kill(childPid, 0); observedLive = true; } catch {}
          }
        }, rig.ctx);
      } catch (error) { outcome = error; }
      finally { clearTimeout(watchdog); }
      expect(rootPid, String(outcome)).toBeGreaterThan(0);
      expect(childPid, String(outcome)).toBeGreaterThan(0);
      expect(observedLive).toBe(true);
      for (const pid of [rootPid, childPid]) await waitFor(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
      expect(rig.records).toEqual([expect.objectContaining({ state: "cancelled", code: "execution-timeout", started: true })]);
    }, 45_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "runs PowerShell Start-Process through the production Windows backend", async () => {
      const rig = setup("default", true);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(rig.layout.workspace, name));
      const command = "$ErrorActionPreference='Stop'; $exe=$env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; $p=Start-Process -FilePath $exe -ArgumentList '-NoProfile -Command exit 0' -Wait -PassThru; if ($p.ExitCode -eq 0) { 'start-success' }";
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-start-process", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain("start-success");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "allows workspace writes while denying a missing protected control directory", async () => {
      const rig = setup("default", true);
      const target = join(rig.layout.workspace, ".aws");
      const allowed = join(rig.layout.workspace, "allowed.txt");
      const command = `[IO.File]::WriteAllText('${allowed.replaceAll("'", "''")}','allowed'); try { [IO.Directory]::CreateDirectory('${target.replaceAll("'", "''")}') | Out-Null; 'created' } catch { 'denied' }`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "native-missing-protected", input: { command } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
      const result = await rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      expect(JSON.stringify(result)).toContain("denied");
      expect(readFileSync(allowed, "utf8")).toBe("allowed");
      expect(existsSync(target)).toBe(false);
      expect(rig.records).toEqual([expect.objectContaining({ state: "completed", started: true })]);
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each([
    { name: "edit", input: { path: "sample.txt", edits: [{ oldText: "needle", newText: "changed" }] }, expected: "changed" },
    { name: "ls", input: { path: "." }, expected: "sample.txt" },
    { name: "grep", input: { path: ".", pattern: "needle" }, expected: "needle" },
    { name: "find", input: { path: ".", pattern: "*.txt" }, expected: "sample.txt" },
  ] as const)("runs the $name builtin through production MXC", async ({ name, input, expected }) => {
    const rig = setup("default", true);
    const file = join(rig.layout.workspace, "sample.txt");
    writeFileSync(file, "needle");
    const event = { type: "tool_call" as const, toolName: name, toolCallId: `native-${name}`, input };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    const result = await rig.definitions.get(name)!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    expect(name === "edit" ? readFileSync(file, "utf8") : JSON.stringify(result)).toContain(expected);
  }, 25_000);
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "blocks the bash builtin before approval through production MXC", async () => {
      const rig = setup("default", true);
      const event = { type: "tool_call" as const, toolName: "bash", toolCallId: "native-bash", input: { command: "printf mxc-bash-ok" } };
      expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toMatchObject({ block: true, reason: expect.stringContaining("sandbox-capability-unsupported") });
      expect(rig.definitions.get("bash")!.exposure).toBe("hidden");
      expect(rig.records).toEqual([]);
    }, 25_000,
  );
  it("keeps final binding in full-access while running the original SDK tool without a helper", async () => {
    const rig = setup("full-access");
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "full-access", input: { path: "approved.txt", content: "approved" } };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true);
    expect(readFileSync(join(rig.layout.workspace, "approved.txt"), "utf8")).toBe("approved");
    expect(rig.records).toEqual([expect.objectContaining({ state: "completed", started: true })]);
    const altered = { ...event, toolCallId: "altered-full-access" };
    expect(await rig.execution.guard(altered, rig.ctx, async () => undefined)).toBeUndefined();
    const blocked = await rig.definitions.get("write")!.execute(altered.toolCallId, { path: "other.txt", content: "changed" }, undefined, undefined, rig.ctx);
    expect(blocked.isError).toBe(true); expect(rig.records).toHaveLength(1);
  });
  it.each([
    { mode: "default" as const, strict: false },
    { mode: "default" as const, strict: true },
    { mode: "auto-review" as const, strict: false },
    { mode: "auto-review" as const, strict: true },
  ].flatMap(settings => [false, true].map(sandboxEnabled => ({ ...settings, sandboxEnabled }))))(
    "runs stdio MCP on the host in $mode mode with strict approval=$strict and OS sandbox=$sandboxEnabled", async ({ mode, strict, sandboxEnabled }) => {
    const rig = setup(mode);
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({
      mode,
      experimental: { sandboxEnabled, mcpSandbox: true },
      execution: { network: { mode: "none" } },
      shellPolicy: { version: 1, rules: [], modes: { [mode]: { defaultPolicy: strict ? "ask" : "sandbox-run" } } },
    }));
    const snapshot = rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    expect(snapshot.source).toBe("global");
    expect(snapshot.config.experimental).toEqual({ sandboxEnabled });
    await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: `establish-${mode}-${strict}`, input: { path: "a.txt" } }, rig.ctx, async () => undefined);
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))], exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    const id = `host-mcp-${mode}-${strict}`;
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: id, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
    const result = await rig.definitions.get("mcp__fixture__ping")!.execute(id, {}, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true);
    expect(rig.records).toContainEqual(expect.objectContaining({ toolName: "mcp__fixture__ping", executionMode: "host", started: true }));
  }, 20_000);

  it("reconnects stdio MCP after configuration reload", async () => {
    const rig = setup();
    await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: "establish-reload", input: { path: "a.txt" } }, rig.ctx, async () => undefined);
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { mcpSandbox: true }, execution: { network: { mode: "none" } } }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))], exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    const invoke = async (id: string) => {
      expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: id, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
      return rig.definitions.get("mcp__fixture__ping")!.execute(id, {}, undefined, undefined, rig.ctx);
    };
    const first = await invoke("mcp-before-reload");
    const firstText = first.content.find(part => part.type === "text");
    if (firstText?.type !== "text") throw new Error("MCP fixture returned no text");
    const firstPid = JSON.parse(firstText.text).pid;

    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ debugLog: true, experimental: { mcpSandbox: false }, execution: { network: { mode: "none" } } }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    rig.execution.configurationChanged(rig.ctx.sessionManager.getSessionId());
    const second = await invoke("mcp-after-reload");
    const secondText = second.content.find(part => part.type === "text");
    if (secondText?.type !== "text") throw new Error("MCP fixture returned no text");
    expect(JSON.parse(secondText.text).pid).not.toBe(firstPid);
    expect(rig.records.filter((record): record is { toolName: string; executionMode: string } =>
      typeof record === "object" && record !== null && "toolName" in record && record.toolName === "mcp__fixture__ping"))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ executionMode: "host" }),
        expect.objectContaining({ executionMode: "host" }),
      ]));
  }, 20_000);

  it.each(["none", "allowlist"] as const)("connects HTTP MCP when built-in network is %s", async networkMode => {
    const rig = setup("auto-review");
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({
      mode: "auto-review",
      execution: { network: networkMode === "none" ? { mode: "none" } : { mode: "allowlist", allow: [{ host: "example.com", port: 443 }] } },
      shellPolicy: { version: 1, rules: [], modes: { "auto-review": { defaultPolicy: "ask" } } },
    }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    const server = createServer(async (request, response) => {
      if (request.method === "GET") { response.writeHead(405).end(); return; }
      if (request.method === "DELETE") { response.writeHead(200).end(); return; }
      let body = "";
      for await (const chunk of request) body += chunk;
      const message = JSON.parse(body);
      if (message.id === undefined) { response.writeHead(202).end(); return; }
      const result = message.method === "initialize"
        ? { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "http-fixture", version: "1" } }
        : message.method === "tools/list"
          ? { tools: [{ name: "ping", description: "Ping", inputSchema: { type: "object" } }] }
          : { content: [{ type: "text", text: "host-http-ok" }] };
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
    });
    cleanup.push(async () => {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      url: `http://127.0.0.1:${port}/mcp`, exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    const event = { type: "tool_call" as const, toolName: "mcp__fixture__ping", toolCallId: `host-http-${networkMode}`, input: {} };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    const result = await rig.definitions.get(event.toolName)!.execute(event.toolCallId, {}, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true);
    expect(result.content).toContainEqual({ type: "text", text: "host-http-ok" });
    expect(rig.records).toContainEqual(expect.objectContaining({ toolName: "mcp__fixture__ping", executionMode: "host", started: true }));
  });
  it("manages extension MCP registration, tool withdrawal and one reusable host connection", async () => {
    const rig = setup();
    // Establish the execution session before Pi connects a dynamically registered service.
    await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: "establish", input: { path: "a.txt" } }, rig.ctx, async () => undefined);
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))], exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    expect(rig.definitions.get("mcp__fixture__ping")?.namespace).toMatchObject({
      name: "mcp__fixture",
      aliases: ["fixture"],
    });
    let sequence = 0;
    const invoke = async (toolName: string) => {
      const id = `mcp-${++sequence}`;
      expect(await rig.execution.guard({ type: "tool_call", toolName, toolCallId: id, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
      return rig.definitions.get(toolName)!.execute(id, {}, undefined, undefined, rig.ctx);
    };
    const first = await invoke("mcp__fixture__ping");
    const firstText = first.content.find(part => part.type === "text");
    if (firstText?.type !== "text") throw new Error("MCP fixture returned no text");
    const pid = JSON.parse(firstText.text).pid;
    await invoke("mcp__fixture__toggle");
    await waitFor(() => rig.definitions.has("mcp__fixture__extra"));
    const extra = await invoke("mcp__fixture__extra");
    const extraText = extra.content.find(part => part.type === "text");
    if (extraText?.type !== "text") throw new Error("MCP fixture returned no text");
    expect(JSON.parse(extraText.text).pid).toBe(pid);
    await invoke("mcp__fixture__toggle");
    await waitFor(() => rig.definitions.get("mcp__fixture__extra")?.exposure === "hidden");
    const review = vi.fn(async () => undefined);
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__extra", toolCallId: "withdrawn", input: {} }, rig.ctx, review)).toMatchObject({ block: true });
    expect(review).not.toHaveBeenCalled();
    rig.registeredServers.length = 0;
    await rig.emit("mcp_servers_change");
    await waitFor(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
    expect(rig.records).toHaveLength(4);
    expect(rig.records).toEqual(expect.arrayContaining([expect.objectContaining({ toolName: "mcp__fixture__ping", state: "completed", started: true })]));
  }, 20_000);
  it("skips repeated review inside Codemode but keeps controlled execution", async () => {
    const rig = setup();
    const review = vi.fn(async () => ({ block: true as const, reason: "nested-review" }));
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "codemode-nested",
      input: { path: "nested.txt", content: "sandboxed" } };
    await runWithApprovedCodemode("controlled-session", () => true, async () => {
      expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
      const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
      expect(result.isError).not.toBe(true);
    });
    expect(review).not.toHaveBeenCalled();
    expect(readFileSync(join(rig.layout.workspace, "nested.txt"), "utf8")).toBe("sandboxed");
    await runWithApprovedCodemode("controlled-session", () => false, async () => {
      expect(await rig.execution.guard({ ...event, toolCallId: "expired-codemode" }, rig.ctx, review))
        .toMatchObject({ block: true, reason: "nested-review" });
    });
    expect(review).toHaveBeenCalledTimes(1);
  });

  it("invalidates a pending approval when only the project execution network changes", async () => {
    const rig = setup();
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: "all" } } }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    const path = rig.paths.projectConfigFile;
    const writeNetwork = (port: number) => {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, JSON.stringify({ experimental: { sandboxEnabled: true }, execution: { network: { mode: "allowlist", allow: [{ host: "example.com", port }] } } }));
    };
    writeNetwork(443);
    const event = { type: "tool_call" as const, toolName: "read", toolCallId: "network-revision", input: { path: "a.txt" } };
    const result = await rig.execution.guard(event, rig.ctx, async () => {
      writeNetwork(8443);
      rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
      return undefined;
    });
    expect(result).toMatchObject({ block: true, reason: expect.stringContaining("plan-invalidated") });
  });
  it("waits for the original close across consecutive configuration invalidations", async () => {
    const rig = setup();
    const event = { type: "tool_call" as const, toolName: "read", toolCallId: "before-retirement", input: { path: "a.txt" } };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    const controller = rig.controllers[0]!;
    const dispose = controller.dispose.bind(controller);
    let release!: () => void;
    const closing = new Promise<void>(resolve => { release = resolve; });
    controller.dispose = async () => { await closing; await dispose(); };
    rig.execution.configurationChanged("controlled-session");
    rig.execution.configurationChanged("controlled-session");
    const next = rig.execution.guard({ ...event, toolCallId: "after-retirement" }, rig.ctx, async () => undefined);
    try {
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(rig.controllers).toHaveLength(1);
    } finally { release(); }
    expect(await next).toBeUndefined();
    expect(rig.controllers).toHaveLength(2);
  });
  it("rejects a forged MCP prefix and a builtin override even when it reuses the schema", async () => {
    const rig = setup();
    const review = vi.fn(async () => undefined);
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: "forged", input: {} }, rig.ctx, review)).toMatchObject({ block: true });
    rig.sources.set("read", join(rig.layout.workspace, "ordinary-plugin.ts"));
    expect(await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: "override", input: { path: "a.txt" } }, rig.ctx, review)).toMatchObject({ block: true });
    expect(review).not.toHaveBeenCalled(); expect(rig.records).toEqual([]);
  });

  it("blocks parameters changed after the sole approval without starting a helper", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "a.txt"), "approved");
    writeFileSync(join(rig.layout.workspace, "b.txt"), "unapproved");
    const event = { type: "tool_call" as const, toolName: "read", toolCallId: "mutated", input: { path: "a.txt" } };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    const result = await rig.definitions.get("read")!.execute(event.toolCallId, { path: "b.txt" }, undefined, undefined, rig.ctx);
    expect(result.isError).toBe(true);
    expect(result.content).toEqual(expect.arrayContaining([expect.objectContaining({ text: expect.stringContaining("action-changed-before-execution") })]));
    expect(rig.records).toEqual([]);
  });

  it("records one successful SDK call after one approval and revokes the next old binding", async () => {
    const rig = setup();
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "owned", input: { path: "@a.txt", content: "approved" } };
    expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
    const result = await rig.definitions.get("write")!.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true); expect(review).toHaveBeenCalledTimes(1);
    expect(readFileSync(join(rig.layout.workspace, "a.txt"), "utf8")).toBe("approved");
    expect(rig.records).toEqual([expect.objectContaining({ state: "completed", started: true, toolName: "write", sessionId: "controlled-session" })]);
    const next = { ...event, toolCallId: "retired" };
    expect(await rig.execution.guard(next, rig.ctx, review)).toBeUndefined();
    rig.execution.configurationChanged("controlled-session");
    const blocked = await rig.definitions.get("write")!.execute(next.toolCallId, next.input, undefined, undefined, rig.ctx);
    expect(blocked.isError).toBe(true); expect(rig.records).toHaveLength(1);
  }, 20_000);
});

describe("tool admission rules at the gate (design §5)", () => {
  function configureRules(rig: ReturnType<typeof setup>, rules: unknown): void {
    const current = existsSync(rig.paths.globalConfigFile)
      ? JSON.parse(readFileSync(rig.paths.globalConfigFile, "utf8")) as Record<string, unknown>
      : {};
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ ...current, toolRules: rules }));
    rig.owner.reload();
  }

  it("refuses a denied tool without running the approval chain", async () => {
    const rig = setup();
    configureRules(rig, [{ id: "deny-mcp", match: { tool: "mcp__*" }, decision: "deny" }]);
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "mcp__shell", toolCallId: "denied-1", input: { command: "ls" } };

    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-denied-tool:deny-mcp",
    });
    expect(review).not.toHaveBeenCalled();
    expect(rig.records).toEqual([expect.objectContaining({
      toolCallId: "denied-1",
      toolName: "mcp__shell",
      decision: "deny",
      ruleId: "deny-mcp",
      scope: "global",
      argumentLevel: false,
    })]);
  });

  it("admits an unmanaged tool declared by an allow rule", async () => {
    const rig = setup();
    configureRules(rig, [{ id: "allow-diff", match: { tool: "watchdog_diff" }, decision: "allow" }]);
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "watchdog_diff", toolCallId: "allowed-1", input: { path: "a.ts" } };

    expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
    expect(review).not.toHaveBeenCalled();
    expect(rig.records).toEqual([expect.objectContaining({ decision: "allow", ruleId: "allow-diff" })]);
  });

  it.each(["default", "read-only", "full-access"] as const)(
    "hands an allow-rule unmanaged host tool to the host in %s mode (single-tool exemption)",
    async (mode) => {
      const rig = setup(mode);
      configureRules(rig, [{ id: "allow-diff", match: { tool: "watchdog_diff" }, decision: "allow" }]);
      const review = vi.fn(async () => undefined);
      const event = { type: "tool_call" as const, toolName: "watchdog_diff", toolCallId: "allow-host", input: { path: "a.ts" } };

      // specs/tool-access.md §10: an allow rule on an unmanaged host tool equals a
      // one-tool exemption. The gate returns no decision and no scope: the host
      // runs its own definition natively, outside this plugin's OS sandbox, in
      // every mode (read-only included). The rule table grants no OS permission.
      expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
      expect(review).not.toHaveBeenCalled();
      expect(rig.definitions.has("watchdog_diff")).toBe(false);
      expect(rig.records).toEqual([expect.objectContaining({
        decision: "allow", ruleId: "allow-diff", toolName: "watchdog_diff", scope: "global", argumentLevel: false,
      })]);
    },
  );

  it("refuses an allow-rule sandbox tool whose module cannot be resolved", async () => {
    const rig = setup();
    configureRules(rig, [{
      id: "allow-missing", match: { tool: "missing_tool" }, decision: "allow",
      sandbox: { path: "./does-not-exist.mjs" },
    }]);
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "missing_tool", toolCallId: "unavailable", input: {} };

    // Declaring `sandbox` opts into the sandbox path; an unusable declaration
    // never falls back to host-native execution.
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-unavailable: missing_tool",
    });
    expect(review).not.toHaveBeenCalled();
    expect(rig.records).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "sandbox-tool-diagnostic", ruleId: "allow-missing", name: "missing_tool", reason: "module-not-found" }),
      expect.objectContaining({ decision: "allow", ruleId: "allow-missing", toolName: "missing_tool" }),
    ]));
  });

  it("still asks for an unmanaged tool without a rule", async () => {
    const rig = setup();
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "watchdog_diff", toolCallId: "unmanaged-1", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-unmanaged-tool: watchdog_diff",
    });
    expect(review).not.toHaveBeenCalled();
  });

  it("takes the ask branch through the review channel for an owned tool", async () => {
    const rig = setup();
    const review = vi.fn(async (_input?: { readonly ask?: boolean }) => undefined);
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "ask-1", input: { path: "a.txt", content: "x" } };
    expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
    expect(review).toHaveBeenCalledWith({ ask: true });
  });

  it("skips the review channel when an allow rule admits an owned tool", async () => {
    const rig = setup();
    configureRules(rig, [{ id: "allow-write", match: { tool: "write" }, decision: "allow" }]);
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "rule-allowed", input: { path: "a.txt", content: "x" } };
    expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
    expect(review).not.toHaveBeenCalled();
  });

  it("validates declared locations before an allow rule runs", async () => {
    const rig = setup();
    configureRules(rig, [{
      id: "allow-diff",
      match: { tool: "watchdog_diff" },
      decision: "allow",
      profile: "file-reader",
      locations: [{ pointer: "/path", access: "read" }],
    }]);
    const event = { type: "tool_call" as const, toolName: "watchdog_diff", toolCallId: "missing-path", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toEqual({
      block: true,
      reason: "sandbox-tool-rule:allow-diff:missing-location",
    });
  });

  it("applies argument-level deny before a tool-level allow", async () => {
    const rig = setup();
    configureRules(rig, [
      { id: "allow-bash", match: { tool: "bash" }, decision: "allow" },
      { id: "deny-rm", match: { tool: "bash", args: { "/command": "rm *" } }, decision: "deny" },
    ]);
    const event = { type: "tool_call" as const, toolName: "write", toolCallId: "arg-deny", input: { path: "a.txt", content: "x" } };
    // `write` is not covered by these rules, so the ask branch still applies.
    const review = vi.fn(async (_input?: { readonly ask?: boolean }) => undefined);
    expect(await rig.execution.guard(event, rig.ctx, review)).toBeUndefined();
    expect(review).toHaveBeenCalledWith({ ask: true });
  });
});

describe("sandbox-hosted tools through the controlled executor (design §6)", () => {
  const COUNTER_TOOL = `
    import { readFile, writeFile } from "node:fs/promises";
    import { join } from "node:path";
    let calls = 0;
    export async function execute(args, ctx) {
      calls += 1;
      const file = join(ctx.stateDirectory, "count");
      let previous = 0;
      try { previous = Number(await readFile(file, "utf8")); } catch {}
      const next = previous + 1;
      await writeFile(file, String(next));
      return { content: [{ type: "text", text: \`persisted=\${next};memory=\${calls};config=\${JSON.stringify(ctx.config)};cwd=\${ctx.cwd}\` }] };
    }
  `;

  function configureSandboxRules(rig: ReturnType<typeof setup>, rules: unknown[]): void {
    const current = existsSync(rig.paths.globalConfigFile)
      ? JSON.parse(readFileSync(rig.paths.globalConfigFile, "utf8")) as Record<string, unknown>
      : {};
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ ...current, toolRules: rules }));
    rig.owner.reload();
  }

  function textOf(result: { content: readonly { type: string; text?: string }[] }): string {
    return result.content.filter((item) => item.type === "text").map((item) => item.text ?? "").join("");
  }

  it("runs a declared tool in the helper and keeps its state across calls", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-counter",
      match: { tool: "counter_tool" },
      decision: "allow",
      sandbox: { path: "./counter-tool.mjs", config: { maxLines: 200 } },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });

    const tool = rig.definitions.get("counter_tool");
    expect(tool).toBeDefined();
    const review = vi.fn(async (_input?: { readonly ask?: boolean }) => undefined);
    const first = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "counter-1", input: {} };
    expect(await rig.execution.guard(first, rig.ctx, review)).toBeUndefined();
    expect(review).not.toHaveBeenCalled();
    const firstResult = await tool!.execute("counter-1", {}, undefined, undefined, rig.ctx);
    expect(firstResult.isError).not.toBe(true);
    expect(textOf(firstResult)).toContain("persisted=1;memory=1");
    expect(textOf(firstResult)).toContain("config={\"maxLines\":200}");

    const second = { ...first, toolCallId: "counter-2" };
    expect(await rig.execution.guard(second, rig.ctx, review)).toBeUndefined();
    const secondResult = await tool!.execute("counter-2", {}, undefined, undefined, rig.ctx);
    expect(textOf(secondResult)).toContain("persisted=2;memory=1");
    expect(existsSync(join(rig.layout.workspace, ".pi", "sandbox-tools", "counter_tool", "count"))).toBe(true);
  }, 30_000);

  it("never registers an undeclared sandbox tool", async () => {
    const rig = setup();
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(false);
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "undeclared", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-unmanaged-tool: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();
  });

  it("returns a module error as an error result and keeps the session usable", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "throw-tool.mjs"),
      "export async function execute() { throw new Error('sandbox tool exploded'); }\n", "utf8");
    configureSandboxRules(rig, [{
      id: "allow-thrower",
      match: { tool: "thrower_tool" },
      decision: "allow",
      sandbox: { path: "./throw-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    const tool = rig.definitions.get("thrower_tool")!;
    const event = { type: "tool_call" as const, toolName: "thrower_tool", toolCallId: "throw-1", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
    // The definition throws; the pi tool layer turns that into the call's error result.
    await expect(tool.execute("throw-1", {}, undefined, undefined, rig.ctx)).rejects.toThrow("sandbox tool exploded");

    // The next call still works: one failing tool never invalidates the session.
    const next = { type: "tool_call" as const, toolName: "read", toolCallId: "after-throw", input: { path: "." } };
    expect(await rig.execution.guard(next, rig.ctx, async () => undefined)).toBeUndefined();
  }, 30_000);

  it("retires a removed sandbox tool and revives it when the rule returns", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    const rule = [{
      id: "allow-counter",
      match: { tool: "counter_tool" },
      decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }];
    configureSandboxRules(rig, rule);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    const tool = rig.definitions.get("counter_tool")!;
    const first = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "live-1", input: {} };
    expect(await rig.execution.guard(first, rig.ctx, async () => undefined)).toBeUndefined();
    expect(textOf(await tool.execute("live-1", {}, undefined, undefined, rig.ctx))).toContain("persisted=1");

    // Removing the declaration leaves the pi tool registered (no unregister
    // API); the gate refuses it before the approval chain in every mode.
    configureSandboxRules(rig, []);
    rig.execution.configurationChanged("controlled-session");
    expect(rig.definitions.has("counter_tool")).toBe(true);
    const review = vi.fn(async () => undefined);
    const retired = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "retired-1", input: {} };
    expect(await rig.execution.guard(retired, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-retired: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();

    // Re-declaring the rule on the next configuration change revives the tool
    // without a restart; its state directory survived the retirement.
    configureSandboxRules(rig, rule);
    rig.execution.configurationChanged("controlled-session");
    const revived = { ...first, toolCallId: "revived-1" };
    expect(await rig.execution.guard(revived, rig.ctx, review)).toBeUndefined();
    expect(review).not.toHaveBeenCalled();
    expect(textOf(await tool.execute("revived-1", {}, undefined, undefined, rig.ctx))).toContain("persisted=2");
  }, 40_000);

  it("retires a removed sandbox tool on the full-access host path", async () => {
    const rig = setup("full-access");
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    const rule = [{
      id: "allow-counter",
      match: { tool: "counter_tool" },
      decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }];
    configureSandboxRules(rig, rule);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    const tool = rig.definitions.get("counter_tool")!;
    const live = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "live-full", input: {} };
    expect(await rig.execution.guard(live, rig.ctx, async () => undefined)).toBeUndefined();
    expect(textOf(await tool.execute("live-full", {}, undefined, undefined, rig.ctx))).toContain("persisted=1");

    configureSandboxRules(rig, []);
    rig.execution.configurationChanged("controlled-session");
    const review = vi.fn(async () => undefined);
    const retired = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "retired-full", input: {} };
    // full-access no longer reaches the host execute path for a retired tool:
    // the gate blocks it before the (auto-approving) approval chain.
    expect(await rig.execution.guard(retired, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-retired: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();
    expect(rig.definitions.has("counter_tool")).toBe(true);
  }, 30_000);

  it("retires the old name and registers a renamed sandbox tool", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-counter", match: { tool: "counter_tool" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(true);

    configureSandboxRules(rig, [{
      id: "allow-counter-v2", match: { tool: "counter_tool_v2" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }]);
    rig.execution.configurationChanged("controlled-session");
    const review = vi.fn(async () => undefined);
    const oldName = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "renamed-old", input: {} };
    expect(await rig.execution.guard(oldName, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-retired: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();

    // The rename registered a new definition during the same synchronization.
    expect(rig.definitions.has("counter_tool_v2")).toBe(true);
    const renamed = { type: "tool_call" as const, toolName: "counter_tool_v2", toolCallId: "renamed-new", input: {} };
    expect(await rig.execution.guard(renamed, rig.ctx, review)).toBeUndefined();
    expect(textOf(await rig.definitions.get("counter_tool_v2")!.execute("renamed-new", {}, undefined, undefined, rig.ctx)))
      .toContain("persisted=1");
  }, 30_000);

  it("keeps sandbox-tool-not-declared for a declared tool whose module disappeared", async () => {
    const rig = setup();
    const modulePath = join(rig.layout.workspace, "counter-tool.mjs");
    writeFileSync(modulePath, COUNTER_TOOL, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-counter", match: { tool: "counter_tool" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(true);

    // The rule still declares the tool, only the module is gone: this is a
    // resolution failure, not a retirement, so it keeps the declared-but-
    // unresolvable reason instead of sandbox-tool-retired.
    rmSync(modulePath);
    rig.execution.configurationChanged("controlled-session");
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "module-gone", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-not-declared: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();
  }, 30_000);

  it("keeps one session's live declaration when another session synchronizes", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-counter", match: { tool: "counter_tool" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(true);

    // A second session with its own workspace, config owner and (empty) rule
    // table. The pi tool registry is process-wide, so its synchronization runs
    // against a name the first session still declares.
    const otherWorkspace = join(rig.layout.root, "workspace-two");
    const otherAgent = join(rig.layout.root, "agent-two");
    for (const directory of [otherWorkspace, otherAgent]) mkdirSync(directory, { recursive: true });
    const otherPaths = resolveConfigPaths({
      agentDir: otherAgent, cwd: otherWorkspace,
      extensionRoot: dirname(dirname(fileURLToPath(new URL("../../src/index.ts", import.meta.url)))),
    });
    const otherOwner = createApprovalChainConfigOwner({ paths: otherPaths, cwd: otherWorkspace, projectTrusted: true });
    const otherSession = { cwd: otherWorkspace, isProjectTrusted: () => true,
      sessionManager: SessionManager.inMemory(otherWorkspace, { id: "second-session" }),
    } as unknown as ExtensionToolContext;
    rig.sessionOwners.set("second-session", otherOwner);
    await rig.emit("session_start", otherSession, { type: "session_start", reason: "startup" });

    // The first session's own snapshot still declares the tool, so its call
    // keeps working: retirement must never leak across sessions.
    const review = vi.fn(async () => undefined);
    const live = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "cross-live", input: {} };
    expect(await rig.execution.guard(live, rig.ctx, review)).toBeUndefined();
    expect(review).not.toHaveBeenCalled();
    expect(textOf(await rig.definitions.get("counter_tool")!.execute("cross-live", {}, undefined, undefined, rig.ctx)))
      .toContain("persisted=1");

    // The same registered name stays refused for the session whose rule table
    // does not declare it: fail-closed, and the approval chain is never asked.
    const foreign = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "cross-foreign", input: {} };
    expect(await rig.execution.guard(foreign, otherSession, review)).toEqual({
      block: true,
      reason: "sandbox-tool-retired: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();
    await rig.emit("session_shutdown", otherSession, { type: "session_shutdown", reason: "quit" });
  }, 40_000);

  it("lets a deny rule win over retirement and keeps its audit record", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-counter", match: { tool: "counter_tool" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(true);

    // The declaration is replaced by a same-name deny rule. The deny branch
    // must run first: the call is attributed to that rule and audited instead
    // of disappearing behind the retired-tool refusal.
    configureSandboxRules(rig, [{ id: "deny-counter", match: { tool: "counter_tool" }, decision: "deny" }]);
    rig.execution.configurationChanged("controlled-session");
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "deny-beats-retired", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-denied-tool:deny-counter",
    });
    expect(review).not.toHaveBeenCalled();
    expect(rig.records).toEqual(expect.arrayContaining([
      expect.objectContaining({
        toolCallId: "deny-beats-retired", toolName: "counter_tool", decision: "deny", ruleId: "deny-counter",
      }),
    ]));
  }, 30_000);

  it("keeps a plain allow re-declaration retired (fail-closed)", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "counter-tool.mjs"), COUNTER_TOOL, "utf8");
    const sandboxRule = {
      id: "allow-counter", match: { tool: "counter_tool" }, decision: "allow",
      sandbox: { path: "./counter-tool.mjs" },
    };
    configureSandboxRules(rig, [sandboxRule]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    expect(rig.definitions.has("counter_tool")).toBe(true);

    // A rule that names the tool but no longer declares `sandbox` does not
    // revive the registered definition: the stale definition may only run
    // through the sandbox contract, so the gate keeps refusing it.
    configureSandboxRules(rig, [{ id: "allow-counter-plain", match: { tool: "counter_tool" }, decision: "allow" }]);
    rig.execution.configurationChanged("controlled-session");
    const review = vi.fn(async () => undefined);
    const event = { type: "tool_call" as const, toolName: "counter_tool", toolCallId: "plain-allow", input: {} };
    expect(await rig.execution.guard(event, rig.ctx, review)).toEqual({
      block: true,
      reason: "sandbox-tool-retired: counter_tool",
    });
    expect(review).not.toHaveBeenCalled();

    // Declaring the sandbox tool again revives it.
    configureSandboxRules(rig, [sandboxRule]);
    rig.execution.configurationChanged("controlled-session");
    expect(await rig.execution.guard({ ...event, toolCallId: "plain-allow-revived" }, rig.ctx, review)).toBeUndefined();
  }, 30_000);

  it("finishes a call whose module leaves an interval handle open and exits its worker", async () => {
    const rig = setup();
    // A module that leaves an event-loop handle open after returning. The
    // one-shot worker must still write its result and exit: the helper only
    // relays the result when the worker process closes, so a linger would turn
    // a completed call into a 60 s execution-timeout.
    writeFileSync(join(rig.layout.workspace, "interval-tool.mjs"), `
      import { writeFile } from "node:fs/promises";
      import { join } from "node:path";
      setInterval(() => {}, 1000);
      export async function execute(args, ctx) {
        await writeFile(join(ctx.stateDirectory, "pid"), String(process.pid));
        return { content: [{ type: "text", text: "interval=ok" }] };
      }
    `, "utf8");
    configureSandboxRules(rig, [{
      id: "allow-interval",
      match: { tool: "interval_tool" },
      decision: "allow",
      sandbox: { path: "./interval-tool.mjs" },
    }]);
    await rig.emit("session_start", rig.ctx, { type: "session_start", reason: "startup" });
    const tool = rig.definitions.get("interval_tool")!;
    expect(tool).toBeDefined();
    const review = vi.fn(async (_input?: { readonly ask?: boolean }) => undefined);
    const first = { type: "tool_call" as const, toolName: "interval_tool", toolCallId: "interval-1", input: {} };
    expect(await rig.execution.guard(first, rig.ctx, review)).toBeUndefined();

    // (a) The call finishes promptly even though the module left a timer open.
    // The bound only has to be far below the 60 s deadline; helper and worker
    // spawn time under parallel test load is orders of magnitude smaller.
    const startedAt = Date.now();
    const firstResult = await tool!.execute("interval-1", {}, undefined, undefined, rig.ctx);
    expect(textOf(firstResult)).toBe("interval=ok");
    expect(Date.now() - startedAt).toBeLessThan(5_000);

    // (c) The worker really exited: it recorded its pid, and that pid is gone.
    const pidFile = join(rig.layout.workspace, ".pi", "sandbox-tools", "interval_tool", "pid");
    let workerPid = 0;
    await waitFor(() => {
      if (!existsSync(pidFile)) return false;
      workerPid = Number(readFileSync(pidFile, "utf8"));
      return Number.isInteger(workerPid) && workerPid > 0;
    });
    expect(await waitForProcessGone(workerPid)).toBe(true);

    // (b) A second call still works: the on-disk state outlives the worker.
    const second = { ...first, toolCallId: "interval-2" };
    expect(await rig.execution.guard(second, rig.ctx, review)).toBeUndefined();
    expect(textOf(await tool!.execute("interval-2", {}, undefined, undefined, rig.ctx))).toBe("interval=ok");
  }, 90_000);
});
