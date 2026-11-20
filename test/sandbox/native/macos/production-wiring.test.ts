import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { ExecutionControllerOptions } from "#sandbox/lifecycle";
import type { PiExecutionPlanOptions } from "#sandbox/pi";
import { EXECUTION_INSTALL_ROOT } from "#sandbox/platform";
import type { ApprovalChainConfigSnapshot } from "#config/owner";

interface WiringCapture {
  controllerOptions: ExecutionControllerOptions | undefined;
  adapterPlan: PiExecutionPlanOptions | undefined;
  adaptersDisposed: number;
}

const harness = vi.hoisted((): { capture: WiringCapture } => ({
  capture: { controllerOptions: undefined, adapterPlan: undefined, adaptersDisposed: 0 },
}));

vi.mock("#sandbox/lifecycle", () => ({
  ExecutionController: class {
    constructor(options: unknown) { (harness.capture as WiringCapture).controllerOptions = options as ExecutionControllerOptions; }
    async execute(): Promise<never> { throw new Error("wiring test must not execute"); }
    async dispose(): Promise<void> {}
  },
}));

vi.mock("#sandbox/pi", async importOriginal => {
  const actual = await importOriginal<typeof import("#sandbox/pi")>();
  return {
    ...actual,
    createPiExecutionAdapter: (input: Parameters<typeof actual.createPiExecutionAdapter>[0]) => {
      (harness.capture as WiringCapture).adapterPlan = input.plan;
      return {
        definitions: [],
        dispose: async () => { (harness.capture as WiringCapture).adaptersDisposed += 1; },
      };
    },
  };
});

import { createControlledExecution } from "#sandbox/production";

const cleanup: (() => void)[] = [];
afterEach(() => {
  for (const dispose of cleanup.splice(0)) dispose();
  harness.capture.controllerOptions = undefined;
  harness.capture.adapterPlan = undefined;
  harness.capture.adaptersDisposed = 0;
});

describe.skipIf(process.platform !== "darwin")("darwin production controller wiring", () => {
  it("passes the host-native Seatbelt backend and the system-runtime id to the controller", async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-darwin-wiring-"));
    cleanup.push(() => rmSync(root, { recursive: true, force: true }));
    const agentDir = join(root, "agent");
    const workspace = join(root, "workspace");
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(workspace, { recursive: true });

    const snapshot = {
      config: {
        mode: "default",
        experimental: { sandboxEnabled: true },
        execution: {},
        shellTools: [],
      },
      source: "global",
      projectConfigInvalid: false,
      toolRules: [],
      paths: { projectConfigDir: workspace, globalConfigDir: agentDir },
      cwd: workspace,
    } as unknown as ApprovalChainConfigSnapshot;
    const runtime = {
      directory: join(root, "plugin", "runtimes", "darwin-arm64"),
      storageRoot: join(root, "plugin"),
      source: "manual" as const,
      manifest: {
        schemaVersion: 1 as const,
        version: "1.0.1",
        stable: true as const,
        platform: "darwin",
        arch: process.arch === "arm64" ? "arm64" : "x64",
        protocolVersion: 3,
        minPluginVersion: "0.0.0",
        maxPluginVersionExclusive: "999999.999.999",
        backendId: "macos-seatbelt",
        files: [],
      },
      files: {},
    };
    const ctx = {
      cwd: workspace,
      isProjectTrusted: () => true,
      sessionManager: {
        getSessionId: () => "darwin-wiring-session",
        getSessionFile: () => undefined,
      },
    } as unknown as ExtensionContext;
    const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
    const api = {
      events: { on: () => undefined },
      registerTool: () => undefined,
      registerToolRenderer: () => undefined,
      registerCommand: () => undefined,
      getAllTools: () => [],
      getMcpServers: () => [],
      getActiveTools: () => [],
      setActiveTools: () => undefined,
      appendEntry: () => undefined,
      on: (event: string, handler: (...args: unknown[]) => unknown) => {
        handlers.set(event, [...(handlers.get(event) ?? []), handler]);
        return () => undefined;
      },
    } as unknown as ExtensionAPI;

    const execution = createControlledExecution({
      agentDir,
      runtime: () => ({ status: "ready", runtime }),
      snapshot: () => snapshot,
      registrationPath: "/pi-sandbox/src/index.ts",
      mcp: { loadConfig: () => ({ servers: [], errors: [] }) },
    });
    execution.install(api);
    for (const handler of handlers.get("session_start") ?? []) await handler({ type: "session_start" }, ctx);

    const options = harness.capture.controllerOptions;
    if (options === undefined) throw new Error("the production controller was not constructed");
    expect(options.directBackend).toMatchObject({ id: "macos-seatbelt", version: "1.0.0" });
    expect(options.runtimeUseLease).toBeUndefined();

    const plan = (harness.capture as WiringCapture).adapterPlan;
    expect(plan?.backendId).toBe("macos-seatbelt");
    expect(plan?.protectedPaths).toContain(EXECUTION_INSTALL_ROOT);
  });
});
