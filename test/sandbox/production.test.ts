import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { createConnection, createServer as createTcpServer } from "node:net";
import { createSocket } from "node:dgram";
import { networkInterfaces } from "node:os";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionManager, type ExtensionAPI, type ExtensionContext, type ExtensionToolContext, type RegisteredMcpServer } from "@earendil-works/pi-coding-agent";
import { resolveConfigPaths } from "#config/config-paths";
import { createApprovalChainConfigOwner } from "#config/owner";
import { createControlledExecution } from "#sandbox/production";
import { runWithApprovedCodemode } from "#sandbox/codemode/approval-scope";
import type { AnyToolDefinition } from "#sandbox/pi";
import { createTestLayout, makeController, removeTestLayout, waitFor } from "./fixtures/harness";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";

const cleanup: (() => Promise<void>)[] = [];
const privateAddress = Object.values(networkInterfaces()).flat().find(address => address?.family === "IPv4" && !address.internal)?.address;
afterEach(async () => { for (const close of cleanup.splice(0)) await close(); });

function setup(
  mode: "default" | "read-only" | "full-access" = "default",
  native = false,
  scenario = "ok",
  mcpSandbox = true,
) {
  const layout = createTestLayout("controlled-production");
  const source = fileURLToPath(new URL("../../src/index.ts", import.meta.url));
  const definitions = new Map<string, AnyToolDefinition>();
  const sources = new Map<string, string>();
  const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
  const records: unknown[] = [];
  const controllers: ReturnType<typeof makeController>[] = [];
  const registeredServers: RegisteredMcpServer[] = [];
  const launches: string[] = [];
  const launchEnvironments: Readonly<Record<string, string>>[] = [];
  const ctx = { cwd: layout.workspace, isProjectTrusted: () => true,
    sessionManager: SessionManager.inMemory(layout.workspace, { id: "controlled-session" }),
  } as unknown as ExtensionToolContext;
  const paths = resolveConfigPaths({ agentDir: layout.agent, cwd: layout.workspace, extensionRoot: dirname(dirname(source)) });
  const owner = createApprovalChainConfigOwner({ paths, cwd: layout.workspace, projectTrusted: true });
  if (mode !== "default" || mcpSandbox) {
    mkdirSync(join(layout.agent, "extensions", "pi-sandbox"), { recursive: true });
    writeFileSync(paths.globalConfigFile, JSON.stringify({ mode, experimental: { mcpSandbox } }));
  }
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
    snapshot: () => owner.snapshot({ sessionId: ctx.sessionManager.getSessionId() }),
    ...(native ? {} : { controller: (_ctx: ExtensionContext, onRecord: (record: import("#sandbox/types").ExecutionRecord) => void) => {
      const controller = makeController({ layout, onRecord, scenario }); controllers.push(controller); return controller;
    } }),
    mcp: { loadConfig: () => ({ servers: [], errors: [] }), prepareStdio: input => {
      launches.push(input.command);
      launchEnvironments.push(input.environment);
      return { executable: input.command, args: input.args, cwd: input.cwd, environment: input.environment };
    } },
  });
  execution.install(api);
  cleanup.push(async () => {
    for (const handler of handlers.get("session_shutdown") ?? []) await handler({ type: "session_shutdown", reason: "quit" }, ctx);
    removeTestLayout(layout);
  });
  const emit = async (name: string, eventContext: ExtensionToolContext = ctx, event: unknown = { type: name }) => {
    for (const handler of handlers.get(name) ?? []) await handler(event, eventContext);
  };
  return { layout, paths, ctx, owner, execution, definitions, sources, records, controllers, registeredServers, emit, launches, launchEnvironments };
}

describe("production controlled execution boundary", () => {
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

  it("executes an escalated managed call once with host permissions and records its mode", async () => {
    const rig = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-write",
      input: { path: "host-escalated.txt", content: "written once" },
    };
    expect(await rig.execution.guard(event, rig.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "user chose one-time escalation",
    }))).toBeUndefined();

    const tool = rig.definitions.get("write")!;
    const result = await tool.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx);
    expect(result.isError).not.toBe(true);
    expect(readFileSync(join(rig.layout.workspace, "host-escalated.txt"), "utf8")).toBe("written once");
    await expect(tool.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx))
      .rejects.toThrow("host-execution:approval-unavailable");
    expect(rig.records).toEqual([expect.objectContaining({
      toolCallId: event.toolCallId,
      toolName: "write",
      executionMode: "host",
      started: true,
      impact: "known",
      state: "completed",
    })]);
  });

  it("binds an escalation to session and exact arguments", async () => {
    const rig = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-bound",
      input: { path: "bound.txt", content: "approved" },
    };
    expect(await rig.execution.guard(event, rig.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "one-time test",
    }))).toBeUndefined();

    const otherSession = {
      ...rig.ctx,
      sessionManager: SessionManager.inMemory(rig.layout.workspace, { id: "different-session" }),
    } as ExtensionToolContext;
    const tool = rig.definitions.get("write")!;
    await expect(tool.execute(event.toolCallId, event.input, undefined, undefined, otherSession))
      .rejects.toThrow("host-execution:approval-binding-invalidated");
    await rig.emit("session_shutdown", otherSession);
    await expect(tool.execute(event.toolCallId, {
      path: "changed.txt",
      content: "not approved",
    }, undefined, undefined, rig.ctx)).rejects.toThrow("host-execution:action-changed-before-execution");
    expect(existsSync(join(rig.layout.workspace, "bound.txt"))).toBe(false);
    expect(existsSync(join(rig.layout.workspace, "changed.txt"))).toBe(false);
    expect(rig.records).toEqual([expect.objectContaining({
      executionMode: "host",
      started: false,
      impact: "none",
      code: "action-changed-before-execution",
    })]);
  });

  it("rejects a grant after a policy change without falling back to sandbox execution", async () => {
    const rig = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-invalidated",
      input: { path: "invalidated.txt", content: "must not write" },
    };
    expect(await rig.execution.guard(event, rig.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "one-time test",
    }))).toBeUndefined();

    rig.execution.configurationChanged("controlled-session");

    await expect(rig.definitions.get("write")!.execute(
      event.toolCallId,
      event.input,
      undefined,
      undefined,
      rig.ctx,
    )).rejects.toThrow("host-execution:approval-unavailable");
    expect(existsSync(join(rig.layout.workspace, "invalidated.txt"))).toBe(false);
    expect(rig.records).toEqual([expect.objectContaining({
      executionMode: "host",
      started: false,
      impact: "none",
      code: "approval-invalidated",
    })]);
  });

  it("records an unknown host result and never retries it", async () => {
    const rig = setup();
    writeFileSync(join(rig.layout.workspace, "occupied"), "not a directory");
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-unknown",
      input: { path: "occupied/child.txt", content: "must not write" },
    };
    expect(await rig.execution.guard(event, rig.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "one-time test",
    }))).toBeUndefined();

    const tool = rig.definitions.get("write")!;
    await expect(tool.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx)).rejects.toThrow();
    expect(rig.records).toEqual([expect.objectContaining({
      executionMode: "host",
      started: "unknown",
      impact: "unknown",
      state: "failed",
    })]);
    await expect(tool.execute(event.toolCallId, event.input, undefined, undefined, rig.ctx))
      .rejects.toThrow("host-execution:approval-unavailable");
    expect(rig.records).toHaveLength(1);
  });

  it("rejects read-only, cancelled, and timed-out escalations before execution", async () => {
    const readOnly = setup("read-only");
    const readOnlyEvent = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-readonly",
      input: { path: "readonly.txt", content: "must not write" },
    };
    expect(await readOnly.execution.guard(readOnlyEvent, readOnly.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "one-time test",
    }))).toMatchObject({ block: true, reason: "host-execution:forbidden-in-read-only" });
    expect(existsSync(join(readOnly.layout.workspace, "readonly.txt"))).toBe(false);

    const cancelled = setup();
    const event = {
      type: "tool_call" as const,
      toolName: "write",
      toolCallId: "host-escalate-cancelled",
      input: { path: "cancelled.txt", content: "must not write" },
    };
    expect(await cancelled.execution.guard(event, cancelled.ctx, async () => ({
      kind: "host-execution" as const,
      reason: "one-time test",
    }))).toBeUndefined();
    const abort = new AbortController();
    abort.abort();
    await expect(cancelled.definitions.get("write")!.execute(
      event.toolCallId,
      event.input,
      abort.signal,
      undefined,
      cancelled.ctx,
    )).rejects.toThrow("host-execution:cancelled-before-execution");
    expect(cancelled.records).toEqual([expect.objectContaining({
      executionMode: "host",
      started: false,
      impact: "none",
      code: "cancelled-before-execution",
    })]);

    const timedOut = setup();
    const timeoutEvent = { ...event, toolCallId: "host-escalate-timeout" };
    expect(await timedOut.execution.guard(timeoutEvent, timedOut.ctx, async () => ({
      block: true as const,
      reason: "approval-chain:deadline",
    }))).toMatchObject({ block: true, reason: "approval-chain:deadline" });
    expect(timedOut.records).toEqual([]);
    expect(existsSync(join(timedOut.layout.workspace, "cancelled.txt"))).toBe(false);
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
        writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
      writeFileSync(config, JSON.stringify({ execution: { network: { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] } } }));
      const command = `$curl=Join-Path $env:SystemRoot 'System32\\curl.exe'; & $curl --silent --proxy $env:HTTP_PROXY --noproxy= 'http://127.0.0.1:${port}/'; Start-Sleep -Seconds 30`;
      const event = { type: "tool_call" as const, toolName: "powershell", toolCallId: "network-reload", input: { command, ...(action === "timeout" ? { timeout: 8 } : {}) } };
      const abort = new AbortController();
      try {
        expect(await rig.execution.guard(event, rig.ctx, async () => undefined)).toBeUndefined();
        const running = rig.definitions.get("powershell")!.execute(event.toolCallId, event.input, abort.signal, undefined, rig.ctx).catch(error => error);
        await waitFor(() => opened, 20_000);
        if (action === "configuration tightening") {
          writeFileSync(config, JSON.stringify({ execution: { network: { mode: "none" } } }));
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: { mode: kind } } }));
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: { mode: kind } } }));
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
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
      writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: {
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
  it("runs MCP through the shared production sandbox and reconnects after reload", async () => {
    const rig = setup();
    await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: "establish", input: { path: "a.txt" } }, rig.ctx, async () => undefined);
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))], exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    expect(rig.launches).toEqual([process.execPath]);
    const id = "unconfigured-mcp";
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: id, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
    expect((await rig.definitions.get("mcp__fixture__ping")!.execute(id, {}, undefined, undefined, rig.ctx)).isError).not.toBe(true);
    const firstEnvironment = rig.launchEnvironments[0]!;
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ mode: "auto-review", experimental: { mcpSandbox: true } }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    rig.execution.configurationChanged("controlled-session");
    const reloadedId = "reloaded-mcp";
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: reloadedId, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
    expect((await rig.definitions.get("mcp__fixture__ping")!.execute(reloadedId, {}, undefined, undefined, rig.ctx)).isError).not.toBe(true);
    expect(rig.launches).toHaveLength(2);
    expect(rig.launchEnvironments[1]?.UV_CACHE_DIR).toBe(firstEnvironment.UV_CACHE_DIR);
    expect(rig.launchEnvironments[1]?.UV_TOOL_DIR).toBe(firstEnvironment.UV_TOOL_DIR);
    expect(firstEnvironment.UV_TOOL_DIR).toContain("mcp-cache");
  }, 20_000);
  it("runs MCP on the host by default without invoking the sandbox launcher", async () => {
    const rig = setup("default", false, "ok", false);
    await rig.execution.guard({ type: "tool_call", toolName: "read", toolCallId: "establish-host-mcp", input: { path: "a.txt" } }, rig.ctx, async () => undefined);
    rig.registeredServers.push({ name: "fixture", extensionPath: join(rig.layout.workspace, "extension.ts"), config: {
      command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))], exposure: "direct",
    } });
    await rig.emit("session_start");
    await waitFor(() => rig.definitions.has("mcp__fixture__ping"));
    expect(rig.launches).toEqual([]);
    const id = "host-mcp-default";
    expect(await rig.execution.guard({ type: "tool_call", toolName: "mcp__fixture__ping", toolCallId: id, input: {} }, rig.ctx, async () => undefined)).toBeUndefined();
    expect((await rig.definitions.get("mcp__fixture__ping")!.execute(id, {}, undefined, undefined, rig.ctx)).isError).not.toBe(true);
    expect(rig.records).toEqual(expect.arrayContaining([expect.objectContaining({ toolName: "mcp__fixture__ping", executionMode: "host", started: true })]));
  }, 20_000);

  it("manages extension MCP registration, tool withdrawal and one reusable native connection", async () => {
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
    expect(rig.launches).toHaveLength(1);
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

  it("invalidates a pending approval when only the project MCP network changes", async () => {
    const rig = setup();
    mkdirSync(dirname(rig.paths.globalConfigFile), { recursive: true });
    writeFileSync(rig.paths.globalConfigFile, JSON.stringify({ execution: { network: { mode: "all" } } }));
    rig.owner.reload({ sessionId: rig.ctx.sessionManager.getSessionId() });
    const path = rig.paths.projectConfigFile;
    const writeNetwork = (port: number) => {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, JSON.stringify({ execution: { network: { mode: "allowlist", allow: [{ host: "example.com", port }] } } }));
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
