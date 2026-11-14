import { afterEach, describe, expect, it } from "vitest";
import { McpAuthRequiredError, McpClient, StdioTransport, type AuthProvider } from "@earendil-works/pi-mcp";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { createMcpExtension, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AnyToolDefinition } from "#sandbox/pi";
import { waitFor, waitForProcessGone } from "./fixtures/harness";
import { ManagedMcpTransports } from "#sandbox/mcp";
import type { McpServerEntry } from "@earendil-works/pi-coding-agent";

const managers: ManagedMcpTransports[] = [];
const servers: Server[] = [];
const clients: McpClient[] = [];
afterEach(async () => {
  await Promise.allSettled(clients.splice(0).map(client => client.close()));
  await Promise.all(managers.splice(0).map(manager => manager.close()));
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); })));
  delete process.env.UNAPPROVED_SECRET;
});
function revision(): string {
  return "r1";
}
function entry(): McpServerEntry {
  return { name: "fixture", source: "test", scope: "extension", config: {
    command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))],
  } };
}
function manager(readRevision: () => string, runConfigCommand?: (command: string, signal: AbortSignal) => Promise<string>) {
  const managed = new ManagedMcpTransports({ revision: readRevision, ...(runConfigCommand ? { runConfigCommand } : {}) });
  managers.push(managed);
  return { managed };
}
describe("managed host MCP transports", () => {
  it("defers config commands to start and resolves multiple values in order", async () => {
    const current = revision();
    const commands: string[] = [];
    let releaseFirst!: (value: string) => void;
    const firstValue = new Promise<string>(resolve => { releaseFirst = resolve; });
    const { managed } = manager(() => current, async command => {
      commands.push(command);
      return command === "first" ? firstValue : "second-value";
    });
    const configured = entry();
    if ("command" in configured.config) configured.config.env = { FIRST: "!first", SECOND: "!second" };
    const transport = managed.createTransport(configured, process.cwd(), undefined);

    expect(commands).toEqual([]);
    const starting = transport.start();
    await waitFor(() => commands.length === 1);
    let timerFired = false;
    await new Promise<void>(resolve => setTimeout(() => { timerFired = true; resolve(); }, 0));
    expect(timerFired).toBe(true);
    expect(commands).toEqual(["first"]);

    releaseFirst(" first-value ");
    await waitFor(() => commands.length === 2);
    expect(commands).toEqual(["first", "second"]);
    await starting;
    await transport.close();
  });

  it("cancels a pending config command on revision change before later values or transport start", async () => {
    let current = revision();
    const commands: string[] = [];
    let aborted = false;
    const { managed } = manager(() => current, (command, signal) => {
      commands.push(command);
      return new Promise<string>((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("private config output"));
        }, { once: true });
      });
    });
    const configured = entry();
    if ("command" in configured.config) configured.config.env = { FIRST: "!first", SECOND: "!second" };
    const transport = managed.createTransport(configured, process.cwd(), undefined);
    const starting = transport.start();
    await waitFor(() => commands.length === 1);

    current = "r2";
    await managed.synchronize();
    await expect(starting).rejects.toThrow("MCP config command failed to produce a value");
    expect(aborted).toBe(true);
    expect(commands).toEqual(["first"]);
  });

  it("stops a real config command when stdout exceeds the output limit", async () => {
    const { managed } = manager(revision);
    const configured: McpServerEntry = { name: "fixture", source: "test", scope: "extension", config: {
      url: "https://example.com/mcp",
      headers: { Authorization: `!node -e "process.stdout.write('x'.repeat(1048577))"` },
    } };
    const transport = managed.createTransport(configured, process.cwd(), undefined);
    try {
      await expect(transport.start()).rejects.toThrow("MCP config command failed to produce a value");
    } finally {
      await transport.close();
    }
  });

  it("reuses the host stdio process and passes its inherited environment", async () => {
    process.env.UNAPPROVED_SECRET = "canary";
    const { managed } = manager(revision);
    await managed.synchronize();
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport(entry(), process.cwd(), undefined));
    const first = await client.callTool("ping", {});
    const second = await client.callTool("ping", {});
    const result = (value: typeof first) => JSON.parse((value.content[0] as { text: string }).text);
    expect(result(first)).toMatchObject({ calls: 1, secretPresent: true });
    expect(result(second)).toMatchObject({ pid: result(first).pid, calls: 2, secretPresent: true });
  });

  it("terminates host stdio descendants when a connection revision changes", async () => {
    let current = revision();
    const { managed } = manager(() => current);
    const configured = entry();
    if ("command" in configured.config) configured.config.args?.push("--spawn-descendant");
    const client = new McpClient({ name: "process-tree-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport(configured, process.cwd(), undefined));
    const result = await client.callTool("ping", {});
    const { pid, descendantPid } = JSON.parse((result.content[0] as { text: string }).text) as { pid: number; descendantPid: number };
    current = "r2";
    await managed.synchronize();
    expect(await waitForProcessGone(pid)).toBe(true);
    expect(await waitForProcessGone(descendantPid)).toBe(true);
  });

  it("revokes old sends synchronously and closes the old tree before a replacement starts", async () => {
    let current = revision();
    const { managed } = manager(() => current);
    await managed.synchronize();
    const old = managed.createTransport(entry(), process.cwd(), undefined);
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client); await client.connect(old);
    const first = await client.callTool("ping", {});
    const oldPid = JSON.parse((first.content[0] as { text: string }).text).pid;
    current = "r2";
    const closing = managed.synchronize();
    await expect(old.send({ jsonrpc: "2.0", id: 99, method: "tools/call", params: { name: "ping" } })).rejects.toThrow("revoked");
    await closing;
    expect(() => process.kill(oldPid, 0)).toThrow();
    const replacement = new McpClient({ name: "permission-test", version: "1" }); clients.push(replacement);
    await replacement.connect(managed.createTransport(entry(), process.cwd(), undefined));
    const second = await replacement.callTool("ping", {});
    expect(JSON.parse((second.content[0] as { text: string }).text)).toMatchObject({ calls: 1 });
  });

  it("exposes managed stdio stderr to Pi's connection diagnostics", async () => {
    const { managed } = manager(revision);
    const transport = managed.createTransport({ name: "fixture", source: "test", config: {
      command: process.execPath, args: ["-e", "console.error('managed-stderr-marker')"],
    } }, process.cwd(), undefined);
    const client = new McpClient({ name: "stderr-test", version: "1" }); clients.push(client);
    await expect(client.connect(transport)).rejects.toThrow();
    if (!(transport instanceof StdioTransport)) throw new Error("managed transport lost its stdio identity");
    expect(transport.stderr).toContain("managed-stderr-marker");
  });

  it("keeps HTTP bearer authentication and does not replay an uncertain tool request", async () => {
    let requests = 0; let authorization: string | undefined; let deletedSessions = 0;
    const server = createServer(async (req, res) => {
      if (req.method === "GET") { res.writeHead(405).end(); return; }
      if (req.method === "DELETE") { deletedSessions++; res.writeHead(200).end(); return; }
      let body = ""; for await (const chunk of req) body += chunk;
      const message = JSON.parse(body);
      if (message.id === undefined) { res.writeHead(202).end(); return; }
      authorization = req.headers.authorization;
      if (message.method === "tools/call" && message.params.name === "reauth") {
        res.writeHead(401, { "WWW-Authenticate": "Bearer" }).end("sign in required"); return;
      }
      if (message.method === "tools/call") { requests++; res.writeHead(404).end("unknown outcome"); return; }
      res.writeHead(200, { "Content-Type": "application/json", "Mcp-Session-Id": "fixture-http-session" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {
        ...(message.method === "tools/list" ? { tools: [{ name: "ping", description: "Ping", inputSchema: { type: "object" } }] }
          : { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "http", version: "1" } }),
      } }));
    });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const { managed } = manager(revision); await managed.synchronize();
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp` } }, process.cwd(), { token: async () => "fixture-token" }));
    await expect(client.callTool("reauth", {})).rejects.toBeInstanceOf(McpAuthRequiredError);
    await expect(client.callTool("ping", {})).rejects.toThrow("outcome unknown");
    expect(requests).toBe(1); expect(authorization).toBe("Bearer fixture-token");
    const definitions = new Map<string, AnyToolDefinition>();
    const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
    const ctx = { cwd: process.cwd(), hasUI: false, ui: { notify: () => undefined }, modelRegistry: {} } as unknown as ExtensionContext;
    const api = {
      events: new EventEmitter(),
      on: (event: string, handler: (...args: unknown[]) => unknown) => { handlers.set(event, [...(handlers.get(event) ?? []), handler]); return () => undefined; },
      registerTool: (definition: AnyToolDefinition) => definitions.set(definition.name, definition),
      registerToolRenderer: () => undefined, registerCommand: () => undefined,
      getMcpServers: () => [], getActiveTools: () => [], setActiveTools: () => undefined,
      getAllTools: () => [...definitions.values()],
    } as unknown as ExtensionAPI;
    createMcpExtension({ createTransport: managed.createTransport, loadConfig: () => ({ errors: [], servers: [{ name: "fixture", source: "test", config: {
      url: `http://127.0.0.1:${port}/mcp`, exposure: "direct", headers: { Authorization: "!echo Bearer fixture-token" },
    } }] }) })(api);
    try {
      for (const handler of handlers.get("session_start") ?? []) await handler({ type: "session_start", reason: "startup" }, ctx);
      await waitFor(() => definitions.has("mcp__fixture__ping"));
      await expect(definitions.get("mcp__fixture__ping")!.execute("native-call", {}, undefined, undefined, ctx as never)).rejects.toThrow("outcome unknown");
      expect(requests).toBe(2);
      expect(authorization).toBe("Bearer fixture-token");
    } finally {
      for (const handler of handlers.get("session_shutdown") ?? []) await handler({ type: "session_shutdown", reason: "quit" }, ctx);
    }
    expect(deletedSessions).toBe(1);
    await client.close();
    expect(deletedSessions).toBe(2);
  });

  it("allows the HTTP auth provider to make recovery requests", async () => {
    let oauthRequests = 0;
    const server = createServer(async (request, response) => {
      if (request.url === "/oauth") { oauthRequests++; response.end("oauth"); return; }
      if (request.method === "GET") { response.writeHead(405).end(); return; }
      if (request.headers.authorization !== "Bearer refreshed") { response.writeHead(401, { "WWW-Authenticate": "Bearer" }).end(); return; }
      let body = ""; for await (const chunk of request) body += chunk;
      const message = JSON.parse(body);
      if (message.id === undefined) { response.writeHead(202).end(); return; }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {
        protocolVersion: message.params.protocolVersion, capabilities: {}, serverInfo: { name: "http", version: "1" },
      } }));
    });
    servers.push(server);
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    const { managed } = manager(revision); await managed.synchronize();
    let token = "expired";
    const authProvider: AuthProvider = {
      token: async () => token,
      onUnauthorized: async context => {
        expect(await (await context.fetch(`${base}/oauth`)).text()).toBe("oauth");
        token = "refreshed";
      },
    };
    const client = new McpClient({ name: "oauth-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport({ name: "fixture", source: "test", config: { url: `${base}/mcp` } }, process.cwd(), authProvider));
    expect(oauthRequests).toBeGreaterThan(0);
  });

  it("allows an opaque model provider to supply its token", async () => {
    let authorization: string | undefined;
    const server = createServer((request, response) => { authorization = request.headers.authorization; response.writeHead(202).end(); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const { managed } = manager(revision); await managed.synchronize();
    let called = false;
    const transport = managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp`, auth: { provider: "custom" } } }, process.cwd(), {
      token: async () => { called = true; return "token"; },
    });
    await transport.start();
    await transport.send({ jsonrpc: "2.0", method: "test" });
    expect(called).toBe(true);
    expect(authorization).toBe("Bearer token");
    await transport.close();
  });

});
