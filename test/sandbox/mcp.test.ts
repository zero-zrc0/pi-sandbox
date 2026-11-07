import { afterEach, describe, expect, it } from "vitest";
import { McpAuthRequiredError, McpClient, StdioTransport, type AuthProvider } from "@earendil-works/pi-mcp";
import { createServer, type Server } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { createMcpExtension, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AnyToolDefinition } from "#sandbox/pi";
import { waitFor } from "./fixtures/harness";
import { ManagedMcpTransports, type McpExecutionPolicy } from "#sandbox/mcp";
import { prepareStdioLaunch } from "#sandbox/platform";
import { EgressService } from "#sandbox/egress/index";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import type { McpServerEntry } from "@earendil-works/pi-coding-agent";

const managers: ManagedMcpTransports[] = [];
const egressServices: EgressService[] = [];
const servers: Server[] = [];
const clients: McpClient[] = [];
const temporaryRoots: string[] = [];
let nativeExecutableCreatedForTest = false;
let nativeBridgeCreatedForTest = false;
afterEach(async () => {
  await Promise.allSettled(clients.splice(0).map(client => client.close()));
  await Promise.all(managers.splice(0).map(manager => manager.close()));
  await Promise.all(egressServices.splice(0).map(service => service.dispose()));
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); })));
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
  if (nativeExecutableCreatedForTest) {
    rmSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url)), { force: true });
    nativeExecutableCreatedForTest = false;
  }
  if (nativeBridgeCreatedForTest) {
    rmSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-egress-bridge", import.meta.url)), { force: true });
    nativeBridgeCreatedForTest = false;
  }
  delete process.env.UNAPPROVED_SECRET;
});
function policy(): McpExecutionPolicy {
  return { revision: "r1", mode: "default", permissions: {
    filesystem: { read: [], write: [] }, network: { mode: "none" }, process: { spawn: "allow" },
  } };
}
function entry(): McpServerEntry {
  return { name: "fixture", source: "test", scope: "extension", config: {
    command: process.execPath, args: [fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url))],
  } };
}
function spawnPolicy(spawn: "allow" | "deny", revision: string, workspace: string): McpExecutionPolicy {
  const base = policy();
  return { ...base, revision, permissions: {
    ...base.permissions,
    filesystem: { read: [], write: [{ path: workspace, granularity: "directory" }] },
    process: { spawn },
  } };
}
function manager(readPolicy: () => McpExecutionPolicy, egress?: EgressService,
  runConfigCommand?: (command: string, signal: AbortSignal) => Promise<string>) {
  const preparations: string[] = [];
  const managed = new ManagedMcpTransports({ policy: readPolicy, ...(egress ? { egress } : {}),
    ...(runConfigCommand ? { runConfigCommand } : {}),
    // A real subprocess verifies protocol/lifecycle only. This fixture grants no OS-isolation claim.
    prepareStdio: input => { preparations.push(input.command); return { executable: input.command, args: input.args, cwd: input.cwd, environment: input.environment }; },
  });
  managers.push(managed);
  return { managed, preparations };
}
describe("controlled native MCP seam", () => {
  it("defers config commands to start and resolves multiple values in order", async () => {
    const current = policy();
    const commands: string[] = [];
    let releaseFirst!: (value: string) => void;
    const firstValue = new Promise<string>(resolve => { releaseFirst = resolve; });
    const { managed } = manager(() => current, undefined, async command => {
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
    let current = policy();
    const commands: string[] = [];
    let aborted = false;
    const { managed } = manager(() => current, undefined, (command, signal) => {
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

    current = { ...current, revision: "r2" };
    await managed.synchronize();
    await expect(starting).rejects.toThrow("MCP config command failed to produce a value");
    expect(aborted).toBe(true);
    expect(commands).toEqual(["first"]);
  });

  it("stops a real config command when stdout exceeds the output limit", async () => {
    const current = policy();
    current.permissions.network = { mode: "all" };
    const { managed } = manager(() => current);
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

  it.skipIf(process.platform !== "linux")("enforces destination egress through the production Linux stdio MCP transport", async () => {
    const native = fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url));
    const bridge = fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-egress-bridge", import.meta.url));
    if (!existsSync(native) && !existsSync(bridge)) {
      execFileSync("bash", [fileURLToPath(new URL("../../src/sandbox/backend/linux/build.sh", import.meta.url)), native]);
      nativeExecutableCreatedForTest = true;
      nativeBridgeCreatedForTest = true;
    }
    const allowed = createServer((_request, response) => response.end("linux-mcp-allowed"));
    const denied = createServer((_request, response) => response.end("linux-mcp-denied"));
    servers.push(allowed, denied);
    await Promise.all([new Promise<void>(resolve => allowed.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => denied.listen(0, "127.0.0.1", resolve))]);
    const allowedPort = (allowed.address() as { port: number }).port;
    const deniedPort = (denied.address() as { port: number }).port;
    const root = mkdtempSync(join(tmpdir(), "linux-mcp-egress-")); temporaryRoots.push(root);
    const workspace = join(root, "workspace"); mkdirSync(workspace);
    const fixture = join(workspace, "server.mjs");
    const original = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
    const prelude = `import { execFileSync } from 'node:child_process';
async function networkProbe() {
  const run = (port) => { try { return execFileSync('/usr/bin/curl', ['--silent','--fail','--proxy',process.env.HTTP_PROXY,'--noproxy','', 'http://127.0.0.1:'+port+'/'], { timeout: 5000 }).toString(); } catch { return 'blocked'; } };
  let direct; try { direct = await (await fetch('http://127.0.0.1:${allowedPort}/', { signal: AbortSignal.timeout(1500) })).text(); } catch { direct = 'blocked'; }
  return { allowed: run(${allowedPort}), denied: run(${deniedPort}), direct, privateEnv: Object.keys(process.env).some(key => key.startsWith('PI_EGRESS_')) };
}
const startupNetwork = await networkProbe();
`;
    writeFileSync(fixture, prelude + original.replace("pid: process.pid, calls:", "startupNetwork, network: await networkProbe(), pid: process.pid, calls:"));
    const base = policy();
    const grant = { path: workspace, granularity: "directory" as const };
    const current = { ...base, permissions: { ...base.permissions,
      filesystem: { read: [grant], write: [] }, network: { mode: "allowlist" as const, allow: [{ host: "127.0.0.1", port: allowedPort }] } } };
    const egress = new EgressService(); egressServices.push(egress);
    const managed = new ManagedMcpTransports({ policy: () => current, egress }); managers.push(managed);
    await managed.synchronize();
    const client = new McpClient({ name: "linux-mcp-egress", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport({ name: "fixture", source: "test", config: { command: process.execPath, args: [fixture] } }, workspace, undefined));
    const response = await client.callTool("ping", {});
    const expected = { allowed: "linux-mcp-allowed", denied: "blocked", direct: "blocked", privateEnv: false };
    const payload = JSON.parse((response.content[0] as { text: string }).text);
    expect(payload, JSON.stringify(payload)).toMatchObject({ startupNetwork: expected, network: expected });
    await managed.close();
    expect(egress.activeLeaseCount).toBe(0);
  }, 30_000);
  it.skipIf(!["win32", "linux"].includes(process.platform) || !existsSync(fileURLToPath(new URL(process.platform === "win32"
    ? "../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe"
    : "../../src/sandbox/backend/linux/linux-sandbox", import.meta.url))))(
    "resolves the configured MCP executable through host PATH without forwarding it", () => {
      const root = mkdtempSync(join(tmpdir(), "mcp-path-resolution-")); temporaryRoots.push(root);
      const native = fileURLToPath(new URL(process.platform === "win32"
        ? "../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe"
        : "../../src/sandbox/backend/linux/linux-sandbox", import.meta.url));
      const spec = prepareStdioLaunch({
        command: process.platform === "win32" ? "cmd" : "sh", args: [], cwd: root, environment: {},
        permissions: { filesystem: { read: [{ path: root, granularity: "directory" }], write: [] },
          network: { mode: "none" }, process: { spawn: "allow" } },
      });
      expect(spec.executable).toBe(native);
      expect(spec.environment.PATH).toBeUndefined();
    });

  it("uses host transports when the MCP sandbox switch is off", async () => {
    const base = policy();
    const current: McpExecutionPolicy = { ...base, sandbox: false, permissions: {
      ...base.permissions, process: { spawn: "deny" },
    } };
    const { managed, preparations } = manager(() => current);
    const client = new McpClient({ name: "host-transport-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport(entry(), process.cwd(), undefined));
    const result = await client.callTool("ping", {});
    expect(JSON.parse((result.content[0] as { text: string }).text)).toMatchObject({ calls: 1 });
    expect(preparations).toEqual([]);
    expect(() => managed.createTransport({ name: "http-fixture", source: "test", config: { url: "http://example.com/mcp" } }, process.cwd(), undefined)).not.toThrow();
  });

  it("uses the shared sandbox network for stdio and HTTP MCP", () => {
    const current = policy();
    current.permissions.network = { mode: "all" };
    let effective: unknown;
    const managed = new ManagedMcpTransports({ policy: () => current,      prepareStdio: input => { effective = input.permissions.network; return { executable: input.command, args: input.args, cwd: input.cwd, environment: input.environment }; } });
    managers.push(managed);
    managed.createTransport(entry(), process.cwd(), undefined);
    expect(effective).toEqual({ mode: "all" });
    expect(() => managed.createTransport({ name: "fixture", source: "test", config: { url: "http://example.com/" } }, process.cwd(), undefined)).not.toThrow();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "example.com", port: 80 }] };
    expect(() => managed.createTransport({ name: "fixture", source: "test", config: { url: "http://example.com/" } }, process.cwd(), undefined)).not.toThrow();
    expect(() => managed.createTransport({ name: "fixture", source: "test", config: { url: "https://example.com/" } }, process.cwd(), undefined)).toThrow("outside the sandbox network scope");
  });
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "enforces destination egress during Windows stdio MCP startup and calls", async () => {
      const allowed = createServer((_request, response) => response.end("mcp-allowed"));
      const denied = createServer((_request, response) => response.end("mcp-denied"));
      servers.push(allowed, denied);
      await Promise.all([new Promise<void>(resolve => allowed.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => denied.listen(0, "127.0.0.1", resolve))]);
      const allowedPort = (allowed.address() as { port: number }).port;
      const deniedPort = (denied.address() as { port: number }).port;
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-egress-")); temporaryRoots.push(root);
      const workspace = join(root, "workspace"); mkdirSync(workspace);
      const fixture = join(workspace, "server.mjs");
      const original = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
      const prelude = `import { execFileSync } from 'node:child_process';
async function networkProbe() {
  const curl = process.env.SystemRoot + '\\\\System32\\\\curl.exe';
  const run = (port, host = '127.0.0.1') => { try { return execFileSync(curl, ['--silent','--fail','--proxy',process.env.HTTP_PROXY,'--noproxy=', 'http://'+host+':'+port+'/'], { timeout: 5000 }).toString(); } catch { return 'blocked'; } };
  let direct; try { direct = await (await fetch('http://127.0.0.1:${allowedPort}/', { signal: AbortSignal.timeout(1500) })).text(); } catch { direct = 'blocked'; }
  return { allowed: run(${allowedPort}), dns: run(${allowedPort}, 'dns-test.invalid'), denied: run(${deniedPort}), direct, safeProxy: process.env.HTTP_PROXY !== 'http://127.0.0.1:9' && !process.env.NO_PROXY };
}
const startupNetwork = await networkProbe();
const backgroundNetwork = new Promise(resolve => setTimeout(async () => resolve(await networkProbe()), 50));
`;
      writeFileSync(fixture, prelude + original.replace("pid: process.pid, calls:", "startupNetwork, backgroundNetwork: await backgroundNetwork, network: await networkProbe(), pid: process.pid, calls:"));
      const base = policy();
      const grant = { path: workspace, granularity: "directory" as const };
      const current = { ...base, permissions: { ...base.permissions,
        filesystem: { read: [grant], write: [] }, network: { mode: "allowlist" as const, allow: [{ host: "127.0.0.1", port: allowedPort }, { host: "dns-test.invalid", port: allowedPort }] } } };
      let dnsTarget = "127.0.0.1";
      const egress = new EgressService({ proxy: { lookup: async () => [dnsTarget] } }); egressServices.push(egress);
      const managed = new ManagedMcpTransports({ policy: () => current, egress }); managers.push(managed);
      await managed.synchronize();
      const client = new McpClient({ name: "mxc-mcp-egress", version: "1" }); clients.push(client);
      await client.connect(managed.createTransport({ name: "fixture", source: "test", config: { command: process.execPath, args: [fixture], env: { HTTP_PROXY: "ignored", NO_PROXY: "ignored" } } }, workspace, undefined));
      const response = await client.callTool("ping", {});
      const expected = { allowed: "mcp-allowed", dns: "mcp-allowed", denied: "blocked", direct: "blocked", safeProxy: true };
      expect(JSON.parse((response.content[0] as { text: string }).text)).toMatchObject({ startupNetwork: expected, backgroundNetwork: expected, network: expected });
      expect(egress.activeLeaseCount).toBe(1);
      dnsTarget = "127.0.0.2";
      const afterDnsChange = await client.callTool("ping", {});
      expect(JSON.parse((afterDnsChange.content[0] as { text: string }).text)).toMatchObject({ network: { ...expected, dns: "blocked" } });
      await egress.dispose();
      const afterProxyStop = await client.callTool("ping", {});
      expect(JSON.parse((afterProxyStop.content[0] as { text: string }).text)).toMatchObject({ network: {
        allowed: "blocked", dns: "blocked", denied: "blocked", direct: "blocked", safeProxy: true,
      } });
      await managed.close();
      expect(egress.activeLeaseCount).toBe(0);
    }, 30_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each([
    { host: "127.0.0.1", kind: "none" }, { host: "127.0.0.1", kind: "all" },
    { host: "::1", kind: "none" }, { host: "::1", kind: "all" },
    ...Object.values(networkInterfaces()).flat().filter(address => address?.family === "IPv4" && !address.internal)
      .flatMap(address => [{ host: address!.address, kind: "none" }, { host: address!.address, kind: "all" }]),
  ] as { host: string; kind: "none" | "all" }[])("enforces MCP network $kind on $host while preserving file protection", async ({ host, kind }) => {
    const server = createServer((_request, response) => response.end("mxc-network-ok")); servers.push(server);
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("listener has no port");
    const target = `http://${host.includes(":") ? `[${host}]` : host}:${address.port}`;
    expect(await (await fetch(target)).text()).toBe("mxc-network-ok");
    const root = mkdtempSync(join(tmpdir(), "mxc-mcp-network-")); temporaryRoots.push(root);
    const workspace = join(root, "workspace"); mkdirSync(workspace);
    const outside = join(root, "outside.txt"); writeFileSync(outside, "unchanged");
    const fixture = join(workspace, "server.mjs");
    const sourceText = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
    const prelude = `import { writeFileSync } from 'node:fs';
async function probeNetwork() {
  try { return await (await fetch(${JSON.stringify(target)}, { signal: AbortSignal.timeout(2000) })).text(); }
  catch { return 'blocked'; }
}
let outsideWrite = 'allowed';
try { writeFileSync(${JSON.stringify(outside)}, 'changed'); } catch { outsideWrite = 'denied'; }
writeFileSync(${JSON.stringify(join(workspace, "allowed.txt"))}, 'allowed');
`;
    writeFileSync(fixture, prelude + sourceText.replace("pid: process.pid, calls:", "network: await probeNetwork(), outsideWrite, pid: process.pid, calls:"));
    const base = policy();
    const grant = { path: workspace, granularity: "directory" as const };
    const current = { ...base, permissions: { ...base.permissions,
      filesystem: { read: [grant], write: [grant] }, network: { mode: kind } } };
    const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
    await managed.synchronize();
    const client = new McpClient({ name: "mxc-network-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
      command: process.execPath, args: [fixture] } }, workspace, undefined));
    const response = await client.callTool("ping", {});
    expect(JSON.parse((response.content[0] as { text: string }).text)).toMatchObject({
      network: kind === "all" ? "mxc-network-ok" : "blocked", outsideWrite: "denied",
    });
    expect(readFileSync(outside, "utf8")).toBe("unchanged");
    expect(readFileSync(join(workspace, "allowed.txt"), "utf8")).toBe("allowed");
  }, 25_000);
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "runs an owned stdio MCP server inside the Windows boundary", async () => {
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-")); temporaryRoots.push(root);
      const workspace = join(root, "workspace"); mkdirSync(workspace);
      const fixture = join(workspace, "server.mjs");
      const fixtureSource = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
      writeFileSync(fixture, fixtureSource.replace("secretPresent: process.env.UNAPPROVED_SECRET !== undefined", "secretPresent: process.env.UNAPPROVED_SECRET !== undefined, bootstrapPresent: process.env.PI_MXC_REQUEST !== undefined"));
      const base = policy();
        const current = { ...base, permissions: { ...base.permissions,
        filesystem: { read: [{ path: workspace, granularity: "directory" as const }], write: [] } } };
      process.env.UNAPPROVED_SECRET = "canary";
      const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
      await managed.synchronize();
      const client = new McpClient({ name: "mxc-test", version: "1" }); clients.push(client);
      await client.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
        command: process.execPath, args: [fixture] } }, workspace, undefined));
      const first = await client.callTool("ping", {});
      const payload = JSON.parse((first.content[0] as { text: string }).text);
      expect(payload).toMatchObject({ calls: 1, secretPresent: false, bootstrapPresent: false });
      const second = await client.callTool("ping", {});
      const next = JSON.parse((second.content[0] as { text: string }).text);
      expect(next).toMatchObject({ pid: payload.pid, calls: 2, secretPresent: false, bootstrapPresent: false });
      await client.close();
      await waitFor(() => { try { process.kill(payload.pid, 0); return false; } catch { return true; } });
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "protects root control files in a writable Windows MCP workspace", async () => {
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-write-")); temporaryRoots.push(root);
      const workspace = join(root, "workspace"); mkdirSync(workspace);
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(workspace, name));
      const protectedFile = join(workspace, ".git", "config");
      const allowedFile = join(workspace, "allowed.txt");
      writeFileSync(protectedFile, "original");
      const fixture = join(workspace, "server.mjs");
      const sourceText = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
      const prelude = `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(allowedFile)}, 'allowed');\nlet protectedWrite = 'allowed'; try { writeFileSync(${JSON.stringify(protectedFile)}, 'changed'); } catch { protectedWrite = 'denied'; }\n`;
      writeFileSync(fixture, prelude + sourceText.replace("pid: process.pid, calls:", "protectedWrite, pid: process.pid, calls:"));
      const base = policy();
        const grant = { path: workspace, granularity: "directory" as const };
      const current = { ...base, permissions: { ...base.permissions,
        filesystem: { read: [grant], write: [grant] } } };
      const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
      await managed.synchronize();
      const client = new McpClient({ name: "mxc-write-test", version: "1" }); clients.push(client);
      await client.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
        command: process.execPath, args: [fixture] } }, workspace, undefined));
      const response = await client.callTool("ping", {});
      expect(JSON.parse((response.content[0] as { text: string }).text)).toMatchObject({ protectedWrite: "denied" });
      expect(readFileSync(allowedFile, "utf8")).toBe("allowed");
      expect(readFileSync(protectedFile, "utf8")).toBe("original");
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)))).each(["close", "policy revision"])(
    "terminates a detached MCP descendant on Windows transport %s", async action => {
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-tree-")); temporaryRoots.push(root);
      const workspace = join(root, "workspace"); mkdirSync(workspace);
      const fixture = join(workspace, "server.mjs");
      const sourceText = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
      const prelude = "import { spawn } from 'node:child_process';\nconst descendant = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 30000)'], { detached: true, stdio: 'ignore' });\ndescendant.unref();\n";
      writeFileSync(fixture, prelude + sourceText.replace("pid: process.pid, calls:", "pid: process.pid, descendantPid: descendant.pid, calls:"));
      const base = policy();
        let current = { ...base, permissions: { ...base.permissions,
        filesystem: { read: [{ path: workspace, granularity: "directory" as const }], write: [] } } };
      const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
      await managed.synchronize();
      const client = new McpClient({ name: "mxc-tree-test", version: "1" }); clients.push(client);
      let descendantPid = 0;
      let replacementPid = 0;
      try {
        await client.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
          command: process.execPath, args: [fixture] } }, workspace, undefined));
        const response = await client.callTool("ping", {});
        const payload = JSON.parse((response.content[0] as { text: string }).text);
        descendantPid = payload.descendantPid;
        expect(descendantPid).toBeGreaterThan(0);
        expect(() => process.kill(descendantPid, 0)).not.toThrow();
        if (action === "close") await client.close();
        else { current = { ...current, revision: "r2" }; await managed.synchronize(); }
        await waitFor(() => { try { process.kill(descendantPid, 0); return false; } catch { return true; } });
        expect(() => process.kill(payload.pid, 0)).toThrow();
        if (action === "policy revision") {
          const replacement = new McpClient({ name: "mxc-tree-replacement", version: "1" }); clients.push(replacement);
          await replacement.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
            command: process.execPath, args: [fixture] } }, workspace, undefined));
          const fresh = await replacement.callTool("ping", {});
          const next = JSON.parse((fresh.content[0] as { text: string }).text);
          replacementPid = next.descendantPid;
          expect(next.pid).not.toBe(payload.pid);
          expect(next.calls).toBe(1);
          expect(replacementPid).toBeGreaterThan(0);
          await replacement.close();
          await waitFor(() => { try { process.kill(replacementPid, 0); return false; } catch { return true; } });
        }
      } finally {
        for (const pid of [descendantPid, replacementPid]) if (pid) { try { process.kill(pid); } catch { /* The process already exited. */ } }
      }
    }, 25_000,
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "rejects Windows MCP process denial and a missing destination lease before launch", async () => {
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-policy-")); temporaryRoots.push(root);
      const base = policy();
        for (const permissions of [
        { ...base.permissions, network: { mode: "allowlist" as const, allow: [{ host: "example.com", port: 443 }] } },
        { ...base.permissions, process: { spawn: "deny" as const } },
      ]) {
        const current = { ...base, permissions };
        const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
        if (permissions.network.mode === "allowlist") {
          await expect(managed.createTransport(entry(), root, undefined).start()).rejects.toThrow("sandbox-capability-unsupported");
        } else expect(() => managed.createTransport(entry(), root, undefined)).toThrow("sandbox-capability-unsupported");
      }
    },
  );
  it.skipIf(process.platform !== "win32" || !existsSync(fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url))))(
    "allows a writable Windows MCP workspace while denying missing protected paths", async () => {
      const root = mkdtempSync(join(tmpdir(), "mxc-mcp-protected-")); temporaryRoots.push(root);
      const allowedFile = join(root, "allowed.txt");
      const protectedDir = join(root, ".git");
      const fixture = join(root, "server.mjs");
      const sourceText = readFileSync(fileURLToPath(new URL("./fixtures/mcp-server.mjs", import.meta.url)), "utf8");
      const prelude = `import { mkdirSync, writeFileSync } from 'node:fs';\nimport { join } from 'node:path';\nwriteFileSync(${JSON.stringify(allowedFile)}, 'allowed');\nlet missingProtected = 'allowed'; try { mkdirSync(${JSON.stringify(protectedDir)}); writeFileSync(join(${JSON.stringify(protectedDir)}, 'config'), 'changed'); } catch { missingProtected = 'denied'; }\n`;
      writeFileSync(fixture, prelude + sourceText.replace("pid: process.pid, calls:", "missingProtected, pid: process.pid, calls:"));
      const base = policy();
        const grant = { path: root, granularity: "directory" as const };
      const current = { ...base, permissions: { ...base.permissions,
        filesystem: { read: [grant], write: [grant] } } };
      const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
      await managed.synchronize();
      const client = new McpClient({ name: "mxc-missing-protected-test", version: "1" }); clients.push(client);
      await client.connect(managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
        command: process.execPath, args: [fixture] } }, root, undefined));
      const response = await client.callTool("ping", {});
      expect(JSON.parse((response.content[0] as { text: string }).text)).toMatchObject({ missingProtected: "denied" });
      expect(readFileSync(allowedFile, "utf8")).toBe("allowed");
      expect(existsSync(protectedDir)).toBe(false);
    }, 25_000,
  );
  it("reuses one owned stdio process and filters controller credentials before initialization", async () => {
    process.env.UNAPPROVED_SECRET = "canary";
    const { managed, preparations } = manager(policy);
    await managed.synchronize();
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport(entry(), process.cwd(), undefined));
    const first = await client.callTool("ping", {});
    const second = await client.callTool("ping", {});
    const result = (value: typeof first) => JSON.parse((value.content[0] as { text: string }).text);
    expect(result(first)).toMatchObject({ calls: 1, secretPresent: false });
    expect(result(second)).toMatchObject({ pid: result(first).pid, calls: 2, secretPresent: false });
    expect(preparations).toHaveLength(1);
  });

  it("revokes old sends synchronously and closes the old tree before a replacement starts", async () => {
    let current = policy();
    const { managed } = manager(() => current);
    await managed.synchronize();
    const old = managed.createTransport(entry(), process.cwd(), undefined);
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client); await client.connect(old);
    const first = await client.callTool("ping", {});
    const oldPid = JSON.parse((first.content[0] as { text: string }).text).pid;
    current = { ...current, revision: "r2" };
    const closing = managed.synchronize();
    await expect(old.send({ jsonrpc: "2.0", id: 99, method: "tools/call", params: { name: "ping" } })).rejects.toThrow("revoked");
    await closing;
    expect(() => process.kill(oldPid, 0)).toThrow();
    const replacement = new McpClient({ name: "permission-test", version: "1" }); clients.push(replacement);
    await replacement.connect(managed.createTransport(entry(), process.cwd(), undefined));
    const second = await replacement.callTool("ping", {});
    expect(JSON.parse((second.content[0] as { text: string }).text)).toMatchObject({ calls: 1 });
  });

  it("runs MCP with the shared sandbox permissions", async () => {
    const { managed, preparations } = manager(policy);
    const client = new McpClient({ name: "permission-test", version: "1" }); clients.push(client);
    const configured = entry();
    if ("command" in configured.config) configured.config.env = { UNAPPROVED_SECRET: "!echo fixture-token" };
    await client.connect(managed.createTransport(configured, process.cwd(), undefined));
    const result = await client.callTool("ping", {});
    expect(JSON.parse((result.content[0] as { text: string }).text).secretPresent).toBe(true);
    expect(preparations).toEqual([process.execPath]);
    expect(() => managed.createTransport({ name: "fixture", source: "test", config: { url: "http://example.com/" } }, process.cwd(), undefined))
      .toThrow("outside the sandbox network scope");
    const another = manager(policy);
    const server = entry();
    if ("command" in server.config) server.config.env = { UNAPPROVED_SECRET: "secret" };
    const anotherTransport = another.managed.createTransport(server, process.cwd(), undefined);
    expect(anotherTransport).toBeInstanceOf(StdioTransport);
    expect(another.preparations).toEqual([process.execPath]);
  });

  it("exposes managed stdio stderr to Pi's connection diagnostics", async () => {
    const { managed } = manager(policy);
    const transport = managed.createTransport({ name: "fixture", source: "test", config: {
      command: process.execPath, args: ["-e", "console.error('managed-stderr-marker')"],
    } }, process.cwd(), undefined);
    const client = new McpClient({ name: "stderr-test", version: "1" }); clients.push(client);
    await expect(client.connect(transport)).rejects.toThrow();
    if (!(transport instanceof StdioTransport)) throw new Error("managed transport lost its stdio identity");
    expect(transport.stderr).toContain("managed-stderr-marker");
  });

  it.skipIf(process.platform !== "linux")("enforces process denial before MCP initialization and across policy restarts", async () => {
    const nativeExecutable = fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url));
    if (!existsSync(nativeExecutable)) {
      execFileSync("bash", [fileURLToPath(new URL("../../src/sandbox/backend/linux/build.sh", import.meta.url)), nativeExecutable]);
      nativeExecutableCreatedForTest = true;
    }
    const root = mkdtempSync(join(tmpdir(), "permission-mcp-process-spawn-")); temporaryRoots.push(root);
    const workspace = join(root, "workspace"); mkdirSync(workspace);
    for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(workspace, name));
    let current = spawnPolicy("allow", "r1", workspace);
    const managed = new ManagedMcpTransports({ policy: () => current }); managers.push(managed);
    await managed.synchronize();

    const open = async () => {
      const client = new McpClient({ name: "process-spawn-test", version: "1" }); clients.push(client);
      const transport = managed.createTransport({ name: "fixture", source: "test", scope: "extension", config: {
        command: process.execPath,
        args: [fileURLToPath(new URL("./fixtures/mcp-process-spawn.mjs", import.meta.url))],
      } }, workspace, undefined);
      const transportErrors: string[] = [];
      transport.onError(error => transportErrors.push(String(error)));
      try { await client.connect(transport); }
      catch (error) {
        throw new Error(`MCP revision ${current.revision} process.spawn=${current.permissions.process.spawn} failed to connect: ${String(error)}; stderr=${transportErrors.join(" | ")}`);
      }
      return { client, transport };
    };
    const probe = async (client: McpClient) => {
      const value = await client.callTool("probe", {});
      return JSON.parse((value.content[0] as { text: string }).text) as {
        pid: number; nonce: string; calls: number;
        startup: { code: string | null; marker: string };
        call: { code: string | null; marker: string };
      };
    };

    const first = await open();
    const allowed = await probe(first.client);
    expect(allowed.startup.code).toBeNull();
    expect(allowed.call.code).toBeNull();
    expect(readFileSync(allowed.startup.marker, "utf8")).toBe("spawned");
    expect(readFileSync(allowed.call.marker, "utf8")).toBe("spawned");
    expect(await probe(first.client)).toMatchObject({ pid: allowed.pid, nonce: allowed.nonce, calls: 2 });

    current = spawnPolicy("deny", "r2", workspace);
    const denyTransition = managed.synchronize();
    await expect(first.transport.send({ jsonrpc: "2.0", id: 999, method: "tools/call", params: { name: "probe" } })).rejects.toThrow("revoked");
    await denyTransition;
    await waitFor(() => existsSync(join(workspace, `exit-${allowed.nonce}.marker`)));
    expect(readFileSync(join(workspace, `exit-${allowed.nonce}.marker`), "utf8")).toBe("exited");
    const second = await open();
    const denied = await probe(second.client);
    expect(denied.startup.code).toBe("EPERM");
    expect(denied.call.code).toBe("EPERM");
    expect(existsSync(denied.startup.marker)).toBe(false);
    expect(existsSync(denied.call.marker)).toBe(false);
    expect(await probe(second.client)).toMatchObject({ pid: denied.pid, nonce: denied.nonce, calls: 2, call: { code: "EPERM" } });

    current = spawnPolicy("allow", "r3", workspace);
    const allowTransition = managed.synchronize();
    await expect(second.transport.send({ jsonrpc: "2.0", id: 1000, method: "tools/call", params: { name: "probe" } })).rejects.toThrow("revoked");
    await allowTransition;
    await waitFor(() => existsSync(join(workspace, `exit-${denied.nonce}.marker`)));
    expect(readFileSync(join(workspace, `exit-${denied.nonce}.marker`), "utf8")).toBe("exited");
    const third = await open();
    const reallowed = await probe(third.client);
    expect(reallowed.startup.code).toBeNull();
    expect(reallowed.call.code).toBeNull();
    expect(readFileSync(reallowed.startup.marker, "utf8")).toBe("spawned");
    expect(new Set([allowed.nonce, denied.nonce, reallowed.nonce]).size).toBe(3);
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
    const current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
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
    expect(deletedSessions).toBe(0);
    await client.close();
    expect(deletedSessions).toBe(0);
  });

  it("leaves OAuth token and recovery requests under Pi's control", async () => {
    let oauthRequests = 0;
    let bypassRequests = 0;
    const forbidden = createServer((_request, response) => { bypassRequests++; response.end("auth-ok"); });
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
    servers.push(server, forbidden);
    await Promise.all([new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)), new Promise<void>(resolve => forbidden.listen(0, "127.0.0.1", resolve))]);
    const port = (server.address() as { port: number }).port;
    const forbiddenPort = (forbidden.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    const current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
    let token = "expired";
    const authProvider: AuthProvider = {
      token: async () => {
        expect(await (await fetch(`http://127.0.0.1:${forbiddenPort}/`)).text()).toBe("auth-ok");
        return token;
      },
      onUnauthorized: async context => {
        const before = bypassRequests;
        await expect(context.fetch(`http://127.0.0.1:${forbiddenPort}/`)).rejects.toThrow("outside the sandbox network scope");
        expect(bypassRequests).toBe(before);
        token = "refreshed";
      },
    };
    const client = new McpClient({ name: "oauth-test", version: "1" }); clients.push(client);
    await client.connect(managed.createTransport({ name: "fixture", source: "test", config: { url: `${base}/mcp` } }, process.cwd(), authProvider));
    expect(oauthRequests).toBe(0);
    expect(bypassRequests).toBeGreaterThan(0);
    expect(egress.activeLeaseCount).toBe(1);
    await managed.close();
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("allows an opaque model provider to supply its token", async () => {
    let authorization: string | undefined;
    const server = createServer((request, response) => { authorization = request.headers.authorization; response.writeHead(202).end(); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
    let called = false;
    const transport = managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp`, auth: { provider: "custom" } } }, process.cwd(), {
      token: async () => { called = true; return "token"; },
    });
    await transport.start();
    await transport.send({ jsonrpc: "2.0", method: "test" });
    expect(called).toBe(true);
    expect(authorization).toBe("Bearer token");
    await transport.close();
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("revokes an active HTTP stream before a tighter network revision takes effect", async () => {
    let streamClosed = false;
    const server = createServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "text/event-stream" });
      response.write(": open\n\n");
      response.on("close", () => { streamClosed = true; });
    });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    let current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
    const transport = managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp` } }, process.cwd(), undefined);
    await transport.start();
    await transport.send({ jsonrpc: "2.0", id: 1, method: "test" });
    await waitFor(() => egress.activeConnectionCount > 0);
    current = { ...current, revision: "r2", permissions: { ...current.permissions, network: { mode: "none" as const } } };
    await managed.synchronize();
    await waitFor(() => streamClosed);
    expect(egress.activeLeaseCount).toBe(0);
    await expect(transport.send({ jsonrpc: "2.0", id: 2, method: "test" })).rejects.toThrow("revoked");
    expect(() => managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp` } }, process.cwd(), undefined)).toThrow("outside the sandbox network scope");
  });

  it("does not fall back to direct HTTP when the policy proxy stops", async () => {
    let requests = 0;
    const server = createServer((_request, response) => { requests++; response.writeHead(202).end(); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
    const transport = managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp` } }, process.cwd(), undefined);
    await transport.start();
    await transport.send({ jsonrpc: "2.0", method: "test" });
    expect(requests).toBe(1);
    await egress.dispose();
    await expect(transport.send({ jsonrpc: "2.0", method: "test" })).rejects.toThrow();
    expect(requests).toBe(1);
  });

  it("rejects HTTP MCP redirects even when their destination is in scope", async () => {
    let redirected = 0;
    const other = createServer((_request, response) => { redirected++; response.end("unexpected"); });
    servers.push(other); await new Promise<void>(resolve => other.listen(0, "127.0.0.1", resolve));
    const otherPort = (other.address() as { port: number }).port;
    const server = createServer((_request, response) => response.writeHead(302, { Location: `http://127.0.0.1:${otherPort}/` }).end());
    servers.push(server); await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const current = policy();
    current.permissions.network = { mode: "allowlist", allow: [{ host: "127.0.0.1", port }, { host: "127.0.0.1", port: otherPort }] };
    const egress = new EgressService(); egressServices.push(egress);
    const { managed } = manager(() => current, egress); await managed.synchronize();
    const transport = managed.createTransport({ name: "fixture", source: "test", config: { url: `http://127.0.0.1:${port}/mcp` } }, process.cwd(), undefined);
    await transport.start();
    await expect(transport.send({ jsonrpc: "2.0", method: "test" })).rejects.toThrow("redirect");
    expect(redirected).toBe(0);
  });
});
