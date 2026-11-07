import { homedir } from "node:os";
import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";
import {
  McpAuthRequiredError, StdioTransport, StreamableHttpTransport,
  type McpTransport, type JsonRpcMessage, type AuthProvider,
} from "@earendil-works/pi-mcp";
import { getShellConfig, type McpServerEntry, type McpTransportFactory } from "@earendil-works/pi-coding-agent";
import { prepareStdioLaunch, type ControlledMcpPermissions } from "./platform";
import type { PermissionMode } from "../contracts";
import { jsonDigest } from "../json";
import { selectExecutionEnvironment } from "./plan";
import { toRuntimeNetworkScope } from "./network-scope";
import { EgressService } from "./egress/index";
import type { EgressGrant } from "./egress/types";
import { leasedMcpTransport } from "./leased-mcp-transport";
import { fetch as undiciFetch, ProxyAgent } from "undici";


export interface McpExecutionPolicy {
  readonly revision: string;
  readonly mode: PermissionMode;
  readonly permissions: ControlledMcpPermissions;
  readonly environment?: Readonly<Record<string, string>>;
  readonly sessionId?: string;
  /** Experimental MCP sandbox; omitted keeps this low-level manager controlled. */
  readonly sandbox?: boolean;
}

function expandHome(value: string): string {
  return value === "~" ? homedir() : value.startsWith("~/") ? resolve(homedir(), value.slice(2)) : value;
}

const MAX_CONFIG_COMMAND_OUTPUT_BYTES = 1024 * 1024;

function runConfigCommand(command: string, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("MCP config command was cancelled"));
      return;
    }
    let child: ChildProcess | undefined;
    let settled = false;
    let pendingFailure: Error | undefined;
    let outputBytes = 0;
    const output: Buffer[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = (): void => {
      if (timer !== undefined) clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    };
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error !== undefined) reject(error);
      else resolve(Buffer.concat(output, outputBytes).toString("utf8"));
    };
    const stop = (error: Error): void => {
      if (settled) return;
      pendingFailure = error;
      try {
        if (!child || !child.kill()) finish(error);
      } catch {
        finish(error);
      }
    };
    const abort = (): void => {
      stop(new Error("MCP config command was cancelled"));
    };
    signal.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => stop(new Error("MCP config command timed out")), 10_000);

    const launch = (usePiShell: boolean): void => {
      let shell: string | undefined;
      let args: string[] = [];
      let stdin = false;
      if (usePiShell) {
        try {
          const configured = getShellConfig();
          shell = configured.shell;
          args = configured.args;
          stdin = configured.commandTransport === "stdin";
        } catch {
          launch(false);
          return;
        }
      }
      let candidate: ChildProcess;
      try {
        candidate = usePiShell
          ? spawn(shell!, stdin ? args : [...args, command], { stdio: [stdin ? "pipe" : "ignore", "pipe", "ignore"], windowsHide: true })
          : spawn(command, [], { shell: true, stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
      } catch {
        finish(new Error("MCP config command failed"));
        return;
      }
      child = candidate;
      candidate.stdout?.on("data", (chunk: Buffer) => {
        if (settled || child !== candidate) return;
        outputBytes += chunk.byteLength;
        if (outputBytes > MAX_CONFIG_COMMAND_OUTPUT_BYTES) {
          stop(new Error("MCP config command output exceeded its limit"));
          return;
        }
        output.push(chunk);
      });
      candidate.stdin?.on("error", () => undefined);
      candidate.once("error", (error) => {
        if (settled || child !== candidate) return;
        if (usePiShell && (error as NodeJS.ErrnoException).code === "ENOENT") {
          launch(false);
          return;
        }
        finish(new Error("MCP config command failed"));
      });
      candidate.once("close", (code) => {
        if (settled || child !== candidate) return;
        if (pendingFailure !== undefined) finish(pendingFailure);
        else if (code !== 0) finish(new Error("MCP config command failed"));
        else finish();
      });
      if (stdin) candidate.stdin?.end(command);
    };

    launch(process.platform === "win32");
  });
}

async function configValue(
  value: string,
  signal: AbortSignal,
  runCommand: (command: string, signal: AbortSignal) => Promise<string>,
): Promise<string> {
  if (value.startsWith("!")) {
    try {
      const resolved = (await runCommand(value.slice(1), signal)).trim();
      if (resolved) return resolved;
    } catch { /* Report the resolution error without exposing the command. */ }
    throw new Error("MCP config command failed to produce a value");
  }
  return resolveConfigReference(value);
}

function resolveConfigReference(value: string): string {
  return value.replace(/\$(\$|!|\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g, (_match, token: string, braced: string | undefined, plain: string | undefined) => {
    if (token === "$" || token === "!") return token;
    const name = braced ?? plain!;
    const found = process.env[name];
    if (!found) throw new Error(`MCP environment reference is unavailable: ${name}`);
    return found;
  });
}

export interface ManagedMcpOptions {
  readonly policy: () => McpExecutionPolicy;
  readonly prepareStdio?: typeof prepareStdioLaunch;
  readonly fetch?: typeof fetch;
  readonly onRequest?: () => void;
  readonly egress?: EgressService;
  readonly runConfigCommand?: (command: string, signal: AbortSignal) => Promise<string>;
}

interface ResolvedMcpValues {
  readonly headers?: Readonly<Record<string, string>>;
  readonly environment?: Readonly<Record<string, string>>;
}

/** Owns transports, never adopts an already-started external stdio process. */
export class ManagedMcpTransports {
  private revision: string | undefined;
  private generation = 0;
  private readonly live = new Map<McpTransport, { retire(): void }>();
  private closing: Promise<void> = Promise.resolve();
  private blocked: unknown;

  constructor(private readonly options: ManagedMcpOptions) {}

  synchronize(): Promise<void> {
    const revision = this.options.policy().revision;
    if (this.revision === revision) return this.closing;
    this.revision = revision;
    return this.close();
  }

  close(): Promise<void> {
    ++this.generation;
    const transports = [...this.live];
    for (const [, state] of transports) state.retire();
    this.closing = this.closing.then(async () => {
      if (this.blocked) throw this.blocked;
      const results = await Promise.allSettled(transports.map(([transport]) => transport.close()));
      const failed = results.find(result => result.status === "rejected");
      if (failed?.status === "rejected") { this.blocked = failed.reason; throw failed.reason; }
      for (const [transport] of transports) this.live.delete(transport);
    });
    // Retain the rejection for the next start while avoiding an unobserved rejection on disposal.
    void this.closing.catch(() => undefined);
    return this.closing;
  }

  readonly createTransport: McpTransportFactory = (entry, cwd, authProvider) => {
    const captured = structuredClone(entry);
    const policy = this.options.policy();
    const revision = policy.revision;
    const generation = this.generation;
    const permissions = policy.permissions;
    const sandbox = policy.sandbox ?? true;
    if (sandbox) this.validateConfiguration(captured, permissions, policy.mode);
    const identity = jsonDigest(captured);
    let retired = false;
    const current = () => {
      if (retired || generation !== this.generation || revision !== this.options.policy().revision || identity !== jsonDigest(entry)) {
        throw new Error("plan-invalidated: MCP connection authorization has been revoked");
      }
    };
    const network = toRuntimeNetworkScope(permissions.network);
    const needsLease = sandbox && policy.mode !== "full-access" && network.kind === "destinations";
    if (sandbox && process.platform === "win32" && policy.mode !== "full-access" && permissions.process.spawn !== "allow") {
      throw new Error("sandbox-capability-unsupported: Windows MCP process denial is unsupported");
    }
    const hasConfigCommand = "url" in captured.config
      ? Object.values(captured.config.headers ?? {}).some(value => value.startsWith("!"))
      : Object.values(captured.config.env ?? {}).some(value => value.startsWith("!"));
    const resolveValuesImmediately = (): ResolvedMcpValues => {
      if ("url" in captured.config) {
        return { headers: Object.fromEntries(Object.entries(captured.config.headers ?? {}).map(([name, value]) => [name, resolveConfigReference(value)])) };
      }
      const environment: Record<string, string> = sandbox ? {
        ...selectExecutionEnvironment(process.env as Record<string, string>),
        ...policy.environment,
      } : {};
      for (const [name, value] of Object.entries(captured.config.env ?? {})) {
        environment[name] = resolveConfigReference(value);
      }
      return { environment };
    };
    const resolveValues = async (signal: AbortSignal): Promise<ResolvedMcpValues> => {
      const runCommand = this.options.runConfigCommand ?? runConfigCommand;
      if ("url" in captured.config) {
        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries(captured.config.headers ?? {})) {
          current();
          headers[name] = await configValue(value, signal, runCommand);
          current();
        }
        return { headers };
      }
      const environment: Record<string, string> = sandbox ? {
        ...selectExecutionEnvironment(process.env as Record<string, string>),
        ...policy.environment,
      } : {};
      for (const [name, value] of Object.entries(captured.config.env ?? {})) {
        current();
        environment[name] = await configValue(value, signal, runCommand);
        current();
      }
      return { environment };
    };
    const prepare = async (signal: AbortSignal) => {
      current();
      const values = await resolveValues(signal);
      current();
      if (!needsLease) {
        return {
          transport: this.buildTransport(captured, cwd, authProvider, permissions, policy.mode, sandbox, current, values),
          release: () => undefined,
        };
      }
      const service = this.options.egress;
      if (!service || network.kind !== "destinations") throw new Error("sandbox-capability-unsupported: MCP egress is unavailable");
      const acquired = await service.acquireForService({ sessionId: policy.sessionId ?? revision, serviceId: captured.name,
        serviceName: captured.name, generation, policyRevision: revision, configRevision: revision, scope: { destinations: network.destinations } });
      if (!acquired) throw new Error("sandbox-capability-unsupported: MCP egress lease is unavailable");
      try {
        current();
        const forwarder = process.platform === "win32" || "url" in captured.config ? await service.openForwarder(acquired.grant) : undefined;
        current();
        const grant = forwarder ? { ...acquired.grant, proxyHost: forwarder.host, proxyPort: forwarder.port } : acquired.grant;
        const dispatcher = "url" in captured.config ? new ProxyAgent(`http://${grant.proxyHost}:${grant.proxyPort}`) : undefined;
        try {
          const transport = this.buildTransport(captured, cwd, authProvider, permissions, policy.mode, sandbox, current, values, grant, dispatcher);
          return { transport, release: () => { service.revoke(acquired.grant.leaseId); void dispatcher?.destroy().catch(() => undefined); } };
        } catch (error) { void dispatcher?.destroy().catch(() => undefined); throw error; }
      } catch (error) { service.revoke(acquired.grant.leaseId); throw error; }
    };
    const inner = needsLease || hasConfigCommand
      ? leasedMcpTransport(prepare)
      : this.buildTransport(captured, cwd, authProvider, permissions, policy.mode, sandbox, current, resolveValuesImmediately());
    const managed: McpTransport = {
      start: async () => {
        await this.closing;
        current();
        await inner.start();
        try { current(); } catch (error) { await inner.close(); throw error; }
      },
      send: async (message: JsonRpcMessage) => {
        current();
        if ("method" in message && ["tools/call", "resources/read", "resources/list", "resources/templates/list"].includes(message.method)) this.options.onRequest?.();
        try { await inner.send(message); }
        catch (error) {
          // A tool may have changed the world before its response was lost. In
          // particular do not let Pi reconnect and replay a tools/call on 404.
          if ("method" in message && message.method === "tools/call" && !(error instanceof McpAuthRequiredError)) {
            throw new Error(`MCP tool outcome unknown; request was not replayed: ${error instanceof Error ? error.message : String(error)}`);
          }
          throw error;
        }
      },
      close: async () => { retired = true; await inner.close(); this.live.delete(transport); },
      onMessage: listener => inner.onMessage(message => { if (!retired && generation === this.generation) listener(message); }),
      onError: listener => inner.onError(listener),
      onClose: listener => inner.onClose(listener),
      setProtocolVersion: version => inner.setProtocolVersion?.(version),
    };
    const transport = inner instanceof StdioTransport ? new Proxy(inner, {
      get: (target, property) => {
        if (property in managed) return Reflect.get(managed, property);
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) : managed;
    this.live.set(transport, { retire: () => { retired = true; } });
    inner.onClose(() => { retired = true; this.live.delete(transport); });
    return transport;
  };

  private validateConfiguration(entry: McpServerEntry, permissions: ControlledMcpPermissions, mode: PermissionMode): void {
    const config = entry.config;
    if (!("url" in config)) return;
    const target = new URL(config.url);
    if (target.username || target.password || !["https:", "http:"].includes(target.protocol)) {
      throw new Error("MCP HTTP target is invalid");
    }
    if (mode !== "full-access") {
      const network = toRuntimeNetworkScope(permissions.network);
      const port = Number(target.port || (target.protocol === "https:" ? 443 : 80));
      if (network.kind === "none" || (network.kind === "destinations" && !network.destinations.some(destination =>
        destination.host.toLowerCase() === target.hostname.toLowerCase() && (destination.port === undefined || destination.port === port)))) {
        throw new Error("sandbox-denied: MCP HTTP target is outside the sandbox network scope");
      }
    }
  }

  private buildTransport(entry: McpServerEntry, cwd: string, authProvider: AuthProvider | undefined,
    permissions: ControlledMcpPermissions, mode: PermissionMode, sandbox: boolean, current: () => void, values: ResolvedMcpValues,
    egress?: EgressGrant, dispatcher?: ProxyAgent): McpTransport {
    const config = entry.config;
    if (!sandbox) {
      if ("url" in config) return new StreamableHttpTransport({ url: new URL(config.url), authProvider, headers: { ...values.headers } });
      return new StdioTransport({ command: expandHome(config.command), args: (config.args ?? []).map(expandHome),
        cwd: resolve(cwd, expandHome(config.cwd ?? ".")), env: { ...values.environment }, inheritEnv: true, stderr: "pipe" });
    }
    if ("url" in config) {
      const target = new URL(config.url);
      if (target.username || target.password || !["https:", "http:"].includes(target.protocol)) throw new Error("MCP HTTP target is invalid");
      if (mode !== "full-access") {
        const network = toRuntimeNetworkScope(permissions.network);
        const port = Number(target.port || (target.protocol === "https:" ? 443 : 80));
        if (network.kind === "none" || (network.kind === "destinations" && !network.destinations.some(destination =>
          destination.host.toLowerCase() === target.hostname.toLowerCase() && (destination.port === undefined || destination.port === port)))) {
          throw new Error("sandbox-denied: MCP HTTP target is outside the sandbox network scope");
        }
      }
      const scope = toRuntimeNetworkScope(permissions.network);
      const proxiedFetch: typeof fetch = async (input, init) => {
        current();
        if (input instanceof Request) throw new Error("sandbox-capability-unsupported: MCP OAuth Request objects are unsupported");
        const destination = new URL(input.toString());
        if (!dispatcher || scope.kind !== "destinations" || destination.username || destination.password ||
          !["http:", "https:"].includes(destination.protocol) || !scope.destinations.some(allowed =>
            allowed.host === destination.hostname.toLowerCase() && (allowed.port === undefined || allowed.port === Number(destination.port || (destination.protocol === "https:" ? 443 : 80))))) {
          throw new Error("sandbox-denied: MCP HTTP request is outside the sandbox network scope");
        }
        const response = await undiciFetch(destination.href, { ...init, redirect: "manual", dispatcher } as Parameters<typeof undiciFetch>[1]);
        if (response.status >= 300 && response.status < 400) {
          void response.body?.cancel().catch(() => undefined);
          throw new Error("sandbox-denied: MCP HTTP redirect is outside the fixed target");
        }
        return response as unknown as Response;
      };
      const managedAuth: AuthProvider | undefined = dispatcher && authProvider ? {
        token: () => authProvider.token(),
        ...(authProvider.onUnauthorized ? { onUnauthorized: context =>
          authProvider.onUnauthorized!({ ...context, fetch: proxiedFetch }) } : {}),
      } : authProvider;
      return new StreamableHttpTransport({
        url: target, authProvider: managedAuth,
        headers: { ...values.headers },
        fetch: async (input, init) => {
          if (init?.method !== "DELETE") current();
          if (new URL(input).href !== target.href) throw new Error("sandbox-denied: MCP HTTP request target changed");
          const response = dispatcher ? await proxiedFetch(input, init) : await (this.options.fetch ?? fetch)(input, { ...init, redirect: "manual" });
          if (response.status >= 300 && response.status < 400) {
            void response.body?.cancel().catch(() => undefined);
            throw new Error("sandbox-denied: MCP HTTP redirect is outside the fixed target");
          }
          return response;
        },
      });
    }
    const environment: Record<string, string> = { ...values.environment };
    const launch = { command: expandHome(config.command), args: (config.args ?? []).map(expandHome),
      cwd: resolve(cwd, expandHome(config.cwd ?? ".")), environment };
    if (mode === "full-access") return new StdioTransport({ ...launch, env: environment, inheritEnv: true, stderr: "pipe" });
    const spec = (this.options.prepareStdio ?? prepareStdioLaunch)({ ...launch, permissions, ...(egress ? { egress } : {}) });
    return new StdioTransport({ command: spec.executable, args: spec.args, cwd: spec.cwd,
      env: { ...spec.environment }, inheritEnv: false, stderr: "pipe" });
  }
}
