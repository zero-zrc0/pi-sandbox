import { homedir } from "node:os";
import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";
import {
  McpAuthRequiredError, StdioTransport, StreamableHttpTransport,
  type McpTransport, type JsonRpcMessage, type AuthProvider, type McpTransportSendOptions,
} from "@earendil-works/pi-mcp";
import { getShellConfig, type McpServerEntry, type McpTransportFactory } from "@earendil-works/pi-coding-agent";
import { jsonDigest } from "../json";

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
  readonly revision: () => string;
  readonly onRequest?: () => void;
  readonly runConfigCommand?: (command: string, signal: AbortSignal) => Promise<string>;
}

interface ResolvedMcpValues {
  readonly headers?: Readonly<Record<string, string>>;
  readonly environment?: Readonly<Record<string, string>>;
}

class DeferredMcpTransport extends StdioTransport {
  private inner: McpTransport | undefined;
  private pending: Promise<void> | undefined;
  private preparing: AbortController | undefined;
  private closedFlag = false;
  private version: string | undefined;

  constructor(private readonly prepare: (signal: AbortSignal) => Promise<McpTransport>) {
    super({ command: "" });
  }

  override get stderr(): string {
    return this.inner instanceof StdioTransport ? this.inner.stderr : "";
  }

  override start(): Promise<void> {
    if (this.pending || this.closedFlag) return Promise.reject(new Error("MCP transport is already started or closed"));
    this.preparing = new AbortController();
    this.pending = (async () => {
      const inner = await this.prepare(this.preparing!.signal);
      this.inner = inner;
      if (this.closedFlag) { await inner.close(); throw new Error("MCP transport is closed"); }
      inner.onMessage(message => { if (!this.closedFlag) this.emitMessage(message); });
      inner.onError(error => { if (!this.closedFlag) this.emitError(error); });
      inner.onClose(() => { if (!this.closedFlag) this.emitClose(); });
      if (this.version !== undefined) inner.setProtocolVersion?.(this.version);
      try { await inner.start(); } catch (error) { await inner.close().catch(() => undefined); throw error; }
      if (this.closedFlag) { await inner.close(); throw new Error("MCP transport is closed"); }
    })();
    return this.pending;
  }

  override async send(message: JsonRpcMessage, options?: McpTransportSendOptions): Promise<void> {
    if (this.closedFlag || !this.inner) throw new Error("MCP transport is closed");
    await this.inner.send(message, options);
  }

  override async close(): Promise<void> {
    this.closedFlag = true;
    this.preparing?.abort();
    if (this.inner) await this.inner.close();
    if (this.pending) await this.pending.catch(() => undefined);
  }

  setProtocolVersion(value: string): void {
    this.version = value;
    this.inner?.setProtocolVersion?.(value);
  }
}

/** Owns host MCP transports and revokes them when their configuration changes. */
export class ManagedMcpTransports {
  private revision: string | undefined;
  private generation = 0;
  private readonly live = new Map<McpTransport, { retire(): void }>();
  private closing: Promise<void> = Promise.resolve();
  private blocked: unknown;

  constructor(private readonly options: ManagedMcpOptions) {}

  synchronize(): Promise<void> {
    const revision = this.options.revision();
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
    void this.closing.catch(() => undefined);
    return this.closing;
  }

  readonly createTransport: McpTransportFactory = (entry, cwd, authProvider) => {
    const captured = structuredClone(entry);
    const revision = this.options.revision();
    const generation = this.generation;
    const identity = jsonDigest(captured);
    let retired = false;
    const current = () => {
      if (retired || generation !== this.generation || revision !== this.options.revision() || identity !== jsonDigest(entry)) {
        throw new Error("plan-invalidated: MCP connection authorization has been revoked");
      }
    };
    const hasConfigCommand = "url" in captured.config
      ? Object.values(captured.config.headers ?? {}).some(value => value.startsWith("!"))
      : Object.values(captured.config.env ?? {}).some(value => value.startsWith("!"));
    const resolveValuesImmediately = (): ResolvedMcpValues => {
      if ("url" in captured.config) {
        return { headers: Object.fromEntries(Object.entries(captured.config.headers ?? {}).map(([name, value]) => [name, resolveConfigReference(value)])) };
      }
      const environment: Record<string, string> = {};
      for (const [name, value] of Object.entries(captured.config.env ?? {})) environment[name] = resolveConfigReference(value);
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
      const environment: Record<string, string> = {};
      for (const [name, value] of Object.entries(captured.config.env ?? {})) {
        current();
        environment[name] = await configValue(value, signal, runCommand);
        current();
      }
      return { environment };
    };
    const build = (values: ResolvedMcpValues): McpTransport => {
      const config = captured.config;
      if ("url" in config) {
        return new StreamableHttpTransport({ url: new URL(config.url), authProvider, headers: { ...values.headers } });
      }
      return new StdioTransport({ command: expandHome(config.command), args: (config.args ?? []).map(expandHome),
        cwd: resolve(cwd, expandHome(config.cwd ?? ".")), env: { ...values.environment }, inheritEnv: true, stderr: "pipe" });
    };
    const inner = hasConfigCommand
      ? new DeferredMcpTransport(async signal => {
          current();
          const values = await resolveValues(signal);
          current();
          return build(values);
        })
      : build(resolveValuesImmediately());
    const managed: McpTransport = {
      start: async () => {
        await this.closing;
        current();
        await inner.start();
        try { current(); } catch (error) { await inner.close(); throw error; }
      },
      send: async (message: JsonRpcMessage, options?: McpTransportSendOptions) => {
        current();
        if ("method" in message && ["tools/call", "resources/read", "resources/list", "resources/templates/list"].includes(message.method)) this.options.onRequest?.();
        try { await inner.send(message, options); }
        catch (error) {
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
}
