/**
 * Controlled stdio MCP transport.
 *
 * Pi's public MCP seam lets a host replace the stdio transport factory. This
 * module is the controlled replacement: it starts one MCP service through the
 * native launcher in `destinations` mode, so the service process and its
 * descendants get the isolated network, the standalone bridge and one fixed
 * egress lease for the whole service generation. Initialization, background
 * tasks and tool calls all share that ceiling; no second approval path is
 * created — targets outside the ceiling are refused by the policy proxy.
 *
 * Only the Linux backend can express this today. Any other platform, a
 * missing bridge, or a missing lease fails closed before the service starts.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";

import { EgressService, type AcquiredEgress } from "./egress/index";
import type { EgressScope } from "./egress/types";

/** Minimal JSON-RPC surface; the host adapter maps Pi's full types onto this. */
export interface JsonRpcMessage {
  readonly jsonrpc?: string;
  readonly id?: string | number | null;
  readonly method?: string;
  readonly params?: unknown;
  readonly result?: unknown;
  readonly error?: unknown;
}

export const MCP_TRANSPORT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
export const MCP_TRANSPORT_MAX_STDERR_BYTES = 64 * 1024;

/* The native launcher announces readiness with an out-of-band marker on
 * stdout; the transport strips exactly that prefix before JSON-RPC framing. */
const LAUNCHER_READY_MARKER = Buffer.from("\x1ePI-LINUX-SANDBOX-READY\x1f");

export type ControlledMcpMessageListener = (message: JsonRpcMessage) => void;
export type ControlledMcpErrorListener = (error: Error) => void;
export type ControlledMcpCloseListener = () => void;

export interface ControlledMcpServiceIdentity {
  readonly sessionId: string;
  readonly serviceId: string;
  readonly serviceName: string;
  readonly generation: number;
  readonly policyRevision: string;
  readonly configRevision: string;
}

export interface ControlledMcpTransportOptions {
  readonly identity: ControlledMcpServiceIdentity;
  /** Fixed permission ceiling for the whole service generation. */
  readonly scope: EgressScope;
  readonly egress: EgressService;
  /** Native launcher binary (linux-sandbox). Must be host-owned. */
  readonly launcherPath: string;
  readonly cwd: string;
  readonly command: string;
  readonly args?: readonly string[];
  /** Filtered service environment; never the controller environment. */
  readonly env?: Readonly<Record<string, string>>;
  /** Read grants the service needs, expressed as launcher --read-dir paths. */
  readonly readDirs?: readonly string[];
  readonly closeTimeoutMs?: number;
  readonly now?: () => number;
  /** Test hook: pretend to run on another platform. */
  readonly platform?: string;
  /** Test hook: substitute the launcher command line. */
  readonly spawnLauncher?: (input: {
    readonly command: string;
    readonly args: readonly string[];
    readonly cwd: string;
    readonly env: Readonly<Record<string, string>>;
  }) => ChildProcess;
}

export type ControlledMcpStartResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code:
        | "sandbox-unavailable"
        | "sandbox-capability-unsupported"
        | "sandbox-start-failed";
      readonly reason: string;
    };

/**
 * One stdio MCP service generation behind the controlled executor. The
 * service sees ordinary stdio JSON-RPC; everything it can reach on the
 * network funnels through one authenticated bridge connection set.
 */
export class ControlledMcpTransport {
  private readonly options: ControlledMcpTransportOptions;
  private readonly closeTimeoutMs: number;
  private messageListeners = new Set<ControlledMcpMessageListener>();
  private errorListeners = new Set<ControlledMcpErrorListener>();
  private closeListeners = new Set<ControlledMcpCloseListener>();
  private acquired: AcquiredEgress | null = null;
  private child: ChildProcess | null = null;
  private started = false;
  private closed = false;
  private closeEmitted = false;
  private stdoutBuffer = Buffer.alloc(0);
  private readyMarkerStripped = false;
  private stderrBytes = 0;
  private stderrText = "";

  constructor(options: ControlledMcpTransportOptions) {
    this.options = options;
    this.closeTimeoutMs = options.closeTimeoutMs ?? 2_000;
  }

  get pid(): number | undefined {
    return this.child?.pid ?? undefined;
  }

  get leaseId(): string | undefined {
    return this.acquired?.grant.leaseId;
  }

  get stderr(): string {
    return this.stderrText;
  }

  onMessage(listener: ControlledMcpMessageListener): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  onError(listener: ControlledMcpErrorListener): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  onClose(listener: ControlledMcpCloseListener): () => void {
    this.closeListeners.add(listener);
    return () => this.closeListeners.delete(listener);
  }

  private emitMessage(message: JsonRpcMessage): void {
    for (const listener of [...this.messageListeners]) listener(message);
  }

  private emitError(error: Error): void {
    for (const listener of [...this.errorListeners]) listener(error);
  }

  private emitClose(): void {
    if (this.closeEmitted) return;
    this.closeEmitted = true;
    for (const listener of [...this.closeListeners]) listener();
  }

  /**
   * Acquire the generation lease and start the service inside the sandbox.
   * Every preparation failure lands before the service process exists.
   */
  async start(): Promise<ControlledMcpStartResult> {
    if (this.started) {
      return { ok: false, code: "sandbox-start-failed", reason: "transport already started" };
    }
    if (this.closed) {
      return { ok: false, code: "sandbox-start-failed", reason: "transport is closed" };
    }
    if ((this.options.platform ?? process.platform) !== "linux") {
      return {
        ok: false,
        code: "sandbox-capability-unsupported",
        reason: "controlled MCP egress is implemented only by the Linux backend",
      };
    }
    if (!existsSync(this.options.launcherPath)) {
      return {
        ok: false,
        code: "sandbox-unavailable",
        reason: `native launcher is missing: ${this.options.launcherPath}`,
      };
    }
    const bridgePath = joinSameDirectory(this.options.launcherPath, "linux-egress-bridge");
    if (!existsSync(bridgePath)) {
      return {
        ok: false,
        code: "sandbox-unavailable",
        reason: `egress bridge is missing: ${bridgePath}`,
      };
    }
    const acquired = await this.options.egress.acquireForService({
      ...this.options.identity,
      scope: this.options.scope,
    });
    if (!acquired) {
      return {
        ok: false,
        code: "sandbox-capability-unsupported",
        reason: "egress service could not issue a lease for this MCP service generation",
      };
    }
    this.acquired = acquired;
    this.started = true;

    const launchEnv: Record<string, string> = {
      PI_EGRESS_PROXY: `${acquired.grant.proxyHost}:${acquired.grant.proxyPort}`,
      PI_EGRESS_LEASE: acquired.grant.leaseId,
      PI_EGRESS_CREDENTIAL: acquired.grant.credential,
    };
    const launchArgs: string[] = [
      "run",
      "--network",
      "destinations",
      "--cwd",
      this.options.cwd,
    ];
    for (const dir of this.options.readDirs ?? []) {
      launchArgs.push("--read-dir", dir);
    }
    launchArgs.push("--", this.options.command, ...(this.options.args ?? []));

    const spawnFn =
      this.options.spawnLauncher ??
      ((input: { command: string; args: readonly string[]; cwd: string; env: Readonly<Record<string, string>> }) =>
        spawn(input.command, [...input.args], {
          cwd: input.cwd,
          env: { ...input.env },
          stdio: ["pipe", "pipe", "pipe"],
          detached: true,
          shell: false,
        }));
    const child = spawnFn({
      command: this.options.launcherPath,
      args: launchArgs,
      cwd: this.options.cwd,
      env: launchEnv,
    });
    this.child = child;
    child.stdout?.on("data", (chunk: Buffer | string) => this.handleStdout(chunk));
    child.stdout?.on("error", (error: Error) => this.emitError(error));
    child.stderr?.on("data", (chunk: Buffer | string) => this.handleStderr(chunk));
    child.stderr?.on("error", (error: Error) => this.emitError(error));
    child.stdin?.on("error", (error: Error) => {
      if (!this.closed) this.emitError(error);
    });
    child.on("error", (error: Error) => {
      this.emitError(error);
      this.emitClose();
    });
    child.on("close", () => {
      this.child = null;
      this.revokeLease();
      this.emitClose();
    });
    return { ok: true };
  }

  /** JSON-RPC over newline-delimited stdio, like the plain stdio transport. */
  async send(message: JsonRpcMessage): Promise<void> {
    if (this.closed || !this.child?.stdin) {
      throw new Error("controlled MCP transport is closed");
    }
    const line = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(line, "utf8") > MCP_TRANSPORT_MAX_MESSAGE_BYTES) {
      throw new Error("MCP message exceeds the transport limit");
    }
    await new Promise<void>((resolve, reject) => {
      this.child!.stdin!.write(line, (error) => (error ? reject(error) : resolve()));
    });
  }

  /**
   * Revoke the generation lease and terminate the service tree. The old
   * generation is fully gone before a new one may start; the bridge and
   * service are never rebuilt while the service keeps running.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.revokeLease();
    const child = this.child;
    if (!child) {
      this.emitClose();
      return;
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        killTree(child, this.platform, "SIGKILL");
        resolve();
      }, this.closeTimeoutMs);
      timer.unref?.();
      child.once("close", () => {
        clearTimeout(timer);
        resolve();
      });
      killTree(child, this.platform, "SIGTERM");
      child.stdin?.end();
    });
    this.emitClose();
  }

  private get platform(): string {
    return this.options.platform ?? process.platform;
  }

  private revokeLease(): void {
    const acquired = this.acquired;
    if (!acquired) return;
    this.acquired = null;
    this.options.egress.revoke(acquired.grant.leaseId);
  }

  private handleStdout(chunk: Buffer | string): void {
    this.stdoutBuffer = Buffer.concat([
      this.stdoutBuffer,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8"),
    ]);
    if (this.stdoutBuffer.length > MCP_TRANSPORT_MAX_MESSAGE_BYTES) {
      this.emitError(new Error("MCP stdout exceeded the message limit"));
      this.stdoutBuffer = Buffer.alloc(0);
      return;
    }
    if (!this.readyMarkerStripped) {
      const prefixLength = Math.min(LAUNCHER_READY_MARKER.length, this.stdoutBuffer.length);
      if (
        !LAUNCHER_READY_MARKER.subarray(0, prefixLength).equals(
          this.stdoutBuffer.subarray(0, prefixLength),
        )
      ) {
        // Not the launcher's readiness stream; parse from the first byte.
        this.readyMarkerStripped = true;
      } else if (this.stdoutBuffer.length >= LAUNCHER_READY_MARKER.length) {
        this.stdoutBuffer = this.stdoutBuffer.subarray(LAUNCHER_READY_MARKER.length);
        this.readyMarkerStripped = true;
      } else {
        return; // wait for the rest of the marker
      }
    }
    for (;;) {
      const newline = this.stdoutBuffer.indexOf(0x0a);
      if (newline < 0) return;
      const line = this.stdoutBuffer.subarray(0, newline).toString("utf8").trim();
      this.stdoutBuffer = this.stdoutBuffer.subarray(newline + 1);
      if (!line) continue;
      try {
        this.emitMessage(JSON.parse(line) as JsonRpcMessage);
      } catch (error) {
        this.emitError(error instanceof Error ? error : new Error(String(error)));
      }
    }
  }

  private handleStderr(chunk: Buffer | string): void {
    const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk;
    const next = this.stderrBytes + Buffer.byteLength(text, "utf8");
    if (next <= MCP_TRANSPORT_MAX_STDERR_BYTES) {
      this.stderrText += text;
      this.stderrBytes = next;
    }
  }
}

function joinSameDirectory(filePath: string, name: string): string {
  const normalized = filePath.replace(/\\/gu, "/");
  const split = normalized.lastIndexOf("/");
  return split < 0 ? name : `${normalized.slice(0, split + 1)}${name}`;
}

function killTree(
  child: ChildProcess,
  platform: string,
  signal: NodeJS.Signals = "SIGKILL",
): void {
  const pid = child.pid;
  if (pid === undefined) return;
  try {
    if (platform === "win32") {
      spawn("taskkill", ["/pid", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      }).on("error", () => {});
      return;
    }
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // The process group is gone; fall through to the direct child.
    }
    child.kill(signal);
  } catch {
    // Already dead.
  }
}
