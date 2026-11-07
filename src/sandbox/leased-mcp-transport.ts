import { StdioTransport, type JsonRpcMessage, type McpTransport, type McpTransportSendOptions } from "@earendil-works/pi-mcp";

class LeasedStdioTransport extends StdioTransport {
  private inner: McpTransport | undefined;
  private release: (() => void) | undefined;
  private pending: Promise<void> | undefined;
  private preparing: AbortController | undefined;
  private closedFlag = false;
  private version: string | undefined;

  constructor(private readonly prepare: (signal: AbortSignal) => Promise<{ transport: McpTransport; release(): void }>) {
    // start() always replaces this placeholder; no process is launched through the base class.
    super({ command: "" });
  }

  override get stderr(): string {
    return this.inner instanceof StdioTransport ? this.inner.stderr : "";
  }

  private retire(): void {
    const action = this.release;
    this.release = undefined;
    action?.();
  }

  override start(): Promise<void> {
    if (this.pending || this.closedFlag) return Promise.reject(new Error("MCP transport is already started or closed"));
    this.preparing = new AbortController();
    this.pending = (async () => {
      const prepared = await this.prepare(this.preparing!.signal);
      this.release = prepared.release;
      this.inner = prepared.transport;
      const inner = this.inner;
      if (this.closedFlag) { this.retire(); await inner.close(); throw new Error("MCP transport is closed"); }
      inner.onMessage(message => { if (!this.closedFlag) this.emitMessage(message); });
      inner.onError(error => { if (!this.closedFlag) this.emitError(error); });
      inner.onClose(() => { this.retire(); this.emitClose(); });
      if (this.version !== undefined) inner.setProtocolVersion?.(this.version);
      try { await inner.start(); } catch (error) { this.retire(); await inner.close().catch(() => undefined); throw error; }
      if (this.closedFlag) { this.retire(); await inner.close(); throw new Error("MCP transport is closed"); }
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
    this.retire();
    if (this.inner) await this.inner.close();
    if (this.pending) await this.pending.catch(() => undefined);
  }

  setProtocolVersion(value: string): void {
    this.version = value;
    this.inner?.setProtocolVersion?.(value);
  }
}

export function leasedMcpTransport(
  prepare: (signal: AbortSignal) => Promise<{ transport: McpTransport; release(): void }>,
): StdioTransport & McpTransport {
  return new LeasedStdioTransport(prepare);
}
