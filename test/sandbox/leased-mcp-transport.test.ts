import { describe, expect, it, vi } from "vitest";
import { StdioTransport, type McpTransport } from "@earendil-works/pi-mcp";
import { leasedMcpTransport } from "#sandbox/leased-mcp-transport";

describe("leased MCP transport", () => {
  it("waits for an in-flight start to settle after revoking its lease", async () => {
    let finish!: () => void;
    const started = new Promise<void>(resolve => { finish = resolve; });
    const release = vi.fn();
    const inner: McpTransport = {
      start: () => started, close: async () => {}, send: async () => {},
      onMessage: () => () => {}, onError: () => () => {}, onClose: () => () => {},
    };
    const transport = leasedMcpTransport(async () => ({ transport: inner, release }));
    const starting = transport.start();
    await Promise.resolve();
    let settled = false;
    const closing = transport.close().then(() => { settled = true; });
    await Promise.resolve();
    expect(release).toHaveBeenCalledOnce();
    expect(settled).toBe(false);
    finish();
    await expect(starting).rejects.toThrow("closed");
    await closing;
    expect(settled).toBe(true);
  });

  it("exposes the underlying stdio transport and its stderr", async () => {
    const inner = new StdioTransport({ command: process.execPath, args: ["-e", "console.error('leased-stderr-marker')"] });
    const transport = leasedMcpTransport(async () => ({ transport: inner, release: () => undefined }));
    const closed = new Promise<void>(resolve => transport.onClose(resolve));
    try {
      expect(transport).toBeInstanceOf(StdioTransport);
      await transport.start();
      await closed;
      expect(transport.stderr).toContain("leased-stderr-marker");
    } finally {
      await transport.close();
    }
  });
});
