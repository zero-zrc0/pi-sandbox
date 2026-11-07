import { type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { EgressService } from "#sandbox/egress/index";
import {
  ControlledMcpTransport,
  type ControlledMcpTransportOptions,
} from "#sandbox/controlled-mcp";

const IDENTITY = Object.freeze({
  sessionId: "session-1",
  serviceId: "service-1",
  serviceName: "filesystem-mcp",
  generation: 1,
  policyRevision: "p1",
  configRevision: "c1",
});

class FakeChild extends EventEmitter {
  stdin = new EventEmitter() as unknown as ChildProcess["stdin"] & {
    write(data: string, cb?: (error?: Error | null) => void): boolean;
    end(): void;
  };
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  pid = 4242;
  killed = false;
  writeCallback: ((line: string) => void) | null = null;

  constructor() {
    super();
    const self = this;
    this.stdin = Object.assign(new EventEmitter(), {
      write(data: string, cb?: (error?: Error | null) => void): boolean {
        setImmediate(() => {
          self.writeCallback?.(data);
          cb?.(null);
        });
        return true;
      },
      end(): void {
        self.emit("close");
      },
    }) as FakeChild["stdin"];
  }

  kill(): boolean {
    this.killed = true;
    this.emit("close");
    return true;
  }

  serviceSays(line: string): void {
    this.stdout.emit("data", Buffer.from(`${line}\n`));
  }
}

describe("ControlledMcpTransport", () => {
  let root: string;
  let egress: EgressService;
  let launcherPath: string;
  let child: FakeChild;
  let spawned: Array<{
    command: string;
    args: readonly string[];
    cwd: string;
    env: Readonly<Record<string, string>>;
  }>;

  function makeTransport(
    overrides: Partial<ControlledMcpTransportOptions> = {},
  ): ControlledMcpTransport {
    return new ControlledMcpTransport({
      identity: IDENTITY,
      scope: { destinations: [{ host: "api.example.com" }] },
      egress,
      launcherPath,
      cwd: root,
      command: "/usr/bin/node",
      args: ["server.mjs"],
      platform: "linux",
      ...overrides,
      spawnLauncher: overrides.spawnLauncher ?? ((input) => {
        spawned.push(input);
        child = new FakeChild();
        return child as unknown as ChildProcess;
      }),
    });
  }

  beforeEach(async () => {
    root = mkdtempSync(join(tmpdir(), "controlled-mcp-"));
    launcherPath = join(root, "linux-sandbox");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(launcherPath, "");
    writeFileSync(join(root, "linux-egress-bridge"), "");
    egress = new EgressService();
    spawned = [];
  });

  afterEach(async () => {
    await egress.dispose();
    rmSync(root, { recursive: true, force: true });
  });

  it("fails closed off Linux", async () => {
    const transport = makeTransport({ platform: "win32" });
    const result = await transport.start();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("sandbox-capability-unsupported");
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("fails closed when the bridge is missing", async () => {
    const { unlinkSync } = await import("node:fs");
    unlinkSync(join(root, "linux-egress-bridge"));
    const transport = makeTransport();
    const result = await transport.start();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("sandbox-unavailable");
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("starts one service with a fixed lease and launcher-only credentials", async () => {
    const transport = makeTransport();
    const result = await transport.start();
    expect(result).toEqual({ ok: true });
    expect(egress.activeLeaseCount).toBe(1);
    expect(transport.leaseId).toBeDefined();
    expect(spawned).toHaveLength(1);
    const launch = spawned[0];
    expect(launch.command).toBe(launcherPath);
    expect(launch.args).toContain("destinations");
    expect(launch.args).toContain("/usr/bin/node");
    expect(launch.args).toContain("server.mjs");
    expect(launch.env.PI_EGRESS_LEASE).toBe(transport.leaseId);
    expect(launch.env.PI_EGRESS_CREDENTIAL).toBeDefined();
    expect(launch.env.PI_EGRESS_PROXY).toMatch(/^127\.0\.0\.1:\d+$/u);
    await transport.close();
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("frames newline-delimited JSON-RPC in both directions", async () => {
    const transport = makeTransport();
    await transport.start();
    const messages: unknown[] = [];
    transport.onMessage((message) => messages.push(message));
    const received = new Promise<string>((resolve) => {
      child.writeCallback = (line) => resolve(line);
    });
    await transport.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    expect(await received).toBe(
      `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`,
    );
    // The native launcher's readiness marker is out-of-band: a service reply
    // that shares the first chunk with the marker still parses.
    child.stdout.emit(
      "data",
      Buffer.concat([
        Buffer.from("\x1ePI-LINUX-SANDBOX-READY\x1f"),
        Buffer.from(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } })}\n`),
      ]),
    );
    expect(messages).toEqual([{ jsonrpc: "2.0", id: 1, result: { ok: true } }]);
    child.serviceSays(JSON.stringify({ jsonrpc: "2.0", id: 3, result: { ok: true } }));
    expect(messages).toEqual([
      { jsonrpc: "2.0", id: 1, result: { ok: true } },
      { jsonrpc: "2.0", id: 3, result: { ok: true } },
    ]);
    await transport.close();
  });

  it("revokes the lease and terminates the tree on close", async () => {
    const transport = makeTransport();
    await transport.start();
    const leaseId = transport.leaseId;
    let closed = false;
    transport.onClose(() => {
      closed = true;
    });
    await transport.close();
    expect(closed).toBe(true);
    expect(child.killed).toBe(true);
    expect(egress.activeLeaseCount).toBe(0);
    expect(egress.revoke(leaseId!)).toBe(false);
  });

  it("revokes the lease when the service exits on its own", async () => {
    const transport = makeTransport();
    await transport.start();
    expect(egress.activeLeaseCount).toBe(1);
    let closed = false;
    transport.onClose(() => {
      closed = true;
    });
    child.emit("close");
    expect(closed).toBe(true);
    expect(egress.activeLeaseCount).toBe(0);
  });

  it("refuses to send after close", async () => {
    const transport = makeTransport();
    await transport.start();
    await transport.close();
    await expect(
      transport.send({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    ).rejects.toThrow("closed");
  });
});
