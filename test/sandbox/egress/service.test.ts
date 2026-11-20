import { describe, expect, it } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createConnection, createServer as createTcpServer } from "node:net";
import { once } from "node:events";

import { EgressService } from "#sandbox/egress/index";
import type { ExecutionRequest } from "#sandbox/types";
import {
  compileTestRequest,
  makeInvocation,
} from "../fixtures/harness";

const PLAN_WORKSPACE = join(tmpdir(), "egress-service-plan-workspace");

function destinationPlan(workspace: string, host: string, port?: number): ExecutionRequest {
  const destination = port === undefined ? { host } : { host, port };
  return compileTestRequest({
    invocation: makeInvocation({
      cwd: workspace,
      toolName: "bash",
      args: { command: "curl example" },
      scopes: [
        {
          id: "scope-1",
          surface: "test",
          target: port === undefined ? host : `${host}:${port}`,
          access: "network",
          state: "allow",
          source: "test",
        },
      ],
    }),
    operation: { kind: "shell", command: "curl example" },
    workspace,
    baselineFilesystem: [{ path: workspace, access: "read", granularity: "directory" }],
    approved: { network: [destination] },
    environment: {},
  });
}

describe("EgressService", () => {
  it("closes an active tunnel and its entry when its lease is revoked", async () => {
    const target = createTcpServer(socket => socket.on("error", () => undefined));
    target.listen(0, "127.0.0.1"); await once(target, "listening");
    const address = target.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const service = new EgressService();
    try {
      const acquired = await service.acquireForPlan(destinationPlan(PLAN_WORKSPACE, "127.0.0.1", address.port));
      const forwarder = await service.openForwarder(acquired!.grant);
      const socket = createConnection(forwarder.port, "127.0.0.1");
      await once(socket, "connect");
      socket.write(`CONNECT 127.0.0.1:${address.port} HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\n\r\n`);
      const [response] = await once(socket, "data");
      expect(response.toString()).toContain("200");
      const closed = once(socket, "close");
      service.revoke(acquired!.grant.leaseId);
      await closed;
      expect(service.activeLeaseCount).toBe(0);
      const after = createConnection(forwarder.port, "127.0.0.1");
      await expect(once(after, "connect")).rejects.toThrow();
    } finally {
      await service.dispose();
      await new Promise<void>(resolve => target.close(() => resolve()));
    }
  });
  it("shares one proxy across concurrent leases and revokes each forwarding endpoint", async () => {
    const target = createServer((_request, response) => response.end("allowed"));
    target.listen(0, "127.0.0.1");
    await once(target, "listening");
    const address = target.address();
    if (!address || typeof address === "string") throw new Error("no address");
    const service = new EgressService();
    try {
      const [first, second] = await Promise.all([
        service.acquireForPlan(destinationPlan(PLAN_WORKSPACE, "127.0.0.1", address.port)),
        service.acquireForPlan(destinationPlan(PLAN_WORKSPACE, "other.example", 443)),
      ]);
      expect(first).not.toBeNull();
      expect(second).not.toBeNull();
      expect(first!.grant.proxyPort).toBe(second!.grant.proxyPort);
      const [forwarder, other] = await Promise.all([service.openForwarder(first!.grant), service.openForwarder(second!.grant)]);
      expect(forwarder.port).not.toBe(other.port);
      const request = async (port: number) => {
        const socket = createConnection(port, "127.0.0.1");
        await once(socket, "connect");
        socket.write(`GET http://127.0.0.1:${address.port}/ HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\nConnection: close\r\n\r\n`);
        let data = "";
        socket.on("data", chunk => data += chunk);
        await once(socket, "close");
        return data;
      };
      expect(await request(forwarder.port)).toContain("allowed");
      expect(await request(other.port)).not.toContain("allowed");
      service.revoke(first!.grant.leaseId);
      await expect(service.openForwarder(first!.grant)).rejects.toThrow("unavailable");
      const refused = createConnection(forwarder.port, "127.0.0.1");
      await expect(once(refused, "connect")).rejects.toThrow();
      service.revoke(second!.grant.leaseId);
    } finally {
      await service.dispose();
      await new Promise<void>(resolve => target.close(() => resolve()));
    }
  });
  it("returns null for plans without destinations", async () => {
    const service = new EgressService();
    const request = destinationPlan(PLAN_WORKSPACE, "api.example.com");
    const noDestinations = { ...request, plan: { ...request.plan, network: { kind: "none" } } } as ExecutionRequest;
    expect(await service.acquireForPlan(noDestinations)).toBeNull();
    await service.dispose();
  });

  it("acquires a grant for a destinations plan", async () => {
    const service = new EgressService();
    const plan = destinationPlan(PLAN_WORKSPACE, "api.example.com", 443);
    const acquired = await service.acquireForPlan(plan);
    expect(acquired).not.toBeNull();
    expect(acquired!.grant.proxyHost).toBe("127.0.0.1");
    expect(acquired!.grant.proxyPort).toBeGreaterThan(0);
    expect(acquired!.grant.leaseId).toBe(acquired!.lease.leaseId);
    expect(acquired!.lease.scope.destinations).toEqual([
      { host: "api.example.com", port: 443, source: "approved-extension" },
    ]);
    expect(service.activeLeaseCount).toBe(1);
    service.revoke(acquired!.grant.leaseId);
    expect(service.activeLeaseCount).toBe(0);
    await service.dispose();
  });

  it("revokes a service lease through closeSession", async () => {
    const service = new EgressService();
    const acquired = await service.acquireForService({
      sessionId: "session-1",
      serviceId: "service-1",
      serviceName: "filesystem-mcp",
      generation: 2,
      policyRevision: "p1",
      configRevision: "c1",
      scope: { destinations: [{ host: "api.example.com" }] },
    });
    expect(acquired).not.toBeNull();
    expect(acquired!.lease.binding.actor).toBe("mcp-service");
    expect(acquired!.lease.binding.actorName).toBe("filesystem-mcp");
    expect(service.closeSession("session-1")).toEqual([acquired!.grant.leaseId]);
    await service.dispose();
  });

  it("emits network events through the host sink", async () => {
    const seen: string[] = [];
    const service = new EgressService({
      onEvent: (event) => seen.push(`${event.result}:${event.actorName}`),
    });
    const plan = destinationPlan(PLAN_WORKSPACE, "api.example.com");
    const acquired = await service.acquireForPlan(plan);
    expect(acquired).not.toBeNull();
    service.revoke(acquired!.grant.leaseId);
    await service.dispose();
  });
});
