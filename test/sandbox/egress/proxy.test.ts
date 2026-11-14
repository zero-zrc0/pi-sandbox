import { createServer, createConnection, type Server, type Socket } from "node:net";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { EgressLeaseRegistry } from "#sandbox/egress/leases";
import { EgressProxyServer } from "#sandbox/egress/proxy";
import {
  type EgressBinding,
  type EgressLease,
  type EgressNetworkEvent,
} from "#sandbox/egress/types";

const BINDING: EgressBinding = Object.freeze({
  sessionId: "session-1",
  requestId: "request-1",
  actor: "tool",
  actorName: "bash",
  generation: 1,
  policyRevision: "policy-r1",
  configRevision: "config-r1",
});

async function readUntil(
  socket: Socket,
  predicate: (buffer: Buffer) => boolean,
  timeoutMs = 3_000,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`read timeout (${buffer.toString("latin1").slice(0, 120)})`));
    }, timeoutMs);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      if (predicate(buffer)) {
        cleanup();
        resolve(buffer);
      }
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onClose = (): void => {
      cleanup();
      resolve(buffer);
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

describe("EgressProxyServer", () => {
  let registry: EgressLeaseRegistry;
  let proxy: EgressProxyServer;
  let proxyPort = 0;
  let events: EgressNetworkEvent[];
  let httpServer: HttpServer;
  let httpPort = 0;
  let httpConnections: Socket[];
  let deniedListener: Server;
  let deniedConnections: number;
  let lease: EgressLease;
  let targets: Array<{ close(): Promise<void> }>;

  function acquire(
    destinations: readonly { host: string; port?: number }[],
  ): EgressLease {
    return registry.acquire(BINDING, { destinations }).lease;
  }

  function authFrame(target: EgressLease): Buffer {
    return Buffer.from(`PIEGRESS1 ${target.leaseId} ${target.credential}\n`);
  }

  function connectProxy(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port: proxyPort });
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
    });
  }

  beforeEach(async () => {
    events = [];
    targets = [];
    httpConnections = [];
    registry = new EgressLeaseRegistry();
    proxy = new EgressProxyServer({
      registry,
      onEvent: (event) => events.push(event),
    });
    const started = await proxy.start();
    if (!started.ok) throw new Error(started.reason);
    proxyPort = started.port;

    httpServer = createHttpServer((request, response) => {
      if (request.url === "/hello") {
        response.writeHead(200, { "content-type": "text/plain" });
        response.end("hello-through-proxy");
        return;
      }
      response.writeHead(404);
      response.end("missing");
    });
    await new Promise<void>((done) =>
      httpServer.listen(0, "127.0.0.1", () => done()),
    );
    const address = httpServer.address();
    if (typeof address === "string" || address === null) throw new Error("no address");
    httpPort = address.port;
    httpServer.on("connection", (socket) => httpConnections.push(socket));
    targets.push({
      close: () => new Promise((done) => httpServer.close(() => done())),
    });

    deniedConnections = 0;
    deniedListener = createServer(() => {
      deniedConnections += 1;
    });
    await new Promise<void>((done) =>
      deniedListener.listen(0, "127.0.0.1", () => done()),
    );
    targets.push({
      close: () => new Promise((done) => deniedListener.close(() => done())),
    });

    lease = acquire([{ host: "127.0.0.1", port: httpPort }]);
  });

  afterEach(async () => {
    registry.closeAll();
    await proxy.close();
    for (const target of targets) await target.close();
  });

  it("proxies an absolute-form HTTP request to an allowed destination", async () => {
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    socket.write(
      `GET http://127.0.0.1:${httpPort}/hello HTTP/1.1\r\nHost: 127.0.0.1:${httpPort}\r\nProxy-Authorization: Basic cm9vdA==\r\n\r\n`,
    );
    const response = await readUntil(
      socket,
      (buffer) => buffer.includes("hello-through-proxy"),
    );
    expect(response.toString("latin1")).toContain("200");
    expect(response.toString("latin1")).toContain("hello-through-proxy");
    expect(response.toString("latin1")).not.toContain("cm9vdA==");
    expect(httpConnections).toHaveLength(1);
    expect(events.map((event) => event.result)).toContain("connected");
    socket.destroy();
  });

  it("checks the exact port and refuses before any external connection", async () => {
    const deniedAddress = deniedListener.address();
    if (typeof deniedAddress === "string" || deniedAddress === null) throw new Error("no address");
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    socket.write(
      `GET http://127.0.0.1:${deniedAddress.port}/ HTTP/1.1\r\nHost: x\r\n\r\n`,
    );
    const response = await readUntil(socket, (buffer) => buffer.includes("403"));
    expect(response.toString("latin1")).toContain("403");
    await new Promise((done) => setTimeout(done, 150));
    expect(deniedConnections).toBe(0);
    expect(events.some((event) => event.result === "denied")).toBe(true);
    socket.destroy();
  });

  it("tunnels an allowed CONNECT target", async () => {
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    socket.write(`CONNECT 127.0.0.1:${httpPort} HTTP/1.1\r\nHost: x\r\n\r\n`);
    const established = await readUntil(socket, (buffer) =>
      buffer.includes("200 Connection Established"),
    );
    expect(established.toString("latin1")).toContain("200");
    socket.write(
      `GET /hello HTTP/1.1\r\nHost: 127.0.0.1:${httpPort}\r\nConnection: close\r\n\r\n`,
    );
    const response = await readUntil(
      socket,
      (buffer) => buffer.includes("hello-through-proxy"),
    );
    expect(response.toString("latin1")).toContain("hello-through-proxy");
    socket.destroy();
  });

  it("speaks SOCKS5 CONNECT with IPv4 and domain address forms", async () => {
    for (const atyp of [0x01, 0x03]) {
      const socket = await connectProxy();
      socket.write(authFrame(lease));
      // Register the reader before writing: loopback replies can arrive
      // before a listener attaches.
      const greetingReply = readUntil(socket, (buffer) => buffer.length >= 2);
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
      await greetingReply;
      const request =
        atyp === 0x01
          ? Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]),
              Buffer.from([(httpPort >> 8) & 0xff, httpPort & 0xff]),
            ])
          : Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x03, 9]),
              Buffer.from("127.0.0.1"),
              Buffer.from([(httpPort >> 8) & 0xff, httpPort & 0xff]),
            ]);
      const grantedReply = readUntil(socket, (buffer) => buffer.length >= 10);
      socket.write(request);
      const granted = await grantedReply;
      expect(granted.subarray(0, 2).toString("hex")).toBe("0500");
      const httpReply = readUntil(socket, (buffer) =>
        buffer.includes("hello-through-proxy"),
      );
      socket.write(
        `GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`,
      );
      const response = await httpReply;
      expect(response.toString("latin1")).toContain("hello-through-proxy");
      socket.destroy();
    }
  });

  it("dispatches SOCKS5 when the greeting arrives after the auth frame", async () => {
    // Regression: an empty buffer at dispatch time must not misroute SOCKS5
    // to the HTTP parser.
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    await new Promise((done) => setTimeout(done, 100));
    const greetingReply = readUntil(socket, (buffer) => buffer.length >= 2);
    socket.write(Buffer.from([0x05, 0x01, 0x00]));
    const greeting = await greetingReply;
    expect(greeting.subarray(0, 2).toString("hex")).toBe("0500");
    socket.destroy();
  });

  it("closes an incomplete SOCKS greeting and frees the connection slot", async () => {
    const timedProxy = new EgressProxyServer({ registry, maxConnections: 1, handshakeTimeoutMs: 40 });
    const started = await timedProxy.start();
    if (!started.ok) throw new Error(started.reason);
    const connect = (): Promise<Socket> => new Promise((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port: started.port });
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
    });
    const waitForCount = async (count: number): Promise<void> => {
      const deadline = Date.now() + 500;
      while (timedProxy.activeCount !== count && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(timedProxy.activeCount).toBe(count);
    };
    try {
      const timedOut = await connect();
      timedOut.on("error", () => undefined);
      const timedOutClosed = new Promise<void>((resolve) => timedOut.once("close", resolve));
      timedOut.write(authFrame(lease));
      timedOut.write(Buffer.from([0x05]));
      const closed = await Promise.race([
        timedOutClosed.then(() => true),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 500)),
      ]);

      expect(closed).toBe(true);
      await waitForCount(0);

      const next = await connect();
      next.on("error", () => undefined);
      const greetingReply = readUntil(next, (buffer) => buffer.length >= 2);
      next.write(authFrame(lease));
      next.write(Buffer.from([0x05, 0x01, 0x00]));
      expect((await greetingReply).subarray(0, 2).toString("hex")).toBe("0500");
      expect(timedProxy.activeCount).toBe(1);
      const nextClosed = new Promise<void>((resolve) => next.once("close", resolve));
      next.destroy();
      await nextClosed;
      await waitForCount(0);

      const invalid = await connect();
      invalid.on("error", () => undefined);
      const invalidGreeting = readUntil(invalid, (buffer) => buffer.length >= 2);
      invalid.write(authFrame(lease));
      invalid.write(Buffer.from([0x05, 0x01, 0x00]));
      await invalidGreeting;
      const invalidReply = readUntil(invalid, (buffer) => buffer.length >= 10);
      const invalidClosed = new Promise<void>((resolve) => invalid.once("close", resolve));
      invalid.write(Buffer.from([0x05, 0x01, 0x00, 0x7f]));
      expect((await invalidReply)[1]).toBe(0x08);
      await invalidClosed;
      await waitForCount(0);
    } finally {
      await timedProxy.close();
    }
  });

  it("refuses SOCKS5 targets outside the scope", async () => {
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    const greetingReply = readUntil(socket, (buffer) => buffer.length >= 2);
    socket.write(Buffer.from([0x05, 0x01, 0x00]));
    await greetingReply;
    const deniedReply = readUntil(socket, (buffer) => buffer.length >= 2);
    socket.write(
      Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]),
        Buffer.from([0x1f, 0x41]),
      ]),
    );
    const reply = await deniedReply;
    expect(reply[1]).toBe(0x02);
    expect(events.some((event) => event.result === "denied")).toBe(true);
    socket.destroy();
  });

  it("rejects connections with an unknown or revoked credential", async () => {
    const socket = await connectProxy();
    socket.write(Buffer.from(`PIEGRESS1 ${lease.leaseId} wrong-credential\n`));
    const data = await readUntil(socket, () => false, 500);
    expect(data.length).toBe(0);
    expect(events.some((event) => event.result === "auth-failed")).toBe(true);

    const revoked = acquire([{ host: "127.0.0.1", port: httpPort }]);
    registry.revoke(revoked.leaseId);
    const second = await connectProxy();
    second.write(authFrame(revoked));
    const data2 = await readUntil(second, () => false, 500);
    expect(data2.length).toBe(0);
  });

  it("releases each rejected connection slot exactly once", async () => {
    const socket = await connectProxy();
    const closed = new Promise<void>((resolve) => socket.once("close", resolve));
    socket.write(Buffer.from(`PIEGRESS1 ${lease.leaseId} wrong-credential\n`));
    await closed;
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(proxy.activeCount).toBe(0);
  });

  it("preserves HTTP body bytes received while DNS is pending", async () => {
    let receivedBody = "";
    let targetConnected!: () => void;
    const targetReady = new Promise<void>((resolve) => { targetConnected = resolve; });
    const target = createHttpServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        receivedBody = Buffer.concat(chunks).toString("utf8");
        response.end("captured");
      });
    });
    target.on("connection", targetConnected);
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
    const address = target.address();
    if (typeof address === "string" || address === null) throw new Error("no address");
    targets.push({ close: () => new Promise((resolve) => target.close(() => resolve())) });

    let lookupStarted!: () => void;
    const resolving = new Promise<void>((resolve) => { lookupStarted = resolve; });
    let finishLookup!: (addresses: readonly string[]) => void;
    const addresses = new Promise<readonly string[]>((resolve) => { finishLookup = resolve; });
    const delayedProxy = new EgressProxyServer({
      registry,
      lookup: async () => {
        lookupStarted();
        return addresses;
      },
    });
    const started = await delayedProxy.start();
    if (!started.ok) throw new Error(started.reason);

    const delayedLease = acquire([
      { host: "slow.example" },
      { host: "127.0.0.1", port: address.port },
    ]);
    const socket = await new Promise<Socket>((resolve, reject) => {
      const candidate = createConnection({ host: "127.0.0.1", port: started.port });
      candidate.once("connect", () => resolve(candidate));
      candidate.once("error", reject);
    });
    try {
      socket.write(authFrame(delayedLease));
      socket.write(
        `POST http://slow.example:${address.port}/ HTTP/1.1\r\nHost: slow.example\r\nContent-Length: 6\r\n\r\nab`,
      );
      await resolving;
      socket.write("cd");
      await new Promise<void>((resolve) => setImmediate(resolve));
      finishLookup(["127.0.0.1"]);
      await targetReady;
      socket.write("ef");

      const response = await readUntil(socket, (buffer) => buffer.includes("captured"));

      expect(response.toString("latin1")).toContain("captured");
      expect(receivedBody).toBe("abcdef");
    } finally {
      socket.destroy();
      await delayedProxy.close();
    }
  });

  it("closes live connections when the lease is revoked", async () => {
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    socket.write(`CONNECT 127.0.0.1:${httpPort} HTTP/1.1\r\n\r\n`);
    await readUntil(socket, (buffer) => buffer.includes("200"));
    registry.revoke(lease.leaseId);
    const rest = await readUntil(socket, () => false, 500);
    expect(rest.length).toBe(0);
  });

  it("closes unauthenticated sockets before completing proxy shutdown", async () => {
    const socket = await connectProxy();
    const closed = new Promise<void>((resolve) => socket.once("close", resolve));
    await new Promise<void>((resolve) => setImmediate(resolve));

    await proxy.close();
    await closed;

    expect(proxy.activeCount).toBe(0);
  });

  it("enforces the per-lease connection bound", async () => {
    const bounded = new EgressLeaseRegistry({ maxConnectionsPerLease: 1 });
    const boundedProxy = new EgressProxyServer({ registry: bounded });
    const started = await boundedProxy.start();
    if (!started.ok) throw new Error(started.reason);
    try {
      const single = bounded.acquire(BINDING, {
        destinations: [{ host: "127.0.0.1", port: httpPort }],
      }).lease;
      const first = await new Promise<Socket>((resolve, reject) => {
        const socket = createConnection({ host: "127.0.0.1", port: started.port });
        socket.once("connect", () => resolve(socket));
        socket.once("error", reject);
      });
      first.write(authFrame(single));
      first.write(`CONNECT 127.0.0.1:${httpPort} HTTP/1.1\r\n\r\n`);
      await readUntil(first, (buffer) => buffer.includes("200"));
      const second = await new Promise<Socket>((resolve, reject) => {
        const socket = createConnection({ host: "127.0.0.1", port: started.port });
        socket.once("connect", () => resolve(socket));
        socket.once("error", reject);
      });
      second.write(authFrame(single));
      second.write(`CONNECT 127.0.0.1:${httpPort} HTTP/1.1\r\n\r\n`);
      const reply = await readUntil(second, () => false, 500);
      expect(reply.length).toBe(0);
      first.destroy();
      second.destroy();
    } finally {
      bounded.closeAll();
      await boundedProxy.close();
    }
  });

  it("serves an internal domain whose private address is explicitly granted", async () => {
    // 内网服务形态：scope 同时批域名与其解析出的私网地址字面量；代理在
    // 宿主侧解析（注入 lookup 模拟内网 DNS），pinned 后连通真实目标。
    const internal = new EgressLeaseRegistry();
    const internalProxy = new EgressProxyServer({
      registry: internal,
      lookup: async () => ["127.0.0.1"],
    });
    const started = await internalProxy.start();
    if (!started.ok) throw new Error(started.reason);
    try {
      const internalLease = internal.acquire(BINDING, {
        destinations: [
          { host: "intra.example" },
          { host: "127.0.0.1", port: httpPort },
        ],
      }).lease;
      const socket = await new Promise<Socket>((resolve, reject) => {
        const candidate = createConnection({ host: "127.0.0.1", port: started.port });
        candidate.once("connect", () => resolve(candidate));
        candidate.once("error", reject);
      });
      const responseReady = readUntil(
        socket,
        (buffer) => buffer.includes("hello-through-proxy"),
      );
      socket.write(authFrame(internalLease));
      socket.write(
        `GET http://intra.example:${httpPort}/hello HTTP/1.1\r\nHost: intra.example\r\n\r\n`,
      );
      const response = await responseReady;
      expect(response.toString("latin1")).toContain("200");
      socket.destroy();
    } finally {
      internal.closeAll();
      await internalProxy.close();
    }
  });

  it("attributes events to the lease identity without leaking the credential", async () => {
    const socket = await connectProxy();
    socket.write(authFrame(lease));
    socket.write(
      `GET http://127.0.0.1:${httpPort}/hello HTTP/1.1\r\nHost: x\r\n\r\n`,
    );
    await readUntil(socket, (buffer) => buffer.includes("hello-through-proxy"));
    socket.destroy();
    await new Promise((done) => setTimeout(done, 100));
    const targetEvents = events.filter((event) => event.leaseId === lease.leaseId);
    expect(targetEvents.length).toBeGreaterThan(0);
    expect(targetEvents.every((event) => event.actor === "tool")).toBe(true);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(lease.credential);
  });
});
