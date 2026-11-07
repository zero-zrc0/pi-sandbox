/**
 * Host policy proxy for controlled network egress.
 *
 * One proxy listener serves every lease on a loopback port. Each bridge
 * authenticates its upstream connection with a private credential frame; the
 * proxy then speaks HTTP forward-proxy (plain requests and CONNECT tunnels)
 * or SOCKS5 CONNECT on the same port. Every new target is normalized, checked
 * against the lease's frozen scope, resolved and pinned before connect.
 * Targets outside the scope are refused before DNS and before any external
 * connection exists.
 */
import { createServer, createConnection, type Server, type Socket } from "node:net";

import { EgressLeaseRegistry } from "./leases";
import {
  destinationMatches,
  normalizeTarget,
  resolveTargetAddress,
  type NormalizedTarget,
} from "./target";
import {
  EGRESS_AUTH_FRAME_MAX_BYTES,
  EGRESS_AUTH_FRAME_PREFIX,
  EGRESS_CONNECT_TIMEOUT_MS,
  EGRESS_HANDSHAKE_TIMEOUT_MS,
  EGRESS_HTTP_HEADLINE_MAX_BYTES,
  EGRESS_MAX_CONNECTIONS_TOTAL,
  type EgressLease,
  type EgressNetworkEvent,
} from "./types";

const CRLF = "\r\n";

interface ConnectionPair {
  upstream: Socket | null;
  ended: boolean;
  closed: Promise<void>;
  destroy(): void;
}

export interface EgressProxyOptions {
  readonly registry: EgressLeaseRegistry;
  readonly host?: string;
  readonly onEvent?: (event: EgressNetworkEvent) => void;
  readonly maxConnections?: number;
  readonly handshakeTimeoutMs?: number;
  readonly connectTimeoutMs?: number;
  readonly now?: () => number;
  /** DNS override, primarily for deterministic tests. */
  readonly lookup?: (host: string) => Promise<readonly string[]>;
}

export type EgressProxyStartResult =
  | { readonly ok: true; readonly host: string; readonly port: number }
  | { readonly ok: false; readonly reason: string };

/**
 * One policy proxy bound to one loopback port. `start` resolves once the
 * listener is live; `close` frees the port and destroys every connection.
 */
export class EgressProxyServer {
  private readonly registry: EgressLeaseRegistry;
  private readonly bindHost: string;
  private readonly onEvent?: (event: EgressNetworkEvent) => void;
  private readonly maxConnections: number;
  private readonly handshakeTimeoutMs: number;
  private readonly connectTimeoutMs: number;
  private readonly now: () => number;
  private readonly lookup?: (host: string) => Promise<readonly string[]>;
  private server: Server | null = null;
  private activeConnections = 0;
  private readonly clients = new Set<Socket>();
  private started = false;

  constructor(options: EgressProxyOptions) {
    this.registry = options.registry;
    this.bindHost = options.host ?? "127.0.0.1";
    this.onEvent = options.onEvent;
    this.maxConnections = options.maxConnections ?? EGRESS_MAX_CONNECTIONS_TOTAL;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? EGRESS_HANDSHAKE_TIMEOUT_MS;
    this.connectTimeoutMs = options.connectTimeoutMs ?? EGRESS_CONNECT_TIMEOUT_MS;
    this.now = options.now ?? Date.now;
    this.lookup = options.lookup;
  }

  start(): Promise<EgressProxyStartResult> {
    if (this.started) {
      return Promise.resolve({ ok: false, reason: "proxy already started" });
    }
    this.started = true;
    return new Promise((resolve) => {
      const server = createServer((socket) => this.accept(socket));
      server.on("error", (error) => {
        if (!this.server) {
          resolve({ ok: false, reason: `egress proxy listen failed: ${error.message}` });
          return;
        }
        this.emit({
          leaseId: "-",
          sessionId: "-",
          actor: "tool",
          actorName: "-",
          generation: 0,
          result: "error",
          reason: `server error: ${error.message}`,
          at: this.now(),
        });
      });
      server.listen(0, this.bindHost, () => {
        server.unref();
        const address = server.address();
        if (typeof address === "string" || address === null) {
          resolve({ ok: false, reason: "egress proxy has no TCP address" });
          return;
        }
        this.server = server;
        resolve({ ok: true, host: this.bindHost, port: address.port });
      });
    });
  }

  get activeCount(): number {
    return this.activeConnections;
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = null;
    const closed = server
      ? new Promise<void>((done) => server.close(() => done()))
      : Promise.resolve();
    const clients = [...this.clients];
    const clientClosures = clients.map((socket) => new Promise<void>((resolve) => {
      if (socket.destroyed) resolve();
      else socket.once("close", () => resolve());
    }));
    for (const socket of clients) socket.destroy();
    await Promise.all([closed, ...clientClosures]);
  }

  private emit(event: EgressNetworkEvent): void {
    try {
      this.onEvent?.(event);
    } catch {
      // The audit sink never breaks the data path.
    }
  }

  private eventFor(
    lease: EgressLease,
    result: EgressNetworkEvent["result"],
    extra?: { target?: NormalizedTarget; reason?: string },
  ): EgressNetworkEvent {
    return {
      leaseId: lease.leaseId,
      sessionId: lease.binding.sessionId,
      actor: lease.binding.actor,
      actorName: lease.binding.actorName,
      generation: lease.binding.generation,
      ...(extra?.target === undefined
        ? {}
        : { targetHost: extra.target.host, targetPort: extra.target.port }),
      result,
      ...(extra?.reason === undefined ? {} : { reason: extra.reason }),
      at: this.now(),
    };
  }

  private accept(socket: Socket): void {
    if (this.activeConnections >= this.maxConnections) {
      socket.destroy();
      return;
    }
    this.activeConnections += 1;
    this.clients.add(socket);
    socket.setNoDelay(true);
    const handshakeTimer = setTimeout(() => {
      socket.destroy();
    }, this.handshakeTimeoutMs);
    handshakeTimer.unref?.();
    const release = (): void => {
      if (!this.clients.delete(socket)) return;
      clearTimeout(handshakeTimer);
      this.activeConnections -= 1;
    };
    socket.once("close", release);
    socket.once("error", () => socket.destroy());
    this.readAuthFrame(socket)
      .then((frame) => {
        if (!frame) return;
        clearTimeout(handshakeTimer);
        this.serve(socket, frame.lease, frame.buffered);
      })
      .catch(() => {
        socket.destroy();
      });
  }

  private readAuthFrame(
    socket: Socket,
  ): Promise<{ lease: EgressLease; buffered: Buffer } | null> {
    return new Promise((resolve, reject) => {
      let buffered = Buffer.alloc(0);
      let settled = false;
      const onData = (chunk: Buffer): void => {
        if (settled) return;
        buffered = Buffer.concat([buffered, chunk]);
        const newline = buffered.indexOf(0x0a);
        if (newline < 0) {
          if (buffered.length > EGRESS_AUTH_FRAME_MAX_BYTES) {
            settled = true;
            cleanup();
            reject(new Error("auth frame too large"));
          }
          return;
        }
        if (newline > EGRESS_AUTH_FRAME_MAX_BYTES) {
          settled = true;
          cleanup();
          reject(new Error("auth frame too large"));
          return;
        }
        settled = true;
        const line = buffered.subarray(0, newline).toString("utf8");
        const rest = buffered.subarray(newline + 1);
        socket.pause();
        cleanup();
        const parts = line.trimEnd().split(" ");
        const [prefix, leaseId, credential] = parts;
        if (
          parts.length !== 3 ||
          prefix !== EGRESS_AUTH_FRAME_PREFIX ||
          !leaseId ||
          !credential
        ) {
          socket.destroy();
          resolve(null);
          return;
        }
        const lease = this.registry.validate(leaseId, credential);
        if (!lease) {
          this.emit({
            leaseId: leaseId ?? "-",
            sessionId: "-",
            actor: "tool",
            actorName: "-",
            generation: 0,
            result: "auth-failed",
            reason: "unknown, revoked or expired lease credential",
            at: this.now(),
          });
          socket.destroy();
          resolve(null);
          return;
        }
        resolve({ lease, buffered: rest });
      };
      const onError = (error: Error): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      };
      const onClose = (): void => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(null);
      };
      const cleanup = (): void => {
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("close", onClose);
      };
      socket.on("data", onData);
      socket.on("error", onError);
      socket.on("close", onClose);
      if (socket.destroyed) onClose();
      else socket.resume();
    });
  }

  private serve(socket: Socket, lease: EgressLease, buffered: Buffer): void {
    let resolveClosed!: () => void;
    const pair: ConnectionPair = {
      upstream: null as Socket | null,
      ended: false,
      closed: new Promise<void>((resolve) => { resolveClosed = resolve; }),
      destroy: (): void => {
        if (pair.ended) return;
        pair.ended = true;
        resolveClosed();
        socket.destroy();
        pair.upstream?.destroy();
        this.registry.detachConnection(lease.leaseId, pair);
      },
    };
    if (!this.registry.attachConnection(lease.leaseId, pair)) {
      this.emit(
        this.eventFor(lease, "denied", { reason: "lease connection bound reached" }),
      );
      socket.destroy();
      return;
    }
    socket.once("close", () => pair.destroy());

    // Protocol dispatch reads the first byte itself: at this point the
    // client may not have sent anything beyond the auth frame yet, so
    // deciding from an empty buffer would misroute SOCKS5 to HTTP.
    void this.dispatchProtocol(socket, lease, buffered, pair);
  }

  private async dispatchProtocol(
    socket: Socket,
    lease: EgressLease,
    buffered: Buffer,
    pair: ConnectionPair,
  ): Promise<void> {
    const lead = await this.readExact(socket, buffered, (buffer) =>
      buffer.length >= 1 ? 1 : null,
    );
    if (!lead) {
      socket.destroy();
      return;
    }
    if (lead.buffer[0] === 0x05) {
      await this.serveSocks(
        socket,
        lease,
        Buffer.concat([lead.buffer, lead.rest]),
        pair,
      );
      return;
    }
    await this.serveHttp(
      socket,
      lease,
      Buffer.concat([lead.buffer, lead.rest]),
      pair,
    );
  }

  /** Check one normalized target against the lease and connect to its pinned IP. */
  private async connectTarget(
    socket: Socket,
    lease: EgressLease,
    host: string,
    port: number,
    pair: ConnectionPair,
  ): Promise<{ ok: true; target: NormalizedTarget; upstream: Socket } | { ok: false; reason: string }> {
    const normalized = normalizeTarget(host, port);
    if (!normalized.ok) {
      this.emit(this.eventFor(lease, "denied", { reason: `invalid target: ${normalized.reason}` }));
      return { ok: false, reason: `invalid target: ${normalized.reason}` };
    }
    const target = normalized.target;
    if (!destinationMatches(lease.scope, target)) {
      this.emit(this.eventFor(lease, "denied", { target, reason: "destination outside the approved scope" }));
      return { ok: false, reason: "destination is not approved" };
    }
    this.emit(this.eventFor(lease, "allowed", { target }));
    const resolved = await Promise.race([
      resolveTargetAddress(target, lease.scope, this.lookup),
      pair.closed.then(() => null),
    ]);
    if (resolved === null) return { ok: false, reason: "connection closed while resolving target" };
    if (!resolved.ok) {
      this.emit(this.eventFor(lease, "denied", { target, reason: resolved.reason }));
      return { ok: false, reason: resolved.reason };
    }
    if (pair.ended || this.registry.isRevoked(lease.leaseId)) {
      return { ok: false, reason: "lease was revoked while connecting" };
    }
    const upstream = await new Promise<Socket | null>((resolveConnect) => {
      const connection = createConnection({
        host: resolved.address,
        port: target.port,
      });
      pair.upstream = connection;
      const timer = setTimeout(() => {
        finish(null);
        connection.destroy();
      }, this.connectTimeoutMs);
      timer.unref?.();
      let connected = false;
      const finish = (value: Socket | null): void => {
        clearTimeout(timer);
        connection.off("connect", onConnect);
        connection.off("close", onClose);
        resolveConnect(value);
      };
      const onConnect = (): void => {
        connected = true;
        connection.setNoDelay(true);
        connection.off("close", onClose);
        connection.once("close", () => {
          this.emit(this.eventFor(lease, "closed", { target }));
          pair.destroy();
        });
        finish(connection);
      };
      const onClose = (): void => finish(null);
      connection.once("connect", onConnect);
      connection.once("close", onClose);
      connection.once("error", () => {
        finish(null);
        if (connected) pair.destroy();
      });
      if (pair.ended) {
        finish(null);
        connection.destroy();
      }
    });
    if (!upstream) {
      this.emit(this.eventFor(lease, "error", { target, reason: "upstream connect failed" }));
      return { ok: false, reason: "upstream connect failed" };
    }
    if (pair.ended) {
      upstream.destroy();
      return { ok: false, reason: "connection closed while connecting" };
    }
    this.emit(this.eventFor(lease, "connected", { target }));
    return { ok: true, target, upstream };
  }

  private refuse(socket: Socket, status: string, message: string): void {
    const body = `${message}${CRLF}`;
    socket.end(
      `HTTP/1.1 ${status}${CRLF}Connection: close${CRLF}Content-Type: text/plain${CRLF}Content-Length: ${Buffer.byteLength(body)}${CRLF}${CRLF}${body}`,
    );
  }

  // ---------------------------------------------------------------- HTTP --

  private async serveHttp(
    socket: Socket,
    lease: EgressLease,
    buffered: Buffer,
    pair: ConnectionPair,
  ): Promise<void> {
    const headline = await this.readHeadline(socket, buffered);
    if (!headline) {
      socket.destroy();
      return;
    }
    const end = headline.buffer.indexOf("\r\n\r\n");
    const head = headline.buffer.subarray(0, end).toString("latin1");
    const rest = headline.buffer.subarray(end + 4);
    const lines = head.split("\r\n");
    const requestLine = lines[0] ?? "";
    const match = /^([A-Z]+) ([^ ]+) HTTP\/(\d)\.(\d)$/u.exec(requestLine);
    if (!match) {
      this.emit(this.eventFor(lease, "error", { reason: "malformed HTTP request line" }));
      this.refuse(socket, "400 Bad Request", "malformed request line");
      return;
    }
    const method = match[1];
    const rawTarget = match[2];

    let host: string;
    let port: number;
    let connectTunnel = false;
    let originPath: string | null = null;
    if (method === "CONNECT") {
      const authority = parseAuthority(rawTarget);
      if (!authority) {
        this.refuse(socket, "400 Bad Request", "malformed CONNECT authority");
        return;
      }
      host = authority.host;
      port = authority.port;
      connectTunnel = true;
    } else {
      let url: URL;
      try {
        url = new URL(rawTarget);
      } catch {
        // Origin-form only makes sense for proxy-invisible requests; a proxy
        // client must send an absolute URI for plain requests.
        this.refuse(socket, "400 Bad Request", "proxy requests require an absolute URI");
        return;
      }
      if (url.protocol !== "http:") {
        this.emit(this.eventFor(lease, "denied", { reason: `unsupported scheme ${url.protocol}` }));
        this.refuse(socket, "403 Forbidden", "only http: plain proxying is supported");
        return;
      }
      host = url.hostname;
      port = url.port === "" ? 80 : Number(url.port);
      originPath = `${url.pathname}${url.search}`;
    }

    const connected = await this.connectTarget(socket, lease, host, port, pair);
    if (!connected.ok) {
      this.refuse(socket, "403 Forbidden", connected.reason);
      return;
    }
    const { upstream } = connected;
    if (pair.ended) return;

    if (connectTunnel) {
      socket.write(`HTTP/1.1 200 Connection Established${CRLF}${CRLF}`);
      this.pipe(socket, upstream, rest.length === 0 ? [] : [rest]);
      return;
    }

    const rewritten = [
      `${method} ${originPath} HTTP/${match[3]}.${match[4]}`,
      ...this.filterHeaders(lines.slice(1)),
      `Connection: close`,
      "",
      "",
    ].join("\r\n");
    this.pipe(socket, upstream, rest.length === 0
      ? [Buffer.from(rewritten)]
      : [Buffer.from(rewritten), rest]);
  }

  /** Drop hop-by-hop headers a proxy must not forward. */
  private filterHeaders(headers: readonly string[]): readonly string[] {
    const blocked = new Set([
      "proxy-authorization",
      "proxy-connection",
      "connection",
      "keep-alive",
      "te",
      "trailer",
      "trailers",
      "upgrade",
    ]);
    return headers.filter((line) => {
      const name = line.slice(0, line.indexOf(":")).trim().toLowerCase();
      return name !== "" && !blocked.has(name);
    });
  }

  private readHeadline(
    socket: Socket,
    buffered: Buffer,
  ): Promise<{ buffer: Buffer } | null> {
    return new Promise((resolve) => {
      let buffer = buffered;
      let settled = false;
      const timer = setTimeout(() => {
        finish(null);
      }, this.handshakeTimeoutMs);
      timer.unref?.();
      const finish = (value: { buffer: Buffer } | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.pause();
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("close", onClose);
        resolve(value);
      };
      const check = (): void => {
        if (settled) return;
        const end = buffer.indexOf("\r\n\r\n");
        if (end >= 0) {
          if (end + 4 <= EGRESS_HTTP_HEADLINE_MAX_BYTES) finish({ buffer });
          else finish(null);
        } else if (buffer.length > EGRESS_HTTP_HEADLINE_MAX_BYTES) finish(null);
      };
      const onData = (chunk: Buffer): void => {
        if (settled) return;
        buffer = Buffer.concat([buffer, chunk]);
        check();
      };
      const onError = (): void => finish(null);
      const onClose = (): void => finish(null);
      socket.on("data", onData);
      socket.on("error", onError);
      socket.on("close", onClose);
      if (socket.destroyed) finish(null);
      else {
        check();
        if (!settled) socket.resume();
      }
    });
  }

  // --------------------------------------------------------------- SOCKS5 --

  private async serveSocks(
    socket: Socket,
    lease: EgressLease,
    buffered: Buffer,
    pair: ConnectionPair,
  ): Promise<void> {
    const greeting = await this.readExact(socket, buffered, (buffer) => {
      if (buffer.length < 2) return null;
      const methods = buffer[1];
      if (buffer.length < 2 + methods) return null;
      return 2 + methods;
    });
    if (!greeting) {
      socket.destroy();
      return;
    }
    if (greeting.buffer[0] !== 0x05) {
      socket.destroy();
      return;
    }
    socket.write(Buffer.from([0x05, 0x00]));
    const request = await this.readExact(socket, greeting.rest, (buffer) => {
      if (buffer.length < 4) return null;
      const atyp = buffer[3];
      let needed: number | null;
      if (atyp === 0x01) needed = 4 + 4 + 2;
      else if (atyp === 0x04) needed = 4 + 16 + 2;
      else if (atyp === 0x03) needed = buffer.length < 5 ? null : 4 + 1 + buffer[4] + 2;
      else return -1;
      return needed === null ? null : buffer.length < needed ? null : needed;
    });
    if (!request) {
      socket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
      return;
    }
    const buffer = request.buffer;
    const command = buffer[1];
    const atyp = buffer[3];
    let host: string;
    let offset: number;
    if (atyp === 0x01) {
      host = `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`;
      offset = 8;
    } else if (atyp === 0x04) {
      const groups: string[] = [];
      for (let index = 0; index < 16; index += 2) {
        groups.push(buffer.subarray(4 + index, 4 + index + 2).toString("hex"));
      }
      host = groups.join(":");
      offset = 20;
    } else {
      const length = buffer[4];
      host = buffer.subarray(5, 5 + length).toString("utf8");
      offset = 5 + length;
    }
    const port = (buffer[offset] << 8) | buffer[offset + 1];
    const reply = (code: number): void => {
      socket.write(Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
    };
    if (command !== 0x01) {
      this.emit(this.eventFor(lease, "denied", { reason: `unsupported SOCKS command ${command}` }));
      reply(0x07);
      socket.end();
      return;
    }
    const connected = await this.connectTarget(socket, lease, host, port, pair);
    if (!connected.ok) {
      reply(0x02);
      socket.end();
      return;
    }
    if (pair.ended) return;
    reply(0x00);
    this.pipe(socket, connected.upstream, request.rest.length === 0 ? [] : [request.rest]);
  }

  private readExact(
    socket: Socket,
    buffered: Buffer,
    needed: (buffer: Buffer) => number | null,
  ): Promise<{ buffer: Buffer; rest: Buffer } | null> {
    return new Promise((resolve) => {
      let buffer = buffered;
      let settled = false;
      const timer = setTimeout(() => finish(null), this.handshakeTimeoutMs);
      timer.unref?.();
      const finish = (value: { buffer: Buffer; rest: Buffer } | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.pause();
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("close", onClose);
        resolve(value);
      };
      const check = (): void => {
        if (settled) return;
        const count = needed(buffer);
        if (count === null || count < 0) {
          if (count !== null) finish(null);
          return;
        }
        finish({ buffer: buffer.subarray(0, count), rest: buffer.subarray(count) });
      };
      const onData = (chunk: Buffer): void => {
        if (settled) return;
        buffer = Buffer.concat([buffer, chunk]);
        check();
      };
      const onError = (): void => finish(null);
      const onClose = (): void => finish(null);
      socket.on("data", onData);
      socket.on("error", onError);
      socket.on("close", onClose);
      if (socket.destroyed) finish(null);
      else {
        check();
        if (!settled) socket.resume();
      }
    });
  }

  // ----------------------------------------------------------------- pipe --

  /** Bidirectional relay with half-close propagation; no automatic replay. */
  private pipe(client: Socket, upstream: Socket, initialClientData: readonly Buffer[] = []): void {
    let clientDone = false;
    let upstreamDone = false;
    const pending = [...initialClientData];
    const maybeDestroy = (): void => {
      if (clientDone && upstreamDone) {
        client.destroy();
        upstream.destroy();
      }
    };
    client.on("data", (chunk) => {
      if (!upstream.write(chunk)) client.pause();
    });
    const writeInitial = (): void => {
      while (pending.length > 0) {
        const chunk = pending.shift();
        if (chunk && !upstream.write(chunk)) {
          client.pause();
          return;
        }
      }
      client.resume();
    };
    upstream.on("drain", writeInitial);
    upstream.on("data", (chunk) => {
      if (!client.write(chunk)) upstream.pause();
    });
    client.on("drain", () => upstream.resume());
    client.on("end", () => {
      clientDone = true;
      upstream.end();
      maybeDestroy();
    });
    upstream.on("end", () => {
      upstreamDone = true;
      client.end();
      maybeDestroy();
    });
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
    writeInitial();
  }
}

function parseAuthority(authority: string): { host: string; port: number } | null {
  const value = authority.trim();
  if (!value) return null;
  if (value.startsWith("[")) {
    const close = value.indexOf("]");
    if (close < 0) return null;
    const host = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (rest === "") return { host, port: 443 };
    if (!rest.startsWith(":")) return null;
    const port = Number(rest.slice(1));
    return Number.isInteger(port) && port > 0 && port <= 65_535 ? { host, port } : null;
  }
  const split = value.lastIndexOf(":");
  if (split < 0) return { host: value, port: 443 };
  const host = value.slice(0, split);
  const port = Number(value.slice(split + 1));
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65_535) return null;
  return { host, port };
}
