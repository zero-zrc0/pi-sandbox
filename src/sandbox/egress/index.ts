/**
 * Composition root for controlled network egress.
 *
 * One `EgressService` per host owns the lease registry and the policy proxy
 * listener. Execution controllers call `acquireForPlan` when an
 * execution plan carries a `destinations` network scope; the returned grant
 * is what the native launcher uses to reach this service. The service is
 * module-internal: callers never see the registry or the sockets.
 */
import type { ExecutionPlan } from "../types";
import { EgressLeaseRegistry, type EgressLeaseRegistryOptions } from "./leases";
import { EgressProxyServer, type EgressProxyOptions } from "./proxy";
import { createEgressForwarder, type EgressForwarder } from "./forwarder";
import {
  type EgressBinding,
  type EgressEventSink,
  type EgressGrant,
  type EgressLease,
  type EgressScope,
} from "./types";

export type EgressServiceStartResult =
  | { readonly ok: true; readonly host: string; readonly port: number }
  | { readonly ok: false; readonly reason: string };

export interface EgressServiceOptions {
  readonly onEvent?: EgressEventSink;
  /** Bind address; defaults to loopback only. */
  readonly host?: string;
  readonly registry?: EgressLeaseRegistryOptions;
  readonly proxy?: Omit<EgressProxyOptions, "registry" | "onEvent" | "host">;
}

export interface AcquiredEgress {
  readonly lease: EgressLease;
  readonly grant: EgressGrant;
}

export class EgressService {
  private readonly registry: EgressLeaseRegistry;
  private readonly server: EgressProxyServer;
  private readonly bindHost: string | undefined;
  private starting: Promise<EgressServiceStartResult> | null = null;
  private readonly forwarders = new Map<string, EgressForwarder>();
  private disposed = false;

  constructor(options: EgressServiceOptions = {}) {
    this.registry = new EgressLeaseRegistry(options.registry ?? {});
    this.registry.onRevoked(leaseId => {
      this.forwarders.get(leaseId)?.close();
      this.forwarders.delete(leaseId);
    });
    this.bindHost = options.host;
    this.server = new EgressProxyServer({
      registry: this.registry,
      ...(options.host === undefined ? {} : { host: options.host }),
      ...(options.onEvent === undefined ? {} : { onEvent: options.onEvent }),
      ...options.proxy,
    });
  }

  /** Lazily starts the listener on first use; later calls reuse it. */
  async ensureStarted(): Promise<EgressServiceStartResult> {
    if (this.disposed) return { ok: false, reason: "egress service is disposed" };
    this.starting ??= this.server.start();
    return this.starting;
  }

  async openForwarder(grant: EgressGrant): Promise<EgressForwarder> {
    const started = await this.ensureStarted();
    if (this.disposed || !started.ok || started.host !== grant.proxyHost || started.port !== grant.proxyPort ||
      !this.registry.validate(grant.leaseId, grant.credential)) throw new Error("egress lease is unavailable");
    if (this.forwarders.has(grant.leaseId)) throw new Error("egress forwarder already exists");
    const forwarder = await createEgressForwarder(grant);
    if (this.disposed || !this.registry.validate(grant.leaseId, grant.credential) || this.forwarders.has(grant.leaseId)) {
      forwarder.close();
      throw new Error("egress lease is unavailable");
    }
    this.forwarders.set(grant.leaseId, forwarder);
    return forwarder;
  }

  /**
   * Acquire one lease for an execution plan whose network scope is
   * `destinations`. The scope snapshot is frozen here; later permission
   * changes can only revoke, never widen.
   */
  async acquireForPlan(plan: ExecutionPlan): Promise<AcquiredEgress | null> {
    if (plan.network.kind !== "destinations") return null;
    const started = await this.ensureStarted();
    if (!started.ok || this.disposed) return null;
    const binding: EgressBinding = Object.freeze({
      sessionId: plan.sessionId,
      requestId: plan.requestId,
      actor: "tool",
      actorName: plan.tool.name,
      generation: 0,
      policyRevision: plan.policyRevision,
      configRevision: plan.configRevision,
    });
    const scope: EgressScope = Object.freeze({
      destinations: plan.network.destinations,
    });
    const { lease } = this.registry.acquire(binding, scope);
    return {
      lease,
      grant: Object.freeze({
        leaseId: lease.leaseId,
        credential: lease.credential,
        proxyHost: started.host,
        proxyPort: started.port,
      }),
    };
  }

  /** Fixed-permission lease for one stdio MCP service generation. */
  async acquireForService(input: {
    readonly sessionId: string;
    readonly serviceId: string;
    readonly serviceName: string;
    readonly generation: number;
    readonly policyRevision: string;
    readonly configRevision: string;
    readonly scope: EgressScope;
  }): Promise<AcquiredEgress | null> {
    const started = await this.ensureStarted();
    if (!started.ok || this.disposed) return null;
    const binding: EgressBinding = Object.freeze({
      sessionId: input.sessionId,
      serviceId: input.serviceId,
      actor: "mcp-service",
      actorName: input.serviceName,
      generation: input.generation,
      policyRevision: input.policyRevision,
      configRevision: input.configRevision,
    });
    const { lease } = this.registry.acquire(binding, input.scope);
    return {
      lease,
      grant: Object.freeze({
        leaseId: lease.leaseId,
        credential: lease.credential,
        proxyHost: started.host,
        proxyPort: started.port,
      }),
    };
  }

  revoke(leaseId: string): boolean {
    return this.registry.revoke(leaseId);
  }

  closeSession(sessionId: string): readonly string[] {
    return this.registry.closeSession(sessionId);
  }

  get activeLeaseCount(): number {
    return this.registry.activeCount;
  }

  get activeConnectionCount(): number {
    return this.server.activeCount;
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    this.registry.closeAll();
    await this.starting;
    await this.server.close();
  }
}
