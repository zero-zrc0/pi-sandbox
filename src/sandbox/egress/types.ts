/**
 * Contracts for the controlled network egress service.
 *
 * The egress service runs inside the Pi host process. A sandboxed tool or
 * stdio MCP service reaches the network only through a per-execution bridge
 * that authenticates to this service with a private credential; the service
 * checks every new upstream target against the lease's frozen scope before
 * DNS and connect. Nothing here is part of the public SDK.
 */
import type { NetworkDestination } from "../types";

export const EGRESS_AUTH_FRAME_PREFIX = "PIEGRESS1";
export const EGRESS_AUTH_FRAME_MAX_BYTES = 4096;
export const EGRESS_LEASE_ID_BYTES = 16;
export const EGRESS_CREDENTIAL_BYTES = 24;
export const EGRESS_MAX_CONNECTIONS_PER_LEASE = 32;
export const EGRESS_MAX_CONNECTIONS_TOTAL = 256;
export const EGRESS_HANDSHAKE_TIMEOUT_MS = 10_000;
export const EGRESS_CONNECT_TIMEOUT_MS = 15_000;
export const EGRESS_HTTP_HEADLINE_MAX_BYTES = 64 * 1024;

/** Immutable identity the lease attaches to: session, actor and revisions. */
export interface EgressBinding {
  readonly sessionId: string;
  /** One of requestId (tool call) or serviceId (MCP service generation). */
  readonly requestId?: string;
  readonly serviceId?: string;
  readonly actor: "tool" | "mcp-service";
  readonly actorName: string;
  readonly generation: number;
  readonly policyRevision: string;
  readonly configRevision: string;
}

/** Frozen snapshot of what the lease may reach. */
export interface EgressScope {
  readonly destinations: readonly NetworkDestination[];
}

/** Public lease identity plus private startup credential. */
export interface EgressLease {
  readonly leaseId: string;
  readonly credential: string;
  readonly binding: EgressBinding;
  readonly scope: EgressScope;
  readonly acquiredAt: number;
}

export type EgressEventResult =
  | "allowed"
  | "denied"
  | "connected"
  | "closed"
  | "interrupted"
  | "auth-failed"
  | "error";

/**
 * One network event. Approval decisions and tool execution results are
 * recorded elsewhere; this only carries the proxy's own view. The private
 * credential, proxy authorization headers and request bodies never appear.
 */
export interface EgressNetworkEvent {
  readonly leaseId: string;
  readonly sessionId: string;
  readonly actor: "tool" | "mcp-service";
  readonly actorName: string;
  readonly generation: number;
  readonly targetHost?: string;
  readonly targetPort?: number;
  readonly result: EgressEventResult;
  readonly reason?: string;
  readonly at: number;
}

/** Host hook used to observe network events; throwing must not break proxying. */
export type EgressEventSink = (event: EgressNetworkEvent) => void;

export type EgressRevokedListener = (leaseId: string) => void;

/**
 * Connection parameters handed to the native launcher. The credential stays
 * out of the plan, the digest, the audit log and any command line.
 */
export interface EgressGrant {
  readonly leaseId: string;
  readonly credential: string;
  readonly proxyHost: string;
  readonly proxyPort: number;
}
