/**
 * Lease registry for controlled network egress.
 *
 * A lease is the runtime qualification of one execution binding: it never
 * carries its own user permission configuration, only the frozen scope the
 * approval chain already granted. Revocation closes every connection the
 * lease still owns.
 */
import { randomBytes, randomUUID } from "node:crypto";

import {
  EGRESS_CREDENTIAL_BYTES,
  EGRESS_LEASE_ID_BYTES,
  EGRESS_MAX_CONNECTIONS_PER_LEASE,
  type EgressBinding,
  type EgressLease,
  type EgressRevokedListener,
  type EgressScope,
} from "./types";

interface LeaseEntry {
  readonly lease: EgressLease;
  revoked: boolean;
  readonly connections: Set<{ destroy(): void }>;
}

export interface EgressLeaseRegistryOptions {
  readonly maxConnectionsPerLease?: number;
  readonly now?: () => number;
  /** Optional absolute expiry applied at acquire time (0/undefined = none). */
  readonly leaseTtlMs?: number;
  readonly random?: () => string;
}

export interface AcquireResult {
  readonly ok: true;
  readonly lease: EgressLease;
  readonly expiresAt?: number;
}

/**
 * Holds live leases and owns their connection sets. The registry is
 * synchronous: the proxy validates and revokes without awaiting, so a
 * permission change takes effect before the proxy answers the next byte.
 */
export class EgressLeaseRegistry {
  private readonly entries = new Map<string, LeaseEntry>();
  private readonly expires = new Map<string, number>();
  private readonly maxConnectionsPerLease: number;
  private readonly leaseTtlMs?: number;
  private readonly now: () => number;
  private readonly random: () => string;
  private listeners: EgressRevokedListener[] = [];

  constructor(options: EgressLeaseRegistryOptions = {}) {
    this.maxConnectionsPerLease =
      options.maxConnectionsPerLease ?? EGRESS_MAX_CONNECTIONS_PER_LEASE;
    this.leaseTtlMs =
      options.leaseTtlMs !== undefined && options.leaseTtlMs > 0
        ? options.leaseTtlMs
        : undefined;
    this.now = options.now ?? Date.now;
    this.random = options.random ?? (() => randomBytes(EGRESS_CREDENTIAL_BYTES).toString("base64url"));
    if (!Number.isInteger(this.maxConnectionsPerLease) || this.maxConnectionsPerLease < 1) {
      throw new Error("maxConnectionsPerLease must be a positive integer");
    }
  }

  /** Credentials are module-internal random values, never caller data. */
  acquire(binding: EgressBinding, scope: EgressScope): AcquireResult {
    this.purgeExpired();
    const lease: EgressLease = Object.freeze({
      leaseId: randomUUID(),
      credential: this.random(),
      binding: Object.freeze({ ...binding }),
      scope: Object.freeze({
        destinations: Object.freeze([...scope.destinations]),
      }),
      acquiredAt: this.now(),
    });
    this.entries.set(lease.leaseId, {
      lease,
      revoked: false,
      connections: new Set(),
    });
    const expiresAt =
      this.leaseTtlMs === undefined
        ? undefined
        : lease.acquiredAt + this.leaseTtlMs;
    if (expiresAt !== undefined) this.expires.set(lease.leaseId, expiresAt);
    return { ok: true, lease, ...(expiresAt === undefined ? {} : { expiresAt }) };
  }

  /** Look up an entry only by private credential; lease id alone proves nothing. */
  validate(leaseId: string, credential: string): EgressLease | null {
    const entry = this.entries.get(leaseId);
    if (!entry || entry.revoked) return null;
    if (entry.lease.credential !== credential) return null;
    const expiresAt = this.expires.get(leaseId);
    if (expiresAt !== undefined && this.now() >= expiresAt) {
      this.revoke(leaseId);
      return null;
    }
    return entry.lease;
  }

  isRevoked(leaseId: string): boolean {
    const entry = this.entries.get(leaseId);
    return !entry || entry.revoked;
  }

  /**
   * Revoke one lease: mark it dead, destroy its connections, notify watchers.
   * Idempotent; safe to call during cancel and again during settle.
   */
  revoke(leaseId: string): boolean {
    const entry = this.entries.get(leaseId);
    if (!entry) return false;
    if (!entry.revoked) {
      entry.revoked = true;
      for (const connection of [...entry.connections]) {
        try {
          connection.destroy();
        } catch {
          // Destruction is best-effort; the socket is already untrusted.
        }
      }
      entry.connections.clear();
      for (const listener of [...this.listeners]) {
        try {
          listener(leaseId);
        } catch {
          // Observation must not break revocation.
        }
      }
    }
    this.entries.delete(leaseId);
    this.expires.delete(leaseId);
    return true;
  }

  /** Revoke every lease of one session; returns the revoked lease ids. */
  closeSession(sessionId: string): readonly string[] {
    const revoked: string[] = [];
    for (const [leaseId, entry] of [...this.entries]) {
      if (entry.lease.binding.sessionId !== sessionId) continue;
      this.revoke(leaseId);
      revoked.push(leaseId);
    }
    return revoked;
  }

  /** Revoke everything; used at host shutdown. */
  closeAll(): readonly string[] {
    const revoked = [...this.entries.keys()];
    for (const leaseId of revoked) this.revoke(leaseId);
    return revoked;
  }

  /** Register one proxy connection against its lease; bounded per lease. */
  attachConnection(leaseId: string, connection: { destroy(): void }): boolean {
    const entry = this.entries.get(leaseId);
    if (!entry || entry.revoked) return false;
    if (entry.connections.size >= this.maxConnectionsPerLease) return false;
    entry.connections.add(connection);
    return true;
  }

  detachConnection(leaseId: string, connection: { destroy(): void }): void {
    this.entries.get(leaseId)?.connections.delete(connection);
  }

  onRevoked(listener: EgressRevokedListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((item) => item !== listener);
    };
  }

  get activeCount(): number {
    return this.entries.size;
  }

  private purgeExpired(): void {
    for (const [leaseId, expiresAt] of [...this.expires]) {
      if (this.now() >= expiresAt) this.revoke(leaseId);
    }
  }
}
