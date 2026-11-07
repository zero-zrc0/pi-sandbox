import { describe, expect, it } from "vitest";

import { EgressLeaseRegistry } from "#sandbox/egress/leases";
import type { EgressBinding } from "#sandbox/egress/types";

const BINDING: EgressBinding = Object.freeze({
  sessionId: "session-1",
  requestId: "request-1",
  actor: "tool",
  actorName: "bash",
  generation: 3,
  policyRevision: "policy-r1",
  configRevision: "config-r1",
});

const SCOPE = Object.freeze({ destinations: Object.freeze([{ host: "api.example.com" }]) });

describe("EgressLeaseRegistry", () => {
  it("issues leases that validate by credential", () => {
    const registry = new EgressLeaseRegistry();
    const { lease } = registry.acquire(BINDING, SCOPE);
    expect(registry.validate(lease.leaseId, lease.credential)).toBe(lease);
    expect(registry.validate(lease.leaseId, "wrong")).toBeNull();
    expect(registry.validate("unknown", lease.credential)).toBeNull();
  });

  it("freezes the scope snapshot at acquire time", () => {
    const registry = new EgressLeaseRegistry();
    const destinations = [{ host: "api.example.com" }];
    const { lease } = registry.acquire(BINDING, { destinations });
    destinations.push({ host: "evil.example" });
    expect(lease.scope.destinations).toHaveLength(1);
  });

  it("revoke destroys attached connections and is idempotent", () => {
    const registry = new EgressLeaseRegistry();
    const { lease } = registry.acquire(BINDING, SCOPE);
    let destroyed = 0;
    const connection = { destroy: () => { destroyed += 1; } };
    expect(registry.attachConnection(lease.leaseId, connection)).toBe(true);
    expect(registry.revoke(lease.leaseId)).toBe(true);
    expect(destroyed).toBe(1);
    expect(registry.validate(lease.leaseId, lease.credential)).toBeNull();
    expect(registry.revoke(lease.leaseId)).toBe(false);
    expect(destroyed).toBe(1);
  });

  it("enforces the per-lease connection bound", () => {
    const registry = new EgressLeaseRegistry({ maxConnectionsPerLease: 1 });
    const { lease } = registry.acquire(BINDING, SCOPE);
    const first = { destroy: () => {} };
    expect(registry.attachConnection(lease.leaseId, first)).toBe(true);
    expect(registry.attachConnection(lease.leaseId, { destroy: () => {} })).toBe(false);
    registry.detachConnection(lease.leaseId, first);
    expect(registry.attachConnection(lease.leaseId, { destroy: () => {} })).toBe(true);
  });

  it("closeSession revokes only that session's leases", () => {
    const registry = new EgressLeaseRegistry();
    const first = registry.acquire(BINDING, SCOPE);
    const second = registry.acquire(
      { ...BINDING, sessionId: "session-2" },
      SCOPE,
    );
    const revoked = registry.closeSession("session-1");
    expect(revoked).toEqual([first.lease.leaseId]);
    expect(registry.validate(second.lease.leaseId, second.lease.credential)).toBe(
      second.lease,
    );
  });

  it("expires leases at their TTL", () => {
    let now = 1_000;
    const registry = new EgressLeaseRegistry({
      leaseTtlMs: 500,
      now: () => now,
    });
    const { lease } = registry.acquire(BINDING, SCOPE);
    now = 1_400;
    expect(registry.validate(lease.leaseId, lease.credential)).toBe(lease);
    now = 1_500;
    expect(registry.validate(lease.leaseId, lease.credential)).toBeNull();
    expect(registry.activeCount).toBe(0);
  });

  it("closeAll revokes every lease once", () => {
    const registry = new EgressLeaseRegistry();
    const first = registry.acquire(BINDING, SCOPE);
    const second = registry.acquire(BINDING, SCOPE);
    const revoked = registry.closeAll();
    expect(new Set(revoked)).toEqual(
      new Set([first.lease.leaseId, second.lease.leaseId]),
    );
    expect(registry.activeCount).toBe(0);
  });

  it("notifies revocation listeners exactly once per lease", () => {
    const registry = new EgressLeaseRegistry();
    const seen: string[] = [];
    registry.onRevoked((leaseId) => seen.push(leaseId));
    const { lease } = registry.acquire(BINDING, SCOPE);
    registry.revoke(lease.leaseId);
    registry.revoke(lease.leaseId);
    expect(seen).toEqual([lease.leaseId]);
  });
});
