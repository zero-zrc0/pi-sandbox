/**
 * Phase 12 permission request identity (specs/host-integration.md §1).
 *
 * Each permission request gets its own `perm-` prefixed UUID. The UUID source
 * is injected so the worked example is exact; the default source is exercised
 * only for freshness and shape.
 */
import { describe, expect, it } from "vitest";
import {
  createPermissionRequestId,
  isPermissionRequestId,
} from "#approve-core/host/permission-request-id";

describe("createPermissionRequestId", () => {
  it("builds perm-<uuid> from the injected source", () => {
    const id = createPermissionRequestId({ randomUUID: () => "123e4567-e89b-42d3-a456-556642440000" });

    expect(id).toBe("perm-123e4567-e89b-42d3-a456-556642440000");
  });

  it("draws one fresh uuid per permission request", () => {
    let calls = 0;
    const source = {
      randomUUID: () => {
        calls += 1;
        return `uuid-${calls}`;
      },
    };

    const first = createPermissionRequestId(source);
    const second = createPermissionRequestId(source);

    expect(first).toBe("perm-uuid-1");
    expect(second).toBe("perm-uuid-2");
    expect(first).not.toBe(second);
    expect(calls).toBe(2);
  });

  it("uses crypto.randomUUID by default and produces distinct valid ids", () => {
    const first = createPermissionRequestId();
    const second = createPermissionRequestId();

    expect(first).toMatch(/^perm-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    expect(isPermissionRequestId(first)).toBe(true);
    expect(isPermissionRequestId(second)).toBe(true);
    expect(first).not.toBe(second);
  });

  it("throws when the source yields an empty string", () => {
    expect(() => createPermissionRequestId({ randomUUID: () => "" })).toThrow();
  });
});

describe("isPermissionRequestId", () => {
  it("accepts ids with the prefix and at least one character", () => {
    expect(isPermissionRequestId("perm-1")).toBe(true);
    expect(isPermissionRequestId("perm-123e4567-e89b-42d3-a456-556642440000")).toBe(true);
  });

  it("rejects ids without a payload, without the prefix or of another type", () => {
    expect(isPermissionRequestId("perm-")).toBe(false);
    expect(isPermissionRequestId("")).toBe(false);
    expect(isPermissionRequestId("tool-123")).toBe(false);
    expect(isPermissionRequestId("PERM-123")).toBe(false);
    expect(isPermissionRequestId("xperm-123")).toBe(false);
    expect(isPermissionRequestId(123)).toBe(false);
    expect(isPermissionRequestId(null)).toBe(false);
    expect(isPermissionRequestId(undefined)).toBe(false);
    expect(isPermissionRequestId({ id: "perm-123" })).toBe(false);
  });
});
