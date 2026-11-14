import { describe, expect, it } from "vitest";

import {
  destinationMatches,
  destinationPermitsNonPublic,
  isNonPublicAddress,
  normalizeTarget,
  resolveTargetAddress,
} from "#sandbox/egress/target";
import type { EgressScope } from "#sandbox/egress/types";

function scope(destinations: readonly { host: string; port?: number }[]): EgressScope {
  return { destinations };
}

describe("normalizeTarget", () => {
  it("lowercases and IDNA-encodes domains", () => {
    const result = normalizeTarget("ExAmPle.COM", 443);
    expect(result).toEqual({
      ok: true,
      target: { host: "example.com", port: 443, literal: false },
    });
  });

  it("strips one trailing dot from domains", () => {
    const result = normalizeTarget("example.com.", 443);
    expect(result.ok && result.target.host).toBe("example.com");
  });

  it("accepts strict IPv4 literals", () => {
    expect(normalizeTarget("8.8.8.8", 53)).toEqual({
      ok: true,
      target: { host: "8.8.8.8", port: 53, literal: true },
    });
    expect(normalizeTarget("8.8.8.256", 53).ok).toBe(false);
    expect(normalizeTarget("08.8.8.8", 53).ok).toBe(false);
  });

  it("accepts bracketed and bare IPv6 literals", () => {
    expect(normalizeTarget("[2606:4700::1111]", 443).ok).toBe(true);
    const bare = normalizeTarget("2606:4700::1111", 443);
    expect(bare).toEqual({
      ok: true,
      target: { host: "2606:4700::1111", port: 443, literal: true },
    });
  });

  it("rejects ambiguous or malformed values", () => {
    expect(normalizeTarget("", 443).ok).toBe(false);
    expect(normalizeTarget("a\0b.com", 443).ok).toBe(false);
    expect(normalizeTarget("example.com/x", 443).ok).toBe(false);
    expect(normalizeTarget("-bad-.com", 443).ok).toBe(false);
    expect(normalizeTarget("a".repeat(64) + ".com", 443).ok).toBe(false);
    expect(normalizeTarget("example.com", 0).ok).toBe(false);
    expect(normalizeTarget("example.com", 65_536).ok).toBe(false);
    expect(normalizeTarget("example.com", 1.5).ok).toBe(false);
  });
});

describe("isNonPublicAddress", () => {
  it("flags loopback, RFC1918, link-local, CGNAT and unspecified", () => {
    for (const ip of [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.1.1",
      "100.64.0.1",
      "0.0.0.0",
      "::1",
      "::",
      "fe80::1",
      "fd00::1",
      "fc00::1",
    ]) {
      expect(isNonPublicAddress(ip)).toBe(true);
    }
  });

  it("passes public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "172.15.0.1", "172.32.0.1", "11.0.0.1"]) {
      expect(isNonPublicAddress(ip)).toBe(false);
    }
  });
});

describe("destinationMatches", () => {
  it("host-only entries allow any TCP port on that host", () => {
    const s = scope([{ host: "api.example.com" }]);
    expect(destinationMatches(s, { host: "api.example.com", port: 443, literal: false })).toBe(true);
    expect(destinationMatches(s, { host: "api.example.com", port: 8443, literal: false })).toBe(true);
    expect(destinationMatches(s, { host: "other.example.com", port: 443, literal: false })).toBe(false);
  });

  it("port-specific entries never widen to other hosts or ports", () => {
    const s = scope([{ host: "api.example.com", port: 443 }]);
    expect(destinationMatches(s, { host: "api.example.com", port: 443, literal: false })).toBe(true);
    expect(destinationMatches(s, { host: "api.example.com", port: 444, literal: false })).toBe(false);
    expect(destinationMatches(s, { host: "api.example.com:443", port: 443, literal: false })).toBe(false);
  });
});

describe("destinationPermitsNonPublic", () => {
  it("requires an explicit literal grant", () => {
    const s = scope([{ host: "127.0.0.1", port: 8080 }]);
    expect(
      destinationPermitsNonPublic(s, { host: "127.0.0.1", port: 8080, literal: true }),
    ).toBe(true);
    expect(
      destinationPermitsNonPublic(s, { host: "127.0.0.1", port: 8080, literal: false }),
    ).toBe(false);
    expect(
      destinationPermitsNonPublic(scope([{ host: "example.com" }]), {
        host: "127.0.0.1",
        port: 8080,
        literal: true,
      }),
    ).toBe(false);
  });
});

describe("resolveTargetAddress", () => {
  it("pins literal public addresses without DNS", async () => {
    const result = await resolveTargetAddress(
      { host: "93.184.216.34", port: 443, literal: true },
      scope([{ host: "93.184.216.34", port: 443 }]),
      async () => ["10.0.0.1"],
    );
    expect(result).toEqual({ ok: true, address: "93.184.216.34" });
  });

  it("denies non-public literals without an explicit grant", async () => {
    const denied = await resolveTargetAddress(
      { host: "127.0.0.1", port: 8080, literal: true },
      scope([{ host: "example.com" }]),
    );
    expect(denied.ok).toBe(false);
    const allowed = await resolveTargetAddress(
      { host: "127.0.0.1", port: 8080, literal: true },
      scope([{ host: "127.0.0.1", port: 8080 }]),
    );
    expect(allowed).toEqual({ ok: true, address: "127.0.0.1" });
  });

  it("denies domains that resolve only to non-public addresses", async () => {
    const result = await resolveTargetAddress(
      { host: "attacker.example", port: 443, literal: false },
      scope([{ host: "attacker.example" }]),
      async () => ["10.0.0.5", "192.168.1.2"],
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("non-public");
    }
  });

  it("allows an internal-service domain whose private address has an explicit literal grant", async () => {
    // 内网服务：按域名访问（自签证书需要名字），同时管理员显式授权了
    // 解析出的私网地址与端口。两把钥匙齐备，按解析结果 pinned 放行。
    const result = await resolveTargetAddress(
      { host: "intra.example", port: 8443, literal: false },
      scope([
        { host: "intra.example" },
        { host: "10.0.0.5", port: 8443 },
      ]),
      async () => ["10.0.0.5"],
    );
    expect(result).toEqual({ ok: true, address: "10.0.0.5" });
  });

  it("never lets a domain grant alone unlock a private address, even partially", async () => {
    // 字面量授权了地址但端口不符：不放行。
    const wrongPort = await resolveTargetAddress(
      { host: "intra.example", port: 8443, literal: false },
      scope([
        { host: "intra.example" },
        { host: "10.0.0.5", port: 9443 },
      ]),
      async () => ["10.0.0.5"],
    );
    expect(wrongPort.ok).toBe(false);
    // 授权了公网地址而不是私网地址：不放行。
    const wrongAddress = await resolveTargetAddress(
      { host: "intra.example", port: 8443, literal: false },
      scope([
        { host: "intra.example" },
        { host: "93.184.216.34", port: 8443 },
      ]),
      async () => ["10.0.0.5"],
    );
    expect(wrongAddress.ok).toBe(false);
  });

  it("prefers public results and only keeps granted private addresses", async () => {
    const result = await resolveTargetAddress(
      { host: "dual.example", port: 443, literal: false },
      scope([
        { host: "dual.example" },
        { host: "10.0.0.5" },
      ]),
      async () => ["10.0.0.5", "93.184.216.34"],
    );
    expect(result).toEqual({ ok: true, address: "93.184.216.34" });
  });

  it("pins the public result and never re-resolves", async () => {
    const result = await resolveTargetAddress(
      { host: "dual.example", port: 443, literal: false },
      scope([{ host: "dual.example" }]),
      async () => ["93.184.216.34", "10.0.0.9"],
    );
    expect(result).toEqual({ ok: true, address: "93.184.216.34" });
  });

  it("surfaces DNS failures as denials", async () => {
    const result = await resolveTargetAddress(
      { host: "missing.example", port: 443, literal: false },
      scope([{ host: "missing.example" }]),
      async () => {
        throw new Error("ENOTFOUND");
      },
    );
    expect(result.ok).toBe(false);
  });
});
