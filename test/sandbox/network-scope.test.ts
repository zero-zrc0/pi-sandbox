import { describe, expect, it } from "vitest";
import { intersectNetworkScopes, toRuntimeNetworkScope } from "#sandbox/network-scope";
import type { NetworkScope } from "#sandbox/types";

describe("network scope intersection", () => {
  const none = { kind: "none" } as const;
  const all = { kind: "all" } as const;
  const scope = (destinations: { host: string; port?: number }[]): NetworkScope => ({ kind: "destinations", destinations });

  it("treats none as empty and all as the identity", () => {
    const hosts = scope([{ host: "example.com", port: 443 }]);
    expect(intersectNetworkScopes(none, hosts)).toEqual(none);
    expect(intersectNetworkScopes(hosts, none)).toEqual(none);
    expect(intersectNetworkScopes(all, hosts)).toEqual(hosts);
    expect(intersectNetworkScopes(hosts, all)).toEqual(hosts);
  });

  it("intersects exact hosts and ports including an unrestricted host port", () => {
    const left = scope([{ host: "a.example" }, { host: "b.example", port: 80 }]);
    const right = scope([{ host: "a.example", port: 443 }, { host: "b.example", port: 443 }, { host: "c.example" }]);
    expect(intersectNetworkScopes(left, right)).toEqual(scope([{ host: "a.example", port: 443 }]));
    expect(intersectNetworkScopes(right, left)).toEqual(scope([{ host: "a.example", port: 443 }]));
    expect(intersectNetworkScopes(left, scope([{ host: "b.example", port: 443 }]))).toEqual(none);
  });
});

describe("network scope configuration conversion", () => {
  it("maps none and all without changing their meaning", () => {
    expect(toRuntimeNetworkScope({ mode: "none" })).toEqual({ kind: "none" });
    expect(toRuntimeNetworkScope({ mode: "all" })).toEqual({ kind: "all" });
  });

  it("expands an omitted port to HTTP and HTTPS only", () => {
    expect(toRuntimeNetworkScope({ mode: "allowlist", allow: [{ host: "github.com" }] })).toEqual({
      kind: "destinations",
      destinations: [{ host: "github.com", port: 80 }, { host: "github.com", port: 443 }],
    });
  });

  it("keeps explicit ports and the explicit any-port escape hatch", () => {
    expect(toRuntimeNetworkScope({
      mode: "allowlist",
      allow: [{ host: "api.example.com", port: 8443 }, { host: "internal.example.com", port: "any" }],
    })).toEqual({
      kind: "destinations",
      destinations: [{ host: "api.example.com", port: 8443 }, { host: "internal.example.com" }],
    });
  });
});
