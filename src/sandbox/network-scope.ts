import type { NetworkScope as ConfiguredNetworkScope } from "#config/execution-source-schema";
import { DEFAULT_NETWORK_PORTS } from "#config/execution-source-schema";
import type { NetworkScope } from "./types";

/** Convert the public configuration shape to the sandbox's internal plan shape. */
export function toRuntimeNetworkScope(scope: ConfiguredNetworkScope): NetworkScope {
  if (scope.mode !== "allowlist") return { kind: scope.mode };
  return {
    kind: "destinations",
    destinations: scope.allow.flatMap(({ host, port }) => {
      if (port === "any") return [{ host }];
      if (port !== undefined) return [{ host, port }];
      return DEFAULT_NETWORK_PORTS.map(defaultPort => ({ host, port: defaultPort }));
    }),
  };
}

export function intersectNetworkScopes(left: NetworkScope, right: NetworkScope): NetworkScope {
  if (left.kind === "none" || right.kind === "none") return { kind: "none" };
  if (left.kind === "all") return right;
  if (right.kind === "all") return left;
  const destinations = [];
  const seen = new Set<string>();
  for (const a of left.destinations) {
    for (const b of right.destinations) {
      if (a.host !== b.host || (a.port !== undefined && b.port !== undefined && a.port !== b.port)) continue;
      const port = a.port ?? b.port;
      const key = `${a.host}\0${port ?? "*"}`;
      if (seen.has(key)) continue;
      seen.add(key);
      destinations.push({ host: a.host, ...(port === undefined ? {} : { port }) });
    }
  }
  return destinations.length ? { kind: "destinations", destinations } : { kind: "none" };
}
