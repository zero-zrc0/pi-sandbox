/**
 * Target normalization, scope matching and DNS pinning for the egress proxy.
 *
 * Plain seccomp filters cannot dereference a sockaddr pointer, so the socket
 * family filter in the sandbox is coarse. The precise host/port decision
 * lives here, in the host policy proxy, where the address is data.
 */
import { isIPv4, isIPv6 } from "node:net";
import { domainToASCII } from "node:url";
import { promises as dns } from "node:dns";

import type { EgressScope } from "./types";

export interface NormalizedTarget {
  /** Lowercased IDNA domain, dotted IPv4 or bracket-free IPv6 literal. */
  readonly host: string;
  readonly port: number;
  /** True when `host` was a literal IP, so no DNS resolution is needed. */
  readonly literal: boolean;
}

export type TargetDeny =
  | "invalid-host"
  | "invalid-port"
  | "ambiguous-target";

/**
 * Normalize one requested target. Domains are IDNA-encoded, IPv6 literals lose
 * their brackets, and anything that could parse two different ways is
 * rejected instead of guessed.
 */
export function normalizeTarget(
  host: string,
  port: number,
): { readonly ok: true; readonly target: NormalizedTarget } | { readonly ok: false; readonly reason: TargetDeny } {
  if (typeof host !== "string") return { ok: false, reason: "invalid-host" };
  let value = host.trim().toLowerCase();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  if (!value || value.includes("\0") || value.includes("/") || value.includes(":") && !isIPv6(value)) {
    return { ok: false, reason: "invalid-host" };
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    return { ok: false, reason: "invalid-port" };
  }
  if (isIPv4(value)) {
    return { ok: true, target: { host: value, port, literal: true } };
  }
  if (isIPv6(value)) {
    return { ok: true, target: { host: value, port, literal: true } };
  }
  if (value.includes(":")) return { ok: false, reason: "invalid-host" };
  let domain = value.endsWith(".") ? value.slice(0, -1) : value;
  domain = domainToASCII(domain);
  if (
    !domain ||
    domain.length > 253 ||
    domain.split(".").some((label) =>
      !label ||
      label.length > 63 ||
      !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/u.test(label),
    )
  ) {
    return { ok: false, reason: "invalid-host" };
  }
  return { ok: true, target: { host: domain, port, literal: false } };
}

function ipv4InCidr(ip: string, cidr: string): boolean {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const toInt = (value: string): number =>
    value.split(".").reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (toInt(ip) & mask) === (toInt(base!) & mask);
}

/**
 * Conservative loopback/private/unspecified classification. A public-scope
 * destination that resolves into any of these is denied before connect, so a
 * domain cannot be re-resolved into a host-internal address.
 */
export function isNonPublicAddress(ip: string): boolean {
  if (isIPv4(ip)) {
    return (
      ip === "0.0.0.0" ||
      ipv4InCidr(ip, "10.0.0.0/8") ||
      ipv4InCidr(ip, "127.0.0.0/8") ||
      ipv4InCidr(ip, "169.254.0.0/16") ||
      ipv4InCidr(ip, "172.16.0.0/12") ||
      ipv4InCidr(ip, "192.168.0.0/16") ||
      ipv4InCidr(ip, "100.64.0.0/10")
    );
  }
  if (isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return (
      lower === "::" ||
      lower === "::1" ||
      lower.startsWith("fe80:") ||
      lower.startsWith("fec0:") ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      lower.startsWith("::ffff:127.") ||
      lower.startsWith("::ffff:10.") ||
      lower.startsWith("::ffff:192.168.") ||
      lower.startsWith("::ffff:172.1") ||
      lower.startsWith("::ffff:172.2") ||
      lower.startsWith("::ffff:172.3")
    );
  }
  return true;
}

/**
 * Scope check for one normalized target. A scope entry without a port allows
 * any TCP port on that host; a scoped port never widens to other hosts. The
 * non-public rule is separate: see {@link destinationPermitsNonPublic}.
 */
export function destinationMatches(
  scope: EgressScope,
  target: NormalizedTarget,
): boolean {
  for (const destination of scope.destinations) {
    if (destination.host !== target.host) continue;
    if (destination.port === undefined) return true;
    if (destination.port === target.port) return true;
  }
  return false;
}

/** Only an explicit literal grant may reach a loopback/private address. */
export function destinationPermitsNonPublic(
  scope: EgressScope,
  target: NormalizedTarget,
): boolean {
  if (!target.literal) return false;
  return addressExplicitlyGranted(scope, target.host, target.port);
}

/**
 * One resolved address is unlocked when the scope names it explicitly as an
 * IP literal with a matching port rule. This is the second key for internal
 * services: a granted domain plus an explicit literal grant for its private
 * address reaches the service by name; a domain grant alone never does.
 */
export function addressExplicitlyGranted(
  scope: EgressScope,
  address: string,
  port: number,
): boolean {
  return scope.destinations.some(
    (destination) =>
      destination.host === address &&
      (destination.port === undefined || destination.port === port),
  );
}

export type ResolveResult =
  | { readonly ok: true; readonly address: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Resolve and pin the target address. The returned address is the exact IP
 * the proxy connects to, so a check-then-resolve race cannot silently change
 * the destination. Public-scope hosts whose resolution is entirely non-public
 * are denied here, before any external connection exists.
 */
export async function resolveTargetAddress(
  target: NormalizedTarget,
  scope: EgressScope,
  lookup: (host: string) => Promise<readonly string[]> = async (host) => {
    const results = await dns.lookup(host, { all: true });
    return results.map((entry) => entry.address);
  },
): Promise<ResolveResult> {
  if (target.literal) {
    if (isNonPublicAddress(target.host) && !destinationPermitsNonPublic(scope, target)) {
      return { ok: false, reason: "non-public address requires an explicit literal grant" };
    }
    return { ok: true, address: target.host };
  }
  let addresses: readonly string[];
  try {
    addresses = await lookup(target.host);
  } catch (error) {
    return {
      ok: false,
      reason: `dns resolution failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (addresses.length === 0) {
    return { ok: false, reason: "dns resolution returned no addresses" };
  }
  /*
   * Public-scope resolutions keep only public addresses. A non-public result
   * survives only while the scope explicitly names that exact address and
   * port as a literal grant — the internal-service configuration — so a
   * domain grant alone can never be rebound into a private network.
   */
  const pool = [
    ...addresses.filter((address) => !isNonPublicAddress(address)),
    ...addresses.filter(
      (address) =>
        isNonPublicAddress(address) &&
        addressExplicitlyGranted(scope, address, target.port),
    ),
  ];
  if (pool.length === 0) {
    return {
      ok: false,
      reason: "dns resolved only to non-public addresses without an explicit literal grant",
    };
  }
  return { ok: true, address: pool[0] };
}
