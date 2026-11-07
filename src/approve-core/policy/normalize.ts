/**
 * Flat permission configuration normalization.
 *
 * A scope's permission map becomes per-surface rule groups attributed to that
 * scope. Bare `path` and `external_directory` families expand into their read
 * and write members inside the same scope: sugar patterns first, explicit
 * direction patterns after, whether or not a pattern was explicitly defined.
 * A group remembers whether its surface value was a catch-all string, because
 * cross-scope merging replaces the whole surface in that case.
 *
 * The universal `*` key only produces the universal default and never a
 * regular rule. Pi MCP catch-all surfaces that can match a complete Pi MCP
 * tool name are also copied onto the `mcp` surface, after every original rule.
 */
import { splitPathSurface } from "../utils/access-intent/path-surfaces";
import type { Rule, RuleAction, RuleOrigin } from "./rule";
import { wildcardMatch } from "./wildcard-matcher";

export type PermissionState = "allow" | "ask" | "deny";

export interface DenyWithReason {
  readonly action: "deny";
  readonly reason?: string;
}

export type PatternValue = PermissionState | DenyWithReason;

export type SurfaceValue = PermissionState | Readonly<Record<string, PatternValue>>;

export type FlatPermissionConfig = Readonly<Record<string, SurfaceValue>>;

/** Upper bound on rules produced from one scope's permission map. */
export const MAX_SCOPE_RULES = 4_096;

export interface UniversalDefault {
  readonly action: RuleAction;
  readonly reason?: string;
}

export interface ScopeRuleEntry {
  readonly pattern: string;
  readonly action: RuleAction;
  readonly reason?: string;
  /** A compatibility copy produced from a Pi MCP surface key. */
  readonly synthetic?: boolean;
}

export interface ScopeRuleGroup {
  readonly surface: string;
  /** The scope's raw surface value was a catch-all string. */
  readonly replacesSurface: boolean;
  readonly entries: readonly ScopeRuleEntry[];
}

export interface ExpandedScopePermission {
  readonly groups: readonly ScopeRuleGroup[];
  readonly universal?: UniversalDefault;
  readonly truncated: boolean;
}

export interface NormalizedPermission {
  readonly rules: readonly Rule[];
  readonly universal?: UniversalDefault;
  readonly truncated: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function actionOf(
  value: unknown,
): { readonly action: RuleAction; readonly reason?: string } | undefined {
  if (value === "allow" || value === "ask" || value === "deny") return { action: value };
  const record = asRecord(value);
  if (record === undefined || record.action !== "deny") return undefined;
  if (record.reason !== undefined && typeof record.reason !== "string") return undefined;
  return record.reason === undefined
    ? { action: "deny" }
    : { action: "deny", reason: record.reason };
}

interface ParsedSurface {
  readonly entries: readonly ScopeRuleEntry[];
  readonly catchAll: boolean;
}

/** Parse one surface value. `undefined` means the value is not a surface value. */
function parseSurface(value: unknown): ParsedSurface | undefined {
  if (typeof value === "string") {
    const parsed = actionOf(value);
    return parsed === undefined
      ? undefined
      : { entries: [{ pattern: "*", ...parsed }], catchAll: true };
  }
  const record = asRecord(value);
  if (record === undefined) return undefined;
  const entries: ScopeRuleEntry[] = [];
  for (const pattern of Object.keys(record)) {
    if (pattern.length === 0) continue;
    const parsed = actionOf(record[pattern]);
    if (parsed === undefined) continue;
    entries.push({ pattern, ...parsed });
  }
  return { entries, catchAll: false };
}

function universalFrom(value: unknown): UniversalDefault | undefined {
  if (typeof value === "string") return actionOf(value);
  const record = asRecord(value);
  if (record === undefined || !Object.hasOwn(record, "*")) return undefined;
  return actionOf(record["*"]);
}

function isCompletePiMcpName(text: string): boolean {
  if (!text.startsWith("mcp__")) return false;
  const rest = text.slice("mcp__".length);
  const split = rest.indexOf("__");
  return split > 0 && split < rest.length - 2;
}

/** True when the pattern can match at least one complete Pi MCP tool name. */
export function matchesPiMcpToolName(pattern: string): boolean {
  const expanded = pattern.replace(/\*/g, "s").replace(/\?/g, "x");
  const probes = [expanded, `${expanded}__t`, "mcp__s__t"];
  for (const probe of probes) {
    if (isCompletePiMcpName(probe) && wildcardMatch(pattern, probe)) return true;
  }
  return false;
}

export function expandScopePermission(permission: unknown): ExpandedScopePermission {
  const raw = asRecord(permission);
  if (raw === undefined) return { groups: [], truncated: false };

  const explicits = new Map<string, ParsedSurface>();
  const families = new Map<string, ParsedSurface>();
  const targetOrder: string[] = [];
  const targets = new Set<string>();
  const piMcpCopies: ScopeRuleEntry[] = [];

  const addTarget = (surface: string): void => {
    if (targets.has(surface)) return;
    targets.add(surface);
    targetOrder.push(surface);
  };

  let universal: UniversalDefault | undefined;
  for (const key of Object.keys(raw)) {
    const value = raw[key];
    if (key === "*") {
      universal = universalFrom(value);
      continue;
    }
    if (key.length === 0 || value === undefined) continue;
    const parsed = parseSurface(value);
    if (parsed === undefined) continue;
    const parts = splitPathSurface(key);
    if (parts !== undefined && parts.direction === undefined) {
      if (parsed.entries.length === 0) continue;
      families.set(parts.family, parsed);
      addTarget(`${parts.family}_read`);
      addTarget(`${parts.family}_write`);
      continue;
    }
    if (parsed.entries.length === 0) continue;
    explicits.set(key, parsed);
    addTarget(key);
    if (parsed.catchAll && matchesPiMcpToolName(key)) {
      const entry = parsed.entries[0];
      piMcpCopies.push({ ...entry, pattern: key, synthetic: true });
    }
  }

  const groups: ScopeRuleGroup[] = [];
  let remaining = MAX_SCOPE_RULES;
  let truncated = false;

  const pushGroup = (group: ScopeRuleGroup): void => {
    if (remaining <= 0) {
      truncated = true;
      return;
    }
    const entries = group.entries.slice(0, remaining);
    if (entries.length < group.entries.length) truncated = true;
    remaining -= entries.length;
    if (entries.length > 0) groups.push({ ...group, entries });
  };

  for (const surface of targetOrder) {
    const parts = splitPathSurface(surface);
    if (parts !== undefined && parts.direction !== undefined) {
      const family = families.get(parts.family);
      const direct = explicits.get(surface);
      if (family === undefined && direct === undefined) continue;
      const explicitEntries = direct?.entries ?? [];
      const defined = new Set(explicitEntries.map((entry) => entry.pattern));
      const sugar = (family?.entries ?? []).filter((entry) => !defined.has(entry.pattern));
      const entries = [...sugar, ...explicitEntries];
      if (entries.length === 0) continue;
      pushGroup({
        surface,
        replacesSurface: direct === undefined
          ? family!.catchAll
          : direct.catchAll,
        entries,
      });
      continue;
    }
    const direct = explicits.get(surface);
    if (direct === undefined) continue;
    pushGroup({ surface, replacesSurface: direct.catchAll, entries: direct.entries });
  }

  if (piMcpCopies.length > 0) {
    pushGroup({ surface: "mcp", replacesSurface: false, entries: piMcpCopies });
  }

  return universal === undefined
    ? { groups, truncated }
    : { groups, universal, truncated };
}

export function normalizePermissionConfig(
  permission: unknown,
  origin: RuleOrigin,
): NormalizedPermission {
  const expanded = expandScopePermission(permission);
  const rules: Rule[] = [];
  for (const group of expanded.groups) {
    for (const entry of group.entries) {
      rules.push({
        surface: group.surface,
        pattern: entry.pattern,
        action: entry.action,
        origin,
        layer: "config",
        ...(entry.reason === undefined ? {} : { reason: entry.reason }),
      });
    }
  }
  return expanded.universal === undefined
    ? { rules, truncated: expanded.truncated }
    : { rules, universal: expanded.universal, truncated: expanded.truncated };
}
