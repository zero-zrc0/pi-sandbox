/**
 * Cross-scope permission merging.
 *
 * When both scopes describe a surface with pattern maps they merge pattern by
 * pattern; in any other combination the higher scope replaces the whole
 * surface value. Every `(surface, pattern)` records the scope that last
 * contributed it. Lower contributions keep their place and a higher scope
 * appends what it contributes, so rule order keeps last-match-wins semantics.
 */
import type {
  ScopeRuleEntry,
  ScopeRuleGroup,
  UniversalDefault,
} from "./normalize";
import type { RuleOrigin } from "./rule";

export interface MergedSurfaceState {
  readonly entries: readonly ScopeRuleEntry[];
  /** The merged surface value is a catch-all string, not a pattern map. */
  readonly catchAll: boolean;
  /** The scope that last contributed each pattern. */
  readonly origins: ReadonlyMap<string, RuleOrigin>;
}

export interface PermissionMergeState {
  readonly surfaces: ReadonlyMap<string, MergedSurfaceState>;
  readonly universal?: UniversalDefault & { readonly origin: RuleOrigin };
}

export function emptyMergeState(): PermissionMergeState {
  return { surfaces: new Map() };
}

/** Merge one scope's expanded groups into the state built from lower scopes. */
export function mergeScopeGroups(
  state: PermissionMergeState,
  groups: readonly ScopeRuleGroup[],
  universal: UniversalDefault | undefined,
  origin: RuleOrigin,
): PermissionMergeState {
  const surfaces = new Map(state.surfaces);
  for (const group of groups) {
    const current = surfaces.get(group.surface);
    const replaces = current === undefined || current.catchAll || group.replacesSurface;
    if (replaces) {
      const origins = new Map<string, RuleOrigin>();
      for (const entry of group.entries) origins.set(entry.pattern, origin);
      surfaces.set(group.surface, {
        entries: group.entries,
        catchAll: group.replacesSurface,
        origins,
      });
      continue;
    }
    const overridden = new Map(group.entries.map((entry) => [entry.pattern, entry]));
    const entries = current.entries.map((entry) => overridden.get(entry.pattern) ?? entry);
    const known = new Set(current.entries.map((entry) => entry.pattern));
    for (const entry of group.entries) {
      if (!known.has(entry.pattern)) entries.push(entry);
    }
    const origins = new Map(current.origins);
    for (const pattern of overridden.keys()) origins.set(pattern, origin);
    surfaces.set(group.surface, {
      entries,
      catchAll: false,
      origins,
    });
  }
  return {
    surfaces,
    ...(universal === undefined
      ? (state.universal === undefined ? {} : { universal: state.universal })
      : { universal: { ...universal, origin } }),
  };
}

/** The scope that last contributed one `(surface, pattern)` pair. */
export function originOf(
  state: PermissionMergeState,
  surface: string,
  pattern: string,
): RuleOrigin | undefined {
  return state.surfaces.get(surface)?.origins.get(pattern);
}
