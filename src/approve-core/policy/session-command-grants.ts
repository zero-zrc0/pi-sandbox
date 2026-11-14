/**
 * Session command grants.
 *
 * When a human chooses "Allow for this session" for a shell call, the exact
 * tool+arguments memory already covers an identical call. This module adds the
 * second half of that decision: a command family can be remembered per unit as
 * a leading token prefix (`git status`, `npm install`, `uv pip install`) so a
 * later `git status --short` inside the same session no longer prompts.
 *
 * A grant never widens on its own: entries are built only from a clean,
 * top-level unit the parser understood; units with a wrapper, a nested
 * execution context, or any unresolved/salvaged shape are remembered as exact
 * text; and a pattern is kept only when its prefix has at least two tokens, so
 * `rm x`, `curl url` and unknown programs stay exact instead of becoming
 * `rm *` / `curl *`. Matching is a strict prefix boundary: `git status`
 * accepts `git status` and `git status --short`, never `git statusx`.
 */
import type { BashCommand } from "../utils/access-intent/bash/command-enumeration";
import { suggestSessionPattern } from "./session-pattern";

export type SessionCommandGrant =
  | { readonly kind: "exact"; readonly text: string }
  | { readonly kind: "prefix"; readonly prefix: string };

/** Upper bound on remembered grants; the oldest entries are dropped first. */
export const MAX_SESSION_COMMAND_GRANTS = 64;

/**
 * A leading environment assignment before a command unit (`PATH=... git
 * status`, `FOO=1 bar`) can change which executable runs; such calls never
 * ride on a family grant.
 */
const LEADING_ASSIGNMENT =
  /(?:^|[;&|]\s*)(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s;&|]+)\s+)+(?=\S)/u;

function normalizedText(unit: BashCommand): string {
  return unit.text.trim();
}

function grantKey(grant: SessionCommandGrant): string {
  return grant.kind === "exact" ? `exact\0${grant.text}` : `prefix\0${grant.prefix}`;
}

function prefixTokenCount(prefix: string): number {
  return prefix.split(/\s+/u).filter((token) => token.length > 0).length;
}

function suggestGrant(unit: BashCommand): SessionCommandGrant | undefined {
  const text = normalizedText(unit);
  if (text.length === 0) return undefined;
  if (unit.wrapperKind !== undefined || unit.context !== undefined ||
      unit.parseUnresolved === true || unit.salvaged === true) {
    return Object.freeze({ kind: "exact" as const, text });
  }
  const suggestion = suggestSessionPattern(text);
  if (suggestion.length === 0 || !suggestion.endsWith("*")) {
    return Object.freeze({ kind: "exact" as const, text });
  }
  const prefix = suggestion.slice(0, -1).trimEnd();
  if (prefix.length === 0 || prefix.includes("\n") || prefixTokenCount(prefix) < 2) {
    return Object.freeze({ kind: "exact" as const, text });
  }
  return Object.freeze({ kind: "prefix" as const, prefix });
}

/**
 * The family grants an explicit human approval can remember for one parsed
 * command. Callers pass only units the parser proved clean; a wrapped or
 * nested unit is still returned as an exact grant.
 */
export function suggestSessionCommandGrants(
  units: readonly BashCommand[],
): readonly SessionCommandGrant[] {
  const grants: SessionCommandGrant[] = [];
  const seen = new Set<string>();
  for (const unit of units) {
    const grant = suggestGrant(unit);
    if (grant === undefined) continue;
    const key = grantKey(grant);
    if (seen.has(key)) continue;
    seen.add(key);
    grants.push(grant);
  }
  return Object.freeze(grants);
}

function grantMatchesUnit(grant: SessionCommandGrant, unit: BashCommand): boolean {
  if (unit.parseUnresolved === true || unit.salvaged === true) return false;
  const text = normalizedText(unit);
  if (grant.kind === "exact") return text === grant.text;
  if (unit.wrapperKind !== undefined || unit.context !== undefined) return false;
  return text === grant.prefix || text.startsWith(`${grant.prefix} `);
}

export interface SessionCommandGrants {
  readonly size: number;
  /** Remember the families of one explicitly approved call. */
  remember(grants: readonly SessionCommandGrant[]): void;
  /**
   * Drop every family grant the denied units would have used. A session deny
   * must win over an earlier family allow.
   */
  forget(units: readonly BashCommand[]): void;
  /**
   * True when every unit of the new command is covered by a remembered grant.
   * The raw command text is checked for a leading environment assignment.
   */
  matches(command: string, units: readonly BashCommand[]): boolean;
  clear(): void;
}

export function createSessionCommandGrants(
  limit = MAX_SESSION_COMMAND_GRANTS,
): SessionCommandGrants {
  const cap = Number.isSafeInteger(limit) && limit > 0 ? limit : MAX_SESSION_COMMAND_GRANTS;
  const entries: SessionCommandGrant[] = [];
  return {
    get size(): number {
      return entries.length;
    },
    remember(grants: readonly SessionCommandGrant[]): void {
      const known = new Set(entries.map(grantKey));
      for (const grant of grants) {
        const key = grantKey(grant);
        if (known.has(key)) continue;
        known.add(key);
        entries.push(grant);
      }
      while (entries.length > cap) entries.shift();
    },
    forget(units: readonly BashCommand[]): void {
      if (entries.length === 0 || units.length === 0) return;
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const entry = entries[index]!;
        if (units.some((unit) => grantMatchesUnit(entry, unit))) entries.splice(index, 1);
      }
    },
    matches(command: string, units: readonly BashCommand[]): boolean {
      if (command.trim().length === 0 || units.length === 0) return false;
      if (LEADING_ASSIGNMENT.test(command)) return false;
      if (entries.length === 0) return false;
      return units.every((unit) =>
        entries.some((entry) => grantMatchesUnit(entry, unit)));
    },
    clear(): void {
      entries.length = 0;
    },
  };
}
