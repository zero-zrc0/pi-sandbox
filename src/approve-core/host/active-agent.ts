/**
 * Active agent identity (specs/host-integration.md §1).
 *
 * The host can name the active agent on two surfaces: the newest session
 * `custom/active_agent` entry, or a `<active_agent name="...">` tag in the
 * system prompt. The entry scan wins because it is the only surface that can
 * explicitly clear the name; a clear must not fall back to an older entry or
 * to the prompt.
 */
import type { ExtensionContext, SessionEntry } from "@earendil-works/pi-coding-agent";

/** The `customType` a session entry uses to carry the active agent name. */
export const ACTIVE_AGENT_ENTRY_TYPE = "active_agent";

/** Minimal session reader the host hands in; structurally compatible with ExtensionContext. */
export interface ActiveAgentHost {
  readonly sessionManager: {
    /**
     * The active leaf's history. `getEntries()` also returns abandoned
     * branches, so the branch is the authoritative active history when the
     * manager exposes it.
     */
    getBranch?: () => readonly SessionEntry[];
    getEntries: () => readonly SessionEntry[];
  };
  readonly getSystemPrompt?: () => string | undefined;
}

const ACTIVE_AGENT_TAG = /<active_agent\s+name\s*=\s*(?:"([^"]*)"|'([^']*)')\s*\/?>/gi;
const ACTIVE_AGENT_ENTRY_DATA = "name";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Latest-valid entry scan; `null` = explicitly cleared; `undefined` = no entry at all.
 *
 * Records that cannot name an agent (missing data, non-string and non-null
 * `name`, blank string) are skipped so the last usable record decides.
 */
export function activeAgentFromEntries(
  entries: readonly SessionEntry[],
): string | undefined | null {
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const entry = entries[index]!;
    if (entry.type !== "custom" || entry.customType !== ACTIVE_AGENT_ENTRY_TYPE) continue;
    const data: unknown = entry.data;
    if (!isRecord(data) || !Object.hasOwn(data, ACTIVE_AGENT_ENTRY_DATA)) continue;
    const name = data[ACTIVE_AGENT_ENTRY_DATA];
    if (name === null) return null;
    if (typeof name !== "string") continue;
    const trimmed = name.trim();
    if (trimmed !== "") return trimmed;
  }
  return undefined;
}

/** Recognize `<active_agent name="...">` (single or double quotes, case-insensitive tag). */
export function activeAgentFromSystemPrompt(prompt: string | undefined): string | undefined {
  if (prompt === undefined || prompt === "") return undefined;
  let result: string | undefined;
  for (const match of prompt.matchAll(ACTIVE_AGENT_TAG)) {
    const value = match[1] ?? match[2];
    if (value === undefined) continue;
    const trimmed = value.trim();
    if (trimmed !== "") result = trimmed;
  }
  return result;
}

/**
 * Entries first (backwards), then system prompt; a cleared entry suppresses the prompt.
 *
 * The scan reads the active branch when the session manager exposes one: the
 * flat entry list also holds abandoned branches, whose names are not active.
 */
export function getActiveAgentName(host: ActiveAgentHost | ExtensionContext): string | undefined {
  const fromEntries = activeAgentFromEntries(
    host.sessionManager.getBranch?.() ?? host.sessionManager.getEntries(),
  );
  if (fromEntries === null) return undefined;
  if (fromEntries !== undefined) return fromEntries;
  const readSystemPrompt = host.getSystemPrompt;
  if (readSystemPrompt === undefined) return undefined;
  return activeAgentFromSystemPrompt(readSystemPrompt());
}
