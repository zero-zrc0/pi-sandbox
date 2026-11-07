/**
 * Host mode reminder (specs/host-integration.md §8).
 *
 * The host asks for a short, hidden informational message the first time a
 * non-extension user input arrives after a permission-mode change. The reminder
 * only describes the current mode and its access restriction; it never runs a
 * permission decision itself. State is persisted as custom session entries so a
 * reload can rebuild the last unmatched reminder state from the branch.
 */
import type { SessionEntry } from "@earendil-works/pi-coding-agent";
import type { ReviewerMode } from "#approve-core/context/types";

export const MODE_REMINDER_ENTRY_TYPE = "permission:mode-reminder";
export const MODE_REMINDER_MESSAGE_TYPE = "permission:mode-reminder";

/**
 * One informational sentence. `{mode}` and `{restriction}` are substituted by
 * `modeReminderText`; the wording never claims to grant or execute access.
 */
export const MODE_REMINDER_TEXT =
  "Mode reminder: the session is in {mode} mode, which means {restriction}; " +
  "this notice is informational and does not approve, deny, or execute anything.";

const MODE_ACCESS_RESTRICTIONS = Object.freeze({
  "read-only": "reads are allowed and writes or commands are blocked",
  default: "commands and file changes require approval",
  "auto-review": "the model reviewer decides which commands and file changes need approval",
  "full-access": "commands and file changes run without sandbox restrictions",
} satisfies Record<ReviewerMode, string>);

/** Render the hidden reminder sentence for one mode. */
export function modeReminderText(mode: ReviewerMode): string {
  return MODE_REMINDER_TEXT.replace("{mode}", mode).replace(
    "{restriction}",
    MODE_ACCESS_RESTRICTIONS[mode],
  );
}

/** Narrow host port: the Pi API calls the reminder needs. */
export interface ModeReminderApi {
  sendMessage(
    message: { readonly customType: string; readonly content: string; readonly display: boolean },
    options?: {
      readonly triggerTurn?: boolean;
      readonly deliverAs?: "steer" | "followUp" | "nextTurn";
    },
  ): void;
  appendEntry(customType: string, data?: unknown): void;
  getBranch(): readonly SessionEntry[];
}

export interface ModeReminderState {
  readonly revision: number;
  readonly mode: ReviewerMode | undefined;
  readonly pending: boolean;
}

export interface ModeReminderInput {
  readonly mode: ReviewerMode;
  readonly source: "interactive" | "rpc" | "extension";
  readonly streamingBehavior?: "steer" | "followUp";
}

export interface ModeReminder {
  /** Session revision++ and pending state persisted. */
  noteModeChange(mode: ReviewerMode): number;
  /** Rebuild state from the branch: last unmatched state and maximum revision. */
  restore(branch?: readonly SessionEntry[]): void;
  /** True when a reminder was actually sent or state was confirmed cleared. */
  handleInput(input: ModeReminderInput): boolean;
  /** Confirm recording; restore the still-pending state when the reminder is missing. */
  agentEnd(branch?: readonly SessionEntry[]): void;
  /** Idle confirmation path. */
  idle(branch?: readonly SessionEntry[]): void;
  state(): ModeReminderState;
}

export interface ModeReminderOptions {
  readonly api: ModeReminderApi;
  readonly now?: () => number;
}

// ---------------------------------------------------------------------------
// Branch scanning
// ---------------------------------------------------------------------------

const REVIEWER_MODES: readonly ReviewerMode[] = Object.freeze([
  "read-only",
  "default",
  "auto-review",
  "full-access",
]);

function isReviewerMode(value: unknown): value is ReviewerMode {
  return typeof value === "string" && (REVIEWER_MODES as readonly string[]).includes(value);
}

interface PersistedReminderState {
  readonly revision: number;
  readonly mode: ReviewerMode;
  readonly pending: boolean;
}

function readPersistedState(data: unknown): PersistedReminderState | undefined {
  if (typeof data !== "object" || data === null) return undefined;
  const record = data as Record<string, unknown>;
  if (
    typeof record.revision !== "number" ||
    !Number.isSafeInteger(record.revision) ||
    record.revision < 0
  ) {
    return undefined;
  }
  if (!isReviewerMode(record.mode)) return undefined;
  if (typeof record.pending !== "boolean") return undefined;
  return { revision: record.revision, mode: record.mode, pending: record.pending };
}

function isReminderMessage(entry: SessionEntry): boolean {
  return entry.type === "custom_message" && entry.customType === MODE_REMINDER_MESSAGE_TYPE;
}

interface BranchSnapshot {
  /** Highest revision ever persisted on this branch. */
  readonly revision: number;
  /** Mode of the last persisted state, if any. */
  readonly mode: ReviewerMode | undefined;
  /** True when the last persisted state still waits for its reminder. */
  readonly pending: boolean;
  /** Raw `pending` flag of the last persisted state. */
  readonly lastPending: boolean;
  /** True when a reminder message appears after the last persisted state. */
  readonly matched: boolean;
}

function readBranch(branch: readonly SessionEntry[]): BranchSnapshot {
  let revision = 0;
  let last: PersistedReminderState | undefined;
  let matched = false;

  for (const entry of branch) {
    if (entry.type === "custom" && entry.customType === MODE_REMINDER_ENTRY_TYPE) {
      const state = readPersistedState(entry.data);
      if (state === undefined) continue;
      last = state;
      revision = Math.max(revision, state.revision);
      matched = false;
    } else if (isReminderMessage(entry) && last !== undefined) {
      matched = true;
    }
  }

  return {
    revision,
    mode: last?.mode,
    pending: last !== undefined && last.pending && !matched,
    lastPending: last?.pending ?? false,
    matched,
  };
}

/**
 * True when a reminder message was persisted after the latest pending state.
 * A later `pending: false` state does not erase the record: it is the queued
 * send's own confirmation write, and agent_end may still need the match.
 */
function hasRecordedReminder(branch: readonly SessionEntry[]): boolean {
  let awaiting = false;
  let recorded = false;

  for (const entry of branch) {
    if (entry.type === "custom" && entry.customType === MODE_REMINDER_ENTRY_TYPE) {
      const state = readPersistedState(entry.data);
      if (state === undefined) continue;
      if (state.pending) {
        awaiting = true;
        recorded = false;
      }
    } else if (isReminderMessage(entry) && awaiting) {
      recorded = true;
    }
  }

  return recorded;
}

export function createModeReminder(options: ModeReminderOptions): ModeReminder {
  const { api } = options;

  let revision = 0;
  let mode: ReviewerMode | undefined;
  let pending = false;
  let queued = false;

  function persist(): void {
    api.appendEntry(MODE_REMINDER_ENTRY_TYPE, { revision, mode, pending });
  }

  function sendReminder(reminderMode: ReviewerMode, deliverAs?: "steer" | "followUp"): void {
    const message = {
      customType: MODE_REMINDER_MESSAGE_TYPE,
      content: modeReminderText(reminderMode),
      display: false,
    };
    if (deliverAs === undefined) api.sendMessage(message);
    else api.sendMessage(message, { deliverAs });
  }

  return {
    noteModeChange(nextMode) {
      revision += 1;
      mode = nextMode;
      pending = true;
      queued = false;
      persist();
      return revision;
    },

    restore(branch) {
      const snapshot = readBranch(branch ?? api.getBranch());
      revision = snapshot.revision;
      mode = snapshot.mode;
      pending = snapshot.pending;
      queued = false;
    },

    handleInput(input) {
      if (input.source === "extension") return false;

      if (input.streamingBehavior !== undefined) {
        if (!pending) return false;
        if (hasRecordedReminder(api.getBranch())) {
          // An idle input already recorded this revision's reminder; a later
          // streaming input confirms it instead of sending a duplicate.
          pending = false;
          persist();
          return true;
        }
        sendReminder(mode ?? input.mode, input.streamingBehavior);
        queued = true;
        pending = false;
        persist();
        return true;
      }

      if (!pending) return false;
      if (hasRecordedReminder(api.getBranch())) {
        pending = false;
        persist();
        return true;
      }
      sendReminder(mode ?? input.mode);
      return true;
    },

    agentEnd(branch) {
      if (!pending && !queued) return;
      const entries = branch ?? api.getBranch();
      if (hasRecordedReminder(entries)) {
        const snapshot = readBranch(entries);
        queued = false;
        pending = false;
        if (snapshot.lastPending) persist();
        return;
      }
      if (queued) {
        // The queued reminder never reached the branch; put the state back so a
        // later input or reload still reminds the user.
        queued = false;
        pending = true;
        persist();
      }
    },

    idle(branch) {
      if (!pending && !queued) return;
      const entries = branch ?? api.getBranch();
      if (!hasRecordedReminder(entries)) return;
      const snapshot = readBranch(entries);
      queued = false;
      pending = false;
      if (snapshot.lastPending) persist();
    },

    state() {
      return Object.freeze({ revision, mode, pending });
    },
  };
}
