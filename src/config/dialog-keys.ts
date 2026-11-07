/**
 * Dialog key preferences for the approval dialog (config schema §8).
 *
 * The approval dialog always offers five actions. Each action has a default
 * single-character shortcut, and a user may override any of them through the
 * optional `permissionDialogKeys` map. Because these bindings only change what
 * the dialog displays, resolution is tolerant: an unusable character, a
 * navigation-reserved character or a duplicate binding is reported and then
 * dropped, never treated as a permission configuration failure.
 *
 * Resolution runs in two passes over the fixed action order. The first pass
 * validates each override in isolation; the second pass removes remaining
 * overrides whose character collides with another action's key until the table
 * is unique. The iteration is bounded so a hostile or surprising input can never
 * loop forever.
 */
import { z } from "zod";

/** The dialog actions in their fixed display order. */
export const DIALOG_KEY_ACTIONS = [
  "approve",
  "approveSession",
  "approveSessionBoth",
  "deny",
  "denyWithReason",
] as const;

export type DialogKeyAction = (typeof DIALOG_KEY_ACTIONS)[number];

/** Default shortcut per action, in the same fixed order. */
export const DEFAULT_DIALOG_KEYS: Readonly<Record<DialogKeyAction, string>> = Object.freeze({
  approve: "y",
  approveSession: "s",
  approveSessionBoth: "b",
  deny: "n",
  denyWithReason: "r",
});

/** Characters kept for list navigation; a preference for them is ignored. */
export const RESERVED_DIALOG_KEYS: readonly string[] = Object.freeze(["j", "k"]);

/**
 * Printable ASCII punctuation accepted as a dialog shortcut.
 *
 * Basis: a shortcut is a single key press, so lowercase ASCII letters and digits
 * are always available and the printable ASCII punctuation range may be used as
 * well. Whitespace cannot stand alone as a key, and "+" is reserved by the key
 * parser as the modifier separator (for example "ctrl+enter"), so both stay out
 * of this set. Uppercase letters are intentionally absent: normalization is not
 * performed, so an uppercase binding is reported as unbindable instead.
 */
const BINDABLE_PUNCTUATION_TEXT = "!\"#$%&'()*,-./:;<=>?@[\\]^_`{|}~";

export const BINDABLE_DIALOG_PUNCTUATION: readonly string[] = Object.freeze([
  ...BINDABLE_PUNCTUATION_TEXT,
]);

const LOWERCASE_LETTER_OR_DIGIT = /^[a-z0-9]$/u;

/** Maximum conflict-removal rounds; the algorithm needs at most one per action. */
const MAX_CONFLICT_ROUNDS = DIALOG_KEY_ACTIONS.length;

/** True when a single character could be bound as a dialog shortcut. */
export function isBindableDialogKey(value: string): boolean {
  return (
    value.length === 1 &&
    (LOWERCASE_LETTER_OR_DIGIT.test(value) || BINDABLE_DIALOG_PUNCTUATION.includes(value))
  );
}

/**
 * Display preferences for the dialog keys.
 *
 * Deliberately tolerant: any string-valued map is accepted so that a display
 * preference can never reject the permission configuration. Unknown actions and
 * unusable bindings are handled later by {@link resolveDialogKeys}, which
 * reports them without failing.
 */
export const permissionDialogKeysSchema: z.ZodType<DialogKeyOverrides> = z.record(
  z.string(),
  z.string(),
);

/** Raw dialog key overrides as written in a configuration file. */
export type DialogKeyOverrides = Readonly<Record<string, string>>;

/** Why a dialog key override was not applied. */
export type DialogKeyIssueCode = "unbindable" | "reserved" | "conflict";

/** One ignored dialog key override. */
export interface DialogKeyIssue {
  readonly action: DialogKeyAction;
  readonly value: string;
  readonly code: DialogKeyIssueCode;
}

/** Fully bound dialog key table: every action is present. */
export type ResolvedDialogKeys = Readonly<Record<DialogKeyAction, string>>;

/** Outcome of dialog key resolution. */
export interface DialogKeysResolution {
  readonly keys: ResolvedDialogKeys;
  readonly issues: readonly DialogKeyIssue[];
}

function isRecordValue(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** First pair of actions sharing a character, searching the fixed action order. */
function findFirstKeyConflict(
  keys: Readonly<Record<DialogKeyAction, string>>,
): readonly [DialogKeyAction, DialogKeyAction] | undefined {
  for (let leftIndex = 0; leftIndex < DIALOG_KEY_ACTIONS.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < DIALOG_KEY_ACTIONS.length; rightIndex += 1) {
      const left = DIALOG_KEY_ACTIONS[leftIndex];
      const right = DIALOG_KEY_ACTIONS[rightIndex];
      if (keys[left] === keys[right]) {
        return [left, right];
      }
    }
  }
  return undefined;
}

function hasEffectiveOverride(
  action: DialogKeyAction,
  overrides: ReadonlyMap<DialogKeyAction, string>,
): boolean {
  const override = overrides.get(action);
  return override !== undefined && override !== DEFAULT_DIALOG_KEYS[action];
}

/**
 * Pick the action whose override to drop. A redundant override (one that repeats
 * the action's own default) cannot change the table, so it is skipped when the
 * other action carries a real override; that keeps one bad character to a single
 * reported conflict instead of a second pointless round.
 */
function chooseConflictVictim(
  left: DialogKeyAction,
  right: DialogKeyAction,
  overrides: ReadonlyMap<DialogKeyAction, string>,
): DialogKeyAction {
  if (hasEffectiveOverride(right, overrides)) return right;
  if (hasEffectiveOverride(left, overrides)) return left;
  // Defensive fallback: still remove something so the bounded loop progresses.
  return overrides.has(right) ? right : left;
}

/**
 * Resolve the tolerant `permissionDialogKeys` map into a complete key table.
 *
 * A non-object value, an unknown action and a non-string value are ignored.
 * Uppercase letters, "+", multi-character values and reserved navigation keys
 * are reported as issues and keep their default. Remaining conflicts are removed
 * override by override, restoring the default for the removed action. Issues are
 * returned in the fixed action order.
 */
export function resolveDialogKeys(value: unknown): DialogKeysResolution {
  if (!isRecordValue(value)) {
    return { keys: { ...DEFAULT_DIALOG_KEYS }, issues: [] };
  }

  const overrides = new Map<DialogKeyAction, string>();
  const issues: DialogKeyIssue[] = [];

  // First pass: validate each known action's override in isolation.
  for (const action of DIALOG_KEY_ACTIONS) {
    if (!Object.hasOwn(value, action)) continue;
    const raw = value[action];
    if (typeof raw !== "string") {
      issues.push({ action, value: String(raw), code: "unbindable" });
      continue;
    }
    if (raw.length !== 1 || !isBindableDialogKey(raw)) {
      issues.push({ action, value: raw, code: "unbindable" });
      continue;
    }
    if (RESERVED_DIALOG_KEYS.includes(raw)) {
      issues.push({ action, value: raw, code: "reserved" });
      continue;
    }
    overrides.set(action, raw);
  }

  const keys: Record<DialogKeyAction, string> = { ...DEFAULT_DIALOG_KEYS };
  for (const action of DIALOG_KEY_ACTIONS) {
    const override = overrides.get(action);
    if (override !== undefined) keys[action] = override;
  }

  // Second pass: remove colliding overrides until the table is unique.
  for (let round = 0; round < MAX_CONFLICT_ROUNDS; round += 1) {
    const conflict = findFirstKeyConflict(keys);
    if (conflict === undefined) break;
    const [left, right] = conflict;
    const victim = chooseConflictVictim(left, right, overrides);
    const conflictValue = keys[victim];
    overrides.delete(victim);
    keys[victim] = DEFAULT_DIALOG_KEYS[victim];
    issues.push({ action: victim, value: conflictValue, code: "conflict" });
  }

  issues.sort(
    (first, second) =>
      DIALOG_KEY_ACTIONS.indexOf(first.action) - DIALOG_KEY_ACTIONS.indexOf(second.action),
  );
  return { keys, issues };
}
