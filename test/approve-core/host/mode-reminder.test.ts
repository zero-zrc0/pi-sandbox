/**
 * Host mode reminder (specs/host-integration.md §8).
 *
 * Every test drives the public `ModeReminder` surface with an in-memory branch
 * and a fake Pi API. The fake `appendEntry` appends a `custom` entry and the
 * fake `sendMessage` records the call plus appends a `custom_message` entry, so
 * the tests observe exactly what the host would persist. Expected values are
 * worked examples from the spec; no module internals are mocked.
 */
import { describe, expect, it } from "vitest";
import {
  MODE_REMINDER_ENTRY_TYPE,
  MODE_REMINDER_MESSAGE_TYPE,
  createModeReminder,
  type ModeReminderApi,
} from "#approve-core/host/mode-reminder";
import type { ReviewerMode } from "#approve-core/context/types";
import type { SessionEntry } from "@earendil-works/pi-coding-agent";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FIXED_TIME = "2026-01-01T00:00:00.000Z";

type SendOptions = {
  readonly triggerTurn?: boolean;
  readonly deliverAs?: "steer" | "followUp" | "nextTurn";
};

interface RecordedMessage {
  readonly message: {
    readonly customType: string;
    readonly content: string;
    readonly display: boolean;
  };
  readonly options?: SendOptions;
}

interface FakeModeReminderApi extends ModeReminderApi {
  readonly entries: SessionEntry[];
  readonly messages: RecordedMessage[];
  readonly appended: { readonly customType: string; readonly data: unknown }[];
}

function createFakeApi(): FakeModeReminderApi {
  const entries: SessionEntry[] = [];
  const messages: RecordedMessage[] = [];
  const appended: { customType: string; data: unknown }[] = [];
  let nextId = 1;
  const base = () => ({ id: `entry-${nextId++}`, parentId: null, timestamp: FIXED_TIME });

  return {
    entries,
    messages,
    appended,
    appendEntry(customType, data) {
      appended.push({ customType, data });
      entries.push({ ...base(), type: "custom", customType, data });
    },
    sendMessage(message, options) {
      messages.push(options === undefined ? { message } : { message, options });
      entries.push({
        ...base(),
        type: "custom_message",
        customType: message.customType,
        content: message.content,
        display: message.display,
      });
    },
    getBranch() {
      return entries;
    },
  };
}

function createReminder(api: FakeModeReminderApi) {
  return createModeReminder({ api, now: () => 0 });
}

let branchSequence = 0;
function branchBase() {
  branchSequence += 1;
  return { id: `branch-${branchSequence}`, parentId: null, timestamp: FIXED_TIME };
}

function modeStateEntry(revision: number, mode: ReviewerMode, pending: boolean): SessionEntry {
  return {
    ...branchBase(),
    type: "custom",
    customType: MODE_REMINDER_ENTRY_TYPE,
    data: { revision, mode, pending },
  };
}

function reminderMessageEntry(): SessionEntry {
  return {
    ...branchBase(),
    type: "custom_message",
    customType: MODE_REMINDER_MESSAGE_TYPE,
    content: "remembered reminder",
    display: false,
  };
}

function foreignCustomEntry(customType: string, data: unknown): SessionEntry {
  return { ...branchBase(), type: "custom", customType, data };
}

// ---------------------------------------------------------------------------
// Revision and persisted pending state (§8 bullet 1)
// ---------------------------------------------------------------------------

describe("mode reminder revision", () => {
  it("starts with no revision, no mode and no pending reminder", () => {
    const reminder = createReminder(createFakeApi());

    expect(reminder.state()).toEqual({ revision: 0, mode: undefined, pending: false });
  });

  it("increments one revision per mode change and persists a pending state entry", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);

    expect(reminder.noteModeChange("default")).toBe(1);
    expect(reminder.noteModeChange("auto-review")).toBe(2);

    expect(reminder.state()).toEqual({ revision: 2, mode: "auto-review", pending: true });
    expect(api.appended).toEqual([
      {
        customType: MODE_REMINDER_ENTRY_TYPE,
        data: { revision: 1, mode: "default", pending: true },
      },
      {
        customType: MODE_REMINDER_ENTRY_TYPE,
        data: { revision: 2, mode: "auto-review", pending: true },
      },
    ]);
    expect(api.entries.map((entry) => entry.type)).toEqual(["custom", "custom"]);
  });

  it("returns a frozen state snapshot that does not change when the session advances", () => {
    const reminder = createReminder(createFakeApi());
    const before = reminder.state();

    reminder.noteModeChange("read-only");

    expect(Object.isFrozen(before)).toBe(true);
    expect(before).toEqual({ revision: 0, mode: undefined, pending: false });
    expect(reminder.state()).toEqual({ revision: 1, mode: "read-only", pending: true });
  });
});

// ---------------------------------------------------------------------------
// Restore from the session branch (§8 bullet 1)
// ---------------------------------------------------------------------------

describe("mode reminder restore", () => {
  it("rebuilds the pending state from the API branch when no branch is passed", () => {
    const api = createFakeApi();
    const before = createReminder(api);
    before.noteModeChange("auto-review");

    const restored = createReminder(api);
    restored.restore();

    expect(restored.state()).toEqual({ revision: 1, mode: "auto-review", pending: true });
  });

  it("treats a reminder message after the pending state as matched", () => {
    const reminder = createReminder(createFakeApi());
    reminder.restore([modeStateEntry(3, "default", true), reminderMessageEntry()]);

    expect(reminder.state()).toEqual({ revision: 3, mode: "default", pending: false });
  });

  it("keeps a pending state whose reminder has not been recorded yet", () => {
    const reminder = createReminder(createFakeApi());
    reminder.restore([
      modeStateEntry(1, "default", true),
      reminderMessageEntry(),
      modeStateEntry(2, "read-only", true),
    ]);

    expect(reminder.state()).toEqual({ revision: 2, mode: "read-only", pending: true });
  });

  it("takes the mode from the last persisted state but the maximum revision ever seen", () => {
    const reminder = createReminder(createFakeApi());
    reminder.restore([
      modeStateEntry(7, "read-only", true),
      modeStateEntry(4, "full-access", true),
    ]);

    expect(reminder.state()).toEqual({ revision: 7, mode: "full-access", pending: true });
  });

  it("ignores foreign entries and invalid persisted reminder states", () => {
    const invalidModeState: SessionEntry = {
      ...branchBase(),
      type: "custom",
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: -1, mode: "bogus", pending: true },
    };
    const reminder = createReminder(createFakeApi());

    reminder.restore([foreignCustomEntry("active_agent", { name: "reviewer" }), invalidModeState]);

    expect(reminder.state()).toEqual({ revision: 0, mode: undefined, pending: false });
  });

  it("keeps revision numbering monotonic across sends", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");
    reminder.handleInput({ mode: "default", source: "interactive", streamingBehavior: "steer" });

    expect(reminder.noteModeChange("full-access")).toBe(2);
    expect(reminder.state()).toEqual({ revision: 2, mode: "full-access", pending: true });
  });

  it("drives a streaming reminder from a restored pending state", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.restore([modeStateEntry(4, "auto-review", true)]);

    expect(
      reminder.handleInput({
        mode: "auto-review",
        source: "interactive",
        streamingBehavior: "steer",
      }),
    ).toBe(true);

    expect(api.messages[0]?.message.content).toContain("auto-review");
    expect(api.messages[0]?.options).toEqual({ deliverAs: "steer" });
    expect(reminder.state()).toEqual({ revision: 4, mode: "auto-review", pending: false });
  });

  it("continues revision numbering after a restore", () => {
    const reminder = createReminder(createFakeApi());
    reminder.restore([modeStateEntry(5, "default", false), reminderMessageEntry()]);

    expect(reminder.noteModeChange("full-access")).toBe(6);
  });
});

// ---------------------------------------------------------------------------
// Input gating (§8 bullets 2 and 6)
// ---------------------------------------------------------------------------

describe("mode reminder input source", () => {
  it("never sends for extension input, even when a reminder is pending", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");

    const handled = reminder.handleInput({ mode: "default", source: "extension" });

    expect(handled).toBe(false);
    expect(api.messages).toEqual([]);
    expect(api.appended).toHaveLength(1);
    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: true });
  });

  it("ignores a streaming behavior on extension input", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");

    const handled = reminder.handleInput({
      mode: "read-only",
      source: "extension",
      streamingBehavior: "steer",
    });

    expect(handled).toBe(false);
    expect(api.messages).toEqual([]);
    expect(reminder.state().pending).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Streaming delivery (§8 bullets 2, 3 and 4)
// ---------------------------------------------------------------------------

const MODE_TEXT_CASES: readonly { readonly mode: ReviewerMode; readonly expected: string }[] = [
  {
    mode: "read-only",
    expected:
      "Mode reminder: the session is in read-only mode, which means reads are allowed and writes or commands are blocked; this notice is informational and does not approve, deny, or execute anything.",
  },
  {
    mode: "default",
    expected:
      "Mode reminder: the session is in default mode, which means commands and file changes require approval; this notice is informational and does not approve, deny, or execute anything.",
  },
  {
    mode: "auto-review",
    expected:
      "Mode reminder: the session is in auto-review mode, which means the model reviewer decides which commands and file changes need approval; this notice is informational and does not approve, deny, or execute anything.",
  },
  {
    mode: "full-access",
    expected:
      "Mode reminder: the session is in full-access mode, which means commands and file changes run without sandbox restrictions; this notice is informational and does not approve, deny, or execute anything.",
  },
];

describe("mode reminder message", () => {
  it.each(MODE_TEXT_CASES)(
    "is hidden, clean-room and names the $mode access restriction",
    ({ mode, expected }) => {
      const api = createFakeApi();
      const reminder = createReminder(api);
      reminder.noteModeChange(mode);

      reminder.handleInput({ mode, source: "interactive", streamingBehavior: "steer" });

      expect(api.messages).toEqual([
        {
          message: {
            customType: MODE_REMINDER_MESSAGE_TYPE,
            content: expected,
            display: false,
          },
          options: { deliverAs: "steer" },
        },
      ]);
    },
  );
});

describe("mode reminder streaming delivery", () => {
  it("sends the pending reminder and queues the state with a cleared pending flag", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    const revision = reminder.noteModeChange("default");

    const handled = reminder.handleInput({
      mode: "default",
      source: "interactive",
      streamingBehavior: "steer",
    });

    expect(handled).toBe(true);
    expect(api.messages).toHaveLength(1);
    expect(reminder.state()).toEqual({ revision, mode: "default", pending: false });
    expect(api.appended[1]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "default", pending: false },
    });
  });

  it("passes the event's followUp streaming behavior through as deliverAs", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("auto-review");

    reminder.handleInput({
      mode: "auto-review",
      source: "rpc",
      streamingBehavior: "followUp",
    });

    expect(api.messages[0]?.options).toEqual({ deliverAs: "followUp" });
  });

  it("does not resend when the same revision was already reminded at idle", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");
    reminder.handleInput({ mode: "default", source: "interactive" });

    const handled = reminder.handleInput({
      mode: "default",
      source: "interactive",
      streamingBehavior: "steer",
    });

    expect(handled).toBe(true);
    expect(api.messages).toHaveLength(1);
    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: false });
    expect(api.appended[1]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "default", pending: false },
    });
  });

  it("never sends twice for the same mode change", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");

    expect(
      reminder.handleInput({ mode: "default", source: "interactive", streamingBehavior: "steer" }),
    ).toBe(true);
    expect(
      reminder.handleInput({ mode: "default", source: "interactive", streamingBehavior: "followUp" }),
    ).toBe(false);

    expect(api.messages).toHaveLength(1);
    expect(api.appended).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Idle delivery (§8 bullets 3 and 5)
// ---------------------------------------------------------------------------

describe("mode reminder idle delivery", () => {
  it("sends one hidden reminder for a pending state without any streaming options", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");

    const handled = reminder.handleInput({ mode: "read-only", source: "interactive" });

    expect(handled).toBe(true);
    expect(api.messages).toEqual([
      {
        message: {
          customType: MODE_REMINDER_MESSAGE_TYPE,
          content: MODE_TEXT_CASES[0].expected,
          display: false,
        },
      },
    ]);
    expect(reminder.state()).toEqual({ revision: 1, mode: "read-only", pending: true });
  });

  it("persists the clear instead of sending again once the reminder is recorded", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");
    reminder.handleInput({ mode: "read-only", source: "interactive" });

    const handled = reminder.handleInput({ mode: "read-only", source: "rpc" });

    expect(handled).toBe(true);
    expect(api.messages).toHaveLength(1);
    expect(api.appended[1]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "read-only", pending: false },
    });
    expect(reminder.state()).toEqual({ revision: 1, mode: "read-only", pending: false });
  });

  it("reports no work once the pending state has been confirmed", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");
    reminder.handleInput({ mode: "read-only", source: "interactive" });
    reminder.handleInput({ mode: "read-only", source: "interactive" });

    expect(reminder.handleInput({ mode: "read-only", source: "interactive" })).toBe(false);
    expect(api.messages).toHaveLength(1);
    expect(api.appended).toHaveLength(2);
  });

  it("sends nothing while idle when no reminder is pending", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);

    expect(reminder.handleInput({ mode: "default", source: "interactive" })).toBe(false);
    expect(api.messages).toEqual([]);
    expect(api.appended).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Turn-end confirmation (§8 bullet 4)
// ---------------------------------------------------------------------------

describe("mode reminder agent_end", () => {
  it("clears a reminder sent at idle once the branch records it", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");
    reminder.handleInput({ mode: "default", source: "interactive" });

    reminder.agentEnd();

    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: false });
    expect(api.appended[1]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "default", pending: false },
    });
  });

  it("keeps a pending state when no reminder was recorded", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");

    reminder.agentEnd();

    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: true });
    expect(api.appended).toHaveLength(1);
  });

  it("does not restore a queued reminder that the branch already recorded", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");
    reminder.handleInput({ mode: "default", source: "interactive", streamingBehavior: "steer" });

    reminder.agentEnd();

    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: false });
    expect(api.appended).toHaveLength(2);
  });

  it("restores the still-pending revision and mode when a queued reminder is missing", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("auto-review");
    reminder.handleInput({
      mode: "auto-review",
      source: "interactive",
      streamingBehavior: "followUp",
    });
    const messageIndex = api.entries.findIndex((entry) => entry.type === "custom_message");
    api.entries.splice(messageIndex, 1); // the branch never recorded the custom message

    reminder.agentEnd();

    expect(reminder.state()).toEqual({ revision: 1, mode: "auto-review", pending: true });
    expect(api.appended[2]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "auto-review", pending: true },
    });
  });

  it("uses an explicitly supplied branch for confirmation", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("default");

    reminder.agentEnd([modeStateEntry(1, "default", true), reminderMessageEntry()]);

    expect(reminder.state()).toEqual({ revision: 1, mode: "default", pending: false });
    expect(api.appended).toHaveLength(2);
  });

  it("is a no-op when no reminder is pending or queued", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);

    reminder.agentEnd();

    expect(reminder.state()).toEqual({ revision: 0, mode: undefined, pending: false });
    expect(api.appended).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Idle confirmation (§8 bullet 5)
// ---------------------------------------------------------------------------

describe("mode reminder idle confirmation", () => {
  it("persists the clear for a recorded idle reminder", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");
    reminder.handleInput({ mode: "read-only", source: "interactive" });

    reminder.idle();

    expect(reminder.state()).toEqual({ revision: 1, mode: "read-only", pending: false });
    expect(api.appended[1]).toEqual({
      customType: MODE_REMINDER_ENTRY_TYPE,
      data: { revision: 1, mode: "read-only", pending: false },
    });
  });

  it("keeps a pending state that has not been recorded", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("read-only");

    reminder.idle();

    expect(reminder.state()).toEqual({ revision: 1, mode: "read-only", pending: true });
    expect(api.appended).toHaveLength(1);
  });

  it("does not restore a queued reminder that the branch recorded", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);
    reminder.noteModeChange("full-access");
    reminder.handleInput({ mode: "full-access", source: "interactive", streamingBehavior: "steer" });

    reminder.idle();

    expect(reminder.state()).toEqual({ revision: 1, mode: "full-access", pending: false });
    expect(api.appended).toHaveLength(2);
  });

  it("is a no-op when nothing is pending", () => {
    const api = createFakeApi();
    const reminder = createReminder(api);

    reminder.idle();

    expect(api.appended).toEqual([]);
    expect(reminder.state().pending).toBe(false);
  });
});
