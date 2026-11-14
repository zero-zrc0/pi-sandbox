/**
 * Phase 12 active-agent identity (specs/host-integration.md §1).
 *
 * Every fixture is a hand-built session entry list or prompt string; the
 * expected name is the spec's worked example, never recomputed from the
 * implementation. Only the public host module is imported.
 */
import { describe, expect, it } from "vitest";
import type { SessionEntry } from "@earendil-works/pi-coding-agent";
import {
  ACTIVE_AGENT_ENTRY_TYPE,
  activeAgentFromEntries,
  activeAgentFromSystemPrompt,
  getActiveAgentName,
} from "#approve-core/host/active-agent";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function customEntry(id: string, customType: string, data?: unknown): SessionEntry {
  return {
    type: "custom",
    id,
    parentId: null,
    timestamp: "2026-01-01T00:00:00.000Z",
    customType,
    data,
  };
}

function activeAgentEntry(id: string, data: unknown): SessionEntry {
  return customEntry(id, ACTIVE_AGENT_ENTRY_TYPE, data);
}

function messageEntry(id: string): SessionEntry {
  return {
    type: "message",
    id,
    parentId: null,
    timestamp: "2026-01-01T00:00:00.000Z",
    message: {} as never,
  };
}

// ---------------------------------------------------------------------------
// Entry scan
// ---------------------------------------------------------------------------

describe("activeAgentFromEntries", () => {
  it("returns undefined when the session has no active-agent entry", () => {
    expect(activeAgentFromEntries([])).toBeUndefined();
    expect(activeAgentFromEntries([messageEntry("m1")])).toBeUndefined();
    expect(activeAgentFromEntries([customEntry("c1", "some_other_state", { name: "x" })])).toBeUndefined();
  });

  it("returns the newest valid name trimmed", () => {
    const entries = [
      activeAgentEntry("a1", { name: "  reviewer-old  " }),
      messageEntry("m1"),
      activeAgentEntry("a2", { name: " reviewer-new " }),
    ];

    expect(activeAgentFromEntries(entries)).toBe("reviewer-new");
  });

  it("treats an explicit null name as a clear and never falls back to an older entry", () => {
    const entries = [
      activeAgentEntry("a1", { name: "reviewer-old" }),
      activeAgentEntry("a2", { name: null }),
    ];

    expect(activeAgentFromEntries(entries)).toBeNull();
  });

  it("skips invalid newer records and keeps scanning older entries", () => {
    const entries = [
      activeAgentEntry("a1", { name: "reviewer-real" }),
      activeAgentEntry("a2", {}),
      activeAgentEntry("a3", { name: 42 }),
      activeAgentEntry("a4", { name: "   " }),
      activeAgentEntry("a5", undefined),
    ];

    expect(activeAgentFromEntries(entries)).toBe("reviewer-real");
  });

  it("ignores non-string and non-null name values without treating them as clears", () => {
    const entries = [
      activeAgentEntry("a1", { name: "reviewer-real" }),
      activeAgentEntry("a2", { name: ["wrong"] }),
      activeAgentEntry("a3", { name: true }),
    ];

    expect(activeAgentFromEntries(entries)).toBe("reviewer-real");
  });
});

// ---------------------------------------------------------------------------
// System prompt parse
// ---------------------------------------------------------------------------

describe("activeAgentFromSystemPrompt", () => {
  it("parses a double-quoted tag", () => {
    expect(activeAgentFromSystemPrompt('preamble <active_agent name="reviewer-one"> tail')).toBe("reviewer-one");
  });

  it("parses a single-quoted tag", () => {
    expect(activeAgentFromSystemPrompt("preamble <active_agent name='reviewer-two'> tail")).toBe("reviewer-two");
  });

  it("accepts a mixed-case tag name", () => {
    expect(activeAgentFromSystemPrompt('<ACTIVE_AGENT name="reviewer-three"/>')).toBe("reviewer-three");
  });

  it("uses the last valid tag when several are present", () => {
    const prompt = '<active_agent name="first"><active_agent name="second">';

    expect(activeAgentFromSystemPrompt(prompt)).toBe("second");
  });

  it("rejects a whitespace-only attribute value and keeps scanning", () => {
    const prompt = '<active_agent name="   "><active_agent name="real">';

    expect(activeAgentFromSystemPrompt(prompt)).toBe("real");
  });

  it("returns undefined for absent prompts, absent tags and unquoted values", () => {
    expect(activeAgentFromSystemPrompt(undefined)).toBeUndefined();
    expect(activeAgentFromSystemPrompt("")).toBeUndefined();
    expect(activeAgentFromSystemPrompt("<active_agent />")).toBeUndefined();
    expect(activeAgentFromSystemPrompt("<active_agent name=reviewer>")).toBeUndefined();
    expect(activeAgentFromSystemPrompt('<other_tag name="reviewer">')).toBeUndefined();
  });

  it("trims the parsed name", () => {
    expect(activeAgentFromSystemPrompt('<active_agent name="  reviewer-four  ">')).toBe("reviewer-four");
  });
});

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

describe("getActiveAgentName", () => {
  it("reads the active branch instead of the flat entry list when both exist", () => {
    const host = {
      sessionManager: {
        getBranch: () => [activeAgentEntry("b1", { name: "branch-name" })],
        getEntries: () => [activeAgentEntry("e1", { name: "abandoned-name" })],
      },
    };

    expect(getActiveAgentName(host)).toBe("branch-name");
  });

  it("treats an empty active branch as no record and never reads abandoned flat entries", () => {
    const host = {
      sessionManager: {
        getBranch: () => [] as SessionEntry[],
        getEntries: () => [activeAgentEntry("e1", { name: "abandoned-name" })],
      },
    };

    expect(getActiveAgentName(host)).toBeUndefined();
  });

  it("falls back to the flat entry list when the manager has no branch reader", () => {
    const host = {
      sessionManager: { getEntries: () => [activeAgentEntry("e1", { name: "flat-only" })] },
    };

    expect(getActiveAgentName(host)).toBe("flat-only");
  });

  it("prefers a session entry over the system prompt", () => {
    const host = {
      sessionManager: { getEntries: () => [activeAgentEntry("a1", { name: "from-entry" })] },
      getSystemPrompt: () => '<active_agent name="from-prompt">',
    };

    expect(getActiveAgentName(host)).toBe("from-entry");
  });

  it("lets an explicit clear suppress the system prompt", () => {
    const host = {
      sessionManager: { getEntries: () => [activeAgentEntry("a1", { name: null })] },
      getSystemPrompt: () => '<active_agent name="from-prompt">',
    };

    expect(getActiveAgentName(host)).toBeUndefined();
  });

  it("falls back to the system prompt when entries hold no valid record", () => {
    const host = {
      sessionManager: { getEntries: () => [activeAgentEntry("a1", {})] },
      getSystemPrompt: () => '<active_agent name="from-prompt">',
    };

    expect(getActiveAgentName(host)).toBe("from-prompt");
  });

  it("skips the prompt when the host exposes no system-prompt reader", () => {
    const host = { sessionManager: { getEntries: () => [] as SessionEntry[] } };

    expect(getActiveAgentName(host)).toBeUndefined();
  });
});
