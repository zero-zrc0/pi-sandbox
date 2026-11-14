/**
 * Policy issue reporter (specs/config-loading.md §11).
 *
 * Same latch as the configuration reporter, but it serves policy composition
 * problems (fail-closed scopes, MCP key migration) and reads the issues of the
 * agent that is current for this session. The latch itself is shared across
 * agents: one reported set per reporter instance.
 */
import { describe, expect, it } from "vitest";
import { formatConfigMessage, type ConfigMessage } from "#config/config-loader";
import { createPolicyIssueReporter } from "#config/policy-issue-reporter";

const CONFIG_FILE = "/work/project/.pi/extensions/pi-sandbox/config.json";
const AGENT_FILE = "/work/project/.pi/agents/reviewer.md";

const INVALID_SCOPE = issue(
  "invalid-scope",
  "The project configuration could not be loaded; inherited allow rules need confirmation.",
  "",
  CONFIG_FILE,
);
const MCP_MIGRATION = issue(
  "mcp-key-migration",
  "The mcp-servers key is deprecated; rename it to mcpServers.",
  "mcp-servers",
  CONFIG_FILE,
);
const AGENT_FAILURE = issue(
  "invalid-scope",
  "The agent configuration could not be loaded; inherited allow rules need confirmation.",
  "",
  AGENT_FILE,
);

function issue(code: string, message: string, path = "", file?: string): ConfigMessage {
  return file === undefined ? { code, path, message } : { code, path, file, message };
}

interface PolicyHarness {
  readonly agentCalls: string[];
  readonly notifications: string[];
  report: (agentName: string) => readonly ConfigMessage[];
  setIssues: (next: readonly ConfigMessage[]) => void;
}

function createHarness(initial: readonly ConfigMessage[]): PolicyHarness {
  let current = [...initial];
  const agentCalls: string[] = [];
  const notifications: string[] = [];
  const reporter = createPolicyIssueReporter({
    readIssues: (agentName) => {
      agentCalls.push(agentName);
      return current;
    },
    notify: (text) => {
      notifications.push(text);
    },
  });
  return {
    agentCalls,
    notifications,
    report: (agentName) => reporter.report(agentName),
    setIssues: (next) => {
      current = [...next];
    },
  };
}

function expectedNotification(issues: readonly ConfigMessage[]): string {
  return issues.map(formatConfigMessage).join("\n");
}

describe("policy issue reporter latch", () => {
  it("passes the current agent name to the reader", () => {
    const harness = createHarness([INVALID_SCOPE]);
    harness.report("reviewer");
    harness.report("planner");
    expect(harness.agentCalls).toEqual(["reviewer", "planner"]);
  });

  it("supports an empty agent name", () => {
    const harness = createHarness([]);
    harness.report("");
    expect(harness.agentCalls).toEqual([""]);
  });

  it("reports every issue on the first read", () => {
    const harness = createHarness([INVALID_SCOPE, MCP_MIGRATION]);
    expect(harness.report("reviewer")).toEqual([INVALID_SCOPE, MCP_MIGRATION]);
    expect(harness.notifications).toEqual([expectedNotification([INVALID_SCOPE, MCP_MIGRATION])]);
  });

  it("does not notify again while the same issues stay", () => {
    const harness = createHarness([INVALID_SCOPE]);
    harness.report("reviewer");
    expect(harness.report("reviewer")).toEqual([]);
    expect(harness.notifications).toHaveLength(1);
  });

  it("shares one latch across agents", () => {
    const harness = createHarness([INVALID_SCOPE]);
    expect(harness.report("reviewer")).toEqual([INVALID_SCOPE]);
    expect(harness.report("planner")).toEqual([]);
    expect(harness.notifications).toHaveLength(1);
  });

  it("reports issues that appear under a different agent", () => {
    const harness = createHarness([INVALID_SCOPE]);
    harness.report("reviewer");
    harness.setIssues([INVALID_SCOPE, AGENT_FAILURE]);
    expect(harness.report("planner")).toEqual([AGENT_FAILURE]);
    expect(harness.notifications).toHaveLength(2);
    expect(harness.notifications[1]).toBe(expectedNotification([AGENT_FAILURE]));
  });

  it("replaces its set with the current one, so disappeared issues are forgotten", () => {
    const harness = createHarness([AGENT_FAILURE]);
    harness.report("reviewer");
    harness.setIssues([]);
    expect(harness.report("reviewer")).toEqual([]);
    harness.setIssues([AGENT_FAILURE]);
    expect(harness.report("reviewer")).toEqual([AGENT_FAILURE]);
    expect(harness.notifications).toHaveLength(2);
  });

  it("collapses a batch of new issues into a single notification", () => {
    const harness = createHarness([]);
    harness.report("reviewer");
    harness.setIssues([INVALID_SCOPE, MCP_MIGRATION, AGENT_FAILURE]);
    expect(harness.report("reviewer")).toHaveLength(3);
    expect(harness.notifications).toHaveLength(1);
    expect(harness.notifications[0].split("\n")).toHaveLength(3);
  });

  it("counts an issue repeated inside one read once", () => {
    const harness = createHarness([MCP_MIGRATION, MCP_MIGRATION]);
    expect(harness.report("reviewer")).toEqual([MCP_MIGRATION]);
    expect(harness.notifications[0].split("\n")).toHaveLength(1);
  });

  it("returns an empty array and does not notify for an empty issue list", () => {
    const harness = createHarness([]);
    expect(harness.report("reviewer")).toEqual([]);
    expect(harness.notifications).toEqual([]);
  });

  it("keeps the latch unchanged when reading throws", () => {
    const notifications: string[] = [];
    let failRead = true;
    const reporter = createPolicyIssueReporter({
      readIssues: () => {
        if (failRead) throw new Error("policy loader exploded");
        return [INVALID_SCOPE];
      },
      notify: (text) => notifications.push(text),
    });
    expect(reporter.report("reviewer")).toEqual([]);
    expect(notifications).toEqual([]);
    failRead = false;
    expect(reporter.report("reviewer")).toEqual([INVALID_SCOPE]);
  });

  it("keeps its result when notify throws and still replaces the latch", () => {
    let notifyCalls = 0;
    const reporter = createPolicyIssueReporter({
      readIssues: () => [MCP_MIGRATION],
      notify: () => {
        notifyCalls += 1;
        throw new Error("UI is gone");
      },
    });
    expect(() => reporter.report("reviewer")).not.toThrow();
    expect(reporter.report("reviewer")).toEqual([]);
    expect(notifyCalls).toBe(1);
  });
});
