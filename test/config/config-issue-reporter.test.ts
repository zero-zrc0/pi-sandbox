/**
 * Configuration issue reporter (specs/config-loading.md §11).
 *
 * The reporter is a pure latch: it reads the current issue set, reports only
 * the issues that were not in the previously reported set as one notification,
 * and then replaces its set with the current one. Tests drive a mutable issue
 * sequence to prove de-duplication, replacement and re-notification; the
 * expected notification text is derived from the shared formatter.
 */
import { describe, expect, it } from "vitest";
import {
  configMessageKey,
  formatConfigMessage,
  type ConfigMessage,
} from "#config/config-loader";
import { createConfigIssueReporter } from "#config/config-issue-reporter";

const CONFIG_FILE = "/home/dev/.pi/agent/extensions/pi-sandbox/config.json";

function issue(code: string, message: string, path = "", file?: string): ConfigMessage {
  return file === undefined ? { code, path, message } : { code, path, file, message };
}

const PARSE_FAILED = issue("parse-failed", "The configuration file is not valid JSON.", "", CONFIG_FILE);
const UNKNOWN_KEY = issue("unknown-key", "Unrecognized configuration key.", "mode", CONFIG_FILE);
const DEPRECATED = issue("deprecated", "toolInputPreviewMaxLength is deprecated.", "toolInputPreviewMaxLength");
const DIALOG_KEY = issue("dialog-key", "The dialog key for approve cannot be used.", "permissionDialogKeys.approve");

interface MutableHarness {
  readonly notifications: string[];
  readonly readCount: () => number;
  report: () => readonly ConfigMessage[];
  setIssues: (next: readonly ConfigMessage[]) => void;
}

function createHarness(initial: readonly ConfigMessage[]): MutableHarness {
  let current = [...initial];
  const notifications: string[] = [];
  let reads = 0;
  const reporter = createConfigIssueReporter({
    readIssues: () => {
      reads += 1;
      return current;
    },
    notify: (text) => {
      notifications.push(text);
    },
  });
  return {
    notifications,
    readCount: () => reads,
    report: () => reporter.report(),
    setIssues: (next) => {
      current = [...next];
    },
  };
}

function expectedNotification(issues: readonly ConfigMessage[]): string {
  return issues.map(formatConfigMessage).join("\n");
}

describe("config issue reporter latch", () => {
  it("reports every issue on the first read", () => {
    const harness = createHarness([PARSE_FAILED, UNKNOWN_KEY]);
    expect(harness.report()).toEqual([PARSE_FAILED, UNKNOWN_KEY]);
    expect(harness.notifications).toEqual([expectedNotification([PARSE_FAILED, UNKNOWN_KEY])]);
  });

  it("returns the exact issue objects it read", () => {
    const harness = createHarness([UNKNOWN_KEY]);
    const reported = harness.report();
    expect(reported[0]).toBe(UNKNOWN_KEY);
  });

  it("reads the current issues on every report", () => {
    const harness = createHarness([UNKNOWN_KEY]);
    harness.report();
    harness.report();
    harness.report();
    expect(harness.readCount()).toBe(3);
  });

  it("does not notify again while the same issues stay", () => {
    const harness = createHarness([PARSE_FAILED, UNKNOWN_KEY]);
    harness.report();
    expect(harness.report()).toEqual([]);
    expect(harness.report()).toEqual([]);
    expect(harness.notifications).toHaveLength(1);
  });

  it("notifies only the issues that were not reported before", () => {
    const harness = createHarness([PARSE_FAILED]);
    harness.report();
    harness.setIssues([PARSE_FAILED, UNKNOWN_KEY, DEPRECATED]);
    expect(harness.report()).toEqual([UNKNOWN_KEY, DEPRECATED]);
    expect(harness.notifications).toHaveLength(2);
    expect(harness.notifications[1]).toBe(expectedNotification([UNKNOWN_KEY, DEPRECATED]));
  });

  it("collapses a batch of new issues into a single notification", () => {
    const harness = createHarness([]);
    harness.report();
    harness.setIssues([PARSE_FAILED, UNKNOWN_KEY, DEPRECATED, DIALOG_KEY]);
    expect(harness.report()).toHaveLength(4);
    expect(harness.notifications).toHaveLength(1);
    expect(harness.notifications[0].split("\n")).toHaveLength(4);
  });

  it("replaces its set with the current one, so disappeared issues are forgotten", () => {
    const harness = createHarness([PARSE_FAILED, UNKNOWN_KEY]);
    harness.report();
    harness.setIssues([PARSE_FAILED]);
    expect(harness.report()).toEqual([]);
    harness.setIssues([PARSE_FAILED, UNKNOWN_KEY]);
    expect(harness.report()).toEqual([UNKNOWN_KEY]);
    expect(harness.notifications).toHaveLength(2);
  });

  it("notifies a disappeared issue again when it reappears", () => {
    const harness = createHarness([DIALOG_KEY]);
    harness.report();
    harness.setIssues([]);
    harness.report();
    harness.setIssues([DIALOG_KEY]);
    expect(harness.report()).toEqual([DIALOG_KEY]);
    expect(harness.notifications).toHaveLength(2);
  });

  it("counts an issue repeated inside one read once", () => {
    const harness = createHarness([PARSE_FAILED, PARSE_FAILED, UNKNOWN_KEY]);
    expect(harness.report()).toEqual([PARSE_FAILED, UNKNOWN_KEY]);
    expect(harness.notifications[0].split("\n")).toHaveLength(2);
  });

  it("does not notify a duplicate that appears while latched", () => {
    const harness = createHarness([PARSE_FAILED]);
    harness.report();
    harness.setIssues([PARSE_FAILED, PARSE_FAILED]);
    expect(harness.report()).toEqual([]);
  });

  it("recognizes an equal issue by its stable key, not object identity", () => {
    const harness = createHarness([PARSE_FAILED]);
    harness.report();
    harness.setIssues([{ ...PARSE_FAILED }]);
    expect(harness.report()).toEqual([]);
    expect(harness.notifications).toHaveLength(1);
  });

  it("treats issues that differ only by one key field as new", () => {
    const harness = createHarness([UNKNOWN_KEY]);
    harness.report();
    const otherPath = { ...UNKNOWN_KEY, path: "permission" };
    harness.setIssues([otherPath]);
    expect(harness.report()).toEqual([otherPath]);
  });

  it("returns an empty array and does not notify for an empty issue list", () => {
    const harness = createHarness([]);
    expect(harness.report()).toEqual([]);
    expect(harness.notifications).toEqual([]);
  });

  it("keeps the latch unchanged when reading throws", () => {
    const issues = [PARSE_FAILED];
    const notifications: string[] = [];
    let failRead = true;
    const reporter = createConfigIssueReporter({
      readIssues: () => {
        if (failRead) throw new Error("loader exploded");
        return issues;
      },
      notify: (text) => notifications.push(text),
    });
    expect(reporter.report()).toEqual([]);
    expect(notifications).toEqual([]);
    failRead = false;
    expect(reporter.report()).toEqual(issues);
    expect(notifications).toHaveLength(1);
  });

  it("keeps its result when notify throws and still replaces the latch", () => {
    const issues = [UNKNOWN_KEY];
    let notifyCalls = 0;
    const reporter = createConfigIssueReporter({
      readIssues: () => issues,
      notify: () => {
        notifyCalls += 1;
        throw new Error("UI is gone");
      },
    });
    expect(() => reporter.report()).not.toThrow();
    expect(reporter.report()).toEqual([]);
    expect(notifyCalls).toBe(1);
  });

  it("exposes a stable de-duplication key for the same message", () => {
    expect(configMessageKey(UNKNOWN_KEY)).toBe(configMessageKey({ ...UNKNOWN_KEY }));
    expect(configMessageKey(UNKNOWN_KEY)).not.toBe(configMessageKey(PARSE_FAILED));
  });
});
