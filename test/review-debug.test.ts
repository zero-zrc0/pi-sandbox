import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createReviewDebugAuditObserver,
  createReviewDebugReporter,
  writeReviewDebug,
} from "../src/review-debug";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("review debug log", () => {
  it("is silent without a caller-provided sink and forwards to an explicit sink", () => {
    const event = { event: "review_end" };
    const silent = createReviewDebugReporter();
    expect(() => silent(event)).not.toThrow();

    const received: Record<string, unknown>[] = [];
    const report = createReviewDebugReporter({ write: (entry) => received.push(entry) });
    report(event);

    expect(received).toEqual([event]);
  });

  it("rotates a full log and preserves its contents", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-log-"));
    directories.push(root);
    const directory = join(root, "logs");
    const file = join(directory, "debug.jsonl");
    writeReviewDebug({ event: "first" }, file);
    writeFileSync(file, "x".repeat(5 * 1024 * 1024));
    writeReviewDebug({ event: "second" }, file);
    const archive = readdirSync(directory).find((name) => name !== "debug.jsonl");
    expect(archive).toBeDefined();
    expect(archive!.endsWith(".jsonl")).toBe(true);
    expect(readFileSync(join(directory, archive!), "utf8")).toHaveLength(5 * 1024 * 1024);
    expect(JSON.parse(readFileSync(file, "utf8")).event).toBe("second");
  });

  it("keeps an oversized entry within the file limit", () => {
    const directory = mkdtempSync(join(tmpdir(), "pi-sandbox-log-"));
    directories.push(directory);
    const file = join(directory, "debug.jsonl");
    writeReviewDebug({ payload: "x".repeat(5 * 1024 * 1024) }, file);
    expect(JSON.parse(readFileSync(file, "utf8")).event).toBe("log-entry-too-large");
  });
});

describe("review debug audit observer", () => {
  it("records publication, invalidate, execution and session-decision events", () => {
    const received: Record<string, unknown>[] = [];
    const observer = createReviewDebugAuditObserver((event) => received.push(event), () => true);

    observer.write({ kind: "publication", sessionId: "s1", generation: 3, mode: "auto-review" });
    observer.write({ kind: "invalidate", sessionId: "s1", reason: "before-agent-start" });
    observer.write({ kind: "execution", sessionId: "s1", phase: "start", toolCallId: "c1", toolName: "bash" });
    observer.write({
      kind: "execution",
      sessionId: "s1",
      phase: "end",
      toolCallId: "c1",
      toolName: "bash",
      parentToolCallId: "c0",
      isError: true,
    });
    observer.write({
      kind: "session-decision",
      sessionId: "s1",
      toolCallId: "c2",
      toolName: "read",
      decision: "allow",
      requestId: "perm-1",
    });

    expect(received).toEqual([
      { event: "approval_chain", kind: "publication", sessionId: "s1", generation: 3, mode: "auto-review" },
      { event: "approval_chain", kind: "invalidate", sessionId: "s1", reason: "before-agent-start" },
      { event: "approval_chain", kind: "execution", sessionId: "s1", phase: "start", toolCallId: "c1", toolName: "bash" },
      {
        event: "approval_chain",
        kind: "execution",
        sessionId: "s1",
        phase: "end",
        toolCallId: "c1",
        toolName: "bash",
        parentToolCallId: "c0",
        isError: true,
      },
      {
        event: "approval_chain",
        kind: "session-decision",
        sessionId: "s1",
        toolCallId: "c2",
        toolName: "read",
        decision: "allow",
        requestId: "perm-1",
      },
    ]);
  });

  it("skips events for a session with the debug node disabled", () => {
    const received: Record<string, unknown>[] = [];
    const observer = createReviewDebugAuditObserver((event) => received.push(event), () => false);
    observer.write({ kind: "invalidate", sessionId: "s1", reason: "before-agent-start" });
    expect(received).toEqual([]);
  });
});
