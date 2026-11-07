import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createReviewDebugReporter, writeReviewDebug } from "../src/review-debug";

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
    writeReviewDebug({ event: "first" }, directory);
    const file = join(directory, "debug.txt");
    writeFileSync(file, "x".repeat(5 * 1024 * 1024));
    writeReviewDebug({ event: "second" }, directory);
    const archive = readdirSync(directory).find((name) => name !== "debug.txt");
    expect(archive).toBeDefined();
    expect(readFileSync(join(directory, archive!), "utf8")).toHaveLength(5 * 1024 * 1024);
    expect(JSON.parse(readFileSync(file, "utf8")).event).toBe("second");
  });

  it("keeps an oversized entry within the file limit", () => {
    const directory = mkdtempSync(join(tmpdir(), "pi-sandbox-log-"));
    directories.push(directory);
    writeReviewDebug({ payload: "x".repeat(5 * 1024 * 1024) }, directory);
    expect(JSON.parse(readFileSync(join(directory, "debug.txt"), "utf8")).event).toBe("log-entry-too-large");
  });
});
