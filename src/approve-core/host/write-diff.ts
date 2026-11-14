import { generateDiffString } from "@earendil-works/pi-coding-agent";

/**
 * Red/green preview lines for write/edit approvals.
 *
 * Pure helpers only: the caller reads the old file content and hands both
 * sides to {@link buildWriteDiff}. Keeping this module free of TUI/theme
 * state lets the truncation logic be unit-tested without a terminal.
 */

export type DiffLineKind = "add" | "remove" | "context" | "plain" | "syntax";

export interface DiffLine {
  readonly kind: DiffLineKind;
  readonly lineNumber?: number;
  readonly text: string;
}

/** Lines shown while collapsed (matches Claude's Write preview cap). */
export const DIFF_PREVIEW_LINES = 10;
/** Lines shown after Show more is expanded. */
export const DIFF_EXPANDED_LINES = 25;
/** Old/new content larger than this skips the diff and shows a new-only preview. */
export const MAX_DIFF_INPUT_BYTES = 512 * 1024;

function splitLines(content: string): string[] {
  if (content === "") return [];
  const normalized = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const parts = normalized.split("\n");
  // A trailing newline terminates the last line, it is not an extra empty line.
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

export function buildWriteDiff(oldContent: string, newContent: string): DiffLine[] {
  const oldNormalized = oldContent.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const newNormalized = newContent.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (oldNormalized === newNormalized) {
    return splitLines(newNormalized).map((text, index) => ({ kind: "context", lineNumber: index + 1, text }));
  }
  const { diff } = generateDiffString(oldNormalized, newNormalized, Number.MAX_SAFE_INTEGER);
  return diff.split("\n").map((line) => {
    const match = /^([+ -])\s*(\d+) (.*)$/.exec(line);
    if (!match) return { kind: "plain" as const, text: line };
    return {
      kind: match[1] === "+" ? "add" as const : match[1] === "-" ? "remove" as const : "context" as const,
      lineNumber: Number(match[2]),
      text: match[3]!,
    };
  });
}

/** A single oldText -> newText edit as remove/add lines without line numbers. */
export function buildEditDiff(oldText: string, newText: string): DiffLine[] {
  const result: DiffLine[] = [];
  for (const line of splitLines(oldText)) result.push({ kind: "remove", text: line });
  for (const line of splitLines(newText)) result.push({ kind: "add", text: line });
  return result;
}

export function isWithinDiffLimit(oldContent: string, newContent: string): boolean {
  return (
    Buffer.byteLength(oldContent, "utf8") <= MAX_DIFF_INPUT_BYTES &&
    Buffer.byteLength(newContent, "utf8") <= MAX_DIFF_INPUT_BYTES
  );
}

/** New-only preview for files too large to diff. */
export function fallbackPreview(newContent: string): DiffLine[] {
  return splitLines(newContent)
    .map((text, index) => ({
      kind: "add" as const,
      lineNumber: index + 1,
      text,
    }));
}
