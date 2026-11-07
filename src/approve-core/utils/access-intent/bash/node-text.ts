/**
 * Command rule text.
 *
 * A command's rule text is the words the user typed, with redirects removed
 * and leading variable assignments stripped. Whitespace the user wrote is
 * preserved between surviving words; a removed redirect between two words
 * collapses to one space. Output spans let callers replace one argument with
 * its absolute spelling without re-lexing the text.
 */
import type { SyntaxNode } from "./parser";

const REDIRECT_TYPES = new Set([
  "file_redirect",
  "heredoc_redirect",
  "herestring_redirect",
]);

export type RuleTextRole = "name" | "argument";

export interface RuleTextPart {
  readonly node: SyntaxNode;
  readonly role: RuleTextRole;
  /** Start offset in {@link CommandRuleText.text}. */
  readonly start: number;
  /** End offset in {@link CommandRuleText.text}. */
  readonly end: number;
}

export interface CommandRuleText {
  readonly text: string;
  readonly parts: readonly RuleTextPart[];
}

export function isRedirectNodeType(type: string): boolean {
  return REDIRECT_TYPES.has(type);
}

/**
 * The statement body of a redirected statement, or the node itself. The
 * grammar wraps postfix redirects around a command; rule text never includes
 * that wrapper.
 */
export function commandBody(node: SyntaxNode): SyntaxNode {
  if (node.type !== "redirected_statement") return node;
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child?.isNamed && !isRedirectNodeType(child.type)) return child;
  }
  return node;
}

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

function commandNameIndex(nodes: readonly SyntaxNode[]): number {
  return nodes.findIndex((node) => node.type === "command_name");
}

function isWhitespace(text: string): boolean {
  return /^\s*$/.test(text);
}

interface SkippedSpan {
  readonly startIndex: number;
  readonly endIndex: number;
}

function overlaps(skipped: readonly SkippedSpan[], start: number, end: number): boolean {
  return skipped.some((span) => span.startIndex < end && span.endIndex > start);
}

export function commandRuleText(node: SyntaxNode, source: string): CommandRuleText {
  const body = commandBody(node);
  if (body.type !== "command") {
    return { text: body.text, parts: [] };
  }

  const direct = children(body);
  const nameIndex = commandNameIndex(direct);
  const kept: Array<{ node: SyntaxNode; role: RuleTextRole }> = [];
  const skipped: SkippedSpan[] = [];
  let seenName = false;

  for (const [index, child] of direct.entries()) {
    if (!child.isNamed) continue;
    if (isRedirectNodeType(child.type)) {
      skipped.push({ startIndex: child.startIndex, endIndex: child.endIndex });
      continue;
    }
    if (child.type === "variable_assignment" && !seenName && nameIndex >= 0) {
      // Assignments before the command name configure the environment; they
      // are not words of the command presented to the policy engine.
      skipped.push({ startIndex: child.startIndex, endIndex: child.endIndex });
      continue;
    }
    if (child.type === "comment") continue;
    if (index === nameIndex) {
      kept.push({ node: child, role: "name" });
      seenName = true;
      continue;
    }
    kept.push({ node: child, role: "argument" });
  }

  let text = "";
  const parts: RuleTextPart[] = [];
  let previousEnd: number | undefined;

  for (const entry of kept) {
    const child = entry.node;
    if (previousEnd !== undefined) {
      const gapStart = previousEnd;
      const gapEnd = child.startIndex;
      const gap = source.slice(gapStart, gapEnd);
      if (overlaps(skipped, gapStart, gapEnd)) {
        if (gap.length > 0) text += " ";
      } else if (isWhitespace(gap)) {
        text += gap;
      } else if (gap.length > 0) {
        text += " ";
      }
    }
    const start = text.length;
    text += child.text;
    parts.push({ node: child, role: entry.role, start, end: text.length });
    previousEnd = child.endIndex;
  }

  return { text, parts };
}
