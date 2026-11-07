/**
 * Heredoc-free single-line salvage candidates.
 *
 * Only scanner-recognized heredoc openers are removed: `<<`/`<<-`, an optional
 * adjacent descriptor, the delimiter and the whitespace before them. A lone
 * `<` or a generic error node is never treated as a heredoc opener.
 */
import type { SyntaxNode } from "./parser";

export interface RemovedSpan {
  readonly startIndex: number;
  readonly endIndex: number;
}

export interface HeredocFreeLine {
  readonly text: string;
  readonly lineStart: number;
  readonly lineEnd: number;
  readonly removed: readonly RemovedSpan[];
}

interface Opener {
  readonly startIndex: number;
  readonly endIndex: number;
}

const TRAILING_CONTROL = /[;&|<>()]/;

export function buildHeredocFreeLine(host: SyntaxNode, source: string): HeredocFreeLine | null {
  const openers = collectOpeners(host);
  if (openers.length === 0) return null;

  const first = openers.reduce((left, right) => (left.startIndex <= right.startIndex ? left : right));
  const lineStart = source.lastIndexOf("\n", first.startIndex - 1) + 1;
  const newline = source.indexOf("\n", first.startIndex);
  const lineEnd = newline < 0 ? source.length : newline;

  const spans = openers
    .filter((opener) => opener.startIndex >= lineStart && opener.startIndex < lineEnd)
    .map((opener) => expandWhitespace(opener, source, lineStart))
    .sort((left, right) => left.startIndex - right.startIndex);
  const merged = mergeSpans(spans);
  if (merged.length === 0) return null;

  const line = source.slice(lineStart, lineEnd);
  let text = line;
  for (const span of [...merged].reverse()) {
    text = text.slice(0, span.startIndex - lineStart) + text.slice(span.endIndex - lineStart);
  }
  return { text, lineStart, lineEnd, removed: merged };
}

function collectOpeners(host: SyntaxNode): Opener[] {
  const openers: Opener[] = [];
  visit(host, openers);
  return openers;
}

function visit(node: SyntaxNode, openers: Opener[]): void {
  if (node.type === "heredoc_redirect") {
    const opener = heredocRedirectOpener(node);
    if (opener) openers.push(opener);
  } else if (node.type === "ERROR") {
    openers.push(...errorOpeners(node));
  }

  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) visit(child, openers);
  }
}

function heredocRedirectOpener(node: SyntaxNode): Opener | null {
  const operatorIndex = findHeredocOperator(node);
  if (operatorIndex < 0) return null;
  const operator = node.child(operatorIndex)!;
  const delimiter = findDelimiter(node, operatorIndex);
  if (!delimiter) return null;

  const descriptor = descriptorBefore(node, operatorIndex, operator.startIndex);
  return {
    startIndex: descriptor?.startIndex ?? operator.startIndex,
    endIndex: delimiterEnd(delimiter),
  };
}

function errorOpeners(node: SyntaxNode): Opener[] {
  const found: Opener[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const operator = node.child(index);
    if (!operator || operator.isNamed || (operator.type !== "<<" && operator.type !== "<<-")) continue;
    const delimiter = node.child(index + 1);
    if (!delimiter?.isNamed || delimiter.type !== "heredoc_start") continue;
    const descriptor = descriptorBefore(node, index, operator.startIndex);
    found.push({
      startIndex: descriptor?.startIndex ?? operator.startIndex,
      endIndex: delimiterEnd(delimiter),
    });
  }
  return found;
}

function findHeredocOperator(node: SyntaxNode): number {
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child && !child.isNamed && (child.type === "<<" || child.type === "<<-")) return index;
  }
  return -1;
}

function findDelimiter(node: SyntaxNode, operatorIndex: number): SyntaxNode | null {
  for (let index = operatorIndex + 1; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child?.isNamed && child.type === "heredoc_start") return child;
  }
  return null;
}

/** An adjacent descriptor (`0<<EOF`, `2<<-X`) belongs to the heredoc opener. */
function descriptorBefore(node: SyntaxNode, operatorIndex: number, operatorStart: number): SyntaxNode | null {
  const previous = node.child(operatorIndex - 1);
  if (!previous?.isNamed) return null;
  if (previous.type !== "file_descriptor" && previous.type !== "number") return null;
  return previous.endIndex === operatorStart ? previous : null;
}

function delimiterEnd(delimiter: SyntaxNode): number {
  let end = delimiter.endIndex;
  const text = delimiter.text;
  let trimmed = text;
  while (trimmed.length > 0 && TRAILING_CONTROL.test(trimmed[trimmed.length - 1]!)) {
    trimmed = trimmed.slice(0, -1);
    end -= 1;
  }
  return end;
}

function expandWhitespace(opener: Opener, source: string, lineStart: number): RemovedSpan {
  let start = opener.startIndex;
  while (start > lineStart) {
    const char = source[start - 1];
    if (char !== " " && char !== "\t") break;
    start -= 1;
  }
  return { startIndex: start, endIndex: opener.endIndex };
}

function mergeSpans(spans: readonly RemovedSpan[]): RemovedSpan[] {
  const merged: RemovedSpan[] = [];
  for (const span of spans) {
    const last = merged[merged.length - 1];
    if (last && span.startIndex <= last.endIndex) {
      merged[merged.length - 1] = {
        startIndex: last.startIndex,
        endIndex: Math.max(last.endIndex, span.endIndex),
      };
      continue;
    }
    merged.push(span);
  }
  return merged;
}
