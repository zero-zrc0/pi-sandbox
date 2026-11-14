/**
 * Structural facts about redirect nodes.
 *
 * The grammar puts the operator in an unnamed child whose type is the source
 * operator text. The first named child after it is the redirect target.
 */
import type { SyntaxNode } from "./parser";

const REDIRECT_TYPES = new Set(["file_redirect", "heredoc_redirect", "herestring_redirect"]);
const READ_ONLY_OPERATORS = new Set(["<", "<<", "<<-", "<<<"]);
const DUPLICATION_OPERATORS = new Set([">&", "<&", ">&-", "<&-"]);

export function isRedirectNode(node: SyntaxNode): boolean {
  return REDIRECT_TYPES.has(node.type);
}

/** Index of the operator child, or -1 when the node has no unnamed child. */
export function redirectOperatorIndex(node: SyntaxNode): number {
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child && !child.isNamed) return index;
  }
  return -1;
}

export function redirectOperator(node: SyntaxNode): string | null {
  const index = redirectOperatorIndex(node);
  if (index < 0) return null;
  return node.child(index)?.type ?? null;
}

/** Index of the first named child after the operator, or -1. */
export function redirectTargetIndex(node: SyntaxNode): number {
  const operator = redirectOperatorIndex(node);
  if (operator < 0) return -1;
  for (let index = operator + 1; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child?.isNamed) return index;
  }
  return -1;
}

export function redirectTargetNode(node: SyntaxNode): SyntaxNode | null {
  const index = redirectTargetIndex(node);
  return index < 0 ? null : node.child(index);
}

export function redirectSourceDescriptor(node: SyntaxNode): string | null {
  const operator = redirectOperatorIndex(node);
  if (operator < 0) return null;
  for (let index = 0; index < operator; index += 1) {
    const child = node.child(index);
    if (child?.isNamed && child.type === "file_descriptor") return child.text;
  }
  return null;
}

/**
 * Provable static target value, or null when the target is missing, dynamic,
 * or produced by an error recovery node.
 */
export function staticRedirectTarget(node: SyntaxNode): string | null {
  const target = redirectTargetNode(node);
  if (!target || target.hasError) return null;
  if (target.type === "heredoc_start") return target.text;
  if (target.type === "number") return target.text;
  if (target.type === "word") return isStaticWord(target.text) ? target.text : null;
  if (target.type === "raw_string") return stripQuotes(target.text, "'");
  if (target.type === "string") return staticStringValue(target);
  return null;
}

export function redirectTargetIsDynamic(node: SyntaxNode): boolean {
  const target = redirectTargetNode(node);
  if (!target) return false;
  return staticRedirectTarget(node) === null;
}

export interface RedirectFacts {
  readonly operator: string | null;
  readonly sourceDescriptor: string | null;
  readonly targetText: string | null;
  readonly targetValue: string | null;
  readonly dynamicTarget: boolean;
  readonly duplicatesDescriptor: boolean;
  readonly mayWriteFile: boolean;
}

export function analyzeRedirect(node: SyntaxNode): RedirectFacts {
  const operator = redirectOperator(node);
  const target = redirectTargetNode(node);
  return {
    operator,
    sourceDescriptor: redirectSourceDescriptor(node),
    targetText: target?.text ?? null,
    targetValue: staticRedirectTarget(node),
    dynamicTarget: redirectTargetIsDynamic(node),
    duplicatesDescriptor: operator !== null && DUPLICATION_OPERATORS.has(operator) && isDescriptorTarget(node, operator),
    mayWriteFile: redirectMayWriteFile(node),
  };
}

export function isDescriptorRedirectTarget(value: string): boolean {
  return /^(?:\d+-?|-)$/.test(value);
}

function isDescriptorTarget(node: SyntaxNode, operator: string): boolean {
  if (operator === ">&-" || operator === "<&-") return true;
  const target = staticRedirectTarget(node);
  return target !== null && isDescriptorRedirectTarget(target);
}

/**
 * Conservative file-write question. Unknown structure, dynamic targets and
 * unresolved redirect positions count as possible writes.
 */
export function redirectMayWriteFile(node: SyntaxNode): boolean {
  if (node.hasError) return true;
  if (node.previousSibling()?.hasError) return true;

  const operator = redirectOperator(node);
  if (operator === null) return true;
  if (DUPLICATION_OPERATORS.has(operator) && isDescriptorTarget(node, operator)) return false;
  if (operator === "<&") return false;
  if (READ_ONLY_OPERATORS.has(operator)) return false;

  if (staticRedirectTarget(node) === "/dev/null") return false;
  return true;
}

function isStaticWord(text: string): boolean {
  if (text.length === 0) return false;
  // Glob, brace, escape, expansion and substitution syntax need runtime work.
  return !/[*?[\]{}$`\\]/.test(text);
}

function stripQuotes(text: string, quote: string): string | null {
  if (text.length < 2) return null;
  if (!text.startsWith(quote) || !text.endsWith(quote)) return null;
  return text.slice(1, -1);
}

function staticStringValue(node: SyntaxNode): string | null {
  let value = "";
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (!child) continue;
    if (!child.isNamed) continue;
    if (child.type !== "string_content") return null;
    value += child.text;
  }
  if (value.length === 0 && node.childCount === 0) return stripQuotes(node.text, '"');
  return value;
}
