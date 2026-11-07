/**
 * Nested execution contexts.
 *
 * Command and process substitutions run commands even when they appear inside
 * a redirect target, a heredoc body or another non-command container. The
 * walker reports the substitution node and leaves the decision to descend to
 * the consumer, so different consumers do not recurse twice.
 */
import type { SyntaxNode } from "./parser";

export type NestedExecutionKind = "command-substitution" | "process-substitution";

export interface NestedExecution {
  readonly kind: NestedExecutionKind;
  readonly node: SyntaxNode;
}

export interface NestedExecutionOptions {
  /** Count the queried node itself when it is a substitution. */
  readonly includeSelf?: boolean;
  /** Continue inside a found substitution instead of stopping there. */
  readonly descendIntoNested?: boolean;
}

export function isNestedExecutionNode(node: SyntaxNode): boolean {
  return node.type === "command_substitution" || node.type === "process_substitution";
}

export function findNestedExecutions(
  node: SyntaxNode,
  options: NestedExecutionOptions = {},
): readonly NestedExecution[] {
  const found: NestedExecution[] = [];
  visit(node, true, options, found);
  return found;
}

function visit(
  node: SyntaxNode,
  isRoot: boolean,
  options: NestedExecutionOptions,
  found: NestedExecution[],
): void {
  const nested = isNestedExecutionNode(node);
  if (nested && (!isRoot || options.includeSelf === true)) {
    found.push({ kind: node.type === "process_substitution" ? "process-substitution" : "command-substitution", node });
    if (options.descendIntoNested !== true) return;
  }

  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) visit(child, false, options, found);
  }
}
