/**
 * Two different parse-health questions.
 *
 * Statement-level failure closed asks whether a node or any descendant is
 * unresolved. A redirect additionally asks whether the operator may have been
 * stranded next to its error, which is visible only through the direct
 * previous sibling.
 */
import type { SyntaxNode } from "./parser";

export function subtreeUnresolved(node: SyntaxNode): boolean {
  return node.hasError;
}

export function redirectPositionUnresolved(node: SyntaxNode): boolean {
  if (node.hasError) return true;
  const previous = node.previousSibling();
  return previous?.hasError === true;
}
