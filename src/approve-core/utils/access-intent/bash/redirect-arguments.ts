/**
 * Return command arguments that the grammar attached to a redirect.
 *
 * When a redirect carries trailing literal arguments, the redirect and every
 * redirect up to it belong to the rightmost real command. Moving them there
 * restores the source order a reader expects.
 */
import type { EditableNode, TreeEditor } from "./parse-view";
import { isRedirectNode, redirectTargetIndex } from "./redirect-analysis";

interface Candidate {
  readonly redirect: EditableNode;
  readonly trailing: readonly EditableNode[];
}

export function returnRedirectArguments(node: EditableNode, editor: TreeEditor): void {
  if (node.type !== "redirected_statement") return;
  if (node.hasError) return;

  const command = rightmostCommand(node, editor);
  if (!command) return;

  const candidates = collectCandidates(node, editor);
  if (!candidates) return;

  let lastCarrying = -1;
  for (let index = 0; index < candidates.length; index += 1) {
    if (candidates[index]!.trailing.length > 0) lastCarrying = index;
  }
  if (lastCarrying < 0) return;

  for (let index = 0; index <= lastCarrying; index += 1) {
    const candidate = candidates[index]!;
    editor.remove(candidate.redirect);
    for (const argument of candidate.trailing) editor.remove(argument);
    editor.appendChild(command, candidate.redirect);
    for (const argument of candidate.trailing) editor.appendChild(command, argument);
  }

  const named = editor.childrenOf(node).filter((child) => child.isNamed);
  if (named.length === 1 && named[0] === command) {
    editor.replace(node, command);
  }
}

function rightmostCommand(node: EditableNode, editor: TreeEditor): EditableNode | null {
  if (node.type === "command") return node;

  if (node.type === "redirected_statement") {
    for (const child of editor.childrenOf(node)) {
      if (!child.isNamed || isRedirectNode(child)) continue;
      return rightmostCommand(child, editor);
    }
    return null;
  }

  if (node.type === "pipeline" || node.type === "list") {
    const named = editor.childrenOf(node).filter((child) => child.isNamed);
    const last = named[named.length - 1];
    return last ? rightmostCommand(last, editor) : null;
  }

  return null;
}

function collectCandidates(node: EditableNode, editor: TreeEditor): Candidate[] | null {
  const candidates: Candidate[] = [];
  for (const child of editor.childrenOf(node)) {
    if (!isRedirectNode(child)) continue;
    const trailing = trailingArguments(child, editor);
    if (!trailing) return null;
    candidates.push({ redirect: child, trailing });

    if (child.type !== "heredoc_redirect") continue;
    for (const nested of editor.childrenOf(child)) {
      if (!isRedirectNode(nested) || nested.type === "heredoc_redirect") continue;
      const nestedTrailing = trailingArguments(nested, editor);
      if (!nestedTrailing) return null;
      candidates.push({ redirect: nested, trailing: nestedTrailing });
    }
  }
  candidates.sort((left, right) => left.redirect.startIndex - right.redirect.startIndex);
  return candidates;
}

function trailingArguments(redirect: EditableNode, editor: TreeEditor): EditableNode[] | null {
  const children = editor.childrenOf(redirect);
  const target = redirectTargetIndex(redirect);
  if (target < 0) return [];

  const trailing: EditableNode[] = [];
  for (let index = target + 1; index < children.length; index += 1) {
    const child = children[index]!;
    if (!child.isNamed) return null;
    if (child.type === "heredoc_body" || child.type === "heredoc_end") continue;
    if (isRedirectNode(child)) continue;
    if (child.type === "ERROR") return null;
    trailing.push(child);
  }
  return trailing;
}
