/**
 * Heredoc tail lifting.
 *
 * tree-sitter-bash may keep a redirect, pipeline or `&&`/`||` tail inside the
 * heredoc node after the delimiter. Lifting them out restores the grouping a
 * plain input redirect would have produced.
 */
import type { EditableNode, TreeEditor } from "./parse-view";
import { isRedirectNode, redirectOperator, redirectTargetIndex } from "./redirect-analysis";

const HOST_TYPES = new Set(["redirected_statement", "command", "pipeline"]);
const PLAIN_ARGUMENT_TYPES = new Set([
  "word",
  "number",
  "string",
  "raw_string",
  "ansi_c_string",
  "simple_expansion",
  "expansion",
  "command_substitution",
  "process_substitution",
  "concatenation",
  "arithmetic_expansion",
  "brace_expression",
  "variable_name",
]);

const STATEMENT_TYPES = new Set([
  "command",
  "redirected_statement",
  "pipeline",
  "list",
  "subshell",
  "compound_statement",
  "if_statement",
  "for_statement",
  "while_statement",
  "case_statement",
  "function_definition",
  "negated_command",
  "test_command",
  "declaration_command",
  "unset_command",
]);

type TailAction =
  | { readonly kind: "redirect"; readonly node: EditableNode }
  | { readonly kind: "pipeline"; readonly node: EditableNode }
  | { readonly kind: "list"; readonly operator: EditableNode; readonly operand: EditableNode };

export function liftHeredocTails(node: EditableNode, editor: TreeEditor): void {
  if (!HOST_TYPES.has(node.type)) return;
  if (node.hasError) return;

  for (const child of [...editor.childrenOf(node)]) {
    if (child.type !== "heredoc_redirect" || child.hasError) continue;
    const actions = readTailActions(child, editor);
    if (!actions || actions.length === 0) continue;
    applyTailActions(node, child, actions, editor);
  }
}

function readTailActions(heredoc: EditableNode, editor: TreeEditor): TailAction[] | null {
  const children = [...editor.childrenOf(heredoc)];
  const start = heredocTailStart(children);
  if (start < 0) return null;
  const tailEnd = children.findIndex((child) => child.type === "heredoc_body" || child.type === "heredoc_end");
  const end = tailEnd < 0 ? children.length : tailEnd;

  const actions: TailAction[] = [];
  let index = start;
  while (index < end) {
    const child = children[index]!;

    if (!child.isNamed) {
      if (child.type === "&&" || child.type === "||") {
        const operand = children[index + 1];
        if (!operand || !isStatement(operand) || operand.hasError) return null;
        if (operand.type === "list" && !isCompleteList(operand, editor)) return null;
        if (index + 2 < end) return null;
        actions.push({ kind: "list", operator: child, operand });
        index += 2;
        continue;
      }
      return null;
    }

    if (isRedirectNode(child)) {
      if (child.type === "heredoc_redirect") return null;
      if (!isLiftableRedirect(child, editor)) return null;
      actions.push({ kind: "redirect", node: child });
      index += 1;
      continue;
    }

    if (child.type === "pipeline") {
      if (child.hasError || !isCompletePipeline(child, editor)) return null;
      actions.push({ kind: "pipeline", node: child });
      index += 1;
      continue;
    }

    // Plain delimiter-line arguments stay in place; redirect-arguments moves
    // them to the command after tail structures are lifted.
    if (!PLAIN_ARGUMENT_TYPES.has(child.type)) return null;
    index += 1;
  }
  return actions;
}

function heredocTailStart(children: readonly EditableNode[]): number {
  let operator = -1;
  for (let index = 0; index < children.length; index += 1) {
    const child = children[index]!;
    if (!child.isNamed && (child.type === "<<" || child.type === "<<-")) {
      operator = index;
      break;
    }
  }
  if (operator < 0) return -1;
  for (let index = operator + 1; index < children.length; index += 1) {
    if (children[index]!.type === "heredoc_start") return index + 1;
  }
  return -1;
}

function isLiftableRedirect(node: EditableNode, editor: TreeEditor): boolean {
  const children = editor.childrenOf(node);
  const target = redirectTargetIndex(node);
  if (target < 0) return true;
  for (let index = target + 1; index < children.length; index += 1) {
    const child = children[index]!;
    if (!child.isNamed || child.type === "ERROR" || isRedirectNode(child)) return false;
  }
  return true;
}

function isCompletePipeline(node: EditableNode, editor: TreeEditor): boolean {
  if (node.type !== "pipeline" || node.hasError) return false;
  let sawOperator = false;
  for (const child of editor.childrenOf(node)) {
    if (!child.isNamed && child.type === "|") {
      sawOperator = true;
      continue;
    }
    if (!isStatement(child)) return false;
  }
  return sawOperator;
}

function isStatement(node: EditableNode): boolean {
  return node.isNamed && STATEMENT_TYPES.has(node.type) && !node.hasError;
}

function isCompleteList(node: EditableNode, editor: TreeEditor): boolean {
  const children = editor.childrenOf(node);
  if (children.length < 3 || children.length % 2 === 0) return false;
  if (!isStatement(children[0]!)) return false;
  for (let index = 1; index < children.length; index += 2) {
    const operator = children[index]!;
    const right = children[index + 1];
    if (operator.isNamed || (operator.type !== "&&" && operator.type !== "||")) return false;
    if (!right || !isStatement(right)) return false;
  }
  return true;
}

function applyTailActions(
  host: EditableNode,
  heredoc: EditableNode,
  actions: readonly TailAction[],
  editor: TreeEditor,
): void {
  let anchor = heredoc;
  let currentHost = host;

  for (const action of actions) {
    if (action.kind === "redirect") {
      editor.remove(action.node);
      editor.insertAfter(anchor, action.node);
      anchor = action.node;
      continue;
    }

    if (action.kind === "pipeline") {
      const parts = flattenPipeline(action.node, editor);
      editor.remove(action.node);
      if (currentHost.type === "pipeline") {
        for (const part of parts) editor.appendChild(currentHost, part);
      } else {
        currentHost = editor.wrap(currentHost, "pipeline", parts);
      }
      continue;
    }

    const pairs = listPairs(action.operator, action.operand, editor);
    if (!pairs) continue;
    for (const pair of pairs) {
      currentHost = editor.wrap(currentHost, "list", [pair.operator, pair.operand]);
    }
  }
}

/** Flatten the right-nested pipeline chain the grammar produces for tails. */
function flattenPipeline(node: EditableNode, editor: TreeEditor): EditableNode[] {
  const parts: EditableNode[] = [];
  for (const child of [...editor.childrenOf(node)]) {
    if (child.type === "pipeline") {
      parts.push(...flattenPipeline(child, editor));
      continue;
    }
    editor.remove(child);
    parts.push(child);
  }
  return parts;
}

interface ListPair {
  readonly operator: EditableNode;
  readonly operand: EditableNode;
}

/**
 * The tail list is right-nested; shell lists are left-associative. Fold it
 * into operator/operand pairs so wrapping produces the plain-redirect shape.
 */
function listPairs(
  operator: EditableNode,
  operand: EditableNode,
  editor: TreeEditor,
): ListPair[] | null {
  if (operand.type !== "list") {
    return isStatement(operand) ? [{ operator, operand }] : null;
  }

  const children = [...editor.childrenOf(operand)];
  if (children.length < 3 || children.length % 2 === 0) return null;
  if (!isStatement(children[0]!)) return null;
  const pairs: ListPair[] = [{ operator, operand: children[0]! }];
  for (let index = 1; index < children.length; index += 2) {
    const op = children[index]!;
    const right = children[index + 1];
    if (op.isNamed) return null;
    if (op.type !== "&&" && op.type !== "||") return null;
    if (!right || !isStatement(right)) return null;
    pairs.push({ operator: op, operand: right });
  }
  editor.remove(operand);
  return pairs;
}
