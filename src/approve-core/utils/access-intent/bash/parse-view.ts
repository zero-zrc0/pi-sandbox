/**
 * Corrected AST view.
 *
 * Grammar quirks are repaired once, at the parser entry. Corrections run
 * bottom-up: heredoc tails are lifted first, then redirect-borne command
 * arguments return to the command. Moved nodes keep their original type,
 * text and absolute source offsets.
 */
import type { SyntaxNode } from "./parser";
import { liftHeredocTails } from "./heredoc-tails";
import { returnRedirectArguments } from "./redirect-arguments";

export interface EditableNode extends SyntaxNode {
  readonly parent: EditableNode | null;
  readonly children: readonly EditableNode[];
}

export interface TreeEditor {
  readonly source: string;
  readonly root: EditableNode;
  childrenOf(node: EditableNode): readonly EditableNode[];
  remove(node: EditableNode): void;
  insertAfter(reference: EditableNode, node: EditableNode): void;
  appendChild(parent: EditableNode, node: EditableNode): void;
  /** Replace a node with a synthetic container holding it plus extra children. */
  wrap(reference: EditableNode, type: string, extraChildren: readonly EditableNode[]): EditableNode;
  replace(node: EditableNode, replacement: EditableNode): void;
  setRoot(node: EditableNode): void;
  isCorrected(node: EditableNode): boolean;
  markCorrected(node: EditableNode): void;
}

class MutableNode implements EditableNode {
  readonly type: string;
  readonly text: string;
  readonly startIndex: number;
  readonly endIndex: number;
  readonly isNamed: boolean;
  readonly ownError: boolean;
  readonly children: MutableNode[] = [];
  parent: MutableNode | null = null;
  corrected = false;

  constructor(source: SyntaxNode, ownError: boolean) {
    this.type = source.type;
    this.text = source.text;
    this.startIndex = source.startIndex;
    this.endIndex = source.endIndex;
    this.isNamed = source.isNamed;
    this.ownError = ownError;
  }

  get childCount(): number {
    return this.children.length;
  }

  get hasError(): boolean {
    if (this.ownError) return true;
    return this.children.some((child) => child.hasError);
  }

  child(index: number): SyntaxNode | null {
    return this.children[index] ?? null;
  }

  previousSibling(): SyntaxNode | null {
    if (!this.parent) return null;
    const index = this.parent.children.indexOf(this);
    return index > 0 ? (this.parent.children[index - 1] ?? null) : null;
  }
}

function copyTree(node: SyntaxNode): MutableNode {
  const children: MutableNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) children.push(copyTree(child));
  }
  const hasErrorChild = children.some((child) => child.hasError);
  const ownError = node.type === "ERROR" || (node.hasError && !hasErrorChild);
  const copy = new MutableNode(node, ownError);
  for (const child of children) {
    child.parent = copy;
    copy.children.push(child);
  }
  return copy;
}

export class SyntaxTreeEditor implements TreeEditor {
  readonly source: string;
  private rootNode: MutableNode;
  private changed = false;

  constructor(root: SyntaxNode, source: string) {
    this.rootNode = copyTree(root);
    this.source = source;
  }

  get root(): EditableNode {
    return this.rootNode;
  }

  get didChange(): boolean {
    return this.changed;
  }

  childrenOf(node: EditableNode): readonly EditableNode[] {
    return (node as MutableNode).children;
  }

  remove(node: EditableNode): void {
    const mutable = node as MutableNode;
    const parent = mutable.parent;
    if (!parent) return;
    const index = parent.children.indexOf(mutable);
    if (index >= 0) parent.children.splice(index, 1);
    mutable.parent = null;
    this.changed = true;
  }

  insertAfter(reference: EditableNode, node: EditableNode): void {
    const parent = (reference as MutableNode).parent;
    if (!parent) return;
    this.detach(node as MutableNode);
    const index = parent.children.indexOf(reference as MutableNode);
    parent.children.splice(index + 1, 0, node as MutableNode);
    (node as MutableNode).parent = parent;
    this.changed = true;
  }

  appendChild(parent: EditableNode, node: EditableNode): void {
    this.detach(node as MutableNode);
    const target = parent as MutableNode;
    target.children.push(node as MutableNode);
    (node as MutableNode).parent = target;
    this.changed = true;
  }

  wrap(reference: EditableNode, type: string, extraChildren: readonly EditableNode[]): EditableNode {
    const ref = reference as MutableNode;
    const parent = ref.parent;
    const index = parent ? parent.children.indexOf(ref) : -1;

    for (const child of extraChildren) this.detach(child as MutableNode);

    const start = Math.min(ref.startIndex, ...extraChildren.map((child) => child.startIndex));
    const end = Math.max(ref.endIndex, ...extraChildren.map((child) => child.endIndex));
    const wrapper = new MutableNode(
      { type, text: this.source.slice(start, end), startIndex: start, endIndex: end, isNamed: true, hasError: false, childCount: 0, child: () => null, previousSibling: () => null },
      false,
    );
    wrapper.corrected = true;
    wrapper.children.push(ref);
    ref.parent = wrapper;
    for (const child of extraChildren) {
      wrapper.children.push(child as MutableNode);
      (child as MutableNode).parent = wrapper;
    }

    if (parent) {
      parent.children[index] = wrapper;
      wrapper.parent = parent;
    } else {
      this.rootNode = wrapper;
    }
    this.changed = true;
    return wrapper;
  }

  replace(node: EditableNode, replacement: EditableNode): void {
    const mutable = node as MutableNode;
    const parent = mutable.parent;
    if (!parent) {
      this.setRoot(replacement);
      return;
    }
    const index = parent.children.indexOf(mutable);
    this.detach(replacement as MutableNode);
    parent.children[index] = replacement as MutableNode;
    (replacement as MutableNode).parent = parent;
    mutable.parent = null;
    this.changed = true;
  }

  setRoot(node: EditableNode): void {
    this.detach(node as MutableNode);
    this.rootNode = node as MutableNode;
    this.rootNode.parent = null;
    this.changed = true;
  }

  isCorrected(node: EditableNode): boolean {
    return (node as MutableNode).corrected;
  }

  markCorrected(node: EditableNode): void {
    (node as MutableNode).corrected = true;
  }

  private detach(node: MutableNode): void {
    const parent = node.parent;
    if (!parent) return;
    const index = parent.children.indexOf(node);
    if (index >= 0) parent.children.splice(index, 1);
    node.parent = null;
    this.changed = true;
  }
}

/** Apply every AST correction. Returns the original root when nothing changed. */
export function applyParseView(root: SyntaxNode, source: string): SyntaxNode {
  const editor = new SyntaxTreeEditor(root, source);
  correctTree(editor.root, editor);
  return editor.didChange ? editor.root : root;
}

function correctTree(node: EditableNode, editor: TreeEditor): void {
  if (editor.isCorrected(node)) return;
  for (const child of [...editor.childrenOf(node)]) correctTree(child, editor);
  liftHeredocTails(node, editor);
  returnRedirectArguments(node, editor);
  editor.markCorrected(node);
}
