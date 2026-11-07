import type { SyntaxNode, SyntaxTree } from "#approve-core/utils/access-intent/bash/parser";

export interface SyntaxOptions {
  readonly named?: boolean;
  readonly error?: boolean;
}

class FakeSyntaxNode implements SyntaxNode {
  parent: FakeSyntaxNode | null = null;
  startIndex: number;
  endIndex: number;

  constructor(
    readonly type: string,
    readonly text: string,
    startIndex: number,
    endIndex: number,
    readonly isNamed: boolean,
    readonly ownError: boolean,
    readonly children: FakeSyntaxNode[],
  ) {
    this.startIndex = startIndex;
    this.endIndex = endIndex;
  }

  get childCount(): number {
    return this.children.length;
  }

  get hasError(): boolean {
    return this.ownError || this.children.some((child) => child.hasError);
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

/**
 * Build a narrow-interface node fixture. Child offsets are placed in source
 * order by searching their text inside the parent text. Children keep their
 * identity so tests can hold references to nested nodes.
 */
export function syntax(
  type: string,
  text: string,
  children: readonly SyntaxNode[] = [],
  options: SyntaxOptions = {},
): SyntaxNode {
  const node = new FakeSyntaxNode(type, text, 0, text.length, options.named ?? true, options.error ?? false, []);
  let cursor = 0;
  for (const child of children) {
    const found = text.indexOf(child.text, cursor);
    const start = found >= 0 ? found : cursor;
    shift(child as FakeSyntaxNode, start - child.startIndex);
    (child as FakeSyntaxNode).parent = node;
    node.children.push(child as FakeSyntaxNode);
    cursor = start + child.text.length;
  }
  return node;
}

export function token(type: string, text: string): SyntaxNode {
  return syntax(type, text, [], { named: false });
}

export function treeOf(root: SyntaxNode): SyntaxTree {
  return { rootNode: root, delete: () => {} };
}

function shift(node: FakeSyntaxNode, delta: number): void {
  if (delta === 0) return;
  node.startIndex += delta;
  node.endIndex += delta;
  for (const child of node.children) shift(child, delta);
}
