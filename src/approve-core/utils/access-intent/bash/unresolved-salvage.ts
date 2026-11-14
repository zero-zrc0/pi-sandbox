/**
 * Unresolved-region salvage.
 *
 * Salvage is additional analysis only. Innermost non-ERROR error regions are
 * reparsed locally; heredoc tails that cannot be reparsed get a heredoc-free
 * single-line candidate. Every accepted tree is released after the callback,
 * whether the callback succeeds or throws.
 */
import type { LocalReparser, SyntaxNode, SyntaxTree } from "./parser";
import { applyParseView } from "./parse-view";
import { buildHeredocFreeLine } from "./heredoc-free-lines";

export type SalvageOrigin = "reparse" | "heredoc-free";

export interface SalvagedRoot {
  readonly root: SyntaxNode;
  readonly origin: SalvageOrigin;
  /** Salvaged units are always uncertain; allow must not bypass review. */
  readonly uncertain: true;
  /** Main-tree region this tree came from. Offsets inside root are local. */
  readonly region: { readonly startIndex: number; readonly endIndex: number };
}

export interface SalvageOptions {
  readonly source: string;
  readonly reparser: LocalReparser;
}

interface Region {
  readonly node: SyntaxNode;
  readonly ancestors: readonly SyntaxNode[];
}

export function withSalvagedRoots<T>(
  root: SyntaxNode,
  options: SalvageOptions,
  use: (roots: readonly SalvagedRoot[]) => T,
): T {
  const trees: SyntaxTree[] = [];
  const salvaged: SalvagedRoot[] = [];
  const seen = new Set<string>();

  try {
    for (const region of collectRegions(root)) {
      const span = { startIndex: region.node.startIndex, endIndex: region.node.endIndex };
      const text = options.source.slice(span.startIndex, span.endIndex);
      if (accept(options.reparser, text, trees, salvaged, "reparse", span, seen)) continue;
      const host = heredocHost(region);
      if (host) acceptHeredocFree(host, options, trees, salvaged, seen);
    }

    for (const region of collectErrorHosts(root)) {
      const host = heredocHost(region) ?? region.node;
      acceptHeredocFree(host, options, trees, salvaged, seen);
    }

    return use(salvaged);
  } finally {
    for (const tree of trees) tree.delete();
  }
}

function accept(
  reparser: LocalReparser,
  text: string,
  trees: SyntaxTree[],
  salvaged: SalvagedRoot[],
  origin: SalvageOrigin,
  region: { readonly startIndex: number; readonly endIndex: number },
  seen: Set<string>,
): boolean {
  const key = `${origin}:${region.startIndex}:${region.endIndex}:${text}`;
  if (seen.has(key)) return false;
  seen.add(key);
  const tree = parseClean(reparser, text);
  if (!tree) return false;
  let root: SyntaxNode;
  try {
    root = applyParseView(tree.rootNode, text);
  } catch (error) {
    tree.delete();
    throw error;
  }
  trees.push({ rootNode: root, delete: () => tree.delete() });
  salvaged.push({ root, origin, uncertain: true, region });
  return true;
}

function acceptHeredocFree(
  host: SyntaxNode,
  options: SalvageOptions,
  trees: SyntaxTree[],
  salvaged: SalvagedRoot[],
  seen: Set<string>,
): void {
  const line = buildHeredocFreeLine(host, options.source);
  if (!line) return;
  accept(
    options.reparser,
    line.text,
    trees,
    salvaged,
    "heredoc-free",
    { startIndex: line.lineStart, endIndex: line.lineEnd },
    seen,
  );
}

function parseClean(reparser: LocalReparser, text: string): SyntaxTree | null {
  if (text.trim().length === 0) return null;
  const tree = reparser.parse(text);
  if (!tree) return null;
  if (tree.rootNode.hasError) {
    tree.delete();
    return null;
  }
  return tree;
}

function collectRegions(root: SyntaxNode): Region[] {
  const regions: Region[] = [];

  const visit = (node: SyntaxNode, ancestors: readonly SyntaxNode[], isRoot: boolean): void => {
    if (!node.hasError || node.type === "ERROR") return;

    const errorChildren: SyntaxNode[] = [];
    for (let index = 0; index < node.childCount; index += 1) {
      const child = node.child(index);
      if (child?.hasError) errorChildren.push(child);
    }
    const descendable = errorChildren.filter((child) => child.type !== "ERROR");
    if (descendable.length > 0) {
      for (const child of descendable) visit(child, [...ancestors, node], false);
      return;
    }
    if (!isRoot) regions.push({ node, ancestors });
  };

  visit(root, [], true);
  return regions;
}

function collectErrorHosts(root: SyntaxNode): Region[] {
  const regions: Region[] = [];

  const visit = (node: SyntaxNode, ancestors: readonly SyntaxNode[]): void => {
    if (node.type === "ERROR") {
      regions.push({ node, ancestors });
      return;
    }
    for (let index = 0; index < node.childCount; index += 1) {
      const child = node.child(index);
      if (child) visit(child, [...ancestors, node]);
    }
  };

  visit(root, []);
  return regions;
}

/** Nearest unresolved redirected statement, else the nearest ERROR. */
function heredocHost(region: Region): SyntaxNode | null {
  for (let index = region.ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = region.ancestors[index]!;
    if (ancestor.type === "redirected_statement" && ancestor.hasError) return ancestor;
  }
  for (let index = region.ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = region.ancestors[index]!;
    if (ancestor.type === "ERROR") return ancestor;
  }
  return region.node.type === "ERROR" ? region.node : null;
}
