import type { PathNormalizer } from "../../path/path-normalizer";
import type { SyntaxNode } from "./parser";
import { readShellWord, type ShellWordContext } from "./shell-variable-expansion";
import { isRedirectNode } from "./redirect-analysis";

export interface WorkingDirectories {
  baseAt(offset: number): string | undefined;
}

/**
 * A cd target is proven only from literal text. A variable, substitution or
 * arithmetic expansion stays runtime-dependent even when the shell word layer
 * can resolve a few of them statically.
 */
const RUNTIME_TARGET_TYPES = new Set([
  "simple_expansion",
  "expansion",
  "command_substitution",
  "process_substitution",
  "arithmetic_expansion",
]);

function hasRuntimeExpansion(node: SyntaxNode): boolean {
  if (RUNTIME_TARGET_TYPES.has(node.type)) return true;
  for (let index = 0; index < node.childCount; index++) {
    const child = node.child(index);
    if (child?.isNamed && hasRuntimeExpansion(child)) return true;
  }
  return false;
}

export function trackWorkingDirectories(root: SyntaxNode, normalizer: PathNormalizer, initial: string | undefined, context: ShellWordContext): WorkingDirectories {
  const ranges: { start: number; end: number; base: string | undefined }[] = [];
  function walk(node: SyntaxNode, base: string | undefined, pipelinePrefix = false): string | undefined {
    ranges.push({ start: node.startIndex, end: node.endIndex, base });
    const children: SyntaxNode[] = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.isNamed) children.push(child);
    }
    if (node.type === "command") {
      for (const child of children) walk(child, base);
      const name = children.find((child) => child.type === "command_name");
      if (!name || readShellWord(name, context).value !== "cd") return base;
      const argNodes = children.slice(children.indexOf(name) + 1).filter((child) => !isRedirectNode(child) && child.type !== "comment");
      const args = argNodes.map((child) => readShellWord(child, context));
      const target = args[0];
      if (args.length !== 1 || !target || hasRuntimeExpansion(argNodes[0]!) || target.computed || !target.value || target.value === "-" || argNodes[0]!.text.startsWith("~") || target.value.startsWith("-")) return undefined;
      const kind = normalizer.interpretCd(target.value).kind;
      if (kind === "absolute") return normalizer.resolveCdOffset(base ?? normalizer.cwd, target.value);
      if (kind === "relative" && base !== undefined) return normalizer.resolveCdOffset(base, target.value);
      return undefined;
    }
    if (node.type === "pipeline" && children[0]?.type === "redirected_statement") {
      const first = children[0];
      let hasList = false;
      for (let i = 0; i < first.childCount; i++) if (first.child(i)?.type === "list") hasList = true;
      if (hasList) {
        const prefixBase = walk(first, base, true);
        for (const stage of children.slice(1)) walk(stage, prefixBase);
        return prefixBase;
      }
    }
    let current = base;
    const sequential = node.type === "program" || node.type === "list" || node.type === "redirected_statement" || node.type === "compound_statement" || node.type === "subshell";
    let lastNamedIndex = -1;
    for (let i = 0; i < node.childCount; i++) if (node.child(i)?.isNamed) lastNamedIndex = i;
    for (let childIndex = 0; childIndex < node.childCount; childIndex++) {
      const child = node.child(childIndex);
      if (!child?.isNamed) continue;
      const redirect = node.type === "redirected_statement" && ["file_redirect", "heredoc_redirect", "herestring_redirect"].includes(child.type);
      const next = walk(child, sequential && !redirect ? current : base, pipelinePrefix && node.type === "redirected_statement" && child.type === "list");
      const background = node.child(childIndex + 1)?.type === "&";
      const terminalPipelineStage = pipelinePrefix && node.type === "list" && childIndex === lastNamedIndex;
      if (sequential && !background && !redirect && !terminalPipelineStage) current = next;
    }
    return sequential && node.type !== "subshell" ? current : base;
  }
  walk(root, initial);
  return { baseAt(offset) {
    for (let i = ranges.length - 1; i >= 0; i--) {
      const range = ranges[i]!;
      if (offset >= range.start && offset < range.end) return range.base;
    }
    return undefined;
  } };
}
