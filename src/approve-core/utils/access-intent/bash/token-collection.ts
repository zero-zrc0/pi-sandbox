import type { EffectProof } from "../effect";
import type { SyntaxNode } from "./parser";
import { readShellWord, type ShellWordContext } from "./shell-variable-expansion";
import { coreCommandEffect } from "./command-effects";
import type { CommandWord } from "./wrapper-analysis";
import { isDescriptorRedirectTarget, isRedirectNode, redirectOperator, redirectTargetNode } from "./redirect-analysis";
import { declaredCommandEffect, type EffectDeclarations } from "./declared-command-effects";
import { redirectPositionUnresolved } from "./parse-health";

export interface PathToken {
  readonly value: string;
  readonly role: "operand" | "file_redirect" | "inert";
  readonly effect: EffectProof;
  readonly span?: { readonly startIndex: number; readonly endIndex: number };
  readonly sourceOffset?: number;
  readonly computed?: boolean;
}

export interface PatternFirstRole {
  /** Positional words consumed as pattern text before the file operands. */
  readonly patterns: number;
  /** Whether `-f`/`--file` names a pattern or script file rather than text. */
  readonly fileFlags: boolean;
  /** Whether `-e`/`--expression`-style flags provide pattern text inline. */
  readonly expression: boolean;
}

/**
 * Pattern-first roster exposed as plain data. Configuration loading injects its
 * own copy for declaration warnings, so the table stays separate from the
 * collection logic below.
 */
export const PATTERN_FIRST_TOOLS: Readonly<Record<string, PatternFirstRole>> = Object.freeze({
  sed: { patterns: 1, fileFlags: true, expression: true },
  awk: { patterns: 1, fileFlags: true, expression: false },
  gawk: { patterns: 1, fileFlags: true, expression: true },
  nawk: { patterns: 1, fileFlags: true, expression: false },
  grep: { patterns: 1, fileFlags: true, expression: true },
  egrep: { patterns: 1, fileFlags: true, expression: true },
  fgrep: { patterns: 1, fileFlags: true, expression: true },
  rg: { patterns: 1, fileFlags: true, expression: true },
  sd: { patterns: 2, fileFlags: false, expression: false },
});

export function collectPathTokens(root: SyntaxNode, context: ShellWordContext, declarations: EffectDeclarations = {}): PathToken[] {
  const result: PathToken[] = [];
  function visit(node: SyntaxNode): void {
    if (node.type === "ERROR" || node.type === "comment") return;
    if (node.type === "case_statement") {
      let beforeIn = true;
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;
        if (child.type === "in" && !child.isNamed) { beforeIn = false; continue; }
        if (child.isNamed && beforeIn && child.type !== "comment") {
          const word = readShellWord(child, context);
          result.push({ value: word.value, role: "operand", effect: { effect: "unproven", source: "unknown" }, ...(word.computed ? { computed: true } : {}), span: { startIndex: child.startIndex, endIndex: child.endIndex } });
        }
        if (child.isNamed) visit(child);
      }
      return;
    }
    if (node.type === "for_statement" || node.type === "select_statement") {
      let inWords = false;
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;
        if (child.type === "in" && !child.isNamed) { inWords = true; continue; }
        if (child.type === ";" || child.type === "do_group") inWords = false;
        if (inWords && child.isNamed && child.type !== "comment") {
          const word = readShellWord(child, context);
          result.push({ value: word.value, role: "operand", effect: { effect: "unproven", source: "unknown" }, ...(word.computed ? { computed: true } : {}), span: { startIndex: child.startIndex, endIndex: child.endIndex } });
        }
        if (child.isNamed) visit(child);
      }
      return;
    }
    if (node.type === "file_redirect") {
      const target = redirectTargetNode(node);
      const word = target ? readShellWord(target, context) : undefined;
      const value = target && !target.hasError && word && !word.computed ? word.value : null;
      const operator = redirectOperator(node);
      if (target && value && !((operator === ">&" || operator === "<&") && isDescriptorRedirectTarget(value))) {
        const direction = operator && [">", ">>", ">|", "&>", "&>>", ">&"].includes(operator) ? "write"
          : operator && ["<", "<&"].includes(operator) ? "read" : "unproven";
        const effect: EffectProof = redirectPositionUnresolved(node) || direction === "unproven"
          ? { effect: "unproven", source: "unknown" } : { effect: direction, source: "syntax" };
        result.push({ value, role: "file_redirect", effect, span: { startIndex: target.startIndex, endIndex: target.endIndex } });
      } else if (target && !value) {
        if (word?.value && ((operator !== ">&" && operator !== "<&") || word.computed)) {
          result.push({ value: word.value, role: "operand", effect: { effect: "unproven", source: "unknown" }, ...(word.computed ? { computed: true } : {}), span: { startIndex: target.startIndex, endIndex: target.endIndex } });
        }
      }
      if (target) visit(target);
      return;
    }
    if (node.type === "command") {
      const nodes: SyntaxNode[] = [];
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child?.isNamed && child.type !== "variable_assignment" && child.type !== "comment" && !isRedirectNode(child)) nodes.push(child);
      }
      const words: CommandWord[] = nodes.map((child) => ({ ...readShellWord(child, context) }));
      const core = coreCommandEffect(words);
      const declared = core === undefined ? declaredCommandEffect(words, declarations) : undefined;
      const effect: EffectProof = core === "read" ? { effect: "read", source: "builtin-core" }
        : declared && (declared.effect === "read" || declared.effect === "write")
          ? { effect: declared.effect, source: declared.source }
          : { effect: "unproven", source: declared?.source === "declaration-retracted" ? "declaration-retracted" : "unknown" };
      const role = declared?.effect === "inert" ? "inert" : "operand";
      const name = words[0]?.value.split(/[\\/]/).pop() ?? "";
      const patternRoles = PATTERN_FIRST_TOOLS[name];
      const filePatternTool = patternRoles?.fileFlags === true;
      const expressionTool = patternRoles?.expression === true;
      const expressionLong = name === "sed" ? "--expression" : name === "gawk" ? "--source" : "--regexp";
      let patterns = patternRoles?.patterns ?? 0;
      let fileOption = false;
      let skipOptionValue = false;
      let optionsEnded = false;
      let ambiguousPattern = false;
      for (let i = 1; i < nodes.length; i++) {
        const argument = nodes[i]!;
        const value = words[i]!.value;
        // A fully quoted dash-leading word is a pattern, not a flag spelling.
        const quoted = argument.type === "raw_string" || argument.type === "string";
        const flag = !optionsEnded && !quoted;
        if (skipOptionValue) { skipOptionValue = false; continue; }
        if (fileOption) {
          fileOption = false;
          result.push({ value, role, effect, ...(words[i]!.computed ? { computed: true } : {}), span: { startIndex: argument.startIndex, endIndex: argument.endIndex } });
          continue;
        }
        if (!optionsEnded && value === "--" && argument.type === "word") { optionsEnded = true; continue; }
        if (flag && ["node", "bun"].includes(name) && ["-e", "--eval", "-p", "--print"].includes(value)) { skipOptionValue = true; continue; }
        if (flag && ["node", "bun"].includes(name) && (/^-(?:e|p).+/.test(value) || /^--(?:eval|print)=/.test(value))) continue;
        if (flag && ["python", "python3"].includes(name) && value === "-c") { skipOptionValue = true; continue; }
        if (flag && ["python", "python3"].includes(name) && /^-c.+/.test(value)) continue;
        if (flag && ["perl", "ruby"].includes(name) && value === "-e") { skipOptionValue = true; continue; }
        if (flag && ["perl", "ruby"].includes(name) && /^-e.+/.test(value)) continue;
        if (flag && name === "sed" && value === "-i" && words[i + 1]?.value === "" && !words[i + 1]?.computed) { i++; continue; }
        if (flag && ["awk", "nawk", "gawk"].includes(name) && ["-F", "-v"].includes(value)) { skipOptionValue = true; continue; }
        if (flag && ["awk", "nawk", "gawk"].includes(name) && /^-[Fv].+/.test(value)) continue;
        if (flag && name === "gawk" && value === "--source") { patterns = 0; skipOptionValue = true; continue; }
        if (flag && name === "gawk" && value.startsWith("--source=")) { patterns = 0; continue; }
        if (flag && ["awk", "nawk"].includes(name) && value.startsWith("--") && value !== "--") ambiguousPattern = true;
        if (flag && name === "rg" && ["-C", "--context"].includes(value)) { skipOptionValue = true; continue; }
        if (flag && name === "rg" && ["-g", "--glob", "--iglob"].includes(value)) { skipOptionValue = true; continue; }
        if (flag && name === "rg" && (/^-g.+/.test(value) || /^--(?:glob|iglob)=/.test(value))) continue;
        if (flag && ["grep", "egrep", "fgrep"].includes(name) && ["-C", "--context"].includes(value)) { ambiguousPattern = true; continue; }
        if (flag && ["grep", "egrep", "fgrep", "rg"].includes(name) && ["-A", "-B", "-m", "--after-context", "--before-context", "--max-count"].includes(value)) { skipOptionValue = true; continue; }
        if (flag && ["grep", "egrep", "fgrep", "rg"].includes(name) && (/^-[ABm].+/.test(value) || /^--(?:after-context|before-context|max-count)=/.test(value))) continue;
        if (flag && filePatternTool && (/^-f.+/.test(value) || value.startsWith("--file="))) {
          const file = value.startsWith("--file=") ? value.slice(7) : value.slice(2);
          patterns = 0;
          if (file) result.push({ value: file, role, effect, ...(words[i]!.computed ? { computed: true } : {}), sourceOffset: argument.startIndex });
          continue;
        }
        if (flag && expressionTool && (value === "-e" || value === expressionLong)) { patterns = 0; skipOptionValue = true; continue; }
        if (flag && expressionTool && (/^-e.+/.test(value) || value.startsWith(`${expressionLong}=`))) { patterns = 0; continue; }
        if (flag && filePatternTool && ["-f", "--file"].includes(value)) { fileOption = true; patterns = 0; }
        else if (patterns > 0 && (optionsEnded || !value.startsWith("-") || quoted)) {
          patterns--;
          if (!ambiguousPattern) continue;
        }
        result.push({ value: words[i]!.value, role, effect, ...(words[i]!.computed ? { computed: true } : {}), span: { startIndex: argument.startIndex, endIndex: argument.endIndex } });
        const attached = /^--?[^=]+=(.+)$/.exec(words[i]!.value);
        if (attached) result.push({ value: attached[1]!, role, effect, ...(words[i]!.computed ? { computed: true } : {}), sourceOffset: argument.startIndex });
      }
      for (let childIndex = 0; childIndex < node.childCount; childIndex++) {
        const child = node.child(childIndex);
        if (!child) continue;
        if (isRedirectNode(child)) { visit(child); continue; }
        for (let i = 0; i < child.childCount; i++) {
          const nested = child.child(i);
          if (nested?.isNamed) visit(nested);
        }
      }
      return;
    }
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.isNamed) visit(child);
    }
  }
  visit(root);
  return result;
}
