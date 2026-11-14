/**
 * Command-unit enumeration.
 *
 * One pass over a parse tree emits the source units a policy engine must judge:
 * statements from program/list/pipeline chains, compound bodies, subshells,
 * command and process substitutions, and unresolved recovery regions. The unit
 * shape stays small; redirect facts, word facts and wrapper analysis ride
 * alongside it so consumers never re-lex the text.
 */
import type { BashCommandContext, FloorExemption } from "#approve-core/contracts";
import type { SyntaxNode } from "./parser";
import { commandRuleText, isRedirectNodeType, type RuleTextPart } from "./node-text";
import { analyzeRedirect, type RedirectFacts } from "./redirect-analysis";
import {
  readShellWord,
  type ShellWord,
  type ShellWordContext,
} from "./shell-variable-expansion";
import {
  analyzeWrapper,
  type CommandWord,
  type ExecutionAnalysis,
  type WrapperKind,
  type WrapperLayer,
} from "./wrapper-analysis";

export interface BashCommand {
  readonly text: string;
  readonly context?: BashCommandContext;
  readonly wrapperKind?: WrapperKind;
  readonly executedUnit?: string;
  readonly floorExemption?: FloorExemption;
  readonly parseUnresolved?: boolean;
  readonly salvaged?: boolean;
  readonly equivalents?: readonly string[];
}

export interface BashRedirectFact {
  readonly operator?: string;
  readonly targetText?: string;
  readonly targetValue?: string;
  readonly dynamicTarget: boolean;
  readonly writesFile: boolean;
}

export interface EnumerateCommandsOptions {
  /** Text the root offsets refer to. Salvage roots use their region text. */
  readonly source: string;
  readonly wordContext: ShellWordContext;
  readonly isAbsolutePath?: (value: string) => boolean;
  readonly salvaged?: boolean;
  readonly isPureReader?: (words: readonly CommandWord[]) => boolean;
}

interface Sidecars {
  readonly redirects: readonly BashRedirectFact[];
  readonly words: readonly CommandWord[];
  readonly execution?: ExecutionAnalysis;
  readonly parts?: readonly { readonly sourceStart: number; readonly sourceEnd: number; readonly textStart: number; readonly textEnd: number }[];
}

const sidecars = new WeakMap<BashCommand, Sidecars>();

export function redirectFactsOf(unit: BashCommand): readonly BashRedirectFact[] {
  return sidecars.get(unit)?.redirects ?? [];
}

export function executionAnalysisOf(unit: BashCommand): ExecutionAnalysis | undefined {
  return sidecars.get(unit)?.execution;
}

export function executionLayersOf(unit: BashCommand): readonly WrapperLayer[] {
  return sidecars.get(unit)?.execution?.layers ?? [];
}

export function wordsOf(unit: BashCommand): readonly CommandWord[] {
  return sidecars.get(unit)?.words ?? [];
}

export function withPathEquivalents(unit: BashCommand, spellings: readonly { readonly startIndex: number; readonly endIndex: number; readonly value: string }[]): BashCommand {
  if (unit.salvaged) return unit;
  const facts = sidecars.get(unit);
  if (!facts?.parts) return unit;
  const variants = new Set(unit.equivalents ?? []);
  for (const part of facts.parts) {
    const spelling = spellings.find((item) => item.startIndex === part.sourceStart && item.endIndex === part.sourceEnd);
    if (spelling) {
      const escaped = /^[A-Za-z0-9_@%+=:,./-]+$/.test(spelling.value)
        ? spelling.value : `'${spelling.value.replaceAll("'", "'\\''")}'`;
      variants.add(`${unit.text.slice(0, part.textStart)}${escaped}${unit.text.slice(part.textEnd)}`);
    }
  }
  variants.delete(unit.text);
  if (!variants.size) return unit;
  const updated = Object.freeze({ ...unit, equivalents: Object.freeze([...variants]) });
  sidecars.set(updated, facts);
  return updated;
}

interface Draft {
  readonly unit: BashCommand;
  readonly startIndex: number;
  readonly primary: boolean;
  readonly node: SyntaxNode;
  readonly words: readonly CommandWord[];
  readonly redirects: readonly BashRedirectFact[];
  readonly execution?: ExecutionAnalysis;
}

const STATEMENT_TYPES = new Set([
  "command",
  "list",
  "pipeline",
  "redirected_statement",
  "subshell",
  "compound_statement",
  "if_statement",
  "for_statement",
  "c_style_for_statement",
  "while_statement",
  "case_statement",
  "case_item",
  "function_definition",
  "negated_command",
  "do_group",
  "else_clause",
  "elif_clause",
  "test_command",
  "declaration_command",
  "unset_command",
  "variable_assignment",
]);

const CONTAINER_TYPES = new Set([
  "program",
  "list",
  "pipeline",
  "do_group",
  "else_clause",
  "elif_clause",
  "case_item",
]);

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

function namedChildren(node: SyntaxNode): SyntaxNode[] {
  return children(node).filter((child) => child.isNamed);
}

function redirectFact(node: SyntaxNode): BashRedirectFact {
  const facts: RedirectFacts = analyzeRedirect(node);
  return {
    ...(facts.operator === null ? {} : { operator: facts.operator }),
    ...(facts.targetText === null ? {} : { targetText: facts.targetText }),
    ...(facts.targetValue === null ? {} : { targetValue: facts.targetValue }),
    dynamicTarget: facts.dynamicTarget,
    writesFile: facts.mayWriteFile,
  };
}

function directRedirectFacts(node: SyntaxNode): BashRedirectFact[] {
  const facts: BashRedirectFact[] = [];
  const collect = (redirect: SyntaxNode): void => {
    facts.push(redirectFact(redirect));
    for (const child of namedChildren(redirect)) {
      if (isRedirectNodeType(child.type)) collect(child);
    }
  };
  for (const child of namedChildren(node)) {
    if (isRedirectNodeType(child.type)) collect(child);
  }
  return facts;
}

function commandWords(
  parts: readonly RuleTextPart[],
  context: ShellWordContext,
): { readonly name?: CommandWord; readonly words: readonly CommandWord[] } {
  const words: CommandWord[] = [];
  let name: CommandWord | undefined;
  for (const part of parts) {
    const word = toCommandWord(readShellWord(part.node, context), part.node);
    if (part.role === "name") {
      name = word;
      words.push(word);
    } else {
      words.push(word);
    }
  }
  return { ...(name === undefined ? {} : { name }), words };
}

function toCommandWord(word: ShellWord, node: SyntaxNode): CommandWord {
  return {
    value: word.value,
    computed: word.computed,
    mayLeadWithDash: word.mayLeadWithDash,
    text: node.text,
    startIndex: node.startIndex,
  };
}

function homePrefixed(text: string): boolean {
  return text === "~" || text.startsWith("~/") ||
    text.startsWith("$HOME") || text.startsWith("${HOME}");
}

function equivalentsFor(
  text: string,
  parts: readonly RuleTextPart[],
  context: ShellWordContext,
  isAbsolutePath: (value: string) => boolean,
): string[] {
  const variants = new Set<string>();
  const namePart = parts.find((part) => part.role === "name");
  if (namePart !== undefined && !context.homeRebound) {
    const source = text.slice(namePart.start, namePart.end);
    const value = readShellWord(namePart.node, context).value;
    if (homePrefixed(source) && value !== source) {
      variants.add(`${value}${text.slice(namePart.end)}`);
    }
  }
  for (const part of parts) {
    if (part.role !== "argument") continue;
    const word = readShellWord(part.node, context);
    if (word.computed || !isAbsolutePath(word.value)) continue;
    const spelling = text.slice(part.start, part.end);
    if (spelling === word.value) continue;
    variants.add(`${text.slice(0, part.start)}${word.value}${text.slice(part.end)}`);
  }
  variants.delete(text);
  return [...variants];
}

interface Enumerator {
  readonly options: EnumerateCommandsOptions;
  readonly context: ShellWordContext;
  readonly isAbsolutePath: (value: string) => boolean;
}

function draftFromStatement(
  node: SyntaxNode,
  enumerator: Enumerator,
  context: BashCommandContext | undefined,
): Draft {
  const rule = commandRuleText(node, enumerator.options.source);
  const redirects = directRedirectFacts(node);
  let words: readonly CommandWord[] = [];
  let execution: ExecutionAnalysis | undefined;
  let equivalents: readonly string[] = [];
  if (node.type === "command") {
    const built = commandWords(rule.parts, enumerator.context);
    words = built.words;
    equivalents = enumerator.options.salvaged === true
      ? []
      : equivalentsFor(rule.text, rule.parts, enumerator.context, enumerator.isAbsolutePath);
    if (built.name !== undefined) {
      execution = analyzeWrapper(built.words, {
        redirectsWrite: redirects.some((fact) => fact.writesFile),
        ...(enumerator.options.isPureReader === undefined
          ? {}
          : { isPureReader: enumerator.options.isPureReader }),
      });
    }
  }
  const wrapperLayer = execution?.layers[0];
  const unit: BashCommand = Object.freeze({
    text: rule.text,
    ...(context === undefined ? {} : { context }),
    ...(wrapperLayer === undefined ? {} : { wrapperKind: wrapperLayer.wrapperKind }),
    ...(execution?.executedUnit === undefined ? {} : { executedUnit: execution.executedUnit }),
    ...(execution?.floorExemption === undefined
      ? {}
      : { floorExemption: execution.floorExemption }),
    ...(node.hasError || enumerator.options.salvaged === true
      ? { parseUnresolved: true }
      : {}),
    ...(enumerator.options.salvaged === true ? { salvaged: true } : {}),
    ...(equivalents.length === 0 ? {} : { equivalents: Object.freeze(equivalents) }),
  });
  return {
    unit,
    startIndex: node.startIndex,
    primary: true,
    node,
    words,
    redirects,
    ...(execution === undefined ? {} : { execution }),
  };
}

function draftFromRegion(
  node: SyntaxNode,
  enumerator: Enumerator,
  context: BashCommandContext | undefined,
): Draft | undefined {
  const text = node.text;
  if (text.trim().length === 0) return undefined;
  const unit: BashCommand = Object.freeze({
    text,
    ...(context === undefined ? {} : { context }),
    parseUnresolved: true,
    ...(enumerator.options.salvaged === true ? { salvaged: true } : {}),
  });
  return {
    unit,
    startIndex: node.startIndex,
    primary: true,
    node,
    words: [],
    redirects: [],
  };
}

function scanNested(
  node: SyntaxNode,
  enumerator: Enumerator,
  context: BashCommandContext | undefined,
  drafts: Draft[],
): void {
  if (node.type === "command_substitution" || node.type === "process_substitution") {
    const nestedContext: BashCommandContext = node.type === "command_substitution"
      ? "command_substitution"
      : "process_substitution";
    walkChildren(node, enumerator, nestedContext, drafts);
    return;
  }
  if (node.type === "subshell") {
    drafts.push(...walk(node, enumerator, context));
    return;
  }
  for (const child of children(node)) scanNested(child, enumerator, context, drafts);
}

function walkChildren(
  node: SyntaxNode,
  enumerator: Enumerator,
  context: BashCommandContext | undefined,
  drafts: Draft[],
): void {
  for (const child of namedChildren(node)) {
    if (STATEMENT_TYPES.has(child.type) || CONTAINER_TYPES.has(child.type)) {
      drafts.push(...walk(child, enumerator, context));
    } else if (child.type === "ERROR") {
      const region = draftFromRegion(child, enumerator, context);
      if (region) drafts.push(region);
    } else {
      scanNested(child, enumerator, context, drafts);
    }
  }
}

function walk(
  node: SyntaxNode,
  enumerator: Enumerator,
  context: BashCommandContext | undefined,
): Draft[] {
  const drafts: Draft[] = [];
  switch (node.type) {
    case "program":
    case "list":
    case "pipeline":
      walkChildren(node, enumerator, context, drafts);
      return drafts;

    case "redirected_statement": {
      const body = namedChildren(node).find((child) => !isRedirectNodeType(child.type));
      const bodyDrafts = body === undefined ? [] : walk(body, enumerator, context);
      drafts.push(...bodyDrafts);

      const redirects = directRedirectFacts(node);
      const primaries = bodyDrafts.filter((draft) => draft.primary);
      const target = primaries[primaries.length - 1];
      if (target !== undefined && redirects.length > 0) {
        const merged = mergeRedirects(target, redirects, enumerator);
        drafts[drafts.indexOf(target)] = merged;
      }
      if (node.hasError && !drafts.some((draft) => draft.unit.parseUnresolved === true)) {
        if (target !== undefined) {
          const index = drafts.findIndex((draft) => draft === target || draft.startIndex === target.startIndex);
          if (index >= 0) drafts[index] = markUnresolved(drafts[index]!);
        }
      }
      for (const child of namedChildren(node)) {
        if (isRedirectNodeType(child.type)) scanNested(child, enumerator, context, drafts);
      }
      return drafts;
    }

    case "subshell": {
      drafts.push(draftFromStatement(node, enumerator, context));
      walkChildren(node, enumerator, "subshell", drafts);
      return drafts;
    }

    case "compound_statement": {
      drafts.push(draftFromStatement(node, enumerator, context));
      walkChildren(node, enumerator, context, drafts);
      return drafts;
    }

    case "if_statement":
    case "for_statement":
    case "c_style_for_statement":
    case "while_statement":
    case "case_statement":
    case "negated_command":
      drafts.push(draftFromStatement(node, enumerator, context));
      walkChildren(node, enumerator, context, drafts);
      return drafts;

    case "function_definition": {
      drafts.push(draftFromStatement(node, enumerator, context));
      for (const child of namedChildren(node)) {
        if (child.type === "compound_statement") {
          // The brace group is the function body syntax, not a second command.
          walkChildren(child, enumerator, context, drafts);
        } else {
          scanNested(child, enumerator, context, drafts);
        }
      }
      return drafts;
    }

    case "do_group":
    case "else_clause":
    case "elif_clause":
    case "case_item":
      walkChildren(node, enumerator, context, drafts);
      return drafts;

    case "command": {
      const statement = draftFromStatement(node, enumerator, context);
      if (statement.unit.text.trim().length > 0) drafts.push(statement);
      scanNested(node, enumerator, context, drafts);
      return drafts;
    }

    case "ERROR": {
      const region = draftFromRegion(node, enumerator, context);
      if (region) drafts.push(region);
      return drafts;
    }

    case "comment":
      return drafts;

    default: {
      drafts.push(draftFromStatement(node, enumerator, context));
      scanNested(node, enumerator, context, drafts);
      return drafts;
    }
  }
}

function mergeRedirects(
  draft: Draft,
  extra: readonly BashRedirectFact[],
  enumerator: Enumerator,
): Draft {
  const redirects = Object.freeze([...draft.redirects, ...extra]);
  const execution = draft.words.length === 0
    ? draft.execution
    : analyzeWrapper(draft.words, {
        redirectsWrite: redirects.some((fact) => fact.writesFile),
        ...(enumerator.options.isPureReader === undefined
          ? {}
          : { isPureReader: enumerator.options.isPureReader }),
      });
  const wrapperLayer = execution?.layers[0];
  const { floorExemption: _previousFloorExemption, ...unitWithoutFloor } = draft.unit;
  const unit: BashCommand = Object.freeze({
    ...unitWithoutFloor,
    ...(wrapperLayer === undefined ? {} : { wrapperKind: wrapperLayer.wrapperKind }),
    ...(execution?.executedUnit === undefined ? {} : { executedUnit: execution.executedUnit }),
    ...(execution?.floorExemption === undefined
      ? {}
      : { floorExemption: execution.floorExemption }),
  });
  return {
    ...draft,
    unit,
    redirects,
    execution,
  };
}

function markUnresolved(draft: Draft): Draft {
  const unit: BashCommand = Object.freeze({ ...draft.unit, parseUnresolved: true });
  return { ...draft, unit };
}

/**
 * Enumerate one parse tree. The result is frozen and in source order; nested
 * execution units follow their enclosing statement.
 */
export function enumerateCommands(
  root: SyntaxNode,
  options: EnumerateCommandsOptions,
): readonly BashCommand[] {
  const enumerator: Enumerator = {
    options,
    context: options.wordContext,
    isAbsolutePath: options.isAbsolutePath ?? ((value) => value.startsWith("/")),
  };
  const drafts = walk(root, enumerator, undefined);
  drafts.sort((left, right) => left.startIndex - right.startIndex);

  if (root.hasError && !drafts.some((draft) => draft.unit.parseUnresolved === true)) {
    const text = options.source;
    if (text.trim().length > 0) {
      const unit: BashCommand = Object.freeze({
        text,
        parseUnresolved: true,
        ...(options.salvaged === true ? { salvaged: true } : {}),
      });
      drafts.push({
        unit,
        startIndex: 0,
        primary: false,
        node: root,
        words: [],
        redirects: [],
      });
    }
  }

  const units: BashCommand[] = [];
  for (const draft of drafts) {
    sidecars.set(draft.unit, {
      redirects: Object.freeze(draft.redirects),
      words: Object.freeze(draft.words),
      parts: commandRuleText(draft.node, options.source).parts.filter((part) => part.role === "argument").map((part) => ({
        sourceStart: part.node.startIndex, sourceEnd: part.node.endIndex, textStart: part.start, textEnd: part.end,
      })),
      ...(draft.execution === undefined ? {} : { execution: draft.execution }),
    });
    units.push(draft.unit);
  }
  return Object.freeze(units);
}
