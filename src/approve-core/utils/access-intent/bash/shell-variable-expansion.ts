/**
 * Shell word reading and variable rebinding.
 *
 * A word exposes only what the program text proves: its value after quote
 * removal and the few static references the shell layer is allowed to resolve,
 * whether runtime expansion may still change it, and whether it could reach a
 * command as a dash-leading option. The rebinding scan runs once per program;
 * position order never matters because functions and loops can reorder
 * execution.
 */
import type { SyntaxNode } from "./parser";

export interface ShellWordContext {
  readonly home: string;
  readonly homeRebound: boolean;
  readonly pwdRebound: boolean;
}

export interface ShellWord {
  readonly value: string;
  readonly computed: boolean;
  readonly mayLeadWithDash: boolean;
}

export interface ReboundVariables {
  readonly home: boolean;
  readonly pwd: boolean;
}

export const NO_REBINDING: ReboundVariables = Object.freeze({
  home: false,
  pwd: false,
});

interface Part {
  readonly text: string;
  readonly computed: boolean;
  /** Whether this part, when it starts the word, could begin with `-`. */
  readonly leadingDash: boolean;
}

const GLOB_OR_ESCAPE = /[*?[\]{}\\]/;
const ASSIGNMENT_OPERATORS = new Set(["=", ":="]);
const ARITHMETIC_MUTATIONS = new Set(["=", "+=", "-=", "*=", "/=", "%=", "++", "--"]);
const BINDING_BUILTINS = new Set([
  "read",
  "readarray",
  "mapfile",
  "getopts",
]);
const INVISIBLE_CODE_COMMANDS = new Set(["eval", "source", ".", "trap"]);

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

function combine(parts: readonly Part[]): ShellWord {
  let value = "";
  let computed = false;
  let leading = true;
  let mayLeadWithDash = false;
  for (const part of parts) {
    if (leading && part.text.length > 0) {
      mayLeadWithDash = part.leadingDash;
      leading = false;
    }
    value += part.text;
    computed = computed || part.computed;
  }
  return { value, computed, mayLeadWithDash };
}

function literal(text: string): Part {
  return { text, computed: false, leadingDash: text.startsWith("-") };
}

function dynamic(text: string, leadingDash = true): Part {
  return { text, computed: true, leadingDash };
}

function unquote(text: string, quote: string): string | null {
  if (text.length < 2 || !text.startsWith(quote) || !text.endsWith(quote)) return null;
  return text.slice(1, -1);
}

function readParts(node: SyntaxNode, context: ShellWordContext): Part[] {
  switch (node.type) {
    case "word":
      return readWordText(node.text, context);
    case "number":
      return [literal(node.text)];
    case "raw_string": {
      const value = unquote(node.text, "'");
      return value === null ? [dynamic(node.text)] : [literal(value)];
    }
    case "string": {
      const content = namedChildren(node);
      if (content.length === 0) {
        const value = unquote(node.text, '"');
        return [value === null ? dynamic(node.text) : literal(value)];
      }
      return content.flatMap((child) =>
        child.type === "string_content"
          ? [literal(child.text)]
          : readParts(child, context)
      );
    }
    case "concatenation":
      return namedChildren(node).flatMap((child) => readParts(child, context));
    case "command_name":
      return namedChildren(node).flatMap((child) => readParts(child, context));
    case "simple_expansion":
    case "expansion":
      return [readExpansion(node, context)];
    case "command_substitution":
      return [dynamic(node.text)];
    case "process_substitution":
      // The program value is a /dev/fd path, so it can never be an option.
      return [dynamic(node.text, false)];
    case "arithmetic_expansion":
    case "ansi_c_string":
    case "translated_string":
    case "extglob_pattern":
      return [dynamic(node.text)];
    default:
      return [dynamic(node.text)];
  }
}

function readWordText(text: string, context: ShellWordContext): Part[] {
  if (text.startsWith("~+") || text.startsWith("~-")) {
    // PWD/OLDPWD aliases are runtime values, not startup paths.
    return [dynamic(text, false)];
  }
  if (text.startsWith("~")) {
    const rest = text.slice(1);
    if (rest.length === 0 || rest.startsWith("/")) {
      if (context.homeRebound || context.home.length === 0) {
        return [dynamic(text, false)];
      }
      const expanded = `${context.home}${rest}`;
      return [{
        text: expanded,
        computed: GLOB_OR_ESCAPE.test(rest),
        leadingDash: false,
      }];
    }
    // ~user depends on the passwd database; the shell layer cannot prove it.
    return [dynamic(text, false)];
  }
  if (GLOB_OR_ESCAPE.test(text)) return [dynamic(text)];
  return [literal(text)];
}

function readExpansion(node: SyntaxNode, context: ShellWordContext): Part {
  const variable = namedChildren(node).find((child) => child.type === "variable_name");
  const operators = children(node)
    .filter((child) => !child.isNamed)
    .map((child) => child.type);
  const plain = operators.every((operator) => operator === "$" || operator === "${" || operator === "}");
  const name = variable?.text;

  if (plain && name === "HOME") {
    return context.homeRebound || context.home.length === 0
      ? dynamic(node.text)
      : literal(context.home);
  }
  if (plain && name === "PWD") {
    // The current base directory is applied later by path projection.
    return context.pwdRebound ? dynamic(node.text) : literal(".");
  }
  return dynamic(node.text);
}

export function readShellWord(node: SyntaxNode, context: ShellWordContext): ShellWord {
  return combine(readParts(node, context));
}

interface RebindAccumulator {
  home: boolean;
  pwd: boolean;
}

function record(accumulator: RebindAccumulator, name: string): void {
  if (name === "HOME") accumulator.home = true;
  else if (name === "PWD") accumulator.pwd = true;
}

function stripQuotes(text: string): string {
  if (text.length < 2) return text;
  const first = text[0];
  const last = text[text.length - 1];
  if ((first === "'" || first === '"') && first === last) return text.slice(1, -1);
  return text;
}

function commandNameOf(node: SyntaxNode): string | undefined {
  const child = namedChildren(node).find((candidate) => candidate.type === "command_name");
  return child === undefined ? undefined : stripQuotes(child.text);
}

function basename(text: string): string {
  const slash = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  return slash === -1 ? text : text.slice(slash + 1);
}

function assignmentName(text: string): string {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(text);
  return match?.[1] ?? "";
}

function isBindingFlag(text: string, flag: string): boolean {
  return text === `-${flag}` || text === `--${flag}`;
}

function recordArguments(
  node: SyntaxNode,
  accumulator: RebindAccumulator,
  include: (child: SyntaxNode, index: number) => boolean,
): void {
  const args = namedChildren(node).filter((child) =>
    child.type !== "command_name" &&
    child.type !== "file_redirect" &&
    child.type !== "heredoc_redirect" &&
    child.type !== "herestring_redirect"
  );
  for (const [index, child] of args.entries()) {
    if (include(child, index)) record(accumulator, stripQuotes(child.text));
  }
}

function scanBindingCommand(
  node: SyntaxNode,
  name: string,
  accumulator: RebindAccumulator,
): void {
  if (INVISIBLE_CODE_COMMANDS.has(name)) {
    accumulator.home = true;
    accumulator.pwd = true;
    return;
  }
  if (BINDING_BUILTINS.has(name)) {
    recordArguments(node, accumulator, (child) => {
      if (name === "getopts") return true;
      // Options are not names; values of options may be, so keep it conservative.
      return !child.text.startsWith("-");
    });
    return;
  }
  if (name === "printf") {
    const args = namedChildren(node).filter((child) => child.type !== "command_name");
    for (const [index, child] of args.entries()) {
      const text = stripQuotes(child.text);
      if (text === "-v") {
        const target = args[index + 1];
        if (target) record(accumulator, stripQuotes(target.text));
      } else if (text.startsWith("-v") && text.length > 2) {
        record(accumulator, text.slice(2));
      }
    }
    return;
  }
  if (name === "let") {
    recordArguments(node, accumulator, (child) =>
      /\b(?:HOME|PWD)\b/.test(child.text) && /(?:[+\-*/%&|^]?=|\+\+|--)/.test(child.text)
    );
    const args = namedChildren(node).filter((child) => child.type !== "command_name");
    for (const child of args) {
      if (/\b(?:HOME|PWD)\b/.test(child.text)) {
        record(accumulator, assignmentName(stripQuotes(child.text)));
      }
    }
  }
}

function scanArithmetic(node: SyntaxNode, accumulator: RebindAccumulator): void {
  if (!node.type.includes("expression")) return;
  const variables = namedChildren(node).filter((child) => child.type === "variable_name");
  if (variables.length === 0) return;
  const operators = children(node)
    .filter((child) => !child.isNamed)
    .map((child) => child.type);
  if (!operators.some((operator) => ARITHMETIC_MUTATIONS.has(operator))) return;
  for (const variable of variables) record(accumulator, variable.text);
}

function visitRebindings(node: SyntaxNode, accumulator: RebindAccumulator): void {
  switch (node.type) {
    case "variable_assignment":
      record(accumulator, assignmentName(node.text));
      break;
    case "declaration_command": {
      const words = namedChildren(node).filter((child) => child.type === "word");
      const queryOnly = words.some((child) => {
        const text = child.text;
        return text === "--print" || /^-[A-Za-z]*p[A-Za-z]*$/.test(text);
      });
      if (!queryOnly) {
        for (const word of words) {
          const text = stripQuotes(word.text);
          record(accumulator, assignmentName(text));
        }
      }
      break;
    }
    case "for_statement":
      for (const child of namedChildren(node)) {
        if (child.type === "variable_name") record(accumulator, child.text);
      }
      break;
    case "unset_command":
      for (const child of namedChildren(node)) {
        if (child.type === "variable_name") record(accumulator, child.text);
      }
      break;
    case "expansion": {
      const operators = children(node)
        .filter((child) => !child.isNamed)
        .map((child) => child.type);
      if (operators.some((operator) => ASSIGNMENT_OPERATORS.has(operator))) {
        const variable = namedChildren(node).find((child) => child.type === "variable_name");
        if (variable) record(accumulator, variable.text);
      }
      break;
    }
    case "command": {
      const name = commandNameOf(node);
      if (name !== undefined) scanBindingCommand(node, basename(name), accumulator);
      break;
    }
    default:
      scanArithmetic(node, accumulator);
      break;
  }
  for (const child of children(node)) visitRebindings(child, accumulator);
}

export function scanRebindings(roots: readonly SyntaxNode[]): ReboundVariables {
  const accumulator: RebindAccumulator = { home: false, pwd: false };
  for (const root of roots) visitRebindings(root, accumulator);
  return {
    home: accumulator.home,
    pwd: accumulator.pwd,
  };
}
