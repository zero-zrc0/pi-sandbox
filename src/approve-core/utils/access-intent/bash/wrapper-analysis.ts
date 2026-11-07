/**
 * Wrapper identification and unwrapping.
 *
 * The analyzer works on an argv of already-read shell words, never on a
 * re-lexed command string. It reports every stripped layer, the executable
 * actions that remain, whether the walk is complete, and why it stopped. A
 * wrapper whose load is another shell program (eval, `sh -c`) is opaque: the
 * payload can be shown, but it is never evidence that the wrapper's floor does
 * not apply.
 */
import type { FloorExemption } from "#approve-core/contracts";
import { coreCommandEffect } from "./command-effects";

export type WrapperKind =
  | "opaque-payload"
  | "privilege"
  | "environment"
  | "command"
  | "executor"
  | "template"
  | "execution-modifier"
  | "watcher"
  | "lock"
  | "finder";

export interface CommandWord {
  readonly value: string;
  readonly computed: boolean;
  readonly mayLeadWithDash: boolean;
  /** Original source spelling, when the caller kept it. */
  readonly text?: string;
  /** Absolute source offset in the root the word came from. */
  readonly startIndex?: number;
}

export interface WrapperLayer {
  readonly commandName: string;
  readonly wrapperKind: WrapperKind;
  /** The wrapper's own words, without the inner command. */
  readonly text: string;
  /** Options were inside this layer's execution-modifier allow table. */
  readonly modifierSafe: boolean;
  /** Every option and value of the layer was a known non-computed word. */
  readonly literal: boolean;
  /** The layer itself cannot have written a file as part of running it. */
  readonly readerSafe: boolean;
}

export interface ExecAction {
  readonly text: string;
  readonly words: readonly CommandWord[];
}

export type WrapperStopReason =
  | "complete"
  | "no-command"
  | "query-mode"
  | "opaque-payload"
  | "template-command"
  | "unknown-option"
  | "ambiguous-option"
  | "computed-option"
  | "computed-command"
  | "missing-option-value"
  | "unknown-primary"
  | "computed-primary-argument"
  | "invalid-exec"
  | "unexpected-operand"
  | "depth-limit";

export interface ExecutionAnalysis {
  readonly layers: readonly WrapperLayer[];
  readonly actions: readonly ExecAction[];
  readonly complete: boolean;
  readonly stopReason: WrapperStopReason;
  readonly executedUnit?: string;
  readonly floorExemption?: FloorExemption;
}

export interface WrapperAnalysisOptions {
  readonly redirectsWrite?: boolean;
  readonly isPureReader?: (words: readonly CommandWord[]) => boolean;
  readonly maxDepth?: number;
}

const DEFAULT_MAX_DEPTH = 4;

const SHELLS = new Set(["bash", "sh", "dash", "zsh", "ksh"]);

/**
 * Wrapper roster exposed as plain data. Configuration loading injects its own
 * copy to warn about declarations that can never take effect; the analysis
 * below is the authority for which kind each name produces.
 */
export const WRAPPER_COMMANDS: ReadonlySet<string> = Object.freeze(new Set([
  "eval",
  ...SHELLS,
  "sudo",
  "doas",
  "env",
  "command",
  "xargs",
  "parallel",
  "rust-parallel",
  "rush",
  "time",
  "timeout",
  "nice",
  "nohup",
  "setsid",
  "stdbuf",
  "watch",
  "flock",
  "find",
  "fd",
]));

const FIND_EXEC_OPTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
const FIND_ZERO_ARITY = new Set([
  "-a",
  "-and",
  "-daystart",
  "-depth",
  "-empty",
  "-executable",
  "-false",
  "-follow",
  "-help",
  "--help",
  "-ignore_readdir_race",
  "-mount",
  "-noleaf",
  "-nogroup",
  "-nouser",
  "-nowarn",
  "-o",
  "-or",
  "-print",
  "-print0",
  "-prune",
  "-quit",
  "-readable",
  "-true",
  "-version",
  "--version",
  "-warn",
  "-writable",
  "-xdev",
  "(",
  ")",
  "!",
]);
const FIND_ONE_ARITY = new Set([
  "-D",
  "-amin",
  "-anewer",
  "-atime",
  "-cmin",
  "-cnewer",
  "-context",
  "-ctime",
  "-fprint",
  "-fprint0",
  "-fls",
  "-files0-from",
  "-fstype",
  "-gid",
  "-group",
  "-ilname",
  "-iname",
  "-inum",
  "-ipath",
  "-iregex",
  "-iwholename",
  "-links",
  "-lname",
  "-maxdepth",
  "-mindepth",
  "-mmin",
  "-mtime",
  "-name",
  "-newer",
  "-path",
  "-perm",
  "-printf",
  "-regex",
  "-regextype",
  "-samefile",
  "-size",
  "-type",
  "-uid",
  "-used",
  "-user",
  "-wholename",
  "-xtype",
]);

function basename(text: string): string {
  const slash = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  return slash === -1 ? text : text.slice(slash + 1);
}

function hasDash(text: string | undefined): boolean {
  if (text === undefined) return false;
  return text.startsWith("-") && text !== "-";
}

function joinValues(words: readonly CommandWord[]): string {
  return words.map((word) => word.value).join(" ");
}

export function wrapperKindOf(
  name: string,
  argv: readonly CommandWord[] = [],
): WrapperKind | undefined {
  const base = basename(name);
  if (!WRAPPER_COMMANDS.has(base)) return undefined;
  if (base === "eval") return "opaque-payload";
  if (SHELLS.has(base) && shellHasCommandFlag(argv.slice(1))) return "opaque-payload";
  switch (base) {
    case "sudo":
    case "doas":
      return "privilege";
    case "env":
      return "environment";
    case "command":
      return "command";
    case "xargs":
      return "executor";
    case "parallel":
    case "rust-parallel":
    case "rush":
      return "template";
    case "time":
    case "timeout":
    case "nice":
    case "nohup":
    case "setsid":
    case "stdbuf":
      return "execution-modifier";
    case "watch":
      return "watcher";
    case "flock":
      return "lock";
    case "find":
      return findHasExec(argv.slice(1)) ? "finder" : undefined;
    case "fd":
      return fdHasExec(argv.slice(1)) ? "finder" : undefined;
    default:
      return undefined;
  }
}

/** A shell is opaque only when a short cluster before `--` contains `c`. */
function shellHasCommandFlag(args: readonly CommandWord[]): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const word = args[index]!;
    if (word.computed) continue;
    if (word.value === "--") return false;
    if (word.value.startsWith("--")) {
      const name = word.value.slice(2).split("=")[0]!;
      if ((name === "rcfile" || name === "init-file") && !word.value.includes("=")) {
        index += 1;
      }
      continue;
    }
    if (!word.value.startsWith("-")) return false;
    const cluster = word.value.slice(1);
    if (cluster.includes("c")) return true;
    if (cluster === "O" || cluster === "o") index += 1;
  }
  return false;
}

function fdHasExec(args: readonly CommandWord[]): boolean {
  return args.some((word) => {
    if (word.computed) return false;
    const value = word.value;
    if (value === "--") return false;
    return value === "-x" || value === "-X" ||
      value === "--exec" || value === "--exec-batch" ||
      value.startsWith("--exec=") || value.startsWith("--exec-batch=");
  });
}

/**
 * Find is a wrapper only when an exec clause is proved to be in operator
 * position. A primary's value that merely spells `-exec` is not a clause, while
 * an unknown primary keeps the possibility open and therefore stays
 * incomplete.
 */
function findHasExec(args: readonly CommandWord[]): boolean {
  const parsed = parseFind(args);
  return parsed.actions.length > 0 || parsed.stop !== undefined;
}

function shortArgs(words: readonly CommandWord[]): readonly CommandWord[] {
  return words.slice(1);
}

interface OptionTable {
  readonly shortFlags: ReadonlySet<string>;
  readonly shortValues: ReadonlySet<string>;
  readonly shortOptional: ReadonlySet<string>;
  readonly longFlags: ReadonlySet<string>;
  readonly longValues: ReadonlySet<string>;
  readonly longOptional: ReadonlySet<string>;
}

interface OptionFailure {
  readonly stop: WrapperStopReason;
}

interface OptionSuccess {
  readonly rest: readonly CommandWord[];
  readonly used: ReadonlySet<string>;
}

type OptionResult = OptionSuccess | OptionFailure;

function optionSet(...text: string[]): ReadonlySet<string> {
  return new Set(text.join(" ").split(/\s+/).filter((item) => item.length > 0));
}

function shortSet(text: string): ReadonlySet<string> {
  return new Set([...text].filter((item) => !/\s/.test(item)));
}

function table(definition: {
  shortFlags?: string;
  shortValues?: string;
  shortOptional?: string;
  longFlags?: readonly string[];
  longValues?: readonly string[];
  longOptional?: readonly string[];
}): OptionTable {
  return {
    shortFlags: shortSet(definition.shortFlags ?? ""),
    shortValues: shortSet(definition.shortValues ?? ""),
    shortOptional: shortSet(definition.shortOptional ?? ""),
    longFlags: optionSet(...(definition.longFlags ?? [])),
    longValues: optionSet(...(definition.longValues ?? [])),
    longOptional: optionSet(...(definition.longOptional ?? [])),
  };
}

interface ShortResult {
  readonly consumeNext?: boolean;
  readonly stop?: WrapperStopReason;
}

function parseShortCluster(
  cluster: string,
  syntax: OptionTable,
  used: Set<string>,
  next: CommandWord | undefined,
): ShortResult {
  for (let index = 0; index < cluster.length; index += 1) {
    const flag = cluster[index]!;
    if (syntax.shortFlags.has(flag)) {
      used.add(flag);
      continue;
    }
    if (syntax.shortValues.has(flag)) {
      used.add(flag);
      if (index < cluster.length - 1) return {};
      return next === undefined ? { stop: "missing-option-value" } : { consumeNext: true };
    }
    if (syntax.shortOptional.has(flag)) {
      used.add(flag);
      return {};
    }
    return { stop: "unknown-option" };
  }
  return {};
}

interface LongMatch {
  readonly kind: "flag" | "value" | "optional" | "ambiguous" | "unknown";
  readonly name?: string;
}

function resolveLong(name: string, syntax: OptionTable): LongMatch {
  const groups: Array<{ kind: LongMatch["kind"]; names: ReadonlySet<string> }> = [
    { kind: "flag", names: syntax.longFlags },
    { kind: "value", names: syntax.longValues },
    { kind: "optional", names: syntax.longOptional },
  ];
  for (const group of groups) {
    if (group.names.has(name)) return { kind: group.kind, name };
  }
  const matches = groups.flatMap((group) =>
    [...group.names]
      .filter((candidate) => candidate.startsWith(name))
      .map((candidate) => ({ kind: group.kind, name: candidate }))
  );
  if (matches.length === 0) return { kind: "unknown" };
  if (matches.length > 1) return { kind: "ambiguous" };
  return matches[0]!;
}

function parseOptions(
  args: readonly CommandWord[],
  syntax: OptionTable,
  options: { readonly bareDashFlag?: string } = {},
): OptionResult {
  const used = new Set<string>();
  let index = 0;
  for (; index < args.length; index += 1) {
    const word = args[index]!;
    if (word.computed) {
      return { stop: word.mayLeadWithDash ? "computed-option" : "computed-command" };
    }
    if (word.value === "--") {
      index += 1;
      break;
    }
    if (word.value === "-") {
      if (options.bareDashFlag !== undefined) {
        used.add(options.bareDashFlag);
        continue;
      }
      break;
    }
    if (!word.value.startsWith("-") || word.value.length === 1) break;
    if (!word.value.startsWith("--")) {
      const result = parseShortCluster(word.value.slice(1), syntax, used, args[index + 1]);
      if (result.stop !== undefined) return { stop: result.stop };
      if (result.consumeNext === true) index += 1;
      continue;
    }

    const body = word.value.slice(2);
    const equals = body.indexOf("=");
    const rawName = equals < 0 ? body : body.slice(0, equals);
    const attached = equals < 0 ? undefined : body.slice(equals + 1);
    const match = resolveLong(rawName, syntax);
    if (match.kind === "unknown") return { stop: "unknown-option" };
    if (match.kind === "ambiguous") return { stop: "ambiguous-option" };
    const name = match.name!;
    if (match.kind === "flag") {
      if (attached !== undefined) return { stop: "unknown-option" };
      used.add(name);
      continue;
    }
    used.add(name);
    if (match.kind === "optional") continue;
    if (attached === undefined) {
      if (args[index + 1] === undefined) return { stop: "missing-option-value" };
      index += 1;
    }
  }
  return { rest: args.slice(index), used };
}

function isFailure(result: OptionResult): result is OptionFailure {
  return "stop" in result;
}

function consumeAssignments(words: readonly CommandWord[]): readonly CommandWord[] {
  let index = 0;
  while (index < words.length) {
    const word = words[index]!;
    if (word.computed) return words.slice(index);
    if (!/^[A-Za-z_][A-Za-z0-9_]*=/.test(word.value)) break;
    index += 1;
  }
  return words.slice(index);
}

type UnwrapOutcome =
  | {
      readonly kind: "inner";
      readonly inner: readonly CommandWord[];
      readonly modifierSafe: boolean;
      readonly readerSafe: boolean;
    }
  | {
      readonly kind: "stop";
      readonly reason: WrapperStopReason;
      readonly payload?: readonly CommandWord[];
      readonly modifierSafe?: boolean;
      readonly readerSafe?: boolean;
    }
  | {
      readonly kind: "no-command";
      readonly exempt: boolean;
      readonly modifierSafe?: boolean;
      readonly readerSafe?: boolean;
    }
  | {
      readonly kind: "query";
      readonly modifierSafe?: boolean;
      readonly readerSafe?: boolean;
    };

const SUDO = table({
  shortFlags: "ABbEHiKkl nPSsVv h".replace(/\s+/g, ""),
  shortValues: "CDgpRrTUu",
  longFlags: [
    "askpass", "background", "bell", "edit", "help", "login", "remove-timestamp",
    "reset-timestamp", "set-home", "shell", "stdin", "validate", "version", "list",
    "non-interactive",
  ],
  longValues: [
    "close-from", "chdir", "chroot", "command-timeout", "group", "host", "prompt",
    "role", "type", "other-user", "user",
  ],
  longOptional: ["preserve-env"],
});

const DOAS = table({
  shortFlags: "nsL",
  shortValues: "Cu",
  longFlags: ["help", "version"],
  longValues: ["config", "user"],
});

const ENV = table({
  shortFlags: "i0v",
  shortValues: "uCS",
  longFlags: ["ignore-environment", "null", "debug", "help", "version"],
  longValues: ["unset", "chdir", "split-string"],
});

const XARGS = table({
  shortFlags: "0p rtx o".replace(/\s+/g, ""),
  shortValues: "adEIJLnPs",
  shortOptional: "eil",
  longFlags: [
    "null", "interactive", "no-run-if-empty", "verbose", "exit", "open-tty",
    "show-limits", "help", "version",
  ],
  longValues: [
    "arg-file", "delimiter", "eof", "replace", "max-lines", "max-args",
    "max-procs", "max-chars", "process-slot-var",
  ],
});

const COMMAND = table({
  shortFlags: "pv V".replace(/\s+/g, ""),
  longFlags: ["help", "version"],
});

const TIME = table({
  shortFlags: "pvqa",
  shortValues: "of",
  longFlags: ["append", "portability", "quiet", "verbose", "help", "version"],
  longValues: ["output", "format"],
});

const TIMEOUT = table({
  shortFlags: "v",
  shortValues: "sk",
  longFlags: ["preserve-status", "foreground", "verbose", "help", "version"],
  longValues: ["signal", "kill-after"],
});

const NICE = table({
  shortValues: "n",
  longValues: ["adjustment"],
  longFlags: ["help", "version"],
});

const SETSID = table({
  shortFlags: "cfw",
  longFlags: ["ctty", "fork", "wait", "help", "version"],
});

const STDBUF = table({
  shortValues: "ioe",
  longValues: ["input", "output", "error"],
  longFlags: ["help", "version"],
});

const NOHUP = table({
  longFlags: ["help", "version"],
});

const WATCH = table({
  shortFlags: "dgctbexp",
  shortValues: "nq",
  longValues: ["interval", "equexit"],
  longFlags: [
    "differences", "chgexit", "color", "no-title", "beep", "errexit", "exec",
    "precise", "help", "version",
  ],
});

const FLOCK = table({
  shortFlags: "sxnoF",
  shortValues: "wEc",
  longValues: ["wait", "timeout", "conflict-exit-code", "command"],
  longFlags: ["shared", "exclusive", "nonblock", "close", "no-fork", "help", "version"],
});

const FD = table({
  shortFlags: "HIusigFLp0lq1".replace(/\s+/g, ""),
  shortValues: "dteEcj",
  longValues: ["max-depth", "min-depth", "type", "extension", "exclude", "color", "threads"],
  longFlags: [
    "hidden", "no-ignore", "unrestricted", "case-sensitive", "ignore-case", "glob",
    "fixed-strings", "follow", "full-path", "print0", "list-details", "quiet",
    "strip-cwd-prefix", "help", "version",
  ],
  longOptional: ["exec", "exec-batch"],
});

function literalWords(words: readonly CommandWord[]): boolean {
  return words.every((word) => !word.computed);
}

function stop(
  reason: WrapperStopReason,
  payload?: readonly CommandWord[],
): UnwrapOutcome {
  return {
    kind: "stop",
    reason,
    ...(payload === undefined ? {} : { payload }),
    modifierSafe: false,
    readerSafe: false,
  };
}

function inner(words: readonly CommandWord[], modifierSafe = false): UnwrapOutcome {
  return { kind: "inner", inner: words, modifierSafe, readerSafe: true };
}

function unwrapSudo(args: readonly CommandWord[], syntax: OptionTable): UnwrapOutcome {
  const parsed = parseOptions(args, syntax);
  if (isFailure(parsed)) return stop(parsed.stop);
  const rest = consumeAssignments(parsed.rest);
  const flags = parsed.used;
  const shellMode =
    flags.has("s") || flags.has("i") || flags.has("shell") || flags.has("login") ||
    flags.has("e") || flags.has("edit");
  const queryMode =
    flags.has("l") || flags.has("list") || flags.has("v") || flags.has("validate") ||
    flags.has("K") || flags.has("remove-timestamp");
  if (shellMode) return stop("opaque-payload", rest);
  if (rest.length === 0) {
    return queryMode ? { kind: "query", readerSafe: true } : { kind: "no-command", exempt: false };
  }
  return inner(rest);
}

function unwrapEnv(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, ENV, { bareDashFlag: "i" });
  if (isFailure(parsed)) return stop(parsed.stop);
  const rest = consumeAssignments(parsed.rest);
  if (parsed.used.has("S") || parsed.used.has("split-string")) {
    return stop("template-command", rest);
  }
  if (rest.length === 0) return { kind: "no-command", exempt: true, readerSafe: true };
  return inner(rest);
}

function unwrapXargs(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, XARGS);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest);
}

function unwrapCommand(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, COMMAND);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.used.has("v") || parsed.used.has("V")) {
    return { kind: "query", readerSafe: true };
  }
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest);
}

function unwrapTime(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, TIME);
  if (isFailure(parsed)) return stop(parsed.stop);
  const writes = parsed.used.has("o") || parsed.used.has("output") ||
    parsed.used.has("a") || parsed.used.has("append");
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return {
    kind: "inner",
    inner: parsed.rest,
    modifierSafe: !writes,
    readerSafe: !writes,
  };
}

function unwrapTimeout(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, TIMEOUT);
  if (isFailure(parsed)) return stop(parsed.stop);
  // The first operand is the duration, never the command.
  const rest = parsed.rest.slice(1);
  if (parsed.rest.length === 0 || rest.length === 0) {
    return { kind: "no-command", exempt: false };
  }
  return inner(rest, true);
}

function unwrapNice(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, NICE);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest, true);
}

function unwrapSetsid(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, SETSID);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest, true);
}

function unwrapStdbuf(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, STDBUF);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest, true);
}

function unwrapNohup(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, NOHUP);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  return inner(parsed.rest);
}

function unwrapWatch(args: readonly CommandWord[]): UnwrapOutcome {
  const parsed = parseOptions(args, WATCH);
  if (isFailure(parsed)) return stop(parsed.stop);
  if (parsed.rest.length === 0) return { kind: "no-command", exempt: false };
  const direct = parsed.used.has("x") || parsed.used.has("exec");
  return direct ? inner(parsed.rest) : stop("template-command", parsed.rest);
}

function unwrapFlock(args: readonly CommandWord[]): UnwrapOutcome {
  for (const [index, word] of args.entries()) {
    if (word.value === "-c" || word.value === "--command") {
      const payload = args[index + 1];
      return stop("opaque-payload", payload === undefined ? [] : [payload]);
    }
    if (word.value.startsWith("--command=")) {
      const attached = word.value.slice("--command=".length);
      return stop("opaque-payload", [{ ...word, value: attached, text: attached }]);
    }
  }
  const parsed = parseOptions(args, FLOCK);
  if (isFailure(parsed)) return stop(parsed.stop);
  // The first operand is the lock file; the command follows it.
  const rest = parsed.rest.slice(1);
  if (parsed.rest.length === 0 || rest.length === 0) {
    return { kind: "no-command", exempt: false };
  }
  return inner(rest);
}

function unwrapTemplate(args: readonly CommandWord[]): UnwrapOutcome {
  return stop("template-command", args);
}

function isExecTerminator(word: CommandWord): boolean {
  if (word.value === "+" || word.value === ";") return true;
  const text = (word.text ?? word.value).replace(/^['"]|['"]$/g, "");
  return text === "\\;";
}

interface FindResult {
  readonly actions: readonly ExecAction[];
  readonly stop?: WrapperStopReason;
  readonly readerSafe: boolean;
}

function parseFind(args: readonly CommandWord[]): FindResult {
  let index = 0;
  while (index < args.length) {
    const word = args[index]!;
    const value = word.value;
    if (value === "-H" || value === "-L" || value === "-P") {
      index += 1;
      continue;
    }
    if (value === "-D") {
      index += 2;
      continue;
    }
    if (value.startsWith("-O")) {
      index += 1;
      continue;
    }
    if (value.startsWith("-") || value === "!" || value === "(" || value === ")") {
      break;
    }
    index += 1;
  }

  const actions: ExecAction[] = [];
  let readerSafe = true;
  while (index < args.length) {
    const word = args[index]!;
    const value = word.value;
    if (value === "(" || value === ")" || value === "!" || value === "-a" ||
        value === "-and" || value === "-o" || value === "-or" || value === "-not") {
      index += 1;
      continue;
    }
    if (FIND_EXEC_OPTIONS.has(value)) {
      const clause: CommandWord[] = [];
      index += 1;
      let terminated = false;
      while (index < args.length) {
        const candidate = args[index]!;
        if (isExecTerminator(candidate)) {
          index += 1;
          terminated = true;
          break;
        }
        if (candidate.computed) {
          return { actions, stop: "computed-primary-argument", readerSafe: false };
        }
        clause.push(candidate);
        index += 1;
      }
      if (clause.length === 0) {
        return { actions, stop: "invalid-exec", readerSafe: false };
      }
      if (!terminated && clause.length === 0) {
        return { actions, stop: "invalid-exec", readerSafe: false };
      }
      actions.push({ text: joinValues(clause), words: clause });
      continue;
    }
    if (value === "-delete" || value === "-fprint" || value === "-fprint0" ||
        value === "-fprintf" || value === "-fls") {
      readerSafe = false;
    }
    if (FIND_ZERO_ARITY.has(value)) {
      index += 1;
      continue;
    }
    if (value === "-fprintf") {
      const file = args[index + 1];
      const format = args[index + 2];
      if (file === undefined || format === undefined) {
        return { actions, stop: "unexpected-operand", readerSafe: false };
      }
      if (file.computed || format.computed) {
        return { actions, stop: "computed-primary-argument", readerSafe: false };
      }
      index += 3;
      continue;
    }
    if (FIND_ONE_ARITY.has(value) || /^-newer[a-zA-Z]{2}$/.test(value)) {
      const argument = args[index + 1];
      if (argument === undefined) return { actions, stop: "unexpected-operand", readerSafe: false };
      if (argument.computed) {
        return { actions, stop: "computed-primary-argument", readerSafe: false };
      }
      index += 2;
      continue;
    }
    if (value.startsWith("-")) return { actions, stop: "unknown-primary", readerSafe: false };
    return { actions, stop: "unexpected-operand", readerSafe: false };
  }
  return { actions, readerSafe };
}

function unwrapFind(args: readonly CommandWord[]): UnwrapOutcome & { readonly actions?: readonly ExecAction[] } {
  const parsed = parseFind(args);
  if (parsed.actions.length === 0 && parsed.stop === undefined) {
    return { kind: "no-command", exempt: false };
  }
  return {
    kind: "stop",
    reason: parsed.stop ?? "complete",
    modifierSafe: false,
    readerSafe: parsed.readerSafe,
    actions: parsed.actions,
  } as UnwrapOutcome & { actions: readonly ExecAction[] };
}

interface FdExecClause {
  readonly words: readonly CommandWord[];
}

function parseFd(args: readonly CommandWord[]): {
  readonly clauses: readonly FdExecClause[];
  readonly stop?: WrapperStopReason;
} {
  const clauses: FdExecClause[] = [];
  let index = 0;
  while (index < args.length) {
    const word = args[index]!;
    if (word.computed) return { clauses, stop: "computed-option" };
    const value = word.value;
    if (value === "--") {
      index += 1;
      continue;
    }
    if (value === "-x" || value === "-X" || value === "--exec" || value === "--exec-batch") {
      const clause: CommandWord[] = [];
      index += 1;
      while (index < args.length && !isExecTerminator(args[index]!)) {
        clause.push(args[index]!);
        index += 1;
      }
      if (index < args.length) index += 1;
      if (clause.length === 0) return { clauses, stop: "invalid-exec" };
      clauses.push({ words: clause });
      continue;
    }
    if (value.startsWith("--exec=") || value.startsWith("--exec-batch=")) {
      const attached = value.slice(value.indexOf("=") + 1);
      const clause: CommandWord[] = [
        { value: attached, computed: word.computed, mayLeadWithDash: attached.startsWith("-"), text: attached },
      ];
      index += 1;
      while (index < args.length && !isExecTerminator(args[index]!)) {
        clause.push(args[index]!);
        index += 1;
      }
      if (index < args.length) index += 1;
      clauses.push({ words: clause });
      continue;
    }
    if (value === "-x" || value === "-X") {
      index += 1;
      continue;
    }
    if (value.startsWith("--")) {
      const body = value.slice(2);
      const name = body.includes("=") ? body.slice(0, body.indexOf("=")) : body;
      const attached = body.includes("=");
      if (FD.longValues.has(name) || FD.longOptional.has(name)) {
        index += attached ? 1 : 2;
        continue;
      }
      if (FD.longFlags.has(name)) {
        if (attached) return { clauses, stop: "unknown-option" };
        index += 1;
        continue;
      }
      return { clauses, stop: "unknown-option" };
    }
    if (value.startsWith("-") && value.length > 1) {
      const cluster = value.slice(1);
      let consumedNext = false;
      for (let offset = 0; offset < cluster.length; offset += 1) {
        const flag = cluster[offset]!;
        if (FD.shortFlags.has(flag)) continue;
        if (FD.shortValues.has(flag)) {
          if (offset === cluster.length - 1) consumedNext = true;
          break;
        }
        return { clauses, stop: "unknown-option" };
      }
      index += consumedNext ? 2 : 1;
      continue;
    }
    index += 1;
  }
  return { clauses };
}

function unwrapFd(args: readonly CommandWord[]): UnwrapOutcome & { readonly actions?: readonly ExecAction[] } {
  const parsed = parseFd(args);
  const actions = parsed.clauses.map((clause) => ({
    text: joinValues(clause.words),
    words: clause.words,
  }));
  if (actions.length === 0 && parsed.stop === undefined) {
    return { kind: "no-command", exempt: false };
  }
  return {
    kind: "stop",
    reason: parsed.stop ?? "complete",
    modifierSafe: false,
    readerSafe: true,
    actions,
  } as UnwrapOutcome & { actions: readonly ExecAction[] };
}

interface ChainResult {
  readonly layers: readonly WrapperLayer[];
  readonly actions: readonly ExecAction[];
  readonly complete: boolean;
  readonly stopReason: WrapperStopReason;
  readonly payload?: readonly CommandWord[];
  readonly noCommandExempt?: boolean;
}

function analyzeChain(
  argv: readonly CommandWord[],
  depth: number,
  options: WrapperAnalysisOptions,
): ChainResult {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const layers: WrapperLayer[] = [];
  let current: readonly CommandWord[] = argv;

  while (current.length > 0) {
    const nameWord = current[0]!;
    if (nameWord.computed) {
      return { layers, actions: [], complete: false, stopReason: "computed-command" };
    }
    const name = basename(nameWord.value);
    const kind = wrapperKindOf(name, current);
    if (kind === undefined) {
      return {
        layers,
        actions: [{ text: joinValues(current), words: current }],
        complete: true,
        stopReason: "complete",
      };
    }
    if (depth >= maxDepth) {
      return { layers, actions: [], complete: false, stopReason: "depth-limit" };
    }

    const args = shortArgs(current);
    const outcome = unwrapFor(name, kind, args);
    const hasInner = outcome.kind === "inner";
    const layerWords = hasInner
      ? current.slice(0, current.length - outcome.inner.length)
      : current;
    layers.push({
      commandName: name,
      wrapperKind: kind,
      text: joinValues(layerWords),
      modifierSafe: outcome.modifierSafe === true,
      literal: literalWords(layerWords.slice(1)),
      readerSafe: outcome.readerSafe !== false,
    });

    if (outcome.kind === "stop") {
      const payload = outcome.payload;
      if (payload !== undefined) {
        return { layers, actions: [], complete: false, stopReason: outcome.reason, payload };
      }
      const actions = (outcome as { actions?: readonly ExecAction[] }).actions;
      if (actions === undefined) {
        return { layers, actions: [], complete: false, stopReason: outcome.reason };
      }
      const nested = actions.map((action) =>
        analyzeChain(action.words, 0, options)
      );
      const mergedLayers = [...layers, ...nested.flatMap((result) => result.layers)];
      const mergedActions = nested.flatMap((result) => result.actions);
      const stopped = outcome.reason === "complete"
        ? nested.find((result) => !result.complete)?.stopReason
        : outcome.reason;
      return {
        layers: mergedLayers,
        actions: mergedActions,
        complete: stopped === undefined,
        stopReason: stopped ?? "complete",
      };
    }
    if (outcome.kind === "query") {
      return { layers, actions: [], complete: true, stopReason: "query-mode", noCommandExempt: true };
    }
    if (outcome.kind === "no-command") {
      return {
        layers,
        actions: [],
        complete: outcome.exempt,
        stopReason: "no-command",
        noCommandExempt: outcome.exempt,
      };
    }
    current = outcome.inner;
    depth += 1;
  }

  return { layers, actions: [], complete: false, stopReason: "no-command" };
}

function unwrapFor(
  name: string,
  kind: WrapperKind,
  args: readonly CommandWord[],
): UnwrapOutcome & { readonly actions?: readonly ExecAction[] } {
  switch (name) {
    case "eval":
      return stop("opaque-payload", args);
    case "sudo":
      return unwrapSudo(args, SUDO);
    case "doas":
      return unwrapSudo(args, DOAS);
    case "env":
      return unwrapEnv(args);
    case "xargs":
      return unwrapXargs(args);
    case "command":
      return unwrapCommand(args);
    case "time":
      return unwrapTime(args);
    case "timeout":
      return unwrapTimeout(args);
    case "nice":
      return unwrapNice(args);
    case "setsid":
      return unwrapSetsid(args);
    case "stdbuf":
      return unwrapStdbuf(args);
    case "nohup":
      return unwrapNohup(args);
    case "watch":
      return unwrapWatch(args);
    case "flock":
      return unwrapFlock(args);
    case "find":
      return unwrapFind(args);
    case "fd":
      return unwrapFd(args);
    case "parallel":
    case "rust-parallel":
    case "rush":
      return unwrapTemplate(args);
    default:
      if (kind === "opaque-payload") {
        return SHELLS.has(name)
          ? stop("opaque-payload", shellPayload(args))
          : stop("opaque-payload", args);
      }
      return stop("unknown-option");
  }
}

/** The program word that follows the short option cluster containing `c`. */
function shellPayload(args: readonly CommandWord[]): readonly CommandWord[] {
  for (let index = 0; index < args.length; index += 1) {
    const word = args[index]!;
    if (word.computed) return args.slice(index);
    if (word.value === "--") return [];
    if (word.value.startsWith("--")) continue;
    if (!word.value.startsWith("-")) return args.slice(index);
    const cluster = word.value.slice(1);
    if (cluster.includes("c")) {
      const payload = args[index + 1];
      return payload === undefined ? [] : [payload];
    }
    if (cluster === "O" || cluster === "o") index += 1;
  }
  return [];
}

function defaultPureReader(words: readonly CommandWord[]): boolean {
  if (words.some((word) => word.computed && word.mayLeadWithDash)) return false;
  return coreCommandEffect(words) === "read";
}

export function analyzeWrapper(
  argv: readonly CommandWord[],
  options: WrapperAnalysisOptions = {},
): ExecutionAnalysis {
  const chain = analyzeChain(argv, 0, options);
  const isPureReader = options.isPureReader ?? defaultPureReader;
  const executedUnit = chain.actions.length === 1
    ? chain.actions[0]!.text
    : chain.payload !== undefined
      ? joinValues(chain.payload)
      : undefined;

  let floorExemption: FloorExemption | undefined;
  if (chain.complete) {
    if (chain.actions.length === 0 && chain.noCommandExempt === true) {
      floorExemption = "no-command";
    } else if (chain.actions.length === 1 && chain.layers.length > 0) {
      const action = chain.actions[0]!;
      const allModifiers = chain.layers.every((layer) =>
        layer.wrapperKind === "execution-modifier" && layer.modifierSafe
      );
      if (allModifiers && action.words.every((word) => !word.computed)) {
        floorExemption = "execution-modifier";
      } else {
        const blocksReader = chain.layers.some((layer) =>
          layer.wrapperKind === "opaque-payload" ||
          layer.wrapperKind === "template" ||
          layer.wrapperKind === "watcher" ||
          layer.readerSafe !== true ||
          layer.literal !== true
        );
        if (!blocksReader && options.redirectsWrite !== true && isPureReader(action.words)) {
          floorExemption = "core-reader";
        }
      }
    }
  }

  return {
    layers: chain.layers,
    actions: chain.actions,
    complete: chain.complete,
    stopReason: chain.stopReason,
    ...(executedUnit === undefined ? {} : { executedUnit }),
    ...(floorExemption === undefined ? {} : { floorExemption }),
  };
}
