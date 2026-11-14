import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import {
  executionAnalysisOf,
  executionLayersOf,
  redirectFactsOf,
} from "#approve-core/utils/access-intent/bash/command-enumeration";
import type { CommandWord } from "#approve-core/utils/access-intent/bash/wrapper-analysis";

/**
 * Project-local Shell risk detection (design §35.5).
 *
 * This is a *limited* check, deliberately not a port of any other agent
 * hosting layer's danger tables, functions, or recursion thresholds. It looks
 * for five families of operation that must not ride a permissive rule into a
 * sandbox default-run:
 *
 * - forced bulk delete,
 * - wide overwrite,
 * - a privilege/inline-payload wrapper,
 * - an incomplete wrapper execution chain,
 * - a known outbound or host-control command.
 *
 * A hit yields `review`, never a fabricated user denial: the local check says
 * "a human should look", not "the user forbade this" (design §35.5).
 */
export type ShellRiskKind =
  | "forced-bulk-delete"
  | "wide-overwrite"
  | "dangerous-wrapper"
  | "incomplete-execution"
  | "outbound-or-host-control";

export interface ShellRisk {
  readonly kind: ShellRiskKind;
  /** The command unit the risk was found in, as typed (never an expanded form). */
  readonly unit: string;
  /** A short, non-sensitive label for what matched. */
  readonly detail: string;
}

export interface ShellRiskOptions {
  /** Whether bounded wrapper truncation should block a builtin default run. */
  readonly includeIncompleteExecution?: boolean;
}

/** Commands whose mere invocation escalates privilege or controls the host. */
const HOST_CONTROL_COMMANDS = new Set([
  "sudo",
  "doas",
  "su",
  "pkexec",
  "mount",
  "umount",
  "modprobe",
  "insmod",
  "rmmod",
  "systemctl",
  "service",
  "shutdown",
  "reboot",
  "poweroff",
  "halt",
  "useradd",
  "userdel",
  "usermod",
  "passwd",
  "crontab",
]);

/** Commands that open an outbound connection or transfer data off-host. */
const OUTBOUND_COMMANDS = new Set([
  "ssh",
  "scp",
  "sftp",
  "rsync",
  "telnet",
  "rsh",
  "rcp",
  "nc",
  "netcat",
  "ncat",
  "socat",
  "ftp",
  "curl",
  "wget",
]);

/** Commands that rewrite a whole target in one shot. */
const WIDESPREAD_WRITE_COMMANDS = new Set(["shred", "wipefs"]);

/** Block-device path prefixes a redirect or `dd of=` may target. */
const BLOCK_DEVICE =
  /^\/dev\/(?:sd|hd|vd|nvme|mmcblk|disk|loop|ram|dm-)/i;

/** Git global options with a separate value, before the subcommand. */
const GIT_GLOBAL_OPTIONS_WITH_VALUE = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--super-prefix",
  "--config-env",
]);

/** Git global flags that do not consume the next word. */
const GIT_GLOBAL_FLAGS = new Set([
  "--bare",
  "--exec-path",
  "--help",
  "--html-path",
  "--info-path",
  "--literal-pathspecs",
  "--man-path",
  "--no-advice",
  "--no-lazy-fetch",
  "--no-optional-locks",
  "--no-pager",
  "--no-replace-objects",
  "--paginate",
  "--version",
  "-p",
  "-P",
]);

/**
 * Detect every risk across a program's command units.
 *
 * It scans each parsed unit's text and parser-owned sidecars. It matches
 * command names, flags, and operands without evaluating Shell text.
 * The parser splits program chains; this module never does, and it never
 * executes or expands Shell text.
 */
export function detectShellRisks(
  units: readonly BashCommand[],
  options: ShellRiskOptions = {},
): readonly ShellRisk[] {
  const risks: ShellRisk[] = [];
  for (const unit of units) {
    risks.push(...detectUnitRisks(unit, options));
  }
  return risks;
}

function detectUnitRisks(
  unit: BashCommand,
  options: ShellRiskOptions,
): ShellRisk[] {
  const risks: ShellRisk[] = [];
  const push = (kind: ShellRiskKind, detail: string): void => {
    risks.push({ kind, unit: unit.text, detail });
  };

  const execution = executionAnalysisOf(unit);
  const analyzedActions = execution?.actions;
  const fallbackTexts = unit.executedUnit === undefined
    ? [unit.text]
    : [unit.text, unit.executedUnit];
  const commandActions: readonly {
    readonly words: readonly string[];
    readonly sourceSpelling: boolean;
  }[] =
    analyzedActions === undefined || analyzedActions.length === 0
      ? fallbackTexts.map((text) => ({
          words: lexicalWords(text),
          sourceSpelling: true,
        }))
      : analyzedActions.map((action) => ({
          words: commandWordValues(action.words),
          sourceSpelling: false,
        }));
  for (const action of commandActions) {
    const words = action.sourceSpelling
      ? action.words.map(decodeSourceWord)
      : action.words;
    const name = commandName(words[0]);
    const flags = collectFlags(words);
    if (isForcedBulkDelete(name, flags, words)) {
      push("forced-bulk-delete", name);
    }
    if (isWideOverwrite(name, words)) push("wide-overwrite", name);
    if (HOST_CONTROL_COMMANDS.has(name)) {
      push("outbound-or-host-control", name);
    } else if (OUTBOUND_COMMANDS.has(name)) {
      push("outbound-or-host-control", name);
    }
  }

  for (const redirect of redirectFactsOf(unit)) {
    if (!redirect.writesFile) continue;
    if (redirect.targetValue === undefined) {
      push("wide-overwrite", "redirect-target-unresolved");
    } else if (isBlockDevicePath(redirect.targetValue)) {
      push("wide-overwrite", "redirect-to-block-device");
    }
  }
  if (
    options.includeIncompleteExecution !== false &&
    execution !== undefined &&
    !execution.complete
  ) {
    push("incomplete-execution", `wrapper-chain-${execution.stopReason}`);
  }
  const dangerousLayer = (execution?.layers ?? executionLayersOf(unit)).find((layer) =>
    isDangerousWrapper(layer.commandName, layer.wrapperKind)
  );
  if (dangerousLayer !== undefined) {
    push(
      "dangerous-wrapper",
      dangerousLayer.commandName,
    );
  } else {
    // Preserve the public risk helper's behavior for synthetic units that do
    // not have parser sidecars. Parsed units use the complete layer list above.
    const outerName = commandName(decodeSourceWord(lexicalWords(unit.text)[0] ?? ""));
    if (isDangerousWrapper(outerName, unit.wrapperKind)) {
      push("dangerous-wrapper", outerName);
    }
  }

  return risks;
}

/** Read the shell-resolved argv values retained by the parser. */
function commandWordValues(words: readonly CommandWord[]): readonly string[] {
  return words.map((word) => word.value);
}

/** `rm -r…f…` (or the long forms): a recursive forced delete. */
function isForcedBulkDelete(
  name: string,
  flags: FlagSet,
  words: readonly string[],
): boolean {
  if (name === "rm" || name === "rmdir") {
    const recursive = flags.hasShort("r") || flags.hasLong("recursive");
    const force = flags.hasShort("f") || flags.hasLong("force");
    return recursive && force;
  }
  if (name === "git") {
    const subcommand = gitSubcommand(words);
    if (subcommand?.name === "clean") {
      // `git clean` can delete many untracked files, and local git config may
      // waive its force flag. Review every live clean; a dry-run has no write.
      return !gitCleanIsDryRun(subcommand.arguments);
    }
  }
  return false;
}

/** Read only Git-clean options before its option terminator or path operands. */
function gitCleanIsDryRun(arguments_: readonly string[]): boolean {
  for (let index = 0; index < arguments_.length;) {
    const argument = arguments_[index] ?? "";
    if (argument === "--") return false;
    if (argument === "--dry-run") return true;
    if (argument.startsWith("--")) {
      if (
        argument === "--force" ||
        argument === "--interactive" ||
        argument === "--quiet" ||
        argument.startsWith("--exclude=")
      ) {
        index++;
        continue;
      }
      // An unknown long option cannot prove this clean is a dry-run.
      return false;
    }
    if (!argument.startsWith("-") || argument === "-") return false;

    const shortOptions = argument.slice(1);
    for (let optionIndex = 0; optionIndex < shortOptions.length; optionIndex++) {
      const option = shortOptions[optionIndex];
      if (option === "n") return true;
      if (option === "d" || option === "f" || option === "i" ||
          option === "q" || option === "x" || option === "X") {
        continue;
      }
      if (option === "e") {
        if (optionIndex === shortOptions.length - 1) index++;
        break;
      }
      // Unknown short options are treated as a live clean.
      return false;
    }
    index++;
  }
  return false;
}

/** `dd of=…`, `mkfs*`, `shred`, `truncate -s 0`, or a redirect to a device. */
function isWideOverwrite(
  name: string,
  words: readonly string[],
): boolean {
  if (name === "dd") {
    return words.some((word) => word.startsWith("of="));
  }
  if (name === "mkfs" || name.startsWith("mkfs.")) return true;
  if (WIDESPREAD_WRITE_COMMANDS.has(name)) return true;
  if (name === "truncate" && hasZeroTruncateSize(words)) return true;
  return targetsBlockDevice(words);
}

/** `truncate -s0`, `truncate -s 0`, or either `--size` spelling. */
function hasZeroTruncateSize(words: readonly string[]): boolean {
  for (let index = 0; index < words.length; index++) {
    const word = words[index] ?? "";
    if (word === "--size=0" || /^-s0$/.test(word)) return true;
    if (
      (word === "-s" || word === "--size") &&
      (words[index + 1] ?? "") === "0"
    ) {
      return true;
    }
  }
  return false;
}

/** Find Git's command after the global options and their values. */
function gitSubcommand(
  words: readonly string[],
): { name: string; arguments: readonly string[] } | undefined {
  let index = 1;
  while (index < words.length) {
    const word = words[index] ?? "";
    if (word === "--") {
      const command = words[index + 1];
      return command === undefined
        ? undefined
        : { name: commandName(command), arguments: words.slice(index + 2) };
    }
    if (!word.startsWith("-")) {
      return { name: commandName(word), arguments: words.slice(index + 1) };
    }
    if (GIT_GLOBAL_OPTIONS_WITH_VALUE.has(word)) {
      if (index + 1 >= words.length) return undefined;
      index += 2;
      continue;
    }
    if (
      word.startsWith("--git-dir=") ||
      word.startsWith("--work-tree=") ||
      word.startsWith("--namespace=") ||
      word.startsWith("--super-prefix=") ||
      word.startsWith("--config-env=") ||
      word.startsWith("--exec-path=") ||
      (word.startsWith("-C") && word.length > 2) ||
      (word.startsWith("-c") && word.length > 2)
    ) {
      index++;
      continue;
    }
    if (GIT_GLOBAL_FLAGS.has(word)) {
      index++;
      continue;
    }
    // Unknown options may consume the next word. Do not guess which word is
    // the command and claim that the risk scan saw the full invocation.
    return undefined;
  }
  return undefined;
}

/** A privilege-escalation command, or an inline-shell payload the parser flagged. */
function isDangerousWrapper(
  name: string,
  wrapperKind: BashCommand["wrapperKind"],
): boolean {
  if (name === "sudo" || name === "doas" || name === "su" || name === "pkexec") {
    return true;
  }
  // `bash -c`/`eval`/`sh -c`: the enumerator tags exactly this class of unit as
  // an opaque payload, so the risk check reuses its verdict rather than
  // re-deriving a shell-payload table of its own.
  return wrapperKind === "opaque-payload";
}

/** True when a parsed, statically known redirect target names a block device. */
function isBlockDevicePath(target: string): boolean {
  return BLOCK_DEVICE.test(target);
}

/** True when a redirect operand or `dd of=` names a block device. */
function targetsBlockDevice(words: readonly string[]): boolean {
  for (const [index, word] of words.entries()) {
    const bare = word;
    if (bare === ">" || bare === ">>") {
      const target = words[index + 1];
      if (target !== undefined && isBlockDevicePath(target)) return true;
      continue;
    }
    if (/^(?:\d+)?>>?/.test(bare)) {
      const target = bare.replace(/^(?:\d+)?>>?/, "");
      if (target.length > 0 && isBlockDevicePath(target)) return true;
      continue;
    }
    if (bare.startsWith("of=") && isBlockDevicePath(bare.slice(3))) return true;
  }
  return false;
}

/** The flags a unit's words carry, short-cluster and long forms kept apart. */
interface FlagSet {
  hasShort(flag: string): boolean;
  hasLong(flag: string): boolean;
}

function collectFlags(words: readonly string[]): FlagSet {
  const short = new Set<string>();
  const long = new Set<string>();
  for (const word of words.slice(1)) {
    if (word === "--") break;
    const bare = word;
    if (/^--[A-Za-z][\w-]*$/.test(bare)) {
      long.add(bare.slice(2));
      continue;
    }
    if (/^-[A-Za-z]+$/.test(bare)) {
      for (const flag of bare.slice(1)) short.add(flag);
    }
  }
  return {
    hasShort: (flag) => short.has(flag) || short.has(flag.toUpperCase()),
    hasLong: (flag) => long.has(flag),
  };
}

/** A trailing path segment, so `/usr/bin/rm` is gated as `rm`. */
function commandName(word: string | undefined): string {
  if (word === undefined) return "";
  const slash = word.lastIndexOf("/");
  return slash === -1 ? word : word.slice(slash + 1);
}

/** Decode one raw source word when no parser argv sidecar is available. */
function decodeSourceWord(word: string): string {
  if (word.length >= 2) {
    const first = word[0];
    const last = word[word.length - 1];
    if ((first === '"' || first === "'") && first === last) {
      return word.slice(1, -1);
    }
  }
  return word;
}

/**
 * Split one unit's raw source text into words, keeping quoted spans together.
 *
 * A limited lexical scan, not a shell grammar: enough to find a command name
 * and its flags while a quoted argument with spaces does not split. It leaves
 * quote characters in each token for the raw-source decoder to handle once.
 */
function lexicalWords(text: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaped = false;
  for (const ch of text) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && quote !== "'") {
      current += ch;
      escaped = true;
      continue;
    }
    if (quote === null && (ch === '"' || ch === "'")) {
      quote = ch;
      current += ch;
      continue;
    }
    if (quote !== null && ch === quote) {
      quote = null;
      current += ch;
      continue;
    }
    if (quote === null && /\s/.test(ch)) {
      if (current.length > 0) words.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.length > 0) words.push(current);
  return words;
}
