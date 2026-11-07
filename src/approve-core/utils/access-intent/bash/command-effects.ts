/**
 * Built-in command effect knowledge.
 *
 * Phase 5 only needs the pure-reader roster for the wrapper core-reader
 * exemption; the full per-argument retraction rules belong to the path
 * analysis domain and extend this module there.
 */
import type { CommandWord } from "./wrapper-analysis";
import { hasGuardedOption } from "./option-guards";
import { isReadOnlyAwk } from "./awk-invocation";
import { isReadOnlySed } from "./sed-invocation";

export const PURE_READER_CORE: ReadonlySet<string> = Object.freeze(new Set([
  "cat",
  "head",
  "tail",
  "wc",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "diff",
  "ls",
  "stat",
  "pwd",
  "basename",
  "dirname",
  "realpath",
  "echo",
  "which",
  "cd",
  "true",
  "false",
  ":",
  "find",
  "fd",
  "sort",
  "sed",
  "awk",
]));

export function coreCommandEffect(words: readonly CommandWord[]): "read" | "unknown" | undefined {
  const command = words[0];
  if (!command || command.computed || command.value.includes("/") || command.value.includes("\\") || !PURE_READER_CORE.has(command.value)) {
    return undefined;
  }
  if (command.value === "sort" && hasGuardedOption(words.slice(1), ["--output", "-o"])) return "unknown";
  if (command.value === "find" && hasGuardedOption(words.slice(1), ["-exec", "-ok", "-delete", "-fprint", "-fprintf", "-fls"])) return "unknown";
  if (command.value === "fd" && hasGuardedOption(words.slice(1), ["--exec", "--exec-batch", "-x", "-X"])) return "unknown";
  if (command.value === "awk") return isReadOnlyAwk(words.slice(1)) ? "read" : "unknown";
  if (command.value === "sed") return isReadOnlySed(words.slice(1)) ? "read" : "unknown";
  return "read";
}
