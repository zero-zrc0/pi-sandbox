import { accessSync, constants, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { getShellExecutionEnvironment } from "./shell-environment";
import type {
  ExecutableIdentity,
  FileTargetFact,
  Knowledge,
  NetworkTargetFact,
  ShellEffect,
  ShellLanguage,
  ShellOperationFact,
} from "./facts";

export interface ProgramAdapterInput {
  readonly operationId: string;
  readonly unitId: string;
  readonly shell: ShellLanguage;
  readonly program: string | undefined;
  readonly argv: readonly string[] | undefined;
  readonly cwd: string | undefined;
  readonly extent: { readonly start: number; readonly end: number };
  readonly environmentStable?: boolean;
  readonly environment?: NodeJS.ProcessEnv;
  readonly platform?: NodeJS.Platform;
}

export interface AdaptedProgramFacts {
  readonly executable: Knowledge<ExecutableIdentity>;
  readonly operation: ShellOperationFact;
}

function unknown<T>(reason: string): Knowledge<T> {
  return Object.freeze({ status: "unknown", reason });
}

function known<T>(value: T): Knowledge<T> {
  return Object.freeze({ status: "known", value });
}

function pathApiFor(platform: NodeJS.Platform): typeof path.win32 {
  return (platform === "win32" ? path.win32 : path.posix) as typeof path.win32;
}

export function resolveProgramExecutable(
  program: string | undefined,
  cwd: string | undefined,
  options: {
    readonly platform?: NodeJS.Platform;
    readonly environmentStable?: boolean;
    readonly environment?: NodeJS.ProcessEnv;
  } = {},
): Knowledge<ExecutableIdentity> {
  if (program === undefined || program.length === 0) return unknown("program-name-unresolved");
  if (cwd === undefined || cwd.length === 0) return unknown("working-directory-unresolved");
  if (options.environmentStable === false) return unknown("command-environment-changed");
  const platform = options.platform ?? process.platform;
  const api = pathApiFor(platform);
  const environment = options.environment ?? getShellExecutionEnvironment();
  const environmentValue = (name: string): string | undefined => {
    const key = Object.keys(environment).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key === undefined ? undefined : environment[key];
  };
  const explicitPath = api.isAbsolute(program) || program.includes("/") || program.includes("\\");
  const pathEntries = (environmentValue("PATH") ?? "").split(platform === "win32" ? ";" : ":");
  const extensions = platform === "win32"
    ? (environmentValue("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
    : [""];
  const baseNames = platform === "win32" && api.extname(program).length === 0
    ? extensions.map((extension) => `${program}${extension}`)
    : [program];
  const directories = explicitPath ? [""] : pathEntries;
  for (const directory of directories) {
    for (const baseName of baseNames) {
      const candidate = api.isAbsolute(baseName)
        ? baseName
        : api.resolve(directory.length === 0 ? cwd : directory, baseName);
      try {
        const resolved = realpathSync.native(candidate);
        if (!statSync(resolved).isFile()) continue;
        if (platform !== "win32") accessSync(resolved, constants.X_OK);
        return known(Object.freeze({
          name: api.basename(program),
          path: known(resolved),
        }));
      } catch {
        continue;
      }
    }
  }
  return unknown("executable-identity-unresolved");
}

function pathTarget(pathValue: string): FileTargetFact {
  return { path: pathValue, effect: "file.read" };
}

interface ProgramEffectsObservation {
  readonly effects: Knowledge<readonly ShellEffect[]>;
  readonly fileTargets: Knowledge<readonly FileTargetFact[]>;
  readonly networkTargets: Knowledge<readonly NetworkTargetFact[]>;
  readonly dynamicExecution: Knowledge<boolean>;
  readonly complete: boolean;
}

function readOnlyProgramEffects(fileTargets: readonly FileTargetFact[]): ProgramEffectsObservation {
  return {
    effects: known<readonly ShellEffect[]>(["file.read", "process.spawn"]),
    fileTargets: known<readonly FileTargetFact[]>(fileTargets),
    networkTargets: known<readonly NetworkTargetFact[]>([]),
    dynamicExecution: known(false),
    complete: true,
  };
}

// `git status` may only add flags that change how the report is displayed.
const GIT_STATUS_FLAGS: ReadonlySet<string> = new Set([
  "-s",
  "-b",
  "-sb",
  "-bs",
  "--short",
  "--branch",
  "--porcelain",
  "--porcelain=v1",
  "--porcelain=v2",
  "--long",
  "--no-ahead-behind",
  "--ahead-behind",
  "--untracked-files=no",
  "--untracked-files=normal",
  "--untracked-files=all",
  "-uno",
  "-unormal",
  "-uall",
  "--ignored",
  "--no-renames",
  "--renames",
  "--show-stash",
  "--column",
  "--no-column",
]);

// `git log` may only add history display flags. Flags that run another program
// (`-p`, `--ext-diff`, `--textconv`), rewrite commits (`--format`, `--pretty`),
// or read arbitrary paths (pathspecs, positionals) are deliberately excluded.
const GIT_LOG_FLAGS: ReadonlySet<string> = new Set([
  "--oneline",
  "--no-decorate",
  "--decorate",
  "--graph",
  "--all",
  "--stat",
  "--name-only",
  "--name-status",
  "--no-renames",
  "--abbrev-commit",
  "--no-abbrev-commit",
  "--first-parent",
  "--merges",
  "--no-merges",
  "--reverse",
  "--topo-order",
  "--date-order",
  "--author-date-order",
  "--no-color",
  "--color=never",
  "--color=always",
]);

const GIT_LOG_VALUE_FLAGS: readonly string[] = [
  "--since=",
  "--until=",
  "--after=",
  "--before=",
  "--author=",
  "--committer=",
  "--grep=",
];

function isGitStatusReadOnly(argv: readonly string[]): boolean {
  return argv[0] === "status" && argv.slice(1).every((argument) => GIT_STATUS_FLAGS.has(argument));
}

function isGitLogReadOnly(argv: readonly string[]): boolean {
  if (argv[0] !== "log") return false;
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];
    if (GIT_LOG_FLAGS.has(argument)) continue;
    if (/^--max-count=\d+$/u.test(argument) || /^-n\d+$/u.test(argument)) continue;
    if (argument === "-n") {
      if (!/^\d+$/u.test(argv[index + 1] ?? "")) return false;
      index += 1;
      continue;
    }
    if (GIT_LOG_VALUE_FLAGS.some((prefix) => argument.length > prefix.length && argument.startsWith(prefix))) {
      continue;
    }
    return false;
  }
  return true;
}

function isGitReadOnly(argv: readonly string[]): boolean {
  if (isGitStatusReadOnly(argv) || isGitLogReadOnly(argv)) return true;
  if (argv.length !== 2) return false;
  if (argv[0] === "branch") return argv[1] === "--show-current";
  if (argv[0] === "rev-parse") {
    return argv[1] === "--show-toplevel" || argv[1] === "--git-dir" || argv[1] === "--is-inside-work-tree";
  }
  return false;
}

// `rg` options that never make the search read anything but its input paths.
const RG_FLAGS: ReadonlySet<string> = new Set([
  "-n",
  "--line-number",
  "-i",
  "--ignore-case",
  "-l",
  "--files-with-matches",
  "-L",
  "--files-without-match",
  "-c",
  "--count",
  "-F",
  "--fixed-strings",
  "-w",
  "--word-regexp",
  "-S",
  "--smart-case",
  "--files",
  "--hidden",
  "--no-ignore",
  "-u",
  "--unrestricted",
  "-v",
  "--invert-match",
  "-x",
  "--line-regexp",
  "-o",
  "--only-matching",
  "-q",
  "--quiet",
  "-H",
  "--with-filename",
  "--no-heading",
  "--heading",
  "--no-messages",
  "-s",
  "--case-sensitive",
]);

const RG_COLOR_VALUES: ReadonlySet<string> = new Set(["never", "always", "auto"]);

function rgValueIsSafe(value: string): boolean {
  return value.length > 0;
}

// Options that consume exactly one value token, either attached or separate.
const RG_LONG_VALUE_FLAGS: ReadonlyMap<string, (value: string) => boolean> = new Map([
  ["--regexp", rgValueIsSafe],
  ["--glob", rgValueIsSafe],
  ["--type", rgValueIsSafe],
  ["--type-not", rgValueIsSafe],
  ["--max-count", rgValueIsSafe],
  ["--color", (value: string) => RG_COLOR_VALUES.has(value)],
]);

const RG_SHORT_VALUE_FLAGS: ReadonlyMap<string, (value: string) => boolean> = new Map([
  ["-e", rgValueIsSafe],
  ["-g", rgValueIsSafe],
  ["-t", rgValueIsSafe],
  ["-T", rgValueIsSafe],
  ["-m", rgValueIsSafe],
  ["-A", rgValueIsSafe],
  ["-B", rgValueIsSafe],
  ["-C", rgValueIsSafe],
]);

// A separate value must not look like an option, so `rg -e --pre` stays
// unresolved instead of reading `--pre` as a pattern.
function separateRgValueIsSafe(value: string | undefined): value is string {
  return value !== undefined && value.length > 0 && !value.startsWith("-");
}

// Returns the positional arguments in order, or undefined when any option is
// outside the conservative read-only whitelist.
function rgPositionalArguments(argv: readonly string[]): readonly string[] | undefined {
  const positional: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--") {
      positional.push(...argv.slice(index + 1));
      return positional;
    }
    if (!argument.startsWith("-")) {
      positional.push(argument);
      continue;
    }
    if (argument === "-") return undefined;
    if (RG_FLAGS.has(argument)) continue;
    if (argument.startsWith("--")) {
      const equalsIndex = argument.indexOf("=");
      if (equalsIndex >= 0) {
        const validate = RG_LONG_VALUE_FLAGS.get(argument.slice(0, equalsIndex));
        if (validate === undefined || !validate(argument.slice(equalsIndex + 1))) return undefined;
        continue;
      }
      const validate = RG_LONG_VALUE_FLAGS.get(argument);
      const value = argv[index + 1];
      if (validate === undefined || !separateRgValueIsSafe(value) || !validate(value)) return undefined;
      index += 1;
      continue;
    }
    const validate = RG_SHORT_VALUE_FLAGS.get(argument.slice(0, 2));
    if (validate === undefined) return undefined;
    if (argument.length > 2) {
      if (!validate(argument.slice(2))) return undefined;
      continue;
    }
    const value = argv[index + 1];
    if (!separateRgValueIsSafe(value) || !validate(value)) return undefined;
    index += 1;
  }
  return positional;
}

function programEffects(
  input: ProgramAdapterInput,
  executable: Knowledge<ExecutableIdentity>,
): ProgramEffectsObservation {
  const program = input.program?.split(/[\\/]/u).at(-1)?.replace(/\.(?:exe|cmd|bat)$/iu, "").toLowerCase();
  const argv = input.argv;
  if (program === undefined || argv === undefined || input.cwd === undefined || input.environmentStable === false) {
    return {
      effects: unknown("program-semantics-unresolved"),
      fileTargets: unknown("file-targets-unresolved"),
      networkTargets: unknown("network-targets-unresolved"),
      dynamicExecution: unknown("dynamic-execution-unresolved"),
      complete: false,
    };
  }
  if (program === "git" && isGitReadOnly(argv)) {
    return readOnlyProgramEffects([pathTarget(input.cwd)]);
  }
  if (program === "rg") {
    const separator = argv.indexOf("--");
    const optionTokens = separator < 0 ? argv : argv.slice(0, separator);
    if (optionTokens.some((argument) => argument === "--pre" || argument.startsWith("--pre="))) {
      return {
        effects: known<readonly ShellEffect[]>(["process.spawn"]),
        fileTargets: unknown("preprocessor-inputs-unresolved"),
        networkTargets: unknown("preprocessor-network-unresolved"),
        dynamicExecution: known(true),
        complete: false,
      };
    }
    const positional = rgPositionalArguments(argv);
    if (positional !== undefined && positional.length > 0) {
      // With `-e/--regexp` every positional is a path; otherwise the first
      // positional is the pattern and the rest are paths.
      const patternFromOption = optionTokens.some((argument) =>
        argument === "-e" || argument === "--regexp" ||
        (argument.startsWith("-e") && argument.length > 2) ||
        argument.startsWith("--regexp="));
      const pathValues = patternFromOption
        ? positional
        : positional.slice(1);
      const paths = pathValues.length === 0 ? [input.cwd] : pathValues.map((value) =>
        pathApiFor(input.platform ?? process.platform).resolve(input.cwd!, value));
      return readOnlyProgramEffects(paths.map(pathTarget));
    }
  }
  if (program === "npm") {
    if (argv.length === 1 && (argv[0] === "--version" || argv[0] === "-v")) {
      const executablePath = executable.status === "known" ? executable.value.path : undefined;
      return {
        effects: known<readonly ShellEffect[]>(["file.read", "process.spawn"]),
        fileTargets: executablePath?.status === "known"
          ? known<readonly FileTargetFact[]>([pathTarget(executablePath.value)])
          : unknown("npm-executable-target-unresolved"),
        networkTargets: known<readonly NetworkTargetFact[]>([]),
        dynamicExecution: known(false),
        complete: executablePath?.status === "known",
      };
    }
    if (argv[0] === "install" || argv[0] === "i" || argv[0] === "ci" || argv[0] === "update") {
      return {
        effects: known<readonly ShellEffect[]>(["file.create", "file.write", "network", "process.spawn"]),
        fileTargets: unknown("npm-lifecycle-targets-unresolved"),
        networkTargets: unknown("npm-network-targets-unresolved"),
        dynamicExecution: known(true),
        complete: false,
      };
    }
    if (argv[0] === "run" || argv[0] === "exec" || argv[0] === "x") {
      return {
        effects: known<readonly ShellEffect[]>(["process.spawn"]),
        fileTargets: unknown("npm-script-targets-unresolved"),
        networkTargets: unknown("npm-script-network-unresolved"),
        dynamicExecution: known(true),
        complete: false,
      };
    }
  }
  return {
    effects: unknown("program-semantics-unresolved"),
    fileTargets: unknown("file-targets-unresolved"),
    networkTargets: unknown("network-targets-unresolved"),
    dynamicExecution: unknown("dynamic-execution-unresolved"),
    complete: false,
  };
}

export function analyzeExternalProgram(input: ProgramAdapterInput): AdaptedProgramFacts {
  const executable = resolveProgramExecutable(input.program, input.cwd, {
    platform: input.platform,
    environmentStable: input.environmentStable,
    environment: input.environment,
  });
  const observed = programEffects(input, executable);
  return Object.freeze({
    executable,
    operation: Object.freeze({
      operationId: input.operationId,
      unitId: input.unitId,
      owner: "external-command",
      effects: observed.effects,
      fileTargets: observed.fileTargets,
      networkTargets: observed.networkTargets,
      dynamicExecution: observed.dynamicExecution,
      processSpawn: known(true),
      complete: observed.complete,
      source: "program-adapter",
    }),
  });
}
