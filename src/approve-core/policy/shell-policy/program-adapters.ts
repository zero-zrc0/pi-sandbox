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

function programEffects(input: ProgramAdapterInput, executable: Knowledge<ExecutableIdentity>): {
  effects: Knowledge<readonly ShellEffect[]>;
  fileTargets: Knowledge<readonly FileTargetFact[]>;
  networkTargets: Knowledge<readonly NetworkTargetFact[]>;
  dynamicExecution: Knowledge<boolean>;
  complete: boolean;
} {
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
  if (program === "git" && argv.length === 1 && argv[0] === "status") {
    return {
      effects: known<readonly ShellEffect[]>(["file.read", "process.spawn"]),
      fileTargets: known<readonly FileTargetFact[]>([pathTarget(input.cwd)]),
      networkTargets: known<readonly NetworkTargetFact[]>([]),
      dynamicExecution: known(false),
      complete: true,
    };
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
    const positional = separator < 0 ? argv : [...optionTokens, ...argv.slice(separator + 1)];
    const optionsAreUnsupported = separator < 0
      ? optionTokens.some((argument) => argument.startsWith("-"))
      : optionTokens.some((argument) => argument.startsWith("-"));
    if (positional.length > 0 && !optionsAreUnsupported) {
      const paths = positional.slice(1).length === 0 ? [input.cwd] : positional.slice(1).map((value) =>
        pathApiFor(input.platform ?? process.platform).resolve(input.cwd!, value));
      return {
        effects: known<readonly ShellEffect[]>(["file.read", "process.spawn"]),
        fileTargets: known<readonly FileTargetFact[]>(paths.map(pathTarget)),
        networkTargets: known<readonly NetworkTargetFact[]>([]),
        dynamicExecution: known(false),
        complete: true,
      };
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
