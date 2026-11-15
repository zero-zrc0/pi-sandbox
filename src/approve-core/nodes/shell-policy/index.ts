import { MAX_REASON_LENGTH, type BashProgramFactsView, type CallState, type UnitDecision } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import type { PermissionMode } from "../../../contracts";
import type { ShellPolicy } from "#config/shell-policy-schema";
import { evaluateShellPolicySubject, type ShellPolicyPathVariables, type ShellPolicySubject } from "#approve-core/policy/shell-policy/evaluate";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { Knowledge, ProgramInvocation, ShellOperationFact } from "#approve-core/policy/shell-policy/facts";
import { jsonDigest } from "../../../json";
import { analyzeExternalProgram } from "#approve-core/policy/shell-policy/program-adapters";
import {
  redirectFactsOf,
  wordsOf,
  type BashCommand,
} from "#approve-core/utils/access-intent/bash/command-enumeration";
import { coreCommandEffect } from "#approve-core/utils/access-intent/bash/command-effects";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import type { FileTargetFact, NetworkTargetFact, ShellEffect } from "#approve-core/policy/shell-policy/facts";

export interface ShellPolicyNodeOptions {
  readonly policy: ShellPolicy | undefined;
  readonly mode?: PermissionMode;
  readonly pathVariables?: ShellPolicyPathVariables;
  readonly platform?: NodeJS.Platform;
}

function clip(value: string): string {
  return value.length <= MAX_REASON_LENGTH ? value : `${value.slice(0, MAX_REASON_LENGTH - 3)}...`;
}

function invocationByOperation(
  view: PowerShellProgramFactsView | undefined,
  operationId: string,
) {
  return view?.analysis.programInvocations.find((invocation) => invocation.operationId === operationId);
}

function getSubject(input: {
  readonly node: "builtin/powershell" | "builtin/external-command";
  readonly call: CallState;
  readonly context: StepContext;
  readonly operation: ShellOperationFact;
  readonly invocation?: ShellPolicySubject["invocation"];
  readonly cwd: string;
  readonly options: ShellPolicyNodeOptions;
}): ShellPolicySubject {
  return {
    node: input.node,
    toolName: input.call.toolName,
    shell: input.call.toolName === "powershell" ? "powershell" : "bash",
    mode: input.options.mode ?? "default",
    cwd: { status: "known", value: input.cwd },
    ...(input.invocation === undefined ? {} : { invocation: input.invocation }),
    operation: input.operation,
  };
}

interface BashProgramCallView {
  readonly unitIndex: number;
  readonly text: string;
  readonly programName: string | null;
  readonly arguments: readonly string[] | null;
  readonly dynamic: boolean;
  readonly wrapperComplete: boolean;
}

function isBashProgramCall(value: object): value is BashProgramCallView {
  const candidate = value as Partial<BashProgramCallView>;
  return Number.isSafeInteger(candidate.unitIndex) && typeof candidate.text === "string" &&
    (candidate.programName === null || typeof candidate.programName === "string") &&
    (candidate.arguments === null || Array.isArray(candidate.arguments)) &&
    typeof candidate.dynamic === "boolean" && typeof candidate.wrapperComplete === "boolean";
}

function unknown<T>(reason: string): Knowledge<T> {
  return { status: "unknown", reason };
}

/**
 * Commands for which a computed argument cannot turn a read into a write or
 * into another program: their option space has no output, delete or exec
 * switch. `rg` stays out because `--pre` starts a preprocessor; `find`, `fd`,
 * `sort`, `sed`, `awk` and `cd` stay out because a computed word could hide
 * `-exec`, `-delete`, `-o`, `-i` or a directory change.
 */
const READ_ONLY_WITH_COMPUTED_ARGUMENTS: ReadonlySet<string> = Object.freeze(new Set([
  "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "diff", "ls", "stat",
  "pwd", "basename", "dirname", "realpath", "echo", "which", "true", "false", ":",
]));

/**
 * Whether one top-level, wrapper-free, fully parsed command is proven
 * read-only by the built-in core roster. This is the narrow bridge that lets
 * the mode node treat `ls` / `cat` / `grep` as proven local reads when the
 * external-program adapter has no semantics for them; anything the guards
 * cannot prove (wrappers, nested contexts, unresolved words, computed options
 * of `find`/`sed`/`sort`/`awk`, `cd`) stays unknown and keeps asking.
 */
function isCoreReadOnlyCommand(unit: BashCommand | undefined): boolean {
  if (unit === undefined) return false;
  if (unit.context !== undefined || unit.wrapperKind !== undefined) return false;
  if (unit.parseUnresolved === true || unit.salvaged === true) return false;
  const words = wordsOf(unit);
  const head = words[0];
  if (head === undefined || head.computed || head.value === "cd") return false;
  if (READ_ONLY_WITH_COMPUTED_ARGUMENTS.has(head.value)) return true;
  if (words.some((word) => word.computed)) return false;
  return coreCommandEffect(words) === "read";
}

/**
 * The mode node's fact for a core command proven read-only. Targets stay empty
 * rather than being invented from arguments; the effects are enough for the
 * mode node to prove a local read, and shell-policy rules that require a
 * concrete target still do not match it.
 */
function coreReadOnlyOperation(input: {
  readonly operationId: string;
  readonly unitId: string;
}): ShellOperationFact {
  return Object.freeze({
    operationId: input.operationId,
    unitId: input.unitId,
    owner: "external-command",
    effects: { status: "known" as const, value: ["file.read", "process.spawn"] as readonly ShellEffect[] },
    fileTargets: { status: "known" as const, value: [] as readonly FileTargetFact[] },
    networkTargets: { status: "known" as const, value: [] as readonly NetworkTargetFact[] },
    dynamicExecution: { status: "known" as const, value: false },
    processSpawn: { status: "known" as const, value: true },
    complete: true,
    source: "bash-parser",
  });
}

export function analyzeBashProgramCalls(input: {
  readonly call: CallState;
  readonly view: BashProgramFactsView | undefined;
  readonly platform?: NodeJS.Platform;
}): {
  readonly operations: readonly ShellOperationFact[];
  readonly invocations: readonly ProgramInvocation[];
  readonly cwd: string;
} {
  if (input.view !== undefined && input.view.commandText !== input.call.arguments.command) {
    return { operations: [], invocations: [], cwd: "" };
  }
  const cwd = typeof input.view?.workingDirectory === "string" ? input.view.workingDirectory : "";
  const calls = input.view?.programCalls ?? [];
  const operations: ShellOperationFact[] = [];
  const invocations: ProgramInvocation[] = [];
  for (const raw of calls) {
    if (!isBashProgramCall(raw)) continue;
    const unit = input.call.units[raw.unitIndex];
    if (unit === undefined) continue;
    const extent = { start: 0, end: raw.text.length };
    const operationId = `${input.call.toolCallId}:op:${jsonDigest({ digest: input.call.digest, index: raw.unitIndex }).slice(0, 16)}`;
    const program = raw.programName === null || raw.dynamic
      ? unknown<string>("dynamic-command-name")
      : { status: "known" as const, value: raw.programName };
    const argv = raw.arguments === null || raw.dynamic
      ? unknown<readonly string[]>("dynamic-or-unsupported-arguments")
      : { status: "known" as const, value: raw.arguments };
    const environmentStable = raw.unitIndex === 0 || !calls.some((candidate) => {
      if (!isBashProgramCall(candidate) || candidate.unitIndex >= raw.unitIndex) return false;
      return /(?:^|[;&|\s])(?:export\s+)?PATH\s*=|(?:^|[;&|\s])(?:alias|unalias|cd|pushd|popd|source|eval|exec)(?:\s|$)|^\s*\./u.test(candidate.text);
    });
    const adapted = analyzeExternalProgram({
      operationId,
      unitId: unit.unitId,
      shell: "bash",
      program: program.status === "known" ? program.value : undefined,
      argv: argv.status === "known" ? argv.value : undefined,
      cwd: cwd.length === 0 ? undefined : cwd,
      extent,
      environmentStable,
      platform: input.platform,
    });
    invocations.push(Object.freeze({
      operationId,
      unitId: unit.unitId,
      shell: "bash",
      program,
      executable: adapted.executable,
      argv,
      cwd: cwd.length === 0 ? unknown<string>("working-directory-unresolved") : { status: "known" as const, value: cwd },
      extent,
    }));
    const command = input.view?.commands[raw.unitIndex] as BashCommand | undefined;
    const coreReadOnly = raw.wrapperComplete && environmentStable &&
      adapted.operation.complete === false && isCoreReadOnlyCommand(command);
    operations.push(coreReadOnly
      ? coreReadOnlyOperation({ operationId, unitId: unit.unitId })
      : adapted.operation);
    if (!raw.wrapperComplete) {
      operations.push(Object.freeze({
        operationId: `${operationId}:wrapper`,
        unitId: unit.unitId,
        owner: "external-command",
        effects: unknown<readonly ShellEffect[]>("wrapper-effects-unresolved"),
        fileTargets: unknown<readonly FileTargetFact[]>("wrapper-targets-unresolved"),
        networkTargets: unknown<readonly NetworkTargetFact[]>("wrapper-network-unresolved"),
        dynamicExecution: unknown<boolean>("wrapper-dynamic-execution"),
        processSpawn: unknown<boolean>("wrapper-process-spawn"),
        complete: false,
        source: "bash-parser",
      }));
    }
  }
  if (input.view !== undefined && cwd.length > 0) {
    const normalizer = new PathNormalizer(pathFlavorForPlatform(input.platform ?? process.platform), cwd);
    for (const [unitIndex, rawCommand] of input.view.commands.entries()) {
      const unit = input.call.units[unitIndex];
      if (unit === undefined) continue;
      for (const [redirectIndex, redirect] of redirectFactsOf(rawCommand as BashCommand).entries()) {
        if (!redirect.writesFile) continue;
        const operationId = `${input.call.toolCallId}:op:${jsonDigest({
          digest: input.call.digest,
          unitIndex,
          redirectIndex,
        }).slice(0, 16)}`;
        const target = !redirect.dynamicTarget && typeof redirect.targetValue === "string"
          ? normalizer.normalPath(redirect.targetValue, cwd).display
          : "";
        operations.push(Object.freeze({
          operationId,
          unitId: unit.unitId,
          owner: "external-command",
          effects: target.length > 0
            ? { status: "known" as const, value: ["file.create", "file.write"] as readonly ShellEffect[] }
            : unknown<readonly ShellEffect[]>("redirection-target-unresolved"),
          fileTargets: target.length > 0
            ? { status: "known" as const, value: [
              { path: target, effect: "file.create" },
              { path: target, effect: "file.write" },
            ] as readonly FileTargetFact[] }
            : unknown<readonly FileTargetFact[]>("redirection-target-unresolved"),
          networkTargets: { status: "known" as const, value: [] as readonly NetworkTargetFact[] },
          dynamicExecution: { status: "known" as const, value: false },
          processSpawn: { status: "known" as const, value: false },
          complete: target.length > 0,
          source: "bash-parser",
        }));
      }
    }
  }
  return { operations, invocations, cwd };
}

export type BashProgramAnalysis = ReturnType<typeof analyzeBashProgramCalls>;

function languageOperations(view: PowerShellProgramFactsView | undefined): readonly ShellOperationFact[] {
  return view?.analysis.operations ?? [];
}

/**\n * The per-unit shell-policy opinion of one node family (uiltin/powershell or\n * uiltin/external-command). Exported so the responsibility chain can read the\n * configured policy as facts instead of letting a node write final decisions:\n * deny/sk become a restriction, llow becomes a grant.\n */
export function shellPolicyUnitDecisions(input: {
  readonly node: "builtin/powershell" | "builtin/external-command";
  readonly call: CallState;
  readonly context: StepContext;
  readonly view: PowerShellProgramFactsView | undefined;
  readonly bashView: BashProgramFactsView | undefined;
  readonly bashAnalysis?: BashProgramAnalysis;
  readonly options: ShellPolicyNodeOptions;
}): readonly UnitDecision[] {
  if (input.call.units.some((unit) => unit.decision === "deny")) return [];
  const owner = input.node === "builtin/powershell" ? "powershell" : "external-command";
  const bash = input.node === "builtin/external-command" && input.view === undefined
    ? input.bashAnalysis ?? analyzeBashProgramCalls({ call: input.call, view: input.bashView, platform: input.options.platform })
    : undefined;
  const operations = (input.view === undefined ? bash?.operations ?? [] : languageOperations(input.view))
    .filter((operation) => operation.owner === owner);
  if (operations.length === 0) return [];
  const groups = new Map<string, Array<{ readonly operation: ShellOperationFact; readonly decision?: "allow" | "ask" | "deny"; readonly rules: readonly string[] }>>();
  for (const operation of operations) {
    const invocation = invocationByOperation(input.view, operation.operationId) ??
      bash?.invocations.find((entry) => entry.operationId === operation.operationId);
    const subject = getSubject({
      node: input.node,
      call: input.call,
      context: input.context,
      operation,
      ...(invocation === undefined ? {} : { invocation }),
      cwd: input.view?.cwd ?? bash?.cwd ?? process.cwd(),
      options: input.options,
    });
    const result = evaluateShellPolicySubject({
      policy: input.options.policy,
      subject,
      platform: input.options.platform,
      pathVariables: input.options.pathVariables,
    });
    const entries = groups.get(operation.unitId) ?? [];
    entries.push({ operation, decision: result.decision, rules: result.ruleIds });
    groups.set(operation.unitId, entries);
  }

  const decisions: UnitDecision[] = [];
  for (const unit of input.call.units) {
    const entries = groups.get(unit.unitId);
    if (entries === undefined || entries.length === 0) continue;
    const decision = entries.some((entry) => entry.decision === "deny")
      ? "deny"
      : entries.some((entry) => entry.decision === "ask") || entries.some((entry) => entry.decision === undefined)
        ? "ask"
        : "allow";
    const ruleIds = [...new Set(entries.flatMap((entry) => entry.rules))];
    const coverage = entries.some((entry) => entry.decision === undefined)
      ? "unmatched"
      : ruleIds.join(",") || "incomplete-coverage";
    decisions.push(Object.freeze({
      toolCallId: input.call.toolCallId,
      unitId: unit.unitId,
      decision,
      reason: clip(`shell-policy:${input.node}:${decision}:${coverage}`),
    }));
  }
  return decisions;
}
