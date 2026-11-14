import { isAbsolute, relative, resolve } from "node:path";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { bashPathFacts } from "#approve-core/utils/access-intent/bash/bash-path-resolver";
import {
  redirectFactsOf,
  type BashCommand,
} from "#approve-core/utils/access-intent/bash/command-enumeration";
import { PURE_READER_CORE } from "#approve-core/utils/access-intent/bash/command-effects";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import type { PermissionMode } from "../../../contracts";
import type { BashProgramFactsView, CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import type { BashProgramProvider, BashProgramRequest } from "#approve-core/nodes/analysis";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { ShellPolicy } from "#config/shell-policy-schema";
import type { ShellPolicyPathVariables, ShellPolicySubject } from "#approve-core/policy/shell-policy/evaluate";
import { evaluateShellPolicySubject } from "#approve-core/policy/shell-policy/evaluate";
import type { ShellEffect, ShellOperationFact } from "#approve-core/policy/shell-policy/facts";
import type { ShellExecutionPermissions } from "#config/execution-source-schema";
import type { ProgramInvocation } from "#approve-core/policy/shell-policy/facts";
import { analyzeBashProgramCalls } from "#approve-core/nodes/shell-policy";

/**
 * Access facts for the responsibility chain (chain/facts/shell.ts).
 *
 * These derivations are the evidence a mode baseline or a shell-policy link
 * reads: the directions one frozen call proves, plus the eview marker for a
 * known shape that still needs a human look. Nothing here decides anything —
 * the chain links own the opinions, and this module only states facts.
 */

/**
 * `review` marks a known operation whose shape still needs human confirmation
 * even though its paths are local (for example a recursive, forced PowerShell
 * delete). Read-only denies through the underlying write, full-access
 * bypasses, and default/auto-review ask without host escalation.
 */
export type AccessKind = "read" | "write" | "network" | "unknown" | "review";

export interface AccessFact {
  readonly kind: AccessKind;
  readonly path?: string;
  /** Set by a host/fact provider when the path is outside the workspace. */
  readonly external?: boolean;
  readonly externalDelete?: boolean;
}

export interface ModeNodeOptions {
  readonly mode: PermissionMode;
  readonly cwd?: string;
  readonly platform?: NodeJS.Platform;
  readonly commandEffects?: unknown;
  readonly shellPolicy?: ShellPolicy;
  readonly shellPathVariables?: ShellPolicyPathVariables;
  readonly enabledShellNodes?: readonly string[];
  readonly shellGrants?: ShellExecutionPermissions;
  /**
   * The step-local BashProgram provider the host hands the built-in nodes
   * When absent — or when it answers `undefined` for a call —
   * the node parses the call itself, exactly as before this injection existed.
   */
  readonly getBashProgram?: BashProgramProvider;
}

const NETWORK_COMMANDS = new Set([
  "ssh", "scp", "sftp", "rsync", "telnet", "rsh", "rcp",
  "nc", "netcat", "ncat", "socat", "ftp", "curl", "wget",
]);

const WRITE_COMMANDS = new Set([
  "rm", "rmdir", "mv", "cp", "mkdir", "touch", "truncate", "tee",
  "chmod", "chown", "ln", "install", "dd", "shred", "wipefs",
]);

function headWord(text: string): string {
  const match = /^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*([^\s|&;<>]+)/.exec(text);
  return (match?.[1] ?? "").replace(/^['"]|['"]$/g, "");
}

function isWithin(candidate: string, root: string, platform: NodeJS.Platform): boolean {
  const normalize = (value: string): string => {
    const absolute = resolve(value);
    return platform === "win32" ? absolute.toLowerCase() : absolute;
  };
  const rootPath = normalize(root);
  const candidatePath = normalize(candidate);
  const rel = relative(rootPath, candidatePath);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function isExternal(
  path: string,
  cwd: string,
  platform: NodeJS.Platform,
): boolean {
  const candidate = isAbsolute(path) ? path : resolve(cwd, path);
  return !isWithin(candidate, cwd, platform);
}

function shellWriteGrantCovers(
  path: string,
  cwd: string,
  platform: NodeJS.Platform,
  grants: ShellExecutionPermissions | undefined,
): boolean {
  if (grants === undefined) return false;
  const target = isAbsolute(path) ? path : resolve(cwd, path);
  return grants.filesystem.write.some((grant) => {
    const root = isAbsolute(grant.path) ? grant.path : resolve(cwd, grant.path);
    return grant.granularity === "file"
      ? isWithin(target, root, platform) && isWithin(root, target, platform)
      : isWithin(target, root, platform);
  });
}

async function shellFacts(
  call: BashProgramRequest,
  command: string,
  cwd: string,
  platform: NodeJS.Platform,
  getBashProgram?: BashProgramProvider,
  commandEffects?: unknown,
  shellGrants?: ShellExecutionPermissions,
): Promise<readonly AccessFact[]> {
  const facts: AccessFact[] = [];
  // The step's shared per-call parse when the host injected a
  // provider; this node's own mode decision still runs on its own reading of
  // the command units and external accesses below.
  const provided = await getBashProgram?.(call);
  const program = provided ??
    await BashProgram.parse(
      command,
      new PathNormalizer(pathFlavorForPlatform(platform), cwd),
      { pathFacts: bashPathFacts, commandEffects },
    );
  const commands = program.commands();
  if (commands.length === 0) return [{ kind: "unknown" }];

  for (const unit of commands) {
    const head = headWord(unit.text);
    if (NETWORK_COMMANDS.has(head)) {
      facts.push({ kind: "network" });
      continue;
    }
    if (WRITE_COMMANDS.has(head) || writesThroughRedirect(unit)) {
      facts.push({ kind: "write" });
      continue;
    }
    if (PURE_READER_CORE.has(head)) {
      facts.push({ kind: "read" });
      continue;
    }
    facts.push({ kind: "unknown" });
  }
  for (const external of program.externalAccesses()) {
    const externalWrite = external.effect.effect === "write" &&
      !shellWriteGrantCovers(external.path.value(), cwd, platform, shellGrants);
    facts.push({
      kind: external.effect.effect === "read"
        ? "read"
        : external.effect.effect === "write"
          ? "write"
          : "unknown",
      path: external.path.value(),
      external: externalWrite,
    });
  }
  if (!program.pathFactsAvailable || !program.parsed || program.parseUnresolved) facts.push({ kind: "unknown" });
  return dedupeFacts(facts);
}

function writesThroughRedirect(unit: BashCommand): boolean {
  return redirectFactsOf(unit).some((fact) => fact.writesFile);
}

function dedupeFacts(facts: readonly AccessFact[]): AccessFact[] {
  const seen = new Set<string>();
  return facts.filter((fact) => {
    const key = `${fact.kind}\0${fact.path ?? ""}\0${fact.external === true ? "1" : "0"}\0${fact.externalDelete === true ? "1" : "0"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function pathFact(
  call: CallState,
  kind: "read" | "write",
  cwd: string,
  platform: NodeJS.Platform,
): readonly AccessFact[] {
  const path = call.arguments.path;
  if (typeof path !== "string" || path.trim().length === 0) {
    return [{ kind: "unknown" }];
  }
  return [{
    kind,
    path,
    external: isExternal(path, cwd, platform),
  }];
}

function knownValue<T>(value: { readonly status: "known"; readonly value: T } | { readonly status: "unknown"; readonly reason: string }): T | undefined {
  return value.status === "known" ? value.value : undefined;
}

const POWERSHELL_DELETE_COMMANDS = new Set([
  "remove-item", "rm", "del", "erase", "rd", "rmdir",
]);

/** A recursive delete switch, including the `-Recurse:$true` form. */
const POWERSHELL_RECURSIVE_DELETE_SWITCH = /^-(?:recurse|r)(?::\s*\$true)?$/iu;

function isPowerShellDeleteCmdlet(program: string): boolean {
  const separator = Math.max(program.lastIndexOf("/"), program.lastIndexOf("\\"));
  const base = separator < 0 ? program : program.slice(separator + 1);
  return POWERSHELL_DELETE_COMMANDS.has(base.toLowerCase());
}

function hasRecursiveDeleteInvocation(
  operation: ShellOperationFact,
  invocation: ProgramInvocation | undefined,
): boolean {
  if (operation.owner !== "powershell" || invocation === undefined ||
      operation.effects.status !== "known" ||
      !operation.effects.value.includes("file.delete")) return false;
  const program = knownValue(invocation.program);
  if (program === undefined || !isPowerShellDeleteCmdlet(program)) return false;
  const argv = knownValue(invocation.argv);
  return argv?.some((token) => POWERSHELL_RECURSIVE_DELETE_SWITCH.test(token.trim())) === true;
}

interface ShellOperationSet {
  readonly shell: "bash" | "powershell";
  readonly cwd: string;
  readonly operations: readonly ShellOperationFact[];
  readonly invocations: readonly ProgramInvocation[];
}

interface ShellModeFacts {
  readonly byUnit: ReadonlyMap<string, readonly AccessFact[]>;
}

function shellAccessFacts(
  call: CallState,
  operationSet: ShellOperationSet,
  options: ModeNodeOptions,
): ShellModeFacts {
  const byUnit = new Map<string, AccessFact[]>();
  const configuredForbid = options.shellPolicy?.modes?.["read-only"]?.forbidEffects ?? [];
  const defaultReadOnlyForbid = new Set<ShellEffect>([
    "file.create", "file.write", "file.delete", "network",
  ]);
  for (const operation of operationSet.operations) {
    const invocation = operationSet.invocations.find((item) => item.operationId === operation.operationId);
    const node = operation.owner === "powershell" ? "builtin/powershell" : "builtin/external-command";
    const enabled = options.enabledShellNodes?.includes(node) === true;
    const subject: ShellPolicySubject = {
      node,
      toolName: call.toolName,
      shell: operationSet.shell,
      mode: options.mode,
      cwd: { status: "known", value: operationSet.cwd },
      ...(invocation === undefined ? {} : { invocation }),
      operation,
    };
    const policyMatch = enabled
      ? evaluateShellPolicySubject({
        policy: options.shellPolicy,
        subject,
        platform: options.platform,
        pathVariables: options.shellPathVariables,
      })
      : undefined;

    const exceptions = options.mode === "read-only"
      ? options.shellPolicy?.modes?.["read-only"]?.exceptions ?? []
      : [];
    const exemptEffects = new Set<ShellEffect>();
    if (enabled && operation.complete && operation.effects.status === "known") {
      for (const exception of exceptions) {
        const rule = options.shellPolicy?.rules.find((candidate) => candidate.id === exception.ruleId);
        if (rule === undefined || rule.node !== node) continue;
        const exceptionMatch = evaluateShellPolicySubject({
          policy: { version: 1, rules: [rule] },
          subject,
          platform: options.platform,
          pathVariables: options.shellPathVariables,
        });
        if (exceptionMatch.decision === "allow" && exceptionMatch.allowEligible &&
            operation.effects.value.every((effect) => exception.effects.includes(effect))) {
          for (const effect of exception.effects) exemptEffects.add(effect);
        }
      }
    }

    const facts = byUnit.get(operation.unitId) ?? [];
    const effects = operation.effects.status === "known"
      ? operation.effects.value.filter((effect) => !exemptEffects.has(effect))
      : undefined;
    if (effects === undefined) {
      facts.push({ kind: "unknown" });
    } else {
      if (effects.length === 0 && operation.complete &&
        operation.dynamicExecution?.status === "known" && !operation.dynamicExecution.value &&
        operation.processSpawn?.status === "known" && !operation.processSpawn.value) {
        facts.push({ kind: "read" });
      }
      for (const effect of effects) {
        if (effect === "file.create" || effect === "file.write" || effect === "file.delete") {
          const targets = knownValue(operation.fileTargets);
          if (targets === undefined) {
            facts.push({ kind: "write" }, { kind: "unknown" });
          } else {
            const paths = targets.filter((target) => target.effect === effect);
            if (paths.length === 0) facts.push({ kind: "write" }, { kind: "unknown" });
            else for (const target of paths) facts.push({
              kind: "write",
              path: target.path,
              external: isExternal(target.path, operationSet.cwd, options.platform ?? process.platform) &&
                (operationSet.shell === "powershell" && effect === "file.delete" ||
                  !shellWriteGrantCovers(target.path, operationSet.cwd, options.platform ?? process.platform, options.shellGrants)),
              externalDelete: operationSet.shell === "powershell" && effect === "file.delete" &&
                isExternal(target.path, operationSet.cwd, options.platform ?? process.platform),
            });
          }
        } else if (effect === "file.read") {
          const targets = knownValue(operation.fileTargets);
          if (targets === undefined) {
            facts.push({ kind: "read" });
          } else {
            const paths = targets.filter((target) => target.effect === effect);
            if (paths.length === 0) {
              facts.push({ kind: "read" });
            } else {
              for (const target of paths) facts.push({
                kind: "read",
                path: target.path,
                external: isExternal(target.path, operationSet.cwd, options.platform ?? process.platform),
              });
            }
          }
        } else if (effect === "network") {
          facts.push({ kind: "network" });
        } else if (effect === "process.spawn" && operation.complete &&
            operation.dynamicExecution?.status === "known" && !operation.dynamicExecution.value) {
          continue;
        } else {
          facts.push({ kind: "unknown" });
        }
      }
    }
    if (!operation.complete) facts.push({ kind: "unknown" });
    // A known PowerShell recursive delete keeps its access evidence but
    // still needs a human look even when the target stays in the workspace.
    if (hasRecursiveDeleteInvocation(operation, invocation)) facts.push({ kind: "review" });
    if (options.mode === "read-only" && effects?.some((effect) =>
      configuredForbid.includes(effect) && !defaultReadOnlyForbid.has(effect))) {
      facts.push({ kind: "write" });
    }
    if (policyMatch?.decision === "ask") facts.push({ kind: "unknown" });
    byUnit.set(operation.unitId, dedupeFacts(facts));
  }
  for (const unit of call.units) {
    if (!byUnit.has(unit.unitId)) byUnit.set(unit.unitId, [{ kind: "unknown" }]);
  }
  return { byUnit };
}

function powerShellAccessFacts(
  call: CallState,
  view: PowerShellProgramFactsView | undefined,
  options: ModeNodeOptions,
): ShellModeFacts | undefined {
  const command = call.arguments.command;
  if (view === undefined || view.callDigest !== call.digest ||
      typeof command !== "string" || view.commandText !== command) return undefined;
  return shellAccessFacts(call, {
    shell: "powershell",
    cwd: view.cwd,
    operations: view.analysis.operations,
    invocations: view.analysis.programInvocations,
  }, options);
}

/**
 * The per-unit access facts of one PowerShell view, for callers that already
 * hold the view (for example `chain/facts/shell.ts`). It is the same derivation
 * and the same view-matching rule the mode node uses; only the private wrapper
 * type is unwrapped.
 */
export function powerShellAccessFactsForView(
  call: CallState,
  view: PowerShellProgramFactsView | undefined,
  options: ModeNodeOptions,
): ReadonlyMap<string, readonly AccessFact[]> | undefined {
  return powerShellAccessFacts(call, view, options)?.byUnit;
}

async function bashAccessFacts(
  call: CallState,
  context: StepContext,
  options: ModeNodeOptions,
): Promise<ShellModeFacts | undefined> {
  return bashFactsForView(call, context.bashPrograms?.[call.toolCallId], options);
}

/**
 * The view-based half of {@link bashAccessFacts}: the caller already holds the
 * per-call Bash view, so no step context is needed. The health rule is the same
 * one the node has always used — complete operations are the answer, an
 * incomplete parse merges the legacy whole-call facts so no proven access is
 * lost.
 *
 * Added for `chain/facts/shell.ts`, which projects facts for the responsibility
 * chain: this function exports the existing derivation, it does not change it.
 */
export async function bashAccessFactsForView(
  call: CallState,
  view: BashProgramFactsView | undefined,
  options: ModeNodeOptions,
): Promise<ReadonlyMap<string, readonly AccessFact[]> | undefined> {
  const facts = await bashFactsForView(call, view, options);
  return facts?.byUnit;
}

async function bashFactsForView(
  call: CallState,
  view: BashProgramFactsView | undefined,
  options: ModeNodeOptions,
): Promise<ShellModeFacts | undefined> {
  const command = call.arguments.command;
  if (view === undefined || typeof command !== "string" || view.commandText !== command) return undefined;
  const analysis = analyzeBashProgramCalls({ call, view, platform: options.platform });
  const facts = shellAccessFacts(call, {
    shell: "bash",
    cwd: analysis.cwd,
    operations: analysis.operations,
    invocations: analysis.invocations,
  }, options);
  if (analysis.operations.every((operation) => operation.complete)) return facts;
  const legacy = await deriveAccessFacts(call, options);
  return {
    byUnit: new Map([...facts.byUnit].map(([unitId, existing]) => [
      unitId,
      dedupeFacts([...existing, ...legacy]),
    ])),
  };
}

/**
 * Derive the access directions one frozen call proves without claiming a
 * sandbox. The result is evidence for this node's own mode decision, not a
 * chain-level coverage proof.
 */
export async function deriveAccessFacts(
  call: CallState,
  options: Pick<ModeNodeOptions, "cwd" | "platform" | "getBashProgram" | "commandEffects" | "shellGrants"> = {},
): Promise<readonly AccessFact[]> {
  const cwd = options.cwd ?? process.cwd();
  const platform = options.platform ?? process.platform;
  const kind = classifyToolKind(call.toolName);
  if (kind === "bash" || call.toolName === "shell") {
    const command = call.arguments.command;
    if (typeof command !== "string" || command.trim().length === 0) {
      return [{ kind: "unknown" }];
    }
    try {
      return await shellFacts(call, command, cwd, platform, options.getBashProgram, options.commandEffects, options.shellGrants);
    } catch {
      return [{ kind: "unknown" }];
    }
  }
  if (kind === "path") {
    if (call.toolName === "read" || call.toolName === "grep" ||
        call.toolName === "find" || call.toolName === "ls") {
      return pathFact(call, "read", cwd, platform);
    }
    if (call.toolName === "write") return pathFact(call, "write", cwd, platform);
    if (call.toolName === "edit") {
      return [
        ...pathFact(call, "read", cwd, platform),
        ...pathFact(call, "write", cwd, platform),
      ];
    }
  }
  return [{ kind: "unknown" }];
}

