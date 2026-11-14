import { domainToASCII } from "node:url";
import type { PermissionMode } from "../../../contracts";
import type { ShellCondition, ShellPolicy, ShellPolicyRule } from "#config/shell-policy-schema";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import type {
  FileTargetFact,
  Knowledge,
  NetworkTargetFact,
  ProgramInvocation,
  ShellLanguage,
  ShellOperationFact,
} from "./facts";
import { allTruth, anyTruth, notTruth, type TruthValue } from "./truth";

export interface ShellPolicyPathVariables {
  readonly workspace?: string;
  readonly tempDir?: string;
}

export interface ShellPolicySubject {
  readonly node: "builtin/powershell" | "builtin/external-command";
  readonly toolName: string;
  readonly shell: ShellLanguage;
  readonly mode: PermissionMode;
  readonly cwd: Knowledge<string>;
  readonly invocation?: ProgramInvocation;
  readonly operation: ShellOperationFact;
}

export interface ShellPolicyMatch {
  readonly decision?: "allow" | "ask" | "deny";
  readonly ruleIds: readonly string[];
  readonly uncertain: boolean;
  readonly allowEligible: boolean;
}

function isKnown<T>(value: Knowledge<T> | undefined): value is { readonly status: "known"; readonly value: T } {
  return value?.status === "known";
}

function normalizerFor(
  cwd: string,
  platform: NodeJS.Platform,
): PathNormalizer {
  return new PathNormalizer(pathFlavorForPlatform(platform), cwd);
}

function expandConfiguredPath(
  input: string,
  variables: ShellPolicyPathVariables,
  platform: NodeJS.Platform | "posix",
): string | undefined {
  const match = /^\$\{(workspace|tempDir)\}(?:[\\/](.*))?$/u.exec(input);
  if (!match) return input.includes("${") ? undefined : input;
  const base = match[1] === "workspace" ? variables.workspace : variables.tempDir;
  if (base === undefined) return undefined;
  const suffix = match[2];
  return suffix === undefined || suffix.length === 0
    ? base
    : pathFlavorForPlatform(platform).join(base, suffix);
}

function pathMatches(
  actual: string,
  expected: string,
  cwd: string,
  normalizer: PathNormalizer,
): boolean {
  const left = normalizer.normalPath(actual, cwd);
  const right = normalizer.normalPath(expected, cwd);
  if (left.display.length === 0 || right.display.length === 0) return false;
  return normalizer.flavor.fold(left.display) === normalizer.flavor.fold(right.display);
}

function withinAny(
  target: string,
  roots: readonly string[],
  cwd: string,
  variables: ShellPolicyPathVariables,
  normalizer: PathNormalizer,
): TruthValue {
  const normalizedTarget = normalizer.normalPath(target, cwd);
  if (normalizedTarget.display.length === 0) return "unknown";
  const normalizedRoots: string[] = [];
  for (const root of roots) {
    const expanded = expandConfiguredPath(root, variables, normalizer.flavor.kind);
    if (expanded === undefined) return "unknown";
    const normalized = normalizer.normalPath(expanded, cwd);
    if (normalized.display.length === 0) return "unknown";
    normalizedRoots.push(normalized.display);
  }
  return normalizedRoots.some((root) => normalizer.flavor.contains(root, normalizedTarget.display))
    ? "true"
    : "false";
}

function programName(value: string, normalizer: PathNormalizer): string {
  let name = normalizer.flavor.basename(value);
  if (normalizer.flavor.kind === "win32") {
    name = name.toLowerCase().replace(/\.(?:exe|cmd|bat)$/u, "");
  }
  return name;
}

function matchString(value: string, expected: string, caseInsensitive: boolean): boolean {
  return caseInsensitive
    ? value.toLowerCase() === expected.toLowerCase()
    : value === expected;
}

function optionSet(argv: readonly string[]): ReadonlySet<string> {
  const found = new Set<string>();
  for (const token of argv) {
    if (token === "--") break;
    if (!token.startsWith("-") || token === "-") continue;
    const equals = token.indexOf("=");
    found.add(equals > 0 ? token.slice(0, equals) : token);
  }
  return found;
}

function matchArguments(
  condition: NonNullable<ShellCondition["args"]>,
  invocation: ProgramInvocation | undefined,
): TruthValue {
  if (invocation === undefined || !isKnown(invocation.argv)) return "unknown";
  const argv = invocation.argv.value;
  const results: TruthValue[] = [];
  if (condition.exact !== undefined) {
    results.push(argv.length === condition.exact.length && argv.every((arg, index) => arg === condition.exact![index])
      ? "true" : "false");
  }
  if (condition.prefix !== undefined) {
    results.push(argv.length >= condition.prefix.length &&
      condition.prefix.every((arg, index) => argv[index] === arg) ? "true" : "false");
  }
  if (condition.contains !== undefined) {
    results.push(condition.contains.every((arg) => argv.includes(arg)) ? "true" : "false");
  }
  if (condition.excludes !== undefined) {
    results.push(condition.excludes.every((arg) => !argv.includes(arg)) ? "true" : "false");
  }
  return allTruth(results);
}

function matchOptions(
  condition: NonNullable<ShellCondition["options"]>,
  invocation: ProgramInvocation | undefined,
): TruthValue {
  if (invocation === undefined || !isKnown(invocation.argv)) return "unknown";
  const options = optionSet(invocation.argv.value);
  const results: TruthValue[] = [];
  if (condition.present !== undefined) {
    results.push(condition.present.every((option) => options.has(option)) ? "true" : "false");
  }
  if (condition.absent !== undefined) {
    results.push(condition.absent.every((option) => !options.has(option)) ? "true" : "false");
  }
  return allTruth(results);
}

function matchTargets(
  constraints: NonNullable<ShellCondition["targets"]>,
  operation: ShellOperationFact,
  cwd: Knowledge<string>,
  platform: NodeJS.Platform,
  variables: ShellPolicyPathVariables,
): TruthValue {
  if (!isKnown(cwd) || !isKnown(operation.fileTargets)) return "unknown";
  const normalizer = normalizerFor(cwd.value, platform);
  const checks: TruthValue[] = [];
  const effectsByKey: Readonly<Record<keyof typeof constraints, readonly FileTargetFact["effect"][]>> = {
    fileReads: ["file.read"],
    fileWrites: ["file.create", "file.write"],
    fileDeletes: ["file.delete"],
  };
  for (const key of Object.keys(effectsByKey) as Array<keyof typeof constraints>) {
    const effects = effectsByKey[key];
    const constraint = constraints[key];
    if (constraint === undefined) continue;
    const targets = operation.fileTargets.value.filter((target) =>
      effects.includes(target.effect as (typeof effects)[number]));
    if (targets.length === 0) {
      checks.push("false");
      continue;
    }
    for (const [kind, roots] of Object.entries(constraint)) {
      if (roots === undefined) continue;
      const within = targets.map((target) => withinAny(target.path, roots, cwd.value, variables, normalizer));
      checks.push(kind === "allWithin" ? allTruth(within) : allTruth(within.map(notTruth)));
    }
  }
  return allTruth(checks);
}

function normalizeHost(value: string): string | undefined {
  if (value.includes(":") || /\s/u.test(value)) return undefined;
  const host = domainToASCII(value.replace(/\.+$/u, "")).toLowerCase();
  return host.length > 0 ? host : undefined;
}

function matchNetwork(
  destinations: readonly { readonly host: string; readonly port?: number }[],
  operation: ShellOperationFact,
): TruthValue {
  if (!isKnown(operation.networkTargets)) return "unknown";
  const targets = operation.networkTargets.value;
  if (targets.length === 0) return "false";
  const expected = destinations.map((destination) => ({
    host: normalizeHost(destination.host),
    port: destination.port,
  }));
  if (expected.some((destination) => destination.host === undefined)) return "unknown";
  return targets.every((target) => expected.some((destination) => {
    const host = normalizeHost(target.host);
    if (host === undefined || host !== destination.host) return false;
    return destination.port === undefined || target.port === destination.port;
  })) ? "true" : "false";
}

function matchCondition(
  condition: ShellCondition,
  subject: ShellPolicySubject,
  platform: NodeJS.Platform,
  variables: ShellPolicyPathVariables,
): TruthValue {
  const checks: TruthValue[] = [];
  const normalizer = isKnown(subject.cwd)
    ? normalizerFor(subject.cwd.value, platform)
    : undefined;
  if (condition.all !== undefined) checks.push(allTruth(condition.all.map((item) => matchCondition(item, subject, platform, variables))));
  if (condition.any !== undefined) checks.push(anyTruth(condition.any.map((item) => matchCondition(item, subject, platform, variables))));
  if (condition.not !== undefined) checks.push(notTruth(matchCondition(condition.not, subject, platform, variables)));
  if (condition.program !== undefined) {
    if (subject.invocation === undefined || !isKnown(subject.invocation.program) || normalizer === undefined) checks.push("unknown");
    else checks.push(matchString(
      programName(subject.invocation.program.value, normalizer),
      programName(condition.program, normalizer),
      normalizer.flavor.kind === "win32" || subject.operation.owner === "powershell",
    ) ? "true" : "false");
  }
  if (condition.executable !== undefined) {
    const path = subject.invocation?.executable;
    if (!isKnown(path) || !isKnown(path.value.path) || normalizer === undefined || !isKnown(subject.cwd)) {
      checks.push("unknown");
    } else {
      const expected = expandConfiguredPath(condition.executable.path, variables, platform);
      checks.push(expected === undefined ? "unknown" : pathMatches(
        path.value.path.value,
        expected,
        subject.cwd.value,
        normalizer,
      ) ? "true" : "false");
    }
  }
  if (condition.args !== undefined) checks.push(matchArguments(condition.args, subject.invocation));
  if (condition.options !== undefined) checks.push(matchOptions(condition.options, subject.invocation));
  if (condition.effects !== undefined) {
    const effects = subject.operation.effects;
    if (!isKnown(effects)) checks.push("unknown");
    else {
      const allowed = condition.effects.only;
      const hasAny = condition.effects.hasAny;
      if (allowed !== undefined) {
        checks.push(subject.operation.complete
          ? effects.value.every((effect) => allowed.includes(effect)) ? "true" : "false"
          : "unknown");
      }
      if (hasAny !== undefined) {
        checks.push(effects.value.some((effect) => hasAny.includes(effect))
          ? "true"
          : subject.operation.complete ? "false" : "unknown");
      }
    }
  }
  if (condition.targets !== undefined) {
    checks.push(matchTargets(condition.targets, subject.operation, subject.cwd, platform, variables));
  }
  if (condition.network !== undefined) {
    checks.push(matchNetwork(condition.network.destinations.allIn, subject.operation));
  }
  if (condition.dynamicExecution !== undefined) {
    checks.push(subject.operation.dynamicExecution === undefined
      ? "unknown"
      : isKnown(subject.operation.dynamicExecution)
        ? subject.operation.dynamicExecution.value === condition.dynamicExecution ? "true" : "false"
        : "unknown");
  }
  if (condition.processSpawn !== undefined) {
    const processSpawn = subject.operation.processSpawn;
    if (processSpawn !== undefined) {
      checks.push(!isKnown(processSpawn) ? "unknown" :
        processSpawn.value === condition.processSpawn ? "true" : "false");
    } else {
      const effects = subject.operation.effects;
      checks.push(!isKnown(effects) ? "unknown" :
        effects.value.includes("process.spawn") === condition.processSpawn ? "true" : "false");
    }
  }
  return allTruth(checks);
}

function matchScope(
  rule: ShellPolicyRule,
  subject: ShellPolicySubject,
  platform: NodeJS.Platform,
  variables: ShellPolicyPathVariables,
): TruthValue {
  const scope = rule.scope;
  if (scope === undefined) return "true";
  const checks: TruthValue[] = [];
  if (scope.tools !== undefined) checks.push(scope.tools.includes(subject.toolName) ? "true" : "false");
  if (scope.shells !== undefined) checks.push(scope.shells.includes(subject.shell) ? "true" : "false");
  if (scope.modes !== undefined) checks.push(scope.modes.includes(subject.mode) ? "true" : "false");
  if (scope.cwd !== undefined) {
    if (!isKnown(subject.cwd)) checks.push("unknown");
    else {
      const cwd = subject.cwd.value;
      const normalizer = normalizerFor(cwd, platform);
      const checksForRoots = scope.cwd.within.map((root) => {
        const expanded = expandConfiguredPath(root, variables, platform);
        return expanded === undefined
          ? "unknown"
          : withinAny(cwd, [expanded], cwd, variables, normalizer);
      });
      checks.push(anyTruth(checksForRoots));
    }
  }
  return allTruth(checks);
}

function allowEligible(subject: ShellPolicySubject): boolean {
  if (!subject.operation.complete || !isKnown(subject.operation.effects) ||
      !isKnown(subject.operation.fileTargets) || !isKnown(subject.operation.networkTargets)) return false;
  if (subject.operation.owner === "powershell") {
    const invocation = subject.invocation;
    return subject.operation.source === "powershell-parser" &&
      invocation?.shell === "powershell" && isKnown(invocation.program) &&
      isKnown(invocation.argv) && isKnown(invocation.cwd) &&
      isKnown(subject.operation.dynamicExecution) && !subject.operation.dynamicExecution.value &&
      isKnown(subject.operation.processSpawn) && !subject.operation.processSpawn.value;
  }
  const executable = subject.invocation?.executable;
  if (subject.invocation === undefined) {
    return subject.operation.source === "bash-parser" &&
      isKnown(subject.operation.dynamicExecution) && !subject.operation.dynamicExecution.value &&
      isKnown(subject.operation.processSpawn) && !subject.operation.processSpawn.value;
  }
  return isKnown(executable) && isKnown(executable.value.path);
}

const DECISION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

export function evaluateShellPolicySubject(input: {
  readonly policy: ShellPolicy | undefined;
  readonly subject: ShellPolicySubject;
  readonly platform?: NodeJS.Platform;
  readonly pathVariables?: ShellPolicyPathVariables;
}): ShellPolicyMatch {
  const platform = input.platform ?? process.platform;
  const variables = input.pathVariables ?? {};
  const matched: ShellPolicyRule[] = [];
  const uncertain: ShellPolicyRule[] = [];
  for (const rule of input.policy?.rules ?? []) {
    if (rule.node !== input.subject.node) continue;
    const scope = matchScope(rule, input.subject, platform, variables);
    if (scope === "false") continue;
    const truth = scope === "true"
      ? matchCondition(rule.when, input.subject, platform, variables)
      : "unknown";
    if (truth === "true") matched.push(rule);
    else if (truth === "unknown") uncertain.push(rule);
  }
  const winner = matched.reduce<ShellPolicyRule | undefined>((current, rule) =>
    current === undefined || DECISION_RANK[rule.then.decision] > DECISION_RANK[current.then.decision]
      ? rule
      : current, undefined);
  const ruleIds = Object.freeze(matched.map((rule) => rule.id));
  const eligible = allowEligible(input.subject);
  if (winner?.then.decision === "deny") {
    return Object.freeze({ decision: "deny", ruleIds, uncertain: uncertain.length > 0, allowEligible: eligible });
  }
  if (winner?.then.decision === "ask") {
    return Object.freeze({ decision: "ask", ruleIds, uncertain: uncertain.length > 0, allowEligible: eligible });
  }
  if (winner?.then.decision === "allow") {
    const blockedByUnknown = uncertain.some((rule) => rule.then.decision !== "allow");
    return Object.freeze({
      decision: eligible && !blockedByUnknown ? "allow" : "ask",
      ruleIds,
      uncertain: blockedByUnknown || !eligible,
      allowEligible: eligible,
    });
  }
  return Object.freeze({
    ...(uncertain.length === 0 ? {} : { decision: "ask" as const }),
    ruleIds,
    uncertain: uncertain.length > 0,
    allowEligible: eligible,
  });
}
