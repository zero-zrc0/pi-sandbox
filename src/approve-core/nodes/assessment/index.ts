import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { bashPathFacts } from "#approve-core/utils/access-intent/bash/bash-path-resolver";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";
import { normalizeToolTargets } from "#approve-core/utils/access-intent/input-normalizer";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform, type PathFlavor } from "#approve-core/utils/path/path-flavor";
import {
  createRuleEvaluator,
  type Rule,
  type RuleEvaluator,
} from "#approve-core/policy/rule";
import { checkBashCommand } from "#approve-core/utils/bash-command-check";
import type { PermissionScope, RegisteredToolFacts } from "../../../action";
import {
  assessLocalCall,
  assessShellCommand,
  type AssessmentCapabilities,
  type LocalAssessment,
  type LocalGateCheck,
  type McpAnnotations,
} from "#approve-core/nodes/assessment/local-assessment";
import type { CallState } from "#approve-core/contracts";
import type { StepContext } from "#approve-core/runtime";
import {
  normalizeToolAccessFacts,
  type ToolAccessFactsResult,
} from "#approve-core/utils/tool-access/access-facts";
import {
  assessToolAccessFacts,
  type ToolExecutorCapability,
} from "#approve-core/utils/tool-access/assessment";
import type { StructureAnalysisOptions } from "#approve-core/nodes/analysis";
import { isBuiltinDefaultAsk, PermissionCheckResult } from "../../contracts";
import { type JsonObject } from "../../../json";

/**
 * Tool-assessment node.
 *
 * The node maps a local assessment onto the original call's units:
 * run → allow, block → deny, review/defer → ask, no opinion → no decision.
 * It reuses the integrated 09 file facts and 10 shell/MCP assessment rather
 * than re-implementing their risk tables.
 *
 * Resource checking belongs to this node. The default resolver reads the
 * effective rules, obtains the complete shell command's program — the step's
 * shared per-call parse when the host injected one, else its own
 * parse — resolves its path candidates, evaluates every explicit rule surface,
 * and feeds those facts to the 10 assessment. The chain is never asked to prove
 * resource coverage.
 */

function isShell(toolName: string): boolean {
  return toolName === "shell" || classifyToolKind(toolName) === "bash";
}

function isPathTool(toolName: string): boolean {
  return classifyToolKind(toolName) === "path";
}

function isMcp(toolName: string): boolean {
  const kind = classifyToolKind(toolName);
  return kind === "mcp" || kind === "mcp-tool";
}

function syntheticAsk(
  toolName: string,
  source: PermissionCheckResult["source"],
  command: string,
  floor?: string,
): PermissionCheckResult {
  return {
    toolName,
    state: "ask",
    source,
    origin: "builtin",
    command,
    ...(floor === undefined ? {} : { matchedPattern: floor, floor }),
  };
}

function explicitCheck(
  surface: string,
  value: string,
  toolName: string,
  evaluator: RuleEvaluator,
): PermissionCheckResult | undefined {
  const rule = evaluator.evaluate(surface, value);
  if (rule.origin === "builtin" || rule.origin === "baseline") return undefined;
  return {
    toolName,
    state: rule.action,
    source: surface === "bash" ? "bash" : surface === "mcp" ? "mcp" : "default",
    origin: rule.origin,
    matchedPattern: rule.pattern,
    ...(surface === "bash" ? { command: value } : { target: value }),
  };
}

function checkKey(check: PermissionCheckResult): string {
  return JSON.stringify([
    check.state,
    check.source,
    check.origin,
    check.matchedPattern ?? "",
    check.target ?? "",
    check.command ?? "",
  ]);
}

function dedupe(checks: readonly PermissionCheckResult[]): PermissionCheckResult[] {
  const seen = new Set<string>();
  return checks.filter((check) => {
    const key = checkKey(check);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function pathChecks(
  program: BashProgram,
  toolName: string,
  evaluator: RuleEvaluator,
): readonly PermissionCheckResult[] {
  const checks: PermissionCheckResult[] = [];
  const addCandidate = (
    surface: string,
    values: readonly string[],
    toolNameForCheck: string,
  ): void => {
    const hit = evaluator.evaluateAnyValue(surface, [...values]);
    if (hit.rule.origin === "builtin" || hit.rule.origin === "baseline") return;
    checks.push({
      toolName: toolNameForCheck,
      state: hit.rule.action,
      source: "default",
      origin: hit.rule.origin,
      matchedPattern: hit.rule.pattern,
      target: hit.value,
    });
  };

  for (const candidate of program.pathRuleCandidates()) {
    const values = candidate.path.matchValues();
    if (candidate.effect.effect === "read") {
      addCandidate("path_read", values, toolName);
    } else if (candidate.effect.effect === "write") {
      addCandidate("path_write", values, toolName);
    } else {
      addCandidate("path_read", values, toolName);
      addCandidate("path_write", values, toolName);
    }
  }
  for (const external of program.externalAccesses()) {
    const values = external.path.matchValues();
    if (external.effect.effect === "read") {
      addCandidate("external_directory_read", values, toolName);
    } else if (external.effect.effect === "write") {
      addCandidate("external_directory_write", values, toolName);
    } else {
      addCandidate("external_directory_read", values, toolName);
      addCandidate("external_directory_write", values, toolName);
    }
  }
  return dedupe(checks);
}

async function shellAssessment(
  call: CallState,
  evaluator: RuleEvaluator,
  options: DefaultAssessmentOptions,
): Promise<LocalAssessment> {
  const raw = call.arguments.command;
  const command = typeof raw === "string" ? raw : "";
  let program: BashProgram;
  try {
    // The step's shared per-call parse when the host injected a
    // provider; a parse failure of that shared program reaches this node as
    // the same rejection its own parse would have produced.
    const provided = await options.getBashProgram?.(call);
    program = provided ??
      await BashProgram.parse(
        command,
        new PathNormalizer(
          pathFlavorForPlatform(options.platform ?? process.platform),
          options.cwd ?? process.cwd(),
        ),
        { pathFacts: bashPathFacts, commandEffects: options.commandEffects },
      );
  } catch {
    if (explicitCheck("bash", command, call.toolName, evaluator)?.state === "deny") {
      return { route: "block", cause: "explicit-rule", reason: "explicit-deny", modelRequests: 0 };
    }
    return {
      route: "defer",
      cause: "incomplete-facts",
      reason: "shell-parser-failed",
      modelRequests: 0,
    };
  }
  const commands = program.commands();
  const verdict = checkBashCommand({
    command,
    units: commands,
    resolve: (text, unit) => {
      const hit = evaluator.evaluateAnyValue("bash", [text, ...(unit?.equivalents ?? [])]);
      if (hit.rule.origin === "builtin" || hit.rule.origin === "baseline") {
        return syntheticAsk(call.toolName, "bash", text);
      }
      return {
        toolName: call.toolName, state: hit.rule.action, source: hit.rule.layer === "session" ? "session" : "bash",
        origin: hit.rule.origin, matchedPattern: hit.rule.pattern, command: text,
        ...(hit.rule.reason === undefined ? {} : { reason: hit.rule.reason }),
      };
    },
  });
  const commandChecks = verdict.units.map((unit) => unit.check);
  const commandCheck = verdict.check;
  const whole = verdict.wholeProgram;
  const asking = commandChecks.filter((check) => check.state === "ask");
  const defaultPolicyEligible = commands.length > 0 && commandCheck.state === "ask" &&
    asking.length > 0 && asking.every(isBuiltinDefaultAsk);

  const toolCheck = explicitCheck("tool", call.toolName, call.toolName, evaluator);
  const additional = dedupe([
    ...pathChecks(program, call.toolName, evaluator),
    ...(toolCheck ? [toolCheck] : []),
  ]);

  const sandbox = options.capabilities?.shellSandbox;
  const assessment = assessShellCommand({
    command,
    units: commands,
    commandCheck,
    ...(commands.length === 0 && whole && whole.state !== "allow"
      ? { wholeProgramCheck: whole }
      : {}),
    defaultPolicyEligible,
    language: "bash",
    toolName: call.toolName,
    registrationRevision:
      options.registrationRevision ?? sandbox?.executionBinding.revision ?? "unspecified",
    actionDigest: call.digest,
    additionalChecks: additional,
    ...(sandbox ? { sandbox } : {}),
  });
  const hasUncertainUnit = commands.some((entry) =>
    entry.parseUnresolved === true || entry.salvaged === true);
  return (hasUncertainUnit || !program.parsed || program.parseUnresolved || !program.pathFactsAvailable) && assessment.route !== "block"
    ? {
        route: "review",
        cause: "not-default-eligible",
        reason: "shell-parse-incomplete",
        modelRequests: 0,
      }
    : assessment;
}

function mcpAssessment(
  call: CallState,
  evaluator: RuleEvaluator,
  options: DefaultAssessmentOptions,
): LocalAssessment {
  // Local assessment is opt-in: without a host capability object the node
  // keeps the call on the review path instead of trusting annotations alone.
  if (options.capabilities === undefined) {
    return {
      route: "defer",
      cause: "capability-unavailable",
      reason: "mcp-assessment-capability-unavailable",
      modelRequests: 0,
    };
  }

  const annotations = options.mcpAnnotations?.(call);
  const conflicts = options.mcpConflicts?.(call);
  const checks: LocalGateCheck[] = [];
  const toolHit = explicitCheck("tool", call.toolName, call.toolName, evaluator);
  if (toolHit) checks.push({ surface: "tool", check: toolHit });
  const targets = options.mcpTargets?.(call) ?? normalizeToolTargets(call.toolName, call.arguments).targets;
  const match = evaluator.evaluateAnyValue("mcp", targets);
  const mcpHit: PermissionCheckResult | undefined = match.rule.origin === "builtin" || match.rule.origin === "baseline"
    ? undefined
    : { toolName: call.toolName, state: match.rule.action, source: "mcp", origin: match.rule.origin, matchedPattern: match.rule.pattern, target: match.value };
  checks.push({
    surface: "mcp",
    check: mcpHit ?? syntheticAsk(call.toolName, "mcp", call.toolName),
  });

  return assessLocalCall({
    toolName: call.toolName,
    checks,
    ...(annotations === undefined ? {} : { mcpAnnotations: annotations }),
    ...(conflicts === undefined ? {} : { mcpConflicts: conflicts }),
    capabilities: options.capabilities,
  }) ?? {
    route: "defer",
    cause: "incomplete-facts",
    reason: "mcp-assessment-not-applicable",
    modelRequests: 0,
  };
}

function fileFacts(call: CallState): ToolAccessFactsResult {
  const path = call.arguments.path;
  if (typeof path !== "string" || path.trim().length === 0) {
    return normalizeToolAccessFacts(
      { accesses: [], complete: false, unknownEffects: ["invalid-file-path"] },
    );
  }
  const accesses: Array<{
    path: string;
    access: "read" | "write";
    operation: "read" | "write";
  }> = [];
  if (call.toolName === "read" || call.toolName === "grep" ||
      call.toolName === "find" || call.toolName === "ls") {
    accesses.push({ path, access: "read", operation: "read" });
  } else if (call.toolName === "write") {
    accesses.push({ path, access: "write", operation: "write" });
  } else if (call.toolName === "edit") {
    accesses.push(
      { path, access: "read", operation: "read" },
      { path, access: "write", operation: "write" },
    );
  } else {
    return normalizeToolAccessFacts(
      { accesses: [], complete: false, unknownEffects: ["unknown-file-tool"] },
    );
  }
  return normalizeToolAccessFacts(
    { accesses, complete: true, unknownEffects: [] },
    syntheticToolFacts(call),
    "builtin",
  );
}

function syntheticToolFacts(call: CallState): RegisteredToolFacts {
  return {
    name: call.toolName,
    origin: `builtin:${call.toolName}`,
    revision: "chain-17c",
    description: "",
    parameters: { type: "object" } as JsonObject,
  };
}

function fileScopes(
  call: CallState,
  facts: ToolAccessFactsResult,
  evaluator: RuleEvaluator,
): readonly PermissionScope[] {
  const scopes: PermissionScope[] = [];
  for (const [index, access] of (facts.accesses ?? []).entries()) {
    const surface = access.access === "write" ? "path_write" : "path_read";
    const rule = evaluator.evaluate(surface, access.path);
    const explicit = rule.origin !== "builtin" && rule.origin !== "baseline";
    scopes.push({
      id: `file-${index}`,
      surface,
      target: access.path,
      access: access.access,
      state: explicit ? rule.action : "ask",
      source: explicit ? `${rule.origin}:${rule.pattern}` : "missing-scope",
    });
  }
  const toolRule = evaluator.evaluate("tool", call.toolName);
  if (toolRule.origin !== "builtin" && toolRule.origin !== "baseline") {
    scopes.push({
      id: "tool",
      surface: "tool",
      target: call.toolName,
      access: "other",
      state: toolRule.action,
      source: `${toolRule.origin}:${toolRule.pattern}`,
    });
  }
  return scopes;
}

function fileAssessment(
  call: CallState,
  evaluator: RuleEvaluator,
  options: DefaultAssessmentOptions,
  providedFacts?: ToolAccessFactsResult,
): LocalAssessment {
  const facts = providedFacts ?? options.fileFacts?.(call) ?? fileFacts(call);
  const assessment = assessToolAccessFacts({
    facts,
    scopes: fileScopes(call, facts, evaluator),
    ...(options.executor === undefined ? {} : { executor: options.executor }),
  });
  const cause = assessment.route === "block"
    ? "explicit-rule"
    : assessment.route === "run"
      ? "all-gates-allow"
      : assessment.route === "review"
        ? "not-default-eligible"
        : "incomplete-facts";
  return {
    route: assessment.route,
    cause,
    reason: assessment.reason,
    modelRequests: 0,
  };
}

export interface DefaultAssessmentOptions extends StructureAnalysisOptions {
  readonly mcpTargets?: (call: CallState) => readonly string[];
  readonly rules: readonly Rule[];
  /**
   * A pre-built evaluator over {@link rules} — the internal dep the host uses
   * to hand this resolver the same evaluation object the rules node already
   * holds. When omitted the resolver builds one over
   * {@link rules} when created and reuses its compiled matchers for every
   * call it answers.
   */
  readonly evaluator?: RuleEvaluator;
  readonly flavor?: PathFlavor;
  readonly capabilities?: AssessmentCapabilities;
  readonly mcpAnnotations?: (call: CallState) => McpAnnotations | undefined;
  readonly mcpConflicts?: (call: CallState) => readonly string[] | undefined;
  readonly executor?: ToolExecutorCapability;
  readonly fileFacts?: (call: CallState) => ToolAccessFactsResult;
  readonly registrationRevision?: string;
}

export type AssessmentResolver = (
  call: CallState,
  context: StepContext,
) => LocalAssessment | null | Promise<LocalAssessment | null>;

/**
 * Build the default resolver from the effective rules and host-probed
 * capabilities. The node still owns the mapping and fail-closed choice; this
 * resolver only gathers facts and asks the integrated 09/10 modules.
 */
export function createDefaultAssessmentResolver(
  options: DefaultAssessmentOptions,
): AssessmentResolver {
  const evaluator = options.evaluator ??
    createRuleEvaluator(
      options.rules,
      options.flavor ?? pathFlavorForPlatform(process.platform),
    );
  return async (call: CallState) => {
    if (isShell(call.toolName)) return shellAssessment(call, evaluator, options);
    if (isMcp(call.toolName)) return mcpAssessment(call, evaluator, options);
    if (isPathTool(call.toolName)) return fileAssessment(call, evaluator, options);
    if (classifyToolKind(call.toolName) === "extension") {
      // Extension tools have no built-in path shape. A verified host binding
      // supplies the file facts; without one this node has no opinion and the
      // call continues to the later nodes unchanged.
      const facts = options.fileFacts?.(call);
      if (facts?.status !== "verified") return null;
      return fileAssessment(call, evaluator, options, facts);
    }
    return null;
  };
}

