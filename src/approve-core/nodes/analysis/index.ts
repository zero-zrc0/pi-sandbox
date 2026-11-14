import {
  MAX_STEP_UNITS,
  MAX_UNITS_PER_CALL,
  type CapturedDirectCall,
  type StepCapture,
  type UnitPreparation,
} from "#approve-core/contracts";
import type { ChainNode, StepContext } from "#approve-core/runtime";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { bashPathFacts } from "#approve-core/utils/access-intent/bash/bash-path-resolver";
import type { SyntaxParser } from "#approve-core/utils/access-intent/bash/parser";
import {
  DEFAULT_POWERSHELL_PARSER_LIMITS,
  type PowerShellParseResult,
  type PowerShellParserPort,
  type PowerShellParserLimits,
} from "#approve-core/utils/access-intent/powershell/parser";
import { powerShellUnitId } from "#approve-core/utils/access-intent/powershell/analysis";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import { jsonDigest } from "../../../json";

/**
 * Structure analysis.
 *
 * The host calls {@link analyzeStep} before `runStepChain`/`prepareStep`: the
 * frozen capture keeps every original call and argument, while this module
 * derives the analysis units the chain initialises as ask. Units are never new tool
 * calls; their ids are deterministic for one frozen call so later nodes can
 * map their own facts back onto the same unit.
 *
 * The node itself deliberately returns no decisions. Initial ask state is owned
 * by `prepareStep`; an analysis node that returned allow/deny would turn
 * structure into policy.
 */

export interface StructureAnalysisOptions {
  /** Working directory used to resolve shell path facts; defaults to process.cwd(). */
  readonly cwd?: string;
  /** Platform used for path normalization; defaults to process.platform. */
  readonly platform?: NodeJS.Platform;
  readonly commandEffects?: unknown;
  readonly normalizer?: PathNormalizer;
  readonly parser?: SyntaxParser;
  /** Test seam for a parser failure; production uses the shared tree-sitter parser. */
  readonly parseCommands?: (command: string) => Promise<readonly string[] | null>;
  /**
   * The step-local BashProgram provider the host hands the built-in nodes
   * the first request for a captured call starts the parse and
   * later consumers of the same call receive the same promise. When absent —
   * or when it answers `undefined` for a call — every consumer parses the call
   * itself, exactly as before this injection existed.
   */
  readonly getBashProgram?: BashProgramProvider;
  readonly getPowerShellParse?: PowerShellProgramProvider;
  readonly powerShellLimits?: Partial<PowerShellParserLimits>;
}

/** The call facts a {@link BashProgramProvider} answers for. */
export type BashProgramRequest = Pick<
  CapturedDirectCall,
  "toolCallId" | "toolName" | "arguments"
>;

/**
 * The internal `getBashProgram(call)` seam: resolve one frozen
 * call's parsed {@link BashProgram}, or `undefined` when the provider holds no
 * program for it (a non-shell call, or a call it did not capture). A parse
 * failure surfaces as the same rejection to every consumer of the call.
 */
export type BashProgramProvider = (
  call: BashProgramRequest,
) => Promise<BashProgram | undefined>;

export type PowerShellProgramRequest = Pick<
  CapturedDirectCall,
  "toolCallId" | "toolName" | "arguments" | "digest"
>;

export type PowerShellProgramProvider = (
  call: PowerShellProgramRequest,
) => Promise<PowerShellParseResult | undefined>;

const SHELL_TOOL_NAMES = new Set(["bash", "shell"]);
const MAX_REASON_TEXT = 160;

function shellCommandOf(
  call: Pick<CapturedDirectCall, "toolName" | "arguments">,
): string | undefined {
  if (!SHELL_TOOL_NAMES.has(call.toolName)) return undefined;
  const command = call.arguments.command;
  return typeof command === "string" ? command : undefined;
}

function powerShellCommandOf(
  call: Pick<CapturedDirectCall, "toolName" | "arguments">,
): string | undefined {
  if (call.toolName !== "powershell") return undefined;
  const command = call.arguments.command;
  return typeof command === "string" ? command : undefined;
}

function clip(text: string): string {
  return text.length <= MAX_REASON_TEXT
    ? text
    : `${text.slice(0, MAX_REASON_TEXT - 3)}...`;
}

/** The stable unit id for one call's analysis fragment. */
function analysisUnitId(
  toolCallId: string,
  index: number,
  text: string,
): string {
  const digest = jsonDigest({ toolCallId, index, text }).slice(0, 16);
  return `${toolCallId}:u${index}:${digest}`;
}

function wholeUnit(
  call: CapturedDirectCall,
  reason: string,
): UnitPreparation {
  return Object.freeze({
    toolCallId: call.toolCallId,
    unitId: `${call.toolCallId}:whole`,
    actionDigest: call.digest,
    reason: clip(reason),
  });
}

/** One analysis fragment, shared with rule/assessment nodes that map by unit. */
export interface CallFragment {
  readonly unitId: string;
  readonly text: string;
  readonly whole: boolean;
}

interface BashFragments {
  readonly fragments: readonly CallFragment[];
  readonly incomplete?: string;
}

interface PowerShellFragments {
  readonly fragments: readonly CallFragment[];
  readonly incomplete?: string;
}

async function bashFragments(
  call: BashProgramRequest,
  command: string,
  options: StructureAnalysisOptions,
): Promise<BashFragments> {
  if (command.trim().length === 0) {
    return {
      fragments: [{ unitId: `${call.toolCallId}:whole`, text: command, whole: true }],
      incomplete: "empty-command",
    };
  }

  let texts: readonly string[];
  let uncertain = false;
  try {
    if (options.parseCommands) {
      texts = (await options.parseCommands(command)) ?? [];
    } else {
      const program = await options.getBashProgram?.(call);
      if (program !== undefined) {
        // The shared per-call parse: the fragments and their
        // incomplete/salvaged health read the same BashProgram the other
        // built-in consumers read, so unit ids and health agree everywhere.
        const parsed = program.commands();
        texts = parsed.map((entry) => entry.text);
        uncertain = parsed.some((entry) =>
          entry.parseUnresolved === true || entry.salvaged === true);
      } else {
        const normalizer = options.normalizer ?? new PathNormalizer(
          pathFlavorForPlatform(options.platform ?? process.platform),
          options.cwd ?? process.cwd(),
        );
        const parsed = (await BashProgram.parse(command, normalizer, { pathFacts: bashPathFacts, commandEffects: options.commandEffects, parser: options.parser })).commands();
        texts = parsed.map((entry) => entry.text);
        uncertain = parsed.some((entry) =>
          entry.parseUnresolved === true || entry.salvaged === true);
      }
    }
  } catch {
    return {
      fragments: [{ unitId: `${call.toolCallId}:whole`, text: command, whole: true }],
      incomplete: "parser-failed",
    };
  }

  if (texts.length === 0) {
    return {
      fragments: [{ unitId: `${call.toolCallId}:whole`, text: command, whole: true }],
      incomplete: "no-units",
    };
  }
  // Leave room for the whole-call unit an uncertain parse appends.
  if (texts.length > MAX_UNITS_PER_CALL || (uncertain && texts.length >= MAX_UNITS_PER_CALL)) {
    return {
      fragments: [{ unitId: `${call.toolCallId}:whole`, text: command, whole: true }],
      incomplete: "unit-limit",
    };
  }

  const fragments: CallFragment[] = texts.map((text, index) => Object.freeze({
    unitId: analysisUnitId(call.toolCallId, index, text),
    text,
    whole: false,
  }));
  if (uncertain) {
    // Recovered fragments are not proof that the whole command was understood;
    // keep one whole-call ask beside them so nothing rides on the recovery.
    fragments.push(Object.freeze({
      unitId: `${call.toolCallId}:whole`,
      text: command,
      whole: true,
    }));
    return { fragments, incomplete: "unresolved-subtree" };
  }
  return { fragments };
}

async function powerShellFragments(
  call: PowerShellProgramRequest,
  command: string,
  options: StructureAnalysisOptions,
): Promise<PowerShellFragments> {
  const fallback = (reason: string): PowerShellFragments => ({
    fragments: [{ unitId: `${call.toolCallId}:whole`, text: command, whole: true }],
    incomplete: reason,
  });
  if (command.trim().length === 0) return fallback("empty-command");
  try {
    const parsed = await options.getPowerShellParse?.(call);
    if (parsed === undefined || !parsed.ok || parsed.summary.completeness !== "complete") {
      return fallback(parsed?.ok ? "parse-incomplete" : parsed?.reason ?? "parser-unavailable");
    }
    const extents = parsed.summary.units;
    if (extents.length === 0) return fallback("no-units");
    if (extents.length > MAX_UNITS_PER_CALL) return fallback("unit-limit");
    const fragments = extents.map(({ start, end }) => Object.freeze({
      unitId: powerShellUnitId(call.toolCallId, call.digest, { start, end }),
      text: command.slice(start, end),
      whole: false,
    }));
    return { fragments };
  } catch {
    return fallback("parser-failed");
  }
}

/**
 * The fragments of one frozen call, keyed by the same unit ids
 * {@link analyzeStep} produced. Rule and assessment nodes use this mapping
 * instead of inventing a second unit registry.
 */
export async function fragmentsForCall(
  call: Pick<CapturedDirectCall, "toolCallId" | "toolName" | "arguments" | "digest">,
  options: StructureAnalysisOptions = {},
): Promise<readonly CallFragment[]> {
  const powershellCommand = powerShellCommandOf(call);
  if (powershellCommand !== undefined) {
    return (await powerShellFragments(call, powershellCommand, options)).fragments;
  }
  const command = shellCommandOf(call);
  if (command === undefined) {
    return [Object.freeze({
      unitId: `${call.toolCallId}:whole`,
      text: "",
      whole: true,
    })];
  }
  return (await bashFragments(call, command, options)).fragments;
}

async function unitsForCall(
  call: CapturedDirectCall,
  options: StructureAnalysisOptions,
): Promise<readonly UnitPreparation[]> {
  const powershellCommand = powerShellCommandOf(call);
  if (powershellCommand !== undefined) {
    const parsed = await powerShellFragments(call, powershellCommand, options);
    return parsed.fragments.map((fragment, index) => Object.freeze({
      toolCallId: call.toolCallId,
      unitId: fragment.unitId,
      actionDigest: call.digest,
      reason: clip(fragment.whole
        ? `structure:analysis-incomplete:${parsed.incomplete ?? "whole-call"}`
        : `structure:powershell:${index}:${fragment.text}`),
    }));
  }
  const command = shellCommandOf(call);
  if (command === undefined) {
    return [wholeUnit(call, `structure:whole-call:${call.toolName}`)];
  }
  const parsed = await bashFragments(call, command, options);
  return parsed.fragments.map((fragment, index) => Object.freeze({
    toolCallId: call.toolCallId,
    unitId: fragment.unitId,
    actionDigest: call.digest,
    reason: clip(fragment.whole
      ? `structure:analysis-incomplete:${parsed.incomplete ?? "whole-call"}`
      : `structure:bash:${index}:${fragment.text}`),
  }));
}

/**
 * Turn one frozen step capture into the ask units `prepareStep` accepts.
 * Every original call receives at least one unit; an incomplete parse keeps a
 * whole-call unit rather than dropping or character-splitting the command.
 */
export async function analyzeStep(
  capture: StepCapture,
  options: StructureAnalysisOptions = {},
): Promise<readonly UnitPreparation[]> {
  const units: UnitPreparation[] = [];
  for (const call of capture.directCalls) {
    units.push(...await unitsForCall(call, options));
  }
  if (units.length > MAX_STEP_UNITS) {
    throw new RangeError("analysis produced more units than one step accepts");
  }
  return Object.freeze(units);
}

/**
 * Build the step-local `getBashProgram(call)` the host hands to the built-in
 * nodes.
 *
 * The provider is keyed by the frozen capture's original calls: the first
 * request for a call starts its `BashProgram.parse` and every later request —
 * from the rules, assessment, or mode consumer of the same call — receives the
 * same promise, so one step's Bash call is analyzed once and all consumers read
 * the same command fragments, path candidates, effects, and parse health. Two
 * calls of one step never share, even with identical command text, and a
 * failure is shared only within the failing call: the promise (settled or
 * rejected) is kept for the step's lifetime and the whole map is dropped with
 * the step, so the next call re-observes the filesystem and may retry.
 *
 * A call that is not a captured shell command with a string command answers
 * `undefined`, and every consumer falls back to its own existing path.
 */
export function createBashProgramProvider(
  calls: readonly BashProgramRequest[],
  options: Pick<StructureAnalysisOptions, "cwd" | "platform" | "commandEffects" | "normalizer" | "parser"> = {},
): BashProgramProvider {
  const commands = new Map<string, string>();
  for (const call of calls) {
    const command = shellCommandOf(call);
    if (command !== undefined) commands.set(call.toolCallId, command);
  }
  const programs = new Map<string, Promise<BashProgram | undefined>>();
  const commandEffects = options.commandEffects === undefined ? undefined : structuredClone(options.commandEffects);
  const normalizer = options.normalizer ?? new PathNormalizer(
    pathFlavorForPlatform(options.platform ?? process.platform),
    options.cwd ?? process.cwd(),
  );
  return (call) => {
    const command = commands.get(call.toolCallId);
    if (command === undefined) return Promise.resolve(undefined);
    let program = programs.get(call.toolCallId);
    if (program === undefined) {
      program = BashProgram.parse(command, normalizer, { pathFacts: bashPathFacts, commandEffects, parser: options.parser });
      programs.set(call.toolCallId, program);
    }
    return program;
  };
}

export function createPowerShellProgramProvider(
  calls: readonly PowerShellProgramRequest[],
  options: {
    readonly parser: PowerShellParserPort;
    readonly limits?: Partial<PowerShellParserLimits>;
    readonly signal?: AbortSignal;
  },
): PowerShellProgramProvider {
  const captured = new Map<string, { readonly digest: string; readonly command: string }>();
  for (const call of calls) {
    const command = powerShellCommandOf(call);
    if (command !== undefined) captured.set(call.toolCallId, { digest: call.digest, command });
  }
  const results = new Map<string, Promise<PowerShellParseResult>>();
  const limits = {
    ...DEFAULT_POWERSHELL_PARSER_LIMITS,
    ...options.limits,
    maxUnits: Math.min(options.limits?.maxUnits ?? DEFAULT_POWERSHELL_PARSER_LIMITS.maxUnits, MAX_UNITS_PER_CALL),
  };
  return (call) => {
    const source = captured.get(call.toolCallId);
    const command = powerShellCommandOf(call);
    if (source === undefined || source.digest !== call.digest || source.command !== command) {
      return Promise.resolve(undefined);
    }
    let result = results.get(call.toolCallId);
    if (result === undefined) {
      result = options.parser.parse({ source: source.command, limits }, options.signal);
      results.set(call.toolCallId, result);
    }
    return result;
  };
}

/**
 * The fixed front node. It exists so the built-in order is explicit; initial
 * ask state was already established from {@link analyzeStep}'s output, and this
 * node never changes a unit's decision.
 */
export function createStructureAnalysisNode(): ChainNode {
  return Object.freeze({
    apiVersion: "1" as const,
    id: "builtin/structure-analysis",
    evaluate: (_context: StepContext) => ({ decisions: [] }),
  });
}
