/**
 * Bash fact view (specs/host-integration.md §2).
 *
 * A step's BashProgram is already parsed once and shared through the step
 * provider. This module projects that program into the frozen plain dictionary
 * a node reads, and collects the per-call views of one step. It never parses,
 * copies or proxies the program output: arrays and entries stay the same
 * object references the program returned.
 */
import type { BashProgramFactsView } from "#approve-core/contracts";
import type {
  BashProgramProvider,
  BashProgramRequest,
} from "#approve-core/nodes/analysis";
import type { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { executionAnalysisOf, wordsOf } from "#approve-core/utils/access-intent/bash/command-enumeration";

/** The reserved built-in keys of one call's fact view, in projection order. */
export const BASH_FACT_KEYS = Object.freeze([
  "commandText",
  "commands",
  "programCalls",
  "workingDirectory",
  "pathRuleCandidates",
  "externalAccesses",
] as const);

function nullProtoRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

/**
 * Project one parsed program into the frozen per-call view. The four built-in
 * keys are own data properties of a null-prototype dictionary; reading them
 * never recomputes or calls back into the program.
 */
export function bashProgramFactsView(program: BashProgram): BashProgramFactsView {
  const view = nullProtoRecord<unknown>();
  const commands = program.commands();
  view.commandText = program.source;
  view.commands = commands;
  view.programCalls = Object.freeze(commands.map((command, unitIndex) => {
    const words = wordsOf(command);
    const name = words[0];
    const execution = executionAnalysisOf(command);
    return Object.freeze({
      unitIndex,
      text: command.text,
      programName: name === undefined || name.computed ? null : name.value,
      arguments: words.slice(1).some((word) => word.computed)
        ? null
        : Object.freeze(words.slice(1).map((word) => word.value)),
      dynamic: name === undefined || name.computed || words.slice(1).some((word) => word.computed),
      wrapperComplete: execution?.complete ?? true,
    });
  }));
  view.workingDirectory = program.baseDir;
  view.pathRuleCandidates = program.pathRuleCandidates();
  view.externalAccesses = program.externalAccesses();
  return Object.freeze(view) as unknown as BashProgramFactsView;
}

/**
 * Collect the per-call fact views of one step through the shared provider.
 *
 * The provider is asked exactly once per call, including calls whose parse
 * fails: a missing program or a rejected parse only omits that call. When
 * every call is omitted the step has no Bash view at all.
 */
export async function collectStepBashFacts(input: {
  readonly calls: readonly BashProgramRequest[];
  readonly provider: BashProgramProvider;
}): Promise<Readonly<Record<string, BashProgramFactsView>> | undefined> {
  const collected = await Promise.all(
    input.calls.map(async (call): Promise<readonly [string, BashProgramFactsView] | undefined> => {
      try {
        const program = await input.provider(call);
        if (program === undefined) return undefined;
        return [call.toolCallId, bashProgramFactsView(program)] as const;
      } catch {
        return undefined;
      }
    }),
  );

  let views: Record<string, BashProgramFactsView> | undefined;
  for (const entry of collected) {
    if (entry === undefined) continue;
    views ??= nullProtoRecord<BashProgramFactsView>();
    views[entry[0]] = entry[1];
  }
  return views === undefined ? undefined : Object.freeze(views);
}
