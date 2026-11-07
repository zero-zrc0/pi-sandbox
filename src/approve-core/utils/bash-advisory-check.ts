/**
 * Synchronous advisory command check.
 *
 * Advisory callers must never wait for the parser. A warm parser gets the same
 * decomposition and adjudication the forced gate uses; a cold one falls back to
 * one whole-string rule match, which is exactly what the caller can do without
 * a parse.
 */
import type { PermissionCheckResult } from "#approve-core/contracts";
import { bashParser, type BashParserRuntime } from "./access-intent/bash/parser";
import {
  BashProgram,
  type BashPathFactsProvider,
} from "./access-intent/bash/program";
import {
  checkBashCommand,
  type BashCommandVerdict,
  type BashUnitResolver,
} from "./bash-command-check";
import type { PathNormalizer } from "./path/path-normalizer";

export interface BashAdvisoryCheckOptions {
  readonly command: string;
  readonly normalizer: PathNormalizer;
  readonly resolve: BashUnitResolver;
  /** Parser runtime; production uses the shared singleton. */
  readonly parser?: Pick<BashParserRuntime, "warm">;
  readonly home?: string;
  readonly workdir?: string;
  readonly pathFacts?: BashPathFactsProvider;
  readonly commandEffects?: unknown;
}

export interface BashAdvisoryResult {
  readonly check: PermissionCheckResult;
  readonly mode: "decomposed" | "whole-command";
  readonly program?: BashProgram;
  readonly verdict?: BashCommandVerdict;
}

export function checkBashAdvisory(
  options: BashAdvisoryCheckOptions,
): BashAdvisoryResult {
  const warm = (options.parser ?? bashParser).warm();
  if (warm === undefined) {
    return {
      check: options.resolve(options.command),
      mode: "whole-command",
    };
  }

  const program = BashProgram.parseSync(options.command, options.normalizer, {
    parser: warm,
    reparser: warm,
    ...(options.home === undefined ? {} : { home: options.home }),
    ...(options.workdir === undefined ? {} : { workdir: options.workdir }),
    ...(options.pathFacts === undefined ? {} : { pathFacts: options.pathFacts }),
    ...(options.commandEffects === undefined
      ? {}
      : { commandEffects: options.commandEffects }),
  });
  if (program === undefined) {
    return {
      check: options.resolve(options.command),
      mode: "whole-command",
    };
  }

  const verdict = checkBashCommand({
    command: options.command,
    units: program.commands(),
    resolve: options.resolve,
  });
  return {
    check: verdict.check,
    mode: "decomposed",
    program,
    verdict,
  };
}
