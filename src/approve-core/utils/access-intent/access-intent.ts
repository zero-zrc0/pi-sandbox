/**
 * Access intents.
 *
 * The four input kinds the policy resolver consumes. Raw tool calls carry
 * unknown inputs; parsed paths are value objects; fixed match values skip
 * path resolution; Bash command units keep the original for display and
 * evaluate every equivalent spelling as one invocation.
 */
import type { PathNormalizer, ResolvedPathValue } from "../path/path-normalizer";
import { classifyToolKind } from "./tool-kind";
import { extractToolInputPath, type PathExtractorLookup } from "./tool-input-path";
import { normalizeToolTargets, type NormalizationOptions } from "./input-normalizer";

export interface RawToolIntent {
  readonly kind: "raw-tool";
  readonly toolName: string;
  readonly input: unknown;
  readonly agent?: string;
}

export interface PathValuesIntent {
  readonly kind: "path-values";
  readonly surface: string;
  readonly paths: readonly ResolvedPathValue[];
  readonly agent?: string;
}

export interface FixedValuesIntent {
  readonly kind: "fixed-values";
  readonly surface: string;
  readonly values: readonly string[];
  readonly agent?: string;
}

export interface BashCommandIntent {
  readonly kind: "bash-command";
  readonly surface: "bash";
  readonly original: string;
  readonly spellings: readonly string[];
  readonly workdir?: string;
  readonly agent?: string;
}

export type AccessIntent = RawToolIntent | PathValuesIntent | FixedValuesIntent | BashCommandIntent;

export function rawToolIntent(toolName: string, input: unknown, agent?: string): RawToolIntent {
  return agent === undefined ? { kind: "raw-tool", toolName, input } : { kind: "raw-tool", toolName, input, agent };
}

export function pathValuesIntent(surface: string, paths: readonly ResolvedPathValue[], agent?: string): PathValuesIntent {
  return agent === undefined ? { kind: "path-values", surface, paths } : { kind: "path-values", surface, paths, agent };
}

export function fixedValuesIntent(surface: string, values: readonly string[], agent?: string): FixedValuesIntent {
  return agent === undefined ? { kind: "fixed-values", surface, values } : { kind: "fixed-values", surface, values, agent };
}

export function bashCommandIntent(
  original: string,
  spellings: readonly string[],
  agent?: string,
  workdir?: string,
): BashCommandIntent {
  return {
    kind: "bash-command",
    surface: "bash",
    original,
    spellings,
    ...(agent !== undefined ? { agent } : {}),
    ...(workdir !== undefined ? { workdir } : {}),
  };
}

export interface IntentBuildOptions extends NormalizationOptions {
  readonly normalizer: PathNormalizer;
  readonly extractorLookup?: PathExtractorLookup;
  readonly agent?: string;
}

/**
 * Route a raw tool call to its intent kind. Path tools with an extractable
 * path become path values; Bash and shell aliases become command units; MCP
 * surfaces become fixed candidates; everything else stays a raw tool intent
 * for the manager to normalize.
 */
export function buildAccessIntent(
  toolName: string,
  input: unknown,
  options: IntentBuildOptions,
): AccessIntent {
  const kind = classifyToolKind(toolName);
  const agent = options.agent;

  if (kind === "path") {
    const extracted = extractToolInputPath(toolName, input, options.extractorLookup);
    if (extracted !== undefined) {
      return pathValuesIntent(toolName, [options.normalizer.normalPath(extracted.path, options.normalizer.cwd)], agent);
    }
  }

  if (kind === "bash" || kind === "extension") {
    const normalized = normalizeToolTargets(toolName, input, options);
    if (normalized.command !== undefined) {
      return bashCommandIntent(
        normalized.command.original,
        normalized.targets,
        agent,
        normalized.workdir,
      );
    }
  }

  if (kind === "mcp" || kind === "mcp-tool") {
    const normalized = normalizeToolTargets(toolName, input, options);
    return fixedValuesIntent(normalized.surface, normalized.targets, agent);
  }

  if (kind === "skill") {
    const normalized = normalizeToolTargets(toolName, input, options);
    return fixedValuesIntent(normalized.surface, normalized.targets, agent);
  }

  return rawToolIntent(toolName, input, agent);
}
