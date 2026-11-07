/**
 * Tool input path extraction.
 *
 * Cross-tool extraction returns a path plus its source. Bash returns none
 * because Bash token analysis owns Bash paths. Registered extractors win
 * for skill, Pi MCP and extension tools; everything else falls back to the
 * conventional `path` property.
 */
import { classifyToolKind } from "./tool-kind";

export type PathExtractionSource = "convention" | "local-extractor" | "inherited-extractor";

export interface ExtractedToolPath {
  readonly path: string;
  readonly source: PathExtractionSource;
}

export interface RegisteredPathExtractor {
  readonly origin: "local" | "inherited";
  readonly extract: (input: unknown) => unknown;
}

export interface PathExtractorLookup {
  readonly lookup: (toolName: string) => RegisteredPathExtractor | undefined;
}

export interface ExtractionOptions {
  /** Only answer for builtin path tools; never consult extractors. */
  readonly builtinOnly?: boolean;
}

function validPath(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function ownValue(object: unknown, key: string): unknown {
  if (typeof object !== "object" || object === null) return undefined;
  if (!Object.prototype.hasOwnProperty.call(object, key)) return undefined;
  return (object as Record<string, unknown>)[key];
}

export function extractToolInputPath(
  toolName: string,
  input: unknown,
  extractorLookup?: PathExtractorLookup,
  options: ExtractionOptions = {},
): ExtractedToolPath | undefined {
  const kind = classifyToolKind(toolName);

  if (kind === "bash") return undefined;
  if (options.builtinOnly === true && kind !== "path") return undefined;
  if (kind === "path") {
    const path = validPath(ownValue(input, "path"));
    return path === undefined ? undefined : { path, source: "convention" };
  }
  if (kind === "mcp") {
    const args = ownValue(input, "arguments");
    const path = validPath(ownValue(args, "path"));
    return path === undefined ? undefined : { path, source: "convention" };
  }

  // skill, Pi MCP and extension tools prefer a registered extractor.
  const extractor = extractorLookup?.lookup(toolName);
  if (extractor !== undefined) {
    const extracted = validPath(extractor.extract(input));
    if (extracted !== undefined) {
      return { path: extracted, source: extractor.origin === "local" ? "local-extractor" : "inherited-extractor" };
    }
  }
  const fallback = validPath(ownValue(input, "path"));
  return fallback === undefined ? undefined : { path: fallback, source: "convention" };
}
