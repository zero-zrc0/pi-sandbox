/**
 * Tool-name access extractor registry (specs/tool-access.md §6).
 *
 * Extractors live in two layers: local registrations owned by this runtime and
 * inherited ones supplied by the host, which a local registration shadows for
 * the same tool name. `resolve` reports which layer answered; the public
 * lookup returns the capability alone so consumers cannot depend on layer
 * metadata. Duplicate and stale-disposer semantics match the adapter registry.
 */
export type PathExtractor = (input: unknown) => unknown;

/** Which layer provided an extractor. */
export type ExtractorSource = "local" | "inherited";

/** One host-supplied extractor, inherited by this registry. */
export interface ToolAccessExtractorEntry {
  readonly name: string;
  readonly extract: PathExtractor;
}

export interface ToolAccessExtractorRegistryOptions {
  /** Extractors supplied by the host; local registrations shadow them. */
  readonly inherited?: readonly ToolAccessExtractorEntry[];
}

export interface ExtractorResolution {
  readonly extractor?: PathExtractor;
  /** "local" also means "nothing found" — the default lookup layer. */
  readonly source: ExtractorSource;
}

function normalizeName(name: unknown): string | undefined {
  if (typeof name !== "string") return undefined;
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function missingResolution(): ExtractorResolution {
  return Object.freeze({ source: "local" as const });
}

export class ToolAccessExtractorRegistry {
  private readonly local = new Map<string, PathExtractor>();
  private readonly inherited = new Map<string, PathExtractor>();

  constructor(options: ToolAccessExtractorRegistryOptions = {}) {
    for (const entry of options.inherited ?? []) {
      const name = normalizeName(entry?.name);
      if (name === undefined || typeof entry?.extract !== "function") {
        throw new Error("tool-access-extractor: invalid inherited registration");
      }
      if (this.inherited.has(name)) {
        throw new Error("tool-access-extractor: duplicate inherited name");
      }
      this.inherited.set(name, entry.extract);
    }
  }

  /** Register a local extractor; duplicate names are rejected. */
  register(name: string, extractor: PathExtractor): () => void {
    const key = normalizeName(name);
    if (key === undefined || typeof extractor !== "function") {
      throw new Error("tool-access-extractor: invalid registration");
    }
    if (this.local.has(key)) throw new Error("tool-access-extractor: duplicate name");
    this.local.set(key, extractor);

    let active = true;
    return (): void => {
      if (!active) return;
      active = false;
      if (this.local.get(key) === extractor) this.local.delete(key);
    };
  }

  /** Resolve a tool name and report which layer supplied the extractor. */
  resolve(toolName: string): ExtractorResolution {
    const key = normalizeName(toolName);
    if (key === undefined) return missingResolution();
    const local = this.local.get(key);
    if (local !== undefined) return Object.freeze({ extractor: local, source: "local" as const });
    const inherited = this.inherited.get(key);
    if (inherited !== undefined) {
      return Object.freeze({ extractor: inherited, source: "inherited" as const });
    }
    return missingResolution();
  }

  /** Public capability lookup: the extractor alone, never layer metadata. */
  lookup(toolName: string): PathExtractor | undefined {
    return this.resolve(toolName).extractor;
  }

  /** Remove local and inherited entries; the registry stays usable afterwards. */
  dispose(): void {
    this.local.clear();
    this.inherited.clear();
  }
}
