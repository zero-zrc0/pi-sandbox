/**
 * Tool-name input formatter registry (specs/tool-access.md §6).
 *
 * Same duplicate, stale-disposer and layered-lookup semantics as the access
 * extractor registry: local registrations shadow host-inherited ones, `resolve`
 * reports the answering layer, and the public lookup returns only the
 * formatter capability.
 */
export type ToolInputFormatter = (input: unknown) => unknown;

/** Which layer provided a formatter. */
export type ToolInputFormatterSource = "local" | "inherited";

/** One host-supplied formatter, inherited by this registry. */
export interface ToolInputFormatterEntry {
  readonly name: string;
  readonly format: ToolInputFormatter;
}

export interface ToolInputFormatterRegistryOptions {
  /** Formatters supplied by the host; local registrations shadow them. */
  readonly inherited?: readonly ToolInputFormatterEntry[];
}

export interface ToolInputFormatterResolution {
  readonly formatter?: ToolInputFormatter;
  /** "local" also means "nothing found" — the default lookup layer. */
  readonly source: ToolInputFormatterSource;
}

function normalizeName(name: unknown): string | undefined {
  if (typeof name !== "string") return undefined;
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function missingResolution(): ToolInputFormatterResolution {
  return Object.freeze({ source: "local" as const });
}

export class ToolInputFormatterRegistry {
  private readonly local = new Map<string, ToolInputFormatter>();
  private readonly inherited = new Map<string, ToolInputFormatter>();

  constructor(options: ToolInputFormatterRegistryOptions = {}) {
    for (const entry of options.inherited ?? []) {
      const name = normalizeName(entry?.name);
      if (name === undefined || typeof entry?.format !== "function") {
        throw new Error("tool-input-formatter: invalid inherited registration");
      }
      if (this.inherited.has(name)) {
        throw new Error("tool-input-formatter: duplicate inherited name");
      }
      this.inherited.set(name, entry.format);
    }
  }

  /** Register a local formatter; duplicate names are rejected. */
  register(name: string, formatter: ToolInputFormatter): () => void {
    const key = normalizeName(name);
    if (key === undefined || typeof formatter !== "function") {
      throw new Error("tool-input-formatter: invalid registration");
    }
    if (this.local.has(key)) throw new Error("tool-input-formatter: duplicate name");
    this.local.set(key, formatter);

    let active = true;
    return (): void => {
      if (!active) return;
      active = false;
      if (this.local.get(key) === formatter) this.local.delete(key);
    };
  }

  /** Resolve a tool name and report which layer supplied the formatter. */
  resolve(toolName: string): ToolInputFormatterResolution {
    const key = normalizeName(toolName);
    if (key === undefined) return missingResolution();
    const local = this.local.get(key);
    if (local !== undefined) return Object.freeze({ formatter: local, source: "local" as const });
    const inherited = this.inherited.get(key);
    if (inherited !== undefined) {
      return Object.freeze({ formatter: inherited, source: "inherited" as const });
    }
    return missingResolution();
  }

  /** Public capability lookup: the formatter alone, never layer metadata. */
  lookup(toolName: string): ToolInputFormatter | undefined {
    return this.resolve(toolName).formatter;
  }

  /** Remove local and inherited entries; the registry stays usable afterwards. */
  dispose(): void {
    this.local.clear();
    this.inherited.clear();
  }
}
