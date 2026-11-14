/**
 * Bash parser seam.
 *
 * Domain code only sees the narrow node/tree/parser contracts below. The
 * tree-sitter implementation lives behind a lazy loader so importing this
 * module never touches WASM.
 */
import { createRequire } from "node:module";
import { createAsyncMemo, type AsyncMemo } from "./async-cache";
import { applyParseView } from "./parse-view";

export interface SyntaxNode {
  readonly type: string;
  readonly text: string;
  readonly startIndex: number;
  readonly endIndex: number;
  readonly childCount: number;
  readonly isNamed: boolean;
  readonly hasError: boolean;
  child(index: number): SyntaxNode | null;
  previousSibling(): SyntaxNode | null;
}

export interface SyntaxTree {
  readonly rootNode: SyntaxNode;
  delete(): void;
}

export interface SyntaxParser {
  parse(text: string): SyntaxTree | null;
}

/** Local reparser used for salvage. It only exposes parse, never ownership. */
export interface LocalReparser {
  parse(text: string): SyntaxTree | null;
}

/** Wrap a raw parser so every tree it returns carries the corrected view. */
export function createCorrectedParser(raw: SyntaxParser): SyntaxParser {
  return {
    parse(text: string): SyntaxTree | null {
      const tree = raw.parse(text);
      if (!tree) return null;
      try {
        const rootNode = applyParseView(tree.rootNode, text);
        return { rootNode, delete: () => tree.delete() };
      } catch (error) {
        tree.delete();
        throw error;
      }
    },
  };
}

export interface BashParserRuntime {
  /** Raw grammar parser, for tests and diagnostics. */
  raw(): Promise<SyntaxParser>;
  /** Corrected parser used by domain consumers. */
  corrected(): Promise<SyntaxParser>;
  /** Warm corrected parser, or undefined when not primed. */
  warm(): SyntaxParser | undefined;
  /** Warm once; failures are swallowed and retried on the next call. */
  prime(): Promise<void>;
  /** Drop only the warm slot; shared parser instances stay alive. */
  resetWarm(): void;
  /** Drop every cached parser; intended for test isolation. */
  reset(): void;
}

export function createBashParserRuntime(loadRaw: () => Promise<SyntaxParser>): BashParserRuntime {
  const rawMemo: AsyncMemo<SyntaxParser> = createAsyncMemo(loadRaw);
  const correctedMemo: AsyncMemo<SyntaxParser> = createAsyncMemo(async () => {
    return createCorrectedParser(await rawMemo.get());
  });

  let warmParser: SyntaxParser | undefined;
  let priming: Promise<void> | undefined;
  let warmGeneration = 0;

  return {
    raw: () => rawMemo.get(),
    corrected: () => correctedMemo.get(),
    warm: () => warmParser,
    prime(): Promise<void> {
      if (warmParser) return Promise.resolve();
      if (priming) return priming;
      const generation = warmGeneration;
      priming = correctedMemo
        .get()
        .then((parser) => {
          if (generation === warmGeneration) warmParser = parser;
        })
        .catch(() => {
          // Warm-up is best effort; the next call retries the async memo.
        })
        .finally(() => {
          if (generation === warmGeneration) priming = undefined;
        });
      return priming;
    },
    resetWarm(): void {
      warmGeneration += 1;
      warmParser = undefined;
      priming = undefined;
    },
    reset(): void {
      warmGeneration += 1;
      rawMemo.reset();
      correctedMemo.reset();
      warmParser = undefined;
      priming = undefined;
    },
  };
}

interface TreeSitterNode {
  readonly type: string;
  readonly text: string;
  readonly startIndex: number;
  readonly endIndex: number;
  readonly childCount: number;
  readonly isNamed: boolean;
  readonly hasError: boolean;
  child(index: number): TreeSitterNode | null;
  readonly previousSibling: TreeSitterNode | null;
}

interface TreeSitterTree {
  readonly rootNode: TreeSitterNode;
  delete(): void;
}

class WrappedNode implements SyntaxNode {
  constructor(private readonly node: TreeSitterNode) {}

  get type(): string {
    return this.node.type;
  }
  get text(): string {
    return this.node.text;
  }
  get startIndex(): number {
    return this.node.startIndex;
  }
  get endIndex(): number {
    return this.node.endIndex;
  }
  get childCount(): number {
    return this.node.childCount;
  }
  get isNamed(): boolean {
    return this.node.isNamed;
  }
  get hasError(): boolean {
    return this.node.hasError;
  }
  child(index: number): SyntaxNode | null {
    const child = this.node.child(index);
    return child ? new WrappedNode(child) : null;
  }
  previousSibling(): SyntaxNode | null {
    const sibling = this.node.previousSibling;
    return sibling ? new WrappedNode(sibling) : null;
  }
}

function wrapTree(tree: TreeSitterTree): SyntaxTree {
  return {
    rootNode: new WrappedNode(tree.rootNode),
    delete: () => tree.delete(),
  };
}

type WebTreeSitterModule = typeof import("web-tree-sitter");

let modulePromise: Promise<WebTreeSitterModule> | undefined;
let languagePromise: Promise<import("web-tree-sitter").Language> | undefined;

function loadWebTreeSitter(): Promise<WebTreeSitterModule> {
  if (!modulePromise) {
    modulePromise = import("web-tree-sitter").catch((error: unknown) => {
      modulePromise = undefined;
      throw error;
    });
  }
  return modulePromise;
}

async function loadBashLanguage(): Promise<import("web-tree-sitter").Language> {
  const { Parser, Language } = await loadWebTreeSitter();
  await Parser.init();
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("tree-sitter-bash/tree-sitter-bash.wasm");
  return Language.load(wasmPath);
}

function getBashLanguage(): Promise<import("web-tree-sitter").Language> {
  if (!languagePromise) {
    languagePromise = loadBashLanguage().catch((error: unknown) => {
      languagePromise = undefined;
      throw error;
    });
  }
  return languagePromise;
}

/** Build a raw tree-sitter Bash parser. The caller owns the returned parser. */
export async function createTreeSitterBashParser(): Promise<SyntaxParser> {
  const { Parser } = await loadWebTreeSitter();
  const language = await getBashLanguage();
  const parser = new Parser();
  parser.setLanguage(language);
  return {
    parse(text: string): SyntaxTree | null {
      const tree = parser.parse(text);
      return tree ? wrapTree(tree) : null;
    },
  };
}

/** Shared runtime used by the domain layer. */
export const bashParser: BashParserRuntime = createBashParserRuntime(createTreeSitterBashParser);
