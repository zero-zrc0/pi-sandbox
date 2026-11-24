// Adapted from Pi tool search at commit 9c4652688; Copyright (c) 2025 Mario Zechner; MIT License.
import type { ToolNamespace } from "@earendil-works/pi-coding-agent";
import type { CodemodeTool } from "@earendil-works/pi-codemode";

export interface ToolSearchDocument {
  readonly name: string;
  readonly text: string;
  readonly namespaceText?: string;
}

export interface ToolSearchMatch {
  readonly name: string;
  readonly score: number;
}

const wordSegmenter = new Intl.Segmenter(undefined, { granularity: "word" });
const STOP_WORDS: ReadonlySet<string> = new Set([
  "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of", "on", "or", "that", "the", "this", "to", "with",
]);

function stem(term: string): string {
  if (term.length > 4 && term.endsWith("ies")) return `${term.slice(0, -3)}y`;
  if (term.length > 4 && /(ches|shes|sses|xes|zes)$/.test(term)) return term.slice(0, -2);
  if (term.length > 3 && term.endsWith("s") && !term.endsWith("ss")) return term.slice(0, -1);
  return term;
}

export function tokenize(text: string): string[] {
  const normalized = text.normalize("NFC")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}]+/gu, " ");
  const words = /^[a-z0-9 ]*$/.test(normalized)
    ? normalized.split(" ")
    : Array.from(wordSegmenter.segment(normalized), segment => segment.isWordLike ? segment.segment : "");
  return words.filter(word => word.length > 0 && !STOP_WORDS.has(word))
    .map(word => /^[a-z0-9]+$/.test(word) ? stem(word) : word);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resolveSchemaRef(ref: string, root: unknown): unknown {
  if (ref !== "#" && !ref.startsWith("#/")) return undefined;
  let current = root;
  for (const segment of ref.slice(2).split("/").filter(Boolean)) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); }
    catch { return undefined; }
    const key = decoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!isObject(current) || !(key in current)) return undefined;
    current = current[key];
  }
  return current === true || isObject(current) ? current : undefined;
}

function schemaText(schema: unknown, root: unknown, parts: string[], seen: Set<unknown>): void {
  if (!isObject(schema)) return;
  if (typeof schema.$ref === "string") {
    const target = resolveSchemaRef(schema.$ref, root);
    if (isObject(target) && !seen.has(target)) {
      seen.add(target);
      schemaText(target, root, parts, seen);
    }
  }
  if (typeof schema.description === "string") parts.push(schema.description);
  if (isObject(schema.properties)) {
    for (const [name, property] of Object.entries(schema.properties)) {
      parts.push(name);
      schemaText(property, root, parts, seen);
    }
  }
  schemaText(schema.items, root, parts, seen);
  for (const key of ["anyOf", "oneOf", "allOf"]) {
    const variants = schema[key];
    if (Array.isArray(variants)) for (const variant of variants) schemaText(variant, root, parts, seen);
  }
}

export function createToolSearchDocument(
  tool: Pick<CodemodeTool, "name" | "description" | "inputSchema">,
  namespace?: ToolNamespace,
): ToolSearchDocument {
  const parts = [tool.description ?? ""];
  schemaText(tool.inputSchema, tool.inputSchema, parts, new Set([tool.inputSchema]));
  const namespaceText = namespace
    ? [namespace.name, namespace.description ?? "", namespace.instructions ?? ""].join(" ")
    : "";
  return { name: tool.name, text: parts.filter(part => part.trim()).join(" "), namespaceText };
}

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/[^a-z0-9_$]/g, "_");
}

function isExactNameQuery(query: string, name: string): boolean {
  const normalized = normalizeName(name);
  return normalized === query || normalized.endsWith(`__${query}`);
}

interface IndexedDocument {
  readonly name: string;
  readonly nameTerms: ReadonlySet<string>;
  readonly localNameTerms: readonly string[];
  readonly textCounts: ReadonlyMap<string, number>;
  readonly textLength: number;
  readonly namespaceTerms: ReadonlySet<string>;
}

function indexDocument(document: ToolSearchDocument): IndexedDocument {
  const textCounts = new Map<string, number>();
  for (const term of tokenize(document.text)) textCounts.set(term, (textCounts.get(term) ?? 0) + 1);
  const segments = document.name.split("__");
  return {
    name: document.name,
    nameTerms: new Set(tokenize(document.name)),
    localNameTerms: [...new Set(tokenize(segments[segments.length - 1] ?? ""))],
    textCounts,
    textLength: [...textCounts.values()].reduce((sum, count) => sum + count, 0),
    namespaceTerms: new Set(tokenize(document.namespaceText ?? "")),
  };
}

const NAME_WEIGHT = 3;
const NAMESPACE_WEIGHT = 0.5;

export class Bm25Ranker {
  rank(query: string, documents: readonly ToolSearchDocument[], limit: number): ToolSearchMatch[] {
    const queryTerms = new Set(tokenize(query));
    if (queryTerms.size === 0 || documents.length === 0 || limit <= 0) return [];
    const indexed = documents.map(indexDocument);
    const averageLength = indexed.reduce((sum, document) => sum + document.textLength, 0) / indexed.length || 1;
    const idf = new Map([...queryTerms].map(term => {
      const frequency = indexed.filter(document => document.nameTerms.has(term) ||
        document.textCounts.has(term) || document.namespaceTerms.has(term)).length;
      return [term, Math.log(1 + (indexed.length - frequency + 0.5) / (frequency + 0.5))] as const;
    }));
    const fullNameBonus = [...idf.values()].reduce((sum, value) => sum + value, 0);
    const exactQuery = normalizeName(query);
    const matches: (ToolSearchMatch & { covered: number; exact: boolean })[] = [];
    for (const document of indexed) {
      const norm = 1.2 * (1 - 0.75 + (0.75 * document.textLength) / averageLength);
      let score = 0;
      let covered = 0;
      for (const term of queryTerms) {
        const count = document.textCounts.get(term) ?? 0;
        const weight = (document.nameTerms.has(term) ? NAME_WEIGHT : 0) +
          (document.namespaceTerms.has(term) ? NAMESPACE_WEIGHT : 0) +
          (count * 2.2) / (count + norm);
        if (weight > 0) covered++;
        score += (idf.get(term) ?? 0) * weight;
      }
      if (score === 0) continue;
      if (document.localNameTerms.length > 0 && document.localNameTerms.every(term => queryTerms.has(term))) {
        score += fullNameBonus;
      }
      matches.push({ name: document.name, score, covered, exact: isExactNameQuery(exactQuery, document.name) });
    }
    return matches.sort((left, right) => Number(right.exact) - Number(left.exact) ||
      right.covered - left.covered || right.score - left.score)
      .slice(0, limit)
      .map(({ name, score }) => ({ name, score }));
  }
}
