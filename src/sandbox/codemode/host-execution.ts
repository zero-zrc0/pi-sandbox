import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  ExtensionToolContext,
  ToolNamespace,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { CodemodeResult, CodemodeTool } from "@earendil-works/pi-codemode";
import type { Usage } from "@earendil-works/pi-ai";
import { parseCodemodeSource } from "@earendil-works/pi-codemode";
import { renderToolSample, toCodemodeIdentifier } from "@earendil-works/pi-codemode/declarations";
import { CODEMODE_RUNTIME_LIMITS } from "./limits";
import { createCodemodeModelGlobals, type CodemodeModelCallOptions } from "./model-bridge";
import { runWithApprovedCodemode } from "./approval-scope";
import {
  type CodemodeRuntimeRequest,
  type CodemodeRuntimeBackend,
} from "./supervisor";

interface CodemodeCallRecord {
  id: string;
  name: string;
  args: string;
  status: "running" | "ok" | "error" | "cancelled";
  durationMs?: number;
  cost?: number;
  error?: string;
}

interface CodemodeExecutionDetails {
  readonly calls: readonly CodemodeCallRecord[];
  readonly fullOutputPath?: string;
}

export interface CodemodeHostToolExecutorOptions {
  readonly supervisor: {
    execute(request: CodemodeRuntimeRequest): Promise<CodemodeResult>;
  };
  readonly resolveBackend: (context: ExtensionToolContext) => CodemodeRuntimeBackend;
  readonly getToolNamespace?: (toolName: string) => ToolNamespace | undefined;
  readonly getToolGuidelines?: (toolName: string) => readonly string[];
  readonly appendEntry?: (customType: string, data: unknown) => void;
  readonly captureValidityGuard?: (context: ExtensionToolContext) => () => boolean;
  readonly modelsEnabled?: boolean;
}

export type ManagedCodemodeToolExecutor = ToolDefinition["execute"] & {
  cancelSession(sessionId: string): Promise<void>;
};

interface ActiveCodemodeExecution {
  readonly controller: AbortController;
  readonly done: Promise<void>;
  finish(): void;
}

interface SearchDocument {
  readonly name: string;
  readonly text: string;
}

const SEARCH_STOP_WORDS = new Set([
  "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of", "on", "or", "that", "the", "this", "to", "with",
]);

function searchTerms(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(term => term.length > 0 && !SEARCH_STOP_WORDS.has(term))
    .map(term => term.length > 4 && term.endsWith("ies")
      ? `${term.slice(0, -3)}y`
      : term.length > 4 && /(ches|shes|sses|xes|zes)$/.test(term)
        ? term.slice(0, -2)
        : term.length > 3 && term.endsWith("s") && !term.endsWith("ss")
          ? term.slice(0, -1)
          : term);
}

function isNamespaceMatch(namespace: ToolNamespace, query: string): boolean {
  const queryId = toCodemodeIdentifier(query);
  return [namespace.name, ...(namespace.aliases ?? [])]
    .some(name => name === query || toCodemodeIdentifier(name) === queryId);
}

function searchMatches(query: string, documents: readonly SearchDocument[], limit: number): string[] {
  const queryTerms = [...new Set(searchTerms(query))];
  if (queryTerms.length === 0 || documents.length === 0) return [];
  const counts = documents.map(document => {
    const frequencies = new Map<string, number>();
    for (const term of searchTerms(document.text)) frequencies.set(term, (frequencies.get(term) ?? 0) + 1);
    return frequencies;
  });
  const lengths = counts.map(frequencies => [...frequencies.values()].reduce((sum, count) => sum + count, 0));
  const averageLength = lengths.reduce((sum, length) => sum + length, 0) / documents.length || 1;
  const scores = documents.map((document, index) => {
    let score = 0;
    for (const term of queryTerms) {
      const frequency = counts[index]?.get(term);
      if (!frequency) continue;
      const documentFrequency = counts.filter(item => item.has(term)).length;
      const inverseFrequency = Math.log(1 + (documents.length - documentFrequency + 0.5) / (documentFrequency + 0.5));
      const norm = 1.2 * (1 - 0.75 + 0.75 * (lengths[index] ?? 0) / averageLength);
      score += inverseFrequency * frequency * 2.2 / (frequency + norm);
    }
    return { name: document.name, score, index };
  });
  return scores
    .filter(match => match.score > 0)
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .slice(0, limit)
    .map(match => match.name);
}

function createDiscoveryGlobals(
  tools: readonly CodemodeTool[],
  namespaces: ReadonlyMap<string, ToolNamespace>,
): CodemodeTool[] {
  const samples = new Map(tools.map(tool => [tool.name, renderToolSample(tool)]));
  const entry = (name: string) => ({ name: toCodemodeIdentifier(name), description: samples.get(name) ?? "" });
  return [
    {
      name: "searchTools",
      spread: true,
      execute(args) {
        const [query, searchOptions] = Array.isArray(args) ? args : [];
        if (typeof query !== "string") throw new Error("searchTools() expects a query string");
        const options = searchOptions !== null && typeof searchOptions === "object" && !Array.isArray(searchOptions)
          ? searchOptions as { limit?: unknown; namespace?: unknown }
          : {};
        const limit = options.limit ?? 8;
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
          throw new Error("searchTools() limit must be a positive integer");
        }
        const namespace = options.namespace;
        if (namespace !== undefined && namespace !== null && typeof namespace !== "string") {
          throw new Error("searchTools() namespace must be a string");
        }
        const documents = tools.flatMap(tool => {
          const toolNamespace = namespaces.get(tool.name);
          if (namespace && (!toolNamespace || !isNamespaceMatch(toolNamespace, namespace))) return [];
          return [{
            name: tool.name,
            text: [tool.name, tool.name.replaceAll("_", " "), tool.description ?? "", JSON.stringify(tool.inputSchema ?? {}) ?? "",
              toolNamespace?.name ?? "", toolNamespace?.description ?? "", toolNamespace?.instructions ?? ""].join(" "),
          }];
        });
        return searchMatches(query, documents, limit).map(entry);
      },
    },
    {
      name: "describeTool",
      spread: true,
      execute(args) {
        const [name] = Array.isArray(args) ? args : [];
        if (typeof name !== "string") throw new Error("describeTool() expects a tool name");
        const tool = tools.find(candidate => candidate.name === name || toCodemodeIdentifier(candidate.name) === name);
        return tool ? samples.get(tool.name) : undefined;
      },
    },
    {
      name: "describeNamespace",
      spread: true,
      execute(args) {
        const [name] = Array.isArray(args) ? args : [];
        if (typeof name !== "string") throw new Error("describeNamespace() expects a namespace name");
        let namespace: ToolNamespace | undefined;
        const names: string[] = [];
        for (const tool of tools) {
          const toolNamespace = namespaces.get(tool.name);
          if (!toolNamespace || !isNamespaceMatch(toolNamespace, name)) continue;
          namespace ??= toolNamespace;
          names.push(toCodemodeIdentifier(tool.name));
        }
        if (!namespace) return undefined;
        return {
          name: namespace.name,
          ...(namespace.description ? { description: namespace.description } : {}),
          ...(namespace.instructions ? { instructions: namespace.instructions } : {}),
          tools: names,
        };
      },
    },
  ];
}

function truncate(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars - 3)}...` : value;
}

function previewArgs(args: unknown): string {
  if (args === undefined) return "";
  try {
    return truncate(JSON.stringify(args) ?? "", 200);
  } catch {
    return "";
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function outputText(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readCodemodeStore(branch: readonly unknown[]): Record<string, unknown> {
  const store = new Map<string, unknown>();
  for (const value of branch) {
    if (!isRecord(value) || value.type !== "custom" || value.customType !== "codemode-store" || !isRecord(value.data)) continue;
    const set = value.data.set;
    const deleted = value.data.delete;
    if (!isRecord(set) || !Array.isArray(deleted) || !deleted.every(key => typeof key === "string")) continue;
    for (const key of deleted) store.delete(key);
    for (const [key, storedValue] of Object.entries(set)) store.set(key, storedValue);
  }
  return Object.fromEntries(store);
}

function formatScriptOutput(
  result: CodemodeResult,
  calls: readonly CodemodeCallRecord[],
  generatedImages: number,
): CodemodeResult["output"] {
  const output = [...result.output];
  if (result.ok && result.value !== undefined) output.push({ type: "text", text: outputText(result.value) });
  const textCount = output.filter(item => item.type === "text" && !item.console).length;
  const formatted: CodemodeResult["output"] = [];
  const consoleLines: string[] = [];
  let textIndex = 0;
  for (const item of output) {
    if (item.type === "image") {
      formatted.push(item);
    } else if (item.console) {
      consoleLines.push(item.text);
    } else {
      textIndex += 1;
      formatted.push({
        type: "text",
        text: textCount > 1 ? `==> text ${textIndex}/${textCount} <==\n${item.text}` : item.text,
      });
    }
  }
  if (consoleLines.length > 0) {
    formatted.push({ type: "text", text: `<console_output>\n${consoleLines.join("\n")}\n</console_output>` });
  }
  if (!result.ok) formatted.push({ type: "text", text: `Script error:\n${formatScriptError(result, calls)}` });
  if (generatedImages > 0 && !formatted.some(item => item.type === "image")) {
    formatted.push({
      type: "text",
      text: `Note: models.generateImages() returned ${generatedImages} image${generatedImages === 1 ? "" : "s"} that the script did not show. Show each image block of result.output with image(block).`,
    });
  }
  return formatted;
}

function joinAdjacentText(items: CodemodeResult["output"]): CodemodeResult["output"] {
  const joined: CodemodeResult["output"] = [];
  let textParts: string[] = [];
  let lastPart = "";
  const flush = () => {
    if (textParts.length > 0) joined.push({ type: "text", text: textParts.join("") });
    textParts = [];
    lastPart = "";
  };
  for (const item of items) {
    if (item.type !== "text") {
      flush();
      joined.push(item);
      continue;
    }
    if (lastPart !== "" && !lastPart.endsWith("\n")) {
      textParts.push("\n");
      lastPart = "\n";
    }
    textParts.push(item.text);
    if (item.text !== "") lastPart = item.text;
  }
  flush();
  return joined;
}

async function writeOutputFile(extension: string, data: string | Uint8Array): Promise<string> {
  const path = join(tmpdir(), `pi-codemode-${randomBytes(8).toString("hex")}${extension}`);
  await writeFile(path, data, { mode: 0o600, flag: "wx" });
  return path;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function saveImages(items: CodemodeResult["output"]): Promise<CodemodeResult["output"]> {
  const extensions: Record<string, string> = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
  };
  const labels = new Map<string, Promise<string>>();
  const saved: CodemodeResult["output"] = [];
  for (const item of items) {
    if (item.type !== "image") {
      saved.push(item);
      continue;
    }
    let label = labels.get(item.data);
    if (!label) {
      label = (async () => {
        const bytes = Buffer.from(item.data, "base64");
        const kind = `${item.mimeType}, ${formatSize(bytes.length)}`;
        const extension = extensions[item.mimeType];
        if (!extension) throw new Error(`No file extension for image type ${item.mimeType}`);
        try {
          const path = await writeOutputFile(extension, bytes);
          return `[Image saved to ${path} (${kind})]`;
        } catch (error) {
          return `[Image (${kind}) could not be saved: ${errorMessage(error)}]`;
        }
      })();
      labels.set(item.data, label);
    }
    saved.push({ type: "text", text: await label }, item);
  }
  return saved;
}

async function truncateOutput(items: CodemodeResult["output"], maxTokens: number): Promise<{
  readonly items: CodemodeResult["output"];
  readonly fullOutputPath?: string;
}> {
  const texts = items.filter((item): item is Extract<CodemodeResult["output"][number], { type: "text" }> => item.type === "text")
    .map(item => item.text);
  const combined = texts.join("\n");
  const budget = maxTokens * 4;
  if (texts.length === 0 || combined.length <= budget) return { items };
  const headChars = Math.floor(budget / 2);
  const tailChars = budget - headChars;
  const removed = combined.length - headChars - tailChars;
  const head = combined.slice(0, headChars);
  const tail = tailChars > 0 ? combined.slice(-tailChars) : "";
  let text = `Warning: truncated output (original token count: ${Math.ceil(combined.length / 4)})\nTotal output lines: ${combined.split("\n").length}\n\n${head}...${Math.ceil(removed / 4)} tokens truncated...${tail}`;
  let fullOutputPath: string | undefined;
  try {
    fullOutputPath = await writeOutputFile(".txt", combined);
    text += `\n\n[Full output: ${fullOutputPath} (read with offset/limit)]`;
  } catch (error) {
    text += `\n\n[Could not save the full output: ${errorMessage(error)}]`;
  }
  return {
    items: [{ type: "text", text }, ...items.filter(item => item.type === "image")],
    ...(fullOutputPath === undefined ? {} : { fullOutputPath }),
  };
}

function formatScriptError(result: Extract<CodemodeResult, { ok: false }>, calls: readonly CodemodeCallRecord[]): string {
  const error = result.error;
  const head = error.kind === "script"
    ? error.stack ?? `${error.name ?? "Error"}: ${error.message}`
    : error.kind === "timeout"
      ? `Script timed out: ${error.message}`
      : error.kind === "aborted"
        ? `Script aborted: ${error.message}`
        : `Script sandbox failed: ${error.message}`;
  const summary = calls.length === 0
    ? "No tool calls were made."
    : `Tool calls made before the failure (they are not undone): ${calls.map(call => `${call.name} (${call.status})`).join(", ")}`;
  return `${head}\n\n${summary}`;
}

function toolError(toolName: string, message: string): Error {
  return new Error(message || `Tool "${toolName}" failed`);
}

function addUsage(current: Usage | undefined, next: Usage): Usage {
  if (current === undefined) return next;
  return {
    input: current.input + next.input,
    output: current.output + next.output,
    cacheRead: current.cacheRead + next.cacheRead,
    cacheWrite: current.cacheWrite + next.cacheWrite,
    totalTokens: current.totalTokens + next.totalTokens,
    cost: {
      input: current.cost.input + next.cost.input,
      output: current.cost.output + next.cost.output,
      cacheRead: current.cost.cacheRead + next.cost.cacheRead,
      cacheWrite: current.cost.cacheWrite + next.cost.cacheWrite,
      total: current.cost.total + next.cost.total,
    },
  };
}

async function response(
  result: CodemodeResult,
  calls: readonly CodemodeCallRecord[],
  startedAt: number,
  maxOutputTokens = 10_000,
  generatedImages = 0,
  usage?: Usage,
): Promise<ReturnType<ToolDefinition["execute"]> extends Promise<infer T> ? T : never> {
  const formatted = formatScriptOutput(result, calls, generatedImages);
  const truncated = await truncateOutput(joinAdjacentText(formatted), maxOutputTokens);
  const output = joinAdjacentText(await saveImages(truncated.items));
  const elapsed = ((performance.now() - startedAt) / 1000).toFixed(1);
  const content = [
    { type: "text" as const, text: `Script ${result.ok ? "completed" : "failed"}\nWall time ${elapsed} seconds\nOutput:\n` },
    ...output.map(item => item.type === "text"
      ? { type: "text" as const, text: item.text }
      : { type: "image" as const, data: item.data, mimeType: item.mimeType }),
  ];
  return {
    content,
    details: {
      calls: calls.map(call => ({ ...call })),
      ...(truncated.fullOutputPath === undefined ? {} : { fullOutputPath: truncated.fullOutputPath }),
    },
    ...(usage === undefined ? {} : { usage }),
    ...(!result.ok ? { isError: true } : {}),
  } as ReturnType<ToolDefinition["execute"]> extends Promise<infer T> ? T : never;
}

function failureResponse(
  message: string,
  calls: readonly CodemodeCallRecord[],
  startedAt: number,
): Promise<ReturnType<ToolDefinition["execute"]> extends Promise<infer T> ? T : never> {
  return response({
    ok: false,
    error: { kind: "sandbox", message },
    output: [],
    calls: [],
  }, calls, startedAt);
}

export function createCodemodeHostToolExecutor(
  options: CodemodeHostToolExecutorOptions,
): ManagedCodemodeToolExecutor {
  const active = new Map<string, Set<ActiveCodemodeExecution>>();
  const execute: ToolDefinition["execute"] = async (toolCallId, params, signal, onUpdate, context) => {
    const startedAt = performance.now();
    const calls: CodemodeCallRecord[] = [];
    const publish = () => onUpdate?.({ content: [], details: { calls: calls.map(call => ({ ...call })) } });
    const code = (params as { readonly code?: unknown } | null)?.code;
    if (typeof code !== "string") return failureResponse("Codemode source code is unavailable", calls, startedAt);

    let parsed: ReturnType<typeof parseCodemodeSource>;
    try {
      parsed = parseCodemodeSource(code);
    } catch (error) {
      return failureResponse(errorMessage(error), calls, startedAt);
    }

    let backend: CodemodeRuntimeBackend;
    try {
      backend = options.resolveBackend(context);
    } catch (error) {
      return failureResponse(errorMessage(error), calls, startedAt);
    }

    const executionController = new AbortController();
    const abortExecution = () => executionController.abort(signal?.reason);
    if (signal?.aborted) abortExecution();
    else signal?.addEventListener("abort", abortExecution, { once: true });
    const sessionId = context.sessionManager.getSessionId();
    const isCurrent = options.captureValidityGuard?.(context) ?? (() => true);
    let finish!: () => void;
    const done = new Promise<void>(resolve => { finish = resolve; });
    const running: ActiveCodemodeExecution = { controller: executionController, done, finish };
    const sessionRuns = active.get(sessionId) ?? new Set<ActiveCodemodeExecution>();
    sessionRuns.add(running);
    active.set(sessionId, sessionRuns);

    let totalNestedCalls = 0;
    let concurrentNestedCalls = 0;
    let generatedImages = 0;
    let modelCallCount = 0;
    let modelUsage: Usage | undefined;
    let quotaFailure: string | undefined;
    const callable = [...context.tools].filter(tool => tool.name !== "codemode");
    const executeNestedTool = async (
      toolName: string,
      args: unknown,
      callSignal: AbortSignal,
      display?: CodemodeModelCallOptions,
    ) => {
      totalNestedCalls += 1;
      const record: CodemodeCallRecord = {
        id: `${toolCallId}/?`,
        name: display?.displayName ?? toolName,
        args: display?.displayArgs ?? previewArgs(args),
        status: "running",
      };
      calls.push(record);
      publish();

      if (totalNestedCalls > CODEMODE_RUNTIME_LIMITS.maxNestedCallsPerRuntime) {
        quotaFailure = `Codemode Runtime exceeded ${CODEMODE_RUNTIME_LIMITS.maxNestedCallsPerRuntime} nested calls`;
        executionController.abort(new Error(quotaFailure));
        record.status = "error";
        record.error = quotaFailure;
        publish();
        throw toolError(toolName, quotaFailure);
      }
      if (concurrentNestedCalls >= CODEMODE_RUNTIME_LIMITS.maxConcurrentNestedCallsPerRuntime) {
        record.status = "error";
        record.error = `Codemode Runtime allows at most ${CODEMODE_RUNTIME_LIMITS.maxConcurrentNestedCallsPerRuntime} concurrent nested calls`;
        publish();
        throw toolError(toolName, record.error);
      }

      concurrentNestedCalls += 1;
      const callStartedAt = performance.now();
      try {
        const outcome = await runWithApprovedCodemode(sessionId, isCurrent, () =>
          context.executeTool(toolName, args, { signal: callSignal }));
        record.id = outcome.toolCall.id;
        record.durationMs = performance.now() - callStartedAt;
        if (outcome.result.usage) record.cost = outcome.result.usage.cost.total;
        if (outcome.isError) {
          record.status = callSignal.aborted ? "cancelled" : "error";
          const text = outcome.result.content
            .filter(block => block.type === "text")
            .map(block => block.text)
            .join("\n");
          record.error = truncate(text || `Tool "${toolName}" failed`, 500);
        } else {
          const modelResult = display && outcome.result.structuredContent &&
            typeof outcome.result.structuredContent === "object"
            ? outcome.result.structuredContent as { readonly stopReason?: unknown; readonly errorMessage?: unknown; readonly output?: unknown }
            : undefined;
          record.status = modelResult?.stopReason === "error"
            ? "error"
            : modelResult?.stopReason === "aborted"
              ? "cancelled"
              : "ok";
          if (typeof modelResult?.errorMessage === "string") record.error = truncate(modelResult.errorMessage, 500);
          if (display?.displayName === "models.generateImages" && Array.isArray(modelResult?.output)) {
            generatedImages += modelResult.output.filter(item => isRecord(item) && item.type === "image").length;
          }
        }
        publish();
        return outcome;
      } catch (error) {
        if (record.status === "running") {
          record.status = callSignal.aborted ? "cancelled" : "error";
          record.durationMs = performance.now() - callStartedAt;
          record.error = truncate(errorMessage(error), 500);
          publish();
        }
        throw error;
      } finally {
        concurrentNestedCalls -= 1;
      }
    };

    const executeModelCall = async (
      display: CodemodeModelCallOptions,
      callSignal: AbortSignal,
      run: () => Promise<unknown>,
    ): Promise<unknown> => {
      totalNestedCalls += 1;
      const record: CodemodeCallRecord = {
        id: `${toolCallId}/${display.displayName}/${++modelCallCount}`,
        name: display.displayName,
        args: display.displayArgs,
        status: "running",
      };
      calls.push(record);
      publish();

      if (totalNestedCalls > CODEMODE_RUNTIME_LIMITS.maxNestedCallsPerRuntime) {
        quotaFailure = `Codemode Runtime exceeded ${CODEMODE_RUNTIME_LIMITS.maxNestedCallsPerRuntime} nested calls`;
        executionController.abort(new Error(quotaFailure));
        record.status = "error";
        record.error = quotaFailure;
        publish();
        throw new Error(quotaFailure);
      }
      if (concurrentNestedCalls >= CODEMODE_RUNTIME_LIMITS.maxConcurrentNestedCallsPerRuntime) {
        record.status = "error";
        record.error = `Codemode Runtime allows at most ${CODEMODE_RUNTIME_LIMITS.maxConcurrentNestedCallsPerRuntime} concurrent nested calls`;
        publish();
        throw new Error(record.error);
      }

      concurrentNestedCalls += 1;
      const callStartedAt = performance.now();
      try {
        const result = await run();
        record.durationMs = performance.now() - callStartedAt;
        const modelResult = isRecord(result)
          ? result as { readonly stopReason?: unknown; readonly errorMessage?: unknown; readonly output?: unknown; readonly usage?: Usage }
          : undefined;
        record.status = modelResult?.stopReason === "aborted"
          ? "cancelled"
          : modelResult?.stopReason === undefined || modelResult.stopReason === "stop"
            ? "ok"
            : "error";
        if (typeof modelResult?.errorMessage === "string") record.error = truncate(modelResult.errorMessage, 500);
        if (modelResult?.usage) {
          record.cost = modelResult.usage.cost.total;
          modelUsage = addUsage(modelUsage, modelResult.usage);
        }
        if (display.displayName === "models.generateImages" && Array.isArray(modelResult?.output)) {
          generatedImages += modelResult.output.filter(item => isRecord(item) && item.type === "image").length;
        }
        publish();
        return result;
      } catch (error) {
        if (record.status === "running") {
          record.status = callSignal.aborted ? "cancelled" : "error";
          record.durationMs = performance.now() - callStartedAt;
          record.error = truncate(errorMessage(error), 500);
          publish();
        }
        throw error;
      } finally {
        concurrentNestedCalls -= 1;
      }
    };

    const namespaces = new Map<string, ToolNamespace>();
    const sandboxTools: CodemodeTool[] = callable.map(tool => {
      const namespace = options.getToolNamespace?.(tool.name);
      if (namespace) namespaces.set(tool.name, namespace);
      const guidelines = options.getToolGuidelines?.(tool.name) ?? [];
      const description = guidelines.some(guideline => guideline.trim())
        ? `${tool.description.trim()}\n\n${guidelines.flatMap(guideline => guideline.trim() ? [`- ${guideline.trim()}`] : []).join("\n")}`
        : tool.description;
      return {
        name: tool.name,
        description,
        inputSchema: tool.parameters as CodemodeTool["inputSchema"],
        outputSchema: (tool.outputSchema ?? { type: "string" }) as CodemodeTool["outputSchema"],
        execute: async (args, toolContext) => {
          const outcome = await executeNestedTool(tool.name, args, toolContext.signal);
          if (tool.outputSchema && outcome.result.structuredContent !== undefined) {
            return outcome.result.structuredContent;
          }
          const text = outcome.result.content
            .filter(block => block.type === "text")
            .map(block => block.text)
            .join("\n");
          if (outcome.isError) throw toolError(tool.name, text);
          return text;
        },
      };
    });
    const discoveryGlobals = createDiscoveryGlobals(sandboxTools, namespaces);
    // Model globals run inside this approved Codemode call; unlike nested tools, they do not start another tool_call.
    const modelGlobals = options.modelsEnabled
      ? createCodemodeModelGlobals({
        modelRegistry: context.modelRegistry,
        runModelCall: executeModelCall,
      })
      : [];

    try {
      const result = await options.supervisor.execute({
        backend,
        code: parsed.code,
        timeoutMs: parsed.options.timeoutMs,
        signal: executionController.signal,
        store: readCodemodeStore(context.sessionManager.getBranch()),
        tools: sandboxTools,
        globals: [...discoveryGlobals, ...modelGlobals],
      });
      for (const call of calls) {
        if (call.status === "running") call.status = "cancelled";
      }
      let finalResult = result;
      if (quotaFailure && !signal?.aborted) {
        finalResult = {
          ok: false,
          error: { kind: "sandbox", message: quotaFailure },
          output: result.output,
          calls: [],
        };
      }
      if (finalResult.ok && (signal?.aborted || executionController.signal.aborted ||
          context.sessionManager.getSessionId() !== sessionId || !isCurrent())) {
        const output = [...finalResult.output];
        if (finalResult.value !== undefined) output.push({ type: "text", text: outputText(finalResult.value) });
        finalResult = {
          ok: false,
          error: { kind: "aborted", message: "Codemode result discarded because its session or policy changed" },
          output,
          calls: finalResult.calls,
        };
      }
      if (finalResult.ok) {
        const { set, delete: deleted } = finalResult.storeWrites;
        if (Object.keys(set).length > 0 || deleted.length > 0) {
          options.appendEntry?.("codemode-store", { set, delete: deleted });
        }
      }
      return await response(finalResult, calls, startedAt, parsed.options.maxOutputTokens, generatedImages, modelUsage);
    } catch (error) {
      return failureResponse(errorMessage(error), calls, startedAt);
    } finally {
      signal?.removeEventListener("abort", abortExecution);
      sessionRuns.delete(running);
      if (sessionRuns.size === 0 && active.get(sessionId) === sessionRuns) active.delete(sessionId);
      running.finish();
    }
  };
  return Object.assign(execute, {
    async cancelSession(sessionId: string) {
      const calls = [...(active.get(sessionId) ?? [])];
      for (const call of calls) call.controller.abort(new Error("Codemode session changed"));
      await Promise.all(calls.map(call => call.done));
    },
  });
}
