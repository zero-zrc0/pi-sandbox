/**
 * Review log input previews (specs/human-review.md §5).
 *
 * The log never repeats a Bash command or an MCP proxy request body, so those
 * surfaces get no preview at all. Built-in path tools reuse their prompt
 * summary, which keeps write/edit bodies out of the log. Every other surface
 * gets a one-line JSON summary whose sensitive keys are masked before any
 * stringification happens.
 */

import type { PreviewLimits } from "#approve-core/nodes/human/tool-input-preview";
import {
  logJsonPreview,
  resolvePreviewLimits,
} from "#approve-core/nodes/human/tool-input-preview";
import { summarizeBuiltinToolInput } from "#approve-core/nodes/human/builtin-tool-input-formatters";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";

export interface ReviewLogPreviewOptions {
  readonly limits?: Partial<PreviewLimits>;
}

export interface ReviewLogToolFacts {
  readonly toolName: string;
  readonly input: unknown;
}

export interface ReviewLogContextFacts extends ReviewLogToolFacts {
  readonly command?: unknown;
  readonly target?: unknown;
  readonly ruleOrigin?: unknown;
}

export interface ReviewLogContext {
  readonly command?: string;
  readonly target?: string;
  readonly toolInputPreview?: string;
  readonly ruleOrigin?: string;
}

function formatPreviewWithLimits(
  toolName: string,
  input: unknown,
  limits: PreviewLimits,
): string | undefined {
  const name = typeof toolName === "string" ? toolName.trim() : "";
  switch (classifyToolKind(name)) {
    case "bash":
    case "mcp":
      // The command / proxy body is already part of the log's other facts.
      return undefined;
    case "path":
      return summarizeBuiltinToolInput(name, input, limits);
    default:
      return logJsonPreview(input, limits.promptInput);
  }
}

/** §5 toolInputPreview: Bash and the MCP proxy are omitted; path tools reuse their prompt summary; everything else is masked generic JSON. */
export function formatToolInputPreview(
  toolName: string,
  input: unknown,
  options?: ReviewLogPreviewOptions,
): string | undefined {
  return formatPreviewWithLimits(toolName, input, resolvePreviewLimits(options?.limits));
}

function trimmedFact(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function buildContextWithLimits(
  facts: ReviewLogContextFacts,
  limits: PreviewLimits,
): ReviewLogContext {
  const context: {
    command?: string;
    target?: string;
    toolInputPreview?: string;
    ruleOrigin?: string;
  } = {};

  const command = trimmedFact(facts.command);
  if (command !== undefined) context.command = command;
  const target = trimmedFact(facts.target);
  if (target !== undefined) context.target = target;
  const toolInputPreview = formatPreviewWithLimits(facts.toolName, facts.input, limits);
  if (toolInputPreview !== undefined) context.toolInputPreview = toolInputPreview;
  const ruleOrigin = trimmedFact(facts.ruleOrigin);
  if (ruleOrigin !== undefined) context.ruleOrigin = ruleOrigin;

  return context;
}

/** Structured log context: absent and blank facts are omitted, never written as "". */
export function buildReviewLogContext(
  facts: ReviewLogContextFacts,
  options?: ReviewLogPreviewOptions,
): ReviewLogContext {
  return buildContextWithLimits(facts, resolvePreviewLimits(options?.limits));
}

/** Convenience binding of both preview helpers to one resolved limits object. */
export function createReviewLogPreviewFormatter(options?: ReviewLogPreviewOptions): {
  preview(toolName: string, input: unknown): string | undefined;
  context(facts: ReviewLogContextFacts): ReviewLogContext;
} {
  const limits = resolvePreviewLimits(options?.limits);
  return {
    preview: (toolName, input) => formatPreviewWithLimits(toolName, input, limits),
    context: (facts) => buildContextWithLimits(facts, limits),
  };
}
