/**
 * Prompt-facing tool-input formatters (specs/human-review.md §2/§4).
 *
 * Custom formatter lookup is injected as a port; the registry class is only
 * referenced by callers that register the built-in MCP formatter through it.
 * Failures inside a custom formatter never block the built-in summaries.
 */
import {
  PREVIEW_ELLIPSIS,
  collapseWhitespace,
  countLabel,
  inlinePreview,
  jsonPreview,
  resolvePreviewLimits,
  truncateWithEllipsis,
  type PreviewLimits,
} from "#approve-core/nodes/human/tool-input-preview";
import { summarizeBuiltinToolInput } from "#approve-core/nodes/human/builtin-tool-input-formatters";
import { classifyToolKind } from "#approve-core/utils/access-intent/tool-kind";

/** Narrow port over the caller-resolved custom formatter lookup. */
export interface ToolInputFormatterLookup {
  lookup(toolName: string): ((input: unknown) => unknown) | undefined;
}

export interface PromptFormatterOptions {
  readonly limits?: Partial<PreviewLimits>;
  /** Custom formatters; local and inherited layers are resolved by the caller. */
  readonly formatters?: ToolInputFormatterLookup;
}

export interface PromptToolInputFormatter {
  /** Prompt input summary for one call, without the "with input" prefix. */
  preview(toolName: string, input: unknown): string | undefined;
  /** Compose the summary onto a title; no summary leaves the title untouched. */
  attach(title: string, preview: string | undefined): string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Fixed fold marker for a nested object argument. */
const OBJECT_ARGUMENT_MARKER = `{${PREVIEW_ELLIPSIS}}`;

function formatMcpArgumentValue(value: unknown, mcpValue: number): string {
  if (typeof value === "string") {
    return `"${truncateWithEllipsis(collapseWhitespace(value), mcpValue)}"`;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return countLabel(value.length, "item", "items");
  if (isPlainObject(value)) return OBJECT_ARGUMENT_MARKER;
  try {
    return String(value);
  } catch {
    return "?";
  }
}

/**
 * Summarize the argument object of the MCP proxy tool. The raw event JSON is
 * never echoed here: the target already identifies the call.
 */
export function formatMcpProxyInput(
  input: unknown,
  limits: PreviewLimits = resolvePreviewLimits(),
): string | undefined {
  if (!isPlainObject(input)) return undefined;
  const args = input.arguments;
  if (!isPlainObject(args)) return undefined;
  const keys = Object.keys(args);
  if (keys.length === 0) return undefined;

  const parts = keys.map((key) => `${key}: ${formatMcpArgumentValue(args[key], limits.mcpValue)}`);
  return truncateWithEllipsis(`parameters ${parts.join(", ")}`, limits.mcpSummary);
}

/** Build the registered MCP formatter bound to one resolved limit set. */
export function createMcpPromptFormatter(
  limits: PreviewLimits = resolvePreviewLimits(),
): (input: unknown) => string | undefined {
  return (input: unknown): string | undefined => formatMcpProxyInput(input, limits);
}

/** Registration seam: the real registry supplies it (duplicate rules are its own). */
export interface FormatterRegistrationPort {
  register(name: string, formatter: (input: unknown) => unknown): () => void;
}

/** Register the built-in MCP prompt formatter under the single name "mcp". */
export function registerMcpPromptFormatter(
  port: FormatterRegistrationPort,
  options?: PromptFormatterOptions,
): () => void {
  return port.register("mcp", createMcpPromptFormatter(resolvePreviewLimits(options?.limits)));
}

interface CustomFormatterAttempt {
  readonly handled: boolean;
  readonly preview?: string;
}

/** Run a custom formatter without letting its failure escape this boundary. */
function runCustomFormatter(
  lookup: ToolInputFormatterLookup | undefined,
  toolName: string,
  input: unknown,
  promptInput: number,
): CustomFormatterAttempt {
  if (lookup === undefined) return { handled: false };
  const formatter = lookup.lookup(toolName);
  if (typeof formatter !== "function") return { handled: false };

  let result: unknown;
  try {
    result = formatter(input);
  } catch {
    return { handled: false };
  }
  if (typeof result !== "string") return { handled: false };
  const preview = inlinePreview(result, promptInput);
  return preview === undefined ? { handled: false } : { handled: true, preview };
}

/** Create the prompt input formatter used by human review titles. */
export function createPromptToolInputFormatter(
  options: PromptFormatterOptions = {},
): PromptToolInputFormatter {
  const limits = resolvePreviewLimits(options.limits);
  const custom = options.formatters;

  return {
    preview(toolName: string, input: unknown): string | undefined {
      const name = typeof toolName === "string" ? toolName.trim() : "";

      if (name.length > 0) {
        const customAttempt = runCustomFormatter(custom, name, input, limits.promptInput);
        if (customAttempt.handled) return customAttempt.preview;

        const kind = classifyToolKind(name);
        if (kind === "mcp") {
          // Proxy MCP never echoes the raw event JSON.
          return formatMcpProxyInput(input, limits);
        }
        if (kind === "path") {
          // A missing path summary is omitted rather than replaced by JSON,
          // so write/edit bodies cannot leak through the generic fallback.
          return summarizeBuiltinToolInput(name, input, limits);
        }
      }

      return jsonPreview(input, limits.promptInput);
    },

    attach(title: string, preview: string | undefined): string {
      if (preview === undefined) return title;
      return `${title} with input ${preview}`;
    },
  };
}
