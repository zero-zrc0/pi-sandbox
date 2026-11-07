/**
 * Tool input normalization.
 *
 * Raw tool inputs become a surface plus an ordered target candidate set.
 * Bash inputs go through the Bash-specific normalization; shell aliases read
 * their declared command argument. Invalid inputs never throw — they fall
 * back to catch-all or empty semantics per surface.
 */
import { classifyToolKind, splitPiMcpName } from "./tool-kind";
import { generateMcpProxyCandidates, generatePiMcpCandidates } from "./mcp-targets";

export interface ShellToolDeclaration {
  readonly commandArgument: string;
  readonly workdirArgument?: string;
}

export type ShellToolsConfig = Readonly<Record<string, ShellToolDeclaration>>;

export interface ShellInvocation {
  readonly command: string;
  readonly workdir?: string;
}

function asObject(input: unknown): Record<string, unknown> | undefined {
  return typeof input === "object" && input !== null && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/**
 * Extract the shell invocation for a tool. The native bash tool reads
 * `command` and never a workdir; configured aliases read their declared
 * arguments. Non-shell tools return no shell semantics at all.
 */
export function extractShellInvocation(
  toolName: string,
  input: unknown,
  shellTools: ShellToolsConfig = {},
): ShellInvocation | undefined {
  const object = asObject(input) ?? {};
  if (toolName === "bash") {
    const command = readString(object.command);
    return { command: command !== undefined && command.trim().length > 0 ? command : "" };
  }
  const declaration = shellTools[toolName];
  if (declaration === undefined) return undefined;
  const rawCommand = readString(object[declaration.commandArgument]);
  const command = rawCommand !== undefined && rawCommand.trim().length > 0 ? rawCommand : "";
  const rawWorkdir = declaration.workdirArgument === undefined ? undefined : readString(object[declaration.workdirArgument]);
  const workdir = rawWorkdir !== undefined && rawWorkdir.trim().length > 0 ? rawWorkdir : undefined;
  return workdir === undefined ? { command } : { command, workdir };
}

export interface BashNormalization {
  /** Normalized command text used for rule matching. */
  readonly command: string;
  /** Original command text, always preserved for facts. */
  readonly original: string;
  /** Equivalent spellings for the same invocation, first occurrence kept. */
  readonly spellings: readonly string[];
}

export function normalizeBashCommand(original: string): BashNormalization {
  let command = original;
  const firstNonWhitespace = original.search(/\S/);
  if (firstNonWhitespace !== -1 && original[firstNonWhitespace] === "#") {
    const lineEnd = original.indexOf("\n");
    const withoutComment = lineEnd === -1 ? "" : original.slice(lineEnd + 1);
    const trimmed = withoutComment.trim();
    if (trimmed.length > 0) command = trimmed;
  } else {
    command = original.trim();
  }
  const spellings: string[] = [];
  for (const spelling of [command, original]) {
    if (spelling.trim().length > 0 && !spellings.includes(spelling)) spellings.push(spelling);
  }
  return { command, original, spellings };
}

export interface NormalizationOptions {
  readonly shellTools?: ShellToolsConfig;
  readonly mcpConfigServers?: readonly string[];
}

export interface NormalizedToolTargets {
  readonly surface: string;
  readonly targets: readonly string[];
  readonly command?: BashNormalization;
  readonly workdir?: string;
}

/**
 * Normalize a raw tool call into surface and target candidates. An empty
 * candidate list is left for the policy layer to fall back to `*`; MCP
 * surfaces always keep their surface-level candidate.
 */
export function normalizeToolTargets(
  toolName: string,
  input: unknown,
  options: NormalizationOptions = {},
): NormalizedToolTargets {
  const trimmedName = toolName.trim();
  const kind = classifyToolKind(trimmedName);
  const object = asObject(input) ?? {};

  const invocation = extractShellInvocation(trimmedName, object, options.shellTools);
  if (invocation !== undefined) {
    const normalization = normalizeBashCommand(invocation.command);
    return {
      surface: "bash",
      targets: normalization.spellings,
      command: normalization,
      ...(invocation.workdir !== undefined ? { workdir: invocation.workdir } : {}),
    };
  }

  if (kind === "skill") {
    const name = readString(object.name);
    return { surface: "skill", targets: [name !== undefined && name.trim().length > 0 ? name : "*"] };
  }

  if (kind === "mcp") {
    const candidates = generateMcpProxyCandidates(object, options.mcpConfigServers ?? []);
    return { surface: "mcp", targets: [...candidates, "mcp"] };
  }

  if (kind === "mcp-tool") {
    const parts = (trimmedName.startsWith("mcp__")
      ? splitPiMcpName(trimmedName.slice(5))
      : undefined) ?? splitPiMcpName(trimmedName);
    if (parts !== undefined) {
      const candidates = generatePiMcpCandidates(trimmedName, parts.server, parts.tool, options.mcpConfigServers ?? []);
      return { surface: "mcp", targets: [...candidates, "mcp"] };
    }
  }

  return { surface: trimmedName, targets: ["*"] };
}
