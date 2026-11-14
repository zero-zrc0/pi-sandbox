/**
 * Tool classification.
 *
 * Names are trimmed, then classified by a fixed priority: native shells, the
 * MCP proxy tool, Pi MCP tools, skill, built-in path tools and finally any
 * other extension surface.
 */

export type ToolKind = "bash" | "powershell" | "mcp" | "mcp-tool" | "skill" | "path" | "extension";

export const BUILTIN_PATH_TOOLS = ["read", "write", "edit", "find", "grep", "ls"] as const;
export type BuiltinPathToolName = (typeof BUILTIN_PATH_TOOLS)[number];

export function isBuiltinPathToolName(name: string): name is BuiltinPathToolName {
  return (BUILTIN_PATH_TOOLS as readonly string[]).includes(name);
}

/**
 * Split a Pi MCP tool name into server and tool at the first double
 * underscore of the remaining text. Both parts must be non-empty.
 */
export function splitPiMcpName(name: string): { readonly server: string; readonly tool: string } | undefined {
  const index = name.indexOf("__");
  if (index <= 0) return undefined;
  const server = name.slice(0, index);
  const tool = name.slice(index + 2);
  if (server.length === 0 || tool.length === 0) return undefined;
  return { server, tool };
}

export function isPiMcpToolName(name: string): boolean {
  return splitPiMcpName(name) !== undefined;
}

export function classifyToolKind(rawName: string): ToolKind {
  const name = rawName.trim();
  if (name === "bash") return "bash";
  if (name === "powershell") return "powershell";
  if (name === "mcp") return "mcp";
  if (isPiMcpToolName(name)) return "mcp-tool";
  if (name === "skill") return "skill";
  if (isBuiltinPathToolName(name)) return "path";
  return "extension";
}
