/**
 * MCP target generation.
 *
 * Candidate lists preserve insertion order, ignore empty values and dedupe.
 * Order only decides which name is reported as matched; rule priority always
 * comes from rule order, never from candidate order.
 */

export const MCP_CALL_CANDIDATE = "mcp:call";
export const MCP_CONNECT_CANDIDATE = "mcp:connect";
export const MCP_DESCRIBE_CANDIDATE = "mcp:describe";
export const MCP_SEARCH_CANDIDATE = "mcp:search";
export const MCP_LIST_CANDIDATE = "mcp:list";
export const MCP_STATUS_CANDIDATE = "mcp:status";

export interface McpProxyArguments {
  readonly tool?: unknown;
  readonly connect?: unknown;
  readonly describe?: unknown;
  readonly search?: unknown;
  readonly server?: unknown;
}

export interface QualifiedToolName {
  readonly server: string;
  readonly tool: string;
  readonly raw: string;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

/** Split a qualified `server:tool` name at the first colon; later colons stay in the tool. */
export function parseQualifiedToolName(raw: string): QualifiedToolName | undefined {
  const index = raw.indexOf(":");
  if (index === -1) return undefined;
  const server = raw.slice(0, index).trim();
  const tool = raw.slice(index + 1).trim();
  if (server.length === 0 || tool.length === 0) return undefined;
  return { server, tool, raw };
}

function pushUnique(list: string[], value: string | undefined): void {
  if (value !== undefined && value.length > 0 && !list.includes(value)) list.push(value);
}

function normalizedConfigServers(configServers: readonly string[]): string[] {
  const seen: string[] = [];
  for (const name of configServers) {
    const trimmed = name.trim();
    if (trimmed.length > 0 && !seen.includes(trimmed)) seen.push(trimmed);
  }
  return seen;
}

/**
 * Tool-call candidates: server/tool combinations, server, tool, the raw
 * reference, then the call category candidate.
 */
export function toolCallCandidates(
  tool: string,
  explicitServer: string | undefined,
  configServers: readonly string[],
): string[] {
  const candidates: string[] = [];
  const qualified = parseQualifiedToolName(tool);
  const servers = normalizedConfigServers(configServers);

  let server = explicitServer ?? qualified?.server;
  const bareTool = qualified?.tool ?? tool;

  if (server !== undefined && server.length > 0) {
    if (bareTool.startsWith(`${server}_`)) {
      pushUnique(candidates, bareTool);
    } else {
      pushUnique(candidates, `${server}_${bareTool}`);
      pushUnique(candidates, `${server}:${bareTool}`);
    }
    pushUnique(candidates, server);
    pushUnique(candidates, bareTool);
    pushUnique(candidates, tool);
  } else {
    // No explicit server: try the longest configured `<server>_` prefix.
    let prefixMatch: string | undefined;
    for (const config of servers) {
      if (bareTool.startsWith(`${config}_`) && (prefixMatch === undefined || config.length > prefixMatch.length)) {
        prefixMatch = config;
      }
    }
    if (prefixMatch !== undefined) {
      pushUnique(candidates, bareTool);
      pushUnique(candidates, prefixMatch);
    } else {
      // Or a `_<server>` suffix against configured names.
      let suffixMatch: string | undefined;
      for (const config of servers) {
        if (bareTool.endsWith(`_${config}`) && (suffixMatch === undefined || config.length > suffixMatch.length)) {
          suffixMatch = config;
        }
      }
      if (suffixMatch !== undefined) {
        pushUnique(candidates, `${suffixMatch}_${bareTool}`);
        pushUnique(candidates, `${suffixMatch}:${bareTool}`);
        pushUnique(candidates, suffixMatch);
      }
      pushUnique(candidates, bareTool);
      pushUnique(candidates, tool);
    }
  }

  pushUnique(candidates, MCP_CALL_CANDIDATE);
  return candidates;
}

/** Candidates for one MCP proxy invocation, by operation priority. */
export function generateMcpProxyCandidates(
  args: McpProxyArguments,
  configServers: readonly string[],
): string[] {
  const server = nonEmptyString(args.server);
  const tool = nonEmptyString(args.tool);
  if (tool !== undefined) return toolCallCandidates(tool, server, configServers);

  const connect = nonEmptyString(args.connect);
  if (connect !== undefined) {
    const candidates: string[] = [];
    pushUnique(candidates, `connect:${connect}`);
    pushUnique(candidates, server);
    pushUnique(candidates, MCP_CONNECT_CANDIDATE);
    return candidates;
  }

  const describe = nonEmptyString(args.describe);
  if (describe !== undefined) {
    const candidates = toolCallCandidates(describe, server, configServers);
    candidates.pop(); // replace the call category with the describe category
    pushUnique(candidates, MCP_DESCRIBE_CANDIDATE);
    return candidates;
  }

  const search = nonEmptyString(args.search);
  if (search !== undefined) {
    const candidates: string[] = [];
    pushUnique(candidates, server);
    pushUnique(candidates, `search:${search}`);
    pushUnique(candidates, MCP_SEARCH_CANDIDATE);
    return candidates;
  }

  if (server !== undefined) {
    return [server, MCP_LIST_CANDIDATE];
  }
  return [MCP_STATUS_CANDIDATE];
}

/** Sanitize a name for config matching: non-ASCII-alphanumeric/underscore become `_`. */
export function sanitizeMcpName(name: string): string {
  return name.replace(/[^A-Za-z0-9_]/g, "_");
}

/**
 * Candidates for a Pi MCP tool name (`mcp__<server>__<tool>`). The server
 * is the longest sanitized match among configured servers, else the part
 * before the first double underscore.
 */
export function generatePiMcpCandidates(
  fullName: string,
  serverPart: string,
  toolPart: string,
  configServers: readonly string[],
): string[] {
  const servers = normalizedConfigServers(configServers);
  const sanitizedServer = sanitizeMcpName(serverPart);

  let chosen: string | undefined;
  for (const config of servers) {
    if (sanitizeMcpName(config) === sanitizedServer) {
      chosen = config;
      break;
    }
  }
  chosen ??= serverPart;

  const spellings: string[] = [];
  pushUnique(spellings, chosen);
  pushUnique(spellings, sanitizeMcpName(chosen));

  const candidates: string[] = [];
  for (const spelling of spellings) {
    pushUnique(candidates, `${spelling}_${toolPart}`);
    pushUnique(candidates, `${spelling}:${toolPart}`);
    pushUnique(candidates, spelling);
  }
  pushUnique(candidates, toolPart);
  pushUnique(candidates, fullName);
  pushUnique(candidates, MCP_CALL_CANDIDATE);
  return candidates;
}
