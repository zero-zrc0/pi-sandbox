/**
 * Sandbox-hosted third-party tools (design §6).
 *
 * A rule whose `sandbox` field is set declares one tool module that pi-sandbox
 * exposes to the model and runs inside the OS sandbox. Two execution paths
 * exist for the same metadata:
 *
 * - the sandbox path (restricted modes) runs one worker process inside the
 *   selected native sandbox and is driven by the execution adapter;
 * - the host path (`full-access`) imports the module in this process, exactly
 *   like every other tool in that mode.
 *
 * The host never imports a module to read its metadata: name, description and
 * parameter schema come from the declaration.
 */
import { createRequire } from "node:module";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { formatPiSandboxError } from "../error-format";
import type { ApprovalChainConfigSnapshot } from "#config/owner";
import type { JsonValue } from "../json";
import type { AnyToolDefinition } from "./pi";

/** Upper bound for one sandbox tool call; the host terminates the worker. */
export const SANDBOX_TOOL_TIMEOUT_MS = 60_000;

/** Default parameter schema for a tool that takes no declared arguments. */
export const EMPTY_TOOL_PARAMETERS = Object.freeze({
  type: "object",
  properties: {},
  additionalProperties: false,
});

/** Everything one declared sandbox tool needs at registration time. */
export interface SandboxToolSpec {
  readonly name: string;
  /** Absolute path of the module the worker imports. */
  readonly modulePath: string;
  /** Directory granted read access so the module's own imports resolve. */
  readonly moduleDirectory: string;
  /** `.pi/sandbox-tools/<tool>/`, the tool's only writable context. */
  readonly stateDirectory: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  readonly config?: JsonValue;
  readonly scope: "global" | "project";
}

export interface SandboxToolSpecDiagnostic {
  readonly ruleId: string;
  readonly name: string;
  readonly reason: string;
}

export interface SandboxToolSpecsResult {
  readonly specs: readonly SandboxToolSpec[];
  readonly diagnostics: readonly SandboxToolSpecDiagnostic[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** Concrete tool names only: a wildcard cannot name one registrable tool. */
function isConcreteToolName(value: string): boolean {
  return !value.includes("*") && !value.includes("?");
}

/** Resolve `<package>/<entry>` from the declaring scope's directory. */
function resolvePackageModule(
  scopeDirectory: string,
  packageName: string,
  entry: string | undefined,
): string | undefined {
  const subpath = entry === undefined ? "" : entry.replace(/^\.\//u, "");
  const request = subpath.length === 0 ? packageName : `${packageName}/${subpath}`;
  try {
    const requireFromScope = createRequire(join(scopeDirectory, "__pi_sandbox_resolve__.js"));
    const resolved = requireFromScope.resolve(request);
    return isAbsolute(resolved) ? resolved : undefined;
  } catch {
    return undefined;
  }
}

/** The state directory is per tool and created by the host before execution. */
export function sandboxToolStateDirectory(cwd: string, toolName: string): string {
  return join(cwd, ".pi", "sandbox-tools", toolName);
}

/**
 * Derive the registrable tool specs from the effective rule table. The first
 * declaration of one name wins; a declaration that cannot be resolved is
 * reported once instead of failing the whole configuration.
 */
export function resolveSandboxToolSpecs(
  snapshot: Pick<ApprovalChainConfigSnapshot, "toolRules" | "paths" | "cwd">,
  cwd: string,
): SandboxToolSpecsResult {
  const specs: SandboxToolSpec[] = [];
  const diagnostics: SandboxToolSpecDiagnostic[] = [];
  const seen = new Set<string>();
  // A local `path` resolves relative to the project root (the workspace) in
  // both scopes; a `package` resolves from the declaring scope's directory, so
  // a global declaration can name a globally installed package.
  const workspaceDirectory = snapshot.cwd;
  const projectDirectory = snapshot.paths.projectConfigDir;
  const globalDirectory = snapshot.paths.globalConfigDir;
  for (const entry of snapshot.toolRules) {
    const rule = entry.rule;
    const sandbox = rule.sandbox;
    if (rule.decision !== "allow" || sandbox === undefined) continue;
    const name = rule.match.tool;
    if (!nonEmpty(name) || !isConcreteToolName(name)) {
      diagnostics.push({ ruleId: rule.id, name, reason: "tool-name-not-concrete" });
      continue;
    }
    if (seen.has(name)) continue;
    const scopeDirectory = entry.scope === "project" ? projectDirectory : globalDirectory;
    let modulePath: string | undefined;
    if (sandbox.path !== undefined) {
      modulePath = isAbsolute(sandbox.path) ? sandbox.path : resolve(workspaceDirectory, sandbox.path);
    } else if (sandbox.package !== undefined) {
      modulePath = resolvePackageModule(scopeDirectory, sandbox.package, sandbox.entry);
    }
    if (modulePath === undefined || !existsSync(modulePath) || !statSync(modulePath).isFile()) {
      diagnostics.push({ ruleId: rule.id, name, reason: "module-not-found" });
      continue;
    }
    const stateDirectory = sandboxToolStateDirectory(cwd, name);
    try {
      mkdirSync(stateDirectory, { recursive: true });
    } catch {
      diagnostics.push({ ruleId: rule.id, name, reason: "state-directory-unavailable" });
      continue;
    }
    seen.add(name);
    specs.push(Object.freeze({
      name,
      modulePath,
      moduleDirectory: dirname(modulePath),
      stateDirectory,
      description: sandbox.description ?? `Sandbox-hosted tool ${name}.`,
      parameters: isPlainObject(sandbox.parameters) ? sandbox.parameters : EMPTY_TOOL_PARAMETERS,
      ...(sandbox.config === undefined ? {} : { config: sandbox.config as JsonValue }),
      scope: entry.scope,
    }));
  }
  return { specs: Object.freeze(specs), diagnostics: Object.freeze(diagnostics) };
}

/**
 * Whether the effective rule table still declares concrete tool `name` as a
 * sandbox tool.
 *
 * `resolveSandboxToolSpecs` derives every registrable tool (and every
 * diagnostic) from exactly this declaration shape, so this predicate is the
 * live counterpart of that resolution: it stays true for a declared name whose
 * module cannot be resolved (that path keeps its own reason) and turns false as
 * soon as the rule is removed or loses its `sandbox` field. It deliberately does
 * not repeat the resolution checks (module exists, state directory usable,
 * name is concrete — the last is enforced at config load). Deriving it per
 * call, instead of remembering retired names in the process, keeps one
 * session's rule table from retiring a name another session still declares.
 */
export function declaresSandboxTool(
  snapshot: Pick<ApprovalChainConfigSnapshot, "toolRules">,
  name: string,
): boolean {
  return snapshot.toolRules.some((entry) =>
    entry.rule.decision === "allow" &&
    entry.rule.sandbox !== undefined &&
    entry.rule.match.tool === name);
}

export interface SandboxToolHostContext {
  readonly cwd: string;
  readonly signal?: AbortSignal;
}

/** Shape of one tool module result; an invalid shape is an execution error. */
function readToolResult(value: unknown): { content: readonly unknown[]; details?: unknown; isError?: boolean } {
  if (!isPlainObject(value) || !Array.isArray(value.content)) {
    throw new Error(formatPiSandboxError("sandbox-tool-invalid-result: execute() must return { content: [...] }"));
  }
  return value as unknown as { content: readonly unknown[]; details?: unknown; isError?: boolean };
}

/**
 * Import one tool module in the host process and call its `execute`.
 *
 * Used only in `full-access`, where there is no sandbox to enter. The module is
 * still loaded by path: the host never imports plugin code for metadata, and a
 * load failure stays a readable tool error (`sandbox-tool-not-loadable`).
 */
export async function runSandboxToolOnHost(
  spec: SandboxToolSpec,
  args: unknown,
  context: SandboxToolHostContext,
): Promise<{ content: readonly unknown[]; details?: unknown; isError?: boolean }> {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort();
  if (context.signal !== undefined) {
    if (context.signal.aborted) controller.abort();
    else context.signal.addEventListener("abort", forwardAbort, { once: true });
  }
  let module: { execute?: unknown; probe?: unknown };
  try {
    module = await import(pathToFileURL(spec.modulePath).href) as { execute?: unknown; probe?: unknown };
  } catch (error) {
    throw new Error(formatPiSandboxError(`sandbox-tool-not-loadable: ${spec.name}: ${error instanceof Error ? error.message : String(error)}`));
  }
  if (typeof module.execute !== "function") {
    throw new Error(formatPiSandboxError(`sandbox-tool-not-loadable: ${spec.name}: module does not export execute()`));
  }
  if (typeof module.probe === "function") {
    try {
      await (module.probe as () => unknown)();
    } catch (error) {
      throw new Error(formatPiSandboxError(`sandbox-tool-not-loadable: ${spec.name}: ${error instanceof Error ? error.message : String(error)}`));
    }
  }
  try {
    const result = await (module.execute as (input: unknown, ctx: unknown) => unknown)(args, {
      cwd: context.cwd,
      stateDirectory: spec.stateDirectory,
      config: spec.config,
      toolName: spec.name,
      signal: controller.signal,
    });
    return readToolResult(result);
  } catch (error) {
    throw new Error(formatPiSandboxError(error));
  } finally {
    if (context.signal !== undefined) context.signal.removeEventListener("abort", forwardAbort);
  }
}

/** Definition metadata shared by both execution paths. */
export function sandboxToolDefinitionFields(spec: SandboxToolSpec): {
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
} {
  return {
    name: spec.name,
    description: spec.description,
    parameters: spec.parameters,
  };
}

/** The `full-access` definition: the same module, imported on the host. */
export function createHostSandboxToolDefinition(
  spec: SandboxToolSpec,
  options: {
    /** Re-check at call time that the declaring rule still exists. */
    readonly isDeclared?: (ctx: { readonly cwd?: string; readonly sessionManager?: unknown }) => boolean;
  } = {},
): AnyToolDefinition {
  return {
    ...sandboxToolDefinitionFields(spec),
    execute: async (toolCallId: string, args: unknown, signal?: AbortSignal, _onUpdate?: unknown, ctx?: { cwd?: string }) => {
      if (options.isDeclared !== undefined && !options.isDeclared(ctx ?? {})) {
        throw new Error(formatPiSandboxError(`sandbox-tool-not-declared: ${spec.name}`));
      }
      return runSandboxToolOnHost(spec, args, {
        cwd: typeof ctx?.cwd === "string" ? ctx.cwd : process.cwd(),
        ...(signal === undefined ? {} : { signal }),
      }) as never;
    },
  } as unknown as AnyToolDefinition;
}
