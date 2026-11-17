import {
  createBashToolDefinition, createPowerShellToolDefinition, createReadToolDefinition,
  createWriteToolDefinition, createEditToolDefinition, createGrepToolDefinition,
  createFindToolDefinition, createLsToolDefinition, createMcpExtension, getAgentDir,
  type McpExtensionOptions,
  type ExtensionAPI, type ExtensionContext, type ToolCallEvent, type ExtensionToolContext,
} from "@earendil-works/pi-coding-agent";
import { join, resolve } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { fileURLToPath } from "node:url";
import type { ApprovalChainConfigSnapshot } from "../config/owner";
import { getActiveAgentName } from "../approve-core/host/active-agent";
import { captureToolInvocationSeed, finalizeToolInvocation, type ToolInvocationFacts } from "../invocation";
import type { PermissionScope } from "../action";
import { jsonDigest, type JsonObject } from "../json";
import type { ToolAccessFactsResult } from "../approve-core/utils/tool-access/access-facts";
import { bindOwnedToolExecution, ToolInvocationBindingStore } from "./execution-binding";
import { ExecutionController } from "./lifecycle";
import { EgressService } from "./egress/index";
import { createPiExecutionAdapter, type AnyToolDefinition, type PiExecutionAdapter } from "./pi";
import { selectExecutionEnvironment } from "./plan";
import { findSystemBubblewrap } from "./backend/linux/bwrap-selection.mjs";
import { prepareMacOSHelperProcess } from "./backend/macos/index";
import { toRuntimeNetworkScope } from "./network-scope";
import { BUILTIN_TOOL_NAMES, type ExecutionRecord, type FilesystemGrantInput } from "./types";
import { EXECUTION_INSTALL_ROOT } from "./platform";
import type { SandboxRuntimeState } from "./runtime-manager";
import type { ResolvedRuntimeFiles } from "./runtime-store";
import { acquireRuntimeUseLease } from "./runtime-installation";
import { ManagedMcpTransports } from "./mcp";
import { resolveHostPathIdentity, findProtectedControlRoot, isPathWithin } from "./path";
import { ensureSessionWorkspace } from "./session-workspace";
import { builtinToolPath, resolveTemporaryToolPath } from "./builtin-path";
import type { ToolElevation } from "../elevation";
import type { SandboxBypassReviewInput } from "../approve-core/host";
import { hasApprovedCodemodeScope } from "./codemode/approval-scope";
import {
  collectToolRuleLocations,
  evaluateToolRules,
  type ToolRuleMatch,
} from "../approve-core/policy/tool-rules";
import {
  createHostSandboxToolDefinition,
  declaresSandboxTool,
  resolveSandboxToolSpecs,
  type SandboxToolSpec,
} from "./sandbox-tools";

const OWNER = "pi-sandbox:controlled-execution";
const BINDING = "builtin-and-mcp:v1";
type Block = { block: true; reason: string; permissionDenied?: boolean };
type HostExecutionApproval = { kind: "host-execution"; reason: string };
type ReviewOutcome = Block | HostExecutionApproval | undefined;
type Review = (input?: { readonly ask?: boolean }) => Promise<ReviewOutcome>;
const factories = [createBashToolDefinition, createPowerShellToolDefinition, createReadToolDefinition,
  createWriteToolDefinition, createEditToolDefinition, createGrepToolDefinition,
  createFindToolDefinition, createLsToolDefinition];
const FILE_TOOL_NAMES = new Set(["read", "write", "edit", "grep", "find", "ls"]);

export interface ControlledExecutionOptions {
  readonly registrationPath?: string;
  readonly agentDir?: string;
  readonly snapshot: (ctx: ExtensionContext) => ApprovalChainConfigSnapshot;
  readonly controller?: (ctx: ExtensionContext, record: (record: ExecutionRecord) => void) => ExecutionController;
  readonly mcp?: Pick<ConstructorParameters<typeof ManagedMcpTransports>[0], "runConfigCommand"> & Pick<McpExtensionOptions, "loadConfig">;
  readonly runtime?: () => SandboxRuntimeState;
}

interface SessionExecution {
  readonly revision: string;
  readonly adapter: PiExecutionAdapter;
  readonly snapshot: ApprovalChainConfigSnapshot;
}

interface ManagedToolLifecycle {
  readonly cancelSession?: (sessionId: string) => Promise<void> | void;
}

/** One approval entry, followed by a one-shot binding at the actual owned execute. */
export function createControlledExecution(options: ControlledExecutionOptions) {
  const disabledShell = process.platform === "win32" ? "bash" : "powershell";
  const disabledShellReason = `sandbox-capability-unsupported: ${disabledShell} is disabled on ${process.platform}; use ${disabledShell === "bash" ? "powershell" : "bash"}`;
  const bindings = new ToolInvocationBindingStore();
  const egress = new EgressService();
  const sessions = new Map<string, SessionExecution>();
  const pendingSessions = new Map<string, Promise<SessionExecution>>();
  const epochs = new Map<string, number>();
  const closedSessions = new Set<string>();
  const retiring = new Map<string, Promise<void>>();
  const owned = new Map<string, AnyToolDefinition>();
  const hostExecutors = new Map<string, AnyToolDefinition>();
  const managedToolCancellers = new Map<string, NonNullable<ManagedToolLifecycle["cancelSession"]>>();
  const mcpCalls = new AsyncLocalStorage<{ attempted: boolean }>();
  const defaultCalls = new Map<string, import("./plan").PlanBaselineScope>();
  const agentDirectory = resolve(options.agentDir ?? getAgentDir());
  let api: ExtensionAPI;
  let activeContext: ExtensionContext | undefined;
  const runtimeState = () => options.runtime?.() ?? { status: "disabled" as const };
  const readyRuntime = (): ResolvedRuntimeFiles | undefined => {
    const state = runtimeState();
    return state.status === "ready" ? state.runtime : undefined;
  };
  const unavailableReason = (): string => {
    const state = runtimeState();
    if (state.status === "unavailable") return state.reason;
    if (state.status === "preparing") return "sandbox runtime preparation is still in progress";
    if (state.status === "disabled") return "sandbox runtime is disabled";
    return "sandbox runtime is unavailable";
  };
  const revision = (snapshot: ApprovalChainConfigSnapshot) => {
    const state = runtimeState();
    return jsonDigest({
      config: snapshot.config,
      invalid: snapshot.source === "invalid" || snapshot.projectConfigInvalid,
      sandboxRuntime: state.status === "ready" ? { status: state.status, version: state.runtime.manifest.version,
        directory: state.runtime.directory } : { status: state.status },
    });
  };
  function sessionWorkspace(ctx: ExtensionContext): string {
    return ensureSessionWorkspace(agentDirectory, ctx.sessionManager.getSessionId());
  }
  const baselineFilesystem = (ctx: ExtensionContext, mode: ApprovalChainConfigSnapshot["config"]["mode"]): FilesystemGrantInput[] => {
    const workspace = sessionWorkspace(ctx);
    const readOnly = mode === "read-only";
    return [{ path: ctx.cwd, access: "read", granularity: "directory" },
      { path: workspace, access: "read", granularity: "directory" },
      ...(readOnly ? [] : [{ path: workspace, access: "write" as const, granularity: "directory" as const }]),
      ...(readOnly ? [] : [{ path: ctx.cwd, access: "write" as const, granularity: "directory" as const }])];
  };
  const environment = () => selectExecutionEnvironment(process.env as Record<string, string>);
  const executionEnvironment = (ctx: ExtensionContext) => {
    const config = options.snapshot(ctx).config;
    if (config.mode === "full-access" || !config.experimental.sandboxEnabled) return environment();
    const workspace = sessionWorkspace(ctx);
    const temporary = join(workspace, "tmp");
    return { ...environment(), PI_SANDBOX_WORK_DIR: workspace, TEMP: temporary, TMP: temporary, TMPDIR: temporary };
  };
  const snapshot = (ctx: ExtensionContext) => options.snapshot(ctx);

  /**
   * A sandboxed session keeps its temporary files in the session workspace,
   * but file-tool arguments are not shell-expanded: a literal `$TMPDIR`
   * would name a project entry while the sandboxed shell resolves it to the
   * workspace. Rewrite that spelling once, before rules, approval, capture
   * and the tool itself read it, so the read or write targets the temporary
   * directory the sandbox actually grants.
   */
  function mapTemporaryFilePath(event: ToolCallEvent, ctx: ExtensionContext): void {
    if (!FILE_TOOL_NAMES.has(event.toolName)) return;
    const input = event.input as Record<string, unknown>;
    const path = input.path;
    if (typeof path !== "string") return;
    const current = snapshot(ctx);
    if (current.config.mode === "full-access") return;
    const host = environment();
    const temporaryRoot = current.config.experimental.sandboxEnabled
      ? executionEnvironment(ctx).TMPDIR
      : host.TMPDIR;
    const mapped = resolveTemporaryToolPath(path, host, temporaryRoot);
    if (mapped !== undefined) input.path = mapped;
  }
  const host = {
    getAllTools: () => api.getAllTools(),
    readRequester: (ctx: ExtensionToolContext) => ({ sessionId: ctx.sessionManager.getSessionId(), agentName: getActiveAgentName(ctx) ?? null }),
    readEnvironment: executionEnvironment,
    verifyScope: (_invocation: unknown, ctx: ExtensionToolContext, approved: string) => {
      const current = revision(snapshot(ctx));
      return { allowed: approved === current, revision: current };
    },
    readCurrentScopeRevision: (ctx: ExtensionToolContext) => revision(snapshot(ctx)),
  };
  const mcp = new ManagedMcpTransports({
    revision: () => {
      if (!activeContext) throw new Error("MCP session is unavailable");
      const current = snapshot(activeContext);
      return `${activeContext.sessionManager.getSessionId()}:${revision(current)}`;
    },
    ...options.mcp,
    onRequest: () => { const call = mcpCalls.getStore(); if (call) call.attempted = true; },
  });

  function cancelManagedSession(id: string): Promise<void> {
    return Promise.all([...managedToolCancellers.values()].map(cancel => cancel(id))).then(() => undefined);
  }

  function owns(name: string): boolean {
    const definition = owned.get(name);
    if (definition?.exposure === "hidden") return false;
    return isCurrentOwnedDefinition(name, definition);
  }

  function isCurrentOwnedDefinition(
    name: string,
    definition = owned.get(name),
  ): boolean {
    const visible = api.getAllTools().filter(tool => tool.name === name);
    const path = visible[0]?.sourceInfo?.path;
    const expected = options.registrationPath ?? fileURLToPath(new URL("../index.ts", import.meta.url));
    const normalize = (value: string) => process.platform === "win32" ? resolve(value).toLowerCase() : resolve(value);
    return definition !== undefined && visible.length === 1 && visible[0]!.parameters === definition.parameters &&
      typeof path === "string" && normalize(path) === normalize(expected);
  }

  async function createSessionExecution(ctx: ExtensionContext): Promise<SessionExecution> {
    activeContext = ctx;
    const id = ctx.sessionManager.getSessionId();
    const epoch = epochs.get(id) ?? 0;
    const current = snapshot(ctx);
    if (current.config.mode !== "full-access" && current.config.experimental.sandboxEnabled) sessionWorkspace(ctx);
    const key = revision(current);
    const previous = sessions.get(id);
    if (previous?.revision === key) return previous;
    // Revoke both paths before waiting for either process owner to close.
    void cancelManagedSession(id).catch(() => undefined);
    egress.closeSession(id);
    bindings.clearSession(id);
    const previousRetirement = retiring.get(id);
    const closingAdapter = Promise.all([previousRetirement, previous?.adapter.dispose()]);
    const closingMcp = mcp.synchronize();
    await Promise.all([closingAdapter, closingMcp]);
    if (closedSessions.has(id) || epoch !== (epochs.get(id) ?? 0)) throw new Error("session-disposed: execution session changed during preparation");
    if (retiring.get(id) === previousRetirement) retiring.delete(id);
    const record = (record: ExecutionRecord) => api.appendEntry("permission:execution", {
      sessionId: id,
      executionMode: "sandbox",
      ...record,
    });
    const runtime = current.config.experimental.sandboxEnabled ? readyRuntime() : undefined;
    const runtimeStorageRoot = runtime?.storageRoot;
    // The macOS runtime is the system sandbox-exec: it has no storage root,
    // no use lease and no runtime directory to pass or protect.
    const macOSSystemRuntime = runtime?.manifest.platform === "darwin";
    const backendId = runtime?.manifest.backendId ?? "unsupported-platform";
    const currentEnvironment = environment();
    const systemBubblewrapPath = process.platform === "linux" && runtime !== undefined
      ? findSystemBubblewrap(currentEnvironment.PATH, ctx.cwd)
      : undefined;
    const controller = options.controller?.(ctx, record) ?? new ExecutionController({
      ...(!runtime ? { unavailableReason: current.config.experimental.sandboxEnabled
        ? unavailableReason() : "the Sandbox total switch is off" } : {}),
      installation: {
        installRoot: EXECUTION_INSTALL_ROOT,
        executable: process.execPath,
        args: [fileURLToPath(new URL(`./backend/${process.platform === "linux" ? "linux" : process.platform === "darwin" ? "macos" : "windows"}/helper.mjs`, import.meta.url))],
        expectedBackendId: backendId,
      },
      ...(runtime === undefined || macOSSystemRuntime ? {} : {
        runtimeUseLease: () => acquireRuntimeUseLease({
          storageRoot: runtime.storageRoot,
          platform: runtime.manifest.platform,
          arch: runtime.manifest.arch,
        }),
      }),
      ...(process.platform === "darwin" ? { prepareHelperProcess: prepareMacOSHelperProcess } : {}),
      helperCwd: resolve(process.env.TEMP ?? process.env.TMPDIR ?? "/tmp"),
      workspace: ctx.cwd, helperEnvironment: {
        ...currentEnvironment, PI_MXC_AGENT_DIR: agentDirectory,
        PI_SANDBOX_WORKSPACE_ROOT: resolve(ctx.cwd),
        ...(process.env.LOCALAPPDATA ? { LOCALAPPDATA: process.env.LOCALAPPDATA } : {}),
        ...(runtime === undefined || macOSSystemRuntime ? {} : {
          PI_SANDBOX_RUNTIME_DIR: runtime.directory,
          PI_SANDBOX_RUNTIME_ROOT: runtimeStorageRoot!,
        }),
        ...(systemBubblewrapPath === undefined ? {} : { PI_SANDBOX_SYSTEM_BWRAP_PATH: systemBubblewrapPath }),
      }, onRecord: record,
      egress: {
        acquire: async plan => {
          const acquired = await egress.acquireForPlan(plan);
          if (!acquired) return null;
          if (process.platform !== "win32") return acquired.grant;
          try {
            const forwarder = await egress.openForwarder(acquired.grant);
            return { ...acquired.grant, proxyHost: forwarder.host, proxyPort: forwarder.port };
          } catch {
            egress.revoke(acquired.grant.leaseId);
            return null;
          }
        },
        revoke: leaseId => { egress.revoke(leaseId); },
      },
    });
    const sandboxTools = resolveSandboxToolSpecs(current, ctx.cwd);
    const adapter = createPiExecutionAdapter({ controller, bindings, host, owner: OWNER, bindingId: BINDING,
      cwd: ctx.cwd,
      sandboxTools: sandboxTools.specs,
      plan: {
        mode: current.config.mode, configRevision: key,
        backendId,
        protectedPaths: [EXECUTION_INSTALL_ROOT,
          ...(runtime === undefined || macOSSystemRuntime ? [] : [runtimeStorageRoot!, runtime.directory]),
          ...(systemBubblewrapPath === undefined ? [] : [systemBubblewrapPath])],
        ...(current.config.execution.shell === undefined ? {} : {
          shellBaseline: {
            filesystem: [
              ...current.config.execution.shell.filesystem.read.map(grant => ({
                path: grant.path,
                access: "read" as const,
                granularity: grant.granularity,
              })),
              ...current.config.execution.shell.filesystem.write.map(grant => ({
                path: grant.path,
                access: "write" as const,
                granularity: grant.granularity,
              })),
            ],
            network: toRuntimeNetworkScope(current.config.execution.shell.network),
          },
        }),
        baseline: {
          filesystem: baselineFilesystem(ctx, current.config.mode),
          network: current.config.execution.network === undefined ? { kind: "none" } : toRuntimeNetworkScope(current.config.execution.network),
        },
        oneCallDefault: invocation => defaultCalls.get(hostExecutionKey(invocation.requester.sessionId, invocation.action.toolCallId)),
        networkCeiling: current.config.execution.network === undefined ? { kind: "none" } : toRuntimeNetworkScope(current.config.execution.network),
        readConfigRevision: () => revision(snapshot(ctx)),
        environment: executionEnvironment(ctx),
      },
    });
    const created = { revision: key, adapter, snapshot: current };
    sessions.set(id, created);
    synchronizeSandboxTools(sandboxTools, ctx);
    return created;
  }

  /**
   * pi tool definitions registered per sandbox tool name. The registry is
   * process-wide and never pruned: whichever session synchronizes last decides
   * the definition metadata. Retirement is derived from the calling session's
   * rule table instead of this map, so entries may outlive their declaration.
   */
  const registeredSandboxTools = new Map<string, SandboxToolSpec>();

  function sameSandboxSpec(left: SandboxToolSpec, right: SandboxToolSpec): boolean {
    return left.modulePath === right.modulePath &&
      left.stateDirectory === right.stateDirectory &&
      left.description === right.description &&
      JSON.stringify(left.parameters) === JSON.stringify(right.parameters) &&
      JSON.stringify(left.config ?? null) === JSON.stringify(right.config ?? null);
  }

  /**
   * Expose one pi tool per declared sandbox tool (design §6.1). Metadata comes
   * from the declaration; execution paths resolve the module by path.
   *
   * The host offers no unregister call, so a rule that disappears leaves its
   * definition visible to the model. The gate derives retirement from the live
   * rule table (`declaresSandboxTool`) instead of remembering names here: a
   * name declines only for the session whose own rule table stopped declaring
   * it, and a declaration that still exists but cannot resolve is not retired,
   * so its own `sandbox-tool-not-declared` reason stays reachable.
   */
  function synchronizeSandboxTools(result: ReturnType<typeof resolveSandboxToolSpecs>, ctx: ExtensionContext): void {
    const sessionId = ctx.sessionManager.getSessionId();
    for (const diagnostic of result.diagnostics) {
      try {
        api.appendEntry("permission:tool-rule", { kind: "sandbox-tool-diagnostic", sessionId, ...diagnostic });
      } catch {
        // Diagnostics are advisory.
      }
    }
    for (const spec of result.specs) {
      const previous = registeredSandboxTools.get(spec.name);
      if (previous !== undefined && sameSandboxSpec(previous, spec)) continue;
      registeredSandboxTools.set(spec.name, spec);
      register(createHostSandboxToolDefinition(spec, {
        isDeclared: (callContext) => {
          const toolContext = callContext as ExtensionToolContext | undefined;
          const live = toolContext?.sessionManager === undefined
            ? sessions.get(sessionId)?.snapshot
            : snapshot(toolContext);
          return live !== undefined && declaresSandboxTool(live, spec.name);
        },
      }), true);
      try {
        api.appendEntry("permission:tool-rule", {
          kind: "sandbox-tool-registered",
          sessionId,
          toolName: spec.name,
          scope: spec.scope,
          modulePath: spec.modulePath,
          stateDirectory: spec.stateDirectory,
        });
      } catch {
        // Registration itself already happened.
      }
    }
  }

  function session(ctx: ExtensionContext): Promise<SessionExecution> {
    const id = ctx.sessionManager.getSessionId();
    if (closedSessions.has(id)) return Promise.reject(new Error("session-disposed"));
    const pending = pendingSessions.get(id);
    if (pending) return pending.then(() => session(ctx));
    const creating = createSessionExecution(ctx);
    pendingSessions.set(id, creating);
    void creating.finally(() => {
      if (pendingSessions.get(id) === creating) pendingSessions.delete(id);
    }).catch(() => undefined);
    return creating;
  }

  function register(definition: AnyToolDefinition, builtin: boolean, lifecycle?: ManagedToolLifecycle) {
    const original = definition;
    if (lifecycle === undefined) hostExecutors.set(definition.name, original);
    if (lifecycle?.cancelSession) managedToolCancellers.set(definition.name, lifecycle.cancelSession);
    const fullAccessBuiltin = builtin ? bindOwnedToolExecution(definition, {
      ...host, owner: OWNER, bindingId: BINDING, bindings, failureDetails: {},
      executeAuthorized: async (invocation, execute) => {
        const record = recordIdentity(invocation);
        try {
          const result = await execute();
          api.appendEntry("permission:execution", { ...record, executionMode: "host", started: true, impact: "known",
            state: result.isError ? "failed" : "completed", ...(result.isError ? { code: "execution-failed" } : {}) });
          return result;
        } catch (error) {
          api.appendEntry("permission:execution", { ...record, executionMode: "host", started: true, impact: "unknown", state: "failed", code: "execution-failed" });
          throw error;
        }
      },
    }) : undefined;
    const controlled = builtin ? { ...definition, execute: async (...args: Parameters<AnyToolDefinition["execute"]>) => {
      const ctx = args[4];
      const current = await session(ctx);
      if (current.snapshot.config.mode === "full-access" || !current.snapshot.config.experimental.sandboxEnabled) {
        return fullAccessBuiltin!.execute(...args);
      }
      const target = current.adapter.definitions.find(tool => tool.name === original.name);
      if (!target || !owns(original.name)) throw new Error("sandbox-unmanaged-tool: owned builtin registration was replaced");
      return target.execute(...args);
    } } : bindOwnedToolExecution(definition, {
      ...host, owner: OWNER, bindingId: BINDING, bindings, failureDetails: {},
      executeAuthorized: async (invocation, execute) => {
        const call = { attempted: false };
        const record = recordIdentity(invocation);
        try {
          if (lifecycle !== undefined) {
            const result = await execute();
            api.appendEntry("permission:execution", { ...record,
              executionMode: sessions.get(record.sessionId)?.snapshot.config.mode === "full-access" ? "host" : "sandbox",
              started: true, impact: "known", state: result.isError ? "failed" : "completed",
              ...(result.isError ? { code: "execution-failed" } : {}) });
            return result;
          }
          const result = await mcpCalls.run(call, execute);
          api.appendEntry("permission:execution", { ...record,
            executionMode: "host",
            started: call.attempted,
            state: result.isError ? "failed" : "completed", impact: call.attempted ? "known" : "none",
            ...(result.isError ? { code: "execution-failed" } : {}) });
          return result;
        } catch (error) {
          api.appendEntry("permission:execution", { ...record,
            executionMode: "host",
            started: call.attempted ? "unknown" : false,
            state: "failed", code: "execution-failed", impact: call.attempted ? "unknown" : "none" });
          throw error;
        }
      },
    });
    const registered = builtin ? controlled : { ...controlled, execute: async (...args: Parameters<AnyToolDefinition["execute"]>) => {
      await session(args[4]);
      if (!owns(original.name)) throw new Error("sandbox-unmanaged-tool: MCP registration was replaced");
      return controlled.execute(...args);
    } };
    const exposed = builtin && definition.name === disabledShell ? {
      ...registered, exposure: "hidden" as const,
      execute: async () => { throw new Error(disabledShellReason); },
    } : registered;
    owned.set(definition.name, exposed);
    api.registerTool(exposed);
  }

  function recordIdentity(invocation: ToolInvocationFacts) {
    const id = invocation.requester.sessionId;
    return { sessionId: id, requestId: invocation.action.requestId, toolCallId: invocation.action.toolCallId,
      actionDigest: invocation.digest, planDigest: jsonDigest({ invocation: invocation.digest, policy: sessions.get(id)?.revision ?? "retired" }),
      generation: epochs.get(id) ?? 0, toolName: invocation.action.tool.name };
  }

  function hostExecutionKey(sessionId: string, toolCallId: string): string {
    return JSON.stringify([sessionId, toolCallId]);
  }

  /** Persist the rule decision that admitted or refused one call (design §5.4). */
  function auditToolRule(
    sessionId: string,
    event: ToolCallEvent,
    match: ToolRuleMatch,
    reason?: string,
  ): void {
    if (match.kind === "ask") return;
    try {
      api.appendEntry("permission:tool-rule", {
        sessionId,
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        decision: match.kind,
        ruleId: match.ruleId,
        scope: match.scope,
        argumentLevel: match.argumentLevel,
        ...(reason === undefined ? {} : { reason }),
      });
    } catch {
      // Audit is advisory and never changes an admission decision.
    }
  }

  function configurationChanged(id: string): void {
    void cancelManagedSession(id).catch(() => undefined);
    egress.closeSession(id);
    bindings.clearSession(id);
    clearElevations(id);
    epochs.set(id, (epochs.get(id) ?? 0) + 1);
    const previous = sessions.get(id);
    sessions.delete(id);
    const closing = Promise.all([retiring.get(id), previous?.adapter.dispose(), mcp.synchronize()]).then(() => undefined);
    retiring.set(id, closing);
    void closing.catch(() => undefined);
  }

  function clearElevations(sessionId: string): void {
    for (const key of defaultCalls.keys()) if (key.startsWith(`${sessionId}:`)) defaultCalls.delete(key);
  }

  function fileTarget(name: string, args: Record<string, unknown>, ctx: ExtensionContext):
    { readonly path: string; readonly accesses: readonly ("read" | "write")[] } | null | undefined {
    if (!["read", "write", "edit", "grep", "find", "ls"].includes(name)) return undefined;
    const pathValue = args.path ?? ".";
    if (typeof pathValue !== "string") return null;
    let target: string | null;
    try {
      target = resolveHostPathIdentity(builtinToolPath(name as import("./types").BuiltinToolName, pathValue, ctx.cwd));
    } catch {
      return null;
    }
    if (target === null) return null;
    const accesses = name === "write" ? ["write"] as const
      : name === "edit" ? ["read", "write"] as const
        : ["read"] as const;
    return { path: target, accesses };
  }

  function missingFileAccesses(
    target: NonNullable<ReturnType<typeof fileTarget>>,
    ctx: ExtensionContext,
  ): readonly ("read" | "write")[] | null {
    const baseline = baselineFilesystem(ctx, snapshot(ctx).config.mode).map(grant => ({
      ...grant,
      path: resolveHostPathIdentity(grant.path),
    }));
    if (baseline.some(grant => grant.path === null)) return null;
    return target.accesses.filter(access => !baseline.some(grant => grant.access === access &&
      isPathWithin(grant.path!, target.path)));
  }

  function readOnlySessionWorkspaceWrite(target: NonNullable<ReturnType<typeof fileTarget>>, ctx: ExtensionContext): boolean {
    if (snapshot(ctx).config.mode !== "read-only" || !target.accesses.includes("write")) return false;
    const workspace = resolveHostPathIdentity(sessionWorkspace(ctx));
    return workspace !== null && isPathWithin(workspace, target.path);
  }

  function defaultWriteScope(ctx: ExtensionContext): ToolElevation["scope"] | null {
    const project = resolveHostPathIdentity(ctx.cwd);
    const workspace = resolveHostPathIdentity(sessionWorkspace(ctx));
    if (project === null || workspace === null) return null;
    return [{ path: project, access: "write" }, { path: workspace, access: "write" }];
  }

  function elevationScope(
    target: NonNullable<ReturnType<typeof fileTarget>>,
    accesses: readonly ("read" | "write")[],
    tier: ToolElevation["tier"],
    ctx: ExtensionContext,
  ):
    | { readonly ok: true; readonly elevation: ToolElevation }
    | { readonly ok: false; readonly reason: "default-scope-unverifiable" | "default-scope-exceeds-project-and-session-workspace" } {
    const scope = tier === "default"
      ? defaultWriteScope(ctx)
      : accesses.map(access => ({ path: target.path, access }));
    if (scope === null) return { ok: false, reason: "default-scope-unverifiable" };
    if (tier === "default" && !scope.some(grant => isPathWithin(grant.path, target.path))) {
      return { ok: false, reason: "default-scope-exceeds-project-and-session-workspace" };
    }
    return { ok: true, elevation: { tier, scope } };
  }

  function fileElevation(
    name: string,
    args: Record<string, unknown>,
    tier: ToolElevation["tier"],
    ctx: ExtensionContext,
  ): ToolElevation | undefined {
    const target = fileTarget(name, args, ctx);
    if (target === undefined || target === null || findProtectedControlRoot(target.path) !== null) return undefined;
    const accesses = missingFileAccesses(target, ctx);
    if (accesses === null || accesses.length === 0) return undefined;
    const scope = elevationScope(target, accesses, tier, ctx);
    return scope.ok ? scope.elevation : undefined;
  }
  function ordinaryFileScopeBlock(name: string, args: Record<string, unknown>, ctx: ExtensionContext): Block | undefined {
    const current = snapshot(ctx);
    if (current.config.mode === "full-access" || !current.config.experimental.sandboxEnabled) return undefined;
    const target = fileTarget(name, args, ctx);
    if (target === undefined) return undefined;
    if (target === null) return { block: true, reason: `permission:path-unverifiable:${String(args.path ?? ".")}` };
    if (findProtectedControlRoot(target.path) !== null) {
      return { block: true, reason: `permission:protected-control-path:${target.path}` };
    }
    if (readOnlySessionWorkspaceWrite(target, ctx)) {
      return { block: true, reason: `permission:mode:read-only:session-workspace-write-forbidden:${target.path}` };
    }
    const accesses = missingFileAccesses(target, ctx);
    if (accesses === null) return { block: true, reason: "permission:baseline-path-unverifiable" };
    if (accesses.length === 0) return undefined;
    const workspace = resolveHostPathIdentity(ctx.cwd);
    if (workspace === null) return { block: true, reason: "permission:workspace-path-unverifiable" };
    const tier = isPathWithin(workspace, target.path) ? "default" : "host";
    const scope = elevationScope(target, accesses, tier, ctx);
    if (!scope.ok) return { block: true, reason: `permission:${scope.reason}:${target.path}` };
    return {
      block: true,
      reason: `permission:elevation-required:${accesses.join("+")} ${target.path}; call request_tool_elevation with toolName "${name}", unchanged complete arguments, a reason, and tier "${tier}"`,
    };
  }

  return {
    sessionWorkspace(ctx: ExtensionContext): string { return sessionWorkspace(ctx); },
    prepareElevation(name: string, args: JsonObject, tier: ToolElevation["tier"], ctx: ExtensionToolContext): ToolElevation | Block {
      const current = snapshot(ctx);
      if (current.config.mode === "full-access" || !current.config.experimental.sandboxEnabled) {
        return { block: true, reason: "sandbox-bypass:elevation-not-available" };
      }
      if (!owns(name) || hostExecutors.get(name) === undefined) {
        return { block: true, reason: `sandbox-bypass:target-executor-unavailable:${name}` };
      }
      const target = fileTarget(name, args, ctx);
      if (target === undefined) return { block: true, reason: `sandbox-bypass:unsupported-target-tool:${name}` };
      if (target === null) return { block: true, reason: `sandbox-bypass:target-path-unverifiable:${String(args.path ?? ".")}` };
      if (findProtectedControlRoot(target.path) !== null) {
        return { block: true, reason: `sandbox-bypass:protected-target:${target.path}` };
      }
      const accesses = missingFileAccesses(target, ctx);
      if (accesses === null) return { block: true, reason: "sandbox-bypass:baseline-path-unverifiable" };
      if (accesses.length === 0) return { block: true, reason: `sandbox-bypass:elevation-not-needed:${target.path}` };
      const scope = elevationScope(target, accesses, tier, ctx);
      if (!scope.ok) {
        if (scope.reason === "default-scope-unverifiable") {
          return { block: true, reason: "sandbox-bypass:default-scope-unverifiable" };
        }
        return { block: true, reason: `sandbox-bypass:default-scope-exceeds-project-and-session-workspace:${target.path}; request tier host for this target` };
      }
      return scope.elevation;
    },
    validateElevation(name: string, args: JsonObject, elevation: ToolElevation, ctx: ExtensionToolContext): boolean {
      const current = fileElevation(name, args, elevation.tier, ctx);
      return !closedSessions.has(ctx.sessionManager.getSessionId()) && owns(name) &&
        snapshot(ctx).config.mode !== "full-access" && snapshot(ctx).config.experimental.sandboxEnabled &&
        current !== undefined && jsonDigest(current) === jsonDigest(elevation);
    },
    async executeDefault(input: SandboxBypassReviewInput, signal: AbortSignal | undefined,
      onUpdate: Parameters<AnyToolDefinition["execute"]>[3], ctx: ExtensionToolContext) {
      const current = await session(ctx);
      if (current.snapshot.config.mode === "full-access" || !current.snapshot.config.experimental.sandboxEnabled) {
        throw new Error("elevation:default-sandbox-unavailable");
      }
      const args = input.arguments as JsonObject;
      const expected = fileElevation(input.targetToolName, args, "default", ctx);
      if (input.elevation.tier !== "default" || expected?.tier !== "default" ||
        jsonDigest(expected) !== jsonDigest(input.elevation) || !owns(input.targetToolName)) {
        throw new Error("elevation:default-scope-invalidated");
      }
      const event = { type: "tool_call" as const, toolName: input.targetToolName, toolCallId: input.toolCallId, input: args };
      const seed = captureToolInvocationSeed({ event, registeredTools: api.getAllTools(), cwd: ctx.cwd,
        requester: host.readRequester(ctx), environment: executionEnvironment(ctx) });
      if (!seed.ok) throw new Error("elevation:binding-unavailable");
      const scopes: PermissionScope[] = input.elevation.scope.map((entry, index) => ({
        id: `elevation:${index}`, surface: entry.access === "write" ? "path_write" : "path_read",
        target: entry.path, access: entry.access, state: "allow", source: "approval-chain",
      }));
      const captured = finalizeToolInvocation(seed.seed, { requestId: `${ctx.sessionManager.getSessionId()}:${input.toolCallId}`,
        scopes, executionBinding: { status: "bound", toolName: input.targetToolName, owner: OWNER, bindingId: BINDING, revision: seed.seed.tool.revision } });
      if (!captured.ok || !bindings.authorize(captured.invocation, current.revision)) throw new Error("elevation:binding-invalid");
      const target = current.adapter.definitions.find(tool => tool.name === input.targetToolName);
      if (target === undefined) throw new Error("elevation:controlled-executor-unavailable");
      const key = hostExecutionKey(ctx.sessionManager.getSessionId(), input.toolCallId);
      defaultCalls.set(key, { filesystem: baselineFilesystem(ctx, current.snapshot.config.mode), network: { kind: "none" } });
      try {
        return await target.execute(input.toolCallId, args, signal, onUpdate, ctx);
      } finally {
        defaultCalls.delete(key);
        bindings.take(ctx.sessionManager.getSessionId(), input.toolCallId);
      }
    },
    async disableRuntime(): Promise<void> {
      const ids = new Set([...sessions.keys(), ...pendingSessions.keys()]);
      const pending = [...pendingSessions.values()];
      const closing: Promise<void>[] = [];
      for (const id of ids) {
        epochs.set(id, (epochs.get(id) ?? 0) + 1);
        bindings.clearSession(id);
        clearElevations(id);
        egress.closeSession(id);
        const cancelling = cancelManagedSession(id);
        const previous = sessions.get(id);
        sessions.delete(id);
        const retirement = Promise.all([retiring.get(id), previous?.adapter.dispose(), cancelling]).then(() => undefined);
        retiring.set(id, retirement);
        closing.push(retirement.finally(() => {
          if (retiring.get(id) === retirement) retiring.delete(id);
        }));
      }
      await Promise.all([...pending.map(item => item.catch(() => undefined)), ...closing, mcp.close()]);
    },
    configurationRevision(ctx: ExtensionContext): string {
      return revision(snapshot(ctx));
    },
    /**
     * C2 (approval-chain v4 §2, priority 60): the execution layer's own statement
     * of what it can confine. The chain turns this into a per-call sandbox
     * receipt and only then may let an opaque-but-clean command run unprompted.
     * Reporting it is not a permission: the chain still requires a clean parse,
     * no danger, no sensitive target, and the mode's configured `defaultPolicy`.
     */
    sandboxCapability(sessionId?: string): {
      readonly backend: string;
      readonly available: boolean;
      readonly networkPolicy: "none" | "proxied";
    } {
      const current = sessionId === undefined ? undefined : sessions.get(sessionId)?.snapshot;
      const runtime = current?.config.experimental.sandboxEnabled ? readyRuntime() : undefined;
      return { backend: runtime?.manifest.backendId ?? "unsupported-platform", available: runtime !== undefined, networkPolicy: "none" };
    },
    resolveHostTool(name: string, schema: AnyToolDefinition["parameters"]): AnyToolDefinition | undefined {
      const definition = hostExecutors.get(name);
      return definition?.parameters === schema && isCurrentOwnedDefinition(name)
        ? definition
        : undefined;
    },
    fileFacts(name: string, args: JsonObject, cwd: string): ToolAccessFactsResult | undefined {
      if (!owns(name) || !["read", "write", "edit", "grep", "find", "ls"].includes(name)) return undefined;
      const path = args.path ?? ".";
      if (typeof path !== "string") return undefined;
      const accesses = name === "write" ? ["write" as const] : name === "edit" ? ["read" as const, "write" as const] : ["read" as const];
      return { status: "verified", source: "builtin", complete: true, unknownEffects: [],
        accesses: accesses.map(access => ({ path, access, operation: access })) };
    },
    registerManagedTool(definition: AnyToolDefinition, lifecycle?: ManagedToolLifecycle): void {
      hostExecutors.set(definition.name, definition);
      register(definition, false, lifecycle ?? {});
    },
    configurationChanged,
    async guard(event: ToolCallEvent, ctx: ExtensionContext, review: Review): Promise<ReviewOutcome> {
      if (event.toolName === disabledShell) return { block: true, reason: disabledShellReason };
      const current = await session(ctx);
      mapTemporaryFilePath(event, ctx);
      const ruleMatch = evaluateToolRules(current.snapshot.toolRules, {
        tool: event.toolName,
        args: event.input,
      });
      if (ruleMatch.kind === "deny") {
        auditToolRule(ctx.sessionManager.getSessionId(), event, ruleMatch);
        return { block: true, reason: `sandbox-denied-tool:${ruleMatch.ruleId}` };
      }
      // The rule table removed the declaration after this tool was registered.
      // Its pi definition cannot be unregistered, so the gate refuses it in
      // every mode before the approval chain. The check is derived from THIS
      // session's live snapshot, never from a process-level memory: another
      // session's synchronization must not retire a name this session still
      // declares. A deny rule above wins so its audit record is kept; the name
      // comes back as soon as the rule declares the sandbox tool again, while a
      // plain `allow` rule without `sandbox` leaves it refused (fail-closed).
      if (registeredSandboxTools.has(event.toolName) && !declaresSandboxTool(current.snapshot, event.toolName)) {
        return { block: true, reason: `sandbox-tool-retired: ${event.toolName}` };
      }
      const allowedByRule = ruleMatch.kind === "allow";
      const sandboxRule = ruleMatch.kind === "allow" ? ruleMatch.rule.sandbox : undefined;
      const matchedRuleId = ruleMatch.kind === "allow" ? ruleMatch.ruleId : "";
      let declaredAccesses: readonly { readonly path: string; readonly access: "read" | "write" }[] = [];
      if (allowedByRule) {
        // §5.1: an allow rule validates its declared arguments before execution.
        const locations = collectToolRuleLocations(ruleMatch.rule, event.input, ctx.cwd);
        if (!locations.ok) {
          auditToolRule(ctx.sessionManager.getSessionId(), event, ruleMatch, locations.reason);
          return { block: true, reason: `sandbox-tool-rule:${ruleMatch.ruleId}:${locations.reason}` };
        }
        declaredAccesses = locations.facts;
        auditToolRule(ctx.sessionManager.getSessionId(), event, ruleMatch);
      }
      if (!owns(event.toolName)) {
        if (allowedByRule) {
          // A declared sandbox tool is executed by its own registered definition;
          // letting the host run an unregistered one would leave the sandbox.
          return sandboxRule === undefined ? undefined : { block: true, reason: `sandbox-tool-unavailable: ${event.toolName}` };
        }
        return current.snapshot.config.mode === "full-access"
          ? review() : { block: true, reason: `sandbox-unmanaged-tool: ${event.toolName}` };
      }
      const scopeBlock = ordinaryFileScopeBlock(event.toolName, event.input as Record<string, unknown>, ctx);
      if (scopeBlock !== undefined) return scopeBlock;
      const seed = captureToolInvocationSeed({ event, registeredTools: api.getAllTools(), cwd: ctx.cwd,
        requester: host.readRequester(ctx as ExtensionToolContext), environment: executionEnvironment(ctx) });
      if (!seed.ok) return { block: true, reason: `sandbox-binding: ${seed.reason}` };
      const answer = allowedByRule || hasApprovedCodemodeScope(ctx.sessionManager.getSessionId())
        ? undefined
        : await review({ ask: true });
      if (answer !== undefined) {
        return "kind" in answer && answer.kind === "host-execution"
          ? { block: true, reason: "permission:ordinary-host-execution-forbidden; use request_tool_elevation for a supported file tool" }
          : answer;
      }
      if (sessions.get(ctx.sessionManager.getSessionId()) !== current || current.revision !== revision(snapshot(ctx)) || !owns(event.toolName)) return { block: true, reason: "plan-invalidated: execution policy or tool changed during approval" };
      if (ctx.signal?.aborted) return { block: true, reason: "host-execution:cancelled-before-start" };
      const scopes: PermissionScope[] = [];
      const name = event.toolName;
      if (sandboxRule !== undefined) {
        // §6.5: the module directory is readable and the per-tool state
        // directory is writable; both grants come from the declaration itself.
        const specs = resolveSandboxToolSpecs(current.snapshot, ctx.cwd).specs;
        const spec = specs.find((candidate) => candidate.name === name);
        if (spec === undefined) return { block: true, reason: `sandbox-tool-not-declared: ${name}` };
        const moduleDirectory = resolveHostPathIdentity(spec.moduleDirectory);
        const stateDirectory = resolveHostPathIdentity(spec.stateDirectory);
        if (moduleDirectory === null || stateDirectory === null) {
          return { block: true, reason: "sandbox-tool-rule: path identity is unavailable" };
        }
        scopes.push({ id: "sandbox-tool:module", surface: "path_read", target: moduleDirectory, access: "read", state: "allow", source: "approval-chain" });
        scopes.push({ id: "sandbox-tool:state", surface: "path_write", target: stateDirectory, access: "write", state: "allow", source: "approval-chain" });
        for (const [index, fact] of declaredAccesses.entries()) {
          const target = resolveHostPathIdentity(fact.path);
          if (target === null) return { block: true, reason: `sandbox-tool-rule:${matchedRuleId}: path identity is unavailable` };
          scopes.push({ id: `sandbox-tool:location:${index}`, surface: `path_${fact.access}`, target, access: fact.access, state: "allow", source: "approval-chain" });
        }
      }
      if (BUILTIN_TOOL_NAMES.includes(name as typeof BUILTIN_TOOL_NAMES[number]) && name !== "bash" && name !== "powershell") {
        const raw = seed.seed.effectiveArguments.path ?? ".";
        if (typeof raw !== "string") return { block: true, reason: "sandbox-binding: invalid path" };
        const path = resolveHostPathIdentity(builtinToolPath(name as typeof BUILTIN_TOOL_NAMES[number], raw, ctx.cwd));
        if (!path) return { block: true, reason: "sandbox-binding: path identity is unavailable" };
        for (const access of name === "write" ? ["write" as const] : name === "edit" ? ["read" as const, "write" as const] : ["read" as const]) {
          scopes.push({ id: `builtin:${access}`, surface: `path_${access}`, target: path, access, state: "allow", source: "approval-chain" });
        }
      }
      const captured = finalizeToolInvocation(seed.seed, { requestId: `${ctx.sessionManager.getSessionId()}:${event.toolCallId}`,
        scopes, executionBinding: { status: "bound", toolName: name, owner: OWNER, bindingId: BINDING, revision: seed.seed.tool.revision } });
      if (!captured.ok) return { block: true, reason: "sandbox-binding: authorization could not be bound" };
      if (!bindings.authorize(captured.invocation, current.revision)) return { block: true, reason: "sandbox-binding: authorization could not be bound" };
      return undefined;
    },
    install(pi: ExtensionAPI) {
      api = pi;
      for (const factory of factories) register(factory(process.cwd()), true);
      pi.on("session_start", async (_event, ctx) => { closedSessions.delete(ctx.sessionManager.getSessionId()); await session(ctx); });
      pi.on("tool_execution_end", (event, ctx) => {
        const sessionId = ctx.sessionManager.getSessionId();
        bindings.take(sessionId, event.toolCallId);
      });
      pi.on("session_shutdown", async (_event, ctx) => {
        const id = ctx.sessionManager.getSessionId();
        clearElevations(id);
        const cancelling = cancelManagedSession(id);
        closedSessions.add(id);
        epochs.set(id, (epochs.get(id) ?? 0) + 1);
        bindings.clearSession(id);
        const previous = sessions.get(id); sessions.delete(id);
        await Promise.all([cancelling, previous?.adapter.dispose(), retiring.get(id), pendingSessions.get(id)?.catch(() => undefined), mcp.close()]);
        egress.closeSession(id);
      });
      pi.on("session_before_switch", async (_event, ctx) => {
        await cancelManagedSession(ctx.sessionManager.getSessionId());
      });
      pi.on("session_before_fork", async (_event, ctx) => {
        await cancelManagedSession(ctx.sessionManager.getSessionId());
      });
      pi.on("mcp_servers_change", (_event, ctx) => {
        configurationChanged(ctx.sessionManager.getSessionId());
      });
      const mcpApi = Object.create(pi) as ExtensionAPI;
      mcpApi.registerTool = definition => register(definition, false);
      createMcpExtension({ createTransport: mcp.createTransport, loadConfig: options.mcp?.loadConfig })(mcpApi);
    },
  };
}
