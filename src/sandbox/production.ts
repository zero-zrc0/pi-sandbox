import {
  createBashToolDefinition, createPowerShellToolDefinition, createReadToolDefinition,
  createWriteToolDefinition, createEditToolDefinition, createGrepToolDefinition,
  createFindToolDefinition, createLsToolDefinition, createMcpExtension, getAgentDir,
  type McpExtensionOptions,
  type ExtensionAPI, type ExtensionContext, type ToolCallEvent, type ExtensionToolContext,
} from "@earendil-works/pi-coding-agent";
import { basename, dirname, join, resolve } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { mcpNetworkScope, type ApprovalChainConfigSnapshot } from "../config/owner";
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
import { toRuntimeNetworkScope } from "./network-scope";
import { BUILTIN_TOOL_NAMES, type ExecutionRecord, type FilesystemGrantInput } from "./types";
import { EXECUTION_INSTALL_ROOT } from "./platform";
import { ManagedMcpTransports } from "./mcp";
import { PROTECTED_CONTROL_DIRECTORY_NAMES, resolveHostPathIdentity } from "./path";
import { builtinToolPath } from "./builtin-path";
import { hasApprovedCodemodeScope } from "./codemode/approval-scope";

const OWNER = "pi-sandbox:controlled-execution";
const BINDING = "builtin-and-mcp:v1";
type Block = { block: true; reason: string };
type HostExecutionApproval = { kind: "host-execution"; reason: string };
type ReviewOutcome = Block | HostExecutionApproval | undefined;
type Review = () => Promise<ReviewOutcome>;
const factories = [createBashToolDefinition, createPowerShellToolDefinition, createReadToolDefinition,
  createWriteToolDefinition, createEditToolDefinition, createGrepToolDefinition,
  createFindToolDefinition, createLsToolDefinition];

export interface ControlledExecutionOptions {
  readonly registrationPath?: string;
  readonly snapshot: (ctx: ExtensionContext) => ApprovalChainConfigSnapshot;
  readonly controller?: (ctx: ExtensionContext, record: (record: ExecutionRecord) => void) => ExecutionController;
  readonly mcp?: Pick<ConstructorParameters<typeof ManagedMcpTransports>[0], "prepareStdio" | "fetch"> & Pick<McpExtensionOptions, "loadConfig">;
}

interface SessionExecution {
  readonly revision: string;
  readonly adapter: PiExecutionAdapter;
  readonly snapshot: ApprovalChainConfigSnapshot;
}

interface PendingHostExecution {
  readonly invocation: ToolInvocationFacts;
  readonly policyRevision: string;
  readonly executor: AnyToolDefinition;
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
  const scratchDirectories = new Map<string, string>();
  const owned = new Map<string, AnyToolDefinition>();
  const hostExecutors = new Map<string, AnyToolDefinition>();
  const managedToolCancellers = new Map<string, NonNullable<ManagedToolLifecycle["cancelSession"]>>();
  const pendingHostExecutions = new Map<string, PendingHostExecution>();
  const issuedHostExecutions = new Map<string, Set<string>>();
  const hostExecutionOwners = new Map<string, string>();
  const mcpCalls = new AsyncLocalStorage<{ attempted: boolean }>();
  let api: ExtensionAPI;
  let activeContext: ExtensionContext | undefined;
  const revision = (snapshot: ApprovalChainConfigSnapshot) => jsonDigest({ config: snapshot.config,
    mcpNetwork: mcpNetworkScope(snapshot) });
  const baselineFilesystem = (ctx: ExtensionContext, mode: ApprovalChainConfigSnapshot["config"]["mode"]): FilesystemGrantInput[] => {
    const scratch = scratchDirectories.get(ctx.sessionManager.getSessionId());
    return [{ path: ctx.cwd, access: "read", granularity: "directory" },
      ...(scratch === undefined ? [] : ["read", "write"].flatMap(access =>
        [{ path: scratch, access: access as "read" | "write", granularity: "directory" as const }])),
      ...(mode === "read-only" ? [] : [{ path: ctx.cwd, access: "write" as const, granularity: "directory" as const }])];
  };
  const environment = () => selectExecutionEnvironment(process.env as Record<string, string>);
  const backendId = process.platform === "linux" ? "linux-bwrap-landlock-seccomp"
    : process.platform === "win32" ? "windows-mxc" : "unsupported-platform";
  const executionEnvironment = (ctx: ExtensionContext) => {
    if (options.snapshot(ctx).config.mode === "full-access") return environment();
    const scratch = scratchDirectories.get(ctx.sessionManager.getSessionId());
    return scratch === undefined ? environment() : { ...environment(), TEMP: scratch, TMP: scratch, TMPDIR: scratch };
  };
  const snapshot = (ctx: ExtensionContext) => options.snapshot(ctx);
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
    policy: () => {
      if (!activeContext) throw new Error("MCP session is unavailable");
      const current = snapshot(activeContext);
      const cacheDirectory = join(current.paths.globalConfigDir, "mcp-cache");
      mkdirSync(cacheDirectory, { recursive: true });
      const filesystem = [...baselineFilesystem(activeContext, current.config.mode),
        { path: cacheDirectory, access: "read" as const, granularity: "directory" as const },
        { path: cacheDirectory, access: "write" as const, granularity: "directory" as const }];
      return { revision: `${activeContext.sessionManager.getSessionId()}:${revision(current)}`, sessionId: activeContext.sessionManager.getSessionId(),
        mode: current.config.mode,
        sandbox: current.config.experimental.mcpSandbox,
        permissions: {
          filesystem: {
            read: filesystem.filter(grant => grant.access === "read").map(({ path, granularity }) => ({ path, granularity })),
            write: filesystem.filter(grant => grant.access === "write").map(({ path, granularity }) => ({ path, granularity })),
          },
          network: mcpNetworkScope(current),
          process: { spawn: "allow" },
        },
        environment: {
          UV_CACHE_DIR: join(cacheDirectory, "uv-cache"),
          UV_TOOL_DIR: join(cacheDirectory, "uv-tools"),
        } };
    },
    egress, ...options.mcp,
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
    if (current.config.mode !== "full-access" && !scratchDirectories.has(id)) {
      const scratch = realpathSync(mkdtempSync(join(tmpdir(), "pi-sandbox-exec-")));
      for (const name of PROTECTED_CONTROL_DIRECTORY_NAMES) mkdirSync(join(scratch, name));
      scratchDirectories.set(id, scratch);
    }
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
    const controller = options.controller?.(ctx, record) ?? new ExecutionController({
      installation: {
        installRoot: EXECUTION_INSTALL_ROOT,
        executable: process.execPath,
        args: [fileURLToPath(new URL(`./backend/${process.platform === "linux" ? "linux" : process.platform === "darwin" ? "macos" : "windows"}/helper.mjs`, import.meta.url))],
        expectedBackendId: backendId,
      },
      helperCwd: resolve(process.env.TEMP ?? process.env.TMPDIR ?? "/tmp"),
      workspace: ctx.cwd, helperEnvironment: process.platform === "win32" && process.env.LOCALAPPDATA
        ? { ...environment(), LOCALAPPDATA: process.env.LOCALAPPDATA, PI_MXC_AGENT_DIR: resolve(getAgentDir()) } : environment(), onRecord: record,
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
    const adapter = createPiExecutionAdapter({ controller, bindings, host, owner: OWNER, bindingId: BINDING,
      cwd: ctx.cwd,
      plan: {
        mode: current.config.mode, configRevision: key,
        backendId,
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
        networkCeiling: current.config.execution.network === undefined ? { kind: "none" } : toRuntimeNetworkScope(current.config.execution.network),
        readConfigRevision: () => revision(snapshot(ctx)),
        environment: executionEnvironment(ctx),
      },
    });
    const created = { revision: key, adapter, snapshot: current };
    sessions.set(id, created);
    return created;
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
      if (hostExecutionBelongsToAnotherSession(ctx.sessionManager.getSessionId(), args[0])) {
        throw new Error("host-execution:approval-binding-invalidated");
      }
      const hostBinding = takeHostExecution(ctx.sessionManager.getSessionId(), args[0]);
      if (hostBinding !== undefined) return executeHostEscalation(hostBinding, args);
      if (hostExecutionWasIssued(ctx.sessionManager.getSessionId(), args[0])) {
        throw new Error("host-execution:approval-unavailable");
      }
      if (current.snapshot.config.mode === "full-access") return fullAccessBuiltin!.execute(...args);
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
            executionMode: sessions.get(record.sessionId)?.snapshot.config.mode === "full-access" ||
              sessions.get(record.sessionId)?.snapshot.config.experimental.mcpSandbox === false ? "host" : "sandbox",
            started: call.attempted,
            state: result.isError ? "failed" : "completed", impact: call.attempted ? "known" : "none",
            ...(result.isError ? { code: "execution-failed" } : {}) });
          return result;
        } catch (error) {
          api.appendEntry("permission:execution", { ...record,
            executionMode: sessions.get(record.sessionId)?.snapshot.config.mode === "full-access" ||
              sessions.get(record.sessionId)?.snapshot.config.experimental.mcpSandbox === false ? "host" : "sandbox",
            started: call.attempted ? "unknown" : false,
            state: "failed", code: "execution-failed", impact: call.attempted ? "unknown" : "none" });
          throw error;
        }
      },
    });
    const registered = builtin ? controlled : { ...controlled, execute: async (...args: Parameters<AnyToolDefinition["execute"]>) => {
      await session(args[4]);
      if (hostExecutionBelongsToAnotherSession(args[4].sessionManager.getSessionId(), args[0])) {
        throw new Error("host-execution:approval-binding-invalidated");
      }
      const hostBinding = takeHostExecution(args[4].sessionManager.getSessionId(), args[0]);
      if (hostBinding !== undefined) return executeHostEscalation(hostBinding, args);
      if (hostExecutionWasIssued(args[4].sessionManager.getSessionId(), args[0])) {
        throw new Error("host-execution:approval-unavailable");
      }
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

  function takeHostExecution(sessionId: string, toolCallId: string): PendingHostExecution | undefined {
    const key = hostExecutionKey(sessionId, toolCallId);
    const binding = pendingHostExecutions.get(key);
    if (binding !== undefined) pendingHostExecutions.delete(key);
    return binding;
  }

  function hostExecutionWasIssued(sessionId: string, toolCallId: string): boolean {
    return issuedHostExecutions.get(sessionId)?.has(toolCallId) === true;
  }

  function hostExecutionBelongsToAnotherSession(sessionId: string, toolCallId: string): boolean {
    const owner = hostExecutionOwners.get(toolCallId);
    return owner !== undefined && owner !== sessionId;
  }

  function clearPendingHostExecutions(
    sessionId: string,
    code = "approval-invalidated",
  ): void {
    for (const [key, binding] of pendingHostExecutions) {
      if (binding.invocation.requester.sessionId !== sessionId) continue;
      pendingHostExecutions.delete(key);
      recordHostExecution(binding.invocation, {
        started: false,
        impact: "none",
        state: "failed",
        code,
      });
    }
  }

  function recordHostExecution(
    invocation: ToolInvocationFacts,
    input: { readonly started: boolean | "unknown"; readonly impact: "known" | "unknown" | "none"; readonly state: "completed" | "failed"; readonly code?: string },
  ): void {
    try {
      api.appendEntry("permission:execution", {
        ...recordIdentity(invocation),
        executionMode: "host",
        ...input,
      });
    } catch {
      return;
    }
  }

  async function executeHostEscalation(
    binding: PendingHostExecution | undefined,
    args: Parameters<AnyToolDefinition["execute"]>,
  ): Promise<Awaited<ReturnType<AnyToolDefinition["execute"]>>> {
    const [toolCallId, params, signal, onUpdate, ctx] = args;
    if (binding === undefined) throw new Error("host-execution:approval-unavailable");
    const approved = binding.invocation;
    const sessionId = ctx.sessionManager.getSessionId();
    const reject = (code: string): never => {
      recordHostExecution(approved, { started: false, impact: "none", state: "failed", code });
      throw new Error(`host-execution:${code}`);
    };
    if (
      sessionId !== approved.requester.sessionId ||
      toolCallId !== approved.action.toolCallId ||
      approved.action.tool.name !== binding.executor.name ||
      hostExecutors.get(binding.executor.name) !== binding.executor ||
      !owns(binding.executor.name) ||
      snapshot(ctx).config.mode === "read-only" ||
      revision(snapshot(ctx)) !== binding.policyRevision
    ) {
      return reject("approval-binding-invalidated");
    }

    let captured: ToolInvocationFacts | undefined;
    try {
      const seed = captureToolInvocationSeed({
        event: {
          type: "tool_call",
          toolName: approved.action.tool.name,
          toolCallId,
          ...(approved.action.parentToolCallId === undefined
            ? {}
            : { parentToolCallId: approved.action.parentToolCallId }),
          input: params,
        },
        registeredTools: api.getAllTools(),
        cwd: ctx.cwd,
        requester: host.readRequester(ctx),
        environment: executionEnvironment(ctx),
      });
      if (!seed.ok) return reject("action-facts-unavailable");
      const current = finalizeToolInvocation(seed.seed, {
        requestId: approved.action.requestId,
        scopes: approved.action.scopes,
        executionBinding: approved.executionBinding,
      });
      if (!current.ok) return reject("action-facts-invalid");
      captured = current.invocation;
    } catch {
      return reject("action-facts-unavailable");
    }
    if (captured.digest !== approved.digest) return reject("action-changed-before-execution");
    if (signal?.aborted || ctx.signal?.aborted) return reject("cancelled-before-execution");

    try {
      const result = await binding.executor.execute(
        toolCallId,
        approved.action.effectiveArguments as never,
        signal,
        onUpdate,
        ctx,
      );
      recordHostExecution(approved, {
        started: true,
        impact: "known",
        state: result.isError === true ? "failed" : "completed",
        ...(result.isError === true ? { code: "execution-failed" } : {}),
      });
      return result;
    } catch (error) {
      recordHostExecution(approved, {
        started: "unknown",
        impact: "unknown",
        state: "failed",
        code: "execution-failed",
      });
      throw error;
    }
  }

  function configurationChanged(id: string): void {
    void cancelManagedSession(id).catch(() => undefined);
    egress.closeSession(id);
    bindings.clearSession(id);
    clearPendingHostExecutions(id);
    epochs.set(id, (epochs.get(id) ?? 0) + 1);
    const previous = sessions.get(id);
    sessions.delete(id);
    const closing = Promise.all([retiring.get(id), previous?.adapter.dispose(), mcp.synchronize()]).then(() => undefined);
    retiring.set(id, closing);
    void closing.catch(() => undefined);
  }

  return {
    configurationRevision(ctx: ExtensionContext): string {
      return revision(snapshot(ctx));
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
      if (!owns(event.toolName)) return current.snapshot.config.mode === "full-access"
        ? review() : { block: true, reason: `sandbox-unmanaged-tool: ${event.toolName}` };
      const seed = captureToolInvocationSeed({ event, registeredTools: api.getAllTools(), cwd: ctx.cwd,
        requester: host.readRequester(ctx as ExtensionToolContext), environment: executionEnvironment(ctx) });
      if (!seed.ok) return { block: true, reason: `sandbox-binding: ${seed.reason}` };
      const answer = hasApprovedCodemodeScope(ctx.sessionManager.getSessionId()) ? undefined : await review();
      const escalation = answer !== undefined && "kind" in answer && answer.kind === "host-execution"
        ? answer
        : undefined;
      if (answer !== undefined && escalation === undefined) return answer;
      if (sessions.get(ctx.sessionManager.getSessionId()) !== current || current.revision !== revision(snapshot(ctx)) || !owns(event.toolName)) return { block: true, reason: "plan-invalidated: execution policy or tool changed during approval" };
      if (ctx.signal?.aborted) return { block: true, reason: "host-execution:cancelled-before-start" };
      const scopes: PermissionScope[] = [];
      const name = event.toolName;
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
      if (escalation !== undefined) {
        const sessionId = ctx.sessionManager.getSessionId();
        if (current.snapshot.config.mode === "read-only") return { block: true, reason: "host-execution:forbidden-in-read-only" };
        const executor = hostExecutors.get(name);
        if (executor === undefined || executor.name !== name) return { block: true, reason: "host-execution:target-unavailable" };
        const issued = issuedHostExecutions.get(sessionId) ?? new Set<string>();
        const owner = hostExecutionOwners.get(event.toolCallId);
        if (issued.has(event.toolCallId) || (owner !== undefined && owner !== sessionId)) {
          return { block: true, reason: "host-execution:already-issued" };
        }
        issued.add(event.toolCallId);
        issuedHostExecutions.set(sessionId, issued);
        hostExecutionOwners.set(event.toolCallId, sessionId);
        pendingHostExecutions.set(hostExecutionKey(sessionId, event.toolCallId), {
          invocation: captured.invocation,
          policyRevision: current.revision,
          executor,
        });
        return undefined;
      }
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
        const cancelling = cancelManagedSession(id);
        closedSessions.add(id);
        epochs.set(id, (epochs.get(id) ?? 0) + 1);
        bindings.clearSession(id);
        clearPendingHostExecutions(id, "session-disposed");
        issuedHostExecutions.delete(id);
        for (const [toolCallId, owner] of hostExecutionOwners) {
          if (owner === id) hostExecutionOwners.delete(toolCallId);
        }
        const previous = sessions.get(id); sessions.delete(id);
        await Promise.all([cancelling, previous?.adapter.dispose(), retiring.get(id), pendingSessions.get(id)?.catch(() => undefined), mcp.close()]);
        egress.closeSession(id);
        const scratch = scratchDirectories.get(id);
        if (scratch !== undefined) {
          const target = realpathSync(scratch);
          if (dirname(target) !== realpathSync(tmpdir()) || !basename(target).startsWith("pi-sandbox-exec-")) throw new Error("refusing to remove an unowned execution directory");
          rmSync(target, { recursive: true, force: true });
          scratchDirectories.delete(id);
        }
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
