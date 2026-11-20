import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
  type ToolInvocationFacts,
} from "../../../src/invocation";
import { compileExecutionPlan, filterExecutionEnvironment } from "#sandbox/plan";
import { builtinToolPath } from "#sandbox/builtin-path";
import { normalizeHostPath } from "#sandbox/path";
import { ExecutionController } from "#sandbox/lifecycle";
import type { DirectBackendDriver } from "#sandbox/backend/direct";
import type {
  ExecutionOperation,
  ExecutionPlan,
  ExecutionRequest,
  NetworkScope,
} from "#sandbox/types";
import { createTestDirectBackend } from "./direct-backend";

export const OWNER = "plan-11-test-owner";
export const BINDING_ID = "plan-11-test-binding";
const SESSION_ID = "plan-11-session";
export const POLICY_REVISION = "policy-r1";
export const CONFIG_REVISION = "config-r1";

export interface TestLayout {
  readonly root: string;
  readonly workspace: string;
  readonly agent: string;
}

export function createTestLayout(prefix = "plan11-exec"): TestLayout {
  // macOS exposes the per-user temp directory through the /var symlink while
  // realpath returns /private/var. Canonicalize once so fixtures that compare
  // sandbox paths (which the backend canonicalizes) stay aligned.
  const root = realpathSync(mkdtempSync(join(tmpdir(), `${prefix}-`)));
  const layout = {
    root,
    workspace: join(root, "workspace"),
    agent: join(root, "agent"),
  };
  for (const directory of [layout.workspace, layout.agent]) {
    mkdirSync(directory, { recursive: true });
  }
  return layout;
}

export function removeTestLayout(layout: TestLayout | undefined): void {
  if (!layout) return;
  rmSync(layout.root, { recursive: true, force: true });
}

export function testExecutionEnvironment(
  extra: Readonly<Record<string, string>> = {},
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of [
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
  ]) {
    const value = process.env[name];
    if (typeof value === "string") result[name] = value;
  }
  for (const [name, value] of Object.entries(extra)) result[name] = value;
  return Object.freeze(result);
}

/** An explicit process environment that contains no controller keys. */
export function runtimeEnvironment(): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of [
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "TMPDIR",
  ]) {
    const value = process.env[name];
    if (typeof value === "string") result[name] = value;
  }
  return Object.freeze(result);
}

function makeToolInfo(name: string): {
  readonly name: string;
  readonly description: string;
  readonly parameters: unknown;
  readonly sourceInfo: {
    readonly path: string;
    readonly source: string;
    readonly scope: string;
    readonly origin: string;
  };
} {
  return {
    name,
    description: `plan 11 ${name} fixture definition`,
    parameters: { type: "object" },
    sourceInfo: {
      path: "<plan11-test>",
      source: "plan11-test",
      scope: "temporary",
      origin: "top-level",
    },
  };
}

export interface MakeInvocationOptions {
  readonly toolName?: string;
  readonly toolCallId?: string;
  readonly requestId?: string;
  readonly cwd: string;
  readonly args?: Readonly<Record<string, unknown>>;
  readonly environment?: Readonly<Record<string, string>>;
  readonly sessionId?: string;
  readonly scopes?: ToolInvocationFacts["action"]["scopes"];
  readonly owner?: string;
  readonly bindingId?: string;
  readonly toolInfo?: ReturnType<typeof makeToolInfo>;
}

export function makeInvocation(
  options: MakeInvocationOptions,
): ToolInvocationFacts {
  const toolName = options.toolName ?? "bash";
  const toolInfo = options.toolInfo ?? makeToolInfo(toolName);
  const toolCallId = options.toolCallId ?? "call-1";
  const seed = captureToolInvocationSeed({
    event: {
      type: "tool_call",
      toolName,
      toolCallId,
      input: options.args ?? {},
    },
    registeredTools: [toolInfo],
    cwd: options.cwd,
    requester: {
      sessionId: options.sessionId ?? SESSION_ID,
      agentName: null,
    },
    environment: options.environment ?? {},
  });
  if (!seed.ok) throw new Error(`invocation seed failed: ${seed.reason}`);
  const captured = finalizeToolInvocation(seed.seed, {
    requestId: options.requestId ?? "request-1",
    scopes: options.scopes ?? [],
    executionBinding: {
      status: "bound",
      owner: options.owner ?? OWNER,
      toolName,
      revision: seed.seed.tool.revision,
      bindingId: options.bindingId ?? BINDING_ID,
    },
  });
  if (!captured.ok) throw new Error(`invocation failed: ${captured.reason}`);
  return captured.invocation;
}

export interface CompileTestPlanOptions {
  readonly invocation: ToolInvocationFacts;
  readonly operation: ExecutionOperation;
  readonly workspace: string;
  readonly baselineFilesystem?: readonly {
    readonly path: string;
    readonly access: "read" | "write";
    readonly granularity: "file" | "directory";
  }[];
  readonly network?: NetworkScope;
  readonly approved?: {
    readonly filesystem?: readonly {
      readonly path: string;
      readonly access: "read" | "write";
      readonly granularity: "file" | "directory";
    }[];
    readonly network?: readonly { readonly host: string; readonly port?: number }[];
  };
  readonly environment?: Readonly<Record<string, string>>;
  readonly deadlineMs?: number;
  readonly now?: number;
  readonly backendId?: string;
  readonly metadataRead?: "none" | "all";
  readonly mode?: "read-only" | "default" | "auto-review";
  readonly owner?: string;
  readonly bindingId?: string;
  readonly protectedControlNames?: readonly string[];
  readonly protectedPaths?: readonly string[];
  readonly runtimeFilesystem?: readonly import("#sandbox/types").FilesystemGrantInput[];
  readonly sensitivePaths?: readonly import("#sandbox/sensitive-paths").SensitivePath[];
  readonly shell?: string;
  readonly resolvePath?: (path: string) => string | null;
}

function compileTestExecution(options: CompileTestPlanOptions): ExecutionRequest {
  const now = options.now ?? Date.now();
  const baselineFilesystem: {
    path: string;
    access: "read" | "write";
    granularity: "file" | "directory";
  }[] = options.baselineFilesystem === undefined
    ? [
      { path: options.workspace, access: "read", granularity: "directory" },
      { path: options.workspace, access: "write", granularity: "directory" },
    ]
    : [...options.baselineFilesystem];
  const environment = filterExecutionEnvironment(options.environment ?? {});
  if (!environment.ok) throw new Error(`environment is invalid: ${environment.reason}`);
  const cwd = normalizeHostPath(options.invocation.action.cwd);
  if (!cwd) throw new Error("test invocation cwd is invalid");
  const operation = options.operation.kind === "shell" && options.shell !== undefined
    ? { ...options.operation, shell: options.shell }
    : options.operation.kind === "builtin-tool" && options.operation.name !== "bash" && options.operation.name !== "powershell"
    ? { ...options.operation, arguments: { ...options.operation.arguments,
      path: builtinToolPath(options.operation.name, String(options.operation.arguments.path ?? "."), cwd) } }
    : options.operation;
  const compiled = compileExecutionPlan({
    invocation: options.invocation,
    baseline: {
      filesystem: baselineFilesystem,
      network: options.network ?? { kind: "none" },
    },
    approved: {
      filesystem: options.approved?.filesystem ?? [],
      ...(options.approved?.network === undefined
        ? {}
        : { network: options.approved.network }),
    },
    metadataRead: options.metadataRead ?? "none",
    ...(options.protectedPaths === undefined ? {} : { protectedPaths: options.protectedPaths }),
    ...(options.runtimeFilesystem === undefined ? {} : { runtimeFilesystem: options.runtimeFilesystem }),
    ...(options.sensitivePaths === undefined ? {} : { sensitivePaths: options.sensitivePaths }),
    ...(options.shell === undefined ? {} : { shell: options.shell }),
    ...(options.resolvePath === undefined
      ? {}
      : { resolvePath: options.resolvePath }),
    ...(options.protectedControlNames === undefined
      ? {}
      : { protectedControlNames: options.protectedControlNames }),
  });
  if (!compiled.ok) {
    throw new Error(`plan compilation failed: ${compiled.code}: ${compiled.reason}`);
  }
  return {
    plan: compiled.plan,
    requestId: options.invocation.action.requestId,
    toolCallId: options.invocation.action.toolCallId,
    actionDigest: options.invocation.digest,
    sessionId: options.invocation.requester.sessionId,
    toolName: options.invocation.action.tool.name,
    mode: options.mode ?? "default",
    policyRevision: POLICY_REVISION,
    configRevision: CONFIG_REVISION,
    backendId: options.backendId ?? "fixture-direct",
    start: {
      cwd,
      operation,
      environment: environment.environment,
      deadlineAt: now + (options.deadlineMs ?? 30_000),
    },
  };
}

export function compileTestPlan(options: CompileTestPlanOptions): ExecutionPlan {
  return compileTestExecution(options).plan;
}

export function compileTestRequest(options: CompileTestPlanOptions): ExecutionRequest {
  return compileTestExecution(options);
}

export interface MakeControllerOptions {
  readonly layout: TestLayout;
  readonly scenario?: string;
  readonly environment?: Readonly<Record<string, string>>;
  readonly directBackend?: DirectBackendDriver;
  readonly startTimeoutMs?: number;
  readonly cancelGraceMs?: number;
  readonly maxConcurrent?: number;
  readonly maxQueue?: number;
  readonly probeTimeoutMs?: number;
  readonly onRecord?: ConstructorParameters<typeof ExecutionController>[0]["onRecord"];
  readonly egress?: ConstructorParameters<typeof ExecutionController>[0]["egress"];
}

export function makeController(
  options: MakeControllerOptions,
): ExecutionController {
  return new ExecutionController({
    directBackend: options.directBackend ?? createTestDirectBackend({
      ...(options.scenario === undefined ? {} : { scenario: options.scenario }),
      ...(options.environment === undefined ? {} : { environment: options.environment }),
    }),
    startTimeoutMs: options.startTimeoutMs ?? 5_000,
    cancelGraceMs: options.cancelGraceMs ?? 500,
    maxConcurrent: options.maxConcurrent ?? 2,
    maxQueue: options.maxQueue ?? 4,
    ...(options.probeTimeoutMs === undefined
      ? {}
      : { probeTimeoutMs: options.probeTimeoutMs }),
    ...(options.onRecord === undefined ? {} : { onRecord: options.onRecord }),
    ...(options.egress === undefined ? {} : { egress: options.egress }),
  });
}

export async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 5_000,
): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("condition was not met before the timeout");
}

export function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function waitForProcessGone(
  pid: number,
  timeoutMs = 5_000,
): Promise<boolean> {
  try {
    await waitFor(() => !processExists(pid), timeoutMs);
    return true;
  } catch {
    return false;
  }
}
