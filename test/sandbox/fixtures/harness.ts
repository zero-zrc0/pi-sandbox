import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
  type ToolInvocationFacts,
} from "../../../src/invocation";
import { compileExecutionPlan } from "#sandbox/plan";
import { ExecutionController } from "#sandbox/lifecycle";
import type { TrustedHelperInstallation } from "#sandbox/helper";
import type {
  ExecutionOperation,
  ExecutionPlan,
  NetworkScope,
} from "#sandbox/types";

export const OWNER = "plan-11-test-owner";
export const BINDING_ID = "plan-11-test-binding";
const SESSION_ID = "plan-11-session";
export const POLICY_REVISION = "policy-r1";
export const CONFIG_REVISION = "config-r1";

export interface TestLayout {
  readonly root: string;
  readonly installRoot: string;
  readonly helperCwd: string;
  readonly workspace: string;
  readonly agent: string;
}

export function createTestLayout(prefix = "plan11-exec"): TestLayout {
  const root = mkdtempSync(join(tmpdir(), `${prefix}-`));
  const layout = {
    root,
    installRoot: join(root, "helper"),
    helperCwd: join(root, "helper-runtime"),
    workspace: join(root, "workspace"),
    agent: join(root, "agent"),
  };
  for (const directory of [
    layout.installRoot,
    layout.helperCwd,
    layout.workspace,
    layout.agent,
  ]) {
    mkdirSync(directory, { recursive: true });
  }
  return layout;
}

export function removeTestLayout(layout: TestLayout | undefined): void {
  if (!layout) return;
  rmSync(layout.root, { recursive: true, force: true });
}

export function installFixtureHelper(layout: TestLayout): TrustedHelperInstallation {
  const source = fileURLToPath(
    new URL("./helper-fixture.mjs", import.meta.url),
  );
  const target = join(layout.installRoot, "helper-fixture.mjs");
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(source, target);
  return {
    installRoot: layout.installRoot,
    executable: process.execPath,
    args: [target],
  };
}

export function fixtureEnvironment(
  scenario: string,
  extra: Readonly<Record<string, string>> = {},
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {
    FIXTURE_SCENARIO: scenario,
    FIXTURE_BUILTIN_WORKER: fileURLToPath(new URL("../../../src/sandbox/builtin-worker.mjs", import.meta.url)),
    FIXTURE_SANDBOX_TOOL_WORKER: fileURLToPath(new URL("../../../src/sandbox/sandbox-tool-worker.mjs", import.meta.url)),
  };
  for (const name of [
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
  ]) {
    const value = process.env[name];
    if (typeof value === "string") result[name] = value;
  }
  for (const [name, value] of Object.entries(extra)) result[name] = value;
  return Object.freeze(result);
}

/** A shell/helper environment that is explicit and contains no controller keys. */
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
  readonly mode?: "read-only" | "default" | "auto-review";
  readonly owner?: string;
  readonly bindingId?: string;
  readonly protectedControlNames?: readonly string[];
  readonly shell?: string;
  readonly resolvePath?: (path: string) => string | null;
}

export function compileTestPlan(options: CompileTestPlanOptions): ExecutionPlan {
  const now = options.now ?? Date.now();
  const baselineFilesystem: {
    path: string;
    access: "read" | "write";
    granularity: "file" | "directory";
  }[] = [
    { path: options.workspace, access: "read", granularity: "directory" },
    { path: options.workspace, access: "write", granularity: "directory" },
  ];
  const compiled = compileExecutionPlan({
    invocation: options.invocation,
    operation: options.operation,
    mode: options.mode ?? "default",
    owner: options.owner ?? OWNER,
    bindingId: options.bindingId ?? BINDING_ID,
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
    backendId: options.backendId ?? "fixture-helper",
    policyRevision: POLICY_REVISION,
    configRevision: CONFIG_REVISION,
    deadlineAt: now + (options.deadlineMs ?? 30_000),
    now,
    environment: options.environment ?? {},
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
  return compiled.plan;
}

export interface MakeControllerOptions {
  readonly layout: TestLayout;
  readonly installation?: TrustedHelperInstallation;
  readonly scenario?: string;
  readonly helperEnvironment?: Readonly<Record<string, string>>;
  readonly workspace?: string;
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
    installation: options.installation ?? installFixtureHelper(options.layout),
    helperCwd: options.layout.helperCwd,
    workspace: options.workspace ?? options.layout.workspace,
    helperEnvironment:
      options.helperEnvironment ??
      fixtureEnvironment(options.scenario ?? "ok"),
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
