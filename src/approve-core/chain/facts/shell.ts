/**
 * Shell access facts and danger hits for one frozen call.
 *
 * `projectShellFacts()` is the shell half of the chain's fact seam (v4 §1
 * `ApprovalContext`, §3): it turns a captured `CallState` plus the host's parse
 * view into the two read-only projections a link may consult —
 *
 * - `access`: one `UnitAccessFact[]` per unit of the call, holding the
 *   direction the analysis proved (read/write/network) or `unknown` when
 *   nothing was proven;
 * - `dangers`: the v3 §5 danger families `risk/danger.ts` derives from the same
 *   structured facts.
 *
 * It does **not** decide anything: no mode, no channel, no explicit rule and no
 * verdict live here. It also parses nothing and executes nothing — the view
 * must come from the host's step-local parse, and a missing or mismatched view
 * yields `undefined` so the caller falls back instead of reading stale facts.
 *
 * Assumptions made here:
 *
 * - `platform` defaults to `process.platform`; `cwd` defaults to the view's
 *   working directory and then to `process.cwd()`, mirroring the existing mode
 *   node;
 * - when `workspaceRoot` is absent, the call's `cwd` is treated as the
 *   workspace root. A caller that knows the real root must pass it: without it
 *   deleting the directory above the cwd is reported as catastrophic (the
 *   assumed root would disappear), while deleting something inside the real
 *   workspace but above the cwd is reported as a bulk delete;
 * - access facts run the incremental shell-policy evaluation under the
 *   `default` mode, because the reused derivation requires a mode. Read-only
 *   exemptions are therefore never applied, and a shell-policy rule scoped to
 *   another mode does not contribute its ask marker; per-mode opinions belong
 *   to the handlers, not to these facts.
 *
 * Everything returned is frozen: the per-unit arrays (and their fact objects),
 * the danger hits (`detectDangers` already freezes them) and the projection.
 */
import type { BashProgramFactsView, CallState } from "#approve-core/contracts";
import {
  bashAccessFactsForView,
  powerShellAccessFactsForView,
  type AccessFact,
  type ModeNodeOptions,
} from "#approve-core/nodes/mode";
import { analyzeBashProgramCalls } from "#approve-core/nodes/shell-policy";
import type { ShellPolicyPathVariables } from "#approve-core/policy/shell-policy/evaluate";
import type { PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { ShellExecutionPermissions } from "#config/execution-source-schema";
import type { ShellPolicy } from "#config/shell-policy-schema";
import { detectDangers, type DangerHit, type DangerInput } from "../../risk/danger";
import type { PermissionMode } from "../../../contracts";
import type { UnitAccessFact } from "../facts";

/** Options the projection passes through to the existing shell derivations. */
export interface ShellFactsOptions {
  readonly platform?: NodeJS.Platform;
  readonly cwd?: string;
  /** The mode the unit is being judged in; defaults to `default`. */
  readonly mode?: PermissionMode;
  readonly workspaceRoot?: string;
  readonly shellPolicy?: ShellPolicy;
  readonly shellPathVariables?: ShellPolicyPathVariables;
  readonly enabledShellNodes?: readonly string[];
  readonly shellGrants?: ShellExecutionPermissions;
  readonly workspaceBulkDeleteAction?: "deny" | "ask";
}

/** What one shell call proves, as read by the chain links. */
export interface ShellFactsProjection {
  readonly cwd: string;
  readonly shell: "bash" | "powershell";
  readonly access: ReadonlyMap<string, readonly UnitAccessFact[]>;
  readonly dangers: readonly DangerHit[];
}

/** The tool names the existing Bash derivation accepts (`nodes/analysis`). */
const BASH_TOOL_NAMES: ReadonlySet<string> = new Set(["bash", "shell"]);

/** What a unit gets when no operation matched it, matching the mode node. */
const UNKNOWN_ACCESS: readonly UnitAccessFact[] = Object.freeze([
  Object.freeze({ kind: "unknown" }),
]);

/**
 * Project the shell facts of one call.
 *
 * Returns `undefined` when the call is not a shell call, when the matching view
 * is absent, when the view was parsed from a different command
 * (`commandText`), or when the view carries a call digest that differs from
 * `call.digest`. A Bash view without a digest is accepted: it is keyed by
 * `toolCallId` already, and its `commandText` is still checked.
 *
 * The returned map has exactly one entry per `call.units` entry, in declaration
 * order; units no operation reached are `[{ kind: "unknown" }]`.
 */
export async function projectShellFacts(input: {
  readonly call: CallState;
  readonly bashView?: BashProgramFactsView;
  readonly powershellView?: PowerShellProgramFactsView;
  readonly options?: ShellFactsOptions;
}): Promise<ShellFactsProjection | undefined> {
  const options = input.options ?? {};
  const command = input.call.arguments.command;
  if (typeof command !== "string") return undefined;

  if (input.call.toolName === "powershell") {
    const view = input.powershellView;
    if (view === undefined || view.callDigest !== input.call.digest ||
        view.commandText !== command) {
      return undefined;
    }
    return projectPowerShellFacts(input.call, view, options);
  }

  if (!BASH_TOOL_NAMES.has(input.call.toolName)) return undefined;
  const view = input.bashView;
  if (view === undefined || view.commandText !== command) return undefined;
  const viewDigest = bashViewDigest(view);
  if (viewDigest !== undefined && viewDigest !== input.call.digest) return undefined;
  return projectBashFacts(input.call, view, options);
}

async function projectBashFacts(
  call: CallState,
  view: BashProgramFactsView,
  options: ShellFactsOptions,
): Promise<ShellFactsProjection> {
  const platform = options.platform ?? process.platform;
  const analysis = analyzeBashProgramCalls({ call, view, platform });
  const cwd = effectiveCwd(analysis.cwd, options.cwd);
  const access = await bashAccessFactsForView(call, view, modeNodeOptions(options, cwd));
  return freezeProjection({
    cwd,
    shell: "bash",
    access: coverUnits(call, access),
    dangers: detectDangers({
      shell: "bash",
      cwd,
      workspaceRoot: workspaceRootOf(options, cwd),
      operations: analysis.operations,
      invocations: analysis.invocations,
      platform,
      options: dangerOptions(options),
    }),
  });
}

function projectPowerShellFacts(
  call: CallState,
  view: PowerShellProgramFactsView,
  options: ShellFactsOptions,
): ShellFactsProjection {
  const platform = options.platform ?? process.platform;
  const cwd = effectiveCwd(view.cwd, options.cwd);
  const access = powerShellAccessFactsForView(call, view, modeNodeOptions(options, cwd));
  return freezeProjection({
    cwd,
    shell: "powershell",
    access: coverUnits(call, access),
    dangers: detectDangers({
      shell: "powershell",
      cwd,
      workspaceRoot: workspaceRootOf(options, cwd),
      operations: view.analysis.operations,
      invocations: view.analysis.programInvocations,
      platform,
      options: dangerOptions(options),
    }),
  });
}

/**
 * `BashProgramFactsView` is keyed by `toolCallId` and does not carry a call
 * digest today. A host (or a future view) may stamp one; when it is a string it
 * must match, when it is absent the command text is the only binding left.
 */
function bashViewDigest(view: BashProgramFactsView): string | undefined {
  const digest: unknown = view.callDigest;
  return typeof digest === "string" ? digest : undefined;
}

/**
 * The mode node's option shape with the mode its derivation has always needed.
 * `default` is the baseline: read-only exemptions are not applied, so the facts
 * do not depend on the mode a later link evaluates. Rules whose `scope.modes`
 * excludes `default` are the one documented exception — the projection has no
 * mode parameter to evaluate them with.
 */
function modeNodeOptions(options: ShellFactsOptions, cwd: string): ModeNodeOptions {
  return {
    mode: options.mode ?? "default",
    cwd,
    platform: options.platform ?? process.platform,
    ...(options.shellPolicy === undefined ? {} : { shellPolicy: options.shellPolicy }),
    ...(options.shellPathVariables === undefined
      ? {}
      : { shellPathVariables: options.shellPathVariables }),
    ...(options.enabledShellNodes === undefined
      ? {}
      : { enabledShellNodes: options.enabledShellNodes }),
    ...(options.shellGrants === undefined ? {} : { shellGrants: options.shellGrants }),
  };
}

/** The cwd the facts were derived in: view first, caller second, process last. */
function effectiveCwd(viewCwd: string, fallback: string | undefined): string {
  if (viewCwd.length > 0) return viewCwd;
  if (fallback !== undefined && fallback.length > 0) return fallback;
  return process.cwd();
}

/** A missing workspace root is assumed to be the call cwd (see the file JSDoc). */
function workspaceRootOf(options: ShellFactsOptions, cwd: string): string {
  const root = options.workspaceRoot;
  return root === undefined || root.trim().length === 0 ? cwd : root;
}

function dangerOptions(options: ShellFactsOptions): DangerInput["options"] {
  return options.workspaceBulkDeleteAction === undefined
    ? undefined
    : { workspaceBulkDeleteAction: options.workspaceBulkDeleteAction };
}

/** One frozen entry per declared unit, so no link can miss or invent a unit. */
function coverUnits(
  call: CallState,
  byUnit: ReadonlyMap<string, readonly AccessFact[]> | undefined,
): ReadonlyMap<string, readonly UnitAccessFact[]> {
  const access = new Map<string, readonly UnitAccessFact[]>();
  for (const unit of call.units) {
    const facts = byUnit?.get(unit.unitId);
    access.set(unit.unitId, facts === undefined ? UNKNOWN_ACCESS : freezeAccessFacts(facts));
  }
  return access;
}

/** Copy the existing facts into the chain's shape and freeze each array. */
function freezeAccessFacts(facts: readonly AccessFact[]): readonly UnitAccessFact[] {
  return Object.freeze(facts.map((fact): UnitAccessFact => Object.freeze({
    kind: fact.kind,
    ...(fact.path === undefined ? {} : { path: fact.path }),
    ...(fact.external === undefined ? {} : { external: fact.external }),
    ...(fact.externalDelete === undefined ? {} : { externalDelete: fact.externalDelete }),
  })));
}

function freezeProjection(projection: ShellFactsProjection): ShellFactsProjection {
  return Object.freeze(projection);
}

