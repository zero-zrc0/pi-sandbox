/**
 * `/permission` command handler (specs/config-loading.md §10).
 *
 * This module renders the status report the host asks for. It never loads or
 * writes configuration itself: the host injects a structured snapshot, so the
 * handler can be exercised without Pi UI or a real config owner. Every
 * dependency callback is isolated behind a guard, because a broken
 * notification must never take the session down with it.
 */
import type { ApprovalChainConfig } from "#config/schema";
import type { ConfigPaths } from "#config/config-paths";
import type { EffectiveNode } from "#approve-core/contracts";

/** Help text shown for unknown input. */
const USAGE = [
  "Usage: /permission [settings]",
  "",
  "Commands:",
  "  settings          Open the permission settings dialog.",
].join("\n");

export interface PermissionArgumentCompletion {
  readonly value: string;
  readonly label: string;
  readonly description?: string;
}

const PERMISSION_SUBCOMMANDS: readonly PermissionArgumentCompletion[] = [
  { value: "settings", label: "settings", description: "Open the permission settings dialog." },
];

function matchesSubcommandPrefix(value: string, prefix: string): boolean {
  let next = 0;
  for (const character of value) {
    if (character === prefix[next]) next += 1;
    if (next === prefix.length) return true;
  }
  return false;
}

export function permissionArgumentCompletions(argumentPrefix: string): PermissionArgumentCompletion[] | null {
  const prefix = argumentPrefix.trimStart();
  if (prefix.length === 0) return PERMISSION_SUBCOMMANDS.map((item) => ({ ...item }));
  if (prefix.search(/\s/u) >= 0) return null;

  const normalized = prefix.toLowerCase();
  if (PERMISSION_SUBCOMMANDS.some((item) => item.value === normalized)) return null;
  const matches = PERMISSION_SUBCOMMANDS.filter((item) => matchesSubcommandPrefix(item.label, normalized));
  return matches.length === 0 ? null : matches.map((item) => ({ ...item }));
}

/**
 * The parts of an approval-chain snapshot the command reads. The owner's real
 * snapshot is structurally assignable to this view, so the command does not
 * depend on the owner module at runtime.
 */
export interface PermissionCommandSnapshot {
  readonly config: ApprovalChainConfig;
  readonly modeSource: "default" | "global" | "project" | "session";
  readonly paths: ConfigPaths;
  readonly nodeConfig: {
    readonly nodes: readonly EffectiveNode[];
  };
}

export interface PermissionCommandDependencies {
  /** Returns the effective snapshot for the requested session. */
  readonly snapshot: (sessionId?: string) => PermissionCommandSnapshot;
  /** The session that issued the command, when the host knows it. */
  readonly sessionId?: string;
  /** Emits command output to the user. */
  readonly notify: (message: string) => void;
}

/**
 * Handle one `/permission` command line.
 *
 * Returns `true` for the recognised branches (the bare status report and
 * argument errors) and `false` only for an unknown command. The return value
 * lets the host decide whether to show the generic command help.
 */
export function handlePermissionCommand(
  input: string,
  dependencies: PermissionCommandDependencies,
): boolean {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    reportSnapshot(dependencies, "Permission status", formatPermissionStatus);
    return true;
  }

  notify(
    dependencies,
    `Unknown command "${trimmed.split(/\s/u)[0]}". ${USAGE.split("\n")[0]}`,
  );
  return false;
}

/* ------------------------------------------------------------------ */
/* Dependency guards                                                   */
/* ------------------------------------------------------------------ */

/** Notify without letting a broken UI callback escape into the command loop. */
function notify(dependencies: PermissionCommandDependencies, message: string): void {
  try {
    dependencies.notify(message);
  } catch {
    // A notification failure must not change the effective configuration.
  }
}

/**
 * Read the snapshot once and render it. A throwing snapshot or renderer is
 * reported as a command failure instead of propagating.
 */
function reportSnapshot(
  dependencies: PermissionCommandDependencies,
  label: string,
  describe: (snapshot: PermissionCommandSnapshot) => string,
): void {
  let message: string;
  try {
    message = describe(dependencies.snapshot(dependencies.sessionId));
  } catch (error) {
    message = `${label} failed: ${errorText(error)}`;
  }
  notify(dependencies, message);
}

function errorText(error: unknown): string {
  if (error instanceof Error) {
    const message = error.message.trim();
    return message.length > 0 ? message : error.name;
  }
  const text = String(error).trim();
  return text.length > 0 ? text : "unknown error";
}

/* ------------------------------------------------------------------ */
/* status                                                              */
/* ------------------------------------------------------------------ */

/**
 * Render the compact status report: the mode and its source, the config
 * file, and — only in auto-review mode — the active approver model. Also
 * used by the settings dialog's Status view.
 */
export function formatPermissionStatus(snapshot: PermissionCommandSnapshot): string {
  const lines: string[] = [
    "Permission status",
    `Mode: ${snapshot.config.mode} (source: ${snapshot.modeSource})`,
    `Config file: ${snapshot.paths.globalConfigFile}`,
  ];
  if (snapshot.config.mode === "auto-review") {
    lines.push(`Model: ${formatApproverModel(snapshot)}`);
  }
  return lines.join("\n");
}

function formatApproverModel(snapshot: PermissionCommandSnapshot): string {
  const approver = snapshot.config.approver;
  const decision = snapshot.nodeConfig.nodes.some(
    (node) => node.id === "builtin/decision-approver" && node.enabled,
  );
  if (decision) {
    return approver.judge?.type === "pi-classifier"
      ? `${approver.judge.provider}/${approver.judge.model}`
      : "not configured";
  }
  return approver.provider && approver.model
    ? `${approver.provider}/${approver.model}`
    : "current session model";
}
