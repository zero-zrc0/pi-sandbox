/**
 * Danger-intent detection (approval-chain v3 §5, v4 §3).
 *
 * One pure call turns the frozen shell facts of a *single* call into the six
 * built-in danger families. The module only reads facts that the analysis step
 * already produced — `operations`, `invocations`, argv, effects, file targets,
 * dynamic execution — so a verdict here never depends on a re-parse, a second
 * reading of the text, or on running anything. It executes no command, expands
 * nothing, reads no file, and does not touch the network.
 *
 * Not in scope:
 *
 * - no chain, node, or verdict algebra: the caller decides how a hit combines
 *   with other restrictions and with the channel (normal = deny, elevation =
 *   ask), and it alone knows the mode;
 * - no cross-call memory (v4 §0.4): an archive produced by one call and an
 *   upload performed by the next are two unrelated facts, so `exfiltration`
 *   only fires when both halves are in the same call;
 * - no sensitive-path policy (`~/.ssh` reads, database data directories, `.git`
 *   writes): that is a separate restriction whose deny stays stricter than an
 *   `ask` here. A bulk delete of such a path is still only the bulk `ask` this
 *   module reports, and the sensitive-path handler is expected to deny it;
 * - no unknown→ask fallback: a shape the facts cannot prove yields no hit, and
 *   the chain's own fallback asks. Facts are never stretched towards "allow":
 *   an unresolved target, argv, or program simply does not match.
 *
 * The one deliberate over-approximation is the "destroy the container itself"
 * branch: a recursive delete of a filesystem root, of the home directory, of
 * the workspace root, or of a window into them (`rm -rf .`) is catastrophic,
 * because those are exactly the shapes v3 §5 lists. Everything else that is
 * proven bulk-and-recursive stays the bulk `ask`, with no path guessing.
 */
import path from "node:path";
import type {
  FileTargetFact,
  Knowledge,
  ProgramInvocation,
  ShellOperationFact,
} from "#approve-core/policy/shell-policy/facts";

export type DangerKind =
  | "destructive-db"
  | "catastrophic-delete"
  | "workspace-bulk-delete"
  | "exfiltration"
  | "credential-upload"
  | "host-control";

export interface DangerHit {
  readonly kind: DangerKind;
  /** normal 通道下的处置；workspace-bulk-delete 可配置，其余固定 deny。 */
  readonly action: "deny" | "ask";
  /** 机器可读原因，形如 risk:<kind>:<detail>，不带提权提示文案。 */
  readonly reason: string;
  /** 命中的调用内单元 id；同一调用内多单元命中（如 tar + curl）要列出全部。 */
  readonly unitIds: readonly string[];
}

export interface DangerInput {
  readonly shell: "bash" | "powershell";
  readonly cwd: string;
  /** 工作区根；不确定时 undefined —— 此时不得据此放宽 catastrophic-delete。 */
  readonly workspaceRoot?: string;
  readonly operations: readonly ShellOperationFact[];
  readonly invocations: readonly ProgramInvocation[];
  /**
   * Accepted for callers that already hold the frozen text. Detection ignores
   * it on purpose: every verdict comes from structured facts, so a text/parse
   * disagreement can never become a weaker verdict.
   */
  readonly commandText?: string;
  readonly platform?: NodeJS.Platform;
  readonly options?: { readonly workspaceBulkDeleteAction?: "deny" | "ask" };
}

type PermissionDisposition = DangerHit["action"];

/** Hit order is the order of the v3 §5 table, so callers see a stable list. */
const DANGER_ORDER: readonly DangerKind[] = Object.freeze([
  "destructive-db",
  "catastrophic-delete",
  "workspace-bulk-delete",
  "exfiltration",
  "credential-upload",
  "host-control",
] satisfies readonly DangerKind[]);

/**
 * Detail precedence inside one kind. Several units can hit one kind with
 * different details (`dd` and `chmod` in one call); the reason keeps a single
 * machine-readable detail and this table makes the choice reproducible instead
 * of dependent on invocation order.
 */
const DETAIL_PRIORITY: ReadonlyMap<DangerKind, readonly string[]> = new Map<
  DangerKind,
  readonly string[]
>([
  ["destructive-db", [
    "drop-database", "drop-table", "truncate", "flushall", "flushdb",
    "drop-collection", "docker-volume-rm", "drop-flag",
  ]],
  ["catastrophic-delete", [
    "root", "home", "workspace-root", "cwd", "block-device", "mkfs", "format",
    "diskpart", "git-clean", "chmod-root",
  ]],
  ["workspace-bulk-delete", ["recursive-delete", "forced-delete", "find-delete", "git-clean"]],
  ["exfiltration", ["archive-upload", "secret-upload"]],
  ["credential-upload", ["ssh", "aws", "dotenv", "private-key", "cloud-credentials"]],
  ["host-control", [
    "privilege-escalation", "service-control", "power-control", "user-management",
    "scheduled-task", "registry",
  ]],
]);

interface DetectContext {
  readonly shell: "bash" | "powershell";
  readonly cwd: string;
  readonly workspaceRoot: string | undefined;
  readonly platform: NodeJS.Platform;
}

interface InvocationFacts {
  readonly unitId: string;
  readonly operationId: string;
  readonly name: string;
  readonly argv: readonly string[] | undefined;
}

interface DangerCandidate {
  readonly detail: string;
  readonly unitId: string;
}

interface UnitSignals {
  archive: boolean;
  secretRead: boolean;
  outbound: boolean;
}

interface DetectionState {
  readonly context: DetectContext;
  readonly operations: readonly ShellOperationFact[];
  readonly candidates: Map<DangerKind, DangerCandidate[]>;
  readonly signals: Map<string, UnitSignals>;
}

interface DeleteOptions {
  readonly bulkDetail: string;
  /** `rm -rf .` removes the directory the call runs in; `find -delete` does not. */
  readonly cwdIsCatastrophic: boolean;
  /** A PowerShell delete can take its targets from the pipeline, so empty argv still counts. */
  readonly emptyIsBulk: boolean;
}

interface PathOperations {
  readonly isAbsolute: (value: string) => boolean;
  readonly resolve: (base: string, target: string) => string;
  readonly relative: (from: string, to: string) => string;
}

export function detectDangers(input: DangerInput): readonly DangerHit[] {
  const state: DetectionState = {
    context: {
      shell: input.shell,
      cwd: input.cwd,
      workspaceRoot: input.workspaceRoot,
      platform: input.platform ?? process.platform,
    },
    operations: input.operations,
    candidates: new Map<DangerKind, DangerCandidate[]>(),
    signals: new Map<string, UnitSignals>(),
  };
  for (const invocation of input.invocations) {
    const program = knownValue(invocation.program);
    if (program === undefined) continue;
    const facts: InvocationFacts = {
      unitId: invocation.unitId,
      operationId: invocation.operationId,
      name: programName(program),
      argv: knownValue(invocation.argv),
    };
    detectDestructiveDatabase(state, facts);
    detectHostControl(state, facts);
    detectDeletion(state, facts);
    detectTransfer(state, facts);
  }
  detectBlockDeviceTargets(state);
  detectExfiltration(state);
  return buildHits(state.candidates, bulkDeleteDisposition(input.options));
}

/* ------------------------------------------------------------------ */
/* output assembly                                                     */
/* ------------------------------------------------------------------ */

function bulkDeleteDisposition(options: DangerInput["options"]): PermissionDisposition {
  return options?.workspaceBulkDeleteAction === "deny" ? "deny" : "ask";
}

function actionFor(kind: DangerKind, bulkDelete: PermissionDisposition): PermissionDisposition {
  return kind === "workspace-bulk-delete" ? bulkDelete : "deny";
}

function preferredDetail(kind: DangerKind, candidates: readonly DangerCandidate[]): string {
  const priority = DETAIL_PRIORITY.get(kind) ?? [];
  for (const detail of priority) {
    if (candidates.some((candidate) => candidate.detail === detail)) return detail;
  }
  return candidates[0]?.detail ?? kind;
}

function unitIdsOf(candidates: readonly DangerCandidate[]): readonly string[] {
  const seen = new Set<string>();
  const unitIds: string[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.unitId)) continue;
    seen.add(candidate.unitId);
    unitIds.push(candidate.unitId);
  }
  return unitIds;
}

function buildHits(
  candidates: ReadonlyMap<DangerKind, readonly DangerCandidate[]>,
  bulkDelete: PermissionDisposition,
): readonly DangerHit[] {
  const hits: DangerHit[] = [];
  for (const kind of DANGER_ORDER) {
    const found = candidates.get(kind);
    if (found === undefined || found.length === 0) continue;
    hits.push(Object.freeze({
      kind,
      action: actionFor(kind, bulkDelete),
      reason: `risk:${kind}:${preferredDetail(kind, found)}`,
      unitIds: Object.freeze(unitIdsOf(found)),
    }));
  }
  return Object.freeze(hits);
}

function noteDanger(
  state: DetectionState,
  kind: DangerKind,
  detail: string,
  unitId: string,
): void {
  const found = state.candidates.get(kind);
  if (found === undefined) state.candidates.set(kind, [{ detail, unitId }]);
  else found.push({ detail, unitId });
}

function signalsFor(state: DetectionState, unitId: string): UnitSignals {
  const existing = state.signals.get(unitId);
  if (existing !== undefined) return existing;
  const created: UnitSignals = { archive: false, secretRead: false, outbound: false };
  state.signals.set(unitId, created);
  return created;
}

/* ------------------------------------------------------------------ */
/* fact access                                                         */
/* ------------------------------------------------------------------ */

function knownValue<T>(value: Knowledge<T>): T | undefined {
  return value.status === "known" ? value.value : undefined;
}

/** A trailing path segment without a Windows executable suffix, lower-cased. */
function programName(program: string): string {
  const separator = Math.max(program.lastIndexOf("/"), program.lastIndexOf("\\"));
  const base = separator < 0 ? program : program.slice(separator + 1);
  return base.replace(/\.(?:exe|com|cmd|bat|ps1)$/u, "").toLowerCase();
}

function fileTargetPaths(
  operations: readonly ShellOperationFact[],
  operationId: string,
  effect: FileTargetFact["effect"],
): readonly string[] {
  const paths: string[] = [];
  for (const operation of operations) {
    if (operation.operationId !== operationId) continue;
    const targets = knownValue(operation.fileTargets);
    if (targets === undefined) continue;
    for (const target of targets) {
      if (target.effect === effect) paths.push(target.path);
    }
  }
  return paths;
}

/** argv plus the resolved file targets: both are facts the analysis produced. */
function observableValues(
  facts: InvocationFacts,
  operations: readonly ShellOperationFact[],
): readonly string[] {
  const values: string[] = [...(facts.argv ?? [])];
  for (const operation of operations) {
    if (operation.operationId !== facts.operationId) continue;
    const targets = knownValue(operation.fileTargets);
    if (targets === undefined) continue;
    for (const target of targets) values.push(target.path);
  }
  return values;
}

interface FlagSet {
  hasShort(flag: string): boolean;
  hasLong(flag: string): boolean;
}

/** Short clusters and long options kept apart; `--` ends the options. */
function collectFlags(argv: readonly string[]): FlagSet {
  const short = new Set<string>();
  const long = new Set<string>();
  for (const argument of argv) {
    if (argument === "--") break;
    if (argument.startsWith("--")) {
      const name = argument.slice(2).split("=")[0].toLowerCase();
      if (name.length > 0) long.add(name);
      continue;
    }
    if (/^-[A-Za-z]+$/u.test(argument)) {
      for (const flag of argument.slice(1)) short.add(flag.toLowerCase());
    }
  }
  return {
    hasShort: (flag: string): boolean => short.has(flag.toLowerCase()),
    hasLong: (flag: string): boolean => long.has(flag.toLowerCase()),
  };
}

function positionalOperands(argv: readonly string[]): readonly string[] {
  const operands: string[] = [];
  let terminated = false;
  for (const argument of argv) {
    if (!terminated && argument === "--") {
      terminated = true;
      continue;
    }
    if (!terminated && argument.length > 1 && argument.startsWith("-")) continue;
    if (argument.length === 0) continue;
    operands.push(argument);
  }
  return operands;
}

/** PowerShell parameter names, including the `-Recurse:$true` spelling. */
function collectSwitches(argv: readonly string[]): ReadonlySet<string> {
  const switches = new Set<string>();
  for (const argument of argv) {
    const match = /^-([A-Za-z]+)(?::\s*\$true)?$/u.exec(argument);
    if (match?.[1] === undefined) continue;
    switches.add(match[1].toLowerCase());
  }
  return switches;
}

/* ------------------------------------------------------------------ */
/* path classification                                                 */
/* ------------------------------------------------------------------ */

function pathOperations(context: DetectContext): PathOperations {
  return context.platform === "win32" ? path.win32 : path.posix;
}

function foldPath(context: DetectContext, value: string): string {
  return context.platform === "win32" ? value.toLowerCase() : value;
}

/** `/`, `/*`, `//`, `C:`, `C:\`, `C:/*`, `\`, and their `.` variants. */
function isRootTarget(target: string): boolean {
  if (/^\/+$/u.test(target)) return true;
  if (/^\/+(?:\.|\*)$/u.test(target)) return true;
  if (/^[A-Za-z]:(?:[\\/]+)?(?:\.|\*)?$/u.test(target)) return true;
  return /^[\\/]{1,2}(?:\.|\*)?$/u.test(target);
}

/** `~`, `$HOME`, `%USERPROFILE%`, and the "everything in home" spellings. */
const HOME_TARGETS: ReadonlySet<string> = Object.freeze(new Set([
  "~", "$HOME", "${HOME}", "%USERPROFILE%",
]));

const HOME_WILDCARD = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)[\\/](?:\.|\*)$/u;

function isHomeTarget(target: string): boolean {
  return HOME_TARGETS.has(target.replace(/[\\/]+$/u, "")) || HOME_WILDCARD.test(target);
}

function isCwdTarget(target: string): boolean {
  const trimmed = target.replace(/[\\/]+$/u, "");
  return trimmed === "" || trimmed === ".";
}

/**
 * The target as an absolute path, or undefined when the text is an expansion,
 * a glob, or a stream name: an unresolved operand must not be guessed.
 */
function absoluteTarget(context: DetectContext, target: string): string | undefined {
  if (target.length === 0 || target === "-") return undefined;
  if (/[$%~*?[\]{}]/u.test(target)) return undefined;
  const api = pathOperations(context);
  const absolute = api.isAbsolute(target) ? target : api.resolve(context.cwd, target);
  return api.resolve(absolute, ".");
}

/** True when deleting `absolute` would also remove the workspace root itself. */
function isWorkspaceRootOrAncestor(context: DetectContext, absolute: string): boolean {
  const root = context.workspaceRoot;
  if (root === undefined || root.trim().length === 0) return false;
  const api = pathOperations(context);
  const foldedRoot = foldPath(context, api.resolve(root, "."));
  const foldedTarget = foldPath(context, absolute);
  if (foldedRoot === foldedTarget) return true;
  const relative = api.relative(foldedTarget, foldedRoot);
  return relative.length > 0 && !relative.startsWith("..") && !api.isAbsolute(relative);
}

interface TargetClass {
  readonly kind: "catastrophic" | "bulk";
  readonly detail: string;
}

function classifyDeleteTarget(
  context: DetectContext,
  target: string,
  options: DeleteOptions,
): TargetClass {
  if (isRootTarget(target)) return { kind: "catastrophic", detail: "root" };
  if (isHomeTarget(target)) return { kind: "catastrophic", detail: "home" };
  const absolute = absoluteTarget(context, target);
  if (absolute !== undefined && isWorkspaceRootOrAncestor(context, absolute)) {
    return { kind: "catastrophic", detail: "workspace-root" };
  }
  if (options.cwdIsCatastrophic && isCwdTarget(target)) {
    return { kind: "catastrophic", detail: "cwd" };
  }
  return { kind: "bulk", detail: options.bulkDetail };
}

function recordDeleteTargets(
  state: DetectionState,
  unitId: string,
  targets: readonly string[],
  options: DeleteOptions,
): void {
  if (targets.length === 0) {
    // A recursive delete that proved no operand is only a bulk ask when the
    // targets can come from elsewhere (a PowerShell pipeline). `rm -r` with no
    // operand deletes nothing, so it stays unmatched.
    if (options.emptyIsBulk) {
      noteDanger(state, "workspace-bulk-delete", options.bulkDetail, unitId);
    }
    return;
  }
  const bulkDetails: string[] = [];
  let catastrophic = false;
  for (const target of targets) {
    const classification = classifyDeleteTarget(state.context, target, options);
    if (classification.kind === "catastrophic") {
      catastrophic = true;
      noteDanger(state, "catastrophic-delete", classification.detail, unitId);
      continue;
    }
    bulkDetails.push(classification.detail);
  }
  if (!catastrophic) {
    noteDanger(state, "workspace-bulk-delete", bulkDetails[0] ?? options.bulkDetail, unitId);
  }
}

const BLOCK_DEVICE =
  /^\/dev\/(?:sd|hd|vd|nvme|mmcblk|disk|loop|ram|dm-|md|sr|mapper)/iu;

function isBlockDevicePath(target: string): boolean {
  return BLOCK_DEVICE.test(target);
}

/* ------------------------------------------------------------------ */
/* destructive-db (v3 §5 row 1)                                        */
/* ------------------------------------------------------------------ */

const DATABASE_PROGRAMS: ReadonlySet<string> = new Set([
  "mysql", "mariadb", "psql", "sqlite3", "mongo", "mongosh", "redis-cli", "docker",
]);

const DOCKER_VOLUME_REMOVALS: ReadonlySet<string> = new Set(["rm", "prune"]);

function detectDestructiveDatabase(state: DetectionState, facts: InvocationFacts): void {
  const argv = facts.argv;
  if (argv === undefined) return;
  // `--drop` rewrites the dump target instead of restoring into it, whatever
  // program carries the flag.
  if (argv.includes("--drop")) {
    noteDanger(state, "destructive-db", "drop-flag", facts.unitId);
  }
  if (!DATABASE_PROGRAMS.has(facts.name)) return;
  if (facts.name === "docker") {
    const group = argv[0]?.toLowerCase();
    const verb = argv[1]?.toLowerCase();
    if (group === "volume" && verb !== undefined && DOCKER_VOLUME_REMOVALS.has(verb)) {
      noteDanger(state, "destructive-db", "docker-volume-rm", facts.unitId);
    }
    return;
  }
  if (facts.name === "redis-cli") {
    for (const argument of argv) {
      const verb = argument.toUpperCase();
      if (verb === "FLUSHALL") noteDanger(state, "destructive-db", "flushall", facts.unitId);
      if (verb === "FLUSHDB") noteDanger(state, "destructive-db", "flushdb", facts.unitId);
    }
    return;
  }
  if (facts.name === "mongo" || facts.name === "mongosh") {
    for (const argument of argv) {
      if (/dropDatabase\s*\(/iu.test(argument)) {
        noteDanger(state, "destructive-db", "drop-database", facts.unitId);
      } else if (/\.drop\s*\(/u.test(argument)) {
        noteDanger(state, "destructive-db", "drop-collection", facts.unitId);
      }
    }
    return;
  }
  const detail = sqlDestructiveDetail(argv);
  if (detail !== undefined) noteDanger(state, "destructive-db", detail, facts.unitId);
}

/** The SQL text a client carries on its command line is already dequoted argv. */
function sqlDestructiveDetail(argv: readonly string[]): string | undefined {
  for (const argument of argv) {
    if (/\bdrop\s+(?:database|schema)\b/iu.test(argument)) return "drop-database";
    if (/\bdrop\s+table\b/iu.test(argument)) return "drop-table";
    if (/\btruncate\b/iu.test(argument)) return "truncate";
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* host-control (v3 §5 row 6)                                          */
/* ------------------------------------------------------------------ */

const PRIVILEGE_PROGRAMS: ReadonlySet<string> = new Set([
  "sudo", "doas", "su", "pkexec", "runas",
]);

const SERVICE_PROGRAMS: ReadonlySet<string> = new Set([
  "systemctl", "service", "sc", "launchctl",
  "set-service", "start-service", "stop-service", "restart-service", "new-service",
  "remove-service", "suspend-service", "resume-service",
]);

const POWER_PROGRAMS: ReadonlySet<string> = new Set([
  "shutdown", "reboot", "poweroff", "halt", "stop-computer", "restart-computer",
]);

const USER_PROGRAMS: ReadonlySet<string> = new Set([
  "useradd", "userdel", "usermod", "groupadd", "groupdel", "adduser", "deluser",
  "chpasswd", "passwd", "visudo",
  "new-localuser", "remove-localuser", "set-localuser", "rename-localuser",
  "enable-localuser", "disable-localuser", "new-localgroup", "remove-localgroup",
  "add-localgroupmember", "remove-localgroupmember",
]);

const REGISTRY_PROGRAMS: ReadonlySet<string> = new Set(["reg", "regedit"]);

const REGISTRY_MUTATIONS: ReadonlySet<string> = new Set([
  "add", "delete", "import", "load", "restore", "copy", "unload",
]);

const SCHEDULE_PROGRAMS: ReadonlySet<string> = new Set(["crontab", "at", "schtasks"]);

const SCHEDULE_CMDLETS: ReadonlySet<string> = new Set([
  "register-scheduledtask", "unregister-scheduledtask", "new-scheduledtask",
  "start-scheduledtask", "stop-scheduledtask", "disable-scheduledtask",
  "enable-scheduledtask",
]);

const SCHEDULE_MUTATIONS: ReadonlySet<string> = new Set([
  "create", "change", "delete", "run", "end", "import",
]);

function detectHostControl(state: DetectionState, facts: InvocationFacts): void {
  const { name, argv } = facts;
  if (PRIVILEGE_PROGRAMS.has(name)) {
    noteDanger(state, "host-control", "privilege-escalation", facts.unitId);
    return;
  }
  if (SERVICE_PROGRAMS.has(name)) {
    noteDanger(state, "host-control", "service-control", facts.unitId);
    return;
  }
  if (POWER_PROGRAMS.has(name)) {
    noteDanger(state, "host-control", "power-control", facts.unitId);
    return;
  }
  if (USER_PROGRAMS.has(name)) {
    noteDanger(state, "host-control", "user-management", facts.unitId);
    return;
  }
  if (SCHEDULE_CMDLETS.has(name)) {
    noteDanger(state, "host-control", "scheduled-task", facts.unitId);
    return;
  }
  if (REGISTRY_PROGRAMS.has(name)) {
    if (isRegistryMutation(name, argv)) {
      noteDanger(state, "host-control", "registry", facts.unitId);
    }
    return;
  }
  if (SCHEDULE_PROGRAMS.has(name)) {
    if (isScheduleMutation(name, argv)) {
      noteDanger(state, "host-control", "scheduled-task", facts.unitId);
    }
    return;
  }
  if (name === "net" && argv !== undefined) detectNetHostControl(state, facts, argv);
}

function isRegistryMutation(name: string, argv: readonly string[] | undefined): boolean {
  if (name === "regedit") return true;
  if (argv === undefined) return false;
  const verb = argv[0]?.toLowerCase();
  return verb !== undefined && REGISTRY_MUTATIONS.has(verb);
}

/**
 * A read-only query stays clean (`reg query`, `schtasks /query`, `crontab -l`,
 * `at -l`); only a proven mutating verb is host control.
 */
function isScheduleMutation(name: string, argv: readonly string[] | undefined): boolean {
  if (argv === undefined) return false;
  if (name === "schtasks") {
    return argv.some((argument) =>
      SCHEDULE_MUTATIONS.has(argument.replace(/^\//u, "").toLowerCase()));
  }
  if (name === "crontab") {
    if (argv.some((argument) => argument === "-e" || argument === "-r" || argument === "-i")) {
      return true;
    }
    // `crontab file` installs a crontab; `crontab -l` only lists one.
    return positionalOperands(argv).length > 0;
  }
  // `at`: the time/command operands schedule a job, `-l`/`-r` handle the queue.
  if (argv.some((argument) => argument === "-l")) return false;
  return positionalOperands(argv).length > 0;
}

function detectNetHostControl(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  const verb = argv[0]?.toLowerCase();
  if (verb === "start" || verb === "stop") {
    noteDanger(state, "host-control", "service-control", facts.unitId);
    return;
  }
  const mutates = argv.some((argument) => /^\/(?:add|delete)$/iu.test(argument));
  const scope = argv.some((argument) => /^(?:user|group|localgroup)$/iu.test(argument));
  if (mutates && scope) noteDanger(state, "host-control", "user-management", facts.unitId);
}

/* ------------------------------------------------------------------ */
/* catastrophic-delete / workspace-bulk-delete (v3 §5 rows 2 and 3)    */
/* ------------------------------------------------------------------ */

const POWERSHELL_DELETE_PROGRAMS: ReadonlySet<string> = new Set([
  "remove-item", "rm", "ri", "del", "erase", "rd", "rmdir",
]);

const GIT_GLOBAL_OPTIONS_WITH_VALUE: ReadonlySet<string> = new Set([
  "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix",
]);

const GIT_GLOBAL_OPTION_WITH_ATTACHED_VALUE =
  /^(?:--git-dir|--work-tree|--namespace|--config-env|--super-prefix|--exec-path)=/u;

/** A Git global flag that neither consumes the next word nor changes the parse. */
const GIT_GLOBAL_FLAG = /^(?:-[Cc].+|-[A-Za-z]|--[A-Za-z][\w-]*)$/u;

function detectDeletion(state: DetectionState, facts: InvocationFacts): void {
  const { name, argv } = facts;
  // Whole-device/format programs decide by name alone: an unresolved argv must
  // still not let `mkfs.ext4` through as an unknown command.
  if (name === "mkfs" || name.startsWith("mkfs.")) {
    noteDanger(state, "catastrophic-delete", "mkfs", facts.unitId);
    return;
  }
  if (name === "format") {
    noteDanger(state, "catastrophic-delete", "format", facts.unitId);
    return;
  }
  if (name === "diskpart") {
    noteDanger(state, "catastrophic-delete", "diskpart", facts.unitId);
    return;
  }
  if (argv === undefined) return;
  if (POWERSHELL_DELETE_PROGRAMS.has(name)) detectPowerShellDeletion(state, facts, argv);
  if (name === "rm") detectRecursiveRm(state, facts, argv);
  if (name === "find") detectFindDelete(state, facts, argv);
  if (name === "chmod") detectRecursiveChmod(state, facts, argv);
  if (name === "dd") detectDiskWrite(state, facts, argv);
  if (name === "git") detectGitClean(state, facts, argv);
}

function detectPowerShellDeletion(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  const switches = collectSwitches(argv);
  const recursive = switches.has("recurse") || switches.has("r");
  const force = switches.has("force") || switches.has("fo");
  if (!recursive && !force) return;
  const targets = [
    ...positionalOperands(argv),
    ...fileTargetPaths(state.operations, facts.operationId, "file.delete"),
  ];
  if (!recursive && !targets.some(target => /[*?\[]/.test(target))) {
    for (const target of targets) {
      const classification = classifyDeleteTarget(state.context, target, {
        bulkDetail: "forced-delete", cwdIsCatastrophic: true, emptyIsBulk: false,
      });
      if (classification.kind === "catastrophic") noteDanger(state, "catastrophic-delete", classification.detail, facts.unitId);
    }
    return;
  }
  recordDeleteTargets(state, facts.unitId, targets, {
    bulkDetail: "forced-delete",
    cwdIsCatastrophic: true,
    emptyIsBulk: true,
  });
}

function detectRecursiveRm(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  const flags = collectFlags(argv);
  // Force only suppresses `rm`'s own prompts; in a non-interactive call the
  // recursive deletion happens either way, so recency is the trigger.
  if (!flags.hasShort("r") && !flags.hasLong("recursive")) return;
  recordDeleteTargets(state, facts.unitId, positionalOperands(argv), {
    bulkDetail: "recursive-delete",
    cwdIsCatastrophic: true,
    emptyIsBulk: false,
  });
}

function detectFindDelete(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  if (!argv.some((argument) => argument === "-delete")) return;
  // `find` removes entries below its start path, not the start directory, so a
  // workspace-root start stays the bulk row of v3 §5. Only a filesystem-root
  // start is the "deleted the root itself" shape.
  if (positionalOperands(argv).some(isRootTarget)) {
    noteDanger(state, "catastrophic-delete", "root", facts.unitId);
    return;
  }
  noteDanger(state, "workspace-bulk-delete", "find-delete", facts.unitId);
}

function detectRecursiveChmod(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  const flags = collectFlags(argv);
  if (!flags.hasShort("r") && !flags.hasLong("recursive")) return;
  const worldWritable = argv.some((argument) =>
    /^(?:0?777|7777|a\+rwx|a=rwx)$/iu.test(argument));
  if (!worldWritable) return;
  if (!positionalOperands(argv).some(isRootTarget)) return;
  noteDanger(state, "catastrophic-delete", "chmod-root", facts.unitId);
}

function detectDiskWrite(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  for (const argument of argv) {
    if (!argument.startsWith("of=")) continue;
    if (!isBlockDevicePath(argument.slice(3))) continue;
    noteDanger(state, "catastrophic-delete", "block-device", facts.unitId);
    return;
  }
}

interface GitCommand {
  readonly name: string;
  readonly args: readonly string[];
}

/** Find Git's subcommand; an unknown global option makes the shape unprovable. */
function gitSubcommand(argv: readonly string[]): GitCommand | undefined {
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] ?? "";
    if (argument === "--") {
      const command = argv[index + 1];
      return command === undefined
        ? undefined
        : { name: command.toLowerCase(), args: argv.slice(index + 2) };
    }
    if (!argument.startsWith("-")) {
      return { name: argument.toLowerCase(), args: argv.slice(index + 1) };
    }
    if (GIT_GLOBAL_OPTIONS_WITH_VALUE.has(argument)) {
      index += 1;
      continue;
    }
    // An attached value (`--git-dir=/x`) or a known flag keeps the subcommand
    // discoverable; anything else could swallow the next word, so the shape
    // stays unprovable rather than guessed.
    if (GIT_GLOBAL_OPTION_WITH_ATTACHED_VALUE.test(argument)) continue;
    if (GIT_GLOBAL_FLAG.test(argument)) continue;
    return undefined;
  }
  return undefined;
}

function detectGitClean(
  state: DetectionState,
  facts: InvocationFacts,
  argv: readonly string[],
): void {
  const command = gitSubcommand(argv);
  if (command?.name !== "clean") return;
  const flags = collectFlags(command.args);
  if (flags.hasShort("n") || flags.hasLong("dry-run")) return;
  const force = flags.hasShort("f") || flags.hasLong("force");
  if (!force) return;
  const directories = flags.hasShort("d") || flags.hasLong("directory");
  const ignored = flags.hasShort("x") || flags.hasShort("X");
  if (directories && ignored) {
    noteDanger(state, "catastrophic-delete", "git-clean", facts.unitId);
    return;
  }
  noteDanger(state, "workspace-bulk-delete", "git-clean", facts.unitId);
}

/** Raw block devices written through a redirect or a write target. */
function detectBlockDeviceTargets(state: DetectionState): void {
  for (const operation of state.operations) {
    const targets = knownValue(operation.fileTargets);
    if (targets === undefined) continue;
    for (const target of targets) {
      if (target.effect === "file.read") continue;
      if (!isBlockDevicePath(target.path)) continue;
      noteDanger(state, "catastrophic-delete", "block-device", operation.unitId);
    }
  }
}

/* ------------------------------------------------------------------ */
/* exfiltration / credential-upload (v3 §5 rows 4 and 5)               */
/* ------------------------------------------------------------------ */

const ARCHIVE_PROGRAMS: ReadonlySet<string> = new Set(["tar", "zip", "7z", "7za", "7zr"]);

const OUTBOUND_PROGRAMS: ReadonlySet<string> = new Set([
  "curl", "wget", "scp", "sftp", "rsync", "ssh", "telnet", "ftp", "tftp",
  "nc", "netcat", "ncat", "socat", "rsh", "rcp",
  "invoke-webrequest", "invoke-restmethod", "iwr", "irm",
  "start-bitstransfer", "send-mailmessage",
]);

const SECRET_READER_PROGRAMS: ReadonlySet<string> = new Set([
  "cat", "head", "tail", "less", "more", "bat", "strings", "base64", "od", "xxd",
  "grep", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq", "diff",
  "get-content", "type", "select-string", "get-childitem",
]);

const SSH_KEY_PATHS =
  /(?:^|[\\/])\.ssh(?:[\\/]|$)|(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/iu;
const AWS_CREDENTIAL_PATHS =
  /(?:^|[\\/])\.aws(?:[\\/]|$)|AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)/u;
const DOTENV_PATHS = /(?:^|[\\/])\.env(?:\.|$)/u;
const PRIVATE_KEY_FILES = /\.(?:pem|key|p12|pfx|jks)$/iu;
const CLOUD_CREDENTIAL_FILES =
  /(?:^|[\\/])\.(?:netrc|git-credentials|npmrc|pypirc|docker|kube)(?:[\\/]|$)/u;
const CLOUD_CREDENTIAL_DIRECTORIES =
  /(?:^|[\\/])\.config[\\/](?:gcloud|gh)(?:[\\/]|$)|(?:^|[\\/])\.azure(?:[\\/]|$)/u;

/**
 * Credential class in precedence order: the first matching class names the
 * reason, and the order is also `DETAIL_PRIORITY` for this kind.
 */
const CREDENTIAL_CLASSES: readonly (readonly [string, readonly RegExp[]])[] = [
  ["ssh", [SSH_KEY_PATHS]],
  ["aws", [AWS_CREDENTIAL_PATHS]],
  ["dotenv", [DOTENV_PATHS]],
  ["private-key", [PRIVATE_KEY_FILES]],
  ["cloud-credentials", [CLOUD_CREDENTIAL_FILES, CLOUD_CREDENTIAL_DIRECTORIES]],
];

function matchesAny(value: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

function credentialDetail(values: readonly string[]): string | undefined {
  for (const [detail, patterns] of CREDENTIAL_CLASSES) {
    if (values.some((value) => matchesAny(value, patterns))) return detail;
  }
  return undefined;
}

function isCredentialReference(value: string): boolean {
  return CREDENTIAL_CLASSES.some(([, patterns]) => matchesAny(value, patterns));
}

function detectTransfer(state: DetectionState, facts: InvocationFacts): void {
  const signals = signalsFor(state, facts.unitId);
  if (isArchiveInvocation(facts)) signals.archive = true;
  if (isSecretReadInvocation(facts, state.operations)) signals.secretRead = true;
  if (!OUTBOUND_PROGRAMS.has(facts.name)) return;
  signals.outbound = true;
  const detail = credentialDetail(observableValues(facts, state.operations));
  if (detail !== undefined) {
    noteDanger(state, "credential-upload", detail, facts.unitId);
  }
}

function isArchiveInvocation(facts: InvocationFacts): boolean {
  const argv = facts.argv;
  if (facts.name === "tar") return argv !== undefined && tarCreatesArchive(argv);
  // `zip` only ever creates or appends; extraction belongs to `unzip`.
  if (facts.name === "zip") return true;
  if (facts.name === "7z" || facts.name === "7za" || facts.name === "7zr") {
    return argv !== undefined && argv[0]?.toLowerCase() === "a";
  }
  if (facts.name === "git" && argv !== undefined) {
    const command = gitSubcommand(argv);
    return command?.name === "bundle" && command.args[0]?.toLowerCase() === "create";
  }
  return false;
}

/**
 * `tar` archives only in create mode. Extraction (`-x`), listing (`-t`) and
 * appending (`-r`) are not evidence of "packaged the workspace for upload", so
 * an extraction next to an upload stays unmatched instead of denying a restore.
 */
function tarCreatesArchive(argv: readonly string[]): boolean {
  const first = argv[0];
  if (first === undefined) return false;
  if (first === "--create") return true;
  const option = first.startsWith("-") ? first.slice(1) : first;
  if (option.length === 0 || !/^[A-Za-z]+$/u.test(option)) return false;
  const letters = option.toLowerCase();
  return letters.includes("c") && !letters.includes("x") && !letters.includes("t") &&
    !letters.includes("r");
}

function isSecretReadInvocation(
  facts: InvocationFacts,
  operations: readonly ShellOperationFact[],
): boolean {
  const argv = facts.argv;
  if (facts.name === "printenv") return true;
  // `env` with operands runs a program; only the bare form dumps the environment.
  if (facts.name === "env" && argv !== undefined && argv.length === 0) return true;
  if (facts.name === "kubectl" && argv !== undefined) {
    const verb = argv[0]?.toLowerCase();
    const resource = argv[1]?.toLowerCase();
    if (verb === "get" && (resource === "secret" || resource === "secrets")) return true;
  }
  // PowerShell has no `env` binary; enumerating the provider is the equivalent
  // dump of the process environment v3 §5 names.
  if ((facts.name === "get-childitem" || facts.name === "get-content") && argv !== undefined &&
      argv.some((argument) => /^env:/iu.test(argument))) {
    return true;
  }
  const values = observableValues(facts, operations);
  if (SECRET_READER_PROGRAMS.has(facts.name) && values.some(isCredentialReference)) {
    return true;
  }
  return fileTargetPaths(operations, facts.operationId, "file.read").some(isCredentialReference);
}

/**
 * Same-call only (v4 §0.4). An archive or a proven secret read on one unit plus
 * an outbound command on any unit of the same call is exfiltration; whether the
 * upload actually carries the file is not provable from facts, and guessing
 * "no" would be exactly the loosening this check exists to prevent.
 */
function detectExfiltration(state: DetectionState): void {
  const archiveUnits: string[] = [];
  const secretUnits: string[] = [];
  const outboundUnits: string[] = [];
  for (const [unitId, signals] of state.signals) {
    if (signals.archive) archiveUnits.push(unitId);
    if (signals.secretRead) secretUnits.push(unitId);
    if (signals.outbound) outboundUnits.push(unitId);
  }
  if (outboundUnits.length === 0) return;
  if (archiveUnits.length === 0 && secretUnits.length === 0) return;
  for (const unitId of archiveUnits) {
    noteDanger(state, "exfiltration", "archive-upload", unitId);
  }
  for (const unitId of secretUnits) {
    noteDanger(state, "exfiltration", "secret-upload", unitId);
  }
  const outboundDetail = archiveUnits.length > 0 ? "archive-upload" : "secret-upload";
  for (const unitId of outboundUnits) {
    noteDanger(state, "exfiltration", outboundDetail, unitId);
  }
}
