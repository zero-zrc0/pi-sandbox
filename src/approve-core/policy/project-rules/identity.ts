/**
 * Project identity and storage locations (project-rule-model spec §2).
 *
 * The identity of a project is fixed by the project root, never by a later
 * shell `cd`. The root normally comes from the host's project configuration,
 * but a git worktree root wins over both the explicit root and the startup
 * cwd. The resulting identity pins one project rules file under the Pi root.
 *
 * Every environment interaction is injectable (`platform`, `home`, `realpath`,
 * `runGit`) so the resolution is a pure function in tests.
 */
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import posixPath from "node:path/posix";
import win32Path from "node:path/win32";
import {
  IDENTITY_HASH_HEX,
  canonicalJson,
  sha256Hex,
  type ProjectIdentity,
} from "./types";

/** Platform path language; the injected value wins over the host process. */
export type IdentityPlatform = "posix" | "win32";

export interface ProjectIdentityInputs {
  /** Explicit host project root. When present it must be non-empty and absolute. */
  readonly projectRoot?: string;
  /** Startup working directory; the last fallback root. */
  readonly cwd: string;
  /** Best-effort `git rev-parse --show-toplevel`; undefined means no worktree. */
  readonly runGit?: (args: readonly string[]) => string | undefined;
  /** Best-effort canonicalization for an existing directory; may throw. */
  readonly realpath?: (path: string) => string;
  readonly platform?: IdentityPlatform;
  /** Host home directory; only used to expand a leading `~` in a root spelling. */
  readonly home?: string;
}

export interface PiRootInputs {
  /** Pi coding agent config directory, for example `<home>/.pi/agent`. */
  readonly agentDir?: string;
  readonly home?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** Directory name of the Pi configuration root, relative to the home directory. */
export const PI_CONFIG_DIR_NAME = ".pi";
/**
 * Stable environment variable that names the Pi coding agent config directory
 * (`<pi-root>/agent`); its parent is the Pi root. This is the same variable the
 * Pi coding agent itself uses (`PI_CODING_AGENT_DIR`). Home comes from `home`
 * input, then `HOME`, then `USERPROFILE`.
 */
export const PI_AGENT_DIR_ENV = "PI_CODING_AGENT_DIR";

/**
 * The project rules JSON file name. Its lock path shares the stem:
 * `project-rules.json` -> `project-rules.lock`.
 */
export const PROJECT_RULES_FILE_NAME = "project-rules.json";
export const PROJECT_RULES_LOCK_NAME = "project-rules.lock";

const SLUG_MAX_LENGTH = 48;
const SLUG_FALLBACK = "project";
const GIT_ROOT_ARGS: readonly string[] = ["rev-parse", "--show-toplevel"];

function platformFor(value: IdentityPlatform | undefined): IdentityPlatform {
  if (value === "posix" || value === "win32") return value;
  return process.platform === "win32" ? "win32" : "posix";
}

function flavorFor(platform: IdentityPlatform): typeof posixPath {
  return platform === "win32" ? win32Path : posixPath;
}

/** Detect the path language of a standalone spelling such as an injected home. */
function platformForPath(path: string): IdentityPlatform {
  return /^[A-Za-z]:[\\/]/u.test(path) || path.startsWith("\\\\") ? "win32" : "posix";
}

/** Root of the spelling, used as the lower bound when trimming separators. */
function pathRoot(path: string, platform: IdentityPlatform): string {
  return platform === "win32" ? win32Path.parse(path).root : posixPath.parse(path).root;
}

/** Normalize one spelling and drop redundant trailing separators. */
function normalizeSpelling(path: string, platform: IdentityPlatform): string {
  const flavor = flavorFor(platform);
  const normalized = flavor.normalize(path);
  const root = pathRoot(normalized, platform);
  let end = normalized.length;
  while (end > root.length) {
    const character = normalized[end - 1];
    if (character === "/" || (platform === "win32" && character === "\\")) end -= 1;
    else break;
  }
  return normalized.slice(0, end);
}

/** Validate a root: it must be non-empty and absolute after normalization. */
function strictRoot(raw: string | undefined, platform: IdentityPlatform): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  const flavor = flavorFor(platform);
  if (!flavor.isAbsolute(trimmed)) return undefined;
  const normalized = normalizeSpelling(trimmed, platform);
  if (normalized.length === 0 || !flavor.isAbsolute(normalized)) return undefined;
  return normalized;
}

/**
 * Expand a leading `~` (host home spelling) before absolute-root validation.
 * Without an injected home the spelling stays relative and is rejected.
 */
function expandTilde(raw: string, home: string | undefined): string {
  const trimmedHome = typeof home === "string" ? home.trim() : "";
  if (trimmedHome.length === 0) return raw;
  if (raw === "~") return trimmedHome;
  if (raw.startsWith("~/") || raw.startsWith("~\\")) return trimmedHome + raw.slice(1);
  return raw;
}

function firstNonEmpty(...values: readonly (string | undefined)[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

function defaultRealpath(path: string): string {
  return realpathSync.native(path);
}

function defaultRunGit(args: readonly string[]): string | undefined {
  const result = spawnSync("git", [...args], { encoding: "utf8", windowsHide: true });
  if (result.error || result.status !== 0) return undefined;
  return typeof result.stdout === "string" ? result.stdout : undefined;
}

/** Best-effort canonical spelling of an existing directory. */
function canonicalizeRoot(
  root: string,
  platform: IdentityPlatform,
  realpath: (path: string) => string,
): string {
  let candidate = root;
  try {
    const resolved = realpath(root);
    const normalized = typeof resolved === "string" ? resolved.trim() : "";
    if (normalized.length > 0) {
      const flavor = flavorFor(platform);
      if (flavor.isAbsolute(normalized)) {
        const stripped = normalizeSpelling(normalized, platform);
        if (stripped.length > 0) candidate = stripped;
      }
    }
  } catch {
    // Best effort: a missing directory keeps the normalized spelling.
  }
  // Windows comparison and storage are case-insensitive; lowercase the root so
  // case variants resolve to exactly one identity.
  return platform === "win32" ? candidate.toLowerCase() : candidate;
}

/** Best-effort git worktree root, discovered from the startup cwd. */
function discoverGitRoot(
  inputs: ProjectIdentityInputs,
  cwd: string,
  platform: IdentityPlatform,
): string | undefined {
  const trimmedCwd = typeof cwd === "string" ? cwd.trim() : "";
  if (trimmedCwd.length === 0) return undefined;
  const args = ["-C", trimmedCwd, ...GIT_ROOT_ARGS];
  let output: string | undefined;
  try {
    output = inputs.runGit ? inputs.runGit(args) : defaultRunGit(args);
  } catch {
    return undefined;
  }
  if (typeof output !== "string") return undefined;
  const trimmed = output.trim();
  if (trimmed.length === 0) return undefined;
  return strictRoot(trimmed, platform);
}

/**
 * Resolve one normalized project identity.
 *
 * Root precedence: git worktree root, then an explicit host `projectRoot`,
 * then the startup `cwd`. An explicit `projectRoot` that is empty or relative
 * is a configuration error: it resolves to `undefined` instead of silently
 * falling back. Returns `undefined` when no absolute root can be proven.
 */
export function resolveProjectIdentity(
  inputs: ProjectIdentityInputs,
): ProjectIdentity | undefined {
  const platform = platformFor(inputs.platform);
  const home = inputs.home;
  const explicitInput =
    inputs.projectRoot === undefined ? undefined : expandTilde(inputs.projectRoot, home);
  const cwdInput = typeof inputs.cwd === "string" ? expandTilde(inputs.cwd, home) : "";

  const explicitRoot = strictRoot(explicitInput, platform);
  if (inputs.projectRoot !== undefined && explicitRoot === undefined) return undefined;

  const gitRoot = discoverGitRoot(inputs, cwdInput, platform);
  const cwdRoot = strictRoot(cwdInput, platform);
  const selected = gitRoot ?? explicitRoot ?? cwdRoot;
  if (selected === undefined) return undefined;

  const rootPath = canonicalizeRoot(selected, platform, inputs.realpath ?? defaultRealpath);
  const flavor = flavorFor(platform);
  const baseName = flavor.basename(rootPath);
  const displayName = baseName.length > 0 ? baseName : rootPath;
  const slug = slugifyProjectName(displayName);
  // The hash covers the complete normalized identity minus the hash itself.
  const identityHash = sha256Hex(
    canonicalJson({ rootPath, displayName, slug }),
  ).slice(0, IDENTITY_HASH_HEX);

  return { rootPath, displayName, slug, identityHash };
}

/**
 * Slug used only for locating the project directory; it is never an
 * authorization credential (the identity hash disambiguates).
 */
export function slugifyProjectName(name: string): string {
  const slug = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, SLUG_MAX_LENGTH)
    .replace(/-+$/gu, "");
  return slug.length > 0 ? slug : SLUG_FALLBACK;
}

/**
 * Resolve the Pi configuration root (the parent of the `agent` directory).
 *
 * Only an explicitly provided agent directory whose basename is exactly
 * `agent` is promoted to its parent; every other agent directory is ignored.
 * Otherwise the Pi root is `<home>/.pi`, where home comes from the injected
 * home, then `HOME`, then `USERPROFILE`, then the host home directory.
 */
export function resolvePiRoot(inputs: PiRootInputs): string {
  const env = inputs.env ?? {};
  const agentDir = firstNonEmpty(inputs.agentDir, env[PI_AGENT_DIR_ENV]);
  if (agentDir !== undefined) {
    const platform = platformForPath(agentDir);
    const flavor = flavorFor(platform);
    if (flavor.isAbsolute(agentDir)) {
      const normalized = normalizeSpelling(agentDir, platform);
      if (normalized.length > 0 && flavor.basename(normalized) === "agent") {
        return flavor.dirname(normalized);
      }
    }
  }

  const home = firstNonEmpty(inputs.home, env.HOME, env.USERPROFILE) ?? homedir();
  const platform = platformForPath(home);
  const flavor = flavorFor(platform);
  const base = home.trim();
  const normalizedHome = flavor.isAbsolute(base) ? normalizeSpelling(base, platform) : base;
  return flavor.join(normalizedHome, PI_CONFIG_DIR_NAME);
}

/**
 * Storage location of one project's rules.
 *
 * Layout: `<piRoot>/<slug>--<identityHash>/`, with the rules JSON file and its
 * same-stem lock file. The path language follows the identity's root spelling.
 */
export function projectRulesLocation(
  identity: ProjectIdentity,
  piRoot: string,
): { readonly directory: string; readonly filePath: string; readonly lockPath: string } {
  const platform = platformForPath(identity.rootPath.length > 0 ? identity.rootPath : piRoot);
  const flavor = flavorFor(platform);
  const normalizedPiRoot = normalizeSpelling(piRoot, platform);
  const directory = flavor.join(
    normalizedPiRoot,
    `${identity.slug}--${identity.identityHash}`,
  );
  return {
    directory,
    filePath: flavor.join(directory, PROJECT_RULES_FILE_NAME),
    lockPath: flavor.join(directory, PROJECT_RULES_LOCK_NAME),
  };
}
