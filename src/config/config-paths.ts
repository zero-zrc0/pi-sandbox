export const PI_PROJECT_DIR = ".pi";
export const EXTENSION_PACKAGE_NAME = "pi-sandbox";

export const COMPAT_PATH_NAMES = Object.freeze({
  extensionsDirName: "extensions",
  projectDirName: PI_PROJECT_DIR,
  configFileName: "config.json",
  logDirName: "logs",
  debugLogFileName: "debug.jsonl",
  reviewLogFileName: "review.jsonl",
  agentsDirName: "agents",
  legacyPolicyFileName: "policy.json",
  legacyExtensionConfigFileName: "config.json",
} as const);

export function resolveGlobalExtensionConfigDir(agentDir: string): string {
  return joinPath(agentDir, COMPAT_PATH_NAMES.extensionsDirName, EXTENSION_PACKAGE_NAME);
}

/** The debug log file for one agent directory; the single source for `ConfigPaths.debugLogFile`. */
export function resolveDebugLogFile(agentDir: string): string {
  return joinPath(agentDir, COMPAT_PATH_NAMES.logDirName, COMPAT_PATH_NAMES.debugLogFileName);
}

export interface ConfigPathRoots {
  readonly agentDir: string;
  readonly cwd: string;
  readonly extensionRoot: string;
}

export interface ConfigPaths {
  readonly globalConfigDir: string;
  readonly globalConfigFile: string;
  readonly projectConfigDir: string;
  readonly projectConfigFile: string;
  readonly logDir: string;
  readonly debugLogFile: string;
  readonly reviewLogFile: string;
  readonly projectAgentsDir: string;
  readonly legacyGlobalPolicyFile: string;
  readonly legacyProjectPolicyFile: string;
  readonly legacyExtensionConfigFile: string;
}

export function resolveConfigPaths(roots: ConfigPathRoots): ConfigPaths {
  const globalConfigDir = resolveGlobalExtensionConfigDir(roots.agentDir);
  const projectConfigDir = joinPath(
    roots.cwd,
    COMPAT_PATH_NAMES.projectDirName,
    COMPAT_PATH_NAMES.extensionsDirName,
    EXTENSION_PACKAGE_NAME,
  );
  const logDir = joinPath(roots.agentDir, COMPAT_PATH_NAMES.logDirName);
  return {
    globalConfigDir,
    globalConfigFile: joinPath(globalConfigDir, COMPAT_PATH_NAMES.configFileName),
    projectConfigDir,
    projectConfigFile: joinPath(projectConfigDir, COMPAT_PATH_NAMES.configFileName),
    logDir,
    debugLogFile: resolveDebugLogFile(roots.agentDir),
    reviewLogFile: joinPath(logDir, COMPAT_PATH_NAMES.reviewLogFileName),
    projectAgentsDir: joinPath(
      roots.cwd,
      COMPAT_PATH_NAMES.projectDirName,
      COMPAT_PATH_NAMES.agentsDirName,
    ),
    legacyGlobalPolicyFile: joinPath(roots.agentDir, COMPAT_PATH_NAMES.legacyPolicyFileName),
    legacyProjectPolicyFile: joinPath(
      roots.cwd,
      COMPAT_PATH_NAMES.projectDirName,
      COMPAT_PATH_NAMES.legacyPolicyFileName,
    ),
    legacyExtensionConfigFile: joinPath(
      roots.extensionRoot,
      COMPAT_PATH_NAMES.legacyExtensionConfigFileName,
    ),
  };
}

/**
 * Joins path pieces lexically. The separator is inferred from `base` — a
 * backslash when the base has a drive letter or already contains a backslash,
 * a forward slash otherwise — so the result does not depend on
 * `process.platform`. Dot segments are kept as-is.
 */
export function joinPath(base: string, ...segments: readonly string[]): string {
  const separator = separatorFor(base);
  const parts = segments
    .map((segment) => stripLeadingSeparators(segment))
    .filter((segment) => segment.length > 0);
  if (base.length === 0) {
    return parts.join("/");
  }
  let result = trimTrailingSeparators(base);
  for (const part of parts) {
    const needsSeparator = !result.endsWith("/") && !result.endsWith("\\");
    result += `${needsSeparator ? separator : ""}${part}`;
  }
  return result;
}

/**
 * Compares two config paths without touching the filesystem. Both values are
 * rewritten to the separator of `left`, trailing separators are dropped (a
 * bare root is kept), then the values are compared exactly — unless either
 * side looks Windows-like (drive letter or backslash), in which case the
 * comparison is ASCII-case-insensitive. Dot segments are not resolved.
 */
export function samePath(left: string, right: string): boolean {
  const separator = separatorFor(left);
  const normalizedLeft = trimTrailingSeparators(normalizeSeparators(left, separator));
  const normalizedRight = trimTrailingSeparators(normalizeSeparators(right, separator));
  if (looksWindowsPath(left) || looksWindowsPath(right)) {
    return asciiLower(normalizedLeft) === asciiLower(normalizedRight);
  }
  return normalizedLeft === normalizedRight;
}

function looksWindowsPath(value: string): boolean {
  return /^[A-Za-z]:/.test(value) || value.includes("\\");
}

function separatorFor(base: string): string {
  return looksWindowsPath(base) ? "\\" : "/";
}

function isSeparator(character: string | undefined): boolean {
  return character === "/" || character === "\\";
}

function stripLeadingSeparators(value: string): string {
  let start = 0;
  while (start < value.length && isSeparator(value[start])) {
    start += 1;
  }
  return value.slice(start);
}

function trimTrailingSeparators(value: string): string {
  let end = value.length;
  while (end > 1 && isSeparator(value[end - 1])) {
    // Keep a bare root such as "/" or "C:\" intact.
    if (end === 3 && /^[A-Za-z]:$/.test(value.slice(0, 2))) {
      break;
    }
    end -= 1;
  }
  return value.slice(0, end);
}

function normalizeSeparators(value: string, separator: string): string {
  return value.replace(/[\\/]/g, separator);
}

function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase());
}
