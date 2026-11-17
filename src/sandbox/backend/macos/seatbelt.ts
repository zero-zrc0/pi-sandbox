import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, join, parse } from "node:path";

import type { TrustedHelperInstallation } from "#sandbox/helper";
import { resolveHostPathIdentity, normalizeHostPath } from "#sandbox/path";
import type { ExecutionPlan } from "#sandbox/types";

export const MACOS_SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec";

const MAX_PROFILE_BYTES = 64 * 1024;
/*
 * macOS 26 dyld aborts every child of a deny-default profile unless the volume
 * root directory itself is readable. A `(subpath "/")` rule would grant the
 * whole filesystem, so this must stay a literal rule.
 */
const VOLUME_ROOT_READ_RULE = '(allow file-read* (literal "/"))';
/*
 * Path resolution stats every ancestor directory. Without global metadata
 * reads an otherwise granted path under a symlinked parent (/tmp, /var) is
 * reported as EPERM before the grant is ever matched.
 */
const METADATA_READ_RULE = '(allow file-read-metadata (subpath "/"))';
const SYSTEM_READ_PATHS = [
  "/System/Library",
  "/System/Volumes/Preboot",
  "/bin",
  "/private/var/db/dyld",
  "/sbin",
  "/usr/bin",
  "/usr/lib",
  "/usr/libexec",
  "/usr/share",
] as const;

const SYSTEM_READ_FILES = [
  "/dev/null",
  "/dev/random",
  "/dev/urandom",
  "/etc/group",
  "/etc/hosts",
  "/etc/localtime",
  "/etc/passwd",
  "/private/etc/group",
  "/private/etc/hosts",
  "/private/etc/localtime",
  "/private/etc/passwd",
] as const;

const HOME_SECRET_DIRECTORIES = [
  ".aws",
  ".azure",
  ".config",
  ".docker",
  ".gnupg",
  ".kube",
  ".ssh",
  "Library/Keychains",
] as const;

const HOME_SECRET_FILES = [
  ".git-credentials",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".pi/agent/auth.json",
  "Library/Application Support/com.apple.TCC/TCC.db",
] as const;

/*
 * System credential stores: the OS protects most of them with POSIX modes, but
 * some (DarwinDirectory, System.keychain, TCC) are world-readable, so the
 * sandbox layer must deny them explicitly instead of relying on DAC. These
 * rules are emitted last because a later rule overrides an earlier one.
 */
const SYSTEM_DENY_PATHS = [
  { path: "/private/var/db/dslocal", granularity: "directory" },
  { path: "/private/var/db/DarwinDirectory", granularity: "directory" },
  { path: "/private/var/db/auth.db", granularity: "file" },
  { path: "/private/etc/master.passwd", granularity: "file" },
  { path: "/private/etc/sudoers", granularity: "file" },
  { path: "/private/etc/sudoers.d", granularity: "directory" },
  { path: "/private/var/db/sudo", granularity: "directory" },
  { path: "/private/var/db/SystemPolicyConfiguration", granularity: "directory" },
  { path: "/Library/Keychains/System.keychain", granularity: "file" },
  { path: "/Library/Application Support/com.apple.TCC/TCC.db", granularity: "file" },
] as const;

export type MacOSSeatbeltProbe =
  | {
      readonly status: "candidate-present";
      readonly executable: typeof MACOS_SANDBOX_EXEC_PATH;
      readonly defaultDenyProbePassed: true;
      readonly nativeMatrixVerified: false;
    }
  | {
      readonly status: "unavailable";
      readonly reason: string;
    };

let cachedProbe: MacOSSeatbeltProbe | undefined;

export type SeatbeltProfileResult =
  | { readonly ok: true; readonly profile: string }
  | SeatbeltPolicyError;

type SeatbeltPolicyError = {
  readonly ok: false;
  readonly code: "sandbox-setup-failed" | "sandbox-capability-unsupported";
  readonly reason: string;
};

type SeatbeltRuleResult =
  | { readonly ok: true; readonly value: string }
  | SeatbeltPolicyError;

type SeatbeltPathResult =
  | { readonly ok: true; readonly path: string }
  | SeatbeltPolicyError;

export function probeMacOSSeatbelt(): MacOSSeatbeltProbe {
  if (cachedProbe) return { ...cachedProbe };
  cachedProbe = probeMacOSSeatbeltOnce();
  return { ...cachedProbe };
}

function probeMacOSSeatbeltOnce(): MacOSSeatbeltProbe {
  if (process.platform !== "darwin") {
    return {
      status: "unavailable",
      reason: "macOS Seatbelt is unavailable on this platform",
    };
  }
  try {
    const resolved = realpathSync.native(MACOS_SANDBOX_EXEC_PATH);
    if (resolved !== MACOS_SANDBOX_EXEC_PATH) {
      return {
        status: "unavailable",
        reason: "sandbox-exec resolved outside its fixed system path",
      };
    }
    if (!statSync(resolved).isFile()) {
      return {
        status: "unavailable",
        reason: "sandbox-exec is not a regular file",
      };
    }
    accessSync(resolved, constants.X_OK);
    accessSync("/etc/passwd", constants.R_OK);
  } catch {
    return {
      status: "unavailable",
      reason: "the fixed /usr/bin/sandbox-exec executable is unavailable",
    };
  }
  const passwdPath = canonicalPath("/etc/passwd");
  if (!passwdPath.ok) {
    return {
      status: "unavailable",
      reason: "the Seatbelt denial probe path could not be resolved",
    };
  }
  const passwdAllow = pathRule("allow", "file-read*", passwdPath.path, "file");
  const passwdDeny = pathRule("deny", "file-read*", passwdPath.path, "file");
  const lexicalPasswdDeny = pathRule("deny", "file-read*", "/etc/passwd", "file");
  if (!passwdAllow.ok) {
    return {
      status: "unavailable",
      reason: passwdAllow.reason,
    };
  }
  if (!passwdDeny.ok) {
    return {
      status: "unavailable",
      reason: passwdDeny.reason,
    };
  }
  if (!lexicalPasswdDeny.ok) {
    return {
      status: "unavailable",
      reason: lexicalPasswdDeny.reason,
    };
  }
  const probeProfile = [
    "(version 1)",
    "(deny default)",
    VOLUME_ROOT_READ_RULE,
    "(allow process-exec)",
    "(allow file-read* (subpath \"/System/Library\"))",
    "(allow file-read* (subpath \"/bin\"))",
    "(allow file-read* (subpath \"/usr/lib\"))",
    "(allow file-read* (subpath \"/usr/bin\"))",
    passwdAllow.value,
    "(allow file-read-metadata (subpath \"/etc\"))",
    "(allow file-read-metadata (subpath \"/private/etc\"))",
    passwdDeny.value,
    lexicalPasswdDeny.value,
  ].join("\n");
  const result = spawnSync(
    MACOS_SANDBOX_EXEC_PATH,
    [
      "-p",
      probeProfile,
      "/bin/sh",
      "-c",
      "if test -r /etc/passwd; then printf allowed; else printf denied; fi",
    ],
    {
      cwd: "/",
      env: { PATH: "/usr/bin:/bin" },
      encoding: "utf8",
      maxBuffer: 4096,
      timeout: 3_000,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0 || result.stdout !== "denied") {
    return {
      status: "unavailable",
      reason: "sandbox-exec did not pass the default-deny file probe",
    };
  }
  return {
    status: "candidate-present",
    executable: MACOS_SANDBOX_EXEC_PATH,
    defaultDenyProbePassed: true,
    nativeMatrixVerified: false,
  };
}

export function buildSeatbeltProfile(input: {
  readonly installation: TrustedHelperInstallation;
  readonly helperHome?: string;
  readonly plan?: ExecutionPlan;
}): SeatbeltProfileResult {
  const rules = [
    "(version 1)",
    "(deny default)",
    VOLUME_ROOT_READ_RULE,
    METADATA_READ_RULE,
    "(allow process-exec)",
    "(allow process-fork)",
    "(allow sysctl-read)",
  ];

  for (const path of SYSTEM_READ_PATHS) {
    const rule = pathRule("allow", "file-read*", path, "directory");
    if (!rule.ok) return rule;
    rules.push(rule.value);
  }
  for (const path of SYSTEM_READ_FILES) {
    const readRule = pathRule("allow", "file-read*", path, "file");
    if (!readRule.ok) return readRule;
    rules.push(readRule.value);
  }
  const nullWrite = pathRule("allow", "file-write*", "/dev/null", "file");
  if (!nullWrite.ok) return nullWrite;
  rules.push(nullWrite.value);

  /*
   * The helper is node itself, and an nvm install lives outside /usr and
   * /System: dyld needs the canonical binary plus its directory readable.
   */
  const nodeExecutable = canonicalPath(process.execPath);
  if (!nodeExecutable.ok) return nodeExecutable;
  const nodeFileRead = pathRule("allow", "file-read*", nodeExecutable.path, "file");
  if (!nodeFileRead.ok) return nodeFileRead;
  const nodeDirectoryRead = pathRule(
    "allow",
    "file-read*",
    dirname(nodeExecutable.path),
    "directory",
  );
  if (!nodeDirectoryRead.ok) return nodeDirectoryRead;
  rules.push(nodeFileRead.value, nodeDirectoryRead.value);

  const installRoot = canonicalPath(input.installation.installRoot);
  if (!installRoot.ok) return installRoot;
  const installRead = pathRule("allow", "file-read*", installRoot.path, "directory");
  if (!installRead.ok) return installRead;
  rules.push(installRead.value);

  const helperExecutable = canonicalPath(input.installation.executable);
  if (!helperExecutable.ok) return helperExecutable;
  const executableParent = parentMetadataRule(helperExecutable.path);
  if (!executableParent.ok) return executableParent;
  rules.push(executableParent.value);

  for (const arg of input.installation.args ?? []) {
    if (!isAbsolute(arg)) continue;
    const helperArgument = canonicalPath(arg);
    if (!helperArgument.ok) return helperArgument;
    const argumentParent = parentMetadataRule(helperArgument.path);
    if (!argumentParent.ok) return argumentParent;
    rules.push(argumentParent.value);
  }

  const protectedPaths = [installRoot.path];
  if (input.plan) {
    if (input.plan.mode === "full-access") {
      return unsupported("full-access does not use the macOS restricted backend");
    }
    if (input.plan.network.kind !== "none") {
      return unsupported("Seatbelt candidate only supports a profile with no network access");
    }
    for (const grant of input.plan.filesystem) {
      const canonical = canonicalPath(grant.path);
      if (!canonical.ok) return canonical;
      if (parse(canonical.path).root === canonical.path) {
        return unsupported("a filesystem grant cannot target the filesystem root");
      }
      const access = grant.access === "read" ? "file-read*" : "file-write*";
      const rule = pathRule("allow", access, canonical.path, grant.granularity);
      if (!rule.ok) return rule;
      rules.push(rule.value);
      if (grant.granularity === "file") {
        const parent = pathRule(
          "allow",
          "file-read-metadata",
          dirname(canonical.path),
          "directory",
        );
        if (!parent.ok) return parent;
        rules.push(parent.value);
      }
    }

    for (const path of input.plan.protectedPaths) {
      const protectedPath = canonicalPath(path);
      if (!protectedPath.ok) return protectedPath;
      protectedPaths.push(protectedPath.path);
    }

    const homePaths = new Set(
      [input.plan.environment.HOME, input.helperHome, process.env.HOME]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .map((value) => normalizeHostPath(value))
        .filter((value): value is string => value !== null),
    );
    for (const home of homePaths) {
      for (const name of HOME_SECRET_DIRECTORIES) {
        const protectedPath = canonicalPath(join(home, name));
        if (!protectedPath.ok) return protectedPath;
        const readDeny = pathRule("deny", "file-read*", protectedPath.path, "directory");
        const writeDeny = pathRule("deny", "file-write*", protectedPath.path, "directory");
        if (!readDeny.ok) return readDeny;
        if (!writeDeny.ok) return writeDeny;
        rules.push(readDeny.value, writeDeny.value);
      }
      for (const name of HOME_SECRET_FILES) {
        const protectedPath = canonicalPath(join(home, name));
        if (!protectedPath.ok) return protectedPath;
        const readDeny = pathRule("deny", "file-read*", protectedPath.path, "file");
        const writeDeny = pathRule("deny", "file-write*", protectedPath.path, "file");
        if (!readDeny.ok) return readDeny;
        if (!writeDeny.ok) return writeDeny;
        rules.push(readDeny.value, writeDeny.value);
      }
    }
  }

  for (const path of protectedPaths) {
    const rule = pathRule("deny", "file-write*", path, "directory");
    if (!rule.ok) return rule;
    rules.push(rule.value);
  }

  for (const entry of SYSTEM_DENY_PATHS) {
    const target = canonicalPath(entry.path);
    if (!target.ok) return target;
    /*
     * `file-read*` does not cover `file-read-metadata` (verified against
     * Seatbelt on macOS 26), so the metadata deny has to be explicit, otherwise
     * the store stays stat-able through the global metadata allow above.
     */
    const metadataDeny = pathRule("deny", "file-read-metadata", target.path, entry.granularity);
    if (!metadataDeny.ok) return metadataDeny;
    const readDeny = pathRule("deny", "file-read*", target.path, entry.granularity);
    if (!readDeny.ok) return readDeny;
    const writeDeny = pathRule("deny", "file-write*", target.path, entry.granularity);
    if (!writeDeny.ok) return writeDeny;
    rules.push(metadataDeny.value, readDeny.value, writeDeny.value);
  }

  const profile = `${rules.join("\n")}\n`;
  if (Buffer.byteLength(profile, "utf8") > MAX_PROFILE_BYTES) {
    return unsupported("compiled Seatbelt profile exceeds the argument size limit");
  }
  return { ok: true, profile };
}

function parentMetadataRule(path: string): SeatbeltRuleResult {
  return pathRule("allow", "file-read-metadata", dirname(path), "directory");
}

function pathRule(
  action: "allow" | "deny",
  operation: string,
  path: string,
  granularity: "file" | "directory",
): SeatbeltRuleResult {
  const quoted = quotePath(path);
  if (!quoted.ok) return quoted;
  const predicate = granularity === "file" ? "literal" : "subpath";
  return {
    ok: true,
    value: `(${action} ${operation} (${predicate} ${quoted.value}))`,
  };
}

function quotePath(
  path: string,
): { readonly ok: true; readonly value: string } | SeatbeltPolicyError {
  if (/[\u0000-\u001f\u007f]/u.test(path)) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "Seatbelt profile path contains a control character",
    };
  }
  return {
    ok: true,
    value: `"${path.replace(/\\/gu, "\\\\").replace(/"/gu, "\\\"")}"`,
  };
}

function canonicalPath(
  path: string,
): SeatbeltPathResult {
  const normalized = normalizeHostPath(path);
  if (!normalized || !isAbsolute(normalized)) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "Seatbelt policy requires absolute host paths",
    };
  }
  const resolved = resolveHostPathIdentity(normalized);
  if (!resolved) {
    return {
      ok: false,
      code: "sandbox-setup-failed",
      reason: "Seatbelt policy path could not be resolved safely",
    };
  }
  return { ok: true, path: resolved };
}

function unsupported(reason: string): SeatbeltPolicyError {
  return {
    ok: false,
    code: "sandbox-capability-unsupported",
    reason,
  };
}
