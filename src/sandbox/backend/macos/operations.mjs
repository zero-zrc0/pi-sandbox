import {
  accessSync,
  constants,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute } from "node:path";

const PLAN_VERSION = 3;
const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const SHELL_ALLOWLIST = new Set(["/bin/sh", "/bin/bash", "/usr/bin/bash"]);
const OPERATION_KINDS = new Set([
  "shell",
  "builtin-tool",
  "sandbox-tool",
  "read-file",
  "access-file",
  "write-file",
  "mkdir",
  "access-dir",
]);
const ENVIRONMENT_ALLOWLIST = new Set([
  "PATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "PI_SANDBOX_WORK_DIR",
  "HOME",
  "LANG",
  "LC_ALL",
  "TERM",
]);

function failure(code, reason) {
  return Object.assign(new Error(reason), { code });
}

function requireAbsolutePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !isAbsolute(value) ||
    value.includes("\0")
  ) {
    throw failure("setup", `${label} must be an absolute macOS path`);
  }
  return value;
}

function validateEnvironment(environment) {
  if (typeof environment !== "object" || environment === null) {
    throw failure("setup", "execution environment is missing");
  }
  for (const [name, value] of Object.entries(environment)) {
    if (
      !ENVIRONMENT_ALLOWLIST.has(name) ||
      typeof value !== "string" ||
      value.includes("\0")
    ) {
      throw failure("unsupported", `environment variable is not allowed: ${name}`);
    }
  }
  return environment;
}

function validateOperation(operation) {
  switch (operation.kind) {
    case "shell": {
      const shell = operation.shell ?? "/bin/sh";
      if (typeof shell !== "string" || !SHELL_ALLOWLIST.has(shell)) {
        throw failure("unsupported", "the macOS backend received an unsupported shell interpreter");
      }
      if (typeof operation.command !== "string" || operation.command.includes("\0")) {
        throw failure("setup", "shell command contains a NUL byte");
      }
      return;
    }
    case "builtin-tool":
    case "sandbox-tool": {
      if (typeof operation.name !== "string" || operation.name.length === 0) {
        throw failure("setup", "tool operation has no tool name");
      }
      return;
    }
    case "read-file":
      requireAbsolutePath(operation.path, "read path");
      return;
    case "access-file":
      requireAbsolutePath(operation.path, "access path");
      if (operation.mode !== "read" && operation.mode !== "read-write") {
        throw failure("setup", "file access mode is invalid");
      }
      return;
    case "write-file":
      requireAbsolutePath(operation.path, "write path");
      if (typeof operation.content !== "string") {
        throw failure("setup", "write content is missing");
      }
      if (Buffer.byteLength(operation.content, "utf8") > MAX_FILE_CONTENT_BYTES) {
        throw failure("unsupported", "file content exceeds the native input limit");
      }
      return;
    case "mkdir":
      requireAbsolutePath(operation.path, "directory path");
      return;
    case "access-dir":
      requireAbsolutePath(operation.path, "directory path");
      return;
    default:
      throw failure("unsupported", `the macOS backend does not support ${operation.kind} operations`);
  }
}

export function validatePlan(plan, start) {
  if (typeof plan !== "object" || plan === null) {
    throw failure("setup", "execution plan is missing");
  }
  if (plan.version !== PLAN_VERSION) {
    throw failure("setup", `execution plan version ${String(plan.version)} is not supported`);
  }
  if (!Array.isArray(plan.filesystem) || plan.filesystem.some(rule =>
    !rule || !["read", "write", "deny-write", "deny-access"].includes(rule.access) ||
    !["file", "directory"].includes(rule.granularity))) {
    throw failure("unsupported", "unknown filesystem rule");
  }
  if (plan.network?.kind !== "none") {
    throw failure("unsupported", "the macOS Seatbelt backend only supports a plan with no network access");
  }
  if (plan.metadataRead !== "all" && plan.metadataRead !== "none") {
    throw failure("unsupported", "unknown metadata read rule");
  }
  const operation = start?.operation;
  if (
    typeof operation !== "object" ||
    operation === null ||
    !OPERATION_KINDS.has(operation.kind)
  ) {
    throw failure("unsupported", "execution operation is unsupported");
  }
  validateOperation(operation);
  return {
    cwd: requireAbsolutePath(start.cwd, "execution cwd"),
    environment: validateEnvironment(start.environment),
    operation,
  };
}

function operationError(error) {
  const code = typeof error?.code === "string" ? error.code : "";
  const errorCode =
    code === "ENOENT" || code === "ENOTDIR"
      ? "missing"
      : code === "EACCES" || code === "EPERM"
        ? "denied"
        : "io";
  return {
    exitCode: 1,
    errorCode,
    error: error instanceof Error ? error.message : String(error),
  };
}

export function performFileOperation(operation) {
  try {
    switch (operation.kind) {
      case "read-file": {
        const content = readFileSync(operation.path);
        if (content.length > MAX_FILE_CONTENT_BYTES) {
          return {
            exitCode: 1,
            errorCode: "unsupported",
            error: "file content exceeds the native result limit",
          };
        }
        return { exitCode: 0, dataBase64: content.toString("base64") };
      }
      case "access-file":
        accessSync(
          operation.path,
          operation.mode === "read-write"
            ? constants.R_OK | constants.W_OK
            : constants.R_OK,
        );
        return { exitCode: 0 };
      case "write-file":
        writeFileSync(operation.path, operation.content, { encoding: "utf8", mode: 0o666 });
        return { exitCode: 0 };
      case "mkdir":
        mkdirSync(operation.path, { recursive: true, mode: 0o777 });
        return { exitCode: 0 };
      case "access-dir": {
        const info = statSync(operation.path);
        if (!info.isDirectory()) {
          return {
            exitCode: 1,
            errorCode: "missing",
            error: `approved directory does not exist: ${operation.path}`,
          };
        }
        return { exitCode: 0 };
      }
      default:
        return {
          exitCode: 1,
          errorCode: "unsupported",
          error: "operation is not supported",
        };
    }
  } catch (error) {
    return operationError(error);
  }
}
