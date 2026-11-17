/*
 * Sandboxed macOS helper, protocol v2.
 *
 * The host spawns this file as
 *   /usr/bin/sandbox-exec -p <profile> <node> .../backend/macos/helper.mjs
 * so the helper itself runs inside the Seatbelt sandbox: it never builds or
 * applies a profile. Its only job is to validate the plan, execute the
 * operation in the inherited sandbox and relay the same wire messages the
 * Linux and Windows helpers use.
 */
import { spawn } from "node:child_process";
import {
  accessSync,
  constants,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";

const protocolVersion = 2;
/** Keep in step with EXECUTION_PLAN_VERSION in src/sandbox/types.ts. */
const planVersion = 2;
const backendId = "macos-seatbelt";
const backendVersion = "1.0.0";
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_CHUNK_BYTES = 48 * 1024;
const MAX_FILE_CONTENT_BYTES = 4 * 1024 * 1024;
const MAX_CAPTURED_OPERATION_ERROR_BYTES = 64 * 1024;
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
/** The host already proved the boundary; these are the limits it negotiated. */
const capabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "file",
    protectedPaths: true,
    environment: true,
  },
  network: "none",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: true,
};

let inputBuffer = "";
let requestId = "";
let generation = 0;
let sequence = 0;
let active;
let shuttingDown = false;

function send(message, callback) {
  if (shuttingDown) return;
  process.stdout.write(`${JSON.stringify(message)}\n`, callback);
}

function sendExit(message, code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`${JSON.stringify(message)}\n`, () => process.exit(code));
}

function failure(code, reason) {
  return Object.assign(new Error(reason), { code });
}

function reject(message, code, reason) {
  sendExit({
    type: "rejected",
    requestId: message.requestId,
    generation: message.generation,
    started: false,
    code,
    reason,
  });
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
        throw failure("unsupported", "file content exceeds the helper input limit");
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

function validatePlan(plan) {
  if (typeof plan !== "object" || plan === null) {
    throw failure("setup", "execution plan is missing");
  }
  if (plan.backend?.id !== backendId) {
    throw failure("setup", "execution plan backend does not match the installed macOS helper");
  }
  if (plan.version !== planVersion) {
    throw failure("setup", `execution plan version ${String(plan.version)} is not supported`);
  }
  if (plan.network?.kind !== "none") {
    throw failure("unsupported", "the macOS Seatbelt backend only supports a plan with no network access");
  }
  const operation = plan.operation;
  if (
    typeof operation !== "object" ||
    operation === null ||
    !OPERATION_KINDS.has(operation.kind)
  ) {
    throw failure("unsupported", "execution operation is unsupported");
  }
  validateOperation(operation);
  return {
    cwd: requireAbsolutePath(plan.cwd, "execution cwd"),
    environment: validateEnvironment(plan.environment),
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

function performFileOperation(operation) {
  try {
    switch (operation.kind) {
      case "read-file": {
        const content = readFileSync(operation.path);
        if (content.length > MAX_FILE_CONTENT_BYTES) {
          return {
            exitCode: 1,
            errorCode: "unsupported",
            error: "file content exceeds the helper result limit",
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

function workerRunner(kind) {
  const name =
    kind === "sandbox-tool"
      ? "sandbox-tool-worker.mjs"
      : "builtin-worker.bundle.mjs";
  try {
    return realpathSync(
      fileURLToPath(new URL(`../../${name}`, import.meta.url)),
    );
  } catch {
    throw failure("setup", "sandbox tool runtime is unavailable");
  }
}

function emitOutput(stream, value) {
  let part = "";
  for (const character of value) {
    if (Buffer.byteLength(part + character, "utf8") > MAX_OUTPUT_CHUNK_BYTES) {
      send({ type: "output", requestId, generation, sequence: sequence++, stream, data: part });
      part = "";
    }
    part += character;
  }
  if (part) {
    send({ type: "output", requestId, generation, sequence: sequence++, stream, data: part });
  }
}

function sendStarted(state, pid) {
  if (state.started || state.settled) return;
  state.started = true;
  send({
    type: "started",
    requestId,
    generation,
    pid,
    startedAt: new Date().toISOString(),
  });
}

function terminate(child) {
  if (typeof child.pid !== "number") return;
  const signalGroup = (signal) => {
    try {
      process.kill(-child.pid, signal);
    } catch {
      try {
        child.kill(signal);
      } catch {
        /* The process tree is already gone. */
      }
    }
  };
  signalGroup("SIGTERM");
  const timer = setTimeout(() => signalGroup("SIGKILL"), 200);
  timer.unref?.();
}

function runFileOperation(operation) {
  const state = { child: undefined, started: false, settled: false, cancelled: false };
  active = state;
  sendStarted(state, null);
  const outcome = performFileOperation(operation);
  sendExit({
    type: "result",
    requestId,
    generation,
    started: true,
    exitCode: outcome.exitCode,
    impact: "known",
    ...(outcome.errorCode === undefined
      ? {}
      : { errorCode: outcome.errorCode, error: outcome.error }),
    ...(outcome.dataBase64 === undefined ? {} : { dataBase64: outcome.dataBase64 }),
  });
}

function runChildOperation(message, cwd, environment, operation) {
  const isWorker = operation.kind === "builtin-tool" || operation.kind === "sandbox-tool";
  let child;
  try {
    if (isWorker) {
      child = spawn(process.execPath, [workerRunner(operation.kind)], {
        cwd,
        env: { ...environment },
        detached: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } else {
      child = spawn(operation.shell ?? "/bin/sh", ["-c", operation.command], {
        cwd,
        env: { ...environment },
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
    }
  } catch (error) {
    reject(message, "setup", error instanceof Error ? error.message : String(error));
    return;
  }

  const state = { child, started: false, settled: false, cancelled: false };
  active = state;
  let diagnostics = "";
  let operationOutput = Buffer.alloc(0);
  let operationOutputTooLarge = false;
  let workerLines = "";
  let workerResult;
  const stdout = new StringDecoder("utf8");
  const stderr = new StringDecoder("utf8");
  const killForProtocol = () => {
    child.kill("SIGKILL");
  };

  // A spawn failure leaves pid unset; only a live process may be announced.
  if (typeof child.pid === "number") sendStarted(state, child.pid);

  if (isWorker) {
    child.stdin.on("error", () => {});
    child.stdin.end(
      `${JSON.stringify({
        ...operation,
        toolCallId: message.plan.toolCallId,
        cwd: message.plan.cwd,
      })}\n`,
      "utf8",
    );
  }

  child.stdout.on("data", (chunk) => {
    if (!isWorker) {
      emitOutput("stdout", stdout.write(chunk));
      return;
    }
    workerLines += stdout.write(chunk);
    if (Buffer.byteLength(workerLines, "utf8") > MAX_INPUT_BYTES) {
      operationOutputTooLarge = true;
      killForProtocol();
      return;
    }
    for (;;) {
      const end = workerLines.indexOf("\n");
      if (end < 0) break;
      const line = workerLines.slice(0, end);
      workerLines = workerLines.slice(end + 1);
      try {
        const packet = JSON.parse(line);
        if (packet.type === "update" && !workerResult) {
          emitOutput("stdout", `${JSON.stringify(packet.result)}\n`);
        } else if (packet.type === "result" && !workerResult) {
          workerResult = packet;
        } else {
          throw new Error("invalid builtin packet");
        }
      } catch {
        diagnostics = "invalid builtin result protocol";
        killForProtocol();
        return;
      }
    }
  });

  child.stderr.on("data", (chunk) => {
    const value = stderr.write(chunk);
    if (!isWorker) {
      emitOutput("stderr", value);
      return;
    }
    if (Buffer.byteLength(diagnostics, "utf8") < MAX_CAPTURED_OPERATION_ERROR_BYTES) {
      diagnostics += value;
    }
  });

  child.on("error", (error) => {
    if (state.settled) return;
    state.settled = true;
    if (!state.started) {
      reject(message, "setup", error.message);
      return;
    }
    sendExit({
      type: "result",
      requestId,
      generation,
      started: true,
      exitCode: null,
      impact: "unknown",
      errorCode: "spawn",
      error: error.message,
    });
  });

  child.on("close", (code, signal) => {
    if (state.settled) return;
    state.settled = true;
    if (state.cancelled) {
      sendExit({
        type: "cancelled",
        requestId,
        generation,
        started: state.started ? true : false,
      });
      return;
    }
    if (!state.started) {
      reject(
        message,
        "setup",
        diagnostics.trim() ||
          `sandboxed process exited before readiness (code=${String(code)})`,
      );
      return;
    }
    if (isWorker) {
      if (!workerResult || workerLines.trim()) {
        sendExit({
          type: "result",
          requestId,
          generation,
          started: true,
          exitCode: null,
          impact: "unknown",
          errorCode: "protocol",
          error: diagnostics || "builtin exited without a complete result",
        });
        return;
      }
      operationOutput = Buffer.from(JSON.stringify(workerResult));
      if (operationOutput.length > MAX_FILE_CONTENT_BYTES) operationOutputTooLarge = true;
    }
    const stdoutEnd = stdout.end();
    const stderrEnd = stderr.end();
    if (!isWorker && stdoutEnd) emitOutput("stdout", stdoutEnd);
    if (!isWorker && stderrEnd) emitOutput("stderr", stderrEnd);
    if (
      isWorker &&
      stderrEnd &&
      Buffer.byteLength(diagnostics, "utf8") < MAX_CAPTURED_OPERATION_ERROR_BYTES
    ) {
      diagnostics += stderrEnd;
    }
    if (operationOutputTooLarge) {
      sendExit({
        type: "result",
        requestId,
        generation,
        started: true,
        exitCode: 1,
        impact: "known",
        errorCode: "unsupported",
        error: "file content exceeds the helper result limit",
      });
      return;
    }
    const toolError =
      isWorker &&
      (typeof workerResult.error === "string" || workerResult.result?.isError === true);
    sendExit({
      type: "result",
      requestId,
      generation,
      started: true,
      exitCode: toolError ? 1 : code ?? null,
      impact: code === null || signal !== null ? "unknown" : "known",
      ...(isWorker
        ? { dataBase64: operationOutput.toString("base64") }
        : {}),
      ...(toolError
        ? {
            errorCode: "tool",
            error: workerResult.error ?? "builtin returned an error result",
          }
        : {}),
      ...(signal ? { errorCode: "signal", error: `sandboxed process exited on ${signal}` } : {}),
    });
  });
}

function run(message) {
  let validated;
  try {
    if (!message.plan || message.plan.backend?.id !== backendId) {
      throw failure("setup", "execution plan backend does not match the installed macOS helper");
    }
    validated = validatePlan(message.plan);
  } catch (error) {
    reject(message, error.code ?? "setup", error.message);
    return;
  }
  requestId = message.requestId;
  generation = message.generation;
  sequence = 0;
  const { cwd, environment, operation } = validated;
  if (operation.kind === "shell" || operation.kind === "builtin-tool" || operation.kind === "sandbox-tool") {
    runChildOperation(message, cwd, environment, operation);
    return;
  }
  runFileOperation(operation);
}

function onHostMessage(message) {
  if (!message || typeof message !== "object") return;
  if (message.type === "hello") {
    if (!Number.isInteger(message.generation) || typeof message.requestId !== "string") return;
    send({
      type: "ready",
      protocolVersion,
      requestId: message.requestId,
      generation: message.generation,
      backend: { id: backendId, version: backendVersion },
      capabilities,
    });
    return;
  }
  if (message.type === "start") {
    if (active || !Number.isInteger(message.generation) || typeof message.requestId !== "string") {
      sendExit({
        type: "rejected",
        requestId: message.requestId,
        generation: message.generation,
        started: false,
        code: "setup",
        reason: "helper already has an active request or correlation is invalid",
      });
      return;
    }
    run(message);
    return;
  }
  if (message.type === "cancel") {
    if (
      active &&
      message.requestId === requestId &&
      message.generation === generation
    ) {
      active.cancelled = true;
      if (active.child) terminate(active.child);
    }
    return;
  }
  if (message.type === "shutdown") {
    shuttingDown = true;
    if (active?.child) active.child.kill("SIGTERM");
    process.exit(0);
  }
}

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  inputBuffer += chunk;
  if (Buffer.byteLength(inputBuffer, "utf8") > MAX_INPUT_BYTES) {
    process.exit(2);
    return;
  }
  for (;;) {
    const newline = inputBuffer.indexOf("\n");
    if (newline < 0) break;
    const line = inputBuffer.slice(0, newline);
    inputBuffer = inputBuffer.slice(newline + 1);
    if (!line.trim()) continue;
    try {
      onHostMessage(JSON.parse(line));
    } catch {
      send({ type: "error", code: "protocol", message: "helper received invalid JSON" });
    }
  }
});
process.stdin.on("end", () => {
  if (active?.child) active.child.kill("SIGTERM");
  process.exitCode = 0;
});
