#!/usr/bin/env node
/**
 * Plan 11 protocol fixture.
 *
 * This is a real Node subprocess speaking the versioned NDJSON protocol. It is
 * NOT an OS sandbox: it only proves transport, negotiation, start/output/result,
 * cancellation, and process-tree cleanup. Tests copy it outside the workspace
 * into a host-owned install root.
 */
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdir, readFile, stat, writeFile } from "node:fs/promises";

const scenario = process.env.FIXTURE_SCENARIO ?? "ok";
const protocolVersion =
  scenario === "wrong-version" ? 3 : Number(process.env.FIXTURE_PROTOCOL_VERSION ?? 2);

const capabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "file",
    protectedPaths: true,
    environment: true,
  },
  network: process.env.FIXTURE_NETWORK ?? "all",
  cancel: true,
  streamOutput: true,
  startedNotification: true,
  processTree: scenario !== "unsupported",
};

let lastEgress;

let generation = 0;
let requestId = "";
let sequence = 0;
let currentChild;
let currentTimer;
let cancelled = false;
let shuttingDown = false;

function send(message) {
  if (shuttingDown) return;
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function sendOutput(stream, data) {
  if (shuttingDown) return;
  const suffix = sequence;
  sequence += 1;
  send({
    type: "output",
    requestId,
    generation,
    sequence: suffix,
    stream,
    data,
  });
}

function sendResult(fields) {
  send({
    type: "result",
    requestId,
    generation,
    started: true,
    exitCode: 0,
    impact: "known",
    ...fields,
  });
}

function cleanupChild() {
  if (currentTimer) {
    clearTimeout(currentTimer);
    currentTimer = undefined;
  }
  if (!currentChild) return;
  const child = currentChild;
  currentChild = undefined;
  try {
    if (process.platform === "win32" && child.pid) {
      spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      }).unref();
    } else {
      child.kill("SIGKILL");
    }
  } catch {
    // Already gone.
  }
}

function onCancel() {
  if (scenario === "grandchild" || scenario === "stubborn") {
    // Deliberately ignore cancellation so the host must reclaim the tree.
    return;
  }
  cancelled = true;
  cleanupChild();
  send({ type: "cancelled", requestId, generation, started: true });
}

function runBuiltin(plan, worker) {
  const child = spawn(process.execPath, [worker ?? process.env.FIXTURE_BUILTIN_WORKER], {
    cwd: plan.cwd, env: { ...plan.environment }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
  });
  currentChild = child;
  let pending = "";
  let envelope;
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", chunk => {
    pending += chunk;
    let end;
    while ((end = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      const packet = JSON.parse(line);
      if (packet.type === "update") sendOutput("stdout", JSON.stringify(packet.result) + "\n");
      else envelope = packet;
    }
  });
  let diagnostics = "";
  child.stderr.on("data", chunk => { diagnostics += chunk.toString(); });
  child.on("error", error => sendResult({ exitCode: 1, errorCode: "io", error: error.message }));
  child.on("close", code => {
    currentChild = undefined;
    if (cancelled) return;
    if (!envelope) { sendResult({ exitCode: 1, errorCode: "io", error: diagnostics || `builtin exited ${code}` }); return; }
    sendResult({ dataBase64: Buffer.from(JSON.stringify(envelope)).toString("base64"),
      ...(typeof envelope.error === "string" || envelope.result?.isError === true
        ? { exitCode: 1, errorCode: "tool", error: envelope.error ?? "builtin returned an error result" } : {}),
    });
  });
  child.stdin.end(JSON.stringify({ ...plan.operation, toolCallId: plan.toolCallId, cwd: plan.cwd }) + "\n");
}

async function runFile(plan) {
  const operation = plan.operation;
  try {
    if (operation.kind === "read-file") {
      const buffer = await readFile(operation.path);
      sendResult({ dataBase64: buffer.toString("base64") });
      return;
    }
    if (operation.kind === "access-file") {
      const mode =
        operation.mode === "read-write"
          ? constants.R_OK | constants.W_OK
          : constants.R_OK;
      await access(operation.path, mode);
      sendResult({});
      return;
    }
    if (operation.kind === "write-file") {
      await writeFile(operation.path, operation.content, "utf8");
      sendResult({});
      return;
    }
    if (operation.kind === "mkdir") {
      await mkdir(operation.path, { recursive: true });
      sendResult({});
      return;
    }
    if (operation.kind === "access-dir") {
      // Metadata only: never creates, so a missing parent is reported and the
      // host must ask for a directory write explicitly.
      const info = await stat(operation.path);
      if (!info.isDirectory()) {
        sendResult({
          exitCode: 1,
          errorCode: "missing",
          error: "path is not a directory",
        });
        return;
      }
      sendResult({});
      return;
    }
    sendResult({ exitCode: 1, errorCode: "unsupported", error: "unknown file operation" });
  } catch (error) {
    const code = error && typeof error === "object" ? error.code : undefined;
    sendResult({
      exitCode: 1,
      errorCode:
        code === "ENOENT"
          ? "missing"
          : code === "EACCES" || code === "EPERM"
            ? "denied"
            : "io",
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function runShell(plan) {
  const operation = plan.operation;
  if (scenario === "echo-egress") {
    sendOutput("stdout", `egress:${lastEgress?.leaseId ?? "none"}`);
    sendResult({ exitCode: 0 });
    return;
  }
  if (scenario === "partial-error") {
    sendOutput("stdout", "partial output");
    send({
      type: "result",
      requestId,
      generation,
      started: true,
      exitCode: null,
      impact: "unknown",
      errorCode: "io",
      error: "stream lost after partial output",
    });
    return;
  }
  if (scenario === "out-of-order") {
    sendOutput("stdout", "first");
    send({
      type: "output",
      requestId,
      generation,
      sequence: 0,
      stream: "stdout",
      data: "out of order",
    });
    return;
  }
  if (scenario === "huge") {
    const chunk = "x".repeat(60 * 1024);
    for (let index = 0; index < 90; index += 1) sendOutput("stdout", chunk);
    sendResult({ exitCode: 0 });
    return;
  }
  if (scenario === "slow") {
    currentTimer = setInterval(() => sendOutput("stdout", "tick\n"), 25);
    return;
  }
  if (scenario === "late-generation") {
    send({
      type: "result",
      requestId,
      generation: generation + 1,
      started: true,
      exitCode: 9,
      impact: "known",
    });
    sendResult({ exitCode: 0 });
    return;
  }
  if (scenario === "grandchild") {
    const child = spawn(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { stdio: "ignore", windowsHide: true },
    );
    currentChild = child;
    if (process.env.FIXTURE_PID_FILE && child.pid) {
      writeFile(process.env.FIXTURE_PID_FILE, String(child.pid), "utf8").catch(
        () => undefined,
      );
    }
    return;
  }
  if (scenario === "stubborn") return;

  let timedOut = false;
  const shell = plan.operation.shell;
  const child = spawn(operation.command, {
    cwd: plan.cwd,
    env: { ...plan.environment },
    shell: typeof shell === "string" && shell ? shell : true,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  currentChild = child;
  child.stdout.on("data", (chunk) => sendOutput("stdout", chunk.toString("utf8")));
  child.stderr.on("data", (chunk) => sendOutput("stderr", chunk.toString("utf8")));
  child.on("error", (error) => {
    if (currentChild === child) currentChild = undefined;
    if (cancelled) return;
    sendResult({
      exitCode: 1,
      impact: "none",
      errorCode: "spawn",
      error: error.message,
    });
  });
  child.on("exit", (code, signal) => {
    if (currentChild === child) currentChild = undefined;
    if (currentTimer) {
      clearTimeout(currentTimer);
      currentTimer = undefined;
    }
    if (cancelled || shuttingDown) return;
    if (timedOut) {
      sendResult({ exitCode: 124, impact: "known" });
      return;
    }
    const exitCode = code ?? (signal ? 1 : 1);
    sendResult({ exitCode, impact: "known" });
  });
  if (operation.timeoutMs) {
    currentTimer = setTimeout(() => {
      timedOut = true;
      cleanupChild();
      sendResult({ exitCode: 124, impact: "known" });
    }, operation.timeoutMs);
    currentTimer.unref?.();
  }
}

async function onStart(message) {
  requestId = message.requestId;
  generation = message.generation;
  sequence = 0;
  cancelled = false;
  lastEgress = message.egress;
  const plan = message.plan;
  if (scenario === "reject") {
    send({
      type: "rejected",
      requestId,
      generation,
      started: false,
      code: "denied",
      reason: "fixture rejected the plan",
    });
    return;
  }
  if (scenario === "start-fail") {
    send({
      type: "error",
      requestId,
      generation,
      code: "setup",
      message: "fixture could not prepare the sandbox",
    });
    return;
  }
  if (scenario === "no-start") return;
  if (scenario === "eof") {
    send({
      type: "started",
      requestId,
      generation,
      pid: process.pid,
      startedAt: new Date().toISOString(),
    });
    setTimeout(() => process.exit(0), 10);
    return;
  }
  send({
    type: "started",
    requestId,
    generation,
    pid: process.pid,
    startedAt: new Date().toISOString(),
  });
  if (process.env.FIXTURE_SELF_PID_FILE) {
    await writeFile(process.env.FIXTURE_SELF_PID_FILE, String(process.pid), "utf8").catch(
      () => undefined,
    );
  }
  if (process.env.FIXTURE_MARKER_FILE) {
    await writeFile(process.env.FIXTURE_MARKER_FILE, "fixture", "utf8").catch(
      () => undefined,
    );
  }
  if (scenario === "error-after-start") {
    // A generic error carries no promise that nothing ran: the host already
    // has an acknowledged start.
    send({
      type: "error",
      requestId,
      generation,
      code: "io",
      message: "helper failed after an acknowledged start",
    });
    return;
  }
  if (plan.operation.kind === "builtin-tool") runBuiltin(plan);
  else if (plan.operation.kind === "sandbox-tool") runBuiltin(plan, process.env.FIXTURE_SANDBOX_TOOL_WORKER);
  else if (plan.operation.kind === "shell") runShell(plan);
  else await runFile(plan);
}

function onHello(message) {
  requestId = message.requestId;
  generation = message.generation;
  if (scenario === "no-ready") return;
  if (scenario === "unavailable") {
    send({ type: "error", requestId, generation, code: "unavailable", message: "native sandbox unavailable" });
    return;
  }
  send({
    type: "ready",
    protocolVersion,
    requestId,
    generation,
    backend: { id: "fixture-helper", version: "1.0.0" },
    capabilities,
  });
}

let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  for (;;) {
    const newline = buffered.indexOf("\n");
    if (newline < 0) break;
    const line = buffered.slice(0, newline);
    buffered = buffered.slice(newline + 1);
    if (!line.trim()) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      send({
        type: "error",
        code: "protocol",
        message: "fixture received invalid JSON",
      });
      continue;
    }
    if (message.type === "hello") onHello(message);
    else if (message.type === "start") void onStart(message);
    else if (message.type === "cancel") onCancel();
    else if (message.type === "shutdown") {
      cleanupChild();
      shuttingDown = true;
      process.exit(0);
    }
  }
});
process.stdin.on("end", () => {
  cleanupChild();
  process.exit(0);
});
