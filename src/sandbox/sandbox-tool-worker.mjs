/*
 * One-shot sandbox-hosted tool worker (design §6).
 *
 * The host starts this process inside the OS sandbox with one JSON line on
 * stdin, loads the declared module by file path, calls its `execute(args, ctx)`
 * once and prints one JSON result line on stdout. The process then exits, so
 * module-level state never survives a call: tools that need context must write
 * into `ctx.stateDirectory` (`.pi/sandbox-tools/<tool>/`).
 *
 * Nothing in this file imports the host package or the pi SDK: the module must
 * be loadable on its own, and the host never imports plugin code.
 */
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

/**
 * Write the one result line and exit. The exit happens in the write callback:
 * a pipe write is asynchronous, so an immediate `process.exit()` could
 * truncate a large result. Exiting is part of the one-shot contract because a
 * module may leave handles open (timers, watchers, keep-alive sockets); the
 * helpers only relay the result once this process closes.
 */
function finish(payload) {
  const line = `${JSON.stringify({ type: "result", ...payload })}\n`;
  process.stdout.write(line, () => process.exit(0));
}

/** Trim a thrown value into a readable, single-line diagnostic. */
function describe(error) {
  if (error instanceof Error) {
    const message = typeof error.message === "string" && error.message.length > 0
      ? error.message
      : "tool execution failed";
    return error.name === "Error" ? message : `${error.name}: ${message}`;
  }
  return String(error);
}

/** Validate the envelope before importing anything from the workspace. */
function readRequest(line) {
  const request = JSON.parse(line);
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("invalid worker request");
  }
  const { modulePath, name } = request;
  if (typeof modulePath !== "string" || modulePath.length === 0) {
    throw new Error("worker request has no module path");
  }
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("worker request has no tool name");
  }
  return request;
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  lines.close();
  let request;
  try {
    request = readRequest(line);
  } catch (error) {
    finish({ error: `sandbox-tool-not-loadable: ${describe(error)}` });
    break;
  }

  const toolName = request.name;
  let module;
  try {
    module = await import(pathToFileURL(request.modulePath).href);
  } catch (error) {
    finish({ error: `sandbox-tool-not-loadable: ${toolName}: ${describe(error)}` });
    break;
  }

  const execute = module?.execute;
  if (typeof execute !== "function") {
    finish({ error: `sandbox-tool-not-loadable: ${toolName}: module does not export execute()` });
    break;
  }

  // §6.3: an optional probe runs once per loading and reports load problems
  // before a real call would.
  if (typeof module.probe === "function") {
    try {
      await module.probe();
    } catch (error) {
      finish({ error: `sandbox-tool-not-loadable: ${toolName}: ${describe(error)}` });
      break;
    }
  }

  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once("SIGTERM", abort);
  process.once("SIGINT", abort);

  try {
    const result = await execute(request.arguments ?? {}, {
      cwd: typeof request.cwd === "string" ? request.cwd : process.cwd(),
      stateDirectory: typeof request.stateDirectory === "string" ? request.stateDirectory : undefined,
      config: request.config,
      toolName,
      signal: controller.signal,
    });
    if (result === null || typeof result !== "object" || !Array.isArray(result.content)) {
      finish({ error: `sandbox-tool-invalid-result: ${toolName}: execute() must return { content: [...] }` });
      break;
    }
    finish({ result });
  } catch (error) {
    finish({ error: describe(error) });
  }
  break;
}
