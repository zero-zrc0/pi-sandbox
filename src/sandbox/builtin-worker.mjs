import { createInterface } from "node:readline";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { delimiter, resolve } from "node:path";
import {
  createBashToolDefinition, createPowerShellToolDefinition, createLocalPowerShellOperations, createReadToolDefinition, createWriteToolDefinition,
  createEditToolDefinition, createGrepToolDefinition, createFindToolDefinition, createLsToolDefinition,
} from "@earendil-works/pi-coding-agent";

const factories = {
  bash: createBashToolDefinition, powershell: createPowerShellToolDefinition, read: createReadToolDefinition,
  write: createWriteToolDefinition, edit: createEditToolDefinition, grep: createGrepToolDefinition,
  find: createFindToolDefinition, ls: createLsToolDefinition,
};
const send = value => process.stdout.write(`${JSON.stringify(value)}\n`);
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  lines.close();
  try {
    const { name, arguments: args, toolCallId, cwd, context = {}, shellPath, mutationQueuePath, useDefaultProxy } = JSON.parse(line);
    if (!Object.hasOwn(factories, name)) throw new Error("unknown builtin tool");
    if ((name === "edit" || name === "write") && typeof mutationQueuePath === "string") {
      // This worker handles one invocation; the host already serializes mutations by canonical path.
      const realpath = fs.realpath;
      fs.realpath = async (path, ...options) => {
        try { return await realpath(path, ...options); }
        catch (error) {
          if (error?.code === "EPERM" && typeof path === "string" &&
              resolve(path).toLowerCase() === resolve(mutationQueuePath).toLowerCase()) return resolve(path);
          throw error;
        } finally { fs.realpath = realpath; syncBuiltinESMExports(); }
      };
      syncBuiltinESMExports();
    }
    let toolOptions;
    if (name === "bash" && shellPath) toolOptions = { shellPath };
    if (name === "powershell") {
      const local = createLocalPowerShellOperations();
      toolOptions = { operations: { exec: (command, commandCwd, options) => {
        const originalPath = process.env.PATH;
        if (originalPath !== undefined) {
          process.env.PATH = originalPath.split(delimiter).filter(entry =>
            !entry.replaceAll("/", "\\").toLowerCase().includes("\\microsoft\\windowsapps")).join(delimiter);
        }
        const prefix = useDefaultProxy ? "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebProxy]::new($env:HTTPS_PROXY);\n" : "";
        try { return local.exec(prefix + command, commandCwd, options); }
        finally {
          if (originalPath === undefined) delete process.env.PATH;
          else process.env.PATH = originalPath;
        }
      } } };
    }
    const result = await factories[name](cwd, toolOptions).execute(toolCallId, args, undefined,
      update => send({ type: "update", result: update }), {
        cwd, model: context.model,
        sessionManager: { getSessionId: () => context.sessionId, getSessionFile: () => context.sessionFile },
      });
    send({ type: "result", result });
  } catch (error) {
    send({ type: "result", error: error instanceof Error ? error.message : String(error) });
  }
  break;
}
