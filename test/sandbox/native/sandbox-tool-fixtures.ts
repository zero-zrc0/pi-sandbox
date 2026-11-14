/**
 * Shared fixtures for the native sandbox-tool suites (design §6).
 *
 * Both platform suites drive the same one-shot worker contract: a declared
 * module exports `execute(args, ctx)`, the helper relays the worker's result
 * envelope in `dataBase64`, and the host decodes it. These module sources are
 * the T1/T5/T8/T9 contract, so they live here instead of drifting apart in two
 * verbatim copies.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

/** The result envelope the one-shot worker prints and the helper relays. */
export interface SandboxToolEnvelope {
  result?: { content?: { type?: string; text?: string }[] };
  error?: unknown;
}

/** A helper message or execution outcome that may carry the base64 envelope. */
export interface EnvelopeSource {
  readonly dataBase64?: unknown;
}

/** Decode the worker envelope, failing loudly when the helper relayed none. */
export function decodeEnvelope(source: EnvelopeSource): SandboxToolEnvelope {
  const dataBase64 = source.dataBase64;
  if (typeof dataBase64 !== "string" || dataBase64.length === 0) {
    throw new Error(`helper result carries no dataBase64 envelope (got ${typeof dataBase64})`);
  }
  return JSON.parse(Buffer.from(dataBase64, "base64").toString("utf8")) as SandboxToolEnvelope;
}

/** Join the text parts of a successful tool result. */
export function textOf(source: EnvelopeSource): string {
  return decodeEnvelope(source).result?.content?.map(part => part.text).join("\n") ?? "";
}

/** The error text of a failed helper result, failing readably when it carries none. */
export function errorTextOf(source: EnvelopeSource): string {
  const error = decodeEnvelope(source).error;
  if (typeof error !== "string") {
    throw new Error(`helper result carries no string error (got ${typeof error})`);
  }
  return error;
}

/** Write one fixture module into a layout's module directory. */
export function writeModule(layout: { readonly modules: string }, name: string, source: string): string {
  const path = join(layout.modules, name);
  writeFileSync(path, source);
  return path;
}

/**
 * A tool that counts its persistent calls in `ctx.stateDirectory`, so a second
 * call proves the one-shot worker sees the state the first call wrote.
 */
export const COUNTER_MODULE = `import { readFileSync, writeFileSync } from "node:fs";
export async function execute(args, ctx) {
  const file = ctx.stateDirectory + "/count.txt";
  let previous = "0";
  try { previous = readFileSync(file, "utf8"); } catch {}
  const count = String(Number(previous) + 1);
  writeFileSync(file, count);
  return { content: [{ type: "text", text: JSON.stringify({ count, value: args.value, cwd: ctx.cwd, toolName: ctx.toolName, config: ctx.config }) }] };
}
`;

/** A tool that writes the path the caller names; the OS sandbox must deny it. */
export const WRITER_MODULE = `import { writeFileSync } from "node:fs";
export async function execute(args) {
  writeFileSync(args.target, "sandbox-tool-escape");
  return { content: [{ type: "text", text: "write-succeeded" }] };
}
`;

export const THROWING_MODULE = `export async function execute() {
  throw new Error("native sandbox tool boom");
}
`;

// A timer keeps the worker's event loop alive, so the tool really hangs until
// the host terminates the sandbox process tree (design §6.4).
export const SLOW_MODULE = `export async function execute() {
  await new Promise(resolve => setTimeout(resolve, 600_000));
  return { content: [] };
}
`;
