/**
 * Sandbox-hosted third-party tools (docs/tool-rules-and-sandbox-tools-design.md §6).
 *
 * The module contract tests drive the real worker process over its stdin/stdout
 * protocol (one JSON request, one JSON result), and the declaration tests cover
 * resolution, diagnostics and the `.pi/sandbox-tools/<tool>/` state directory.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EMPTY_TOOL_PARAMETERS,
  resolveSandboxToolSpecs,
  runSandboxToolOnHost,
  SANDBOX_TOOL_TIMEOUT_MS,
  sandboxToolStateDirectory,
} from "#sandbox/sandbox-tools";
import type { ScopedToolRule } from "#approve-core/policy/tool-rules";

const worker = fileURLToPath(new URL("../../src/sandbox/sandbox-tool-worker.mjs", import.meta.url));

const cleanup: string[] = [];
afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function workspace(): string {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-tools-"));
  cleanup.push(root);
  mkdirSync(join(root, "project"), { recursive: true });
  mkdirSync(join(root, "agent"), { recursive: true });
  return root;
}

function writeModule(root: string, name: string, source: string): string {
  const file = join(root, "project", name);
  writeFileSync(file, source, "utf8");
  return file;
}

/** Declare one sandbox rule in the project scope. */
function sandboxRule(
  name: string,
  sandbox: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): ScopedToolRule {
  return {
    scope: "project",
    rule: {
      id: `allow-${name}`,
      match: { tool: name },
      decision: "allow",
      sandbox,
      ...extra,
    } as ScopedToolRule["rule"],
  };
}

function snapshotOf(root: string, rules: readonly ScopedToolRule[]) {
  return {
    toolRules: rules,
    cwd: join(root, "project"),
    paths: {
      projectConfigDir: join(root, "project"),
      globalConfigDir: join(root, "agent"),
    },
  } as never;
}

function runWorker(request: Record<string, unknown>, cwd: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [worker], { cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      const line = stdout.trim().split("\n")[0];
      if (line === undefined || line.length === 0) {
        reject(new Error(`worker produced no result (exit ${String(code)}): ${stderr}`));
        return;
      }
      resolve(JSON.parse(line) as Record<string, unknown>);
    });
    child.stdin.end(`${JSON.stringify(request)}\n`);
  });
}

describe("sandbox tool declarations (§6.1)", () => {
  it("resolves a local module path and creates its state directory", () => {
    const root = workspace();
    writeModule(root, "tool.mjs", "export async function execute() { return { content: [] }; }\n");
    const cwd = join(root, "project");
    const result = resolveSandboxToolSpecs(snapshotOf(root, [
      sandboxRule("local_tool", { path: "./tool.mjs", description: "a declared tool" }),
    ]), cwd);

    expect(result.diagnostics).toEqual([]);
    expect(result.specs).toHaveLength(1);
    expect(result.specs[0]).toMatchObject({
      name: "local_tool",
      modulePath: join(root, "project", "tool.mjs"),
      moduleDirectory: join(root, "project"),
      stateDirectory: sandboxToolStateDirectory(cwd, "local_tool"),
      description: "a declared tool",
      parameters: EMPTY_TOOL_PARAMETERS,
      scope: "project",
    });
    expect(result.specs[0]?.stateDirectory).toBe(join(cwd, ".pi", "sandbox-tools", "local_tool"));
  });

  it("keeps a declared parameter schema and opaque config", () => {
    const root = workspace();
    writeModule(root, "tool.mjs", "export async function execute() { return { content: [] }; }\n");
    const parameters = { type: "object", properties: { path: { type: "string" } }, additionalProperties: false };
    const spec = resolveSandboxToolSpecs(snapshotOf(root, [
      sandboxRule("declared_tool", { path: "./tool.mjs", parameters, config: { maxLines: 200 } }),
    ]), join(root, "project")).specs[0];

    expect(spec?.parameters).toEqual(parameters);
    expect(spec?.config).toEqual({ maxLines: 200 });
  });

  it("reports a missing module, a wildcard name and a duplicate instead of failing", () => {
    const root = workspace();
    writeModule(root, "tool.mjs", "export async function execute() { return { content: [] }; }\n");
    const result = resolveSandboxToolSpecs(snapshotOf(root, [
      sandboxRule("missing_tool", { path: "./absent.mjs" }),
      sandboxRule("wild_*", { path: "./tool.mjs" }),
      sandboxRule("tool_one", { path: "./tool.mjs" }),
      sandboxRule("tool_one", { path: "./tool.mjs" }),
    ]), join(root, "project"));

    expect(result.specs.map((spec) => spec.name)).toEqual(["tool_one"]);
    expect(result.diagnostics.map((entry) => [entry.name, entry.reason])).toEqual([
      ["missing_tool", "module-not-found"],
      ["wild_*", "tool-name-not-concrete"],
    ]);
  });

  it("ignores rules that do not declare a sandbox module", () => {
    const root = workspace();
    const result = resolveSandboxToolSpecs(snapshotOf(root, [
      { scope: "global", rule: { id: "plain", match: { tool: "bash" }, decision: "allow" } },
    ]), join(root, "project"));
    expect(result.specs).toEqual([]);
  });
});

describe("sandbox tool worker protocol (§6.1, §6.3, §6.4)", () => {
  it("returns the module result envelope", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", `
      export async function execute(args, ctx) {
        return { content: [{ type: "text", text: \`hello \${args.name} from \${ctx.toolName}\` }] };
      }
    `);
    const result = await runWorker({ name: "greeter", modulePath: file, arguments: { name: "world" }, stateDirectory: join(root, "state") }, root);
    expect(result).toEqual({ type: "result", result: { content: [{ type: "text", text: "hello world from greeter" }] } });
  });

  it("reports a module without execute as not loadable", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", "export const nothing = 1;\n");
    const result = await runWorker({ name: "no_exec", modulePath: file, arguments: {} }, root);
    expect(String(result.error)).toContain("sandbox-tool-not-loadable: no_exec");
    expect(String(result.error)).toContain("does not export execute()");
  });

  it("reports a failing probe as not loadable", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", `
      export async function probe() { throw new Error("mechanism missing"); }
      export async function execute() { return { content: [] }; }
    `);
    const result = await runWorker({ name: "probe_fail", modulePath: file, arguments: {} }, root);
    expect(String(result.error)).toBe("sandbox-tool-not-loadable: probe_fail: mechanism missing");
  });

  it("reports a module that cannot be imported as not loadable", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", "export async function execute() { return { content: [] }; }\n");
    const result = await runWorker({ name: "absent", modulePath: join(root, "project", "absent.mjs") }, root);
    expect(String(result.error)).toContain("sandbox-tool-not-loadable: absent");
    expect(String(result.error)).toContain("absent.mjs");
  });

  it("returns a thrown execute error as a readable result", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", `
      export async function execute() { throw new Error("boom"); }
    `);
    const result = await runWorker({ name: "thrower", modulePath: file, arguments: {} }, root);
    expect(result).toEqual({ type: "result", error: "boom" });
  });

  it("persists state across calls but not module memory", async () => {
    const root = workspace();
    const file = writeModule(root, "tool.mjs", `
      import { readFile, writeFile } from "node:fs/promises";
      import { join } from "node:path";
      let calls = 0;
      export async function execute(args, ctx) {
        calls += 1;
        const state = join(ctx.stateDirectory, "count");
        let previous = 0;
        try { previous = Number(await readFile(state, "utf8")); } catch {}
        const next = previous + 1;
        await writeFile(state, String(next));
        return { content: [{ type: "text", text: \`persisted=\${next};memory=\${calls}\` }] };
      }
    `);
    const state = join(root, "state");
    mkdirSync(state, { recursive: true });
    const request = { name: "counter", modulePath: file, arguments: {}, stateDirectory: state };

    expect(await runWorker(request, root)).toEqual({ type: "result", result: { content: [{ type: "text", text: "persisted=1;memory=1" }] } });
    expect(await runWorker(request, root)).toEqual({ type: "result", result: { content: [{ type: "text", text: "persisted=2;memory=1" }] } });
  });
});

describe("host execution path (full-access)", () => {
  it("imports the declared module and returns its result", async () => {
    const root = workspace();
    writeModule(root, "tool.mjs", `
      export async function execute(args, ctx) {
        return { content: [{ type: "text", text: \`\${ctx.toolName}:\${args.value}\` }], isError: false };
      }
    `);
    const spec = resolveSandboxToolSpecs(snapshotOf(root, [
      sandboxRule("host_tool", { path: "./tool.mjs" }),
    ]), join(root, "project")).specs[0]!;

    const result = await runSandboxToolOnHost(spec, { value: 7 }, { cwd: join(root, "project") });
    expect(result.content).toEqual([{ type: "text", text: "host_tool:7" }]);
  });

  it("rejects a module without execute and a failing probe", async () => {
    const root = workspace();
    writeModule(root, "no-exec.mjs", "export const value = 1;\n");
    writeModule(root, "probe.mjs", "export async function probe() { throw new Error('nope'); }\nexport async function execute() { return { content: [] }; }\n");
    const specs = resolveSandboxToolSpecs(snapshotOf(root, [
      sandboxRule("no_exec", { path: "./no-exec.mjs" }),
      sandboxRule("probe_fail", { path: "./probe.mjs" }),
    ]), join(root, "project")).specs;

    await expect(runSandboxToolOnHost(specs[0]!, {}, { cwd: join(root, "project") }))
      .rejects.toThrow("sandbox-tool-not-loadable: no_exec");
    await expect(runSandboxToolOnHost(specs[1]!, {}, { cwd: join(root, "project") }))
      .rejects.toThrow("sandbox-tool-not-loadable: probe_fail: nope");
  });
});

/**
 * Platform independent: this is the host-side adapter bound, not a native
 * backend property, so it is asserted once here instead of in each native suite.
 */
describe("sandbox tool adapter bounds (§6.4)", () => {
  it("caps one sandbox tool call at sixty seconds", () => {
    expect(SANDBOX_TOOL_TIMEOUT_MS).toBe(60_000);
  });
});
