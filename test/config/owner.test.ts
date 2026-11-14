/**
 * Formal approval-chain configuration owner (specs/config-loading.md §5–§9).
 *
 * Every test drives the owner against a real temporary file tree: the injected
 * paths point inside a per-test `mkdtemp` directory, and the production file
 * reader is used unless a test needs to simulate an unreadable file. Platform
 * dependent path behaviour is exercised through the exported pure helpers with
 * explicit platforms, and through the owner's injected `platform` option.
 *
 * The assertions describe the specification, not the implementation: effective
 * network and mode provenance, node composition, revision
 * stability, and the exact on-disk write result.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveConfigPaths, type ConfigPaths } from "#config/config-paths";
import { createConfigFileReader, type ConfigFileReader } from "#config/config-loader";
import { applyExperiments } from "#config/experiments";
import type { ApprovalChainConfig } from "#config/schema";
import {
  createApprovalChainConfigOwner,
  normalizeExecutionHost,
  resolveExecutionGrantPath,
  type ApprovalChainConfigOwner,
  type ApprovalChainConfigOwnerOptions,
  type ApprovalChainConfigSnapshot,
  type ConfigSaveResult,
  type ProjectRuleSaveResult,
} from "#config/owner";

/* ------------------------------------------------------------------------- */
/* Temporary tree harness                                                     */
/* ------------------------------------------------------------------------- */

const HOST_PLATFORM = process.platform;
const POSIX = "posix";
const WINDOWS = "win32";

interface Harness {
  readonly root: string;
  readonly projectCwd: string;
  readonly paths: ConfigPaths;
  readonly readFile: ConfigFileReader;
  writeGlobal(value: unknown): void;
  writeGlobalText(text: string): void;
  writeProject(value: unknown): void;
  writeProjectText(text: string): void;
  globalFileContent(): string;
  projectFileContent(): string;
  cleanup(): void;
}

const harnesses: Harness[] = [];

afterEach(() => {
  while (harnesses.length > 0) {
    harnesses.pop()!.cleanup();
  }
});

function writeJsonFile(file: string, value: unknown): void {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function createHarness(): Harness {
  const root = mkdtempSync(join(tmpdir(), "pi-owner-test-"));
  const agentDir = join(root, "agent");
  const extensionRoot = join(root, "extension-root");
  const projectCwd = join(root, "project");
  mkdirSync(projectCwd, { recursive: true, mode: 0o700 });
  const paths = resolveConfigPaths({ agentDir, cwd: projectCwd, extensionRoot });
  const readFile = createConfigFileReader();
  const harness: Harness = {
    root,
    projectCwd,
    paths,
    readFile,
    writeGlobal(value) {
      writeJsonFile(paths.globalConfigFile, value);
    },
    writeGlobalText(text) {
      mkdirSync(dirname(paths.globalConfigFile), { recursive: true });
      writeFileSync(paths.globalConfigFile, text, "utf8");
    },
    writeProject(value) {
      writeJsonFile(paths.projectConfigFile, value);
    },
    writeProjectText(text) {
      mkdirSync(dirname(paths.projectConfigFile), { recursive: true });
      writeFileSync(paths.projectConfigFile, text, "utf8");
    },
    globalFileContent() {
      return readFileSync(paths.globalConfigFile, "utf8");
    },
    projectFileContent() {
      return readFileSync(paths.projectConfigFile, "utf8");
    },
    cleanup() {
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 });
    },
  };
  harnesses.push(harness);
  return harness;
}

function ownerFor(
  harness: Harness,
  overrides: Partial<ApprovalChainConfigOwnerOptions> = {},
): ApprovalChainConfigOwner {
  return createApprovalChainConfigOwner({
    paths: harness.paths,
    cwd: harness.projectCwd,
    projectTrusted: true,
    readFile: harness.readFile,
    platform: HOST_PLATFORM,
    ...overrides,
  });
}

function countingReader(inner: ConfigFileReader): { read: ConfigFileReader; calls: string[] } {
  const calls: string[] = [];
  const read: ConfigFileReader = (path) => {
    calls.push(path);
    return inner(path);
  };
  return { read, calls };
}

function unreadableAt(target: string, inner: ConfigFileReader): ConfigFileReader {
  return (path) => path === target
    ? { state: "unreadable", reason: "EACCES" }
    : inner(path);
}

/* ------------------------------------------------------------------------- */
/* Fixtures                                                                   */
/* ------------------------------------------------------------------------- */

function snapshotOf(
  owner: ApprovalChainConfigOwner,
  sessionId?: string,
): ApprovalChainConfigSnapshot {
  return sessionId === undefined ? owner.snapshot() : owner.snapshot({ sessionId });
}

function codes(snapshot: ApprovalChainConfigSnapshot): string[] {
  return snapshot.issues.map((issue) => issue.code);
}

function pathsFor(snapshot: ApprovalChainConfigSnapshot, code: string): string[] {
  return snapshot.issues.filter((issue) => issue.code === code).map((issue) => issue.path);
}

function userNodeIds(snapshot: ApprovalChainConfigSnapshot): string[] {
  return snapshot.nodeConfig.nodes.filter((node) => node.position === "user").map((node) => node.id);
}

function nodeById(snapshot: ApprovalChainConfigSnapshot, id: string) {
  return snapshot.nodeConfig.nodes.find((node) => node.id === id);
}

function expectSaveFailure(result: ConfigSaveResult): Exclude<ConfigSaveResult, { ok: true }> {
  if (result.ok) throw new Error("expected a save failure, got success");
  return result;
}

function expectProjectRuleFailure(
  result: ProjectRuleSaveResult,
): Exclude<ProjectRuleSaveResult, { ok: true }> {
  if (result.ok) throw new Error("expected a project rule failure, got success");
  return result;
}

function expectSaveSuccess(result: ConfigSaveResult): Extract<ConfigSaveResult, { ok: true }> {
  if (!result.ok) throw new Error(`expected a save success, got ${result.code}`);
  return result;
}

function expectProjectRuleSuccess(
  result: ProjectRuleSaveResult,
): Extract<ProjectRuleSaveResult, { ok: true }> {
  if (!result.ok) throw new Error(`expected a project rule success, got ${result.code}`);
  return result;
}

/* ------------------------------------------------------------------------- */
/* Pure normalization helpers                                                 */
/* ------------------------------------------------------------------------- */

describe("resolveExecutionGrantPath", () => {
  it("resolves a relative grant under the injected base directory", () => {
    expect(resolveExecutionGrantPath("/work/project", "data/files", POSIX)).toBe("/work/project/data/files");
    expect(resolveExecutionGrantPath("/work/project", "./data/./files/", POSIX)).toBe("/work/project/data/files");
  });

  it("folds dot segments and clamps at the filesystem root", () => {
    expect(resolveExecutionGrantPath("/work/project", "src/../lib", POSIX)).toBe("/work/project/lib");
    expect(resolveExecutionGrantPath("/work/project", "../../../../etc", POSIX)).toBe("/etc");
    expect(resolveExecutionGrantPath("/", "a/../..", POSIX)).toBe("/");
  });

  it("keeps absolute POSIX grants and removes trailing separators", () => {
    expect(resolveExecutionGrantPath("/work", "/etc/hosts/", POSIX)).toBe("/etc/hosts");
    expect(resolveExecutionGrantPath("/work", "/", POSIX)).toBe("/");
  });

  it("resolves win32 relative grants with backslash separators", () => {
    expect(resolveExecutionGrantPath("C:\\work\\project", "data\\files", WINDOWS)).toBe(
      "C:\\work\\project\\data\\files",
    );
    expect(resolveExecutionGrantPath("C:\\work\\project", "..\\sibling", WINDOWS)).toBe("C:\\work\\sibling");
  });

  it("keeps win32 absolute grants, including UNC shares, and clamps above the root", () => {
    expect(resolveExecutionGrantPath("C:\\work", "D:/other/", WINDOWS)).toBe("D:\\other");
    expect(resolveExecutionGrantPath("C:\\work", "..\\..\\..\\top", WINDOWS)).toBe("C:\\top");
    expect(resolveExecutionGrantPath("C:\\work", "\\\\server\\share\\folder", WINDOWS)).toBe(
      "\\\\server\\share\\folder",
    );
    expect(resolveExecutionGrantPath("C:\\work", "\\\\server\\share\\..\\..\\escape", WINDOWS)).toBe(
      "\\\\server\\share\\escape",
    );
  });

  it("rejects empty, whitespace-only and NUL-containing grant paths", () => {
    expect(resolveExecutionGrantPath("/work", "", POSIX)).toBeUndefined();
    expect(resolveExecutionGrantPath("/work", "   ", POSIX)).toBeUndefined();
    expect(resolveExecutionGrantPath("/work", "a\u0000b", POSIX)).toBeUndefined();
  });
});

describe("normalizeExecutionHost", () => {
  it("lowercases the host and strips trailing dots", () => {
    expect(normalizeExecutionHost("API.Example.COM")).toBe("api.example.com");
    expect(normalizeExecutionHost("api.example.com.")).toBe("api.example.com");
    expect(normalizeExecutionHost("api.example.com...")).toBe("api.example.com");
  });

  it("converts IDNA host names to ASCII", () => {
    expect(normalizeExecutionHost("BÜCHER.example")).toBe("xn--bcher-kva.example");
  });

  it("rejects whitespace and the reserved URL characters", () => {
    for (const host of ["a b.com", "api/example.com", "api:443", "user@example.com", "*.example.com", "**"]) {
      expect(normalizeExecutionHost(host)).toBeUndefined();
    }
  });

  it("rejects empty labels, oversized labels and oversized hosts", () => {
    expect(normalizeExecutionHost(".example.com")).toBeUndefined();
    expect(normalizeExecutionHost("a..b")).toBeUndefined();
    expect(normalizeExecutionHost(`${"a".repeat(64)}.com`)).toBeUndefined();
    expect(normalizeExecutionHost(`${"a".repeat(250)}.com`)).toBeUndefined();
  });

  it("rejects labels with an illegal edge or character", () => {
    expect(normalizeExecutionHost("-a.com")).toBeUndefined();
    expect(normalizeExecutionHost("a-.com")).toBeUndefined();
    expect(normalizeExecutionHost("a_b.com")).toBeUndefined();
  });

  it("accepts IPv4 and single-label hosts but rejects IPv6", () => {
    expect(normalizeExecutionHost("127.0.0.1")).toBe("127.0.0.1");
    expect(normalizeExecutionHost("localhost")).toBe("localhost");
    expect(normalizeExecutionHost("::1")).toBeUndefined();
    expect(normalizeExecutionHost("[::1]")).toBeUndefined();
  });
});

/* ------------------------------------------------------------------------- */
/* Global scope loading                                                       */
/* ------------------------------------------------------------------------- */

describe("global configuration scope", () => {
  it("uses schema defaults when the global file is missing", () => {
    const harness = createHarness();
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("default");
    expect(snapshot.modeSource).toBe("default");
    expect(snapshot.canWrite).toBe(true);
    expect(snapshot.projectConfigInvalid).toBe(false);
    expect(snapshot.projectConfig).toBeUndefined();
    expect(snapshot.config.mode).toBe("default");
    expect(snapshot.globalConfig.mode).toBe("default");
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
    expect(snapshot.issues).toEqual([]);
    expect(snapshot.revision).toBe(1);
  });

  it("loads a valid global file and marks the source as global", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "auto-review", debugLog: true, promptMaxRows: 7 });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("global");
    expect(snapshot.modeSource).toBe("global");
    expect(snapshot.config.mode).toBe("auto-review");
    expect(snapshot.config.debugLog).toBe(true);
    expect(snapshot.config.promptMaxRows).toBe(7);
    expect(snapshot.issues).toEqual([]);
    expect(snapshot.canWrite).toBe(true);
  });

  it.each([true, false])("loads and drops the retired MCP sandbox setting (%s)", mcpSandbox => {
    const harness = createHarness();
    harness.writeGlobal({ experimental: { mcpSandbox }, execution: { network: { mode: "none" } } });
    const owner = ownerFor(harness);
    const snapshot = owner.snapshot();
    expect(snapshot.source).toBe("global");
    expect(snapshot.canWrite).toBe(true);
    expect(snapshot.issues).toEqual([]);
    expect(snapshot.config.experimental).toEqual({ sandboxEnabled: false });

    expectSaveSuccess(owner.save({ mode: "default", experimental: { mcpSandbox } }));
    expect(JSON.parse(harness.globalFileContent())).not.toHaveProperty("experimental");
  });

  it("preserves the OS sandbox switch while dropping the retired MCP switch", () => {
    const harness = createHarness();
    harness.writeGlobal({ experimental: { sandboxEnabled: true, mcpSandbox: true } });
    const owner = ownerFor(harness);
    expect(owner.snapshot().config.experimental).toEqual({ sandboxEnabled: true });
    expectSaveSuccess(owner.save({ experimental: { sandboxEnabled: true, mcpSandbox: false } }));
    expect(JSON.parse(harness.globalFileContent()).experimental).toEqual({ sandboxEnabled: true });
  });

  it("reports a JSON syntax error as an invalid scope", () => {
    const harness = createHarness();
    harness.writeGlobalText("{ mode: 'default', }");
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(snapshot.modeSource).toBe("default");
    expect(snapshot.canWrite).toBe(false);
    expect(codes(snapshot)).toEqual(["parse-failed"]);
    expect(snapshot.issues[0]?.file).toBe(harness.paths.globalConfigFile);
  });

  it("reports a non-object root as invalid", () => {
    const harness = createHarness();
    harness.writeGlobalText("[]");
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(snapshot.canWrite).toBe(false);
    expect(codes(snapshot)).toEqual(["invalid-config"]);
    expect(snapshot.config.mode).toBe("default");
  });

  it("reports an unreadable global file as invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const snapshot = ownerFor(harness, {
      readFile: unreadableAt(harness.paths.globalConfigFile, harness.readFile),
    }).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(codes(snapshot)).toEqual(["read-failed"]);
  });

  it("reports unknown keys one issue per key", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default", bogus: 1, alsoBad: 2 });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(codes(snapshot)).toEqual(["unknown-key", "unknown-key"]);
    expect(pathsFor(snapshot, "unknown-key").sort()).toEqual(["alsoBad", "bogus"]);
  });

  it("rejects legacy decision judge endpoint and profile declarations", () => {
    for (const type of ["endpoint", "profile"]) {
      const harness = createHarness();
      harness.writeGlobal({ approver: { judge: { type, url: "https://example.com" } } });
      const snapshot = ownerFor(harness).snapshot();
      expect(snapshot.source).toBe("invalid");
      expect(codes(snapshot)).toEqual(["legacy-declaration"]);
      expect(pathsFor(snapshot, "legacy-declaration")).toEqual(["approver.judge"]);
    }
  });

  it("ignores legacy classifier keys once and keeps the rest strictly validated", () => {
    const harness = createHarness();
    harness.writeGlobal({ classifier: { model: "x" }, classifierModel: "y", mode: "read-only" });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("global");
    expect(snapshot.config.mode).toBe("read-only");
    expect(codes(snapshot)).toEqual(["migration"]);
    expect((snapshot.config as unknown as Record<string, unknown>).classifier).toBeUndefined();
    expect((snapshot.config as unknown as Record<string, unknown>).classifierModel).toBeUndefined();
  });

  it("still reports schema problems after stripping the legacy classifier keys", () => {
    const harness = createHarness();
    harness.writeGlobal({ classifier: {}, unknownField: true });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(codes(snapshot)).toEqual(["migration", "unknown-key"]);
  });

  it("refuses to write an invalid global configuration", () => {
    const harness = createHarness();
    harness.writeGlobalText("{ not json");
    const owner = ownerFor(harness);
    const saveFailure = expectSaveFailure(owner.save({ mode: "read-only" }));
    expect(saveFailure.code).toBe("not-writable");
    const updateFailure = expectSaveFailure(owner.update((current) => ({ ...current, mode: "read-only" })));
    expect(updateFailure.code).toBe("not-writable");
    expect(harness.globalFileContent()).toBe("{ not json");
  });

  it("accepts JSON with comments", () => {
    const harness = createHarness();
    harness.writeGlobalText(`{
      // A line comment before the field.
      "mode": "read-only",
      /* A block comment with an URL: https://example.com */
      "debugLog": true
    }`);
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("global");
    expect(snapshot.config.mode).toBe("read-only");
    expect(snapshot.config.debugLog).toBe(true);
    expect(snapshot.issues).toEqual([]);
  });

  it("keeps the global schema marker and migration metadata", () => {
    const harness = createHarness();
    harness.writeGlobal({
      $schema: "urn:example:global",
      migration: { version: 1, from: "legacy-global-policy" },
      mode: "read-only",
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.$schema).toBe("urn:example:global");
    expect(snapshot.config.migration).toEqual({ version: 1, from: "legacy-global-policy" });
    expect(snapshot.source).toBe("global");
  });
});

/* ------------------------------------------------------------------------- */
/* Project scope loading and merge                                            */
/* ------------------------------------------------------------------------- */

describe("project configuration scope", () => {
  it("ignores a project file that exists but is untrusted", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    harness.writeProject({ mode: "default" });
    const snapshot = ownerFor(harness, { projectTrusted: false }).snapshot();
    expect(snapshot.projectConfig).toBeUndefined();
    expect(snapshot.projectConfigInvalid).toBe(false);
    expect(snapshot.source).toBe("global");
    expect(snapshot.config.mode).toBe("read-only");
    expect(codes(snapshot)).toEqual(["untrusted-project"]);
    expect(snapshot.issues[0]?.file).toBe(harness.paths.projectConfigFile);
  });

  it("does not read the project scope when the working directory is empty", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    harness.writeProject({ mode: "default" });
    const counting = countingReader(harness.readFile);
    const snapshot = ownerFor(harness, { cwd: "", readFile: counting.read }).snapshot();
    expect(counting.calls).not.toContain(harness.paths.projectConfigFile);
    expect(snapshot.projectConfig).toBeUndefined();
    expect(snapshot.issues).toEqual([]);
    expect(snapshot.config.mode).toBe("read-only");
  });

  it("keeps the global configuration when the project file is missing", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "auto-review" });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.projectConfig).toBeUndefined();
    expect(snapshot.source).toBe("global");
    expect(snapshot.config.mode).toBe("auto-review");
    expect(snapshot.issues).toEqual([]);
  });

  it("marks an invalid project file and fails execution closed", () => {
    const harness = createHarness();
    harness.writeGlobal({ execution: { network: { mode: "all" } } });
    harness.writeProjectText("{ definitely not json");
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.projectConfigInvalid).toBe(true);
    expect(snapshot.projectConfig).toBeUndefined();
    expect(snapshot.source).toBe("global");
    expect(snapshot.canWrite).toBe(true);
    expect(codes(snapshot)).toEqual(["parse-failed"]);
    expect(snapshot.issues[0]?.file).toBe(harness.paths.projectConfigFile);
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
  });

  it("adopts a lower or equal project mode and marks the mode source", () => {
    const lower = createHarness();
    lower.writeGlobal({ mode: "auto-review" });
    lower.writeProject({ mode: "read-only" });
    const lowerSnapshot = ownerFor(lower).snapshot();
    expect(lowerSnapshot.config.mode).toBe("read-only");
    expect(lowerSnapshot.modeSource).toBe("project");
    expect(lowerSnapshot.source).toBe("project");

    const equal = createHarness();
    equal.writeGlobal({ mode: "default" });
    equal.writeProject({ mode: "default" });
    const equalSnapshot = ownerFor(equal).snapshot();
    expect(equalSnapshot.config.mode).toBe("default");
    expect(equalSnapshot.modeSource).toBe("project");
    expect(equalSnapshot.source).toBe("project");
  });

  it("refuses a project mode escalation and reports it", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    harness.writeProject({ mode: "full-access" });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.mode).toBe("read-only");
    expect(snapshot.modeSource).toBe("global");
    expect(snapshot.source).toBe("global");
    expect(codes(snapshot)).toEqual(["mode-escalation"]);
    expect(pathsFor(snapshot, "mode-escalation")).toEqual(["mode"]);
  });

  it("rejects user-scope-only project declarations without changing the global values", () => {
    const harness = createHarness();
    harness.writeGlobal({});
    harness.writeProject({
      approver: { provider: "provider-a", model: "model-a" },
      learning: { enabled: true },
      toolBindings: [],
      experimental: { sandboxEnabled: true, mcpSandbox: true },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["user-scope-only", "user-scope-only", "user-scope-only", "user-scope-only"]);
    expect(pathsFor(snapshot, "user-scope-only").sort()).toEqual(["approver", "experimental", "learning", "toolBindings"]);
    expect(snapshot.config.approver.provider).toBeUndefined();
    expect(snapshot.config.learning.enabled).toBe(false);
    expect(snapshot.config.toolBindings).toEqual([]);
    expect(snapshot.config.experimental).toEqual({ sandboxEnabled: false });
    expect(snapshot.source).toBe("global");
  });

  it("merges declared engine fields with scalar and array replacement", () => {
    const harness = createHarness();
    harness.writeGlobal({
      debugLog: true,
      forwardingTimeoutMs: 100,
      promptNotifications: ["bell"],
      promptMaxRows: 3,
    });
    harness.writeProject({ debugLog: false, forwardingTimeoutMs: 200, promptNotifications: [], promptMaxRows: 9 });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.debugLog).toBe(false);
    expect(snapshot.config.forwardingTimeoutMs).toBe(200);
    expect(snapshot.config.promptNotifications).toEqual([]);
    expect(snapshot.config.promptMaxRows).toBe(9);
    expect(snapshot.source).toBe("project");
  });

  it("merges permission maps per surface and shell tools per name, and replaces dialog keys", () => {
    const harness = createHarness();
    harness.writeGlobal({
      permission: { bash: { "git *": "allow" }, path_read: "ask" },
      shellTools: { bash: { commandArgument: "command" } },
      permissionDialogKeys: { approve: "a" },
    });
    harness.writeProject({
      permission: { bash: { "npm *": "ask" }, mcp: "deny" },
      shellTools: { bash: { commandArgument: "command", workdirArgument: "cwd" }, zsh: { commandArgument: "cmd" } },
      permissionDialogKeys: { approve: "x", deny: "d" },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.permission).toEqual({
      bash: { "git *": "allow", "npm *": "ask" },
      path_read: "ask",
      mcp: "deny",
    });
    expect(snapshot.config.shellTools).toEqual({
      bash: { commandArgument: "command", workdirArgument: "cwd" },
      zsh: { commandArgument: "cmd" },
    });
    expect(snapshot.config.permissionDialogKeys).toEqual({ approve: "x", deny: "d" });
    expect(snapshot.source).toBe("project");
  });

  it("marks the source default when only rejected project fields are declared", () => {
    const harness = createHarness();
    harness.writeProject({ approver: { provider: "p", model: "m" } });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("default");
    expect(snapshot.modeSource).toBe("default");
    expect(codes(snapshot)).toEqual(["user-scope-only"]);
  });

  it("folds project command effects over the global declarations", () => {
    const harness = createHarness();
    harness.writeGlobal({ commandEffects: { git: { effects: "read" }, ls: { effects: "read" } } });
    harness.writeProject({ commandEffects: { git: { effects: "write" } } });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.commandEffects).toEqual({
      git: { effects: "write" },
      ls: { effects: "read" },
    });
    expect(snapshot.source).toBe("project");
  });

  it("accepts a project file with comments", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "auto-review" });
    harness.writeProjectText(`{
      // Only the mode is lowered here.
      "mode": "read-only"
    }`);
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("project");
    expect(snapshot.config.mode).toBe("read-only");
    expect(snapshot.issues).toEqual([]);
  });

  it("ignores the project schema marker and keeps the global one", () => {
    const harness = createHarness();
    harness.writeGlobal({ $schema: "urn:example:global", mode: "auto-review" });
    harness.writeProject({ $schema: "urn:example:project", mode: "read-only" });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.$schema).toBe("urn:example:global");
    expect(snapshot.config.mode).toBe("read-only");
  });
});

/* ------------------------------------------------------------------------- */
/* Session mode override                                                      */
/* ------------------------------------------------------------------------- */

describe("session mode", () => {
  it("applies an override only to the requested session", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    owner.setSessionMode("session-a", "read-only");
    const sessionA = snapshotOf(owner, "session-a");
    expect(sessionA.config.mode).toBe("read-only");
    expect(sessionA.modeSource).toBe("session");
    expect(sessionA.sessionId).toBe("session-a");
    expect(sessionOf(owner, "session-b").config.mode).toBe("default");
    expect(sessionOf(owner, "session-b").modeSource).toBe("global");
    expect(owner.snapshot().config.mode).toBe("default");
    expect("sessionId" in owner.snapshot()).toBe(false);
  });

  it("clears an override and reuses the persisted mode", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "auto-review" });
    const owner = ownerFor(harness);
    owner.setSessionMode("session-a", "read-only");
    owner.setSessionMode("session-a", null);
    const snapshot = snapshotOf(owner, "session-a");
    expect(snapshot.config.mode).toBe("auto-review");
    expect(snapshot.modeSource).toBe("global");
  });

  it("rejects setting an override without a session id", () => {
    const harness = createHarness();
    const owner = ownerFor(harness);
    expect(() => owner.setSessionMode(undefined, "read-only")).toThrow(Error);
    expect(() => owner.setSessionMode("   ", "read-only")).toThrow(Error);
    expect(() => owner.setSessionMode(undefined, null)).not.toThrow();
  });

  it("does not apply a session override to an invalid global configuration", () => {
    const harness = createHarness();
    harness.writeGlobalText("{ broken");
    const owner = ownerFor(harness);
    owner.setSessionMode("session-a", "full-access");
    const snapshot = snapshotOf(owner, "session-a");
    expect(snapshot.source).toBe("invalid");
    expect(snapshot.modeSource).toBe("default");
    expect(snapshot.config.mode).toBe("default");
  });
});

function sessionOf(owner: ApprovalChainConfigOwner, sessionId: string): ApprovalChainConfigSnapshot {
  return owner.snapshot({ sessionId });
}

/* ------------------------------------------------------------------------- */
/* Effective approval nodes                                                   */
/* ------------------------------------------------------------------------- */

describe("effective approval nodes", () => {
  it("does not let a project declaration enable an optional builtin node", () => {
    const harness = createHarness();
    harness.writeProject({ approval: { nodes: { "builtin/powershell": { enabled: true } } } });

    const snapshot = ownerFor(harness).snapshot();

    expect(nodeById(snapshot, "builtin/powershell")).toBeUndefined();
    expect(codes(snapshot)).toContain("node-config");
  });

  it("merges unique project shell rules without replacing global rules", () => {
    const harness = createHarness();
    harness.writeGlobal({
      shellPolicy: { version: 1, rules: [
        { id: "shared-rule", node: "builtin/external-command", when: { program: "git" }, then: { decision: "ask" } },
      ] },
    });
    harness.writeProject({
      shellPolicy: { version: 1, rules: [
        { id: "shared-rule", node: "builtin/external-command", when: { program: "git" }, then: { decision: "allow" } },
        { id: "project-rule", node: "builtin/external-command", when: { program: "rg" }, then: { decision: "deny" } },
      ] },
    });

    const snapshot = ownerFor(harness).snapshot();

    expect(snapshot.config.shellPolicy?.rules.map((rule) => [rule.id, rule.then.decision])).toEqual([
      ["shared-rule", "ask"],
      ["project-rule", "deny"],
    ]);
    expect(pathsFor(snapshot, "shell-policy")).toEqual(["shellPolicy"]);
    expect(snapshot.source).toBe("project");
  });

  it("warns about a shadowed project node and keeps the global declaration", () => {
    const harness = createHarness();
    harness.writeGlobal({ approval: { nodes: { shared: { path: "/global.mjs" } } } });
    harness.writeProject({ approval: { nodes: { shared: { path: "/project.mjs" } } } });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.nodeConfig.warnings).toEqual([{ code: "project-node-shadowed", id: "shared" }]);
    expect(snapshot.config.approval.nodes).toEqual({ shared: { path: "/global.mjs" } });
    expect(userNodeIds(snapshot)).toEqual(["shared"]);
    expect(nodeById(snapshot, "shared")?.source).toBe("global");
    expect(snapshot.source).toBe("global");
  });

  it("falls back to the global nodes when the combined composition fails", () => {
    const harness = createHarness();
    harness.writeGlobal({ approval: { nodes: { global: { path: "/global.mjs" } } } });
    harness.writeProject({ approval: { nodes: { broken: {} } } });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["node-config"]);
    expect(userNodeIds(snapshot)).toEqual(["global"]);
    expect(snapshot.config.approval.nodes).toEqual({ global: { path: "/global.mjs" } });
  });

  it("falls back to an empty node configuration when the global nodes are invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({ approval: { nodes: { "builtin/unknown": { enabled: true } } } });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["node-config", "node-config"]);
    expect(snapshot.config.approval.nodes).toEqual({});
    expect(userNodeIds(snapshot)).toEqual([]);
    expect(nodeById(snapshot, "builtin/llm-approver")?.enabled).toBe(true);
    expect(snapshot.source).toBe("global");
  });

  it("exposes a stable node digest that changes with the declarations", () => {
    const harness = createHarness();
    harness.writeGlobal({ approval: { nodes: { node: { path: "/node.mjs" } } } });
    const owner = ownerFor(harness);
    const first = owner.snapshot();
    const second = owner.reload();
    expect(first.nodeConfig.digest).toBe(second.nodeConfig.digest);

    harness.writeGlobal({ approval: { nodes: { node: { path: "/other.mjs" } } } });
    const third = owner.reload();
    expect(third.nodeConfig.digest).not.toBe(first.nodeConfig.digest);
  });
});

/* ------------------------------------------------------------------------- */
/* Project execution ceiling                                                  */
/* ------------------------------------------------------------------------- */

describe("project execution ceiling", () => {
  const sharedDir = (harness: Harness) => join(harness.root, "shared");
  const shellPermissions = (read: readonly unknown[], write: readonly unknown[], network: unknown) => ({
    filesystem: { read, write },
    network,
  });

  it("accepts project shell grants that narrow the global filesystem and network ceiling", () => {
    const harness = createHarness();
    const projectDirectory = harness.projectCwd;
    harness.writeGlobal({
      execution: { shell: shellPermissions(
        [{ path: harness.root, granularity: "directory" }],
        [],
        { mode: "all" },
      ) },
    });
    harness.writeProject({
      execution: { shell: shellPermissions(
        [{ path: projectDirectory, granularity: "directory" }],
        [],
        { mode: "allowlist", allow: [{ host: "api.example.com", port: 443 }] },
      ) },
    });

    const snapshot = ownerFor(harness).snapshot();

    expect(codes(snapshot)).toEqual([]);
    expect(snapshot.config.execution.shell?.filesystem.read[0]?.path).toBe(projectDirectory);
    expect(snapshot.config.execution.shell?.network).toEqual({
      mode: "allowlist",
      allow: [{ host: "api.example.com", port: 443 }],
    });
  });

  it("disables project shell grants outside the global ceiling", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { shell: shellPermissions(
        [{ path: sharedDir(harness), granularity: "directory" }],
        [],
        { mode: "none" },
      ) },
    });
    harness.writeProject({
      execution: { shell: shellPermissions(
        [{ path: join(harness.root, "outside"), granularity: "directory" }],
        [],
        { mode: "none" },
      ) },
    });

    const snapshot = ownerFor(harness).snapshot();

    expect(codes(snapshot)).toContain("execution");
    expect(snapshot.config.execution.shell).toEqual({
      filesystem: { read: [], write: [] },
      network: { mode: "none" },
    });
  });

  it("expands only the host-provided shell path variables", () => {
    const harness = createHarness();
    const temporaryRoot = join(harness.root, "temp");
    harness.writeGlobal({
      execution: { shell: shellPermissions(
        [{ path: "${tempDir}/agent", granularity: "directory" }],
        [{ path: "${workspace}/output", granularity: "directory" }],
        { mode: "none" },
      ) },
    });

    const snapshot = ownerFor(harness, {
      shellPathVariables: { workspace: harness.projectCwd, tempDir: temporaryRoot },
    }).snapshot();

    expect(snapshot.globalConfig.execution.shell?.filesystem.read[0]?.path).toBe(join(temporaryRoot, "agent"));
    expect(snapshot.globalConfig.execution.shell?.filesystem.write[0]?.path).toBe(join(harness.projectCwd, "output"));
  });

  it("disables shell grants with unresolved path variables", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { shell: shellPermissions(
        [{ path: "${unknown}/agent", granularity: "directory" }],
        [],
        { mode: "none" },
      ) },
    });

    const snapshot = ownerFor(harness).snapshot();

    expect(codes(snapshot)).toContain("execution");
    expect(snapshot.globalConfig.execution.shell?.filesystem.read).toEqual([]);
  });
});

/* ------------------------------------------------------------------------- */
/* Top-level execution network and MCP visibility scope                       */
/* ------------------------------------------------------------------------- */

describe("execution network", () => {
  it("adopts a declared global network after host normalization", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { network: { mode: "allowlist", allow: [{ host: "API.Example.COM.", port: 8443 }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.globalConfig.execution.network).toEqual({
      mode: "allowlist",
      allow: [{ host: "api.example.com", port: 8443 }],
    });
    expect(snapshot.config.execution.network).toEqual(snapshot.globalConfig.execution.network);
  });

  it("defaults an omitted port to HTTP and HTTPS only", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { network: { mode: "allowlist", allow: [{ host: "github.com" }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.execution.network).toEqual({
      mode: "allowlist",
      allow: [{ host: "github.com", port: 80 }, { host: "github.com", port: 443 }],
    });
  });

  it("forces the network to none when a declared global host is invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { network: { mode: "allowlist", allow: [{ host: "bad host" }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["network"]);
    expect(pathsFor(snapshot, "network")).toEqual(["execution.network"]);
    expect(snapshot.globalConfig.execution.network).toEqual({ mode: "none" });
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
  });

  it("narrows a declared project network when it is a subset of the global network", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { network: { mode: "allowlist", allow: [{ host: "api.example.com", port: 443 }] } },
    });
    harness.writeProject({
      execution: { network: { mode: "allowlist", allow: [{ host: "API.example.com", port: 443 }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual([]);
    expect(snapshot.config.execution.network).toEqual({
      mode: "allowlist",
      allow: [{ host: "api.example.com", port: 443 }],
    });
    expect(snapshot.source).toBe("project");
  });

  it("forces the network to none when the project network exceeds the global network", () => {
    const harness = createHarness();
    harness.writeGlobal({
      execution: { network: { mode: "allowlist", allow: [{ host: "api.example.com", port: 443 }] } },
    });
    harness.writeProject({
      execution: { network: { mode: "allowlist", allow: [{ host: "other.example.com" }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["network"]);
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
    expect(snapshot.source).toBe("global");
  });

  it("forces the network to none when a project host is invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({ execution: { network: { mode: "all" } } });
    harness.writeProject({
      execution: { network: { mode: "allowlist", allow: [{ host: "no spaces" }] } },
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(codes(snapshot)).toEqual(["network"]);
    expect(snapshot.projectConfig?.execution.network).toEqual({ mode: "none" });
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
  });

  it("forces the network to none when the project configuration is invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({ execution: { network: { mode: "all" } } });
    harness.writeProjectText("{ broken");
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.config.execution.network).toEqual({ mode: "none" });
  });

});

/* ------------------------------------------------------------------------- */
/* Snapshot immutability and revision                                         */
/* ------------------------------------------------------------------------- */

describe("snapshot immutability", () => {
  it("freezes the snapshot, its configurations, nodes and paths", () => {
    const harness = createHarness();
    harness.writeGlobal({ approval: { nodes: { node: { path: "/node.mjs" } } } });
    harness.writeProject({ mode: "read-only" });
    const snapshot = ownerFor(harness).snapshot();
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.config)).toBe(true);
    expect(Object.isFrozen(snapshot.config.execution)).toBe(true);
    expect(Object.isFrozen(snapshot.globalConfig)).toBe(true);
    expect(Object.isFrozen(snapshot.projectConfig)).toBe(true);
    expect(Object.isFrozen(snapshot.nodeConfig)).toBe(true);
    expect(Object.isFrozen(snapshot.nodeConfig.nodes)).toBe(true);
    expect(Object.isFrozen(snapshot.nodeConfig.warnings)).toBe(true);
    expect(Object.isFrozen(snapshot.paths)).toBe(true);
    expect(Object.isFrozen(snapshot.issues)).toBe(true);
    expect(() => {
      (snapshot.config as { mode: string }).mode = "full-access";
    }).toThrow(TypeError);
  });
});

describe("revision", () => {
  it("starts at 1 and stays stable while the effective configuration is unchanged", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const owner = ownerFor(harness);
    expect(owner.snapshot().revision).toBe(1);
    expect(owner.snapshot().revision).toBe(1);
    expect(owner.reload().revision).toBe(1);
  });

  it("increments only when a changed configuration is explicitly reloaded", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const owner = ownerFor(harness);
    expect(owner.snapshot().revision).toBe(1);
    harness.writeGlobal({ mode: "auto-review" });
    expect(owner.snapshot().config.mode).toBe("read-only");
    expect(owner.snapshot().revision).toBe(1);
    expect(owner.reload().config.mode).toBe("auto-review");
    expect(owner.snapshot().revision).toBe(2);
    harness.writeGlobal({ mode: "full-access" });
    expect(owner.snapshot().revision).toBe(2);
    expect(owner.reload().config.mode).toBe("full-access");
    expect(owner.snapshot().revision).toBe(3);
  });

  it("ignores display-issue-only changes", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const owner = ownerFor(harness, { projectTrusted: false });
    expect(owner.snapshot().revision).toBe(1);
    harness.writeProject({ mode: "default" });
    expect(codes(owner.snapshot())).toEqual([]);
    const snapshot = owner.reload();
    expect(codes(snapshot)).toEqual(["untrusted-project"]);
    expect(snapshot.revision).toBe(1);
  });

  it("keeps a reload candidate inactive until its commit succeeds", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const owner = ownerFor(harness);
    const previous = owner.snapshot();
    harness.writeGlobal({ mode: "auto-review" });
    const candidate = owner.prepareReload();
    expect(candidate.snapshot.config.mode).toBe("auto-review");
    expect(owner.snapshot()).toBe(previous);
    expect(candidate.commit()).toBe(true);
    expect(owner.snapshot().config.mode).toBe("auto-review");
    expect(candidate.commit()).toBe(false);
  });

  it("keeps independent counters per session key", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    expect(sessionOf(owner, "session-a").revision).toBe(1);
    expect(sessionOf(owner, "session-b").revision).toBe(1);
    owner.setSessionMode("session-a", "read-only");
    expect(sessionOf(owner, "session-a").revision).toBe(2);
    expect(sessionOf(owner, "session-b").revision).toBe(1);
    owner.setSessionMode("session-a", null);
    expect(sessionOf(owner, "session-a").revision).toBe(3);
    expect(sessionOf(owner, "session-b").revision).toBe(1);
  });

  it("counts trust changes under a separate key", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    harness.writeProject({ mode: "read-only" });
    expect(ownerFor(harness, { projectTrusted: false }).snapshot().revision).toBe(1);
    expect(ownerFor(harness, { projectTrusted: true }).snapshot().revision).toBe(1);
  });
});

/* ------------------------------------------------------------------------- */
/* Global writes                                                              */
/* ------------------------------------------------------------------------- */

describe("global writes", () => {
  it("writes strict JSON with a trailing newline without changing the active snapshot", () => {
    const harness = createHarness();
    const owner = ownerFor(harness);
    const previous = owner.snapshot();
    const result = expectSaveSuccess(owner.save({ mode: "read-only" }));
    expect(harness.globalFileContent()).toBe(`${JSON.stringify({ mode: "read-only" }, null, 2)}\n`);
    expect(result.snapshot).toBe(previous);
    expect(result.snapshot.config.mode).toBe("default");
    expect(owner.snapshot().config.mode).toBe("default");
    expect(owner.reload().config.mode).toBe("read-only");
  });

  it("replaces the previous file content as a whole", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "full-access", debugLog: true });
    expect(harness.globalFileContent()).toContain("full-access");
    expectSaveSuccess(ownerFor(harness).save({ mode: "read-only" }));
    const content = harness.globalFileContent();
    expect(content).not.toContain("full-access");
    expect(content).not.toContain("debugLog");
    expect(JSON.parse(content)).toEqual({ mode: "read-only" });
  });

  it("rejects an invalid configuration without touching the file", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const before = harness.globalFileContent();
    const failure = expectSaveFailure(ownerFor(harness).save({ mode: "default", unknownKey: true }));
    expect(failure.code).toBe("invalid-config");
    expect(failure.messages.map((message) => message.code)).toContain("unknown-key");
    expect(failure.messages[0]?.file).toBe(harness.paths.globalConfigFile);
    expect(harness.globalFileContent()).toBe(before);
  });

  it("reports a write failure and leaves no temporary file behind", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const before = harness.globalFileContent();
    const failure = expectSaveFailure(ownerFor(harness, {
      tempName: () => {
        throw new Error("temp-name-failed");
      },
    }).save({ mode: "auto-review" }));
    expect(failure.code).toBe("write-failed");
    expect(failure.messages[0]?.code).toBe("write-failed");
    expect(harness.globalFileContent()).toBe(before);
    expect(existsSync(join(harness.paths.globalConfigDir, "config.json"))).toBe(true);
  });

  it("leaves the target intact when the temporary path cannot be created", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    const before = harness.globalFileContent();
    // An existing directory at the temporary name makes the exclusive create fail.
    mkdirSync(join(harness.paths.globalConfigDir, "blocking-temp"), { recursive: true });
    const failure = expectSaveFailure(ownerFor(harness, { tempName: () => "blocking-temp" }).save({ mode: "auto-review" }));
    expect(failure.code).toBe("write-failed");
    expect(harness.globalFileContent()).toBe(before);
    const entries = readdirSync(harness.paths.globalConfigDir);
    expect(entries.sort()).toEqual(["blocking-temp", "config.json"]);
  });

  it("applies an update mutation and persists it", () => {    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    let observed: ApprovalChainConfig | undefined;
    const result = expectSaveSuccess(owner.update((current) => {
      observed = current;
      return { ...current, mode: "auto-review" };
    }));
    expect(observed?.mode).toBe("default");
    expect(result.snapshot.config.mode).toBe("default");
    expect(JSON.parse(harness.globalFileContent()).mode).toBe("auto-review");
    expect(owner.reload().config.mode).toBe("auto-review");
  });

  it("persists Decision reviewer enablement across owner recreation (restart)", () => {
    const harness = createHarness();
    harness.writeGlobal({
      mode: "default",
      approver: { provider: "cc-switch-kimi", model: "kimi-for-coding" },
      approval: {
        nodes: {
          "builtin/llm-approver": { enabled: true },
          "builtin/decision-approver": { enabled: false },
        },
      },
    });
    const owner = ownerFor(harness);
    const decisionEnabled = (candidate: ApprovalChainConfigOwner): boolean | undefined =>
      candidate.snapshot().nodeConfig.nodes.find((node) => node.id === "builtin/decision-approver")?.enabled;
    expect(decisionEnabled(owner)).toBe(false);

    expectSaveSuccess(owner.update(
      (current) => applyExperiments(
        current,
        { decision: true },
        { provider: "typesafe", model: "jev" },
      ),
    ));
    const onDisk = JSON.parse(harness.globalFileContent());
    expect(onDisk.approval.nodes["builtin/decision-approver"]).toEqual({ enabled: true });
    expect(onDisk.approval.nodes["builtin/llm-approver"]).toEqual({ enabled: false });
    expect(onDisk.approver.judge).toMatchObject({ type: "pi-classifier", provider: "typesafe", model: "jev" });
    expect(decisionEnabled(ownerFor(harness))).toBe(true);
  });

  it("preserves external disk edits when updating a setting before reload", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    const active = owner.snapshot();
    harness.writeGlobal({ mode: "default", debugLog: true });

    const result = expectSaveSuccess(owner.setMode("read-only"));

    const savedConfig = JSON.parse(harness.globalFileContent()) as Record<string, unknown>;
    expect(savedConfig.mode).toBe("read-only");
    expect(savedConfig.debugLog).toBe(true);
    expect(result.snapshot).toBe(active);
    expect(owner.snapshot()).toBe(active);
    expect(owner.reload().globalConfig.debugLog).toBe(true);
  });

  it("refuses an update when the current disk configuration is invalid", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    const active = owner.snapshot();
    harness.writeGlobalText("{ invalid");

    const failure = expectSaveFailure(owner.setMode("read-only"));

    expect(failure.code).toBe("not-writable");
    expect(harness.globalFileContent()).toBe("{ invalid");
    expect(owner.snapshot()).toBe(active);
  });

  it("bases consecutive updates on the latest disk configuration", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default", debugLog: true });
    const owner = ownerFor(harness);
    const active = owner.snapshot();

    expectSaveSuccess(owner.setMode("read-only"));
    expectSaveSuccess(owner.setMode("auto-review"));

    const savedConfig = JSON.parse(harness.globalFileContent()) as Record<string, unknown>;
    expect(savedConfig.mode).toBe("auto-review");
    expect(savedConfig.debugLog).toBe(true);
    expect(owner.snapshot()).toBe(active);
    expect(owner.reload().config.mode).toBe("auto-review");
  });

  it("reports a throwing mutator as an invalid configuration", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const before = harness.globalFileContent();
    const failure = expectSaveFailure(ownerFor(harness).update(() => {
      throw new Error("mutation-broken");
    }));
    expect(failure.code).toBe("invalid-config");
    expect(failure.messages[0]?.code).toBe("invalid-config");
    expect(harness.globalFileContent()).toBe(before);
  });

  it("persists a valid mode and rejects an unknown mode", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "default" });
    const owner = ownerFor(harness);
    const success = expectSaveSuccess(owner.setMode("auto-review"));
    expect(success.snapshot.config.mode).toBe("default");
    expect(JSON.parse(harness.globalFileContent()).mode).toBe("auto-review");
    expect(owner.reload().config.mode).toBe("auto-review");

    const before = harness.globalFileContent();
    const failure = expectSaveFailure(owner.setMode("turbo" as never));
    expect(failure.code).toBe("invalid-config");
    expect(failure.messages[0]?.path).toBe("mode");
    expect(harness.globalFileContent()).toBe(before);
  });
});

/* ------------------------------------------------------------------------- */
/* Project rule persistence                                                   */
/* ------------------------------------------------------------------------- */

describe("project rule persistence", () => {
  it("refuses to write an untrusted project file", () => {
    const harness = createHarness();
    harness.writeProject({ mode: "default" });
    const failure = expectProjectRuleFailure(
      ownerFor(harness, { projectTrusted: false }).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(failure.code).toBe("not-trusted");
  });

  it("refuses when no project file exists or the working directory is empty", () => {
    const missing = createHarness();
    const missingFailure = expectProjectRuleFailure(
      ownerFor(missing).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(missingFailure.code).toBe("no-project");

    const emptyCwd = createHarness();
    emptyCwd.writeProject({ mode: "default" });
    const cwdFailure = expectProjectRuleFailure(
      ownerFor(emptyCwd, { cwd: "" }).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(cwdFailure.code).toBe("no-project");
  });

  it("refuses a corrupt project file", () => {
    const harness = createHarness();
    harness.writeProjectText("{ broken");
    const failure = expectProjectRuleFailure(
      ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(failure.code).toBe("corrupt-file");
  });

  it("refuses empty surface or pattern values", () => {
    const harness = createHarness();
    harness.writeProject({ mode: "default" });
    for (const input of [
      { surface: "", pattern: "git status" },
      { surface: "bash", pattern: "   " },
    ]) {
      const failure = expectProjectRuleFailure(ownerFor(harness).saveProjectRule(input));
      expect(failure.code).toBe("invalid-config");
    }
    expect(JSON.parse(harness.projectFileContent())).toEqual({ mode: "default" });
  });

  it("refuses a project document that fails strict validation", () => {
    const harness = createHarness();
    harness.writeProject({ mode: "default", unknownKey: true });
    const failure = expectProjectRuleFailure(
      ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(failure.code).toBe("invalid-config");
    expect(failure.messages.map((message) => message.path)).toContain("unknownKey");
  });

  it("appends an allow rule, creating the permission map and surface", () => {
    const harness = createHarness();
    harness.writeProject({ mode: "read-only" });
    const owner = ownerFor(harness);
    const result = expectProjectRuleSuccess(
      owner.saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(JSON.parse(harness.projectFileContent())).toEqual({
      mode: "read-only",
      permission: { bash: { "git status": "allow" } },
    });
    expect(result.snapshot.projectConfig).toBeDefined();
    expect(result.snapshot.config.permission).toBeUndefined();
    const reloaded = owner.reload();
    expect(reloaded.projectConfigInvalid).toBe(false);
    expect(reloaded.config.permission).toEqual({ bash: { "git status": "allow" } });
    expect(reloaded.source).toBe("project");
  });

  it("converts a string catch-all surface into an equivalent pattern map", () => {
    const harness = createHarness();
    harness.writeProject({ permission: { bash: "ask" } });
    expectProjectRuleSuccess(ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }));
    const written = JSON.parse(harness.projectFileContent()) as {
      permission: { bash: Record<string, string> };
    };
    expect(Object.keys(written.permission.bash)).toEqual(["*", "git status"]);
    expect(written.permission.bash).toEqual({ "*": "ask", "git status": "allow" });
  });

  it("overrides an existing pattern to allow without moving it", () => {
    const harness = createHarness();
    harness.writeProject({ permission: { bash: { "git status": "ask", "npm *": "allow" } } });
    expectProjectRuleSuccess(ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }));
    const written = JSON.parse(harness.projectFileContent()) as {
      permission: { bash: Record<string, string> };
    };
    expect(Object.keys(written.permission.bash)).toEqual(["git status", "npm *"]);
    expect(written.permission.bash).toEqual({ "git status": "allow", "npm *": "allow" });
  });

  it("appends a new pattern at the end of an existing surface map", () => {
    const harness = createHarness();
    harness.writeProject({ permission: { bash: { "npm *": "allow" } } });
    expectProjectRuleSuccess(ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }));
    const written = JSON.parse(harness.projectFileContent()) as {
      permission: { bash: Record<string, string> };
    };
    expect(Object.keys(written.permission.bash)).toEqual(["npm *", "git status"]);
  });

  it("preserves other project fields and rules", () => {
    const harness = createHarness();
    harness.writeProject({
      mode: "auto-review",
      debugLog: true,
      permission: { bash: { "npm *": "allow" } },
    });
    expectProjectRuleSuccess(ownerFor(harness).saveProjectRule({ surface: "mcp", pattern: "server/tool" }));
    expect(JSON.parse(harness.projectFileContent())).toEqual({
      mode: "auto-review",
      debugLog: true,
      permission: {
        bash: { "npm *": "allow" },
        mcp: { "server/tool": "allow" },
      },
    });
  });

  it("refuses a rule covered by a project deny wildcard", () => {
    const deniedByPrefix = createHarness();
    deniedByPrefix.writeProject({ permission: { bash: { "rm *": "deny" } } });
    const prefixFailure = expectProjectRuleFailure(
      ownerFor(deniedByPrefix).saveProjectRule({ surface: "bash", pattern: "rm -rf /" }),
    );
    expect(prefixFailure.code).toBe("denied-by-policy");

    const deniedByCatchAll = createHarness();
    deniedByCatchAll.writeProject({ permission: { bash: "deny" } });
    const catchAllFailure = expectProjectRuleFailure(
      ownerFor(deniedByCatchAll).saveProjectRule({ surface: "bash", pattern: "git status" }),
    );
    expect(catchAllFailure.code).toBe("denied-by-policy");
  });

  it("refuses a rule covered by a global deny wildcard", () => {
    const harness = createHarness();
    harness.writeGlobal({ permission: { bash: { "git push*": "deny" } } });
    harness.writeProject({ mode: "default" });
    const failure = expectProjectRuleFailure(
      ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git push --force" }),
    );
    expect(failure.code).toBe("denied-by-policy");
    expect(JSON.parse(harness.projectFileContent())).toEqual({ mode: "default" });
  });

  it("writes only the project file, never the global file", () => {
    const harness = createHarness();
    harness.writeGlobal({ mode: "read-only" });
    harness.writeProject({ mode: "default" });
    const globalBefore = harness.globalFileContent();
    expectProjectRuleSuccess(ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "git status" }));
    expect(harness.globalFileContent()).toBe(globalBefore);
  });

  it("adds a rule that existing deny patterns do not cover", () => {
    const harness = createHarness();
    harness.writeGlobal({ permission: { bash: { "rm *": "deny" } } });
    harness.writeProject({ permission: { bash: { "chmod 777 *": { action: "deny", reason: "unsafe" } } } });
    const result = expectProjectRuleSuccess(
      ownerFor(harness).saveProjectRule({ surface: "bash", pattern: "ls -la" }),
    );
    expect(result.ok).toBe(true);
    expect(JSON.parse(harness.projectFileContent())).toEqual({
      permission: {
        bash: {
          "chmod 777 *": { action: "deny", reason: "unsafe" },
          "ls -la": "allow",
        },
      },
    });
  });
});


/* ------------------------------------------------------------------------- */
/* Tool admission rules (design §5.4, §5.5)                                   */
/* ------------------------------------------------------------------------- */

describe("tool admission rules", () => {
  const allowBash = { id: "allow-bash", match: { tool: "bash" }, decision: "allow" };
  const denyMcp = { id: "deny-mcp", match: { tool: "mcp__*" }, decision: "deny" };

  it("orders project rules before global rules for evaluation", () => {
    const harness = createHarness();
    harness.writeGlobal({ toolRules: [allowBash] });
    harness.writeProject({ toolRules: [denyMcp] });

    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.toolRules.map((entry) => [entry.scope, entry.rule.id])).toEqual([
      ["project", "deny-mcp"],
      ["global", "allow-bash"],
    ]);
    expect(snapshot.config.toolRules.map((rule) => rule.id)).toEqual(["deny-mcp", "allow-bash"]);
    expect(snapshot.source).toBe("project");
  });

  it("keeps global rules when the project declares none", () => {
    const harness = createHarness();
    harness.writeGlobal({ toolRules: [allowBash] });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.toolRules).toEqual([{ scope: "global", rule: allowBash }]);
  });

  it("ignores project rules when the project is not trusted", () => {
    const harness = createHarness();
    harness.writeGlobal({ toolRules: [allowBash] });
    harness.writeProject({ toolRules: [denyMcp] });
    const snapshot = ownerFor(harness, { projectTrusted: false }).snapshot();
    expect(snapshot.toolRules.map((entry) => entry.rule.id)).toEqual(["allow-bash"]);
  });

  it("bumps the revision when a rule table changes", () => {
    const harness = createHarness();
    harness.writeGlobal({ toolRules: [allowBash] });
    const owner = ownerFor(harness);
    const first = owner.snapshot();
    harness.writeGlobal({ toolRules: [denyMcp] });
    const second = owner.reload();
    expect(second.revision).toBeGreaterThan(first.revision);
    expect(second.toolRules.map((entry) => entry.rule.id)).toEqual(["deny-mcp"]);
  });

  it("migrates toolBindings into allow rules with one deprecation message", () => {
    const harness = createHarness();
    harness.writeGlobal({
      toolBindings: [{
        tool: "watchdog_diff",
        origin: "pi-subagents",
        profile: "file-reader",
        locations: [{ pointer: "/path", access: "read" }],
      }],
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.toolRules).toHaveLength(1);
    expect(snapshot.toolRules[0]?.rule).toMatchObject({
      match: { tool: "watchdog_diff" },
      decision: "allow",
      profile: "file-reader",
      locations: [{ pointer: "/path", access: "read" }],
    });
    expect(snapshot.issues.filter((issue) => issue.code === "deprecated").length).toBe(1);
  });

  it("does not migrate when toolRules are already declared", () => {
    const harness = createHarness();
    harness.writeGlobal({
      toolRules: [allowBash],
      toolBindings: [{
        tool: "watchdog_diff",
        origin: "pi-subagents",
        profile: "file-reader",
        locations: [{ pointer: "/path", access: "read" }],
      }],
    });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.toolRules.map((entry) => entry.rule.id)).toEqual(["allow-bash"]);
    expect(snapshot.issues.some((issue) => issue.code === "deprecated")).toBe(false);
  });

  it("rejects an invalid rule table with an addressed message", () => {
    const harness = createHarness();
    harness.writeGlobal({ toolRules: [{ id: "bad", match: { tool: "bash" }, decision: "ask" }] });
    const snapshot = ownerFor(harness).snapshot();
    expect(snapshot.source).toBe("invalid");
    expect(snapshot.toolRules).toEqual([]);
  });
});
