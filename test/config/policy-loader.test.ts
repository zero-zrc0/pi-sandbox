import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createPolicyLoader,
  type PolicyLoader,
  type PolicyLoaderOptions,
  type PolicyLoaderView,
  type PolicyScopeFiles,
} from "#config/policy-loader";
import { createConfigFileReader, type ConfigFileReader, type ConfigFileStat } from "#config/config-loader";
import { joinPath, resolveConfigPaths, type ConfigPaths } from "#config/config-paths";
import type { PolicyLoaderView as ManagerPolicyLoaderView } from "#approve-core/policy/permission-manager";

const temporaryRoots: string[] = [];

afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root !== undefined) rmSync(root, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

interface HarnessOptions {
  readonly cwd?: string;
  readonly projectTrusted?: boolean;
  readonly globalAgentsDir?: string;
  readonly projectAgentsDir?: string;
  /** Path relative to the temporary root; absent means "not configured". */
  readonly mcpConfigFile?: string;
  /** Path relative to the temporary root; absent means "not configured". */
  readonly projectMcpConfigFile?: string;
  readonly mcpServerNames?: readonly string[];
  readonly unreadable?: (path: string) => boolean;
  /** Leave `readFile`/`readMtime` to the loader defaults (real node:fs). */
  readonly useDefaultIo?: boolean;
}

interface Harness {
  readonly root: string;
  readonly loader: PolicyLoader;
  readonly paths: ConfigPaths;
  readonly cwd: string;
  readonly globalAgentsDir: string;
  readonly mcpConfigFile: string | undefined;
  readonly projectMcpConfigFile: string | undefined;
  readonly reads: string[];
  readonly mtimeCalls: string[];
  write(path: string, content: string, mtime?: number): string;
  writeWithoutMtime(path: string, content: string): string;
  setMtime(path: string, mtime: number): void;
  readCount(path: string): number;
}

function createHarness(options: HarnessOptions = {}): Harness {
  const root = mkdtempSync(join(tmpdir(), "pi-policy-loader-"));
  temporaryRoots.push(root);
  const agentDir = join(root, "agent");
  const cwd = options.cwd ?? join(root, "project");
  const basePaths = resolveConfigPaths({ agentDir, cwd, extensionRoot: join(root, "extension") });
  const paths: ConfigPaths =
    options.projectAgentsDir === undefined
      ? basePaths
      : { ...basePaths, projectAgentsDir: options.projectAgentsDir };
  const globalAgentsDir = options.globalAgentsDir ?? join(agentDir, "agents");
  const mcpConfigFile = options.mcpConfigFile === undefined ? undefined : join(root, options.mcpConfigFile);
  const projectMcpConfigFile =
    options.projectMcpConfigFile === undefined ? undefined : join(root, options.projectMcpConfigFile);
  const mtimes = new Map<string, number>();
  const reads: string[] = [];
  const mtimeCalls: string[] = [];
  const realReader = createConfigFileReader();
  const readFile: ConfigFileReader = (path) => {
    reads.push(path);
    if (options.unreadable?.(path) === true) return { state: "unreadable", reason: "simulated read failure" };
    return realReader(path);
  };
  const readMtime: ConfigFileStat = (path) => {
    mtimeCalls.push(path);
    return mtimes.get(path);
  };
  let clock = 100;
  const writeRaw = (path: string, content: string): void => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, "utf8");
  };
  const write = (path: string, content: string, mtime?: number): string => {
    writeRaw(path, content);
    clock += 1;
    mtimes.set(path, mtime ?? clock);
    return path;
  };
  const writeWithoutMtime = (path: string, content: string): string => {
    writeRaw(path, content);
    mtimes.delete(path);
    return path;
  };
  const loaderOptions: PolicyLoaderOptions = {
    paths,
    cwd,
    projectTrusted: options.projectTrusted ?? true,
    globalAgentsDir,
    ...(options.useDefaultIo === true ? {} : { readFile, readMtime }),
    ...(mcpConfigFile === undefined ? {} : { mcpConfigFile }),
    ...(projectMcpConfigFile === undefined ? {} : { projectMcpConfigFile }),
    ...(options.mcpServerNames === undefined ? {} : { mcpServerNames: options.mcpServerNames }),
  };
  return {
    root,
    loader: createPolicyLoader(loaderOptions),
    paths,
    cwd,
    globalAgentsDir,
    mcpConfigFile,
    projectMcpConfigFile,
    reads,
    mtimeCalls,
    write,
    writeWithoutMtime,
    setMtime(path: string, mtime: number): void {
      mtimes.set(path, mtime);
    },
    readCount(path: string): number {
      return reads.filter((read) => read === path).length;
    },
  };
}

function approvalConfig(permission: unknown, extra: Readonly<Record<string, unknown>> = {}): string {
  return JSON.stringify({ permission, ...extra });
}

function mcpContent(names: readonly string[], key: "mcpServers" | "mcp-servers" = "mcpServers"): string {
  return JSON.stringify({ [key]: Object.fromEntries(names.map((name) => [name, {}])) });
}

function agentDocument(frontmatter: readonly string[], body = "Body text"): string {
  return ["---", ...frontmatter, "---", body].join("\n");
}

const GLOBAL_AGENT_FILE = (harness: Harness, name: string): string =>
  joinPath(harness.globalAgentsDir, `${name}.md`);
const PROJECT_AGENT_FILE = (harness: Harness, name: string): string =>
  joinPath(harness.paths.projectAgentsDir, `${name}.md`);

/* ------------------------------------------------------------------ */
/* Scope availability                                                  */
/* ------------------------------------------------------------------ */

describe("scope availability", () => {
  it("always provides the global scope and marks unavailable scopes with a dash", () => {
    const harness = createHarness({ cwd: "", projectTrusted: false });
    const view = harness.loader.load();

    expect(Object.keys(view.scopes)).toEqual(["global"]);
    expect(view.scopes.global).toEqual({});
    expect(view.paths).toEqual({ globalConfigFile: harness.paths.globalConfigFile });
    expect(view.stamp).toBe("g=missing|p=-|a=-|pa=-|m=-|pm=-");
    expect(view.messages).toEqual([]);
    expect(view.mcpServerNames).toEqual([]);
  });

  it("adds the project scope when the project directory is known and trusted", () => {
    const harness = createHarness({ cwd: "/work/project", projectTrusted: true });
    const view = harness.loader.load();

    expect(Object.keys(view.scopes)).toEqual(["global", "project"]);
    expect(view.paths.projectConfigFile).toBe(harness.paths.projectConfigFile);
    expect(view.stamp).toBe("g=missing|p=missing|a=-|pa=-|m=-|pm=-");
  });

  it("does not read a project file when the project is untrusted", () => {
    const harness = createHarness({ projectTrusted: false });
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "deny" }), 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toBeUndefined();
    expect(view.paths.projectConfigFile).toBeUndefined();
    expect(view.stamp).toContain("|p=-|");
    expect(harness.mtimeCalls).not.toContain(harness.paths.projectConfigFile);
    expect(harness.reads).not.toContain(harness.paths.projectConfigFile);
  });

  it("does not read a project file when the working directory is empty", () => {
    const harness = createHarness({ cwd: "" });

    const view = harness.loader.load();

    expect(view.scopes.project).toBeUndefined();
    expect(harness.mtimeCalls).not.toContain(harness.paths.projectConfigFile);
    expect(harness.reads).not.toContain(harness.paths.projectConfigFile);
  });

  it("treats a whitespace-only working directory as unavailable", () => {
    const harness = createHarness({ cwd: "   " });
    expect(harness.loader.load().scopes.project).toBeUndefined();
  });

  it("adds the agent scope for a valid agent name and a non-empty agent directory", () => {
    const harness = createHarness();
    const view = harness.loader.load("planner");

    expect(view.paths.agentFile).toBe(GLOBAL_AGENT_FILE(harness, "planner"));
    expect(view.stamp).toBe("g=missing|p=missing|a=missing|pa=missing|m=-|pm=-");
    expect(Object.keys(view.scopes)).toEqual(["global", "project", "agent", "project-agent"]);
  });

  it("omits the agent scope when no agent name is given", () => {
    const harness = createHarness();
    const view = harness.loader.load();

    expect(view.scopes.agent).toBeUndefined();
    expect(view.paths.agentFile).toBeUndefined();
    expect(view.stamp).toContain("|a=-|");
  });

  it.each(["", " ", "a/b", "a\\b", "..", "a b", "\tplanner"])(
    "treats agent name %j as absent",
    (name) => {
      const harness = createHarness();
      const view = harness.loader.load(name);

      expect(view.scopes.agent).toBeUndefined();
      expect(view.scopes["project-agent"]).toBeUndefined();
      expect(view.paths.agentFile).toBeUndefined();
      expect(view.stamp).toContain("|a=-|");
      // Only the global and project files are candidates for this load.
      expect(harness.mtimeCalls).toHaveLength(2);
    },
  );

  it("omits the agent scope when the global agent directory is empty", () => {
    const harness = createHarness({ globalAgentsDir: "" });
    const view = harness.loader.load("planner");

    expect(view.scopes.agent).toBeUndefined();
    expect(view.paths.agentFile).toBeUndefined();
    expect(view.stamp).toContain("|a=-|");
  });

  it("adds the project-agent scope only with a trusted project, a valid agent and a project agent directory", () => {
    const harness = createHarness();
    const view = harness.loader.load("planner");

    expect(view.paths.projectAgentFile).toBe(PROJECT_AGENT_FILE(harness, "planner"));
    expect(view.stamp).toContain("pa=missing");
  });

  it("omits the project-agent scope when the project is untrusted", () => {
    const harness = createHarness({ projectTrusted: false });
    const view = harness.loader.load("planner");

    expect(view.scopes["project-agent"]).toBeUndefined();
    expect(view.paths.projectAgentFile).toBeUndefined();
    expect(view.stamp).toContain("|pa=-|");
  });

  it("omits the project-agent scope when the project agent directory is empty", () => {
    const harness = createHarness({ projectAgentsDir: "" });
    const view = harness.loader.load("planner");

    expect(view.scopes.agent).toBeDefined();
    expect(view.scopes["project-agent"]).toBeUndefined();
    expect(view.paths.projectAgentFile).toBeUndefined();
    expect(view.stamp).toContain("|pa=-|");
  });
});

/* ------------------------------------------------------------------ */
/* Global scope                                                        */
/* ------------------------------------------------------------------ */

describe("global scope", () => {
  it("provides the parsed permission map", () => {
    const harness = createHarness();
    harness.write(
      harness.paths.globalConfigFile,
      approvalConfig({ bash: "deny", mcp: { gh: "ask" } }, { mode: "full-access" }),
      100,
    );

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({ permission: { bash: "deny", mcp: { gh: "ask" } } });
    expect(view.scopes.global?.invalid).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("accepts JSONC comments in the global file", () => {
    const harness = createHarness();
    harness.write(
      harness.paths.globalConfigFile,
      '// a comment\n{\n /* block */ "permission": {\n    "bash": "allow" // trailing\n  }\n}\n',
      100,
    );

    expect(harness.loader.load().scopes.global?.permission).toEqual({ bash: "allow" });
  });

  it("returns an empty scope when the global file is missing", () => {
    const harness = createHarness();
    expect(harness.loader.load().scopes.global).toEqual({});
  });

  it("returns an empty scope when the global config has no permission map", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, JSON.stringify({ mode: "read-only" }), 100);

    expect(harness.loader.load().scopes.global).toEqual({});
  });

  it("does not mark a global parse failure invalid and reports no message", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, "{ this is not json", 100);

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({});
    expect(view.scopes.global?.invalid).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("does not surface global schema problems", () => {
    const harness = createHarness();
    harness.write(
      harness.paths.globalConfigFile,
      JSON.stringify({ permission: { bash: "maybe" }, unexpectedField: true }),
      100,
    );

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({});
    expect(view.messages).toEqual([]);
  });

  it("treats an unreadable global file as an empty scope without messages", () => {
    const unreadable = new Set<string>();
    const harness = createHarness({ unreadable: (path) => unreadable.has(path) });
    unreadable.add(harness.paths.globalConfigFile);
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "deny" }), 100);

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({});
    expect(view.scopes.global?.invalid).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("treats a non-object global root as an empty scope", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, "[]", 100);

    expect(harness.loader.load().scopes.global).toEqual({});
  });
});

/* ------------------------------------------------------------------ */
/* Project scope                                                       */
/* ------------------------------------------------------------------ */

describe("project scope", () => {
  it("provides the parsed project permission map", () => {
    const harness = createHarness();
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "allow", mcp: { gh: "deny" } }), 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({ permission: { bash: "allow", mcp: { gh: "deny" } } });
    expect(view.scopes.project?.invalid).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("returns an empty scope when the project file is missing", () => {
    const harness = createHarness();
    expect(harness.loader.load().scopes.project).toEqual({});
  });

  it("returns an empty scope when the project config declares no permission", () => {
    const harness = createHarness();
    harness.write(harness.paths.projectConfigFile, JSON.stringify({ mode: "read-only" }), 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({});
    expect(view.messages).toEqual([]);
  });

  it("marks an unparsable project file invalid and reports one fail-closed message", () => {
    const harness = createHarness();
    harness.write(harness.paths.projectConfigFile, "{ broken", 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({ invalid: true });
    expect(view.messages).toHaveLength(1);
    expect(view.messages[0]).toMatchObject({
      code: "invalid-scope",
      file: harness.paths.projectConfigFile,
      path: "",
    });
    expect(view.messages[0]?.message).toMatch(/project/i);
    expect(view.messages[0]?.message).toMatch(/allow/i);
    expect(view.messages[0]?.message).toMatch(/confirmation/i);
  });

  it("marks a schema-invalid project file invalid", () => {
    const harness = createHarness();
    harness.write(harness.paths.projectConfigFile, JSON.stringify({ permission: { bash: "sometimes" } }), 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({ invalid: true });
    expect(view.messages.map((message) => message.code)).toEqual(["invalid-scope"]);
  });

  it("marks an unreadable project file invalid", () => {
    const unreadable = new Set<string>();
    const harness = createHarness({ unreadable: (path) => unreadable.has(path) });
    unreadable.add(harness.paths.projectConfigFile);
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "allow" }), 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({ invalid: true });
    expect(view.messages).toHaveLength(1);
  });

  it("ignores the project file entirely when the project is untrusted", () => {
    const harness = createHarness({ projectTrusted: false });
    harness.write(harness.paths.projectConfigFile, "{ broken", 200);

    const view = harness.loader.load();

    expect(view.scopes.project).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("does not report global problems while reporting a broken project file", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, "{ broken", 100);
    harness.write(harness.paths.projectConfigFile, "{ also broken", 200);

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({});
    expect(view.messages.map((message) => message.code)).toEqual(["invalid-scope"]);
  });
});

/* ------------------------------------------------------------------ */
/* Agent scopes                                                        */
/* ------------------------------------------------------------------ */

describe("agent scopes", () => {
  it("reads permission from the agent frontmatter", () => {
    const harness = createHarness();
    harness.write(
      GLOBAL_AGENT_FILE(harness, "planner"),
      agentDocument(["permission:", "  bash: deny", "  mcp:", '    "gh": ask']),
      300,
    );

    const view = harness.loader.load("planner");

    expect(view.scopes.agent).toEqual({ permission: { bash: "deny", mcp: { gh: "ask" } } });
    expect(view.scopes.agent?.invalid).toBeUndefined();
    expect(view.messages).toEqual([]);
  });

  it("keeps a deny-with-reason pattern value", () => {
    const harness = createHarness();
    harness.write(
      GLOBAL_AGENT_FILE(harness, "planner"),
      agentDocument([
        "permission:",
        "  bash:",
        '    "*":',
        "      action: deny",
        "      reason: blocked by policy",
      ]),
      300,
    );

    expect(harness.loader.load("planner").scopes.agent?.permission).toEqual({
      bash: { "*": { action: "deny", reason: "blocked by policy" } },
    });
  });

  it("loosely normalizes broken agent permission entries away", () => {
    const harness = createHarness();
    harness.write(
      GLOBAL_AGENT_FILE(harness, "planner"),
      agentDocument([
        "permission:",
        "  bash: maybe",
        "  mcp:",
        '    "gh": perhaps',
        "  path_read:",
        '    "/tmp/**": allow',
        "  path_write:",
        "    - allow",
        "  skill: ask",
      ]),
      300,
    );

    expect(harness.loader.load("planner").scopes.agent?.permission).toEqual({
      path_read: { "/tmp/**": "allow" },
      skill: "ask",
    });
  });

  it("returns an empty scope when the permission value is not a map", () => {
    const harness = createHarness();
    harness.write(GLOBAL_AGENT_FILE(harness, "planner"), agentDocument(["permission: allow"]), 300);

    const view = harness.loader.load("planner");

    expect(view.scopes.agent).toEqual({});
    expect(view.messages).toEqual([]);
  });

  it("returns an empty scope when the frontmatter has no permission entry", () => {
    const harness = createHarness();
    harness.write(GLOBAL_AGENT_FILE(harness, "planner"), agentDocument(["tools: bash"]), 300);

    expect(harness.loader.load("planner").scopes.agent).toEqual({});
  });

  it("returns an empty scope for an agent document without frontmatter", () => {
    const harness = createHarness();
    harness.write(GLOBAL_AGENT_FILE(harness, "planner"), "Only body text, no frontmatter.", 300);

    expect(harness.loader.load("planner").scopes.agent).toEqual({});
  });

  it("marks an unreadable agent file invalid with one fail-closed message", () => {
    const unreadable = new Set<string>();
    const harness = createHarness({ unreadable: (path) => unreadable.has(path) });
    const agentFile = GLOBAL_AGENT_FILE(harness, "planner");
    harness.write(agentFile, agentDocument(["permission:", "  bash: allow"]), 300);
    unreadable.add(agentFile);

    const view = harness.loader.load("planner");

    expect(view.scopes.agent).toEqual({ invalid: true });
    expect(view.messages).toHaveLength(1);
    expect(view.messages[0]).toMatchObject({ code: "invalid-scope", file: agentFile, path: "" });
    expect(view.messages[0]?.message).toMatch(/confirmation/i);
  });

  it("reads project-agent permission from the project agent directory", () => {
    const harness = createHarness();
    harness.write(GLOBAL_AGENT_FILE(harness, "planner"), agentDocument(["permission:", "  bash: ask"]), 300);
    harness.write(
      PROJECT_AGENT_FILE(harness, "planner"),
      agentDocument(["permission:", "  mcp:", '    "gh": deny']),
      400,
    );

    const view = harness.loader.load("planner");

    expect(view.scopes.agent?.permission).toEqual({ bash: "ask" });
    expect(view.scopes["project-agent"]?.permission).toEqual({ mcp: { gh: "deny" } });
  });

  it("marks an unreadable project-agent file invalid", () => {
    const unreadable = new Set<string>();
    const harness = createHarness({ unreadable: (path) => unreadable.has(path) });
    const projectAgentFile = PROJECT_AGENT_FILE(harness, "planner");
    harness.write(projectAgentFile, agentDocument(["permission:", "  bash: allow"]), 400);
    unreadable.add(projectAgentFile);

    const view = harness.loader.load("planner");

    expect(view.scopes["project-agent"]).toEqual({ invalid: true });
    expect(view.messages.map((message) => message.file)).toEqual([projectAgentFile]);
  });

  it("ignores project-agent permissions for different agent names", () => {
    const harness = createHarness();
    harness.write(
      PROJECT_AGENT_FILE(harness, "other"),
      agentDocument(["permission:", "  bash: deny"]),
      400,
    );

    expect(harness.loader.load("planner").scopes["project-agent"]).toEqual({});
  });
});

/* ------------------------------------------------------------------ */
/* Cache stamps and mtime cache                                        */
/* ------------------------------------------------------------------ */

describe("cache stamp", () => {
  it("combines the six candidate mtimes in the frozen format", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json", projectMcpConfigFile: "mcp/project.json" });
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }), 101);
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "ask" }), 102);
    harness.write(GLOBAL_AGENT_FILE(harness, "planner"), agentDocument(["permission:", "  bash: ask"]), 103);
    harness.write(PROJECT_AGENT_FILE(harness, "planner"), agentDocument(["permission:", "  bash: ask"]), 104);
    harness.write(harness.mcpConfigFile!, mcpContent(["global-server"]), 105);
    harness.write(harness.projectMcpConfigFile!, mcpContent(["project-server"]), 106);

    const view = harness.loader.load("planner");

    expect(view.stamp).toBe("g=101|p=102|a=103|pa=104|m=105|pm=106");
    expect(harness.loader.load("planner").stamp).toBe(view.stamp);
  });

  it("changes when any candidate mtime changes", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }), 101);
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "allow" }), 102);
    harness.write(harness.mcpConfigFile!, mcpContent(["server"]), 105);
    harness.write(
      GLOBAL_AGENT_FILE(harness, "planner"),
      agentDocument(["permission:", "  bash: allow"]),
      103,
    );

    const before = harness.loader.load("planner").stamp;
    harness.setMtime(harness.paths.globalConfigFile, 900);
    const after = harness.loader.load("planner").stamp;

    expect(before).toBe("g=101|p=102|a=103|pa=missing|m=105|pm=-");
    expect(after).toBe("g=900|p=102|a=103|pa=missing|m=105|pm=-");
    expect(after).not.toBe(before);
  });

  it("marks undefined mtimes as missing and unavailable scopes as a dash", () => {
    const harness = createHarness({ cwd: "", projectTrusted: false, globalAgentsDir: "" });

    expect(harness.loader.load("planner").stamp).toBe("g=missing|p=-|a=-|pa=-|m=-|pm=-");
  });

  it("records a dash for MCP files bypassed by the explicit override", () => {
    const harness = createHarness({
      mcpConfigFile: "mcp/global.json",
      projectMcpConfigFile: "mcp/project.json",
      mcpServerNames: ["explicit"],
    });

    const view = harness.loader.load();

    expect(view.stamp).toContain("|m=-|pm=-");
    expect(harness.mtimeCalls).not.toContain(harness.mcpConfigFile);
    expect(harness.mtimeCalls).not.toContain(harness.projectMcpConfigFile);
  });
});

describe("mtime cache", () => {
  it("reuses a parsed file across loads without reading it again", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }), 100);

    harness.loader.load();
    harness.loader.load();
    harness.loader.load();

    expect(harness.readCount(harness.paths.globalConfigFile)).toBe(1);
    expect(harness.mtimeCalls.filter((path) => path === harness.paths.globalConfigFile)).toHaveLength(3);
  });

  it("re-reads a file after its mtime changes and reflects the new contents", () => {
    const harness = createHarness();
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }), 100);
    expect(harness.loader.load().scopes.global?.permission).toEqual({ bash: "allow" });

    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "deny" }), 200);

    expect(harness.loader.load().scopes.global?.permission).toEqual({ bash: "deny" });
    expect(harness.readCount(harness.paths.globalConfigFile)).toBe(2);
  });

  it("caches each candidate file independently", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }), 100);
    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "ask" }), 200);
    const agentFile = GLOBAL_AGENT_FILE(harness, "planner");
    harness.write(agentFile, agentDocument(["permission:", "  bash: ask"]), 300);
    const projectAgentFile = PROJECT_AGENT_FILE(harness, "planner");
    harness.write(projectAgentFile, agentDocument(["permission:", "  bash: ask"]), 400);
    harness.write(harness.mcpConfigFile!, mcpContent(["server"]), 500);

    harness.loader.load("planner");
    harness.loader.load("planner");

    expect(harness.readCount(harness.paths.globalConfigFile)).toBe(1);
    expect(harness.readCount(harness.paths.projectConfigFile)).toBe(1);
    expect(harness.readCount(agentFile)).toBe(1);
    expect(harness.readCount(projectAgentFile)).toBe(1);
    expect(harness.readCount(harness.mcpConfigFile!)).toBe(1);
  });

  it("never reads a file whose mtime is unknown", () => {
    const harness = createHarness();
    harness.writeWithoutMtime(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }));

    const view = harness.loader.load();

    expect(view.scopes.global).toEqual({});
    expect(view.stamp).toContain("g=missing");
    expect(harness.reads).not.toContain(harness.paths.globalConfigFile);
  });

  it("recovers after a project file is fixed at a new mtime", () => {
    const harness = createHarness();
    harness.write(harness.paths.projectConfigFile, "{ broken", 200);
    expect(harness.loader.load().scopes.project).toEqual({ invalid: true });

    harness.write(harness.paths.projectConfigFile, approvalConfig({ bash: "allow" }), 300);

    const view = harness.loader.load();

    expect(view.scopes.project).toEqual({ permission: { bash: "allow" } });
    expect(view.messages).toEqual([]);
  });

  it("invalidates the MCP cache when the MCP file changes", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, mcpContent(["first"]), 500);
    expect(harness.loader.load().mcpServerNames).toEqual(["first"]);

    harness.write(harness.mcpConfigFile!, mcpContent(["second"]), 600);

    expect(harness.loader.load().mcpServerNames).toEqual(["second"]);
    expect(harness.readCount(harness.mcpConfigFile!)).toBe(2);
  });
});

/* ------------------------------------------------------------------ */
/* MCP server names                                                    */
/* ------------------------------------------------------------------ */

describe("MCP server names", () => {
  it("trims, drops empty names, dedupes and sorts by length then code point", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(
      harness.mcpConfigFile!,
      JSON.stringify({ mcpServers: { b: {}, " aa ": {}, a: {}, "": {}, aa: {}, A: {} } }),
      500,
    );

    expect(harness.loader.load().mcpServerNames).toEqual(["aa", "A", "a", "b"]);
  });

  it("merges the global then the project file and dedupes across files", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json", projectMcpConfigFile: "mcp/project.json" });
    harness.write(
      harness.mcpConfigFile!,
      JSON.stringify({ mcpServers: { gh: {}, shared: {}, zzz: {} } }),
      500,
    );
    harness.write(
      harness.projectMcpConfigFile!,
      JSON.stringify({ mcpServers: { shared: {}, " bb ": {} } }),
      600,
    );

    expect(harness.loader.load().mcpServerNames).toEqual(["shared", "zzz", "bb", "gh"]);
  });

  it("accepts the legacy mcp-servers key and reports one migration message", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, mcpContent(["old-server"], "mcp-servers"), 500);

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual(["old-server"]);
    expect(view.messages).toHaveLength(1);
    expect(view.messages[0]).toMatchObject({
      code: "mcp-key-migration",
      file: harness.mcpConfigFile,
      path: "mcp-servers",
    });
    expect(view.messages[0]?.message).toMatch(/mcpServers/);
  });

  it("prefers mcpServers when both keys are present", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(
      harness.mcpConfigFile!,
      JSON.stringify({ mcpServers: { modern: {} }, "mcp-servers": { legacy: {} } }),
      500,
    );

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual(["modern"]);
    expect(view.messages).toEqual([]);
  });

  it("ignores the project MCP file when the project is untrusted", () => {
    const harness = createHarness({
      projectTrusted: false,
      mcpConfigFile: "mcp/global.json",
      projectMcpConfigFile: "mcp/project.json",
    });
    harness.write(harness.mcpConfigFile!, mcpContent(["global-server"]), 500);
    harness.write(harness.projectMcpConfigFile!, mcpContent(["project-server"]), 600);

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual(["global-server"]);
    expect(view.stamp).toContain("|pm=-");
    expect(harness.mtimeCalls).not.toContain(harness.projectMcpConfigFile);
    expect(harness.reads).not.toContain(harness.projectMcpConfigFile);
  });

  it("does not contribute from a missing MCP file and reports no message", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual([]);
    expect(view.messages).toEqual([]);
  });

  it("does not contribute from an unparsable MCP file and reports no message", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, "{ not json", 500);

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual([]);
    expect(view.messages).toEqual([]);
  });

  it("does not contribute when the server declaration is not a plain object", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, JSON.stringify({ mcpServers: ["gh"] }), 500);

    expect(harness.loader.load().mcpServerNames).toEqual([]);
  });

  it("does not contribute when the document root is not an object", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, "[]", 500);

    expect(harness.loader.load().mcpServerNames).toEqual([]);
  });

  it("uses the explicit override without sorting, trimming and keeping first order", () => {
    const harness = createHarness({
      mcpConfigFile: "mcp/global.json",
      mcpServerNames: [" bb ", "aa", "", "bb", "aa", "z"],
    });
    harness.write(harness.mcpConfigFile!, mcpContent(["ignored"]), 500);

    const view = harness.loader.load();

    expect(view.mcpServerNames).toEqual(["bb", "aa", "z"]);
    expect(harness.reads).not.toContain(harness.mcpConfigFile);
    expect(view.messages).toEqual([]);
  });

  it("reports the migration message again on a later load but reads the file once", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.mcpConfigFile!, mcpContent(["old"], "mcp-servers"), 500);

    const first = harness.loader.load();
    const second = harness.loader.load();

    expect(first.messages).toHaveLength(1);
    expect(second.messages).toHaveLength(1);
    expect(harness.readCount(harness.mcpConfigFile!)).toBe(1);
  });

  it("orders fail-closed messages before MCP migration messages", () => {
    const unreadable = new Set<string>();
    const harness = createHarness({
      unreadable: (path) => unreadable.has(path),
      mcpConfigFile: "mcp/global.json",
      projectMcpConfigFile: "mcp/project.json",
    });
    harness.write(harness.paths.projectConfigFile, "{ broken", 200);
    const agentFile = GLOBAL_AGENT_FILE(harness, "planner");
    harness.write(agentFile, agentDocument(["permission:", "  bash: allow"]), 300);
    unreadable.add(agentFile);
    harness.write(harness.mcpConfigFile!, mcpContent(["g"], "mcp-servers"), 500);
    harness.write(harness.projectMcpConfigFile!, mcpContent(["p"], "mcp-servers"), 600);

    const view = harness.loader.load("planner");

    expect(view.messages.map((message) => message.code)).toEqual([
      "invalid-scope",
      "invalid-scope",
      "mcp-key-migration",
      "mcp-key-migration",
    ]);
    expect(view.messages.map((message) => message.file)).toEqual([
      harness.paths.projectConfigFile,
      agentFile,
      harness.mcpConfigFile,
      harness.projectMcpConfigFile,
    ]);
  });
});

/* ------------------------------------------------------------------ */
/* Snapshot shape                                                      */
/* ------------------------------------------------------------------ */

describe("snapshot shape", () => {
  it("freezes the view and every returned collection", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json" });
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "deny" }), 100);
    harness.write(harness.paths.projectConfigFile, "{ broken", 200);
    harness.write(harness.mcpConfigFile!, mcpContent(["gh"], "mcp-servers"), 500);

    const view = harness.loader.load();

    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.isFrozen(view.scopes)).toBe(true);
    expect(Object.isFrozen(view.scopes.global)).toBe(true);
    expect(Object.isFrozen(view.scopes.global?.permission)).toBe(true);
    expect(Object.isFrozen(view.mcpServerNames)).toBe(true);
    expect(Object.isFrozen(view.messages)).toBe(true);
    expect(Object.isFrozen(view.messages[0])).toBe(true);
    expect(Object.isFrozen(view.paths)).toBe(true);
  });

  it("exposes every resolved path when all scopes are available", () => {
    const harness = createHarness({ mcpConfigFile: "mcp/global.json", projectMcpConfigFile: "mcp/project.json" });

    const view = harness.loader.load("planner");

    expect(view.paths).toEqual({
      globalConfigFile: harness.paths.globalConfigFile,
      projectConfigFile: harness.paths.projectConfigFile,
      agentFile: GLOBAL_AGENT_FILE(harness, "planner"),
      projectAgentFile: PROJECT_AGENT_FILE(harness, "planner"),
      mcpGlobalFile: harness.mcpConfigFile,
      mcpProjectFile: harness.projectMcpConfigFile,
    });
    expect(Object.isFrozen(view.paths)).toBe(true);
  });

  it("omits path entries for unavailable scopes", () => {
    const harness = createHarness({ cwd: "", projectTrusted: false, globalAgentsDir: "" });

    const paths: PolicyScopeFiles = harness.loader.load("planner").paths;

    expect(paths).toEqual({ globalConfigFile: harness.paths.globalConfigFile });
  });

  it("is structurally assignable to the policy manager loader view", () => {
    const harness = createHarness();
    const own: PolicyLoaderView = harness.loader.load("planner");
    const managerView: ManagerPolicyLoaderView = own;

    expect(typeof managerView.stamp).toBe("string");
    expect(Array.isArray(managerView.mcpServerNames)).toBe(true);
  });

  it("defaults to the node file reader and stat implementation", () => {
    const harness = createHarness({ useDefaultIo: true });
    harness.write(harness.paths.globalConfigFile, approvalConfig({ bash: "allow" }));

    const view = harness.loader.load();

    expect(view.scopes.global?.permission).toEqual({ bash: "allow" });
    expect(view.stamp).toMatch(/^g=\d+(\.\d+)?\|p=missing\|a=-\|pa=-\|m=-\|pm=-$/);
  });
});
