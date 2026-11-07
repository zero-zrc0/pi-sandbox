import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  configMessageKey,
  createConfigFileReader,
  createConfigFileStat,
  extractRuntimeFields,
  foldCommandEffects,
  formatConfigMessage,
  loadConfigScope,
  loadUnifiedConfig,
  mergeRuntimeConfigs,
  messagesFromIssues,
  normalizeFlatPermissionValue,
  stripJsonComments,
  type ConfigFileContent,
  type ConfigFileReader,
  type ConfigMessage,
} from "#config/config-loader";
import { parseRuntimeConfig } from "#config/schema";
import { resolveConfigPaths, type ConfigPaths } from "#config/config-paths";
import type { ConfigIssue } from "#config/config-schema";
import type { ApprovalChainConfig, RuntimeConfig } from "#config/schema";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "pi-config-loader-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory !== undefined) rmSync(directory, { recursive: true, force: true });
  }
});

function readerOf(files: Readonly<Record<string, ConfigFileContent>>): ConfigFileReader {
  return (path) => files[path] ?? { state: "missing" };
}

function textReader(files: Readonly<Record<string, string>>): ConfigFileReader {
  return (path) => {
    const text = files[path];
    return text === undefined ? { state: "missing" } : { state: "text", text };
  };
}

function message(overrides: Partial<ConfigMessage> = {}): ConfigMessage {
  return { code: "invalid", path: "", message: "broken", ...overrides };
}

/* ------------------------------------------------------------------ */
/* JSONC stripping                                                     */
/* ------------------------------------------------------------------ */

describe("stripJsonComments", () => {
  it("keeps documents without comments unchanged", () => {
    expect(stripJsonComments('{"a":1}')).toBe('{"a":1}');
    expect(stripJsonComments("")).toBe("");
  });

  it("removes a line comment but keeps the newline", () => {
    expect(stripJsonComments('// leading\n{"a":1}')).toBe('\n{"a":1}');
    expect(stripJsonComments('{"a":1} // trailing\ntrue')).toBe('{"a":1} \ntrue');
  });

  it("removes a line comment at end of input without a newline", () => {
    expect(stripJsonComments('{"a":1} // end')).toBe('{"a":1} ');
  });

  it("keeps a lone slash that does not start a comment", () => {
    expect(stripJsonComments('{"path":"/usr/bin"} /')).toBe('{"path":"/usr/bin"} /');
  });

  it("removes a block comment, including its markers and content", () => {
    expect(stripJsonComments('/* a "quoted" // nested\n */{"a":1}')).toBe('{"a":1}');
  });

  it("removes an unclosed block comment to the end of the input", () => {
    expect(stripJsonComments('{"a":1} /* never closed')).toBe('{"a":1} ');
    expect(stripJsonComments("/*")).toBe("");
  });

  it("removes adjacent comments", () => {
    expect(stripJsonComments('{/*x*/"a"/*y*/:/*z*/1}')).toBe('{"a":1}');
  });

  it("preserves comment markers inside double-quoted strings", () => {
    expect(stripJsonComments('{"url":"https://example.com/a/*b*/"}')).toBe(
      '{"url":"https://example.com/a/*b*/"}',
    );
    expect(stripJsonComments('{"text":"// not a comment"}')).toBe('{"text":"// not a comment"}');
  });

  it("preserves comment markers inside single-quoted strings", () => {
    expect(stripJsonComments("{'text':'// keep', 'x':'/* keep */'} // drop")).toBe(
      "{'text':'// keep', 'x':'/* keep */'} ",
    );
  });

  it("keeps an escaped quote inside a string from ending the string", () => {
    expect(stripJsonComments('{"s":"a\\"b"} // drop')).toBe('{"s":"a\\"b"} ');
    expect(stripJsonComments('{"s":"a\\"//b"} // drop')).toBe('{"s":"a\\"//b"} ');
  });

  it("keeps an escaped backslash from escaping the closing quote", () => {
    expect(stripJsonComments('{"s":"a\\\\"} // drop')).toBe('{"s":"a\\\\"} ');
  });

  it("keeps an unclosed string intact so the JSON parse can fail later", () => {
    expect(stripJsonComments('{"a":"// not a comment')).toBe('{"a":"// not a comment');
  });

  it("keeps carriage returns that end a line comment", () => {
    expect(stripJsonComments("// c\r\n{}")).toBe("\r\n{}");
  });
});

/* ------------------------------------------------------------------ */
/* File access ports                                                   */
/* ------------------------------------------------------------------ */

describe("createConfigFileReader", () => {
  it("reports a missing file", () => {
    const directory = temporaryDirectory();
    expect(createConfigFileReader()(join(directory, "absent.json"))).toEqual({ state: "missing" });
  });

  it("reads an existing file as text", () => {
    const directory = temporaryDirectory();
    const file = join(directory, "config.json");
    writeFileSync(file, '{"a":1}', "utf8");
    expect(createConfigFileReader()(file)).toEqual({ state: "text", text: '{"a":1}' });
  });

  it("reports a directory that cannot be read as text", () => {
    const directory = temporaryDirectory();
    const nested = join(directory, "nested");
    mkdirSync(nested);
    const content = createConfigFileReader()(nested);
    expect(content.state).toBe("unreadable");
  });
});

describe("createConfigFileStat", () => {
  it("returns undefined for a missing file", () => {
    const directory = temporaryDirectory();
    expect(createConfigFileStat()(join(directory, "absent.json"))).toBeUndefined();
  });

  it("returns a positive mtime for an existing file and follows changes", () => {
    const directory = temporaryDirectory();
    const file = join(directory, "config.json");
    writeFileSync(file, "{}", "utf8");
    const stat = createConfigFileStat();
    const first = stat(file);
    expect(typeof first).toBe("number");
    expect(first!).toBeGreaterThan(0);
    writeFileSync(file, '{"a":1}', "utf8");
    expect(stat(file)).toEqual(expect.any(Number));
  });
});

/* ------------------------------------------------------------------ */
/* Display messages                                                    */
/* ------------------------------------------------------------------ */

describe("ConfigMessage helpers", () => {
  it("builds a stable key from every field", () => {
    const base = message({ code: "invalid", file: "/a.json", path: "mode", message: "bad" });
    expect(configMessageKey(base)).toBe(configMessageKey({ ...base }));
    expect(configMessageKey(base)).not.toBe(configMessageKey({ ...base, code: "unknown-key" }));
    expect(configMessageKey(base)).not.toBe(configMessageKey({ ...base, file: "/b.json" }));
    expect(configMessageKey(base)).not.toBe(configMessageKey({ ...base, path: "approver" }));
    expect(configMessageKey(base)).not.toBe(configMessageKey({ ...base, message: "other" }));
  });

  it("renders the file, field path and sentence", () => {
    expect(formatConfigMessage({
      code: "invalid",
      file: "/a.json",
      path: "mode",
      message: "expected one of the permissions modes",
    })).toBe("/a.json: mode: expected one of the permissions modes");
  });

  it("renders a whole-document problem without a field path", () => {
    expect(formatConfigMessage({ code: "parse-failed", file: "/a.json", path: "", message: "bad JSON" }))
      .toBe("/a.json: bad JSON");
  });

  it("renders a problem without a file", () => {
    expect(formatConfigMessage({ code: "invalid-scope", path: "permission", message: "ignored" }))
      .toBe("permission: ignored");
    expect(formatConfigMessage({ code: "invalid-scope", path: "", message: "ignored" }))
      .toBe("ignored");
  });

  it("maps schema issues to messages keeping their paths and codes", () => {
    const issues: readonly ConfigIssue[] = [
      { path: "mode", code: "invalid", message: "bad mode" },
      { path: "extra", code: "unknown-key", message: "unexpected field: extra" },
    ];
    expect(messagesFromIssues("/a.json", issues)).toEqual([
      { code: "invalid", file: "/a.json", path: "mode", message: "bad mode" },
      { code: "unknown-key", file: "/a.json", path: "extra", message: "unexpected field: extra" },
    ]);
  });
});

/* ------------------------------------------------------------------ */
/* Strict single-file loading                                          */
/* ------------------------------------------------------------------ */

describe("loadConfigScope", () => {
  const path = "/config.json";

  it("returns the empty scope for a missing file", () => {
    const result = loadConfigScope<RuntimeConfig>({
      path,
      readFile: readerOf({}),
      parse: parseRuntimeConfig,
      empty: () => ({}),
    });
    expect(result).toEqual({ config: {}, exists: false, invalid: false, messages: [] });
  });

  it("parses comments, reports existence and keeps the raw value", () => {
    const result = loadConfigScope<RuntimeConfig>({
      path,
      readFile: textReader({ [path]: '// prefs\n{"debugLog":true}' }),
      parse: parseRuntimeConfig,
      empty: () => ({}),
    });
    expect(result.exists).toBe(true);
    expect(result.invalid).toBe(false);
    expect(result.config).toEqual({ debugLog: true });
    expect(result.raw).toEqual({ debugLog: true });
    expect(result.messages).toEqual([]);
  });

  it("reports unreadable files without a scope", () => {
    const result = loadConfigScope<RuntimeConfig>({
      path,
      readFile: readerOf({ [path]: { state: "unreadable", reason: "permission denied" } }),
      parse: parseRuntimeConfig,
      empty: () => ({}),
    });
    expect(result.exists).toBe(true);
    expect(result.invalid).toBe(true);
    expect(result.config).toEqual({});
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0]!.code).toBe("read-failed");
    expect(result.messages[0]!.file).toBe(path);
  });

  it("reports malformed JSON as one parse failure", () => {
    const result = loadConfigScope<RuntimeConfig>({
      path,
      readFile: textReader({ [path]: '{"debugLog":true,}' }),
      parse: parseRuntimeConfig,
      empty: () => ({}),
    });
    expect(result.exists).toBe(true);
    expect(result.invalid).toBe(true);
    expect(result.config).toEqual({});
    expect(result.raw).toBeUndefined();
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0]!.code).toBe("parse-failed");
    expect(result.messages[0]!.file).toBe(path);
    expect(result.messages[0]!.message.length).toBeGreaterThan(0);
  });

  it("rejects the whole scope when any field fails, reporting field paths", () => {
    const result = loadConfigScope<RuntimeConfig>({
      path,
      readFile: textReader({ [path]: '{"debugLog":true,"promptTimeoutMs":"soon","bogus":1}' }),
      parse: parseRuntimeConfig,
      empty: () => ({}),
    });
    expect(result.invalid).toBe(true);
    expect(result.config).toEqual({});
    const codesByPath = Object.fromEntries(result.messages.map((entry) => [entry.path, entry.code]));
    expect(codesByPath).toEqual({ promptTimeoutMs: "invalid", bogus: "unknown-key" });
  });
});

/* ------------------------------------------------------------------ */
/* Loose permission normalization (agent frontmatter)                  */
/* ------------------------------------------------------------------ */

describe("normalizeFlatPermissionValue", () => {
  it("rejects values that are not plain objects", () => {
    for (const value of [undefined, null, 42, "allow", true, ["allow"]]) {
      expect(normalizeFlatPermissionValue(value)).toBeUndefined();
    }
  });

  it("returns undefined for an empty map or only invalid surfaces", () => {
    expect(normalizeFlatPermissionValue({})).toBeUndefined();
    expect(normalizeFlatPermissionValue({ bash: "execute" })).toBeUndefined();
    expect(normalizeFlatPermissionValue({ bash: [] })).toBeUndefined();
    expect(normalizeFlatPermissionValue({ bash: { ls: "execute" } })).toBeUndefined();
  });

  it("keeps catch-all action strings and deny pattern objects", () => {
    expect(normalizeFlatPermissionValue({ bash: "allow" })).toEqual({ bash: "allow" });
    expect(normalizeFlatPermissionValue({ bash: { rm: { action: "deny", reason: "no" } } })).toEqual({
      bash: { rm: { action: "deny", reason: "no" } },
    });
  });

  it("keeps only valid pattern entries and drops empty surfaces", () => {
    expect(normalizeFlatPermissionValue({
      path: { ls: "allow", cat: "execute", rm: { action: "deny", reason: "never" } },
      mcp: { tool: 5 },
    })).toEqual({
      path: {
        ls: "allow",
        rm: { action: "deny", reason: "never" },
      },
    });
  });

  it("drops deny objects with extra keys or an over-long reason", () => {
    expect(normalizeFlatPermissionValue({ bash: { rm: { action: "deny", reason: "x", extra: true } } }))
      .toBeUndefined();
    expect(normalizeFlatPermissionValue({ bash: { rm: { action: "deny", reason: "x".repeat(501) } } }))
      .toBeUndefined();
  });

  it("drops empty surface names and empty pattern names", () => {
    expect(normalizeFlatPermissionValue({ "": "allow", bash: { "": "allow", ls: "ask" } })).toEqual({
      bash: { ls: "ask" },
    });
  });

  it("keeps unknown surface names, because agent permissions are open", () => {
    expect(normalizeFlatPermissionValue({ path_reqd: "deny" })).toEqual({ path_reqd: "deny" });
  });
});

/* ------------------------------------------------------------------ */
/* Unified merging                                                     */
/* ------------------------------------------------------------------ */

describe("mergeRuntimeConfigs", () => {
  it("returns an empty object for two empty layers", () => {
    expect(mergeRuntimeConfigs({}, {})).toEqual({});
  });

  it("replaces scalars, arrays and notifications rather than merging them", () => {
    const base: RuntimeConfig = {
      debugLog: true,
      promptTimeoutMs: 100,
      piInfrastructureReadPaths: ["/a", "/b"],
      promptNotifications: ["bell"],
    };
    const override: RuntimeConfig = {
      debugLog: false,
      promptTimeoutMs: 200,
      piInfrastructureReadPaths: ["/c"],
      promptNotifications: ["osc9", "osc777"],
    };
    expect(mergeRuntimeConfigs(base, override)).toEqual(override);
  });

  it("treats a defined falsy or empty override as a replacement", () => {
    expect(mergeRuntimeConfigs({ debugLog: true }, { debugLog: false })).toEqual({ debugLog: false });
    expect(mergeRuntimeConfigs({ promptMaxRows: 3 }, { promptMaxRows: 0 })).toEqual({ promptMaxRows: 0 });
    expect(mergeRuntimeConfigs({ piInfrastructureReadPaths: ["/a"] }, { piInfrastructureReadPaths: [] }))
      .toEqual({ piInfrastructureReadPaths: [] });
  });

  it("does not introduce keys the override left undefined", () => {
    expect(mergeRuntimeConfigs({ debugLog: true }, {})).toEqual({ debugLog: true });
    expect(mergeRuntimeConfigs({}, { debugLog: true })).toEqual({ debugLog: true });
  });

  it("replaces the whole dialog key map", () => {
    expect(mergeRuntimeConfigs(
      { permissionDialogKeys: { approve: "a", deny: "n" } },
      { permissionDialogKeys: { deny: "q" } },
    )).toEqual({ permissionDialogKeys: { deny: "q" } });
  });

  it("merges shell tools by tool name", () => {
    expect(mergeRuntimeConfigs(
      { shellTools: { shell: { commandArgument: "command" }, other: { commandArgument: "cmd" } } },
      { shellTools: { shell: { commandArgument: "input", workdirArgument: "cwd" } } },
    )).toEqual({
      shellTools: {
        shell: { commandArgument: "input", workdirArgument: "cwd" },
        other: { commandArgument: "cmd" },
      },
    });
  });

  it("merges permission surfaces pattern by pattern when both are maps", () => {
    expect(mergeRuntimeConfigs(
      { permission: { bash: { ls: "allow" }, mcp: "ask" } },
      { permission: { bash: { rm: "deny" } } },
    )).toEqual({ permission: { bash: { ls: "allow", rm: "deny" }, mcp: "ask" } });
  });

  it("replaces a whole surface when either side is not a pattern map", () => {
    expect(mergeRuntimeConfigs(
      { permission: { bash: { ls: "allow" } } },
      { permission: { bash: "deny" } },
    )).toEqual({ permission: { bash: "deny" } });
    expect(mergeRuntimeConfigs(
      { permission: { bash: "deny" } },
      { permission: { bash: { ls: "ask" } } },
    )).toEqual({ permission: { bash: { ls: "ask" } } });
  });

  it("appends new permission surfaces after existing ones", () => {
    const merged = mergeRuntimeConfigs(
      { permission: { bash: { ls: "allow" }, mcp: "deny" } },
      { permission: { skill: "ask", bash: { rm: "ask" } } },
    );
    expect(Object.keys(merged.permission!)).toEqual(["bash", "mcp", "skill"]);
    expect(Object.keys((merged.permission as Record<string, Record<string, unknown>>).bash!))
      .toEqual(["ls", "rm"]);
  });

  it("excludes command effects and the schema marker from the merged output", () => {
    const base: RuntimeConfig = {
      $schema: "./schema.json",
      commandEffects: { grep: { effects: "read" } },
      debugLog: true,
    };
    const override: RuntimeConfig = { commandEffects: { sed: { effects: "write" } } };
    expect(mergeRuntimeConfigs(base, override)).toEqual({ debugLog: true });
  });

  it("does not mutate its inputs", () => {
    const base: RuntimeConfig = { permission: { bash: { ls: "allow" } }, debugLog: true };
    const override: RuntimeConfig = { permission: { bash: { rm: "deny" } } };
    const merged = mergeRuntimeConfigs(base, override);
    expect(base).toEqual({ permission: { bash: { ls: "allow" } }, debugLog: true });
    expect(override).toEqual({ permission: { bash: { rm: "deny" } } });
    expect(merged).not.toBe(base);
    expect(merged.permission).not.toBe(base.permission);
  });
});

describe("extractRuntimeFields", () => {
  it("keeps only the runtime fields of a formal configuration", () => {
    const config: ApprovalChainConfig = {
      mode: "read-only",
      debugLog: true,
      permission: { bash: "deny" },
      permissionDialogKeys: { approve: "a" },
      toolBindings: [],
      approver: { timeoutMs: 15000, decisionContextAcquisition: "llm" },
      learning: { enabled: false },
      execution: {},
      experimental: { mcpSandbox: false },
      approval: { nodes: {} },
      commandEffects: { grep: { effects: "read" } },
    };
    expect(extractRuntimeFields(config)).toEqual({
      debugLog: true,
      permission: { bash: "deny" },
      permissionDialogKeys: { approve: "a" },
    });
  });

  it("returns an empty object when no runtime field is set", () => {
    expect(extractRuntimeFields({
      mode: "default",
      toolBindings: [],
      approver: { timeoutMs: 15000, decisionContextAcquisition: "llm" },
      learning: { enabled: false },
      execution: {},
      experimental: { mcpSandbox: false },
      approval: { nodes: {} },
    })).toEqual({});
  });
});

/* ------------------------------------------------------------------ */
/* Command effect folding                                              */
/* ------------------------------------------------------------------ */

describe("foldCommandEffects", () => {
  it("returns a frozen empty map for no layers", () => {
    const folded = foldCommandEffects([]);
    expect(folded).toEqual({});
    expect(Object.isFrozen(folded)).toBe(true);
  });

  it("folds low to high, replacing same-name declarations in place", () => {
    const folded = foldCommandEffects([
      {
        scope: "global",
        declarations: {
          grep: { effects: "read" },
          sudo: { effects: "write" },
        },
      },
      {
        scope: "project",
        declarations: {
          sudo: { effects: "read" },
          awk: { effects: ["read"] },
        },
      },
    ]);
    expect(Object.keys(folded)).toEqual(["grep", "sudo", "awk"]);
    expect(folded.grep).toEqual({ declaration: { effects: "read" }, scope: "global" });
    expect(folded.sudo).toEqual({ declaration: { effects: "read" }, scope: "project" });
    expect(folded.awk).toEqual({ declaration: { effects: ["read"] }, scope: "project" });
  });
});

/* ------------------------------------------------------------------ */
/* Unified multi-source loading                                        */
/* ------------------------------------------------------------------ */

interface Fixture {
  readonly root: string;
  readonly paths: ConfigPaths;
}

function fixture(): Fixture {
  const root = temporaryDirectory();
  const paths = resolveConfigPaths({
    agentDir: join(root, "agent"),
    cwd: join(root, "cwd"),
    extensionRoot: join(root, "extension"),
  });
  return { root, paths };
}

function writeConfig(path: string, content: unknown, withComments = false): void {
  mkdirSync(join(path, ".."), { recursive: true });
  const text = typeof content === "string" ? content : JSON.stringify(content, null, 2);
  writeFileSync(path, withComments ? `// edited by hand\n${text}\n` : text, "utf8");
}

function sourceLabels(result: ReturnType<typeof loadUnifiedConfig>): readonly string[] {
  return result.layers.map((layer) => layer.source);
}

describe("loadUnifiedConfig", () => {
  it("returns an empty merged config when no file exists", () => {
    const { paths } = fixture();
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: true });
    expect(result.config).toEqual({});
    expect(result.commandEffects).toEqual({});
    expect(result.messages).toEqual([]);
    expect(sourceLabels(result)).toEqual([
      "legacy-global-policy",
      "legacy-extension-config",
      "global",
      "legacy-project-policy",
      "project",
    ]);
    expect(result.layers.every((layer) => layer.exists === false)).toBe(true);
  });

  it("omits project layers when the project is not trusted", () => {
    const { paths } = fixture();
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(sourceLabels(result)).toEqual([
      "legacy-global-policy",
      "legacy-extension-config",
      "global",
    ]);
  });

  it("omits project layers when cwd is empty", () => {
    const { paths } = fixture();
    const result = loadUnifiedConfig({ paths, cwd: "", projectTrusted: true });
    expect(sourceLabels(result)).not.toContain("project");
    expect(sourceLabels(result)).not.toContain("legacy-project-policy");
  });

  it("reads the five layers in low-to-high order and merges per the unified rules", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyGlobalPolicyFile, { permission: { bash: "deny", mcp: "ask" } });
    writeConfig(paths.legacyExtensionConfigFile, { debugLog: true, permission: { skill: "ask" } });
    writeConfig(paths.globalConfigFile, {
      permission: { bash: { ls: "allow" } },
      promptTimeoutMs: 1000,
    }, true);
    writeConfig(paths.legacyProjectPolicyFile, { permission: { mcp: "allow" } });
    writeConfig(paths.projectConfigFile, { permission: { bash: { rm: "ask" } } });

    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: true });
    expect(sourceLabels(result)).toEqual([
      "legacy-global-policy",
      "legacy-extension-config",
      "global",
      "legacy-project-policy",
      "project",
    ]);
    expect(result.layers.every((layer) => layer.exists)).toBe(true);
    expect(result.config.debugLog).toBe(true);
    expect(result.config.promptTimeoutMs).toBe(1000);
    // bash: legacy string denied in step 1, replaced by the global map in step 3,
    // then extended pattern by pattern with the project map in step 5.
    // mcp: legacy ask replaced by the project legacy allow (string replaces surface).
    expect(result.config.permission).toEqual({
      bash: { ls: "allow", rm: "ask" },
      mcp: "allow",
      skill: "ask",
    });
  });

  it("merges a formal global layer as runtime fields only", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, {
      mode: "read-only",
      permission: { bash: "deny" },
      approver: { provider: "p", model: "m" },
      toolBindings: [],
    });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config).toEqual({ permission: { bash: "deny" } });
    expect(result.layers[2]!.config).toEqual({ permission: { bash: "deny" } });
  });

  it("treats a flat legacy policy file as a permission map", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyGlobalPolicyFile, { bash: "allow", path: { "/tmp": "ask" } });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config.permission).toEqual({ bash: "allow", path: { "/tmp": "ask" } });
  });

  it("reports field paths for an invalid new global file and contributes nothing", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, { mode: "bogus", unknownKey: 1 });
    writeConfig(paths.legacyExtensionConfigFile, { debugLog: true });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config).toEqual({ debugLog: true });
    const codes = result.messages.map((entry) => `${entry.path}:${entry.code}`);
    expect(codes).toContain("mode:invalid");
    expect(codes).toContain("unknownKey:unknown-key");
    expect(result.layers[2]!.exists).toBe(true);
    expect(result.layers[2]!.config).toEqual({});
  });

  it("replaces legacy schema problems with a single migration notice", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyExtensionConfigFile, { promptTimeoutMs: "soon", bogus: 1 });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.layers[1]!.config).toEqual({});
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0]!.code).toBe("migration");
    expect(result.messages[0]!.file).toBe(paths.legacyExtensionConfigFile);
  });

  it("reports malformed legacy JSON as one migration notice", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyGlobalPolicyFile, "{not json");
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0]!.code).toBe("migration");
    expect(result.layers[0]!.config).toEqual({});
  });

  it("produces a migration notice for every legacy file that exists", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyGlobalPolicyFile, { permission: { bash: "ask" } });
    writeConfig(paths.legacyExtensionConfigFile, { debugLog: true });
    writeConfig(paths.legacyProjectPolicyFile, { permission: { mcp: "ask" } });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: true });
    const migrationFiles = result.messages
      .filter((entry) => entry.code === "migration")
      .map((entry) => entry.file);
    expect(migrationFiles).toEqual([
      paths.legacyGlobalPolicyFile,
      paths.legacyExtensionConfigFile,
      paths.legacyProjectPolicyFile,
    ]);
  });

  it("ignores a legacy classifier declaration once without reading it", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyExtensionConfigFile, {
      classifier: { provider: "p", model: "m" },
      classifierModel: { anything: true },
      debugLog: true,
    });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config).toEqual({ debugLog: true });
    const classifierNotices = result.messages.filter((entry) => entry.code === "legacy-classifier");
    expect(classifierNotices).toHaveLength(1);
    expect(classifierNotices[0]!.file).toBe(paths.legacyExtensionConfigFile);
  });

  it("skips the legacy extension config when it resolves to the new global path", () => {
    const { root } = fixture();
    const agentDir = join(root, "agent");
    const paths = resolveConfigPaths({
      agentDir,
      cwd: join(root, "cwd"),
      extensionRoot: join(agentDir, "extensions", "pi-sandbox"),
    });
    writeConfig(paths.globalConfigFile, { debugLog: true });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(sourceLabels(result)).toEqual(["legacy-global-policy", "global"]);
    expect(result.config).toEqual({ debugLog: true });
  });

  it("warns about a broad universal allow that Bash inherits", () => {
    const { paths } = fixture();
    const warningFor = (permission: unknown): readonly string[] => {
      writeConfig(paths.globalConfigFile, { permission });
      const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
      return result.messages.filter((entry) => entry.code === "broad-default").map((entry) => entry.path);
    };
    expect(warningFor({ "*": "allow" })).toEqual(["permission"]);
    expect(warningFor({ "*": { "*": "allow" } })).toEqual(["permission"]);
    expect(warningFor({ "*": "allow", bash: "ask" })).toEqual([]);
    expect(warningFor({ "*": "allow", bash: { "*": "ask" } })).toEqual([]);
    expect(warningFor({ "*": "allow", bash: { ls: "ask" } })).toEqual(["permission"]);
    expect(warningFor({ "*": "deny" })).toEqual([]);
    expect(warningFor({ "*": { "*": { action: "deny" } } })).toEqual([]);
  });

  it("warns about each deprecated preview cap", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, {
      toolInputPreviewMaxLength: 120,
      toolTextSummaryMaxLength: 80,
    });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.messages.map((entry) => [entry.code, entry.path])).toEqual([
      ["deprecated", "toolInputPreviewMaxLength"],
      ["deprecated", "toolTextSummaryMaxLength"],
    ]);
  });

  it("merges dialog key issues into display messages while keeping the merged map", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, { permissionDialogKeys: { approve: "n" } });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config.permissionDialogKeys).toEqual({ approve: "n" });
    const dialogMessages = result.messages.filter((entry) => entry.code === "dialog-key");
    expect(dialogMessages).toHaveLength(1);
    expect(dialogMessages[0]!.path).toBe("permissionDialogKeys.approve");
    expect(dialogMessages[0]!.message).toMatch(/approve/u);
  });

  it("does not warn about dialog keys that resolve cleanly", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, { permissionDialogKeys: { approve: "q" } });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.messages.filter((entry) => entry.code === "dialog-key")).toEqual([]);
  });

  it("folds command effects with a scope and reports declarations shadowed by core commands", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, {
      commandEffects: { grep: { effects: "read" }, sudo: { effects: "write" } },
    });
    writeConfig(paths.projectConfigFile, {
      commandEffects: { sudo: { effects: "read" }, awk: { effects: "read" } },
    });
    const result = loadUnifiedConfig({
      paths,
      cwd: paths.projectConfigDir,
      projectTrusted: true,
      coreCommands: ["grep"],
      wrapperCommands: ["sudo"],
    });
    expect(Object.keys(result.commandEffects)).toEqual(["grep", "sudo", "awk"]);
    expect(result.commandEffects.bash).toBeUndefined();
    expect(result.commandEffects.sudo!.scope).toBe("project");
    expect(result.commandEffects.sudo!.declaration).toEqual({ effects: "read" });
    expect(result.config.commandEffects).toBeUndefined();
    const collisions = result.messages
      .filter((entry) => entry.code === "command-effect")
      .map((entry) => entry.path);
    expect(collisions).toEqual(["commandEffects.grep", "commandEffects.sudo"]);
  });

  it("keeps command effects when only global declares them and the project is untrusted", () => {
    const { paths } = fixture();
    writeConfig(paths.globalConfigFile, { commandEffects: { grep: { effects: "read" } } });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.commandEffects.grep!.scope).toBe("global");
  });

  it("with ignoreExtensionConfigFiles reads only the legacy policies", () => {
    const { paths } = fixture();
    writeConfig(paths.legacyGlobalPolicyFile, { permission: { bash: "ask" } });
    writeConfig(paths.legacyProjectPolicyFile, { permission: { mcp: "ask" } });
    writeConfig(paths.legacyExtensionConfigFile, { debugLog: true });
    writeConfig(paths.globalConfigFile, { debugLog: true });
    writeConfig(paths.projectConfigFile, { promptTimeoutMs: 5 });
    const result = loadUnifiedConfig({
      paths,
      cwd: paths.projectConfigDir,
      projectTrusted: true,
      ignoreExtensionConfigFiles: true,
    });
    expect(sourceLabels(result)).toEqual(["legacy-global-policy", "legacy-project-policy"]);
    expect(result.config).toEqual({ permission: { bash: "ask", mcp: "ask" } });
    const ignoredProjectConfig = result.messages.filter(
      (entry) => entry.code === "ignored-project-config",
    );
    expect(ignoredProjectConfig).toHaveLength(1);
    expect(ignoredProjectConfig[0]!.file).toBe(paths.projectConfigFile);
  });

  it("does not notice an ignored project config that equals the managed policy path", () => {
    const { root, paths } = fixture();
    writeConfig(paths.projectConfigFile, { debugLog: true });
    const custom: ConfigPaths = { ...paths, legacyProjectPolicyFile: paths.projectConfigFile };
    const result = loadUnifiedConfig({
      paths: custom,
      cwd: join(root, "cwd"),
      projectTrusted: true,
      ignoreExtensionConfigFiles: true,
    });
    expect(result.messages.some((entry) => entry.code === "ignored-project-config")).toBe(false);
  });

  it("does not read project files for an untrusted project even when they exist", () => {
    const { paths } = fixture();
    writeConfig(paths.projectConfigFile, { debugLog: true });
    const result = loadUnifiedConfig({ paths, cwd: paths.projectConfigDir, projectTrusted: false });
    expect(result.config).toEqual({});
    expect(result.layers.some((layer) => layer.source === "project")).toBe(false);
  });
});
