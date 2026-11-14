import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createCodemodeExtension,
  DefaultResourceLoader,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it } from "vitest";
import { createManagedCodemodeExtension } from "#sandbox/codemode/tool-adapter";

describe("managed codemode extension", () => {
  let tempDirectory: string | undefined;

  afterEach(async () => {
    if (tempDirectory !== undefined) {
      await rm(tempDirectory, { recursive: true, force: true });
      tempDirectory = undefined;
    }
  });

  it("replaces Pi's built-in tool while preserving its public definition", async () => {
    tempDirectory = await mkdtemp(join(tmpdir(), "pi-codemode-extension-"));
    const cwd = join(tempDirectory, "project");
    const agentDir = join(tempDirectory, "agent");
    await Promise.all([
      mkdir(cwd, { recursive: true }),
      mkdir(agentDir, { recursive: true }),
    ]);

    const loader = new DefaultResourceLoader({
      cwd,
      agentDir,
      settingsManager: SettingsManager.inMemory({ defaultTools: ["codemode"] }),
      extensionFactories: [
        {
          name: "codemode",
          builtin: true,
          replaceable: true,
          factory: createCodemodeExtension(),
        },
        createManagedCodemodeExtension({
          execute: async () => ({
            content: [{ type: "text", text: "managed" }],
            details: undefined,
          }),
        }),
      ],
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();

    const result = loader.getExtensions();
    const codemodeTools = result.extensions.flatMap((extension) => {
      const registered = extension.tools.get("codemode");
      return registered === undefined
        ? []
        : [{ path: extension.path, definition: registered.definition }];
    });

    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: "builtin:codemode" })]),
    );
    expect(codemodeTools).toHaveLength(1);
    expect(codemodeTools[0]?.path).not.toBe("builtin:codemode");
    expect(codemodeTools[0]?.definition).toMatchObject({
      name: "codemode",
      defaultActive: false,
      parameters: { properties: { code: { type: "string" } } },
    });
    expect(codemodeTools[0]?.definition.prepareLoadout).toBeTypeOf("function");
    expect(codemodeTools[0]?.definition.reachesTools).toBeTypeOf("function");
    expect(codemodeTools[0]?.definition.execute).toBeTypeOf("function");
    expect(codemodeTools[0]?.definition.renderCall).toBeTypeOf("function");
    expect(codemodeTools[0]?.definition.renderResult).toBeTypeOf("function");
  });

  it("fails Pi CLI startup when separate extensions register the same tool", async () => {
    tempDirectory = await mkdtemp(join(tmpdir(), "pi-codemode-cli-conflict-"));
    const agentDir = join(tempDirectory, "agent");
    const extensionDirectory = join(tempDirectory, "extensions");
    await Promise.all([
      mkdir(agentDir, { recursive: true }),
      mkdir(extensionDirectory, { recursive: true }),
    ]);

    const piModuleUrl = import.meta.resolve("@earendil-works/pi-coding-agent");
    const extensionSource = [
      `import { createCodemodeExtension } from ${JSON.stringify(piModuleUrl)};`,
      "export default createCodemodeExtension();",
    ].join("\n");
    const firstExtension = join(extensionDirectory, "first.js");
    const secondExtension = join(extensionDirectory, "second.js");
    await Promise.all([
      writeFile(firstExtension, extensionSource),
      writeFile(secondExtension, extensionSource),
    ]);

    const packageEntry = fileURLToPath(piModuleUrl);
    const cliPath = join(dirname(packageEntry), "cli.js");
    for (const extensionPaths of [
      [firstExtension, secondExtension],
      [secondExtension, firstExtension],
    ]) {
      const result = spawnSync(
        process.execPath,
        [
          cliPath,
          "--no-session",
          "--no-extensions",
          "--no-mcp",
          "--no-skills",
          "--no-prompt-templates",
          "--no-themes",
          "--no-context-files",
          "--no-tools",
          ...extensionPaths.flatMap((path) => ["--extension", path]),
          "--print",
          "probe",
        ],
        {
          cwd: tempDirectory,
          encoding: "utf8",
          timeout: 15_000,
          env: {
            ...process.env,
            PI_CODING_AGENT_DIR: agentDir,
            PI_CODING_AGENT_SESSION_DIR: join(agentDir, "sessions"),
          },
        },
      );

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(`${result.stdout}\n${result.stderr}`).toContain('Tool "codemode" conflicts');
    }
  }, 35_000);

  it("loads a repeated explicit extension path once", async () => {
    tempDirectory = await mkdtemp(join(tmpdir(), "pi-codemode-duplicate-"));
    const agentDir = join(tempDirectory, "agent");
    const extensionDirectory = join(tempDirectory, "extensions");
    await Promise.all([
      mkdir(agentDir, { recursive: true }),
      mkdir(extensionDirectory, { recursive: true }),
    ]);

    const piModuleUrl = import.meta.resolve("@earendil-works/pi-coding-agent");
    const extensionPath = join(extensionDirectory, "codemode.js");
    const markerPath = join(tempDirectory, "loads.txt");
    await writeFile(
      extensionPath,
      [
        'import { appendFileSync } from "node:fs";',
        `import { createCodemodeExtension } from ${JSON.stringify(piModuleUrl)};`,
        "const factory = createCodemodeExtension();",
        "export default async (api) => {",
        `  appendFileSync(${JSON.stringify(markerPath)}, "loaded\\n");`,
        "  await factory(api);",
        "};",
      ].join("\n"),
    );

    const loader = new DefaultResourceLoader({
      cwd: tempDirectory,
      agentDir,
      settingsManager: SettingsManager.inMemory({ defaultTools: ["codemode"] }),
      additionalExtensionPaths: [extensionPath, extensionPath],
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();

    const result = loader.getExtensions();
    expect(result.errors).toEqual([]);
    expect(result.extensions.filter((extension) => extension.path === extensionPath)).toHaveLength(1);
    expect(await readFile(markerPath, "utf8")).toBe("loaded\n");
  });
});
