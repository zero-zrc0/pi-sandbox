import { copyFileSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import { createAgentSession, DefaultResourceLoader, initTheme, ModelRuntime, SessionManager, type ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { expect, it, vi } from "vitest";
import { getPermissionsService } from "../../src/service";
import { sessionWorkspacePath } from "../../src/sandbox/session-workspace";
import { createTestLayout, removeTestLayout } from "../sandbox/fixtures/harness";
import { installLinuxTestRuntime, windowsRuntimeFiles } from "../sandbox/fixtures/runtime";

type TestMode = "default" | "read-only" | "full-access";

async function openSession(
  layout: ReturnType<typeof createTestLayout>,
  config: { readonly mode: TestMode; readonly toolRules?: readonly unknown[]; readonly permission?: unknown; readonly execution?: unknown; readonly experimental?: { readonly sandboxEnabled: boolean } },
  extensionPaths: readonly string[] = [],
  sessionId?: string,
  agentDir = layout.agent,
  postSandboxPaths: readonly string[] = [],
  uiContext?: ExtensionUIContext,
) {
  const configDir = join(agentDir, "extensions", "pi-sandbox");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.json"), JSON.stringify(config));

  const cwd = layout.workspace;
  const loader = new DefaultResourceLoader({
    cwd, agentDir, noExtensions: true,
    noSkills: true, noThemes: true, noPromptTemplates: true, noContextFiles: true,
    additionalExtensionPaths: [...extensionPaths, fileURLToPath(new URL("../../src/index.ts", import.meta.url)), ...postSandboxPaths],
  });
  await loader.reload();
  const sessionManager = SessionManager.inMemory(cwd, sessionId === undefined ? undefined : { id: sessionId });
  const modelRuntime = await ModelRuntime.create({ authPath: join(agentDir, "auth.json"), modelsPath: null });
  const model = fauxProvider();
  modelRuntime.registerNativeProvider(model.provider);
  const { session, extensionsResult } = await createAgentSession({
    cwd, agentDir, resourceLoader: loader, sessionManager, modelRuntime, model: model.getModel(),
  });
  expect(extensionsResult.errors).toEqual([]);
  const errors: string[] = [];
  await session.bindExtensions({ onError: error => errors.push(error.error), ...(uiContext === undefined ? {} : { uiContext, mode: "tui" }) });
  return { session, model, sessionManager, runner: session.extensionRunner, errors };
}

it.for(["read-only", "full-access"] as const)("enforces %s during a Pi session and withdraws its service on shutdown", { timeout: 30_000 }, async (mode, t) => {
  const layout = createTestLayout("pi-permission-session");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const { session, model, runner, errors } = await openSession(layout, {
    mode,
    toolRules: [{ id: "deny-edit", match: { tool: "edit" }, decision: "deny" }],
  });
  t.onTestFinished(() => session.dispose());
  const id = session.sessionManager.getSessionId();
  expect(runner.getCommand("permission")).toBeDefined();
  expect(getPermissionsService(id)).toBeDefined();

  const path = join(layout.workspace, "notes.txt");
  writeFileSync(path, "seed");
  const expectedContent = mode === "read-only" ? "seed" : "original";
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path, content: "original" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("edit", { path, edits: [{ oldText: expectedContent, newText: "changed" }] }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("read", { path }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write notes.txt, edit it, then read it back.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: mode === "read-only" },
    { toolName: "edit", isError: true, content: [{ text: expect.stringContaining("deny-edit") }] },
    { toolName: "read", isError: false, content: [{ text: expectedContent }] },
  ]);
  expect(readFileSync(path, "utf8")).toBe(expectedContent);

  await runner.emit({ type: "session_shutdown", reason: "quit" });
  expect(getPermissionsService(id)).toBeUndefined();
  expect(errors).toEqual([]);
});

it("delivers a queued Pi follow-up in the next model turn", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-queued-follow-up-session");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const { session, model } = await openSession(layout, { mode: "default" });
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    async () => {
      await new Promise(resolve => setTimeout(resolve, 50));
      return fauxAssistantMessage("First turn finished.");
    },
    fauxAssistantMessage("Queued instruction received."),
  ]);

  const firstTurn = session.prompt("Start the first turn.");
  await vi.waitFor(() => expect(model.state.callCount).toBe(1));
  await session.followUp("Apply this instruction in the next turn.");
  await firstTurn;

  expect(model.state.callCount).toBe(2);
  expect(session.messages.some(message => message.role === "user" &&
    JSON.stringify(message.content).includes("Apply this instruction in the next turn."))).toBe(true);
});

it("refuses a one-time elevation denied by the target tool rule in a Pi session", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-denied-elevation-session");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const { session, model } = await openSession(layout, {
    mode: "read-only",
    experimental: { sandboxEnabled: true },
    toolRules: [{ id: "deny-host-write", match: { tool: "write" }, decision: "deny" }],
  });
  t.onTestFinished(() => session.dispose());
  const targetPath = join(layout.agent, "denied-write.txt");
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("request_tool_elevation", {
      reason: "write a file outside the workspace",
      toolName: "write",
      arguments: { path: targetPath, content: "must not be written" },
      tier: "host",
    }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);

  await session.prompt("Request one-time host access to save a file.");

  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "request_tool_elevation", isError: true, content: [{ text: expect.stringContaining("deny-host-write") }] },
  ]);
  expect(existsSync(targetPath)).toBe(false);
});

it("writes and reads a temporary file through Pi's captured tool calls", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-temp-path-session");
  t.onTestFinished(() => removeTestLayout(layout));
  const agentDir = join(layout.workspace, ".pi-agent");
  mkdirSync(agentDir);
  vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
  const sessionId = "pi-sandbox-temp-path-session";
  const sessionTemporary = join(sessionWorkspacePath(agentDir, sessionId), "tmp");
  mkdirSync(sessionTemporary, { recursive: true });
  const hostTemporary = sessionTemporary;
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, hostTemporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });

  const observerPath = join(layout.agent, "observe-temp-path.ts");
  writeFileSync(observerPath, [
    "export default function(pi) {",
    "  pi.on('tool_call', event => {",
    "    if (event.toolName === 'write') process.env.PI_SANDBOX_TEST_OBSERVED_PATH = event.input.path;",
    "  });",
    "}",
  ].join("\n"));
  vi.stubEnv("PI_SANDBOX_TEST_OBSERVED_PATH", "");
  const { session, model } = await openSession(layout, { mode: "default" }, [], sessionId, agentDir, [observerPath]);
  t.onTestFinished(() => session.dispose());
  const inputPath = "$TMPDIR/notes.txt";
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: inputPath, content: "temporary approval survived capture" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("read", { path: inputPath }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);

  await session.prompt("Write a note in the temporary directory and read it back.");
  expect(process.env.PI_SANDBOX_TEST_OBSERVED_PATH).toBe(inputPath);

  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: false },
    { toolName: "read", isError: false, content: [{ text: "temporary approval survived capture" }] },
  ]);
  const temporaryFile = join(sessionWorkspacePath(agentDir, session.sessionManager.getSessionId()), "tmp", "notes.txt");
  expect(readFileSync(temporaryFile, "utf8")).toBe("temporary approval survived capture");
  const recordedWriteCall = session.messages
    .filter(message => message.role === "assistant")
    .flatMap(message => message.content)
    .find(part => part.type === "toolCall" && part.name === "write");
  expect(recordedWriteCall?.type === "toolCall" ? recordedWriteCall.arguments.path : undefined).toBe(inputPath);
});

it("denies both temporary and absolute spellings of the selected write target", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-temp-path-deny");
  t.onTestFinished(() => removeTestLayout(layout));
  const agentDir = join(layout.workspace, ".pi-agent");
  mkdirSync(agentDir);
  vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
  const sessionId = "pi-sandbox-temp-path-deny";
  const temporary = join(sessionWorkspacePath(agentDir, sessionId), "tmp");
  mkdirSync(temporary, { recursive: true });
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const target = join(temporary, "denied-note.txt");
  const { session, model } = await openSession(layout, {
    mode: "default", permission: { path_write: { [target]: "deny" } },
  }, [], sessionId, agentDir);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/denied-note.txt", content: "first" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: target, content: "second" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write the denied file using both paths.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
  ]);
  expect(existsSync(target)).toBe(false);
  const calls = session.messages.filter(message => message.role === "assistant").flatMap(message => message.content)
    .filter(part => part.type === "toolCall" && part.name === "write");
  expect(calls.map(call => call.type === "toolCall" && call.arguments.path)).toEqual(["$TMPDIR/denied-note.txt", target]);
});

it("applies selected path rules to every write in one Pi assistant step", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-batch-path-deny");
  t.onTestFinished(() => removeTestLayout(layout));
  const agentDir = join(layout.workspace, ".pi-agent");
  mkdirSync(agentDir);
  vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
  const temporary = join(layout.workspace, "tmp");
  mkdirSync(temporary);
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const denied = join(temporary, "denied.txt");
  const allowed = join(temporary, "allowed.txt");
  const { session, model } = await openSession(layout, {
    mode: "default", permission: { path_write: { [denied]: "deny" } },
  }, [], undefined, agentDir);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage([
      fauxToolCall("write", { path: "$TMPDIR/allowed.txt", content: "allowed" }),
      fauxToolCall("write", { path: "$TMPDIR/denied.txt", content: "denied" }),
    ], { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write both files.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: false },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
  ]);
  expect(readFileSync(allowed, "utf8")).toBe("allowed");
  expect(existsSync(denied)).toBe(false);
});

it.skipIf(process.platform !== "linux").for([false, true])("keeps a selected target when a later symlink changes (deny=%s)", { timeout: 30_000 }, async (deny, t) => {
  const layout = createTestLayout("pi-sandbox-selected-symlink");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const first = join(layout.workspace, "first.txt");
  const second = join(layout.workspace, "second.txt");
  const link = join(layout.workspace, "current.txt");
  writeFileSync(first, "original first");
  writeFileSync(second, "original second");
  symlinkSync(first, link);
  const extension = join(layout.agent, "switch-link.ts");
  writeFileSync(extension, [
    "import { unlinkSync, symlinkSync } from 'node:fs';",
    "export default function(pi) { let calls = 0; pi.on('tool_call', event => {",
    `  if (event.toolName === 'write' && ++calls === 2) { unlinkSync(${JSON.stringify(link)}); symlinkSync(${JSON.stringify(second)}, ${JSON.stringify(link)}); }`,
    "}); }",
  ].join("\n"));
  const { session, model } = await openSession(layout, {
    mode: "default", ...(deny ? { permission: { path_write: { [first]: "deny" } } } : {}),
  }, [extension]);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage([
      fauxToolCall("write", { path: join(layout.workspace, "trigger.txt"), content: "trigger" }),
      fauxToolCall("write", { path: link, content: "selected" }),
    ], { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write both files.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: false }, { toolName: "write", isError: deny },
  ]);
  expect(readFileSync(first, "utf8")).toBe(deny ? "original first" : "selected");
  expect(readFileSync(second, "utf8")).toBe("original second");
});

const windowsNative = process.platform === "win32" && existsSync(process.env.PI_SANDBOX_TEST_MXC_EXECUTABLE ??
  fileURLToPath(new URL("../../src/sandbox/backend/windows/mxc/pi-sandbox-windows-mxc.exe", import.meta.url)));

function installWindowsSessionRuntime(agentDir: string): void {
  const source = windowsRuntimeFiles();
  const directory = join(agentDir, "extensions", "pi-sandbox", "runtimes", `win32-${process.arch}-${source.manifest.version}`);
  mkdirSync(directory, { recursive: true });
  for (const file of source.manifest.files) copyFileSync(source.files[file.role]!, join(directory, file.path));
  writeFileSync(join(directory, "runtime.json"), JSON.stringify(source.manifest));
}

function approvingUi(rendered: string[], choice: number): ExtensionUIContext {
  const theme = { fg: (_color: string, value: string) => value, bg: (_color: string, value: string) => value,
    bold: (value: string) => value, getFgAnsi: () => "" };
  const keys = { matches: (data: string, action: string) =>
    (data === "\u001b[B" && action === "tui.select.down") || (data === "\r" && action === "tui.select.confirm") };
  return {
    notify: () => undefined,
    custom: async (factory: (tui: unknown, theme: unknown, keys: unknown, done: (value: unknown) => void) =>
      { render(width: number): string[]; handleInput(data: string): void }) => new Promise(resolve => {
      const component = factory({ setClearOnShrink: () => undefined }, theme, keys, resolve);
      rendered.push(component.render(200).join("\n"));
      for (let step = 0; step <= choice; step += 1) component.handleInput("\u001b[B");
      component.handleInput("\r");
    }),
  } as unknown as ExtensionUIContext;
}

it.skipIf(!windowsNative)("enforces selected path rules and protected reads in a native Windows Pi session", { timeout: 60_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-native-path-rules");
  t.onTestFinished(() => removeTestLayout(layout));
  const agentDir = layout.agent;
  vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
  const sessionId = "native-path-rules";
  const temporary = join(sessionWorkspacePath(agentDir, sessionId), "tmp");
  mkdirSync(temporary, { recursive: true });
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  installWindowsSessionRuntime(agentDir);
  const denied = join(temporary, "denied.txt");
  const allowed = join(temporary, "allowed.txt");
  const secret = join(layout.workspace, "secret.txt");
  writeFileSync(secret, "native-secret-do-not-disclose");
  const { session, model } = await openSession(layout, {
    mode: "default", experimental: { sandboxEnabled: true },
    permission: { path_write: { [denied]: "deny" } }, execution: { denyPaths: [secret] },
  }, [], sessionId, agentDir);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/allowed.txt", content: "native allowed" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/denied.txt", content: "denied" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: denied, content: "denied" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("read", { path: secret }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write the temporary files and read the protected file.");
  const results = session.messages.filter(message => message.role === "toolResult");
  expect(results[0]?.isError, JSON.stringify(results[0]?.content)).toBe(false);
  expect(results).toMatchObject([
    { toolName: "write", isError: false },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
    { toolName: "read", isError: true },
  ]);
  expect(JSON.stringify(results)).not.toContain("native-secret-do-not-disclose");
  expect(readFileSync(allowed, "utf8")).toBe("native allowed");
  expect(existsSync(denied)).toBe(false);
  const calls = session.messages.filter(message => message.role === "assistant").flatMap(message => message.content)
    .filter(part => part.type === "toolCall" && part.name === "write");
  expect(calls.map(call => call.type === "toolCall" && call.arguments.path)).toEqual(["$TMPDIR/allowed.txt", "$TMPDIR/denied.txt", denied]);
});

it.skipIf(!windowsNative)("shows the selected path in a native Windows Pi approval", { timeout: 60_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-native-path-prompt");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  vi.stubEnv("LC_ALL", "zh-CN");
  const sessionId = "native-path-prompt";
  const temporary = join(sessionWorkspacePath(layout.agent, sessionId), "tmp");
  mkdirSync(temporary, { recursive: true });
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  installWindowsSessionRuntime(layout.agent);
  initTheme(undefined, false);
  const rendered: string[] = [];
  const uiContext = approvingUi(rendered, 0);
  const mapped = join(temporary, "mapped.txt");
  const absolute = join(temporary, "absolute.txt");
  const { session, model } = await openSession(layout, {
    mode: "default", experimental: { sandboxEnabled: true },
    permission: { path_write: { [mapped]: "ask", [absolute]: "ask" } },
  }, [], sessionId, layout.agent, [], uiContext);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/mapped.txt", content: "mapped" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: absolute, content: "absolute" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Approve both writes.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: false }, { toolName: "write", isError: false },
  ]);
  expect(rendered).toHaveLength(2);
  const pathLines = (value: string) => value.split("\n").filter(line =>
    line.startsWith("请求路径") || line.startsWith("解析路径") || line.startsWith("路径  "));
  expect(pathLines(rendered[0]!)).toHaveLength(2);
  expect(pathLines(rendered[0]!).join("\n")).toContain("$TMPDIR/mapped.txt");
  expect(pathLines(rendered[0]!).join("\n")).toContain(mapped);
  expect(pathLines(rendered[1]!)).toHaveLength(1);
  expect(pathLines(rendered[1]!).join("\n")).toContain(absolute);
  expect(readFileSync(mapped, "utf8")).toBe("mapped");
  expect(readFileSync(absolute, "utf8")).toBe("absolute");
});

it("remembers the selected temporary directory for subsequent Pi calls", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-session-path-scope");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  vi.stubEnv("LC_ALL", "zh-CN");
  const temporary = join(layout.workspace, "tmp");
  mkdirSync(temporary);
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  initTheme(undefined, false);
  const first = join(temporary, "first.txt");
  const second = join(temporary, "second.txt");
  const rendered: string[] = [];
  const { session, model } = await openSession(layout, {
    mode: "default", permission: { path_write: { [first]: "ask", [second]: "ask" } },
  }, [], undefined, layout.agent, [], approvingUi(rendered, 2));
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/first.txt", content: "first" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: second, content: "second" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write both files, remembering the first approval.");
  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: false }, { toolName: "write", isError: false },
  ]);
  expect(rendered).toHaveLength(1);
  expect(readFileSync(first, "utf8")).toBe("first");
  expect(readFileSync(second, "utf8")).toBe("second");
});

const linuxNative = process.platform === "linux" && existsSync("/usr/bin/bwrap") &&
  existsSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-sandbox", import.meta.url))) &&
  existsSync(fileURLToPath(new URL("../../src/sandbox/backend/linux/linux-egress-bridge", import.meta.url)));

function installLinuxSessionRuntime(agentDir: string): void {
  const directory = join(agentDir, "extensions", "pi-sandbox", "runtimes", `linux-${process.arch}-1.0.0`);
  mkdirSync(directory, { recursive: true });
  for (const name of ["linux-sandbox", "linux-egress-bridge"]) {
    copyFileSync(fileURLToPath(new URL(`../../src/sandbox/backend/linux/${name}`, import.meta.url)), join(directory, name));
  }
  installLinuxTestRuntime(directory);
}

it.skipIf(!linuxNative)("enforces selected path rules in a native Linux Pi session", { timeout: 60_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-linux-path-rules");
  t.onTestFinished(() => removeTestLayout(layout));
  const agentDir = layout.agent;
  vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
  const sessionId = "linux-path-rules";
  const temporary = join(sessionWorkspacePath(agentDir, sessionId), "tmp");
  mkdirSync(temporary, { recursive: true });
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, temporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  installLinuxSessionRuntime(agentDir);
  const denied = join(temporary, "denied.txt");
  const allowed = join(temporary, "allowed.txt");
  const { session, model } = await openSession(layout, {
    mode: "default", experimental: { sandboxEnabled: true }, permission: { path_write: { [denied]: "deny" } },
  }, [], sessionId, agentDir);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/allowed.txt", content: "linux allowed" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/denied.txt", content: "denied" }), { stopReason: "toolUse" }),
    fauxAssistantMessage(fauxToolCall("write", { path: denied, content: "denied" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Write the temporary files.");
  const results = session.messages.filter(message => message.role === "toolResult");
  expect(results[0]?.isError, JSON.stringify(results[0]?.content)).toBe(false);
  expect(results).toMatchObject([
    { toolName: "write", isError: false },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("rules:global:deny") }] },
  ]);
  expect(readFileSync(allowed, "utf8")).toBe("linux allowed");
  expect(existsSync(denied)).toBe(false);
});

it("emits paired nested CodeMode events through a real full-access Pi session", { timeout: 60_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-windows-codemode-events");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });
  const target = join(layout.workspace, "nested.txt");
  writeFileSync(target, "nested-result-content");
  const log = join(layout.agent, "nested-events.jsonl");
  const observer = join(layout.agent, "observe-nested.ts");
  writeFileSync(observer, [
    "import { appendFileSync } from 'node:fs';",
    "export default function(pi) {",
    `  for (const name of ['tool_execution_start', 'tool_execution_end']) pi.on(name, event => { if (event.parentToolCallId) appendFileSync(${JSON.stringify(log)}, JSON.stringify(event) + '\\n'); });`,
    "}",
  ].join("\n"));
  const { session, model } = await openSession(layout, {
    mode: "full-access",
    toolRules: [{ id: "allow-code", match: { tool: "codemode" }, decision: "allow" }],
  }, [observer]);
  t.onTestFinished(() => session.dispose());
  session.setActiveToolsByName(["codemode", "read"]);
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("codemode", { code: `return await tools.read({ path: ${JSON.stringify(target)} });` }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);
  await session.prompt("Read the file using CodeMode.");
  const result = session.messages.filter(message => message.role === "toolResult").find(message => message.toolName === "codemode");
  expect(result?.isError, JSON.stringify(result?.content)).toBe(false);
  expect(JSON.stringify(result?.content)).toContain("nested-result-content");
  const events = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line) as Record<string, unknown>);
  expect(events).toHaveLength(2);
  expect(events[0]).toMatchObject({ type: "tool_execution_start", toolName: "read", args: { path: target } });
  expect(events[1]).toMatchObject({ type: "tool_execution_end", toolName: "read", toolCallId: events[0]?.toolCallId,
    parentToolCallId: events[0]?.parentToolCallId, isError: false });
  expect(JSON.stringify(events[1]?.result)).toContain("nested-result-content");
});

it("rejects a temporary-path rewrite when another write argument changes", { timeout: 30_000 }, async t => {
  const layout = createTestLayout("pi-sandbox-temp-path-tamper");
  t.onTestFinished(() => removeTestLayout(layout));
  vi.stubEnv("PI_CODING_AGENT_DIR", layout.agent);
  const hostTemporary = join(layout.root, "host-tmp");
  mkdirSync(hostTemporary);
  for (const name of ["TMPDIR", "TEMP", "TMP"]) vi.stubEnv(name, hostTemporary);
  t.onTestFinished(() => { vi.unstubAllEnvs(); });

  const mutateExtension = join(layout.agent, "mutate-write.ts");
  writeFileSync(mutateExtension, [
    "export default function(pi) {",
    "  pi.on('tool_call', event => {",
    "    if (event.toolName === 'write') event.input = { ...event.input, content: 'changed after model response' };",
    "  });",
    "}",
  ].join("\n"));
  const { session, model } = await openSession(layout, { mode: "default" }, [mutateExtension]);
  t.onTestFinished(() => session.dispose());
  model.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: "$TMPDIR/tampered.txt", content: "original model content" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("Done"),
  ]);

  await session.prompt("Write a temporary file.");

  expect(session.messages.filter(message => message.role === "toolResult")).toMatchObject([
    { toolName: "write", isError: true, content: [{ text: expect.stringContaining("permission:step-facts") }] },
  ]);
  const temporaryFile = join(sessionWorkspacePath(layout.agent, session.sessionManager.getSessionId()), "tmp", "tampered.txt");
  expect(existsSync(temporaryFile)).toBe(false);
});
