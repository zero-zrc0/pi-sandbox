import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { SessionManager, type ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import type { CodemodeResult, CodemodeToolContext } from "@earendil-works/pi-codemode";
import { Type } from "typebox";
import { describe, expect, it, vi } from "vitest";
import { createCodemodeHostToolExecutor } from "#sandbox/codemode/host-execution";
import { hasApprovedCodemodeScope } from "#sandbox/codemode/approval-scope";
import type { CodemodeRuntimeRequest } from "#sandbox/codemode/supervisor";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

function success(): CodemodeResult {
  return { ok: true, value: undefined, output: [], calls: [], storeWrites: { set: {}, delete: [] } };
}

describe("Codemode host execution", () => {
  it("passes host sensitive paths only to a restricted runtime", async () => {
    const context = { tools: [], sessionManager: { getSessionId: () => "paths", getBranch: () => [] },
      executeTool: async () => { throw new Error("not called"); } } as unknown as ExtensionToolContext;
    const paths = [{ requestedPath: "/secret", path: "/secret", granularity: "file" as const,
      identity: { device: "1", inode: "2" } }];
    const requests: CodemodeRuntimeRequest[] = [];
    let restricted = true;
    const resolveSensitivePaths = vi.fn(() => paths);
    const execute = createCodemodeHostToolExecutor({
      supervisor: { async execute(request) { requests.push(request); return success(); } },
      resolveBackend: () => restricted ? "restricted" : "full-access", resolveSensitivePaths,
    });
    await execute("restricted", { code: "return 1;" }, undefined, undefined, context);
    restricted = false;
    await execute("full-access", { code: "return 1;" }, undefined, undefined, context);
    expect(requests[0]?.sensitivePaths).toEqual(paths);
    expect(requests[1]?.sensitivePaths).toBeUndefined();
    expect(resolveSensitivePaths).toHaveBeenCalledTimes(1);
  });

  it("formats console output, preserves images, and spills output over its token budget", async () => {
    const context = {
      tools: [],
      sessionManager: { getSessionId: () => "host-execution-session", getBranch: () => [] },
      executeTool: async () => { throw new Error("not called"); },
    } as unknown as ExtensionToolContext;
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute() {
          return {
            ok: true,
            value: { result: "returned" },
            output: [
              { type: "text", text: "head text" },
              { type: "text", text: "debug line", console: true },
              { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
              { type: "text", text: "tail text" },
            ],
            calls: [],
            storeWrites: { set: {}, delete: [] },
          } satisfies CodemodeResult;
        },
      },
      resolveBackend: () => "full-access",
    });
    const result = await execute(
      "codemode-parent",
      { code: '// @options: {"max_output_tokens":2}\nreturn { result: "returned" };' },
      undefined,
      undefined,
      context,
    );
    const outputText = result.content.filter(block => block.type === "text").map(block => block.text).join("\n");
    const fullOutputPath = (result.details as { fullOutputPath?: string }).fullOutputPath;
    const imagePath = outputText.match(/\[Image saved to ([^\s]+) \(/)?.[1];
    const outputPaths = [fullOutputPath, imagePath].filter((path): path is string => path !== undefined);

    try {
      expect(outputText).toContain("Warning: truncated output");
      expect(outputText).toContain("[Full output:");
      expect(fullOutputPath).toBeDefined();
      expect(imagePath).toBeDefined();
      expect(result.content.some(block => block.type === "image" && block.mimeType === "image/png")).toBe(true);
      expect(outputPaths.every(path => path.startsWith(tmpdir()))).toBe(true);
      const fullOutput = await readFile(fullOutputPath!, "utf8");
      expect(fullOutput).toContain("<console_output>\ndebug line\n</console_output>");
      expect(fullOutput).toContain("tail text");
      expect(await readFile(imagePath!)).toEqual(Buffer.from("aGVsbG8=", "base64"));
    } finally {
      for (const path of outputPaths) await rm(path, { force: true });
    }
  });

  it("loads store values from the active branch and appends writes only after success", async () => {
    const sessionManager = SessionManager.inMemory("codemode-store-test");
    const branchStart = sessionManager.appendCustomEntry("codemode-store", { set: { keep: "branch", old: true }, delete: [] });
    sessionManager.appendCustomEntry("codemode-store", { set: { added: 7 }, delete: ["old"] });
    const context = {
      tools: [],
      sessionManager,
      executeTool: async () => { throw new Error("not called"); },
    } as unknown as ExtensionToolContext;
    const appended: Array<{ customType: string; data: unknown }> = [];
    let outcome: CodemodeResult = {
      ok: true,
      value: undefined,
      output: [],
      calls: [],
      storeWrites: { set: { result: "saved" }, delete: ["keep"] },
    };
    const requests: CodemodeRuntimeRequest[] = [];
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute(request) {
          requests.push(request);
          return outcome;
        },
      },
      resolveBackend: () => "full-access",
      appendEntry: (customType, data) => {
        appended.push({ customType, data });
        sessionManager.appendCustomEntry(customType, data);
      },
    });

    await execute("codemode-parent", { code: "return load('keep');" }, undefined, undefined, context);
    expect(requests[0]?.store).toEqual({ keep: "branch", added: 7 });
    expect(appended).toEqual([{
      customType: "codemode-store",
      data: { set: { result: "saved" }, delete: ["keep"] },
    }]);
    expect(sessionManager.getBranch().at(-1)).toMatchObject({
      type: "custom",
      customType: "codemode-store",
      data: { set: { result: "saved" }, delete: ["keep"] },
    });

    sessionManager.branch(branchStart);
    outcome = {
      ok: true,
      value: undefined,
      output: [],
      calls: [],
      storeWrites: { set: {}, delete: [] },
    };
    await execute("codemode-parent-branch", { code: "return load('keep');" }, undefined, undefined, context);
    expect(requests[1]?.store).toEqual({ keep: "branch", old: true });
    expect(appended).toHaveLength(1);

    outcome = {
      ok: false,
      error: { kind: "script", message: "failed after a store write" },
      output: [],
      calls: [],
    };
    await execute("codemode-parent-2", { code: "store('failed', true); throw Error('failed');" }, undefined, undefined, context);
    expect(appended).toHaveLength(1);
  });

  it("aborts the session's Runtime and waits for shutdown before returning", async () => {
    const started = deferred<CodemodeRuntimeRequest>();
    const runtimeResult = deferred<CodemodeResult>();
    const context = {
      tools: [],
      sessionManager: { getSessionId: () => "cancel-session", getBranch: () => [] },
      executeTool: async () => { throw new Error("not called"); },
    } as unknown as ExtensionToolContext;
    const appendEntry = vi.fn();
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        execute(request) {
          started.resolve(request);
          request.signal?.addEventListener("abort", () => undefined, { once: true });
          return runtimeResult.promise;
        },
      },
      resolveBackend: () => "full-access",
      appendEntry,
    });
    const running = execute("cancel-parent", { code: "store('stale', true); return 1;" }, undefined, undefined, context);
    const request = await started.promise;
    let cancelled = false;
    const cancellation = execute.cancelSession("cancel-session").then(() => { cancelled = true; });

    expect(request.signal?.aborted).toBe(true);
    await Promise.resolve();
    expect(cancelled).toBe(false);
    runtimeResult.resolve({
      ok: false,
      error: { kind: "aborted", message: "session changed" },
      output: [],
      calls: [],
    });
    await cancellation;
    const result = await running;

    expect(cancelled).toBe(true);
    expect(result.isError).toBe(true);
    expect(appendEntry).not.toHaveBeenCalled();
  });

  it("discards successful late results and store writes after policy validity changes", async () => {
    const started = deferred<void>();
    const runtimeResult = deferred<CodemodeResult>();
    const context = {
      tools: [],
      sessionManager: { getSessionId: () => "stale-session", getBranch: () => [] },
      executeTool: async () => { throw new Error("not called"); },
    } as unknown as ExtensionToolContext;
    const appendEntry = vi.fn();
    let current = true;
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute() {
          started.resolve();
          return runtimeResult.promise;
        },
      },
      resolveBackend: () => "full-access",
      captureValidityGuard: () => () => current,
      appendEntry,
    });
    const running = execute("stale-parent", { code: "store('stale', true); return 'late';" }, undefined, undefined, context);
    await started.promise;
    current = false;
    runtimeResult.resolve({
      ok: true,
      value: "late",
      output: [],
      calls: [],
      storeWrites: { set: { stale: true }, delete: [] },
    });

    const result = await running;
    const output = result.content.filter(block => block.type === "text").map(block => block.text).join("\n");
    expect(result.isError).toBe(true);
    expect(output).toContain("result discarded because its session or policy changed");
    expect(output).toContain("late");
    expect(appendEntry).not.toHaveBeenCalled();
  });

  it("reports generated model images that the script did not add to its output", async () => {
    const imageModel = {
      type: "image",
      provider: "image-provider",
      id: "image-model",
      api: "fixture-images",
      baseUrl: "https://provider.example.test",
      name: "Image fixture",
      input: ["text"],
      output: ["image"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    };
    const generated = {
      api: imageModel.api,
      provider: imageModel.provider,
      model: imageModel.id,
      stopReason: "stop",
      output: [{ type: "image", data: "aGVsbG8=", mimeType: "image/png" }],
      usage: {
        input: 1,
        output: 2,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 3,
        cost: { input: 0, output: 0.01, cacheRead: 0, cacheWrite: 0, total: 0.01 },
      },
      timestamp: 123,
    };
    const context = {
      tools: [],
      modelRegistry: {
        getModelsOfType: () => [imageModel],
        getAvailableOfType: async () => [imageModel],
        getModelOfType: () => imageModel,
        classify: async () => { throw new Error("not called"); },
        generateImages: async () => generated,
      },
      sessionManager: { getSessionId: () => "host-execution-session", getBranch: () => [] },
      executeTool: async () => { throw new Error("model calls must stay inside the approved Codemode call"); },
    } as unknown as ExtensionToolContext;
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute(request) {
          const generateImages = request.globals?.find(global => global.name === "models.generateImages");
          if (!generateImages) throw new Error("model globals were not supplied");
          await generateImages.execute([
            { provider: "image-provider", id: "image-model" },
            { input: [{ type: "text", text: "draw a probe" }] },
          ], { signal: new AbortController().signal });
          return success();
        },
      },
      resolveBackend: () => "full-access",
      modelsEnabled: true,
    });

    const result = await execute("codemode-parent", { code: "return 'done';" }, undefined, undefined, context);

    expect(result.content.filter(block => block.type === "text").map(block => block.text).join("\n"))
      .toContain("models.generateImages() returned 1 image that the script did not show");
    expect(result.content.some(block => block.type === "image")).toBe(false);
    expect(result.details).toMatchObject({
      calls: [{ name: "models.generateImages", id: "codemode-parent/models.generateImages/1", status: "ok", cost: 0.01 }],
    });
    expect(result.usage).toEqual(generated.usage);
  });

  it("keeps partial script output and prior tool calls when the script fails", async () => {
    let nestedScope = false;
    const context = {
      tools: [{
        name: "echo",
        label: "Echo",
        description: "Returns text.",
        parameters: Type.Object({ message: Type.String() }),
        execute: () => undefined,
      }],
      sessionManager: { getSessionId: () => "host-execution-session", getBranch: () => [] },
      executeTool: async () => {
        nestedScope = hasApprovedCodemodeScope("host-execution-session");
        return {
        isError: false,
        toolCall: { id: "codemode-parent/1" },
        result: { content: [{ type: "text" as const, text: "finished" }], details: {} },
      };
      },
    } as unknown as ExtensionToolContext;
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute(request) {
          await request.tools?.[0]?.execute(
            { message: "run first" },
            { signal: new AbortController().signal },
          );
          return {
            ok: false,
            error: { kind: "script", message: "later step failed", stack: "Error: later step failed" },
            output: [{ type: "text", text: "partial result" }],
            calls: [],
          };
        },
      },
      resolveBackend: () => "full-access",
    });

    const result = await execute("codemode-parent", { code: "await tools.echo({message:'run first'}); throw Error('later step failed');" }, undefined, undefined, context);
    const output = result.content.filter(block => block.type === "text").map(block => block.text).join("\n");

    expect(result.isError).toBe(true);
    expect(nestedScope).toBe(true);
    expect(hasApprovedCodemodeScope("host-execution-session")).toBe(false);
    expect(output).toContain("partial result");
    expect(output).toContain("Error: later step failed");
    expect(output).toContain("Tool calls made before the failure (they are not undone): echo (ok)");
  });

  it("exposes callable tools through search and descriptions, including namespace guidance", async () => {
    let runtimeRequest: CodemodeRuntimeRequest | undefined;
    const context = {
      tools: [
        {
          name: "mcp__issues__search",
          label: "Search issues",
          description: "Search the issue tracker.",
          parameters: Type.Object({ query: Type.String({ description: "Issue title or text" }) }),
          execute: () => undefined,
        },
        {
          name: "echo",
          label: "Echo",
          description: "Returns the supplied message.",
          parameters: Type.Object({ message: Type.String() }),
          execute: () => undefined,
        },
      ],
      sessionManager: { getSessionId: () => "host-execution-session", getBranch: () => [] },
      executeTool: async () => { throw new Error("not called"); },
    } as unknown as ExtensionToolContext;
    const execute = createCodemodeHostToolExecutor({
      supervisor: {
        async execute(request) {
          runtimeRequest = request;
          return success();
        },
      },
      resolveBackend: () => "full-access",
      getToolNamespace: name => name.startsWith("mcp__issues__")
        ? { name: "mcp__issues", aliases: ["issues"], description: "Issue tracker", instructions: "Search before creating." }
        : undefined,
      getToolGuidelines: name => name === "mcp__issues__search" ? ["Use exact issue identifiers when available."] : [],
    });

    await execute("codemode-parent", { code: "return 1;" }, undefined, undefined, context);

    const tools = runtimeRequest?.tools ?? [];
    expect(tools.find(tool => tool.name === "mcp__issues__search")?.description)
      .toContain("Use exact issue identifiers when available.");
    const globals = runtimeRequest?.globals ?? [];
    const searchTools = globals.find(global => global.name === "searchTools");
    const describeTool = globals.find(global => global.name === "describeTool");
    const describeNamespace = globals.find(global => global.name === "describeNamespace");
    expect(searchTools).toBeDefined();
    expect(describeTool).toBeDefined();
    expect(describeNamespace).toBeDefined();
    const toolContext: CodemodeToolContext = { signal: new AbortController().signal };
    expect(searchTools?.execute(["issue title", { namespace: "issues" }], toolContext))
      .toEqual([expect.objectContaining({ name: "mcp__issues__search" })]);
    expect(describeTool?.execute(["mcp__issues__search"], toolContext))
      .toContain("Use exact issue identifiers when available.");
    expect(describeNamespace?.execute(["issues"], toolContext)).toMatchObject({
      name: "mcp__issues",
      description: "Issue tracker",
      instructions: "Search before creating.",
      tools: ["mcp__issues__search"],
    });
  });

  it("limits parallel nested tool work to 64 while preserving real Pi call outcomes", async () => {
    const ready = deferred<void>();
    const release = deferred<void>();
    let activeCalls = 0;
    let maximumConcurrentCalls = 0;
    const callIds: string[] = [];
    const context = {
      tools: [{
        name: "echo",
        label: "Echo",
        description: "Returns the supplied message.",
        parameters: Type.Object({ message: Type.String() }),
        execute: () => undefined,
      }],
      sessionManager: { getSessionId: () => "host-execution-session", getBranch: () => [] },
      executeTool: async (_name: string, _args: unknown, _options: { signal: AbortSignal }) => {
        const id = `codemode-call/${callIds.length + 1}`;
        callIds.push(id);
        activeCalls += 1;
        maximumConcurrentCalls = Math.max(maximumConcurrentCalls, activeCalls);
        if (activeCalls === 64) ready.resolve();
        await release.promise;
        activeCalls -= 1;
        return {
          isError: false,
          toolCall: { id },
          result: { content: [{ type: "text", text: "ok" }], details: {} },
        };
      },
    } as unknown as ExtensionToolContext;

    const supervisor = {
      async execute(request: CodemodeRuntimeRequest) {
        const tool = request.tools?.[0];
        if (!tool) throw new Error("host tool was not supplied to Runtime");
        const signal = new AbortController().signal;
        const results = await Promise.allSettled(Array.from({ length: 65 }, (_, index) =>
          tool.execute({ message: String(index) }, { signal } satisfies CodemodeToolContext),
        ));
        expect(results.filter(result => result.status === "rejected")).toHaveLength(1);
        return success();
      },
    };
    const execute = createCodemodeHostToolExecutor({ supervisor, resolveBackend: () => "full-access" });
    const running = execute(
      "codemode-parent",
      { code: "return 1;" },
      undefined,
      undefined,
      context,
    );

    await ready.promise;
    expect(maximumConcurrentCalls).toBe(64);
    expect(callIds).toHaveLength(64);
    release.resolve();

    const result = await running;
    expect(result.isError).toBeUndefined();
    const details = result.details as { calls: Array<{ id: string; status: string }> };
    expect(details.calls).toHaveLength(65);
    expect(details.calls[0]).toMatchObject({ id: "codemode-call/1", status: "ok" });
    expect(details.calls[63]).toMatchObject({ id: "codemode-call/64", status: "ok" });
    expect(details.calls[64]).toMatchObject({ id: "codemode-parent/?", status: "error" });
    expect(callIds).toHaveLength(64);
  });
});
