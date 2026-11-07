import type { ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import type { ClassifierModel, ClassifierResult, ImageModel, Usage } from "@earendil-works/pi-ai";
import type { CodemodeToolContext } from "@earendil-works/pi-codemode";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCodemodeModelGlobals } from "#sandbox/codemode/model-bridge";

const usage: Usage = {
  input: 2,
  output: 3,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 5,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

const classifier: ClassifierModel<"fixture-classifier"> = {
  type: "classifier",
  id: "fixture-id",
  name: "Fixture classifier",
  provider: "fixture-provider",
  api: "fixture-classifier",
  baseUrl: "https://configured.example.test/v1",
  headers: { authorization: "configured-secret" },
  input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 1024,
};

const imageModel: ImageModel<"fixture-images"> = {
  type: "image",
  id: "fixture-image-id",
  name: "Fixture image model",
  provider: "fixture-image-provider",
  api: "fixture-images",
  baseUrl: "https://configured.example.test/v1",
  input: ["text"],
  output: ["image"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
};

const classifierResult: ClassifierResult = {
  api: classifier.api,
  provider: classifier.provider,
  model: classifier.id,
  answers: {},
  usage,
  stopReason: "stop",
  timestamp: 123,
};

function registry(overrides: Record<string, unknown> = {}) {
  return {
    getModelsOfType: vi.fn((type: string) => type === "image" ? [imageModel] : [classifier]),
    getAvailableOfType: vi.fn(async (type: string) => type === "image" ? [imageModel] : [classifier]),
    getModelOfType: vi.fn((type: string, provider: string, id: string) => {
      if (type === "classifier" && provider === classifier.provider && id === classifier.id) return classifier;
      if (type === "image" && provider === imageModel.provider && id === imageModel.id) return imageModel;
      return undefined;
    }),
    classify: vi.fn(async () => classifierResult),
    generateImages: vi.fn(async () => ({ ...classifierResult, api: imageModel.api, provider: imageModel.provider, model: imageModel.id, output: [] })),
    ...overrides,
  } as unknown as ExtensionToolContext["modelRegistry"];
}

function context() {
  return { state: { message: "fixture" }, questions: { q: { type: "bool", instructions: "?", criteria: { true: "yes", false: "no" } } } };
}

describe("Codemode model globals", () => {
  afterEach(() => vi.restoreAllMocks());

  it("calls the registered classifier directly under the Codemode host callback", async () => {
    const modelRegistry = registry();
    const runModelCall = vi.fn(async (_details: unknown, _signal: AbortSignal, run: () => Promise<unknown>) => run());
    const globals = createCodemodeModelGlobals({ modelRegistry, runModelCall });
    const classify = globals.find(global => global.name === "models.classify")!;
    const signal = new AbortController().signal;
    const result = await classify.execute([
      { provider: classifier.provider, id: classifier.id, baseUrl: "https://attacker.example", headers: { authorization: "script-secret" } },
      context(),
    ], { signal } satisfies CodemodeToolContext);

    expect(globals.map(global => global.name)).not.toContain("permission_model");
    expect(modelRegistry.getModelOfType).toHaveBeenCalledWith("classifier", classifier.provider, classifier.id);
    expect(modelRegistry.classify).toHaveBeenCalledWith(classifier, context(), { signal });
    expect(runModelCall).toHaveBeenCalledWith(
      { displayName: "models.classify", displayArgs: `${classifier.provider}/${classifier.id}` },
      signal,
      expect.any(Function),
    );
    expect(result).toEqual(classifierResult);
  });

  it("reads model catalogs from the registry and removes credentials", async () => {
    const modelRegistry = registry();
    const globals = createCodemodeModelGlobals({ modelRegistry });
    const signal = new AbortController().signal;
    const call = (name: string, args: unknown[]) => globals.find(global => global.name === name)!
      .execute(args, { signal } satisfies CodemodeToolContext);
    const visibleClassifier = { ...classifier };
    delete visibleClassifier.headers;

    await expect(call("models.getModelsOfType", ["classifier", "fixture-provider"])).resolves.toEqual([
      visibleClassifier,
    ]);
    await expect(call("models.getAvailableOfType", ["classifier", null])).resolves.toEqual([
      visibleClassifier,
    ]);
    await expect(call("models.getModelOfType", ["classifier", "fixture-provider", "missing"])).resolves.toBeUndefined();
    expect(modelRegistry.getAvailableOfType).toHaveBeenCalledWith("classifier", undefined, { signal });
  });

  it("calls the registered image model directly and preserves returned images and usage", async () => {
    const generated = {
      api: imageModel.api,
      provider: imageModel.provider,
      model: imageModel.id,
      output: [{ type: "image", data: "aW1hZ2U=", mimeType: "image/png" }],
      usage,
      stopReason: "stop",
      timestamp: 123,
    };
    const modelRegistry = registry({ generateImages: vi.fn(async () => generated) });
    const globals = createCodemodeModelGlobals({ modelRegistry });
    const generateImages = globals.find(global => global.name === "models.generateImages")!;
    const signal = new AbortController().signal;
    const result = await generateImages.execute([
      { provider: imageModel.provider, id: imageModel.id },
      { input: [{ type: "text", text: "fixture image" }] },
    ], { signal } satisfies CodemodeToolContext);

    expect(modelRegistry.generateImages).toHaveBeenCalledWith(imageModel, { input: [{ type: "text", text: "fixture image" }] }, { signal });
    expect(result).toEqual(generated);
  });

  it.each([
    { name: "models.classify", modelType: "classifier", model: classifier, method: "classify" },
    { name: "models.generateImages", modelType: "image", model: imageModel, method: "generateImages" },
  ] as const)("preserves $name errors and does not call the provider after cancellation", async item => {
    const modelCall = vi.fn(async () => { throw new Error("fixture provider unavailable"); });
    const modelRegistry = registry({
      classify: item.method === "classify" ? modelCall : vi.fn(),
      generateImages: item.method === "generateImages" ? modelCall : vi.fn(),
    });
    const globals = createCodemodeModelGlobals({ modelRegistry });
    const global = globals.find(candidate => candidate.name === item.name)!;
    const input = item.method === "classify" ? context() : { input: [{ type: "text", text: "fixture image" }] };
    const failed = await global.execute([
      { provider: item.model.provider, id: item.model.id }, input,
    ], { signal: new AbortController().signal } satisfies CodemodeToolContext);
    expect(failed).toMatchObject({ stopReason: "error", errorMessage: "fixture provider unavailable" });

    modelCall.mockClear();
    const controller = new AbortController();
    controller.abort(new Error("Codemode cancelled"));
    const cancelled = await global.execute([
      { provider: item.model.provider, id: item.model.id }, input,
    ], { signal: controller.signal } satisfies CodemodeToolContext);
    expect(cancelled).toMatchObject({ stopReason: "aborted" });
    expect(modelCall).not.toHaveBeenCalled();
  });

  it("limits parallel classifier and image requests to four", async () => {
    let release!: () => void;
    let resolveFourth!: () => void;
    const released = new Promise<void>(resolve => { release = resolve; });
    const fourthStarted = new Promise<void>(resolve => { resolveFourth = resolve; });
    let active = 0;
    let maximum = 0;
    const modelCall = vi.fn(async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 4) resolveFourth();
      await released;
      active -= 1;
      return classifierResult;
    });
    const modelRegistry = registry({ classify: modelCall });
    const classify = createCodemodeModelGlobals({ modelRegistry }).find(global => global.name === "models.classify")!;
    const calls = Promise.all(Array.from({ length: 5 }, () => classify.execute([
      { provider: classifier.provider, id: classifier.id }, context(),
    ], { signal: new AbortController().signal } satisfies CodemodeToolContext)));

    await fourthStarted;
    expect(active).toBe(4);
    release();
    await calls;
    expect(maximum).toBe(4);
  });
});
