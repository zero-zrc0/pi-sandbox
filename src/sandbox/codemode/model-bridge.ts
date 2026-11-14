import type { ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import type {
  AssistantImages,
  ClassifierApi,
  ClassifierContext,
  ClassifierModel,
  ClassifierResult,
  ImageApi,
  ImageModel,
  ImagesContext,
  ModelType,
} from "@earendil-works/pi-ai";
import type { CodemodeTool } from "@earendil-works/pi-codemode";

export interface CodemodeModelCallOptions {
  readonly displayName: string;
  readonly displayArgs: string;
}

export interface CodemodeModelGlobalsOptions {
  readonly modelRegistry: ExtensionToolContext["modelRegistry"];
  readonly runModelCall?: (
    details: CodemodeModelCallOptions,
    signal: AbortSignal,
    run: () => Promise<unknown>,
  ) => Promise<unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function modelType(value: unknown): ModelType {
  if (value === "chat" || value === "image" || value === "classifier") return value;
  throw new Error(`Unknown model type ${JSON.stringify(value)}. Use "chat", "image", or "classifier".`);
}

function optionalProvider(value: unknown): string | undefined {
  if (value == null) return undefined;
  if (typeof value !== "string") throw new Error("provider must be a string");
  return value;
}

function modelReference(value: unknown, operation: string): { provider: string; id: string } {
  if (!isRecord(value) || typeof value.provider !== "string" || typeof value.id !== "string") {
    throw new Error(`${operation}() expects a model with string provider and id`);
  }
  return { provider: value.provider, id: value.id };
}

function checkClassifierContext(value: unknown): ClassifierContext {
  if (!isRecord(value)) throw new Error("models.classify() expects a context object");
  const { state, images, questions } = value;
  if (!isRecord(state)) throw new Error("models.classify() context.state must be an object");
  if (images !== undefined && (!Array.isArray(images) || images.some(image =>
    !isRecord(image) || image.type !== "image" || typeof image.data !== "string" || typeof image.mimeType !== "string"))) {
    throw new Error("models.classify() context.images must contain image blocks");
  }
  if (!isRecord(questions) || Object.keys(questions).length === 0) {
    throw new Error("models.classify() context.questions must be a non-empty object");
  }
  const nonEmptyStrings = (items: unknown[]): boolean => items.length > 0 && items.every(item => typeof item === "string");
  for (const [id, rawQuestion] of Object.entries(questions)) {
    if (!isRecord(rawQuestion) || typeof rawQuestion.instructions !== "string") {
      throw new Error(`models.classify() context.questions.${id} must contain instructions`);
    }
    if (rawQuestion.type === "choice") {
      if (!isRecord(rawQuestion.criteria) || !nonEmptyStrings(Object.values(rawQuestion.criteria))) {
        throw new Error(`models.classify() context.questions.${id}.criteria must map labels to meanings`);
      }
    } else if (rawQuestion.type === "score") {
      if (!Array.isArray(rawQuestion.criteria) || !nonEmptyStrings(rawQuestion.criteria)) {
        throw new Error(`models.classify() context.questions.${id}.criteria must list score levels`);
      }
    } else if (rawQuestion.type === "bool") {
      if (!isRecord(rawQuestion.criteria) || typeof rawQuestion.criteria.true !== "string" ||
          typeof rawQuestion.criteria.false !== "string") {
        throw new Error(`models.classify() context.questions.${id}.criteria must define true and false meanings`);
      }
    } else {
      throw new Error(`models.classify() context.questions.${id}.type must be choice, score, or bool`);
    }
  }
  return value as unknown as ClassifierContext;
}

function checkImagesContext(value: unknown): ImagesContext {
  if (!isRecord(value) || !Array.isArray(value.input) || value.input.length === 0 || value.input.some(block =>
    !isRecord(block) ||
    !(block.type === "text" && typeof block.text === "string") &&
    !(block.type === "image" && typeof block.data === "string" && typeof block.mimeType === "string"))) {
    throw new Error("models.generateImages() context.input must be a non-empty array of text or image blocks");
  }
  return value as unknown as ImagesContext;
}

function modelInfo<T extends object>(model: T): Omit<T, "headers"> {
  const info = { ...model } as T & { headers?: unknown };
  delete info.headers;
  return info;
}

function classifierError(
  model: ClassifierModel<ClassifierApi>,
  reason: unknown,
  signal: AbortSignal,
): ClassifierResult {
  const stopReason = signal.aborted ? "aborted" : "error";
  const errorMessage = reason instanceof Error ? reason.message : String(reason);
  return { api: model.api, provider: model.provider, model: model.id, answers: {}, stopReason, errorMessage, timestamp: Date.now() };
}

function imageError(
  model: ImageModel<ImageApi>,
  reason: unknown,
  signal: AbortSignal,
): AssistantImages {
  const stopReason = signal.aborted ? "aborted" : "error";
  const errorMessage = reason instanceof Error ? reason.message : String(reason);
  return { api: model.api, provider: model.provider, model: model.id, output: [], stopReason, errorMessage, timestamp: Date.now() };
}

function createModelLimiter(limit: number) {
  let active = 0;
  const queue: Array<{ resolve: () => void; reject: (error: Error) => void; signal: AbortSignal; onAbort: () => void }> = [];

  async function acquire(signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) throw signal.reason ?? new Error("Model request aborted");
    if (active < limit) {
      active += 1;
    } else {
      await new Promise<void>((resolve, reject) => {
        const waiter = {
          resolve,
          reject,
          signal,
          onAbort: () => {
            const index = queue.indexOf(waiter);
            if (index >= 0) queue.splice(index, 1);
            reject(signal.reason instanceof Error ? signal.reason : new Error("Model request aborted"));
          },
        };
        queue.push(waiter);
        signal.addEventListener("abort", waiter.onAbort, { once: true });
      });
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = queue.shift();
      if (next) {
        next.signal.removeEventListener("abort", next.onAbort);
        next.resolve();
      } else active -= 1;
    };
  }

  return async <T>(signal: AbortSignal, run: () => Promise<T>): Promise<T> => {
    const release = await acquire(signal);
    try {
      return await run();
    } finally {
      release();
    }
  };
}

export function createCodemodeModelGlobals(options: CodemodeModelGlobalsOptions): CodemodeTool[] {
  const models = options.modelRegistry;
  const limitModelCalls = createModelLimiter(4);
  const runModelCall = (displayName: string, displayArgs: string, signal: AbortSignal, run: () => Promise<unknown>) =>
    options.runModelCall?.({ displayName, displayArgs }, signal, run) ?? run();

  const runClassifier = async (args: unknown[], signal: AbortSignal): Promise<ClassifierResult> => {
    const [given, rawContext] = args;
    const reference = modelReference(given, "models.classify");
    const model = models.getModelOfType("classifier", reference.provider, reference.id);
    if (!model) throw new Error(`Unknown classifier model "${reference.provider}/${reference.id}"`);
    const classifier = model as ClassifierModel<ClassifierApi>;
    const context = checkClassifierContext(rawContext);
    try {
      return await limitModelCalls(signal, () => runModelCall(
        "models.classify",
        `${reference.provider}/${reference.id}`,
        signal,
        async () => {
          try {
            if (signal.aborted) throw signal.reason ?? new Error("Model request aborted");
            return await models.classify(classifier, context, { signal });
          } catch (error) {
            return classifierError(classifier, error, signal);
          }
        },
      ) as Promise<ClassifierResult>);
    } catch (error) {
      return classifierError(classifier, error, signal);
    }
  };

  const runImages = async (args: unknown[], signal: AbortSignal): Promise<AssistantImages> => {
    const [given, rawContext] = args;
    const reference = modelReference(given, "models.generateImages");
    const model = models.getModelOfType("image", reference.provider, reference.id);
    if (!model) throw new Error(`Unknown image model "${reference.provider}/${reference.id}"`);
    const image = model as ImageModel<ImageApi>;
    const context = checkImagesContext(rawContext);
    try {
      return await limitModelCalls(signal, () => runModelCall(
        "models.generateImages",
        `${reference.provider}/${reference.id}`,
        signal,
        async () => {
          try {
            if (signal.aborted) throw signal.reason ?? new Error("Model request aborted");
            return await models.generateImages(image, context, { signal });
          } catch (error) {
            return imageError(image, error, signal);
          }
        },
      ) as Promise<AssistantImages>);
    } catch (error) {
      return imageError(image, error, signal);
    }
  };

  return [
    {
      name: "models.getModelsOfType",
      spread: true,
      execute: (args, { signal }) => {
        const [type, provider] = args as unknown[];
        const resolvedType = modelType(type);
        const resolvedProvider = optionalProvider(provider);
        return runModelCall("models.getModelsOfType", `${resolvedType}${resolvedProvider === undefined ? "" : ` ${resolvedProvider}`}`, signal, async () =>
          models.getModelsOfType(resolvedType, resolvedProvider).map(modelInfo));
      },
    },
    {
      name: "models.getAvailableOfType",
      spread: true,
      execute: (args, { signal }) => {
        const [type, provider] = args as unknown[];
        const resolvedType = modelType(type);
        const resolvedProvider = optionalProvider(provider);
        return runModelCall("models.getAvailableOfType", `${resolvedType}${resolvedProvider === undefined ? "" : ` ${resolvedProvider}`}`, signal, async () =>
          (await models.getAvailableOfType(resolvedType, resolvedProvider, { signal })).map(modelInfo));
      },
    },
    {
      name: "models.getModelOfType",
      spread: true,
      execute: (args, { signal }) => {
        const [type, provider, id] = args as unknown[];
        const resolvedType = modelType(type);
        if (typeof provider !== "string" || typeof id !== "string") {
          throw new Error("models.getModelOfType(type, provider, id) expects three strings");
        }
        return runModelCall("models.getModelOfType", `${provider}/${id}`, signal, async () => {
          const model = models.getModelOfType(resolvedType, provider, id);
          return model === undefined ? undefined : modelInfo(model);
        });
      },
    },
    {
      name: "models.classify",
      spread: true,
      execute: (args, { signal }) => runClassifier(args as unknown[], signal),
    },
    {
      name: "models.generateImages",
      spread: true,
      execute: (args, { signal }) => runImages(args as unknown[], signal),
    },
  ];
}
