import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyChatEndpoint,
  listModelsJsonProviders,
  mergeChatEndpoint,
  mergeModelsJsonEndpoint,
  modelsJsonProviderIds,
} from "#config/models-json";

describe("mergeModelsJsonEndpoint", () => {
  it("creates the provider entry on an empty document", () => {
    const result = mergeModelsJsonEndpoint({}, "typesafe", { apiKey: "secret" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc).toEqual({ providers: { typesafe: { apiKey: "secret" } } });
  });

  it("preserves unrelated providers and keys", () => {
    const doc = {
      $schema: "https://pi.dev/schemas/models.schema.json",
      providers: {
        ollama: { baseUrl: "http://localhost:11434/v1", models: [{ id: "qwen2.5-coder:7b" }] },
      },
    };
    const result = mergeModelsJsonEndpoint(doc, "typesafe", { baseUrl: "https://custom.example" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.$schema).toBe(doc.$schema);
    expect(result.doc.providers).toEqual({
      ollama: doc.providers.ollama,
      typesafe: { baseUrl: "https://custom.example" },
    });
    // The input document is not mutated.
    expect((doc.providers as Record<string, unknown>).typesafe).toBeUndefined();
  });

  it("merges into an existing provider entry without dropping its fields", () => {
    const doc = { providers: { openrouter: { headers: { "X-Key": "$KEY" } } } };
    const result = mergeModelsJsonEndpoint(doc, "openrouter", { apiKey: "literal-key" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.providers).toEqual({
      openrouter: { headers: { "X-Key": "$KEY" }, apiKey: "literal-key" },
    });
  });

  it("ignores blank patch fields", () => {
    const doc = { providers: { typesafe: { baseUrl: "https://existing.example" } } };
    const result = mergeModelsJsonEndpoint(doc, "typesafe", { baseUrl: "   ", apiKey: "" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.providers).toEqual({ typesafe: { baseUrl: "https://existing.example" } });
  });

  it("does not create an empty entry for an unknown provider with a blank patch", () => {
    const result = mergeModelsJsonEndpoint({}, "typesafe", { baseUrl: "  ", apiKey: "" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc).toEqual({});
  });

  it("rejects a non-object document", () => {
    const result = mergeModelsJsonEndpoint([1, 2], "typesafe", { apiKey: "secret" });
    expect(result.ok).toBe(false);
  });

  it("rejects a non-object providers value", () => {
    const result = mergeModelsJsonEndpoint({ providers: "nope" }, "typesafe", { apiKey: "secret" });
    expect(result.ok).toBe(false);
  });

  it("rejects a non-object provider entry", () => {
    const result = mergeModelsJsonEndpoint({ providers: { typesafe: "nope" } }, "typesafe", {
      apiKey: "secret",
    });
    expect(result.ok).toBe(false);
  });
});

describe("mergeChatEndpoint", () => {
  it("overrides an existing chat provider and keeps its models", () => {
    const doc = {
      providers: {
        ollama: { baseUrl: "http://localhost:11434/v1", models: [{ id: "qwen3:8b" }] },
      },
    };
    const result = mergeChatEndpoint(doc, {
      providerId: "ollama",
      baseUrl: "https://custom.example/v1",
      apiKey: "secret",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.providers).toEqual({
      ollama: {
        baseUrl: "https://custom.example/v1",
        models: [{ id: "qwen3:8b" }],
        apiKey: "secret",
      },
    });
  });

  it("creates a new chat provider with one model and a default wire API", () => {
    const result = mergeChatEndpoint({}, {
      providerId: "my-custom-llm",
      baseUrl: "https://api.example.com/v1",
      apiKey: "secret",
      modelId: "my-model",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.providers).toEqual({
      "my-custom-llm": {
        baseUrl: "https://api.example.com/v1",
        apiKey: "secret",
        api: "openai-completions",
        models: [{ id: "my-model", name: "my-model" }],
      },
    });
  });

  it("rejects a new provider without a base URL or a model id", () => {
    expect(mergeChatEndpoint({}, { providerId: "new-one", modelId: "m" }).ok).toBe(false);
    expect(
      mergeChatEndpoint({}, { providerId: "new-one", baseUrl: "https://api.example.com/v1" }).ok,
    ).toBe(false);
  });

  it("appends a model to an existing provider without duplicating it", () => {
    const doc = {
      providers: {
        ollama: { baseUrl: "http://localhost:11434/v1", models: [{ id: "qwen3:8b" }] },
      },
    };
    const result = mergeChatEndpoint(doc, {
      providerId: "ollama",
      apiKey: "secret",
      modelId: "qwen3:8b",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc.providers).toEqual({
      ollama: { baseUrl: "http://localhost:11434/v1", models: [{ id: "qwen3:8b" }], apiKey: "secret" },
    });
    const withNewModel = mergeChatEndpoint(doc, { providerId: "ollama", modelId: "llama4:8b" });
    expect(withNewModel.ok).toBe(true);
    if (!withNewModel.ok) return;
    expect(withNewModel.doc.providers).toEqual({
      ollama: {
        baseUrl: "http://localhost:11434/v1",
        models: [{ id: "qwen3:8b" }, { id: "llama4:8b", name: "llama4:8b" }],
      },
    });
  });
});

describe("applyChatEndpoint", () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "models-json-test-"));
    file = join(dir, "models.json");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates a new provider entry in a missing file", () => {
    const result = applyChatEndpoint(file, {
      providerId: "my-custom-llm",
      baseUrl: "https://api.example.com/v1",
      apiKey: "secret",
      modelId: "my-model",
    });
    expect(result.ok).toBe(true);
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({
      providers: {
        "my-custom-llm": {
          baseUrl: "https://api.example.com/v1",
          apiKey: "secret",
          api: "openai-completions",
          models: [{ id: "my-model", name: "my-model" }],
        },
      },
    });
  });

  it("reports a corrupt file without overwriting it", () => {
    writeFileSync(file, "{ not json", "utf8");
    const result = applyChatEndpoint(file, {
      providerId: "my-custom-llm",
      baseUrl: "https://api.example.com/v1",
      modelId: "my-model",
    });
    expect(result.ok).toBe(false);
    expect(readFileSync(file, "utf8")).toBe("{ not json");
  });
});

describe("modelsJsonProviderIds", () => {
  it("lists only providers with actual configuration (non-empty entries)", () => {
    expect(modelsJsonProviderIds({
      providers: { opencode: {}, "cc-switch-kimi": { baseUrl: "https://api.kimi.com/coding/" }, sd: { baseUrl: "x", apiKey: "y" } },
    })).toEqual(["cc-switch-kimi", "sd"]);
    expect(modelsJsonProviderIds({})).toEqual([]);
    expect(modelsJsonProviderIds({ providers: "nope" })).toEqual([]);
    expect(modelsJsonProviderIds([1, 2])).toEqual([]);
  });
});

describe("listModelsJsonProviders", () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "models-json-test-"));
    file = join(dir, "models.json");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns [] when the file is missing or unparsable", () => {
    expect(listModelsJsonProviders(file)).toEqual([]);
    writeFileSync(file, "{ not json", "utf8");
    expect(listModelsJsonProviders(file)).toEqual([]);
  });

  it("returns the provider ids of an existing file", () => {
    writeFileSync(file, `${JSON.stringify({ providers: { typesafe: { apiKey: "k" } } })}\n`, "utf8");
    expect(listModelsJsonProviders(file)).toEqual(["typesafe"]);
  });
});
