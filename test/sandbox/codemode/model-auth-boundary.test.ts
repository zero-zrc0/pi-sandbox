import {
  InMemoryCredentialStore,
  type ClassifierModel,
  type OAuthCredential,
} from "@earendil-works/pi-ai";
import { createModels, createProvider } from "@earendil-works/pi-ai/models";
import { describe, expect, it, vi } from "vitest";

describe("Pi model auth boundary", () => {
  it("refreshes OAuth before applying the provider request fetch hook", async () => {
    const order: string[] = [];
    const credentials = new InMemoryCredentialStore();
    const models = createModels({ credentials });
    const model: ClassifierModel<"fixture-classifier"> = {
      type: "classifier",
      id: "classifier",
      name: "Classifier",
      provider: "fixture-oauth",
      api: "fixture-classifier",
      baseUrl: "https://model.example.test/v1",
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 1024,
    };
    const provider = createProvider({
      id: "fixture-oauth",
      baseUrl: model.baseUrl,
      auth: {
        oauth: {
          name: "Fixture OAuth",
          async login() {
            return { type: "oauth", refresh: "refresh", access: "access", expires: Date.now() + 60_000 };
          },
          async refresh(credential) {
            await fetch("https://auth.example.test/token");
            order.push("oauth-refresh");
            return { ...credential, access: "refreshed", expires: Date.now() + 60_000 };
          },
          async toAuth() {
            return { apiKey: "fixture-token" };
          },
        },
      },
      models: [model],
      classifiers: {
        "fixture-classifier": {
          async classify(_model, _context, options) {
            await options?.fetch?.("https://model.example.test/classify");
            order.push("provider-request");
            return {
              api: "fixture-classifier",
              provider: "fixture-oauth",
              model: "classifier",
              answers: {},
              stopReason: "stop",
              timestamp: Date.now(),
            };
          },
        },
      },
    });
    models.setProvider(provider);
    await credentials.modify("fixture-oauth", async () => ({
      type: "oauth",
      refresh: "refresh",
      access: "expired",
      expires: Date.now() - 1,
    } satisfies OAuthCredential));

    const available = await models.getAvailableOfType("classifier", "fixture-oauth");

    expect(available.map((entry) => entry.id)).toEqual(["classifier"]);
    expect(order).toEqual([]);

    const defaultFetch = vi.fn(async () => {
      order.push("global-fetch");
      return new Response("auth");
    });
    const providerFetch = vi.fn(async (_input: RequestInfo | URL) => new Response("model"));
    vi.stubGlobal("fetch", defaultFetch);
    try {
      await models.classify(model, { state: { fixture: true }, questions: {} }, {
        fetch: async (input) => {
          order.push("custom-fetch");
          return providerFetch(input);
        },
      });
    } finally {
      vi.unstubAllGlobals();
    }

    expect(order).toEqual(["global-fetch", "oauth-refresh", "custom-fetch", "provider-request"]);
    expect(defaultFetch).toHaveBeenCalledWith("https://auth.example.test/token");
    expect(providerFetch).toHaveBeenCalledWith("https://model.example.test/classify");
  });

  it("runs provider API-key resolution from availability without a fetch override", async () => {
    const defaultFetch = vi.fn(async () => new Response("auth"));
    const credentials = new InMemoryCredentialStore();
    const models = createModels({ credentials });
    const model: ClassifierModel<"fixture-classifier"> = {
      type: "classifier",
      id: "classifier",
      name: "Classifier",
      provider: "fixture-api-key",
      api: "fixture-classifier",
      baseUrl: "https://model.example.test/v1",
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 1024,
    };
    models.setProvider(createProvider({
      id: "fixture-api-key",
      auth: {
        apiKey: {
          name: "Fixture API key",
          async resolve() {
            await fetch("https://auth.example.test/check");
            return { auth: { apiKey: "fixture-key" } };
          },
        },
      },
      models: [model],
      classifiers: {
        "fixture-classifier": {
          async classify() {
            return {
              api: "fixture-classifier",
              provider: "fixture-api-key",
              model: "classifier",
              answers: {},
              stopReason: "stop",
              timestamp: Date.now(),
            };
          },
        },
      },
    }));
    vi.stubGlobal("fetch", defaultFetch);
    try {
      const available = await models.getAvailableOfType("classifier", "fixture-api-key");
      expect(available.map((entry) => entry.id)).toEqual(["classifier"]);
      expect(defaultFetch).toHaveBeenCalledWith("https://auth.example.test/check");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
