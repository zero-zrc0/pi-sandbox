import { describe, expect, it } from "vitest";
import { captureModel } from "../../src/approve-core/nodes/llm-approver/profile";
import type { LlmReviewerProfile } from "../../src/approve-core/nodes/llm-approver/types";
import type { Api, Model } from "@earendil-works/pi-ai";

describe("reviewer model snapshot", () => {
  it("accepts registry models with unset optional fields", () => {
    const model = { id: "model", provider: "provider", api: "openai-completions", contextWindow: 1000,
      maxTokens: 100, headers: undefined, compat: { optional: undefined } } as unknown as Model<Api>;
    const profile = { modelId: "model", provider: "provider", contextWindowTokens: 1000,
      maxOutputTokens: 100 } as LlmReviewerProfile;
    expect(captureModel(model, profile)).toMatchObject({ id: "model", compat: {} });
  });
});
