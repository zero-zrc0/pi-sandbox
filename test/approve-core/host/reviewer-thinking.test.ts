import { describe, expect, it } from "vitest";
import type { Api, Model } from "@earendil-works/pi-ai";
import { reviewerThinking } from "../../../src/approve-core/host/reviewer-thinking";

describe("reviewer thinking", () => {
  it("turns thinking off when the model supports it", () => {
    expect(reviewerThinking({ reasoning: true } as Model<Api>)).toBeUndefined();
  });

  it("uses low when the model cannot turn thinking off", () => {
    expect(reviewerThinking({ reasoning: true, thinkingLevelMap: { off: null, minimal: null, low: "low" } } as Model<Api>)).toBe("low");
  });

  it("chooses the lowest supported level when low is unavailable", () => {
    expect(reviewerThinking({ reasoning: true, thinkingLevelMap: { off: null, low: null } } as Model<Api>)).toBe("minimal");
  });
});
