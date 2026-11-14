import type { ClassifierApi, ClassifierModel } from "@earendil-works/pi-ai";
import { jsonDigest } from "../../../json";

export type DecisionClassifierProfile =
  | {
      readonly kind: "pi-classifier";
      readonly model: ClassifierModel<ClassifierApi>;
      readonly timeoutMs: number;
      readonly contextBudgetTokens: number;
      readonly allowConfidenceThreshold: number;
      readonly denyConfidenceThreshold: number;
    }
  | {
      readonly kind: "custom";
      readonly baseUrl: string;
      readonly modelId: string;
      readonly apiKey?: string;
      readonly timeoutMs: number;
      readonly contextBudgetTokens: number;
      readonly allowConfidenceThreshold: number;
      readonly denyConfidenceThreshold: number;
    };

export function decisionClassifierIdentity(
  profile: DecisionClassifierProfile | undefined,
): string {
  if (profile === undefined) return "unavailable";
  if (profile.kind === "custom") {
    return jsonDigest({
      kind: "custom",
      baseUrl: profile.baseUrl,
      model: profile.modelId,
      apiKey: profile.apiKey === undefined ? "" : "set",
      timeoutMs: profile.timeoutMs,
      contextBudgetTokens: profile.contextBudgetTokens,
      allowConfidenceThreshold: profile.allowConfidenceThreshold,
      denyConfidenceThreshold: profile.denyConfidenceThreshold,
    });
  }
  return jsonDigest({
    api: profile.model.api,
    provider: profile.model.provider,
    model: profile.model.id,
    baseUrl: profile.model.baseUrl,
    timeoutMs: profile.timeoutMs,
    contextBudgetTokens: profile.contextBudgetTokens,
    allowConfidenceThreshold: profile.allowConfidenceThreshold,
    denyConfidenceThreshold: profile.denyConfidenceThreshold,
  });
}