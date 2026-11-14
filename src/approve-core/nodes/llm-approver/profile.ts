import type { Api, Model } from "@earendil-works/pi-ai";
import type {
  LlmProjectRulesSnapshot,
  LlmReviewerProfile,
} from "#approve-core/nodes/llm-approver/types";
import { freezeJson, jsonDigest } from "../../../json";

const MAX_PROFILE_BYTES = 256 * 1024;
const MAX_MODEL_BYTES = 256 * 1024;

export function boundedInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isSafeInteger(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

export function captureProfile(value: unknown): LlmReviewerProfile | undefined {
  let captured: unknown;
  try {
    captured = freezeJson(value);
    const serialized = JSON.stringify(captured);
    if (typeof serialized !== "string" ||
        new TextEncoder().encode(serialized).byteLength > MAX_PROFILE_BYTES) {
      return undefined;
    }
  } catch {
    return undefined;
  }
  if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return undefined;
  const profile = captured as Record<string, unknown>;
  const profileKeys = [
    "provider", "modelId", "contextWindowTokens", "maxOutputTokens", "outputTokens",
    "endpointRevision", "authSubjectRevision", "protocolRevision", "projectionRevision",
    "rubric", "guidance", "framingMarginTokens",
  ];
  if (Object.keys(profile).length !== profileKeys.length ||
      profileKeys.some((key) => !(key in profile))) {
    return undefined;
  }
  for (const key of [
    "provider", "modelId", "endpointRevision", "authSubjectRevision",
    "protocolRevision", "projectionRevision", "rubric",
  ]) {
    if (typeof profile[key] !== "string" || profile[key].trim() === "") return undefined;
  }
  if (!Number.isSafeInteger(profile.contextWindowTokens) ||
      Number(profile.contextWindowTokens) < 0) {
    return undefined;
  }
  for (const key of ["maxOutputTokens", "outputTokens"]) {
    if (!Number.isSafeInteger(profile[key]) || Number(profile[key]) <= 0) return undefined;
  }
  if (!Number.isSafeInteger(profile.framingMarginTokens) ||
      Number(profile.framingMarginTokens) < 0) {
    return undefined;
  }
  if (!Array.isArray(profile.guidance)) return undefined;
  for (const entry of profile.guidance) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return undefined;
    const guidance = entry as Record<string, unknown>;
    if (
      Object.keys(guidance).length !== 4 ||
      ["path", "content", "trusted", "digest"].some((key) => !(key in guidance)) ||
      typeof guidance.path !== "string" || guidance.path.trim() === "" ||
      typeof guidance.content !== "string" ||
      typeof guidance.trusted !== "boolean" ||
      typeof guidance.digest !== "string" || guidance.digest.trim() === ""
    ) {
      return undefined;
    }
  }
  return captured as unknown as LlmReviewerProfile;
}

export function captureModel(
  value: Model<Api> | undefined,
  profile: LlmReviewerProfile,
): Model<Api> | undefined {
  if (!value) return undefined;
  let captured: unknown;
  try {
    const serializedModel = JSON.stringify(value, function (_key, entry: unknown) {
      if (entry === undefined && !Array.isArray(this)) return undefined;
      if (entry === undefined || typeof entry === "function" || typeof entry === "symbol" ||
          typeof entry === "bigint" || (typeof entry === "number" && !Number.isFinite(entry))) {
        throw new TypeError("invalid model value");
      }
      if (entry !== null && typeof entry === "object") {
        const prototype = Object.getPrototypeOf(entry);
        if ((!Array.isArray(entry) && prototype !== Object.prototype && prototype !== null) ||
            Object.getOwnPropertySymbols(entry).length > 0) throw new TypeError("invalid model object");
      }
      return entry;
    });
    captured = freezeJson(JSON.parse(serializedModel));
    const serialized = JSON.stringify(captured);
    if (typeof serialized !== "string" ||
        new TextEncoder().encode(serialized).byteLength > MAX_MODEL_BYTES) {
      return undefined;
    }
  } catch {
    return undefined;
  }
  if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return undefined;
  const model = captured as Record<string, unknown>;
  if (
    model.id !== profile.modelId ||
    model.provider !== profile.provider ||
    typeof model.api !== "string" || model.api.trim() === "" ||
    !Number.isSafeInteger(model.contextWindow) ||
    !Number.isSafeInteger(model.maxTokens) ||
    Number(model.contextWindow) < profile.contextWindowTokens ||
    Number(model.maxTokens) < profile.maxOutputTokens
  ) {
    return undefined;
  }
  return captured as unknown as Model<Api>;
}

export function captureProjectRules(
  value: LlmProjectRulesSnapshot | undefined,
): LlmProjectRulesSnapshot | undefined {
  if (value === undefined) return undefined;
  try {
    const captured = freezeJson(value) as unknown as LlmProjectRulesSnapshot;
    if (!Number.isSafeInteger(captured.rulesRevision) || captured.rulesRevision < 0) return undefined;
    if (!Number.isSafeInteger(captured.intentRevision) || captured.intentRevision < 0) return undefined;
    if (!Array.isArray(captured.rules)) return undefined;
    for (const rule of captured.rules) {
      if (
        typeof rule.id !== "string" || rule.id.trim() === "" ||
        (rule.effect !== "allow" && rule.effect !== "deny") ||
        (rule.status !== "active" && rule.status !== "needs_review" && rule.status !== "revoked") ||
        typeof rule.applicable !== "boolean" ||
        rule.match === null || typeof rule.match !== "object" || Array.isArray(rule.match)
      ) {
        return undefined;
      }
    }
    return captured;
  } catch {
    return undefined;
  }
}

/**
 * Stable reviewer identity. It covers the judge, endpoint, auth subject,
 * rubric, guidance content/trust and project-rule facts, never a credential or
 * the current leaf.
 */
export function compatibilityFingerprint(
  profile: LlmReviewerProfile,
  projectRules?: LlmProjectRulesSnapshot,
): string {
  return jsonDigest({
    provider: profile.provider,
    modelId: profile.modelId,
    endpointRevision: profile.endpointRevision,
    authSubjectRevision: profile.authSubjectRevision,
    protocolRevision: profile.protocolRevision,
    projectionRevision: profile.projectionRevision,
    rubric: profile.rubric,
    contextWindowTokens: profile.contextWindowTokens,
    maxOutputTokens: profile.maxOutputTokens,
    outputTokens: profile.outputTokens,
    framingMarginTokens: profile.framingMarginTokens,
    guidance: profile.guidance.map((entry) => ({
      path: entry.path,
      trusted: entry.trusted,
      digest: entry.digest,
      content: entry.content,
    })),
    projectRulesDigest: projectRules === undefined ? null : jsonDigest(projectRules),
  });
}
