/**
 * Model-node assembly tests (specs/host-integration.md §5).
 *
 * The assembly is a pure composition seam: node factories and the model
 * registry are injected ports. Tests capture the dependency objects the
 * factories receive and drive their resolvers directly, so no chain run,
 * transport call or real registry is ever involved.
 */
import { describe, expect, it, vi } from "vitest";
import type {
  Api,
  ClassifierApi,
  ClassifierModel,
  Model,
} from "@earendil-works/pi-ai";
import type { EffectiveNode } from "#approve-core/contracts";
import type { ChainNode } from "#approve-core/runtime";
import type {
  LlmApproverNodeDependencies,
  LlmCompleteFn,
  LlmGuidance,
  LlmReviewerProfile,
} from "#approve-core/nodes/llm-approver/types";
import type { DecisionApproverNodeDependencies } from "#approve-core/nodes/decision-approver/types";
import type {
  ReviewerContextStore,
  ReviewerLearningLifecycle,
  ReviewerMode,
  ReviewerSessionFacts,
  ReviewRevisions,
  ReviewView,
} from "#approve-core/context/types";
import { reviewDigest } from "#approve-core/context/types";
import {
  assembleModelNodes,
  type ApproverConfig,
  type ModelAssemblyInput,
  type ModelNodeAssembly,
  type ModelNodeEvent,
  type ProjectRulesPort,
} from "#approve-core/host/model-nodes";

// ---------------------------------------------------------------------------
// Domain fixtures
// ---------------------------------------------------------------------------

const OWNER = "owner-1";
const MODE: ReviewerMode = "auto-review";

const VIEW: ReviewView = {
  owner: OWNER,
  sessionId: "session-1",
  historyVersion: 3,
  captureSeq: 7,
  leafId: "leaf-1",
  branchRootId: "root-1",
  transcript: [],
  authorization: [],
  degraded: false,
};

const CONTEXT = {} as unknown as ReviewerContextStore;

function effectiveNode(
  id: string,
  enabled: boolean,
  overrides: Partial<EffectiveNode> = {},
): EffectiveNode {
  return {
    id,
    source: "builtin",
    position: "post",
    order: 0,
    enabled,
    priority: null,
    ...overrides,
  };
}

interface FakeNode extends ChainNode {
  dispose: () => void;
}

function fakeNode(id: string, dispose?: () => void): FakeNode {
  return {
    apiVersion: "1",
    id,
    evaluate: () => ({ decisions: [] }),
    dispose: dispose ?? vi.fn(),
  };
}

function modelOf(overrides: Partial<Model<Api>> = {}): Model<Api> {
  return {
    id: "approver-model",
    name: "Approver Model",
    api: "anthropic-messages",
    provider: "anthropic",
    baseUrl: "https://api.example.test",
    input: ["text"],
    cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
    reasoning: false,
    contextWindow: 200_000,
    maxTokens: 8_192,
    ...overrides,
  };
}

function classifierModelOf(
  overrides: Partial<ClassifierModel<ClassifierApi>> = {},
): ClassifierModel<ClassifierApi> {
  return {
    id: "classifier-model",
    name: "Classifier Model",
    api: "typesafe-system-one",
    provider: "typesafe",
    baseUrl: "https://classifier.example.test",
    input: ["text"],
    cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
    type: "classifier",
    contextWindow: 16_384,
    ...overrides,
  };
}

interface HarnessOptions {
  readonly generation?: number;
  readonly effectiveNodes?: readonly EffectiveNode[];
  readonly approver?: ApproverConfig;
  readonly models?: Readonly<Record<string, Model<Api>>>;
  readonly classifiers?: Readonly<Record<string, ClassifierModel<ClassifierApi>>>;
  readonly currentModel?: { readonly provider: string; readonly modelId: string };
  readonly rubric?: string;
  readonly guidance?: readonly LlmGuidance[];
  readonly onEvent?: (event: ModelNodeEvent) => void;
  readonly complete?: LlmApproverNodeDependencies["complete"];
  readonly classify?: ModelAssemblyInput["classify"];
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly learning?: NonNullable<ModelAssemblyInput["learning"]>;
  readonly projectRules?: NonNullable<ModelAssemblyInput["projectRules"]>;
  readonly resolveSession?: LlmApproverNodeDependencies["resolveSession"];
  readonly verifyFacts?: LlmApproverNodeDependencies["verifyFacts"];
  readonly llmDispose?: () => void;
  readonly decisionDispose?: () => void;
}

interface Harness {
  readonly input: ModelAssemblyInput;
  readonly assembly: ModelNodeAssembly;
  readonly llmDeps: () => LlmApproverNodeDependencies;
  readonly decisionDeps: () => DecisionApproverNodeDependencies;
  readonly llmNode: () => FakeNode;
  readonly decisionNode: () => FakeNode;
  readonly find: ReturnType<typeof vi.fn>;
  readonly findClassifier: ReturnType<typeof vi.fn>;
  readonly createLlmNode: ReturnType<typeof vi.fn>;
  readonly createDecisionNode: ReturnType<typeof vi.fn>;
}

const BOTH_ENABLED: readonly EffectiveNode[] = [
  effectiveNode("builtin/llm-approver", true, { order: 1 }),
  effectiveNode("builtin/decision-approver", true, { order: 2 }),
];

function harness(options: HarnessOptions = {}): Harness {
  const models = options.models ?? {};
  const classifiers = options.classifiers ?? {};
  const find = vi.fn((provider: string, modelId: string) => models[`${provider}/${modelId}`]);
  const findClassifier = vi.fn((provider: string, modelId: string) =>
    classifiers[`${provider}/${modelId}`],
  );

  let llmDeps: LlmApproverNodeDependencies | undefined;
  let decisionDeps: DecisionApproverNodeDependencies | undefined;
  let llmNode: FakeNode | undefined;
  let decisionNode: FakeNode | undefined;

  const createLlmNode = vi.fn((deps: LlmApproverNodeDependencies) => {
    llmDeps = deps;
    llmNode = fakeNode("builtin/llm-approver", options.llmDispose);
    return llmNode;
  });
  const createDecisionNode = vi.fn((deps: DecisionApproverNodeDependencies) => {
    decisionDeps = deps;
    decisionNode = fakeNode("builtin/decision-approver", options.decisionDispose);
    return decisionNode;
  });

  const input: ModelAssemblyInput = {
    generation: options.generation ?? 3,
    effectiveNodes: options.effectiveNodes ?? BOTH_ENABLED,
    approver: options.approver ?? { provider: "anthropic", modelId: "approver-model" },
    registry: { find, findClassifier },
    context: CONTEXT,
    resolveSession:
      options.resolveSession ?? (() => Promise.reject(new Error("session is not exercised"))),
    verifyFacts: options.verifyFacts ?? (() => false),
    complete: options.complete ?? (() => Promise.reject(new Error("complete is not exercised"))),
    classify: options.classify ?? (() => Promise.reject(new Error("classify is not exercised"))),
    createLlmNode,
    createDecisionNode,
    ...(options.currentModel === undefined ? {} : { currentModel: options.currentModel }),
    ...(options.rubric === undefined ? {} : { rubric: options.rubric }),
    ...(options.guidance === undefined ? {} : { guidance: options.guidance }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.learning === undefined ? {} : { learning: options.learning }),
    ...(options.projectRules === undefined ? {} : { projectRules: options.projectRules }),
    ...(options.onEvent === undefined ? {} : { onEvent: options.onEvent }),
  };

  const assembly = assembleModelNodes(input);
  return {
    input,
    assembly,
    llmDeps: () => {
      if (llmDeps === undefined) throw new Error("llm node was not created");
      return llmDeps;
    },
    decisionDeps: () => {
      if (decisionDeps === undefined) throw new Error("decision node was not created");
      return decisionDeps;
    },
    llmNode: () => {
      if (llmNode === undefined) throw new Error("llm node was not created");
      return llmNode;
    },
    decisionNode: () => {
      if (decisionNode === undefined) throw new Error("decision node was not created");
      return decisionNode;
    },
    find,
    findClassifier,
    createLlmNode,
    createDecisionNode,
  };
}

function profileOf(h: Harness): LlmReviewerProfile {
  const profile = h.llmDeps().resolveProfile({ owner: OWNER, mode: MODE, view: VIEW });
  if (profile === undefined) throw new Error("profile is unavailable");
  return profile;
}

// ---------------------------------------------------------------------------
// Enabled state comes only from the effective node configuration (§5)
// ---------------------------------------------------------------------------

describe("assembly enabled state", () => {
  it("binds only the enabled model node and keeps post/null positions", () => {
    const h = harness({
      generation: 9,
      effectiveNodes: [
        effectiveNode("builtin/llm-approver", true),
        effectiveNode("builtin/decision-approver", false),
      ],
    });

    expect(h.assembly.generation).toBe(9);
    expect(h.assembly.nodes).toHaveLength(1);
    expect(h.assembly.nodes[0]?.position).toBe("post");
    expect(h.assembly.nodes[0]?.priority).toBeNull();
    expect(h.assembly.nodes[0]?.node.id).toBe("builtin/llm-approver");
    expect(h.createLlmNode).toHaveBeenCalledTimes(1);
    expect(h.createDecisionNode).not.toHaveBeenCalled();
  });

  it("binds nothing when no model node is enabled", () => {
    const h = harness({
      effectiveNodes: [
        effectiveNode("builtin/llm-approver", false),
        effectiveNode("builtin/decision-approver", false, { order: 2 }),
      ],
    });

    expect(h.assembly.nodes).toEqual([]);
    expect(h.createLlmNode).not.toHaveBeenCalled();
    expect(h.createDecisionNode).not.toHaveBeenCalled();
  });

  it("treats a model node missing from the configuration as disabled", () => {
    const h = harness({
      effectiveNodes: [effectiveNode("builtin/mode", true)],
    });

    expect(h.assembly.nodes).toEqual([]);
    expect(h.createLlmNode).not.toHaveBeenCalled();
    expect(h.createDecisionNode).not.toHaveBeenCalled();
  });

  it("keeps the effective configuration order across both model nodes", () => {
    const h = harness({
      effectiveNodes: [
        effectiveNode("builtin/decision-approver", true, { order: 1 }),
        effectiveNode("builtin/llm-approver", true, { order: 2 }),
      ],
    });

    expect(h.assembly.nodes.map((binding) => binding.node.id)).toEqual([
      "builtin/decision-approver",
      "builtin/llm-approver",
    ]);
    expect(h.assembly.nodes.every((binding) => binding.position === "post")).toBe(true);
    expect(h.assembly.nodes.every((binding) => binding.priority === null)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// LLM judge precedence: judge pair, then approver pair, then current model (§5)
// ---------------------------------------------------------------------------

const LLM_ONLY: readonly EffectiveNode[] = [effectiveNode("builtin/llm-approver", true)];
const JUDGE_MODEL = modelOf({
  id: "judge-model",
  provider: "openai",
  api: "openai-completions",
  baseUrl: "https://judge.example.test",
  contextWindow: 128_000,
  maxTokens: 4_096,
});
const APPROVER_MODEL = modelOf();
const CURRENT_MODEL = modelOf({
  id: "current-model",
  provider: "current-provider",
  baseUrl: "https://current.example.test",
});

function judgeProfile(h: Harness): LlmReviewerProfile | undefined {
  return h.llmDeps().resolveProfile({ owner: OWNER, mode: MODE, view: VIEW });
}

describe("llm judge precedence", () => {
  it("prefers the explicit pi-model judge pair", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: {
        provider: "anthropic",
        modelId: "approver-model",
        judge: { kind: "pi-model", provider: "openai", modelId: "judge-model" },
      },
      models: {
        "openai/judge-model": JUDGE_MODEL,
        "anthropic/approver-model": APPROVER_MODEL,
      },
    });

    const profile = judgeProfile(h);
    expect(profile?.provider).toBe("openai");
    expect(profile?.modelId).toBe("judge-model");
    expect(h.find.mock.calls).toEqual([["openai", "judge-model"]]);
  });

  it("falls back to the approver pair when the judge is a classifier", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: {
        provider: "anthropic",
        modelId: "approver-model",
        judge: { kind: "pi-classifier", provider: "typesafe", modelId: "classifier-model" },
      },
      models: { "anthropic/approver-model": APPROVER_MODEL },
    });

    const profile = judgeProfile(h);
    expect(profile?.provider).toBe("anthropic");
    expect(profile?.modelId).toBe("approver-model");
    expect(h.find.mock.calls).toEqual([["anthropic", "approver-model"]]);
  });

  it("falls back to the approver pair when the pi-model judge pair is incomplete", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: {
        provider: "anthropic",
        modelId: "approver-model",
        judge: { kind: "pi-model", provider: "openai" },
      },
      models: { "anthropic/approver-model": APPROVER_MODEL },
    });

    expect(judgeProfile(h)?.modelId).toBe("approver-model");
    expect(h.find.mock.calls).toEqual([["anthropic", "approver-model"]]);
  });

  it("prefers the approver pair over the current model", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      currentModel: { provider: "current-provider", modelId: "current-model" },
      models: {
        "anthropic/approver-model": APPROVER_MODEL,
        "current-provider/current-model": CURRENT_MODEL,
      },
    });

    expect(judgeProfile(h)?.provider).toBe("anthropic");
    expect(h.find.mock.calls).toEqual([["anthropic", "approver-model"]]);
  });

  it("falls back to the host current model when no configured pair exists", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: {},
      currentModel: { provider: "current-provider", modelId: "current-model" },
      models: { "current-provider/current-model": CURRENT_MODEL },
    });

    const profile = judgeProfile(h);
    expect(profile?.provider).toBe("current-provider");
    expect(profile?.modelId).toBe("current-model");
    expect(h.find.mock.calls).toEqual([["current-provider", "current-model"]]);
  });

  it("answers no profile when no pair can be resolved", () => {
    const h = harness({ effectiveNodes: LLM_ONLY, approver: {} });

    expect(judgeProfile(h)).toBeUndefined();
    expect(h.find).not.toHaveBeenCalled();
  });

  it("is lazy: the registry is read per evaluation, never at assembly", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
    });

    expect(h.find).not.toHaveBeenCalled();
    const profile = judgeProfile(h);
    expect(h.find.mock.calls).toEqual([["anthropic", "approver-model"]]);
    expect(h.llmDeps().resolveModel(profile as LlmReviewerProfile)).toBe(APPROVER_MODEL);
    expect(h.find.mock.calls).toEqual([
      ["anthropic", "approver-model"],
      ["anthropic", "approver-model"],
    ]);
  });

  it("answers no profile when the resolved pair is absent from the registry", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "missing-model" },
    });

    expect(judgeProfile(h)).toBeUndefined();
    expect(h.find.mock.calls).toEqual([["anthropic", "missing-model"]]);
    expect(h.findClassifier).not.toHaveBeenCalled();
  });
});

describe("llm profile capacity", () => {
  it.each([
    ["zero", 0],
    ["negative", -1],
    ["fractional", 12.5],
    ["NaN", Number.NaN],
    ["missing", undefined],
  ])("rejects a model with a %s context window", (_label, contextWindow) => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: {
        "anthropic/approver-model": modelOf({ contextWindow: contextWindow as number }),
      },
    });

    expect(judgeProfile(h)).toBeUndefined();
  });

  it("does not fall through to a lower-precedence pair when the chosen model is unusable", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: {
        provider: "anthropic",
        modelId: "approver-model",
        judge: { kind: "pi-model", provider: "openai", modelId: "judge-model" },
      },
      models: {
        "openai/judge-model": modelOf({ id: "judge-model", provider: "openai", contextWindow: 0 }),
        "anthropic/approver-model": APPROVER_MODEL,
      },
    });

    expect(judgeProfile(h)).toBeUndefined();
    expect(h.find.mock.calls).toEqual([["openai", "judge-model"]]);
  });
});

// ---------------------------------------------------------------------------
// Output budget comes from the model only (§5; config-schema has no such field)
// ---------------------------------------------------------------------------

describe("llm profile output budget", () => {
  it("caps the reserved output at 4096 while keeping the model output limit", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: {
        "anthropic/approver-model": modelOf({ contextWindow: 300_000, maxTokens: 200_000 }),
      },
    });

    const profile = profileOf(h);
    expect(profile.maxOutputTokens).toBe(200_000);
    expect(profile.outputTokens).toBe(4_096);
  });

  it("reserves no more than the model output limit when that is smaller", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": modelOf({ maxTokens: 1_000 }) },
    });

    const profile = profileOf(h);
    expect(profile.maxOutputTokens).toBe(1_000);
    expect(profile.outputTokens).toBe(1_000);
  });

  it.each([
    ["zero", 0],
    ["negative", -1],
    ["fractional", 12.5],
    ["NaN", Number.NaN],
    ["missing", undefined],
  ])("treats a %s model output limit as unusable and lets the node fall back", (_label, maxTokens) => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": modelOf({ maxTokens: maxTokens as number }) },
    });

    // The llm node's model capture requires an integer output limit that can
    // cover the profile, so there is no usable judge profile for such a model.
    expect(judgeProfile(h)).toBeUndefined();
  });

  it("keeps framingMarginTokens at zero because no configuration owns it yet", () => {
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
    });

    expect(profileOf(h).framingMarginTokens).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Reviewer identity revisions digest the documented dimensions only (§5)
// ---------------------------------------------------------------------------

const BASE_MODEL = modelOf();

function profileForModel(
  model: Model<Api>,
  options: Partial<Omit<HarnessOptions, "models" | "approver" | "effectiveNodes">> = {},
): LlmReviewerProfile {
  const h = harness({
    ...options,
    effectiveNodes: LLM_ONLY,
    approver: { provider: model.provider, modelId: model.id },
    models: { [`${model.provider}/${model.id}`]: model },
  });
  return profileOf(h);
}

function identityOf(profile: LlmReviewerProfile) {
  return {
    endpoint: profile.endpointRevision,
    authSubject: profile.authSubjectRevision,
    protocol: profile.protocolRevision,
    projection: profile.projectionRevision,
  };
}

describe("llm profile identity revisions", () => {
  it("digests the documented dimension fields", () => {
    const profile = profileForModel(BASE_MODEL);

    expect(profile.endpointRevision).toBe(
      reviewDigest({ api: BASE_MODEL.api, baseUrl: BASE_MODEL.baseUrl }),
    );
    expect(profile.authSubjectRevision).toBe(
      reviewDigest({ provider: BASE_MODEL.provider, modelId: BASE_MODEL.id }),
    );
    expect(profile.protocolRevision).toBe(reviewDigest({ api: BASE_MODEL.api }));
    expect(profile.projectionRevision).toBe(
      reviewDigest({
        contextWindow: BASE_MODEL.contextWindow,
        maxTokens: BASE_MODEL.maxTokens,
      }),
    );
    expect(new Set(Object.values(identityOf(profile))).size).toBe(4);
  });

  it("changes the endpoint revision for an API identity change", () => {
    const base = identityOf(profileForModel(BASE_MODEL));

    const moved = identityOf(
      profileForModel({ ...BASE_MODEL, baseUrl: "https://moved.example.test" }),
    );
    expect(moved.endpoint).not.toBe(base.endpoint);
    expect(moved.authSubject).toBe(base.authSubject);
    expect(moved.protocol).toBe(base.protocol);
    expect(moved.projection).toBe(base.projection);

    const switched = identityOf(
      profileForModel({ ...BASE_MODEL, api: "openai-completions" }),
    );
    expect(switched.endpoint).not.toBe(base.endpoint);
    expect(switched.authSubject).toBe(base.authSubject);
    expect(switched.protocol).not.toBe(base.protocol);
    expect(switched.projection).toBe(base.projection);
  });

  it("changes the auth subject revision for a registry identity change", () => {
    const base = identityOf(profileForModel(BASE_MODEL));

    const provider = identityOf(
      profileForModel({ ...BASE_MODEL, provider: "openai" }),
    );
    expect(provider.authSubject).not.toBe(base.authSubject);
    expect(provider.endpoint).toBe(base.endpoint);
    expect(provider.protocol).toBe(base.protocol);
    expect(provider.projection).toBe(base.projection);

    const model = identityOf(profileForModel({ ...BASE_MODEL, id: "other-model" }));
    expect(model.authSubject).not.toBe(base.authSubject);
    expect(model.endpoint).toBe(base.endpoint);
    expect(model.protocol).toBe(base.protocol);
    expect(model.projection).toBe(base.projection);
  });

  it("changes the projection revision for window or output-limit changes", () => {
    const base = identityOf(profileForModel(BASE_MODEL));

    const window = identityOf(
      profileForModel({ ...BASE_MODEL, contextWindow: 100_000 }),
    );
    expect(window.projection).not.toBe(base.projection);
    expect(window.endpoint).toBe(base.endpoint);
    expect(window.authSubject).toBe(base.authSubject);
    expect(window.protocol).toBe(base.protocol);

    const limit = identityOf(profileForModel({ ...BASE_MODEL, maxTokens: 4_096 }));
    expect(limit.projection).not.toBe(base.projection);
    expect(limit.endpoint).toBe(base.endpoint);
    expect(limit.authSubject).toBe(base.authSubject);
    expect(limit.protocol).toBe(base.protocol);
  });

  it("ignores model fields that carry no reviewer identity", () => {
    const base = identityOf(profileForModel(BASE_MODEL));
    const renamed = identityOf(
      profileForModel({ ...BASE_MODEL, name: "Renamed Model", reasoning: true }),
    );

    expect(renamed).toEqual(base);
  });
});

// ---------------------------------------------------------------------------
// Rubric, guidance and framing margin defaults (§5)
// ---------------------------------------------------------------------------

const GUIDANCE: readonly LlmGuidance[] = [
  { path: "AGENTS.md", content: "Prefer small diffs.", trusted: true, digest: "digest-1" },
  { path: "docs/review.md", content: "Ask before pushing.", trusted: false, digest: "digest-2" },
];

describe("llm profile rubric and guidance", () => {
  it("uses the configured rubric verbatim", () => {
    const profile = profileForModel(BASE_MODEL, { rubric: "Custom rubric." });
    expect(profile.rubric).toBe("Custom rubric.");
  });

  it("falls back to a stable non-empty default rubric", () => {
    const first = profileForModel(BASE_MODEL);
    const second = profileForModel(BASE_MODEL);

    expect(first.rubric.trim()).not.toBe("");
    expect(second.rubric).toBe(first.rubric);
    expect(first.rubric).not.toBe("Custom rubric.");
  });

  it("passes configured guidance through and defaults to an empty list", () => {
    const withGuidance = profileForModel(BASE_MODEL, { guidance: GUIDANCE });
    expect(withGuidance.guidance).toEqual(GUIDANCE);

    const withoutGuidance = profileForModel(BASE_MODEL);
    expect(withoutGuidance.guidance).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Decision classifier profile: only a pi-classifier judge, defaults filled (§5)
// ---------------------------------------------------------------------------

const DECISION_ONLY: readonly EffectiveNode[] = [
  effectiveNode("builtin/decision-approver", true),
];
const CLASSIFIER_MODEL = classifierModelOf();
const CLASSIFIER_JUDGE: ApproverConfig = {
  judge: { kind: "pi-classifier", provider: "typesafe", modelId: "classifier-model" },
};

function classifierProfileOf(h: Harness): ReturnType<
  DecisionApproverNodeDependencies["resolveProfile"]
> {
  return h.decisionDeps().resolveProfile(OWNER);
}

describe("decision classifier profile", () => {
  it("builds a profile with the documented defaults for a pi-classifier judge", () => {
    const h = harness({
      effectiveNodes: DECISION_ONLY,
      approver: CLASSIFIER_JUDGE,
      classifiers: { "typesafe/classifier-model": CLASSIFIER_MODEL },
    });

    expect(h.findClassifier).not.toHaveBeenCalled();
    const profile = classifierProfileOf(h);
    expect((profile as { model?: unknown } | undefined)?.model).toBe(CLASSIFIER_MODEL);
    expect(profile?.timeoutMs).toBe(15_000);
    expect(profile?.contextBudgetTokens).toBe(32_768);
    expect(profile?.allowConfidenceThreshold).toBe(0.9);
    expect(profile?.denyConfidenceThreshold).toBe(0.8);
    expect(h.findClassifier.mock.calls).toEqual([["typesafe", "classifier-model"]]);
    expect(h.find).not.toHaveBeenCalled();
  });

  it("inherits the common approver timeout when the judge has none", () => {
    const h = harness({
      effectiveNodes: DECISION_ONLY,
      approver: { ...CLASSIFIER_JUDGE, timeoutMs: 7_000 },
      classifiers: { "typesafe/classifier-model": CLASSIFIER_MODEL },
    });

    expect(classifierProfileOf(h)?.timeoutMs).toBe(7_000);
  });

  it("keeps configured classifier values", () => {
    const h = harness({
      effectiveNodes: DECISION_ONLY,
      approver: {
        judge: {
          kind: "pi-classifier",
          provider: "typesafe",
          modelId: "classifier-model",
          timeoutMs: 9_000,
          contextBudgetTokens: 8_000,
          allowConfidenceThreshold: 0.7,
          denyConfidenceThreshold: 0.6,
        },
      },
      classifiers: { "typesafe/classifier-model": CLASSIFIER_MODEL },
    });

    const profile = classifierProfileOf(h);
    expect(profile?.timeoutMs).toBe(9_000);
    expect(profile?.contextBudgetTokens).toBe(8_000);
    expect(profile?.allowConfidenceThreshold).toBe(0.7);
    expect(profile?.denyConfidenceThreshold).toBe(0.6);
  });

  it("replaces unusable classifier numbers with the documented defaults", () => {
    const h = harness({
      effectiveNodes: DECISION_ONLY,
      approver: {
        judge: {
          kind: "pi-classifier",
          provider: "typesafe",
          modelId: "classifier-model",
          timeoutMs: 0,
          contextBudgetTokens: -5,
          allowConfidenceThreshold: 1.5,
          denyConfidenceThreshold: Number.NaN,
        },
      },
      classifiers: { "typesafe/classifier-model": CLASSIFIER_MODEL },
    });

    const profile = classifierProfileOf(h);
    expect(profile?.timeoutMs).toBe(15_000);
    expect(profile?.contextBudgetTokens).toBe(32_768);
    expect(profile?.allowConfidenceThreshold).toBe(0.9);
    expect(profile?.denyConfidenceThreshold).toBe(0.8);
  });

  it("answers no classifier profile for a pi-model or absent judge", () => {
    const piModel = harness({
      effectiveNodes: DECISION_ONLY,
      approver: {
        provider: "anthropic",
        modelId: "approver-model",
        judge: { kind: "pi-model", provider: "openai", modelId: "judge-model" },
      },
    });
    expect(classifierProfileOf(piModel)).toBeUndefined();
    expect(piModel.findClassifier).not.toHaveBeenCalled();

    const absent = harness({ effectiveNodes: DECISION_ONLY, approver: {} });
    expect(classifierProfileOf(absent)).toBeUndefined();
    expect(absent.findClassifier).not.toHaveBeenCalled();
  });

  it("answers no classifier profile when the model is missing", () => {
    const h = harness({ effectiveNodes: DECISION_ONLY, approver: CLASSIFIER_JUDGE });

    expect(classifierProfileOf(h)).toBeUndefined();
    expect(h.findClassifier.mock.calls).toEqual([["typesafe", "classifier-model"]]);
  });

  it("wires the decision dependencies without a guidance mapping", () => {
    const classify = vi.fn(() => Promise.reject(new Error("not exercised")));
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const now = () => 1_234;
    const h = harness({
      effectiveNodes: DECISION_ONLY,
      approver: { ...CLASSIFIER_JUDGE, decisionContextAcquisition: "decision" },
      classifiers: { "typesafe/classifier-model": CLASSIFIER_MODEL },
      rubric: "Host rubric.",
      classify,
      fetch: fetchImpl,
      now,
    });

    const deps = h.decisionDeps();
    expect(deps.context).toBe(CONTEXT);
    expect(deps.rubric).toBe("Host rubric.");
    expect(deps.contextAcquisition).toBe("decision");
    expect("resolveGuidance" in deps).toBe(false);
    expect(deps.classify).toBe(classify);
    expect(deps.fetch).toBe(fetchImpl);
    expect(deps.now).toBe(now);

    const withoutOptional = harness({ effectiveNodes: DECISION_ONLY, approver: CLASSIFIER_JUDGE });
    expect(withoutOptional.decisionDeps().fetch).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Dependency wiring: injected seams are forwarded, never re-created (§5)
// ---------------------------------------------------------------------------

const REVISIONS: ReviewRevisions = {
  owner: 1,
  navigation: 2,
  authorization: 3,
  projectRules: 4,
  intent: 5,
};

function projectRulesPort(
  snapshot: ProjectRulesPort["snapshot"],
): ProjectRulesPort {
  return { snapshot };
}

describe("llm dependency wiring", () => {
  it("forwards the injected seams by identity", () => {
    const learning = {} as ReviewerLearningLifecycle;
    const now = () => 1_111;
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
      learning,
      now,
    });

    const deps = h.llmDeps();
    expect(deps.context).toBe(CONTEXT);
    expect(deps.complete).toBe(h.input.complete);
    expect(deps.resolveSession).toBe(h.input.resolveSession);
    expect(deps.verifyFacts).toBe(h.input.verifyFacts);
    expect(deps.learning).toBe(learning);
    expect(deps.now).toBe(now);
    expect("bounds" in deps).toBe(false);
    expect("resolveProjectRules" in deps).toBe(false);
    expect(deps.onEvent).toBeUndefined();
  });

  it("resolves project rules through the injected port", async () => {
    const rules = { rulesRevision: 4, intentRevision: 5, rules: [] };
    const snapshot = vi.fn(() => rules);
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
      projectRules: projectRulesPort(snapshot),
    });

    const resolveProjectRules = h.llmDeps().resolveProjectRules;
    expect(resolveProjectRules).toBeTypeOf("function");
    const resolved = await resolveProjectRules?.(
      { owner: OWNER, mode: MODE, view: VIEW, revisions: REVISIONS },
    );

    expect(resolved).toBe(rules);
    expect(snapshot.mock.calls).toEqual([
      [{ owner: OWNER, mode: MODE, view: VIEW, revisions: REVISIONS }],
    ]);
  });

  it("forwards a pending project-rules snapshot unchanged", async () => {
    const rules = { rulesRevision: 4, intentRevision: 5, rules: [] };
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
      projectRules: projectRulesPort(async () => rules),
    });

    const resolved = await h.llmDeps().resolveProjectRules?.({
      owner: OWNER,
      mode: MODE,
      view: VIEW,
      revisions: REVISIONS,
    });
    expect(resolved).toBe(rules);
  });

  it("forwards the session resolver and facts verifier results", async () => {
    const facts: ReviewerSessionFacts = {
      view: VIEW,
      revisions: REVISIONS,
      mode: MODE,
    };
    const complete = vi.fn() as unknown as LlmCompleteFn;
    const h = harness({
      effectiveNodes: LLM_ONLY,
      approver: { provider: "anthropic", modelId: "approver-model" },
      models: { "anthropic/approver-model": APPROVER_MODEL },
      resolveSession: () => facts,
      verifyFacts: () => true,
      complete,
    });

    const deps = h.llmDeps();
    await expect(Promise.resolve(deps.resolveSession({} as never))).resolves.toBe(facts);
    expect(
      deps.verifyFacts({ owner: OWNER, mode: MODE, view: VIEW, revisions: REVISIONS, calls: [] }),
    ).toBe(true);
    expect(deps.complete).toBe(complete);
  });
});

// ---------------------------------------------------------------------------
// Audit events are forever bound to the generation of their assembly (§5)
// ---------------------------------------------------------------------------

const LLM_EVENT = {
  kind: "llm",
  nodeId: "builtin/llm-approver",
  owner: OWNER,
  requests: 1,
  outcome: "sent",
} as const;

const DECISION_EVENT = {
  kind: "decision",
  nodeId: "builtin/decision-approver",
  owner: OWNER,
  requests: 1,
  outcome: "failed",
} as const;

describe("model node event audit", () => {
  it("tags both node events with the assembly generation", () => {
    const events: ModelNodeEvent[] = [];
    const h = harness({ generation: 7, onEvent: (event) => events.push(event) });

    h.llmDeps().onEvent?.(LLM_EVENT);
    h.decisionDeps().onEvent?.(DECISION_EVENT);

    expect(events).toEqual([
      { ...LLM_EVENT, generation: 7 },
      { ...DECISION_EVENT, generation: 7 },
    ]);
    expect("generation" in LLM_EVENT).toBe(false);
  });

  it("keeps each assembly bound to its own generation across a later reload", () => {
    const events: ModelNodeEvent[] = [];
    const first = harness({
      generation: 1,
      effectiveNodes: LLM_ONLY,
      onEvent: (event) => events.push(event),
    });
    const firstDeps = first.llmDeps();

    const second = harness({
      generation: 2,
      effectiveNodes: LLM_ONLY,
      onEvent: (event) => events.push(event),
    });
    second.llmDeps();

    firstDeps.onEvent?.(LLM_EVENT);
    second.llmDeps().onEvent?.(LLM_EVENT);

    expect(events.map((event) => event.generation)).toEqual([1, 2]);
  });

  it("omits event audit when no observer is injected", () => {
    const h = harness();
    expect(h.llmDeps().onEvent).toBeUndefined();
    expect(h.decisionDeps().onEvent).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Dispose releases both nodes exactly once, isolating a failing peer (§5)
// ---------------------------------------------------------------------------

describe("assembly dispose", () => {
  it("releases both created nodes and is idempotent", () => {
    const llmDispose = vi.fn();
    const decisionDispose = vi.fn();
    const h = harness({ llmDispose, decisionDispose });

    h.assembly.dispose();
    expect(llmDispose).toHaveBeenCalledTimes(1);
    expect(decisionDispose).toHaveBeenCalledTimes(1);

    h.assembly.dispose();
    expect(llmDispose).toHaveBeenCalledTimes(1);
    expect(decisionDispose).toHaveBeenCalledTimes(1);
  });

  it("still releases the peer when one node release throws", () => {
    const decisionDispose = vi.fn();
    const h = harness({
      llmDispose: () => {
        throw new Error("release failed");
      },
      decisionDispose,
    });

    expect(() => h.assembly.dispose()).not.toThrow();
    expect(decisionDispose).toHaveBeenCalledTimes(1);

    expect(() => h.assembly.dispose()).not.toThrow();
    expect(decisionDispose).toHaveBeenCalledTimes(1);
  });

  it("releases only the nodes it actually created", () => {
    const llmDispose = vi.fn();
    const decisionDispose = vi.fn();
    const h = harness({
      effectiveNodes: [effectiveNode("builtin/decision-approver", false)],
      llmDispose,
      decisionDispose,
    });

    h.assembly.dispose();
    expect(llmDispose).not.toHaveBeenCalled();
    expect(decisionDispose).not.toHaveBeenCalled();
  });
});
