import { describe, expect, it } from "vitest";
import type {
  ProjectRulesListResult,
  ProjectRulesRevokeResult,
  ProjectRulesRuleSummary,
} from "#approve-core/policy/project-rules/service";
import type { LearningCandidate, LearningRejection } from "#approve-core/policy/project-rules/candidates";
import {
  PROJECT_RULE_POLICY_TOOL_NAMES,
  createProjectRulePolicyTools,
  type LearningLifecyclePort,
  type LearningStagePort,
  type ProjectRulePolicyRevokeResult,
  type ProjectRulePolicyToolsOptions,
  type ProjectRuleServicePort,
} from "#approve-core/policy/project-rules/policy-tools";

const NOW = new Date("2026-03-01T12:00:00.000Z");
const RULE_ID = "rule-0123456789abcdef01234567";
const OTHER_RULE_ID = "rule-0123456789abcdef01234568";

function summary(overrides: Partial<ProjectRulesRuleSummary> = {}): ProjectRulesRuleSummary {
  return {
    id: RULE_ID,
    effect: "allow",
    status: "active",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    provenance: { quote: "以后允许读取 file.txt", actor: "user-1" },
    tool: { name: "bash", origin: "builtin", definitionRevision: "7" },
    cwd: "/work/project",
    requiredScopes: [{ surface: "bash", target: "file.txt", access: "read" }],
    ...overrides,
  };
}

function listResult(overrides: Partial<ProjectRulesListResult> = {}): ProjectRulesListResult {
  return { kind: "available", revision: 3, rules: [summary()], ...overrides } as ProjectRulesListResult;
}

function validRevokeInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ruleId: RULE_ID,
    confidence: 0.95,
    reason: "用户要求撤销该规则",
    expectedRevision: 3,
    requestId: "req-revoke-1",
    evidence: {
      sourceEntryId: "entry-1",
      quote: `以后撤销规则 ${RULE_ID}`,
      confidence: 0.95,
      judge: "judge-1",
      sessionId: "session-1",
      actor: "user-1",
    },
    ...overrides,
  };
}

class FakeService implements ProjectRuleServicePort {
  current: ProjectRulesListResult = listResult();
  listCalls = 0;
  readonly revokeCalls: unknown[] = [];
  readonly suspendCalls: string[][] = [];

  async list(): Promise<ProjectRulesListResult> {
    this.listCalls += 1;
    return this.current;
  }

  async revoke(request: unknown): Promise<ProjectRulesRevokeResult> {
    this.revokeCalls.push(request);
    return { kind: "not-found", revision: 0 };
  }

  isSuspended(): boolean {
    return false;
  }

  suspendRuleIds(ids: readonly string[]): void {
    this.suspendCalls.push([...ids]);
  }
}

class FakeCollector implements LearningStagePort {
  attemptId: string | undefined = "attempt-1";
  readonly parseCalls: Array<{ input: unknown; context: { attemptId?: string; requestId: string } | undefined }> = [];
  staged: { candidates: readonly LearningCandidate[]; rejections: readonly LearningRejection[] } = {
    candidates: [],
    rejections: [],
  };
  stagedCandidateCount = 0;

  constructor() {
    this.stagedCandidateCount = 1;
  }

  currentAttemptId(): string | undefined {
    return this.attemptId;
  }

  parse(input: unknown, context?: { attemptId?: string; requestId: string }): {
    candidates: readonly LearningCandidate[];
    rejections: readonly LearningRejection[];
  } {
    this.parseCalls.push({ input, context });
    const candidateCount = this.stagedCandidateCount;
    const candidates: LearningCandidate[] =
      candidateCount > 0
        ? [{
            attemptId: context?.attemptId ?? "attempt-1",
            requestId: context?.requestId ?? "req-revoke-1",
            field: "revoke",
            index: 0,
            value: { ruleId: RULE_ID, sourceEntryId: "entry-1", quote: `以后撤销规则 ${RULE_ID}`, confidence: 0.95 },
          }]
        : [];
    return { candidates, rejections: this.staged.rejections };
  }

  hasStagedData(): boolean {
    return this.stagedCandidateCount > 0;
  }
}

interface Harness {
  readonly tools: ReturnType<typeof createProjectRulePolicyTools>;
  readonly service: FakeService;
  readonly collector: FakeCollector;
  readonly options: ProjectRulePolicyToolsOptions;
}

function createTools(overrides: {
  readonly learning?: LearningLifecyclePort;
  readonly attemptId?: string | undefined;
  readonly stageCandidateCount?: number;
  readonly stageRejections?: readonly LearningRejection[];
  readonly requestId?: () => string | undefined;
} = {}): Harness {
  const service = new FakeService();
  const collector = new FakeCollector();
  if (Object.prototype.hasOwnProperty.call(overrides, "attemptId")) collector.attemptId = overrides.attemptId;
  if (overrides.stageCandidateCount !== undefined) collector.stagedCandidateCount = overrides.stageCandidateCount;
  if (overrides.stageRejections !== undefined) collector.staged = { candidates: [], rejections: overrides.stageRejections };
  const options: ProjectRulePolicyToolsOptions = {
    service,
    collector,
    now: () => NOW,
    ...(overrides.learning === undefined ? {} : { learning: overrides.learning }),
    ...(overrides.requestId === undefined ? {} : { requestId: overrides.requestId }),
  };
  return { tools: createProjectRulePolicyTools(options), service, collector, options };
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

describe("project rule policy tools: list", () => {
  it("returns the current project state, revision and safe summaries", async () => {
    const { tools, service } = createTools();

    const result = await tools.list({});

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.state).toBe("available");
    expect(result.revision).toBe(3);
    expect(service.listCalls).toBe(1);
    expect(result.rules[0]).toMatchObject({
      id: RULE_ID,
      effect: "allow",
      status: "active",
      createdAt: "2026-01-01T00:00:00.000Z",
      provenance: { quote: "以后允许读取 file.txt", actor: "user-1" },
      tool: { name: "bash", origin: "builtin" },
      cwd: "/work/project",
      requiredScopes: [{ surface: "bash", target: "file.txt", access: "read" }],
    });
    expect(result.rules[0]).not.toHaveProperty("arguments");
    expect(result.rules[0]).not.toHaveProperty("environmentDigest");
  });

  it("reports a missing file as an empty available state rather than a failure", async () => {
    const { tools, service } = createTools();
    service.current = { kind: "missing", revision: 0, rules: [] };

    const result = await tools.list(undefined);

    expect(result).toMatchObject({ ok: true, state: "missing", revision: 0, rules: [] });
  });

  it("fails without leaking other project data when the file is unavailable", async () => {
    const { tools, service } = createTools();
    service.current = { kind: "unavailable", revision: 0, category: "corrupt", diagnostic: "/secret/path.json", rules: [] };

    const result = await tools.list({});

    expect(result).toMatchObject({ ok: false, state: "unavailable", category: "corrupt" });
    expect(JSON.stringify(result)).not.toContain("/secret");
    expect(result).not.toHaveProperty("diagnostic");
  });

  it("fails on invalid list input", async () => {
    const { tools } = createTools();

    expect((await tools.list({ path: "/other/project" })).ok).toBe(false);
    expect((await tools.list("project_rules_list")).ok).toBe(false);
    expect((await tools.list([])).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

describe("project rule policy tools: revoke", () => {
  it("stages the revoke candidate through the collector and never writes durably", async () => {
    const { tools, service, collector } = createTools();

    const result = await tools.revoke(validRevokeInput());

    expect(result).toMatchObject({
      ok: true,
      staged: true,
      durable: false,
      ruleId: RULE_ID,
      requestId: "req-revoke-1",
      stagedAt: NOW.toISOString(),
    });
    if (!result.ok) throw new Error("unreachable");
    expect(result.rejections).toEqual([]);

    expect(collector.parseCalls).toHaveLength(1);
    expect(collector.parseCalls[0]?.context).toEqual({ attemptId: "attempt-1", requestId: "req-revoke-1" });
    expect(collector.parseCalls[0]?.input).toEqual({
      revoke: [{
        ruleId: RULE_ID,
        sourceEntryId: "entry-1",
        quote: `以后撤销规则 ${RULE_ID}`,
        confidence: 0.95,
        reason: "用户要求撤销该规则",
      }],
    });
    expect(service.revokeCalls).toEqual([]);
    expect(service.suspendCalls).toEqual([]);
  });

  it("fails on unknown tool names", async () => {
    const { tools } = createTools();
    const result = await tools.dispatch("project_rules_delete", validRevokeInput());
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("unknown-tool");
  });

  it("dispatches the two known tool names", async () => {
    const { tools, service } = createTools();
    const listed = await tools.dispatch(PROJECT_RULE_POLICY_TOOL_NAMES.list, {});
    expect(listed).toMatchObject({ ok: true, tool: "list" });
    expect(service.listCalls).toBe(1);
    const revoked = await tools.dispatch(PROJECT_RULE_POLICY_TOOL_NAMES.revoke, validRevokeInput());
    expect(revoked).toMatchObject({ ok: true, tool: "revoke" });
  });

  it("fails on invalid input without staging anything", async () => {
    const { tools, collector } = createTools();
    const cases: unknown[] = [
      validRevokeInput({ ruleId: "rule-xyz" }),
      validRevokeInput({ confidence: 0.5 }),
      validRevokeInput({ confidence: 2 }),
      validRevokeInput({ reason: "  " }),
      validRevokeInput({ expectedRevision: -1 }),
      validRevokeInput({ evidence: { sourceEntryId: "entry-1" } }),
      validRevokeInput({ evidence: { ...validRevokeInput().evidence as Record<string, unknown>, quote: "" } }),
      { ...validRevokeInput(), extra: true },
      "revoke",
      null,
    ];
    for (const input of cases) {
      const result = await tools.revoke(input);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason).toBe("invalid-input");
    }
    expect(collector.parseCalls).toEqual([]);
  });

  it("fails when the expected revision is stale", async () => {
    const { tools, collector } = createTools();
    const result = await tools.revoke(validRevokeInput({ expectedRevision: 2 }));
    expect(result).toMatchObject({ ok: false, staged: false, reason: "revision-mismatch" });
    expect(collector.parseCalls).toEqual([]);
  });

  it("fails for an unknown rule", async () => {
    const { tools } = createTools();
    const result = await tools.revoke(validRevokeInput({ ruleId: OTHER_RULE_ID }));
    expect(result).toMatchObject({ ok: false, reason: "unknown-rule" });
  });

  it("fails for a rule that is no longer active", async () => {
    const { tools, service } = createTools();
    service.current = listResult({ rules: [summary({ status: "revoked" })] });
    const result = await tools.revoke(validRevokeInput());
    expect(result).toMatchObject({ ok: false, reason: "inactive-rule" });
  });

  it("fails when the current project rules are unavailable", async () => {
    const { tools, service } = createTools();
    service.current = { kind: "unavailable", revision: 0, category: "io", rules: [] };
    const result = await tools.revoke(validRevokeInput({ expectedRevision: 0 }));
    expect(result).toMatchObject({ ok: false, reason: "unavailable" });
  });

  it("stages under the reviewed action request id supplied by the host", async () => {
    const { tools, collector } = createTools({ requestId: () => "req-reviewed" });

    const result = await tools.revoke(validRevokeInput({ requestId: undefined }));

    expect(result).toMatchObject({ ok: true, staged: true, requestId: "req-reviewed" });
    expect(collector.parseCalls[0]?.context).toEqual({ attemptId: "attempt-1", requestId: "req-reviewed" });
  });

  it("fails when no capture attempt is active", async () => {
    const { tools, collector } = createTools({ attemptId: undefined });
    const result = await tools.revoke(validRevokeInput());
    expect(result).toMatchObject({ ok: false, reason: "no-attempt" });
    expect(collector.parseCalls).toEqual([]);
  });

  it("fails when the collector cannot stage the candidate", async () => {
    const { tools } = createTools({
      stageCandidateCount: 0,
      stageRejections: [{ attemptId: "attempt-1", requestId: "req-revoke-1", field: "revoke", reason: "invalid-candidate" }],
    });
    const result: ProjectRulePolicyRevokeResult = await tools.revoke(validRevokeInput());
    expect(result).toMatchObject({ ok: false, reason: "stage-failed" });
    if (result.ok) throw new Error("unreachable");
    expect(result.rejections).toHaveLength(1);
  });

  it("fails when the learning lifecycle is disposed", async () => {
    const { tools, collector } = createTools({ learning: { disposed: true } });
    const result = await tools.revoke(validRevokeInput());
    expect(result).toMatchObject({ ok: false, reason: "disposed" });
    expect(collector.parseCalls).toEqual([]);
  });
});
