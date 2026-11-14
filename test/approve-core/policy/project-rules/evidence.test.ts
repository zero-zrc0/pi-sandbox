/**
 * Phase 7 user-evidence verification (specs/project-rule-model.md §8-§11).
 *
 * The evidence verifier is a pure function over frozen authorization entries,
 * exact actions and stored rules: these tables are the executable spec. They
 * deliberately avoid mocks and only inspect observable results (ok / stable
 * failure reason / returned context), never internal helpers.
 */
import { describe, expect, it } from "vitest";
import {
  classifyStatement,
  splitStatements,
  verifyCreateEvidence,
  verifyRevokeEvidence,
  type CreateEvidenceRequest,
  type CreateEvidenceResult,
  type EvidenceFailure,
  type RevokeEvidenceRequest,
  type RevokeEvidenceResult,
  type StatementClassification,
} from "#approve-core/policy/project-rules/evidence";
import {
  EXACT_ACTION_CONTRACT_VERSION,
  canonicalJson,
  sha256Hex,
  type ActionScope,
  type AuthorizationEntry,
  type ExactAction,
  type EvidenceProposal,
  type RuleEffect,
  type RuleRevocation,
  type RuleScope,
  type RuleStatus,
  type ScopeAccess,
  type StoredProjectRule,
} from "#approve-core/policy/project-rules/types";

type FailureReason = EvidenceFailure["reason"];
type CreateOk = Extract<CreateEvidenceResult, { ok: true }>;
type RevokeOk = Extract<RevokeEvidenceResult, { ok: true }>;

const TOOL = { name: "bash", origin: "pi", definitionRevision: "rev-1" } as const;
const ARGS = { command: "npm test" } as const;
const ARGS_DIGEST = sha256Hex(canonicalJson(ARGS));
const CWD = "C:\\work\\project";

const RULE_A = `rule-${"a".repeat(24)}`;
const RULE_B = `rule-${"b".repeat(24)}`;
const RULE_C = `rule-${"c".repeat(24)}`;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function actionWith(overrides: Partial<ExactAction> = {}): ExactAction {
  return {
    requestId: "req-1",
    tool: TOOL,
    definitionDigest: "def-digest",
    arguments: ARGS,
    argumentsDigest: ARGS_DIGEST,
    cwd: CWD,
    environmentDigest: "env-digest",
    scopes: [{ id: "s1", surface: "bash", target: "npm test", access: "execute" }],
    ...overrides,
  };
}

function scope(target: string, access: ScopeAccess, id = `s-${target}`): ActionScope {
  return { id, surface: "bash", target, access };
}

function userEntry(id: string, text: string): AuthorizationEntry {
  return { id, source: "user", text };
}

function evidenceProposal(overrides: Partial<EvidenceProposal> = {}): EvidenceProposal {
  return {
    sourceEntryId: "e1",
    quote: "以后允许运行 npm test",
    confidence: 0.95,
    judge: "judge-1",
    sessionId: "session-1",
    actor: "model",
    ...overrides,
  };
}

interface CreateCaseOptions {
  readonly action?: ExactAction;
  readonly batch?: readonly ExactAction[];
  readonly authorization?: readonly AuthorizationEntry[];
  readonly proposal?: Partial<EvidenceProposal>;
  readonly effect?: RuleEffect;
}

function createRequest(options: CreateCaseOptions = {}): CreateEvidenceRequest {
  const action = options.action ?? actionWith();
  return {
    action,
    batch: options.batch ?? [action],
    authorization: options.authorization ?? [userEntry("e1", "以后允许运行 npm test。")],
    proposal: evidenceProposal(options.proposal),
    effect: options.effect ?? "allow",
  };
}

interface StoredRuleOptions {
  readonly id?: string;
  readonly effect?: RuleEffect;
  readonly status?: RuleStatus;
  readonly revocation?: RuleRevocation;
  readonly requiredScopes?: readonly RuleScope[];
  readonly argumentValue?: unknown;
  readonly argumentsDigest?: string;
}

function storedRule(options: StoredRuleOptions = {}): StoredProjectRule {
  const argumentValue = options.argumentValue ?? ARGS;
  return {
    id: options.id ?? RULE_A,
    effect: options.effect ?? "allow",
    status: options.status ?? "active",
    match: {
      contractVersion: EXACT_ACTION_CONTRACT_VERSION,
      type: "exact_action",
      tool: TOOL,
      definitionDigest: "def-digest",
      arguments: argumentValue,
      argumentsDigest: options.argumentsDigest ?? sha256Hex(canonicalJson(argumentValue)),
      cwd: CWD,
      environmentDigest: "env-digest",
      requiredScopes: options.requiredScopes ?? [{ surface: "bash", target: "npm test", access: "execute" }],
    },
    provenance: {
      sessionId: "session-1",
      sourceEntryId: "e1",
      quote: "以后允许运行 npm test",
      confidence: 0.95,
      judge: "judge-1",
      actor: "model",
    },
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    revocation: options.revocation,
  };
}

const REVOCATION: RuleRevocation = { revokedAt: "2026-01-02T00:00:00.000Z", actor: "user" };

interface RevokeCaseOptions {
  readonly action?: ExactAction;
  readonly batch?: readonly ExactAction[];
  readonly authorization?: readonly AuthorizationEntry[];
  readonly proposal?: Partial<EvidenceProposal>;
  readonly rules?: readonly StoredProjectRule[];
  readonly targetRuleId?: string;
}

function revokeRequest(options: RevokeCaseOptions = {}): RevokeEvidenceRequest {
  const action = options.action ?? actionWith();
  return {
    action,
    batch: options.batch ?? [action],
    authorization: options.authorization ?? [userEntry("e1", "撤销这条规则。")],
    proposal: evidenceProposal({ quote: "撤销这条规则", ...options.proposal }),
    rules: options.rules ?? [storedRule()],
    targetRuleId: options.targetRuleId,
  };
}

// ---------------------------------------------------------------------------
// splitStatements
// ---------------------------------------------------------------------------

describe("splitStatements", () => {
  it("returns nothing for empty or whitespace-only text", () => {
    expect(splitStatements("")).toEqual([]);
    expect(splitStatements("   \r\n\t")).toEqual([]);
  });

  it("keeps a single sentence with exact trimmed offsets", () => {
    expect(splitStatements("Hello world.")).toEqual([{ text: "Hello world.", start: 0, end: 12 }]);
  });

  it("splits English sentence punctuation", () => {
    expect(splitStatements("One. Two! Three? Four; Five").map((span) => span.text)).toEqual([
      "One.",
      "Two!",
      "Three?",
      "Four;",
      "Five",
    ]);
  });

  it("splits Chinese sentence punctuation", () => {
    expect(splitStatements("允许运行。禁止删除！可以吗？好；行").map((span) => span.text)).toEqual([
      "允许运行。",
      "禁止删除！",
      "可以吗？",
      "好；",
      "行",
    ]);
  });

  it("splits on newlines including CRLF and trims each unit", () => {
    expect(splitStatements("第一行\n第二行\r\n第三行").map((span) => span.text)).toEqual([
      "第一行",
      "第二行",
      "第三行",
    ]);
  });

  it("keeps trimmed start/end offsets in the original text", () => {
    expect(splitStatements("A。 B")).toEqual([
      { text: "A。", start: 0, end: 2 },
      { text: "B", start: 3, end: 4 },
    ]);
  });

  it("does not split a decimal point or comma", () => {
    expect(splitStatements("3.14 is pi.").map((span) => span.text)).toEqual(["3.14 is pi."]);
    expect(splitStatements("允许运行，测试").map((span) => span.text)).toEqual(["允许运行，测试"]);
  });
});

// ---------------------------------------------------------------------------
// classifyStatement
// ---------------------------------------------------------------------------

interface ClassificationCase {
  readonly name: string;
  readonly text: string;
  readonly expected: Partial<StatementClassification>;
}

const CLASSIFICATION_CASES: readonly ClassificationCase[] = [
  {
    name: "classifies a Chinese persistent allow for execution",
    text: "以后允许运行测试",
    expected: { allow: true, persistent: true, executes: true, ephemeral: false },
  },
  {
    name: "classifies a Chinese explicit deny",
    text: "禁止编辑文件",
    expected: { deny: true, allow: false, writes: true },
  },
  {
    name: "classifies a negated allow as a deny",
    text: "以后不允许运行测试",
    expected: { allow: false, deny: true, persistent: true, executes: true },
  },
  {
    name: "classifies write authorization as implying read",
    text: "以后允许编辑 src/foo.ts",
    expected: { allow: true, writes: true, reads: true, executes: false },
  },
  {
    name: "does not let a read authorization imply write",
    text: "查看文件",
    expected: { reads: true, writes: false },
  },
  {
    name: "does not let an execute authorization imply read or write",
    text: "运行命令",
    expected: { executes: true, reads: false, writes: false },
  },
  {
    name: "classifies ephemeral Chinese markers",
    text: "仅这次允许运行测试",
    expected: { ephemeral: true, persistent: false, allow: true, executes: true },
  },
  {
    name: "classifies Chinese persistent markers",
    text: "以后每次都要允许编辑",
    expected: { persistent: true, ephemeral: false, allow: true, writes: true },
  },
  {
    name: "classifies Chinese broad markers",
    text: "允许所有操作",
    expected: { broad: true, allow: true },
  },
  {
    name: "classifies a Chinese revoke",
    text: "撤销这条规则",
    expected: { revoke: true, negatedRevoke: false },
  },
  {
    name: "classifies a deleted rule as a revoke",
    text: "删除这条规则",
    expected: { revoke: true, writes: true },
  },
  {
    name: "does not treat deleting a file as a rule revoke",
    text: "删除 src/foo.ts",
    expected: { revoke: false, writes: true },
  },
  {
    name: "does not treat a negated revoke as a revoke",
    text: "不要撤销这条规则",
    expected: { revoke: false, negatedRevoke: true },
  },
  {
    name: "does not treat a negated rule deletion as a revoke",
    text: "不要删除这条规则",
    expected: { revoke: false, negatedRevoke: true },
  },
  {
    name: "keeps revoke and ephemeral independent",
    text: "仅这次撤销所有规则",
    expected: { revoke: true, ephemeral: true, broad: true },
  },
  {
    name: "classifies English persistent allow for execution",
    text: "always allow running tests from now on",
    expected: { allow: true, persistent: true, executes: true },
  },
  {
    name: "classifies English ephemeral allow for reading",
    text: "just this once allow reading files",
    expected: { allow: true, ephemeral: true, reads: true, persistent: false },
  },
  {
    name: "classifies English broad allow",
    text: "all edits are allowed",
    expected: { allow: true, broad: true, writes: true, reads: true },
  },
  {
    name: "classifies English never allow as a deny",
    text: "never allow editing files",
    expected: { allow: false, deny: true, writes: true },
  },
  {
    name: "classifies English not allowed as a deny",
    text: "not allowed to edit",
    expected: { allow: false, deny: true, writes: true },
  },
  {
    name: "classifies English revoke",
    text: "revoke this rule",
    expected: { revoke: true, negatedRevoke: false },
  },
  {
    name: "classifies English negated revoke",
    text: "don't revoke this rule",
    expected: { revoke: false, negatedRevoke: true },
  },
  {
    name: "classifies mixed allow and deny",
    text: "允许读取，但不能写入",
    expected: { allow: true, deny: true, reads: true, writes: true },
  },
  {
    name: "leaves operation flags unset when no operation is named",
    text: "以后允许这个动作",
    expected: { allow: true, persistent: true, reads: false, writes: false, executes: false },
  },
];

describe("classifyStatement", () => {
  for (const testCase of CLASSIFICATION_CASES) {
    it(testCase.name, () => {
      const classification = classifyStatement(testCase.text);
      for (const [field, expected] of Object.entries(testCase.expected)) {
        expect(classification[field as keyof StatementClassification], `${field} of ${testCase.text}`).toBe(expected);
      }
    });
  }

  it("returns every field of the frozen classification shape", () => {
    expect(classifyStatement("以后允许所有编辑，每次都可以")).toEqual({
      ephemeral: false,
      persistent: true,
      allow: true,
      deny: false,
      revoke: false,
      negatedRevoke: false,
      broad: true,
      reads: true,
      writes: true,
      executes: false,
    });
  });
});

// ---------------------------------------------------------------------------
// verifyCreateEvidence: source validation and statement classification
// ---------------------------------------------------------------------------

const SENSITIVE_QUOTE = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz";

const NON_USER_SOURCES = ["tool", "assistant", "system", "summary", "reviewer", "extension", "log", "context"] as const;

interface CreateFailureCase {
  readonly name: string;
  readonly request: CreateEvidenceRequest;
  readonly reason: FailureReason;
}

const CREATE_FAILURE_CASES: readonly CreateFailureCase[] = [
  {
    name: "rejects an empty quote",
    request: createRequest({ proposal: { quote: "" } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a whitespace-only quote",
    request: createRequest({ proposal: { quote: "   " } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a quote longer than 500 characters",
    request: createRequest({
      authorization: [userEntry("e1", `${"以后允许运行 npm test"}${"x".repeat(500)}。`)],
      proposal: { quote: `${"以后允许运行 npm test"}${"x".repeat(500)}` },
    }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects an empty source entry id",
    request: createRequest({ proposal: { sourceEntryId: "" } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a non-finite confidence",
    request: createRequest({ proposal: { confidence: Number.NaN } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects an infinite confidence",
    request: createRequest({ proposal: { confidence: Number.POSITIVE_INFINITY } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a confidence below 0.9",
    request: createRequest({ proposal: { confidence: 0.899 } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a confidence above 1",
    request: createRequest({ proposal: { confidence: 1.5 } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a sensitive quote",
    request: createRequest({
      authorization: [userEntry("e1", `以后允许运行 curl -H "${SENSITIVE_QUOTE}" 命令。`)],
      proposal: { quote: SENSITIVE_QUOTE },
    }),
    reason: "sensitive",
  },
  {
    name: "rejects a quote that cites an unknown entry",
    request: createRequest({ proposal: { sourceEntryId: "entry-missing" } }),
    reason: "unknown-entry",
  },
  {
    name: "rejects a quote that is not verbatim",
    request: createRequest({ proposal: { quote: "以后允许运行 npm test 命令" } }),
    reason: "quote-not-verbatim",
  },
  {
    name: "rejects a paraphrase in curly quotes",
    request: createRequest({
      authorization: [userEntry("e1", "之前我说过“以后允许运行 npm test”，你记一下。")],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a paraphrase in backticks",
    request: createRequest({
      authorization: [userEntry("e1", "规则里写着`以后允许运行 npm test`。")],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote attributed to a tool",
    request: createRequest({
      authorization: [userEntry("e1", "工具说以后允许运行 npm test。")],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote attributed to the assistant in English",
    request: createRequest({
      authorization: [userEntry("e1", "The assistant said you are allowed to run npm test from now on.")],
      proposal: { quote: "you are allowed to run npm test from now on" },
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote that is not unique across user entries",
    request: createRequest({
      authorization: [
        userEntry("e1", "以后允许运行 npm test。"),
        userEntry("e2", "再说一次：以后允许运行 npm test。"),
      ],
    }),
    reason: "quote-ambiguous",
  },
  {
    name: "rejects a quote that occurs twice in one entry",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。再说一次：以后允许运行 npm test。")],
    }),
    reason: "quote-ambiguous",
  },
  {
    name: "rejects an ephemeral quote",
    request: createRequest({
      authorization: [userEntry("e1", "仅这次允许运行 npm test。")],
      proposal: { quote: "仅这次允许运行 npm test" },
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects ephemeral context around a persistent quote",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test，但仅这次不要记住。")],
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects a quote without a persistent marker",
    request: createRequest({
      authorization: [userEntry("e1", "允许运行 npm test。")],
      proposal: { quote: "允许运行 npm test" },
    }),
    reason: "no-persistent",
  },
  {
    name: "rejects a negated allow",
    request: createRequest({
      authorization: [userEntry("e1", "以后不要允许运行 npm test。")],
      proposal: { quote: "以后不要允许运行 npm test" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects an explicit deny when creating an allow rule",
    request: createRequest({
      authorization: [userEntry("e1", "以后禁止运行 npm test。")],
      proposal: { quote: "以后禁止运行 npm test" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a revoke inside the allowing context",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test，撤销之前的限制。")],
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a contradictory other unit without an independent subject",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。以后禁止运行 ls。")],
    }),
    reason: "contradictory",
  },
  {
    name: "rejects an ephemeral other unit without an independent subject",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。仅这次允许运行 ls。")],
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects a different persistent target in the context",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许所有编辑。以后允许编辑 src/bar.ts。")],
      proposal: { quote: "以后允许所有编辑" },
    }),
    reason: "unrelated-context",
  },
  {
    name: "rejects a read-only limitation on the same target",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。但只能查看 src/foo.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects a generic inspect-only limitation",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。只能查看。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects a broad grant qualified by an inspect-only limitation",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许所有编辑，但只能查看。")],
      proposal: { quote: "以后允许所有编辑" },
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects a deny grant whose operation misses the ask access",
    request: createRequest({
      action: actionWith({ scopes: [scope("npm test", "execute")] }),
      authorization: [userEntry("e1", "以后禁止编辑 src/foo.ts。")],
      proposal: { quote: "以后禁止编辑 src/foo.ts" },
      effect: "deny",
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects a quote that names an additional unknown target",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts 和 src/bar.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts 和 src/bar.ts" },
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a deny rule without an explicit deny",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。")],
      effect: "deny",
    }),
    reason: "contradictory",
  },
  {
    name: "rejects an execute grant for a read action",
    request: createRequest({
      action: actionWith({ scopes: [scope("npm test", "read")] }),
      authorization: [userEntry("e1", "以后允许运行 npm test。")],
      proposal: { quote: "以后允许运行 npm test" },
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects a read-only grant for a write action",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许读取 src/foo.ts。")],
      proposal: { quote: "以后允许读取 src/foo.ts" },
    }),
    reason: "operation-unprovable",
  },
  {
    name: "rejects partial target coverage",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/a.ts", "read", "s1"), scope("src/b.ts", "read", "s2")] }),
      authorization: [userEntry("e1", "以后允许读取 src/a.ts。")],
      proposal: { quote: "以后允许读取 src/a.ts" },
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a batch whose target set is not unique",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      batch: [
        actionWith({ scopes: [scope("src/foo.ts", "write")] }),
        actionWith({ requestId: "req-2", scopes: [scope("src/foo.ts", "write", "s2")] }),
      ],
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects when the quote does not name the action target",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。")],
      proposal: { quote: "以后允许运行" },
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a pointer when the batch has more than one action",
    request: createRequest({
      batch: [
        actionWith(),
        actionWith({ requestId: "req-2", scopes: [scope("ls", "execute", "s2")] }),
      ],
      authorization: [userEntry("e1", "以后允许运行这个动作。")],
      proposal: { quote: "以后允许运行这个动作" },
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects an action without any ask scope",
    request: createRequest({
      action: actionWith({ scopes: [] }),
      authorization: [userEntry("e1", "以后允许运行 npm test。")],
      proposal: { quote: "以后允许运行 npm test" },
    }),
    reason: "target-unprovable",
  },
];

describe("verifyCreateEvidence failures", () => {
  for (const testCase of CREATE_FAILURE_CASES) {
    it(testCase.name, () => {
      const result = verifyCreateEvidence(testCase.request);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe(testCase.reason);
    });
  }

  for (const source of NON_USER_SOURCES) {
    it(`rejects an authorization entry sourced from ${source}`, () => {
      const text = "以后允许运行 npm test。";
      const result = verifyCreateEvidence(createRequest({
        authorization: [{ id: "e1", source, text }],
      }));
      expect(result).toEqual({ ok: false, reason: "not-user-source" });
    });
  }
});

// ---------------------------------------------------------------------------
// verifyCreateEvidence: accepted bindings
// ---------------------------------------------------------------------------

interface CreateSuccessCase {
  readonly name: string;
  readonly request: CreateEvidenceRequest;
  readonly assert?: (result: CreateOk) => void;
}

const CREATE_SUCCESS_CASES: readonly CreateSuccessCase[] = [
  {
    name: "accepts a narrow Chinese allow for execution",
    request: createRequest(),
    assert: (result) => {
      expect(result.classification.allow).toBe(true);
      expect(result.classification.persistent).toBe(true);
      expect(result.classification.executes).toBe(true);
      expect(result.context).toContain("以后允许运行 npm test");
    },
  },
  {
    name: "accepts a persistent English allow for execution",
    request: createRequest({
      authorization: [userEntry("e1", "From now on, allow running npm test.")],
      proposal: { quote: "From now on, allow running npm test" },
    }),
    assert: (result) => {
      expect(result.classification.allow).toBe(true);
      expect(result.classification.persistent).toBe(true);
    },
  },
  {
    name: "accepts a deny grant",
    request: createRequest({
      action: actionWith({ scopes: [scope("rm -rf", "execute")] }),
      authorization: [userEntry("e1", "以后禁止运行 rm -rf。")],
      proposal: { quote: "以后禁止运行 rm -rf" },
      effect: "deny",
    }),
    assert: (result) => {
      expect(result.classification.deny).toBe(true);
    },
  },
  {
    name: "accepts a broad persistent allow",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许所有编辑。")],
      proposal: { quote: "以后允许所有编辑" },
    }),
    assert: (result) => {
      expect(result.classification.broad).toBe(true);
      expect(result.classification.writes).toBe(true);
      expect(result.classification.reads).toBe(true);
    },
  },
  {
    name: "accepts a pointer grant for a single action",
    request: createRequest({
      authorization: [userEntry("e1", "以后允许运行这个动作。")],
      proposal: { quote: "以后允许运行这个动作" },
    }),
  },
  {
    name: "accepts a write grant for a read action",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "read")] }),
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
  },
  {
    name: "accepts a grant that references every action target",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/a.ts", "read", "s1"), scope("src/b.ts", "read", "s2")] }),
      authorization: [userEntry("e1", "以后允许读取 src/a.ts 和 src/b.ts。")],
      proposal: { quote: "以后允许读取 src/a.ts 和 src/b.ts" },
    }),
  },
  {
    name: "accepts a unique target set in a larger batch",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      batch: [
        actionWith({ scopes: [scope("src/foo.ts", "write")] }),
        actionWith({ requestId: "req-2", scopes: [scope("src/bar.ts", "write", "s2")] }),
      ],
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
  },
  {
    name: "accepts an additional persistent statement about the same target",
    request: createRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "write")] }),
      authorization: [userEntry("e1", "以后允许编辑 src/foo.ts。以后也允许修改 src/foo.ts。")],
      proposal: { quote: "以后允许编辑 src/foo.ts" },
    }),
  },
  {
    name: "returns the statement context that intersects the quote",
    request: createRequest({
      authorization: [userEntry("e1", "先说明一下。以后允许运行 npm test。")],
    }),
    assert: (result) => {
      expect(result.context).toBe("以后允许运行 npm test。");
    },
  },
  {
    name: "accepts a confidence of exactly 0.9",
    request: createRequest({ proposal: { confidence: 0.9 } }),
  },
];

describe("verifyCreateEvidence successes", () => {
  for (const testCase of CREATE_SUCCESS_CASES) {
    it(testCase.name, () => {
      const result = verifyCreateEvidence(testCase.request);
      expect(result.ok).toBe(true);
      if (result.ok) testCase.assert?.(result);
    });
  }
});

// ---------------------------------------------------------------------------
// verifyRevokeEvidence: target proof
// ---------------------------------------------------------------------------

interface RevokeSuccessCase {
  readonly name: string;
  readonly request: RevokeEvidenceRequest;
  readonly assert?: (result: RevokeOk) => void;
}

const REVOKE_SUCCESS_CASES: readonly RevokeSuccessCase[] = [
  {
    name: "accepts a pointer revoke when exactly one active rule matches",
    request: revokeRequest(),
    assert: (result) => {
      expect(result.targetRuleId).toBe(RULE_A);
      expect(result.context).toContain("撤销这条规则");
    },
  },
  {
    name: "accepts a revoke that names the exact rule id",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则 ${RULE_A}。`)],
      proposal: { quote: `撤销规则 ${RULE_A}` },
    }),
    assert: (result) => {
      expect(result.targetRuleId).toBe(RULE_A);
    },
  },
  {
    name: "accepts a complete path that maps to one active rule",
    request: revokeRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "read")] }),
      authorization: [userEntry("e1", "撤销 src/foo.ts 的规则。")],
      proposal: { quote: "撤销 src/foo.ts 的规则" },
      rules: [storedRule({ requiredScopes: [{ surface: "bash", target: "src/foo.ts", access: "read" }] })],
    }),
  },
  {
    name: "accepts a declared target rule id when the evidence proves it",
    request: revokeRequest({ targetRuleId: RULE_A }),
  },
  {
    name: "accepts a pointer when a multi-action batch still has one matching rule",
    request: revokeRequest({
      batch: [
        actionWith(),
        actionWith({ requestId: "req-2", scopes: [scope("ls", "execute", "s2")] }),
      ],
    }),
  },
  {
    name: "accepts an exact rule id that resolves a two-rule conflict",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则 ${RULE_A}。`)],
      proposal: { quote: `撤销规则 ${RULE_A}` },
      rules: [storedRule({ id: RULE_A }), storedRule({ id: RULE_B, effect: "deny" })],
    }),
    assert: (result) => {
      expect(result.targetRuleId).toBe(RULE_A);
    },
  },
  {
    name: "returns the revoke statement context",
    request: revokeRequest(),
    assert: (result) => {
      expect(result.context).toBe("撤销这条规则。");
    },
  },
];

describe("verifyRevokeEvidence successes", () => {
  for (const testCase of REVOKE_SUCCESS_CASES) {
    it(testCase.name, () => {
      const result = verifyRevokeEvidence(testCase.request);
      expect(result.ok).toBe(true);
      if (result.ok) testCase.assert?.(result);
    });
  }
});

// ---------------------------------------------------------------------------
// verifyRevokeEvidence: failures
// ---------------------------------------------------------------------------

interface RevokeFailureCase {
  readonly name: string;
  readonly request: RevokeEvidenceRequest;
  readonly reason: FailureReason;
}

const REVOKE_FAILURE_CASES: readonly RevokeFailureCase[] = [
  {
    name: "rejects an empty quote",
    request: revokeRequest({ proposal: { quote: "" } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a quote longer than 500 characters",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销这条规则${"x".repeat(500)}。`)],
      proposal: { quote: `撤销这条规则${"x".repeat(500)}` },
    }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects an empty source entry id",
    request: revokeRequest({ proposal: { sourceEntryId: "" } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects low confidence",
    request: revokeRequest({ proposal: { confidence: 0.5 } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a non-finite confidence",
    request: revokeRequest({ proposal: { confidence: Number.NaN } }),
    reason: "invalid-evidence",
  },
  {
    name: "rejects a sensitive quote",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则，但先看 ${SENSITIVE_QUOTE}。`)],
      proposal: { quote: SENSITIVE_QUOTE },
    }),
    reason: "sensitive",
  },
  {
    name: "rejects a quote that cites an unknown entry",
    request: revokeRequest({ proposal: { sourceEntryId: "entry-missing" } }),
    reason: "unknown-entry",
  },
  {
    name: "rejects a non-user source",
    request: revokeRequest({
      authorization: [{ id: "e1", source: "assistant", text: "撤销这条规则。" }],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote that is not verbatim",
    request: revokeRequest({ proposal: { quote: "撤销该规则" } }),
    reason: "quote-not-verbatim",
  },
  {
    name: "rejects a paraphrase in curly quotes",
    request: revokeRequest({
      authorization: [userEntry("e1", "之前我说过“撤销这条规则”。")],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote attributed to a tool",
    request: revokeRequest({
      authorization: [userEntry("e1", "工具说撤销这条规则。")],
    }),
    reason: "not-user-source",
  },
  {
    name: "rejects a quote that is not unique across user entries",
    request: revokeRequest({
      authorization: [
        userEntry("e1", "撤销这条规则。"),
        userEntry("e2", "再说一次：撤销这条规则。"),
      ],
    }),
    reason: "quote-ambiguous",
  },
  {
    name: "rejects a quote that occurs twice in one entry",
    request: revokeRequest({
      authorization: [userEntry("e1", "撤销这条规则。撤销这条规则。")],
    }),
    reason: "quote-ambiguous",
  },
  {
    name: "rejects an ephemeral revoke",
    request: revokeRequest({
      authorization: [userEntry("e1", "仅这次撤销这条规则。")],
      proposal: { quote: "仅这次撤销这条规则" },
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects ephemeral context",
    request: revokeRequest({
      authorization: [userEntry("e1", "撤销这条规则，就这一次。")],
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects an English ephemeral revoke",
    request: revokeRequest({
      authorization: [userEntry("e1", "just this once revoke this rule.")],
      proposal: { quote: "just this once revoke this rule" },
    }),
    reason: "ephemeral",
  },
  {
    name: "rejects a negated revoke",
    request: revokeRequest({
      authorization: [userEntry("e1", "不要撤销这条规则。")],
      proposal: { quote: "不要撤销这条规则" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects an English negated revoke",
    request: revokeRequest({
      authorization: [userEntry("e1", "don't revoke this rule.")],
      proposal: { quote: "don't revoke this rule" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a negated revoke in the context",
    request: revokeRequest({
      authorization: [userEntry("e1", "撤销这条规则，但不要撤销其他规则。")],
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a quote without a revoke",
    request: revokeRequest({
      authorization: [userEntry("e1", "以后允许运行 npm test。")],
      proposal: { quote: "以后允许运行 npm test" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a revoke that exists only in the context",
    request: revokeRequest({
      authorization: [userEntry("e1", "请撤销这条规则。")],
      proposal: { quote: "这条规则" },
    }),
    reason: "contradictory",
  },
  {
    name: "rejects a rule that is no longer active",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则 ${RULE_A}。`)],
      proposal: { quote: `撤销规则 ${RULE_A}` },
      rules: [storedRule({ status: "revoked", revocation: REVOCATION })],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a revoke when there are no active rules",
    request: revokeRequest({ rules: [] }),
    reason: "target-unprovable",
  },
  {
    name: "rejects two explicit rule ids in one revoke unit",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则 ${RULE_A} 和 ${RULE_B}。`)],
      proposal: { quote: `撤销规则 ${RULE_A} 和 ${RULE_B}` },
      rules: [storedRule({ id: RULE_A }), storedRule({ id: RULE_B })],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a path that maps to more than one active rule",
    request: revokeRequest({
      action: actionWith({ scopes: [scope("src/foo.ts", "read")] }),
      authorization: [userEntry("e1", "撤销 src/foo.ts 的规则。")],
      proposal: { quote: "撤销 src/foo.ts 的规则" },
      rules: [
        storedRule({ id: RULE_A, requiredScopes: [{ surface: "bash", target: "src/foo.ts", access: "read" }] }),
        storedRule({
          id: RULE_B,
          requiredScopes: [{ surface: "bash", target: "src/foo.ts", access: "read" }],
          argumentValue: { command: "view foo" },
        }),
      ],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a pointer when two active rules match the action",
    request: revokeRequest({
      rules: [storedRule({ id: RULE_A }), storedRule({ id: RULE_B, effect: "deny" })],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a declared target rule id that does not exist",
    request: revokeRequest({ targetRuleId: RULE_C }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a declared target rule id that is not active",
    request: revokeRequest({
      targetRuleId: RULE_A,
      rules: [storedRule({ status: "revoked", revocation: REVOCATION })],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a declared target rule id that contradicts the proof",
    request: revokeRequest({
      authorization: [userEntry("e1", `撤销规则 ${RULE_A}。`)],
      proposal: { quote: `撤销规则 ${RULE_A}` },
      rules: [storedRule({ id: RULE_A }), storedRule({ id: RULE_B, effect: "deny" })],
      targetRuleId: RULE_B,
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a pointer when a conflicting path is named",
    request: revokeRequest({
      authorization: [userEntry("e1", "撤销这条规则，src/bar.ts 也要处理。")],
    }),
    reason: "target-unprovable",
  },
  {
    name: "rejects a pointer when no active rule matches the action",
    request: revokeRequest({
      rules: [storedRule({ argumentValue: { command: "something else" } })],
    }),
    reason: "target-unprovable",
  },
];

describe("verifyRevokeEvidence failures", () => {
  for (const testCase of REVOKE_FAILURE_CASES) {
    it(testCase.name, () => {
      const result = verifyRevokeEvidence(testCase.request);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe(testCase.reason);
    });
  }
});
