import { describe, expect, it } from "vitest";
import type { ExecutionRequest } from "../../../../src/elevation";
import type {
  ApprovalContext,
  ChainCallFacts,
  ChainUnitFacts,
} from "#approve-core/chain/facts";
import {
  createSandboxDefaultRunHandler,
  SANDBOX_DEFAULT_RUN_ID,
  SANDBOX_DEFAULT_RUN_PRIORITY,
  type SandboxDefaultRunOptions,
} from "#approve-core/chain/handlers/sandbox-default-run";
import {
  chainCallDigest,
  createSandboxReceipt,
  readSandboxReceipt,
  receiptAllows,
  type ReceiptCheckInput,
  type SandboxReceipt,
  type SandboxReceiptFields,
} from "#approve-core/chain/receipt";
import type { Handler } from "#approve-core/chain/run";
import {
  allowVerdict,
  askVerdict,
  denyVerdict,
  NO_VERDICT,
  unknownVerdict,
  type HandlerResult,
  type Verdict,
} from "#approve-core/chain/verdict";
import type { DangerHit } from "#approve-core/risk/danger";

const NOW = 1_700_000_000_000;
const SESSION = "session-c2";
const WORKSPACE = "C:\\workspace";
const LINUX_BACKEND = "linux-bwrap-landlock-seccomp";
const WINDOWS_BACKEND = "windows-mxc";
const PLAN_REVISION = "plan-rev-7";

const RECEIPT_FIELDS: SandboxReceiptFields = {
  sessionId: SESSION,
  backend: LINUX_BACKEND,
  planRevision: PLAN_REVISION,
  callDigest: "call-digest",
  issuedAtMs: NOW - 1_000,
  expiresAtMs: NOW + 60_000,
  workspaceRoot: WORKSPACE,
  networkPolicy: "proxied",
};

function makeUnit(overrides: Partial<ChainUnitFacts> = {}): ChainUnitFacts {
  return { unitId: "unit-1", toolName: "bash", access: [{ kind: "unknown" }], ...overrides };
}

function makeCall(units: readonly ChainUnitFacts[]): ChainCallFacts {
  return { toolCallId: "call-1", toolName: "bash", units };
}

function makeContext(
  options: {
    readonly unit?: Partial<ChainUnitFacts>;
    readonly mode?: ApprovalContext["mode"];
    readonly channel?: ApprovalContext["channel"];
    readonly accumulated?: Verdict;
    readonly hostExecutionRequest?: ExecutionRequest;
  } = {},
): ApprovalContext {
  const unit = makeUnit(options.unit);
  const call: ChainCallFacts = {
    ...makeCall([unit]),
    ...(options.hostExecutionRequest === undefined
      ? {}
      : { hostExecutionRequest: options.hostExecutionRequest }),
  };
  return {
    call,
    unit,
    mode: options.mode ?? "default",
    channel: options.channel ?? "normal",
    accumulated:
      options.accumulated ?? unknownVerdict("mode:default:effect-unproven", "builtin/mode-base"),
  };
}

function makeReceipt(
  call: ChainCallFacts,
  overrides: Partial<SandboxReceiptFields> = {},
): SandboxReceipt {
  return createSandboxReceipt({
    sessionId: SESSION,
    backend: LINUX_BACKEND,
    planRevision: PLAN_REVISION,
    callDigest: chainCallDigest(call),
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    workspaceRoot: WORKSPACE,
    networkPolicy: "proxied",
    ...overrides,
  });
}

function makeHandler(
  context: ApprovalContext,
  options: Partial<SandboxDefaultRunOptions> = {},
): Handler {
  return createSandboxDefaultRunHandler({
    receipt: makeReceipt(context.call),
    nowMs: () => NOW,
    sessionId: SESSION,
    workspaceRoot: WORKSPACE,
    ...options,
  });
}

async function opinion(
  context: ApprovalContext,
  options: Partial<SandboxDefaultRunOptions> = {},
): Promise<HandlerResult> {
  return await makeHandler(context, options).evaluate(context);
}

function checkInput(
  context: ApprovalContext,
  overrides: Partial<ReceiptCheckInput> = {},
): ReceiptCheckInput {
  return {
    callDigest: chainCallDigest(context.call),
    nowMs: NOW,
    sessionId: SESSION,
    workspaceRoot: WORKSPACE,
    ...overrides,
  };
}

function allowReason(backend = LINUX_BACKEND): string {
  return `sandbox:default-run:${backend}`;
}

const DANGER: DangerHit = {
  kind: "workspace-bulk-delete",
  action: "deny",
  reason: "risk:workspace-bulk-delete:recursive-delete",
  unitIds: ["unit-1"],
};

describe("sandbox receipt shape", () => {
  it("seals a valid receipt with a stable self-digest", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(receipt.digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(receipt.digest).not.toBe(receipt.callDigest);
    expect(Object.isFrozen(receipt)).toBe(true);
    expect(readSandboxReceipt(receipt)).toEqual(receipt);
  });

  it("produces the same digest regardless of declaration order", () => {
    const first = createSandboxReceipt({ ...RECEIPT_FIELDS });
    const second = createSandboxReceipt({
      networkPolicy: RECEIPT_FIELDS.networkPolicy,
      workspaceRoot: RECEIPT_FIELDS.workspaceRoot,
      expiresAtMs: RECEIPT_FIELDS.expiresAtMs,
      issuedAtMs: RECEIPT_FIELDS.issuedAtMs,
      callDigest: RECEIPT_FIELDS.callDigest,
      planRevision: RECEIPT_FIELDS.planRevision,
      backend: RECEIPT_FIELDS.backend,
      sessionId: RECEIPT_FIELDS.sessionId,
    });
    expect(first.digest).toBe(second.digest);
  });

  it("drops properties outside the sealed fields", () => {
    const widened: SandboxReceiptFields & { readonly note: string } = {
      ...RECEIPT_FIELDS,
      note: "not sealed",
    };
    const sealed = createSandboxReceipt(widened);
    expect(readSandboxReceipt(sealed)).toEqual(sealed);
    expect(Object.keys(sealed)).not.toContain("note");
  });

  it.each([null, undefined, 42, "receipt", [], true])(
    "rejects the non-object receipt %s",
    (value) => {
      expect(readSandboxReceipt(value)).toBeUndefined();
    },
  );

  it("rejects a receipt missing its digest", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    const { digest: _digest, ...unsealed } = receipt;
    expect(readSandboxReceipt(unsealed)).toBeUndefined();
  });

  it("rejects an extra field even when the digest matches", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(readSandboxReceipt({ ...receipt, note: "widened" })).toBeUndefined();
  });

  it("rejects empty identity fields", () => {
    expect(readSandboxReceipt(createSandboxReceipt({ ...RECEIPT_FIELDS, sessionId: "" })))
      .toBeUndefined();
    expect(readSandboxReceipt(createSandboxReceipt({ ...RECEIPT_FIELDS, backend: "" })))
      .toBeUndefined();
    expect(readSandboxReceipt(createSandboxReceipt({ ...RECEIPT_FIELDS, callDigest: "" })))
      .toBeUndefined();
    expect(readSandboxReceipt(createSandboxReceipt({ ...RECEIPT_FIELDS, workspaceRoot: "" })))
      .toBeUndefined();
  });

  it("rejects an unknown network policy", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(readSandboxReceipt({ ...receipt, networkPolicy: "unrestricted" })).toBeUndefined();
  });

  it("rejects a non-positive or inverted validity window", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(readSandboxReceipt({ ...receipt, expiresAtMs: receipt.issuedAtMs })).toBeUndefined();
    expect(readSandboxReceipt({ ...receipt, expiresAtMs: receipt.issuedAtMs - 1 })).toBeUndefined();
    expect(readSandboxReceipt({ ...receipt, issuedAtMs: -1 })).toBeUndefined();
    expect(readSandboxReceipt({ ...receipt, issuedAtMs: 1.5 })).toBeUndefined();
  });

  it("rejects a malformed self-digest", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(readSandboxReceipt({ ...receipt, digest: "not-a-digest" })).toBeUndefined();
    expect(readSandboxReceipt({ ...receipt, digest: "A".repeat(64) })).toBeUndefined();
  });

  it("rejects a mutated field that kept the old digest", () => {
    const receipt = createSandboxReceipt(RECEIPT_FIELDS);
    expect(readSandboxReceipt({ ...receipt, planRevision: "plan-rev-8" })).toBeUndefined();
    expect(readSandboxReceipt({ ...receipt, networkPolicy: "host" })).toBeUndefined();
  });
});

describe("receiptAllows", () => {
  it("accepts a receipt bound to this call, clock, session and workspace", () => {
    const context = makeContext();
    expect(receiptAllows(makeReceipt(context.call), checkInput(context))).toEqual({ ok: true });
  });

  it("reports a missing receipt", () => {
    expect(receiptAllows(undefined, checkInput(makeContext()))).toEqual({
      ok: false,
      reason: "missing",
    });
  });

  it("reports a tampered self-digest", () => {
    const context = makeContext();
    const receipt = { ...makeReceipt(context.call), digest: "0".repeat(64) };
    expect(receiptAllows(receipt, checkInput(context))).toEqual({
      ok: false,
      reason: "tampered",
    });
  });

  it("reports any mutated field as tampered", () => {
    const context = makeContext();
    const receipt = { ...makeReceipt(context.call), backend: WINDOWS_BACKEND };
    expect(receiptAllows(receipt, checkInput(context))).toEqual({
      ok: false,
      reason: "tampered",
    });
  });

  it("accepts the half-open window boundaries", () => {
    const context = makeContext();
    const receipt = makeReceipt(context.call);
    expect(receiptAllows(receipt, checkInput(context, { nowMs: receipt.issuedAtMs })))
      .toEqual({ ok: true });
    expect(receiptAllows(receipt, checkInput(context, { nowMs: receipt.expiresAtMs - 1 })))
      .toEqual({ ok: true });
  });

  it("reports expiry at the exclusive end instant", () => {
    const context = makeContext();
    const receipt = makeReceipt(context.call);
    expect(receiptAllows(receipt, checkInput(context, { nowMs: receipt.expiresAtMs })))
      .toEqual({ ok: false, reason: "expired" });
  });

  it("reports expiry after the window and before issuance", () => {
    const context = makeContext();
    const receipt = makeReceipt(context.call);
    expect(receiptAllows(receipt, checkInput(context, { nowMs: NOW + 60_001 })))
      .toEqual({ ok: false, reason: "expired" });
    expect(receiptAllows(receipt, checkInput(context, { nowMs: NOW - 1_001 })))
      .toEqual({ ok: false, reason: "expired" });
  });

  it("reports a non-finite clock as expired", () => {
    const context = makeContext();
    expect(receiptAllows(makeReceipt(context.call), checkInput(context, { nowMs: Number.NaN })))
      .toEqual({ ok: false, reason: "expired" });
  });

  it("reports a receipt bound to another frozen call", () => {
    const context = makeContext();
    expect(
      receiptAllows(makeReceipt(context.call), checkInput(context, { callDigest: "other-call" })),
    ).toEqual({ ok: false, reason: "digest-mismatch" });
  });

  it("reports a receipt from another session", () => {
    const context = makeContext();
    expect(receiptAllows(makeReceipt(context.call), checkInput(context, { sessionId: "other" })))
      .toEqual({ ok: false, reason: "cross-session" });
  });

  it("reports a receipt from another workspace", () => {
    const context = makeContext();
    expect(
      receiptAllows(makeReceipt(context.call), checkInput(context, { workspaceRoot: "D:\\other" })),
    ).toEqual({ ok: false, reason: "cross-session" });
  });

  it("reports an unavailable backend", () => {
    const context = makeContext();
    expect(
      receiptAllows(
        makeReceipt(context.call, { backend: "unsupported-platform" }),
        checkInput(context),
      ),
    ).toEqual({ ok: false, reason: "backend-unavailable" });
    expect(
      receiptAllows(makeReceipt(context.call, { backend: "custom-sandbox" }), checkInput(context)),
    ).toEqual({ ok: false, reason: "backend-unavailable" });
  });

  it("accepts each backend's own shell", () => {
    const context = makeContext();
    expect(
      receiptAllows(makeReceipt(context.call), checkInput(context, { shell: "bash" })),
    ).toEqual({ ok: true });
    expect(
      receiptAllows(
        makeReceipt(context.call, { backend: WINDOWS_BACKEND }),
        checkInput(context, { shell: "powershell" }),
      ),
    ).toEqual({ ok: true });
  });

  it("reports a shell the backend cannot run", () => {
    const context = makeContext();
    expect(
      receiptAllows(makeReceipt(context.call), checkInput(context, { shell: "powershell" })),
    ).toEqual({ ok: false, reason: "unsupported-shell" });
    expect(
      receiptAllows(
        makeReceipt(context.call, { backend: WINDOWS_BACKEND }),
        checkInput(context, { shell: "bash" }),
      ),
    ).toEqual({ ok: false, reason: "unsupported-shell" });
  });

  it("ignores the shell when the caller does not state one", () => {
    const context = makeContext();
    expect(
      receiptAllows(
        makeReceipt(context.call, { backend: WINDOWS_BACKEND }),
        checkInput(context),
      ),
    ).toEqual({ ok: true });
  });

  it("requires a proxied policy when the call proves network access", () => {
    const context = makeContext();
    expect(
      receiptAllows(
        makeReceipt(context.call, { networkPolicy: "none" }),
        checkInput(context, { needsNetwork: true }),
      ),
    ).toEqual({ ok: false, reason: "network-policy-missing" });
    expect(
      receiptAllows(
        makeReceipt(context.call, { networkPolicy: "host" }),
        checkInput(context, { needsNetwork: true }),
      ),
    ).toEqual({ ok: false, reason: "network-policy-missing" });
    expect(
      receiptAllows(
        makeReceipt(context.call, { networkPolicy: "proxied" }),
        checkInput(context, { needsNetwork: true }),
      ),
    ).toEqual({ ok: true });
  });

  it("does not need a proxied policy without proven network access", () => {
    const context = makeContext();
    expect(
      receiptAllows(
        makeReceipt(context.call, { networkPolicy: "none" }),
        checkInput(context, { needsNetwork: false }),
      ),
    ).toEqual({ ok: true });
    expect(
      receiptAllows(
        makeReceipt(context.call, { networkPolicy: "host" }),
        checkInput(context),
      ),
    ).toEqual({ ok: true });
  });

  it("reports integrity before freshness and freshness before binding", () => {
    const context = makeContext();
    const expired = makeReceipt(context.call, { issuedAtMs: NOW - 60_000, expiresAtMs: NOW - 1 });
    const tampered = { ...expired, backend: WINDOWS_BACKEND };
    expect(receiptAllows(tampered, checkInput(context))).toEqual({
      ok: false,
      reason: "tampered",
    });
    expect(receiptAllows(expired, checkInput(context, { callDigest: "other" }))).toEqual({
      ok: false,
      reason: "expired",
    });
  });
});

describe("sandbox-default-run metadata", () => {
  it("is the unresolved sandbox baseline", () => {
    const handler = createSandboxDefaultRunHandler({});
    expect(handler.id).toBe("builtin/sandbox-default-run");
    expect(handler.id).toBe(SANDBOX_DEFAULT_RUN_ID);
    expect(handler.priority).toBe(60);
    expect(handler.priority).toBe(SANDBOX_DEFAULT_RUN_PRIORITY);
    expect(handler.kind).toBe("base");
    expect(Object.isFrozen(handler)).toBe(true);
  });
});

describe("sandbox-default-run allows", () => {
  it("resolves an unknown verdict with a valid receipt in default", async () => {
    const context = makeContext({ unit: { access: [{ kind: "write" }] } });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows in auto-review", async () => {
    const context = makeContext({ mode: "auto-review" });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows an opaque unit whose access is all unknown", async () => {
    const context = makeContext({ unit: { access: [{ kind: "unknown" }, { kind: "unknown" }] } });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows a unit with no proven access", async () => {
    const context = makeContext({ unit: { access: [] } });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows proven local read and write facts", async () => {
    const context = makeContext({
      unit: {
        access: [
          { kind: "read", path: "C:\\workspace\\a.ts" },
          { kind: "write", path: "C:\\workspace\\b.ts" },
        ],
      },
    });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows network access through a proxied receipt", async () => {
    const context = makeContext({ unit: { access: [{ kind: "network" }] } });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("allows network plus a proven local write through a proxied receipt", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "network" }, { kind: "write", path: "C:\\workspace\\c" }] },
    });
    expect(await opinion(context)).toEqual({ action: "allow", reason: allowReason() });
  });

  it("preserves an explicit ask instead of default-running it", async () => {
    const context = makeContext({
      accumulated: askVerdict("rules:ask", "builtin/explicit-rules-restrict", { askFor: "allow" }),
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("allows on the last valid instant before expiry", async () => {
    const context = makeContext();
    const receipt = makeReceipt(context.call);
    expect(await opinion(context, { nowMs: () => receipt.expiresAtMs - 1 })).toEqual({
      action: "allow",
      reason: allowReason(),
    });
  });

  it("allows the platform's own shell", async () => {
    const context = makeContext({
      unit: { toolName: "powershell", access: [{ kind: "read" }] },
    });
    expect(
      await opinion(context, {
        receipt: makeReceipt(context.call, { backend: WINDOWS_BACKEND }),
      }),
    ).toEqual({ action: "allow", reason: allowReason(WINDOWS_BACKEND) });
  });

  it("allows a non-network unit under a host-policy receipt", async () => {
    const context = makeContext();
    expect(
      await opinion(context, {
        receipt: makeReceipt(context.call, { networkPolicy: "host" }),
      }),
    ).toEqual({ action: "allow", reason: allowReason() });
  });
});

describe("sandbox-default-run stays silent", () => {
  it("passes in read-only", async () => {
    expect(await opinion(makeContext({ mode: "read-only" }))).toEqual({ action: "pass" });
  });

  it("passes in full-access", async () => {
    expect(await opinion(makeContext({ mode: "full-access" }))).toEqual({ action: "pass" });
  });

  it("passes on the elevation channel", async () => {
    const context = makeContext({ channel: "elevation" });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("does not resolve a missing mode opinion", async () => {
    const context = makeContext({ accumulated: NO_VERDICT });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes when the ask was already lifted", async () => {
    const context = makeContext({ accumulated: allowVerdict("mode:allow", "builtin/mode-base") });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes when the call was already denied", async () => {
    const context = makeContext({ accumulated: denyVerdict("rule:deny", "builtin/rules") });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on an escalation ask", async () => {
    const context = makeContext({
      accumulated: askVerdict("mode:host", "builtin/mode-base", { askFor: "escalate" }),
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on a locked ask", async () => {
    const locked: Verdict = { state: "ask", locked: true, reason: "human", source: "user" };
    expect(await opinion(makeContext({ accumulated: locked }))).toEqual({ action: "pass" });
  });

  it("passes when the host issued no receipt", async () => {
    expect(await opinion(makeContext(), { receipt: undefined })).toEqual({ action: "pass" });
  });

  it("passes on an expired receipt", async () => {
    const context = makeContext();
    expect(await opinion(context, { nowMs: () => NOW + 60_000 })).toEqual({ action: "pass" });
  });

  it("passes on a tampered self-digest", async () => {
    const context = makeContext();
    const receipt = { ...makeReceipt(context.call), digest: "0".repeat(64) };
    expect(await opinion(context, { receipt })).toEqual({ action: "pass" });
  });

  it("passes on a mutated receipt field", async () => {
    const context = makeContext();
    const receipt = { ...makeReceipt(context.call), planRevision: "plan-rev-8" };
    expect(await opinion(context, { receipt })).toEqual({ action: "pass" });
  });

  it("passes when the receipt belongs to another session", async () => {
    expect(await opinion(makeContext(), { sessionId: "other-session" })).toEqual({
      action: "pass",
    });
  });

  it("passes when the receipt belongs to another workspace", async () => {
    expect(await opinion(makeContext(), { workspaceRoot: "D:\\other" })).toEqual({
      action: "pass",
    });
  });

  it("passes when the current session or workspace is unknown", async () => {
    const context = makeContext();
    expect(await opinion(context, { sessionId: undefined })).toEqual({ action: "pass" });
    expect(await opinion(context, { workspaceRoot: undefined })).toEqual({ action: "pass" });
    expect(await opinion(context, { sessionId: "" })).toEqual({ action: "pass" });
    expect(await opinion(context, { workspaceRoot: "" })).toEqual({ action: "pass" });
  });

  it("passes on an unavailable backend", async () => {
    const context = makeContext();
    expect(
      await opinion(context, {
        receipt: makeReceipt(context.call, { backend: "unsupported-platform" }),
      }),
    ).toEqual({ action: "pass" });
  });

  it("passes when the unit's shell is not the backend's shell", async () => {
    const context = makeContext();
    expect(
      await opinion(context, {
        receipt: makeReceipt(context.call, { backend: WINDOWS_BACKEND }),
      }),
    ).toEqual({ action: "pass" });
  });

  it("passes when the receipt binds another frozen call", async () => {
    const context = makeContext();
    const otherCall = makeCall([makeUnit({ unitId: "unit-2" })]);
    expect(await opinion(context, { receipt: makeReceipt(otherCall) })).toEqual({
      action: "pass",
    });
  });

  it("passes on danger hits", async () => {
    const context = makeContext({ unit: { dangers: [DANGER] } });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on sensitive references", async () => {
    const context = makeContext({
      unit: { sensitive: [{ path: WORKSPACE + "\\.env", category: "dotenv", surface: "read" }] },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on a review-marked shape", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "write" }, { kind: "review" }] },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on an external read", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "read", path: "/etc/passwd", external: true }] },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on an external write", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "write", path: "/outside/a", external: true }] },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on an external delete", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "write", externalDelete: true }] },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes on network access without a proxied policy", async () => {
    const context = makeContext({ unit: { access: [{ kind: "network" }] } });
    for (const networkPolicy of ["none", "host"] as const) {
      expect(
        await opinion(context, { receipt: makeReceipt(context.call, { networkPolicy }) }),
      ).toEqual({ action: "pass" });
    }
  });

  it("passes on proxied network plus an external write", async () => {
    const context = makeContext({
      unit: {
        access: [
          { kind: "network" },
          { kind: "write", path: "/outside/upload", external: true },
        ],
      },
    });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("allows mixed unknown and local facts under the same sandbox", async () => {
    const context = makeContext({
      unit: { access: [{ kind: "unknown" }, { kind: "read" }] },
    });
    expect(await opinion(context)).toMatchObject({ action: "allow" });
  });

  it("passes on a host execution request", async () => {
    const context = makeContext({ hostExecutionRequest: {
      reason: "bypass",
      elevation: { tier: "host", scope: [{ path: "/outside/target", access: "write" }] },
    } });
    expect(await opinion(context)).toEqual({ action: "pass" });
  });

  it("passes when the clock throws", async () => {
    const context = makeContext();
    expect(
      await opinion(context, {
        nowMs: () => {
          throw new Error("clock unavailable");
        },
      }),
    ).toEqual({ action: "pass" });
  });
});
