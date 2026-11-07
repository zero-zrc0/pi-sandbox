/**
 * Experiments dialog computation (specs/config-loading.md §10).
 *
 * `applyExperiments` maps the checked experiments to the next configuration;
 * these tests lock the reviewer-node exclusivity, the MCP sandbox flag and
 * the judge write rules.
 */
import { describe, expect, it } from "vitest";
import { parseApprovalChainConfig, type ApprovalChainConfig } from "#config/schema";
import { applyExperiments } from "#config/experiments";

function buildConfig(overrides: Record<string, unknown> = {}): ApprovalChainConfig {
  const result = parseApprovalChainConfig(overrides);
  if (!result.ok) {
    throw new Error(`invalid configuration fixture: ${JSON.stringify(result.issues)}`);
  }
  return result.config;
}

describe("applyExperiments", () => {
  it("enabling the Decision reviewer disables the LLM approver", () => {
    const next = applyExperiments(buildConfig(), { decision: true, mcpSandbox: false });

    expect(next.approval.nodes["builtin/decision-approver"]).toEqual({ enabled: true });
    expect(next.approval.nodes["builtin/llm-approver"]).toEqual({ enabled: false });
  });

  it("disabling the Decision reviewer enables the LLM approver", () => {
    const current = applyExperiments(buildConfig(), { decision: true, mcpSandbox: false });
    const next = applyExperiments(current, { decision: false, mcpSandbox: false });

    expect(next.approval.nodes["builtin/decision-approver"]).toEqual({ enabled: false });
    expect(next.approval.nodes["builtin/llm-approver"]).toEqual({ enabled: true });
  });

  it("writes the MCP sandbox flag both ways", () => {
    const on = applyExperiments(buildConfig(), { decision: false, mcpSandbox: true });
    expect(on.experimental.mcpSandbox).toBe(true);

    const off = applyExperiments(on, { decision: false, mcpSandbox: false });
    expect(off.experimental.mcpSandbox).toBe(false);
  });

  it("creates a classifier judge with documented defaults when none exists", () => {
    const next = applyExperiments(
      buildConfig(),
      { decision: true, mcpSandbox: false },
      { provider: "p", model: "m" },
    );

    expect(next.approver.judge).toEqual({
      type: "pi-classifier",
      provider: "p",
      model: "m",
      timeoutMs: 15000,
      contextBudgetTokens: 32768,
      allowThreshold: 0.9,
      denyThreshold: 0.8,
    });
  });

  it("replaces only the model pair of an existing classifier judge", () => {
    const current = applyExperiments(
      buildConfig(),
      { decision: true, mcpSandbox: false },
      { provider: "p1", model: "m1" },
    );
    const tuned = buildConfig({
      approver: {
        judge: {
          type: "pi-classifier",
          provider: "p1",
          model: "m1",
          timeoutMs: 5000,
          contextBudgetTokens: 4096,
          allowThreshold: 0.95,
          denyThreshold: 0.7,
        },
      },
    });

    for (const start of [current, tuned]) {
      const next = applyExperiments(start, { decision: true, mcpSandbox: false }, { provider: "p2", model: "m2" });
      expect(next.approver.judge).toMatchObject({
        type: "pi-classifier",
        provider: "p2",
        model: "m2",
        timeoutMs: start.approver.judge?.type === "pi-classifier" ? start.approver.judge.timeoutMs : 15000,
      });
    }
  });

  it("leaves the judge untouched when none is provided", () => {
    const current = applyExperiments(
      buildConfig(),
      { decision: true, mcpSandbox: true },
      { provider: "p", model: "m" },
    );
    const next = applyExperiments(current, { decision: true, mcpSandbox: false });

    expect(next.approver.judge).toEqual(current.approver.judge);
    expect(next.experimental.mcpSandbox).toBe(false);
    expect(next.approval.nodes["builtin/decision-approver"]).toEqual({ enabled: true });
  });

  it("leaves unrelated configuration sections unchanged", () => {
    const current = buildConfig({ mode: "auto-review", approver: { provider: "p", model: "m", timeoutMs: 60000 } });
    const next = applyExperiments(current, { decision: false, mcpSandbox: true });

    expect(next.mode).toBe("auto-review");
    expect(next.approver.provider).toBe("p");
    expect(next.approver.model).toBe("m");
    expect(next.approver.timeoutMs).toBe(60000);
  });
});
