/**
 * `/permission` command handler (specs/config-loading.md §10).
 *
 * The handler is a pure display/decision layer: it never touches the
 * filesystem or the owner. Tests inject a fake structured snapshot, capture
 * the notifications it emits and record the mode-persistence hooks it calls,
 * so no Pi UI is involved.
 */
import { describe, expect, it } from "vitest";
import {
  parseApprovalChainConfig,
  type ApprovalChainConfig,
} from "#config/schema";
import type { ConfigPaths } from "#config/config-paths";
import type { EffectiveNode } from "#approve-core/contracts";
import {
  handlePermissionCommand,
  permissionArgumentCompletions,
  type PermissionCommandDependencies,
  type PermissionCommandSnapshot,
} from "#config/command";

const PATHS: ConfigPaths = {
  globalConfigDir: "/home/dev/.pi/agent/extensions/pi-sandbox",
  globalConfigFile: "/home/dev/.pi/agent/extensions/pi-sandbox/config.json",
  projectConfigDir: "/work/project/.pi/extensions/pi-sandbox",
  projectConfigFile: "/work/project/.pi/extensions/pi-sandbox/config.json",
  logDir: "/home/dev/.pi/agent/logs",
  debugLogFile: "/home/dev/.pi/agent/logs/debug.jsonl",
  reviewLogFile: "/home/dev/.pi/agent/logs/review.jsonl",
  projectAgentsDir: "/work/project/.pi/agents",
  legacyGlobalPolicyFile: "/home/dev/.pi/agent/policy.json",
  legacyProjectPolicyFile: "/work/project/.pi/policy.json",
  legacyExtensionConfigFile: "/opt/pi-sandbox/config.json",
};

function buildConfig(overrides: Record<string, unknown> = {}): ApprovalChainConfig {
  const result = parseApprovalChainConfig({
    mode: "default",
    execution: {},
    ...overrides,
  });
  if (!result.ok) {
    throw new Error(`invalid configuration fixture: ${JSON.stringify(result.issues)}`);
  }
  return result.config;
}

function effectiveNode(
  overrides: Partial<EffectiveNode> & Pick<EffectiveNode, "id">,
): EffectiveNode {
  return {
    source: "builtin",
    position: "front",
    order: 0,
    enabled: true,
    priority: null,
    ...overrides,
  };
}

/** The standard fixture: five nodes, both model nodes present, no problems. */
function standardNodes(): readonly EffectiveNode[] {
  return [
    effectiveNode({ id: "builtin/structure-analysis", order: 0 }),
    effectiveNode({ id: "builtin/llm-approver", position: "post", order: 1 }),
    effectiveNode({ id: "builtin/decision-approver", position: "post", order: 2, enabled: false }),
    effectiveNode({ id: "builtin/human", position: "post", order: 3 }),
    effectiveNode({
      id: "custom/reviewer",
      source: "global",
      position: "user",
      order: 4,
      priority: 5,
      path: "/plugins/reviewer.js",
    }),
  ];
}

function buildSnapshot(
  overrides: Partial<PermissionCommandSnapshot> = {},
): PermissionCommandSnapshot {
  return {
    config: buildConfig(),
    modeSource: "global",
    paths: PATHS,
    nodeConfig: {
      nodes: standardNodes(),
    },
    ...overrides,
  };
}

interface HarnessOptions {
  readonly snapshot?: (sessionId?: string) => PermissionCommandSnapshot;
  readonly sessionId?: string;
}

interface Harness {
  readonly dependencies: PermissionCommandDependencies;
  readonly notifications: string[];
  readonly snapshotCalls: (string | undefined)[];
}

function createHarness(options: HarnessOptions = {}): Harness {
  const notifications: string[] = [];
  const snapshotCalls: (string | undefined)[] = [];
  const snapshot = options.snapshot ?? (() => buildSnapshot());
  const dependencies: PermissionCommandDependencies = {
    snapshot: (sessionId) => {
      snapshotCalls.push(sessionId);
      return snapshot(sessionId);
    },
    ...(options.sessionId === undefined ? {} : { sessionId: options.sessionId }),
    notify: (message) => {
      notifications.push(message);
    },
  };
  return { dependencies, notifications, snapshotCalls };
}

describe("permission command parsing", () => {
  it("completes the settings subcommand only", () => {
    expect(permissionArgumentCompletions("")?.map((item) => item.value)).toEqual(["settings"]);
    expect(permissionArgumentCompletions("se")?.map((item) => item.value)).toEqual(["settings"]);
    expect(permissionArgumentCompletions("settings")).toBeNull();
    expect(permissionArgumentCompletions("status")).toBeNull();
    expect(permissionArgumentCompletions("mode")).toBeNull();
    expect(permissionArgumentCompletions("unknown")).toBeNull();
    expect(permissionArgumentCompletions("settings extra")).toBeNull();
  });

  it("defaults an empty input to status", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("", harness.dependencies)).toBe(true);
    expect(harness.snapshotCalls).toEqual([undefined]);
    expect(harness.notifications).toHaveLength(1);
    expect(harness.notifications[0]).toContain("Permission status");
  });

  it("defaults a whitespace-only input to status", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("   \t ", harness.dependencies)).toBe(true);
    expect(harness.notifications[0]).toContain("Permission status");
  });

  it("treats a mixed-case former subcommand as unknown", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("  STATUS  ", harness.dependencies)).toBe(false);
    expect(harness.notifications[0]).toContain("Unknown command");
  });

  it("treats a mixed-case unknown verb as unknown", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("  HE LP ", harness.dependencies)).toBe(false);
    expect(harness.notifications[0]).toContain("Unknown command");
  });
});

describe("permission command status", () => {
  it("shows the mode and its source", () => {
    const harness = createHarness({
      snapshot: () =>
        buildSnapshot({
          config: buildConfig({ mode: "auto-review" }),
          modeSource: "session",
        }),
    });
    handlePermissionCommand("", harness.dependencies);
    const text = harness.notifications[0] ?? "";
    expect(text).toContain("Mode: auto-review");
    expect(text).toContain("source: session");
  });

  it("shows the global config file path", () => {
    const harness = createHarness();
    handlePermissionCommand("", harness.dependencies);
    expect(harness.notifications[0]).toContain(`Config file: ${PATHS.globalConfigFile}`);
  });

  it("omits the model outside auto-review mode", () => {
    const harness = createHarness();
    handlePermissionCommand("", harness.dependencies);
    expect(harness.notifications[0]).not.toContain("Model:");
  });

  it("shows the LLM approver model in auto-review mode", () => {
    const harness = createHarness({
      snapshot: () =>
        buildSnapshot({
          config: buildConfig({
            mode: "auto-review",
            approver: { provider: "cloudflare-workers-ai", model: "@cf/cloudflare/clef" },
          }),
        }),
    });
    handlePermissionCommand("", harness.dependencies);
    expect(harness.notifications[0]).toContain("Model: cloudflare-workers-ai/@cf/cloudflare/clef");
  });

  it("shows the judge model in auto-review mode when the Decision reviewer is enabled", () => {
    const harness = createHarness({
      snapshot: () =>
        buildSnapshot({
          config: buildConfig({
            mode: "auto-review",
            approver: {
              provider: "cloudflare-workers-ai",
              model: "@cf/cloudflare/clef",
              judge: { type: "pi-classifier", provider: "judge-provider", model: "judge-model" },
            },
          }),
          nodeConfig: {
            nodes: [
              effectiveNode({ id: "builtin/llm-approver", position: "post", order: 0, enabled: false }),
              effectiveNode({ id: "builtin/decision-approver", position: "post", order: 1 }),
            ],
          },
        }),
    });
    handlePermissionCommand("", harness.dependencies);
    expect(harness.notifications[0]).toContain("Model: judge-provider/judge-model");
  });

  it("falls back to the session model when no approver model is configured", () => {
    const harness = createHarness({
      snapshot: () => buildSnapshot({ config: buildConfig({ mode: "auto-review" }) }),
    });
    handlePermissionCommand("", harness.dependencies);
    expect(harness.notifications[0]).toContain("Model: current session model");
  });

  it("reads the snapshot for the requested session exactly once", () => {
    const harness = createHarness({ sessionId: "session-42" });
    handlePermissionCommand("", harness.dependencies);
    expect(harness.snapshotCalls).toEqual(["session-42"]);
  });

  it("does not throw when the snapshot fails", () => {
    const harness = createHarness({
      snapshot: () => {
        throw new Error("owner exploded");
      },
    });
    expect(() => handlePermissionCommand("", harness.dependencies)).not.toThrow();
    expect(handlePermissionCommand("", harness.dependencies)).toBe(true);
    expect(harness.notifications[0]).toContain("Permission status failed");
    expect(harness.notifications[0]).toContain("owner exploded");
  });
});

describe("permission command unknown input", () => {
  it("returns false and prints the usage line", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("yolo", harness.dependencies)).toBe(false);
    expect(harness.notifications[0]).toContain("yolo");
    expect(harness.notifications[0]).toContain("Usage: /permission [settings]");
    expect(harness.snapshotCalls).toEqual([]);
  });

  it("returns false for an unknown verb with arguments", () => {
    const harness = createHarness();
    expect(handlePermissionCommand("grant everything", harness.dependencies)).toBe(false);
    expect(harness.notifications[0]).toContain("grant");
  });
});

describe("permission command robustness", () => {
  it("does not throw when notify itself throws", () => {
    const harness = createHarness();
    const dependencies: PermissionCommandDependencies = {
      ...harness.dependencies,
      notify: () => {
        throw new Error("UI is gone");
      },
    };
    expect(() => handlePermissionCommand("yolo", dependencies)).not.toThrow();
    expect(handlePermissionCommand("yolo", dependencies)).toBe(false);
    expect(handlePermissionCommand("", dependencies)).toBe(true);
  });
});
