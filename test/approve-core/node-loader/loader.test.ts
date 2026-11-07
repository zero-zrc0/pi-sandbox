import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadApprovalNodes } from "#approve-core/node-loader/loader";
import type { EffectiveNode, EffectiveNodeConfiguration } from "#approve-core/contracts";
import type { ApprovalPermissionQuery } from "../../../src/sdk";

function effectiveNode(overrides: Partial<EffectiveNode> = {}): EffectiveNode {
  return {
    id: "user/check",
    source: "global",
    position: "user",
    order: 0,
    enabled: true,
    path: "nodes/check.js",
    priority: 4,
    options: { safe: true },
    ...overrides,
  };
}

const nodeConfig: EffectiveNodeConfiguration = {
  nodes: [],
  warnings: [],
  digest: "config-digest",
};

describe("loadApprovalNodes", () => {
  it("loads only trusted enabled declarations and publishes frozen bindings", async () => {
    const globalConfigDir = join(tmpdir(), "pi-sandbox-global");
    const projectConfigDir = join(tmpdir(), "pi-sandbox-project");
    const calls: string[] = [];
    const permissions: ApprovalPermissionQuery = {
      checkPermission: () => ({ state: "deny", origin: "test" }),
      getToolPermission: () => "deny",
    };
    const loaded = await loadApprovalNodes({
      effectiveNodes: [
        effectiveNode({ id: "project/untrusted", source: "project" }),
        effectiveNode({ id: "global/disabled", enabled: false }),
        effectiveNode({ id: "user/check", priority: -2 }),
      ],
      nodeConfig,
      configDigest: "config-digest",
      globalConfigDir,
      projectConfigDir,
      projectTrusted: false,
      permissions,
      importModule: async (url) => {
        calls.push(url);
        return {
          apiVersion: "1",
          createNode(context: unknown) {
            return {
              apiVersion: "1",
              id: "user/check",
              evaluate() {
                return { decisions: [] };
              },
              context,
            };
          },
        };
      },
    });

    expect(calls).toHaveLength(1);
    expect(fileURLToPath(calls[0]!)).toBe(join(globalConfigDir, "nodes/check.js"));
    expect(loaded.nodes.map(({ id }) => id)).toEqual(["user/check"]);
    expect(loaded.skippedDisabledIds).toEqual(["global/disabled"]);
    expect(loaded.warnings).toEqual([]);
    expect(loaded.bindings).toHaveLength(1);
    expect(loaded.bindings[0]).toMatchObject({ position: "user", priority: -2 });
    expect(Object.isFrozen(loaded.bindings)).toBe(true);
    expect(loaded.bindings[0]!.node.evaluate).toBeTypeOf("function");
  });
});
