import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { createApprovalNodeHost } from "#approve-core/node-loader/manager";
import type { EffectiveNode, EffectiveNodeConfiguration } from "#approve-core/contracts";
import type { ApprovalNodeLoadPlan } from "../../../src/sdk";

const nodeConfig: EffectiveNodeConfiguration = {
  nodes: [],
  warnings: [],
  digest: "config-digest",
};

function plan(): ApprovalNodeLoadPlan {
  const node: EffectiveNode = {
    id: "user/check",
    source: "global",
    position: "user",
    order: 0,
    enabled: true,
    path: "check.js",
    priority: 0,
  };
  return {
    effectiveNodes: [node],
    nodeConfig,
    configDigest: "config-digest",
    globalConfigDir: join(tmpdir(), "pi-sandbox-global"),
    projectConfigDir: join(tmpdir(), "pi-sandbox-project"),
    projectTrusted: false,
  };
}

describe("createApprovalNodeHost", () => {
  it("serializes publications and releases only retired or disposed generations", async () => {
    let disposals = 0;
    const host = createApprovalNodeHost({
      now: () => 100,
      importModule: async () => ({
        apiVersion: "1",
        createNode: () => ({
          apiVersion: "1",
          id: "user/check",
          evaluate: () => ({ decisions: [] }),
        }),
        dispose: () => { disposals += 1; },
      }),
    });
    const permissions = {
      checkPermission: () => ({ state: "ask" as const, origin: "unavailable" }),
      getToolPermission: () => "ask" as const,
    };

    const first = await host.publish({ plan: plan(), permissions });
    const second = await host.publish({ plan: plan(), permissions });

    expect(first.generation).toBe(1);
    expect(second.generation).toBe(2);
    expect(host.current()).toBe(second);
    expect(host.isCurrent(first.generation)).toBe(false);
    expect(host.isCurrent(second.generation)).toBe(true);
    expect(disposals).toBe(0);
    expect(await host.release(first.generation)).toEqual([]);
    expect(disposals).toBe(1);
    expect(await host.release(second.generation)).toEqual([]);
    expect(disposals).toBe(1);
    expect(await host.dispose()).toEqual([]);
    expect(disposals).toBe(2);
    expect(host.current()).toBeUndefined();
    expect(host.isCurrent(second.generation)).toBe(false);
    await expect(host.publish({ plan: plan(), permissions })).rejects.toThrow("disposed");
  });

  it("keeps a prepared candidate unpublished until commit and disposes it on discard", async () => {
    let loadedModules = 0;
    const disposedModules: number[] = [];
    const host = createApprovalNodeHost({
      importModule: async () => {
        const moduleId = ++loadedModules;
        return {
          apiVersion: "1",
          createNode: () => ({ apiVersion: "1", id: "user/check", evaluate: () => ({ decisions: [] }) }),
          dispose: () => { disposedModules.push(moduleId); },
        };
      },
    });
    const permissions = {
      checkPermission: () => ({ state: "ask" as const, origin: "unavailable" }),
      getToolPermission: () => "ask" as const,
    };

    const first = await host.publish({ plan: plan(), permissions });
    const discarded = await host.prepare({ plan: plan(), permissions });
    expect(host.current()).toBe(first);
    expect(discarded.publication.generation).toBe(2);
    await discarded.dispose();
    expect(host.current()).toBe(first);
    expect(disposedModules).toEqual([2]);

    const next = await host.prepare({ plan: plan(), permissions });
    expect(next.publication.generation).toBe(2);
    expect(next.commit()).toBe(true);
    expect(host.current()).toBe(next.publication);
    expect(await host.release(first.generation)).toEqual([]);
    expect(disposedModules).toEqual([2, 1]);
    await host.dispose();
    expect(disposedModules).toEqual([2, 1, 3]);
  });
});
