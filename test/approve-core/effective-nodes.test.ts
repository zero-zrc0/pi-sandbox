import { describe, expect, it } from "vitest";

import { describeEffectiveNodes } from "#approve-core/effective-nodes";

describe("effective approval nodes", () => {
  it("keeps builtin positions and sorts user nodes by priority, source, and declaration order", () => {
    const result = describeEffectiveNodes([
      { id: "builtin/powershell", enabled: true },
      { id: "global-late", path: "/global-late.mjs", priority: 5 },
      { id: "global-first", path: "/global-first.mjs", priority: 2 },
      { id: "global-second", path: "/global-second.mjs", priority: 2 },
    ], [
      { id: "project-first", path: "/project-first.mjs", priority: 2 },
      { id: "project-mid", path: "/project-mid.mjs", priority: 3 },
    ]);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.nodes.map((node) => node.id)).toEqual([
      "builtin/structure-analysis",
      "builtin/identity",
      "builtin/rules",
      "builtin/assessment",
      "builtin/powershell",
      "builtin/mode",
      "global-first",
      "global-second",
      "project-first",
      "project-mid",
      "global-late",
      "builtin/llm-approver",
      "builtin/decision-approver",
      "builtin/human",
    ]);
    expect(result.configuration.nodes.map((node) => node.order)).toEqual(
      result.configuration.nodes.map((_, index) => index),
    );
    expect(result.configuration.nodes.find((node) => node.id === "builtin/decision-approver")?.enabled)
      .toBe(false);
  });

  it("keeps global nodes when a project node shadows the same id", () => {
    const result = describeEffectiveNodes(
      [{ id: "shared", path: "/global.mjs" }],
      [{ id: "shared", path: "/project.mjs" }],
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.warnings).toEqual([
      { code: "project-node-shadowed", id: "shared" },
    ]);
    expect(result.configuration.nodes.find((node) => node.id === "shared"))
      .toMatchObject({ source: "global", path: "/global.mjs" });
  });

  it.each([
    [[{ id: "builtin/unknown", enabled: true }], [], "unknown-builtin-node"],
    [[{ id: "node", path: "/a.mjs" }, { id: "node", path: "/b.mjs" }], [], "duplicate-node-id"],
    [[], [{ id: "builtin/powershell", enabled: true }], "project-builtin-forbidden"],
    [[{ id: "node", path: 7 }], [], "invalid-user-node"],
    [[{ id: "node", path: "/node.mjs", options: { text: "x".repeat(64 * 1024) } }], [], "invalid-user-node"],
    [[{ id: "node", path: "/node.mjs", options: { value: 1n } }], [], "invalid-config"],
  ] as const)("rejects unsupported node declarations with %s", (globalNodes, projectNodes, reason) => {
    expect(describeEffectiveNodes(globalNodes as never, projectNodes as never)).toEqual({
      ok: false,
      reason,
    });
  });

  it("freezes a defensive copy of node options", () => {
    const options = { nested: { key: "value" } };
    const result = describeEffectiveNodes([{ id: "node", path: "/node.mjs", options }]);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const node = result.configuration.nodes.find((candidate) => candidate.id === "node");
    expect(node?.options).not.toBe(options);
    expect(Object.isFrozen(node?.options)).toBe(true);
    expect(Object.isFrozen(node?.options?.nested)).toBe(true);
    expect(Object.isFrozen(options)).toBe(false);
  });

  it("keeps the existing digest for the same effective node data", () => {
    const result = describeEffectiveNodes([{ id: "node", path: "/node.mjs" }]);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.digest)
      .toBe("1d31ea13594cab7f120aca3e15d5a38b0b956557ef52f987e5be54b8e12757f4");
  });

  it("propagates a custom node description into the effective node", () => {
    const result = describeEffectiveNodes([
      { id: "node", path: "/node.mjs", description: "Blocks file writes outside the workspace." },
    ]);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.nodes.find((node) => node.id === "node")?.description)
      .toBe("Blocks file writes outside the workspace.");
  });

  it("omits the description field when none is declared", () => {
    const result = describeEffectiveNodes([{ id: "node", path: "/node.mjs" }]);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.configuration.nodes.find((node) => node.id === "node")).not.toHaveProperty("description");
  });

  it("rejects a non-string node description", () => {
    expect(describeEffectiveNodes(
      [{ id: "node", path: "/node.mjs", description: 7 } as never],
      [],
    )).toEqual({ ok: false, reason: "invalid-user-node" });
  });
});
