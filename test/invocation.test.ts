import { describe, expect, it } from "vitest";
import { Type } from "typebox";
import {
  captureToolInvocationSeed,
  finalizeToolInvocation,
  toolInvocationDigestMatches,
} from "../src/invocation";

function mcpTool(overrides: Record<string, unknown> = {}) {
  return {
    name: "mcp__fetch__fetch",
    description: "Fetch a URL",
    parameters: { type: "object" },
    sourceInfo: {
      path: "C:\\extensions\\mcp.js",
      source: "mcp",
      scope: "user",
      origin: "top-level",
    },
    ...overrides,
  };
}

function captureMcpTool(registeredTool: Record<string, unknown>) {
  return captureToolInvocationSeed({
    event: {
      type: "tool_call",
      toolName: "mcp__fetch__fetch",
      toolCallId: "mcp-call",
      input: { url: "https://example.com" },
    },
    registeredTools: [registeredTool],
    cwd: "C:\\work",
    requester: { sessionId: "session-1", agentName: null },
    environment: {},
  });
}

describe("tool invocation facts", () => {
  it("normalizes Pi TypeBox schemas and binds an object namespace", () => {
    const parameters = Type.Object({
      url: Type.String(),
      method: Type.Optional(Type.String()),
    });
    Object.defineProperty(parameters, "~kind", { value: "Object", enumerable: true });
    Object.defineProperty(parameters.properties.url, "~kind", { value: "String", enumerable: true });
    Object.defineProperties(parameters.properties.method, {
      "~kind": { value: "String", enumerable: true },
      "~optional": { value: true, enumerable: true },
      "~readonly": { value: true, enumerable: true },
    });
    const namespace = {
      name: "mcp__fetch",
      aliases: ["fetch"],
      description: "Fetch tools",
      instructions: "Use an absolute URL.",
    };
    const capture = captureMcpTool(mcpTool({ parameters, namespace }));

    expect(capture.ok).toBe(true);
    if (!capture.ok) throw new Error(capture.reason);
    expect(capture.seed.tool.parameters).toEqual({
      type: "object",
      properties: { url: { type: "string" }, method: { type: "string" } },
      required: ["url"],
    });
    expect(capture.seed.tool.namespace).toEqual(namespace);
    expect(Object.isFrozen(capture.seed.tool.namespace)).toBe(true);
    expect(Object.isFrozen(capture.seed.tool.namespace?.aliases)).toBe(true);
    const changedNamespace = captureMcpTool(mcpTool({
      parameters,
      namespace: { ...namespace, aliases: ["other"] },
    }));
    expect(changedNamespace.ok).toBe(true);
    if (!changedNamespace.ok) throw new Error(changedNamespace.reason);
    expect(changedNamespace.seed.tool.revision).not.toBe(capture.seed.tool.revision);
  });

  it("rejects malformed namespaces and TypeBox markers", () => {
    let readAccessor = false;
    const accessorNamespace = Object.defineProperty({}, "name", {
      enumerable: true,
      get: () => { readAccessor = true; return "mcp__fetch"; },
    });
    for (const namespace of [
      { name: "" },
      { name: "mcp__fetch", aliases: [""] },
      { name: "mcp__fetch", unexpected: true },
      { name: "mcp__fetch", instructions: false },
      accessorNamespace,
    ]) {
      const capture = captureMcpTool(mcpTool({ namespace }));
      expect(capture).toEqual({ ok: false, reason: "tool-definition-invalid" });
    }
    expect(readAccessor).toBe(false);

    const parameters = Type.Object({ url: Type.String() });
    Object.defineProperty(parameters, "~optional", { value: false, enumerable: true });
    expect(captureMcpTool(mcpTool({ parameters, namespace: { name: "mcp__fetch" } })))
      .toEqual({ ok: false, reason: "tool-definition-invalid" });
  });

  it("freezes the captured call and binds its scopes into a verifiable digest", () => {
    const capture = captureToolInvocationSeed({
      event: {
        type: "tool_call",
        toolName: "read",
        toolCallId: "call-1",
        input: { path: "notes.txt" },
      },
      registeredTools: [
        {
          name: "read",
          description: "Read a file",
          parameters: {
            type: "object",
            properties: { path: { type: "string" } },
            required: ["path"],
          },
          sourceInfo: {
            path: "C:\\extensions\\read.js",
            source: "read-plugin",
            scope: "user",
            origin: "top-level",
          },
        },
      ],
      cwd: "C:\\work",
      requester: { sessionId: "session-1", agentName: null },
      environment: { PATH: "C:\\bin" },
    });

    expect(capture.ok).toBe(true);
    if (!capture.ok) throw new Error(capture.reason);

    const finalized = finalizeToolInvocation(capture.seed, {
      requestId: "session-1:call-1",
      scopes: [
        {
          id: "read-file",
          surface: "path_read",
          target: "C:\\work\\notes.txt",
          access: "read",
          state: "allow",
          source: "approval-chain",
        },
      ],
      executionBinding: {
        status: "bound",
        owner: "pi-sandbox",
        toolName: "read",
        bindingId: "builtin:v1",
        revision: capture.seed.tool.revision,
      },
    });

    expect(finalized.ok).toBe(true);
    if (!finalized.ok) throw new Error(finalized.reason);

    const invocation = finalized.invocation;
    expect(invocation.action.effectiveArguments).toEqual({ path: "notes.txt" });
    expect(invocation.action.scopes[0]).toMatchObject({
      target: "C:\\work\\notes.txt",
      state: "allow",
    });
    expect(invocation.requester).toMatchObject({ sessionId: "session-1", agentName: null });
    expect(Object.isFrozen(invocation.action.effectiveArguments)).toBe(true);
    expect(Object.isFrozen(invocation.action.scopes[0])).toBe(true);
    expect(toolInvocationDigestMatches(invocation)).toBe(true);

    const changed = {
      ...invocation,
      action: {
        ...invocation.action,
        effectiveArguments: { path: "other.txt" },
      },
    };
    expect(toolInvocationDigestMatches(changed)).toBe(false);
  });
});
