import { describe, expect, it } from "vitest";
import {
  captureToolInvocation,
  validateShellSandboxCapability,
  type AssessmentInvocationCaptureResult,
} from "#approve-core/utils/tool-access/invocation-snapshot";

const rawTool = {
  name: "bash",
  origin: "builtin:bash",
  revision: "7",
  description: "Run a shell command",
  parameters: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
};

const expectedTool = { name: "bash", origin: "builtin:bash", revision: "7" };

function incomplete(result: AssessmentInvocationCaptureResult): string {
  if (result.status !== "incomplete") throw new Error(`expected incomplete, got ${result.status}`);
  return result.reason;
}

function captured(result: AssessmentInvocationCaptureResult) {
  if (result.status !== "captured") throw new Error(`expected captured, got ${result.status}`);
  return result.capture;
}

describe("captureToolInvocation", () => {
  it("captures a raw tool definition, the final JSON arguments and the cwd", () => {
    const result = captureToolInvocation({ tool: rawTool, input: { command: "ls", depth: 2 } }, "C:/work/project");

    const capture = captured(result);
    expect(capture.tool.identity).toEqual({ name: "bash", origin: "builtin:bash", revision: "7" });
    expect(capture.arguments).toEqual({ command: "ls", depth: 2 });
    expect(capture.cwd).toBe("C:/work/project");
    expect(capture.argumentsDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(capture)).toBe(true);
    expect(Object.isFrozen(capture.tool)).toBe(true);
    expect(Object.isFrozen(capture.arguments)).toBe(true);
  });

  it("returns the same digest for equivalent argument objects in a different key order", () => {
    const first = captured(captureToolInvocation({ tool: rawTool, input: { command: "ls", depth: 2 } }, "C:/work"));
    const second = captured(captureToolInvocation({ tool: rawTool, input: { depth: 2, command: "ls" } }, "C:/work"));
    expect(second.argumentsDigest).toBe(first.argumentsDigest);
  });

  it("resolves exactly one definition by tool name from the registered tools", () => {
    const result = captureToolInvocation({
      toolName: "bash",
      registeredTools: [rawTool, { ...rawTool, name: "read", origin: "builtin:read" }],
      input: { command: "ls" },
    }, "C:/work");

    expect(captured(result).tool.identity.name).toBe("bash");
  });

  it("rejects an ambiguous, unknown or definition-less registered tool instead of guessing", () => {
    expect(incomplete(captureToolInvocation({
      toolName: "bash",
      registeredTools: [rawTool, { ...rawTool }],
      input: {},
    }, "C:/work"))).toBe("tool-definition-ambiguous");

    expect(incomplete(captureToolInvocation({
      toolName: "missing",
      registeredTools: [rawTool],
      input: {},
    }, "C:/work"))).toBe("tool-definition-unavailable");

    expect(incomplete(captureToolInvocation({ toolName: "bash", input: {} }, "C:/work")))
      .toBe("tool-definition-unavailable");

    expect(incomplete(captureToolInvocation({ input: {} }, "C:/work")))
      .toBe("tool-definition-unavailable");
  });

  it("cannot extract without a usable cwd", () => {
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: {} }, "")))
      .toBe("cwd-unavailable");
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: {} }, "   ")))
      .toBe("cwd-unavailable");
  });

  it("uses the raw cwd when the argument cwd is empty", () => {
    const result = captureToolInvocation({ tool: rawTool, input: {}, cwd: "C:/from-raw" }, "");
    expect(captured(result).cwd).toBe("C:/from-raw");
  });

  it("rejects a final input that is not a JSON object", () => {
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: "ls" }, "C:/work")))
      .toBe("input-unavailable");
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: [] }, "C:/work")))
      .toBe("input-unavailable");
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: null }, "C:/work")))
      .toBe("input-unavailable");
    expect(incomplete(captureToolInvocation({ tool: rawTool }, "C:/work")))
      .toBe("input-unavailable");
  });

  it("rejects values that cannot be frozen as JSON", () => {
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: { run: () => 1 } }, "C:/work")))
      .toBe("input-unavailable");

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: cyclic }, "C:/work")))
      .toBe("input-unavailable");
  });

  it("marks an inherited call unbound when the expected identity differs", () => {
    const result = captureToolInvocation({ tool: rawTool, input: {} }, "C:/work", expectedTool);
    expect(result.status).toBe("captured");

    for (const mismatch of [
      { ...expectedTool, name: "read" },
      { ...expectedTool, origin: "sdk:bash" },
      { ...expectedTool, revision: "8" },
    ]) {
      const unbound = captureToolInvocation({ tool: rawTool, input: {} }, "C:/work", mismatch);
      expect(unbound.status).toBe("unbound");
    }
  });

  it("treats an unreadable expected tool as incomplete", () => {
    expect(incomplete(captureToolInvocation({ tool: rawTool, input: {} }, "C:/work", { name: "bash" })))
      .toBe("expected-tool-unavailable");
  });

  it("accepts the arguments alias and a pre-nested definition", () => {
    const result = captureToolInvocation({
      tool: {
        identity: { name: "bash", origin: "builtin:bash", revision: "7" },
        description: "Run a shell command",
        parameters: rawTool.parameters,
      },
      arguments: { command: "pwd" },
    }, "C:/work");

    expect(captured(result).arguments).toEqual({ command: "pwd" });
  });
});

function capability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    available: true,
    enforcesAllLimits: true,
    boundary: "windows-mxc",
    actionDigest: "action-digest-1",
    executionBinding: {
      status: "bound",
      owner: "pi-sandbox:controlled-execution",
      toolName: "bash",
      bindingId: "builtin-and-mcp:v1",
      revision: "rev-7",
    },
    ...overrides,
  };
}

describe("validateShellSandboxCapability", () => {
  it("returns a validated capability and identity for a matching proof", () => {
    const validated = validateShellSandboxCapability(capability(), "action-digest-1", "bash", "rev-7");

    expect(validated).toEqual({
      available: true,
      enforcesAllLimits: true,
      boundary: "windows-mxc",
      actionDigest: "action-digest-1",
      executionBinding: {
        status: "bound",
        owner: "pi-sandbox:controlled-execution",
        toolName: "bash",
        bindingId: "builtin-and-mcp:v1",
        revision: "rev-7",
      },
    });
    expect(Object.isFrozen(validated)).toBe(true);
  });

  it("returns undefined for an absent or non-object capability", () => {
    expect(validateShellSandboxCapability(undefined, "d", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(null, "d", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability("sandbox", "d", "bash", "rev-7")).toBeUndefined();
  });

  it("rejects a proof for a different action digest, tool name or registration revision", () => {
    expect(validateShellSandboxCapability(capability(), "other-digest", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability(), "action-digest-1", "powershell", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability(), "action-digest-1", "bash", "rev-8")).toBeUndefined();
  });

  it("rejects missing or malformed required fields", () => {
    expect(validateShellSandboxCapability(capability({ available: "yes" }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ enforcesAllLimits: undefined }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ boundary: undefined }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ actionDigest: undefined }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ executionBinding: undefined }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ boundary: "  " }), "action-digest-1", "bash", "rev-7")).toBeDefined();
  });

  it("rejects an execution identity that is not bound or is incomplete", () => {
    expect(validateShellSandboxCapability(capability({
      executionBinding: { status: "unbound", owner: "o", toolName: "bash", bindingId: "b", revision: "rev-7" },
    }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({
      executionBinding: { status: "bound", toolName: "bash", bindingId: "b", revision: "rev-7" },
    }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({
      executionBinding: { status: "bound", owner: "o", toolName: "bash", revision: "rev-7" },
    }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({
      executionBinding: { status: "bound", owner: "o", toolName: "bash", bindingId: "b", revision: 7 },
    }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
  });

  it("rejects unknown fields on the capability or its identity", () => {
    expect(validateShellSandboxCapability(capability({ extra: true }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({
      executionBinding: { status: "bound", owner: "o", toolName: "bash", bindingId: "b", revision: "rev-7", extra: true },
    }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
  });

  it("rejects a non-string reason and passes a string reason through", () => {
    expect(validateShellSandboxCapability(capability({ reason: 7 }), "action-digest-1", "bash", "rev-7")).toBeUndefined();
    expect(validateShellSandboxCapability(capability({ reason: "probe failed" }), "action-digest-1", "bash", "rev-7")?.reason)
      .toBe("probe failed");
  });

  it("accepts an identity without an explicit status and keeps unavailable capabilities for the caller", () => {
    const validation = validateShellSandboxCapability(capability({
      available: false,
      enforcesAllLimits: false,
      boundary: "none",
      executionBinding: { owner: "o", toolName: "bash", bindingId: "b", revision: "rev-7" },
    }), "action-digest-1", "bash", "rev-7");

    expect(validation?.available).toBe(false);
    expect(validation?.enforcesAllLimits).toBe(false);
    expect(validation?.boundary).toBe("none");
  });
});
