import { join } from "node:path";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { describe, expect, it } from "vitest";

import {
  captureExecutionRequest,
  compileExecutionPlan,
  filterExecutionEnvironment,
  selectExecutionEnvironment,
} from "#sandbox/plan";
import {
  CONFIG_REVISION,
  POLICY_REVISION,
  compileTestPlan,
  compileTestRequest,
  makeInvocation,
} from "./fixtures/harness";

const workspace = process.platform === "win32" ? "C:\\work\\project" : "/work/project";

function invocation(scopes: Parameters<typeof makeInvocation>[0]["scopes"] = []) {
  return makeInvocation({
    cwd: workspace,
    toolName: "write",
    args: { path: "out.txt", content: "data" },
    scopes,
  });
}

describe("execution plan compilation", () => {
  it("keeps the selected system bubblewrap binary in the protected paths", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-protected-runtime-"));
    const systemBubblewrapPath = join(root, "bwrap");
    writeFileSync(systemBubblewrapPath, "runtime");
    try {
      const result = compileExecutionPlan({
        invocation: makeInvocation({ cwd: root, toolName: "bash", args: { command: "true" } }),
        baseline: { filesystem: [{ path: root, access: "write", granularity: "directory" }], network: { kind: "none" } },
        approved: { filesystem: [] },
        protectedPaths: [systemBubblewrapPath],
      });
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error(result.reason);
      expect(result.plan.filesystem).toContainEqual(expect.objectContaining({ path: systemBubblewrapPath, access: "deny-write" }));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("does not let an approved destination cross the configured network ceiling", () => {
    const facts = invocation([{ id: "network", surface: "network", target: "api.example.com:443", access: "network", state: "allow", source: "user" }]);
    const input = {
      invocation: facts,

      baseline: { filesystem: [{ path: workspace, access: "write" as const, granularity: "directory" as const }], network: { kind: "none" as const } },
      approved: { filesystem: [], network: [{ host: "api.example.com", port: 443 }] },

    };
    const denied = compileExecutionPlan({ ...input, networkCeiling: { kind: "none" } });
    expect(denied.ok && denied.plan.network).toEqual({ kind: "none" });
    const allowed = compileExecutionPlan({ ...input, networkCeiling: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] } });
    expect(allowed.ok && allowed.plan.network).toEqual({ kind: "destinations", destinations: [{ host: "api.example.com", port: 443, source: "approved-extension" }] });
  });
  it("gives equal permissions the same digest across calls", () => {
    const baseline = { filesystem: [{ path: workspace, access: "write" as const, granularity: "directory" as const }], network: { kind: "none" as const } };
    const compile = (requestId: string, command: string) => compileExecutionPlan({
      invocation: makeInvocation({ cwd: workspace, toolName: "bash", requestId, toolCallId: requestId, args: { command } }),
      baseline,
      approved: { filesystem: [] },
    });
    const first = compile("first", "echo one");
    const second = compile("second", "echo two");
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok) throw new Error(first.reason);
    if (!second.ok) throw new Error(second.reason);
    expect(first.plan.digest).toBe(second.plan.digest);
  });
  it("preserves action, revisions, granularity, source, cwd, environment and deadline", () => {
    const facts = invocation([
      {
        id: "scope-1",
        surface: "write",
        target: join(workspace, "out.txt"),
        access: "write",
        state: "allow",
        source: "user",
      },
    ]);
    const request = compileTestRequest({
      invocation: facts,
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "data" },
      workspace,
      approved: {
        filesystem: [
          {
            path: join(workspace, "out.txt"),
            access: "write",
            granularity: "file",
          },
        ],
      },
      environment: { PATH: "C:\\Windows\\System32" },
      deadlineMs: 60_000,
    });

    const plan = request.plan;
    expect(plan.version).toBe(3);
    expect(request.requestId).toBe(facts.action.requestId);
    expect(request.toolCallId).toBe(facts.action.toolCallId);
    expect(request.actionDigest).toBe(facts.digest);
    expect(request.sessionId).toBe(facts.requester.sessionId);
    expect(request.toolName).toBe("write");
    expect(request.mode).toBe("default");
    expect(request.policyRevision).toBe(POLICY_REVISION);
    expect(request.configRevision).toBe(CONFIG_REVISION);
    expect(request.backendId).toBe("fixture-direct");
    expect(request.start.cwd).toBe(workspace);
    expect(request.start.environment).toEqual({ PATH: "C:\\Windows\\System32" });
    expect(plan.filesystem).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: workspace,
          access: "write",
          granularity: "directory",
          source: "baseline",
        }),
        expect.objectContaining({
          path: join(workspace, "out.txt"),
          access: "write",
          granularity: "file",
          source: "approved-extension",
        }),
      ]),
    );
    expect(request.start.deadlineAt).toBeGreaterThan(Date.now());
  });

  it("adds sensitive path rules to the permission digest", () => {
    const secret = join(workspace, "secret");
    const input = {
      invocation: invocation(),
      baseline: { filesystem: [
        { path: workspace, access: "read" as const, granularity: "directory" as const },
        { path: workspace, access: "write" as const, granularity: "directory" as const },
      ], network: { kind: "none" as const } },
      approved: { filesystem: [] },

      sensitivePaths: [{ requestedPath: secret, path: secret, granularity: "directory" as const,
        identity: { device: "1", inode: "2" } }],
    };
    const plan = compileExecutionPlan({ ...input });
    expect(plan.ok).toBe(true);
    if (!plan.ok) throw new Error(plan.reason);
    expect(plan.plan.filesystem).toContainEqual({ ...input.sensitivePaths[0], access: "deny-access", source: "protection" });
    const withoutSensitivePath = compileExecutionPlan({ ...input, sensitivePaths: [] });
    expect(withoutSensitivePath.ok).toBe(true);
    if (!withoutSensitivePath.ok) throw new Error(withoutSensitivePath.reason);
    expect(withoutSensitivePath.plan.digest).not.toBe(plan.plan.digest);
  });

  it("records runtime filesystem grants in the bound plan", () => {
    const runtimePath = join(workspace, "runtime");
    const result = compileExecutionPlan({
      invocation: invocation(),

      baseline: { filesystem: [{ path: workspace, access: "write", granularity: "directory" }], network: { kind: "none" } },
      runtimeFilesystem: [{ path: runtimePath, access: "read", granularity: "directory" }],
      approved: { filesystem: [] },

    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason);
    expect(result.plan.filesystem).toContainEqual({ path: runtimePath, access: "read", granularity: "directory", source: "runtime" });
    const withoutRuntime = compileExecutionPlan({
      invocation: invocation(),

      baseline: { filesystem: [{ path: workspace, access: "write", granularity: "directory" }], network: { kind: "none" } },
      approved: { filesystem: [] },

    });
    expect(withoutRuntime.ok).toBe(true);
    if (!withoutRuntime.ok) throw new Error(withoutRuntime.reason);
    expect(withoutRuntime.plan.digest).not.toBe(result.plan.digest);
  });

  it("rejects an approved grant without an exact allow scope", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,




      baseline: { filesystem: [], network: { kind: "none" } },
      approved: {
        filesystem: [
          {
            path: join(workspace, "out.txt"),
            access: "write",
            granularity: "file",
          },
        ],
      },





    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("does not widen a read approval into write", () => {
    const facts = invocation([
      {
        id: "scope-1",
        surface: "read",
        target: join(workspace, "out.txt"),
        access: "read",
        state: "allow",
        source: "user",
      },
    ]);
    const result = compileExecutionPlan({
      invocation: facts,




      baseline: { filesystem: [], network: { kind: "none" } },
      approved: {
        filesystem: [
          {
            path: join(workspace, "out.txt"),
            access: "write",
            granularity: "file",
          },
        ],
      },





    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("omits missing automatic control paths", () => {
    const target = join(workspace, ".git", "config");
    const plan = compileTestPlan({
      invocation: invocation(),
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "x" },
      workspace,
    });
    expect(plan.filesystem).not.toContainEqual(expect.objectContaining({ path: join(workspace, ".git"), access: "deny-write" }));
  });

  it("protects an existing control directory under a writable grant", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-plan-control-"));
    const git = join(root, ".git");
    mkdirSync(git);
    try {
      const target = join(git, "config");
      const facts = makeInvocation({ cwd: root, toolName: "write", args: { path: target, content: "x" }, scopes: [
        { id: "scope-1", surface: "write", target, access: "write", state: "allow", source: "user" },
      ] });
      const plan = compileTestPlan({
        invocation: facts,
        operation: { kind: "write-file", path: target, content: "x" },
        workspace: root,
        approved: { filesystem: [{ path: target, access: "write", granularity: "file" }] },
      });
      expect(plan.filesystem).toContainEqual(expect.objectContaining({ path: git, access: "deny-write" }));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("requires an exact approved read grant for a protected control read", () => {
    const target = join(workspace, ".aws", "credentials");
    const facts = invocation([
      {
        id: "scope-1",
        surface: "read",
        target,
        access: "read",
        state: "allow",
        source: "user",
      },
    ]);
    const allowed = compileTestPlan({
      invocation: facts,
      operation: { kind: "read-file", path: target },
      workspace,
      approved: {
        filesystem: [{ path: target, access: "read", granularity: "file" }],
      },
    });
    expect(allowed.filesystem).toContainEqual(
      expect.objectContaining({
        path: target,
        access: "read",
        granularity: "file",
        source: "approved-extension",
      }),
    );
  });

  it("rejects a directory write grant inside a protected control path", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,




      baseline: {
        filesystem: [
          {
            path: join(workspace, ".agents"),
            access: "write",
            granularity: "directory",
          },
        ],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },





    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "protected-path" }),
    );
  });

  it("records the host-approved shell interpreter in a shell plan", () => {
    const command = "echo ok";
    const facts = makeInvocation({
      cwd: workspace,
      toolName: "bash",
      args: { command },
    });
    const request = compileTestRequest({
      invocation: facts,
      operation: { kind: "shell", command },
      workspace,
      shell: "C:\\Windows\\System32\\cmd.exe",
    });
    expect(request.start.operation).toMatchObject({
      kind: "shell",
      command,
      shell: "C:\\Windows\\System32\\cmd.exe",
    });
  });

  it("rejects an approved grant whose canonical target differs from the approved path", () => {
    const link = join(workspace, "link.txt");
    const outside = process.platform === "win32" ? "C:\\outside\\secret.txt" : "/outside/secret.txt";
    const facts = makeInvocation({
      cwd: workspace,
      toolName: "read",
      args: { path: "link.txt" },
      scopes: [
        {
          id: "scope-1",
          surface: "read",
          target: link,
          access: "read",
          state: "allow",
          source: "user",
        },
      ],
    });
    const result = compileExecutionPlan({
      invocation: facts,




      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [{ path: link, access: "read", granularity: "file" }],
      },





      resolvePath: (path) => (path === link ? outside : path),
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
    if (!result.ok) {
      expect(result.reason).toContain("resolves to a different target");
    }
  });

  it("keeps the exact network destination and rejects an unapproved one", () => {
    const facts = invocation([
      {
        id: "net-1",
        surface: "network",
        target: "api.example.com:443",
        access: "network",
        state: "allow",
        source: "user",
      },
    ]);
    const approved = compileTestPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      workspace,
      approved: {
        network: [{ host: "api.example.com", port: 443 }],
      },
    });
    expect(approved.network).toEqual({
      kind: "destinations",
      destinations: [
        { host: "api.example.com", port: 443, source: "approved-extension" },
      ],
    });

    const denied = compileExecutionPlan({
      invocation: facts,




      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [],
        network: [{ host: "other.example.com", port: 443 }],
      },





    });
    expect(denied).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("keeps baseline network destinations and adds an approved extension", () => {
    const facts = invocation([
      {
        id: "net-1",
        surface: "network",
        target: "a.example.com:443",
        access: "network",
        state: "allow",
        source: "user",
      },
      {
        id: "net-2",
        surface: "network",
        target: "b.example.com:443",
        access: "network",
        state: "allow",
        source: "user",
      },
    ]);
    const plan = compileTestPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      workspace,
      network: {
        kind: "destinations",
        destinations: [{ host: "a.example.com", port: 443 }],
      },
      approved: { network: [{ host: "b.example.com", port: 443 }] },
    });
    expect(plan.network).toEqual({
      kind: "destinations",
      destinations: [
        { host: "a.example.com", port: 443, source: "baseline" },
        { host: "b.example.com", port: 443, source: "approved-extension" },
      ],
    });
    const all = compileTestPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      workspace,
      network: { kind: "all" },
      approved: { network: [{ host: "b.example.com", port: 443 }] },
    });
    expect(all.network).toEqual({ kind: "all" });
  });

  it("combines baseline and approved destinations without duplicating or widening", () => {
    const facts = invocation([
      {
        id: "net-1",
        surface: "network",
        target: "b.example.com:8443",
        access: "network",
        state: "allow",
        source: "user",
      },
      {
        id: "net-2",
        surface: "network",
        target: "a.example.com:443",
        access: "network",
        state: "allow",
        source: "user",
      },
    ]);
    const base = {
      invocation: facts,
      operation: { kind: "shell" as const, command: "echo ok" },
      workspace,
    };
    expect(
      compileTestPlan({
        ...base,
        network: {
          kind: "destinations",
          destinations: [
            { host: "a.example.com", port: 443 },
            { host: "b.example.com", port: 8443 },
          ],
        },
        approved: { network: [{ host: "b.example.com", port: 8443 }] },
      }).network,
    ).toEqual({
      kind: "destinations",
      destinations: [
        { host: "a.example.com", port: 443, source: "baseline" },
        { host: "b.example.com", port: 8443, source: "baseline" },
      ],
    });

    expect(
      compileTestPlan({
        ...base,
        network: {
          kind: "destinations",
          destinations: [{ host: "a.example.com" }],
        },
        approved: { network: [{ host: "a.example.com", port: 443 }] },
      }).network,
    ).toEqual({
      kind: "destinations",
      destinations: [{ host: "a.example.com", source: "baseline" }],
    });

    expect(
      compileTestPlan({
        ...base,
        network: { kind: "none" },
        approved: { network: [{ host: "b.example.com", port: 8443 }] },
      }).network,
    ).toEqual({
      kind: "destinations",
      destinations: [
        { host: "b.example.com", port: 8443, source: "approved-extension" },
      ],
    });

    expect(
      compileTestPlan({
        ...base,
        network: { kind: "none" },
        approved: { network: [] },
      }).network,
    ).toEqual({ kind: "none" });
  });

  it("refuses an invalid baseline destination and an extension without an allow scope", () => {
    const facts = invocation([]);
    const base = {
      invocation: facts,
      operation: { kind: "shell" as const, command: "echo ok" },
      workspace,
    };
    expect(
      compileExecutionPlan({
        ...base,



        baseline: {
          filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
          network: {
            kind: "destinations",
            destinations: [{ host: "a.example.com", port: 0 }],
          },
        },
        approved: { filesystem: [] },





      }),
    ).toEqual(expect.objectContaining({ ok: false, code: "scope-expansion" }));

    const compiled = compileExecutionPlan({
      ...base,



      baseline: {
        filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [],
        network: [{ host: "unapproved.example.com", port: 443 }],
      },





    });
    expect(compiled).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it.skipIf(process.platform !== "win32")("preserves Windows executable paths regardless of environment-name case", () => {
    expect(selectExecutionEnvironment({ Path: "C:\\tools", ComSpec: "C:\\Windows\\cmd.exe" })).toEqual({
      PATH: "C:\\tools",
      COMSPEC: "C:\\Windows\\cmd.exe",
    });
    expect(filterExecutionEnvironment({ ComSpec: "C:\\Windows\\cmd.exe" })).toEqual({
      ok: true,
      environment: { COMSPEC: "C:\\Windows\\cmd.exe" },
    });
  });

  it("filters environment names before creating a request", () => {
    expect(
      filterExecutionEnvironment({ CONTROLLER_API_KEY: "secret" }),
    ).toEqual(
      expect.objectContaining({ ok: false }),
    );
  });

  it("keeps call, mode, deadline and environment outside the permission digest", () => {
    const facts = invocation([]);
    const request = compileTestRequest({ invocation: facts, operation: { kind: "shell", command: "echo ok" }, workspace });
    const changedStart = compileTestRequest({ invocation: facts, operation: { kind: "shell", command: "echo changed" },
      workspace, mode: "auto-review", environment: { PATH: "C:\\Windows\\System32" }, deadlineMs: 60_000 });
    expect(changedStart.plan.digest).toBe(request.plan.digest);
    expect(captureExecutionRequest({ ...request, start: { ...request.start, deadlineAt: Number.NaN } })).toBeNull();
  });

  it("freezes every nested object and array of a compiled plan", () => {
    const facts = invocation([
      {
        id: "scope-1",
        surface: "write",
        target: join(workspace, "out.txt"),
        access: "write",
        state: "allow",
        source: "user",
      },
    ]);
    const request = compileTestRequest({ invocation: facts, operation: { kind: "shell", command: "echo ok" }, workspace,
      baselineFilesystem: [{ path: workspace, access: "write", granularity: "directory" }],
      network: { kind: "destinations", destinations: [{ host: "example.com", port: 443 }] } });
    const captured = captureExecutionRequest(request);
    expect(captured).not.toBeNull();
    if (!captured) throw new Error("request capture failed");
    const plan = captured.plan;
    for (const value of [
      plan,
      plan.filesystem,
      plan.filesystem[0],
      plan.network,
      (plan.network.kind === "destinations" ? plan.network.destinations : [])[0],
      captured.start,
      captured.start.operation,
      captured.start.environment,
    ]) {
      expect(Object.isFrozen(value as object)).toBe(true);
    }
    expect(() => {
      (captured.start.operation as { command?: string }).command = "echo tampered";
    }).toThrow(TypeError);
  });
});
