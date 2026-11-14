import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  compileExecutionPlan,
  executionPlanVerifies,
  filterExecutionEnvironment,
  selectExecutionEnvironment,
} from "#sandbox/plan";
import { PROTECTED_CONTROL_DIRECTORY_NAMES } from "#sandbox/path";
import {
  BINDING_ID,
  CONFIG_REVISION,
  OWNER,
  POLICY_REVISION,
  compileTestPlan,
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
    const systemBubblewrapPath = join(workspace, "..", ".local", "bin", "bwrap");
    const facts = invocation();
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "builtin-tool", name: "write", arguments: { path: "out.txt", content: "data" } },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
      protectedPaths: [systemBubblewrapPath],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason);
    expect(result.plan.protectedPaths).toContain(systemBubblewrapPath);
  });

  it("does not let an approved destination cross the configured network ceiling", () => {
    const facts = invocation([{ id: "network", surface: "network", target: "api.example.com:443", access: "network", state: "allow", source: "user" }]);
    const input = {
      invocation: facts, operation: { kind: "write-file" as const, path: join(workspace, "out.txt"), content: "data" },
      mode: "default" as const, owner: OWNER, bindingId: BINDING_ID,
      baseline: { filesystem: [{ path: workspace, access: "write" as const, granularity: "directory" as const }], network: { kind: "none" as const } },
      approved: { filesystem: [], network: [{ host: "api.example.com", port: 443 }] }, backendId: "fixture-helper",
      policyRevision: POLICY_REVISION, configRevision: CONFIG_REVISION, deadlineAt: Date.now() + 30_000, environment: {},
    };
    const denied = compileExecutionPlan({ ...input, networkCeiling: { kind: "none" } });
    expect(denied.ok && denied.plan.network).toEqual({ kind: "none" });
    const allowed = compileExecutionPlan({ ...input, networkCeiling: { kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] } });
    expect(allowed.ok && allowed.plan.network).toEqual({ kind: "destinations", destinations: [{ host: "api.example.com", port: 443 }] });
  });
  it("binds a complete builtin tool and every argument to the original invocation", () => {
    const facts = invocation();
    const input = {
      invocation: facts, mode: "default" as const, owner: OWNER, bindingId: BINDING_ID,
      baseline: { filesystem: [{ path: workspace, access: "write" as const, granularity: "directory" as const }], network: { kind: "none" as const } },
      approved: { filesystem: [] }, backendId: "fixture-helper", policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION, deadlineAt: Date.now() + 30_000, environment: {},
    };
    expect(compileExecutionPlan({ ...input, operation: { kind: "builtin-tool", name: "write", arguments: { path: "out.txt", content: "data" } } }).ok).toBe(true);
    expect(compileExecutionPlan({ ...input, operation: { kind: "builtin-tool", name: "write", arguments: { path: "out.txt", content: "mutated" } } })).toMatchObject({ ok: false });
    expect(compileExecutionPlan({ ...input, operation: { kind: "builtin-tool", name: "read", arguments: { path: "out.txt", content: "data" } } })).toMatchObject({ ok: false });
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
    const plan = compileTestPlan({
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

    expect(plan.version).toBe(2);
    expect(plan.requestId).toBe(facts.action.requestId);
    expect(plan.toolCallId).toBe(facts.action.toolCallId);
    expect(plan.actionDigest).toBe(facts.digest);
    expect(plan.sessionId).toBe(facts.requester.sessionId);
    expect(plan.tool).toMatchObject({
      name: "write",
      owner: OWNER,
      bindingId: BINDING_ID,
      revision: facts.action.tool.revision,
    });
    expect(plan.mode).toBe("default");
    expect(plan.policyRevision).toBe(POLICY_REVISION);
    expect(plan.configRevision).toBe(CONFIG_REVISION);
    expect(plan.cwd).toBe(workspace);
    expect(plan.backend).toEqual({ id: "fixture-helper" });
    expect(plan.environment).toEqual({ PATH: "C:\\Windows\\System32" });
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
    expect(plan.deadlineAt).toBeGreaterThan(Date.now());
    expect(executionPlanVerifies(plan)).toBe(true);
  });

  it("rejects an approved grant without an exact allow scope", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "data" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
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
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
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
      operation: { kind: "write-file", path: join(workspace, "out.txt"), content: "data" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
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
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("keeps protected control directories behind an exact approved file grant", () => {
    const target = join(workspace, ".git", "config");
    const facts = invocation([
      {
        id: "scope-1",
        surface: "write",
        target,
        access: "write",
        state: "allow",
        source: "user",
      },
    ]);
    const denied = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "write-file", path: target, content: "x" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(denied).toEqual(
      expect.objectContaining({ ok: false, code: "protected-path" }),
    );

    const allowed = compileTestPlan({
      invocation: facts,
      operation: { kind: "write-file", path: target, content: "x" },
      workspace,
      approved: {
        filesystem: [{ path: target, access: "write", granularity: "file" }],
      },
    });
    expect(allowed.protectedPaths).toContain(join(workspace, ".git"));
    expect(
      allowed.protectedPaths.some((path) =>
        PROTECTED_CONTROL_DIRECTORY_NAMES.some((name) => path.endsWith(name)),
      ),
    ).toBe(true);
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
    const denied = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "read-file", path: target },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(denied).toEqual(
      expect.objectContaining({ ok: false, code: "protected-path" }),
    );

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
    expect(allowed.protectedPaths).toContain(join(workspace, ".aws"));
  });

  it("rejects a directory write grant inside a protected control path", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "read-file", path: join(workspace, "README.md") },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
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
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "protected-path" }),
    );
  });

  it("does not cover a sibling directory whose name shares a prefix", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "read-file", path: `${workspace}-evil/secret.txt` },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("records the host-approved shell interpreter in a shell plan", () => {
    const command = "echo ok";
    const facts = makeInvocation({
      cwd: workspace,
      toolName: "bash",
      args: { command },
    });
    const plan = compileTestPlan({
      invocation: facts,
      operation: { kind: "shell", command },
      workspace,
      shell: "C:\\Windows\\System32\\cmd.exe",
    });
    expect(plan.operation).toMatchObject({
      kind: "shell",
      command,
      shell: "C:\\Windows\\System32\\cmd.exe",
    });
  });

  it("rejects a canonical path that escapes the approved scope", () => {
    const lexical = join(workspace, "link", "secret.txt");
    const outside = process.platform === "win32" ? "C:\\outside\\secret.txt" : "/outside/secret.txt";
    const facts = makeInvocation({
      cwd: workspace,
      toolName: "read",
      args: { path: join("link", "secret.txt") },
    });
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "read-file", path: lexical },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
      resolvePath: (path) => (path === lexical ? outside : path),
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
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
      operation: { kind: "read-file", path: link },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [{ path: link, access: "read", granularity: "file" }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
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
      operation: { kind: "shell", command: "echo ok" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "read", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [],
        network: [{ host: "other.example.com", port: 443 }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
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
      operation: { kind: "shell", command: "echo ok" } as const,
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
      operation: { kind: "shell", command: "echo ok" } as const,
      workspace,
    };
    expect(
      compileExecutionPlan({
        ...base,
        mode: "default",
        owner: OWNER,
        bindingId: BINDING_ID,
        baseline: {
          filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
          network: {
            kind: "destinations",
            destinations: [{ host: "a.example.com", port: 0 }],
          },
        },
        approved: { filesystem: [] },
        backendId: "fixture-helper",
        policyRevision: POLICY_REVISION,
        configRevision: CONFIG_REVISION,
        deadlineAt: Date.now() + 30_000,
        environment: {},
      }),
    ).toEqual(expect.objectContaining({ ok: false, code: "scope-expansion" }));

    const compiled = compileExecutionPlan({
      ...base,
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [{ path: workspace, access: "write", granularity: "directory" }],
        network: { kind: "none" },
      },
      approved: {
        filesystem: [],
        network: [{ host: "unapproved.example.com", port: 443 }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
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

  it("rejects environment names outside the allowlist before execution", () => {
    expect(
      filterExecutionEnvironment({ CONTROLLER_API_KEY: "secret" }),
    ).toEqual(
      expect.objectContaining({ ok: false }),
    );
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: { CONTROLLER_API_KEY: "secret" },
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "environment-not-allowed" }),
    );
  });

  it("rejects past, invalid and over-horizon deadlines", () => {
    const facts = invocation([]);
    const base = {
      invocation: facts,
      operation: { kind: "shell" as const, command: "echo ok" },
      mode: "default" as const,
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" as const } },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      environment: {},
    };
    expect(
      compileExecutionPlan({ ...base, deadlineAt: Date.now() - 1 }),
    ).toEqual(expect.objectContaining({ ok: false, code: "deadline-invalid" }));
    expect(
      compileExecutionPlan({ ...base, deadlineAt: Number.NaN }),
    ).toEqual(expect.objectContaining({ ok: false, code: "deadline-invalid" }));
    expect(
      compileExecutionPlan({
        ...base,
        deadlineAt: Date.now() + 25 * 60 * 60 * 1000,
      }),
    ).toEqual(expect.objectContaining({ ok: false, code: "deadline-invalid" }));
  });

  it("refuses full access and detects a mutated plan", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      mode: "full-access",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "mode-not-sandboxed" }),
    );

    const plan = compileTestPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      workspace,
    });
    const mutated = {
      ...plan,
      operation: { kind: "shell" as const, command: "echo changed" },
    };
    expect(executionPlanVerifies(mutated)).toBe(false);
  });

  it("requires timing-safe integer deadlines and a future value", () => {
    const facts = invocation([]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 1.5,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "deadline-invalid" }),
    );
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
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "shell", command: "echo ok" },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: {
        filesystem: [
          { path: workspace, access: "write", granularity: "directory" },
        ],
        network: {
          kind: "destinations",
          destinations: [{ host: "example.com", port: 443 }],
        },
      },
      approved: { filesystem: [] },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: { PATH: "C:\\Windows\\System32" },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason);
    const plan = result.plan;
    for (const value of [
      plan,
      plan.tool,
      plan.operation,
      plan.environment,
      plan.filesystem,
      plan.filesystem[0],
      plan.protectedPaths,
      plan.network,
      (plan.network.kind === "destinations" ? plan.network.destinations : [])[0],
      plan.backend,
    ]) {
      expect(Object.isFrozen(value as object)).toBe(true);
    }
    expect(() => {
      (plan.operation as { command?: string }).command = "echo tampered";
    }).toThrow(TypeError);
  });

  it("checks an approved file's parent directory without a directory write grant", () => {
    const parent = process.platform === "win32" ? "D:\\data" : "/data";
    const file = join(parent, "report.txt");
    const facts = invocation([
      {
        id: "scope-1",
        surface: "write",
        target: file,
        access: "write",
        state: "allow",
        source: "user",
      },
    ]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "access-dir", path: parent, forFile: file },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: {
        filesystem: [{ path: file, access: "write", granularity: "file" }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.reason);
    expect(result.plan.operation).toEqual({
      kind: "access-dir",
      path: parent,
      forFile: file,
    });
    expect(
      result.plan.filesystem.filter((grant) => grant.granularity === "directory"),
    ).toEqual([]);
    expect(executionPlanVerifies(result.plan)).toBe(true);
  });

  it("refuses an access-dir whose file is not covered by a write grant", () => {
    const parent = process.platform === "win32" ? "D:\\data" : "/data";
    const file = join(parent, "report.txt");
    const facts = invocation([
      {
        id: "scope-1",
        surface: "read",
        target: file,
        access: "read",
        state: "allow",
        source: "user",
      },
    ]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "access-dir", path: parent, forFile: file },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: {
        filesystem: [{ path: file, access: "read", granularity: "file" }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "scope-expansion" }),
    );
  });

  it("refuses an access-dir that probes a directory other than the approved parent", () => {
    const file = process.platform === "win32" ? "D:\\data\\report.txt" : "/data/report.txt";
    const facts = invocation([
      {
        id: "scope-1",
        surface: "write",
        target: file,
        access: "write",
        state: "allow",
        source: "user",
      },
    ]);
    const result = compileExecutionPlan({
      invocation: facts,
      operation: { kind: "access-dir", path: process.platform === "win32" ? "D:\\other" : "/other", forFile: file },
      mode: "default",
      owner: OWNER,
      bindingId: BINDING_ID,
      baseline: { filesystem: [], network: { kind: "none" } },
      approved: {
        filesystem: [{ path: file, access: "write", granularity: "file" }],
      },
      backendId: "fixture-helper",
      policyRevision: POLICY_REVISION,
      configRevision: CONFIG_REVISION,
      deadlineAt: Date.now() + 30_000,
      environment: {},
    });
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: "unsupported-operation" }),
    );
  });
});
