import { join } from "node:path";

import {
  realpathSync,
  rmdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";

import { describe, expect, it } from "vitest";

import {
  capabilityGap,
  requiredCapabilities,
  resolveTrustedHelper,
  versionMatches,
  type RequiredCapabilities,
} from "#sandbox/helper";
import type { BackendCapabilities } from "#sandbox/types";
import {
  createTestLayout,
  installFixtureHelper,
  makeInvocation,
  removeTestLayout,
} from "./fixtures/harness";
import { compileTestPlan } from "./fixtures/harness";

const capabilities: BackendCapabilities = {
  filesystem: {
    read: true,
    write: true,
    granularity: "directory",
    protectedPaths: false,
    environment: false,
  },
  network: "none",
  cancel: false,
  streamOutput: false,
  startedNotification: true,
  processTree: false,
};

function baseRequired(): RequiredCapabilities {
  return {
    read: false,
    write: false,
    fileGranularity: false,
    protectedPaths: false,
    environment: false,
    network: "domains",
    cancel: true,
    streamOutput: true,
    startedNotification: true,
    processTree: true,
  };
}

describe("trusted helper resolution", () => {
  it("resolves a host-owned install root and node script", () => {
    const layout = createTestLayout();
    try {
      const installation = installFixtureHelper(layout);
      const result = resolveTrustedHelper(installation, {
        cwd: layout.helperCwd,
      });
      expect(result.ok).toBe(true);
    } finally {
      removeTestLayout(layout);
    }
  });

  it("rejects a helper selected from the workspace or cwd", () => {
    const layout = createTestLayout();
    try {
      const installation = {
        ...installFixtureHelper(layout),
        installRoot: layout.workspace,
      };
      expect(
        resolveTrustedHelper(installation, { cwd: layout.workspace }),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
      expect(
        resolveTrustedHelper(installation, { cwd: join(layout.workspace, "sub") }),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
      expect(
        resolveTrustedHelper(installation, {
          cwd: layout.helperCwd,
          workspace: layout.workspace,
        }),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
    } finally {
      removeTestLayout(layout);
    }
  });

  it("rejects a node script outside the install root", () => {
    const layout = createTestLayout();
    try {
      const installation = {
        installRoot: layout.installRoot,
        executable: process.execPath,
        args: [join(layout.workspace, "other.mjs")],
      };
      expect(
        resolveTrustedHelper(installation, { cwd: layout.helperCwd }),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
    } finally {
      removeTestLayout(layout);
    }
  });

  it("reports a missing installation and executable distinctly", () => {
    const layout = createTestLayout();
    try {
      expect(
        resolveTrustedHelper(
          {
            installRoot: join(layout.root, "missing"),
            executable: process.execPath,
          },
          { cwd: layout.helperCwd },
        ),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-unavailable" }),
      );
      expect(
        resolveTrustedHelper(
          {
            installRoot: layout.installRoot,
            executable: join(layout.installRoot, "missing.exe"),
          },
          { cwd: layout.helperCwd },
        ),
      ).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-unavailable" }),
      );
    } finally {
      removeTestLayout(layout);
    }
  });

  it("rejects an install root whose junction resolves into the workspace", () => {
    const layout = createTestLayout();
    const junction = join(layout.root, "root-junction");
    try {
      writeFileSync(join(layout.workspace, "sneaky.mjs"), "// host file\n", "utf8");
      symlinkSync(layout.workspace, junction, "junction");
      const result = resolveTrustedHelper(
        {
          installRoot: junction,
          executable: process.execPath,
          args: [join(junction, "sneaky.mjs")],
        },
        { cwd: layout.helperCwd, workspace: layout.workspace },
      );
      expect(result).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
      if (result.ok) return;
      expect(result.reason).toContain("workspace");
    } finally {
      rmdirSync(junction);
      removeTestLayout(layout);
    }
  });

  it("rejects a script that sits lexically inside the root but resolves into the workspace", () => {
    const layout = createTestLayout();
    const linked = join(layout.installRoot, "linked");
    try {
      installFixtureHelper(layout);
      writeFileSync(join(layout.workspace, "victim.mjs"), "// host file\n", "utf8");
      symlinkSync(layout.workspace, linked, "junction");
      const result = resolveTrustedHelper(
        {
          installRoot: layout.installRoot,
          executable: process.execPath,
          args: [join(linked, "victim.mjs")],
        },
        { cwd: layout.helperCwd, workspace: layout.workspace },
      );
      expect(result).toEqual(
        expect.objectContaining({ ok: false, code: "sandbox-setup-failed" }),
      );
      if (result.ok) return;
      expect(result.reason).toContain("install root");
    } finally {
      rmdirSync(linked);
      removeTestLayout(layout);
    }
  });

  it("keeps a host-pinned node interpreter that lives outside the install root", () => {
    const layout = createTestLayout();
    try {
      const result = resolveTrustedHelper(installFixtureHelper(layout), {
        cwd: layout.helperCwd,
        workspace: layout.workspace,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.installation.executable).toBe(
        realpathSync.native(process.execPath),
      );
      expect(result.installation.installRoot).toBe(
        realpathSync.native(layout.installRoot),
      );
    } finally {
      removeTestLayout(layout);
    }
  });

  it("checks protocol, backend id and version expectations", () => {
    const installation = {
      installRoot: "C:\\helper",
      executable: "C:\\helper\\helper.exe",
      expectedProtocolVersion: 2,
      expectedBackendId: "fixture-helper",
      expectedBackendVersion: "1.0.0",
    };
    expect(versionMatches(installation, 2, "1.0.0", "fixture-helper")).toBe(true);
    expect(versionMatches(installation, 3, "1.0.0", "fixture-helper")).toBe(false);
    expect(versionMatches(installation, 2, "1.0.0", "other")).toBe(false);
    expect(versionMatches(installation, 1, "2.0.0", "fixture-helper")).toBe(false);
  });
});

describe("backend capability negotiation", () => {
  it("lists every requirement a coarse backend cannot express", () => {
    const workspace = process.platform === "win32" ? "C:\\work\\project" : "/work/project";
    const notes = join(workspace, "notes.txt");
    const invocation = makeInvocation({
      cwd: workspace,
      toolName: "read",
      args: { path: "notes.txt" },
      scopes: [
        {
          id: "read-1",
          surface: "read",
          target: notes,
          access: "read",
          state: "allow",
          source: "user",
        },
      ],
    });
    const plan = compileTestPlan({
      invocation,
      operation: { kind: "read-file", path: notes },
      workspace,
      approved: {
        filesystem: [{ path: notes, access: "read", granularity: "file" }],
      },
      environment: { PATH: "C:\\Windows\\System32" },
    });
    const gaps = capabilityGap(capabilities, requiredCapabilities(plan));
    expect(gaps).toEqual(
      expect.arrayContaining([
        "filesystem-file-granularity",
        "protected-path-deny",
        "environment-filter",
        "cancel",
        "stream-output",
        "process-tree",
      ]),
    );
  });

  it("does not let a coarse network capability satisfy a domain requirement", () => {
    const exact = {
      ...capabilities,
      filesystem: { ...capabilities.filesystem, granularity: "file" as const },
      cancel: true,
      streamOutput: true,
      processTree: true,
    };
    const required = baseRequired();
    expect(capabilityGap({ ...exact, network: "none" }, required)).toContain(
      "network-domains",
    );
    expect(capabilityGap({ ...exact, network: "all" }, required)).toContain(
      "network-domains",
    );
    expect(capabilityGap({ ...exact, network: "domains" }, required)).not.toContain(
      "network-domains",
    );
    expect(
      capabilityGap({ ...exact, network: "domains" }, {
        ...required,
        network: "all",
      }),
    ).not.toContain("network-all");
  });

  it("derives every network requirement level from the reported capability", () => {
    const exact: BackendCapabilities = {
      ...capabilities,
      filesystem: { ...capabilities.filesystem, granularity: "file" },
      cancel: true,
      streamOutput: true,
      processTree: true,
    };
    const levels = ["none", "all", "domains"] as const;
    const required = baseRequired();
    for (const reported of levels) {
      for (const wanted of levels) {
        const gaps = capabilityGap({ ...exact, network: reported }, {
          ...required,
          network: wanted,
        }).filter((gap) => gap.startsWith("network-"));
        // `none` needs nothing; `domains` is a superset capability that can
        // also execute unrestricted plans; everything else must match exactly.
        const satisfied =
          wanted === "none" ||
          wanted === reported ||
          (wanted === "all" && reported === "domains");
        if (satisfied) {
          expect(gaps, `required ${wanted} against ${reported}`).toEqual([]);
        } else {
          expect(gaps, `required ${wanted} against ${reported}`).toEqual([
            `network-${wanted}`,
          ]);
        }
      }
    }
  });
});
