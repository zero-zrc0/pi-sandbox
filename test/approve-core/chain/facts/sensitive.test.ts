import { describe, expect, it } from "vitest";
import type { CallState, UnitState } from "#approve-core/contracts";
import type { UnitAccessFact } from "#approve-core/chain/facts";
import {
  projectSensitiveFacts,
  sensitivePathCategory,
  type ProjectSensitiveFactsInput,
} from "#approve-core/chain/facts/sensitive";

const CWD = "/work/project";

function unit(unitId: string): UnitState {
  return { unitId, decision: "ask", reason: "initial", source: "initial", history: [] };
}

function callState(
  toolName: string,
  args: Readonly<Record<string, string>> = {},
): CallState {
  return {
    toolCallId: "call-1",
    toolName,
    arguments: args,
    argumentsDigest: "arguments-digest",
    digest: "call-digest",
    units: [unit("call-1:u1")],
  };
}

function input(
  access: readonly UnitAccessFact[],
  overrides: Partial<ProjectSensitiveFactsInput> = {},
): ProjectSensitiveFactsInput {
  return { call: callState("bash", { command: "true" }), access, cwd: CWD, ...overrides };
}

describe("projectSensitiveFacts — direction and family mapping", () => {
  it("maps a relative dotenv write to an absolute write reference", () => {
    const refs = projectSensitiveFacts(input([{ kind: "write", path: ".env" }], {
      platform: "linux",
    }));
    expect(refs).toEqual([{ path: `${CWD}/.env`, category: "dotenv", surface: "write" }]);
  });

  it("maps a dotenv variant write", () => {
    const refs = projectSensitiveFacts(input([{ kind: "write", path: `${CWD}/.env.local` }], {
      platform: "linux",
    }));
    expect(refs).toEqual([{ path: `${CWD}/.env.local`, category: "dotenv", surface: "write" }]);
  });

  it("maps a .git write", () => {
    const refs = projectSensitiveFacts(input([{ kind: "write", path: `${CWD}/.git/config` }], {
      platform: "linux",
    }));
    expect(refs).toEqual([{ path: `${CWD}/.git/config`, category: "git", surface: "write" }]);
  });

  it("maps the .git directory itself", () => {
    const refs = projectSensitiveFacts(input([{ kind: "write", path: `${CWD}/.git` }], {
      platform: "linux",
    }));
    expect(refs[0]?.category).toBe("git");
  });

  it.each([
    ["read of an SSH key", "read", "/home/me/.ssh/id_rsa", "ssh", "read"],
    ["write of an SSH key", "write", "/home/me/.ssh/id_rsa", "ssh", "write"],
    ["read of the .ssh directory", "read", "/home/me/.ssh", "ssh", "read"],
    ["read of a public key", "read", "/home/me/.ssh/id_ed25519.pub", "ssh", "read"],
    ["read of AWS credentials", "read", "/home/me/.aws/credentials", "aws", "read"],
    ["write of a pem key", "write", "/work/project/certs/server.pem", "private-key", "write"],
    ["write of a .key file", "write", "/work/project/certs/server.key", "private-key", "write"],
    ["write of .netrc", "write", "/home/me/.netrc", "cloud-credentials", "write"],
    ["write of .npmrc", "write", "/home/me/.npmrc", "cloud-credentials", "write"],
  ] as const)("maps %s", (_name, kind, path, category, surface) => {
    const refs = projectSensitiveFacts(input([{ kind, path }], { platform: "linux" }));
    expect(refs).toEqual([{ path, category, surface }]);
  });

  it("maps a cloud config directory on the POSIX path language", () => {
    const refs = projectSensitiveFacts(input(
      [{ kind: "read", path: "/home/me/.config/gcloud/credentials.db" }],
      { platform: "linux" },
    ));
    expect(refs[0]?.category).toBe("cloud-credentials");
    expect(refs[0]?.surface).toBe("read");
  });

  it("maps an external delete to the delete surface", () => {
    const refs = projectSensitiveFacts(input(
      [{
        kind: "write",
        path: "C:\\Users\\me\\.ssh\\id_rsa",
        external: true,
        externalDelete: true,
      }],
      { platform: "win32", cwd: "C:\\work" },
    ));
    expect(refs).toEqual([{
      path: "C:\\Users\\me\\.ssh\\id_rsa",
      category: "ssh",
      surface: "delete",
    }]);
  });

  it("ignores externalDelete on a read", () => {
    const refs = projectSensitiveFacts(input(
      [{ kind: "read", path: `${CWD}/.env`, externalDelete: true }],
      { platform: "linux" },
    ));
    expect(refs[0]?.surface).toBe("read");
  });

  it.each([
    ["unknown", "/work/project/.env"],
    ["network", "/work/project/.env"],
    ["review", "/work/project/.git/config"],
  ] as const)("produces nothing for a %s fact", (kind, path) => {
    const refs = projectSensitiveFacts(input([{ kind, path }], { platform: "linux" }));
    expect(refs).toEqual([]);
  });

  it("produces nothing for an ordinary path", () => {
    const refs = projectSensitiveFacts(input(
      [{ kind: "write", path: `${CWD}/src/app.ts` }],
      { platform: "linux" },
    ));
    expect(refs).toEqual([]);
  });

  it("collapses identical path/surface repeats", () => {
    const refs = projectSensitiveFacts(input([
      { kind: "write", path: `${CWD}/.env` },
      { kind: "write", path: `${CWD}/.env` },
    ], { platform: "linux" }));
    expect(refs).toHaveLength(1);
    expect(refs[0]?.surface).toBe("write");
  });

  it("keeps one reference per surface for the same path", () => {
    const refs = projectSensitiveFacts(input([
      { kind: "write", path: `${CWD}/.env` },
      { kind: "read", path: `${CWD}/.env` },
      { kind: "write", path: `${CWD}/.env` },
    ], { platform: "linux" }));
    expect(refs.map((ref) => ref.surface)).toEqual(["write", "read"]);
    expect(refs.every((ref) => ref.path === `${CWD}/.env`)).toBe(true);
  });

  it("does not treat a lookalike segment as protected", () => {
    for (const path of [`${CWD}/.gitignore`, `${CWD}/.envrc`, `${CWD}/git/config`]) {
      expect(projectSensitiveFacts(input([{ kind: "write", path }], { platform: "linux" })))
        .toEqual([]);
    }
  });
});

describe("projectSensitiveFacts — path language and call fallback", () => {
  it("folds categories case-insensitively on win32", () => {
    const refs = projectSensitiveFacts(input(
      [{ kind: "read", path: "C:\\Users\\me\\.SSH\\KNOWN_HOSTS_ID_RSA" }],
      { platform: "win32", cwd: "C:\\work" },
    ));
    expect(refs).toEqual([{
      path: "C:\\Users\\me\\.SSH\\KNOWN_HOSTS_ID_RSA",
      category: "ssh",
      surface: "read",
    }]);
  });

  it("keeps case-sensitive matching on the POSIX path language", () => {
    expect(sensitivePathCategory("/home/me/.SSH/known_hosts", "linux")).toBeUndefined();
    expect(sensitivePathCategory("/home/me/.ssh/known_hosts", "linux")).toBe("ssh");
  });

  it("uses the call's path argument when a direction fact has no path", () => {
    const call = callState("write", { path: `${CWD}/.env` });
    const refs = projectSensitiveFacts({
      call,
      access: [{ kind: "write" }],
      cwd: CWD,
      platform: "linux",
    });
    expect(refs).toEqual([{ path: `${CWD}/.env`, category: "dotenv", surface: "write" }]);
  });

  it("has no call-level path fallback for a shell call", () => {
    const call = callState("bash", { command: "cat .env" });
    const refs = projectSensitiveFacts({
      call,
      access: [{ kind: "read" }],
      cwd: CWD,
      platform: "linux",
    });
    expect(refs).toEqual([]);
  });

  it("ignores empty and whitespace-only paths", () => {
    const refs = projectSensitiveFacts(input([
      { kind: "write", path: "   " },
      { kind: "read", path: "" },
    ], { platform: "linux" }));
    expect(refs).toEqual([]);
  });

  it("returns a frozen list of frozen references", () => {
    const refs = projectSensitiveFacts(input([{ kind: "write", path: `${CWD}/.env` }], {
      platform: "linux",
    }));
    expect(Object.isFrozen(refs)).toBe(true);
    expect(refs.every((ref) => Object.isFrozen(ref))).toBe(true);
  });

  it("exposes the family classifier for audit and tests", () => {
    expect(sensitivePathCategory(`${CWD}/.env`, "linux")).toBe("dotenv");
    expect(sensitivePathCategory(`${CWD}/.git/HEAD`, "linux")).toBe("git");
    expect(sensitivePathCategory("C:\\work\\.config\\gh\\hosts.yml", "win32"))
      .toBe("cloud-credentials");
    expect(sensitivePathCategory(`${CWD}/src/app.ts`, "linux")).toBeUndefined();
  });
});
