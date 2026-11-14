import { describe, expect, it } from "vitest";
import {
  projectRulesLocation,
  resolvePiRoot,
  resolveProjectIdentity,
  slugifyProjectName,
  type PiRootInputs,
  type ProjectIdentityInputs,
} from "#approve-core/policy/project-rules/identity";
import type { ProjectIdentity } from "#approve-core/policy/project-rules/types";

/** A realpath stand-in for a directory that does not exist: best-effort use fails. */
const missing = (): string => {
  throw new Error("ENOENT");
};

function identityInputs(overrides: Partial<ProjectIdentityInputs>): ProjectIdentityInputs {
  return { cwd: "/repo/sub", platform: "posix", realpath: missing, ...overrides };
}

function piRootInputs(overrides: Partial<PiRootInputs>): PiRootInputs {
  return { home: "/home/u", ...overrides };
}

describe("slugifyProjectName", () => {
  it("lowercases and collapses non-alphanumerics into single hyphens", () => {
    expect(slugifyProjectName("My Project")).toBe("my-project");
    expect(slugifyProjectName("  Hello, World!  ")).toBe("hello-world");
    expect(slugifyProjectName("a__b..c")).toBe("a-b-c");
  });

  it("decomposes accents before folding", () => {
    expect(slugifyProjectName("Café Über")).toBe("cafe-uber");
  });

  it("caps the slug at 48 characters without a trailing hyphen", () => {
    expect(slugifyProjectName("a".repeat(60))).toBe("a".repeat(48));
    const slug = slugifyProjectName(`${"a".repeat(47)} bcd`);
    expect(slug).toBe("a".repeat(47));
    expect(slug.endsWith("-")).toBe(false);
  });

  it("falls back to project when nothing alphanumeric remains", () => {
    expect(slugifyProjectName("")).toBe("project");
    expect(slugifyProjectName("!!!")).toBe("project");
  });
});

describe("resolveProjectIdentity root selection", () => {
  it("prefers the git worktree root over an explicit project root and cwd", () => {
    const calls: string[][] = [];
    const identity = resolveProjectIdentity(identityInputs({
      projectRoot: "/explicit",
      runGit: (args) => {
        calls.push([...args]);
        return "/repo\n";
      },
    }));

    expect(identity).toMatchObject({ rootPath: "/repo", displayName: "repo", slug: "repo" });
    expect(calls).toEqual([["-C", "/repo/sub", "rev-parse", "--show-toplevel"]]);
  });

  it("uses the explicit project root when git reports no worktree", () => {
    const identity = resolveProjectIdentity(identityInputs({
      projectRoot: "/explicit",
      runGit: () => undefined,
    }));

    expect(identity).toMatchObject({ rootPath: "/explicit", displayName: "explicit", slug: "explicit" });
  });

  it("falls back to cwd when neither git nor an explicit root is available", () => {
    expect(resolveProjectIdentity(identityInputs({}))).toMatchObject({ rootPath: "/repo/sub" });
    expect(resolveProjectIdentity(identityInputs({ runGit: () => { throw new Error("not a repo"); } })))
      .toMatchObject({ rootPath: "/repo/sub" });
  });

  it("rejects a relative explicit project root instead of falling back", () => {
    expect(resolveProjectIdentity(identityInputs({ projectRoot: "relative/project" }))).toBeUndefined();
  });

  it("rejects an empty explicit project root instead of falling back", () => {
    expect(resolveProjectIdentity(identityInputs({ projectRoot: "   " }))).toBeUndefined();
  });

  it("rejects a relative or empty cwd when no root can be discovered", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "repo/sub" }))).toBeUndefined();
    expect(resolveProjectIdentity(identityInputs({ cwd: "" }))).toBeUndefined();
  });

  it("ignores a relative git root and keeps resolving", () => {
    const identity = resolveProjectIdentity(identityInputs({
      projectRoot: "/explicit",
      runGit: () => "repo/sub\n",
    }));

    expect(identity).toMatchObject({ rootPath: "/explicit" });
  });

  it("trims redundant trailing separators", () => {
    expect(resolveProjectIdentity(identityInputs({ projectRoot: "/work/app///" })))
      .toMatchObject({ rootPath: "/work/app" });
  });

  it("keeps the posix root marker", () => {
    expect(resolveProjectIdentity(identityInputs({ projectRoot: "/" }))).toMatchObject({
      rootPath: "/",
      displayName: "/",
      slug: "project",
    });
  });

  it("expands a leading tilde with the injected home", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "~/work/app", home: "/home/u" })))
      .toMatchObject({ rootPath: "/home/u/work/app", displayName: "app" });
  });

  it("rejects a tilde root when no home was provided", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "~/work/app" }))).toBeUndefined();
  });

  it("uses an injected realpath when the directory resolves", () => {
    const identity = resolveProjectIdentity(identityInputs({
      cwd: "/work/link",
      realpath: (path) => (path === "/work/link" ? "/work/real" : path),
    }));

    expect(identity).toMatchObject({ rootPath: "/work/real", displayName: "real", slug: "real" });
  });

  it("keeps the normalized root when realpath cannot resolve it", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "/work/app", realpath: missing })))
      .toMatchObject({ rootPath: "/work/app" });
  });

  it("ignores a non-absolute realpath result", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "/work/app", realpath: () => "relative" })))
      .toMatchObject({ rootPath: "/work/app" });
  });

  it("folds the Windows root to lowercase so case variants are one identity", () => {
    const upper = resolveProjectIdentity(identityInputs({
      cwd: "C:\\Work\\App",
      platform: "win32",
    }));
    const lower = resolveProjectIdentity(identityInputs({
      cwd: "c:\\work\\app",
      platform: "win32",
    }));

    expect(upper).toEqual(lower);
    expect(upper).toMatchObject({
      rootPath: "c:\\work\\app",
      displayName: "app",
      slug: "app",
    });
  });

  it("folds a Windows git root as well", () => {
    expect(resolveProjectIdentity(identityInputs({
      cwd: "C:\\Work\\App\\src",
      platform: "win32",
      runGit: () => "C:\\Work\\App\\\n",
    }))).toMatchObject({ rootPath: "c:\\work\\app", displayName: "app" });
  });

  it("does not fold case on posix", () => {
    const upper = resolveProjectIdentity(identityInputs({ cwd: "/Work/App" }));
    const lower = resolveProjectIdentity(identityInputs({ cwd: "/work/app" }));

    expect(upper).toMatchObject({ rootPath: "/Work/App", displayName: "App" });
    expect(upper?.identityHash).not.toBe(lower?.identityHash);
  });
});

describe("resolveProjectIdentity names and hash", () => {
  it("derives displayName from the root directory name", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "/srv/projects/app" })))
      .toMatchObject({ displayName: "app", slug: "app" });
    expect(resolveProjectIdentity(identityInputs({ cwd: "/work/My Project" })))
      .toMatchObject({ displayName: "My Project", slug: "my-project" });
  });

  it("produces a 16 character lowercase hexadecimal identity hash", () => {
    const identity = resolveProjectIdentity(identityInputs({ cwd: "/repo/app" }));

    expect(identity?.identityHash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("hashes the canonical identity fields", () => {
    const identity = resolveProjectIdentity(identityInputs({ cwd: "/repo/app" }));

    expect(identity?.identityHash).toBe("6a7d0f2360d36493");
  });

  it("normalizes the root before hashing", () => {
    const plain = resolveProjectIdentity(identityInputs({ cwd: "/repo/app" }));
    const trailing = resolveProjectIdentity(identityInputs({ cwd: "/repo/app///" }));

    expect(trailing?.identityHash).toBe(plain?.identityHash);
  });

  it("binds the hash to the root", () => {
    const first = resolveProjectIdentity(identityInputs({ cwd: "/repo/app" }));
    const second = resolveProjectIdentity(identityInputs({ cwd: "/repo/other" }));

    expect(first?.identityHash).not.toBe(second?.identityHash);
  });

  it("is deterministic across calls", () => {
    expect(resolveProjectIdentity(identityInputs({ cwd: "/repo/app" })))
      .toEqual(resolveProjectIdentity(identityInputs({ cwd: "/repo/app" })));
  });
});

describe("resolvePiRoot", () => {
  it("derives the pi root from an agent directory", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "/home/u/.pi/agent" }))).toBe("/home/u/.pi");
  });

  it("ignores trailing separators on the agent directory", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "/home/u/.pi/agent///" }))).toBe("/home/u/.pi");
  });

  it("derives a win32 pi root", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "C:\\Users\\u\\.pi\\agent" })))
      .toBe("C:\\Users\\u\\.pi");
  });

  it("does not treat an arbitrary directory as the pi root", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "/opt/picache" }))).toBe("/home/u/.pi");
  });

  it("requires the basename to be exactly agent", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "/home/u/.pi/agents" }))).toBe("/home/u/.pi");
  });

  it("falls back to home/.pi when no agent directory is given", () => {
    expect(resolvePiRoot({ home: "/home/u" })).toBe("/home/u/.pi");
    expect(resolvePiRoot(piRootInputs({}))).toBe("/home/u/.pi");
  });

  it("reads home from the environment", () => {
    expect(resolvePiRoot({ env: { HOME: "/env/home" } })).toBe("/env/home/.pi");
  });

  it("lets an explicit home beat the environment", () => {
    expect(resolvePiRoot({ home: "/explicit", env: { HOME: "/env/home" } })).toBe("/explicit/.pi");
  });

  it("reads the agent directory from the environment", () => {
    expect(resolvePiRoot({ env: { PI_CODING_AGENT_DIR: "/srv/pi/agent", HOME: "/env/home" } }))
      .toBe("/srv/pi");
  });

  it("lets an explicit agent directory beat the environment", () => {
    expect(resolvePiRoot({
      agentDir: "/custom/.pi/agent",
      env: { PI_CODING_AGENT_DIR: "/srv/pi/agent" },
    })).toBe("/custom/.pi");
  });

  it("does not promote a relative agent directory to the pi root", () => {
    expect(resolvePiRoot(piRootInputs({ agentDir: "agent" }))).toBe("/home/u/.pi");
  });

  it("falls back to home when the env agent directory is not named agent", () => {
    expect(resolvePiRoot({ env: { PI_CODING_AGENT_DIR: "/srv/pi/cache", HOME: "/env/home" } }))
      .toBe("/env/home/.pi");
  });
});

describe("projectRulesLocation", () => {
  const POSIX_IDENTITY: ProjectIdentity = {
    rootPath: "/repo/app",
    displayName: "app",
    slug: "app",
    identityHash: "0123456789abcdef",
  };
  const WIN32_IDENTITY: ProjectIdentity = {
    rootPath: "c:\\work\\app",
    displayName: "app",
    slug: "app",
    identityHash: "0123456789abcdef",
  };

  it("builds the project directory, rules file and lock path under the pi root", () => {
    expect(projectRulesLocation(POSIX_IDENTITY, "/home/u/.pi")).toEqual({
      directory: "/home/u/.pi/app--0123456789abcdef",
      filePath: "/home/u/.pi/app--0123456789abcdef/project-rules.json",
      lockPath: "/home/u/.pi/app--0123456789abcdef/project-rules.lock",
    });
  });

  it("joins win32 locations with the win32 flavour", () => {
    expect(projectRulesLocation(WIN32_IDENTITY, "C:\\Users\\u\\.pi")).toEqual({
      directory: "C:\\Users\\u\\.pi\\app--0123456789abcdef",
      filePath: "C:\\Users\\u\\.pi\\app--0123456789abcdef\\project-rules.json",
      lockPath: "C:\\Users\\u\\.pi\\app--0123456789abcdef\\project-rules.lock",
    });
  });

  it("normalizes a trailing separator on the pi root", () => {
    expect(projectRulesLocation(POSIX_IDENTITY, "/home/u/.pi///")).toEqual(
      projectRulesLocation(POSIX_IDENTITY, "/home/u/.pi"),
    );
  });

  it("keeps the rules file and its lock in the same project directory", () => {
    const location = projectRulesLocation(POSIX_IDENTITY, "/home/u/.pi");

    expect(location.filePath.startsWith(`${location.directory}/`)).toBe(true);
    expect(location.lockPath.startsWith(`${location.directory}/`)).toBe(true);
  });
});
