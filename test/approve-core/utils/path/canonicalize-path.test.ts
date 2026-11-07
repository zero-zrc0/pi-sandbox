import { describe, expect, it } from "vitest";
import { canonicalizePath, canonicalizePathSync } from "#approve-core/utils/path/canonicalize-path";

const realMap: Record<string, string> = {
  "/proj": "/real/proj",
  "/proj/src": "/real/proj/src",
  "/real": "/real",
};

function realpath(path: string): string {
  if (path in realMap) return realMap[path];
  const error = new Error("missing") as Error & { code: string };
  error.code = "ENOENT";
  throw error;
}

const realpathAsync = (path: string): Promise<string> => Promise.resolve().then(() => realpath(path));

describe("canonicalizePath", () => {
  it("resolves the longest existing ancestor and appends the non-existent tail", async () => {
    await expect(canonicalizePath("/proj/src/new/dir", { realpath: realpathAsync })).resolves.toBe(
      "/real/proj/src/new/dir",
    );
    await expect(canonicalizePath("/proj", { realpath: realpathAsync })).resolves.toBe("/real/proj");
  });

  it("resolves a symlinked nearest ancestor before a more distant directory", async () => {
    const resolve = async (path: string): Promise<string> => {
      if (path === "/work/link") return "/outside";
      if (path === "/work") return path;
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    };
    await expect(canonicalizePath("/work/link/new.txt", { realpath: resolve })).resolves.toBe("/outside/new.txt");
  });

  it("keeps ENOENT and ENOTDIR retriable while walking upward", async () => {
    const notDir = new Error("not dir") as Error & { code: string };
    notDir.code = "ENOTDIR";
    await expect(
      canonicalizePath("/proj/file/child", {
        realpath: (p) => Promise.resolve().then(() => {
          if (p === "/proj/file") throw notDir;
          return realpath(p);
        }),
      }),
    ).resolves.toBe("/real/proj/file/child");
  });

  it("returns the original on non-retriable errors", async () => {
    const denied = new Error("denied") as Error & { code: string };
    denied.code = "EACCES";
    await expect(canonicalizePath("/proj/x", { realpath: () => Promise.reject(denied) })).resolves.toBe("/proj/x");
  });

  it("returns the original when no ancestor resolves", async () => {
    await expect(canonicalizePath("/missing/also-missing", { realpath: realpathAsync })).resolves.toBe(
      "/missing/also-missing",
    );
  });

  it("returns empty input unchanged", async () => {
    await expect(canonicalizePath("", { realpath: realpathAsync })).resolves.toBe("");
  });
});

describe("canonicalizePathSync", () => {
  it("matches the async variant", () => {
    expect(canonicalizePathSync("/proj/src/new", { realpath })).toBe("/real/proj/src/new");
    expect(canonicalizePathSync("/missing/x", { realpath })).toBe("/missing/x");
    expect(canonicalizePathSync("", { realpath })).toBe("");
  });

  it("resolves the nearest existing Windows ancestor before appending the tail", () => {
    const resolve = (path: string): string => {
      if (path === "C:\\work\\link") return "D:\\outside";
      if (path === "C:\\work") return path;
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    };
    expect(canonicalizePathSync("C:\\work\\link\\new.txt", { realpath: resolve })).toBe("D:\\outside\\new.txt");
  });
});
