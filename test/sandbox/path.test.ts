import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { findProtectedControlReadRoot, findProtectedControlRoot, resolveHostPathIdentity } from "#sandbox/path";
describe("host path identity", () => {
  it("canonicalizes an existing parent and appends a missing target", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-execution-path-"));
    try {
      const target = join(root, "missing", "file.txt");
      const canonicalRoot = realpathSync.native(root);
      expect(resolveHostPathIdentity(target)).toBe(
        join(canonicalRoot, "missing", "file.txt"),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects relative and NUL-bearing values", () => {
    expect(resolveHostPathIdentity("relative/file.txt")).toBeNull();
    expect(resolveHostPathIdentity("C:\\bad\0name")).toBeNull();
  });

  it("treats .agents as write-protected but readable", () => {
    const skill = join(tmpdir(), "project", ".agents", "skills", "demo", "SKILL.md");
    expect(findProtectedControlRoot(skill)).toBe(join(tmpdir(), "project", ".agents"));
    expect(findProtectedControlReadRoot(skill)).toBeNull();
    expect(findProtectedControlReadRoot(join(tmpdir(), "project", ".git", "config")))
      .toBe(join(tmpdir(), "project", ".git"));
  });

  it("treats .codex as write-protected but readable like .agents", () => {
    const entry = join(tmpdir(), "project", ".codex", "config.toml");
    expect(findProtectedControlRoot(entry)).toBe(join(tmpdir(), "project", ".codex"));
    expect(findProtectedControlReadRoot(entry)).toBeNull();
  });
});
