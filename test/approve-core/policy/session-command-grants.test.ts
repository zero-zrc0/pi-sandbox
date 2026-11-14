import { describe, expect, it } from "vitest";
import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import {
  createSessionCommandGrants,
  suggestSessionCommandGrants,
  type SessionCommandGrant,
} from "#approve-core/policy/session-command-grants";

function unit(text: string, extra: Partial<BashCommand> = {}): BashCommand {
  return { text, ...extra } as BashCommand;
}

function grantsOf(units: readonly BashCommand[]): readonly SessionCommandGrant[] {
  return suggestSessionCommandGrants(units);
}

describe("session command grants", () => {
  it.each([
    ["git status", { kind: "prefix", prefix: "git status" }],
    ["git status --short", { kind: "prefix", prefix: "git status" }],
    ["git log --oneline", { kind: "prefix", prefix: "git log" }],
    ["npm run build", { kind: "prefix", prefix: "npm run build" }],
    ["uv pip install pkg", { kind: "prefix", prefix: "uv pip install" }],
  ])("remembers a multi-token family for %s", (text, expected) => {
    expect(grantsOf([unit(text)])).toEqual([expected]);
  });

  it.each([
    ["rm -rf build"],
    ["rm *.txt"],
    ["ls -la"],
    ["curl https://example.com"],
  ])("keeps the single-token command %s exact", (text) => {
    expect(grantsOf([unit(text)])).toEqual([{ kind: "exact", text }]);
  });

  it("keeps wrapped and nested units exact", () => {
    expect(grantsOf([unit("sudo git status", { wrapperKind: "privilege" })]))
      .toEqual([{ kind: "exact", text: "sudo git status" }]);
    expect(grantsOf([unit("cat $(pwd)", { context: "command_substitution" })]))
      .toEqual([{ kind: "exact", text: "cat $(pwd)" }]);
  });

  it("matches a family only on a token boundary and only when every unit matches", () => {
    const grants = createSessionCommandGrants();
    grants.remember(grantsOf([unit("git status")]));

    expect(grants.matches("git status", [unit("git status")])).toBe(true);
    expect(grants.matches("git status --short", [unit("git status --short")])).toBe(true);
    expect(grants.matches("git statusx", [unit("git statusx")])).toBe(false);
    expect(grants.matches("git status && git log", [unit("git status"), unit("git log")])).toBe(false);
    expect(grants.matches("PATH=./bin git status", [unit("git status")])).toBe(false);
    expect(grants.matches("", [])).toBe(false);
  });

  it("keeps exact grants literal", () => {
    const grants = createSessionCommandGrants();
    grants.remember(grantsOf([unit("rm *.txt")]));

    expect(grants.matches("rm *.txt", [unit("rm *.txt")])).toBe(true);
    expect(grants.matches("rm important.txt", [unit("rm important.txt")])).toBe(false);
  });

  it("forgets a family when the same session denies one of its commands", () => {
    const grants = createSessionCommandGrants();
    grants.remember(grantsOf([unit("git status"), unit("rm -rf build")]));

    grants.forget([unit("git status -s")]);

    expect(grants.matches("git status", [unit("git status")])).toBe(false);
    expect(grants.matches("rm -rf build", [unit("rm -rf build")])).toBe(true);
  });

  it("bounds the remembered families and drops the oldest", () => {
    const grants = createSessionCommandGrants(2);
    grants.remember(grantsOf([unit("git status"), unit("npm install pkg"), unit("uv pip install pkg")]));

    expect(grants.size).toBe(2);
    expect(grants.matches("git status", [unit("git status")])).toBe(false);
    expect(grants.matches("npm install pkg", [unit("npm install pkg")])).toBe(true);
    expect(grants.matches("uv pip install pkg", [unit("uv pip install pkg")])).toBe(true);
  });
});
