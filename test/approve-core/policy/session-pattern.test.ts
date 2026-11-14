import { describe, expect, it } from "vitest";
import { suggestSessionPattern } from "#approve-core/policy/session-pattern";

describe("plain commands", () => {
  it("returns nothing for blank or all-comment input", () => {
    expect(suggestSessionPattern("")).toBe("");
    expect(suggestSessionPattern("   ")).toBe("");
    expect(suggestSessionPattern("# only a comment\n")).toBe("");
  });

  it("drops whole-line comments before choosing a prefix", () => {
    expect(suggestSessionPattern("# install deps\nuv pip install pkg")).toBe("uv pip install *");
  });

  it("returns a single token as written", () => {
    expect(suggestSessionPattern("ls")).toBe("ls");
    expect(suggestSessionPattern("  ls  ")).toBe("ls");
  });

  it("uses the arity prefix and marks the remaining arguments", () => {
    expect(suggestSessionPattern("ls -la /tmp")).toBe("ls *");
    expect(suggestSessionPattern("uv pip install pkg")).toBe("uv pip install *");
    expect(suggestSessionPattern("uv pip uninstall pkg")).toBe("uv pip uninstall *");
    expect(suggestSessionPattern("mytool --flag x")).toBe("mytool *");
  });

  it("appends * when the prefix covers every token", () => {
    expect(suggestSessionPattern("git status")).toBe("git status*");
  });

  it("looks up case-insensitively but preserves the original case", () => {
    expect(suggestSessionPattern("GIT status --short")).toBe("GIT status *");
  });
});

describe("commands that cannot generalize", () => {
  it("keeps shell syntax exact", () => {
    expect(suggestSessionPattern("git status && rm -rf /")).toBe("git status && rm -rf /");
    expect(suggestSessionPattern("git $(pwd)")).toBe("git $(pwd)");
    expect(suggestSessionPattern("cat < input")).toBe("cat < input");
    expect(suggestSessionPattern("echo `date`")).toBe("echo `date`");
    expect(suggestSessionPattern("ls\ngit status")).toBe("ls\ngit status");
  });

  it("keeps reserved words exact", () => {
    expect(suggestSessionPattern("if true; then ls; fi")).toBe("if true; then ls; fi");
  });

  it("ignores shell syntax inside quotes", () => {
    expect(suggestSessionPattern("grep 'a|b' file")).toBe("grep *");
    expect(suggestSessionPattern('echo "a > b"')).toBe("echo *");
  });
});

describe("wrapped commands", () => {
  it("keeps the wrapper text and applies arity to the inner command", () => {
    expect(suggestSessionPattern({
      kind: "wrapped",
      text: "sudo -u root ls /etc",
      prefix: "sudo -u root",
      inner: { kind: "literal", text: "ls /etc" },
      generalizable: true,
    })).toBe("sudo -u root ls *");
  });

  it("keeps the whole command when a layer is not generalizable", () => {
    expect(suggestSessionPattern({
      kind: "wrapped",
      text: "xargs -n1 rm",
      prefix: "xargs -n1",
      inner: { kind: "literal", text: "rm" },
      generalizable: false,
    })).toBe("xargs -n1 rm");
  });

  it("keeps the whole command for an opaque inner payload", () => {
    expect(suggestSessionPattern({
      kind: "wrapped",
      text: "bash -c 'git status'",
      prefix: "bash -c",
      inner: { kind: "opaque", text: "git status" },
      generalizable: true,
    })).toBe("bash -c 'git status'");
  });

  it("returns the inner command alone when the wrapper prefix is empty", () => {
    expect(suggestSessionPattern({
      kind: "wrapped",
      text: "ls /tmp",
      prefix: "  ",
      inner: { kind: "literal", text: "ls /tmp" },
      generalizable: true,
    })).toBe("ls *");
  });
});
