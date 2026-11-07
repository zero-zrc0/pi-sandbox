import { describe, expect, it } from "vitest";
import {
  checkBashCommand,
  type BashUnitResolver,
} from "#approve-core/utils/bash-command-check";
import type { BashCommand } from "#approve-core/utils/access-intent/bash/command-enumeration";
import { enumerateCommands } from "#approve-core/utils/access-intent/bash/command-enumeration";
import type { PermissionCheckResult } from "#approve-core/contracts";
import { syntax, token } from "#approve-core-test/utils/access-intent/bash/fake-syntax";

function allow(overrides: Partial<PermissionCheckResult> = {}): PermissionCheckResult {
  return {
    toolName: "bash",
    state: "allow",
    source: "bash",
    origin: "global",
    ...overrides,
  };
}

function ask(overrides: Partial<PermissionCheckResult> = {}): PermissionCheckResult {
  return { ...allow(overrides), state: "ask" };
}

function deny(overrides: Partial<PermissionCheckResult> = {}): PermissionCheckResult {
  return { ...allow(overrides), state: "deny" };
}

function unit(text: string, overrides: Partial<BashCommand> = {}): BashCommand {
  return Object.freeze({ text, ...overrides });
}

function byText(map: Record<string, PermissionCheckResult>): BashUnitResolver {
  return (command) => map[command] ?? allow({ command });
}

function word(text: string): ReturnType<typeof syntax> {
  return syntax("word", text);
}

function command(name: string, ...args: string[]): ReturnType<typeof syntax> {
  return syntax("command", [name, ...args].join(" "), [
    syntax("command_name", name, [word(name)]),
    ...args.map((arg) => word(arg)),
  ]);
}

function enumerate(root: ReturnType<typeof syntax>): readonly BashCommand[] {
  return enumerateCommands(root, {
    source: root.text,
    wordContext: { home: "/home/t", homeRebound: false, pwdRebound: false },
  });
}

describe("unit adjudication", () => {
  it("takes deny over ask over allow and keeps the first of a rank", () => {
    const verdict = checkBashCommand({
      command: "a; b; c",
      units: [unit("a"), unit("b"), unit("c")],
      resolve: byText({ a: allow(), b: deny(), c: deny() }),
    });
    expect(verdict.check.state).toBe("deny");
    expect(verdict.check.command).toBe("b");
  });

  it("lets an allow unit be outweighed by an ask unit", () => {
    const verdict = checkBashCommand({
      command: "a; b",
      units: [unit("a"), unit("b")],
      resolve: byText({ a: allow(), b: ask() }),
    });
    expect(verdict.check.state).toBe("ask");
  });

  it("raises an unresolved unit's allow to ask", () => {
    const verdict = checkBashCommand({
      command: "bad &&",
      units: [unit("bad", { parseUnresolved: true })],
      resolve: byText({ bad: allow() }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.floor).toBe("<bash-parse-unresolved>");
    expect(verdict.units[0]!.floor?.kind).toBe("parse");
  });

  it("raises a salvaged unit's allow to ask", () => {
    const verdict = checkBashCommand({
      command: "frag",
      units: [unit("frag", { salvaged: true, parseUnresolved: true })],
      resolve: byText({ frag: allow() }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.floor).toBe("<bash-salvaged-region>");
    expect(verdict.units[0]!.floor?.kind).toBe("salvage");
  });

  it("authorizes the whole command when a parse floor applies", () => {
    const verdict = checkBashCommand({
      command: "echo hi && broken",
      units: [unit("broken", { parseUnresolved: true })],
      resolve: byText({ broken: allow() }),
    });
    expect(verdict.check.command).toBe("echo hi && broken");
    expect(verdict.check.askingUnits).toEqual([
      { command: "broken", floor: "<bash-parse-unresolved>" },
    ]);
  });

  it("keeps every asking unit and its own floor", () => {
    const verdict = checkBashCommand({
      command: "a; b",
      units: [unit("a", { parseUnresolved: true }), unit("b", { salvaged: true, parseUnresolved: true })],
      resolve: byText({ a: allow(), b: allow() }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.askingUnits).toEqual([
      { command: "a", floor: "<bash-parse-unresolved>" },
      { command: "b", floor: "<bash-salvaged-region>" },
    ]);
  });

  it("does not let an explicit ask or deny be raised by a parse floor", () => {
    const asked = checkBashCommand({
      command: "a",
      units: [unit("a", { parseUnresolved: true })],
      resolve: byText({ a: ask({ matchedPattern: "a*" }) }),
    });
    expect(asked.check.floor).toBeUndefined();
    expect(asked.check.matchedPattern).toBe("a*");
  });

  it("lets an exact session allow bypass parse and wrapper floors", () => {
    const session = allow({ origin: "session", source: "session" });
    const verdict = checkBashCommand({
      command: "sudo rm x",
      units: [unit("sudo rm x", { wrapperKind: "privilege", parseUnresolved: true })],
      resolve: byText({ "sudo rm x": session }),
    });
    expect(verdict.check.state).toBe("allow");
    expect(verdict.check.floor).toBeUndefined();
  });
});

describe("wrapper floors", () => {
  it("raises a non-exempt wrapper allow to ask", () => {
    const verdict = checkBashCommand({
      command: "sudo rm x",
      units: [unit("sudo rm x", { wrapperKind: "privilege", executedUnit: "rm x" })],
      resolve: byText({ "sudo rm x": allow() }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.floor).toBe("<wrapper:privilege>");
    expect(verdict.units[0]!.floor?.kind).toBe("wrapper");
  });

  it("lets an execution-modifier exemption decide by the inner command", () => {
    const units = enumerate(command("time", "rm", "x"));
    const verdict = checkBashCommand({
      command: "time rm x",
      units,
      resolve: (text) => text === "time rm x" ? allow() : deny({ command: text }),
    });
    expect(verdict.check.state).toBe("deny");
    expect(verdict.check.command).toBe("time rm x");
    expect(verdict.check.executedUnit).toBe("rm x");
    expect(verdict.check.floorExemption).toBe("execution-modifier");
  });

  it("lets a core-reader exemption decide by the inner reader's rule", () => {
    const units = enumerate(command("sudo", "cat", "file"));
    const verdict = checkBashCommand({
      command: "sudo cat file",
      units,
      resolve: (text) => text === "sudo cat file" ? allow() : deny({ command: text }),
    });
    expect(verdict.check.state).toBe("deny");
    expect(verdict.check.command).toBe("sudo cat file");
    expect(verdict.check.executedUnit).toBe("cat file");
  });

  it("resolves each unit once and adds inner lookups only for an exemption", () => {
    const units = enumerate(command("time", "rm", "x"));
    const calls = new Map<string, number>();
    checkBashCommand({
      command: "time rm x",
      units,
      resolve: (text) => {
        calls.set(text, (calls.get(text) ?? 0) + 1);
        return allow({ command: text });
      },
    });
    expect(Object.fromEntries(calls)).toEqual({ "time rm x": 1, "rm x": 1 });
  });

  it("keeps the asking unit's floor when an exemption is followed by uncertainty", () => {
    const root = syntax("command", "time rm x", [
      syntax("command_name", "time", [word("time")]),
      word("rm"),
      word("x"),
    ], { error: true });
    const units = enumerate(root);
    const verdict = checkBashCommand({
      command: "time rm x",
      units,
      resolve: (text) => allow({ command: text }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.floor).toBe("<bash-parse-unresolved>");
  });

  it("keeps a wrapper's explicit ask instead of substituting the inner result", () => {
    const units = enumerate(command("time", "rm", "x"));
    const verdict = checkBashCommand({
      command: "time rm x",
      units,
      resolve: (text) => text === "time rm x"
        ? ask({ matchedPattern: "time *" })
        : allow({ command: text }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.matchedPattern).toBe("time *");
  });
});

describe("whole-command cases", () => {
  it("evaluates an empty command as-is", () => {
    const verdict = checkBashCommand({
      command: "   ",
      units: [],
      resolve: () => allow(),
    });
    expect(verdict.check.state).toBe("allow");
  });

  it("evaluates a comment-only command as-is", () => {
    const verdict = checkBashCommand({
      command: "# nothing here",
      units: [],
      resolve: () => allow(),
    });
    expect(verdict.check.state).toBe("allow");
  });

  it("fails closed when the parser produced no units and the whole command is allowed", () => {
    const whole = allow();
    const verdict = checkBashCommand({
      command: "unparseable (((",
      units: [],
      resolve: () => whole,
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.check.floor).toBe("<unparseable-bash-command>");
    expect(verdict.wholeProgram).toEqual(whole);
  });

  it("returns an explicit whole deny immediately", () => {
    const whole = deny();
    const verdict = checkBashCommand({
      command: "unparseable (((",
      units: [],
      resolve: () => whole,
    });
    expect(verdict.check).toEqual(whole);
    expect(verdict.wholeProgram).toEqual(whole);
  });

  it("keeps an explicit whole ask", () => {
    const whole = ask({ matchedPattern: "unparseable*" });
    const verdict = checkBashCommand({
      command: "unparseable (((",
      units: [],
      resolve: () => whole,
    });
    expect(verdict.check).toEqual(whole);
    expect(verdict.wholeProgram).toEqual(whole);
  });

  it("lets an exact session whole allow stand", () => {
    const whole = allow({ origin: "session", source: "session" });
    const verdict = checkBashCommand({
      command: "unparseable (((",
      units: [],
      resolve: () => whole,
    });
    expect(verdict.check.state).toBe("allow");
    expect(verdict.check.floor).toBeUndefined();
  });

  it("merges an explicit whole ask with salvaged units", () => {
    const verdict = checkBashCommand({
      command: "frag &&",
      units: [unit("frag", { salvaged: true, parseUnresolved: true })],
      resolve: (text) => text === "frag &&" ? ask({ matchedPattern: "frag*" }) : allow({ command: text }),
    });
    expect(verdict.check.state).toBe("ask");
    expect(verdict.wholeProgram?.matchedPattern).toBe("frag*");
    expect(verdict.check.askingUnits).toEqual([
      { command: "frag", floor: "<bash-salvaged-region>" },
    ]);
  });
});

describe("failures", () => {
  it("absorbs a later evaluation failure once a deny exists", () => {
    const verdict = checkBashCommand({
      command: "a; b",
      units: [unit("a"), unit("b")],
      resolve: (text) => {
        if (text === "a") return deny();
        throw new Error("resolver failed");
      },
    });
    expect(verdict.check.state).toBe("deny");
    expect(verdict.check.command).toBe("a");
  });

  it("rethrows a failure when no deny has been seen", () => {
    expect(() => checkBashCommand({
      command: "a; b",
      units: [unit("a"), unit("b")],
      resolve: (text) => {
        if (text === "a") return allow();
        throw new Error("resolver failed");
      },
    })).toThrow("resolver failed");
  });

  it("keeps a salvaged deny when a later salvaged unit fails", () => {
    const verdict = checkBashCommand({
      command: "whole",
      units: [
        unit("bad", { salvaged: true, parseUnresolved: true }),
        unit("boom", { salvaged: true, parseUnresolved: true }),
      ],
      resolve: (text) => {
        if (text === "whole") return allow();
        if (text === "bad") return deny();
        throw new Error("resolver failed");
      },
    });
    expect(verdict.check.state).toBe("deny");
    expect(verdict.check.command).toBe("bad");
  });
});
