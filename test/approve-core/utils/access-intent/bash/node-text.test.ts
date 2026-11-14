import { describe, expect, it } from "vitest";
import { commandRuleText } from "#approve-core/utils/access-intent/bash/node-text";
import { syntax, token } from "./fake-syntax";

function command(text: string, children: Parameters<typeof syntax>[2]): ReturnType<typeof syntax> {
  return syntax("command", text, children);
}

function word(text: string): ReturnType<typeof syntax> {
  return syntax("word", text);
}

function redirect(
  text: string,
  operator: string,
  target: string | null,
): ReturnType<typeof syntax> {
  const children = [token(operator, operator)];
  if (target) children.push(word(target));
  return syntax("file_redirect", text, children);
}

describe("command rule text", () => {
  it("keeps plain words and their original spacing", () => {
    const node = command("echo  hi", [
      syntax("command_name", "echo", [word("echo")]),
      word("hi"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("echo  hi");
  });

  it("drops a leading assignment", () => {
    const node = command("FOO=1 bar baz", [
      syntax("variable_assignment", "FOO=1"),
      syntax("command_name", "bar", [word("bar")]),
      word("baz"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("bar baz");
  });

  it("drops a leading redirect and joins the first argument", () => {
    const node = command(">out echo hi", [
      redirect(">out", ">", "out"),
      syntax("command_name", "echo", [word("echo")]),
      word("hi"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("echo hi");
  });

  it("drops a trailing redirect", () => {
    const node = syntax("redirected_statement", "echo hi >out", [
      command("echo hi", [
        syntax("command_name", "echo", [word("echo")]),
        word("hi"),
      ]),
      redirect(">out", ">", "out"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("echo hi");
  });

  it("joins words separated by a redirect with one space", () => {
    const node = command("git 2>/dev/null push --force", [
      syntax("command_name", "git", [word("git")]),
      redirect("2>/dev/null", ">", "/dev/null"),
      word("push"),
      word("--force"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("git push --force");
  });

  it("drops a redirect between two words", () => {
    const node = command("echo >out hi", [
      syntax("command_name", "echo", [word("echo")]),
      redirect(">out", ">", "out"),
      word("hi"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("echo hi");
  });

  it("keeps a pure assignment statement", () => {
    const node = syntax("variable_assignment", "FOO=1");
    expect(commandRuleText(node, node.text).text).toBe("FOO=1");
  });

  it("keeps an assignment without a command name", () => {
    const node = command("FOO=1 BAR=2", [
      syntax("variable_assignment", "FOO=1"),
      syntax("variable_assignment", "BAR=2"),
    ]);
    expect(commandRuleText(node, node.text).text).toBe("FOO=1 BAR=2");
  });

  it("reports output spans for the command name and arguments", () => {
    const name = syntax("command_name", "echo", [word("echo")]);
    const first = word("hi");
    const second = word("there");
    const node = command("echo hi there", [name, first, second]);

    const rule = commandRuleText(node, node.text);
    expect(rule.parts.map((part) => [part.role, part.start, part.end])).toEqual([
      ["name", 0, 4],
      ["argument", 5, 7],
      ["argument", 8, 13],
    ]);
    expect(rule.parts.map((part) => rule.text.slice(part.start, part.end))).toEqual([
      "echo",
      "hi",
      "there",
    ]);
  });

  it("falls back to the whole text for a non-command statement", () => {
    const node = syntax("test_command", "[ -f x ]");
    const rule = commandRuleText(node, node.text);
    expect(rule.text).toBe("[ -f x ]");
    expect(rule.parts).toEqual([]);
  });
});
