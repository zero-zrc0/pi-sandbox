import { describe, expect, it } from "vitest";
import { redirectPositionUnresolved, subtreeUnresolved } from "#approve-core/utils/access-intent/bash/parse-health";
import { syntax, token } from "./fake-syntax";

describe("parse health", () => {
  it("reports a subtree error from the node or any descendant", () => {
    const healthy = syntax("command", "echo hi", [syntax("word", "echo"), syntax("word", "hi")]);
    const broken = syntax("command", "echo $(", [syntax("word", "echo"), syntax("ERROR", "$(", [], { error: true })]);
    const wrapper = syntax("redirected_statement", "echo $(", [broken]);

    expect(subtreeUnresolved(healthy)).toBe(false);
    expect(subtreeUnresolved(broken)).toBe(true);
    expect(subtreeUnresolved(wrapper)).toBe(true);
  });

  it("checks the direct previous sibling for redirect position health", () => {
    const command = syntax("command", "cat", [syntax("command_name", "cat")]);
    const stranded = syntax("ERROR", "<", [token("<", "<")], { error: true });
    const redirect = syntax("file_redirect", "> out", [token(">", ">"), syntax("word", "out")]);
    const statement = syntax("redirected_statement", "cat <> out", [command, stranded, redirect]);

    expect(redirectPositionUnresolved(redirect)).toBe(true);
    expect(redirectPositionUnresolved(stranded)).toBe(true);
  });

  it("does not spread an earlier sibling error to later redirects", () => {
    const command = syntax("command", "cat", [syntax("command_name", "cat")]);
    const stranded = syntax("ERROR", "<", [token("<", "<")], { error: true });
    const first = syntax("file_redirect", "< in", [token("<", "<"), syntax("word", "in")]);
    const second = syntax("file_redirect", "> out", [token(">", ">"), syntax("word", "out")]);
    syntax("redirected_statement", "cat <> in > out", [command, stranded, first, second]);

    expect(redirectPositionUnresolved(second)).toBe(false);
  });

  it("reports a redirect whose own subtree is unresolved", () => {
    const redirect = syntax(
      "file_redirect",
      "<> rw",
      [token("<", "<"), syntax("ERROR", ">", [token(">", ">")], { error: true }), syntax("word", "rw")],
    );

    expect(redirectPositionUnresolved(redirect)).toBe(true);
  });
});
