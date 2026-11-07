import { describe, expect, it } from "vitest";
import {
  findNestedExecutions,
  isNestedExecutionNode,
} from "#approve-core/utils/access-intent/bash/nested-execution";
import { syntax, token } from "./fake-syntax";

function command(text: string) {
  return syntax("command", text, [syntax("command_name", text)]);
}

function substitution(text: string, inner: string) {
  return syntax("command_substitution", text, [token("$(", "$("), command(inner), token(")", ")")]);
}

function processSubstitution(text: string, inner: string) {
  return syntax("process_substitution", text, [token("<(", "<("), command(inner), token(")", ")")]);
}

describe("nested execution discovery", () => {
  it("finds command substitutions in arguments", () => {
    const node = syntax("command", "echo $(date)", [syntax("command_name", "echo"), substitution("$(date)", "date")]);
    const found = findNestedExecutions(node);

    expect(found).toHaveLength(1);
    expect(found[0]?.kind).toBe("command-substitution");
    expect(found[0]?.node.text).toBe("$(date)");
  });

  it("finds process substitutions in source order", () => {
    const node = syntax("command", "diff <(a) <(b)", [
      syntax("command_name", "diff"),
      processSubstitution("<(a)", "a"),
      processSubstitution("<(b)", "b"),
    ]);
    const found = findNestedExecutions(node);

    expect(found.map((entry) => entry.kind)).toEqual(["process-substitution", "process-substitution"]);
    expect(found.map((entry) => entry.node.text)).toEqual(["<(a)", "<(b)"]);
  });

  it("searches redirect targets and heredoc bodies", () => {
    const redirect = syntax("file_redirect", "> $(mktemp)", [token(">", ">"), substitution("$(mktemp)", "mktemp")]);
    const body = syntax("heredoc_body", "$(date)\n", [substitution("$(date)", "date"), syntax("heredoc_content", "")]);
    const heredoc = syntax("heredoc_redirect", "<<EOF\n$(date)\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      body,
      syntax("heredoc_end", "EOF"),
    ]);

    expect(findNestedExecutions(redirect)).toHaveLength(1);
    expect(findNestedExecutions(heredoc)).toHaveLength(1);
  });

  it("does not search plain quoted heredoc text", () => {
    const heredoc = syntax("heredoc_redirect", "<<'EOF'\n$(date)\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "'EOF'"),
      syntax("heredoc_body", "$(date)\n"),
      syntax("heredoc_end", "EOF"),
    ]);

    expect(findNestedExecutions(heredoc)).toHaveLength(0);
  });

  it("distinguishes the queried node itself from descendants", () => {
    const node = substitution("$(date)", "date");

    expect(findNestedExecutions(node)).toHaveLength(0);
    expect(findNestedExecutions(node, { includeSelf: true })).toHaveLength(1);
    expect(isNestedExecutionNode(node)).toBe(true);
  });

  it("stops at the first nested context unless asked to descend", () => {
    const inner = substitution("$(date)", "date");
    const outer = syntax("command_substitution", "$(echo $(date))", [
      token("$(", "$("),
      syntax("command", "echo $(date)", [syntax("command_name", "echo"), inner]),
      token(")", ")"),
    ]);
    const root = syntax("command", "echo $(echo $(date))", [syntax("command_name", "echo"), outer]);

    expect(findNestedExecutions(root).map((entry) => entry.node.text)).toEqual(["$(echo $(date))"]);
    expect(findNestedExecutions(root, { descendIntoNested: true }).map((entry) => entry.node.text)).toEqual([
      "$(echo $(date))",
      "$(date)",
    ]);
  });
});
