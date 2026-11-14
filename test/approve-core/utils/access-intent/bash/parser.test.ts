import { describe, expect, it } from "vitest";
import {
  createBashParserRuntime,
  createCorrectedParser,
  type SyntaxNode,
  type SyntaxParser,
  type SyntaxTree,
} from "#approve-core/utils/access-intent/bash/parser";
import { syntax, token } from "./fake-syntax";

function rawParser(root: SyntaxNode | null): { parser: SyntaxParser; state: { deleted: number } } {
  const state = { deleted: 0 };
  const parser: SyntaxParser = {
    parse(): SyntaxTree | null {
      if (!root) return null;
      return { rootNode: root, delete: () => (state.deleted += 1) };
    },
  };
  return { parser, state };
}

function heredocQuirk(): SyntaxNode {
  return syntax("redirected_statement", "cat <<EOF > out\nbody\nEOF", [
    syntax("command", "cat", [syntax("command_name", "cat", [syntax("word", "cat")])]),
    syntax("heredoc_redirect", "<<EOF > out\nbody\nEOF", [
      token("<<", "<<"),
      syntax("heredoc_start", "EOF"),
      syntax("file_redirect", "> out", [token(">", ">"), syntax("word", "out")]),
      syntax("heredoc_body", "body\n"),
      syntax("heredoc_end", "EOF"),
    ]),
  ]);
}

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) result.push(child);
  }
  return result;
}

describe("corrected parser", () => {
  it("applies the corrected view and forwards tree deletion", () => {
    const { parser, state } = rawParser(heredocQuirk());
    const corrected = createCorrectedParser(parser);

    const tree = corrected.parse("cat <<EOF > out\nbody\nEOF")!;

    expect(children(tree.rootNode).map((child) => child.type)).toEqual([
      "command",
      "heredoc_redirect",
      "file_redirect",
    ]);
    tree.delete();
    expect(state.deleted).toBe(1);
  });

  it("returns null when the raw parser has no tree", () => {
    const { parser } = rawParser(null);
    expect(createCorrectedParser(parser).parse("x")).toBeNull();
  });

  it("releases the raw tree when correction throws", () => {
    const throwing: SyntaxNode = {
      type: "program",
      text: "x",
      startIndex: 0,
      endIndex: 1,
      childCount: 1,
      isNamed: true,
      hasError: false,
      child: () => {
        throw new Error("boom");
      },
      previousSibling: () => null,
    };
    const { parser, state } = rawParser(throwing);

    expect(() => createCorrectedParser(parser).parse("x")).toThrow("boom");
    expect(state.deleted).toBe(1);
  });
});

describe("bash parser runtime", () => {
  it("memoizes the loader across concurrent corrected calls", async () => {
    let calls = 0;
    const { parser } = rawParser(heredocQuirk());
    const runtime = createBashParserRuntime(async () => {
      calls += 1;
      return parser;
    });

    const [first, second] = await Promise.all([runtime.corrected(), runtime.corrected()]);

    expect(calls).toBe(1);
    expect(first).toBe(second);
    expect(await runtime.raw()).toBe(parser);
    expect(calls).toBe(1);
  });

  it("retries after a failed initialization", async () => {
    let calls = 0;
    const { parser } = rawParser(heredocQuirk());
    const runtime = createBashParserRuntime(async () => {
      calls += 1;
      if (calls === 1) throw new Error("init failed");
      return parser;
    });

    await expect(runtime.corrected()).rejects.toThrow("init failed");
    await expect(runtime.corrected()).resolves.toBeDefined();
    expect(calls).toBe(2);
  });

  it("exposes a warm parser only after priming", async () => {
    let calls = 0;
    const { parser } = rawParser(heredocQuirk());
    const runtime = createBashParserRuntime(async () => {
      calls += 1;
      return parser;
    });

    expect(runtime.warm()).toBeUndefined();
    await runtime.prime();
    const warm = runtime.warm();
    expect(warm).toBeDefined();
    await runtime.prime();
    expect(runtime.warm()).toBe(warm);
    expect(calls).toBe(1);

    runtime.resetWarm();
    expect(runtime.warm()).toBeUndefined();
    await runtime.prime();
    expect(runtime.warm()).toBe(warm);
    expect(calls).toBe(1);
  });

  it("does not warm an in-flight prime after the warm slot is reset", async () => {
    let resolveParser!: (parser: SyntaxParser) => void;
    const gate = new Promise<SyntaxParser>((resolve) => {
      resolveParser = resolve;
    });
    const { parser } = rawParser(heredocQuirk());
    const runtime = createBashParserRuntime(() => gate);

    const priming = runtime.prime();
    runtime.resetWarm();
    resolveParser(parser);
    await priming;
    expect(runtime.warm()).toBeUndefined();

    await runtime.prime();
    expect(runtime.warm()).toBeDefined();
  });

  it("swallows warm-up failure and retries later", async () => {
    let calls = 0;
    const { parser } = rawParser(heredocQuirk());
    const runtime = createBashParserRuntime(async () => {
      calls += 1;
      if (calls === 1) throw new Error("init failed");
      return parser;
    });

    await expect(runtime.prime()).resolves.toBeUndefined();
    expect(runtime.warm()).toBeUndefined();
    await expect(runtime.prime()).resolves.toBeUndefined();
    expect(runtime.warm()).toBeDefined();
    expect(calls).toBe(2);
  });
});
