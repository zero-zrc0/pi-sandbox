import { describe, expect, it } from "vitest";
import {
  formatToolInputPreview,
  buildReviewLogContext,
  createReviewLogPreviewFormatter,
} from "#approve-core/nodes/human/tool-preview-formatter";
import { PREVIEW_ELLIPSIS, REDACTED_VALUE } from "#approve-core/nodes/human/tool-input-preview";

describe("formatToolInputPreview: omitted previews", () => {
  it("omits the preview for Bash so the command is not repeated", () => {
    expect(formatToolInputPreview("bash", { command: "rm -rf /" })).toBeUndefined();
    expect(formatToolInputPreview("  bash  ", { command: "ls" })).toBeUndefined();
  });

  it("omits the preview for the MCP proxy so the request body is not repeated", () => {
    expect(
      formatToolInputPreview("mcp", { tool: "search", arguments: { query: "hello" } }),
    ).toBeUndefined();
    expect(formatToolInputPreview("  mcp  ", { arguments: { query: "hello" } })).toBeUndefined();
  });
});

describe("formatToolInputPreview: path tools reuse the prompt summary", () => {
  it.each([
    ["read", { path: "src/a.ts" }, "read src/a.ts"],
    ["read", { file_path: "src/b.ts" }, "read src/b.ts"],
    ["write", { path: "out.txt", content: "a\nb\nc" }, "write out.txt: 3 lines, 5 characters"],
    [
      "edit",
      { path: "notes.txt", edits: [{ oldText: "x", newText: "y\nz\nw" }, { oldText: "p", newText: "q" }] },
      "edit notes.txt: 2 replacements, first edit replaces 1 line with 3 lines, 1 more edit",
    ],
    [
      "find",
      { pattern: "TODO", glob: "*.ts", path: "src" },
      'find pattern "TODO", glob "*.ts", path src',
    ],
    ["grep", { pattern: "needle" }, 'grep pattern "needle", in the current working directory'],
    ["ls", {}, "ls in the current working directory"],
  ] as const)("uses the prompt summary for %s", (toolName, input, expected) => {
    expect(formatToolInputPreview(toolName, input)).toBe(expected);
  });

  it("never leaks write/edit bodies or unrelated credential keys", () => {
    const writePreview = formatToolInputPreview("write", {
      path: "out.txt",
      content: "const hidden = 1;",
      password: "hunter2",
    });
    expect(writePreview).toBe("write out.txt: 1 line, 17 characters");
    expect(writePreview).not.toContain("hidden");
    expect(writePreview).not.toContain("hunter2");

    const editPreview = formatToolInputPreview("edit", {
      path: "a.ts",
      oldText: "const secret = 1;",
      newText: "const other = 2;",
    });
    expect(editPreview).toBe("edit a.ts: 1 replacement, first edit replaces 1 line with 1 line");
    expect(editPreview).not.toContain("secret");
  });

  it("omits the preview when the prompt summary is empty", () => {
    expect(formatToolInputPreview("read", {})).toBeUndefined();
    expect(formatToolInputPreview("read", { offset: 5 })).toBeUndefined();
    expect(formatToolInputPreview("write", { content: "x" })).toBeUndefined();
    expect(
      formatToolInputPreview("edit", { edits: [{ oldText: "a", newText: "b" }] }),
    ).toBeUndefined();
    expect(formatToolInputPreview("read", "not-an-object")).toBeUndefined();
    expect(formatToolInputPreview("read", null)).toBeUndefined();
  });

  it("passes the injected text summary limit into the prompt summary", () => {
    expect(
      formatToolInputPreview("grep", { pattern: "x".repeat(20) }, { limits: { textSummary: 10 } }),
    ).toBe(`grep pattern "xxxxxxxxxx${PREVIEW_ELLIPSIS}", in the current working directory`);
  });

  it("trims the tool name before classifying it", () => {
    expect(formatToolInputPreview("  read  ", { path: "a.ts" })).toBe("read a.ts");
  });

  it("treats only the exact lowercase names as path tools", () => {
    expect(formatToolInputPreview("Read", { path: "a.ts" })).toBe('{"path":"a.ts"}');
  });
});

describe("formatToolInputPreview: masked generic JSON", () => {
  it("uses masked generic JSON for Pi MCP tools", () => {
    expect(
      formatToolInputPreview("mcp__files__read", { path: "notes.txt", apiKey: "sk-live" }),
    ).toBe(`{"path":"notes.txt","apiKey":"${REDACTED_VALUE}"}`);
  });

  it("masks sensitive keys of Pi MCP tools before stringification", () => {
    const preview = formatToolInputPreview("mcp__server__tool", {
      query: "hello",
      auth: { token: "t0ken", password: "hunter2" },
    });
    expect(preview).toBe(`{"query":"hello","auth":{"token":"${REDACTED_VALUE}","password":"${REDACTED_VALUE}"}}`);
    expect(preview).not.toContain("t0ken");
    expect(preview).not.toContain("hunter2");
  });

  it("produces no preview for empty or unserializable Pi MCP input", () => {
    expect(formatToolInputPreview("mcp__server__tool", {})).toBeUndefined();
    expect(formatToolInputPreview("mcp__server__tool", null)).toBeUndefined();
    // Masking replaces cycles before stringification, so a cycle still yields a preview.
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(formatToolInputPreview("mcp__server__tool", circular)).toBe(
      `{"self":"${REDACTED_VALUE}"}`,
    );
    // A BigInt at an ordinary key survives masking and then fails JSON.stringify.
    expect(formatToolInputPreview("mcp__server__tool", { count: 1n })).toBeUndefined();
  });

  it("uses masked generic JSON for other extension tools", () => {
    expect(formatToolInputPreview("custom_tool", { path: "a.txt", count: 2 })).toBe(
      '{"path":"a.txt","count":2}',
    );
    expect(formatToolInputPreview("skill", { name: "fix" })).toBe('{"name":"fix"}');
  });

  it("masks sensitive keys of extension tools before stringification", () => {
    const preview = formatToolInputPreview("extension_x", {
      password: "hunter2",
      nested: { authorization: "Bearer abc" },
    });
    expect(preview).toBe(
      `{"password":"${REDACTED_VALUE}","nested":{"authorization":"${REDACTED_VALUE}"}}`,
    );
    expect(preview).not.toContain("hunter2");
    expect(preview).not.toContain("Bearer abc");
  });

  it("bounds generic JSON with the injected prompt input limit", () => {
    const preview = formatToolInputPreview(
      "custom_tool",
      { a: "x".repeat(100) },
      { limits: { promptInput: 20 } },
    );
    expect(preview).toHaveLength(21);
    expect(preview!.endsWith(PREVIEW_ELLIPSIS)).toBe(true);
  });

  it("falls back to generic JSON for an empty tool name", () => {
    expect(formatToolInputPreview("", { a: 1 })).toBe('{"a":1}');
  });
});

describe("buildReviewLogContext", () => {
  it("includes supplied facts in the documented field order", () => {
    const context = buildReviewLogContext({
      toolName: "read",
      input: { path: "src/a.ts" },
      command: "  ls -la  ",
      target: " src ",
      ruleOrigin: "  project  ",
    });
    expect(context).toEqual({
      command: "ls -la",
      target: "src",
      toolInputPreview: "read src/a.ts",
      ruleOrigin: "project",
    });
    expect(Object.keys(context)).toEqual(["command", "target", "toolInputPreview", "ruleOrigin"]);
  });

  it("omits absent and blank facts instead of writing empty strings", () => {
    const context = buildReviewLogContext({
      toolName: "bash",
      input: { command: "rm -rf /" },
      command: "",
      target: " \t ",
      ruleOrigin: "\n",
    });
    expect(context).toEqual({});
    expect(Object.values(context)).not.toContain("");
  });

  it("keeps the documented order when earlier fields are absent", () => {
    const targetOnly = buildReviewLogContext({ toolName: "read", input: {}, target: "src" });
    expect(targetOnly).toEqual({ target: "src" });

    const previewOnly = buildReviewLogContext({ toolName: "custom_tool", input: { a: 1 } });
    expect(previewOnly).toEqual({ toolInputPreview: '{"a":1}' });
  });

  it("omits non-string fact values", () => {
    const context = buildReviewLogContext({
      toolName: "read",
      input: { path: "a.ts" },
      command: 42,
      target: {},
      ruleOrigin: null,
    });
    expect(context).toEqual({ toolInputPreview: "read a.ts" });
  });

  it("does not duplicate the Bash command or the MCP proxy request", () => {
    expect(
      buildReviewLogContext({ toolName: "bash", input: { command: "ls" }, command: "ls" }),
    ).toEqual({ command: "ls" });
    expect(
      buildReviewLogContext({
        toolName: "mcp",
        input: { tool: "search", arguments: { query: "q" } },
      }),
    ).toEqual({});
  });

  it("omits toolInputPreview when the path summary is empty", () => {
    expect(buildReviewLogContext({ toolName: "write", input: { content: "x" }, target: "o.txt" })).toEqual({
      target: "o.txt",
    });
  });

  it("masks sensitive keys before they reach the log context", () => {
    const context = buildReviewLogContext({
      toolName: "custom_tool",
      input: { apiKey: "sk-live", mode: "fast" },
    });
    expect(context.toolInputPreview).toBe(`{"apiKey":"${REDACTED_VALUE}","mode":"fast"}`);
    expect(JSON.stringify(context)).not.toContain("sk-live");
  });

  it("applies injected limits while building the context", () => {
    const context = buildReviewLogContext(
      { toolName: "custom_tool", input: { a: "x".repeat(100) } },
      { limits: { promptInput: 20 } },
    );
    expect(context.toolInputPreview).toHaveLength(21);
  });
});

describe("createReviewLogPreviewFormatter", () => {
  it("delegates preview and context to the same behavior", () => {
    const formatter = createReviewLogPreviewFormatter();
    expect(formatter.preview("read", { path: "a.ts" })).toBe("read a.ts");
    expect(formatter.preview("bash", { command: "ls" })).toBeUndefined();
    expect(formatter.context({ toolName: "read", input: { path: "a.ts" }, command: " ls " })).toEqual({
      command: "ls",
      toolInputPreview: "read a.ts",
    });
  });

  it("binds one resolved limits object to preview and context", () => {
    const formatter = createReviewLogPreviewFormatter({ limits: { promptInput: 20 } });
    const longInput = { a: "x".repeat(100) };
    expect(formatter.preview("custom_tool", longInput)).toHaveLength(21);
    expect(formatter.context({ toolName: "custom_tool", input: longInput }).toolInputPreview).toHaveLength(
      21,
    );
  });

  it("keeps limits independent between formatter instances", () => {
    const narrow = createReviewLogPreviewFormatter({ limits: { promptInput: 10 } });
    const wide = createReviewLogPreviewFormatter({ limits: { promptInput: 200 } });
    const longInput = { a: "x".repeat(50) };
    expect(narrow.preview("custom_tool", longInput)).toHaveLength(11);
    expect(wide.preview("custom_tool", longInput)!.length).toBeGreaterThan(11);
  });
});
