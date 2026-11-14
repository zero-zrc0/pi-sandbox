/**
 * Built-in tool input summaries (specs/human-review.md §3).
 *
 * Every path tool is driven directly through its public summarize surface with
 * table-driven fixtures. Write and edit cases additionally assert that no
 * content or replacement body text ever appears in the summary.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_PREVIEW_LIMITS,
  PREVIEW_ELLIPSIS,
  resolvePreviewLimits,
} from "#approve-core/nodes/human/tool-input-preview";
import {
  BUILTIN_TOOL_SUMMARIES,
  summarizeBuiltinToolInput,
  summarizeEdit,
  summarizeFind,
  summarizeGrep,
  summarizeLs,
  summarizeRead,
  summarizeWrite,
  toolInputPath,
  type BuiltinToolName,
} from "#approve-core/nodes/human/builtin-tool-input-formatters";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type SummaryCase = [label: string, input: unknown, expected: string | undefined];
type DispatchCase = [label: string, toolName: string, input: unknown, expected: string | undefined];

const TIGHT_LIMITS = resolvePreviewLimits({ textSummary: 5 });

const PATH_CASES: SummaryCase[] = [
  ["a path key", { path: "src/a.ts" }, "src/a.ts"],
  ["the file_path fallback", { file_path: "src/b.ts" }, "src/b.ts"],
  ["path over file_path", { path: "src/a.ts", file_path: "src/b.ts" }, "src/a.ts"],
  ["surrounding whitespace", { path: "  src/a.ts \n" }, "src/a.ts"],
  ["a blank path with a file_path fallback", { path: "   ", file_path: " src/b.ts " }, "src/b.ts"],
  ["a non-string path with a file_path fallback", { path: 42, file_path: "src/b.ts" }, "src/b.ts"],
  ["a blank file_path", { file_path: "\t " }, undefined],
  ["missing keys", {}, undefined],
  ["a null input", null, undefined],
  ["a primitive input", "src/a.ts", undefined],
  ["an array input", ["src/a.ts"], undefined],
];

const READ_CASES: SummaryCase[] = [
  ["a path only", { path: "src/a.ts" }, "read src/a.ts"],
  ["a file_path fallback", { file_path: "src/a.ts" }, "read src/a.ts"],
  ["offset and limit", { path: "src/a.ts", offset: 10, limit: 20 }, "read src/a.ts, offset 10, limit 20"],
  ["an offset only", { path: "src/a.ts", offset: 0 }, "read src/a.ts, offset 0"],
  ["a limit only", { path: "src/a.ts", limit: 5 }, "read src/a.ts, limit 5"],
  ["a negative offset", { path: "src/a.ts", offset: -1 }, "read src/a.ts, offset -1"],
  ["a numeric string offset", { path: "src/a.ts", offset: "10", limit: 5 }, "read src/a.ts, limit 5"],
  ["non-finite values", { path: "src/a.ts", offset: Number.NaN, limit: Number.POSITIVE_INFINITY }, "read src/a.ts"],
  ["no path", { offset: 10, limit: 20 }, undefined],
  ["a null input", null, undefined],
];

const WRITE_CASES: SummaryCase[] = [
  [
    "three lines with a line count",
    { path: "out.txt", content: `${"a".repeat(40)}\n\n` },
    "write out.txt: 3 lines, 42 characters",
  ],
  ["a single line", { path: "a.txt", content: "hi" }, "write a.txt: 1 line, 2 characters"],
  ["CRLF line endings", { path: "a.txt", content: "a\r\nb" }, "write a.txt: 2 lines, 4 characters"],
  ["empty content", { path: "out.txt", content: "" }, "write out.txt: 0 lines, 0 characters"],
  ["missing content", { path: "out.txt" }, "write out.txt: 0 lines, 0 characters"],
  ["non-string content", { path: "out.txt", content: 42 }, "write out.txt: 0 lines, 0 characters"],
  ["a file_path fallback", { file_path: "out.txt", content: "x" }, "write out.txt: 1 line, 1 character"],
  ["no path", { content: "x" }, undefined],
  ["a null input", null, undefined],
];

const WRITE_BODIES: Array<[label: string, content: string]> = [
  ["a single line body", "SECRET_CODE_BODY"],
  ["a multiline body", "SECRET_CODE_BODY\nconst token = 'abc';"],
  ["a whitespace padded body", "  SECRET_CODE_BODY  "],
];

const EDIT_CASES: SummaryCase[] = [
  [
    "multiple edits",
    {
      path: "notes.txt",
      edits: [
        { oldText: "a", newText: "b\nc\nd" },
        { oldText: "x", newText: "y" },
      ],
    },
    "edit notes.txt: 2 replacements, first edit replaces 1 line with 3 lines, 1 more edit",
  ],
  [
    "a single edit",
    { path: "a.ts", edits: [{ oldText: "x", newText: "y" }] },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  [
    "three edits with a plural remainder",
    {
      path: "a.ts",
      edits: [
        { oldText: "a", newText: "b" },
        { oldText: "c", newText: "d" },
        { oldText: "e", newText: "f" },
      ],
    },
    "edit a.ts: 3 replacements, first edit replaces 1 line with 1 line, 2 more edits",
  ],
  [
    "invalid edit items skipped",
    {
      path: "a.ts",
      edits: [{ oldText: 1, newText: "x" }, { oldText: "a", newText: "b" }, null],
    },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  ["no valid edits", { path: "a.ts", edits: [{ oldText: 1, newText: "x" }] }, "edit a.ts"],
  [
    "non-array edits fall back to the top-level pair",
    { path: "a.ts", edits: "nope", oldText: "a\nb", newText: "c" },
    "edit a.ts: 1 replacement, first edit replaces 2 lines with 1 line",
  ],
  [
    "empty edits fall back to the top-level pair",
    { path: "a.ts", edits: [], oldText: "a", newText: "b" },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  [
    "a top-level pair only",
    { path: "a.ts", oldText: "a\nb", newText: "c\nd\ne" },
    "edit a.ts: 1 replacement, first edit replaces 2 lines with 3 lines",
  ],
  [
    "empty replacement strings count zero lines",
    { path: "a.ts", edits: [{ oldText: "", newText: "" }] },
    "edit a.ts: 1 replacement, first edit replaces 0 lines with 0 lines",
  ],
  [
    "a file_path fallback",
    { file_path: "a.ts", edits: [{ oldText: "a", newText: "b" }] },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  ["no path", { edits: [{ oldText: "a", newText: "b" }] }, undefined],
  ["a null input", null, undefined],
];

const EDIT_BODIES: Array<[label: string, input: unknown]> = [
  [
    "an edits array",
    {
      path: "a.ts",
      edits: [{ oldText: "SECRET_OLD_BODY\nline two", newText: "SECRET_NEW_BODY\nline two" }],
    },
  ],
  ["a top-level pair", { path: "a.ts", oldText: "SECRET_OLD_BODY", newText: "SECRET_NEW_BODY" }],
];

const FIND_CASES: SummaryCase[] = [
  [
    "pattern, glob and path",
    { pattern: "TODO", glob: "*.ts", path: "src" },
    'find pattern "TODO", glob "*.ts", path src',
  ],
  ["a pattern only", { pattern: "needle" }, 'find pattern "needle", in the current working directory'],
  ["a glob only", { glob: "*.md" }, 'find glob "*.md", in the current working directory'],
  ["a path only", { path: "src" }, "find path src"],
  ["no fields", {}, "find in the current working directory"],
  [
    "a blank pattern omitted",
    { pattern: "  \n\t ", glob: "*.md", path: "docs" },
    'find glob "*.md", path docs',
  ],
  [
    "a whitespace collapsed pattern",
    { pattern: "  a \n  b  " },
    'find pattern "a b", in the current working directory',
  ],
  ["non-string pattern and glob", { pattern: 42, glob: ["*.ts"], path: "src" }, "find path src"],
  ["a non-string path", { pattern: "x", path: 42 }, 'find pattern "x", in the current working directory'],
  ["a file_path fallback", { pattern: "x", file_path: "lib" }, 'find pattern "x", path lib'],
  ["a null input", null, "find in the current working directory"],
];

const GREP_CASES: SummaryCase[] = [
  [
    "pattern, glob and path",
    { pattern: "needle", glob: "*.ts", path: "src" },
    'grep pattern "needle", glob "*.ts", path src',
  ],
  ["a pattern only", { pattern: "needle" }, 'grep pattern "needle", in the current working directory'],
  ["a glob and a path", { glob: "*.ts", path: "src" }, 'grep glob "*.ts", path src'],
  ["a path only", { path: "src" }, "grep path src"],
  ["no fields", {}, "grep in the current working directory"],
  [
    "a blank glob omitted",
    { pattern: "needle", glob: "   " },
    'grep pattern "needle", in the current working directory',
  ],
];

const LS_CASES: SummaryCase[] = [
  ["a path", { path: "src" }, "ls path src"],
  ["a file_path", { file_path: "lib" }, "ls path lib"],
  ["a trimmed path", { path: "  src  " }, "ls path src"],
  ["no path", {}, "ls in the current working directory"],
  ["a blank path", { path: "   " }, "ls in the current working directory"],
  ["a null input", null, "ls in the current working directory"],
  ["an array input", [], "ls in the current working directory"],
];

const DISPATCH_CASES: DispatchCase[] = [
  ["read", "read", { path: "src/a.ts", offset: 2 }, "read src/a.ts, offset 2"],
  ["write", "write", { path: "a.txt", content: "hi" }, "write a.txt: 1 line, 2 characters"],
  [
    "edit",
    "edit",
    { path: "a.ts", edits: [{ oldText: "a", newText: "b" }] },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  ["find", "find", { pattern: "TODO", path: "src" }, 'find pattern "TODO", path src'],
  ["grep", "grep", { pattern: "needle" }, 'grep pattern "needle", in the current working directory'],
  ["ls", "ls", { path: "src" }, "ls path src"],
];

const NON_BUILTIN_NAMES: Array<[label: string, toolName: string]> = [
  ["bash", "bash"],
  ["the MCP proxy", "mcp"],
  ["uppercase read", "READ"],
  ["mixed case Edit", "Edit"],
  ["an unknown tool", "grep2"],
  ["an empty name", ""],
  ["a whitespace name", "   "],
  ["extension tools", "extension"],
  ["MCP tools", "mcp-tool"],
];

const BUILTIN_NAMES: readonly BuiltinToolName[] = ["read", "write", "edit", "find", "grep", "ls"];

const TABLE_CASES: Array<[BuiltinToolName, unknown, string]> = [
  ["read", { path: "a.ts" }, "read a.ts"],
  ["write", { path: "a.txt", content: "hi" }, "write a.txt: 1 line, 2 characters"],
  [
    "edit",
    { path: "a.ts", oldText: "a", newText: "b" },
    "edit a.ts: 1 replacement, first edit replaces 1 line with 1 line",
  ],
  ["find", { path: "src" }, "find path src"],
  ["grep", { pattern: "x" }, 'grep pattern "x", in the current working directory'],
  ["ls", {}, "ls in the current working directory"],
];

// ---------------------------------------------------------------------------
// toolInputPath
// ---------------------------------------------------------------------------

describe("toolInputPath", () => {
  it.each(PATH_CASES)("resolves %s", (_label, input, expected) => {
    expect(toolInputPath(input)).toBe(expected);
  });

  it("accepts plain objects with a null prototype", () => {
    const input = Object.assign(Object.create(null) as Record<string, unknown>, { path: "src/a.ts" });
    expect(toolInputPath(input)).toBe("src/a.ts");
  });
});

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

describe("summarizeRead", () => {
  it.each(READ_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeRead(input)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

describe("summarizeWrite", () => {
  it.each(WRITE_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeWrite(input)).toBe(expected);
  });

  it.each(WRITE_BODIES)("never includes the content body (%s)", (_label, content) => {
    const summary = summarizeWrite({ path: "a.txt", content });
    expect(summary).toBeDefined();
    expect(summary).not.toContain("SECRET_CODE_BODY");
    expect(summary).not.toContain("const token");
  });
});

// ---------------------------------------------------------------------------
// edit
// ---------------------------------------------------------------------------

describe("summarizeEdit", () => {
  it.each(EDIT_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeEdit(input)).toBe(expected);
  });

  it.each(EDIT_BODIES)("never includes the old or new body text (%s)", (_label, input) => {
    const summary = summarizeEdit(input);
    expect(summary).toBeDefined();
    expect(summary).not.toContain("SECRET_OLD_BODY");
    expect(summary).not.toContain("SECRET_NEW_BODY");
    expect(summary).not.toContain("line two");
  });
});

// ---------------------------------------------------------------------------
// find / grep
// ---------------------------------------------------------------------------

describe("summarizeFind", () => {
  it.each(FIND_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeFind(input)).toBe(expected);
  });

  it("uses the default text summary cap when limits are omitted", () => {
    const atCap = "x".repeat(DEFAULT_PREVIEW_LIMITS.textSummary);
    expect(summarizeFind({ pattern: atCap })).toBe(
      `find pattern "${atCap}", in the current working directory`,
    );
    expect(summarizeFind({ pattern: `${atCap}x` })).toBe(
      `find pattern "${atCap}${PREVIEW_ELLIPSIS}", in the current working directory`,
    );
  });
});

describe("summarizeGrep", () => {
  it.each(GREP_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeGrep(input)).toBe(expected);
  });
});

describe("find and grep injected text summary cap", () => {
  it("truncates the find pattern inside its quotes", () => {
    expect(summarizeFind({ pattern: "abcdefgh", glob: "*.ts" }, TIGHT_LIMITS)).toBe(
      `find pattern "abcde${PREVIEW_ELLIPSIS}", glob "*.ts", in the current working directory`,
    );
  });

  it("truncates the grep glob inside its quotes", () => {
    expect(summarizeGrep({ pattern: "x", glob: "abcdefgh" }, TIGHT_LIMITS)).toBe(
      `grep pattern "x", glob "abcde${PREVIEW_ELLIPSIS}", in the current working directory`,
    );
  });
});

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

describe("summarizeLs", () => {
  it.each(LS_CASES)("summarizes %s", (_label, input, expected) => {
    expect(summarizeLs(input)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

describe("summarizeBuiltinToolInput", () => {
  it.each(DISPATCH_CASES)("dispatches %s", (_label, toolName, input, expected) => {
    expect(summarizeBuiltinToolInput(toolName, input)).toBe(expected);
  });

  it("trims the tool name before dispatching", () => {
    expect(summarizeBuiltinToolInput("  read \n", { path: "a.ts" })).toBe("read a.ts");
  });

  it.each(NON_BUILTIN_NAMES)("ignores %s", (_label, toolName) => {
    expect(summarizeBuiltinToolInput(toolName, { path: "a.ts", pattern: "x" })).toBeUndefined();
  });

  it("returns undefined for a non-string tool name", () => {
    expect(summarizeBuiltinToolInput(undefined as never, { path: "a.ts" })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// BUILTIN_TOOL_SUMMARIES
// ---------------------------------------------------------------------------

describe("BUILTIN_TOOL_SUMMARIES", () => {
  it("exposes exactly the six builtin summarizers", () => {
    expect(Object.keys(BUILTIN_TOOL_SUMMARIES).sort()).toEqual([...BUILTIN_NAMES].sort());
    for (const name of BUILTIN_NAMES) {
      expect(typeof BUILTIN_TOOL_SUMMARIES[name]).toBe("function");
    }
  });

  it.each(TABLE_CASES)("%s matches the dispatcher", (name, input, expected) => {
    expect(BUILTIN_TOOL_SUMMARIES[name](input)).toBe(expected);
    expect(summarizeBuiltinToolInput(name, input)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// input shape
// ---------------------------------------------------------------------------

describe("input shape", () => {
  it("treats non-plain objects as an empty input object", () => {
    class PathLike {
      readonly path = "src/a.ts";
    }
    expect(toolInputPath(new PathLike())).toBeUndefined();
    expect(summarizeRead(new PathLike())).toBeUndefined();
    expect(summarizeLs(new PathLike())).toBe("ls in the current working directory");
    expect(summarizeFind(new Date(0))).toBe("find in the current working directory");
  });
});
