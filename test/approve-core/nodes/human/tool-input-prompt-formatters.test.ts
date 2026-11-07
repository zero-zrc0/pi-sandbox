import { describe, expect, it } from "vitest";
import {
  PREVIEW_ELLIPSIS,
  resolvePreviewLimits,
} from "#approve-core/nodes/human/tool-input-preview";
import {
  createMcpPromptFormatter,
  createPromptToolInputFormatter,
  formatMcpProxyInput,
  registerMcpPromptFormatter,
  type FormatterRegistrationPort,
  type PromptToolInputFormatter,
  type ToolInputFormatterLookup,
} from "#approve-core/nodes/human/tool-input-prompt-formatters";
import { ToolInputFormatterRegistry } from "#approve-core/utils/tool-access/tool-input-formatter-registry";

interface FakeLookup extends ToolInputFormatterLookup {
  readonly calls: string[];
}

/** Hand-rolled lookup seam: records the queried names, never mocks a module. */
function fakeLookup(table: Readonly<Record<string, (input: unknown) => unknown>>): FakeLookup {
  const calls: string[] = [];
  return {
    calls,
    lookup(toolName: string) {
      calls.push(toolName);
      return table[toolName];
    },
  };
}

describe("attach", () => {
  it("returns the bare title when there is no preview", () => {
    const formatter = createPromptToolInputFormatter();
    expect(formatter.attach("Approve this call once", undefined)).toBe("Approve this call once");
  });

  it("appends the preview with the documented connector", () => {
    const formatter = createPromptToolInputFormatter();
    expect(formatter.attach("Approve this call once", "read src/a.ts")).toBe(
      "Approve this call once with input read src/a.ts",
    );
  });
});

describe("createPromptToolInputFormatter custom formatter dispatch", () => {
  it("prefers a custom formatter over the built-in summary", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ read: () => "custom read preview" }),
    });
    expect(formatter.preview("read", { path: "src/a.ts" })).toBe("custom read preview");
  });

  it("looks up the trimmed tool name", () => {
    const lookup = fakeLookup({ read: () => "custom read preview" });
    const formatter = createPromptToolInputFormatter({ formatters: lookup });
    expect(formatter.preview("  read  ", { path: "src/a.ts" })).toBe("custom read preview");
    expect(lookup.calls).toEqual(["read"]);
  });

  it("inline-sanitizes the custom formatter result", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ webfetch: () => "  noisy \n\t text  " }),
    });
    expect(formatter.preview("webfetch", { url: "https://example.test" })).toBe("noisy text");
  });

  it("bounds a custom formatter result by the prompt input cap", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ webfetch: () => "z".repeat(300) }),
    });
    const preview = formatter.preview("webfetch", {});
    expect(preview).toBe(`${"z".repeat(200)}${PREVIEW_ELLIPSIS}`);
    expect(preview).toHaveLength(201);
  });

  it("honors an injected prompt input cap", () => {
    const formatter = createPromptToolInputFormatter({
      limits: { promptInput: 10 },
      formatters: fakeLookup({ webfetch: () => "abcdefghijklmnop" }),
    });
    expect(formatter.preview("webfetch", {})).toBe(`abcdefghij${PREVIEW_ELLIPSIS}`);
  });

  it("treats a declined custom formatter as absent and falls back to the built-in summary", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ read: () => undefined }),
    });
    expect(formatter.preview("read", { path: "src/a.ts" })).toBe("read src/a.ts");
  });

  it("treats a throwing custom formatter as absent and falls back to the built-in summary", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({
        read: () => {
          throw new Error("custom formatter exploded");
        },
      }),
    });
    expect(() => formatter.preview("read", { path: "src/a.ts" })).not.toThrow();
    expect(formatter.preview("read", { path: "src/a.ts" })).toBe("read src/a.ts");
  });

  it("treats a throwing custom formatter as absent and falls back to generic JSON", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({
        bash: () => {
          throw new Error("custom formatter exploded");
        },
      }),
    });
    expect(formatter.preview("bash", { command: "ls -la" })).toBe('{"command":"ls -la"}');
  });

  it("treats a non-string custom result as declined", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ read: () => 42 }),
    });
    expect(formatter.preview("read", { path: "src/a.ts" })).toBe("read src/a.ts");
  });

  it("falls through when the custom result sanitizes to empty text", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ read: () => "   \n\t " }),
    });
    expect(formatter.preview("read", { path: "src/a.ts" })).toBe("read src/a.ts");
  });

  it("skips the custom lookup entirely for a blank tool name", () => {
    const lookup = fakeLookup({ read: () => "custom read preview" });
    const formatter = createPromptToolInputFormatter({ formatters: lookup });
    expect(formatter.preview("   ", { a: 1 })).toBe('{"a":1}');
    expect(lookup.calls).toHaveLength(0);
  });

  it("continues into the MCP formatter when the custom formatter declines", () => {
    const formatter = createPromptToolInputFormatter({
      formatters: fakeLookup({ mcp: () => undefined }),
    });
    expect(formatter.preview("mcp", { arguments: { query: "hello", limit: 5 } })).toBe(
      'parameters query: "hello", limit: 5',
    );
  });
});

describe("createPromptToolInputFormatter built-in dispatch", () => {
  const formatter: PromptToolInputFormatter = createPromptToolInputFormatter();

  it("summarizes built-in path tools", () => {
    expect(formatter.preview("read", { path: "src/a.ts", offset: 10, limit: 20 })).toBe(
      "read src/a.ts, offset 10, limit 20",
    );
    expect(formatter.preview("write", { path: "out.txt", content: "a\nb\nc" })).toBe(
      "write out.txt: 3 lines, 5 characters",
    );
    expect(formatter.preview("find", { pattern: "TODO", path: "src" })).toBe(
      'find pattern "TODO", path src',
    );
  });

  it("does not fall back to generic JSON when a path summary is unavailable", () => {
    expect(formatter.preview("read", {})).toBeUndefined();
    expect(formatter.preview("edit", { oldText: "a", newText: "b" })).toBeUndefined();
  });

  it("never leaks write or edit bodies into the prompt preview", () => {
    const edit = formatter.preview("edit", {
      path: "notes.txt",
      edits: [{ oldText: "OLD_SECRET", newText: "NEW_SECRET" }],
    });
    expect(edit).toBe("edit notes.txt: 1 replacement, first edit replaces 1 line with 1 line");
    expect(edit).not.toContain("OLD_SECRET");
    expect(edit).not.toContain("NEW_SECRET");
  });

  it("does not fall back to generic JSON for the MCP proxy", () => {
    expect(formatter.preview("mcp", {})).toBeUndefined();
    expect(formatter.preview("mcp", { arguments: {} })).toBeUndefined();
    expect(formatter.preview("mcp", { arguments: null })).toBeUndefined();
    expect(formatter.preview("mcp", { arguments: ["query"] })).toBeUndefined();
    expect(formatter.preview("mcp", { arguments: {}, extra: "leaked" })).toBeUndefined();
  });

  it("falls back to generic JSON for bash, Pi MCP and extension tools", () => {
    expect(formatter.preview("bash", { command: "rm -rf build" })).toBe('{"command":"rm -rf build"}');
    expect(formatter.preview("server__search", { query: "needle" })).toBe('{"query":"needle"}');
    expect(formatter.preview("webfetch", { url: "https://example.test" })).toBe(
      '{"url":"https://example.test"}',
    );
  });

  it("produces no generic JSON preview for null and empty object payloads", () => {
    expect(formatter.preview("bash", null)).toBeUndefined();
    expect(formatter.preview("bash", {})).toBeUndefined();
  });

  it("bounds generic JSON by the 200 character prompt cap", () => {
    const preview = formatter.preview("webfetch", { url: "x".repeat(400) });
    expect(preview).toHaveLength(201);
    expect(preview?.endsWith(PREVIEW_ELLIPSIS)).toBe(true);
  });
});

describe("formatMcpProxyInput", () => {
  it("formats string, number, boolean, array and object arguments", () => {
    expect(
      formatMcpProxyInput({
        arguments: {
          query: "hello",
          limit: 5,
          ratio: 3.5,
          enabled: true,
          tags: ["a", "b"],
          filter: { nested: true },
        },
      }),
    ).toBe(
      'parameters query: "hello", limit: 5, ratio: 3.5, enabled: true, tags: 2 items, filter: {…}',
    );
  });

  it("uses the singular item label for one-element arrays", () => {
    expect(formatMcpProxyInput({ arguments: { tags: ["only"] } })).toBe("parameters tags: 1 item");
  });

  it("collapses whitespace inside string arguments before quoting", () => {
    expect(formatMcpProxyInput({ arguments: { q: "  hello \n\t world  " } })).toBe(
      'parameters q: "hello world"',
    );
  });

  it("quotes an empty string argument", () => {
    expect(formatMcpProxyInput({ arguments: { q: "" } })).toBe('parameters q: ""');
  });

  it("renders non-finite numbers and primitive fallbacks with String()", () => {
    expect(formatMcpProxyInput({ arguments: { n: Number.NaN } })).toBe("parameters n: NaN");
    expect(formatMcpProxyInput({ arguments: { n: null } })).toBe("parameters n: null");
    expect(formatMcpProxyInput({ arguments: { flag: false } })).toBe("parameters flag: false");
  });

  it("returns undefined for a missing, null or non-object arguments field", () => {
    expect(formatMcpProxyInput(undefined)).toBeUndefined();
    expect(formatMcpProxyInput(null)).toBeUndefined();
    expect(formatMcpProxyInput("input")).toBeUndefined();
    expect(formatMcpProxyInput({})).toBeUndefined();
    expect(formatMcpProxyInput({ arguments: null })).toBeUndefined();
    expect(formatMcpProxyInput({ arguments: [] })).toBeUndefined();
    expect(formatMcpProxyInput({ arguments: "query" })).toBeUndefined();
  });

  it("returns undefined for an arguments object with no parameters", () => {
    expect(formatMcpProxyInput({ arguments: {} })).toBeUndefined();
  });

  it("truncates each string value at the default 60 character cap", () => {
    expect(formatMcpProxyInput({ arguments: { q: "a".repeat(70) } })).toBe(
      `parameters q: "${"a".repeat(60)}${PREVIEW_ELLIPSIS}"`,
    );
  });

  it("respects an injected mcp value cap", () => {
    const limits = resolvePreviewLimits({ mcpValue: 3 });
    expect(formatMcpProxyInput({ arguments: { q: "abcdefghij" } }, limits)).toBe(
      `parameters q: "abc${PREVIEW_ELLIPSIS}"`,
    );
  });

  it("truncates the whole summary at the default 160 character cap", () => {
    const preview = formatMcpProxyInput({
      arguments: {
        alpha: "a".repeat(50),
        beta: "b".repeat(50),
        gamma: "c".repeat(50),
      },
    });
    expect(preview).toBeDefined();
    expect(preview?.length).toBe(161);
    expect(preview?.endsWith(PREVIEW_ELLIPSIS)).toBe(true);
    expect(preview?.startsWith("parameters ")).toBe(true);
  });

  it("truncates the whole summary including the parameters prefix", () => {
    const limits = resolvePreviewLimits({ mcpSummary: 10 });
    expect(formatMcpProxyInput({ arguments: { query: "hello" } }, limits)).toBe(
      `parameters${PREVIEW_ELLIPSIS}`,
    );
  });
});

describe("createMcpPromptFormatter", () => {
  it("returns the documented arguments preview", () => {
    const formatter = createMcpPromptFormatter();
    expect(formatter({ arguments: { query: "hello" } })).toBe('parameters query: "hello"');
  });

  it("returns undefined for empty arguments", () => {
    const formatter = createMcpPromptFormatter();
    expect(formatter({ arguments: {} })).toBeUndefined();
    expect(formatter({})).toBeUndefined();
  });

  it("applies injected limits", () => {
    const formatter = createMcpPromptFormatter(resolvePreviewLimits({ mcpSummary: 6 }));
    expect(formatter({ arguments: { query: "hello" } })).toBe(`parame${PREVIEW_ELLIPSIS}`);
  });
});

describe("registerMcpPromptFormatter", () => {
  it("registers exactly one formatter named mcp through the injected port", () => {
    const registrations: Array<{ name: string; formatter: (input: unknown) => unknown }> = [];
    const port: FormatterRegistrationPort = {
      register(name, formatter) {
        registrations.push({ name, formatter });
        return () => {};
      },
    };

    const dispose = registerMcpPromptFormatter(port, { limits: { mcpSummary: 6 } });

    expect(registrations).toHaveLength(1);
    expect(registrations[0]?.name).toBe("mcp");
    expect(registrations[0]?.formatter({ arguments: { query: "hello" } })).toBe(
      `parame${PREVIEW_ELLIPSIS}`,
    );
    expect(typeof dispose).toBe("function");
  });

  it("registers into the real public ToolInputFormatterRegistry", () => {
    const registry = new ToolInputFormatterRegistry();
    const dispose = registerMcpPromptFormatter(registry);

    const formatter = registry.lookup("mcp");
    expect(typeof formatter).toBe("function");
    expect(formatter?.({ arguments: { query: "hello", limit: 5 } })).toBe(
      'parameters query: "hello", limit: 5',
    );
    expect(registry.lookup("read")).toBeUndefined();
    expect(registry.lookup("bash")).toBeUndefined();

    dispose();
    expect(registry.lookup("mcp")).toBeUndefined();
  });

  it("lets the real registry reject a duplicate mcp registration and recovers after disposal", () => {
    const registry = new ToolInputFormatterRegistry();
    const dispose = registerMcpPromptFormatter(registry);

    expect(() => registerMcpPromptFormatter(registry)).toThrow(
      "tool-input-formatter: duplicate name",
    );

    dispose();
    const disposeAgain = registerMcpPromptFormatter(registry, { limits: { mcpSummary: 5 } });
    expect(registry.lookup("mcp")?.({ arguments: { query: "hello" } })).toBe(
      `param${PREVIEW_ELLIPSIS}`,
    );
    disposeAgain();
  });
});
