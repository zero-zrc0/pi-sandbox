import { describe, expect, it } from "vitest";
import {
  classifyToolKind,
  isBuiltinPathToolName,
  isPiMcpToolName,
  splitPiMcpName,
} from "#approve-core/utils/access-intent/tool-kind";

describe("classifyToolKind priority", () => {
  it("classifies by fixed priority after trimming", () => {
    expect(classifyToolKind("  bash ")).toBe("bash");
    expect(classifyToolKind("powershell")).toBe("powershell");
    expect(classifyToolKind("mcp")).toBe("mcp");
    expect(classifyToolKind("mcp__github__create_issue")).toBe("mcp-tool");
    expect(classifyToolKind("skill")).toBe("skill");
    expect(classifyToolKind("read")).toBe("path");
    expect(classifyToolKind("write")).toBe("path");
    expect(classifyToolKind("edit")).toBe("path");
    expect(classifyToolKind("find")).toBe("path");
    expect(classifyToolKind("grep")).toBe("path");
    expect(classifyToolKind("ls")).toBe("path");
    expect(classifyToolKind("my_extension_tool")).toBe("extension");
  });

  it("requires both parts of a Pi MCP name at the first double underscore", () => {
    expect(splitPiMcpName("mcp__a__b__c")).toEqual({ server: "mcp", tool: "a__b__c" });
    expect(splitPiMcpName("__tool")).toBeUndefined();
    expect(splitPiMcpName("server__")).toBeUndefined();
    expect(splitPiMcpName("noseparator")).toBeUndefined();
    expect(isPiMcpToolName("plain__name")).toBe(true);
    expect(isPiMcpToolName("plain")).toBe(false);
    // Prefix alone without both parts is not the category.
    expect(classifyToolKind("mcp__")).toBe("extension");
    expect(classifyToolKind("__x")).toBe("extension");
  });

  it("recognizes builtin path tool names exactly", () => {
    expect(isBuiltinPathToolName("read")).toBe(true);
    expect(isBuiltinPathToolName("reader")).toBe(false);
  });
});
