import { describe, expect, it } from "vitest";
import { Bm25Ranker, createToolSearchDocument, type ToolSearchDocument } from "#sandbox/codemode/tool-search";

describe("Pi-compatible CodeMode tool search", () => {
  const ranker = new Bm25Ranker();

  it("matches Chinese descriptions", () => {
    const documents: ToolSearchDocument[] = [
      { name: "mcp__crm__find_customer", text: "查找客户电子邮件地址" },
      { name: "read_file", text: "读取工作区文本文件" },
    ];

    expect(ranker.rank("客户 电子邮件", documents, 2)[0]?.name).toBe("mcp__crm__find_customer");
  });

  it("matches English descriptions", () => {
    const documents: ToolSearchDocument[] = [
      { name: "read_file", text: "Read text files from the workspace" },
      { name: "mcp__mail__search", text: "Search messages by recipient and subject" },
    ];

    expect(ranker.rank("recipient subject", documents, 2)[0]?.name).toBe("mcp__mail__search");
  });

  it("prioritizes an exact namespaced tool name", () => {
    const documents: ToolSearchDocument[] = [
      { name: "mcp__calendar__find_event", text: "Search calendar entries" },
      { name: "find_event_history", text: "Search event history" },
    ];

    expect(ranker.rank("find_event", documents, 2)[0]?.name).toBe("mcp__calendar__find_event");
  });

  it("indexes namespace descriptions and aliases", () => {
    const document = createToolSearchDocument({
      name: "mcp__accounting__list_records",
      description: "Returns records",
      inputSchema: { type: "object", properties: {} },
    } as never, {
      name: "accounting",
      aliases: ["ledger"],
      description: "Invoices and payments",
      instructions: "Use for bookkeeping",
    } as never);

    expect(ranker.rank("ledger invoices", [document], 1)[0]?.name).toBe("mcp__accounting__list_records");
  });

  it("indexes local schema references and returns search data without mutating documents", () => {
    const schema = {
      $defs: {
        CustomerFilter: {
          type: "object",
          properties: {
            customerId: { type: "string", description: "Stable customer identifier" },
          },
        },
      },
      type: "object",
      properties: { filter: { $ref: "#/$defs/CustomerFilter" } },
    };
    const document = createToolSearchDocument({
      name: "crm__lookup_customer",
      description: "Fetch one customer",
      inputSchema: schema,
    } as never);
    const before = structuredClone(document);
    const matches = ranker.rank("stable customer identifier", [document], 1);

    expect(matches[0]?.name).toBe("crm__lookup_customer");
    expect(Object.keys(matches[0] ?? {}).sort()).toEqual(["name", "score"]);
    expect(document).toEqual(before);
  });

  it("ranks both ordinary and MCP tools without activating either", () => {
    const documents: ToolSearchDocument[] = [
      { name: "read_file", text: "Read local workspace files" },
      { name: "mcp__drive__find_file", text: "Search remote cloud storage" },
    ];
    const before = structuredClone(documents);

    expect(ranker.rank("workspace files", documents, 1)[0]?.name).toBe("read_file");
    expect(ranker.rank("remote cloud storage", documents, 1)[0]?.name).toBe("mcp__drive__find_file");
    expect(documents).toEqual(before);
  });
});