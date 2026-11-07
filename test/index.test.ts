import { describe, expect, it } from "vitest";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import registerExtension from "../src/index";
import type { PermissionArgumentCompletion } from "../src/config/command";

describe("Pi extension entrypoint", () => {
  it("registers the permission command and approval lifecycle hooks", () => {
    const commands = new Map<string, {
      readonly getArgumentCompletions?: (argumentPrefix: string) => PermissionArgumentCompletion[] | null;
    }>();
    const events: string[] = [];
    const api = {
      registerCommand: (name: string, options: {
        readonly getArgumentCompletions?: (argumentPrefix: string) => PermissionArgumentCompletion[] | null;
      }) => commands.set(name, options),
      registerTool: () => undefined,
      getAllTools: () => [],
      getActiveTools: () => [],
      setActiveTools: () => undefined,
      appendEntry: () => undefined,
      registerToolRenderer: () => undefined,
      on: (event: string) => {
        events.push(event);
        return () => undefined;
      },
    } as unknown as ExtensionAPI;
    registerExtension(api);

    expect(commands.has("permission")).toBe(true);
    expect(commands.get("permission")?.getArgumentCompletions?.("")).toMatchObject([
      { value: "settings", label: "settings" },
    ]);
    expect(commands.get("permission")?.getArgumentCompletions?.("se")).toMatchObject([
      { value: "settings", label: "settings" },
    ]);
    expect(events).toContain("session_start");
    expect(events).toContain("tool_call");
    expect(events).toContain("session_shutdown");
  });
});
