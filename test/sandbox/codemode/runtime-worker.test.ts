import { CodemodeSandbox } from "@earendil-works/pi-codemode";
import { describe, expect, it } from "vitest";

describe("pi-codemode public worker runtime", () => {
  it("runs a script and returns its host tool call through the public worker", async () => {
    const sandbox = new CodemodeSandbox({ timeoutMs: 10_000 });
    const calls: unknown[] = [];
    let run: ReturnType<typeof sandbox.start>;

    try {
      run = sandbox.start(
        `const result = await tools.echo({ message: "hello" });
text(result.message);
return result.message;`,
        {
          startedAt: Date.now(),
          seed: 7,
          tools: [{ name: "echo", description: "Returns the host message." }],
          onCall(call) {
            calls.push(call);
            run.deliver(1, Date.now(), call.id, {
              ok: true,
              value: { message: "host result" },
            });
          },
        },
      );

      const result = await run.result;

      expect(calls).toEqual([
        {
          id: 1,
          target: "tool",
          name: "echo",
          args: { message: "hello" },
        },
      ]);
      expect(result).toMatchObject({
        ok: true,
        value: "host result",
        output: [{ type: "text", text: "host result" }],
        calls: [{ name: "echo", status: "ok" }],
      });
    } finally {
      await sandbox.close();
    }
  });
});
