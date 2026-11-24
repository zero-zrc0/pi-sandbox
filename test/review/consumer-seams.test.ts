import { describe, expect, it } from "vitest";
import { captureStep, prepareStep } from "#approve-core/contracts";
import { deriveAccessFacts } from "#approve-core/nodes/mode";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { PermissionService } from "#approve-core/policy/permissions-service";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { checkBashCommand } from "#approve-core/utils/bash-command-check";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { POSIX_PATH_FLAVOR } from "#approve-core/utils/path/path-flavor";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { jsonDigest } from "../../src/json";

function policy(permission: unknown) {
  const normalizer = new PathNormalizer(POSIX_PATH_FLAVOR, "/review/project", {
    home: "/review/home",
    realpathSync: (value) => value,
    existsSync: () => false,
  });
  const session = new SessionRuleStore({ flavor: POSIX_PATH_FLAVOR });
  const manager = new PermissionManager({
    flavor: POSIX_PATH_FLAVOR,
    session,
    loadPolicy: () => ({ stamp: "review-1", scopes: { global: { permission } } }),
  });
  const resolver = new PermissionResolver({ manager, normalizer, mcpConfigServers: ["my.server"] });
  return { normalizer, session, manager, resolver };
}

describe("rule evaluator consumer contracts", () => {
  it("uses the last matching rule for aliases and the most restrictive result for separate paths", () => {
    const { manager, resolver } = policy({
      mcp: { "short-name": "deny", "long-name": "allow" },
      path_read: { "/review/project/*": "allow", "/review/private/*": "deny" },
    });
    expect(manager.check({ kind: "fixed-values", surface: "mcp", values: ["short-name", "long-name"] }).state)
      .toBe("allow");
    expect(resolver.checkPathValues("path_read", [
      { display: "/review/project/a.txt", boundary: "/review/project/a.txt", matchValues: ["/review/project/a.txt"] },
      { display: "/review/private/b.txt", boundary: "/review/private/b.txt", matchValues: ["/review/private/b.txt"] },
    ]).state).toBe("deny");
  });
});

describe("permission service and gate consistency", () => {
  it("uses the same configured MCP server aliases as the gate resolver", () => {
    const parts = policy({ mcp: { "*": "allow", "my.server_lookup": "deny" } });
    const service = new PermissionService(parts);
    expect(parts.resolver.check({ toolName: "my_server__lookup", input: {} }).state).toBe("deny");
    expect(service.checkMcp("my_server__lookup").state).toBe("deny");
  });

  it("keeps the gate wrapper floor in a warm advisory query", async () => {
    const parts = policy({ bash: "allow" });
    const command = "sh -c 'printf review'";
    const program = await BashProgram.parse(command, parts.normalizer);
    expect(program.commands().some((unit) => unit.wrapperKind !== undefined)).toBe(true);
    const gate = checkBashCommand({
      command,
      units: program.commands(),
      resolve: (text) => parts.manager.checkBashCommand(text, [text]),
    });
    expect(gate.check.state).toBe("ask");
    const service = new PermissionService({
      ...parts,
      bash: { units: () => program.commands().map((unit) => unit.text) },
    });
    expect(service.checkBash(command).state).toBe("ask");
  });

  it("preserves an explicit denial in both the gate and warm advisory query", async () => {
    const parts = policy({ bash: "deny" });
    const command = "printf review";
    const program = await BashProgram.parse(command, parts.normalizer);
    const gate = checkBashCommand({
      command,
      units: program.commands(),
      resolve: (text) => parts.manager.checkBashCommand(text, [text]),
    });
    const service = new PermissionService({ ...parts, bash: { units: () => [command] } });
    expect(gate.check.state).toBe("deny");
    expect(service.checkBash(command).state).toBe("deny");
  });
});

describe("Bash path facts at the mode node consumer", () => {
  it("keeps an outside redirect target in the mode node facts with the default parsing path", async () => {
    const args = { command: "printf review > /review/result.txt" };
    const capture = captureStep({
      stepKey: "review-step", sessionId: "review-session", sourceEntryId: "review-source",
      manifestRevision: 0, complete: true,
      directCalls: [{ toolCallId: "review-call", toolName: "bash", arguments: args, argumentsDigest: jsonDigest(args) }],
    });
    if (!capture.ok) throw new Error(`capture failed: ${capture.reason}`);
    const call = capture.capture.directCalls[0];
    const prepared = prepareStep(capture.capture, [{
      toolCallId: call.toolCallId, unitId: "review-unit", actionDigest: call.digest, reason: "review",
    }]);
    if (!prepared.ok) throw new Error(`preparation failed: ${prepared.reason}`);
    const facts = await deriveAccessFacts(prepared.state.calls[0], { cwd: "/review/project", platform: "linux" });
    expect(facts).toContainEqual({ kind: "write", path: "/review/result.txt", external: true });
  });
});
