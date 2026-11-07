import { describe, expect, it } from "vitest";
import { createRuleEvaluator, type Rule } from "#approve-core/policy/rule";
import { compileWildcard } from "#approve-core/policy/wildcard-matcher";
import { POSIX_PATH_FLAVOR as POSIX, WIN32_PATH_FLAVOR as WIN32 } from "#approve-core/utils/path/path-flavor";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { BashProgram } from "#approve-core/utils/access-intent/bash/program";
import { createBashProgramProvider } from "#approve-core/nodes/analysis";
import { createModeNode, deriveAccessFacts } from "#approve-core/nodes/mode";
import { createDefaultAssessmentResolver } from "#approve-core/nodes/assessment";
import { createRulesNode } from "#approve-core/nodes/rules";
import type { NodeHost, StepContext } from "#approve-core/runtime";
import { captureStep, prepareStep } from "#approve-core/contracts";
import { jsonDigest } from "../../src/json";
import { PermissionManager } from "#approve-core/policy/permission-manager";
import { PermissionResolver } from "#approve-core/policy/permission-resolver";
import { PermissionService } from "#approve-core/policy/permissions-service";
import { SessionRuleStore } from "#approve-core/policy/session-rules";
import { checkBashCommand } from "#approve-core/utils/bash-command-check";
import { normalizeToolTargets } from "#approve-core/utils/access-intent/input-normalizer";

const rule = (surface: string, pattern: string, action: Rule["action"]): Rule => ({ surface, pattern, action, origin: "global", layer: "config" });
const normalizer = () => new PathNormalizer(POSIX, "/work/project", { realpathSync: (p) => p, existsSync: () => false });
function prepared(command: string, toolName = "bash", args: Record<string, unknown> = { command }) {
  const capture = captureStep({ stepKey: "s", sessionId: "s", sourceEntryId: "e", manifestRevision: 0, complete: true,
    directCalls: [{ toolCallId: "c", toolName, arguments: args, argumentsDigest: jsonDigest(args) }] });
  if (!capture.ok) throw Error(capture.reason);
  const call = capture.capture.directCalls[0]!;
  const state = prepareStep(capture.capture, [{ toolCallId: call.toolCallId, unitId: "u", actionDigest: call.digest, reason: "test" }]);
  if (!state.ok) throw Error(state.reason);
  return state.state.calls[0]!;
}

describe("completion boundaries", () => {
  it("matches surface wildcards with ordered rules, case sensitivity, and shared compilation", () => {
    let surfaceCompiles = 0; let valueCompiles = 0;
    const evaluator = createRuleEvaluator([rule("doc_*", "*", "deny"), rule("doc_?", "safe", "allow")], WIN32, {
      compileSurfacePattern: (p, o) => { surfaceCompiles++; return compileWildcard(p, o); },
      compilePattern: (p, o) => { valueCompiles++; return compileWildcard(p, o); },
    });
    expect(evaluator.evaluate("doc_x", "safe").action).toBe("allow");
    expect(evaluator.evaluate("doc_xy", "safe").action).toBe("deny");
    expect(evaluator.evaluate("Doc_x", "safe").action).toBe("ask");
    expect(evaluator.isSurfaceFullyDenied("doc_x")).toBe(false);
    expect(surfaceCompiles).toBe(2); expect(valueCompiles).toBe(2);
    const reversed = createRuleEvaluator([rule("doc_x", "*", "allow"), rule("doc_*", "*", "deny")], POSIX);
    expect(reversed.evaluate("doc_x", "safe").action).toBe("deny");
  });

  it("isolates the old rule order and exposed view from array mutations", () => {
    const input = [rule("a", "*", "deny"), rule("a", "safe", "allow"), rule("b", "*", "deny")];
    const old = createRuleEvaluator(input, POSIX);
    input.reverse(); input.splice(1, 1); input[0] = rule("b", "*", "allow");
    expect(old.evaluate("a", "safe").action).toBe("allow");
    expect(old.evaluate("b", "x").action).toBe("deny");
    expect(Object.isFrozen(old.rules)).toBe(true);
    expect(createRuleEvaluator(input, POSIX).evaluate("b", "x").action).toBe("allow");
  });

  it("shares one parsed program and respects declared write effects", async () => {
    const parser = await (await import("#approve-core/utils/access-intent/bash/parser")).bashParser.corrected();
    let parses = 0;
    const call = prepared("custom ../result.txt");
    const get = createBashProgramProvider([call], { normalizer: normalizer(), parser: { parse: (text) => { parses++; return parser.parse(text); } }, commandEffects: { project: { custom: { effects: "write" } } } });
    const [first, second] = await Promise.all([get(call), get(call)]);
    expect(first).toBe(second); expect(parses).toBe(1);
    expect(first!.externalAccesses().map((x) => [x.path.value(), x.effect.effect])).toContainEqual(["/work/result.txt", "write"]);
  });

  it("keeps unavailable or failed path analysis unknown to mode", async () => {
    const call = prepared("printf x");
    const withoutPaths = await BashProgram.parse("printf x", normalizer());
    expect(withoutPaths.pathFactsAvailable).toBe(false);
    expect(await deriveAccessFacts(call, { getBashProgram: async () => withoutPaths })).toContainEqual({ kind: "unknown" });
    expect(await deriveAccessFacts(call, { getBashProgram: async () => { throw Error("failed"); } })).toEqual([{ kind: "unknown" }]);
  });

  it("keeps configured MCP aliases and updates both resolver and service together", () => {
    let names = ["my.server"];
    const session = new SessionRuleStore({ flavor: POSIX });
    const manager = new PermissionManager({ flavor: POSIX, session, loadPolicy: () => ({ stamp: "1", scopes: { global: { permission: { mcp: { "*": "allow", "my.server_lookup": "deny" } } } } }) });
    const n = normalizer();
    const resolver = new PermissionResolver({ manager, normalizer: n, mcpConfigServers: () => names });
    const service = new PermissionService({ manager, resolver, normalizer: n, session });
    const query = () => service.checkMcp("mcp__my_server__lookup");
    const gate = () => resolver.check({ toolName: "mcp__my_server__lookup", input: {} });
    expect(query()).toMatchObject({ state: "deny", target: "my.server_lookup" });
    expect(query()).toEqual(gate());
    const pinned = resolver.buildIntent("mcp__my_server__lookup", {});
    names = ["other"];
    expect(query().state).toBe("allow"); expect(query()).toEqual(gate());
    expect(manager.check(pinned).state).toBe("deny");
  });

  it("uses proxy tool arguments consistently for queries and the rules node", async () => {
    const args = { tool: "gh:pr", arguments: { state: "open" } };
    const rules = [rule("mcp", "mcp", "allow"), rule("mcp", "gh_pr", "deny")];
    const session = new SessionRuleStore({ flavor: POSIX });
    const manager = new PermissionManager({ flavor: POSIX, session, loadPolicy: () => ({ stamp: "1", scopes: { global: { permission: { mcp: { mcp: "allow", gh_pr: "deny" } } } } }) });
    const n = normalizer();
    const resolver = new PermissionResolver({ manager, normalizer: n });
    const service = new PermissionService({ manager, resolver, normalizer: n, session });
    const call = prepared("", "mcp", args);
    const candidates = normalizeToolTargets(call.toolName, call.arguments).targets;
    const node = createRulesNode({ rules, mcpTargets: () => candidates });
    const result = await node.evaluate({ state: { calls: [call] } } as unknown as StepContext, {} as NodeHost);
    expect(service.checkTool("mcp", args)).toMatchObject({ state: "deny", target: "gh_pr" });
    expect(resolver.check({ toolName: "mcp", input: args })).toMatchObject({ state: "deny", target: "gh_pr" });
    expect(result.decisions).toContainEqual(expect.objectContaining({ decision: "deny" }));
  });

  it("retains each structured asking unit and its floor in advisory queries", async () => {
    const command = "sh -c 'echo one'; sh -c 'echo two'";
    const n = normalizer(); const program = await BashProgram.parse(command, n);
    const session = new SessionRuleStore({ flavor: POSIX });
    const manager = new PermissionManager({ flavor: POSIX, session, loadPolicy: () => ({ stamp: "1", scopes: { global: { permission: { bash: "allow" } } } }) });
    const resolver = new PermissionResolver({ manager, normalizer: n });
    const service = new PermissionService({ manager, resolver, normalizer: n, session, bash: { units: () => program.commands() } });
    const gate = checkBashCommand({ command, units: program.commands(), resolve: (text) => manager.checkBashCommand(text, [text]) }).check;
    const result = service.checkBash(command);
    expect(result).toMatchObject({ state: "ask", bashAnalysis: "decomposed", askingUnits: gate.askingUnits });
    expect(result.askingUnits!.filter((item) => item.floor?.startsWith("<wrapper:")).length).toBeGreaterThanOrEqual(2);
  });
  it("requires escalation for outside redirects and rejects writes in read-only mode", async () => {
    const call = prepared("printf x > ../result.txt");
    const context = { state: { calls: [call] } } as unknown as StepContext;
    const n = normalizer();
    const provider = createBashProgramProvider([call], { normalizer: n });
    for (const mode of ["default", "auto-review"] as const) {
      const result = await createModeNode({ mode, getBashProgram: provider }).evaluate(context, {} as NodeHost);
      expect(result.decisions).toContainEqual(expect.objectContaining({ decision: "ask", askFor: "escalate" }));
    }
    const readOnly = await createModeNode({ mode: "read-only", getBashProgram: provider }).evaluate(context, {} as NodeHost);
    expect(readOnly.decisions).toContainEqual(expect.objectContaining({ decision: "deny" }));
  });

  it("retains explicit path deny and wrapper floor in assessment", async () => {
    const call = prepared("printf x > ../result.txt");
    const provider = createBashProgramProvider([call], { normalizer: normalizer() });
    const assessment = createDefaultAssessmentResolver({ rules: [rule("bash", "*", "allow"), rule("external_directory_write", "*", "deny")], getBashProgram: provider });
    expect(await assessment(call, {} as StepContext)).toMatchObject({ route: "block" });
    const wrapped = prepared("sh -c 'echo x'");
    const wrapperAssessment = createDefaultAssessmentResolver({ rules: [rule("bash", "*", "allow")], getBashProgram: createBashProgramProvider([wrapped], { normalizer: normalizer() }) });
    expect(await wrapperAssessment(wrapped, {} as StepContext)).toMatchObject({ route: "review" });
  });

  it("uses the last matching MCP rule across aliases in the actual rules node", async () => {
    const call = prepared("", "mcp__my_server__lookup");
    const context = { state: { calls: [call] } } as unknown as StepContext;
    const candidates = ["my.server_lookup", "my_server_lookup", "mcp"];
    const node = createRulesNode({ rules: [rule("mcp", "my.server_lookup", "deny"), rule("mcp", "mcp", "allow")], mcpTargets: () => candidates });
    const result = await node.evaluate(context, {} as NodeHost);
    expect(result.decisions).toContainEqual(expect.objectContaining({ decision: "allow" }));
    const reversed = createRulesNode({ rules: [rule("mcp", "mcp", "allow"), rule("mcp", "my.server_lookup", "deny")], mcpTargets: () => candidates });
    const denied = await reversed.evaluate(context, {} as NodeHost);
    expect(denied.decisions).toContainEqual(expect.objectContaining({ decision: "deny" }));
  });

  it("preserves exact session grants but does not exempt wildcard grants from a wrapper floor", async () => {
    const command = "sh -c 'echo x'";
    const n = normalizer(); const program = await BashProgram.parse(command, n);
    const session = new SessionRuleStore({ flavor: POSIX });
    const manager = new PermissionManager({ flavor: POSIX, session, loadPolicy: () => ({ stamp: "1", scopes: { global: { permission: { bash: "allow" } } } }) });
    const resolver = new PermissionResolver({ manager, normalizer: n });
    const service = new PermissionService({ manager, resolver, normalizer: n, session, bash: { units: () => program.commands() } });
    session.approve("bash", "sh *");
    expect(service.checkBash(command)).toMatchObject({ state: "ask", floor: expect.stringMatching(/^<wrapper:/) });
    session.approve("bash", command);
    expect(service.checkBash(command)).toMatchObject({ state: "allow", source: "session" });
  });

  it("preserves an explicit denial when the shared parser fails", async () => {
    const call = prepared("blocked --flag");
    const assessment = createDefaultAssessmentResolver({ rules: [rule("bash", "blocked *", "deny")], getBashProgram: async () => { throw Error("unavailable"); } });
    expect(await assessment(call, {} as StepContext)).toMatchObject({ route: "block" });
  });

  it("pins command effects before a later configuration update", async () => {
    const call = prepared("custom ../result.txt");
    const effects = { project: { custom: { effects: "write" } } };
    const old = createBashProgramProvider([call], { normalizer: normalizer(), commandEffects: effects });
    effects.project.custom.effects = "read";
    const next = createBashProgramProvider([call], { normalizer: normalizer(), commandEffects: effects });
    expect((await old(call))!.externalAccesses()[0]!.effect.effect).toBe("write");
    expect((await next(call))!.externalAccesses()[0]!.effect.effect).toBe("read");
  });

  it("reports advisory analysis failure without losing an explicit deny", () => {
    const n = normalizer();
    const session = new SessionRuleStore({ flavor: POSIX });
    const manager = new PermissionManager({ flavor: POSIX, session, loadPolicy: () => ({ stamp: "1", scopes: { global: { permission: { bash: { "*": "allow", "blocked *": "deny" } } } } }) });
    const resolver = new PermissionResolver({ manager, normalizer: n });
    const service = new PermissionService({ manager, resolver, normalizer: n, session, commandEffects: () => { throw Error("unavailable"); } });
    expect(service.checkBash("echo ok")).toMatchObject({ state: "ask", bashAnalysis: "incomplete" });
    expect(service.checkBash("blocked x")).toMatchObject({ state: "deny", bashAnalysis: "incomplete" });
  });

});

