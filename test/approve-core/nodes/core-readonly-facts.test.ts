import { describe, expect, it } from "vitest";
import {
  applyNodeResult,
  captureStep,
  prepareStep,
  readyCallResults,
  type CallSummary,
  type StepState,
} from "#approve-core/contracts";
import { analyzeStep, createBashProgramProvider } from "#approve-core/nodes/analysis";
import { createDecisionNode } from "#approve-core/nodes/decision";
import { createDefaultAssessmentResolver } from "#approve-core/nodes/assessment";
import { collectStepBashFacts } from "#approve-core/host/bash-facts";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import { POSIX_PATH_FLAVOR as POSIX } from "#approve-core/utils/path/path-flavor";
import { jsonDigest } from "../../../src/json";

const CWD = "/work/project";

/**
 * Run the production front chain for one Bash command: the same unit
 * preparation, shared parse provider and facts view the extension uses, then the
 * single decision node (`structure-analysis`/`identity` add nothing here), with
 * its batch applied to the step state.
 */
async function runChain(
  command: string,
  mode: "default" | "read-only" = "default",
): Promise<CallSummary> {
  const args = { command };
  const capture = captureStep({
    stepKey: "s",
    sessionId: "s",
    sourceEntryId: "e",
    manifestRevision: 0,
    complete: true,
    directCalls: [{ toolCallId: "c", toolName: "bash", arguments: args, argumentsDigest: jsonDigest(args) }],
  });
  if (!capture.ok) throw Error(capture.reason);
  const provider = createBashProgramProvider(capture.capture.directCalls, {
    normalizer: new PathNormalizer(POSIX, CWD, { realpathSync: (p) => p, existsSync: () => false }),
  });
  const units = await analyzeStep(capture.capture, { getBashProgram: provider });
  const prepared = prepareStep(capture.capture, units);
  if (!prepared.ok) throw Error(prepared.reason);
  const bashPrograms = await collectStepBashFacts({
    calls: capture.capture.directCalls,
    provider,
  });
  const node = createDecisionNode({
    mode,
    cwd: CWD,
    platform: "linux",
    rules: [],
    getBashProgram: provider,
    workspaceRoot: CWD,
    workspaceBulkDeleteAction: "deny",
    resolveAssessment: createDefaultAssessmentResolver({
      rules: [],
      cwd: CWD,
      getBashProgram: provider,
    }),
  });
  const context = {
    capture: capture.capture,
    state: prepared.state,
    node: { id: node.id, position: "front", priority: null },
    signal: new AbortController().signal,
    deadlineAt: null,
    ...(bashPrograms === undefined ? {} : { bashPrograms }),
  };
  const result = await node.evaluate(context as never, {} as never);
  const applied = applyNodeResult(
    prepared.state,
    { node: { id: node.id, priority: null }, evaluatedRevision: prepared.state.revision, result },
    bashPrograms === undefined ? {} : { bashPrograms },
  );
  if (!applied.ok) throw Error(applied.reason);
  const summary = readyCallResults(applied.state as StepState)[0];
  if (summary === undefined) throw Error("no-summary");
  return summary;
}

describe("core read-only Bash facts", () => {
  it.each([
    "ls",
    "ls *.ts",
    "ls -la",
    "cat README.md",
    "cat $FILE",
    "grep TODO src/",
    "echo hi",
    "pwd",
    "find . -name '*.ts'",
    "git status",
    "git status && ls",
    "ls && cat README.md",
    "echo hi > out.txt",
  ])("allows proven read-only command %s in default mode", async (command) => {
    expect((await runChain(command)).decision).toBe("allow");
  });

  it.each([
    "cd sub",
    "cd sub && ls",
    "export PATH=/tmp && ls",
    "sort -o out.txt f.txt",
    "sed -i s/a/b/ f.txt",
    "find . -exec rm {} \\;",
    "eval ls",
    "ls \"",
  ])("keeps uncertain or write-capable command %s on the ask path", async (command) => {
    expect((await runChain(command)).decision).toBe("ask");
  });

  it("denies a host-control command instead of asking", async () => {
    const summary = await runChain("sudo ls");
    expect(summary.decision).toBe("deny");
    expect(summary.reasons[0].reason).toContain("risk:host-control");
  });

  it("escalates a redirect outside the workspace", async () => {
    const summary = await runChain("echo hi > ../outside.txt");
    expect(summary.decision).toBe("ask");
    expect(summary.askFor).toBe("escalate");
  });

  it("denies a proven workspace write in read-only mode and allows a core read", async () => {
    expect((await runChain("ls", "read-only")).decision).toBe("allow");
    expect((await runChain("echo hi > out.txt", "read-only")).decision).toBe("deny");
  });
});
