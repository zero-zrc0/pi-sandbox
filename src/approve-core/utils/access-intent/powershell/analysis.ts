import { jsonDigest } from "../../../../json";
import { pathFlavorForPlatform } from "#approve-core/utils/path/path-flavor";
import { PathNormalizer } from "#approve-core/utils/path/path-normalizer";
import type {
  ExecutableIdentity,
  FileTargetFact,
  Knowledge,
  NetworkTargetFact,
  ProgramInvocation,
  ShellEffect,
  ShellOperationFact,
  SourceExtent,
} from "#approve-core/policy/shell-policy/facts";
import { analyzeExternalProgram } from "#approve-core/policy/shell-policy/program-adapters";
import type {
  PowerShellLanguageOperationKind,
  PowerShellParseResult,
  PowerShellParseSummary,
} from "./parser";

export interface PowerShellAnalysisUnit extends SourceExtent {
  readonly unitId: string;
  readonly text: string;
}

export interface PowerShellCallAnalysis {
  readonly completeness: "complete" | "uncertain" | "failed";
  readonly engineIdentity?: string;
  readonly units: readonly PowerShellAnalysisUnit[];
  readonly programInvocations: readonly ProgramInvocation[];
  readonly operations: readonly ShellOperationFact[];
  readonly diagnostics: readonly string[];
}

export interface PowerShellProgramFactsView {
  readonly callDigest: string;
  readonly commandText: string;
  readonly cwd: string;
  readonly result: PowerShellParseResult;
  readonly analysis: PowerShellCallAnalysis;
}

export interface PowerShellAnalysisCall {
  readonly toolCallId: string;
  readonly digest: string;
}

export function powerShellUnitId(
  toolCallId: string,
  callDigest: string,
  extent: SourceExtent,
): string {
  const digest = jsonDigest({ toolCallId, callDigest, start: extent.start, end: extent.end }).slice(0, 16);
  return `${toolCallId}:u${extent.start}-${extent.end}:${digest}`;
}

function operationId(
  toolCallId: string,
  callDigest: string,
  kind: string,
  extent: SourceExtent,
): string {
  const digest = jsonDigest({ toolCallId, callDigest, kind, start: extent.start, end: extent.end }).slice(0, 16);
  return `${toolCallId}:op:${extent.start}-${extent.end}:${digest}`;
}

function unknown<T>(reason: string): Knowledge<T> {
  return Object.freeze({ status: "unknown", reason });
}

function known<T>(value: T): Knowledge<T> {
  return Object.freeze({ status: "known", value });
}

const POWERSHELL_INTERNAL_COMMANDS = new Set([
  "add-content", "clear-content", "clear-item", "copy-item", "export-csv", "get-childitem",
  "get-command", "get-content", "get-date", "get-help", "get-item", "get-itemproperty",
  "get-location", "get-variable", "invoke-command", "invoke-expression", "invoke-restmethod",
  "invoke-webrequest", "measure-object", "move-item", "new-alias", "new-item", "out-file",
  "out-null", "out-string", "pop-location", "push-location", "remove-alias", "remove-item",
  "remove-itemproperty", "select-object", "set-alias", "set-content", "set-item", "set-location",
  "sort-object", "start-job", "start-process", "test-path", "where-object", "write-host",
  "write-output",
]);

function isPowerShellNativeCandidate(call: PowerShellParseSummary["programCalls"][number]): boolean {
  if (call.dynamic || call.dotSource || call.commandName === null) return true;
  return !POWERSHELL_INTERNAL_COMMANDS.has(call.commandName.toLowerCase());
}

function wholeCallUnit(toolCallId: string, commandText: string): PowerShellAnalysisUnit {
  return Object.freeze({ unitId: `${toolCallId}:whole`, start: 0, end: commandText.length, text: commandText });
}

function unitForExtent(units: readonly PowerShellAnalysisUnit[], extent: SourceExtent): string {
  return units.find((unit) => unit.start <= extent.start && unit.end >= extent.end)?.unitId ??
    units[0]?.unitId ?? "unknown-unit";
}

function operationForLanguageFact(
  call: PowerShellAnalysisCall,
  operation: PowerShellParseSummary["languageOperations"][number],
  unitId: string,
  cwd: string,
  normalizer: PathNormalizer,
): ShellOperationFact {
  const id = operationId(call.toolCallId, call.digest, operation.kind, operation);
  if (operation.kind === "process-spawn") {
    return Object.freeze({
      operationId: id,
      unitId,
      owner: "powershell",
      effects: known<readonly ShellEffect[]>(["process.spawn"]),
      fileTargets: known<readonly FileTargetFact[]>([]),
      networkTargets: unknown<readonly NetworkTargetFact[]>("child-network-effects-unresolved"),
      dynamicExecution: known(false),
      processSpawn: known(true),
      complete: false,
      source: "powershell-parser",
    });
  }
  if (operation.kind === "redirection" && operation.target !== null) {
    const target = normalizer.normalPath(operation.target, cwd).display;
    return Object.freeze({
      operationId: id,
      unitId,
      owner: "powershell",
      effects: known<readonly ShellEffect[]>(["file.create", "file.write"]),
      fileTargets: known<readonly FileTargetFact[]>([
        { path: target, effect: "file.create" as const },
        { path: target, effect: "file.write" as const },
      ]),
      networkTargets: known<readonly NetworkTargetFact[]>([]),
      dynamicExecution: known(false),
      processSpawn: known(false),
      complete: target.length > 0,
      source: "powershell-parser",
    });
  }
  const definiteEffects: Partial<Record<PowerShellLanguageOperationKind, readonly ShellEffect[]>> = {
    "file-read": ["file.read"],
    "file-write": ["file.create", "file.write"],
    "file-delete": ["file.delete"],
    "network-access": ["network"],
  };
  const observed = definiteEffects[operation.kind];
  if (observed !== undefined) {
    if (operation.kind === "network-access") {
      try {
        const target = operation.target === null ? undefined : new URL(operation.target);
        if (target !== undefined && (target.protocol === "http:" || target.protocol === "https:")) {
          return Object.freeze({
            operationId: id,
            unitId,
            owner: "powershell",
            effects: known<readonly ShellEffect[]>(observed),
            fileTargets: known<readonly FileTargetFact[]>([]),
            networkTargets: known<readonly NetworkTargetFact[]>([{
              host: target.hostname,
              ...(target.port.length === 0 ? {} : { port: Number(target.port) }),
            }]),
            dynamicExecution: known(false),
            processSpawn: known(false),
            complete: false,
            source: "powershell-parser",
          });
        }
      } catch {
        return Object.freeze({
          operationId: id,
          unitId,
          owner: "powershell",
          effects: known<readonly ShellEffect[]>(observed),
          fileTargets: known<readonly FileTargetFact[]>([]),
          networkTargets: unknown<readonly NetworkTargetFact[]>("network-target-unresolved"),
          dynamicExecution: known(false),
          processSpawn: known(false),
          complete: false,
          source: "powershell-parser",
        });
      }
    }
    const hasFileTarget = operation.target !== null && operation.target.length > 0 &&
      !/[?*]/u.test(operation.target) &&
      !/^(?:[A-Za-z][A-Za-z0-9+.-]*:|Registry::)/u.test(operation.target.replace(/^[A-Za-z]:[\\/]/u, ""));
    if (hasFileTarget) {
      const path = normalizer.normalPath(operation.target!, cwd).display;
      if (path.length > 0) {
        const effect = observed[0];
        const targets: FileTargetFact[] = operation.kind === "file-write"
          ? [
            { path, effect: "file.create" },
            { path, effect: "file.write" },
          ]
          : [{ path, effect: effect as FileTargetFact["effect"] }];
        return Object.freeze({
          operationId: id,
          unitId,
          owner: "powershell",
          effects: known<readonly ShellEffect[]>(observed),
          fileTargets: known<readonly FileTargetFact[]>(targets),
          networkTargets: known<readonly NetworkTargetFact[]>([]),
          dynamicExecution: known(false),
          processSpawn: known(false),
          complete: true,
          source: "powershell-parser",
        });
      }
    }
    return Object.freeze({
      operationId: id,
      unitId,
      owner: "powershell",
      effects: known<readonly ShellEffect[]>(observed),
      fileTargets: unknown<readonly FileTargetFact[]>(`target-unresolved:${operation.kind}`),
      networkTargets: unknown<readonly NetworkTargetFact[]>(`target-unresolved:${operation.kind}`),
      dynamicExecution: unknown<boolean>(`language-operation:${operation.kind}`),
      processSpawn: unknown<boolean>(`language-operation:${operation.kind}`),
      complete: false,
      source: "powershell-parser",
    });
  }
  return Object.freeze({
    operationId: id,
    unitId,
    owner: "powershell",
    effects: unknown<readonly ShellEffect[]>(`language-operation:${operation.kind}`),
    fileTargets: unknown<readonly FileTargetFact[]>(`language-operation:${operation.kind}`),
    networkTargets: unknown<readonly NetworkTargetFact[]>(`language-operation:${operation.kind}`),
    dynamicExecution: operation.kind === "dynamic-execution" ? known(true) : unknown<boolean>(`language-operation:${operation.kind}`),
    processSpawn: unknown<boolean>(`language-operation:${operation.kind}`),
    complete: false,
    source: "powershell-parser",
  });
}

export function analyzePowerShellParse(input: {
  readonly call: PowerShellAnalysisCall;
  readonly commandText: string;
  readonly cwd: string;
  readonly result: PowerShellParseResult;
  readonly platform?: NodeJS.Platform;
}): PowerShellCallAnalysis {
  if (!input.result.ok || input.result.summary.completeness !== "complete") {
    return Object.freeze({
      completeness: "failed",
      units: Object.freeze([wholeCallUnit(input.call.toolCallId, input.commandText)]),
      programInvocations: Object.freeze([]),
      operations: Object.freeze([]),
      diagnostics: Object.freeze([input.result.ok ? "parse-incomplete" : input.result.reason]),
    });
  }

  const summary = input.result.summary;
  const units = Object.freeze(summary.units.map((extent) => Object.freeze({
    ...extent,
    unitId: powerShellUnitId(input.call.toolCallId, input.call.digest, extent),
    text: input.commandText.slice(extent.start, extent.end),
  })));
  if (units.length === 0 || units.some((unit) => unit.text.length === 0)) {
    return Object.freeze({
      completeness: "failed",
      units: Object.freeze([wholeCallUnit(input.call.toolCallId, input.commandText)]),
      programInvocations: Object.freeze([]),
      operations: Object.freeze([]),
      diagnostics: Object.freeze(["empty-or-missing-ast-unit"]),
    });
  }

  const normalizer = new PathNormalizer(
    pathFlavorForPlatform(input.platform ?? process.platform),
    input.cwd,
  );
  const operations: ShellOperationFact[] = [];
  const contextChanges = new Set([
    "alias-change", "assignment", "control-flow", "dot-source", "dynamic-execution",
    "environment-change", "function-definition", "location-change", "process-spawn", "unknown",
  ]);
  let firstContextChange = Number.POSITIVE_INFINITY;
  let firstLocationChange = Number.POSITIVE_INFINITY;
  for (const operation of summary.languageOperations) {
    if (contextChanges.has(operation.kind)) firstContextChange = Math.min(firstContextChange, operation.start);
    if (operation.kind === "location-change") firstLocationChange = Math.min(firstLocationChange, operation.start);
  }
  const languageFactsByExtent = new Map<string, ShellOperationFact[]>();
  for (const operation of summary.languageOperations) {
    const unitId = unitForExtent(units, operation);
    const fact = operationForLanguageFact(
      input.call,
      operation,
      unitId,
      input.cwd,
      normalizer,
    );
    const contextStable = firstContextChange >= operation.start;
    const key = `${operation.start}:${operation.end}`;
    const extentFacts = languageFactsByExtent.get(key) ?? [];
    extentFacts.push(fact);
    languageFactsByExtent.set(key, extentFacts);
    if (contextStable) {
      operations.push(fact);
      continue;
    }
    const effects = fact.effects.status === "known" ? fact.effects.value : [];
    operations.push(Object.freeze({
      ...fact,
      ...(effects.some((effect) => effect.startsWith("file."))
        ? { fileTargets: unknown<readonly FileTargetFact[]>("script-context-changed") }
        : {}),
      ...(effects.includes("network")
        ? { networkTargets: unknown<readonly NetworkTargetFact[]>("script-context-changed") }
        : {}),
      complete: false,
    }));
  }
  const programInvocations: ProgramInvocation[] = [];
  for (const programCall of summary.programCalls) {
    const extent = { start: programCall.start, end: programCall.end };
    const unitId = unitForExtent(units, extent);
    const candidate = programCall.commandName !== null && !programCall.dynamic
      ? known(programCall.commandName)
      : unknown<string>("dynamic-command-name");
    const contextStable = firstContextChange >= programCall.start;
    const locationChanged = firstLocationChange < programCall.start;
    const argv = programCall.arguments === null
      ? unknown<readonly string[]>("dynamic-or-unsupported-arguments")
      : known<readonly string[]>(Object.freeze([...programCall.arguments]));
    if (isPowerShellNativeCandidate(programCall)) {
      const id = operationId(input.call.toolCallId, input.call.digest, "program", extent);
      const adapted = analyzeExternalProgram({
        operationId: id,
        unitId,
        shell: "powershell",
        program: candidate.status === "known" ? candidate.value : undefined,
        argv: argv.status === "known" ? argv.value : undefined,
        cwd: locationChanged ? undefined : input.cwd,
        extent,
        environmentStable: contextStable,
        platform: input.platform,
      });
      operations.push(adapted.operation);
      programInvocations.push(Object.freeze({
        operationId: id,
        unitId,
        shell: "powershell",
        program: candidate,
        executable: adapted.executable,
        argv,
        cwd: locationChanged ? unknown<string>("working-directory-changed-in-script") : known<string>(input.cwd),
        extent: Object.freeze(extent),
      }));
      continue;
    }
    for (const operation of languageFactsByExtent.get(`${extent.start}:${extent.end}`) ?? []) {
      programInvocations.push(Object.freeze({
        operationId: operation.operationId,
        unitId,
        shell: "powershell",
        program: candidate,
        executable: unknown<ExecutableIdentity>("powershell-cmdlet"),
        argv,
        cwd: locationChanged ? unknown<string>("working-directory-changed-in-script") : known<string>(input.cwd),
        extent: Object.freeze(extent),
      }));
    }
  }
  const uncertain = operations.some((operation) => !operation.complete) || programInvocations.length > 0;
  return Object.freeze({
    completeness: uncertain ? "uncertain" : "complete",
    engineIdentity: summary.engineIdentity,
    units,
    programInvocations: Object.freeze(programInvocations),
    operations: Object.freeze(operations),
    diagnostics: Object.freeze([]),
  });
}
