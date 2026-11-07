/**
 * Command-chain adjudication.
 *
 * Every enumerated unit is resolved independently. Parse and wrapper floors can
 * only strengthen an allow; an explicit deny or ask is never rewritten. A
 * wrapper whose floor exemption is proved is decided by the command it actually
 * executes, while prompts and session authorization still point at the unit the
 * user typed. Multiple asks keep every asking unit and its own floor.
 */
import type { BashCommand } from "./access-intent/bash/command-enumeration";
import { executionAnalysisOf } from "./access-intent/bash/command-enumeration";
import type { AskingBashUnit, PermissionCheckResult } from "#approve-core/contracts";
import { pickMostRestrictive } from "#approve-core/policy/restrictiveness";

export type BashFloorKind = "parse" | "salvage" | "wrapper" | "unparseable";

export interface BashFloor {
  readonly kind: BashFloorKind;
  readonly reason: string;
}

export interface BashUnitVerdict {
  readonly unit: BashCommand;
  readonly check: PermissionCheckResult;
  readonly floor?: BashFloor;
}

export interface BashCommandVerdict {
  readonly check: PermissionCheckResult;
  readonly units: readonly BashUnitVerdict[];
  /** The independent whole-string result, only when no main unit exists. */
  readonly wholeProgram?: PermissionCheckResult;
}

/** A synchronous per-unit rule lookup. */
export type BashUnitResolver = (
  command: string,
  unit?: BashCommand,
) => PermissionCheckResult;

export interface BashCommandCheckOptions {
  readonly command: string;
  readonly units: readonly BashCommand[];
  readonly resolve: BashUnitResolver;
}

const PARSE_FLOOR = "<bash-parse-unresolved>";
const SALVAGE_FLOOR = "<bash-salvaged-region>";
const UNPARSEABLE_FLOOR = "<unparseable-bash-command>";

function isInertCommand(command: string): boolean {
  return command.split(/\r?\n/).every((line) =>
    line.trim().length === 0 || line.trimStart().startsWith("#")
  );
}

interface Raised {
  readonly check: PermissionCheckResult;
  readonly floor: BashFloor;
}

function raise(
  check: PermissionCheckResult,
  marker: string,
  kind: BashFloorKind,
  reason: string,
): Raised {
  return {
    check: {
      ...check,
      state: "ask",
      matchedPattern: marker,
      floor: marker,
    },
    floor: { kind, reason },
  };
}

function sessionExactAllow(check: PermissionCheckResult, command: string): boolean {
  return check.state === "allow" && check.origin === "session" &&
    (check.matchedPattern === undefined || check.matchedPattern === command);
}

function displayFacts(
  check: PermissionCheckResult,
  unit: BashCommand,
  command: string,
): PermissionCheckResult {
  return {
    ...check,
    command,
    ...(unit.context === undefined ? {} : { commandContext: unit.context }),
    ...(unit.executedUnit === undefined || check.executedUnit !== undefined
      ? {}
      : { executedUnit: unit.executedUnit }),
  };
}

function evaluateUnit(
  unit: BashCommand,
  options: BashCommandCheckOptions,
): BashUnitVerdict {
  let check = options.resolve(unit.text, unit);
  const uncertain = unit.parseUnresolved === true || unit.salvaged === true;
  if (check.state === "allow" || (check.state === "ask" && check.origin === "builtin")) {
    const sessionCheck = uncertain && unit.text !== options.command ? options.resolve(options.command) : check;
    if (sessionExactAllow(sessionCheck, uncertain ? options.command : unit.text)) {
      return { unit, check: displayFacts(sessionCheck, unit, uncertain ? options.command : unit.text) };
    }
  }

  let floor: BashFloor | undefined;

  if (check.state === "allow" && unit.wrapperKind !== undefined) {
    const execution = executionAnalysisOf(unit);
    const exemption = execution?.floorExemption;
    if (exemption === "no-command") {
      // The wrapper's own rule decides; its bare form runs no other command.
    } else if (
      (exemption === "core-reader" || exemption === "execution-modifier") &&
      execution !== undefined &&
      execution.actions.length > 0
    ) {
      const innerChecks = execution.actions.map((action) =>
        options.resolve(action.text, unit)
      );
      const inner = pickMostRestrictive(innerChecks);
      if (inner !== undefined) {
        check = {
          ...inner,
          command: unit.text,
          ...(execution.executedUnit === undefined
            ? {}
            : { executedUnit: execution.executedUnit }),
          floorExemption: exemption,
        };
      }
    } else {
      const marker = `<wrapper:${unit.wrapperKind}>`;
      const reason = execution?.stopReason === undefined
        ? `wrapper:${unit.wrapperKind}`
        : `wrapper:${unit.wrapperKind}:${execution.stopReason}`;
      const raised = raise(check, marker, "wrapper", reason);
      check = raised.check;
      floor = raised.floor;
    }
  }

  if (check.state === "allow" && (unit.parseUnresolved === true || unit.salvaged === true)) {
    const salvaged = unit.salvaged === true;
    const marker = salvaged ? SALVAGE_FLOOR : PARSE_FLOOR;
    const raised = raise(
      check,
      marker,
      salvaged ? "salvage" : "parse",
      salvaged ? "salvage:region" : "parse:unresolved",
    );
    check = raised.check;
    floor = raised.floor;
  }

  return {
    unit,
    check: displayFacts(
      check,
      unit,
      floor?.kind === "parse" || floor?.kind === "salvage"
        ? options.command
        : unit.text,
    ),
    ...(floor === undefined ? {} : { floor }),
  };
}

function askingUnitsOf(verdicts: readonly BashUnitVerdict[]): AskingBashUnit[] {
  return verdicts
    .filter((verdict) => verdict.check.state === "ask")
    .map((verdict) => ({
      command: verdict.unit.text,
      ...(verdict.check.floor === undefined ? {} : { floor: verdict.check.floor }),
    }));
}

function finalize(
  verdicts: readonly BashUnitVerdict[],
): BashCommandVerdict {
  const winner = pickMostRestrictive(verdicts.map((verdict) => verdict.check));
  if (winner === undefined) {
    throw new Error("command adjudication requires at least one unit verdict");
  }
  if (winner.state !== "ask") return { check: winner, units: verdicts };
  const asking = askingUnitsOf(verdicts);
  return {
    check: asking.length === 0
      ? winner
      : { ...winner, askingUnits: asking },
    units: verdicts,
  };
}

export function checkBashCommand(
  options: BashCommandCheckOptions,
): BashCommandVerdict {
  if (isInertCommand(options.command)) {
    return { check: options.resolve(options.command), units: [] };
  }

  const main = options.units.filter((unit) => unit.salvaged !== true);
  const salvaged = options.units.filter((unit) => unit.salvaged === true);

  if (main.length === 0) {
    const whole = options.resolve(options.command);
    if (whole.state === "deny") {
      return { check: whole, units: [], wholeProgram: whole };
    }
    if (salvaged.length === 0) {
      if (sessionExactAllow(whole, options.command)) {
        return { check: whole, units: [], wholeProgram: whole };
      }
      if (whole.state === "ask") {
        return { check: whole, units: [], wholeProgram: whole };
      }
      const raised = raise(
        whole,
        UNPARSEABLE_FLOOR,
        "unparseable",
        "unparseable:no-units",
      );
      return { check: raised.check, units: [], wholeProgram: whole };
    }

    const verdicts: BashUnitVerdict[] = [];
    // A deny on the whole command already returned above, so the salvaged-only
    // path starts without a decided deny.
    let deniedSeen = false;
    for (const unitResult of salvaged) {
      let verdict: BashUnitVerdict;
      try {
        verdict = evaluateUnit(unitResult, options);
      } catch (error) {
        if (deniedSeen) {
          const winner = pickMostRestrictive([
            whole,
            ...verdicts.map((verdict) => verdict.check),
          ])!;
          return { check: winner, units: verdicts, wholeProgram: whole };
        }
        throw error;
      }
      verdicts.push(verdict);
      if (verdict.check.state === "deny") deniedSeen = true;
    }
    const winner = pickMostRestrictive([
      whole,
      ...verdicts.map((verdict) => verdict.check),
    ])!;
    const asking = askingUnitsOf(verdicts);
    const check = winner.state === "ask" && asking.length > 0
      ? { ...winner, askingUnits: asking }
      : winner;
    return { check, units: verdicts, wholeProgram: whole };
  }

  const verdicts: BashUnitVerdict[] = [];
  let deniedSeen = false;
  for (const unitResult of main) {
    let verdict: BashUnitVerdict;
    try {
      verdict = evaluateUnit(unitResult, options);
    } catch (error) {
      if (deniedSeen) return finalize(verdicts);
      throw error;
    }
    verdicts.push(verdict);
    if (verdict.check.state === "deny") deniedSeen = true;
  }
  for (const unitResult of salvaged) {
    let verdict: BashUnitVerdict;
    try {
      verdict = evaluateUnit(unitResult, options);
    } catch (error) {
      if (deniedSeen) return finalize(verdicts);
      throw error;
    }
    verdicts.push(verdict);
    if (verdict.check.state === "deny") deniedSeen = true;
  }
  return finalize(verdicts);
}
