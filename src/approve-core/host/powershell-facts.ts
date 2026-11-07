import { analyzePowerShellParse, type PowerShellProgramFactsView } from "#approve-core/utils/access-intent/powershell/analysis";
import type { PowerShellParseResult } from "#approve-core/utils/access-intent/powershell/parser";
import type {
  PowerShellProgramProvider,
  PowerShellProgramRequest,
} from "#approve-core/nodes/analysis";

function nullProtoRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

export async function collectStepPowerShellFacts(input: {
  readonly calls: readonly PowerShellProgramRequest[];
  readonly provider: PowerShellProgramProvider;
  readonly cwd: string;
}): Promise<Readonly<Record<string, PowerShellProgramFactsView>> | undefined> {
  const collected = await Promise.all(
    input.calls.map(async (call): Promise<readonly [string, PowerShellProgramFactsView] | undefined> => {
      try {
        const result: PowerShellParseResult | undefined = await input.provider(call);
        if (result === undefined || typeof call.arguments.command !== "string") return undefined;
        return [call.toolCallId, Object.freeze({
          callDigest: call.digest,
          commandText: call.arguments.command,
          cwd: input.cwd,
          result,
          analysis: analyzePowerShellParse({
            call,
            commandText: call.arguments.command,
            cwd: input.cwd,
            result,
          }),
        })] as const;
      } catch {
        return undefined;
      }
    }),
  );

  let views: Record<string, PowerShellProgramFactsView> | undefined;
  for (const entry of collected) {
    if (entry === undefined) continue;
    views ??= nullProtoRecord<PowerShellProgramFactsView>();
    views[entry[0]] = entry[1];
  }
  return views === undefined ? undefined : Object.freeze(views);
}
