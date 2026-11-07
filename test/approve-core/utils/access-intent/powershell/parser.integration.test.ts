import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PowerShellParser,
  resolveTrustedPowerShellEngine,
} from "#approve-core/utils/access-intent/powershell/parser";

const engine = resolveTrustedPowerShellEngine();
const temporaryDirectories: string[] = [];

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe.skipIf(engine === undefined)("official PowerShell parser contract", () => {
  it("splits PowerShell statements by AST extents and preserves quoted separators", async () => {
    const parser = new PowerShellParser({ engine: engine! });
    const source = "$value = '😀;first;second'; Get-Content -LiteralPath input.txt | Set-Content -LiteralPath output.txt";

    const result = await parser.parse({ source });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.summary.completeness).toBe("complete");
      expect(result.summary.units.map(({ start, end }) => source.slice(start, end))).toEqual([
        "$value = '😀;first;second'",
        "Get-Content -LiteralPath input.txt | Set-Content -LiteralPath output.txt",
      ]);
      expect(result.summary.programCalls.map((call) => call.commandName)).toEqual([
        "Get-Content",
        "Set-Content",
      ]);
      expect(result.summary.languageOperations.map((operation) => operation.kind)).toEqual([
        "file-read",
        "file-write",
        "assignment",
      ]);
      expect(result.summary.languageOperations.map((operation) => operation.target)).toEqual([
        "input.txt",
        "output.txt",
        null,
      ]);
    }
    parser.dispose();
  });

  it("marks cwd changes as language operations for later source ranges", async () => {
    const parser = new PowerShellParser({ engine: engine! });
    const source = "Set-Location subdir; git status";

    const result = await parser.parse({ source });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.summary.languageOperations.map((operation) => operation.kind)).toContain("location-change");
      expect(result.summary.programCalls.map((call) => call.commandName)).toContain("git");
    }
    parser.dispose();
  });

  it("parses hostile text without executing it", async () => {
    const directory = mkdtempSync(join(tmpdir(), "pi-powershell-parser-"));
    temporaryDirectories.push(directory);
    const marker = join(directory, "must-not-exist.txt");
    const parser = new PowerShellParser({ engine: engine! });

    const result = await parser.parse({
      source: `Set-Content -LiteralPath '${marker}' -Value 'executed'`,
    });

    expect(result.ok).toBe(true);
    expect(existsSync(marker)).toBe(false);
    parser.dispose();
  });
});
