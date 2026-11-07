import type { CommandWord } from "./wrapper-analysis";

function isReadOnlyScript(script: string): boolean {
  if (script.includes("\n")) {
    const lines = script.split("\n");
    if (lines.slice(0, -1).some((line) => line.endsWith("\\"))) return false;
    return lines.every((line) => /^\s*(?:#.*)?$/.test(line) || isReadOnlyScript(line));
  }
  if (/^\s*#/.test(script)) return true;
  if (/^\s*(?::\s*[A-Za-z_][A-Za-z0-9_]*|[btT](?:\s+[A-Za-z_][A-Za-z0-9_]*)?)\s*$/.test(script)) return true;
  const numericRegexRange = /^\s*(?:\d+|\$)\s*,\s*(\/)/.exec(script);
  if (numericRegexRange) return isReadOnlyScript(script.slice(numericRegexRange[0].length - 1));
  const addressedBlock = /^\s*(?:\d+|\$)(?:\s*,\s*(?:\d+|\$))?\s*!?\s*(\{[\s\S]*\})\s*$/.exec(script);
  if (addressedBlock) return isReadOnlyScript(addressedBlock[1]!);
  const addressedReplacement = /^\s*(?:\d+|\$)(?:\s*,\s*(?:\d+|\$))?\s*!?\s*(?=[sy])/.exec(script);
  if (addressedReplacement) return isReadOnlyScript(script.slice(addressedReplacement[0].length));
  if (script.startsWith("{") && script.endsWith("}")) {
    return isReadOnlyScript(script.slice(1, -1));
  }
  if (script.startsWith("/")) {
    let bracket = false;
    for (let index = 1; index < script.length; index++) {
      const char = script[index]!;
      if (char === "\\") { if (++index >= script.length) return false; continue; }
      if (char === "[" && bracket && script[index + 1] !== undefined && ":.=".includes(script[index + 1]!)) {
        const marker = script[++index]!;
        const end = script.indexOf(`${marker}]`, index + 1);
        if (end < 0) return false;
        index = end + 1;
      } else if (char === "[") bracket = true;
      else if (char === "]") bracket = false;
      else if (char === "/" && !bracket) {
        const rest = script.slice(index + 1).trimStart();
        if (rest.startsWith(",")) {
          const second = rest.slice(1).trimStart();
          if (!second.startsWith("/") && !/^(?:\d+|\$)/.test(second)) return false;
          return isReadOnlyScript(second);
        }
        return isReadOnlyScript(rest.startsWith("!") ? rest.slice(1).trimStart() : rest);
      }
    }
    return false;
  }
  if (/^\s*(?:(?:\d+|\$)(?:\s*,\s*(?:\d+|\$))?\s*)?!?\s*[pPdDnNhHgGx=qQlz]\s*(?:;\s*(?:(?:\d+|\$)(?:\s*,\s*(?:\d+|\$))?\s*)?!?\s*[pPdDnNhHgGx=qQlz]\s*)*;?\s*$/.test(script)) return true;
  const firstCommand = /^\s*(?:(?:\d+|\$)(?:\s*,\s*(?:\d+|\$))?\s*)?!?\s*[pPdDnNhHgGx=qQlz]\s*;\s*/.exec(script);
  if (firstCommand) return isReadOnlyScript(script.slice(firstCommand[0].length));
  if (script.length < 4 || (script[0] !== "s" && script[0] !== "y")) return false;
  const delimiter = script[1]!;
  if (delimiter === "\\" || delimiter === "\n") return false;
  let index = 2;
  for (let part = 0; part < 2; part++) {
    let closed = false;
    let bracket = false;
    while (index < script.length) {
      const char = script[index++]!;
      if (char === "\\") { if (index >= script.length) return false; index++; continue; }
      if (script[0] === "s" && part === 0 && char === "[" && bracket && ":.=".includes(script[index] ?? "")) {
        const marker = script[index++]!;
        const end = script.indexOf(`${marker}]`, index);
        if (end < 0) return false;
        index = end + 2;
      } else if (script[0] === "s" && part === 0 && char === "[") bracket = true;
      else if (script[0] === "s" && part === 0 && char === "]") bracket = false;
      else if (char === delimiter && !bracket) { closed = true; break; }
    }
    if (!closed || bracket) return false;
  }
  const separator = script.indexOf(";", index);
  const flags = script.slice(index, separator < 0 ? undefined : separator).trim();
  if (script[0] === "y" ? flags !== "" : !/^[gpIiMm0-9]*$/.test(flags)) return false;
  return separator < 0 || script.slice(separator + 1).trim() === "" || isReadOnlyScript(script.slice(separator + 1).trimStart());
}

export function isReadOnlySed(args: readonly CommandWord[]): boolean {
  if (args.some((arg) => arg.computed)) return false;
  let index = 0;
  let expression = false;
  let optionsEnded = false;
  while (index < args.length) {
    const value = args[index]!.value;
    if (value === "--") { index++; optionsEnded = true; break; }
    if (["-n", "-E", "-r", "--quiet", "--silent", "--regexp-extended", "--posix"].includes(value)) { index++; continue; }
    if (value === "-e" || value === "--expression") {
      if (!args[index + 1] || !isReadOnlyScript(args[index + 1]!.value)) return false;
      expression = true;
      index += 2;
      continue;
    }
    if (value.startsWith("--expression=")) {
      if (!isReadOnlyScript(value.slice("--expression=".length))) return false;
      expression = true;
      index++;
      continue;
    }
    if (value.startsWith("-e") && value.length > 2) {
      if (!isReadOnlyScript(value.slice(2))) return false;
      expression = true;
      index++;
      continue;
    }
    break;
  }
  if (!expression && !isReadOnlyScript(args[index++]?.value ?? "")) return false;
  return optionsEnded || !args.slice(index).some((arg) => arg.value.startsWith("-"));
}
