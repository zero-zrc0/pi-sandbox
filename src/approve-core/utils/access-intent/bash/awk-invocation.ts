import type { CommandWord } from "./wrapper-analysis";

export function isReadOnlyAwk(args: readonly CommandWord[]): boolean {
  if (args.some((arg) => arg.computed)) return false;
  let index = 0;
  while (index < args.length) {
    const value = args[index]!.value;
    if (value === "--") { index++; break; }
    if (value === "-F" || value === "-v") {
      if (index + 1 >= args.length) return false;
      index += 2;
    } else if (/^-(F|v).+/.test(value)) {
      index++;
    } else if (value.startsWith("-")) {
      return false;
    } else {
      break;
    }
  }
  const program = args[index]?.value;
  if (args.slice(index + 1).some((arg) => arg.value.startsWith("-"))) return false;
  return program !== undefined && !/[>|@]|system/.test(program);
}
