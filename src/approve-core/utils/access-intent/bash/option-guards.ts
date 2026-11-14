import type { CommandWord } from "./wrapper-analysis";

export function hasGuardedOption(words: readonly CommandWord[], stems: readonly string[]): boolean {
  return words.some((word) => stems.some((stem) => {
    if (word.computed && word.mayLeadWithDash) return true;
    const option = word.value.split("=", 1)[0]!;
    if (/^-[^-]$/.test(stem)) {
      return option.startsWith("-") && !option.startsWith("--") && option.slice(1).includes(stem[1]!);
    }
    if (stem.startsWith("--")) return option.length > 2 && option.startsWith("--") && stem.startsWith(option);
    return option.startsWith(stem);
  }));
}
