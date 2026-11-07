export type TruthValue = "true" | "false" | "unknown";

export function notTruth(value: TruthValue): TruthValue {
  if (value === "unknown") return value;
  return value === "true" ? "false" : "true";
}

export function allTruth(values: readonly TruthValue[]): TruthValue {
  if (values.includes("false")) return "false";
  return values.every((value) => value === "true") ? "true" : "unknown";
}

export function anyTruth(values: readonly TruthValue[]): TruthValue {
  if (values.includes("true")) return "true";
  return values.every((value) => value === "false") ? "false" : "unknown";
}
