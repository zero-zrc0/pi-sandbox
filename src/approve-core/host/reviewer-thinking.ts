import { getSupportedThinkingLevels, type Api, type Model, type ThinkingLevel } from "@earendil-works/pi-ai";

export function reviewerThinking(model: Model<Api>): ThinkingLevel | undefined {
  const levels = getSupportedThinkingLevels(model);
  if (levels.includes("off")) return undefined;
  if (levels.includes("low")) return "low";
  return levels.find((level): level is ThinkingLevel => level !== "off");
}
