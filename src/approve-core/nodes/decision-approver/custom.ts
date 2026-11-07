import type { ClassifierContext, ClassifierResult } from "@earendil-works/pi-ai";
import type { DecisionClassifierProfile } from "./model";

/**
 * Issue a classifier request directly to a user-owned backend. The request
 * body mirrors the Pi classifier shape (`state` + `questions`); the response
 * is expected to carry `answers` in the same shape Pi's classifier returns.
 */
export async function classifyCustomJudge(
  profile: Extract<DecisionClassifierProfile, { readonly kind: "custom" }>,
  context: ClassifierContext,
  options: {
    readonly signal?: AbortSignal;
    readonly timeoutMs?: number;
    readonly fetch?: typeof fetch;
  } = {},
): Promise<ClassifierResult> {
  const output: ClassifierResult = {
    api: "custom",
    provider: "custom",
    model: profile.modelId,
    answers: {},
    stopReason: "stop",
    timestamp: Date.now(),
  };
  const fetchImpl = options.fetch ?? globalThis.fetch;
  try {
    const timeoutSignal =
      options.timeoutMs !== undefined ? AbortSignal.timeout(options.timeoutMs) : undefined;
    const signal =
      options.signal && timeoutSignal
        ? AbortSignal.any([options.signal, timeoutSignal])
        : (options.signal ?? timeoutSignal);
    const response = await fetchImpl(profile.baseUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(profile.apiKey === undefined ? {} : { authorization: `Bearer ${profile.apiKey}` }),
      },
      body: JSON.stringify({ state: context.state, questions: context.questions }),
      signal,
    });
    if (!response.ok) {
      throw new Error(`custom judge returned ${response.status}`);
    }
    const body = (await response.json()) as { answers?: unknown; verdict?: unknown };
    const answers = body?.answers ?? (body?.verdict !== undefined ? { verdict: body.verdict } : {});
    output.answers = answers as ClassifierResult["answers"];
    return output;
  } catch (error) {
    output.stopReason = options.signal?.aborted ? "aborted" : "error";
    output.errorMessage = error instanceof Error ? error.message : String(error);
    return output;
  }
}