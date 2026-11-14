/**
 * Merging endpoint credentials (base URL / API key) into the agent-level
 * `models.json`. Pi applies `providers.<id>.baseUrl` and `apiKey` on top of
 * the built-in providers, so overriding those two fields is enough to point
 * built-in models at a custom endpoint. For chat providers, `models` entries
 * additionally create chat models (including brand-new providers), while
 * classifier models can only come from built-in providers (override keeps
 * their classifier catalog).
 */

import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

export interface EndpointPatch {
  /** Overrides the provider's endpoint; ignored when blank. */
  readonly baseUrl?: string;
  /** Literal key written to models.json; ignored when blank. */
  readonly apiKey?: string;
}

export type MergeModelsJsonResult =
  | { readonly ok: true; readonly doc: Record<string, unknown> }
  | { readonly ok: false; readonly message: string };

/**
 * Merge one provider's endpoint fields into a parsed models.json document.
 * Existing providers and unrelated keys are preserved; blank patch fields
 * leave the corresponding entry untouched.
 */
export function mergeModelsJsonEndpoint(
  doc: unknown,
  providerId: string,
  patch: EndpointPatch,
): MergeModelsJsonResult {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return { ok: false, message: "models.json is not a JSON object" };
  }
  const root = { ...(doc as Record<string, unknown>) };
  const providers =
    root.providers === undefined
      ? {}
      : root.providers;
  if (providers === null || typeof providers !== "object" || Array.isArray(providers)) {
    return { ok: false, message: 'models.json "providers" is not a JSON object' };
  }
  const providersRecord = { ...(providers as Record<string, unknown>) };
  const existing = providersRecord[providerId];
  if (existing !== undefined && (existing === null || typeof existing !== "object" || Array.isArray(existing))) {
    return { ok: false, message: `models.json provider "${providerId}" is not a JSON object` };
  }
  const entry: Record<string, unknown> = {
    ...((existing ?? {}) as Record<string, unknown>),
  };
  const baseUrl = patch.baseUrl?.trim();
  const apiKey = patch.apiKey?.trim();
  if (baseUrl) entry.baseUrl = baseUrl;
  if (apiKey) entry.apiKey = apiKey;
  // A patch that adds nothing to an unknown provider must not materialize
  // an empty marker entry; such entries would read as "user-added" providers.
  // Leave the document completely untouched in that case.
  if (existing !== undefined || Object.keys(entry).length > 0) {
    providersRecord[providerId] = entry;
    root.providers = providersRecord;
  }
  return { ok: true, doc: root };
}

/**
 * Provider ids with actual configuration in a parsed models.json document
 * (non-empty object entries), in declaration order: these are the
 * user-added providers. Empty entries are not counted.
 */
export function modelsJsonProviderIds(doc: unknown): readonly string[] {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return [];
  const providers = (doc as Record<string, unknown>).providers;
  if (providers === null || typeof providers !== "object" || Array.isArray(providers)) return [];
  return Object.entries(providers as Record<string, unknown>)
    .filter(([, entry]) => entry !== null && typeof entry === "object" && !Array.isArray(entry) && Object.keys(entry).length > 0)
    .map(([id]) => id);
}

/**
 * Provider ids already added to the agent-level models.json; empty when the
 * file is missing or unparsable (best effort for picker filtering).
 */
export function listModelsJsonProviders(filePath: string): readonly string[] {
  try {
    return modelsJsonProviderIds(JSON.parse(readFileSync(filePath, "utf8")) as unknown);
  } catch {
    return [];
  }
}

export type ApplyEndpointResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string };

export interface ChatEndpointPatch {
  readonly providerId: string;
  /** Overrides the provider's endpoint; required for a brand-new provider. */
  readonly baseUrl?: string;
  /** Literal key written to models.json; ignored when blank. */
  readonly apiKey?: string;
  /**
   * Model to expose for a brand-new provider (required then), or to append
   * to an existing provider's `models` array. Omit to only override an
   * existing provider's endpoint.
   */
  readonly modelId?: string;
  /** Wire API for a brand-new provider; defaults to "openai-completions". */
  readonly api?: string;
}

/**
 * Merge a chat endpoint into a parsed models.json document. An existing
 * provider is only overridden (its models are kept, plus the requested model
 * appended when given); a brand-new provider is created with one model and
 * needs both a base URL and a model id because pi requires `api` + `baseUrl`
 * to build chat models from scratch.
 */
export function mergeChatEndpoint(
  doc: unknown,
  patch: ChatEndpointPatch,
): MergeModelsJsonResult {
  const merged = mergeModelsJsonEndpoint(doc, patch.providerId, {
    baseUrl: patch.baseUrl,
    apiKey: patch.apiKey,
  });
  if (!merged.ok) return merged;
  // A blank patch against an unknown provider creates nothing, so the merged
  // entry may be absent here; the branch below rejects that case before any
  // mutation. When this provider carries classifier models, the merge always
  // wrote the entry (a non-blank base URL / API key was merged in).
  const entry = (
    (merged.doc.providers as Record<string, unknown> | undefined)?.[patch.providerId]
  ) as Record<string, unknown>;
  // mergeModelsJsonEndpoint validated the document, so reading the original
  // provider entry here is safe: it tells whether the entry is brand-new.
  const hadEntry =
    (doc as { providers?: Record<string, unknown> | undefined }).providers?.[patch.providerId] !== undefined;
  const modelId = patch.modelId?.trim();
  if (!hadEntry) {
    // Brand-new provider: the merge above may have created an entry with
    // the endpoint fields only, so require the fields pi needs to build
    // chat models.
    const baseUrl = patch.baseUrl?.trim();
    if (!baseUrl || !modelId) {
      return {
        ok: false,
        message: `a new provider "${patch.providerId}" needs a base URL and a model id`,
      };
    }
    entry.api = patch.api?.trim() || "openai-completions";
    entry.models = [{ id: modelId, name: modelId }];
    return merged;
  }
  if (modelId !== undefined && modelId !== "") {
    const models = entry.models;
    if (models !== undefined && !Array.isArray(models)) {
      return { ok: false, message: `models.json provider "${patch.providerId}" "models" is not an array` };
    }
    const list = [...(models as unknown[] | undefined ?? [])];
    const alreadyPresent = list.some(
      (item) => item !== null && typeof item === "object" && (item as Record<string, unknown>).id === modelId,
    );
    if (!alreadyPresent) list.push({ id: modelId, name: modelId });
    entry.models = list;
  }
  return merged;
}

/**
 * Read the agent-level models.json, merge the chat endpoint, and write it
 * back atomically. A missing file is treated as an empty document; a
 * corrupt file is reported without being overwritten.
 */
export function applyChatEndpoint(
  filePath: string,
  patch: ChatEndpointPatch,
): ApplyEndpointResult {
  return applyModelsJson(filePath, (doc) => mergeChatEndpoint(doc, patch));
}

function applyModelsJson(
  filePath: string,
  merge: (doc: unknown) => MergeModelsJsonResult,
): ApplyEndpointResult {
  let doc: unknown = {};
  try {
    doc = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, message: `could not read models.json: ${(error as Error).message}` };
    }
  }
  const merged = merge(doc);
  if (!merged.ok) return merged;
  try {
    atomicWrite(filePath, merged.doc);
  } catch (error) {
    return { ok: false, message: `could not write models.json: ${(error as Error).message}` };
  }
  return { ok: true };
}

function atomicWrite(filePath: string, value: unknown): void {
  const directory = dirname(filePath);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = join(directory, `.${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}.tmp`);
  let handle: number | undefined;
  try {
    handle = openSync(temporaryPath, "wx", 0o600);
    writeSync(handle, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(handle);
    closeSync(handle);
    handle = undefined;
    renameSync(temporaryPath, filePath);
  } catch (error) {
    if (handle !== undefined) {
      try {
        closeSync(handle);
      } catch {
        // Best effort: the write already failed.
      }
    }
    try {
      unlinkSync(temporaryPath);
    } catch {
      // Best effort: the temporary file may never have been created.
    }
    throw error;
  }
}
