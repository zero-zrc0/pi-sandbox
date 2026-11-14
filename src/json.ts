import { cloneFrozenJson } from "#approve-core/utils/tool-access/tool-definition";
import { canonicalJson, sha256Hex } from "#approve-core/policy/project-rules/types";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type JsonObject = { readonly [key: string]: JsonValue };

export function freezeJson(value: unknown): JsonValue {
  const result = cloneFrozenJson(value);
  if (!result.ok) throw new TypeError("value is not JSON data");
  return result.value as JsonValue;
}

export function jsonDigest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

export function jsonBytes(value: JsonValue): number {
  return new TextEncoder().encode(canonicalJson(value)).byteLength;
}
