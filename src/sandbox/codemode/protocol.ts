import type { WorkerToHostMessage } from "@earendil-works/pi-codemode/portable";
import {
  CODEMODE_MAX_FRAME_BYTES,
  CODEMODE_MAX_LOGICAL_MESSAGE_BYTES,
  CODEMODE_PROTOCOL_VERSION,
  FrameDecoder,
  createFrameSequence,
  decodeFrame,
  encodeFrame,
  type RuntimeFrameSequence,
} from "./physical-codec.js";

export {
  CODEMODE_MAX_FRAME_BYTES,
  CODEMODE_MAX_LOGICAL_MESSAGE_BYTES,
  CODEMODE_PROTOCOL_VERSION,
  CODEMODE_FRAGMENT_BYTES,
  CODEMODE_MAX_QUEUED_BYTES,
} from "./physical-codec.js";

export interface RuntimeEnvelope {
  readonly version: typeof CODEMODE_PROTOCOL_VERSION;
  readonly generation: string;
  readonly type: "ready" | "message" | "failure" | "stopped";
  readonly message?: WorkerToHostMessage;
  readonly error?: { readonly name?: string; readonly message: string; readonly stack?: string };
}

export type { RuntimeFrameSequence };

function isRuntimeEnvelope(value: { readonly type: string }): value is RuntimeEnvelope {
  return ["ready", "message", "failure", "stopped"].includes(value.type);
}

export function encodeRuntimeFrame(value: unknown): Buffer {
  return encodeFrame(value);
}

export function createRuntimeFrameSequence(
  value: unknown,
  generation: string,
  id: number,
): RuntimeFrameSequence {
  return createFrameSequence(value, generation, id);
}

export function decodeRuntimeFrame(frame: Buffer, generation: string): RuntimeEnvelope {
  const envelope = decodeFrame(frame, generation);
  if (envelope.type === "fragment") throw new Error("Codemode Runtime IPC frame is incomplete");
  if (!isRuntimeEnvelope(envelope)) {
    throw new Error("Codemode Runtime IPC generation or version is invalid");
  }
  return envelope;
}

export class RuntimeFrameDecoder {
  private readonly decoder: FrameDecoder;

  constructor(generation: string) {
    this.decoder = new FrameDecoder({ generation });
  }

  push(chunk: Buffer): readonly RuntimeEnvelope[] {
    const envelopes = this.decoder.push(chunk);
    for (const envelope of envelopes) {
      if (!isRuntimeEnvelope(envelope)) {
        throw new Error("Codemode Runtime IPC generation or version is invalid");
      }
    }
    return envelopes as readonly RuntimeEnvelope[];
  }

  finish(): void {
    this.decoder.finish();
  }
}
