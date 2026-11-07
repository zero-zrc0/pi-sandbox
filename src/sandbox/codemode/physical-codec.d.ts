export const CODEMODE_PROTOCOL_VERSION: 1;
export const CODEMODE_MAX_FRAME_BYTES: number;
export const CODEMODE_MAX_LOGICAL_MESSAGE_BYTES: number;
export const CODEMODE_FRAGMENT_BYTES: number;
export const CODEMODE_MAX_QUEUED_BYTES: number;

export interface RuntimeFrameSequence {
  readonly byteLength: number;
  readonly frames: Iterable<Buffer>;
}

export interface FrameDecoderOptions {
  readonly generation?: string;
  readonly allowInitialGeneration?: boolean;
  readonly maxFrameBytes?: number;
}

export interface PhysicalEnvelope {
  readonly version: number;
  readonly generation: string;
  readonly type: string;
  readonly [key: string]: unknown;
}

export interface FrameDecoderStats {
  readonly scannedBytes: number;
  readonly copiedBytes: number;
  readonly mergeCount: number;
}

export function encodeFrame(value: unknown, maxBytes?: number): Buffer;
export function createFrameSequence(value: unknown, generation: string, id: number): RuntimeFrameSequence;
export function decodeFrame(frame: Buffer, generation?: string, maxBytes?: number): PhysicalEnvelope;

export class FrameDecoder {
  constructor(options?: FrameDecoderOptions);
  readonly generation: string | undefined;
  push(chunk: Buffer): readonly PhysicalEnvelope[];
  finish(): void;
  stats(): FrameDecoderStats;
}
