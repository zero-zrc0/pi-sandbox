'use strict';

const CODEMODE_PROTOCOL_VERSION = 1;
const CODEMODE_MAX_FRAME_BYTES = 16 * 1024 * 1024;
const CODEMODE_MAX_LOGICAL_MESSAGE_BYTES = 128 * 1024 * 1024;
const CODEMODE_FRAGMENT_BYTES = 8 * 1024 * 1024;
const CODEMODE_MAX_QUEUED_BYTES = 2 * CODEMODE_MAX_LOGICAL_MESSAGE_BYTES;

const NEWLINE = 0x0a;

function encodeFrame(value, maxBytes = CODEMODE_MAX_FRAME_BYTES) {
  const frame = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  if (frame.byteLength > maxBytes) throw new Error("Codemode Runtime IPC frame exceeds 16 MiB");
  return frame;
}

function createFrameSequence(value, generation, id) {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.byteLength > CODEMODE_MAX_LOGICAL_MESSAGE_BYTES) {
    throw new Error("Codemode Runtime IPC message exceeds 128 MiB");
  }
  if (payload.byteLength + 1 <= CODEMODE_MAX_FRAME_BYTES) {
    return { byteLength: payload.byteLength, frames: [Buffer.concat([payload, Buffer.from("\n")])] };
  }

  function* fragments() {
    for (let offset = 0, index = 0; offset < payload.byteLength; offset += CODEMODE_FRAGMENT_BYTES, index += 1) {
      const end = Math.min(offset + CODEMODE_FRAGMENT_BYTES, payload.byteLength);
      yield encodeFrame({
        version: CODEMODE_PROTOCOL_VERSION,
        generation,
        type: "fragment",
        id,
        index,
        final: end === payload.byteLength,
        data: payload.subarray(offset, end).toString("base64"),
      });
    }
  }

  return { byteLength: payload.byteLength, frames: fragments() };
}

function decodeFrame(frame, generation, maxBytes = CODEMODE_MAX_FRAME_BYTES) {
  if (frame.byteLength === 0 || frame.byteLength > maxBytes) {
    throw new Error("Codemode Runtime IPC frame is invalid");
  }
  let value;
  try {
    value = JSON.parse(frame.toString("utf8"));
  } catch {
    throw new Error("Codemode Runtime IPC frame is not valid JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Codemode Runtime IPC envelope is invalid");
  }
  if (value.version !== CODEMODE_PROTOCOL_VERSION || typeof value.generation !== "string" ||
      (generation !== undefined && value.generation !== generation) || typeof value.type !== "string") {
    throw new Error("Codemode Runtime IPC generation or version is invalid");
  }
  if (value.type !== "fragment") return value;

  const keys = Object.keys(value).sort().join(",");
  if (keys !== "data,final,generation,id,index,type,version" ||
      !Number.isSafeInteger(value.id) || value.id < 0 ||
      !Number.isSafeInteger(value.index) || value.index < 0 ||
      typeof value.final !== "boolean" || typeof value.data !== "string" ||
      value.data.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value.data)) {
    throw new Error("Codemode Runtime IPC fragment is invalid");
  }
  const bytes = Buffer.from(value.data, "base64");
  if (bytes.byteLength === 0 || bytes.byteLength > CODEMODE_FRAGMENT_BYTES || bytes.toString("base64") !== value.data) {
    throw new Error("Codemode Runtime IPC fragment is invalid");
  }
  return { ...value, bytes };
}

class FrameLineReader {
  #maxFrameBytes;
  #parts = [];
  #pendingBytes = 0;
  #scannedBytes = 0;
  #copiedBytes = 0;
  #mergeCount = 0;

  constructor(maxFrameBytes) {
    this.#maxFrameBytes = maxFrameBytes;
  }

  push(chunk) {
    const frames = [];
    let cursor = 0;
    while (cursor < chunk.byteLength) {
      const newline = chunk.indexOf(NEWLINE, cursor);
      const end = newline < 0 ? chunk.byteLength : newline;
      const part = chunk.subarray(cursor, end);
      this.#pendingBytes += part.byteLength;
      if (part.byteLength > 0) this.#parts.push(part);
      const consumed = newline < 0 ? chunk.byteLength - cursor : newline + 1 - cursor;
      this.#scannedBytes += consumed;
      if (this.#pendingBytes + 1 > this.#maxFrameBytes) {
        throw new Error("Codemode Runtime IPC frame exceeds 16 MiB");
      }
      if (newline < 0) return frames;

      const frame = this.#parts.length === 0
        ? Buffer.alloc(0)
        : this.#parts.length === 1
          ? this.#parts[0]
          : Buffer.concat(this.#parts, this.#pendingBytes);
      if (this.#parts.length > 1) {
        this.#mergeCount += 1;
        this.#copiedBytes += this.#pendingBytes;
      }
      this.#parts = [];
      this.#pendingBytes = 0;
      frames.push(frame);
      cursor = newline + 1;
    }
    return frames;
  }

  finish() {
    if (this.#pendingBytes !== 0) throw new Error("Codemode Runtime IPC frame is incomplete");
  }

  stats() {
    return Object.freeze({
      scannedBytes: this.#scannedBytes,
      copiedBytes: this.#copiedBytes,
      mergeCount: this.#mergeCount,
    });
  }
}

class FrameDecoder {
  #lines;
  #generation;
  #allowInitialGeneration;
  #fragments;

  constructor(options = {}) {
    this.#lines = new FrameLineReader(options.maxFrameBytes ?? CODEMODE_MAX_FRAME_BYTES);
    this.#generation = options.generation;
    this.#allowInitialGeneration = options.allowInitialGeneration === true;
  }

  push(chunk) {
    const messages = [];
    for (const frame of this.#lines.push(chunk)) {
      const value = decodeFrame(frame, this.#generation);
      if (value.type !== "fragment") {
        if (this.#fragments !== undefined) {
          throw new Error("Codemode Runtime IPC message interrupted by another frame");
        }
        this.#bindGeneration(value);
        messages.push(value);
        continue;
      }

      let pending = this.#fragments;
      if (pending === undefined) {
        if (value.index !== 0) throw new Error("Codemode Runtime IPC fragment sequence is invalid");
        pending = {
          id: value.id,
          generation: value.generation,
          chunks: [],
          byteLength: 0,
          nextIndex: 0,
        };
        this.#fragments = pending;
      }
      if (value.id !== pending.id || value.generation !== pending.generation || value.index !== pending.nextIndex ||
          (!value.final && value.bytes.byteLength !== CODEMODE_FRAGMENT_BYTES) ||
          pending.byteLength + value.bytes.byteLength > CODEMODE_MAX_LOGICAL_MESSAGE_BYTES) {
        throw new Error("Codemode Runtime IPC fragment sequence is invalid");
      }
      pending.chunks.push(value.bytes);
      pending.byteLength += value.bytes.byteLength;
      pending.nextIndex += 1;
      if (!value.final) continue;

      const payload = pending.chunks.length === 1
        ? pending.chunks[0]
        : Buffer.concat(pending.chunks, pending.byteLength);
      this.#fragments = undefined;
      const logical = decodeFrame(payload, pending.generation, CODEMODE_MAX_LOGICAL_MESSAGE_BYTES);
      if (logical.type === "fragment") throw new Error("Codemode Runtime IPC fragments cannot be nested");
      this.#bindGeneration(logical);
      messages.push(logical);
    }
    return messages;
  }

  finish() {
    this.#lines.finish();
    if (this.#fragments !== undefined) throw new Error("Codemode Runtime IPC fragments are incomplete");
  }

  get generation() {
    return this.#generation;
  }

  stats() {
    return this.#lines.stats();
  }

  #bindGeneration(value) {
    if (this.#generation !== undefined) {
      if (value.generation !== this.#generation) {
        throw new Error("Codemode Runtime IPC generation or version is invalid");
      }
      return;
    }
    if (!this.#allowInitialGeneration || value.type !== "start") {
      throw new Error("Codemode Runtime IPC generation or version is invalid");
    }
    this.#generation = value.generation;
  }
}

const { Worker } = require("node:worker_threads");
const { readFileSync } = require("node:fs");

const MAX_QUEUED_BYTES = CODEMODE_MAX_QUEUED_BYTES;
const decoder = new FrameDecoder({ allowInitialGeneration: true });
let outputTail = Promise.resolve();
let outputBytes = 0;
let worker;
let workerExited = false;
let interrupt;
let generation;
let nextMessageId = 1;
let ready = false;
let startReceived = false;
let finished = false;
let failed = false;
let stopping = false;
let stopSent = false;

function send(type, fields = {}) {
  const sequence = createFrameSequence({ version: 1, generation, type, ...fields }, generation, nextMessageId++);
  if (outputBytes + sequence.byteLength > MAX_QUEUED_BYTES) {
    throw new Error("Codemode Runtime IPC output queue exceeds 256 MiB");
  }
  outputBytes += sequence.byteLength;
  outputTail = outputTail.then(async () => {
    for (const frame of sequence.frames) {
      await new Promise((resolve, reject) => {
        process.stdout.write(frame, error => error ? reject(error) : resolve());
      });
    }
  }).finally(() => { outputBytes -= sequence.byteLength; });
  return outputTail;
}

function fail(error) {
  if (failed) return;
  failed = true;
  finished = true;
  const value = error instanceof Error ? error : new Error(String(error));
  let failureSent = Promise.resolve();
  try {
    failureSent = send("failure", { error: { name: value.name, message: value.message, stack: value.stack } });
  } catch {
    failureSent = Promise.resolve();
  }
  void failureSent.catch(() => undefined).finally(() => {
    if (worker) void worker.terminate().catch(() => undefined);
    process.exitCode = 1;
    process.stdin.pause();
  });
}

function finishStop() {
  if (stopSent) return;
  stopSent = true;
  void send("stopped").catch(() => undefined).finally(() => {
    process.exitCode = 0;
    process.stdin.pause();
  });
}

async function start(frame) {
  if (ready || !Number.isInteger(frame.version) || frame.version !== 1 ||
      typeof frame.generation !== "string" || typeof frame.workerSource !== "string" ||
      typeof frame.wasmPath !== "string" || frame.wasmPath.length === 0 || !frame.data || typeof frame.data !== "object") {
    throw new Error("Codemode Runtime start frame is invalid");
  }
  generation = frame.generation;
  const wasm = await WebAssembly.compile(readFileSync(frame.wasmPath));
  interrupt = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  worker = new Worker(frame.workerSource, {
    eval: true,
    workerData: { ...frame.data, wasm, interrupt },
  });
  worker.on("message", message => {
    if (message && message.type === "done") finished = true;
    try {
      void send("message", { message }).catch(fail);
    } catch (error) {
      fail(error);
    }
  });
  worker.on("error", fail);
  worker.on("exit", code => {
    workerExited = true;
    if (stopping) {
      finishStop();
      return;
    }
    if (!finished) fail(new Error(`Codemode worker exited with code ${code} before completion`));
  });
  ready = true;
  await send("ready");
}

async function receive(frame) {
  if (!startReceived) {
    if (frame.type !== "start") throw new Error("Codemode Runtime start frame is invalid");
    startReceived = true;
    return start(frame);
  }
  if (!ready) throw new Error("Codemode Runtime IPC message arrived before readiness");
  if (frame.version !== 1 || frame.generation !== generation) {
    throw new Error("Codemode Runtime IPC generation or version is invalid");
  }
  if (frame.type === "message") {
    const message = frame.message;
    if (!message || message.type !== "result" || !Number.isInteger(message.id) ||
        typeof message.ok !== "boolean" || (message.payload !== undefined && typeof message.payload !== "string")) {
      throw new Error("Codemode Runtime result frame is invalid");
    }
    if (!finished) worker.postMessage(message);
    return;
  }
  if (frame.type === "stop") {
    if (stopping) return;
    stopping = true;
    Atomics.store(new Int32Array(interrupt), 0, 1);
    if (worker && !workerExited) await worker.terminate();
    else finishStop();
    return;
  }
  throw new Error("Codemode Runtime IPC frame type is invalid");
}

process.stdin.on("data", chunk => {
  try {
    for (const frame of decoder.push(chunk)) {
      void receive(frame).catch(fail);
    }
  } catch (error) {
    fail(error);
  }
});
process.stdin.on("end", () => {
  try {
    decoder.finish();
  } catch (error) {
    fail(error);
    return;
  }
  if (!stopping) fail(new Error("Codemode Runtime input pipe closed"));
});
process.stdin.on("error", fail);
