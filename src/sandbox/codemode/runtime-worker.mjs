const { Worker } = require("node:worker_threads");
import {
  CODEMODE_MAX_QUEUED_BYTES,
  FrameDecoder,
  createFrameSequence,
} from "./physical-codec.js";

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
      typeof frame.wasmBase64 !== "string" || !frame.data || typeof frame.data !== "object") {
    throw new Error("Codemode Runtime start frame is invalid");
  }
  generation = frame.generation;
  const wasm = await WebAssembly.compile(Buffer.from(frame.wasmBase64, "base64"));
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
