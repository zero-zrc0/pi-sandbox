import { createInterface } from "node:readline";
import { performFileOperation } from "./operations.mjs";

const READY = "\x1ePI-MACOS-OPERATION-READY\x1f";
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  lines.close();
  process.stdout.write(READY);
  try {
    process.stdout.write(`${JSON.stringify(performFileOperation(JSON.parse(line)))}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ exitCode: 1, errorCode: "protocol", error: error instanceof Error ? error.message : String(error) })}\n`);
    process.exitCode = 1;
  }
  break;
}
