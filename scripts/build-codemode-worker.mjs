import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { rollup } from "rollup";

async function build(input, output) {
  const bundle = await rollup({ input, external: id => id.startsWith("node:") });
  try {
    const generated = await bundle.generate({
      format: "cjs",
      exports: "none",
      inlineDynamicImports: true,
    });
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, generated.output[0].code, "utf8");
  } finally {
    await bundle.close();
  }
}

const codemodeDir = new URL("../src/sandbox/codemode/", import.meta.url);
const workerBundle = fileURLToPath(new URL("worker.bundle.cjs", codemodeDir));
const bootstrapBundle = fileURLToPath(new URL("runtime-worker.bundle.cjs", codemodeDir));
const worker = await rollup({
  input: fileURLToPath(import.meta.resolve("@earendil-works/pi-codemode/worker")),
  external: id => id.startsWith("node:"),
  plugins: [{
    name: "resolve-public-quickjs-wasi-entry",
    resolveId(source) {
      return source === "quickjs-wasi" ? fileURLToPath(import.meta.resolve(source)) : null;
    },
  }],
});
try {
  const generated = await worker.generate({ format: "cjs", exports: "none", inlineDynamicImports: true });
  await mkdir(dirname(workerBundle), { recursive: true });
  await writeFile(workerBundle, generated.output[0].code, "utf8");
} finally {
  await worker.close();
}

await build(fileURLToPath(new URL("../src/sandbox/codemode/runtime-worker.mjs", import.meta.url)), bootstrapBundle);
