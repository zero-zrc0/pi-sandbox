import { build } from "esbuild";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

/*
 * The sandboxed worker cannot resolve the pi SDK on its own: managed installs
 * omit peer dependencies, and the native sandbox only grants read access to
 * this package and the Node executable. Bundling keeps the artifact self-contained.
 */
const outfile = fileURLToPath(new URL("../src/sandbox/builtin-worker.bundle.mjs", import.meta.url));

/*
 * The package root also re-exports the model runtime and every provider SDK,
 * and pi declares no "sideEffects": false, so esbuild cannot tree-shake it.
 * Resolving the bare import to the tools subtree keeps only the tool factories.
 */
const toolsEntry = fileURLToPath(new URL(
  "../node_modules/@earendil-works/pi-coding-agent/dist/core/tools/index.js", import.meta.url));
const sizeLimit = 1_000_000;

const { outputFiles } = await build({
  entryPoints: [fileURLToPath(new URL("../src/sandbox/builtin-worker.mjs", import.meta.url))],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  minify: true,
  external: ["node:*"],
  plugins: [{
    name: "pi-tools-subtree",
    setup(builder) {
      builder.onResolve({ filter: /^@earendil-works\/pi-coding-agent$/ }, () => ({ path: toolsEntry }));
    },
  }],
  // ESM output has no CommonJS `require`, which bundled dependencies still call.
  banner: { js: "import { createRequire as __createRequire } from \"node:module\"; const require = __createRequire(import.meta.url);" },
  // Written after the size check so an oversized build never reaches disk.
  write: false,
  logLevel: "warning",
});

const artifact = outputFiles?.[0];
if (artifact === undefined) throw new Error("builtin worker build produced no output");
if (artifact.contents.byteLength > sizeLimit) {
  throw new Error(`builtin worker bundle is ${artifact.contents.byteLength} bytes, over the ${sizeLimit} byte limit `
    + "— the tools subtree entry did not apply");
}
await writeFile(outfile, artifact.contents);
