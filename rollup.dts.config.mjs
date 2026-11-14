import { dts } from "rollup-plugin-dts";

function bundle(input, file) {
  return {
    input,
    output: { file, format: "es" },
    external: [/^@earendil-works\//, /^node:/],
    plugins: [dts({ tsconfig: "./tsconfig.json" })],
  };
}

export default [
  bundle("src/service.ts", "dist/public.d.ts"),
  bundle("src/sdk/index.ts", "dist/sdk.d.ts"),
];
