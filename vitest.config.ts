import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "#approve-core": path.resolve(import.meta.dirname, "src/approve-core"),
      "#sandbox": path.resolve(import.meta.dirname, "src/sandbox"),
      "#config": path.resolve(import.meta.dirname, "src/config"),
      "#approve-core-test": path.resolve(import.meta.dirname, "test/approve-core"),
      "#permissions": path.resolve(import.meta.dirname, "src/service.ts"),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    maxWorkers: 4,
  },
});
