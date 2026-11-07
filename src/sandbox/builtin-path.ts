import { existsSync } from "node:fs";
import { resolveNativeToolTarget } from "../approve-core/utils/path/native-tool-target";
import { pathFlavorForPlatform } from "../approve-core/utils/path/path-flavor";
import type { BuiltinToolName } from "./types";

export function builtinToolPath(name: BuiltinToolName, path: string, cwd: string): string {
  return resolveNativeToolTarget(path, {
    cwd, flavor: pathFlavorForPlatform(process.platform), readFallbacks: name === "read", exists: existsSync,
  }).target;
}
