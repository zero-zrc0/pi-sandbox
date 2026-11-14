import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const EXECUTION_INSTALL_ROOT = realpathSync(fileURLToPath(new URL("../../", import.meta.url)));
