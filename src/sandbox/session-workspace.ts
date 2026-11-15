import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { isSamePath } from "./path";

function canonicalAgentDirectory(agentDir: string): string {
  try {
    return realpathSync(agentDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    mkdirSync(agentDir, { recursive: true });
    return realpathSync(agentDir);
  }
}

export function sessionWorkspacePath(agentDir: string, sessionId: string): string {
  return join(canonicalAgentDirectory(agentDir), "workspaces", "pi-sandbox", createHash("sha256").update(sessionId, "utf8").digest("hex"));
}

export function ensureSessionWorkspace(agentDir: string, sessionId: string): string {
  const root = canonicalAgentDirectory(agentDir);
  let parent = root;
  for (const part of ["workspaces", "pi-sandbox", createHash("sha256").update(sessionId, "utf8").digest("hex")]) {
    const path = join(parent, part);
    try {
      mkdirSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const metadata = lstatSync(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("session-workspace:expected-real-directory");
    }
    parent = realpathSync(path);
    if (!isSamePath(parent, path)) throw new Error("session-workspace:canonical-path-changed");
  }
  const temporary = join(parent, "tmp");
  try {
    mkdirSync(temporary);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const temporaryMetadata = lstatSync(temporary);
  if (!temporaryMetadata.isDirectory() || temporaryMetadata.isSymbolicLink() || !isSamePath(realpathSync(temporary), temporary)) {
    throw new Error("session-workspace:invalid-temporary-directory");
  }
  return parent;
}
