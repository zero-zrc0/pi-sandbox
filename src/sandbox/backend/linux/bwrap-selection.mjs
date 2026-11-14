import { realpathSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join, relative, sep } from "node:path";

function pathWithin(parent, child) {
  const path = relative(parent, child);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

export function resolveSystemBubblewrap(candidatePath, workspaceRoot) {
  if (typeof candidatePath !== "string" || !isAbsolute(candidatePath) || typeof workspaceRoot !== "string") {
    return undefined;
  }
  try {
    const workspace = realpathSync(workspaceRoot);
    const candidate = realpathSync(candidatePath);
    const metadata = statSync(candidate);
    if (!metadata.isFile() || (metadata.mode & 0o111) === 0 || pathWithin(workspace, candidate)) return undefined;
    return candidate;
  } catch {
    return undefined;
  }
}

export function findSystemBubblewrap(pathValue, workspaceRoot) {
  for (const entry of (pathValue ?? "").split(delimiter)) {
    if (!entry || !isAbsolute(entry)) continue;
    try {
      const directory = realpathSync(entry);
      const candidate = resolveSystemBubblewrap(join(directory, "bwrap"), workspaceRoot);
      if (candidate !== undefined) return candidate;
    } catch {}
  }
  return undefined;
}

export function selectBubblewrapCandidate(systemPath, bundledPath, probe) {
  const candidates = [
    ...(systemPath === undefined ? [] : [{ path: systemPath }]),
    ...(bundledPath === undefined ? [] : [{ path: bundledPath.path, version: bundledPath.version }]),
  ];
  for (const candidate of candidates) {
    const version = probe(candidate.path, candidate.version);
    if (version !== undefined) return { ...candidate, version };
  }
  return undefined;
}
