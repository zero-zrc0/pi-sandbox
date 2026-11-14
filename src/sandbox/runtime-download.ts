import { closeSync, constants, createWriteStream, existsSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";
import { isAbsolute, join, relative, sep } from "node:path";
import type { RuntimeResourceEntry } from "./runtime-catalog";
import { trustedReleaseUrl, trustedRuntimeRedirectUrl } from "./runtime-catalog";

interface ResumeState {
  readonly schemaVersion: 1;
  readonly url: string;
  readonly archiveSizeBytes: number;
  readonly archiveSha256: string;
  readonly etag?: string;
  readonly lastModified?: string;
}

export interface RuntimeDownloadProgress {
  readonly receivedBytes: number;
  readonly totalBytes: number;
}

class OversizedRuntimeArchiveError extends Error {
  constructor() {
    super("runtime download exceeded the trusted archive size");
  }
}

function isRegularFile(path: string): boolean {
  if (!existsSync(path)) return false;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
    throw new Error("runtime download staging file is not a regular file");
  }
  return true;
}

function clearPartial(partPath: string, statePath: string): void {
  for (const path of [partPath, statePath]) {
    if (isRegularFile(path)) rmSync(path);
  }
}

function loadResumeState(entry: RuntimeResourceEntry, partPath: string, statePath: string): ResumeState | undefined {
  const partExists = isRegularFile(partPath);
  const stateExists = isRegularFile(statePath);
  if (!partExists || !stateExists) {
    if (partExists || stateExists) clearPartial(partPath, statePath);
    return undefined;
  }
  try {
    const state = JSON.parse(readFileSync(statePath, "utf8")) as ResumeState;
    const size = statSync(partPath).size;
    if (state.schemaVersion !== 1 || state.url !== entry.url || state.archiveSizeBytes !== entry.archiveSizeBytes ||
        state.archiveSha256 !== entry.archiveSha256 || size < 1 || size > entry.archiveSizeBytes) throw new Error();
    if (size < entry.archiveSizeBytes && !state.etag && !state.lastModified) throw new Error();
    return state;
  } catch {
    clearPartial(partPath, statePath);
    return undefined;
  }
}

function saveResumeState(path: string, state: ResumeState): void {
  if (existsSync(path)) {
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
      throw new Error("runtime resume metadata is not a regular file");
    }
  }
  writeFileSync(path, `${JSON.stringify(state)}\n`, { mode: 0o600 });
}

async function requestTrustedAsset(
  entry: RuntimeResourceEntry,
  fetcher: typeof fetch,
  headers: Headers,
  signal?: AbortSignal,
): Promise<Response> {
  let url = entry.url;
  let redirected = false;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (redirected) trustedRuntimeRedirectUrl(url);
    else trustedReleaseUrl(url);
    const response = await fetcher(url, {
      headers,
      redirect: "manual",
      ...(signal === undefined ? {} : { signal }),
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      if (response.url) {
        if (redirected) trustedRuntimeRedirectUrl(response.url);
        else trustedReleaseUrl(response.url);
      }
      return response;
    }
    const location = response.headers.get("location");
    await response.body?.cancel();
    if (!location || redirects === 5) throw new Error("runtime download redirect is invalid");
    url = new URL(location, url).href;
    redirected = true;
    trustedRuntimeRedirectUrl(url);
  }
  throw new Error("runtime download exceeded the redirect limit");
}

function contentRange(response: Response): { readonly start: number; readonly end: number; readonly total: number } | undefined {
  const value = response.headers.get("content-range");
  const match = value && /^bytes (\d+)-(\d+)\/(\d+)$/u.exec(value);
  if (!match) return undefined;
  return { start: Number(match[1]), end: Number(match[2]), total: Number(match[3]) };
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function writeResponse(
  response: Response,
  partPath: string,
  append: boolean,
  input: { readonly stagingDirectory: string; readonly totalBytes: number; readonly initialBytes: number; readonly signal?: AbortSignal; readonly onProgress?: (progress: RuntimeDownloadProgress) => void },
): Promise<void> {
  if (!response.body) throw new Error("runtime download response has no body");
  const source = Readable.fromWeb(response.body as never);
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const flags = append
    ? constants.O_WRONLY | constants.O_APPEND | noFollow
    : constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow;
  const descriptor = openSync(partPath, flags, 0o600);
  const metadata = fstatSync(descriptor);
  const actualPath = realpathSync(partPath);
  const relativePath = relative(input.stagingDirectory, actualPath);
  if (!metadata.isFile() || (relativePath !== "" && (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)))) {
    closeSync(descriptor);
    throw new Error("runtime download file resolves outside its staging directory");
  }
  const destination = createWriteStream(partPath, { fd: descriptor, autoClose: true });
  let receivedBytes = input.initialBytes;
  const progress = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      if (receivedBytes + chunk.byteLength > input.totalBytes) {
        callback(new OversizedRuntimeArchiveError());
        return;
      }
      receivedBytes += chunk.byteLength;
      input.onProgress?.({ receivedBytes, totalBytes: input.totalBytes });
      callback(null, chunk);
    },
  });
  await pipeline(source, progress, destination, input.signal === undefined ? {} : { signal: input.signal });
}

export async function downloadRuntimeArchive(input: {
  readonly entry: RuntimeResourceEntry;
  readonly stagingDirectory: string;
  readonly fetch?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: RuntimeDownloadProgress) => void;
}): Promise<string> {
  const entry = input.entry;
  const fetcher = input.fetch ?? fetch;
  const timeout = AbortSignal.timeout(10 * 60 * 1000);
  const signal = input.signal === undefined ? timeout : AbortSignal.any([input.signal, timeout]);
  const partPath = join(input.stagingDirectory, "runtime.tar.gz.part");
  const statePath = join(input.stagingDirectory, "runtime-download.json");
  const state = loadResumeState(entry, partPath, statePath);
  let offset = state === undefined ? 0 : statSync(partPath).size;
  if (offset === entry.archiveSizeBytes && await sha256File(partPath) === entry.archiveSha256) return partPath;
  if (offset === entry.archiveSizeBytes) {
    clearPartial(partPath, statePath);
    offset = 0;
  }

  const headers = new Headers();
  if (offset > 0 && state !== undefined) {
    headers.set("range", `bytes=${offset}-`);
    headers.set("if-range", state.etag ?? state.lastModified!);
  }
  let response = await requestTrustedAsset(entry, fetcher, headers, signal);
  let append = offset > 0;
  if (append) {
    const range = contentRange(response);
    const responseEtag = response.headers.get("etag") ?? undefined;
    const responseModified = response.headers.get("last-modified") ?? undefined;
    const sameValidator = state!.etag ? responseEtag === state!.etag : responseModified === state!.lastModified;
    if (response.status !== 206 || !range || range.start !== offset || range.total !== entry.archiveSizeBytes || !sameValidator) {
      await response.body?.cancel();
      clearPartial(partPath, statePath);
      offset = 0;
      append = false;
      response = await requestTrustedAsset(entry, fetcher, new Headers(), signal);
    }
  }
  if ((!append && response.status !== 200) || (append && response.status !== 206)) {
    await response.body?.cancel();
    throw new Error(`runtime download returned HTTP ${response.status}`);
  }

  const total = entry.archiveSizeBytes;
  if (append) {
    const range = contentRange(response);
    if (!range || range.start !== offset || range.total !== total || range.end < range.start || range.end >= total) {
      await response.body?.cancel();
      clearPartial(partPath, statePath);
      throw new Error("runtime resume Content-Range does not match the requested bytes");
    }
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && Number(contentLength) !== range.end - range.start + 1) {
      await response.body?.cancel();
      clearPartial(partPath, statePath);
      throw new Error("runtime resume Content-Length does not match Content-Range");
    }
  } else {
    const contentRangeHeader = response.headers.get("content-range");
    if (contentRangeHeader !== null) {
      await response.body?.cancel();
      throw new Error("runtime server returned partial content without a resume request");
    }
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && Number(contentLength) !== total) {
      await response.body?.cancel();
      throw new Error("runtime Content-Length does not match the trusted archive size");
    }
  }

  const nextState: ResumeState = {
    schemaVersion: 1,
    url: entry.url,
    archiveSizeBytes: entry.archiveSizeBytes,
    archiveSha256: entry.archiveSha256,
    ...(response.headers.get("etag") ? { etag: response.headers.get("etag")! } : {}),
    ...(response.headers.get("last-modified") ? { lastModified: response.headers.get("last-modified")! } : {}),
  };
  if (append && state?.etag && nextState.etag !== state.etag || append && state?.lastModified && nextState.lastModified !== state.lastModified) {
    await response.body?.cancel();
    clearPartial(partPath, statePath);
    throw new Error("runtime asset validator changed during resume");
  }
  saveResumeState(statePath, nextState);
  try {
    await writeResponse(response, partPath, append, {
      stagingDirectory: realpathSync(input.stagingDirectory),
      totalBytes: total,
      initialBytes: offset,
      signal,
      ...(input.onProgress === undefined ? {} : { onProgress: input.onProgress }),
    });
  } catch (error) {
    if (error instanceof OversizedRuntimeArchiveError) clearPartial(partPath, statePath);
    throw error;
  }
  const received = statSync(partPath).size;
  if (received < total) throw new Error("runtime download is incomplete and can be resumed");
  if (received > total) {
    clearPartial(partPath, statePath);
    throw new Error("runtime download exceeded the trusted archive size");
  }
  const digest = await sha256File(partPath);
  if (digest !== entry.archiveSha256) {
    clearPartial(partPath, statePath);
    throw new Error("runtime archive SHA-256 does not match the trusted resource entry");
  }
  return partPath;
}
