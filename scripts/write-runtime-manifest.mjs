import { createHash } from "node:crypto";
import { createReadStream, lstatSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [directoryArg, platform, arch, version, minPluginVersion, maxPluginVersionExclusive, bubblewrapVersion, bubblewrapSourceCommit] = process.argv.slice(2);
if (!directoryArg || !platform || !arch || !version || !minPluginVersion || !maxPluginVersionExclusive) {
  throw new Error("usage: node write-runtime-manifest.mjs DIRECTORY PLATFORM ARCH VERSION MIN_PLUGIN MAX_PLUGIN");
}
const directory = resolve(directoryArg);
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const compare = (left, right) => {
  const a = left.split(".").map(Number), b = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
};
for (const value of [version, minPluginVersion, maxPluginVersionExclusive]) {
  if (!versionPattern.test(value)) throw new Error(`invalid stable version: ${value}`);
}
if (compare(minPluginVersion, maxPluginVersionExclusive) >= 0) throw new Error("plugin compatibility range is empty");

const files = platform === "linux" && ["x64", "arm64"].includes(arch)
  ? [
      ["linuxLauncher", "linux-sandbox", true],
      ["egressBridge", "linux-egress-bridge", true],
      ["bubblewrap", "bwrap", true],
      ["bubblewrapLicense", "bwrap.LICENSE", false],
    ]
  : platform === "win32" && ["x64", "arm64"].includes(arch)
    ? [
        ["windowsExecutable", "pi-sandbox-windows-mxc.exe", true],
        ["mxcManifest", "mxc-runtime.json", false],
      ]
    : undefined;
if (!files) throw new Error(`unsupported runtime target: ${platform}/${arch}`);
if (platform === "linux" && (!bubblewrapVersion || !versionPattern.test(bubblewrapVersion) ||
    !bubblewrapSourceCommit || !/^[0-9a-f]{40}$/u.test(bubblewrapSourceCommit))) {
  throw new Error("Linux runtimes require the bubblewrap version and source commit");
}
const hashFile = async path => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};
const entries = [];
for (const [role, name, executable] of files) {
  const path = join(directory, name);
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink > 1) {
    throw new Error(`${name} must be a regular file`);
  }
  if (platform === "linux" && executable && (metadata.mode & 0o111) === 0) {
    throw new Error(`${name} must have executable permissions`);
  }
  entries.push({ role, path: name, sha256: await hashFile(path), executable });
}
const manifest = {
  schemaVersion: 1,
  version,
  stable: true,
  platform,
  arch,
  protocolVersion: 2,
  minPluginVersion,
  maxPluginVersionExclusive,
  backendId: platform === "linux" ? "linux-bwrap-landlock-seccomp" : "windows-mxc",
  files: entries,
  ...(platform === "linux" ? {
    components: {
      bubblewrapVersion,
      bubblewrapSourceCommit,
    },
  } : {}),
};
const temporary = join(directory, "runtime.json.tmp");
writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
renameSync(temporary, join(directory, "runtime.json"));
