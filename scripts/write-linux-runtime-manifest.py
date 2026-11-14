#!/usr/bin/env python3
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


if len(sys.argv) != 8:
    raise SystemExit("usage: write-linux-runtime-manifest.py DIRECTORY ARCH VERSION MIN_PLUGIN MAX_PLUGIN BWRAP_VERSION BWRAP_COMMIT")

directory = Path(sys.argv[1]).resolve(strict=True)
arch, version, min_plugin, max_plugin, bwrap_version, bwrap_commit = sys.argv[2:]
version_pattern = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def version_tuple(value, label):
    if not version_pattern.fullmatch(value):
        raise ValueError(f"{label} must be a stable semantic version")
    return tuple(map(int, value.split(".")))


minimum = version_tuple(min_plugin, "minimum plugin version")
maximum = version_tuple(max_plugin, "maximum plugin version")
version_tuple(version, "runtime version")
version_tuple(bwrap_version, "Bubblewrap version")
if minimum >= maximum:
    raise ValueError("plugin compatibility range is empty")
if arch not in ("x64", "arm64"):
    raise ValueError(f"unsupported Linux architecture: {arch}")
if not re.fullmatch(r"[0-9a-f]{40}", bwrap_commit):
    raise ValueError("Bubblewrap source commit must be a 40 character lowercase Git SHA")

files = [
    ("linuxLauncher", "linux-sandbox", True),
    ("egressBridge", "linux-egress-bridge", True),
    ("bubblewrap", "bwrap", True),
    ("bubblewrapLicense", "bwrap.LICENSE", False),
]
entries = []
for role, name, executable in files:
    path = directory / name
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
        raise ValueError(f"{name} must be a regular file")
    if executable and metadata.st_mode & 0o111 == 0:
        raise ValueError(f"{name} must have executable permissions")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    entries.append({"role": role, "path": name, "sha256": digest.hexdigest(), "executable": executable})

manifest = {
    "schemaVersion": 1,
    "version": version,
    "stable": True,
    "platform": "linux",
    "arch": arch,
    "protocolVersion": 2,
    "minPluginVersion": min_plugin,
    "maxPluginVersionExclusive": max_plugin,
    "backendId": "linux-bwrap-landlock-seccomp",
    "files": entries,
    "components": {"bubblewrapVersion": bwrap_version, "bubblewrapSourceCommit": bwrap_commit},
}

temporary = directory / "runtime.json.tmp"
with temporary.open("x", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
os.replace(temporary, directory / "runtime.json")
