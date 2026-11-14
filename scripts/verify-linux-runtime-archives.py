#!/usr/bin/env python3
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path


if len(sys.argv) != 5:
    raise SystemExit("usage: verify-linux-runtime-archives.py DIRECTORY RUNTIME_VERSION MIN_PLUGIN MAX_PLUGIN")

root = Path(sys.argv[1]).resolve(strict=True)
runtime_version, min_plugin, max_plugin = sys.argv[2:]
bwrap_version = "0.13.1"
bwrap_commit = "362936aea0d5c6e70f7af75d2d44b5a914cb4ba2"
expected_files = {
    "linux-sandbox": ("linuxLauncher", True),
    "linux-egress-bridge": ("egressBridge", True),
    "bwrap": ("bubblewrap", True),
    "bwrap.LICENSE": ("bubblewrapLicense", False),
}
hash_pattern = re.compile(r"^[0-9a-f]{64}$")


def fail(message):
    raise ValueError(message)


for arch in ("x64", "arm64"):
    archive_name = f"pi-sandbox-linux-{arch}.tar.gz"
    arch_dir = root / arch
    archive_path = arch_dir / archive_name
    size_path = arch_dir / f"{archive_name}.size"
    digest_path = arch_dir / f"{archive_name}.sha256"
    manifest_sidecar = arch_dir / f"pi-sandbox-linux-{arch}.runtime.json"
    if not all(path.is_file() for path in (archive_path, size_path, digest_path, manifest_sidecar)):
        fail(f"{arch} archive set is incomplete")
    actual_size = archive_path.stat().st_size
    if size_path.read_text(encoding="ascii").strip() != str(actual_size):
        fail(f"{arch} archive size sidecar is incorrect")
    digest_line = digest_path.read_text(encoding="ascii").strip().split()
    if len(digest_line) != 2 or digest_line[1].lstrip("*") != archive_name or not hash_pattern.fullmatch(digest_line[0]):
        fail(f"{arch} archive SHA-256 sidecar is malformed")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest != digest_line[0]:
        fail(f"{arch} archive SHA-256 does not match its sidecar")

    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if {member.name for member in members} != {*expected_files, "runtime.json"} or len(members) != 5:
            fail(f"{arch} archive contains an unexpected file layout")
        if any(not member.isfile() for member in members):
            fail(f"{arch} archive contains a link or non-regular entry")
        manifest_bytes = archive.extractfile("runtime.json").read()
        manifest = json.loads(manifest_bytes)
        if manifest != json.loads(manifest_sidecar.read_text(encoding="utf-8")):
            fail(f"{arch} runtime manifest sidecar differs from the archive")
        if manifest.get("schemaVersion") != 1 or manifest.get("stable") is not True or \
           manifest.get("version") != runtime_version or manifest.get("platform") != "linux" or \
           manifest.get("arch") != arch or manifest.get("protocolVersion") != 2 or \
           manifest.get("minPluginVersion") != min_plugin or \
           manifest.get("maxPluginVersionExclusive") != max_plugin or \
           manifest.get("backendId") != "linux-bwrap-landlock-seccomp" or \
           manifest.get("components") != {"bubblewrapVersion": bwrap_version, "bubblewrapSourceCommit": bwrap_commit}:
            fail(f"{arch} runtime manifest metadata is invalid")
        entries = manifest.get("files")
        if not isinstance(entries, list) or len(entries) != len(expected_files):
            fail(f"{arch} runtime manifest file list is incomplete")
        seen = set()
        for entry in entries:
            role = entry.get("role")
            path = entry.get("path")
            if path not in expected_files or expected_files[path] != (role, entry.get("executable")) or path in seen:
                fail(f"{arch} runtime manifest contains an invalid file entry")
            seen.add(path)
            if not hash_pattern.fullmatch(entry.get("sha256", "")):
                fail(f"{arch} runtime manifest has an invalid file SHA-256")
            member = archive.getmember(path)
            if entry["executable"] and member.mode & 0o111 == 0:
                fail(f"{arch} runtime file {path} is missing executable permissions")
            if hashlib.sha256(archive.extractfile(member).read()).hexdigest() != entry["sha256"]:
                fail(f"{arch} runtime file {path} failed SHA-256 verification")
    print(f"Verified {arch}: {archive_name}, {actual_size} bytes, SHA-256 {digest}")
