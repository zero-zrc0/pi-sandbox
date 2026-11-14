#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "$script_dir/../../../../" && pwd)"
label="${PLAN13_EVIDENCE_LABEL:-linux}"
case "$label" in
  ''|*[!a-z0-9-]*)
    printf 'PLAN13_EVIDENCE_LABEL must contain only lowercase letters, digits, and hyphens\n' >&2
    exit 2
    ;;
esac

artifact_root="${PLAN13_ARTIFACT_ROOT:-$repo_root/.cache/auto-approval/plan-13}"
mkdir -p -- "$artifact_root"
binary="$artifact_root/linux-sandbox"
environment_file="$artifact_root/$label-environment.txt"
probe_file="$artifact_root/$label-probe.json"
report_file="$artifact_root/$label-native.json"

bash "$repo_root/src/sandbox/backend/linux/build.sh" "$binary"
{
  printf 'evidence_label=%s\n' "$label"
  printf 'os_release:\n'; cat /etc/os-release
  printf 'uname='; uname -a
  printf 'kernel_release='; cat /proc/sys/kernel/osrelease
  printf 'architecture='; uname -m
  printf 'node_platform='; node -p 'process.platform'
  printf 'node='; node --version
  printf 'npm='; npm --version
  printf 'cc='; cc --version | sed -n '1p'
  printf 'bubblewrap='; /usr/bin/bwrap --version
} > "$environment_file"
"$binary" probe > "$probe_file"
npm test -- \
  test/sandbox/native/linux/backend.test.ts \
  test/sandbox/native/linux/sandbox-tool-native.test.ts \
  --reporter=json \
  --outputFile="$report_file"
