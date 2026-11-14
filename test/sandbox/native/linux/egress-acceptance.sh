#!/usr/bin/env bash
# Native acceptance for the controlled network egress on Linux/WSL.
# Covers the scenarios the vitest suites cannot express natively on a
# Node-less host. Run inside WSL: bash test/sandbox/native/linux/egress-acceptance.sh
set -uo pipefail

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$script_dir"
while [[ "$repo_root" != "/" && ! -f "$repo_root/package.json" ]]; do
  repo_root="$(dirname -- "$repo_root")"
done
work="$(mktemp -d /tmp/egress-acceptance.XXXXXX)"
trap 'rm -rf "$work"' EXIT

cc -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie \
  "$repo_root/src/sandbox/backend/linux/native.c" -o "$work/native"
cc -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie \
  "$repo_root/src/sandbox/backend/linux/bridge.c" -o "$work/linux-egress-bridge"
cp "$work/linux-egress-bridge" "$work/bridge-kept"

mkdir -p "$work/out"
echo acceptance-ok > "$work/out/marker.txt"
python3 -m http.server 18180 --bind 127.0.0.1 --directory "$work/out" >/dev/null 2>&1 &
target_pid=$!
sleep 0.5

run_sandbox() {
  PI_EGRESS_PROXY=127.0.0.1:18081 PI_EGRESS_LEASE=accept-lease \
  PI_EGRESS_CREDENTIAL=accept-cred \
    "$work/native" run --network destinations --cwd "$work/out" \
    --read-dir /usr --read-dir /etc --read-dir "$work" -- "$@"
}

pass=0
fail=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    printf 'PASS %s\n' "$name"
    pass=$((pass + 1))
  else
    printf 'FAIL %s (wanted substring: %s)\n' "$name" "$expected"
    printf '  actual: %s\n' "$actual"
    fail=$((fail + 1))
  fi
}

# NET-04: socket capability shaping and a clean descriptor table.
out="$(run_sandbox /usr/bin/python3 -c '
import os, socket
fds = []
for fd in range(3, 64):
    try:
        os.fstat(fd)
        fds.append(fd)
    except OSError:
        pass
print("fds=" + (",".join(map(str, fds)) if fds else "none"))
a, b = socket.socketpair()
print("socketpair-ok")
try:
    socket.socket(40, socket.SOCK_STREAM)
    print("vsock-created")
except OSError:
    print("vsock-blocked")
' 2>&1)"
check "NET-04 tool descriptor table is stdio only" "fds=none" "$out"
check "NET-04 unix socketpair allowed" "socketpair-ok" "$out"
check "NET-04 vsock blocked" "vsock-blocked" "$out"

# NET-06: with the bridge missing, preparation fails and the tool never runs.
mv "$work/linux-egress-bridge" "$work/bridge-moved"
out="$(run_sandbox /usr/bin/echo tool-ran 2>&1)"
status=$?
mv "$work/bridge-moved" "$work/linux-egress-bridge"
check "NET-06 zero start on handoff failure" "egress bridge binary is missing" "$out"
if [[ "$out" != *"tool-ran"* ]]; then
  printf 'PASS NET-06 tool process never executed\n'
  pass=$((pass + 1))
else
  printf 'FAIL NET-06 tool executed despite failed preparation\n'
  fail=$((fail + 1))
fi

# NET-11: none and all semantics are unchanged by the proxy mode.
out="$("$work/native" run --network none --cwd "$work/out" \
  --read-dir /usr --read-dir /etc --read-dir "$work" -- \
  /usr/bin/curl -s -m 3 http://127.0.0.1:18180/marker.txt 2>&1)"
if [[ "$out" != *"acceptance-ok"* ]]; then
  printf 'PASS NET-11 network none stays offline\n'
  pass=$((pass + 1))
else
  printf 'FAIL NET-11 none mode reached the network: %s\n' "$out"
  fail=$((fail + 1))
fi
out="$("$work/native" run --network all --cwd "$work/out" \
  --read-dir /usr --read-dir /etc --read-dir "$work" -- \
  /usr/bin/curl -s -m 3 http://127.0.0.1:18180/marker.txt 2>&1)"
check "NET-11 network all keeps direct access" "acceptance-ok" "$out"

# NET-12: every launcher-spawned process is gone after the run.
sleep 0.3
leftovers="$(ps -eo args | grep -E "linux-egress-bridge|bwrap|http.server 18180" | grep -v grep | grep -v "egress-acceptance")"
if [[ -z "$leftovers" ]]; then
  printf 'PASS NET-12 full process cleanup\n'
  pass=$((pass + 1))
else
  printf 'FAIL NET-12 leftover processes: %s\n' "$leftovers"
  fail=$((fail + 1))
fi

kill "$target_pid" 2>/dev/null || true
printf 'acceptance summary: %d passed, %d failed\n' "$pass" "$fail"
exit "$fail"
