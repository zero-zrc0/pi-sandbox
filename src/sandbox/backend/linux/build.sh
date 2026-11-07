#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: build.sh OUTPUT [BRIDGE_OUTPUT]\n' >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
output="$1"
bridge_output="${2:-$(dirname -- "$output")/linux-egress-bridge}"
mkdir -p -- "$(dirname -- "$output")"
cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
  "$script_dir/native.c" -o "$output"
cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
  "$script_dir/bridge.c" -o "$bridge_output"
chmod 0755 "$output" "$bridge_output"
