#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: build.sh OUTPUT [BRIDGE_OUTPUT]\n' >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
output="$1"
bridge_output="${2:-$(dirname -- "$output")/linux-egress-bridge}"
cc="${CC:-cc}"
read -r -a extra_cflags <<< "${SANDBOX_CFLAGS:-}"
read -r -a extra_ldflags <<< "${SANDBOX_LDFLAGS:-}"
mkdir -p -- "$(dirname -- "$output")"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
  "${extra_cflags[@]}" "$script_dir/native.c" "${extra_ldflags[@]}" -o "$output"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
  "${extra_cflags[@]}" "$script_dir/bridge.c" "${extra_ldflags[@]}" -o "$bridge_output"
chmod 0755 "$output" "$bridge_output"
