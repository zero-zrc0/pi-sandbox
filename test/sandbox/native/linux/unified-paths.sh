#!/usr/bin/env bash
set -euo pipefail

launcher=${1:?pass the compiled Linux sandbox launcher}
bwrap=${PI_SANDBOX_BWRAP_PATH:-$(command -v bwrap)}
fixture=$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-unified.XXXXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/readonly" "$fixture/secret-dir"
printf 'readonly-content' > "$fixture/readonly/data"
printf 'directory-secret' > "$fixture/secret-dir/data"
printf 'private-file-content-unique' > "$fixture/secret-file"
printf 'second-secret' > "$fixture/secret-file-2"
read -r dir_device dir_inode < <(stat -c '%d %i' "$fixture/secret-dir")
read -r file_device file_inode < <(stat -c '%d %i' "$fixture/secret-file")
read -r second_device second_inode < <(stat -c '%d %i' "$fixture/secret-file-2")
read -r nested_device nested_inode < <(stat -c '%d %i' "$fixture/secret-dir/data")
read -r readonly_device readonly_inode < <(stat -c '%d %i' "$fixture/readonly")
shell=$(realpath /bin/sh)

PI_SANDBOX_BWRAP_PATH="$bwrap" "$launcher" run --network none --cwd "$fixture" --virtual-dev yes \
  --execute-dir /usr --read-file "$(realpath /etc/ld.so.cache)" \
  --read-dir "$fixture" --write-dir "$fixture" --protected "$fixture/readonly" directory "$readonly_device" "$readonly_inode" \
  --mask-dir "$fixture/secret-dir" "$dir_device" "$dir_inode" \
  --mask-file "$fixture/secret-file" "$file_device" "$file_inode" \
  --mask-file "$fixture/secret-file-2" "$second_device" "$second_inode" \
  --mask-file "$fixture/secret-dir/data" "$nested_device" "$nested_inode" \
  -- "$shell" -c '
    set -eu
    test "$(cat readonly/data)" = readonly-content
    if printf x > readonly/data 2>/dev/null; then exit 11; fi
    printf sibling > sibling
    test ! -e secret-dir/data
    if printf x > secret-dir/new 2>/dev/null; then exit 12; fi
    test "$(stat -c %s secret-file)" = 0
    test "$(stat -c %s secret-file-2)" = 0
    if test "$(cat secret-file 2>/dev/null || :)" = private-file-content-unique; then exit 13; fi
  '
test "$(cat "$fixture/sibling")" = sibling
test "$(cat "$fixture/readonly/data")" = readonly-content
test "$(cat "$fixture/secret-dir/data")" = directory-secret
test "$(cat "$fixture/secret-file")" = private-file-content-unique
test "$(cat "$fixture/secret-file-2")" = second-secret

if PI_SANDBOX_BWRAP_PATH="$bwrap" "$launcher" run --network none --cwd "$fixture" --virtual-dev yes \
  --execute-dir /usr --read-file "$(realpath /etc/ld.so.cache)" \
  --read-dir "$fixture" --write-dir "$fixture" \
  --mask-file "$fixture/secret-file" "$file_device" "$((file_inode + 1))" \
  -- "$shell" -c 'touch must-not-start'; then
  exit 14
fi
test ! -e "$fixture/must-not-start"

if PI_SANDBOX_BWRAP_PATH="$bwrap" "$launcher" run --network none --cwd "$fixture" --virtual-dev yes \
  --execute-dir /usr --read-file "$(realpath /etc/ld.so.cache)" \
  --read-dir "$fixture" --write-dir "$fixture" \
  --protected "$fixture/readonly" directory "$readonly_device" 0 \
  -- "$shell" -c 'touch protected-identity-must-not-start'; then
  exit 15
fi
test ! -e "$fixture/protected-identity-must-not-start"
