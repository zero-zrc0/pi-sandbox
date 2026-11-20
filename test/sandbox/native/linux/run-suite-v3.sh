#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../../../../" && pwd)
fixture=$(mktemp -d /tmp/pi-linux-suite.XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
cd "$fixture"
curl -fsSLO https://nodejs.org/dist/v24.9.0/SHASUMS256.txt
curl -fsSLO https://nodejs.org/dist/v24.9.0/node-v24.9.0-linux-x64.tar.xz
grep '  node-v24.9.0-linux-x64.tar.xz$' SHASUMS256.txt | sha256sum -c -
tar -xf node-v24.9.0-linux-x64.tar.xz
export PATH="$fixture/node-v24.9.0-linux-x64/bin:$PATH"
mkdir "$fixture/repo"
tar -C "$repo_root" --exclude='./.git' --exclude='./node_modules' --exclude='./runtimes' \
  --exclude='./.cache' --exclude='./src/sandbox/backend/windows/mxc/target' -cf - . | tar -C "$fixture/repo" -xf -
cd "$fixture/repo"
npm ci --no-audit --no-fund
bash src/sandbox/backend/linux/build.sh src/sandbox/backend/linux/linux-sandbox
TEMP=/var/tmp npm test -- test/sandbox/native/linux/backend.test.ts test/sandbox/native/linux/sandbox-tool-native.test.ts test/sandbox/production.test.ts
