#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
package_root="$(cd -- "$script_dir/.." && pwd)"
tool_root="$package_root/.cache/pi-sandbox-build-tools-ubuntu24"
packages="$tool_root/packages"
prefix="$tool_root/prefix"
zig_version='0.17.1'
zig_archive="zig-x86_64-linux-$zig_version.tar.xz"
zig_sha256='3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a'
output_root="$package_root/.cache/linux-runtime-builds"
source_cache="$package_root/.cache/pi-sandbox-source-cache"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf 'this WSL builder requires an x86_64 Linux environment\n' >&2
  exit 1
fi
for command in apt-get dpkg-deb python3 gcc; do
  command -v "$command" >/dev/null || { printf 'required WSL build command is missing: %s\n' "$command" >&2; exit 1; }
done

mkdir -p -- "$packages" "$prefix" "$tool_root/bin" "$source_cache" "$output_root/x64" "$output_root/arm64"
if [[ ! -f "$tool_root/.tools-ready" ]]; then
  (
    cd -- "$packages"
    apt-get download meson ninja-build pkg-config pkgconf pkgconf-bin libpkgconf3 python3-packaging \
      musl-tools musl-dev make linux-libc-dev
  )
  for package in "$packages"/*.deb; do dpkg-deb -x "$package" "$prefix"; done
  touch "$tool_root/.tools-ready"
fi

specs_source="$prefix/usr/lib/x86_64-linux-musl/musl-gcc.specs"
specs_local="$prefix/usr/lib/x86_64-linux-musl/musl-gcc-local.specs"
sed \
  -e "s|/usr/include/x86_64-linux-musl|$prefix/usr/include/x86_64-linux-musl|g" \
  -e "s|/usr/lib/x86_64-linux-musl|$prefix/usr/lib/x86_64-linux-musl|g" \
  -e "s|/lib/ld-musl-x86_64.so.1|$prefix/lib/ld-musl-x86_64.so.1|g" \
  "$specs_source" > "$specs_local"
host_gcc="$(command -v gcc)"
cat > "$tool_root/bin/x86_64-linux-musl-gcc" <<EOF
#!/bin/sh
exec "$host_gcc" -specs "$specs_local" "\$@"
EOF
chmod 0755 "$tool_root/bin/x86_64-linux-musl-gcc"

export PATH="$tool_root/bin:$prefix/usr/bin:$PATH"
export PYTHONPATH="$prefix/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"
export LD_LIBRARY_PATH="$prefix/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PI_SANDBOX_SOURCE_CACHE="$source_cache"

package_version="$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$package_root/package.json" | head -n 1)"
[[ "$package_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'package.json version is missing or invalid\n' >&2; exit 1; }
runtime_version="${PI_SANDBOX_RUNTIME_VERSION:-$package_version}"
plugin_major="${package_version%%.*}"
max_plugin_version_exclusive="$((plugin_major + 1)).0.0"

export CC="$tool_root/bin/x86_64-linux-musl-gcc"
export SANDBOX_KERNEL_INCLUDE="$prefix/usr/include"
export SANDBOX_KERNEL_MULTIARCH_INCLUDE="$prefix/usr/include/x86_64-linux-gnu"
bash "$script_dir/build-linux-runtime.sh" "$runtime_version" "$package_version" \
  "$max_plugin_version_exclusive" x64 "$output_root/x64"

zig_tarball="$tool_root/$zig_archive"
if [[ ! -f "$zig_tarball" ]]; then
  partial="$zig_tarball.part.$$"
  curl --fail --location --retry 2 --connect-timeout 10 --max-time 300 \
    "https://ziglang.org/download/$zig_version/$zig_archive" -o "$partial"
  printf '%s  %s\n' "$zig_sha256" "$partial" | sha256sum --check --status
  mv -- "$partial" "$zig_tarball"
fi
printf '%s  %s\n' "$zig_sha256" "$zig_tarball" | sha256sum --check --status
zig_root="$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-zig.XXXXXX")"
tar -xJf "$zig_tarball" --strip-components=1 -C "$zig_root"

cat > "$tool_root/bin/aarch64-linux-musl-gcc" <<EOF
#!/bin/sh
for argument in "\$@"; do
  if [ "\$argument" = '-Wl,--version' ]; then
    printf 'LLD 0.17.1 (Zig toolchain)\\n'
    exit 0
  fi
done
exec "$zig_root/zig" cc -target aarch64-linux-musl "\$@"
EOF
chmod 0755 "$tool_root/bin/aarch64-linux-musl-gcc"
native_probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-x64-probe.XXXXXX")"
trap 'rm -rf -- "$native_probe_dir" "$zig_root"' EXIT
tar -xzf "$output_root/x64/pi-sandbox-linux-x64.tar.gz" -C "$native_probe_dir"

export CC="$tool_root/bin/aarch64-linux-musl-gcc"
export ALLOW_CROSS_BUILD=1
export SKIP_NAMESPACE_SMOKE=1
export BWRAP_HELP_BINARY="$native_probe_dir/bwrap"
export SANDBOX_KERNEL_INCLUDE=
export SANDBOX_KERNEL_MULTIARCH_INCLUDE=
bash "$script_dir/build-linux-runtime.sh" "$runtime_version" "$package_version" \
  "$max_plugin_version_exclusive" arm64 "$output_root/arm64"

printf 'Built Linux x64 and ARM64 runtime archives under %s\n' "$output_root"
python3 "$script_dir/verify-linux-runtime-archives.py" "$output_root" "$runtime_version" \
  "$package_version" "$max_plugin_version_exclusive"
