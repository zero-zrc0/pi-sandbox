#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  printf 'usage: build-linux-runtime.sh RUNTIME_VERSION MIN_PLUGIN_VERSION MAX_PLUGIN_VERSION_EXCLUSIVE ARCH OUTPUT_DIR\n' >&2
  exit 2
fi

runtime_version="$1"
min_plugin_version="$2"
max_plugin_version_exclusive="$3"
target_arch="$4"
output_dir="$5"
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
package_root="$(cd -- "$script_dir/.." && pwd)"

case "$target_arch" in
  x64) expected_machine='Advanced Micro Devices X86-64'; native_arch='x86_64' ;;
  arm64) expected_machine='AArch64'; native_arch='aarch64' ;;
  *) printf 'unsupported target architecture: %s\n' "$target_arch" >&2; exit 1 ;;
esac
build_arch="$(uname -m)"
is_cross_build=0
if [[ "$target_arch:$build_arch" != "x64:x86_64" && "$target_arch:$build_arch" != "x64:amd64" &&
      "$target_arch:$build_arch" != "arm64:aarch64" && "$target_arch:$build_arch" != "arm64:arm64" ]]; then
  if [[ "${ALLOW_CROSS_BUILD:-0}" != "1" ]]; then
    printf 'target architecture %s does not match build machine %s\n' "$target_arch" "$build_arch" >&2
    exit 1
  fi
  is_cross_build=1
fi

readonly bwrap_version='0.13.1'
readonly bwrap_source_commit='362936aea0d5c6e70f7af75d2d44b5a914cb4ba2'
readonly bwrap_archive='bubblewrap-0.13.1.tar.xz'
readonly bwrap_archive_sha256='0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d'
readonly libcap_version='2.75'
readonly libcap_archive='libcap2_2.75.orig.tar.xz'
readonly libcap_archive_sha256='de4e7e064c9ba451d5234dd46e897d7c71c96a9ebf9a0c445bc04f4742d83632'

for command in meson ninja pkg-config make readelf tar xz curl sha256sum python3; do
  command -v "$command" >/dev/null || { printf 'required build command is missing: %s\n' "$command" >&2; exit 1; }
done
cc="${CC:-musl-gcc}"
command -v "$cc" >/dev/null || { printf 'musl compiler is missing: %s\n' "$cc" >&2; exit 1; }

source_cache="${PI_SANDBOX_SOURCE_CACHE:-${TMPDIR:-/tmp}/pi-sandbox-runtime-source}"
mkdir -p -- "$source_cache"
fetch_verified() {
  local url="$1" expected="$2" file="$3" partial="${3}.part.$$"
  if [[ ! -f "$file" ]]; then
    curl --fail --location --retry 2 --connect-timeout 10 --max-time 120 "$url" -o "$partial"
    printf '%s  %s\n' "$expected" "$partial" | sha256sum --check --status
    mv -- "$partial" "$file"
  fi
  printf '%s  %s\n' "$expected" "$file" | sha256sum --check --status || {
    printf 'cached source archive failed SHA-256 verification: %s\n' "$file" >&2
    return 1
  }
}

bwrap_tarball="$source_cache/$bwrap_archive"
libcap_tarball="$source_cache/$libcap_archive"
fetch_verified "https://github.com/containers/bubblewrap/releases/download/v${bwrap_version}/${bwrap_archive}" \
  "$bwrap_archive_sha256" "$bwrap_tarball"
fetch_verified "https://deb.debian.org/debian/pool/main/libc/libcap2/${libcap_archive}" \
  "$libcap_archive_sha256" "$libcap_tarball"

build_root="$(mktemp -d "${TMPDIR:-/tmp}/pi-sandbox-linux-runtime.XXXXXX")"
trap 'rm -rf -- "$build_root"' EXIT
runtime_dir="$build_root/runtime"
mkdir -p -- "$runtime_dir" "$build_root/bwrap-source" "$build_root/libcap-source" "$build_root/libcap-prefix"
tar -xJf "$bwrap_tarball" -C "$build_root/bwrap-source"
tar -xJf "$libcap_tarball" -C "$build_root/libcap-source"
bwrap_source="$build_root/bwrap-source/bubblewrap-$bwrap_version"
libcap_source="$build_root/libcap-source/libcap-$libcap_version"
[[ -f "$bwrap_source/COPYING" ]] || { printf 'pinned Bubblewrap source archive is missing COPYING\n' >&2; exit 1; }
[[ -d "$libcap_source/libcap" ]] || { printf 'pinned libcap source archive has an unexpected layout\n' >&2; exit 1; }

libcap_prefix="$build_root/libcap-prefix"
mkdir -p -- "$libcap_prefix/lib/pkgconfig" "$libcap_prefix/include/linux" "$libcap_prefix/include/sys"
make -C "$libcap_source/libcap" -j"$(nproc)" libcap.a CC="$cc" BUILD_CC=cc AR=ar RANLIB=ranlib
install -m 0644 "$libcap_source/libcap/libcap.a" "$libcap_prefix/lib/libcap.a"
install -m 0644 "$libcap_source/libcap/include/uapi/linux/capability.h" "$libcap_prefix/include/linux/capability.h"
install -m 0644 "$libcap_source/libcap/include/sys/capability.h" "$libcap_prefix/include/sys/capability.h"
cat > "$libcap_prefix/lib/pkgconfig/libcap.pc" <<EOF
prefix=$libcap_prefix
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: libcap
Description: Linux capabilities
Version: $libcap_version
Libs: -L\${libdir} -lcap
Cflags: -I\${includedir}
EOF

export CC="$cc"
kernel_include="${SANDBOX_KERNEL_INCLUDE-/usr/include}"
kernel_multiarch_include="${SANDBOX_KERNEL_MULTIARCH_INCLUDE-}"
if [[ -n "$kernel_include" && -z "$kernel_multiarch_include" ]]; then
  kernel_multiarch_include="$kernel_include/$(gcc -dumpmachine)"
fi
kernel_cflags=()
if [[ -n "$kernel_include" ]]; then kernel_cflags+=(-idirafter "$kernel_include"); fi
if [[ -n "$kernel_multiarch_include" ]]; then kernel_cflags+=(-idirafter "$kernel_multiarch_include"); fi
export CFLAGS="-O2 -I$libcap_prefix/include ${kernel_cflags[*]}"
export LDFLAGS="-static -L$libcap_prefix/lib"
export PKG_CONFIG_LIBDIR="$libcap_prefix/lib/pkgconfig"
export PKG_CONFIG_PATH="$PKG_CONFIG_LIBDIR"
meson_args=(--prefix=/usr --buildtype=release -Dselinux=disabled -Dman=disabled -Dtests=false)
if (( is_cross_build )); then
  [[ -n "${BWRAP_HELP_BINARY:-}" && -x "$BWRAP_HELP_BINARY" ]] || {
    printf 'cross builds require a native bwrap binary from the same pinned source for option verification\n' >&2
    exit 1
  }
  cross_file="$build_root/target-cross.ini"
  pkg_config="$(command -v pkg-config)"
  cat > "$cross_file" <<EOF
[binaries]
c = '$cc'
c_ld = 'lld'
pkg-config = '$pkg_config'

[properties]
needs_exe_wrapper = true

[host_machine]
system = 'linux'
cpu_family = '$native_arch'
cpu = '$native_arch'
endian = 'little'
EOF
  meson_args+=(--cross-file "$cross_file")
fi
meson setup "$build_root/bwrap-build" "$bwrap_source" "${meson_args[@]}"
meson compile -C "$build_root/bwrap-build"
install -m 0755 "$build_root/bwrap-build/bwrap" "$runtime_dir/bwrap"

license_file="$(find "$libcap_source" -maxdepth 1 -type f \( -iname 'license' -o -iname 'copying' \) -print -quit)"
[[ -n "$license_file" ]] || { printf 'pinned libcap source archive does not contain its license text\n' >&2; exit 1; }
{
  printf 'Bubblewrap %s license\n\n' "$bwrap_version"
  cat "$bwrap_source/COPYING"
  printf '\n\nlibcap %s license\n\n' "$libcap_version"
  cat "$license_file"
} > "$runtime_dir/bwrap.LICENSE"

help_output="$build_root/bwrap-help.txt"
probe_bwrap="$runtime_dir/bwrap"
if (( is_cross_build )); then probe_bwrap="$BWRAP_HELP_BINARY"; fi
"$probe_bwrap" --help > "$help_output" 2>&1
for flag in --die-with-parent --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
  --disable-userns --assert-userns-disabled --ro-bind --dev --proc --bind-fd --ro-bind-fd \
  --tmpfs --dir --file --clearenv --setenv --chdir; do
  if ! grep --fixed-strings --quiet -- "$flag" "$help_output"; then
    printf 'built bubblewrap lacks required option %s\n' "$flag" >&2
    exit 1
  fi
done
actual_bwrap_version="$("$probe_bwrap" --version | sed -E 's/^bubblewrap ([0-9]+\.[0-9]+\.[0-9]+).*$/\1/')"
[[ "$actual_bwrap_version" == "$bwrap_version" ]] || {
  printf 'bubblewrap version mismatch: expected %s, got %s\n' "$bwrap_version" "$actual_bwrap_version" >&2
  exit 1
}

CC="$cc" SANDBOX_CFLAGS="${kernel_cflags[*]}" SANDBOX_LDFLAGS='-static' \
  "$script_dir/../src/sandbox/backend/linux/build.sh" "$runtime_dir/linux-sandbox" "$runtime_dir/linux-egress-bridge"
for binary in "$runtime_dir/linux-sandbox" "$runtime_dir/linux-egress-bridge" "$runtime_dir/bwrap"; do
  machine="$(readelf --file-header "$binary" | sed -n 's/^  Machine:[[:space:]]*//p')"
  [[ "$machine" == "$expected_machine" ]] || { printf '%s has unexpected architecture: %s\n' "$binary" "$machine" >&2; exit 1; }
  if readelf --program-headers "$binary" | grep --quiet 'INTERP'; then
    printf '%s is dynamically linked; runtime packages must use the musl static target\n' "$binary" >&2
    exit 1
  fi
done

if [[ "${SKIP_NAMESPACE_SMOKE:-0}" == "1" ]]; then
  printf 'Skipped native namespace smoke for %s; the target cannot be run on this builder\n' "$target_arch"
else
  "$runtime_dir/bwrap" --die-with-parent --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
    --disable-userns --assert-userns-disabled --ro-bind / / --dev /dev --proc /proc \
    --clearenv --setenv PATH /usr/bin:/bin --chdir / -- /usr/bin/true
  printf 'Bubblewrap user-namespace smoke passed for %s\n' "$target_arch"
fi

python3 "$script_dir/write-linux-runtime-manifest.py" "$runtime_dir" "$target_arch" \
  "$runtime_version" "$min_plugin_version" "$max_plugin_version_exclusive" "$bwrap_version" "$bwrap_source_commit"

mkdir -p -- "$output_dir"
archive_name="pi-sandbox-linux-$target_arch.tar.gz"
tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime='2020-01-01 00:00:00Z' \
  -cf - -C "$runtime_dir" linux-sandbox linux-egress-bridge bwrap bwrap.LICENSE runtime.json | gzip -n > "$build_root/$archive_name"
archive_size="$(stat -c '%s' "$build_root/$archive_name")"
if (( archive_size > 536870912 )); then
  printf 'runtime archive exceeds the 512 MiB catalog limit\n' >&2
  exit 1
fi
install -m 0644 "$build_root/$archive_name" "$output_dir/$archive_name"
install -m 0644 "$runtime_dir/runtime.json" "$output_dir/pi-sandbox-linux-$target_arch.runtime.json"
printf '%s\n' "$archive_size" > "$output_dir/$archive_name.size"
(cd -- "$output_dir" && sha256sum "$archive_name" > "$archive_name.sha256")
printf 'Built Linux %s static musl runtime %s with bubblewrap %s (%s)\n' \
  "$target_arch" "$runtime_version" "$bwrap_version" "$bwrap_source_commit"
printf 'Archive: %s/%s (%s bytes)\n' "$output_dir" "$archive_name" "$archive_size"
