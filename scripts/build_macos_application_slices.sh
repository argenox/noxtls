#!/usr/bin/env bash
# Build all NoxTLS application binaries for macOS arm64 and x86_64.
# Invoked by the CMake target noxtls_macos_application_slices.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BUILD_TYPE="${2:-Release}"
shift 2 2>/dev/null || true
EXTRA_CMAKE_ARGS=("$@")

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build_macos_application_slices.sh: requires macOS (Darwin)" >&2
  exit 1
fi

for arch in arm64 x86_64; do
  build_dir="${ROOT}/build-apps-${arch}"
  binary_dir="${ROOT}/binary-${arch}"
  echo "=== NoxTLS applications (${arch}) ==="
  cmake -S "${ROOT}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_TESTS=OFF \
    -DBUILD_APPLICATIONS=ON \
    -DCMAKE_OSX_ARCHITECTURES="${arch}" \
    -DNOXTLS_APPLICATIONS_BINARY_DIR="${binary_dir}" \
    "${EXTRA_CMAKE_ARGS[@]}"
  cmake --build "${build_dir}" --parallel
  echo "Output: ${binary_dir}"
done

echo "macOS application slices ready under ${ROOT}/binary-arm64 and ${ROOT}/binary-x86_64"
