#!/usr/bin/env bash
# Stage a self-contained ESP-IDF component for registry upload.
# The in-repo port lives at ports/esp-idf and expects the library at ../../ ;
# the registry package bundles lib_root/ inside the component directory.
set -euo pipefail

ROOT="$(cd "${1:-.}" && pwd)"
OUT="${2:?output staging directory required}"

if [[ ! -f "${ROOT}/ports/esp-idf/idf_component.yml" ]]; then
  echo "Run from NoxTLS source root (ports/esp-idf/idf_component.yml missing)" >&2
  exit 1
fi

rm -rf "${OUT}"
mkdir -p "${OUT}/lib_root"

rsync -a \
  --exclude='examples/' \
  "${ROOT}/ports/esp-idf/" "${OUT}/"

rsync -a "${ROOT}/noxtls-lib/" "${OUT}/lib_root/noxtls-lib/"
rsync -a "${ROOT}/utility/" "${OUT}/lib_root/utility/"

for f in CMakeLists.txt noxtls_check_config.h noxtls_common.h noxtls_version.h; do
  cp "${ROOT}/${f}" "${OUT}/lib_root/${f}"
done

echo "Staged ESP-IDF component at ${OUT}"
echo "  lib_root/noxtls-lib: $(find "${OUT}/lib_root/noxtls-lib" -name '*.c' | wc -l) C files"
echo "  (examples/ excluded — shipped separately in noxtls-esp32-applications zip)"
