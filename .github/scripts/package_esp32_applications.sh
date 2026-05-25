#!/usr/bin/env bash
# Package ports/esp-idf/examples into noxtls-esp32-applications-<version>.zip
# with LICENSE.md at the archive root.
set -euo pipefail

ROOT="$(cd "${1:-.}" && pwd)"
OUT_DIR="${2:-release-assets}"
VERSION="${3:?version required}"

if [[ "${OUT_DIR}" != /* ]]; then
  OUT_DIR="${ROOT}/${OUT_DIR}"
fi

EXAMPLES_DIR="${ROOT}/ports/esp-idf/examples"
LICENSE_FILE="${ROOT}/LICENSE.md"
ARCHIVE_NAME="noxtls-esp32-applications-${VERSION}.zip"
OUTPUT="${OUT_DIR}/${ARCHIVE_NAME}"

if [[ ! -d "${EXAMPLES_DIR}" ]]; then
  echo "Missing ESP-IDF examples directory: ${EXAMPLES_DIR}" >&2
  exit 1
fi

if [[ ! -f "${LICENSE_FILE}" ]]; then
  echo "Missing LICENSE file: ${LICENSE_FILE}" >&2
  exit 1
fi

STAGING="$(mktemp -d)"
cleanup() {
  rm -rf "${STAGING}"
}
trap cleanup EXIT

cp "${LICENSE_FILE}" "${STAGING}/LICENSE.md"
cp "${EXAMPLES_DIR}/README.md" "${STAGING}/README.md"
rsync -a \
  --exclude='sdkconfig' \
  --exclude='sdkconfig.old' \
  --exclude='build/' \
  "${EXAMPLES_DIR}/" "${STAGING}/"

# Standalone zip: add registry manifest to each example (not used for in-repo builds).
STANDALONE_MANIFEST="${EXAMPLES_DIR}/idf_component.yml.standalone"
if [[ ! -f "${STANDALONE_MANIFEST}" ]]; then
  echo "Missing standalone manifest template: ${STANDALONE_MANIFEST}" >&2
  exit 1
fi
for example_main in "${STAGING}"/*/main; do
  if [[ -d "${example_main}" ]]; then
    cp "${STANDALONE_MANIFEST}" "${example_main}/idf_component.yml"
  fi
done

# Standalone builds use the registry component (argenox__noxtls), not REQUIRES esp-idf.
STAGING="${STAGING}" python3 - <<'PY'
import os
import pathlib

staging = pathlib.Path(os.environ["STAGING"])
for cmake in staging.glob("*/main/CMakeLists.txt"):
    text = cmake.read_text(encoding="utf-8")
    updated = text.replace("REQUIRES esp-idf", "REQUIRES argenox__noxtls")
    updated = updated.replace("esp-idf\n", "argenox__noxtls\n")
    if updated != text:
        cmake.write_text(updated, encoding="utf-8")
        print(f"Patched {cmake.relative_to(staging)} for registry component")
PY

mkdir -p "${OUT_DIR}"
(
  cd "${STAGING}"
  zip -r "${OUTPUT}" .
)

echo "Created ${OUTPUT}"
unzip -l "${OUTPUT}" | head -30
