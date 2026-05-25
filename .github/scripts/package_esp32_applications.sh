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
rsync -a \
  --exclude='sdkconfig' \
  --exclude='sdkconfig.old' \
  --exclude='build/' \
  "${EXAMPLES_DIR}/" "${STAGING}/"

mkdir -p "${OUT_DIR}"
(
  cd "${STAGING}"
  zip -r "${OUTPUT}" .
)

echo "Created ${OUTPUT}"
unzip -l "${OUTPUT}" | head -30
