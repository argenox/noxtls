#!/usr/bin/env bash
# Build a NoxTLS ESP-IDF example for one IDF target (default: https_server).
# Intended for use inside espressif/idf Docker images (e.g. v6.0.1).
set -euo pipefail

TARGET="${1:?Usage: $0 <idf-target> [project-dir]}"
PROJECT_DIR="${2:-}"

if [[ -z "${PROJECT_DIR}" ]]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	PROJECT_DIR="${SCRIPT_DIR}/../../ports/esp-idf/examples/https_server"
fi

if [[ ! -f "${PROJECT_DIR}/CMakeLists.txt" ]]; then
	echo "ESP-IDF example project not found at: ${PROJECT_DIR}" >&2
	exit 1
fi

cd "${PROJECT_DIR}"

echo "Building ESP-IDF example for IDF target: ${TARGET}"
echo "Project directory: ${PROJECT_DIR}"

idf.py set-target "${TARGET}"
idf.py build

echo "Build succeeded for ${TARGET}"
