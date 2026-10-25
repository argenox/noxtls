#!/usr/bin/env bash
# Host source-based coverage (clang -fprofile-instr-generate -fcoverage-mapping)
# of the post-quantum modules under the ut/pq KAT suites.
#
# usage: scripts/pq_coverage.sh [--build-dir DIR] [--min-lines PCT] [--all] [--html DIR]
#                               [-- extra cmake args]
#
#   --min-lines PCT  fail (exit 1) if line coverage of pkc/mlkem, pkc/mldsa,
#                    pkc/falcon, pkc/lms or pkc/xmss (each module aggregated) is below PCT
#   --all            also report pkc/slhdsa
#   --html DIR       additionally write an llvm-cov HTML report
#
# Environment: CC (default clang), LLVM_PROFDATA / LLVM_COV (default
# llvm-profdata / llvm-cov on PATH).  On Windows the clang default
# (x86_64-pc-windows-msvc) target ships the profile runtime; the MinGW target
# usually does not.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build-pq-coverage"
MIN_LINES=""
ALL=0
HTML=""
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --min-lines) MIN_LINES="$2"; shift 2 ;;
        --all) ALL=1; shift ;;
        --html) HTML="$2"; shift 2 ;;
        --) shift; EXTRA=("$@"); break ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

CC="${CC:-clang}"
LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV="${LLVM_COV:-llvm-cov}"
COVF="-fprofile-instr-generate -fcoverage-mapping"
TESTS=(pq_mlkem_kat pq_mldsa_kat pq_falcon_kat pq_slhdsa_kat pq_hbs_api)
TESTS+=(pq_lms_kat)
TESTS+=(pq_xmss_kat)

GEN=()
if command -v ninja >/dev/null 2>&1; then GEN=(-G Ninja); fi
cmake -S "$ROOT" -B "$BUILD_DIR" "${GEN[@]}" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=Debug \
    "-DCMAKE_C_FLAGS=$COVF -O1 -D_CRT_SECURE_NO_WARNINGS" \
    "-DCMAKE_EXE_LINKER_FLAGS=-fprofile-instr-generate" \
    -DBUILD_TESTS=ON -DBUILD_APPLICATIONS=OFF \
    -DNOXTLS_CFG_FEATURE_ML_KEM=ON -DNOXTLS_CFG_FEATURE_ML_DSA=ON -DNOXTLS_CFG_FEATURE_FALCON=ON \
    -DNOXTLS_CFG_FEATURE_SLH_DSA=ON -DNOXTLS_CFG_FEATURE_LMS_HSS=ON -DNOXTLS_CFG_FEATURE_XMSS=ON \
    "${EXTRA[@]}" > "$BUILD_DIR.cfg.log" 2>&1 || { tail -30 "$BUILD_DIR.cfg.log"; exit 1; }
cmake --build "$BUILD_DIR" --target "${TESTS[@]}" -j 8 > "$BUILD_DIR.build.log" 2>&1 \
    || { grep -E "error|FAILED" "$BUILD_DIR.build.log" | head -30; exit 1; }

PROF="$BUILD_DIR/profiles"
rm -rf "$PROF"; mkdir -p "$PROF"
OBJS=()
for t in "${TESTS[@]}"; do
    exe="$(find "$BUILD_DIR/ut/pq" -maxdepth 1 -type f \( -name "$t" -o -name "$t.exe" \) | head -1)"
    [ -n "$exe" ] || { echo "missing test binary $t" >&2; exit 1; }
    LLVM_PROFILE_FILE="$PROF/$t.profraw" "$exe" | tail -1
    OBJS+=("-object" "$exe")
done
"$LLVM_PROFDATA" merge -sparse -o "$PROF/pq.profdata" "$PROF"/*.profraw

MODULES=(mlkem mldsa falcon lms xmss)
[ "$ALL" = 1 ] && MODULES+=(slhdsa)
SRCS=()
for m in "${MODULES[@]}"; do
    while IFS= read -r f; do SRCS+=("$f"); done < <(find "$ROOT/noxtls-lib/pkc/$m" -name '*.c' | sort)
done

# The first -object is passed positionally, the rest with -object.
FIRST="${OBJS[1]}"
REST=("${OBJS[@]:2}")
"$LLVM_COV" report "$FIRST" "${REST[@]}" -instr-profile="$PROF/pq.profdata" "${SRCS[@]}" | tee "$PROF/report.txt"
if [ -n "$HTML" ]; then
    "$LLVM_COV" show "$FIRST" "${REST[@]}" -instr-profile="$PROF/pq.profdata" -format=html \
        -output-dir="$HTML" "${SRCS[@]}"
fi

# Per-module aggregation (lines / branches) from the JSON export.
"$LLVM_COV" export "$FIRST" "${REST[@]}" -instr-profile="$PROF/pq.profdata" -summary-only "${SRCS[@]}" \
    > "$PROF/summary.json"
PYTHON="${PYTHON:-python3}"
"$PYTHON" --version >/dev/null 2>&1 || PYTHON=python
"$PYTHON" - "$PROF/summary.json" "${MIN_LINES:-0}" "${MODULES[@]}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
minimum = float(sys.argv[2])
modules = sys.argv[3:]
agg = {m: [0, 0, 0, 0] for m in modules}
for f in data["data"][0]["files"]:
    name = f["filename"].replace("\\", "/")
    for m in modules:
        if "/pkc/%s/" % m in name:
            s = f["summary"]
            agg[m][0] += s["lines"]["covered"]; agg[m][1] += s["lines"]["count"]
            agg[m][2] += s["branches"]["covered"]; agg[m][3] += s["branches"]["count"]
rc = 0
print("\nmodule      lines             branches")
for m in modules:
    lc, lt, bc, bt = agg[m]
    lp = 100.0 * lc / lt if lt else 100.0
    bp = 100.0 * bc / bt if bt else 100.0
    print("%-10s %6d/%-6d %5.1f%%  %6d/%-6d %5.1f%%" % (m, lc, lt, lp, bc, bt, bp))
    if m in ("mlkem", "mldsa", "falcon", "lms", "xmss") and lp < minimum:
        print("  -> below the %.1f%% line-coverage threshold" % minimum)
        rc = 1
sys.exit(rc)
PY
