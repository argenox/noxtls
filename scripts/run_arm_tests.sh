#!/usr/bin/env bash
# Cross-build NoxTLS for Cortex-M or RISC-V and run the semihosting test images
# under QEMU.
#
# usage: scripts/run_arm_tests.sh [--cpu m4|m3|m7|m33|rv32|rv64] [--features pq|default]
#                                 [--build-dir DIR] [--jobs N] [--no-run] [-- extra cmake args]
#
#   --cpu       m4  -> cortex-m4 toolchain, qemu mps2-an386 (default)
#               m3  -> cortex-m4 code is not valid on M3; uses -mcpu=cortex-m3, mps2-an385
#               m7  -> -mcpu=cortex-m7, mps2-an500
#               m33 -> cortex-m33 toolchain, mps2-an505
#               rv32 -> riscv-none-elf rv32imac/ilp32, qemu-system-riscv32 virt
#               rv64 -> riscv-none-elf rv64imac/lp64, qemu-system-riscv64 virt
#   --features  pq      : ML-KEM, ML-DSA, Falcon, SLH-DSA, LMS/HSS, XMSS ON (default)
#               default : library defaults (PQ OFF; classic KATs only)
#   --no-run    configure + build only (no QEMU needed)
#
# Requirements: arm-none-eabi-gcc (newlib-nano) or riscv-none-elf-gcc (newlib-nano,
# e.g. the xPack build; on PATH or under $RISCV_GNU_TOOLCHAIN_ROOT), cmake >= 3.13,
# ninja (or make), and qemu-system-arm >= 6.0 or qemu-system-riscv32/64 >= 7.0 for
# running (found on PATH, via $QEMU_SYSTEM_ARM / $QEMU_SYSTEM_RISCV, or in
# "C:/Program Files/qemu" on Windows).  Each test prints
# "[probe] <op> stack=<bytes> heap=<bytes>" lines and a final
# "[arm] exit=<rc> stack_high_water=... heap_live_peak=..." summary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPU=m4
FEATURES=pq
BUILD_DIR=""
JOBS=8
RUN=1
EXTRA=()

while [ $# -gt 0 ]; do
    case "$1" in
        --cpu) CPU="$2"; shift 2 ;;
        --features) FEATURES="$2"; shift 2 ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --no-run) RUN=0; shift ;;
        --) shift; EXTRA=("$@"); break ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$CPU" in
    m4)  TC="$ROOT/cmake/toolchains/arm-none-eabi-cortex-m4.cmake"; MACHINE=mps2-an386; CPUFLAGS="" ;;
    m3)  TC="$ROOT/cmake/toolchains/arm-none-eabi-cortex-m4.cmake"; MACHINE=mps2-an385; CPUFLAGS="-mcpu=cortex-m3 -mthumb" ;;
    m7)  TC="$ROOT/cmake/toolchains/arm-none-eabi-cortex-m4.cmake"; MACHINE=mps2-an500; CPUFLAGS="-mcpu=cortex-m7 -mthumb" ;;
    m33) TC="$ROOT/cmake/toolchains/arm-none-eabi-cortex-m33.cmake"; MACHINE=mps2-an505; CPUFLAGS="" ;;
    rv32) TC="$ROOT/cmake/toolchains/riscv-none-elf-rv32imac.cmake"; MACHINE=virt; CPUFLAGS="" ;;
    rv64) TC="$ROOT/cmake/toolchains/riscv-none-elf-rv64imac.cmake"; MACHINE=virt; CPUFLAGS="" ;;
    *) echo "unsupported --cpu $CPU" >&2; exit 2 ;;
esac

case "$FEATURES" in
    pq) FEAT=(-DNOXTLS_CFG_FEATURE_ML_KEM=ON -DNOXTLS_CFG_FEATURE_ML_DSA=ON -DNOXTLS_CFG_FEATURE_FALCON=ON
              -DNOXTLS_CFG_FEATURE_SLH_DSA=ON -DNOXTLS_CFG_FEATURE_LMS_HSS=ON -DNOXTLS_CFG_FEATURE_XMSS=ON) ;;
    default) FEAT=() ;;
    *) echo "unsupported --features $FEATURES" >&2; exit 2 ;;
esac

[ -n "$BUILD_DIR" ] || BUILD_DIR="$ROOT/build-arm-$CPU-$FEATURES"

# Locate QEMU (only needed when running).
case "$CPU" in
    rv32) QNAME=qemu-system-riscv32; QVAR=QEMU_SYSTEM_RISCV ;;
    rv64) QNAME=qemu-system-riscv64; QVAR=QEMU_SYSTEM_RISCV ;;
    *)    QNAME=qemu-system-arm; QVAR=QEMU_SYSTEM_ARM ;;
esac
QEMU_BIN="${!QVAR:-}"
if [ -z "$QEMU_BIN" ]; then
    if command -v "$QNAME" >/dev/null 2>&1; then
        QEMU_BIN="$(command -v "$QNAME")"
    elif [ -x "/c/Program Files/qemu/$QNAME.exe" ]; then
        QEMU_BIN="/c/Program Files/qemu/$QNAME.exe"
    fi
fi
if [ -n "$QEMU_BIN" ]; then
    export "$QVAR=$QEMU_BIN"
    export PATH="$(dirname "$QEMU_BIN"):$PATH"
elif [ "$RUN" = 1 ]; then
    echo "$QNAME not found (set $QVAR or use --no-run)" >&2
    exit 2
fi

GEN=()
if command -v ninja >/dev/null 2>&1; then GEN=(-G Ninja); fi
CPUARG=()
if [ -n "$CPUFLAGS" ]; then CPUARG=("-DNOXTLS_ARM_CPU_FLAGS=$CPUFLAGS"); fi

cmake -S "$ROOT/ut/pq/arm" -B "$BUILD_DIR" "${GEN[@]}" \
    -DCMAKE_TOOLCHAIN_FILE="$TC" -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DNOXTLS_ARM_MACHINE="$MACHINE" "${CPUARG[@]}" "${FEAT[@]}" "${EXTRA[@]}"
cmake --build "$BUILD_DIR" -j "$JOBS"

if [ "$RUN" = 1 ]; then
    ctest --test-dir "$BUILD_DIR" -j "$JOBS" --output-on-failure -V 2>&1 \
        | tee "$BUILD_DIR/arm-test.log" \
        | grep -E '^\s*[0-9]+: \[(pq|probe|arm)\]|tests passed|tests failed|Test +#' || true
    # ctest's exit status is lost in the pipe; re-derive it from the log.
    if grep -q "100% tests passed" "$BUILD_DIR/arm-test.log"; then
        echo "ARM tests: all passed ($MACHINE)"  # same wording for every target; tools parse it
    else
        echo "ARM tests: FAILURES ($MACHINE), see $BUILD_DIR/arm-test.log" >&2
        exit 1
    fi
fi
