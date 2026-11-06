#!/bin/bash
# Builds NoxTLS with the ESP32-S31 accelerator ports and links the RAM-loaded hardware check.
# usage: build.sh <noxadk-root> <outdir>
set -e
ROOT=${1:-/e/Works_NoxADK_ESP32S31_Port/noxadk}
OUT=${2:-/tmp/noxtls_s31}
HERE="$(cd "$(dirname "$0")" && pwd)"
NOXTLS="$HERE/../.."
DL=$ROOT/components/nox-driver-lib
S31=$DL/platforms/esp32s31
TC=/c/Espressif/tools/riscv32-esp-elf/esp-15.2.0_20251204/riscv32-esp-elf/bin
mkdir -p "$OUT"
cmake -S "$NOXTLS" -B "$OUT/lib" -G Ninja -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/toolchains/riscv32-esp32s31-elf-gcc.cmake" \
  -DNOXTLS_CFG_FEATURE_ESP32S31_HW_ACCEL=ON -DNOXTLS_ESP32S31_DRIVER_DIR="$DL" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$OUT/lib" --target noxtls_hash noxtls_encryption noxtls_pkc noxtls_drbg noxtls_common
FLAGS="-march=rv32imafc_zicsr_zifencei_zaamo_zalrsc -mabi=ilp32f -mtune=esp-base -O2 -ffunction-sections -fdata-sections"
INC="-I$NOXTLS -I$NOXTLS/noxtls-lib -I$NOXTLS/noxtls-lib/common -I$NOXTLS/noxtls-lib/mdigest -I$NOXTLS/noxtls-lib/mdigest/sha256 \
 -I$NOXTLS/noxtls-lib/mdigest/sha512 -I$NOXTLS/noxtls-lib/encryption/aes -I$NOXTLS/noxtls-lib/pkc/ecc -I$NOXTLS/noxtls-lib/pkc/ecdsa \
 -I$OUT/lib $(find "$OUT/lib" -name 'noxtls_config*.h' -printf '-I%h\n' | sort -u | tr '\n' ' ') \
 -I$DL/drivers -I$DL/drivers/hash -I$DL/drivers/aes -I$DL/drivers/pka -I$S31/common -I$S31/sha -I$S31/aes -I$S31/pka -I$ROOT/tools/arch/esp32s31"
DRV="$S31/sha/esp32s31_sha.c $S31/aes/esp32s31_aes.c $S31/pka/esp32s31_pka.c"
"$TC/riscv32-esp-elf-gcc.exe" $FLAGS $INC -DNOXTLS_FEATURE_ESP32S31_HW_ACCEL=1 -nostartfiles --specs=nano.specs \
  -Wl,--gc-sections -Wl,--no-warn-rwx-segments -T "$ROOT/tools/arch/esp32s31/esp32s31_ram.ld" -Wl,-Map,"$OUT/hw.map" \
  "$HERE/hw_noxtls.c" $DRV "$ROOT/tools/arch/esp32s31/system_esp32s31.c" "$ROOT/tools/arch/esp32s31/syscalls.c" \
  "$ROOT/tools/arch/esp32s31/startup_esp32s31.S" \
  -Wl,--start-group $(find "$OUT/lib" -name '*.a' | tr '\n' ' ') -Wl,--end-group -lm -o "$OUT/hw_noxtls.elf"
"$TC/riscv32-esp-elf-size.exe" "$OUT/hw_noxtls.elf"
