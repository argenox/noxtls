# RV32IMAC (32-bit, integer, multiply, atomics, compressed; ilp32 soft-float
# ABI) cross toolchain for NoxTLS, the class of ESP32-C6 / GD32VF103 parts.
#
# Static libraries only. Example:
#   cmake -S . -B build-rv32 -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/riscv-none-elf-rv32imac.cmake \
#         -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_TESTS=OFF -DBUILD_APPLICATIONS=OFF
#
# The QEMU semihosting test images run on the "virt" machine
# (scripts/run_arm_tests.sh --cpu rv32). Override the flags with
# -DNOXTLS_RISCV_CPU_FLAGS="..." (e.g. -march=rv32imc_zicsr for ESP32-C3).

set(NOXTLS_RISCV_CPU_FLAGS "-march=rv32imac_zicsr -mabi=ilp32" CACHE STRING "Target CPU flags for riscv-none-elf-gcc")
include("${CMAKE_CURRENT_LIST_DIR}/riscv-none-elf-common.cmake")
