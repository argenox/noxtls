# RV64IMAC (64-bit, integer, multiply, atomics, compressed; lp64 soft-float
# ABI) cross toolchain for NoxTLS. Used to check the library on a 64-bit
# bare-metal target (scripts/run_arm_tests.sh --cpu rv64, QEMU "virt").

set(NOXTLS_RISCV_CPU_FLAGS "-march=rv64imac_zicsr -mabi=lp64" CACHE STRING "Target CPU flags for riscv-none-elf-gcc")
include("${CMAKE_CURRENT_LIST_DIR}/riscv-none-elf-common.cmake")
set(CMAKE_SYSTEM_PROCESSOR riscv64)
