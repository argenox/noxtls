# Cortex-M33 (ARMv8-M Mainline, Thumb-2, soft-float ABI) cross toolchain for NoxTLS.
# Static libraries only; see arm-none-eabi-cortex-m4.cmake for a usage example.
# The PQ semihosting test image runs on QEMU's mps2-an505 with this toolchain
# (scripts/run_arm_tests.sh --cpu m33).

set(NOXTLS_ARM_CPU_FLAGS "-mcpu=cortex-m33 -mthumb" CACHE STRING "Target CPU flags for arm-none-eabi-gcc")
include("${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi-common.cmake")
