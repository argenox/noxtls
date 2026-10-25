# Cortex-M0+ (ARMv6-M, Thumb) cross toolchain for NoxTLS.  Static libraries only;
# see arm-none-eabi-cortex-m4.cmake for a usage example.  The QEMU test image is
# not provided for M0+ (no mps2 machine); use it for compile/size checks.

set(NOXTLS_ARM_CPU_FLAGS "-mcpu=cortex-m0plus -mthumb" CACHE STRING "Target CPU flags for arm-none-eabi-gcc")
include("${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi-common.cmake")
