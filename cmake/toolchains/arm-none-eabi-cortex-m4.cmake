# Cortex-M4 (ARMv7E-M, Thumb-2, soft-float ABI) cross toolchain for NoxTLS.
#
# Static libraries only.  Example (library with the post-quantum suites ON):
#   cmake -S . -B build-m4 -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi-cortex-m4.cmake \
#         -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_TESTS=OFF -DBUILD_APPLICATIONS=OFF \
#         -DNOXTLS_CFG_FEATURE_ML_KEM=ON -DNOXTLS_CFG_FEATURE_ML_DSA=ON -DNOXTLS_CFG_FEATURE_FALCON=ON
#   cmake --build build-m4
#
# The QEMU semihosting test image lives in ut/pq/arm (see scripts/run_arm_tests.sh).
# Override the CPU flags with -DNOXTLS_ARM_CPU_FLAGS="..." (e.g. to add an FPU ABI).

set(NOXTLS_ARM_CPU_FLAGS "-mcpu=cortex-m4 -mthumb" CACHE STRING "Target CPU flags for arm-none-eabi-gcc")
include("${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi-common.cmake")
