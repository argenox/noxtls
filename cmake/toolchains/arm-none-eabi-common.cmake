# Shared part of the arm-none-eabi-cortex-m*.cmake toolchain files.
# Expects NOXTLS_ARM_CPU_FLAGS to be set by the including file.

include("${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi.cmake")

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES NOXTLS_ARM_CPU_FLAGS)

set(CMAKE_C_FLAGS_INIT "${NOXTLS_ARM_CPU_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_ASM_FLAGS_INIT "${NOXTLS_ARM_CPU_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${NOXTLS_ARM_CPU_FLAGS} --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections")
