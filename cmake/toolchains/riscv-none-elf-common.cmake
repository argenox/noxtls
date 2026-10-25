# Shared part of the riscv-none-elf-rv*.cmake toolchain files.
# Expects NOXTLS_RISCV_CPU_FLAGS to be set by the including file.
#
# The compiler is found on PATH, or under RISCV_GNU_TOOLCHAIN_ROOT (CMake or
# environment variable), e.g. the xPack GNU RISC-V Embedded GCC:
#   -DRISCV_GNU_TOOLCHAIN_ROOT=D:/Gnu/xpack-riscv-none-elf-gcc-15.2.0-1

include("${CMAKE_CURRENT_LIST_DIR}/riscv-none-elf.cmake")

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES NOXTLS_RISCV_CPU_FLAGS)

# medany: the images are linked at 0x80000000, outside medlow's +-2 GB on RV64.
set(CMAKE_C_FLAGS_INIT "${NOXTLS_RISCV_CPU_FLAGS} -mcmodel=medany -ffunction-sections -fdata-sections")
set(CMAKE_ASM_FLAGS_INIT "${NOXTLS_RISCV_CPU_FLAGS} -mcmodel=medany")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${NOXTLS_RISCV_CPU_FLAGS} -mcmodel=medany --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections")
