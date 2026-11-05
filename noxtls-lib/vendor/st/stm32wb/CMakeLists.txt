# STM32WB5x hardware backend (STM32WB50 / WB55 / WB5M, CPU1).
# Register-level drivers for AES1 (ECB, CBC, CTR, GCM/GMAC, CCM), the PKA (P-256 ECC, ECDSA,
# modular exponentiation), the RNG and the HSEM ownership layer. The accelerator port glue
# (noxtls_stm32wb_port_*.c) is compiled into the algorithm libraries by noxtls-lib/encryption,
# pkc and drbg; this library holds the drivers.
#
# Build: -DNOXTLS_CFG_FEATURE_STM32WB_HW_ACCEL=ON (with -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard
# for the target). Settings live in noxtls_stm32wb_config.h and can be overridden with
# NOXTLS_STM32WB_EXTRA_DEFINITIONS (for example NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA=1U).
include("${CMAKE_CURRENT_LIST_DIR}/../../../../cmake/nox_noxtls_sections.cmake")
set(NOXTLS_STM32WB_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
include(${NOXTLS_STM32WB_DIR}/noxtls_stm32wb_sources.cmake)

add_library(noxtls_stm32wb STATIC ${NOXTLS_STM32WB_DRIVER_SOURCES})
nox_noxtls_enable_sections("noxtls_stm32wb")
get_filename_component(_noxtls_stm32wb_project_root "${NOXTLS_LIB_ROOT}/.." ABSOLUTE)
target_include_directories(noxtls_stm32wb PUBLIC
  ${NOXTLS_STM32WB_DIR}
  ${_noxtls_stm32wb_project_root}
  ${NOXTLS_LIB_ROOT}
)
target_link_libraries(noxtls_stm32wb PUBLIC noxtls_common)
if(NOXTLS_STM32WB_EXTRA_DEFINITIONS)
  target_compile_definitions(noxtls_stm32wb PUBLIC ${NOXTLS_STM32WB_EXTRA_DEFINITIONS})
endif()
if(MSVC)
  target_compile_options(noxtls_stm32wb PRIVATE /wd5045)
endif()
