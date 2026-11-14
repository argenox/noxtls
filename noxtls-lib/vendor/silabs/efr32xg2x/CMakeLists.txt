# EFR32xG2x (Silicon Labs Series 2) hardware backend (EFR32MG26 and relatives).
# Register-level drivers for the RADIOAES BA411E engine (AES-ECB / CBC / CTR /
# CCM) and the Secure Engine mailbox (TRNG, SHA-2 block compression, P-256 /
# P-384 point multiply, ECDH and ECDSA). The accelerator port glue
# (noxtls_efr32_port_*.c) is compiled into the algorithm libraries by
# noxtls-lib/encryption, mdigest, pkc and drbg; this library holds the drivers.
#
# NOXTLS_EFR32_EXTRA_DEFINITIONS: optional list of NOXTLS_EFR32_CONFIG_* overrides
# (for example NOXTLS_EFR32_CONFIG_NONSECURE=1 or the small budgets of the host tests).
# The backend needs no vendor SDK: register maps are Argenox definitions (noxtls_efr32_regs.h).
# Target builds only need the compiler (for example -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard).
include("${CMAKE_CURRENT_LIST_DIR}/../../../../cmake/nox_noxtls_sections.cmake")
set(NOXTLS_EFR32_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
include(${NOXTLS_EFR32_DIR}/noxtls_efr32_sources.cmake)

set(_noxtls_efr32_sources ${NOXTLS_EFR32_DRIVER_SOURCES})

add_library(noxtls_efr32 STATIC ${_noxtls_efr32_sources})
nox_noxtls_enable_sections("noxtls_efr32")
get_filename_component(_noxtls_efr32_project_root "${NOXTLS_LIB_ROOT}/.." ABSOLUTE)
target_include_directories(noxtls_efr32 PUBLIC
  ${NOXTLS_EFR32_DIR}
  ${_noxtls_efr32_project_root}
  ${NOXTLS_LIB_ROOT}
)
target_link_libraries(noxtls_efr32 PUBLIC noxtls_common)
if(NOXTLS_EFR32_EXTRA_DEFINITIONS)
  target_compile_definitions(noxtls_efr32 PUBLIC ${NOXTLS_EFR32_EXTRA_DEFINITIONS})
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(noxtls_efr32 PRIVATE -Wall -Wextra -Werror)
endif()
if(MSVC)
  target_compile_options(noxtls_efr32 PRIVATE /wd5045)
endif()
