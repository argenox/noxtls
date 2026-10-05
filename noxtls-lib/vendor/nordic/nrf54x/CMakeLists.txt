# nRF54L CRACEN hardware backend (nRF54LM20 / nRF54L15).
# Register-level drivers for the CryptoMaster (AES, AES-GCM/CCM, SHA-2), the
# TRNG, the BA414EP public-key engine and the KMU. The accelerator port glue
# (noxtls_nrf54_port_*.c) is compiled into the algorithm libraries by
# noxtls-lib/encryption, mdigest, pkc and drbg; this library holds the drivers.
#
# NOXTLS_NRF54_EXTRA_DEFINITIONS: optional list of NOXTLS_NRF54_CONFIG_* overrides
# (for example NOXTLS_NRF54_CONFIG_CHIP_L15=1 or the small budgets of the host tests).
set(NOXTLS_NRF54_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
include(${NOXTLS_NRF54_DIR}/noxtls_nrf54_sources.cmake)

add_library(noxtls_nrf54 STATIC ${NOXTLS_NRF54_DRIVER_SOURCES})
get_filename_component(_noxtls_nrf54_project_root "${NOXTLS_LIB_ROOT}/.." ABSOLUTE)
target_include_directories(noxtls_nrf54 PUBLIC
  ${NOXTLS_NRF54_DIR}
  ${_noxtls_nrf54_project_root}
  ${NOXTLS_LIB_ROOT}
)
target_link_libraries(noxtls_nrf54 PUBLIC noxtls_common)
if(NOXTLS_NRF54_EXTRA_DEFINITIONS)
  target_compile_definitions(noxtls_nrf54 PUBLIC ${NOXTLS_NRF54_EXTRA_DEFINITIONS})
endif()
if(MSVC)
  target_compile_options(noxtls_nrf54 PRIVATE /wd5045)
endif()
