# DRBG (Deterministic Random Bit Generator) library
# Implements AES-CTR-DRBG per NIST SP 800-90A

set(NOXTLS_DRBG_SOURCES noxtls_drbg.c)
if(NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL)
    # nRF54L CRACEN TRNG as the NOXTLS_ENTROPY_SOURCE_AUTO entropy source.
    include(${NOXTLS_LIB_ROOT}/vendor/nordic/nrf54x/noxtls_nrf54_sources.cmake)
    list(APPEND NOXTLS_DRBG_SOURCES ${NOXTLS_NRF54_PORT_DRBG_SOURCES})
endif()
add_library(noxtls_drbg STATIC
    ${NOXTLS_DRBG_SOURCES}
)

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_drbg PRIVATE /wd5045)
endif()

target_include_directories(noxtls_drbg PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/drbg
    ${NOXTLS_LIB_ROOT}/encryption
    ${NOXTLS_LIB_ROOT}/encryption/aes
)

target_link_libraries(noxtls_drbg PUBLIC
    noxtls_encryption
)
if(NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL)
    target_link_libraries(noxtls_drbg PUBLIC noxtls_nrf54)
endif()
# Windows Crypto API (CryptGenRandom etc.) used by drbg for entropy
if(WIN32)
    target_link_libraries(noxtls_drbg PUBLIC advapi32)
endif()


