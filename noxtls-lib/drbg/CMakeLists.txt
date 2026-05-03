# DRBG (Deterministic Random Bit Generator) library
# Implements AES-CTR-DRBG per NIST SP 800-90A

add_library(noxtls_drbg STATIC
    noxtls_drbg.c
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
# Windows Crypto API (CryptGenRandom etc.) used by drbg for entropy
if(WIN32)
    target_link_libraries(noxtls_drbg PUBLIC advapi32)
endif()


