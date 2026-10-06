# Key derivation function library (HKDF RFC 5869, PBKDF2 RFC 8018)

set(NOXTLS_KDF_SOURCES)
# Builds that add this directory directly (e.g. the OEM unit-test tree) may not
# define the HKDF knob; keep HKDF compiled unless it is explicitly disabled.
if(NOT DEFINED NOXTLS_CFG_FEATURE_HKDF OR NOXTLS_CFG_FEATURE_HKDF)
    list(APPEND NOXTLS_KDF_SOURCES noxtls_hkdf.c)
endif()
if(NOXTLS_CFG_FEATURE_PBKDF2)
    list(APPEND NOXTLS_KDF_SOURCES noxtls_pbkdf.c)
endif()

add_library(noxtls_kdf STATIC
    ${NOXTLS_KDF_SOURCES}
    noxtls_kdf_api_refs.c
)

if(MSVC)
    target_compile_options(noxtls_kdf PRIVATE /wd5045)
endif()

target_include_directories(noxtls_kdf PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/kdf
    ${NOXTLS_LIB_ROOT}/mac
    ${NOXTLS_LIB_ROOT}/mdigest
)

target_link_libraries(noxtls_kdf PUBLIC
    noxtls_mac
    noxtls_common
)
