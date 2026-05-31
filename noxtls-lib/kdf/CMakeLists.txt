# Key derivation function (HKDF) library

add_library(noxtls_kdf STATIC
    noxtls_hkdf.c
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
