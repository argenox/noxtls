# Message authentication code (HMAC) library

add_library(noxtls_mac STATIC
    noxtls_hmac.c
)

if(MSVC)
    target_compile_options(noxtls_mac PRIVATE /wd5045)
endif()

target_include_directories(noxtls_mac PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/mac
    ${NOXTLS_LIB_ROOT}/mdigest
)

target_link_libraries(noxtls_mac PUBLIC
    noxtls_hash
    noxtls_common
)
