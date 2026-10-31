# Message authentication code (HMAC) library
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/nox_noxtls_sections.cmake")
option(NOXTLS_HMAC_SHA256_SHARED_STATE "Deprecated, no effect: HMAC contexts embed their hash state" OFF)

add_library(noxtls_mac STATIC
    noxtls_hmac.c
    noxtls_mac_api_refs.c
)
nox_noxtls_enable_sections("noxtls_mac")

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

if(NOXTLS_HMAC_SHA256_SHARED_STATE)
    target_compile_definitions(noxtls_mac PUBLIC NOXTLS_HMAC_SHA256_SHARED_STATE=1)
endif()
