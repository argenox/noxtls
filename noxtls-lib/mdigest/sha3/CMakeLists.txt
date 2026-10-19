# SHA-3 library
include("${CMAKE_CURRENT_LIST_DIR}/../../../cmake/nox_noxtls_sections.cmake")
add_library(noxtls_sha3 STATIC
    noxtls_sha3.c
)
nox_noxtls_enable_sections("noxtls_sha3")

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_sha3 PRIVATE /wd5045)
endif()

target_include_directories(noxtls_sha3 PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/mdigest/sha3
)
