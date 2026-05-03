# When built as standalone (e.g. dtls_psk_demo), project root is provided via NOXTLS_PROJECT_ROOT
if(NOT DEFINED NOXTLS_PROJECT_ROOT)
    get_filename_component(NOXTLS_PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
endif()
# Utility library
add_library(noxtls_utility STATIC
    utility.c
    base64.c
)

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_utility PRIVATE /wd5045)
endif()

target_include_directories(noxtls_utility PUBLIC
    ${NOXTLS_PROJECT_ROOT}
    ${NOXTLS_PROJECT_ROOT}/utility
)
