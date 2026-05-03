# Common library
set(COMMON_SOURCES
    string_common.c
    noxtls_memory.c
    noxtls_debug_printf.c
)
if(WIN32)
    list(APPEND COMMON_SOURCES getopt_win.c)
endif()
add_library(noxtls_common STATIC ${COMMON_SOURCES})

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_common PRIVATE /wd5045)
endif()

target_include_directories(noxtls_common PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
)
