# Common library
option(NOXTLS_DEBUG_PRINTF_STDIO "Use stdio/stdarg-backed noxtls_debug_printf" OFF)

set(COMMON_SOURCES
    string_common.c
    noxtls_memory.c
    noxtls_memory_stdlib.c
    noxtls_ct.c
    noxtls_time.c
)
if(NOXTLS_DEBUG_PRINTF_STDIO)
    list(APPEND COMMON_SOURCES noxtls_debug_printf_stdio.c)
else()
    list(APPEND COMMON_SOURCES noxtls_debug_printf.c)
endif()
if(WIN32)
    list(APPEND COMMON_SOURCES getopt_win.c)
endif()
list(APPEND COMMON_SOURCES noxtls_common_api_refs.c)
add_library(noxtls_common STATIC ${COMMON_SOURCES})

if(NOXTLS_DEBUG_PRINTF_STDIO)
    target_compile_definitions(noxtls_common PUBLIC NOXTLS_DEBUG_PRINTF_STDIO=1)
endif()

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_common PRIVATE /wd5045)
endif()

target_include_directories(noxtls_common PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
)

