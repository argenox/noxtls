# Common library
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/nox_noxtls_sections.cmake")
option(NOXTLS_DEBUG_PRINTF_STDIO "Use stdio/stdarg-backed noxtls_debug_printf" OFF)

set(COMMON_SOURCES
    string_common.c
    noxtls_memory.c
    noxtls_memory_stdlib.c
    noxtls_ct.c
    noxtls_time.c
    noxtls_abi.c
)
# Shared CC13xx callback binding: needed by either per-engine port. The
# umbrella is honored here too for consumers that add noxtls-lib directly.
if(NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL OR NOXTLS_CFG_FEATURE_CC13XX_AES_ACCEL OR
   NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL OR NOXTLS_CFG_FEATURE_CC13XX_X25519_ACCEL)
    list(APPEND COMMON_SOURCES noxtls_cc13xx_crypto.c)
endif()
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
nox_noxtls_enable_sections("noxtls_common")
# Every NoxTLS library links this one, so it defines the ABI fingerprint that
# their translation units reference, and hands consumers the layout hash.
target_compile_definitions(noxtls_common INTERFACE NOXTLS_ABI_LAYOUT_HASH=0x${NOXTLS_ABI_LAYOUT_HASH_VALUE}U)

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

