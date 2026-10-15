# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
cmake_minimum_required(VERSION 3.20)
project(noxtls_key_share_memory C)
enable_testing()
get_filename_component(_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
add_executable(key_share_memory_ut key_share_memory_ut.c
    "${_root}/noxtls-lib/tls/noxtls_tls_extensions.c"
    "${_root}/noxtls-lib/common/noxtls_memory.c"
    "${_root}/noxtls-lib/common/noxtls_ct.c")
target_include_directories(key_share_memory_ut PRIVATE "${_root}" "${_root}/noxtls-lib"
    "${_root}/noxtls-lib/tls" "${_root}/noxtls-lib/common")
target_compile_definitions(key_share_memory_ut PRIVATE NOXTLS_USE_STATIC_BUFFERS=1
    NOXTLS_STATIC_ALLOCATOR_MODE=0 NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION=1)
target_link_libraries(key_share_memory_ut PRIVATE utnox)
add_test(NAME key_share_memory_ut COMMAND key_share_memory_ut RUN_ALL)
