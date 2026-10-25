# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
cmake_minimum_required(VERSION 3.20)
project(noxtls_ed25519_readonly C)
enable_testing()
get_filename_component(_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
if(NOT TARGET utnox)
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
# lazy/readonly: compact SMALL_BASE tables in RAM / flash.
# comb_lazy/comb: default signed-comb tables in RAM (legacy) / flash (default).
# comb_a1/comb_a16: smallest / largest verify public-key table.
foreach(profile lazy readonly comb_lazy comb comb_a1 comb_a16)
    add_executable(ed25519_${profile}_ut ed25519_readonly_ut.c
        "${_root}/noxtls-lib/pkc/ed25519/noxtls_ed25519_fe.c"
        "${_root}/noxtls-lib/pkc/ed25519/noxtls_ed25519_fe_arm.c"
        "${_root}/noxtls-lib/common/noxtls_ct.c"
        "${_root}/noxtls-lib/common/noxtls_memory.c"
        "${_root}/noxtls-lib/common/noxtls_memory_stdlib.c")
    target_include_directories(ed25519_${profile}_ut PRIVATE "${_root}"
        "${_root}/noxtls-lib" "${_root}/noxtls-lib/common" "${_root}/noxtls-lib/mdigest")
    if(profile STREQUAL "lazy" OR profile STREQUAL "readonly")
        target_compile_definitions(ed25519_${profile}_ut PRIVATE NOXTLS_ED25519_SMALL_BASE=1)
    endif()
    target_link_libraries(ed25519_${profile}_ut PRIVATE utnox)
    if(profile STREQUAL "readonly")
        target_compile_definitions(ed25519_${profile}_ut PRIVATE NOXTLS_ED25519_READONLY_SMALL_BASE=1)
    endif()
    if(profile STREQUAL "comb_lazy")
        target_compile_definitions(ed25519_${profile}_ut PRIVATE NOXTLS_ED25519_READONLY_COMB=0)
    endif()
    if(profile STREQUAL "comb_a1")
        target_compile_definitions(ed25519_${profile}_ut PRIVATE NOXTLS_ED25519_VERIFY_A_ODD_COUNT=1U)
    endif()
    if(profile STREQUAL "comb_a16")
        target_compile_definitions(ed25519_${profile}_ut PRIVATE NOXTLS_ED25519_VERIFY_A_ODD_COUNT=16U)
    endif()
    add_test(NAME ed25519_${profile}_ut COMMAND ed25519_${profile}_ut RUN_ALL)
endforeach()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
foreach(layout small comb)
    add_executable(ed25519_readonly_${layout}_generator
        "${_root}/tools/generate_ed25519_${layout}_base.c"
        "${_root}/noxtls-lib/pkc/ed25519/noxtls_ed25519_fe.c"
        "${_root}/noxtls-lib/pkc/ed25519/noxtls_ed25519_fe_arm.c"
        "${_root}/noxtls-lib/common/noxtls_ct.c"
        "${_root}/noxtls-lib/common/noxtls_memory.c"
        "${_root}/noxtls-lib/common/noxtls_memory_stdlib.c")
    target_include_directories(ed25519_readonly_${layout}_generator PRIVATE "${_root}"
        "${_root}/noxtls-lib" "${_root}/noxtls-lib/common" "${_root}/noxtls-lib/mdigest")
endforeach()
add_test(NAME ed25519_readonly_regeneration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_regeneration.py"
        "$<TARGET_FILE:ed25519_readonly_small_generator>"
        "$<TARGET_FILE:ed25519_readonly_comb_generator>" "${CMAKE_C_COMPILER}" "${_root}"
        "${CMAKE_C_COMPILER_ID}" "${CMAKE_C_COMPILER_FRONTEND_VARIANT}")
