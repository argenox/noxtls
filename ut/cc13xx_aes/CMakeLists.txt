cmake_minimum_required(VERSION 3.20)
project(noxtls_cc13xx_aes_tests C)
enable_testing()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
get_filename_component(NOXTLS_CC13XX_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
set(CC13XX_LIB "${NOXTLS_CC13XX_ROOT}/noxtls-lib")
# name|NOXTLS_FEATURE_CC13XX_HW_ACCEL|..._AES_ACCEL|..._P256_ACCEL|C standard.
# enabled0/1 are the original umbrella-off/on targets; the others cover each
# per-engine switch, and the c99 target the non-C11 atomic guard primitive.
set(CC13XX_AES_CONFIGS "enabled0|0|0|0|11" "enabled1|1|0|0|11" "aes_only|0|1|0|11"
    "p256_only|0|0|1|11" "aes_only_c99|0|1|0|99")
foreach(config IN LISTS CC13XX_AES_CONFIGS)
    string(REPLACE "|" ";" fields "${config}")
    list(GET fields 0 name)
    list(GET fields 1 umbrella)
    list(GET fields 2 aes)
    list(GET fields 3 p256)
    list(GET fields 4 standard)
    set(target "noxtls_cc13xx_aes_${name}_ut")
    add_executable(${target} cc13xx_aes_ut.c)
    if(umbrella OR aes)
        target_sources(${target} PRIVATE
            "${CC13XX_LIB}/common/noxtls_cc13xx_crypto.c"
            "${CC13XX_LIB}/common/noxtls_ct.c"
            "${CC13XX_LIB}/encryption/aes/noxtls_aes_accel_cc13xx_port.c")
    else()
        target_sources(${target} PRIVATE "${CC13XX_LIB}/encryption/aes/noxtls_aes_accel_esp.c")
    endif()
    target_include_directories(${target} PRIVATE "${NOXTLS_CC13XX_ROOT}"
        "${CC13XX_LIB}" "${CC13XX_LIB}/common" "${CC13XX_LIB}/encryption/aes")
    target_compile_definitions(${target} PRIVATE NOXTLS_FEATURE_CC13XX_HW_ACCEL=${umbrella}
        NOXTLS_FEATURE_CC13XX_AES_ACCEL=${aes} NOXTLS_FEATURE_CC13XX_P256_ACCEL=${p256}
        NOXTLS_FEATURE_AES_ACCEL_NI=0 NOXTLS_FEATURE_AES_ACCEL_APPLE=0)
    if(standard STREQUAL "99")
        # UTNox assertions use typeof, a GNU extension before C23.
        set_target_properties(${target} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS ON)
    else()
        set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    endif()
    target_link_libraries(${target} PRIVATE utnox)
    add_test(NAME ${target} COMMAND ${target} RUN_ALL)
endforeach()
