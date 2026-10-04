cmake_minimum_required(VERSION 3.20)
project(noxtls_cc13xx_p256_tests C)
enable_testing()
get_filename_component(NOXTLS_P256_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
set(P256_TLS "${NOXTLS_P256_ROOT}/noxtls-lib")
file(GLOB P256_AES "${P256_TLS}/encryption/aes/*.c")
list(FILTER P256_AES EXCLUDE REGEX "noxtls_aes_(accel_(ni|apple|nrf52_port|noxv_port|stm32_port|cc13xx_port)|debug).*\\.c$")
foreach(enabled IN ITEMS 0 1)
    set(target "noxtls_cc13xx_p256_enabled${enabled}_ut")
    add_executable(${target} cc13xx_p256_ut.c
        "${P256_TLS}/pkc/ecc/noxtls_ecc.c"
        "${P256_TLS}/pkc/rsa/noxtls_bignum.c"
        "${P256_TLS}/pkc/rsa/noxtls_bn_platform.c"
        "${P256_TLS}/drbg/noxtls_drbg.c"
        "${P256_TLS}/common/noxtls_memory.c"
        "${P256_TLS}/common/noxtls_cc13xx_crypto.c"
        "${P256_TLS}/common/noxtls_ct.c"
        "${P256_TLS}/common/noxtls_debug_printf.c" ${P256_AES})
    target_include_directories(${target} PRIVATE "${NOXTLS_P256_ROOT}" "${P256_TLS}"
        "${P256_TLS}/common" "${P256_TLS}/pkc/ecc" "${P256_TLS}/encryption/aes")
    target_compile_definitions(${target} PRIVATE NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS=0
        NOXTLS_FEATURE_CC13XX_HW_ACCEL=${enabled}
        NOXTLS_EMBEDDED_NO_STDIO=1 NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0
        NOXTLS_FEATURE_AES_ACCEL_NI=0 NOXTLS_FEATURE_AES_ACCEL_APPLE=0 NOXTLS_PORT_AES_ACCEL=0)
    target_link_libraries(${target} PRIVATE utnox)
    if(WIN32)
        target_link_libraries(${target} PRIVATE advapi32)
    endif()
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
    add_test(NAME ${target} COMMAND ${target} RUN_ALL)
endforeach()
