cmake_minimum_required(VERSION 3.20)
project(noxtls_ecc_accel_errors_tests C)
enable_testing()
get_filename_component(NOXTLS_ECC_ERROR_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
set(ECC_ERROR_TLS "${NOXTLS_ECC_ERROR_ROOT}/noxtls-lib")
file(GLOB ECC_ERROR_AES "${ECC_ERROR_TLS}/encryption/aes/*.c")
list(FILTER ECC_ERROR_AES EXCLUDE REGEX "noxtls_aes_(accel_(ni|apple|nrf52_port|noxv_port|stm32_port)|debug).*\\.c$")
option(NOXTLS_ECC_ERRORS_TEST_PERFORMANCE_DIAGNOSTICS "Also build pre-existing ECC performance diagnostic branch" OFF)
set(ECC_ERROR_DIAGNOSTICS 0)
if(NOXTLS_ECC_ERRORS_TEST_PERFORMANCE_DIAGNOSTICS)
    list(APPEND ECC_ERROR_DIAGNOSTICS 1)
endif()
foreach(diagnostics IN LISTS ECC_ERROR_DIAGNOSTICS)
    set(target "noxtls_ecc_accel_errors_diag${diagnostics}_ut")
    add_executable(${target} ecc_accel_errors_ut.c
        "${ECC_ERROR_TLS}/pkc/ecc/noxtls_ecc.c"
        "${ECC_ERROR_TLS}/pkc/rsa/noxtls_bignum.c"
        "${ECC_ERROR_TLS}/pkc/rsa/noxtls_bn_platform.c"
        "${ECC_ERROR_TLS}/drbg/noxtls_drbg.c"
        "${ECC_ERROR_TLS}/common/noxtls_memory.c"
        "${ECC_ERROR_TLS}/common/noxtls_ct.c"
        "${ECC_ERROR_TLS}/common/noxtls_debug_printf.c" ${ECC_ERROR_AES})
    target_include_directories(${target} PRIVATE "${NOXTLS_ECC_ERROR_ROOT}" "${ECC_ERROR_TLS}"
        "${ECC_ERROR_TLS}/common" "${ECC_ERROR_TLS}/pkc/ecc" "${ECC_ERROR_TLS}/encryption/aes")
    target_compile_definitions(${target} PRIVATE NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS=${diagnostics}
        NOXTLS_EMBEDDED_NO_STDIO=1 NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0
        NOXTLS_FEATURE_AES_ACCEL_NI=0 NOXTLS_FEATURE_AES_ACCEL_APPLE=0 NOXTLS_PORT_AES_ACCEL=0)
    target_link_libraries(${target} PRIVATE utnox)
    if(WIN32)
        target_link_libraries(${target} PRIVATE advapi32)
    endif()
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
    add_test(NAME ${target} COMMAND ${target} RUN_ALL)
endforeach()
