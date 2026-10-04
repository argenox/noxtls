cmake_minimum_required(VERSION 3.20)
project(noxtls_aes_accel_errors_tests C)
enable_testing()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT DEFINED NOXTLS_AES_ERROR_ROOT)
    get_filename_component(NOXTLS_AES_ERROR_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
endif()
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
set(ERROR_LIB "${NOXTLS_AES_ERROR_ROOT}/noxtls-lib")
set(ERROR_SOURCES aes_accel_errors_ut.c
    "${ERROR_LIB}/encryption/aes/noxtls_aes.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_ecb.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_cbc.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_ctr.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_cfb.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_ofb.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_xts.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_ccm.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_gcm.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_cmac.c"
    "${ERROR_LIB}/drbg/noxtls_drbg.c"
    "${ERROR_LIB}/common/noxtls_ct.c"
    "${ERROR_LIB}/common/noxtls_memory.c")
foreach(profile IN ITEMS software nordic stm32 hardware_only)
    set(target "noxtls_aes_accel_errors_${profile}_ut")
    add_executable(${target} ${ERROR_SOURCES})
    target_include_directories(${target} PRIVATE "${NOXTLS_AES_ERROR_ROOT}" "${ERROR_LIB}"
        "${ERROR_LIB}/common" "${ERROR_LIB}/encryption/aes" "${ERROR_LIB}/drbg")
    target_compile_definitions(${target} PRIVATE NOXTLS_EMBEDDED_NO_STDIO=1
        NOXTLS_FEATURE_AES_ACCEL_NI=0 NOXTLS_FEATURE_AES_ACCEL_APPLE=0 NOXTLS_PORT_AES_ACCEL=1)
    if(profile STREQUAL "nordic")
        target_compile_definitions(${target} PRIVATE NOXTLS_FEATURE_NRF52_HW_ACCEL=1)
    elseif(profile STREQUAL "stm32")
        target_compile_definitions(${target} PRIVATE NOXTLS_FEATURE_STM32_HW_ACCEL=1)
    elseif(profile STREQUAL "hardware_only")
        target_compile_definitions(${target} PRIVATE NOXTLS_FEATURE_STM32_HW_ACCEL=1 NOXTLS_FEATURE_STM32_HW_AES_ONLY=1)
    endif()
    target_link_libraries(${target} PRIVATE utnox)
    if(WIN32)
        target_link_libraries(${target} PRIVATE advapi32)
    endif()
    if(NOT MSVC)
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME ${target} COMMAND ${target} RUN_ALL)
endforeach()

# Existing NIST known-answer test, with the actual default unsupported port.
set(DEFAULT_REGRESSION_SOURCES ${ERROR_SOURCES})
list(REMOVE_ITEM DEFAULT_REGRESSION_SOURCES aes_accel_errors_ut.c)
add_executable(noxtls_aes_error_default_gcm_regression
    "${NOXTLS_AES_ERROR_ROOT}/ut/aes_gcm_nist_test.c"
    "${ERROR_LIB}/encryption/aes/noxtls_aes_accel_esp.c"
    ${DEFAULT_REGRESSION_SOURCES})
target_include_directories(noxtls_aes_error_default_gcm_regression PRIVATE
    "${NOXTLS_AES_ERROR_ROOT}" "${ERROR_LIB}" "${ERROR_LIB}/common"
    "${ERROR_LIB}/encryption/aes")
target_compile_definitions(noxtls_aes_error_default_gcm_regression PRIVATE
    NOXTLS_EMBEDDED_NO_STDIO=1 NOXTLS_FEATURE_AES_ACCEL_NI=0
    NOXTLS_FEATURE_AES_ACCEL_APPLE=0 NOXTLS_PORT_AES_ACCEL=0)
if(WIN32)
    target_link_libraries(noxtls_aes_error_default_gcm_regression PRIVATE advapi32)
endif()
add_test(NAME noxtls_aes_error_default_gcm_regression
    COMMAND noxtls_aes_error_default_gcm_regression)
