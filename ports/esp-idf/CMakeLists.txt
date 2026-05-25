# SPDX-License-Identifier: Apache-2.0
# ESP-IDF component wrapper for NoxTLS (see ports/esp-idf/README.md).

get_filename_component(_noxtls_esp_idf_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)

# Registry package: library under lib_root/ inside this component directory.
# In-repo layout: this file is ports/esp-idf, library at ../../ .
if(EXISTS "${_noxtls_esp_idf_dir}/lib_root/noxtls-lib")
    set(NOXTLS_PROJECT_ROOT "${_noxtls_esp_idf_dir}/lib_root")
    set(NOXTLS_ESP_IDF_DIR "${_noxtls_esp_idf_dir}")
elseif(EXISTS "${_noxtls_esp_idf_dir}/../../noxtls-lib")
    get_filename_component(NOXTLS_PROJECT_ROOT "${_noxtls_esp_idf_dir}/../.." ABSOLUTE)
    set(NOXTLS_ESP_IDF_DIR "${_noxtls_esp_idf_dir}")
else()
    message(FATAL_ERROR
        "NoxTLS ESP-IDF port: library sources not found. Expected either "
        "${_noxtls_esp_idf_dir}/lib_root/noxtls-lib (registry component) or "
        "${_noxtls_esp_idf_dir}/../../noxtls-lib (in-repo ports/esp-idf layout).")
endif()

set(NOXTLS_ESP_IDF_DIR "${NOXTLS_ESP_IDF_DIR}" CACHE INTERNAL "")
set(NOXTLS_PROJECT_ROOT "${NOXTLS_PROJECT_ROOT}" CACHE PATH "" FORCE)

# Application projects set NOXTLS_APPLICATION_CONFIG_DIR to their main/ folder
# (containing a project-local noxtls_config.h). That must precede NOXTLS_PROJECT_ROOT
# so the library does not pick up the shared repo-root noxtls_config.h.
set(_noxtls_config_include_dirs "")

idf_component_register(
    SRCS
        "src/noxtls_esp_idf_glue.c"
    INCLUDE_DIRS
        "include"
        "${NOXTLS_PROJECT_ROOT}/utility"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/common"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/mdigest"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/mdigest/sha256"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/encryption"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/encryption/aes"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/drbg"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/pkc"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/certs"
        "${NOXTLS_PROJECT_ROOT}/noxtls-lib/tls"
    PRIV_REQUIRES
        esp_timer
        esp_system
        esp_hw_support
        freertos
    REQUIRES
        mbedtls
        newlib
)

if(NOT CONFIG_NOXTLS)
    return()
endif()

set(NOXTLS_GENERATED_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated_noxtls_config")
file(MAKE_DIRECTORY "${NOXTLS_GENERATED_CONFIG_DIR}")

if(NOXTLS_APPLICATION_CONFIG_DIR AND
   EXISTS "${NOXTLS_APPLICATION_CONFIG_DIR}/noxtls_config.h")
    list(APPEND _noxtls_config_include_dirs "${NOXTLS_APPLICATION_CONFIG_DIR}")
    list(APPEND _noxtls_config_include_dirs "${NOXTLS_GENERATED_CONFIG_DIR}")
else()
    # No application header: emit a standalone noxtls_config.h from menuconfig only.
    file(WRITE "${NOXTLS_GENERATED_CONFIG_DIR}/noxtls_config.h"
        "/* Generated from ESP-IDF sdkconfig (menuconfig). */\n"
        "#ifndef _NOXTLS_CONFIG_H_\n"
        "#define _NOXTLS_CONFIG_H_\n"
        "#include \"noxtls_config_features.h\"\n"
        "#include \"noxtls_esp_hw_accel.h\"\n"
        "#include \"noxtls_check_config.h\"\n"
        "#endif\n")
    list(APPEND _noxtls_config_include_dirs "${NOXTLS_GENERATED_CONFIG_DIR}")
endif()

# noxtls_check_config.h and other repo-root headers (not noxtls_config.h when app dir is set).
list(APPEND _noxtls_config_include_dirs "${NOXTLS_PROJECT_ROOT}")

target_include_directories(${COMPONENT_LIB} BEFORE PUBLIC ${_noxtls_config_include_dirs})

set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(BUILD_BOGO_SHIM    OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)
set(NOXTLS_ECDSA_SIGN_SELF_VERIFY OFF CACHE BOOL "" FORCE)

set(NOXTLS_PROFILE "${CONFIG_NOXTLS_PROFILE}" CACHE STRING "" FORCE)
set(NOXTLS_SIDECHANNEL_PROFILE "${CONFIG_NOXTLS_SIDECHANNEL}" CACHE STRING "" FORCE)

include(${CMAKE_CURRENT_LIST_DIR}/noxtls_esp_idf_kconfig.cmake)

add_subdirectory(${NOXTLS_PROJECT_ROOT} noxtls_build)

# After Kconfig -> cache and profile overrides in root CMakeLists (final NOXTLS_CFG_*).
include(${CMAKE_CURRENT_LIST_DIR}/noxtls_esp_idf_config_header.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/noxtls_esp_idf_hw_accel_header.cmake)
noxtls_esp_idf_write_config_features_header(
    "${NOXTLS_GENERATED_CONFIG_DIR}/noxtls_config_features.h")
noxtls_esp_idf_write_hw_accel_header(
    "${NOXTLS_GENERATED_CONFIG_DIR}/noxtls_esp_hw_accel.h")

set(NOXTLS_ESP_IDF_LIBS
    noxtls_common
    noxtls_hash
    noxtls_encryption
    noxtls_drbg
    noxtls_pkc
    noxtls_utility
)

set(NOXTLS_ESP_IDF_CRYPTO_HAL_INCLUDE_DIRS
    "${IDF_PATH}/components/mbedtls/port/include"
    "${IDF_PATH}/components/mbedtls/mbedtls/include")

if(TARGET noxtls_certificates)
    list(APPEND NOXTLS_ESP_IDF_LIBS noxtls_certificates)
endif()

if(TARGET noxtls_cert)
    list(APPEND NOXTLS_ESP_IDF_LIBS noxtls_cert)
endif()

if(TARGET noxtls_tls)
    list(APPEND NOXTLS_ESP_IDF_LIBS noxtls_tls)
endif()

target_link_libraries(${COMPONENT_LIB} PUBLIC ${NOXTLS_ESP_IDF_LIBS})

foreach(_noxtls_lib IN LISTS NOXTLS_ESP_IDF_LIBS)
    if(TARGET ${_noxtls_lib})
        # add_subdirectory() libs only see ESP_PLATFORM as a CMake variable (for
        # source lists), not as a C macro — port .c files need -DESP_PLATFORM=1.
        target_compile_definitions(${_noxtls_lib} PUBLIC ESP_PLATFORM=1)
        target_include_directories(${_noxtls_lib} BEFORE PUBLIC ${_noxtls_config_include_dirs})
        target_include_directories(${_noxtls_lib} BEFORE PUBLIC ${NOXTLS_ESP_IDF_CRYPTO_HAL_INCLUDE_DIRS})
        if(EXISTS "${PROJECT_BINARY_DIR}/config")
            target_include_directories(${_noxtls_lib} PRIVATE "${PROJECT_BINARY_DIR}/config")
        endif()
    endif()
endforeach()

# Propagate sdkconfig HW toggles into NoxTLS static libs (belt-and-suspenders with sdkconfig.h).
if(TARGET noxtls_pkc)
    target_include_directories(noxtls_pkc BEFORE PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")
    target_link_libraries(noxtls_pkc PRIVATE mbedtls)
    if(CONFIG_NOXTLS_ESP_HW_ECC)
        target_compile_definitions(noxtls_pkc PUBLIC CONFIG_NOXTLS_ESP_HW_ECC=1)
    endif()
    if(CONFIG_NOXTLS_ESP_HW_ECDSA)
        target_compile_definitions(noxtls_pkc PUBLIC CONFIG_NOXTLS_ESP_HW_ECDSA=1)
    endif()
    if(CONFIG_NOXTLS_ESP_HW_MPI)
        target_compile_definitions(noxtls_pkc PUBLIC CONFIG_NOXTLS_ESP_HW_MPI=1)
    endif()
    if(CONFIG_MBEDTLS_HARDWARE_MPI)
        target_compile_definitions(noxtls_pkc PUBLIC CONFIG_MBEDTLS_HARDWARE_MPI=1)
    endif()
endif()

if(TARGET noxtls_encryption AND CONFIG_NOXTLS_ESP_HW_AES)
    target_compile_definitions(noxtls_encryption PUBLIC CONFIG_NOXTLS_ESP_HW_AES=1)
endif()

if(TARGET noxtls_hash AND CONFIG_NOXTLS_ESP_HW_SHA)
    target_compile_definitions(noxtls_hash PUBLIC CONFIG_NOXTLS_ESP_HW_SHA=1)
endif()
