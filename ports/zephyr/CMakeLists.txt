# SPDX-License-Identifier: Apache-2.0
# Zephyr RTOS port for NoxTLS (see ports/zephyr/README.md).

if(NOT CONFIG_NOXTLS)
  return()
endif()

set(NOXTLS_PROJECT_ROOT ${ZEPHYR_NOXTLS_MODULE_DIR} CACHE PATH "NoxTLS source root" FORCE)

set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(BUILD_BOGO_SHIM    OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)

set(NOXTLS_PROFILE "${CONFIG_NOXTLS_PROFILE}" CACHE STRING "" FORCE)
set(NOXTLS_SIDECHANNEL_PROFILE "${CONFIG_NOXTLS_SIDECHANNEL}" CACHE STRING "" FORCE)

include(${CMAKE_CURRENT_LIST_DIR}/noxtls_zephyr_kconfig.cmake)

add_subdirectory(${ZEPHYR_NOXTLS_MODULE_DIR} noxtls_build)

zephyr_interface_library_named(noxtls)

set(NOXTLS_ZEPHYR_LIBS
  noxtls_common
  noxtls_hash
  noxtls_encryption
  noxtls_drbg
  noxtls_pkc
  noxtls_utility
)

if(TARGET noxtls_certificates)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_certificates)
endif()

if(TARGET noxtls_mac)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_mac)
endif()

if(TARGET noxtls_kdf)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_kdf)
endif()

if(TARGET noxtls_cert)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_cert)
endif()

if(TARGET noxtls_tls)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_tls)
endif()

target_link_libraries(noxtls INTERFACE ${NOXTLS_ZEPHYR_LIBS})

zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR})
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/utility)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/common)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/mdigest)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/mdigest/sha256)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/encryption)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/encryption/aes)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/drbg)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/pkc)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/certs)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/tls)

zephyr_library()
zephyr_library_sources(src/noxtls_zephyr_glue.c)
zephyr_library_link_libraries(noxtls_drbg)

if(CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY)
  zephyr_library_link_libraries_ifdef(CONFIG_ENTROPY_HAS_DRIVER zephyr_interface)
endif()
