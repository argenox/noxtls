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

# Consumers and the standalone archives must use the same target ABI and
# feature definitions. Plain add_subdirectory() targets do not automatically
# inherit Zephyr's Cortex-M CPU flags or generated configuration includes.
add_library(noxtls_zephyr_config INTERFACE)
target_link_libraries(noxtls_zephyr_config INTERFACE zephyr_interface)
get_directory_property(_noxtls_definitions
  DIRECTORY ${ZEPHYR_NOXTLS_MODULE_DIR} COMPILE_DEFINITIONS)
target_compile_definitions(noxtls_zephyr_config INTERFACE ${_noxtls_definitions})
get_directory_property(_noxtls_includes
  DIRECTORY ${ZEPHYR_NOXTLS_MODULE_DIR} INCLUDE_DIRECTORIES)
target_include_directories(noxtls_zephyr_config BEFORE INTERFACE ${_noxtls_includes})
set_property(TARGET noxtls_common PROPERTY NOXTLS_SOURCE_ROOT ${ZEPHYR_NOXTLS_MODULE_DIR})
if(NOXTLS_EXTERNAL_CONFIG_INCLUDE_DIR)
  set_property(TARGET noxtls_common PROPERTY NOXTLS_CONFIG_INCLUDE_DIR ${NOXTLS_EXTERNAL_CONFIG_INCLUDE_DIR})
else()
  set_property(TARGET noxtls_common PROPERTY NOXTLS_CONFIG_INCLUDE_DIR ${ZEPHYR_NOXTLS_MODULE_DIR})
endif()

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
if(TARGET noxtls_sha3)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_sha3)
endif()

if(TARGET noxtls_mac)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_mac)
endif()

if(TARGET noxtls_kdf)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_kdf)
endif()

if(TARGET noxtls_pake)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_pake)
endif()

if(TARGET noxtls_cert)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_cert)
endif()

if(TARGET noxtls_tls)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_tls)
endif()

target_link_libraries(noxtls INTERFACE ${NOXTLS_ZEPHYR_LIBS})
target_link_libraries(noxtls INTERFACE noxtls_zephyr_config)
foreach(_lib IN LISTS NOXTLS_ZEPHYR_LIBS)
  add_dependencies(${_lib} zephyr_generated_headers)
  # The standalone library uses both CMake link signatures across targets.
  # Appending properties works with either without changing native builds.
  set_property(TARGET ${_lib} APPEND PROPERTY LINK_LIBRARIES noxtls_zephyr_config)
  set_property(TARGET ${_lib} APPEND PROPERTY INTERFACE_LINK_LIBRARIES noxtls_zephyr_config)
endforeach()

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
