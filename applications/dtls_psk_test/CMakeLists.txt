# DTLS PSK test application: server and client in one process,
# exchange application data both ways, verify payloads. Requires BUILD_DTLS=ON.

cmake_minimum_required(VERSION 3.10)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(dtls_psk_test C)
    set(BUILDING_STANDALONE TRUE)
    get_filename_component(LIB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    set(NOXTLS_LIB_ROOT "${LIB_ROOT}/noxtls-lib")
else()
    set(BUILDING_STANDALONE FALSE)
    set(LIB_ROOT "${CMAKE_SOURCE_DIR}")
    set(NOXTLS_LIB_ROOT "${CMAKE_SOURCE_DIR}/noxtls-lib")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
if(MSVC)
    set(CMAKE_C_FLAGS_DEBUG "/Od /Zi")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
else()
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
    set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIB_ROOT}
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/mdigest/sha256
)

if(BUILDING_STANDALONE)
    add_library(noxtls_common STATIC
        ${NOXTLS_LIB_ROOT}/common/string_common.c
        ${NOXTLS_LIB_ROOT}/common/noxtls_memory.c
    )
    add_library(noxtls_hash STATIC
        ${NOXTLS_LIB_ROOT}/mdigest/noxtls_hash.c
        ${NOXTLS_LIB_ROOT}/mdigest/noxtls_sha.c
        ${NOXTLS_LIB_ROOT}/mdigest/sha256/noxtls_sha256.c
    )
    target_link_libraries(noxtls_hash noxtls_common)
endif()

add_executable(dtls_psk_test main.c)

# App-local noxtls_config.h takes precedence over top-level (per project policy)
target_include_directories(dtls_psk_test BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(dtls_psk_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    target_compile_options(dtls_psk_test PRIVATE /wd4710 /wd5045)
endif()

target_link_libraries(dtls_psk_test noxtls_common noxtls_hash)
if(TARGET noxtls_tls)
    target_link_libraries(dtls_psk_test noxtls_tls)
endif()
