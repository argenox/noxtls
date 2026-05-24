cmake_minimum_required(VERSION 3.10)

# Detect if building standalone or as part of main project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Building standalone
    project(dtls_psk_demo C)
    set(BUILDING_STANDALONE TRUE)
    get_filename_component(LIB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    set(NOXTLS_LIB_ROOT "${LIB_ROOT}/noxtls-lib")
else()
    # Building as part of main project
    set(BUILDING_STANDALONE FALSE)
    set(LIB_ROOT "${CMAKE_SOURCE_DIR}")
    set(NOXTLS_LIB_ROOT "${CMAKE_SOURCE_DIR}/noxtls-lib")
endif()

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
if(MSVC)
    set(CMAKE_C_FLAGS_DEBUG "/Od /Zi")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
else()
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
    set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIB_ROOT}
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/mdigest/sha256
)

# If building standalone, add full noxtls-lib (and utility) so noxtls_tls + DTLS are available
if(BUILDING_STANDALONE)
    set(NOXTLS_PROJECT_ROOT ${LIB_ROOT})
    set(BUILD_DTLS ON CACHE BOOL "Build DTLS" FORCE)
    set(NOXTLS_OMIT_UT_SOURCES ON CACHE BOOL "Omit unit-test sources in standalone" FORCE)
    add_subdirectory(${LIB_ROOT}/utility utility)
    add_subdirectory(${NOXTLS_LIB_ROOT}/common noxtls_common_dir)
    add_subdirectory(${NOXTLS_LIB_ROOT}/mdigest noxtls_mdigest)
    add_subdirectory(${NOXTLS_LIB_ROOT}/certs noxtls_certificates)
    add_subdirectory(${NOXTLS_LIB_ROOT}/encryption noxtls_encryption)
    add_subdirectory(${NOXTLS_LIB_ROOT}/pkc noxtls_pkc)
    add_subdirectory(${NOXTLS_LIB_ROOT}/drbg noxtls_drbg)
    add_subdirectory(${NOXTLS_LIB_ROOT}/cert noxtls_cert)
    add_subdirectory(${NOXTLS_LIB_ROOT}/tls noxtls_tls_dir)
endif()

# Optional: server cert for full DTLS 1.2 handshake (ECDHE + cert)
set(DTLS12_CERT_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
if(BUILDING_STANDALONE)
    set(DTLS12_CERT_SOURCE_DIR "${LIB_ROOT}")
endif()
set(DTLS12_SERVER_CERT_C "${DTLS12_CERT_SOURCE_DIR}/data/certs/server/server_cert.c")
if(EXISTS "${DTLS12_SERVER_CERT_C}")
    set(DTLS12_DEMO_SOURCES main.c "${DTLS12_SERVER_CERT_C}")
    set(DTLS12_DEMO_DEFINITIONS DTLS12_DEMO_USE_CERT_DATA)
else()
    set(DTLS12_DEMO_SOURCES main.c)
    set(DTLS12_DEMO_DEFINITIONS "")
endif()

# DTLS PSK Demo application
add_executable(dtls_psk_demo
    ${DTLS12_DEMO_SOURCES}
)

# App-local noxtls_config.h takes precedence over top-level (per project policy)
target_include_directories(dtls_psk_demo BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(dtls_psk_demo PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()
target_compile_definitions(dtls_psk_demo PRIVATE ${DTLS12_DEMO_DEFINITIONS})

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for dtls_psk_demo on MSVC.
    target_compile_options(dtls_psk_demo PRIVATE /wd4710 /wd5045)
endif()

target_link_libraries(dtls_psk_demo PRIVATE
    noxtls_common
    noxtls_hash
)

if(TARGET noxtls_tls)
    target_link_libraries(dtls_psk_demo PRIVATE noxtls_tls)
endif()
# Threads for full DTLS 1.2 handshake (client/server in separate threads)
if(NOT MSVC)
    find_package(Threads QUIET)
    if(Threads_FOUND)
        target_link_libraries(dtls_psk_demo PRIVATE Threads::Threads)
    endif()
endif()


