cmake_minimum_required(VERSION 3.10)

# Detect if building standalone or as part of main project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Building standalone
    project(tls_test C)
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
)

# TLS test application
add_executable(tls_test
    main.c
)

# If noxsight exists next to noxtls in this workspace, link it into tls_test.
set(NOXSIGHT_ROOT "${LIB_ROOT}/../noxsight")
if(EXISTS "${NOXSIGHT_ROOT}/noxsight.c" AND EXISTS "${NOXSIGHT_ROOT}/noxsight.h")
    target_sources(tls_test PRIVATE "${NOXSIGHT_ROOT}/noxsight.c")
    target_include_directories(tls_test PRIVATE "${NOXSIGHT_ROOT}")
endif()

if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(tls_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for tls_test on MSVC.
    target_compile_options(tls_test PRIVATE /wd4710 /wd5045)
endif()

target_link_libraries(tls_test
    noxtls_tls
    noxtls_cert
    noxtls_pkc
    noxtls_encryption
    noxtls_hash
    noxtls_common
    noxtls_drbg
)


