cmake_minimum_required(VERSION 3.10)

# Detect if building standalone or as part of main project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Building standalone
    project(noxtls C)
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
    ${LIB_ROOT}/applications/noxtls
)

# If building standalone, build libraries inline
if(BUILDING_STANDALONE)
    # Common library
    add_library(noxtls_common STATIC
        ${NOXTLS_LIB_ROOT}/common/string_common.c
    )
    
    # Hash library
    add_library(noxtls_hash STATIC
        ${NOXTLS_LIB_ROOT}/mdigest/noxtls_hash.c
        ${NOXTLS_LIB_ROOT}/mdigest/noxtls_sha.c
        ${NOXTLS_LIB_ROOT}/mdigest/md4/noxtls_md4.c
        ${NOXTLS_LIB_ROOT}/mdigest/md5/noxtls_md5.c
        ${NOXTLS_LIB_ROOT}/mdigest/sha1/noxtls_sha1.c
        ${NOXTLS_LIB_ROOT}/mdigest/sha256/noxtls_sha256.c
        ${NOXTLS_LIB_ROOT}/mdigest/sha512/noxtls_sha512.c
    )
    
    # Encryption library
    add_library(noxtls_encryption STATIC
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_debug.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_ecb.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_cbc.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_ctr.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_cfb.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_ofb.c
    )
    
    target_link_libraries(noxtls_encryption noxtls_hash)
endif()

# noxtls digest application
add_executable(noxtls
    main.c
    message_digest.c
)
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(noxtls PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for noxtls on MSVC.
    target_compile_options(noxtls PRIVATE /wd4710 /wd5045)
endif()

target_link_libraries(noxtls
    noxtls_common
    noxtls_hash
    noxtls_encryption
)
