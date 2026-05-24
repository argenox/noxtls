cmake_minimum_required(VERSION 3.10)

# Detect if building standalone or as part of main project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Building standalone
    project(cert C)
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
    ${LIB_ROOT}/utility
)

# If building standalone, build libraries inline
if(BUILDING_STANDALONE)
    # Common library
    add_library(noxtls_common STATIC
        ${NOXTLS_LIB_ROOT}/common/string_common.c
    )
    
    # Utility library
    add_library(noxtls_utility STATIC
        ${LIB_ROOT}/utility/utility.c
        ${LIB_ROOT}/utility/base64.c
    )
    
    # Certificates library
    add_library(noxtls_certificates STATIC
        ${NOXTLS_LIB_ROOT}/certs/asn1.c
        ${NOXTLS_LIB_ROOT}/certs/certificates.c
        ${NOXTLS_LIB_ROOT}/certs/oids.c
    )
    
    # Cert library
    add_library(noxtls_cert STATIC
        ${NOXTLS_LIB_ROOT}/certs/noxtls_x509.c
    )
    
    target_link_libraries(noxtls_certificates noxtls_utility)
    target_link_libraries(noxtls_cert
        noxtls_certificates
        noxtls_utility
        noxtls_common
    )
endif()

# Cert application
add_executable(cert
    main.c
)

# App-local noxtls_config.h takes precedence over top-level (per project policy)
target_include_directories(cert BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(cert PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for cert on MSVC.
    target_compile_options(cert PRIVATE /wd4710 /wd5045)
endif()

target_link_libraries(cert
    noxtls_common
    noxtls_utility
    noxtls_certificates
    noxtls_cert
    noxtls_pkc
)

