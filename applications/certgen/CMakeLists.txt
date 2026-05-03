cmake_minimum_required(VERSION 3.10)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(certgen C)
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
    ${LIB_ROOT}/utility
)

add_executable(certgen
    main.c
)
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(certgen PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for certgen on MSVC.
    target_compile_options(certgen PRIVATE /wd4710 /wd5045)
endif()

# Use certificate write/generate APIs when NOXTLS_HAVE_CERT_WRITE is set (e.g. cmake -DNOXTLS_HAVE_CERT_WRITE=ON)
if(NOXTLS_HAVE_CERT_WRITE)
    target_compile_definitions(certgen PRIVATE NOXTLS_HAVE_CERT_WRITE=1)
endif()

target_link_libraries(certgen
    noxtls_cert
    noxtls_certificates
    noxtls_utility
    noxtls_pkc
    noxtls_hash
    noxtls_common
    noxtls_drbg
)
