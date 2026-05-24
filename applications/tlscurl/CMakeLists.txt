cmake_minimum_required(VERSION 3.10)

# Detect if building standalone or as part of main project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(tlscurl C)
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
)

add_executable(tlscurl
    main.c
)

# App-local noxtls_config.h takes precedence over top-level (per project policy)
target_include_directories(tlscurl BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(tlscurl PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    target_compile_options(tlscurl PRIVATE /wd4710 /wd5045 /wd4668 /wd4820)
endif()

target_link_libraries(tlscurl
    noxtls_tls
    noxtls_cert
    noxtls_pkc
    noxtls_encryption
    noxtls_hash
    noxtls_common
    noxtls_drbg
)

if(WIN32)
    target_link_libraries(tlscurl ws2_32)
endif()
