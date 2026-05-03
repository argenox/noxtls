# Message Digest library
set(NOXTLS_HASH_SOURCES
    noxtls_hash.c
    noxtls_sha.c
)

if(NOXTLS_CFG_FEATURE_MD4)
    list(APPEND NOXTLS_HASH_SOURCES md4/noxtls_md4.c)
endif()
if(NOXTLS_CFG_FEATURE_MD5)
    list(APPEND NOXTLS_HASH_SOURCES md5/noxtls_md5.c)
endif()
if(NOXTLS_CFG_FEATURE_SHA1)
    list(APPEND NOXTLS_HASH_SOURCES sha1/noxtls_sha1.c)
endif()
if(NOXTLS_CFG_FEATURE_SHA224 OR NOXTLS_CFG_FEATURE_SHA256)
    list(APPEND NOXTLS_HASH_SOURCES sha256/noxtls_sha256.c)
endif()
if(NOXTLS_CFG_FEATURE_SHA384 OR NOXTLS_CFG_FEATURE_SHA512)
    list(APPEND NOXTLS_HASH_SOURCES sha512/noxtls_sha512.c)
endif()
if(NOXTLS_CFG_FEATURE_SHA3)
    list(APPEND NOXTLS_HASH_SOURCES sha3/noxtls_sha3.c)
endif()
if(NOXTLS_CFG_FEATURE_RIPEMD160)
    list(APPEND NOXTLS_HASH_SOURCES ripemd160/noxtls_ripemd160.c)
endif()
if(NOXTLS_CFG_FEATURE_BLAKE2)
    list(APPEND NOXTLS_HASH_SOURCES blake2/noxtls_blake2.c)
endif()

add_library(noxtls_hash STATIC ${NOXTLS_HASH_SOURCES})

# Use CURRENT_SOURCE_DIR so this works when mdigest is built as a subdirectory (e.g. from ut/)
target_include_directories(noxtls_hash PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/md4
    ${CMAKE_CURRENT_SOURCE_DIR}/md5
    ${CMAKE_CURRENT_SOURCE_DIR}/sha1
    ${CMAKE_CURRENT_SOURCE_DIR}/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/sha512
    ${CMAKE_CURRENT_SOURCE_DIR}/sha3
    ${CMAKE_CURRENT_SOURCE_DIR}/ripemd160
    ${CMAKE_CURRENT_SOURCE_DIR}/blake2
)

target_link_libraries(noxtls_hash
    noxtls_common
)

if(MSVC)
    # Suppress Spectre mitigation notice for mdigest on MSVC.
    target_compile_options(noxtls_hash PRIVATE /wd5045)
endif()
