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
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/encryption
    ${NOXTLS_LIB_ROOT}/encryption/aes
    ${NOXTLS_LIB_ROOT}/tls
    ${NOXTLS_LIB_ROOT}/drbg
    ${NOXTLS_LIB_ROOT}/certs
    ${NOXTLS_LIB_ROOT}/pkc
    ${NOXTLS_LIB_ROOT}/pkc/rsa
    ${NOXTLS_LIB_ROOT}/pkc/ecc
    ${NOXTLS_LIB_ROOT}/pkc/ecdsa
    ${NOXTLS_LIB_ROOT}/pkc/ecdh
    ${NOXTLS_LIB_ROOT}/pkc/dh
    ${NOXTLS_LIB_ROOT}/pkc/x25519
    ${NOXTLS_LIB_ROOT}/pkc/x448
    ${NOXTLS_LIB_ROOT}/pkc/ed25519
    ${NOXTLS_LIB_ROOT}/pkc/dsa
    ${LIB_ROOT}/utility
    ${LIB_ROOT}/applications/noxtls
)

# If building standalone, build libraries inline
if(BUILDING_STANDALONE)
    # Common library
    add_library(noxtls_common STATIC
        ${NOXTLS_LIB_ROOT}/common/string_common.c
        ${NOXTLS_LIB_ROOT}/common/noxtls_memory.c
        ${NOXTLS_LIB_ROOT}/common/noxtls_debug_printf.c
        ${NOXTLS_LIB_ROOT}/common/noxtls_ct.c
    )

    add_library(noxtls_utility STATIC
        ${LIB_ROOT}/utility/utility.c
        ${LIB_ROOT}/utility/base64.c
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
        ${NOXTLS_LIB_ROOT}/mdigest/sha3/noxtls_sha3.c
        ${NOXTLS_LIB_ROOT}/mdigest/ripemd160/noxtls_ripemd160.c
        ${NOXTLS_LIB_ROOT}/mdigest/blake2/noxtls_blake2.c
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
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_xts.c
        ${NOXTLS_LIB_ROOT}/encryption/aes/noxtls_aes_gcm.c
    )
    
    target_link_libraries(noxtls_encryption noxtls_hash)

    add_library(noxtls_drbg STATIC
        ${NOXTLS_LIB_ROOT}/drbg/noxtls_drbg.c
    )
    target_link_libraries(noxtls_drbg noxtls_encryption)

    add_library(noxtls_pkc STATIC
        ${NOXTLS_LIB_ROOT}/pkc/rsa/noxtls_bignum.c
        ${NOXTLS_LIB_ROOT}/pkc/rsa/noxtls_rsa.c
        ${NOXTLS_LIB_ROOT}/pkc/ecc/noxtls_ecc.c
        ${NOXTLS_LIB_ROOT}/pkc/ecdsa/noxtls_ecdsa.c
        ${NOXTLS_LIB_ROOT}/pkc/ecdh/noxtls_ecdh.c
        ${NOXTLS_LIB_ROOT}/pkc/dh/noxtls_dh.c
        ${NOXTLS_LIB_ROOT}/pkc/dh/noxtls_ffdhe_params.c
        ${NOXTLS_LIB_ROOT}/pkc/x25519/noxtls_x25519.c
        ${NOXTLS_LIB_ROOT}/pkc/x448/noxtls_x448.c
        ${NOXTLS_LIB_ROOT}/pkc/ed25519/noxtls_ed25519.c
        ${NOXTLS_LIB_ROOT}/pkc/dsa/noxtls_dsa.c
    )
    target_link_libraries(noxtls_pkc
        noxtls_hash
        noxtls_common
        noxtls_drbg
    )

    add_library(noxtls_certificates STATIC
        ${NOXTLS_LIB_ROOT}/certs/asn1.c
        ${NOXTLS_LIB_ROOT}/certs/certificates.c
        ${NOXTLS_LIB_ROOT}/certs/oids.c
    )
    target_link_libraries(noxtls_certificates noxtls_utility)

    add_library(noxtls_cert STATIC
        ${NOXTLS_LIB_ROOT}/certs/noxtls_x509.c
    )
    target_link_libraries(noxtls_cert
        noxtls_certificates
        noxtls_utility
        noxtls_pkc
        noxtls_hash
        noxtls_encryption
        noxtls_common
    )
endif()

# noxtls digest application
add_executable(noxtls
    main.c
    message_digest.c
    encryption_command.c
    ${LIB_ROOT}/applications/pkc/main.c
    ${LIB_ROOT}/applications/cert/main.c
)
if(DEFINED NOXTLS_APPLICATIONS_BINARY_DIR)
    set_target_properties(noxtls PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NOXTLS_APPLICATIONS_BINARY_DIR}")
endif()

if(MSVC)
    # Suppress C4710 ("function not inlined") and C5045 (Spectre mitigation notice) for noxtls on MSVC.
    target_compile_options(noxtls PRIVATE /wd4710 /wd5045)
endif()

set_source_files_properties(${LIB_ROOT}/applications/pkc/main.c PROPERTIES
    COMPILE_DEFINITIONS "main=noxtls_pkc_app_main;print_usage=noxtls_pkc_print_usage;print_version=noxtls_pkc_print_version;print_hex=noxtls_pkc_print_hex;debug_lvl=noxtls_pkc_debug_lvl"
)
set_source_files_properties(${LIB_ROOT}/applications/cert/main.c PROPERTIES
    COMPILE_DEFINITIONS "main=noxtls_cert_app_main;print_usage=noxtls_cert_print_usage;print_version=noxtls_cert_print_version;print_hex=noxtls_cert_print_hex;debug_lvl=noxtls_cert_debug_lvl"
)

target_link_libraries(noxtls
    noxtls_common
    noxtls_hash
    noxtls_encryption
    noxtls_pkc
    noxtls_cert
    noxtls_certificates
    noxtls_utility
    noxtls_drbg
)
