# TLS (Transport Layer Security) library
# Implements TLS 1.2 and TLS 1.3

option(BUILD_DTLS "Build DTLS-related code (in progress)" ON)
option(TLS13_PREFER_CHACHA "Prefer ChaCha20-Poly1305 over AES-GCM for TLS 1.3 / DTLS 1.3" OFF)

if(NOXTLS_CFG_FEATURE_DTLS)
  set(BUILD_DTLS ON CACHE BOOL "Build DTLS-related code (in progress)" FORCE)
else()
  set(BUILD_DTLS OFF CACHE BOOL "Build DTLS-related code (in progress)" FORCE)
endif()

set(TLS_SOURCES
    noxtls_tls_common.c
    noxtls_tls_auto.c
    noxtls_tls_key_exchange.c
    noxtls_tls_kdf.c
    noxtls_tls_extensions.c
    noxtls_tls_record.c
)
if(NOXTLS_CFG_FEATURE_TLS12)
  list(APPEND TLS_SOURCES noxtls_tls12.c)
endif()
if(NOXTLS_CFG_FEATURE_TLS10)
  list(APPEND TLS_SOURCES noxtls_tls10.c)
endif()
if(NOXTLS_CFG_FEATURE_TLS11)
  list(APPEND TLS_SOURCES noxtls_tls11.c)
endif()
if(NOXTLS_CFG_FEATURE_TLS13)
  list(APPEND TLS_SOURCES noxtls_tls13.c noxtls_tls13_psk.c)
endif()
if(NOXTLS_CFG_FEATURE_TLS12 OR NOXTLS_CFG_FEATURE_TLS13)
  list(APPEND TLS_SOURCES noxtls_tls_unified.c)
endif()
if(NOT NOXTLS_CFG_FEATURE_TLS10 AND NOT NOXTLS_CFG_FEATURE_TLS11 AND NOT NOXTLS_CFG_FEATURE_TLS12 AND NOT NOXTLS_CFG_FEATURE_TLS13)
  message(FATAL_ERROR "NOXTLS_FEATURE_TLS requires at least one TLS version enabled.")
endif()
if(NOT NOXTLS_CFG_FEATURE_HMAC)
  message(FATAL_ERROR "NOXTLS_FEATURE_TLS requires NOXTLS_CFG_FEATURE_HMAC.")
endif()
if(NOT NOXTLS_CFG_FEATURE_HKDF)
  message(FATAL_ERROR "NOXTLS_FEATURE_TLS requires NOXTLS_CFG_FEATURE_HKDF.")
endif()
if(BUILD_DTLS)
    list(APPEND TLS_SOURCES noxtls_dtls_common.c)
else()
    list(APPEND TLS_SOURCES noxtls_dtls_stub.c)
endif()

add_library(noxtls_tls STATIC ${TLS_SOURCES})

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_tls PRIVATE /wd5045)
endif()
if(TLS13_PREFER_CHACHA)
    target_compile_definitions(noxtls_tls PRIVATE NOXTLS_TLS13_PREFER_CHACHA=1)
endif()

target_include_directories(noxtls_tls PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/tls
    ${NOXTLS_LIB_ROOT}/pkc
    ${NOXTLS_LIB_ROOT}/pkc/rsa
    ${NOXTLS_LIB_ROOT}/pkc/ecc
    ${NOXTLS_LIB_ROOT}/pkc/ecdsa
    ${NOXTLS_LIB_ROOT}/pkc/ed25519
    ${NOXTLS_LIB_ROOT}/pkc/ed448
    ${NOXTLS_LIB_ROOT}/pkc/mlkem
    ${NOXTLS_LIB_ROOT}/pkc/mldsa
    ${NOXTLS_LIB_ROOT}/encryption
    ${NOXTLS_LIB_ROOT}/encryption/aes
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/drbg
    ${NOXTLS_LIB_ROOT}/mac
    ${NOXTLS_LIB_ROOT}/kdf
    ${NOXTLS_LIB_ROOT}/common
)

target_link_libraries(noxtls_tls
    noxtls_kdf
    noxtls_mac
    noxtls_pkc
    noxtls_encryption
    noxtls_hash
    noxtls_common
    noxtls_drbg
    noxtls_cert
)

