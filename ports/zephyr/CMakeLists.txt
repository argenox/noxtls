# SPDX-License-Identifier: Apache-2.0
# Zephyr RTOS port for NoxTLS (see ports/zephyr/README.md).

if(NOT CONFIG_NOXTLS)
  return()
endif()

set(NOXTLS_PROJECT_ROOT ${ZEPHYR_NOXTLS_MODULE_DIR} CACHE PATH "NoxTLS source root" FORCE)

set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(BUILD_BOGO_SHIM    OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)

set(NOXTLS_PROFILE "${CONFIG_NOXTLS_PROFILE}" CACHE STRING "" FORCE)
set(NOXTLS_SIDECHANNEL_PROFILE "${CONFIG_NOXTLS_SIDECHANNEL}" CACHE STRING "" FORCE)

macro(noxtls_zephyr_map_bool kconfig_sym cache_var)
  if(DEFINED ${kconfig_sym} AND ${kconfig_sym})
    set(${cache_var} ON CACHE BOOL "" FORCE)
  else()
    set(${cache_var} OFF CACHE BOOL "" FORCE)
  endif()
endmacro()

noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_HASH         NOXTLS_CFG_FEATURE_HASH)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ENCRYPTION   NOXTLS_CFG_FEATURE_ENCRYPTION)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_DRBG         NOXTLS_CFG_FEATURE_DRBG)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_PKC          NOXTLS_CFG_FEATURE_PKC)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_CERT         NOXTLS_CFG_FEATURE_CERT)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_TLS          NOXTLS_CFG_FEATURE_TLS)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_TLS10        NOXTLS_CFG_FEATURE_TLS10)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_TLS11        NOXTLS_CFG_FEATURE_TLS11)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_TLS12        NOXTLS_CFG_FEATURE_TLS12)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_TLS13        NOXTLS_CFG_FEATURE_TLS13)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_DTLS         NOXTLS_CFG_FEATURE_DTLS)

noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_MD4          NOXTLS_CFG_FEATURE_MD4)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_MD5          NOXTLS_CFG_FEATURE_MD5)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA1         NOXTLS_CFG_FEATURE_SHA1)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA224       NOXTLS_CFG_FEATURE_SHA224)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA256       NOXTLS_CFG_FEATURE_SHA256)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA384       NOXTLS_CFG_FEATURE_SHA384)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA512       NOXTLS_CFG_FEATURE_SHA512)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_SHA3         NOXTLS_CFG_FEATURE_SHA3)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_RIPEMD160    NOXTLS_CFG_FEATURE_RIPEMD160)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_BLAKE2       NOXTLS_CFG_FEATURE_BLAKE2)

noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES          NOXTLS_CFG_FEATURE_AES)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_128      NOXTLS_CFG_FEATURE_AES_128)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_192      NOXTLS_CFG_FEATURE_AES_192)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_256      NOXTLS_CFG_FEATURE_AES_256)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_ECB      NOXTLS_CFG_FEATURE_AES_ECB)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_CBC      NOXTLS_CFG_FEATURE_AES_CBC)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_CTR      NOXTLS_CFG_FEATURE_AES_CTR)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_CFB      NOXTLS_CFG_FEATURE_AES_CFB)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_OFB      NOXTLS_CFG_FEATURE_AES_OFB)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_XTS      NOXTLS_CFG_FEATURE_AES_XTS)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_GCM      NOXTLS_CFG_FEATURE_AES_GCM)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_CCM      NOXTLS_CFG_FEATURE_AES_CCM)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_AES_CMAC     NOXTLS_CFG_FEATURE_AES_CMAC)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ARIA         NOXTLS_CFG_FEATURE_ARIA)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_CAMELLIA     NOXTLS_CFG_FEATURE_CAMELLIA)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_CHACHA20_POLY1305 NOXTLS_CFG_FEATURE_CHACHA20_POLY1305)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_DES          NOXTLS_CFG_FEATURE_DES)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_RC4          NOXTLS_CFG_FEATURE_RC4)

noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_RSA          NOXTLS_CFG_FEATURE_RSA)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ECC          NOXTLS_CFG_FEATURE_ECC)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ECDSA        NOXTLS_CFG_FEATURE_ECDSA)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ECDH         NOXTLS_CFG_FEATURE_ECDH)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_DH           NOXTLS_CFG_FEATURE_DH)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_X25519       NOXTLS_CFG_FEATURE_X25519)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_X448         NOXTLS_CFG_FEATURE_X448)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ED25519      NOXTLS_CFG_FEATURE_ED25519)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ED448         NOXTLS_CFG_FEATURE_ED448)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_DSA          NOXTLS_CFG_FEATURE_DSA)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ML_KEM        NOXTLS_CFG_FEATURE_ML_KEM)
noxtls_zephyr_map_bool(CONFIG_NOXTLS_FEATURE_ML_DSA        NOXTLS_CFG_FEATURE_ML_DSA)

set(NOXTLS_CFG_FEATURE_AES_ACCEL_NI OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_FEATURE_SLH_DSA OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_HAVE_CERT_WRITE OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_PQC_STRICT_OFFICIAL_VECTORS OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES OFF CACHE BOOL "" FORCE)

add_subdirectory(${ZEPHYR_NOXTLS_MODULE_DIR} noxtls_build)

zephyr_interface_library_named(noxtls)

set(NOXTLS_ZEPHYR_LIBS
  noxtls_common
  noxtls_hash
  noxtls_encryption
  noxtls_drbg
  noxtls_pkc
  noxtls_utility
)

if(TARGET noxtls_certificates)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_certificates)
endif()

if(TARGET noxtls_cert)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_cert)
endif()

if(TARGET noxtls_tls)
  list(APPEND NOXTLS_ZEPHYR_LIBS noxtls_tls)
endif()

target_link_libraries(noxtls INTERFACE ${NOXTLS_ZEPHYR_LIBS})

zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR})
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/utility)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/common)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/mdigest)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/mdigest/sha256)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/encryption)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/encryption/aes)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/drbg)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/pkc)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/certs)
zephyr_include_directories(${ZEPHYR_NOXTLS_MODULE_DIR}/noxtls-lib/tls)

zephyr_library()
zephyr_library_sources(src/noxtls_zephyr_glue.c)
zephyr_library_link_libraries(noxtls_drbg)

if(CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY)
  zephyr_library_link_libraries_ifdef(CONFIG_ENTROPY_HAS_DRIVER zephyr_interface)
endif()
