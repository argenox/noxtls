# Public Key Cryptography library
# This library contains implementations of public key cryptography algorithms
# including RSA, ECC (Elliptic Curve Cryptography), ECDSA, ECDH, etc.
#
option(USE_REF_ECC_POINT_MUL "Use reference ECC point multiply for tests" OFF)
option(NOXTLS_ECDSA_VERIFY_DEBUG "Enable ECDSA verify debug prints (hex dumps of h, r, s, u1, u2, v)" OFF)
# Force Montgomery ladder only (disable windowed scalar mult). Use to isolate windowed-path bugs.
option(NOXTLS_ECC_LADDER_ONLY "Use Montgomery ladder only for ECC point multiply (set NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0)" OFF)

set(PKC_SOURCES
)
if(NOXTLS_CFG_FEATURE_RSA)
    list(APPEND PKC_SOURCES rsa/noxtls_bignum.c rsa/noxtls_rsa.c)
endif()
if(NOXTLS_CFG_FEATURE_DSA AND NOT NOXTLS_CFG_FEATURE_RSA)
    list(APPEND PKC_SOURCES rsa/noxtls_bignum.c)
endif()
if(NOXTLS_CFG_FEATURE_ECC)
    list(APPEND PKC_SOURCES ecc/noxtls_ecc.c)
endif()
if(NOXTLS_CFG_FEATURE_ECDSA)
    list(APPEND PKC_SOURCES ecdsa/noxtls_ecdsa.c)
endif()
if(NOXTLS_CFG_FEATURE_ECDH)
    list(APPEND PKC_SOURCES ecdh/noxtls_ecdh.c)
endif()
if(NOXTLS_CFG_FEATURE_DH)
    list(APPEND PKC_SOURCES dh/noxtls_dh.c dh/noxtls_ffdhe_params.c)
endif()
if(NOXTLS_CFG_FEATURE_X25519)
    list(APPEND PKC_SOURCES x25519/noxtls_x25519.c)
endif()
if(NOXTLS_CFG_FEATURE_X448)
    list(APPEND PKC_SOURCES x448/noxtls_x448.c)
endif()
if(NOXTLS_CFG_FEATURE_ED25519)
    list(APPEND PKC_SOURCES ed25519/noxtls_ed25519.c)
endif()
if(NOXTLS_CFG_FEATURE_ED448)
    list(APPEND PKC_SOURCES ed448/noxtls_ed448.c)
endif()
if(NOXTLS_CFG_FEATURE_DSA)
    list(APPEND PKC_SOURCES dsa/noxtls_dsa.c)
endif()
if(NOXTLS_CFG_FEATURE_ML_KEM)
    list(APPEND PKC_SOURCES mlkem/noxtls_mlkem.c)
endif()
if(NOXTLS_CFG_FEATURE_ML_DSA)
    list(APPEND PKC_SOURCES
        mldsa/noxtls_mldsa.c
        mldsa/noxtls_zetas.c
        mldsa/noxtls_mldsa44_ref.c
        mldsa/noxtls_mldsa65_ref.c
        mldsa/noxtls_mldsa87_ref.c
    )
endif()
if(NOT PKC_SOURCES)
    message(FATAL_ERROR "NOXTLS_FEATURE_PKC is enabled but no PKC primitive sources are selected.")
endif()
if(USE_REF_ECC_POINT_MUL)
endif()

add_library(noxtls_pkc STATIC ${PKC_SOURCES})

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_pkc PRIVATE /wd5045)
endif()

# Ensure noxtls_config.h at repo root is found (NOXTLS_LIB_ROOT is noxtls-lib/)
get_filename_component(_project_root "${NOXTLS_LIB_ROOT}/.." ABSOLUTE)
target_include_directories(noxtls_pkc PUBLIC
    ${_project_root}
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/pkc
    ${NOXTLS_LIB_ROOT}/pkc/rsa
    ${NOXTLS_LIB_ROOT}/pkc/ecc
    ${NOXTLS_LIB_ROOT}/pkc/ecdsa
    ${NOXTLS_LIB_ROOT}/pkc/ecdh
    ${NOXTLS_LIB_ROOT}/pkc/dh
    ${NOXTLS_LIB_ROOT}/pkc/x25519
    ${NOXTLS_LIB_ROOT}/pkc/x448
    ${NOXTLS_LIB_ROOT}/pkc/ed25519
    ${NOXTLS_LIB_ROOT}/pkc/ed448
    ${NOXTLS_LIB_ROOT}/pkc/dsa
    ${NOXTLS_LIB_ROOT}/pkc/mlkem
    ${NOXTLS_LIB_ROOT}/pkc/mldsa
    ${NOXTLS_LIB_ROOT}/mdigest
)

target_link_libraries(noxtls_pkc PRIVATE
    noxtls_hash
    noxtls_common
    noxtls_drbg
)

if(NOXTLS_ECDSA_VERIFY_DEBUG)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_VERIFY_DEBUG)
endif()
if(NOXTLS_ECC_LADDER_ONLY)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0)
endif()

if(USE_REF_ECC_POINT_MUL)
endif()

