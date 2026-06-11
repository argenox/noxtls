# Public Key Cryptography library
# This library contains implementations of public key cryptography algorithms
# including RSA, ECC (Elliptic Curve Cryptography), ECDSA, ECDH, etc.
#
option(USE_REF_ECC_POINT_MUL "Use reference ECC point multiply for tests" OFF)
option(NOXTLS_ECDSA_VERIFY_DEBUG "Enable ECDSA verify debug prints (hex dumps of h, r, s, u1, u2, v)" OFF)
option(NOXTLS_ECDSA_SIGN_SELF_VERIFY "Re-verify signatures inside noxtls_ecdsa_sign (safety check)" OFF)
option(NOXTLS_ECDSA_SIGN_SKIP_SELF_VERIFY_P256 "Skip sign-time self-verify for 32-byte curves (P-256 class) to improve performance" ON)
# Force Montgomery ladder only (disable windowed scalar mult). Use to isolate windowed-path bugs.
option(NOXTLS_ECC_LADDER_ONLY "Use Montgomery ladder only for ECC point multiply (set NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0)" OFF)

set(PKC_SOURCES
)

# Multiprecision backend shared by classic PKC primitives.
# NOXTLS_CFG_ED25519_FIELD_MATH preserves legacy Ed25519-over-bignum builds.
if(NOXTLS_CFG_FEATURE_BIGNUM OR NOXTLS_CFG_ED25519_FIELD_MATH)
    list(APPEND PKC_SOURCES rsa/noxtls_bignum.c rsa/noxtls_bn_platform.c)
endif()
if(NOT NOXTLS_CFG_FEATURE_BIGNUM AND
   (NOXTLS_CFG_FEATURE_RSA OR
    NOXTLS_CFG_FEATURE_DSA OR
    NOXTLS_CFG_FEATURE_ECC OR
    NOXTLS_CFG_FEATURE_ECDSA OR
    NOXTLS_CFG_FEATURE_DH OR
    NOXTLS_CFG_FEATURE_X448 OR
    NOXTLS_CFG_FEATURE_ED448 OR
    NOXTLS_CFG_FEATURE_FALCON))
    message(FATAL_ERROR
        "NOXTLS_CFG_FEATURE_BIGNUM must be ON for RSA/DSA/ECC/ECDSA/DH/X448/ED448/FALCON.")
endif()
if(NOXTLS_CFG_FEATURE_RSA)
    list(APPEND PKC_SOURCES rsa/noxtls_rsa.c)
endif()
if(ESP_PLATFORM AND NOXTLS_CFG_FEATURE_PKC)
    set(_noxtls_esp32_bignum "${NOXTLS_ESP_IDF_DIR}/target/esp32/noxtls_esp32_bignum_mpi.c")
    if(EXISTS "${_noxtls_esp32_bignum}")
        list(APPEND PKC_SOURCES "${_noxtls_esp32_bignum}")
    endif()
endif()
if(NOXTLS_CFG_FEATURE_ECC)
    list(APPEND PKC_SOURCES ecc/noxtls_ecc.c)
    if(ESP_PLATFORM)
        set(_noxtls_esp32_ecc "${NOXTLS_ESP_IDF_DIR}/target/esp32/noxtls_esp32_ecc_accel.c")
        if(EXISTS "${_noxtls_esp32_ecc}")
            list(APPEND PKC_SOURCES "${_noxtls_esp32_ecc}")
        else()
            list(APPEND PKC_SOURCES ecc/noxtls_ecc_accel_port.c)
        endif()
    else()
        list(APPEND PKC_SOURCES ecc/noxtls_ecc_accel_port.c)
    endif()
endif()
if(NOXTLS_CFG_FEATURE_ECDSA)
    list(APPEND PKC_SOURCES ecdsa/noxtls_ecdsa.c)
    if(ESP_PLATFORM)
        set(_noxtls_esp32_ecdsa "${NOXTLS_ESP_IDF_DIR}/target/esp32/noxtls_esp32_ecdsa_accel.c")
        if(EXISTS "${_noxtls_esp32_ecdsa}")
            list(APPEND PKC_SOURCES "${_noxtls_esp32_ecdsa}")
        else()
            list(APPEND PKC_SOURCES ecdsa/noxtls_ecdsa_accel_port.c)
        endif()
    else()
        list(APPEND PKC_SOURCES ecdsa/noxtls_ecdsa_accel_port.c)
    endif()
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
        mldsa/noxtls_mldsa_internal.c
        mldsa/noxtls_mldsa_backend.c
        mldsa/noxtls_mldsa_sampling.c
        mldsa/noxtls_mldsa_packing.c
        mldsa/noxtls_mldsa_ntt.c
        mldsa/noxtls_mldsa_polyarith.c
        mldsa/noxtls_mldsa_polyvec.c
        mldsa/noxtls_mldsa_challenge.c
        mldsa/noxtls_mldsa_hint.c
        mldsa/noxtls_mldsa_sigcodec.c
    )
endif()
if(NOXTLS_CFG_FEATURE_SLH_DSA)
    list(APPEND PKC_SOURCES slhdsa/noxtls_slhdsa.c)
endif()
if(NOXTLS_CFG_FEATURE_FALCON)
    list(APPEND PKC_SOURCES
        falcon/noxtls_falcon.c
        falcon/noxtls_falcon_internal.c
    )
endif()
if(NOXTLS_CFG_FEATURE_LMS_HSS)
    list(APPEND PKC_SOURCES lms/noxtls_lms.c)
endif()
if(NOXTLS_CFG_FEATURE_XMSS)
    list(APPEND PKC_SOURCES xmss/noxtls_xmss.c)
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
    ${NOXTLS_LIB_ROOT}/pkc/slhdsa
    ${NOXTLS_LIB_ROOT}/pkc/falcon
    ${NOXTLS_LIB_ROOT}/pkc/lms
    ${NOXTLS_LIB_ROOT}/pkc/xmss
    ${NOXTLS_LIB_ROOT}/mdigest
)

target_link_libraries(noxtls_pkc PRIVATE
    noxtls_hash
    noxtls_common
    noxtls_drbg
)
if(NOT MSVC)
    target_link_libraries(noxtls_pkc PRIVATE m)
endif()

if(NOXTLS_ECDSA_VERIFY_DEBUG)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_VERIFY_DEBUG)
endif()
if(NOXTLS_ECDSA_SIGN_SELF_VERIFY)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_SIGN_SELF_VERIFY=1)
else()
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_SIGN_SELF_VERIFY=0)
endif()
if(NOXTLS_ECDSA_SIGN_SKIP_SELF_VERIFY_P256)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_SIGN_SKIP_SELF_VERIFY_P256=1)
else()
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECDSA_SIGN_SKIP_SELF_VERIFY_P256=0)
endif()
if(NOXTLS_ECC_LADDER_ONLY)
    target_compile_definitions(noxtls_pkc PRIVATE NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0)
endif()

if(USE_REF_ECC_POINT_MUL)
endif()
