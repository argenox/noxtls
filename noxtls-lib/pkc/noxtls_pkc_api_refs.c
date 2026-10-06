/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_pkc_api_refs.c
* Summary: Second-TU references for public PKC APIs (MISRA Rule 8.7).
*****************************************************************************/

#include <stdint.h>
#include "noxtls_misra_refs.h"

#include "noxtls_config.h"
#if NOXTLS_FEATURE_RSA || NOXTLS_FEATURE_DSA || NOXTLS_FEATURE_ECC || NOXTLS_FEATURE_DH
#include "rsa/noxtls_bn_platform.h"
#endif
#if NOXTLS_FEATURE_DSA
#include "dsa/noxtls_dsa.h"
#endif
#if NOXTLS_FEATURE_ECC
#include "ecc/noxtls_ecc.h"
#endif
#if NOXTLS_FEATURE_ECDH
#include "ecdh/noxtls_ecdh.h"
#endif
#if NOXTLS_FEATURE_X25519
#include "x25519/noxtls_x25519.h"
#endif

#if NOXTLS_FEATURE_ED25519
#include "ed25519/noxtls_ed25519.h"
#endif

#if NOXTLS_FEATURE_ECDSA
#include "ecdsa/noxtls_ecdsa.h"
#endif

#if NOXTLS_FEATURE_RSA
#include "rsa/noxtls_rsa.h"
#endif

#if NOXTLS_FEATURE_X448
#include "x448/noxtls_x448.h"
#endif
#if NOXTLS_FEATURE_ML_DSA
#include "mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_ML_KEM
#include "mlkem/noxtls_mlkem.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "slhdsa/noxtls_slhdsa.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "falcon/noxtls_falcon.h"
#endif

static void noxtls_pkc_misra_api_refs(void)
{
#if NOXTLS_FEATURE_RSA || NOXTLS_FEATURE_DSA || NOXTLS_FEATURE_ECC || NOXTLS_FEATURE_DH
    NOXTLS_MISRA_REF_FN(&noxtls_bn_platform_register);
#endif
#if NOXTLS_FEATURE_DSA
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_key_free);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_key_generate);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_key_init);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_key_set_private);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_key_set_public);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_sign);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_signature_free);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_signature_init);
    NOXTLS_MISRA_REF_FN(&noxtls_dsa_verify);
#endif
#if NOXTLS_FEATURE_ECC
    NOXTLS_MISRA_REF_FN(&noxtls_ecc_point_mul_window_size);
    NOXTLS_MISRA_REF_FN(&noxtls_ecc_point_multiply_uses_ref);
#endif
#if NOXTLS_FEATURE_ECDH
    NOXTLS_MISRA_REF_FN(&noxtls_ecdh_compute_shared_secret);
#endif
#if NOXTLS_FEATURE_X25519
    NOXTLS_MISRA_REF_FN(&noxtls_x25519_clamp_scalar);
    NOXTLS_MISRA_REF_FN(&noxtls_x25519_public_key);
    { uint32_t v = (uint32_t)NOXTLS_X25519_BN_PRODUCT_BYTES; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_X25519_BN_SUM_BYTES; (void)v; }
#endif
#if NOXTLS_FEATURE_ED25519
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_generate_key);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_public_key);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_verify_stream_final);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_verify_stream_init);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_verify_stream_update);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519_verify_split);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519ctx_sign);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519ctx_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519ph_sign);
    NOXTLS_MISRA_REF_FN(&noxtls_ed25519ph_verify);
    { uint32_t v = (uint32_t)NOXTLS_ED25519_SCALAR_WIDE_BYTES; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_ED25519_BN_SUM_WORK_BYTES; (void)v; }
#endif
#if NOXTLS_FEATURE_ECDSA
    NOXTLS_MISRA_REF_FN(&noxtls_ecdsa_last_sign_timing);
#endif
#if NOXTLS_FEATURE_RSA
    NOXTLS_MISRA_REF_FN(&noxtls_rsa_decrypt);
    NOXTLS_MISRA_REF_FN(&noxtls_rsa_key_generate);
    NOXTLS_MISRA_REF_FN(&noxtls_rsa_key_init);
    NOXTLS_MISRA_REF_FN(&noxtls_rsa_decrypt_crt_only);
#endif
#if NOXTLS_FEATURE_X448
    NOXTLS_MISRA_REF_FN(&noxtls_x448_clamp_scalar);
    NOXTLS_MISRA_REF_FN(&noxtls_x448_public_key);
#endif
#if NOXTLS_FEATURE_ECC
    NOXTLS_MISRA_REF_FN(&noxtls_ecc_point_add);
    NOXTLS_MISRA_REF_FN(&noxtls_ecc_point_double);
#endif
#if NOXTLS_FEATURE_ML_DSA
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_MAX_SIGNATURE_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_SEED_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_RND_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_MAX_CONTEXT_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_PURE_PRE_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_MLDSA_TEST_OVERRIDE_PRE_LEN; (void)v; }
#endif
#if NOXTLS_FEATURE_ML_KEM
    { uint32_t v = (uint32_t)NOXTLS_MLKEM_SHARED_SECRET_LEN; (void)v; }
    { uint32_t v = (uint32_t)MLKEM_N; (void)v; }
    { uint32_t v = (uint32_t)MLKEM_QINV; (void)v; }
#endif
#if NOXTLS_FEATURE_SLH_DSA
    { uint32_t v = (uint32_t)NOXTLS_SLHDSA_MAX_CONTEXT_LEN; (void)v; }
    { uint32_t v = (uint32_t)NOXTLS_SLHDSA_MAX_SIGNATURE_LEN; (void)v; }
#endif
#if NOXTLS_FEATURE_FALCON
    { uint32_t v = (uint32_t)NOXTLS_FALCON_MAX_SIGNATURE_LEN; (void)v; }
#endif
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_pkc_misra_api_refs_keep(void)
{
    noxtls_pkc_misra_api_refs();
}
