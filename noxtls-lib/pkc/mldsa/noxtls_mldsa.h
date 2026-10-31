/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_mldsa.h
* Summary: ML-DSA (NIST FIPS 204) API surface.
*
*
*****************************************************************************/

#ifndef NOXTLS_MLDSA_H_
#define NOXTLS_MLDSA_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Unsigned parameter ids (MISRA C:2025 Rule 10.3); values match historical enum. */
typedef uint32_t noxtls_mldsa_param_t;
#define NOXTLS_MLDSA_NONE ((noxtls_mldsa_param_t)0U)
#define NOXTLS_MLDSA_44   ((noxtls_mldsa_param_t)1U)
#define NOXTLS_MLDSA_65   ((noxtls_mldsa_param_t)2U)
#define NOXTLS_MLDSA_87   ((noxtls_mldsa_param_t)3U)

#define NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN 2592u
#define NOXTLS_MLDSA_MAX_SECRET_KEY_LEN 4896u
#define NOXTLS_MLDSA_MAX_SIGNATURE_LEN 4627u
#define NOXTLS_MLDSA_SEED_LEN 32U
#define NOXTLS_MLDSA_RND_LEN 32U
#define NOXTLS_MLDSA_MAX_CONTEXT_LEN 255u
#define NOXTLS_MLDSA_PURE_PRE_LEN (2U + NOXTLS_MLDSA_MAX_CONTEXT_LEN)
#define NOXTLS_MLDSA_TEST_OVERRIDE_PRE_LEN (3U + NOXTLS_MLDSA_MAX_CONTEXT_LEN)

typedef struct
{
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
} mldsa_sizes_t;

/** HashML-DSA pre-hash function identifiers (FIPS 204 Section 5.4). */
typedef uint32_t noxtls_mldsa_prehash_t;
#define NOXTLS_MLDSA_PH_SHA2_224     ((noxtls_mldsa_prehash_t)1U)
#define NOXTLS_MLDSA_PH_SHA2_256     ((noxtls_mldsa_prehash_t)2U)
#define NOXTLS_MLDSA_PH_SHA2_384     ((noxtls_mldsa_prehash_t)3U)
#define NOXTLS_MLDSA_PH_SHA2_512     ((noxtls_mldsa_prehash_t)4U)
#define NOXTLS_MLDSA_PH_SHA2_512_224 ((noxtls_mldsa_prehash_t)5U)
#define NOXTLS_MLDSA_PH_SHA2_512_256 ((noxtls_mldsa_prehash_t)6U)
#define NOXTLS_MLDSA_PH_SHA3_224     ((noxtls_mldsa_prehash_t)7U)
#define NOXTLS_MLDSA_PH_SHA3_256     ((noxtls_mldsa_prehash_t)8U)
#define NOXTLS_MLDSA_PH_SHA3_384     ((noxtls_mldsa_prehash_t)9U)
#define NOXTLS_MLDSA_PH_SHA3_512     ((noxtls_mldsa_prehash_t)10U)
#define NOXTLS_MLDSA_PH_SHAKE128     ((noxtls_mldsa_prehash_t)11U) /**< 32-byte output */
#define NOXTLS_MLDSA_PH_SHAKE256     ((noxtls_mldsa_prehash_t)12U) /**< 64-byte output */

/** Largest value returned by noxtls_mldsa_workspace_len() (ML-DSA-87 sign). */
#define NOXTLS_MLDSA_MAX_WORKSPACE_LEN 11264u

#if NOXTLS_FEATURE_ML_DSA
uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param);
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param);
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param);
/**
 * @brief Workspace bytes covering every operation of a parameter set
 *        (sign (k+3) KiB, verify (l+3) KiB, keygen 3 KiB): 7168 / 9216 / 11264.
 */
uint32_t noxtls_mldsa_workspace_len(noxtls_mldsa_param_t param);
/** @deprecated No-op kept for ABI compatibility; use noxtls_mldsa_keygen_ex() with a seed. */
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len);
/** @deprecated No-op kept for ABI compatibility; use the _ex / _internal signing APIs. */
void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu);

noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len);
noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len);

/*
 * Extended API. Every `ws` argument is an optional caller workspace (4-byte
 * aligned, at least noxtls_mldsa_workspace_len(param) bytes); pass NULL to let
 * the library allocate exactly what the operation needs with NOXTLS_MALLOC.
 * The workspace is wiped before return. `rnd` == NULL selects hedged signing
 * (32 bytes from the DRBG); 32 zero bytes give the deterministic variant.
 * Verification returns NOXTLS_RETURN_SUCCESS for a valid signature,
 * NOXTLS_RETURN_FAILED for an invalid one and NOXTLS_RETURN_INVALID_PARAM for
 * a signature of the wrong length.
 */

/** @brief ML-DSA.KeyGen; seed = 32-byte xi (KeyGen_internal) or NULL for a DRBG seed. */
noxtls_return_t noxtls_mldsa_keygen_ex(noxtls_mldsa_param_t param,
                                       const uint8_t *seed,
                                       uint8_t *public_key,
                                       uint8_t *secret_key,
                                       void *ws,
                                       uint32_t ws_len);
/** @brief Pure ML-DSA.Sign with a context string (ctx_len <= 255). */
noxtls_return_t noxtls_mldsa_sign_ex(noxtls_mldsa_param_t param,
                                     const uint8_t *secret_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *ctx,
                                     uint32_t ctx_len,
                                     const uint8_t *rnd,
                                     uint8_t *signature,
                                     uint32_t *signature_len,
                                     void *ws,
                                     uint32_t ws_len);
/** @brief Pure ML-DSA.Verify with a context string. */
noxtls_return_t noxtls_mldsa_verify_ex(noxtls_mldsa_param_t param,
                                       const uint8_t *public_key,
                                       const uint8_t *message,
                                       uint32_t message_len,
                                       const uint8_t *ctx,
                                       uint32_t ctx_len,
                                       const uint8_t *signature,
                                       uint32_t signature_len,
                                       void *ws,
                                       uint32_t ws_len);
/** @brief HashML-DSA.Sign over a caller-computed digest PH(M). */
noxtls_return_t noxtls_mldsa_hash_sign_ex(noxtls_mldsa_param_t param,
                                          const uint8_t *secret_key,
                                          noxtls_mldsa_prehash_t ph,
                                          const uint8_t *digest,
                                          uint32_t digest_len,
                                          const uint8_t *ctx,
                                          uint32_t ctx_len,
                                          const uint8_t *rnd,
                                          uint8_t *signature,
                                          uint32_t *signature_len,
                                          void *ws,
                                          uint32_t ws_len);
/** @brief HashML-DSA.Verify over a caller-computed digest PH(M). */
noxtls_return_t noxtls_mldsa_hash_verify_ex(noxtls_mldsa_param_t param,
                                            const uint8_t *public_key,
                                            noxtls_mldsa_prehash_t ph,
                                            const uint8_t *digest,
                                            uint32_t digest_len,
                                            const uint8_t *ctx,
                                            uint32_t ctx_len,
                                            const uint8_t *signature,
                                            uint32_t signature_len,
                                            void *ws,
                                            uint32_t ws_len);
/** @brief ML-DSA.Sign_internal over M' (or a 64-byte external mu when external_mu != 0). */
noxtls_return_t noxtls_mldsa_sign_internal(noxtls_mldsa_param_t param,
                                           const uint8_t *secret_key,
                                           const uint8_t *mprime,
                                           uint32_t mprime_len,
                                           uint8_t external_mu,
                                           const uint8_t *rnd,
                                           uint8_t *signature,
                                           uint32_t *signature_len,
                                           void *ws,
                                           uint32_t ws_len);
/** @brief ML-DSA.Verify_internal over M' (or a 64-byte external mu when external_mu != 0). */
noxtls_return_t noxtls_mldsa_verify_internal(noxtls_mldsa_param_t param,
                                             const uint8_t *public_key,
                                             const uint8_t *mprime,
                                             uint32_t mprime_len,
                                             uint8_t external_mu,
                                             const uint8_t *signature,
                                             uint32_t signature_len,
                                             void *ws,
                                             uint32_t ws_len);


#endif /* NOXTLS_FEATURE_ML_DSA */
#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_MLDSA_H_ */
