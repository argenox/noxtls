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
* File:    noxtls_slhdsa.h
* Summary: SLH-DSA (NIST FIPS 205) API and parameter contracts definition
*
*
*****************************************************************************/

#ifndef NOXTLS_SLHDSA_H_
#define NOXTLS_SLHDSA_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef uint32_t noxtls_slhdsa_param_t;
#define NOXTLS_SLHDSA_NONE       ((noxtls_slhdsa_param_t)0U)
#define NOXTLS_SLHDSA_SHA2_128S  ((noxtls_slhdsa_param_t)1U)
#define NOXTLS_SLHDSA_SHA2_128F  ((noxtls_slhdsa_param_t)2U)
#define NOXTLS_SLHDSA_SHA2_192S  ((noxtls_slhdsa_param_t)3U)
#define NOXTLS_SLHDSA_SHA2_192F  ((noxtls_slhdsa_param_t)4U)
#define NOXTLS_SLHDSA_SHA2_256S  ((noxtls_slhdsa_param_t)5U)
#define NOXTLS_SLHDSA_SHA2_256F  ((noxtls_slhdsa_param_t)6U)
#define NOXTLS_SLHDSA_SHAKE_128S ((noxtls_slhdsa_param_t)7U)
#define NOXTLS_SLHDSA_SHAKE_128F ((noxtls_slhdsa_param_t)8U)
#define NOXTLS_SLHDSA_SHAKE_192S ((noxtls_slhdsa_param_t)9U)
#define NOXTLS_SLHDSA_SHAKE_192F ((noxtls_slhdsa_param_t)10U)
#define NOXTLS_SLHDSA_SHAKE_256S ((noxtls_slhdsa_param_t)11U)
#define NOXTLS_SLHDSA_SHAKE_256F ((noxtls_slhdsa_param_t)12U)

#define NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN 64U
#define NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN 128U
#define NOXTLS_SLHDSA_MAX_SIGNATURE_LEN 49856u
#define NOXTLS_SLHDSA_MAX_CONTEXT_LEN 255u

typedef struct
{
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint32_t security_category;
    uint8_t hash_family_sha2;
    uint8_t small_variant;
} slhdsa_sizes_t;

#if NOXTLS_FEATURE_SLH_DSA
uint32_t noxtls_slhdsa_public_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_secret_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_signature_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_security_category(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_sha2(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_small(noxtls_slhdsa_param_t param);

noxtls_return_t noxtls_slhdsa_keygen(noxtls_slhdsa_param_t param,
                                     uint8_t *public_key,
                                     uint8_t *secret_key);
noxtls_return_t noxtls_slhdsa_sign(noxtls_slhdsa_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *noxtls_message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len);
noxtls_return_t noxtls_slhdsa_verify(noxtls_slhdsa_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len);

/*
 * FIPS 205 interface notes:
 *  - noxtls_slhdsa_sign / noxtls_slhdsa_verify implement the pure external
 *    interface (slh_sign / slh_verify) with an empty context string, i.e. the
 *    signed message is M' = 0x00 || 0x00 || M.  Signing is hedged (fresh
 *    DRBG randomness for opt_rand).
 *  - The *_ctx variants take a context string of at most 255 bytes.
 *  - The *_internal variants operate on a caller-formatted M' (FIPS 205
 *    slh_sign_internal / slh_verify_internal); addrnd == NULL selects the
 *    deterministic variant (opt_rand = PK.seed).
 *  - noxtls_slhdsa_keygen_from_seed is slh_keygen_internal(SK.seed, SK.prf, PK.seed);
 *    each seed is n bytes (16/24/32 for the 128/192/256 sets).
 */
noxtls_return_t noxtls_slhdsa_keygen_from_seed(noxtls_slhdsa_param_t param,
                                               const uint8_t *sk_seed,
                                               const uint8_t *sk_prf,
                                               const uint8_t *pk_seed,
                                               uint8_t *public_key,
                                               uint8_t *secret_key);
noxtls_return_t noxtls_slhdsa_sign_ctx(noxtls_slhdsa_param_t param,
                                       const uint8_t *secret_key,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       const uint8_t *ctx,
                                       uint32_t ctx_len,
                                       uint8_t *signature,
                                       uint32_t *signature_len);
noxtls_return_t noxtls_slhdsa_verify_ctx(noxtls_slhdsa_param_t param,
                                         const uint8_t *public_key,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t *ctx,
                                         uint32_t ctx_len,
                                         const uint8_t *signature,
                                         uint32_t signature_len);
noxtls_return_t noxtls_slhdsa_sign_internal(noxtls_slhdsa_param_t param,
                                            const uint8_t *secret_key,
                                            const uint8_t *noxtls_message,
                                            uint32_t message_len,
                                            const uint8_t *addrnd,
                                            uint8_t *signature,
                                            uint32_t *signature_len);
noxtls_return_t noxtls_slhdsa_verify_internal(noxtls_slhdsa_param_t param,
                                              const uint8_t *public_key,
                                              const uint8_t *noxtls_message,
                                              uint32_t message_len,
                                              const uint8_t *signature,
                                              uint32_t signature_len);

#endif /* NOXTLS_FEATURE_SLH_DSA */
#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_SLHDSA_H_ */
