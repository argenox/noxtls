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
* File:    noxtls_mlkem.h
* Summary: ML-KEM (NIST FIPS 203) API surface.
*
*
*****************************************************************************/

#ifndef NOXTLS_MLKEM_H_
#define NOXTLS_MLKEM_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef uint32_t noxtls_mlkem_param_t;
#define NOXTLS_MLKEM_NONE  ((noxtls_mlkem_param_t)0U)
#define NOXTLS_MLKEM_512   ((noxtls_mlkem_param_t)1U)
#define NOXTLS_MLKEM_768   ((noxtls_mlkem_param_t)2U)
#define NOXTLS_MLKEM_1024  ((noxtls_mlkem_param_t)3U)

#define NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN 1568u
#define NOXTLS_MLKEM_MAX_SECRET_KEY_LEN 3168u
#define NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN 1568u
#define NOXTLS_MLKEM_SHARED_SECRET_LEN 32U

#define MLKEM_Q 3329
#define MLKEM_N 256
#define MLKEM_MAX_K 4
#define MLKEM_POLY12_BYTES 384u
#define MLKEM_QINV (-3327)

typedef struct
{
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
    uint8_t du;
    uint8_t dv;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t ciphertext_len;
} mlkem_params_t;

typedef struct
{
    int16_t c[MLKEM_N];
} mlkem_poly_t;

typedef struct
{
    mlkem_poly_t v[MLKEM_MAX_K];
} mlkem_polyvec_t;

#if NOXTLS_FEATURE_ML_KEM
uint32_t noxtls_mlkem_public_key_len(noxtls_mlkem_param_t param);
uint32_t noxtls_mlkem_secret_key_len(noxtls_mlkem_param_t param);
uint32_t noxtls_mlkem_ciphertext_len(noxtls_mlkem_param_t param);

noxtls_return_t noxtls_mlkem_keygen(noxtls_mlkem_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
noxtls_return_t noxtls_mlkem_encaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);
noxtls_return_t noxtls_mlkem_decaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *secret_key,
                                    const uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);

/**
 * Deterministic ML-KEM.KeyGen_internal (FIPS 203 Alg. 16) from the 32-byte
 * seeds d and z. Intended for known-answer tests and key derivation from an
 * externally managed seed.
 */
noxtls_return_t noxtls_mlkem_keygen_derand(noxtls_mlkem_param_t param,
                                           const uint8_t *d,
                                           const uint8_t *z,
                                           uint8_t *public_key,
                                           uint8_t *secret_key);
/**
 * Deterministic ML-KEM.Encaps_internal (FIPS 203 Alg. 17) with the 32-byte
 * message m; performs the encapsulation-key modulus check.
 */
noxtls_return_t noxtls_mlkem_encaps_derand(noxtls_mlkem_param_t param,
                                           const uint8_t *public_key,
                                           const uint8_t *m,
                                           uint8_t *ciphertext,
                                           uint8_t *shared_secret_32);
/**
 * @brief Length-checked ML-KEM.Encaps for untrusted peer keys.
 *
 * Same as noxtls_mlkem_encaps(), but first requires @p public_key_len to equal
 * noxtls_mlkem_public_key_len(@p param), so a short peer value is rejected
 * instead of being over-read. Use this for keys received from the network.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Peer encapsulation key.
 * @param[in] public_key_len Length of @p public_key in bytes.
 * @param[out] ciphertext Ciphertext (noxtls_mlkem_ciphertext_len bytes).
 * @param[out] shared_secret_32 32-byte shared secret.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_BAD_DATA (wrong length or invalid key) or an entropy/hash error.
 */
noxtls_return_t noxtls_mlkem_encaps_ex(noxtls_mlkem_param_t param,
                                       const uint8_t *public_key,
                                       uint32_t public_key_len,
                                       uint8_t *ciphertext,
                                       uint8_t *shared_secret_32);
/**
 * @brief Length-checked ML-KEM.Decaps for untrusted ciphertexts.
 *
 * Same as noxtls_mlkem_decaps(), but first requires @p ciphertext_len to equal
 * noxtls_mlkem_ciphertext_len(@p param), so a short peer ciphertext is
 * rejected instead of being over-read. Use this for ciphertexts received from
 * the network.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Own encapsulation key.
 * @param[in] secret_key Own decapsulation key.
 * @param[in] ciphertext Peer ciphertext.
 * @param[in] ciphertext_len Length of @p ciphertext in bytes.
 * @param[out] shared_secret_32 32-byte shared secret.
 * @return As noxtls_mlkem_decaps(), plus NOXTLS_RETURN_BAD_DATA for a wrong length.
 */
noxtls_return_t noxtls_mlkem_decaps_ex(noxtls_mlkem_param_t param,
                                       const uint8_t *public_key,
                                       const uint8_t *secret_key,
                                       const uint8_t *ciphertext,
                                       uint32_t ciphertext_len,
                                       uint8_t *shared_secret_32);
/** FIPS 203 §7.2 encapsulation-key modulus check (NOXTLS_RETURN_BAD_DATA if invalid). */
noxtls_return_t noxtls_mlkem_check_public_key(noxtls_mlkem_param_t param, const uint8_t *public_key);
/** FIPS 203 §7.3 decapsulation-key hash check (NOXTLS_RETURN_BAD_DATA if invalid). */
noxtls_return_t noxtls_mlkem_check_secret_key(noxtls_mlkem_param_t param, const uint8_t *secret_key);

/* Test-only deterministic hook for vector conformance harnesses. */
void noxtls_mlkem_set_test_random_sequence(const uint8_t *bytes, uint32_t byte_len);


#endif /* NOXTLS_FEATURE_ML_KEM */
#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_MLKEM_H_ */
