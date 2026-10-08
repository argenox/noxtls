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
* File:    noxtls_ecjpake_internal.h
* Summary: EC-JPAKE internal interfaces shared by the module source files
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake_internal.h
 * @brief Internal EC-JPAKE scalar, point, ZKP and encoding interfaces.
 * @ingroup noxtls_ecjpake
 *
 * Not part of the public API. Unit tests include this header to exercise
 * the building blocks and to inject deterministic random scalars for the
 * reference-vector test.
 */

#ifndef NOXTLS_ECJPAKE_INTERNAL_H_
#define NOXTLS_ECJPAKE_INTERNAL_H_

#include <stdint.h>

#include "noxtls_ecjpake.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Random source callback: fill rng_out with rng_len random octets.
 *
 * @param[in] rng_user Opaque pointer given to noxtls_ecjpake_set_random_source().
 * @param[out] rng_out Destination.
 * @param[in] rng_len Number of octets.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
typedef noxtls_return_t (*noxtls_ecjpake_random_cb_t)(void *rng_user, uint8_t *rng_out, uint32_t rng_len);

/** @brief One parsed ECJPAKEKeyKP (draft-cragie-tls-ecjpake-01 section 7.1.1). */
typedef struct
{
    uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE];     /**< Public value X. */
    uint8_t V[NOXTLS_ECJPAKE_POINT_SIZE];     /**< ZKP commitment V. */
    uint8_t r[NOXTLS_ECJPAKE_SCALAR_SIZE];    /**< ZKP response r, left-padded to 32 octets. */
} noxtls_ecjpake_key_kp_t;

/* ------------------------------------------------------------------------ */
/* Scalar arithmetic modulo the P-256 order n (noxtls_ecjpake_scalar.c).    */
/* All functions run in time independent of the operand values.             */
/* ------------------------------------------------------------------------ */

/**
 * @brief Reduce a big-endian integer of any length modulo n.
 *
 * @param[in] in Big-endian integer (may be NULL when in_len is 0).
 * @param[in] in_len Length of in.
 * @param[out] out 32-octet result in [0, n-1].
 */
void noxtls_ecjpake_scalar_reduce(const uint8_t *in, uint32_t in_len,
                                  uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/**
 * @brief out = a * b mod n.
 *
 * @param[in] a 32-octet big-endian operand.
 * @param[in] b 32-octet big-endian operand.
 * @param[out] out 32-octet result (may alias a or b).
 */
void noxtls_ecjpake_scalar_mul(const uint8_t a[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               const uint8_t b[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/**
 * @brief out = a - b mod n for a, b in [0, n-1].
 *
 * @param[in] a 32-octet big-endian operand.
 * @param[in] b 32-octet big-endian operand.
 * @param[out] out 32-octet result (may alias a or b).
 */
void noxtls_ecjpake_scalar_sub(const uint8_t a[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               const uint8_t b[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/**
 * @brief Test whether a 32-octet scalar is in [1, n-1].
 *
 * @param[in] scalar Big-endian scalar.
 *
 * @return 1 when valid, 0 otherwise.
 */
uint32_t noxtls_ecjpake_scalar_is_valid(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/**
 * @brief Test whether a 32-octet value is below n (zero allowed).
 *
 * @param[in] scalar Big-endian value.
 *
 * @return 1 when below n, 0 otherwise.
 */
uint32_t noxtls_ecjpake_scalar_is_below_order(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/* ------------------------------------------------------------------------ */
/* Point operations (noxtls_ecjpake_group.c).                               */
/* ------------------------------------------------------------------------ */

/**
 * @brief Validate an encoded point: prefix 0x04, coordinates below p, on curve, not identity.
 *
 * @param[in] point 65-octet encoding.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_BAD_DATA.
 */
noxtls_return_t noxtls_ecjpake_point_validate(const uint8_t point[NOXTLS_ECJPAKE_POINT_SIZE]);

/**
 * @brief out = scalar * P (P = NULL selects the generator G).
 *
 * @param[in] scalar 32-octet big-endian scalar below n (0 gives the identity).
 * @param[in] point 65-octet encoding of P, or NULL for G.
 * @param[out] out 65-octet encoding; all-zero coordinates encode the identity.
 *
 * @return NOXTLS_RETURN_SUCCESS or an ECC error (out erased).
 */
noxtls_return_t noxtls_ecjpake_point_mul(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t *point,
                                         uint8_t out[NOXTLS_ECJPAKE_POINT_SIZE]);

/**
 * @brief out = a + b, or out = a - b when subtract is non-zero.
 *
 * @param[in] a 65-octet encoding (identity allowed).
 * @param[in] b 65-octet encoding (identity allowed).
 * @param[in] subtract Non-zero to compute a - b.
 * @param[out] out 65-octet encoding; all-zero coordinates encode the identity.
 *
 * @return NOXTLS_RETURN_SUCCESS or an ECC error (out erased).
 */
noxtls_return_t noxtls_ecjpake_point_add(const uint8_t a[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t b[NOXTLS_ECJPAKE_POINT_SIZE],
                                         uint32_t subtract,
                                         uint8_t out[NOXTLS_ECJPAKE_POINT_SIZE]);

/**
 * @brief Test whether an encoding holds the identity (all-zero coordinates).
 *
 * @param[in] point 65-octet encoding.
 *
 * @return 1 for the identity, 0 otherwise.
 */
uint32_t noxtls_ecjpake_point_is_identity(const uint8_t point[NOXTLS_ECJPAKE_POINT_SIZE]);

/* ------------------------------------------------------------------------ */
/* Schnorr NIZK (noxtls_ecjpake_zkp.c): RFC 8235 section 3, draft 8.2.      */
/* ------------------------------------------------------------------------ */

/**
 * @brief Compute h = int(SHA-256(len||gen || len||V || len||X || len||id)) mod n.
 *
 * @param[in] gen Generator encoding.
 * @param[in] V Commitment encoding.
 * @param[in] X Public value encoding.
 * @param[in] id User identity octets.
 * @param[in] id_len Length of id.
 * @param[out] h 32-octet challenge.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_ecjpake_zkp_hash(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t V[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t *id, uint32_t id_len,
                                        uint8_t h[NOXTLS_ECJPAKE_SCALAR_SIZE]);

/**
 * @brief Prove knowledge of x for X = gen*x: V = gen*v, r = v - x*h mod n.
 *
 * @param[in] gen Generator encoding.
 * @param[in] x 32-octet secret in [1, n-1].
 * @param[in] X Public value gen*x.
 * @param[in] v 32-octet nonce in [1, n-1].
 * @param[in] id Prover identity.
 * @param[in] id_len Length of id.
 * @param[out] kp Receives X, V and r.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code (kp erased).
 */
noxtls_return_t noxtls_ecjpake_zkp_prove(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t x[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t v[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t *id, uint32_t id_len,
                                         noxtls_ecjpake_key_kp_t *kp);

/**
 * @brief Verify a ZKP: X and V valid, r below n, V == gen*r + X*h.
 *
 * @param[in] gen Generator encoding (not the identity).
 * @param[in] kp Parsed key and proof.
 * @param[in] id Prover identity.
 * @param[in] id_len Length of id.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER for an
 *         invalid point or proof, or another error code.
 */
noxtls_return_t noxtls_ecjpake_zkp_verify(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                          const noxtls_ecjpake_key_kp_t *kp,
                                          const uint8_t *id, uint32_t id_len);

/**
 * @brief Encode an ECJPAKEKeyKP (r in minimal length).
 *
 * @param[in] kp Key and proof.
 * @param[out] out Output buffer.
 * @param[in] out_size Size of out.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_INVALID_PARAM (too small).
 */
noxtls_return_t noxtls_ecjpake_kp_write(const noxtls_ecjpake_key_kp_t *kp,
                                        uint8_t *out, uint32_t out_size, uint32_t *out_len);

/**
 * @brief Decode an ECJPAKEKeyKP (encoding only; no point validation).
 *
 * @param[in] in Input.
 * @param[in] in_len Octets available.
 * @param[out] kp Parsed key and proof.
 * @param[out] used Octets consumed.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR.
 */
noxtls_return_t noxtls_ecjpake_kp_read(const uint8_t *in, uint32_t in_len,
                                       noxtls_ecjpake_key_kp_t *kp, uint32_t *used);

/* ------------------------------------------------------------------------ */
/* Random scalars (noxtls_ecjpake.c).                                       */
/* ------------------------------------------------------------------------ */

/**
 * @brief Override the random source used for secret scalars and nonces.
 *
 * Intended for known-answer tests only. NULL restores the NoxTLS DRBG. Every
 * call also drops the module DRBG instance, so the next DRBG draw re-seeds
 * from the configured entropy source.
 *
 * @param[in] cb Callback or NULL.
 * @param[in] user Opaque pointer passed to cb.
 */
void noxtls_ecjpake_set_random_source(noxtls_ecjpake_random_cb_t cb, void *user);

/**
 * @brief Draw a uniformly random scalar in [1, n-1].
 *
 * @param[out] out 32-octet scalar (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, an RNG error, or NOXTLS_RETURN_FAILED after
 *         NOXTLS_ECJPAKE_MAX_RANDOM_RETRIES zero draws.
 */
noxtls_return_t noxtls_ecjpake_random_scalar(uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ECJPAKE_INTERNAL_H_ */
