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
* File:    noxtls_falcon_internal.h
* Summary: Falcon (round-3 specification) internal backend: encodings,
*          hash-to-point, NTT mod q, FFT, fast-Fourier sampling and NTRUGen.
*
*****************************************************************************/

#ifndef NOXTLS_FALCON_INTERNAL_H_
#define NOXTLS_FALCON_INTERNAL_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Falcon modulus `q`. */
#define NOXTLS_FALCON_Q                12289u
/** Maximum supported Falcon ring degree. */
#define NOXTLS_FALCON_MAX_N            1024U
/** Maximum supported log2 of the ring degree. */
#define NOXTLS_FALCON_MAX_LOGN         10U
/** Falcon nonce/salt length in bytes. */
#define NOXTLS_FALCON_SALT_LEN         40U
/** Length of the signing-RNG seed drawn per signing attempt (reference layout). */
#define NOXTLS_FALCON_SIGN_SEED_LEN    48U
/** Length of the key-generation RNG seed. */
#define NOXTLS_FALCON_KEYGEN_SEED_LEN  48U
/** Serialized public-key header high nibble. */
#define NOXTLS_FALCON_PUBLIC_KEY_HDR   0x00u
/** Serialized secret-key header high nibble. */
#define NOXTLS_FALCON_PRIVATE_KEY_HDR  0x50u
/** Serialized compressed / padded signature header high nibble. */
#define NOXTLS_FALCON_SIG_COMP_HDR     0x30u

/**
 * @brief Resolved Falcon parameter-set constants.
 */
typedef struct
{
    noxtls_falcon_param_t param;
    uint8_t logn;
    uint16_t n;
    uint8_t fg_bits;
    uint8_t F_bits;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint32_t l2bound;
} noxtls_falcon_param_spec_t;

/**
 * @brief Bit-level writer used by Falcon serialization helpers.
 */
typedef struct
{
    uint8_t *buf;
    uint32_t bit_len;
    uint32_t bit_pos;
} falcon_bit_writer_t;

/**
 * @brief Bit-level reader used by Falcon serialization helpers.
 */
typedef struct
{
    const uint8_t *buf;
    uint32_t bit_len;
    uint32_t bit_pos;
} falcon_bit_reader_t;

/**
 * @brief Resolve the fixed constants for a supported Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[out] spec Output specification record.
 * @return `NOXTLS_RETURN_SUCCESS`, `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_INVALID_PARAM`.
 */
noxtls_return_t noxtls_falcon_internal_get_param_spec(noxtls_falcon_param_t param,
                                                      noxtls_falcon_param_spec_t *spec);

/**
 * @brief Encode a public key `h` (14 bits per coefficient, header `0x00 | logn`).
 */
noxtls_return_t noxtls_falcon_encode_public_key(const noxtls_falcon_param_spec_t *spec,
                                                const uint16_t *h,
                                                uint8_t *encoded,
                                                uint32_t encoded_len);

/**
 * @brief Decode and range-check a public key; every coefficient must be `< q`.
 */
noxtls_return_t noxtls_falcon_decode_public_key(const noxtls_falcon_param_spec_t *spec,
                                                const uint8_t *encoded,
                                                uint32_t encoded_len,
                                                uint16_t *h);

/**
 * @brief Encode a secret key `(f, g, F)` (header `0x50 | logn`).
 */
noxtls_return_t noxtls_falcon_encode_private_key(const noxtls_falcon_param_spec_t *spec,
                                                 const int8_t *f,
                                                 const int8_t *g,
                                                 const int8_t *F,
                                                 uint8_t *encoded,
                                                 uint32_t encoded_len);

/**
 * @brief Decode a secret key `(f, g, F)`; rejects the forbidden value `-2^(bits-1)`.
 */
noxtls_return_t noxtls_falcon_decode_private_key(const noxtls_falcon_param_spec_t *spec,
                                                 const uint8_t *encoded,
                                                 uint32_t encoded_len,
                                                 int8_t *f,
                                                 int8_t *g,
                                                 int8_t *F);

/**
 * @brief Compress `s2` (sign, 7 low bits, unary high part) into `encoded`.
 *
 * @param[out] used_len Number of bytes actually used (the rest of `encoded` is zeroed).
 * @return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` when the encoding does not fit,
 *         `NOXTLS_RETURN_INVALID_PARAM` when a coefficient is out of range.
 */
noxtls_return_t noxtls_falcon_comp_encode(const int16_t *s2,
                                          uint32_t coeff_count,
                                          uint8_t *encoded,
                                          uint32_t encoded_len,
                                          uint32_t *used_len);

/**
 * @brief Decompress `s2`; rejects `-0`, values above 2047 and non-zero trailing bits.
 */
noxtls_return_t noxtls_falcon_comp_decode(const uint8_t *encoded,
                                          uint32_t encoded_len,
                                          int16_t *s2,
                                          uint32_t coeff_count);

/**
 * @brief Hash `salt || message` to a point of Z_q[x]/(x^n + 1) (SHAKE-256, rejection on 61445).
 */
noxtls_return_t noxtls_falcon_hash_to_point(const uint8_t *salt,
                                            const uint8_t *message,
                                            uint32_t message_len,
                                            uint16_t *c,
                                            uint32_t n);

/** @return Bytes of workspace required by noxtls_falcon_internal_keygen() for `logn`. */
uint32_t noxtls_falcon_internal_keygen_ws_len(uint8_t logn);
/** @return Bytes of workspace required by the signing core for `logn`. */
uint32_t noxtls_falcon_internal_sign_ws_len(uint8_t logn);
/** @return Bytes of workspace required by noxtls_falcon_internal_verify() for `logn`. */
uint32_t noxtls_falcon_internal_verify_ws_len(uint8_t logn);

/**
 * @brief Generate a Falcon key pair from a seeded SHAKE-256 stream (NTRUGen).
 *
 * @param[in] spec Parameter set.
 * @param[in,out] rng Finalized SHAKE-256 context used as randomness source.
 * @param[out] f,g,F,G Secret polynomials (n entries each).
 * @param[out] h Public polynomial `g/f mod q`.
 * @param[in] ws Workspace (8-byte aligned) of noxtls_falcon_internal_keygen_ws_len() bytes.
 * @return `NOXTLS_RETURN_SUCCESS`, or `NOXTLS_RETURN_FAILED` when this candidate is rejected
 *         (the caller samples again), or another error code.
 */
noxtls_return_t noxtls_falcon_internal_keygen(const noxtls_falcon_param_spec_t *spec,
                                              noxtls_sha3_ctx_t *rng,
                                              int8_t *f,
                                              int8_t *g,
                                              int8_t *F,
                                              int8_t *G,
                                              uint16_t *h,
                                              void *ws,
                                              uint32_t ws_len);

/**
 * @brief Recompute `G = g*F/f mod q` (centered) and reject keys with `|G| > 127`.
 *
 * @param[in] tmp Scratch of `4*n` bytes (2-byte aligned).
 */
noxtls_return_t noxtls_falcon_internal_complete_private(const noxtls_falcon_param_spec_t *spec,
                                                        const int8_t *f,
                                                        const int8_t *g,
                                                        const int8_t *F,
                                                        int8_t *G,
                                                        uint16_t *tmp);

/**
 * @brief Compute the public key `h = g/f mod q`; fails if `f` is not invertible.
 *
 * @param[in] tmp Scratch of `2*n` bytes.
 */
noxtls_return_t noxtls_falcon_internal_compute_public(const noxtls_falcon_param_spec_t *spec,
                                                      const int8_t *f,
                                                      const int8_t *g,
                                                      uint16_t *h,
                                                      uint16_t *tmp);

/**
 * @brief Produce `s2` for the hashed message `hm` (ffSampling over the dynamic LDL tree).
 *
 * Mirrors the Falcon reference `sign_dyn`: each attempt seeds a ChaCha20 PRNG
 * from 56 bytes of `rng`, samples with SamplerZ and accepts when the aggregate
 * vector `(s1, s2)` is within the squared-norm bound.
 *
 * @param[in] ws Workspace of noxtls_falcon_internal_sign_ws_len() bytes (8-byte aligned);
 *               the first `72*n` bytes are used as floating-point scratch.
 */
noxtls_return_t noxtls_falcon_internal_sign_dyn(const noxtls_falcon_param_spec_t *spec,
                                                noxtls_sha3_ctx_t *rng,
                                                const int8_t *f,
                                                const int8_t *g,
                                                const int8_t *F,
                                                const int8_t *G,
                                                const uint16_t *hm,
                                                int16_t *s2,
                                                void *ws);

/**
 * @brief Expand a secret key and sign with explicit nonce and RNG seed (reference `crypto_sign` flow).
 *
 * Test/vector hook: with the NIST KAT DRBG outputs as `salt` and `seed` this reproduces the
 * round-3 KAT signatures.  `comp` receives the compressed `s2` (variable length, no header).
 *
 * @param[in] ws Workspace of noxtls_falcon_internal_sign_ws_len() bytes (8-byte aligned).
 */
noxtls_return_t noxtls_falcon_internal_sign_seeded(const noxtls_falcon_param_spec_t *spec,
                                                   const uint8_t *secret_key,
                                                   const uint8_t *message,
                                                   uint32_t message_len,
                                                   const uint8_t *salt,
                                                   const uint8_t *seed,
                                                   uint32_t seed_len,
                                                   uint8_t *comp,
                                                   uint32_t comp_cap,
                                                   uint32_t *comp_len,
                                                   void *ws);

/**
 * @brief Verify a decoded signature `(salt, s2)` against an encoded public key.
 *
 * @param[in] ws Workspace of noxtls_falcon_internal_verify_ws_len() bytes.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, `NOXTLS_RETURN_FAILED` if not short enough,
 *         `NOXTLS_RETURN_BAD_DATA` for malformed keys.
 */
noxtls_return_t noxtls_falcon_internal_verify(const noxtls_falcon_param_spec_t *spec,
                                              const uint8_t *public_key,
                                              const uint8_t *salt,
                                              const uint8_t *message,
                                              uint32_t message_len,
                                              const int16_t *s2,
                                              void *ws);

/**
 * @brief Test hook: `exp(-x) * ccs * 2^63` with the integer polynomial of the specification.
 */
uint64_t noxtls_falcon_internal_expm_p63(double x, double ccs);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FALCON_INTERNAL_H_ */
