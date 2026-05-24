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
* File:    noxtls_falcon.c
* Summary: Falcon/FN-DSA API boundary.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_falcon.h"
#include "noxtls_falcon_internal.h"

/** Maximum number of public Falcon signing attempts before returning failure. */
#define NOXTLS_FALCON_SIGN_MAX_ATTEMPTS 1024U
/** Maximum number of public Falcon key-generation attempts before returning failure. */
#define NOXTLS_FALCON_KEYGEN_MAX_ATTEMPTS 256u

/**
 * @brief Convert a reduced signed 32-bit Falcon polynomial into a signed 16-bit polynomial.
 *
 * @param[in] src Input signed 32-bit coefficients.
 * @param[in] n Number of coefficients to convert.
 * @param[out] dst Output signed 16-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if any coefficient does not fit in signed 16 bits.
 */
static noxtls_return_t falcon_poly_i32_to_i16(const int32_t *src,
                                              uint16_t n,
                                              int16_t *dst)
{
    uint16_t i;

    if(src == NULL || dst == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < n; i++) {
        if(src[i] < (int32_t)INT16_MIN || src[i] > (int32_t)INT16_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        dst[i] = (int16_t)src[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the inclusive Falcon squared-norm acceptance bound for a parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return The inclusive `floor(beta^2)` acceptance bound, or `0` if unsupported.
 */
static uint32_t falcon_get_l2bound(noxtls_falcon_param_t param)
{
    switch(param) {
        case NOXTLS_FALCON_NONE: return 0U;
        case NOXTLS_FALCON_512: return 34034726u;
        case NOXTLS_FALCON_1024: return 70265242u;
        default: return 0U;
    }
}

/**
 * @brief Hash `salt || message` into Falcon challenge coefficients.
 *
 * @param[in] salt 40-byte Falcon nonce/salt.
 * @param[in] message Message bytes. May be `NULL` only when `message_len` is `0`.
 * @param[in] message_len Length of `message` in bytes.
 * @param[out] coeffs Output coefficient array.
 * @param[in] coeff_count Number of coefficients to generate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a hash/parameter error code.
 */
static noxtls_return_t falcon_hash_to_point_salted(const uint8_t *salt,
                                                   const uint8_t *message,
                                                   uint32_t message_len,
                                                   uint16_t *coeffs,
                                                   uint32_t coeff_count)
{
    noxtls_sha3_ctx_t shake;
    uint8_t block[2];
    uint32_t i = 0U;
    uint32_t limit = (65536u / NOXTLS_FALCON_Q) * NOXTLS_FALCON_Q;
    noxtls_return_t rc;

    if(salt == NULL || coeffs == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_shake256_init(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, salt, NOXTLS_FALCON_SALT_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, message, message_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_final(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    while(i < coeff_count) {
        uint32_t t;

        rc = noxtls_shake256_squeeze(&shake, block, sizeof(block));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        t = ((uint32_t)block[0] << 8) | (uint32_t)block[1];
        if(t < limit) {
            coeffs[i++] = (uint16_t)(t % NOXTLS_FALCON_Q);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply an integer polynomial by a Falcon public key modulo `x^n + 1` and `q`.
 *
 * @param[out] out Output polynomial coefficients modulo `q`.
 * @param[in] a Signed integer polynomial.
 * @param[in] b Public-key polynomial modulo `q`.
 * @param[in] n Polynomial degree.
 */
static void falcon_poly_mul_mod_q(uint16_t *out,
                                  const int16_t *a,
                                  const uint16_t *b,
                                  uint16_t n)
{
    int64_t accum[1024];
    uint32_t i;
    uint32_t j;

    memset(accum, 0, sizeof(accum));

    for(i = 0U; i < n; i++) {
        int32_t ai = (int32_t)a[i];
        for(j = 0U; j < n; j++) {
            uint32_t idx = i + j;
            int64_t term = (int64_t)ai * (int64_t)b[j];
            if(idx < n) {
                accum[idx] += term;
            } else {
                accum[idx - n] -= term;
            }
        }
    }

    for(i = 0U; i < n; i++) {
        out[i] = noxtls_falcon_mod_q_reduce_i32((int32_t)(accum[i] % (int64_t)NOXTLS_FALCON_Q));
    }
}

/**
 * @brief Check whether the concatenated Falcon signature vector is short enough.
 *
 * @param[in] s1 First signature vector.
 * @param[in] s2 Second signature vector.
 * @param[in] n Polynomial degree.
 * @param[in] l2bound Inclusive squared-norm bound.
 * @return `1` if the squared norm is within the bound, otherwise `0`.
 */
static uint8_t falcon_is_short(const int16_t *s1,
                               const int16_t *s2,
                               uint16_t n,
                               uint32_t l2bound)
{
    uint64_t norm = 0U;
    uint32_t i;

    for(i = 0U; i < n; i++) {
        int32_t x1 = (int32_t)s1[i];
        int32_t x2 = (int32_t)s2[i];

        norm += (uint64_t)(x1 * x1);
        if(norm > l2bound) {
            return 0U;
        }
        norm += (uint64_t)(x2 * x2);
        if(norm > l2bound) {
            return 0U;
        }
    }

    return 1U;
}

/**
 * @brief Decode the fixed-width padded Falcon signature format used by the public API.
 *
 * @param[in] spec Resolved Falcon parameter specification.
 * @param[in] signature Serialized signature bytes.
 * @param[in] signature_len Length of `signature` in bytes.
 * @param[out] salt Output 40-byte salt.
 * @param[out] s2 Output decoded `s2` coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a serialization error code.
 */
static noxtls_return_t falcon_decode_signature(const noxtls_falcon_param_spec_t *spec,
                                               const uint8_t *signature,
                                               uint32_t signature_len,
                                               uint8_t *salt,
                                               int16_t *s2)
{
    if(spec == NULL || signature == NULL || salt == NULL || s2 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(signature_len != spec->signature_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(signature[0] != (uint8_t)(NOXTLS_FALCON_SIG_COMP_HDR | spec->logn)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    memcpy(salt, signature + 1U, NOXTLS_FALCON_SALT_LEN);
    return noxtls_falcon_comp_decode(signature + 1U + NOXTLS_FALCON_SALT_LEN,
                                     signature_len - 1U - NOXTLS_FALCON_SALT_LEN,
                                     s2,
                                     spec->n);
}

/**
 * @brief Encode the fixed-width padded Falcon signature format used by the public API.
 *
 * @param[in] spec Resolved Falcon parameter specification.
 * @param[in] salt 40-byte Falcon nonce/salt.
 * @param[in] s2 Falcon `s2` signature coefficients.
 * @param[out] signature Output serialized signature.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a serialization error code.
 */
static noxtls_return_t falcon_encode_signature(const noxtls_falcon_param_spec_t *spec,
                                               const uint8_t *salt,
                                               const int16_t *s2,
                                               uint8_t *signature)
{
    uint32_t comp_len;

    if(spec == NULL || salt == NULL || s2 == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(signature, 0, spec->signature_len);
    signature[0] = (uint8_t)(NOXTLS_FALCON_SIG_COMP_HDR | spec->logn);
    memcpy(signature + 1U, salt, NOXTLS_FALCON_SALT_LEN);
    comp_len = spec->signature_len - 1U - NOXTLS_FALCON_SALT_LEN;
    return noxtls_falcon_comp_encode(s2, spec->n, signature + 1U + NOXTLS_FALCON_SALT_LEN, comp_len);
}

/**
 * @brief Scale a Falcon FFT vector by a real scalar in place.
 *
 * @param[in,out] vec FFT vector to scale.
 * @param[in] n Number of coefficients.
 * @param[in] scalar Real scaling factor.
 */
static void falcon_fft_scale_real(noxtls_falcon_complex_t *vec,
                                  uint16_t n,
                                  double scalar)
{
    uint32_t i;

    for(i = 0U; i < n; i++) {
        vec[i].re *= scalar;
        vec[i].im *= scalar;
    }
}

/**
 * @brief Build Falcon's FFT-domain signing target from a hashed challenge and expanded basis.
 *
 * The returned target is the normalized vector corresponding to `[c, 0] / q`
 * in the NTRU lattice basis coordinates.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[in] c Falcon challenge coefficients modulo `q`.
 * @param[out] t0_fft First FFT-domain target component.
 * @param[out] t1_fft Second FFT-domain target component.
 * @param[out] hm_fft Scratch/output FFT of the hashed challenge.
 * @param[in] b01_fft FFT of `-f`.
 * @param[in] b11_fft FFT of `-F`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or a numerical/parameter error code.
 */
static noxtls_return_t falcon_build_sign_target_fft(const noxtls_falcon_expanded_key_t *expanded,
                                                    const uint16_t *c,
                                                    noxtls_falcon_complex_t *t0_fft,
                                                    noxtls_falcon_complex_t *t1_fft,
                                                    noxtls_falcon_complex_t *hm_fft,
                                                    const noxtls_falcon_complex_t *b01_fft,
                                                    const noxtls_falcon_complex_t *b11_fft)
{
    int16_t hm_poly[NOXTLS_FALCON_MAX_N];
    uint32_t i;
    noxtls_return_t rc;

    if(expanded == NULL || c == NULL || t0_fft == NULL || t1_fft == NULL ||
       hm_fft == NULL || b01_fft == NULL || b11_fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < expanded->spec.n; i++) {
        hm_poly[i] = (int16_t)c[i];
    }

    rc = noxtls_falcon_poly_forward_fft(hm_poly, expanded->spec.n, hm_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_fft_pointwise_mul(hm_fft, b11_fft, expanded->spec.n, t0_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_fft_pointwise_mul(hm_fft, b01_fft, expanded->spec.n, t1_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    falcon_fft_scale_real(t0_fft, expanded->spec.n, 1.0 / (double)NOXTLS_FALCON_Q);
    falcon_fft_scale_real(t1_fft, expanded->spec.n, -1.0 / (double)NOXTLS_FALCON_Q);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map a sampled Falcon lattice vector back to the signature pair `(s1, s2)`.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[in] c Falcon challenge coefficients modulo `q`.
 * @param[in] z0_fft First sampled FFT-domain coefficient vector.
 * @param[in] z1_fft Second sampled FFT-domain coefficient vector.
 * @param[in] b00_fft FFT of `g`.
 * @param[in] b01_fft FFT of `-f`.
 * @param[in] b10_fft FFT of `G`.
 * @param[in] b11_fft FFT of `-F`.
 * @param[out] s1 Output first signature vector.
 * @param[out] s2 Output second signature vector.
 * @return `NOXTLS_RETURN_SUCCESS` on success or a numerical/parameter error code.
 */
static noxtls_return_t falcon_sign_map_sample_to_signature(const noxtls_falcon_expanded_key_t *expanded,
                                                           const uint16_t *c,
                                                           const noxtls_falcon_complex_t *z0_fft,
                                                           const noxtls_falcon_complex_t *z1_fft,
                                                           const noxtls_falcon_complex_t *b00_fft,
                                                           const noxtls_falcon_complex_t *b01_fft,
                                                           const noxtls_falcon_complex_t *b10_fft,
                                                           const noxtls_falcon_complex_t *b11_fft,
                                                           int16_t *s1,
                                                           int16_t *s2)
{
    noxtls_falcon_complex_t v0a_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t v0b_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t v1a_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t v1b_fft[NOXTLS_FALCON_MAX_N];
    int16_t v0[NOXTLS_FALCON_MAX_N];
    int16_t v1[NOXTLS_FALCON_MAX_N];
    uint32_t i;
    noxtls_return_t rc;

    if(expanded == NULL || c == NULL || z0_fft == NULL || z1_fft == NULL ||
       b00_fft == NULL || b01_fft == NULL || b10_fft == NULL || b11_fft == NULL ||
       s1 == NULL || s2 == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_fft_pointwise_mul(z0_fft, b00_fft, expanded->spec.n, v0a_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_fft_pointwise_mul(z1_fft, b10_fft, expanded->spec.n, v0b_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_fft_pointwise_mul(z0_fft, b01_fft, expanded->spec.n, v1a_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_fft_pointwise_mul(z1_fft, b11_fft, expanded->spec.n, v1b_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < expanded->spec.n; i++) {
        v0a_fft[i].re += v0b_fft[i].re;
        v0a_fft[i].im += v0b_fft[i].im;
        v1a_fft[i].re += v1b_fft[i].re;
        v1a_fft[i].im += v1b_fft[i].im;
    }
    rc = noxtls_falcon_poly_inverse_fft(v0a_fft, expanded->spec.n, v0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < expanded->spec.n; i++) {
        int32_t diff = (int32_t)c[i] - (int32_t)v0[i];

        if(diff < -32768 || diff > 32767) {
            return NOXTLS_RETURN_FAILED;
        }
        s1[i] = (int16_t)diff;
    }
    rc = noxtls_falcon_poly_inverse_fft(v1a_fft, expanded->spec.n, v1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < expanded->spec.n; i++) {
        if(v1[i] == INT16_MIN) {
            return NOXTLS_RETURN_FAILED;
        }
        s2[i] = (int16_t)(-v1[i]);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the exact serialized public-key length for a Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return Public-key length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_public_key_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;
    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.public_key_len : 0U;
}

/**
 * @brief Get the exact serialized secret-key length for a Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return Secret-key length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_secret_key_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;
    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.secret_key_len : 0U;
}

/**
 * @brief Get the default fixed-width Falcon signature length for a parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return Signature length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_signature_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;
    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.signature_len : 0U;
}

/**
 * @brief Generate a Falcon keypair.
 *
 * @param[in] param Falcon parameter selector.
 * @param[out] public_key Output buffer for the serialized public key.
 * @param[in] public_key_len Size of `public_key` in bytes.
 * @param[out] secret_key Output buffer for the serialized secret key.
 * @param[in] secret_key_len Size of `secret_key` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success.
 * @return `NOXTLS_RETURN_NULL` if a required pointer is `NULL`.
 * @return `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 * @return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` if a buffer length is incorrect.
 * @return `NOXTLS_RETURN_FAILED` if no valid Falcon keypair is found within the bounded retry loop.
 * @return `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY` if the configured entropy source fails.
 */
noxtls_return_t noxtls_falcon_keygen(noxtls_falcon_param_t param,
                                     uint8_t *public_key,
                                     uint32_t public_key_len,
                                     uint8_t *secret_key,
                                     uint32_t secret_key_len)
{
    noxtls_falcon_param_spec_t spec;
    noxtls_falcon_sampler_ctx_t sampler;
    int16_t f[NOXTLS_FALCON_MAX_N];
    int16_t g[NOXTLS_FALCON_MAX_N];
    int32_t F32[NOXTLS_FALCON_MAX_N];
    int32_t G32[NOXTLS_FALCON_MAX_N];
    int16_t F16[NOXTLS_FALCON_MAX_N];
    uint8_t seed[DRBG_SEEDLEN_AES256];
    uint32_t attempt;
    noxtls_return_t rc;

    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(public_key_len != spec.public_key_len || secret_key_len != spec.secret_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    for(attempt = 0U; attempt < NOXTLS_FALCON_KEYGEN_MAX_ATTEMPTS; attempt++) {
        rc = noxtls_drbg_get_entropy(seed, (uint32_t)sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_sampler_init(&sampler, param, seed, (uint32_t)sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_keygen_sample_prechecked_fg(&sampler, param, f, g);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(rc == NOXTLS_RETURN_FAILED) {
                continue;
            }
            return rc;
        }
        rc = noxtls_falcon_keygen_solve_ntru_reduced(f, g, spec.n, F32, G32);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(rc == NOXTLS_RETURN_FAILED) {
                continue;
            }
            return rc;
        }
        rc = falcon_poly_i32_to_i16(F32, spec.n, F16);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            continue;
        }
        rc = noxtls_falcon_build_keypair_from_secret_components(param,
                                                                f,
                                                                g,
                                                                F16,
                                                                secret_key,
                                                                secret_key_len,
                                                                public_key,
                                                                public_key_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if(rc != NOXTLS_RETURN_BAD_DATA &&
           rc != NOXTLS_RETURN_FAILED &&
           rc != NOXTLS_RETURN_INVALID_PARAM) {
            return rc;
        }
    }

    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Sign a message with a Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] message Message bytes to sign.
 * @param[in] message_len Length of `message` in bytes.
 * @param[out] signature Output buffer for the serialized signature.
 * @param[in,out] signature_len On input, signature buffer capacity. On output, actual signature length.
 * @return `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM`, `NOXTLS_RETURN_INVALID_BLOCK_SIZE`,
 *         `NOXTLS_RETURN_BAD_DATA`, `NOXTLS_RETURN_FAILED`, or `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY`.
 */
noxtls_return_t noxtls_falcon_sign(noxtls_falcon_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len)
{
    noxtls_falcon_param_spec_t spec;
    noxtls_falcon_expanded_key_t expanded;
    noxtls_falcon_complex_t tree[NOXTLS_FALCON_MAX_TREE_LEN];
    noxtls_falcon_complex_t b00_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b01_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b10_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b11_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t hm_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t t0_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t t1_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t z0_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t z1_fft[NOXTLS_FALCON_MAX_N];
    uint16_t c[NOXTLS_FALCON_MAX_N];
    int16_t s1[NOXTLS_FALCON_MAX_N];
    int16_t s2[NOXTLS_FALCON_MAX_N];
    uint8_t entropy[NOXTLS_FALCON_SALT_LEN + DRBG_SEEDLEN_AES256];
    uint8_t *salt = entropy;
    uint8_t *seed = entropy + NOXTLS_FALCON_SALT_LEN;
    uint32_t l2bound;
    uint32_t attempt;
    noxtls_return_t rc;

    if(secret_key == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(*signature_len < spec.signature_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    rc = noxtls_falcon_expand_private_key(param, secret_key, spec.secret_key_len, &expanded);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_expand_basis_fft(&expanded, b00_fft, b01_fft, b10_fft, b11_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_build_normalized_expanded_key_ldl_tree(&expanded, tree,
                                                              noxtls_falcon_ldl_tree_complex_len(spec.n));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    l2bound = falcon_get_l2bound(param);
    if(l2bound == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    *signature_len = spec.signature_len;

    for(attempt = 0U; attempt < NOXTLS_FALCON_SIGN_MAX_ATTEMPTS; attempt++) {
        noxtls_falcon_sampler_ctx_t sampler;

        rc = noxtls_drbg_get_entropy(entropy, (uint32_t)sizeof(entropy));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_hash_to_point_salted(salt, message, message_len, c, spec.n);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_sampler_init(&sampler, param, seed, DRBG_SEEDLEN_AES256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_build_sign_target_fft(&expanded, c, t0_fft, t1_fft, hm_fft, b01_fft, b11_fft);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_sample_fft_tree(&sampler, tree, t0_fft, t1_fft, spec.n, z0_fft, z1_fft);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_sign_map_sample_to_signature(&expanded, c, z0_fft, z1_fft,
                                                 b00_fft, b01_fft, b10_fft, b11_fft, s1, s2);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(rc == NOXTLS_RETURN_FAILED) {
                continue;
            }
            return rc;
        }
        if(falcon_is_short(s1, s2, spec.n, l2bound) == 0U) {
            continue;
        }
        rc = falcon_encode_signature(&spec, salt, s2, signature);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if(rc != NOXTLS_RETURN_INVALID_BLOCK_SIZE) {
            return rc;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Verify a Falcon signature in the fixed-width padded format.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] public_key Serialized Falcon public key.
 * @param[in] message Message bytes.
 * @param[in] message_len Length of `message` in bytes.
 * @param[in] signature Serialized Falcon signature.
 * @param[in] signature_len Length of `signature` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, `NOXTLS_RETURN_FAILED` if invalid,
 *         or a parameter/serialization error code.
 */
noxtls_return_t noxtls_falcon_verify(noxtls_falcon_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len)
{
    noxtls_falcon_param_spec_t spec;
    uint16_t h[NOXTLS_FALCON_MAX_N];
    uint16_t c[NOXTLS_FALCON_MAX_N];
    uint16_t prod[NOXTLS_FALCON_MAX_N];
    int16_t s1[NOXTLS_FALCON_MAX_N];
    int16_t s2[NOXTLS_FALCON_MAX_N];
    uint8_t salt[NOXTLS_FALCON_SALT_LEN];
    uint32_t l2bound;
    uint32_t i;
    noxtls_return_t rc;

    if(public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    l2bound = falcon_get_l2bound(param);
    if(l2bound == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_falcon_decode_public_key(param, public_key, spec.public_key_len, h);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = falcon_decode_signature(&spec, signature, signature_len, salt, s2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = falcon_hash_to_point_salted(salt, message, message_len, c, spec.n);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    falcon_poly_mul_mod_q(prod, s2, h, spec.n);
    for(i = 0U; i < spec.n; i++) {
        s1[i] = noxtls_falcon_mod_q_center(noxtls_falcon_mod_q_sub(c[i], prod[i]));
    }

    return falcon_is_short(s1, s2, spec.n, l2bound) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}
