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
* File:    noxtls_dh.c
* Summary: Finite-field Diffie-Hellman (FFDHE) per RFC 7919
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "noxtls_dh.h"
#include "noxtls_ffdhe_params.h"
#include "noxtls_tls_common.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "noxtls_ct.h"

/**
 * @brief Returns 1 if modulus matches a built-in RFC 7919 safe-prime group.
 *
 * @param[in] p Prime modulus bytes.
 * @param[in] p_len Length of modulus in bytes.
 * @return 1 when @p p is a known FFDHE prime; otherwise 0.
 */
static uint8_t dh_is_known_ffdhe_prime(const uint8_t *p, uint32_t p_len)
{
    if (p == NULL) {
        return 0U;
    }
    if ((p_len == NOXTLS_FFDHE2048_P_BYTES) &&
       (noxtls_secret_memcmp(p, noxtls_ffdhe2048_p, (size_t)(p_len)) == 0)) {
        return 1U;
    }
    if ((p_len == NOXTLS_FFDHE3072_P_BYTES) &&
       (noxtls_secret_memcmp(p, noxtls_ffdhe3072_p, (size_t)(p_len)) == 0)) {
        return 1U;
    }
    if ((p_len == NOXTLS_FFDHE4096_P_BYTES) &&
       (noxtls_secret_memcmp(p, noxtls_ffdhe4096_p, (size_t)(p_len)) == 0)) {
        return 1U;
    }
    if ((p_len == NOXTLS_FFDHE6144_P_BYTES) &&
       (noxtls_secret_memcmp(p, noxtls_ffdhe6144_p, (size_t)(p_len)) == 0)) {
        return 1U;
    }
    if ((p_len == NOXTLS_FFDHE8192_P_BYTES) &&
       (noxtls_secret_memcmp(p, noxtls_ffdhe8192_p, (size_t)(p_len)) == 0)) {
        return 1U;
    }
    return 0U;
}

/** Maximum DRBG draws for private-key rejection sampling (failure probability < 2^-100). */
#define DH_PRIV_MAX_TRIES 256U

/**
 * @brief Returns the bit length of a big-endian unsigned value (0 for zero).
 *
 * @param[in] x Value bytes (big-endian).
 * @param[in] len Length of @p x in bytes.
 * @return Number of significant bits.
 */
static uint32_t dh_bitlen(const uint8_t *x, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t bits = 0U;
    uint32_t found = 0U;

    while ((i < len) && (found == 0U)) {
        if (x[i] != 0U) {
            uint8_t top = x[i];
            bits = (len - i - 1U) * 8U;
            while (top != 0U) {
                bits += 1U;
                top = (uint8_t)(top >> 1U);
            }
            found = 1U;
        }
        i += 1U;
    }
    return bits;
}

/**
 * @brief Right-aligns a big-endian value into a fixed-width buffer.
 *
 * A source longer than @p dst_len is accepted only when its extra leading
 * bytes are all zero (the value fits); otherwise the call fails.
 *
 * @param[out] dst Destination buffer (dst_len bytes), fully written on success.
 * @param[in] dst_len Destination width in bytes.
 * @param[in] src Source value (big-endian).
 * @param[in] src_len Source length in bytes.
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED when the value does not fit.
 */
static noxtls_return_t dh_load_fixed(uint8_t *dst, uint32_t dst_len,
                                     const uint8_t *src, uint32_t src_len)
{
    uint32_t i = 0U;
    uint8_t extra = 0U;

    noxtls_secure_zero(dst, (size_t)dst_len);
    if (src_len > dst_len) {
        for (i = 0U; i < (src_len - dst_len); i += 1U) {
            extra |= src[i];
        }
        if (extra != 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(dst, (size_t)dst_len, &src[(src_len - dst_len)], (size_t)dst_len);
    } else if (src_len > 0U) {
        noxtls_copy_u8(&dst[(dst_len - src_len)], (size_t)src_len, src, (size_t)src_len);
    } else {
        /* empty source: value zero */
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Draws a uniformly random exponent x with 2 <= x <= upper and x < 2^bits.
 *
 * Bounded rejection sampling: each draw is masked to @p bits bits (counted from
 * the least significant end of the p_len-byte buffer, so the mask lands on the
 * most significant byte of the exponent) and rejected if outside the range.
 *
 * @param[in,out] drbg Instantiated DRBG.
 * @param[out] out Exponent buffer (len bytes, big-endian).
 * @param[in] len Buffer length in bytes.
 * @param[in] bits Exponent bit length (1 <= bits <= 8 * len).
 * @param[in] upper Inclusive upper bound (len bytes, big-endian), typically p - 2.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED on DRBG failure or exhaustion.
 */
static noxtls_return_t dh_random_exponent(drbg_state_t *drbg, uint8_t *out, uint32_t len,
                                          uint32_t bits, const uint8_t *upper)
{
    static const uint8_t s_top_mask[8] = {
        0xFFU, 0x01U, 0x03U, 0x07U, 0x0FU, 0x1FU, 0x3FU, 0x7FU
    };
    const uint32_t nbytes = (bits + 7U) / 8U;
    uint32_t tries = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t done = 0U;

    if ((bits == 0U) || (nbytes > len)) {
        return NOXTLS_RETURN_FAILED;
    }
    while ((done == 0U) && (tries < DH_PRIV_MAX_TRIES)) {
        tries += 1U;
        noxtls_secure_zero(out, (size_t)len);
        if (drbg_generate(drbg, &out[(len - nbytes)], nbytes * 8U, NULL, 0U) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED;
            done = 1U;
        } else {
            out[(len - nbytes)] &= s_top_mask[(bits % 8U)];
            if ((noxtls_bn_is_zero(out, len) == 0) && (noxtls_bn_is_one(out, len) == 0) &&
                (noxtls_bn_cmp(out, upper, len) <= 0)) {
                rc = NOXTLS_RETURN_SUCCESS;
                done = 1U;
            }
        }
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, (size_t)len);
    }
    return rc;
}

/**
 * @brief Computes p - 2 into @p p_minus_2 after checking p is a usable DH modulus.
 *
 * Rejects even p and p < 5 (for which [2, p-2] is empty or degenerate).
 *
 * @param[out] p_minus_2 Output (p_len bytes).
 * @param[in] p Prime modulus (p_len bytes, big-endian).
 * @param[in] p_len Length in bytes.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED for degenerate p, or
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 */
static noxtls_return_t dh_p_minus_2(uint8_t *p_minus_2, const uint8_t *p, uint32_t p_len)
{
    uint8_t *two = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if (((p[p_len - 1U] & 1U) == 0U) || (dh_bitlen(p, p_len) < 3U)) {
        return NOXTLS_RETURN_FAILED;   /* even, or p < 4 */
    }
    two = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if (two == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    two[p_len - 1U] = 0x02U;
    rc = noxtls_bn_copy(p_minus_2, p, p_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_bn_sub(p_minus_2, p_minus_2, two, p_len);
    }
    /* p odd and >= 4 means p >= 5, so p - 2 >= 3 > 2: range [2, p-2] is non-empty. */
    (void)noxtls_free(two);
    return rc;
}

/**
 * @brief Validates a DH peer public value for FFDHE key agreement (2 <= y <= p - 2).
 *
 * @param[in] peer_mod Peer public value padded to @p p_len bytes.
 * @param[in] p Prime modulus.
 * @param[in] p_len Length of modulus in bytes.
 * @return NOXTLS_RETURN_SUCCESS when peer value is acceptable; otherwise failure.
 */
static noxtls_return_t dh_validate_peer_public(const uint8_t *peer_mod,
                                               const uint8_t *p,
                                               uint32_t p_len)
{
    uint8_t *two = NULL;
    uint8_t *p_minus_2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((peer_mod == NULL) || (p == NULL) || (p_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    two = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    p_minus_2 = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if ((two == NULL) || (p_minus_2 == NULL)) {
        if (two != NULL) {
            (void)noxtls_free(two);
        }
        if (p_minus_2 != NULL) {
            (void)noxtls_free(p_minus_2);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    two[p_len - 1U] = 0x02U;

    /* p < 4 has no valid peer value; also guards the p - 2 subtraction against wrap-around. */
    if (dh_bitlen(p, p_len) < 3U) {
        (void)noxtls_free(two);
        (void)noxtls_free(p_minus_2);
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_bn_copy(p_minus_2, p, p_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(two);
        (void)noxtls_free(p_minus_2);
        return rc;
    }
    rc = noxtls_bn_sub(p_minus_2, p_minus_2, two, p_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(two);
        (void)noxtls_free(p_minus_2);
        return rc;
    }

    {
        int cmp_lo = noxtls_bn_cmp(peer_mod, two, p_len);
        int cmp_hi = noxtls_bn_cmp(peer_mod, p_minus_2, p_len);
        if ((cmp_lo < 0) || (cmp_hi > 0)) {
            (void)noxtls_free(two);
            (void)noxtls_free(p_minus_2);
            return NOXTLS_RETURN_FAILED;
        }
    }

    (void)noxtls_free(two);
    (void)noxtls_free(p_minus_2);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * RFC 7919 Table 2 — minimum recommended private exponent length (bits) per group.
 * 
 * @param named_group The named group
 * @return The minimum private bits
 */
static uint32_t dh_ffdhe_min_private_bits(uint16_t named_group)
{
    switch (named_group) {
        case TLS_NAMED_GROUP_FFDHE2048:
            return NOXTLS_FFDHE2048_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE3072:
            return NOXTLS_FFDHE3072_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE4096:
            return NOXTLS_FFDHE4096_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE6144:
            return NOXTLS_FFDHE6144_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE8192:
            return NOXTLS_FFDHE8192_MIN_PRIVATE_BITS;
        default:
            return 0U;
    }
}

/**
 * @brief Generate an ephemeral DH key pair
 *
 * The private exponent is uniform in [2, 2^min_bits) where min_bits is the
 * RFC 7919 Table 2 minimum exponent length for the group; the length mask is
 * applied to the most significant byte of the exponent.
 *
 * @param named_group The named group
 * @param private_out The private output (p_len bytes, big-endian, high bytes zero)
 * @param public_out The public output (p_len bytes)
 * @return The return value
 */
noxtls_return_t noxtls_dh_ffdhe_generate_ephemeral(uint16_t named_group,
                                                   uint8_t *private_out,
                                                   uint8_t *public_out)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0U;
    uint32_t min_bits = 0U;
    drbg_state_t drbg;
    uint8_t *p_minus_2 = NULL;
    uint8_t *g_padded = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((private_out == NULL) || (public_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    min_bits = dh_ffdhe_min_private_bits(named_group);
    if (min_bits == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if (p_len == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (dh_is_known_ffdhe_prime(p, p_len) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (((min_bits + 7U) / 8U) > p_len) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero((private_out), (size_t)(p_len));
    noxtls_secure_zero((public_out), (size_t)(p_len));

    p_minus_2 = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    g_padded = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if ((p_minus_2 == NULL) || (g_padded == NULL)) {
        if (p_minus_2 != NULL) {
            (void)noxtls_free(p_minus_2);
        }
        if (g_padded != NULL) {
            (void)noxtls_free(g_padded);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    rc = dh_p_minus_2(p_minus_2, p, p_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(p_minus_2);
        (void)noxtls_free(g_padded);
        return rc;
    }

    if (drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_drbg_uninstantiate(&drbg);
        (void)noxtls_free(p_minus_2);
        (void)noxtls_free(g_padded);
        return NOXTLS_RETURN_FAILED;
    }

    rc = dh_random_exponent(&drbg, private_out, p_len, min_bits, p_minus_2);
    (void)noxtls_drbg_uninstantiate(&drbg);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(g_padded, (size_t)p_len, g, (size_t)p_len);
        rc = noxtls_bn_mod_exp(public_out, g_padded, private_out, p_len, p, p_len);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero((private_out), (size_t)(p_len));
        noxtls_secure_zero((public_out), (size_t)(p_len));
    }
    (void)noxtls_free(p_minus_2);
    (void)noxtls_free(g_padded);
    return rc;
}

/**
 * @brief Validate a client key share
 * 
 * @param named_group The named group
 * @param key_exchange The key exchange
 * @param key_exchange_len The length of the key exchange
 * @return The return value
 */
noxtls_return_t noxtls_dh_ffdhe_validate_client_key_share(uint16_t named_group,
                                                        const uint8_t *key_exchange,
                                                        uint32_t key_exchange_len)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0U;
    uint8_t *peer_mod = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((key_exchange_len > 0U) && (key_exchange == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS) || (p_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((key_exchange_len != p_len) || (key_exchange == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    peer_mod = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if (peer_mod == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8(peer_mod, (size_t)p_len, key_exchange, (size_t)p_len);
    rc = dh_validate_peer_public(peer_mod, p, p_len);
    (void)noxtls_free(peer_mod);
    return rc;
}

/**
 * @brief Get FFDHE group parameters
 * 
 * @param named_group The named group
 * @param p The prime modulus
 * @param g The generator
 * @param p_len The length of the prime modulus
 * @return The return value
 */
noxtls_return_t noxtls_dh_ffdhe_params(uint16_t named_group,
                                        const uint8_t **p,
                                        const uint8_t **g,
                                        uint32_t *p_len)
{
    if ((p == NULL) || (g == NULL) || (p_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch (named_group) {
        case TLS_NAMED_GROUP_FFDHE2048:
            *p = noxtls_ffdhe2048_p;
            *g = noxtls_ffdhe_g_2048;
            *p_len = NOXTLS_FFDHE2048_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE3072:
            *p = noxtls_ffdhe3072_p;
            *g = noxtls_ffdhe_g_3072;
            *p_len = NOXTLS_FFDHE3072_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE4096:
            *p = noxtls_ffdhe4096_p;
            *g = noxtls_ffdhe_g_4096;
            *p_len = NOXTLS_FFDHE4096_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE6144:
            *p = noxtls_ffdhe6144_p;
            *g = noxtls_ffdhe_g_6144;
            *p_len = NOXTLS_FFDHE6144_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE8192:
            *p = noxtls_ffdhe8192_p;
            *g = noxtls_ffdhe_g_8192;
            *p_len = NOXTLS_FFDHE8192_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Generate an ephemeral finite-field DH key pair: private in [2, p-2], public = g^private mod p.
 *
 * The private value is drawn by bounded rejection sampling over bitlen(p) bits,
 * so generation terminates for any modulus (including ones with leading zero
 * bytes or a small top byte).
 *
 * @param[in] p Prime modulus p (big-endian, p_len bytes; leading zero bytes allowed).
 * @param[in] p_len Length of p in bytes; must be positive.
 * @param[in] g Generator g (big-endian, g_len bytes; commonly 2). A g_len larger than
 *              p_len is accepted only if the extra leading bytes are zero.
 * @param[in] g_len Length of g in bytes; must be positive.
 * @param[out] private_out Private exponent (p_len bytes), suitable for noxtls_dh_shared_secret().
 * @param[out] public_out Public value g^private mod p (p_len bytes, big-endian).
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if p, g, private_out, or public_out is NULL.
 * @return NOXTLS_RETURN_FAILED if p_len or g_len is zero, p is even or < 5, g is not in
 *         [2, p-2], or DRBG setup/generation fails.
 * @return NOXTLS_RETURN_NOT_ENOUGH_MEMORY if a temporary buffer cannot be allocated.
 * @return Other noxtls_return_t values propagated from bignum operations on failure.
 */
noxtls_return_t noxtls_dh_generate_key(const uint8_t *p, uint32_t p_len,
                                        const uint8_t *g, uint32_t g_len,
                                        uint8_t *private_out,
                                        uint8_t *public_out)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    drbg_state_t drbg;
    uint8_t *p_minus_2 = NULL;
    uint8_t *priv_buf = NULL;
    uint8_t *g_padded = NULL;

    if ((p == NULL) || (g == NULL) || (private_out == NULL) || (public_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((p_len == 0U) || (g_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if (p_len > (uint32_t)(UINT32_MAX / 8U)) {
        return NOXTLS_RETURN_FAILED;
    }

    p_minus_2 = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    priv_buf = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    g_padded = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if ((p_minus_2 == NULL) || (priv_buf == NULL) || (g_padded == NULL)) {
        if (p_minus_2 != NULL) { (void)noxtls_free(p_minus_2); }
        if (priv_buf != NULL) { (void)noxtls_free(priv_buf); }
        if (g_padded != NULL) { (void)noxtls_free(g_padded); }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* p - 2 (also rejects even p and p < 5) */
    rc = dh_p_minus_2(p_minus_2, p, p_len);

    /* g must fit in p_len bytes and lie in [2, p-2]. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dh_load_fixed(g_padded, p_len, g, g_len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dh_validate_peer_public(g_padded, p, p_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED;
        } else {
            rc = dh_random_exponent(&drbg, priv_buf, p_len, dh_bitlen(p, p_len), p_minus_2);
        }
        (void)noxtls_drbg_uninstantiate(&drbg);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(private_out, (size_t)p_len, priv_buf, (size_t)p_len);
        rc = noxtls_bn_mod_exp(public_out, g_padded, private_out, p_len, p, p_len);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_out, (size_t)p_len);
        noxtls_secure_zero(public_out, (size_t)p_len);
    }
    (void)noxtls_free(p_minus_2);
    NOXTLS_SECURE_FREE(priv_buf, (size_t)p_len);
    (void)noxtls_free(g_padded);
    return rc;
}

/**
 * @brief Compute the shared secret Z = peer_public^private_key mod p.
 *
 * @param[in] private_key Local private exponent (private_len bytes, big-endian).
 * @param[in] private_len Length of private_key in bytes.
 * @param[in] peer_public Peer's public DH value (peer_len bytes, big-endian).
 * @param[in] peer_len Length of peer_public in bytes. A value longer than p_len is accepted
 *                     only if its extra leading bytes are zero (the low p_len bytes are then
 *                     used); otherwise it is rejected.
 * @param[in] p Prime modulus (p_len bytes, big-endian).
 * @param[in] p_len Length of p in bytes; must be positive.
 * @param[out] secret_out Shared secret (p_len bytes, big-endian); caller must provide p_len bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if private_key, peer_public, p, or secret_out is NULL.
 * @return NOXTLS_RETURN_FAILED if p_len or private_len is zero, or the peer value is not in [2, p-2].
 * @return NOXTLS_RETURN_NOT_ENOUGH_MEMORY if a temporary buffer cannot be allocated.
 * @return Other noxtls_return_t values propagated from modular exponentiation on failure.
 */
noxtls_return_t noxtls_dh_shared_secret(const uint8_t *private_key,
                                         uint32_t private_len,
                                         const uint8_t *peer_public,
                                         uint32_t peer_len,
                                         const uint8_t *p,
                                         uint32_t p_len,
                                         uint8_t *secret_out)
{
    uint8_t *peer_mod = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((private_key == NULL) || (peer_public == NULL) || (p == NULL) || (secret_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (p_len == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    if (private_len == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    peer_mod = (uint8_t*)NOXTLS_CALLOC(p_len, 1);
    if (peer_mod == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = dh_load_fixed(peer_mod, p_len, peer_public, peer_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dh_validate_peer_public(peer_mod, p, p_len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_bn_mod_exp(secret_out, peer_mod, private_key, private_len, p, p_len);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(secret_out, (size_t)p_len);
    }
    (void)noxtls_free(peer_mod);
    return rc;
}
