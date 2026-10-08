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
* File:    noxtls_ecjpake_scalar.c
* Summary: Constant-time P-256 scalar arithmetic modulo the group order
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake_scalar.c
 * @brief Constant-time arithmetic modulo the P-256 order n for EC-JPAKE.
 * @ingroup noxtls_ecjpake
 *
 * EC-JPAKE needs s = int(password) mod n (draft-cragie-tls-ecjpake-01
 * section 8.3), h = int(hash) mod n (section 8.2), xs = x2*s mod n
 * (sections 8.5.1, 8.6.1) and r = v - x*h mod n (RFC 8235 section 3.2).
 * Every routine below runs a fixed sequence of operations that depends only
 * on operand lengths, never on secret values.
 */

#include <stdint.h>

#include "noxtls_ecjpake_internal.h"
#include "common/noxtls_ct.h"

/** @brief Number of 32-bit limbs in a P-256 scalar. */
#define NOXTLS_ECJPAKE_LIMBS (8U)
/** @brief Limb count with one extra limb for the shifted-out bit during reduction. */
#define NOXTLS_ECJPAKE_LIMBS_EXT (NOXTLS_ECJPAKE_LIMBS + 1U)
/** @brief Limb count of a full 512-bit product. */
#define NOXTLS_ECJPAKE_LIMBS_WIDE (NOXTLS_ECJPAKE_LIMBS * 2U)
/** @brief Bytes per 32-bit limb. */
#define NOXTLS_ECJPAKE_LIMB_BYTES (4U)
/** @brief Bits per limb. */
#define NOXTLS_ECJPAKE_LIMB_BITS (32U)
/** @brief Most significant bit index of a limb. */
#define NOXTLS_ECJPAKE_LIMB_MSB (31U)
/** @brief Bits per byte. */
#define NOXTLS_ECJPAKE_BITS_PER_BYTE (8U)
/** @brief Mask selecting one byte. */
#define NOXTLS_ECJPAKE_BYTE_MASK (0xFFU)
/** @brief Size of a full 512-bit product in bytes. */
#define NOXTLS_ECJPAKE_WIDE_SIZE (NOXTLS_ECJPAKE_SCALAR_SIZE * 2U)

/** @brief P-256 group order n (SEC 2 v2.0 section 2.4.2), little-endian 32-bit limbs. */
static const uint32_t s_ecjpake_order[NOXTLS_ECJPAKE_LIMBS] = {
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
};

/**
 * @brief Load a big-endian byte string of limb_count * 4 bytes into little-endian limbs.
 * @internal
 *
 * @param[out] limbs Destination limbs.
 * @param[in] bytes Big-endian source.
 * @param[in] limb_count Number of limbs to load.
 */
static void noxtls_ecjpake_load(uint32_t *limbs, const uint8_t *bytes, uint32_t limb_count)
{
    uint32_t limb;

    for (limb = 0U; limb < limb_count; ++limb) {
        uint32_t base = (limb_count - limb - 1U) * NOXTLS_ECJPAKE_LIMB_BYTES;

        limbs[limb] = ((uint32_t)bytes[base] << 24) |
                      ((uint32_t)bytes[base + 1U] << 16) |
                      ((uint32_t)bytes[base + 2U] << 8) |
                      (uint32_t)bytes[base + 3U];
    }
}

/**
 * @brief Store little-endian limbs as a big-endian byte string of limb_count * 4 bytes.
 * @internal
 *
 * @param[out] bytes Big-endian destination.
 * @param[in] limbs Source limbs.
 * @param[in] limb_count Number of limbs to store.
 */
static void noxtls_ecjpake_store(uint8_t *bytes, const uint32_t *limbs, uint32_t limb_count)
{
    uint32_t limb;

    for (limb = 0U; limb < limb_count; ++limb) {
        uint32_t base = (limb_count - limb - 1U) * NOXTLS_ECJPAKE_LIMB_BYTES;

        bytes[base] = (uint8_t)((limbs[limb] >> 24) & NOXTLS_ECJPAKE_BYTE_MASK);
        bytes[base + 1U] = (uint8_t)((limbs[limb] >> 16) & NOXTLS_ECJPAKE_BYTE_MASK);
        bytes[base + 2U] = (uint8_t)((limbs[limb] >> 8) & NOXTLS_ECJPAKE_BYTE_MASK);
        bytes[base + 3U] = (uint8_t)(limbs[limb] & NOXTLS_ECJPAKE_BYTE_MASK);
    }
}

/**
 * @brief Compare a value with n by computing the borrow of a - n.
 * @internal
 *
 * @param[in] a Value limbs.
 *
 * @return 1 when a < n, 0 otherwise.
 */
static uint32_t noxtls_ecjpake_less_than_order(const uint32_t a[NOXTLS_ECJPAKE_LIMBS])
{
    uint32_t borrow = 0U;
    uint32_t limb;

    for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS; ++limb) {
        uint64_t diff = (uint64_t)a[limb] - (uint64_t)s_ecjpake_order[limb] - (uint64_t)borrow;

        borrow = (uint32_t)(diff >> NOXTLS_ECJPAKE_LIMB_BITS) & 1U;
    }

    return borrow;
}

void noxtls_ecjpake_scalar_reduce(const uint8_t *in, uint32_t in_len,
                                  uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t r[NOXTLS_ECJPAKE_LIMBS_EXT];
    uint32_t t[NOXTLS_ECJPAKE_LIMBS_EXT];
    uint32_t byte_index;

    noxtls_secure_zero(r, sizeof(r));
    noxtls_secure_zero(t, sizeof(t));

    /* Left-to-right binary reduction: r = 2r + bit, then r -= n when r >= n.
     * The invariant r < n bounds 2r + 1 below 2^257, so one extra limb holds
     * the shifted-out bit. The work depends only on in_len. */
    for (byte_index = 0U; byte_index < in_len; ++byte_index) {
        uint32_t bit_index;

        for (bit_index = NOXTLS_ECJPAKE_BITS_PER_BYTE; bit_index > 0U; --bit_index) {
            uint32_t carry = ((uint32_t)in[byte_index] >> (bit_index - 1U)) & 1U;
            uint32_t borrow = 0U;
            uint32_t keep_mask;
            uint32_t limb;

            for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS_EXT; ++limb) {
                uint32_t next_carry = r[limb] >> NOXTLS_ECJPAKE_LIMB_MSB;

                r[limb] = (r[limb] << 1) | carry;
                carry = next_carry;
            }

            for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS_EXT; ++limb) {
                uint32_t n_limb = (limb < NOXTLS_ECJPAKE_LIMBS) ? s_ecjpake_order[limb] : 0U;
                uint64_t diff = (uint64_t)r[limb] - (uint64_t)n_limb - (uint64_t)borrow;

                t[limb] = (uint32_t)diff;
                borrow = (uint32_t)(diff >> NOXTLS_ECJPAKE_LIMB_BITS) & 1U;
            }

            /* borrow == 1 means r < n: keep r; otherwise take t = r - n. */
            keep_mask = (uint32_t)0U - borrow;
            for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS_EXT; ++limb) {
                r[limb] = (r[limb] & keep_mask) | (t[limb] & ~keep_mask);
            }
        }
    }

    noxtls_ecjpake_store(out, r, NOXTLS_ECJPAKE_LIMBS);
    noxtls_secure_zero(r, sizeof(r));
    noxtls_secure_zero(t, sizeof(t));
}

void noxtls_ecjpake_scalar_mul(const uint8_t a[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               const uint8_t b[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t a_limbs[NOXTLS_ECJPAKE_LIMBS];
    uint32_t b_limbs[NOXTLS_ECJPAKE_LIMBS];
    uint32_t product[NOXTLS_ECJPAKE_LIMBS_WIDE];
    uint8_t wide[NOXTLS_ECJPAKE_WIDE_SIZE];
    uint32_t i;

    noxtls_ecjpake_load(a_limbs, a, NOXTLS_ECJPAKE_LIMBS);
    noxtls_ecjpake_load(b_limbs, b, NOXTLS_ECJPAKE_LIMBS);
    noxtls_secure_zero(product, sizeof(product));

    /* Schoolbook 256 x 256 -> 512-bit product; every limb pair is visited. */
    for (i = 0U; i < NOXTLS_ECJPAKE_LIMBS; ++i) {
        uint64_t carry = 0U;
        uint32_t j;

        for (j = 0U; j < NOXTLS_ECJPAKE_LIMBS; ++j) {
            uint64_t acc = ((uint64_t)a_limbs[i] * (uint64_t)b_limbs[j]) +
                           (uint64_t)product[i + j] + carry;

            product[i + j] = (uint32_t)acc;
            carry = acc >> NOXTLS_ECJPAKE_LIMB_BITS;
        }

        product[i + NOXTLS_ECJPAKE_LIMBS] = (uint32_t)carry;
    }

    noxtls_ecjpake_store(wide, product, NOXTLS_ECJPAKE_LIMBS_WIDE);
    noxtls_ecjpake_scalar_reduce(wide, NOXTLS_ECJPAKE_WIDE_SIZE, out);
    noxtls_secure_zero(a_limbs, sizeof(a_limbs));
    noxtls_secure_zero(b_limbs, sizeof(b_limbs));
    noxtls_secure_zero(product, sizeof(product));
    noxtls_secure_zero(wide, sizeof(wide));
}

void noxtls_ecjpake_scalar_sub(const uint8_t a[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               const uint8_t b[NOXTLS_ECJPAKE_SCALAR_SIZE],
                               uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t a_limbs[NOXTLS_ECJPAKE_LIMBS];
    uint32_t b_limbs[NOXTLS_ECJPAKE_LIMBS];
    uint32_t borrow = 0U;
    uint32_t carry = 0U;
    uint32_t add_mask;
    uint32_t limb;

    noxtls_ecjpake_load(a_limbs, a, NOXTLS_ECJPAKE_LIMBS);
    noxtls_ecjpake_load(b_limbs, b, NOXTLS_ECJPAKE_LIMBS);

    for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS; ++limb) {
        uint64_t diff = (uint64_t)a_limbs[limb] - (uint64_t)b_limbs[limb] - (uint64_t)borrow;

        a_limbs[limb] = (uint32_t)diff;
        borrow = (uint32_t)(diff >> NOXTLS_ECJPAKE_LIMB_BITS) & 1U;
    }

    /* A borrow means a < b: add n back (masked, no branch). */
    add_mask = (uint32_t)0U - borrow;
    for (limb = 0U; limb < NOXTLS_ECJPAKE_LIMBS; ++limb) {
        uint64_t sum = (uint64_t)a_limbs[limb] + ((uint64_t)s_ecjpake_order[limb] & (uint64_t)add_mask) +
                       (uint64_t)carry;

        a_limbs[limb] = (uint32_t)sum;
        carry = (uint32_t)(sum >> NOXTLS_ECJPAKE_LIMB_BITS);
    }

    noxtls_ecjpake_store(out, a_limbs, NOXTLS_ECJPAKE_LIMBS);
    noxtls_secure_zero(a_limbs, sizeof(a_limbs));
    noxtls_secure_zero(b_limbs, sizeof(b_limbs));
}

uint32_t noxtls_ecjpake_scalar_is_below_order(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t limbs[NOXTLS_ECJPAKE_LIMBS];
    uint32_t below;

    noxtls_ecjpake_load(limbs, scalar, NOXTLS_ECJPAKE_LIMBS);
    below = noxtls_ecjpake_less_than_order(limbs);
    noxtls_secure_zero(limbs, sizeof(limbs));
    return below;
}

uint32_t noxtls_ecjpake_scalar_is_valid(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t acc = 0U;
    uint32_t index;
    uint32_t non_zero;

    for (index = 0U; index < NOXTLS_ECJPAKE_SCALAR_SIZE; ++index) {
        acc |= (uint32_t)scalar[index];
    }

    /* acc in [0, 255]: (0 - acc) has its top bit set exactly when acc != 0. */
    non_zero = (((uint32_t)0U - acc) >> NOXTLS_ECJPAKE_LIMB_MSB) & 1U;
    return non_zero & noxtls_ecjpake_scalar_is_below_order(scalar);
}
