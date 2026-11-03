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
* File:    noxtls_ed25519_sc.c
* Summary: Ed25519 scalar arithmetic mod L (RFC 8032)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_sc.c
 * @brief Constant-time scalar reduction and muladd modulo L for Ed25519.
 * @ingroup noxtls_ed25519
 *
 * Byte-limb schoolbook multiply and fixed-schedule reduction (TweetNaCl modL),
 * with all secret limbs in named arrays that are wiped on return.
 * Order L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032).
 * Wire format at API edges remains little-endian (RFC 8032).
 */

#include "common/noxtls_ct.h"
#include <stdint.h>
#include <string.h>

#include "noxtls_ed25519_sc.h"
#include "noxtls_common.h"

/* Field / group / scalar code is used only by Ed25519 (X25519 has its own field
 * arithmetic), so the whole unit compiles to nothing when Ed25519 is disabled. */
#if NOXTLS_FEATURE_ED25519

/** Number of byte limbs in the 512-bit working value. */
#define NOXTLS_ED25519_SC_WIDE_LIMBS 64U

/**
 * Group order L = 2^252 + 27742317777372353535851937790883648493 as 32
 * little-endian byte limbs.
 */
static const int64_t sc25519_L[NOXTLS_ED25519_FE25519_BYTES] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
};

/**
 * @brief Floor division by 2^bits without implementation-defined signed shifts.
 * @internal
 *
 * The unsigned conversion is defined modulo 2^64; both converted terms fit
 * int64_t for 1 < bits < 64. Branch-free for secret values.
 *
 * @param[in] value Signed input.
 * @param[in] bits Shift amount (4 or 8 here).
 *
 * @return floor(value / 2^bits).
 */
static int64_t sc25519_asr(int64_t value, uint32_t bits)
{
    uint64_t u = (uint64_t)value;
    uint64_t magnitude = u >> bits;
    uint64_t correction = (u >> 63U) << (64U - bits);
    return (int64_t)magnitude - (int64_t)correction;
}

/**
 * @brief Reduce a 64-limb radix-2^8 value modulo L into 32 LE bytes.
 * @internal
 *
 * Fixed-iteration, branch-free reduction (the TweetNaCl modL schedule). All
 * secret intermediates live in @p x, which the caller wipes; this keeps the
 * scalar out of unnamed compiler temporaries that a wipe cannot reach.
 *
 * @param[out] r 32-byte little-endian result.
 * @param[in,out] x 64 signed limbs, each |x[i]| < 2^24; clobbered.
 */
static void sc25519_mod_l(uint8_t *r, int64_t *x)
{
    int64_t carry;
    uint32_t i;
    uint32_t j;

    for(i = NOXTLS_ED25519_SC_WIDE_LIMBS - 1U; i >= NOXTLS_ED25519_FE25519_BYTES; i--) {
        carry = 0;
        for(j = i - 32U; j < (i - 12U); j++) {
            x[j] += carry - (16 * x[i] * sc25519_L[j - (i - 32U)]);
            carry = sc25519_asr(x[j] + 128, 8U);
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for(j = 0U; j < NOXTLS_ED25519_FE25519_BYTES; j++) {
        x[j] += carry - (sc25519_asr(x[31], 4U) * sc25519_L[j]);
        carry = sc25519_asr(x[j], 8U);
        x[j] -= carry * 256;
    }
    for(j = 0U; j < NOXTLS_ED25519_FE25519_BYTES; j++) {
        x[j] -= carry * sc25519_L[j];
    }
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        x[i + 1U] += sc25519_asr(x[i], 8U);
        r[i] = (uint8_t)((uint64_t)x[i] & 0xFFU);
    }
}

/**
 * @brief Reduce a 64-byte little-endian integer modulo L into 32 LE bytes.
 *
 * @param[out] out_le Reduced 32-byte little-endian scalar.
 * @param[in] in_le 64-byte little-endian input (e.g. SHA-512 digest).
 */
void sc25519_reduce(uint8_t *out_le,
                    const uint8_t *in_le)
{
    int64_t x[NOXTLS_ED25519_SC_WIDE_LIMBS];
    uint32_t i;

    for(i = 0U; i < NOXTLS_ED25519_SC_WIDE_LIMBS; i++) {
        x[i] = (int64_t)in_le[i];
    }
    sc25519_mod_l(out_le, x);
    /* The input is the secret nonce digest when signing. */
    noxtls_secure_zero(x, sizeof(x));
}

/**
 * @brief Compute out = (a*b + c) mod L in little-endian wire format.
 *
 * RFC 8032 §5.1.6: S = (r + k*s) mod L. Limbs of the secret scalar and nonce
 * are held only in a named array, which is wiped before returning.
 *
 * @param[out] out_le Resulting 32-byte little-endian scalar.
 * @param[in] a_le First factor.
 * @param[in] b_le Second factor.
 * @param[in] c_le Addend.
 */
void sc25519_muladd(uint8_t *out_le,
                    const uint8_t *a_le,
                    const uint8_t *b_le,
                    const uint8_t *c_le)
{
    int64_t x[NOXTLS_ED25519_SC_WIDE_LIMBS];
    uint32_t i;
    uint32_t j;

    for(i = 0U; i < NOXTLS_ED25519_SC_WIDE_LIMBS; i++) {
        x[i] = (i < NOXTLS_ED25519_FE25519_BYTES) ? (int64_t)c_le[i] : 0;
    }
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        for(j = 0U; j < NOXTLS_ED25519_FE25519_BYTES; j++) {
            x[i + j] += (int64_t)((uint32_t)a_le[i] * (uint32_t)b_le[j]);
        }
    }
    sc25519_mod_l(out_le, x);
    noxtls_secure_zero(x, sizeof(x));
}

#endif /* NOXTLS_FEATURE_ED25519 */
