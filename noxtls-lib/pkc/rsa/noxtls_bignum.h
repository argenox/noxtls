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
* File:    noxtls_bignum.h
* Summary: Big Number Arithmetic Operations
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_BIGNUM_H_
#define _NOXTLS_BIGNUM_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @internal
 *  Big Number Operations (byte arrays, big-endian). Used internally by ECC/RSA; not part of the public API.
 */
/* Comparison and utility functions */
int noxtls_bn_cmp(const uint8_t *a, const uint8_t *b, uint32_t len);
int noxtls_bn_is_zero(const uint8_t *a, uint32_t len);
int noxtls_bn_is_one(const uint8_t *a, uint32_t len);
noxtls_return_t noxtls_bn_zero(uint8_t *a, uint32_t len);
noxtls_return_t noxtls_bn_one(uint8_t *a, uint32_t len);
noxtls_return_t noxtls_bn_copy(uint8_t *dst, const uint8_t *src, uint32_t len);

/* Basic arithmetic operations */
noxtls_return_t noxtls_bn_add(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len);
noxtls_return_t noxtls_bn_sub(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len);
noxtls_return_t noxtls_bn_mul(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);

/* Bit operations */
noxtls_return_t noxtls_bn_rshift1(uint8_t *a, uint32_t len);

/* Modular arithmetic operations */
noxtls_return_t noxtls_bn_mod(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *mod, uint32_t mod_len);
noxtls_return_t noxtls_bn_mod_exp(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len);
noxtls_return_t noxtls_bn_mod_inv(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *m, uint32_t m_len);


/* Test-only functions: expose internal shift and 2n-by-n limb functions for unit testing */
#ifdef NOXTLS_BIGNUM_TEST_INTERNAL
/* Shift buf (big-endian, length len) right by k bits (0 <= k <= 8). Test wrapper for static bn_shift_r_bits. */
void noxtls_bn_test_shift_r_bits(uint8_t *buf, uint32_t len, unsigned k);
/* Shift buf (big-endian, length *len) left by k bits (0 <= k <= 8). Test wrapper for static bn_shift_l_bits. */
void noxtls_bn_test_shift_l_bits(uint8_t *buf, uint32_t *len, unsigned k);
/* 2n-by-n limb path Layer 0: byte/limb conversion and limb arithmetic */
void noxtls_bn_test_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len);
void noxtls_bn_test_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len);
int noxtls_bn_test_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len);
void noxtls_bn_test_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len);
int noxtls_bn_test_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n);
int noxtls_bn_test_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q, const uint32_t *mod, uint32_t n);
uint32_t noxtls_bn_test_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n);
/* Normalization for 2n-by-n: count leading zeros in high limb; shift limbs (0<=k<=31). Match bn_mod_2n_by_n_limb. */
unsigned noxtls_bn_test_clz(uint32_t x);
void noxtls_bn_test_limbs_shl(uint32_t *a, uint32_t len, unsigned k);
void noxtls_bn_test_limbs_shr(uint32_t *a, uint32_t len, unsigned k);
/* Layer 2: run only the quotient-digit loop (no normalize, no byte I/O). rem_limbs has 2*n or 2*n+1 limbs, mod_limbs n limbs. rem_limb_count=0 means 2*n. */
void noxtls_bn_test_division_loop_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count);
/* Layer 3: run only the normalize loop (high limbs zero, low n limbs in [0, mod)). rem_limb_count = total rem limbs (2n or 2n+1); 0 means 2n. */
void noxtls_bn_test_normalize_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count);
/* Direct wrappers to internal reduction paths for diagnostics. */
noxtls_return_t noxtls_bn_test_mod_2n_by_n_limb(uint8_t *rem_out, uint32_t mod_len,
                                                const uint8_t *a, uint32_t a_len, const uint8_t *mod);
noxtls_return_t noxtls_bn_test_div_remainder_limb(uint8_t *rem_out, uint32_t mod_len,
                                                  const uint8_t *a, uint32_t a_len,
                                                  const uint8_t *b, uint32_t b_len);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_BIGNUM_H_ */


