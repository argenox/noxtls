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

#ifndef NOXTLS_BIGNUM_H_
#define NOXTLS_BIGNUM_H_

#include <stdint.h>
#include "noxtls_common.h"

/* NOXTLS_BIGNUM_ENABLED: 1 when the bignum module is compiled in (its sources are wrapped in
 * #if NOXTLS_BIGNUM_ENABLED). It is needed by RSA, DSA, DH, ECC/ECDSA/ECDH (incl. the PAKEs
 * built on ECC), X448, Ed448 and Falcon; NOXTLS_FEATURE_BIGNUM=1 (CMake
 * NOXTLS_CFG_FEATURE_BIGNUM, passed as a -D) forces it on for other users. A build without
 * CMake, where NOXTLS_FEATURE_BIGNUM is not defined, gets it whenever a consumer is enabled. */
#ifndef NOXTLS_BIGNUM_ENABLED
#if (defined(NOXTLS_FEATURE_BIGNUM) && (NOXTLS_FEATURE_BIGNUM != 0)) || \
    NOXTLS_FEATURE_RSA || NOXTLS_FEATURE_DSA || NOXTLS_FEATURE_DH || \
    NOXTLS_FEATURE_ECC || NOXTLS_FEATURE_ECDSA || NOXTLS_FEATURE_ECDH || \
    NOXTLS_FEATURE_X448 || NOXTLS_FEATURE_ED448 || NOXTLS_FEATURE_FALCON
#define NOXTLS_BIGNUM_ENABLED 1
#else
#define NOXTLS_BIGNUM_ENABLED 0
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @internal
 *  Big Number Operations (byte arrays, big-endian). Used internally by ECC/RSA; not part of the public API.
 */
/* Comparison and utility functions */
int32_t noxtls_bn_cmp(const uint8_t *a, const uint8_t *b, uint32_t len);
int32_t noxtls_bn_is_zero(const uint8_t *a, uint32_t len);
int32_t noxtls_bn_is_one(const uint8_t *a, uint32_t len);
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
/* Optional per-call software service callback. Preserve all operand buffers;
 * callback lifetime ends before return. Hardware port calls are not sliced. */
typedef void (*noxtls_bn_service_fn)(void);
noxtls_return_t noxtls_bn_mod_exp_service(uint8_t *result, const uint8_t *base,
    const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len,
    noxtls_bn_service_fn service);
noxtls_return_t noxtls_bn_mod_exp(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len);
/* result = base ^ exp mod mod for a PUBLIC exponent (RSA e, verification exponents):
 * table-free Montgomery square-and-multiply, (6n + 2) limbs of scratch for an odd modulus.
 * Variable time in the exponent bits only; never use it with a secret exponent. */
noxtls_return_t noxtls_bn_mod_exp_public(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len);
noxtls_return_t noxtls_bn_mod_inv(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *m, uint32_t m_len);

/**
 * @brief Constant-time modular reduction: result = a mod mod.
 *
 * For values derived from private keys or nonces and for a secret modulus (RSA p, q).
 * Control flow and memory access depend only on @p a_len and @p mod_len and on the parity
 * of @p mod (odd: Montgomery Horner evaluation, even: bit-serial masked subtraction); leading
 * zero bytes of @p a are not stripped and no platform accelerator hook is used.
 * noxtls_bn_mod() stays the faster variable-time reducer for public operands.
 *
 * @param[out] result  mod_len bytes, big-endian; may alias @p a (a is read completely first).
 * @param[in]  a       Dividend, a_len bytes big-endian (a_len may be 0: result is 0).
 * @param[in]  a_len   Dividend length in bytes.
 * @param[in]  mod     Modulus, mod_len bytes big-endian, non-zero.
 * @param[in]  mod_len Modulus length in bytes (> 0).
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM (zero modulus or
 *         length), NOXTLS_RETURN_FAILED (implausible length) or NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 *         @p result is zeroed on failure.
 */
noxtls_return_t noxtls_bn_mod_ct(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *mod, uint32_t mod_len);

/**
 * @brief Constant-time inverse modulo an odd prime p: result = a^(p-2) mod p (Fermat).
 *
 * a is reduced with noxtls_bn_mod_ct() and raised to p - 2 with the fixed-window Montgomery
 * exponentiation; the result is verified (a * result == 1 mod p) before it is returned, so a
 * zero a or a composite p fails rather than producing a wrong value. Use it for secret
 * values such as signature nonces; noxtls_bn_mod_inv() is variable time.
 *
 * @param[out] result p_len bytes, big-endian; may alias @p a.
 * @param[in]  a      Value to invert, a_len bytes big-endian.
 * @param[in]  a_len  Length of @p a in bytes.
 * @param[in]  p      Odd prime modulus (> 2), p_len bytes big-endian.
 * @param[in]  p_len  Modulus length in bytes.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_FAILED when a is 0 mod p or p is not prime;
 *         NOXTLS_RETURN_INVALID_PARAM for an even or too small p; NOXTLS_RETURN_NULL or
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY. @p result is zeroed on failure.
 */
noxtls_return_t noxtls_bn_mod_inv_prime_ct(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *p, uint32_t p_len);

/* Test-only functions: expose internal shift and 2n-by-n limb functions for unit testing */
#ifdef NOXTLS_BIGNUM_TEST_INTERNAL
/* Shift buf (big-endian, length len) right by k bits (0 <= k <= 8). Test wrapper for static bn_shift_r_bits. */
void noxtls_bn_test_shift_r_bits(uint8_t *buf, uint32_t len, uint32_t k);
/* Shift buf (big-endian, length *len) left by k bits (0 <= k <= 8). Test wrapper for static bn_shift_l_bits. */
void noxtls_bn_test_shift_l_bits(uint8_t *buf, uint32_t *len, uint32_t k);
/* 2n-by-n limb path Layer 0: byte/limb conversion and limb arithmetic */
void noxtls_bn_test_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len);
void noxtls_bn_test_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len);
int noxtls_bn_test_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len);
void noxtls_bn_test_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len);
int noxtls_bn_test_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n);
int noxtls_bn_test_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q, const uint32_t *mod, uint32_t n);
uint32_t noxtls_bn_test_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n);
/* Normalization for 2n-by-n: count leading zeros in high limb; shift limbs (0<=k<=31). Match bn_mod_2n_by_n_limb. */
uint32_t noxtls_bn_test_clz(uint32_t x);
void noxtls_bn_test_limbs_shl(uint32_t *a, uint32_t len, uint32_t k);
void noxtls_bn_test_limbs_shr(uint32_t *a, uint32_t len, uint32_t k);
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

#endif /* NOXTLS_BIGNUM_H_ */

