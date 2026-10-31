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
* File:    noxtls_rsa.c
* Summary: RSA Public Key Cryptography Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_debug_printf.h"
#include "common/noxtls_ct.h"
#include "noxtls_config.h"
#include "pkc/noxtls_pkc_rng.h"
#include "noxtls_rsa.h"
#include "noxtls_bignum.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_RSA

/* Big number operations are now in NOXTLS_bignum.c */

#define RSA_PKCS1_PAD_RETRY_MAX 16U

/**
 * @brief Generate random bytes from the shared PKC DRBG (NOXTLS_PKC_RNG_SLOT_RSA).
 *
 * Same fail-closed semantics as the former module-private DRBG: on failure the output is
 * wiped and the instance is re-instantiated from fresh entropy on the next call.
 *
 * @param buf Buffer to store the random bytes
 * @param len Length of the buffer
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
static noxtls_return_t rsa_random_bytes(uint8_t *buf, uint32_t len)
{
    if((buf == NULL) || (len > (UINT32_MAX / 8U))) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_RSA, buf, len * 8U) != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(buf, (size_t)len);
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}


/**
 * @brief Divide big-endian number by small divisor (base-256), returning quotient and remainder.
 * 
 * @param quotient Quotient output big integer
 * @param remainder Remainder output big integer
 * @param num Number to divide
 * @param num_len Length of the number to divide
 * @param divisor Divisor
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_div_mod_small(uint8_t *quotient,
                                         uint32_t *remainder,
                                         const uint8_t *num,
                                         uint32_t num_len,
                                         uint32_t divisor)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t rem = 0U;

    if((quotient == NULL) || (remainder == NULL) || (num == NULL) || (divisor == 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    
    for(uint32_t i = 0U; i < num_len; i += 1U) {
        uint32_t acc = (uint32_t)((rem << 8U) | num[i]);
        quotient[i] = (uint8_t)(acc / divisor);
        rem = acc % divisor;
    }

    *remainder = rem;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute num mod small divisor (divisor <= 65535).
 * 
 * @param num Number to mod
 * @param num_len Length of the number to mod
 * @param divisor Divisor
 * @return uint32_t Remainder
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint32_t rsa_mod_small(const uint8_t *num, uint32_t num_len, uint32_t divisor)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t rem = 0U;
    for(uint32_t i = 0U; i < num_len; i += 1U) {
        rem = ((rem << 8U) | num[i]) % divisor;
    }
    return rem;
}

/**
 * @brief Multiply big-endian number by small multiplier.
 * 
 * @param out Output big integer
 * @param in Input big integer
 * @param in_len Length of the input big integer
 * @param multiplier Multiplier
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_mul_small(uint8_t *out,
                          const uint8_t *in,
                          uint32_t in_len,
                          uint32_t multiplier)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t carry = 0U;
    for(uint32_t i = in_len; i > 0U; i -= 1U) {
        uint32_t prod = (uint32_t)(((uint32_t)in[i - 1U] * multiplier) + carry);
        out[i - 1U] = (uint8_t)(prod & 0xFFU);
        carry = (uint32_t)prod >> 8U;
    }
}

/**
 * @brief Add small value to big-endian number in-place.
 * 
 * @param inout Input/output big integer
 * @param len Length of the input/output big integer
 * @param addend Addend
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_add_small(uint8_t *inout, uint32_t len, uint32_t addend)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t carry = (uint32_t)(addend);
    for(uint32_t i = len; (i > 0U) && (carry > 0U); i -= 1U) {
        uint32_t sum = (uint32_t)inout[i - 1U] + (carry & 0xFFU);
        inout[i - 1U] = (uint8_t)(sum & 0xFFU);
        carry = (carry >> 8U) + (sum >> 8U);
    }
}

/**
 * @brief Modular inverse for small odd a modulo large (possibly even) modulus.
 * 
 * @param result Result big integer
 * @param mod Modulus big integer
 * @param mod_len Length of the modulus big integer
 * @param a First big integer
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL
 */
static noxtls_return_t rsa_mod_inv_small(uint8_t *result,
                                         const uint8_t *mod,
                                         uint32_t mod_len,
                                         uint32_t a)
{
    if((result == NULL) || (mod == NULL) || (mod_len == 0U) || (a == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    uint8_t *quotient = (uint8_t*)NOXTLS_CALLOC(mod_len, 1);
    uint8_t *qy = (uint8_t*)NOXTLS_CALLOC(mod_len, 1);
    if((quotient == NULL) || (qy == NULL)) {
        if(quotient != NULL) { (void)noxtls_free(quotient); }
        if(qy != NULL) { (void)noxtls_free(qy); }
        return NOXTLS_RETURN_FAILED;
    }

    uint32_t r = 0U;
    if(rsa_div_mod_small(quotient, &r, mod, mod_len, a) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(quotient);
        (void)noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }
    if(r == 0U) {
        (void)noxtls_free(quotient);
        (void)noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }

    /* Compute y = r^-1 mod a (small integer inverse). */
    int64_t t = 0;
    int64_t newt = 1;
    int64_t rr = (int64_t)a;
    int64_t newr = (int64_t)r;
    while(newr != 0) {
        int64_t q = rr / newr;
        int64_t tmp_t = newt;
        newt = t - (q * newt);
        t = tmp_t;
        int64_t tmp_r = newr;
        newr = rr - (q * newr);
        rr = tmp_r;
    }
    if(rr != 1) {
        (void)noxtls_free(quotient);
        (void)noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }
    if(t < 0) {
        t += (int64_t)a;
    }
    uint32_t y = (uint32_t)t;

    uint64_t k = (uint64_t)((((uint64_t)r * (uint64_t)y) - 1ULL) / (uint64_t)a);

    /* t = (q * y) + k */
    rsa_mul_small(qy, quotient, mod_len, y);
    rsa_add_small(qy, mod_len, (uint32_t)k);

    if(noxtls_bn_cmp(qy, mod, mod_len) >= 0) {
        (void)noxtls_bn_sub(qy, qy, mod, mod_len);
    }

    if(noxtls_bn_is_zero(qy, mod_len) != 0) {
        (void)noxtls_bn_zero(result, mod_len);
    } else {
        (void)noxtls_bn_sub(result, mod, qy, mod_len);
    }

    (void)noxtls_free(quotient);
    (void)noxtls_free(qy);
    return NOXTLS_RETURN_SUCCESS;
}

/* Forward declaration */
static int32_t rsa_is_prime(const uint8_t *n, uint32_t len, int32_t iterations);

#if NOXTLS_DEBUG_PRINTF_ENABLED
/**
 * @brief Test Miller-Rabin with known primes
 *
 * Diagnostic only: the results are reported through noxtls_debug_printf and do not affect
 * key generation, so the self-check is compiled only when debug output is compiled in.
 */
static void test_miller_rabin_known_primes(void)
{
    /* Test with small known primes */
    const uint8_t known_prime_17[] = {0x11U};  /* 17 is prime */
    const uint8_t known_prime_97[] = {0x61U};  /* 97 is prime */
    const uint8_t known_prime_101[] = {0x65U}; /* 101 is prime */
    
    (void)noxtls_debug_printf((const uint8_t *)"Testing Miller-Rabin with known primes...\n");
    int32_t result = 0;
    
    /* Test small primes */
    result = rsa_is_prime(known_prime_17, 1, 3);
    (void)noxtls_debug_printf((const uint8_t *)"  Known prime 17: %s\n", (result != 0) ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    result = rsa_is_prime(known_prime_97, 1, 3);
    (void)noxtls_debug_printf((const uint8_t *)"  Known prime 97: %s\n", (result != 0) ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    result = rsa_is_prime(known_prime_101, 1, 3);
    (void)noxtls_debug_printf((const uint8_t *)"  Known prime 101: %s\n", (result != 0) ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    /* Test composite numbers to ensure they're rejected */
    const uint8_t composite_15[] = {0x0FU};  /* 15 = 3 * 5 */
    const uint8_t composite_21[] = {0x15U};  /* 21 = 3 * 7 */
    
    result = rsa_is_prime(composite_15, 1, 3);
    (void)noxtls_debug_printf((const uint8_t *)"  Composite 15: %s\n", (result != 0) ? "FAIL (incorrectly accepted)" : "PASS (correctly rejected)");
    result = rsa_is_prime(composite_21, 1, 3);
    (void)noxtls_debug_printf((const uint8_t *)"  Composite 21: %s\n", (result != 0) ? "FAIL (incorrectly accepted)" : "PASS (correctly rejected)");
    (void)noxtls_debug_printf((const uint8_t *)"Miller-Rabin test verification complete.\n");
}
#endif /* NOXTLS_DEBUG_PRINTF_ENABLED */

/**
 * @brief Miller-Rabin primality test
 * 
 * @param n Number to test
 * @param len Length of the number to test
 * @param iterations Number of iterations
 * @return 1 if the number is probably prime, 0 if it is composite (or n <= 1 / even),
 *         -1 if the test could not be completed (allocation or bignum failure). A
 *         failed bignum step is never interpreted as "probably prime".
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static int32_t rsa_is_prime(const uint8_t *n, uint32_t len, int32_t iterations)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint8_t *n_minus_1 = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *d = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *a = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *x = (uint8_t*)NOXTLS_CALLOC(len, 1);
    /* temp needs to be len * 2 because noxtls_bn_mul(x, len, x, len) produces len * 2 bytes */
    uint8_t *temp = (uint8_t*)NOXTLS_CALLOC((size_t)len * 2U, 1);
    
    if((n_minus_1 == NULL) || (d == NULL) || (a == NULL) || (x == NULL) || (temp == NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: rsa_is_prime: Memory allocation failed!\n");
        if(n_minus_1 != NULL) { (void)noxtls_free(n_minus_1); }
        if(d != NULL) { (void)noxtls_free(d); }
        if(a != NULL) { (void)noxtls_free(a); }
        if(x != NULL) { (void)noxtls_free(x); }
        if(temp != NULL) { (void)noxtls_free(temp); }
        return -1;
    }

    /* n must be > 1 */
    {
        int32_t n_is_one = noxtls_bn_is_one(n, len);
        int32_t n_is_zero = noxtls_bn_is_zero(n, len);
        if((n_is_one != 0) || (n_is_zero != 0)) {
            (void)noxtls_free(n_minus_1);
            (void)noxtls_free(d);
            (void)noxtls_free(a);
            (void)noxtls_free(x);
            (void)noxtls_free(temp);
            return 0;
        }
    }
    
    /* Check if even */
    if((n[len - 1U] & 1U) == 0U) {
        (void)noxtls_free(n_minus_1);
        (void)noxtls_free(d);
        (void)noxtls_free(a);
        (void)noxtls_free(x);
        (void)noxtls_free(temp);
        return 0;
    }
    
    /* Write n - 1U as d * 2^r */
    uint8_t *one = (uint8_t*)NOXTLS_CALLOC(len, 1);
    if(one == NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: rsa_is_prime: Failed to allocate 'one'\n");
        (void)noxtls_free(n_minus_1);
        (void)noxtls_free(d);
        (void)noxtls_free(a);
        (void)noxtls_free(x);
        (void)noxtls_free(temp);
        return -1;
    }
    (void)noxtls_bn_one(one, len);
    (void)noxtls_bn_copy(n_minus_1, n, len);
    (void)noxtls_bn_sub(n_minus_1, n_minus_1, one, len);  /* n - 1U */
    (void)noxtls_bn_copy(d, n_minus_1, len);
    (void)noxtls_free(one);
    
    uint32_t r = 0U;
    uint32_t max_divisions = (uint32_t)(len * 8U);  /* Safety limit */
    {
        uint8_t d_shift_done = 0U;
        while (d_shift_done == 0U) {
            int32_t d_nonzero;
            if((d[len - 1U] & 1U) != 0U) {
                d_shift_done = 1U;
            } else if(r >= max_divisions) {
                d_shift_done = 1U;
            } else {
                d_nonzero = noxtls_bn_is_zero(d, len);
                if(d_nonzero != 0) {
                    d_shift_done = 1U;
                } else {
                    (void)noxtls_bn_rshift1(d, len);
                    r += 1U;
                }
            }
        }
    }
    
    {
        int32_t d_is_zero = noxtls_bn_is_zero(d, len);
        if((r >= max_divisions) || (d_is_zero != 0)) {
            (void)noxtls_debug_printf((const uint8_t *)"ERROR: rsa_is_prime: Invalid d value after division\n");
            (void)noxtls_free(n_minus_1);
            (void)noxtls_free(d);
            (void)noxtls_free(a);
            (void)noxtls_free(x);
            (void)noxtls_free(temp);
            return 0;
        }
    }
    
    uint8_t *two = (uint8_t*)NOXTLS_CALLOC(len, 1);
    if(two == NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: rsa_is_prime: Failed to allocate 'two'\n");
        (void)noxtls_free(n_minus_1);
        (void)noxtls_free(d);
        (void)noxtls_free(a);
        (void)noxtls_free(x);
        (void)noxtls_free(temp);
        return -1;
    }
    (void)noxtls_bn_zero(two, len);
    two[len - 1U] = 2;  /* Set to 2 */
    
    /* Debug: Print d and r for small numbers */
    if((len == 1U) && (n[0] < 255U)) {
        (void)noxtls_debug_printf((const uint8_t *)"  [DEBUG] Testing n=%u, d=%u, r=%u\n", n[0], d[0], r);
    }
    
    uint32_t iterations_u = (uint32_t)((iterations < 0) ? 0U : (uint32_t)iterations);
    int32_t bn_failed = 0;
    for(i = 0U; (i < iterations_u) && (bn_failed == 0); i += 1U) {
        /* Choose random a in [2, n - 2U] */
        /* For small numbers, use deterministic witnesses for better testing */
        if((len == 1U) && (n[0] < 255U)) {
            /* Use small deterministic witnesses for testing small primes */
            uint8_t small_witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
            if(i < (sizeof(small_witnesses)) ){
                uint8_t w = (uint8_t)(small_witnesses[i]);
                if((w >= n[0]) || (w == 0U)) {
                    (void)noxtls_bn_copy(a, two, len);  /* Fallback to 2 */
                } else {
                    (void)noxtls_bn_zero(a, len);
                    a[len - 1U] = w;
                }
            } else {
                (void)noxtls_bn_copy(a, two, len);
            }
        } else {
            /* Use deterministic witnesses first to reduce RNG dependence */
            static const uint8_t mr_witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
            if(i < (uint32_t)(sizeof(mr_witnesses) / sizeof(mr_witnesses[0]))) {
                uint8_t w = (uint8_t)(mr_witnesses[i]);
                (void)noxtls_bn_zero(a, len);
                a[len - 1U] = w;
            } else {
            /* Simple approach: generate random, reduce modulo n, ensure it's in [2, n - 2U] */
            uint32_t retry_count = 0U;
            {
                uint8_t a_pick_done = 0U;
                while (a_pick_done == 0U) {
                    int32_t a_is_zero = 0;
                    int32_t a_is_one = 0;
                    int32_t a_cmp_nm1 = 0;
                    int32_t a_bad = 0;
                    if(rsa_random_bytes(a, len) != NOXTLS_RETURN_SUCCESS) {
                        (void)noxtls_bn_copy(a, two, len);
                        a_pick_done = 1U;
                    } else if(noxtls_bn_mod(a, a, len, n, len) != NOXTLS_RETURN_SUCCESS) {
                        /* reduction failed: fall back to the fixed witness 2 */
                        (void)noxtls_bn_copy(a, two, len);
                        a_pick_done = 1U;
                    } else {
                        retry_count += 1U;
                        a_is_zero = noxtls_bn_is_zero(a, len);
                        a_is_one = noxtls_bn_is_one(a, len);
                        a_cmp_nm1 = noxtls_bn_cmp(a, n_minus_1, len);
                        a_bad = ((a_is_zero != 0) || (a_is_one != 0) || (a_cmp_nm1 == 0)) ? 1 : 0;
                        if((a_bad == 0) || (retry_count >= 20U)) {
                            a_pick_done = 1U;
                        }
                    }
                }
            }
            /* If we still don't have a valid a, set it to a safe value */
            {
                int32_t a_is_zero = noxtls_bn_is_zero(a, len);
                int32_t a_is_one = noxtls_bn_is_one(a, len);
                int32_t a_cmp_nm1 = noxtls_bn_cmp(a, n_minus_1, len);
                if((a_is_zero != 0) || (a_is_one != 0) || (a_cmp_nm1 == 0)) {
                /* Use a deterministic value: 2 + (i mod (n - 4U)) to ensure variety */
                (void)noxtls_bn_copy(a, two, len);
                if((noxtls_bn_is_zero(n_minus_1, len) == 0)) {
                    uint8_t *offset = (uint8_t*)NOXTLS_CALLOC(len, 1);
                    if(offset != NULL) {
                        /* offset = (i + 1U) mod (n - 4U), but simplified: just use i + 1U if small enough */
                        if(((i + 1U) < 256U) && ((i + 1U) < len)) {
                            offset[len - 1U] = (uint8_t)(i + 1U);
                            (void)noxtls_bn_add(a, a, offset, len);
                            (void)noxtls_free(offset);
                        } else {
                            (void)noxtls_free(offset);
                        }
                    }
                }
                }
            }
            }
        }
        
        /* Final safety check: ensure a is in [2, n - 2U] */
        if(noxtls_bn_cmp(a, n, len) >= 0) {
            /* Reduce modulo n again */
            if(noxtls_bn_mod(a, a, len, n, len) != NOXTLS_RETURN_SUCCESS) {
                bn_failed = 1;
                continue;
            }
        }
        {
            int32_t a_is_zero = noxtls_bn_is_zero(a, len);
            int32_t a_is_one = noxtls_bn_is_one(a, len);
            if((a_is_zero != 0) || (a_is_one != 0)) {
                (void)noxtls_bn_copy(a, two, len);
            }
        }
        if(noxtls_bn_cmp(a, n_minus_1, len) == 0) {
            /* a == n - 1U, use n - 2U instead */
            (void)noxtls_bn_sub(a, n_minus_1, two, len);
        }
        
        /* x = a^d mod n. A failed exponentiation must not be read as x == 1 ("probably prime"). */
        if(noxtls_bn_mod_exp(x, a, d, len, n, len) != NOXTLS_RETURN_SUCCESS) {
            bn_failed = 1;
            continue;
        }

        /* Debug for small numbers */
        if((len == 1U) && (n[0] < 255U)) {
            (void)noxtls_debug_printf((const uint8_t *)"    [DEBUG] Witness a=%u, x=a^d mod n=%u\n", a[0], x[0]);
        }
        
        {
            int32_t x_is_one = noxtls_bn_is_one(x, len);
            int32_t x_cmp_nm1 = noxtls_bn_cmp(x, n_minus_1, len);
            if((x_is_one != 0) || (x_cmp_nm1 == 0)) {
                continue;  /* This witness says "probably prime", continue to next witness */
            }
        }
        
        /* Check if x^(2^j) == n - 1U for some j in [1, r-1] */
        int32_t composite = 1;
        for(j = 0U; (j < (r - 1U)) && (bn_failed == 0); j += 1U) {
            if((noxtls_bn_mul(temp, x, len, x, len) != NOXTLS_RETURN_SUCCESS) ||
               (noxtls_bn_mod(x, temp, len * 2U, n, len) != NOXTLS_RETURN_SUCCESS)) {
                bn_failed = 1;
                continue;
            }

            /* Debug for small numbers */
            if((len == 1U) && (n[0] < 255U)) {
                (void)noxtls_debug_printf((const uint8_t *)"      [DEBUG] After square %u: x=%u\n", j + 1U, x[0]);
            }
            
            if(noxtls_bn_cmp(x, n_minus_1, len) == 0) {
                composite = 0;  /* Found that x^(2^j) == n - 1U, so probably prime */
                break;
            }
        }
        
        if(bn_failed != 0) {
            continue;
        }
        if(composite != 0) {
            /* Debug for small numbers */
            if((len == 1U) && (n[0] < 255U)) {
                (void)noxtls_debug_printf((const uint8_t *)"    [DEBUG] Witness a=%u says COMPOSITE\n", a[0]);
            }
            /* This witness says "composite" */
            (void)noxtls_free(n_minus_1);
            (void)noxtls_free(d);
            (void)noxtls_free(a);
            (void)noxtls_free(x);
            (void)noxtls_free(temp);
            (void)noxtls_free(two);
            return 0;
        }
    }
    
    (void)noxtls_free(n_minus_1);
    (void)noxtls_free(d);
    (void)noxtls_free(a);
    (void)noxtls_free(x);
    (void)noxtls_free(temp);
    (void)noxtls_free(two);
    return (bn_failed != 0) ? -1 : 1;
}

/* Quick divisibility test for small primes */
/**
 * @brief Quick divisibility test for small primes
 * 
 * @param n The n value
 * @param len The length of the n value
 * @return 1 if the number is prime, 0 otherwise
 */
static int rsa_quick_divisibility_test(const uint8_t *n, uint32_t len)
{
    /* small primes table (Rule 8.9). */
    /* Test divisibility by a wider set of small primes for faster rejection */
    static const uint16_t small_primes[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
        557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
        613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
        673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
        743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
        821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
        881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
        953, 967, 971, 977, 983, 991, 997,
        1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061,
        1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
        1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
        1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
        1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361,
        1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
        1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
        1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
        1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627,
        1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721,
        1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
        1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
        1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973,
        1979, 1987, 1993, 1997
    };


    uint32_t i = 0U;
    uint32_t j = 0U;
    
    /* Compute n mod each small prime using modular arithmetic */
    for(i = 0U; i < (uint32_t)(sizeof(small_primes) / sizeof(small_primes[0])); i += 1U) {
        uint32_t mod = 0U;  /* Use uint32_t to avoid overflow */
        uint16_t prime = (uint16_t)(small_primes[i]);
        
        /* Compute n mod prime using: (a * 256 + b) mod p = ((a mod p) * 256 + b) mod p */
        for(j = 0U; j < len; j += 1U) {
            mod = ((mod * 256U) + n[j]) % prime;
        }
        if(mod == 0U) {
            return 0;  /* Divisible by small prime, definitely composite */
        }
    }
    return 1;  /* Not divisible by small primes, might be prime */
}

/* Prime-search wheel modulo 2310 = 2*3*5*7*11: the 480 residues coprime to 2310, stored
 * as the gaps between consecutive residues starting at residue 1 (residue i = 1 + sum of
 * the first i gaps; the last gap wraps to 1 + 2310). Generated offline by
 * scripts/gen_rsa_wheel_tables.py (run it with --check noxtls_rsa.c to verify this table);
 * replaces the two 480-entry uint16_t tables formerly built in RAM at run time. */
#define RSA_WHEEL_MODULUS 2310U
#define RSA_WHEEL_COUNT   480U
static const uint8_t s_rsa_wheel_gaps[RSA_WHEEL_COUNT] = {
    12U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  6U,  6U,  2U,  6U,  4U,  2U,  6U,  4U,  6U,  8U,
     4U,  2U,  4U,  2U,  4U, 14U,  4U,  6U,  2U, 10U,  2U,  6U,  6U,  4U,  2U,  4U,  6U,  2U, 10U,  2U,
     4U,  2U, 12U, 10U,  2U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  6U,  6U,  6U,  2U,  6U,  4U,  2U,  6U,
     4U,  6U,  8U,  4U,  2U,  4U,  6U,  8U,  6U, 10U,  2U,  4U,  6U,  2U,  6U,  6U,  4U,  2U,  4U,  6U,
     2U,  6U,  4U,  2U,  6U, 10U,  2U, 10U,  2U,  4U,  2U,  4U,  6U,  8U,  4U,  2U,  4U, 12U,  2U,  6U,
     4U,  2U,  6U,  4U,  6U, 12U,  2U,  4U,  2U,  4U,  8U,  6U,  4U,  6U,  2U,  4U,  6U,  2U,  6U, 10U,
     2U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  2U, 10U,  2U, 10U,  2U,  4U,  6U,  6U,  2U,  6U,  6U,  4U,
     6U,  6U,  2U,  6U,  4U,  2U,  6U,  4U,  6U,  8U,  4U,  2U,  6U,  4U,  8U,  6U,  4U,  6U,  2U,  4U,
     6U,  8U,  6U,  4U,  2U, 10U,  2U,  6U,  4U,  2U,  4U,  2U, 10U,  2U, 10U,  2U,  4U,  2U,  4U,  8U,
     6U,  4U,  2U,  4U,  6U,  6U,  2U,  6U,  4U,  8U,  4U,  6U,  8U,  4U,  2U,  4U,  2U,  4U,  8U,  6U,
     4U,  6U,  6U,  6U,  2U,  6U,  6U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  2U, 10U,  2U, 10U,
     2U,  6U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  6U,  6U,  8U,  4U,  2U,  6U, 10U,  8U,  4U,  2U,  4U,
     2U,  4U,  8U, 10U,  6U,  2U,  4U,  8U,  6U,  6U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  6U,  2U, 10U,
     2U, 10U,  2U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  6U,  6U,  2U,  6U,  6U,  6U,  4U,  6U,
     8U,  4U,  2U,  4U,  2U,  4U,  8U,  6U,  4U,  8U,  4U,  6U,  2U,  6U,  6U,  4U,  2U,  4U,  6U,  8U,
     4U,  2U,  4U,  2U, 10U,  2U, 10U,  2U,  4U,  2U,  4U,  6U,  2U, 10U,  2U,  4U,  6U,  8U,  6U,  4U,
     2U,  6U,  4U,  6U,  8U,  4U,  6U,  2U,  4U,  8U,  6U,  4U,  6U,  2U,  4U,  6U,  2U,  6U,  6U,  4U,
     6U,  6U,  2U,  6U,  6U,  4U,  2U, 10U,  2U, 10U,  2U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  2U, 10U,
     6U,  2U,  6U,  4U,  2U,  6U,  4U,  6U,  8U,  4U,  2U,  4U,  2U, 12U,  6U,  4U,  6U,  2U,  4U,  6U,
     2U, 12U,  4U,  2U,  4U,  8U,  6U,  4U,  2U,  4U,  2U, 10U,  2U, 10U,  6U,  2U,  4U,  6U,  2U,  6U,
     4U,  2U,  4U,  6U,  6U,  2U,  6U,  4U,  2U, 10U,  6U,  8U,  6U,  4U,  2U,  4U,  8U,  6U,  4U,  6U,
     2U,  4U,  6U,  2U,  6U,  6U,  6U,  4U,  6U,  2U,  6U,  4U,  2U,  4U,  2U, 10U, 12U,  2U,  4U,  2U,
    10U,  2U,  6U,  4U,  2U,  4U,  6U,  6U,  2U, 10U,  2U,  6U,  4U, 14U,  4U,  2U,  4U,  2U,  4U,  8U,
     6U,  4U,  6U,  2U,  4U,  6U,  2U,  6U,  6U,  4U,  2U,  4U,  6U,  2U,  6U,  4U,  2U,  4U, 12U,  2U
};

/**
 * @brief Align a candidate up to the next wheel residue.
 *
 * Adds the smallest delta >= 0 that makes @p prime coprime to 2310 and sets the wheel
 * position (@p wheel_idx: index of the gap to add next, @p wheel_rem: prime mod 2310).
 *
 * @param[in,out] prime     Candidate, big-endian.
 * @param[in]     len       Length of @p prime.
 * @param[out]    wheel_idx Wheel index.
 * @param[out]    wheel_rem Candidate residue modulo 2310.
 */
static void rsa_wheel_align(uint8_t *prime, uint32_t len, uint32_t *wheel_idx, uint32_t *wheel_rem)
{
    uint32_t rem = rsa_mod_small(prime, len, RSA_WHEEL_MODULUS);
    uint32_t residue = 1U;
    uint32_t idx = 0U;

    /* First residue >= rem; running off the end means rem > 2309: wrap to 1 + 2310. */
    while((idx < RSA_WHEEL_COUNT) && (residue < rem)) {
        residue += (uint32_t)s_rsa_wheel_gaps[idx];
        idx += 1U;
    }
    if(idx >= RSA_WHEEL_COUNT) {
        idx = 0U;
    }
    rsa_add_small(prime, len, residue - rem);
    *wheel_rem = residue % RSA_WHEEL_MODULUS;
    *wheel_idx = idx;
}

/**
 * @brief Advance the wheel for prime generation.
 *
 * @param prime The prime value
 * @param len The length of the prime value
 * @param wheel_idx The wheel index value
 * @param wheel_rem The wheel remainder value
 * @return The return value
 */
static noxtls_return_t rsa_wheel_advance(uint8_t *prime, uint32_t len,
                                         uint32_t *wheel_idx, uint32_t *wheel_rem)
{
    uint32_t step = (uint32_t)(s_rsa_wheel_gaps[*wheel_idx]);
    rsa_add_small(prime, len, step);
    *wheel_rem = (*wheel_rem + step) % RSA_WHEEL_MODULUS;
    *wheel_idx = (*wheel_idx + 1U) % RSA_WHEEL_COUNT;
    /* If we wrapped past the size (MSB cleared), reseed and realign */
    if((prime[0] & 0x80U) == 0U) {
        if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        prime[0] |= 0x80U;
        prime[len - 1U] |= 1U;
        rsa_wheel_align(prime, len, wheel_idx, wheel_rem);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate a prime number
 *
 * @param prime The prime value
 * @param len The length of the prime value
 * @return 1 if the prime is found, 0 otherwise
 */
static int rsa_generate_prime(uint8_t *prime, uint32_t len)
{
#if NOXTLS_DEBUG_PRINTF_ENABLED
    static int test_run = 0;
#endif
    uint32_t attempts = 0U;
    uint32_t prime_bits = (uint32_t)(len * 8U);
    uint32_t wheel_idx = 0U;
    uint32_t wheel_rem = 0U;

#if NOXTLS_DEBUG_PRINTF_ENABLED
    /* Run Miller-Rabin test verification once on first prime generation */
    if(test_run == 0) {
        test_miller_rabin_known_primes();
        test_run = 1;
    }
#endif

    (void)noxtls_debug_printf((const uint8_t *)"  Starting prime generation (this may take several minutes for large keys)...\n");

    /* Seed candidate and align to wheel residue */
    if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    prime[0] |= 0x80U;  /* Set MSB to ensure correct bit length */
    prime[len - 1U] |= 1U;  /* Make odd */
    rsa_wheel_align(prime, len, &wheel_idx, &wheel_rem);

    do {
        attempts += 1U;
        
#if NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL > 0
        if((attempts % NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL) == 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"  Testing candidate %u...\n", attempts);
        }
#endif
        
        /* Quick divisibility test before expensive Miller-Rabin */
#if NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST
        if((rsa_quick_divisibility_test(prime, len) == 0)) {
            if(rsa_wheel_advance(prime, len, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
                return 0;
            }
            continue;  /* Skip this candidate, it's divisible by a small prime */
        }
#endif
        
#if NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL > 0
        if((attempts % NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL) == 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"  Checking primality of candidate %u (passed quick test)...\n", attempts);
        }
#endif
        
        /* Determine number of Miller-Rabin iterations based on prime size */
        int32_t iterations = 0;
        if(prime_bits <= NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS) {
            iterations = (int)NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL;
        } else {
            iterations = (int)NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE;
        }
        
        int32_t is_prime = rsa_is_prime(prime, len, iterations);
        if(is_prime < 0) {
            /* Primality test could not complete (e.g. out of memory): fail, never accept. */
            return 0;
        }
        if(is_prime > 0) {
            (void)noxtls_debug_printf((const uint8_t *)"  Found prime after %u attempts!\n", attempts);
            return 1;
        }
        
#if NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL > 0
        /* Debug: count rejected candidates. Candidate bytes are never printed: the next
         * candidates (and so the final prime) differ from this one only by small wheel steps. */
        if(((attempts % NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL) == 0U) &&
           (attempts <= NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS)) {
            (void)noxtls_debug_printf((const uint8_t *)"  Rejected candidate %u\n", attempts);
        }
#endif
        /* Advance to next wheel residue for next candidate */
        if(rsa_wheel_advance(prime, len, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
            return 0;
        }
    } while(attempts < NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
    
    (void)noxtls_debug_printf((const uint8_t *)"  Warning: Failed to find prime after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
    return 0;  /* Failed to find prime */
}

/**
 * @brief PKCS#1 v1.5 Encryption Padding
 * 
 * @param padded The padded value
 * @param padded_len The length of the padded value
 * @param data The data value
 * @param data_len The length of the data value
 * @return The return value
 */
static noxtls_return_t rsa_pkcs1_v15_encrypt_pad(uint8_t *padded, uint32_t padded_len, const uint8_t *data, uint32_t data_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(data_len > (padded_len - 11U)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    padded[0] = 0x00U;
    padded[1] = 0x02U;  /* Encryption block type */
    
    /* Random padding (non-zero bytes) */
    uint32_t pad_len = (uint32_t)(padded_len - data_len - 3U);
    rc = rsa_random_bytes(&padded[2], pad_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(uint32_t i = 0U; i < pad_len; i += 1U) {
        uint32_t retries = 0U;
        while((padded[2U + i] == 0U) && (retries < RSA_PKCS1_PAD_RETRY_MAX)) {
            rc = rsa_random_bytes(&padded[2U + i], 1U);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            retries += 1U;
        }
        if(padded[2U + i] == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    padded[2U + pad_len] = 0x00U;  /* Separator */
    noxtls_copy_u8(&padded[3U + pad_len], (size_t)(data_len), data, (size_t)(data_len));
    return NOXTLS_RETURN_SUCCESS;
}

/* PKCS#1 v1.5 Signature Padding */
/**
 * @brief PKCS#1 v1.5 Signature Padding
 * 
 * @param padded The padded value
 * @param padded_len The length of the padded value
 * @param hash The hash value
 * @param hash_len The length of the hash value
 * @param hash_algo The hash algorithm value
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_pkcs1_v15_encode_digest(uint8_t *padded, uint32_t padded_len, const uint8_t *hash, uint32_t hash_len,
                                                   noxtls_hash_algos_t hash_algo, uint32_t omit_null_params)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t hash_oid[20];
    uint32_t oid_len = 0U;

    if((hash_algo != NOXTLS_HASH_MD5) &&
       (hash_algo != NOXTLS_HASH_SHA1) &&
       (hash_algo != NOXTLS_HASH_SHA_224) &&
       (hash_algo != NOXTLS_HASH_SHA_256) &&
       (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    /* ASN.1 DigestInfo structure */
    {
        uint32_t hash_algo_u = (uint32_t)hash_algo;
        switch (hash_algo_u) {
        case (uint32_t)NOXTLS_HASH_MD5:
            /* MD5 OID: 1.2.840.113549.2.5 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x20U; hash_oid[2] = 0x30U; hash_oid[3] = 0x0CU;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x08U; hash_oid[6] = 0x2AU; hash_oid[7] = 0x86U;
            hash_oid[8] = 0x48U; hash_oid[9] = 0x86U; hash_oid[10] = 0xF7U; hash_oid[11] = 0x0DU;
            hash_oid[12] = 0x02U; hash_oid[13] = 0x05U; hash_oid[14] = 0x05U; hash_oid[15] = 0x00U;
            hash_oid[16] = 0x04U; hash_oid[17] = 0x10U;
            oid_len = 18U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA1:
            /* SHA-1 OID: 1.3.14.3.2.26 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x21U; hash_oid[2] = 0x30U; hash_oid[3] = 0x09U;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x05U; hash_oid[6] = 0x2BU; hash_oid[7] = 0x0EU;
            hash_oid[8] = 0x03U; hash_oid[9] = 0x02U; hash_oid[10] = 0x1AU; hash_oid[11] = 0x05U;
            hash_oid[12] = 0x00U; hash_oid[13] = 0x04U; hash_oid[14] = 0x14U;
            oid_len = 15U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_224:
            /* SHA-224 OID: 2.16.840.1.101.3.4.2.4 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x2dU; hash_oid[2] = 0x30U; hash_oid[3] = 0x0dU;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x09U; hash_oid[6] = 0x60U; hash_oid[7] = 0x86U;
            hash_oid[8] = 0x48U; hash_oid[9] = 0x01U; hash_oid[10] = 0x65U; hash_oid[11] = 0x03U;
            hash_oid[12] = 0x04U; hash_oid[13] = 0x02U; hash_oid[14] = 0x04U; hash_oid[15] = 0x05U;
            hash_oid[16] = 0x00U; hash_oid[17] = 0x04U; hash_oid[18] = 0x1cU;
            oid_len = 19U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_256:
            /* SHA-256 OID: 2.16.840.1.101.3.4.2.1 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x31U; hash_oid[2] = 0x30U; hash_oid[3] = 0x0DU;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x09U; hash_oid[6] = 0x60U; hash_oid[7] = 0x86U;
            hash_oid[8] = 0x48U; hash_oid[9] = 0x01U; hash_oid[10] = 0x65U; hash_oid[11] = 0x03U;
            hash_oid[12] = 0x04U; hash_oid[13] = 0x02U; hash_oid[14] = 0x01U; hash_oid[15] = 0x05U;
            hash_oid[16] = 0x00U; hash_oid[17] = 0x04U; hash_oid[18] = 0x20U;
            oid_len = 19U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_384:
            /* SHA-384 OID: 2.16.840.1.101.3.4.2.2 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x41U; hash_oid[2] = 0x30U; hash_oid[3] = 0x0dU;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x09U; hash_oid[6] = 0x60U; hash_oid[7] = 0x86U;
            hash_oid[8] = 0x48U; hash_oid[9] = 0x01U; hash_oid[10] = 0x65U; hash_oid[11] = 0x03U;
            hash_oid[12] = 0x04U; hash_oid[13] = 0x02U; hash_oid[14] = 0x02U; hash_oid[15] = 0x05U;
            hash_oid[16] = 0x00U; hash_oid[17] = 0x04U; hash_oid[18] = 0x30U;
            oid_len = 19U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_512:
            /* SHA-512 OID: 2.16.840.1.101.3.4.2.3 */
            hash_oid[0] = 0x30U; hash_oid[1] = 0x51U; hash_oid[2] = 0x30U; hash_oid[3] = 0x0dU;
            hash_oid[4] = 0x06U; hash_oid[5] = 0x09U; hash_oid[6] = 0x60U; hash_oid[7] = 0x86U;
            hash_oid[8] = 0x48U; hash_oid[9] = 0x01U; hash_oid[10] = 0x65U; hash_oid[11] = 0x03U;
            hash_oid[12] = 0x04U; hash_oid[13] = 0x02U; hash_oid[14] = 0x03U; hash_oid[15] = 0x05U;
            hash_oid[16] = 0x00U; hash_oid[17] = 0x04U; hash_oid[18] = 0x40U;
            oid_len = 19U;
            break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    }

    if(omit_null_params != 0U) {
        /* Alternative DigestInfo with absent AlgorithmIdentifier parameters
         * (RFC 8017 section 9.2 note 1): drop the "05 00" NULL that precedes
         * the "04 <hLen>" OCTET STRING header and shorten both SEQUENCEs. */
        hash_oid[oid_len - 4U] = hash_oid[oid_len - 2U];
        hash_oid[oid_len - 3U] = hash_oid[oid_len - 1U];
        hash_oid[1] = (uint8_t)(hash_oid[1] - 2U);
        hash_oid[3] = (uint8_t)(hash_oid[3] - 2U);
        oid_len -= 2U;
    }

    /* EMSA-PKCS1-v1_5 (RFC 8017 section 9.2): emLen >= tLen + 11, i.e. PS >= 8 bytes. */
    if((padded_len < 11U) || ((oid_len + hash_len) > (padded_len - 11U))) {
        return NOXTLS_RETURN_FAILED;
    }
    
    padded[0] = 0x00U;
    padded[1] = 0x01U;  /* Signature block type */
    
    /* Padding with 0xFFU */
    uint32_t pad_len = (uint32_t)(padded_len - oid_len - hash_len - 3U);
    {
        uint32_t pi = 0U;
        for(pi = 0U; pi < pad_len; pi += 1U) {
            padded[2U + pi] = 0xFFU;
        }
    }
    
    padded[2U + pad_len] = 0x00U;  /* Separator */
    noxtls_copy_u8(&padded[3U + pad_len], (size_t)(oid_len), hash_oid, (size_t)(oid_len));
    noxtls_copy_u8(&padded[3U + pad_len + oid_len], (size_t)(hash_len), hash, (size_t)(hash_len));
    return NOXTLS_RETURN_SUCCESS;
}

/*
 * Hashing helpers. Every digest computed by this file (message digests, the PSS M' hash and
 * the MGF1 blocks) goes through rsa_digest(), whose per-family leaf helpers are the only
 * frames that hold a hash context. They are kept out of line so a context is never stacked
 * on top of another context or of the PSS buffers in a single frame, and the input is
 * passed as up to three segments so callers never assemble M' (8 + 64 + 64 bytes) or
 * seed || counter in a temporary buffer.
 */
#if defined(__GNUC__) || defined(__clang__)
#define RSA_NOINLINE __attribute__((noinline))
#else
#define RSA_NOINLINE
#endif

/** Up to three input segments for one digest (unused segments: NULL / 0). */
typedef struct
{
    const uint8_t *p1;
    uint32_t l1;
    const uint8_t *p2;
    uint32_t l2;
    const uint8_t *p3;
    uint32_t l3;
} rsa_digest_in_t;

#if NOXTLS_FEATURE_MD5
RSA_NOINLINE static noxtls_return_t rsa_hash_run_md5(uint8_t *hash, const rsa_digest_in_t *in)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_md5_update(&ctx, in->p1, in->l1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if((in->l2 != 0U) && (noxtls_md5_update(&ctx, in->p2, in->l2) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if((in->l3 != 0U) && (noxtls_md5_update(&ctx, in->p3, in->l3) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_MD5 */

#if NOXTLS_FEATURE_SHA1
RSA_NOINLINE static noxtls_return_t rsa_hash_run_sha1(uint8_t *hash, const rsa_digest_in_t *in, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, in->p1, in->l1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if((in->l2 != 0U) && (noxtls_sha1_update(&ctx, in->p2, in->l2) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if((in->l3 != 0U) && (noxtls_sha1_update(&ctx, in->p3, in->l3) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA1 */

#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
RSA_NOINLINE static noxtls_return_t rsa_hash_run_sha256(uint8_t *hash, const rsa_digest_in_t *in, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha256_update(&ctx, in->p1, in->l1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if((in->l2 != 0U) && (noxtls_sha256_update(&ctx, in->p2, in->l2) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if((in->l3 != 0U) && (noxtls_sha256_update(&ctx, in->p3, in->l3) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256 */

#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
RSA_NOINLINE static noxtls_return_t rsa_hash_run_sha512(uint8_t *hash, const rsa_digest_in_t *in, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha512_ctx_t ctx512;
    if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_update(&ctx512, in->p1, in->l1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if((in->l2 != 0U) && (noxtls_sha512_update(&ctx512, in->p2, in->l2) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if((in->l3 != 0U) && (noxtls_sha512_update(&ctx512, in->p3, in->l3) != NOXTLS_RETURN_SUCCESS)) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512 */

/**
 * @brief hash = H(in->p1 || in->p2 || in->p3) for the given algorithm.
 *
 * @param[out] hash      Digest output (at least 64 bytes).
 * @param[out] hash_len  Digest length.
 * @param[in]  in        Input segments.
 * @param[in]  hash_algo Hash algorithm.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NOT_SUPPORTED for a digest compiled out of
 *         the build or not usable here; NOXTLS_RETURN_INVALID_ALGORITHM; NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t rsa_digest(uint8_t *hash, uint32_t *hash_len, const rsa_digest_in_t *in, noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    {
        uint32_t hash_algo_u = (uint32_t)hash_algo;
        switch (hash_algo_u) {
        /* Digests compiled out of this build are NOT_SUPPORTED. */
        case (uint32_t)NOXTLS_HASH_MD5:
#if NOXTLS_FEATURE_MD5
            rc = rsa_hash_run_md5(hash, in);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 16U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_SHA1:
#if NOXTLS_FEATURE_SHA1
            rc = rsa_hash_run_sha1(hash, in, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 20U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_SHA_224:
#if NOXTLS_FEATURE_SHA224
            rc = rsa_hash_run_sha256(hash, in, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 28U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_SHA_256:
#if NOXTLS_FEATURE_SHA256
            rc = rsa_hash_run_sha256(hash, in, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 32U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_SHA_384:
#if NOXTLS_FEATURE_SHA384
            rc = rsa_hash_run_sha512(hash, in, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 48U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_SHA_512:
#if NOXTLS_FEATURE_SHA512
            rc = rsa_hash_run_sha512(hash, in, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 64U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_HASH_MD4:
        case (uint32_t)NOXTLS_HASH_SHA_512_224:
        case (uint32_t)NOXTLS_HASH_SHA_512_256:
        case (uint32_t)NOXTLS_HASH_SHA3_224:
        case (uint32_t)NOXTLS_HASH_SHA3_256:
        case (uint32_t)NOXTLS_HASH_SHA3_384:
        case (uint32_t)NOXTLS_HASH_SHA3_512:
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Hash noxtls_message
 *
 * @param hash The hash value
 * @param hash_len The length of the hash value
 * @param noxtls_message The noxtls_message value
 * @param message_len The length of the message value
 * @param hash_algo The hash algorithm value
 * @return The return value
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    rsa_digest_in_t in;
    in.p1 = noxtls_message;
    in.l1 = message_len;
    in.p2 = NULL;
    in.l2 = 0U;
    in.p3 = NULL;
    in.l3 = 0U;
    return rsa_digest(hash, hash_len, &in, hash_algo);
}

/**
 * @brief Initialize RSA key structure
 * 
 * @param key The key value
 * @param key_size The key size value
 * @return The return value
 */
noxtls_return_t noxtls_rsa_key_init(rsa_key_t *key, rsa_key_size_t key_size)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(((uint32_t)key_size < RSA_MIN_KEY_SIZE) || ((uint32_t)key_size > RSA_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t key_bytes = (uint32_t)key_size / 8U;
    
    noxtls_secure_zero((key), sizeof(rsa_key_t));
    key->key_size = (uint32_t)key_size;
    key->key_bytes = key_bytes;
    
    /* Allocate memory for key components */
    key->n = (uint8_t*)NOXTLS_CALLOC(key_bytes, 1);
    key->e = (uint8_t*)NOXTLS_CALLOC(key_bytes, 1);
    key->d = (uint8_t*)NOXTLS_CALLOC(key_bytes, 1);
    key->p = (uint8_t*)NOXTLS_CALLOC(key_bytes / 2U, 1U);
    key->q = (uint8_t*)NOXTLS_CALLOC(key_bytes / 2U, 1U);
    key->dp = (uint8_t*)NOXTLS_CALLOC(key_bytes / 2U, 1U);
    key->dq = (uint8_t*)NOXTLS_CALLOC(key_bytes / 2U, 1U);
    key->qi = (uint8_t*)NOXTLS_CALLOC(key_bytes / 2U, 1U);
    
    if((key->n == NULL) || (key->e == NULL) || (key->d == NULL) || (key->p == NULL) || (key->q == NULL) || (key->dp == NULL) || (key->dq == NULL) || (key->qi == NULL)) {
        (void)noxtls_rsa_key_free(key);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    
    /* Set default public exponent (65537 = 0x10001) */
    key->e[key_bytes - 3U] = 0x01U;
    key->e[key_bytes - 2U] = 0x00U;
    key->e[key_bytes - 1U] = 0x01U;
    key->e_len = key_bytes;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize a public-only RSA key (n and e only).
 *
 * See noxtls_rsa.h. Only n (key_bytes) and e (significant length) are allocated; all
 * private-component pointers stay NULL.
 *
 * @param[out] key      Key to initialize.
 * @param[in]  key_size Key size in bits (RSA_MIN_KEY_SIZE..RSA_MAX_KEY_SIZE).
 * @param[in]  n        Modulus, big-endian (leading zero bytes allowed).
 * @param[in]  n_len    Length of @p n in bytes.
 * @param[in]  e        Public exponent, big-endian (leading zero bytes allowed).
 * @param[in]  e_len    Length of @p e in bytes.
 * @return See noxtls_rsa.h.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_key_init_public(rsa_key_t *key, rsa_key_size_t key_size,
                                           const uint8_t *n, uint32_t n_len,
                                           const uint8_t *e, uint32_t e_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    const uint8_t *n_sig = n;
    const uint8_t *e_sig = e;
    uint32_t n_sig_len = n_len;
    uint32_t e_sig_len = e_len;
    uint32_t key_bytes = 0U;

    if((key == NULL) || (n == NULL) || (e == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(((uint32_t)key_size < RSA_MIN_KEY_SIZE) || ((uint32_t)key_size > RSA_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    key_bytes = (uint32_t)key_size / 8U;
    while((n_sig_len > 0U) && (n_sig[0] == 0U)) {
        n_sig = &n_sig[1];
        n_sig_len -= 1U;
    }
    while((e_sig_len > 0U) && (e_sig[0] == 0U)) {
        e_sig = &e_sig[1];
        e_sig_len -= 1U;
    }
    if((n_sig_len == 0U) || (n_sig_len > key_bytes) || (e_sig_len == 0U) || (e_sig_len > key_bytes)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_secure_zero((key), sizeof(rsa_key_t));
    key->key_size = (uint32_t)key_size;
    key->key_bytes = key_bytes;
    key->n = (uint8_t*)NOXTLS_CALLOC(key_bytes, 1U);
    key->e = (uint8_t*)NOXTLS_CALLOC(e_sig_len, 1U);
    if((key->n == NULL) || (key->e == NULL)) {
        (void)noxtls_rsa_key_free(key);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8(&key->n[key_bytes - n_sig_len], (size_t)n_sig_len, n_sig, (size_t)n_sig_len);
    noxtls_copy_u8(key->e, (size_t)e_sig_len, e_sig, (size_t)e_sig_len);
    key->e_len = e_sig_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Length of the public exponent buffer of @p key.
 *
 * Keys initialized by noxtls_rsa_key_init() have a key_bytes-long, right-aligned e;
 * noxtls_rsa_key_init_public() stores only the significant bytes. A key assembled by
 * hand (e_len == 0) is treated as the legacy key_bytes layout.
 */
static uint32_t rsa_e_len(const rsa_key_t *key)
{
    return ((key->e_len != 0U) && (key->e_len <= key->key_bytes)) ? key->e_len : key->key_bytes;
}

/**
 * @brief Check that @p key carries the public components (n, e) and a usable size.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL (missing buffer) or
 *         NOXTLS_RETURN_INVALID_PARAM (size out of range).
 */
static noxtls_return_t rsa_check_public_key(const rsa_key_t *key)
{
    if((key->n == NULL) || (key->e == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* 11 bytes: the smallest block the PKCS#1 v1.5 paddings fit in (keeps their length
     * arithmetic from wrapping for hand-built keys). */
    if((key->key_bytes < 11U) || (key->key_bytes > (RSA_MAX_KEY_SIZE / 8U))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check that @p key can be used for a private-key operation (n, e and d present).
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_INVALID_PARAM for a public-only key.
 */
static noxtls_return_t rsa_check_private_key(const rsa_key_t *key)
{
    noxtls_return_t rc = rsa_check_public_key(key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return (rc == NOXTLS_RETURN_NULL) ? NOXTLS_RETURN_INVALID_PARAM : rc;
    }
    if(key->d == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate RSA key pair
 * 
 * @param key The key value
 * @param key_size The key size value
 * @return The return value
 */
noxtls_return_t noxtls_rsa_key_generate(rsa_key_t *key, rsa_key_size_t key_size)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_return_t rc = noxtls_rsa_key_init(key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    uint32_t prime_len = (uint32_t)(key->key_bytes >> 1U);
    uint8_t *phi = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    uint8_t *p_minus_1 = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *q_minus_1 = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *temp = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    uint8_t *one = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    
    if((phi == NULL) || (p_minus_1 == NULL) || (q_minus_1 == NULL) || (temp == NULL) || (one == NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: noxtls_rsa_key_generate: Memory allocation failed!\n");
        if(phi != NULL) { (void)noxtls_free(phi); }
        if(p_minus_1 != NULL) { (void)noxtls_free(p_minus_1); }
        if(q_minus_1 != NULL) { (void)noxtls_free(q_minus_1); }
        if(temp != NULL) { (void)noxtls_free(temp); }
        if(one != NULL) { (void)noxtls_free(one); }
        return NOXTLS_RETURN_FAILED;
    }
    
    (void)noxtls_bn_one(one, prime_len);
    
    /* Generate two primes p and q */
    (void)noxtls_debug_printf((const uint8_t *)"Generating prime p (%u bits)...\n", prime_len * 8U);
    if((rsa_generate_prime(key->p, prime_len) == 0)) {
        (void)noxtls_debug_printf((const uint8_t *)"Error: Failed to generate prime p after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
        (void)noxtls_free(phi);
        (void)noxtls_free(p_minus_1);
        (void)noxtls_free(q_minus_1);
        (void)noxtls_free(temp);
        (void)noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    /* The primes are private key material: report progress only, never their value. */
    (void)noxtls_debug_printf((const uint8_t *)"Prime p generated successfully!\n");
    (void)noxtls_debug_printf((const uint8_t *)"Generating prime q (%u bits)...\n", prime_len * 8U);
    if((rsa_generate_prime(key->q, prime_len) == 0)) {
        (void)noxtls_debug_printf((const uint8_t *)"Error: Failed to generate prime q after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
        (void)noxtls_free(phi);
        (void)noxtls_free(p_minus_1);
        (void)noxtls_free(q_minus_1);
        (void)noxtls_free(temp);
        (void)noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    (void)noxtls_debug_printf((const uint8_t *)"Prime q generated successfully!\n");
    (void)noxtls_debug_printf((const uint8_t *)"Computing key components...\n");
    /* Compute n = p * q */
    rc = noxtls_bn_mul(key->n, key->p, prime_len, key->q, prime_len);

    /* Compute phi(n) = (p - 1U) * (q-1) */
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_copy(p_minus_1, key->p, prime_len); }
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_sub(p_minus_1, p_minus_1, one, prime_len); }
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_copy(q_minus_1, key->q, prime_len); }
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_sub(q_minus_1, q_minus_1, one, prime_len); }
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mul(phi, p_minus_1, prime_len, q_minus_1, prime_len); }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: noxtls_rsa_key_generate: Failed to compute n / phi(n)\n");
        NOXTLS_SECURE_FREE(phi, key->key_bytes);
        NOXTLS_SECURE_FREE(p_minus_1, prime_len);
        NOXTLS_SECURE_FREE(q_minus_1, prime_len);
        NOXTLS_SECURE_FREE(temp, key->key_bytes);
        (void)noxtls_free(one);
        return rc;
    }

    /* Compute d = e^-1 mod phi(n) (phi is even; use small-e inverse helper) */
    if(rsa_mod_inv_small(key->d, phi, key->key_bytes, 65537U) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: noxtls_rsa_key_generate: Failed to compute private exponent d\n");
        (void)noxtls_free(phi);
        (void)noxtls_free(p_minus_1);
        (void)noxtls_free(q_minus_1);
        (void)noxtls_free(temp);
        (void)noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Compute CRT parameters */
    rc = noxtls_bn_mod(key->dp, key->d, key->key_bytes, p_minus_1, prime_len);
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(key->dq, key->d, key->key_bytes, q_minus_1, prime_len); }
    /* qi = q^(p - 2U) mod p (Fermat), avoids mod_inv pitfalls */
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_sub(p_minus_1, p_minus_1, one, prime_len); } /* p_minus_1 now p - 2U */
    if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(key->qi, key->q, p_minus_1, prime_len, key->p, prime_len); }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Never hand out a key whose CRT components were not computed. */
        noxtls_secure_zero(key->d, key->key_bytes);
        noxtls_secure_zero(key->dp, prime_len);
        noxtls_secure_zero(key->dq, prime_len);
        noxtls_secure_zero(key->qi, prime_len);
    }

    NOXTLS_SECURE_FREE(phi, key->key_bytes);
    NOXTLS_SECURE_FREE(p_minus_1, prime_len);
    NOXTLS_SECURE_FREE(q_minus_1, prime_len);
    NOXTLS_SECURE_FREE(temp, key->key_bytes);
    (void)noxtls_free(one);

    return rc;
}

/**
 * @brief Free RSA key structure
 * 
 * @param key The key value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_rsa_key_free(rsa_key_t *key)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Public components: plain free. Private components (allocated by noxtls_rsa_key_init
     * with key_bytes / key_bytes / 2 bytes) are wiped first. Every pointer may be NULL
     * (public-only keys from noxtls_rsa_key_init_public, partially initialized keys). */
    {
        const size_t full = (size_t)key->key_bytes;
        const size_t half = (size_t)(key->key_bytes >> 1U);
        if(key->n != NULL) { (void)noxtls_free(key->n); key->n = NULL; }
        if(key->e != NULL) { (void)noxtls_free(key->e); key->e = NULL; }
        NOXTLS_SECURE_FREE(key->d, full);
        NOXTLS_SECURE_FREE(key->p, half);
        NOXTLS_SECURE_FREE(key->q, half);
        NOXTLS_SECURE_FREE(key->dp, half);
        NOXTLS_SECURE_FREE(key->dq, half);
        NOXTLS_SECURE_FREE(key->qi, half);
    }

    noxtls_secure_zero((key), sizeof(rsa_key_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Encryption
 * 
 * @param key The key value
 * @param plaintext The plaintext value
 * @param plaintext_len The length of the plaintext value
 * @param ciphertext The ciphertext value
 * @param ciphertext_len The length of the ciphertext value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_FAILED if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_rsa_encrypt(const rsa_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t *ciphertext_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((key == NULL) || (plaintext == NULL) || (ciphertext == NULL) || (ciphertext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = rsa_check_public_key(key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(plaintext_len > (key->key_bytes - 11U)) {
        (void)noxtls_debug_printf((const uint8_t *)"[noxtls_rsa_encrypt] FAIL: plaintext_len %lu > key_bytes - 11U %lu\n",
                (unsigned long)plaintext_len, (unsigned long)(key->key_bytes - 11U));
        return NOXTLS_RETURN_FAILED;
    }
    
    if(*ciphertext_len < key->key_bytes) {
        (void)noxtls_debug_printf((const uint8_t *)"[noxtls_rsa_encrypt] FAIL: *ciphertext_len %lu < key_bytes %lu\n",
                (unsigned long)*ciphertext_len, (unsigned long)key->key_bytes);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Apply PKCS#1 v1.5 padding */
    uint8_t *padded = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(padded == NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"[noxtls_rsa_encrypt] FAIL: NOXTLS_CALLOC(key_bytes=%lu) returned NULL\n",
                (unsigned long)key->key_bytes);
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = rsa_pkcs1_v15_encrypt_pad(padded, key->key_bytes, plaintext, plaintext_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(padded);
        return rc;
    }
    
    /* Encrypt: c = m^e mod n */
    rc = noxtls_bn_mod_exp_public(ciphertext, padded, key->e, rsa_e_len(key), key->n, key->key_bytes);
    NOXTLS_SECURE_FREE(padded, key->key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ciphertext, key->key_bytes);
        return rc;
    }

    *ciphertext_len = key->key_bytes;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief out = (a * b) mod m.
 *
 * @p out may alias @p a or @p b (the product is formed in a separate buffer first).
 * The product buffer is wiped: operands may be secret (blinding factors, CRT values).
 *
 * @return NOXTLS_RETURN_SUCCESS or the bignum / allocation error; @p out is zeroed on failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_mul_mod(uint8_t *out, const uint8_t *a, uint32_t a_len,
                                   const uint8_t *b, uint32_t b_len,
                                   const uint8_t *m, uint32_t m_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    const size_t wide_len = (size_t)a_len + (size_t)b_len;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    uint8_t *wide = (uint8_t*)NOXTLS_CALLOC(wide_len, 1U);

    if(wide != NULL) {
        rc = noxtls_bn_mul(wide, a, a_len, b, b_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(out, wide, (uint32_t)wide_len, m, m_len);
        }
    }
    NOXTLS_SECURE_FREE(wide, wide_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, (size_t)m_len);
    }
    return rc;
}

/**
 * @brief out = (a - b) mod m for a, b < m (big-endian, len bytes), without secret-dependent
 *        branches: the borrow of a - b selects, by mask, whether m is added back.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_sub_mod_ct(uint8_t *out, const uint8_t *a, const uint8_t *b,
                           const uint8_t *m, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t i = 0U;
    uint32_t borrow = 0U;
    uint32_t carry = 0U;
    uint32_t mask = 0U;

    for(i = len; i > 0U; i -= 1U) {
        uint32_t d = ((uint32_t)a[i - 1U] - (uint32_t)b[i - 1U]) - borrow;
        out[i - 1U] = (uint8_t)(d & 0xFFU);
        borrow = (d >> 8U) & 1U;
    }
    mask = 0U - borrow;
    for(i = len; i > 0U; i -= 1U) {
        uint32_t s = (uint32_t)out[i - 1U] + ((uint32_t)m[i - 1U] & mask) + carry;
        out[i - 1U] = (uint8_t)(s & 0xFFU);
        carry = s >> 8U;
    }
}

/**
 * @brief 1 when the len-byte value is zero, 0 otherwise; scans every byte (no early exit
 *        that would reveal the position of the first non-zero byte of a secret value).
 */
static uint32_t rsa_is_zero_ct(const uint8_t *a, uint32_t len)
{
    uint32_t acc = 0U;
    uint32_t i = 0U;
    for(i = 0U; i < len; i += 1U) {
        acc |= (uint32_t)a[i];
    }
    return ((acc - 1U) >> 31U) & 1U;
}

/**
 * @brief 1 when @p key carries usable CRT components (p, q, dp, dq, qi present and non-zero).
 *
 * noxtls_rsa_key_init() allocates the CRT buffers zero-filled, so a key whose caller only
 * filled n, e and d is detected here and keeps using the full-exponent path.
 */
static uint32_t rsa_key_has_crt(const rsa_key_t *key)
{
    const uint32_t pl = (uint32_t)(key->key_bytes >> 1U);

    if((pl == 0U) || (key->p == NULL) || (key->q == NULL) || (key->dp == NULL) ||
       (key->dq == NULL) || (key->qi == NULL)) {
        return 0U;
    }
    return (rsa_is_zero_ct(key->p, pl) | rsa_is_zero_ct(key->q, pl) | rsa_is_zero_ct(key->dp, pl) |
            rsa_is_zero_ct(key->dq, pl) | rsa_is_zero_ct(key->qi, pl)) ^ 1U;
}

/**
 * @brief Fresh blinding pair: blind = r^e mod n and r_inv = r^-1 mod n for a random r.
 *
 * The inversion runs on r * s mod n for a second random s and r^-1 is recovered as
 * (r * s)^-1 * s, so the (variable-time) binary-GCD inversion only ever sees a value that
 * is independent of r. Fails closed: if no usable factor can be produced (RNG failure or
 * repeated non-invertible values), no private-key operation is performed.
 *
 * @param[in]  key   RSA key (n, e).
 * @param[out] blind key_bytes buffer: r^e mod n.
 * @param[out] r_inv key_bytes buffer: r^-1 mod n.
 */
static noxtls_return_t rsa_blinding_pair(const rsa_key_t *key, uint8_t *blind, uint8_t *r_inv)
{
    const uint32_t len = (uint32_t)(key->key_bytes);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t attempt = 0U;
    uint8_t *r = (uint8_t*)NOXTLS_CALLOC(len, 1U);
    uint8_t *s = (uint8_t*)NOXTLS_CALLOC(len, 1U);

    if((r == NULL) || (s == NULL)) {
        NOXTLS_SECURE_FREE(r, len);
        NOXTLS_SECURE_FREE(s, len);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    for(attempt = 0U; attempt < 8U; attempt += 1U) {
        /* r, s in [1, n - 1]; blind is scratch for the raw random bytes. */
        if(rsa_random_bytes(blind, len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED; /* never proceed with weak/no randomness */
            break;
        }
        rc = noxtls_bn_mod(r, blind, len, key->n, len);
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        if(rsa_random_bytes(blind, len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED;
            break;
        }
        rc = noxtls_bn_mod(s, blind, len, key->n, len);
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        if((noxtls_bn_is_zero(r, len) != 0) || (noxtls_bn_is_zero(s, len) != 0)) {
            rc = NOXTLS_RETURN_FAILED;
            continue;
        }
        /* blind = r * s mod n; r_inv = (r * s)^-1 mod n. Only a non-invertible value
         * (gcd != 1, negligible probability) is retried; other errors abort. */
        rc = rsa_mul_mod(blind, r, len, s, len, key->n, len);
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        rc = noxtls_bn_mod_inv(r_inv, blind, len, key->n, len);
        if(rc == NOXTLS_RETURN_FAILED) { continue; }
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        /* r_inv = (r * s)^-1 * s = r^-1 mod n */
        rc = rsa_mul_mod(r_inv, r_inv, len, s, len, key->n, len);
        /* blind = r^e mod n (public exponent: table-free path; time does not depend on r) */
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod_exp_public(blind, r, key->e, rsa_e_len(key), key->n, len);
        }
        break;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(blind, (size_t)len);
        noxtls_secure_zero(r_inv, (size_t)len);
    }
    NOXTLS_SECURE_FREE(r, len);
    NOXTLS_SECURE_FREE(s, len);
    return rc;
}

/**
 * @brief In-place CRT exponentiation: xy = x^d mod n computed from p, q, dp, dq, qi (Garner).
 *
 *   m1 = x^dp mod p, m2 = x^dq mod q, h = qi * (m1 - m2) mod p, y = m2 + h * q.
 *
 * The half-size exponentiations use the constant-time windowed Montgomery path; the
 * subtraction mod p is masked. @p xy (key_bytes) holds x on entry and y on success; it is
 * also used as scratch once x has been reduced. Every intermediate is wiped. A wrong CRT
 * component yields a wrong y, which the caller's fault check rejects.
 */
static noxtls_return_t rsa_crt_exp(const rsa_key_t *key, uint8_t *xy)
{
    const uint32_t kb = (uint32_t)(key->key_bytes);
    const uint32_t pl = (uint32_t)(kb >> 1U);
    noxtls_return_t rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    uint8_t *m1 = (uint8_t*)NOXTLS_CALLOC(pl, 1U);
    uint8_t *m2 = (uint8_t*)NOXTLS_CALLOC(pl, 1U);

    if((m1 != NULL) && (m2 != NULL)) {
        /* m1 = (x mod p)^dp mod p, m2 = (x mod q)^dq mod q */
        rc = noxtls_bn_mod(m1, xy, kb, key->p, pl);
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(m2, xy, kb, key->q, pl); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(m1, m1, key->dp, pl, key->p, pl); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(m2, m2, key->dq, pl, key->q, pl); }
        /* x is no longer needed: xy[0..pl) = m2 mod p (m2 < q may exceed p) */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(xy, m2, pl, key->p, pl); }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            /* m1 = h = (m1 - m2) * qi mod p */
            rsa_sub_mod_ct(m1, m1, xy, key->p, pl);
            rc = rsa_mul_mod(m1, m1, pl, key->qi, pl, key->p, pl);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            /* y = m2 + h * q (< p * q = n, so it fits in key_bytes) */
            noxtls_secure_zero(xy, (size_t)kb);
            rc = noxtls_bn_mul(&xy[kb - (2U * pl)], m1, pl, key->q, pl);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            uint32_t carry = 0U;
            uint32_t i = 0U;
            for(i = 0U; i < kb; i += 1U) {
                uint32_t idx = kb - 1U - i;
                uint32_t add = (i < pl) ? (uint32_t)m2[pl - 1U - i] : 0U;
                uint32_t sum = (uint32_t)xy[idx] + add + carry;
                xy[idx] = (uint8_t)(sum & 0xFFU);
                carry = sum >> 8U;
            }
        }
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(xy, (size_t)kb);
    }
    NOXTLS_SECURE_FREE(m1, pl);
    NOXTLS_SECURE_FREE(m2, pl);
    return rc;
}

/**
 * @brief Blinded RSA private-key operation with fault check: output = input^d mod n.
 *
 *   x = input * r^e mod n;  y = x^d mod n (CRT when p, q, dp, dq, qi are present, otherwise
 *   the full exponent d);  output = y * r^-1 mod n;  then output^e mod n must equal input.
 *
 * Base blinding (NX-15) decorrelates the attacker-chosen input from any residual timing of
 * the reductions. The fault check (verify with the public exponent before releasing the
 * result) defeats CRT fault attacks (a single faulty half would otherwise reveal p or q);
 * on mismatch the output is wiped and NOXTLS_RETURN_FAILED is returned. All intermediates
 * are wiped.
 *
 * @param[in]  key         RSA key (n, e and either CRT components or d).
 * @param[in]  input       key_bytes block, numerically < n.
 * @param[out] output      key_bytes result (must not alias @p input).
 * @param[in]  require_crt 1 to fail instead of using d when CRT components are missing.
 */
static noxtls_return_t rsa_private_op(const rsa_key_t *key, const uint8_t *input, uint8_t *output,
                                      uint32_t require_crt)
{
    const uint32_t len = (uint32_t)(key->key_bytes);
    const uint32_t use_crt = rsa_key_has_crt(key);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *x = NULL;
    uint8_t *r_inv = NULL;

    if((use_crt == 0U) && ((require_crt != 0U) || (key->d == NULL))) {
        noxtls_secure_zero(output, (size_t)len);
        return NOXTLS_RETURN_FAILED;
    }
    x = (uint8_t*)NOXTLS_CALLOC(len, 1U);
    r_inv = (uint8_t*)NOXTLS_CALLOC(len, 1U);
    if((x == NULL) || (r_inv == NULL)) {
        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    } else {
        /* x = blind = r^e, then x = input * r^e mod n */
        rc = rsa_blinding_pair(key, x, r_inv);
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = rsa_mul_mod(x, input, len, x, len, key->n, len); }
        /* x = x^d mod n = input^d * r mod n */
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(use_crt != 0U) {
                rc = rsa_crt_exp(key, x);
            } else {
                rc = noxtls_bn_mod_exp(x, x, key->d, len, key->n, len);
            }
        }
        /* output = x * r^-1 mod n = input^d mod n */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = rsa_mul_mod(output, x, len, r_inv, len, key->n, len); }
    }
    NOXTLS_SECURE_FREE(x, len);
    NOXTLS_SECURE_FREE(r_inv, len);

    /* Fault check: output^e mod n == input before anything is released. */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        uint8_t *chk = (uint8_t*)NOXTLS_CALLOC(len, 1U);
        if(chk == NULL) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        } else {
            rc = noxtls_bn_mod_exp_public(chk, output, key->e, rsa_e_len(key), key->n, len);
            if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_secret_memcmp(chk, input, (size_t)len) != 0)) {
                rc = NOXTLS_RETURN_FAILED;
            }
        }
        NOXTLS_SECURE_FREE(chk, len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, (size_t)len);
    }
    return rc;
}

/**
 * @brief Constant-time PKCS#1 v1.5 type-2 unpadding (RFC 8017), shared by the decrypt APIs.
 *
 * SECURITY (NX-03): the whole block is scanned without secret-dependent branches; padding
 * validity and the separator position are computed as masks so that the time taken does
 * not reveal WHERE the padding check failed (Bleichenbacher oracle hardening).
 */
static noxtls_return_t rsa_pkcs1_v15_unpad_ct(const uint8_t *decrypted, uint32_t kb,
                                              uint8_t *plaintext, uint32_t *plaintext_len)
{
    uint32_t good;       /* 0xFFFFFFFFU when padding is valid, 0 otherwise */
    uint32_t found_sep;  /* all-ones once the 0x00U separator has been seen */
    uint32_t sep_index;  /* index of the separator byte */
    uint32_t data_len = 0U;
    uint32_t i = 0U;

    if(kb < 11U) {
        return NOXTLS_RETURN_FAILED;
    }

    /* good := (decrypted[0] == 0x00) & (decrypted[1] == 0x02) */
    good  = (uint32_t)0U - (uint32_t)(((uint32_t)decrypted[0U] - 1U) >> 31U);          /* b0 == 0 */
    good &= (uint32_t)0U - (uint32_t)((((uint32_t)decrypted[1U] ^ 0x02U) - 1U) >> 31U); /* b1 == 2 */

    found_sep = 0U;
    sep_index = 0U;
    for(i = 2U; i < kb; i += 1U) {
        /* is_zero = all-ones when decrypted[i] == 0 */
        uint32_t is_zero = (uint32_t)0U - (uint32_t)(((uint32_t)decrypted[i] - 1U) >> 31U);
        uint32_t is_first = (uint32_t)(is_zero & ~found_sep);
        sep_index |= i & is_first;
        found_sep |= is_zero;
    }
    good &= found_sep;
    /* At least 8 non-zero padding bytes: separator index must be >= 10. */
    good &= (uint32_t)0U - (uint32_t)((9U - sep_index) >> 31U);

    data_len = (kb - sep_index - 1U) & good;

    if((good == 0U) || (data_len > *plaintext_len)) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(plaintext, (size_t)(data_len), &decrypted[sep_index + 1U], (size_t)(data_len));
    *plaintext_len = data_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Decryption (PKCS#1 v1.5): blinded CRT when the key has CRT components,
 *        blinded full exponent otherwise; fault-checked; constant-time unpadding.
 */
noxtls_return_t noxtls_rsa_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *decrypted = NULL;

    if((key == NULL) || (ciphertext == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(rsa_check_private_key(key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;  /* public-only or incomplete key */
    }
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    /* RSADP (RFC 8017 section 5.1.2) step 1: the ciphertext representative must be < n
     * ("ciphertext representative out of range"). c and n are public: no oracle. */
    if(noxtls_bn_cmp(ciphertext, key->n, key->key_bytes) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }

    decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1U);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = rsa_private_op(key, ciphertext, decrypted, 0U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = rsa_pkcs1_v15_unpad_ct(decrypted, (uint32_t)key->key_bytes, plaintext, plaintext_len);
    }
    NOXTLS_SECURE_FREE(decrypted, key->key_bytes);
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief RSA decrypt using the CRT path only (for unit testing).
 *
 * Same blinded, fault-checked private operation and constant-time unpadding as
 * noxtls_rsa_decrypt(), but fails instead of falling back to d when the key has no
 * CRT components. d is not required.
 */
noxtls_return_t noxtls_rsa_decrypt_crt_only(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *decrypted = NULL;

    if((key == NULL) || (ciphertext == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(rsa_check_public_key(key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    if(rsa_key_has_crt(key) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    /* RSADP step 1 (RFC 8017 section 5.1.2): ciphertext representative must be < n. */
    if(noxtls_bn_cmp(ciphertext, key->n, key->key_bytes) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }

    decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1U);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    /* The decrypted block is secret (plaintext + padding): it is never logged. */
    rc = rsa_private_op(key, ciphertext, decrypted, 1U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = rsa_pkcs1_v15_unpad_ct(decrypted, (uint32_t)key->key_bytes, plaintext, plaintext_len);
    }
    NOXTLS_SECURE_FREE(decrypted, key->key_bytes);
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/*
 * Internal hash_algo flag: the input of the PKCS#1 v1.5 sign / PSS verify core is already the
 * digest of the (unflagged) hash. Never a valid noxtls_hash_algos_t value; the public message
 * APIs reject it.
 */
#define RSA_INPUT_IS_DIGEST ((noxtls_hash_algos_t)0x80000000U)

/**
 * @brief hash = Hash(message), or hash = message itself (exactly the digest length of the hash)
 *        when @p hash_algo carries RSA_INPUT_IS_DIGEST.
 */
static noxtls_return_t rsa_hash_or_digest(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message,
                                          uint32_t message_len, noxtls_hash_algos_t hash_algo)
{
    uint32_t want = 0U;
    const uint32_t algo_u = (uint32_t)(hash_algo & ~RSA_INPUT_IS_DIGEST);

    if((hash_algo & RSA_INPUT_IS_DIGEST) == 0U) {
        return rsa_hash_message(hash, hash_len, noxtls_message, message_len, hash_algo);
    }
    switch(algo_u) {
        case (uint32_t)NOXTLS_HASH_MD5:     want = 16U; break;
        case (uint32_t)NOXTLS_HASH_SHA1:    want = 20U; break;
        case (uint32_t)NOXTLS_HASH_SHA_224: want = 28U; break;
        case (uint32_t)NOXTLS_HASH_SHA_256: want = 32U; break;
        case (uint32_t)NOXTLS_HASH_SHA_384: want = 48U; break;
        case (uint32_t)NOXTLS_HASH_SHA_512: want = 64U; break;
        default: return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if((noxtls_message == NULL) || (message_len != want)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_copy_u8(hash, 64U, noxtls_message, (size_t)message_len);
    *hash_len = message_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSASSA-PKCS1-v1_5 signature over Hash(message), or over a precomputed digest
 *        (RSA_INPUT_IS_DIGEST); shared by noxtls_rsa_sign() and noxtls_rsa_sign_digest().
 */
static noxtls_return_t rsa_sign_core(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(rsa_check_private_key(key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;  /* public-only or incomplete key */
    }
    
    if(*signature_len < key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Hash the noxtls_message (or take the caller's digest) */
    uint8_t hash[64];
    uint32_t hash_len = 0U;
    noxtls_return_t rc = rsa_hash_or_digest(hash, &hash_len, noxtls_message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    const noxtls_hash_algos_t enc_algo = (noxtls_hash_algos_t)(hash_algo & ~RSA_INPUT_IS_DIGEST);

    /* Apply PKCS#1 v1.5 signature padding */
    uint8_t *padded = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(padded == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = rsa_pkcs1_v15_encode_digest(padded, key->key_bytes, hash, hash_len, enc_algo, 0U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(padded, key->key_bytes);
        (void)noxtls_free(padded);
        return rc;
    }
    
    /* Sign (blinded CRT when available, fault-checked; NX-15): s = EM^d mod n */
    rc = rsa_private_op(key, padded, signature, 0U);
    (void)noxtls_free(padded);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    *signature_len = key->key_bytes;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Signature Generation
 */
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if((hash_algo & RSA_INPUT_IS_DIGEST) != 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return rsa_sign_core(key, noxtls_message, message_len, signature, signature_len, hash_algo);
}

/**
 * @brief RSASSA-PKCS1-v1_5 signature over a precomputed digest.
 *
 * Same as noxtls_rsa_sign() with the digest of @p hash_algo supplied by the caller
 * (e.g. TLS 1.2 CertificateVerify over a running transcript hash): EM = 0x00 01 FF..FF 00 ||
 * DigestInfo(hash_algo) || digest.
 *
 * @param key RSA private key
 * @param digest Message digest (exactly the output length of @p hash_algo)
 * @param digest_len Digest length
 * @param signature Signature output (>= key size bytes)
 * @param signature_len In: capacity, out: signature length
 * @param hash_algo Digest algorithm (MD5, SHA-1, SHA-224/256/384/512)
 * @return As noxtls_rsa_sign(); NOXTLS_RETURN_INVALID_PARAM when @p digest_len does not match
 *         @p hash_algo.
 */
noxtls_return_t noxtls_rsa_sign_digest(const rsa_key_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if((hash_algo & RSA_INPUT_IS_DIGEST) != 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return rsa_sign_core(key, digest, digest_len, signature, signature_len,
                         (noxtls_hash_algos_t)(hash_algo | RSA_INPUT_IS_DIGEST));
}

/**
 * @brief RSA Signature Verification
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_verify(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    {
        noxtls_return_t key_rc = rsa_check_public_key(key);
        if(key_rc != NOXTLS_RETURN_SUCCESS) {
            return key_rc;
        }
    }
    
    if(signature_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* RSAVP1 (RFC 8017 section 5.2.2): the signature representative must be < n. */
    if(noxtls_bn_cmp(signature, key->n, key->key_bytes) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify: EM = signature^e mod n. The expected-encoding buffer is only allocated once the
     * exponentiation scratch has been released, so the two never coexist. */
    uint8_t *expected = NULL;
    uint8_t *decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_return_t rc = noxtls_bn_mod_exp_public(decrypted, signature, key->e, rsa_e_len(key), key->n, key->key_bytes);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        expected = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
        if(expected == NULL) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }

    /* Hash the noxtls_message */
    uint8_t hash[64];
    uint32_t hash_len = 0U;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = rsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    }

    /* RSASSA-PKCS1-v1_5-VERIFY (RFC 8017 section 8.2.2): re-encode the digest and
     * compare the whole encoded message. Only the standard DigestInfo and the
     * variant with absent NULL parameters are accepted; no lenient parsing. */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = rsa_pkcs1_v15_encode_digest(expected, key->key_bytes, hash, hash_len, hash_algo, 0U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(noxtls_secret_memcmp(decrypted, expected, (size_t)key->key_bytes) != 0) {
            rc = rsa_pkcs1_v15_encode_digest(expected, key->key_bytes, hash, hash_len, hash_algo, 1U);
            if((rc == NOXTLS_RETURN_SUCCESS) &&
               (noxtls_secret_memcmp(decrypted, expected, (size_t)key->key_bytes) != 0)) {
                rc = NOXTLS_RETURN_FAILED;
            }
        }
    }

    NOXTLS_SECURE_FREE(decrypted, key->key_bytes);
    NOXTLS_SECURE_FREE(expected, key->key_bytes);
    /* Hash selection errors (NOT_SUPPORTED, INVALID_ALGORITHM) propagate; any
     * encoding mismatch has already been mapped to NOXTLS_RETURN_FAILED. */
    return rc;
}

/* --- RSA-PSS (RFC 8017) --- */

static uint32_t rsa_pss_digest_len(noxtls_hash_algos_t hash_algo)
{
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        return 32U;
    }
    if(hash_algo == NOXTLS_HASH_SHA_384) {
        return 48U;
    }
    if(hash_algo == NOXTLS_HASH_SHA_512) {
        return 64U;
    }
    return 0U;
}

/** Hash for PSS: SHA-256, SHA-384, or SHA-512 (for TLS 1.3). */
static noxtls_return_t pss_hash_message(noxtls_hash_algos_t hash_algo, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *hash, uint32_t *hash_len)
{
    if(rsa_pss_digest_len(hash_algo) == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return rsa_hash_message(hash, hash_len, noxtls_message, message_len, hash_algo);
}

/**
 * @brief out[0..out_len) ^= MGF1(seed, out_len) (RFC 8017 B.2.1).
 *
 * The mask is produced one digest block at a time and XORed straight into @p out, so no
 * mask buffer and no seed || counter copy is needed.
 */
static noxtls_return_t mgf1_xor(noxtls_hash_algos_t hash_algo, const uint8_t *seed, uint32_t seed_len, uint8_t *out, uint32_t out_len)
{
    const uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t counter[4];
    uint8_t T_buf[64];
    uint32_t offset = 0U;
    uint32_t block = 0U;
    uint32_t d_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    rsa_digest_in_t in;

    if((seed == NULL) || ((out == NULL) && (out_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    if(h_len == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    in.p1 = seed;
    in.l1 = seed_len;
    in.p2 = counter;
    in.l2 = 4U;
    in.p3 = NULL;
    in.l3 = 0U;
    while((offset < out_len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t copy = (uint32_t)(out_len - offset);
        uint32_t i = 0U;
        counter[0] = (uint8_t)(block >> 24U);
        counter[1] = (uint8_t)(block >> 16U);
        counter[2] = (uint8_t)(block >> 8U);
        counter[3] = (uint8_t)block;
        rc = rsa_digest(T_buf, &d_len, &in, hash_algo);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(copy > h_len) { copy = h_len; }
            for(i = 0U; i < copy; i += 1U) {
                out[offset + i] ^= T_buf[i];
            }
            offset += copy;
            block += 1U;
        }
    }
    noxtls_secure_zero(T_buf, sizeof(T_buf));
    return rc;
}

/**
 * @brief Number of significant bits of a big-endian modulus (RFC 8017 modBits).
 *
 * @param[in] n   Modulus, big-endian.
 * @param[in] len Length of @p n in bytes.
 * @return Bit length of n (0 when n is zero).
 */
static uint32_t rsa_modulus_bits(const uint8_t *n, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t bits = 0U;

    while((i < len) && (n[i] == 0U)) {
        i += 1U;
    }
    if(i < len) {
        uint32_t top = (uint32_t)n[i];
        bits = (len - i - 1U) * 8U;
        while(top != 0U) {
            bits += 1U;
            top >>= 1U;
        }
    }
    return bits;
}

/**
 * @brief Mask of the bits of EM's first octet that may be non-zero (RFC 8017 9.1.1 step 11,
 *        9.1.2 step 6): the leftmost 8*emLen - emBits bits must be zero.
 */
static uint8_t rsa_pss_top_mask(uint32_t em_len, uint32_t em_bits)
{
    uint32_t unused = (uint32_t)((em_len * 8U) - em_bits); /* 0..7 */
    return (uint8_t)(0xFFU >> unused);
}

/** EMSA-PSS-ENCODE (RFC 8017). salt_len must equal h_len; em_len == ceil(em_bits / 8).
 *  DB = PS || 0x01 || salt is built in place in @p em, H = Hash(0^8 || mHash || salt) is
 *  written to its final position and MGF1(H) is XORed over DB in place. */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t emsa_pss_encode(const uint8_t *m_hash, uint32_t h_len,
    uint32_t em_len, uint32_t em_bits, noxtls_hash_algos_t hash_algo, uint32_t salt_len,
    uint8_t *em)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t zeros8[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    rsa_digest_in_t in;
    uint32_t d_len = 0U;

    if((m_hash == NULL) || (em == NULL)) { return NOXTLS_RETURN_NULL; }
    if((h_len > 64U) || (salt_len > 64U)) { return NOXTLS_RETURN_INVALID_PARAM; }
    if((em_len == 0U) || (em_len != ((em_bits + 7U) / 8U))) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(h_len > (uint32_t)(UINT32_MAX - salt_len - 8U)) { return NOXTLS_RETURN_FAILED; }
    if(em_len < (h_len + salt_len + 2U)) { return NOXTLS_RETURN_FAILED; }
    uint32_t ps_len = (uint32_t)(em_len - salt_len - h_len - 2U);
    uint32_t db_len = (uint32_t)(em_len - h_len - 1U);

    noxtls_secure_zero((em), (size_t)(ps_len));
    em[ps_len] = 0x01U;
    if((salt_len > 0U) && (rsa_random_bytes(&em[ps_len + 1U], salt_len) != NOXTLS_RETURN_SUCCESS)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* H = Hash(M'), M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    in.p1 = zeros8;
    in.l1 = 8U;
    in.p2 = m_hash;
    in.l2 = h_len;
    in.p3 = &em[ps_len + 1U];
    in.l3 = salt_len;
    if(rsa_digest(&em[db_len], &d_len, &in, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(d_len != h_len) {
        return NOXTLS_RETURN_FAILED;
    }
    /* maskedDB = DB xor MGF1(H, emLen - hLen - 1) */
    if(mgf1_xor(hash_algo, &em[db_len], h_len, em, db_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Step 11: clear the leftmost 8*emLen - emBits bits so that EM < 2^emBits <= n. */
    em[0] &= rsa_pss_top_mask(em_len, em_bits);
    em[em_len - 1U] = 0xbcU;
    return NOXTLS_RETURN_SUCCESS;
}

/* Set to 1 to trace PSS verify failures to stderr (e.g. for unit tests). */
#ifndef NOXTLS_DEBUG_PSS_VERIFY
#define NOXTLS_DEBUG_PSS_VERIFY 0
#endif

/** EMSA-PSS-VERIFY (RFC 8017). em_len == ceil(em_bits / 8). maskedDB is unmasked in place
 *  (@p em is a scratch copy of the recovered encoded message). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t emsa_pss_verify(const uint8_t *m_hash, uint32_t h_len,
    uint8_t *em, uint32_t em_len, uint32_t em_bits, noxtls_hash_algos_t hash_algo, uint32_t salt_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t zeros8[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    uint8_t top_mask;
    rsa_digest_in_t in;
    uint32_t d_len = 0U;

    if((m_hash == NULL) || (em == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((h_len > 64U) || (salt_len > 64U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((em_len == 0U) || (em_len != ((em_bits + 7U) / 8U))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    top_mask = rsa_pss_top_mask(em_len, em_bits);
    if(h_len > (uint32_t)(UINT32_MAX - salt_len - 8U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((em_len < (h_len + salt_len + 2U)) || (em[em_len - 1U] != 0xbcU)) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: em_len=%u last_byte=0x%02x (expect 0xbc)\n",
            (uint32_t)em_len, (uint32_t)(em_len > 0U ? em[em_len - 1U] : 0U));
#endif
        return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] step: trailer 0xbc ok em_len=%u\n", (uint32_t)em_len);
#endif
    uint32_t db_len = (uint32_t)(em_len - h_len - 1U);
    uint32_t ps_len_val = (uint32_t)(em_len - salt_len - h_len - 2U);

    uint8_t *DB = em;                 /* maskedDB, unmasked in place below */
    const uint8_t *H = &em[db_len];

    /* Step 6: the leftmost 8*emLen - emBits bits of maskedDB must be zero (reject, never mask). */
    if((DB[0] & (uint8_t)~top_mask) != 0U) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: maskedDB[0]=0x%02x has bits outside 0x%02x\n",
            (uint32_t)DB[0], (uint32_t)top_mask);
#endif
        return NOXTLS_RETURN_FAILED;
    }

    /* DB = maskedDB xor MGF1(H, db_len) */
    if(mgf1_xor(hash_algo, H, h_len, DB, db_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Step 9: set the leftmost 8*emLen - emBits bits of DB to zero. */
    DB[0] &= top_mask;

    /* Padding: ps_len_val zeros, then 0x01 (at index ps_len_val). */
    uint32_t i = 0U;
    for(i = 0U; (i < ps_len_val) && (DB[i] == 0U); i += 1U) { }
    if((i != ps_len_val) || (i >= db_len) || (DB[i] != 0x01U)) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: padding: i=%u ps_len_val=%u db_len=%u DB[i]=0x%02x (expect 0x01 at i==ps_len_val)\n",
            (uint32_t)i, (uint32_t)ps_len_val, (uint32_t)db_len, (uint32_t)(i < db_len ? DB[i] : 0));
#endif
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t salt_offset = (uint32_t)(i + 1U);
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] step: padding ok i=%u salt_offset=%u\n", (uint32_t)i, (uint32_t)salt_offset);
#endif
    if((salt_offset > db_len) || (salt_len > (db_len - salt_offset))) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: salt_offset+salt_len > db_len\n");
#endif
        return NOXTLS_RETURN_FAILED;
    }

    /* H' = Hash(0^8 || mHash || salt) */
    uint8_t H_prime[64];
    in.p1 = zeros8;
    in.l1 = 8U;
    in.p2 = m_hash;
    in.l2 = h_len;
    in.p3 = &DB[salt_offset];
    in.l3 = salt_len;
    if((rsa_digest(H_prime, &d_len, &in, hash_algo) != NOXTLS_RETURN_SUCCESS) || (d_len != h_len)) {
        return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] step: comparing H, H' (h_len=%u)\n", (uint32_t)h_len);
#endif
    if(noxtls_secret_memcmp(H, H_prime, (size_t)(h_len)) != 0) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: H != H' (hash mismatch)\n");
#endif
        return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] ok\n");
#endif
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sign the message using PSS
 * 
 * @param[in] key The RSA key.
 * @param[in] noxtls_message The message to sign.
 * @param[in] message_len The length of the message.
 * @param[out] signature The signature.
 * @param[in] signature_len The length of the signature.
 * @param[in] hash_algo The hash algorithm.
 * @return The return value.
 */
noxtls_return_t noxtls_rsa_sign_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL) || (signature_len == NULL)) { return NOXTLS_RETURN_NULL; }
    if(rsa_check_private_key(key) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_INVALID_PARAM; }
    if((hash_algo != NOXTLS_HASH_SHA_256) &&
       (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) { return NOXTLS_RETURN_INVALID_ALGORITHM; }
    if(*signature_len < key->key_bytes) { return NOXTLS_RETURN_FAILED; }

    uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t m_hash[64];
    if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }

    /* RFC 8017 8.1.1: emBits = modBits - 1, emLen = ceil(emBits / 8). EM occupies the low emLen
     * octets of the key_bytes-long representative (one leading zero octet when modBits = 8k + 1). */
    uint32_t mod_bits = rsa_modulus_bits(key->n, key->key_bytes);
    if(mod_bits < 2U) { return NOXTLS_RETURN_FAILED; }
    uint32_t em_bits = mod_bits - 1U;
    uint32_t em_len = (em_bits + 7U) / 8U;
    uint32_t em_off = (uint32_t)(key->key_bytes - em_len);

    uint8_t *em = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(em == NULL) { return NOXTLS_RETURN_FAILED; }

    /* RFC 8017: noxtls_message representative m = OS2IP(EM) must be < n (guaranteed by emBits < modBits;
     * the retry is kept as a defensive check). */
    unsigned retries = 0;
    const unsigned max_retries = 16;
    do {
        noxtls_return_t encode_rc = emsa_pss_encode(m_hash, h_len, em_len, em_bits, hash_algo, h_len, &em[em_off]);
        if(encode_rc != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return encode_rc; }
        if(noxtls_bn_cmp(em, key->n, key->key_bytes) < 0) {
            break;
        }
        retries += 1U;
        if(retries >= max_retries) {
            (void)noxtls_free(em);
            return NOXTLS_RETURN_FAILED;
        }
    /* cppcheck-suppress duplicateExpression ; MISRA C:2025 Rule 14.3 infinite-loop idiom */
    } while(1U == 1U);

    /* Sign (blinded CRT when available, fault-checked; NX-15): s = em^d mod n */
    noxtls_return_t rc = rsa_private_op(key, em, signature, 0U);
    (void)noxtls_free(em);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
    *signature_len = key->key_bytes;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify the message using PSS
 * 
 * @param[in] key The RSA key.
 * @param[in] noxtls_message The message to verify.
 * @param[in] message_len The length of the message.
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 * @param[in] hash_algo The hash algorithm.
 * @return The return value.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_verify_pss_core(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo_in)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    /* RSA_INPUT_IS_DIGEST: noxtls_message is mHash itself (noxtls_rsa_verify_pss_digest()). */
    const noxtls_hash_algos_t hash_algo = (noxtls_hash_algos_t)(hash_algo_in & ~RSA_INPUT_IS_DIGEST);
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL)) { return NOXTLS_RETURN_NULL; }
    {
        noxtls_return_t key_rc = rsa_check_public_key(key);
        if(key_rc != NOXTLS_RETURN_SUCCESS) { return key_rc; }
    }
    if(signature_len != key->key_bytes) { return NOXTLS_RETURN_FAILED; }
    if((hash_algo != NOXTLS_HASH_SHA_256) &&
       (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) { return NOXTLS_RETURN_INVALID_ALGORITHM; }

    /* RSAVP1 (RFC 8017 section 5.2.2) step 1: the signature representative must be < n,
     * otherwise s + n would verify as well (signature malleability). */
    if(noxtls_bn_cmp(signature, key->n, key->key_bytes) >= 0) { return NOXTLS_RETURN_FAILED; }

    /* RFC 8017 8.1.2 step 2c: emBits = modBits - 1, emLen = ceil(emBits / 8). */
    uint32_t mod_bits = rsa_modulus_bits(key->n, key->key_bytes);
    if(mod_bits < 2U) { return NOXTLS_RETURN_FAILED; }
    uint32_t em_bits = mod_bits - 1U;
    uint32_t em_len = (em_bits + 7U) / 8U;
    uint32_t em_off = (uint32_t)(key->key_bytes - em_len);

    uint8_t *em = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(em == NULL) { return NOXTLS_RETURN_FAILED; }
    noxtls_return_t rc = noxtls_bn_mod_exp_public(em, signature, key->e, rsa_e_len(key), key->n, key->key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return rc; }

    /* I2OSP(m, emLen) fails ("invalid signature") when m does not fit in emLen octets. */
    for(uint32_t i = 0U; i < em_off; i += 1U) {
        if(em[i] != 0U) { rc = NOXTLS_RETURN_FAILED; }
    }
    if(rc != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return rc; }

    uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t m_hash[64];
    if((hash_algo_in & RSA_INPUT_IS_DIGEST) != 0U) {
        if(message_len != h_len) { (void)noxtls_free(em); return NOXTLS_RETURN_INVALID_PARAM; }
        noxtls_copy_u8(m_hash, sizeof(m_hash), noxtls_message, (size_t)h_len);
    } else if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(em);
        return NOXTLS_RETURN_FAILED;
    } else {
        /* m_hash = Hash(message) */
    }

    rc = emsa_pss_verify(m_hash, h_len, &em[em_off], em_len, em_bits, hash_algo, h_len);
    (void)noxtls_free(em);
    return rc;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_verify_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((hash_algo & RSA_INPUT_IS_DIGEST) != 0U) { return NOXTLS_RETURN_INVALID_ALGORITHM; }
    return rsa_verify_pss_core(key, noxtls_message, message_len, signature, signature_len, hash_algo);
}

/**
 * @brief Verify an RSASSA-PSS signature against a precomputed message digest.
 *
 * Same as noxtls_rsa_verify_pss() with mHash = @p digest (the output length of
 * @p hash_algo; salt length = hash length) instead of Hash(message).
 *
 * @param[in] key The RSA public key.
 * @param[in] digest The message digest.
 * @param[in] digest_len The digest length (32, 48 or 64 for SHA-256/384/512).
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 * @param[in] hash_algo The hash algorithm (SHA-256, SHA-384 or SHA-512).
 * @return NOXTLS_RETURN_SUCCESS when valid; NOXTLS_RETURN_FAILED otherwise.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_verify_pss_digest(const rsa_key_t *key, const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((hash_algo & RSA_INPUT_IS_DIGEST) != 0U) { return NOXTLS_RETURN_INVALID_ALGORITHM; }
    return rsa_verify_pss_core(key, digest, digest_len, signature, signature_len,
                               (noxtls_hash_algos_t)(hash_algo | RSA_INPUT_IS_DIGEST));
}

#endif /* NOXTLS_FEATURE_RSA */
