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
#include "drbg/noxtls_drbg.h"
#include "noxtls_rsa.h"
#include "noxtls_bignum.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"

/* Big number operations are now in NOXTLS_bignum.c */

#define RSA_DRBG_SEED_LEN_BYTES 48U
#define RSA_PKCS1_PAD_RETRY_MAX 16U

/* Generate random number using DRBG */
/**
 * @brief Generate random bytes using DRBG
 * 
 * @param buf Buffer to store the random bytes
 * @param len Length of the buffer
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
static noxtls_return_t rsa_random_bytes(uint8_t *buf, uint32_t len)
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t seed[RSA_DRBG_SEED_LEN_BYTES];
    
    /* Initialize DRBG once and reuse it */
    if(drbg_initialized == 0) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Instantiate DRBG */
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        noxtls_secure_zero(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_drbg_uninstantiate(&drbg_state);
            return NOXTLS_RETURN_FAILED;
        }
        
        drbg_initialized = 1;
    }
    
    /* Generate random bytes using existing DRBG instance */
    rc = drbg_generate(&drbg_state, buf, len * 8U, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Fail closed for this call and drop the instance: a failed generate
         * (AES failure) wipes the state, which drbg_reseed() then rejects, so
         * the next call re-instantiates from fresh entropy instead. */
        (void)noxtls_drbg_uninstantiate(&drbg_state);
        drbg_initialized = 0;
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

/**
 * @brief Test Miller-Rabin with known primes
 * 
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

/**
 * @brief Initialize wheel residues/steps for modulo 2310 (2*3*5*7*11).
 * 
 * @param residues The residues value
 * @param steps The steps value
 * @param count The count value
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_wheel_init(uint16_t *residues, uint16_t *steps, uint32_t *count)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t idx = 0U;
    for(uint32_t r = 1U; r < 2310U; r += 1U) {
        if(((r % 2U) == 0U) || ((r % 3U) == 0U) || ((r % 5U) == 0U) || ((r % 7U) == 0U) || ((r % 11U) == 0U)) {
            continue;
        }
        residues[idx] = (uint16_t)r;
        idx += 1U;
    }
    *count = idx;
    for(uint32_t i = 0U; i < *count; i += 1U) {
        uint32_t curr = (uint32_t)(residues[i]);
        uint32_t next = ((i + 1U) < *count) ? (uint32_t)residues[i + 1U] : ((uint32_t)residues[0U] + 2310U);
        steps[i] = (uint16_t)(next - curr);
    }
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Advance the wheel for prime generation.
 * 
 * @param prime The prime value
 * @param len The length of the prime value
 * @param wheel_residues The wheel residues value
 * @param wheel_steps The wheel steps value
 * @param wheel_count The wheel count value
 * @param wheel_idx The wheel index value
 * @param wheel_rem The wheel remainder value
 * @return The return value
 */
static noxtls_return_t rsa_wheel_advance(uint8_t *prime, uint32_t len,
                                         const uint16_t *wheel_residues, const uint16_t *wheel_steps,
                                         uint32_t wheel_count, uint32_t *wheel_idx, uint32_t *wheel_rem)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(wheel_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    uint32_t step = (uint32_t)(wheel_steps[*wheel_idx]);
    rsa_add_small(prime, len, step);
    *wheel_rem = (*wheel_rem + step) % 2310U;
    *wheel_idx = (*wheel_idx + 1U) % wheel_count;
    /* If we wrapped past the size (MSB cleared), reseed and realign */
    if((prime[0] & 0x80U) == 0U) {
        if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        prime[0] |= 0x80U;
        prime[len - 1U] |= 1U;
        *wheel_rem = rsa_mod_small(prime, len, 2310);
        *wheel_idx = 0U;
        while((*wheel_idx < wheel_count) && (wheel_residues[*wheel_idx] < *wheel_rem)) {
            (*wheel_idx)++;
        }
        if(*wheel_idx >= wheel_count) {
            uint32_t delta = (uint32_t)((2310U - *wheel_rem) + wheel_residues[0U]);
            rsa_add_small(prime, len, delta);
            *wheel_rem = (*wheel_rem + delta) % 2310U;
            *wheel_idx = 0U;
        } else if(wheel_residues[*wheel_idx] != *wheel_rem) {
            uint32_t delta = (uint32_t)wheel_residues[*wheel_idx] - *wheel_rem;
            rsa_add_small(prime, len, delta);
            *wheel_rem = (*wheel_rem + delta) % 2310U;
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }
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
    static int test_run = 0;
    uint32_t attempts = 0U;
    uint32_t prime_bits = (uint32_t)(len * 8U);
    static int wheel_init = 0;
    static uint16_t wheel_residues[480];
    static uint16_t wheel_steps[480];
    static uint32_t wheel_count = 0U;
    uint32_t wheel_idx = 0U;
    uint32_t wheel_rem = 0U;
    /* No quotient needed; just compute modulus for wheel alignment. */
    
    /* Run Miller-Rabin test verification once on first prime generation */
    if(test_run == 0) {
        test_miller_rabin_known_primes();
        test_run = 1;
    }
    
    (void)noxtls_debug_printf((const uint8_t *)"  Starting prime generation (this may take several minutes for large keys)...\n");
    if(wheel_init == 0) {
        rsa_wheel_init(wheel_residues, wheel_steps, &wheel_count);
        wheel_init = 1;
    }
    
    /* Seed candidate and align to wheel residue */
    if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    prime[0] |= 0x80U;  /* Set MSB to ensure correct bit length */
    prime[len - 1U] |= 1U;  /* Make odd */
    wheel_rem = rsa_mod_small(prime, len, 2310);
    wheel_idx = 0U;
    while((wheel_idx < wheel_count) && (wheel_residues[wheel_idx] < wheel_rem)) {
        wheel_idx += 1U;
    }
    if(wheel_idx >= wheel_count) {
        uint32_t delta = (uint32_t)((2310U - wheel_rem) + wheel_residues[0U]);
        rsa_add_small(prime, len, delta);
        wheel_rem = (wheel_rem + delta) % 2310U;
        wheel_idx = 0U;
    } else if(wheel_residues[wheel_idx] != wheel_rem) {
        uint32_t delta = (uint32_t)wheel_residues[wheel_idx] - wheel_rem;
        rsa_add_small(prime, len, delta);
        wheel_rem = (wheel_rem + delta) % 2310U;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }
    
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
            if(rsa_wheel_advance(prime, len, wheel_residues, wheel_steps, wheel_count, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
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
        
        /* Debug: Check if this might be a false negative */
        if(((attempts % 200U) == 0U) && (attempts <= 1000U)) {
            (void)noxtls_debug_printf((const uint8_t *)"  Debug: Candidate rejected (first byte: 0x%02x, last byte: 0x%02x)\n", 
                   prime[0], prime[len - 1U]);
        }
        
#if NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL > 0
        /* Debug: Print first few bytes of rejected candidate */
        if(((attempts % NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL) == 0U) &&
           (attempts <= NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS)) {
            (void)noxtls_debug_printf((const uint8_t *)"  Rejected candidate (first 4 bytes): %02x %02x %02x %02x\n", 
                   prime[0], prime[1], prime[2], prime[3]);
        }
#endif
        /* Advance to next wheel residue for next candidate */
        if(rsa_wheel_advance(prime, len, wheel_residues, wheel_steps, wheel_count, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
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
static noxtls_return_t rsa_hash_run_md5(uint8_t *hash, const uint8_t *msg, uint32_t len)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_md5_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t rsa_hash_run_sha1(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t rsa_hash_run_sha256(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha256_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t rsa_hash_run_sha512(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha512_ctx_t ctx512;
    if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_update(&ctx512, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    {
        uint32_t hash_algo_u = (uint32_t)hash_algo;
        switch (hash_algo_u) {
        case (uint32_t)NOXTLS_HASH_MD5:
            rc = rsa_hash_run_md5(hash, noxtls_message, message_len);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 16U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA1:
            rc = rsa_hash_run_sha1(hash, noxtls_message, message_len, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 20U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_224:
            rc = rsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 28U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_256:
            rc = rsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 32U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_384:
            rc = rsa_hash_run_sha512(hash, noxtls_message, message_len, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 48U;
            break;
        case (uint32_t)NOXTLS_HASH_SHA_512:
            rc = rsa_hash_run_sha512(hash, noxtls_message, message_len, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 64U;
            break;
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
    (void)noxtls_debug_printf((const uint8_t *)"Prime p generated successfully!\n");
    (void)noxtls_debug_printf((const uint8_t *)"Prime p (hex): ");
    uint32_t i = 0U;
    for(i = 0U; i < prime_len; i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02x", key->p[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
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
    (void)noxtls_debug_printf((const uint8_t *)"Prime q (hex): ");
    for(i = 0U; i < prime_len; i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02x", key->q[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
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
    
    if(key->n != NULL) { (void)noxtls_free(key->n); key->n = NULL; }
    if(key->e != NULL) { (void)noxtls_free(key->e); key->e = NULL; }
    if(key->d != NULL) { (void)noxtls_free(key->d); key->d = NULL; }
    if(key->p != NULL) { (void)noxtls_free(key->p); key->p = NULL; }
    if(key->q != NULL) { (void)noxtls_free(key->q); key->q = NULL; }
    if(key->dp != NULL) { (void)noxtls_free(key->dp); key->dp = NULL; }
    if(key->dq != NULL) { (void)noxtls_free(key->dq); key->dq = NULL; }
    if(key->qi != NULL) { (void)noxtls_free(key->qi); key->qi = NULL; }
    
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
    rc = noxtls_bn_mod_exp(ciphertext, padded, key->e, key->key_bytes, key->n, key->key_bytes);
    NOXTLS_SECURE_FREE(padded, key->key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ciphertext, key->key_bytes);
        return rc;
    }

    *ciphertext_len = key->key_bytes;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief CRT-only raw block decryption: m = c^d mod n using p, q, dp, dq, qi.
 * Fills decrypted with key->key_bytes. Caller must strip padding.
 */
static noxtls_return_t do_rsa_crt_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint8_t *decrypted)
{
    uint32_t prime_len = (uint32_t)(key->key_bytes >> 1U);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    (void)noxtls_debug_printf((const uint8_t *)"[CRT] do_rsa_crt_decrypt: start key_bytes=%lu prime_len=%lu\n", (unsigned long)key->key_bytes, (unsigned long)prime_len);
    uint8_t *c_mod_p = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *c_mod_q = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *m1 = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *m2 = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *h = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *p_inv = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *q_minus_2 = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *two_buf = (uint8_t*)NOXTLS_CALLOC(prime_len, 1);
    uint8_t *temp = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    uint8_t *m1_padded = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    uint8_t *sum = (uint8_t*)NOXTLS_CALLOC(key->key_bytes + 1U, 1);
    uint8_t *h_sum = NULL;

    if((c_mod_p == NULL) || (c_mod_q == NULL) || (m1 == NULL) || (m2 == NULL) || (h == NULL) || (p_inv == NULL) || (q_minus_2 == NULL) || (two_buf == NULL) || (temp == NULL) || (m1_padded == NULL) || (sum == NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"[CRT] do_rsa_crt_decrypt: alloc failed\n");
        rc = NOXTLS_RETURN_FAILED;
    } else {
        /* Every bignum step is checked: a failed reduction/exponentiation must never be
         * recombined into a "decrypted" block. */
        /* Reduce c mod p and mod q first; bn_mod_exp uses only first mod_len bytes of base. */
        rc = noxtls_bn_mod(c_mod_p, ciphertext, key->key_bytes, key->p, prime_len);
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(c_mod_q, ciphertext, key->key_bytes, key->q, prime_len); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(m1, c_mod_p, key->dp, prime_len, key->p, prime_len); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(m2, c_mod_q, key->dq, prime_len, key->q, prime_len); }

        /* Symmetric CRT: m = m1 + (h * p) where h = (m2 - m1) * p_inv mod q.
         * Compute p_inv via Fermat (p^(q-2) mod q) to avoid mod_inv issues. */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_copy(q_minus_2, key->q, prime_len); }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            two_buf[prime_len - 1U] = 2;
            rc = noxtls_bn_sub(q_minus_2, q_minus_2, two_buf, prime_len);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(p_inv, key->p, q_minus_2, prime_len, key->q, prime_len); }
        if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(p_inv, prime_len) != 0)) {
            (void)noxtls_debug_printf((const uint8_t *)"[CRT] do_rsa_crt_decrypt: p_inv is zero\n");
            rc = NOXTLS_RETURN_FAILED;
        }
        /* h = m1 mod q (m1 can be >= q) */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(h, m1, prime_len, key->q, prime_len); }
        /* h = (m2 - h) mod q */
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(noxtls_bn_cmp(m2, h, prime_len) >= 0) {
                rc = noxtls_bn_sub(temp, m2, h, prime_len);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    noxtls_copy_u8(h, (size_t)(prime_len), temp, (size_t)(prime_len));
                }
            } else {
                h_sum = (uint8_t*)NOXTLS_CALLOC(prime_len + 1U, 1);
                if(h_sum == NULL) {
                    (void)noxtls_debug_printf((const uint8_t *)"[CRT] do_rsa_crt_decrypt: h_sum alloc failed\n");
                    rc = NOXTLS_RETURN_FAILED;
                } else {
                    rc = noxtls_bn_sub(&h_sum[1], key->q, h, prime_len);
                }
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    uint16_t carry = 0U;
                    for(uint32_t i = prime_len; i > 0U; i -= 1U) {
                        uint16_t s = (uint16_t)((uint16_t)h_sum[i] + (uint16_t)m2[i - 1U] + carry);
                        h_sum[i] = (uint8_t)(s & 0xFFU);
                        {
                            uint32_t next_carry = (uint32_t)s;
                            next_carry >>= 8U;
                            carry = (uint16_t)next_carry;
                        }
                    }
                    h_sum[0] = (uint8_t)carry;
                }
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *h_ptr = &h_sum[1];
                    uint32_t h_len = (uint32_t)(prime_len);
                    if(h_sum[0] != 0U) {
                        h_ptr = h_sum;
                        h_len = prime_len + 1U;
                    }
                    rc = noxtls_bn_mod(h, h_ptr, h_len, key->q, prime_len);
                }
                NOXTLS_SECURE_FREE(h_sum, (size_t)prime_len + 1U);
            }
        }
        /* h = h * p_inv mod q */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mul(temp, h, prime_len, p_inv, prime_len); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(h, temp, prime_len * 2U, key->q, prime_len); }
        /* m = m1 + (h * p): m1_padded has m1 in low prime_len bytes; temp = h*p */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mul(temp, h, prime_len, key->p, prime_len); }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(&m1_padded[key->key_bytes - prime_len], (size_t)(prime_len), m1, (size_t)(prime_len));  /* m1 in low half */
            {
                uint16_t carry = 0U;
                for(uint32_t i = (uint32_t)(key->key_bytes); i > 0U; i -= 1U) {
                    uint16_t s = (uint16_t)((uint16_t)m1_padded[i - 1U] + (uint16_t)temp[i - 1U] + carry);
                    sum[i] = (uint8_t)(s & 0xFFU);
                    {
                        uint32_t next_carry = (uint32_t)s;
                        next_carry >>= 8U;
                        carry = (uint16_t)next_carry;
                    }
                }
                sum[0] = (uint8_t)carry;
            }
            if(sum[0] != 0U) {
                rc = noxtls_bn_mod(decrypted, sum, key->key_bytes + 1U, key->n, key->key_bytes);
            } else {
                rc = noxtls_bn_mod(decrypted, &sum[1], key->key_bytes, key->n, key->key_bytes);
            }
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(decrypted, key->key_bytes);
        }
    }

    /* All intermediates are derived from the private key or the plaintext: wipe them. */
    NOXTLS_SECURE_FREE(c_mod_p, prime_len);
    NOXTLS_SECURE_FREE(c_mod_q, prime_len);
    NOXTLS_SECURE_FREE(m1, prime_len);
    NOXTLS_SECURE_FREE(m2, prime_len);
    NOXTLS_SECURE_FREE(h, prime_len);
    NOXTLS_SECURE_FREE(p_inv, prime_len);
    NOXTLS_SECURE_FREE(temp, key->key_bytes);
    NOXTLS_SECURE_FREE(m1_padded, key->key_bytes);
    NOXTLS_SECURE_FREE(sum, (size_t)key->key_bytes + 1U);
    NOXTLS_SECURE_FREE(q_minus_2, prime_len);
    NOXTLS_SECURE_FREE(two_buf, prime_len);
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief Blinded RSA private-key operation: output = input^d mod n (NX-15).
 *
 * Masks the input with a fresh random factor before exponentiating so any residual
 * data-dependent timing in the bignum primitives cannot be correlated with the
 * attacker-chosen ciphertext/message (Bleichenbacher / Marvin timing hardening):
 *   x = input * r^e mod n;  y = x^d mod n;  output = y * r^(-1) mod n.
 *
 * Fails closed: if no usable blinding factor can be produced (RNG failure or repeated
 * inversion failure), the private-key operation is NOT performed unblinded.
 *
 * @param[in]  key    RSA key with n, e and d populated; key_bytes sized buffers.
 * @param[in]  input  Input block, key->key_bytes long, numerically less than n.
 * @param[out] output Result block, key->key_bytes long.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, error code otherwise.
 */
static noxtls_return_t rsa_private_mod_exp_blinded(const rsa_key_t *key, const uint8_t *input, uint8_t *output)
{
    const uint32_t len = (uint32_t)(key->key_bytes);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t attempt = 0U;
    uint8_t *r     = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *r_inv = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *blind = (uint8_t*)NOXTLS_CALLOC(len, 1);
    uint8_t *wide  = (uint8_t*)NOXTLS_CALLOC((size_t)len * 2U, 1);

    if((r == NULL) || (r_inv == NULL) || (blind == NULL) || (wide == NULL)) {
        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        NOXTLS_SECURE_FREE(r, len);
        NOXTLS_SECURE_FREE(r_inv, len);
        NOXTLS_SECURE_FREE(blind, len);
        NOXTLS_SECURE_FREE(wide, (size_t)len * 2U);
        return rc;
    }

    for(attempt = 0U; attempt < 8U; attempt += 1U) {
        /* Fresh random blinding factor r in [1, n - 1U] with gcd(r, n) == 1. */
        if(rsa_random_bytes(wide, len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED; /* never proceed with weak/no randomness */
            NOXTLS_SECURE_FREE(r, len);
            NOXTLS_SECURE_FREE(r_inv, len);
            NOXTLS_SECURE_FREE(blind, len);
            NOXTLS_SECURE_FREE(wide, (size_t)len * 2U);
            return rc;
        }
        /* Only a zero r or a non-invertible r (gcd(r, n) != 1) is retried with a fresh
         * factor; any other bignum error (e.g. NOT_ENOUGH_MEMORY) aborts immediately. */
        rc = noxtls_bn_mod(r, wide, len, key->n, len);
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        if(noxtls_bn_is_zero(r, len) != 0) { rc = NOXTLS_RETURN_FAILED; continue; }
        /* r_inv = r^-1 mod n; fails when gcd(r, n) != 1 (negligible probability) */
        rc = noxtls_bn_mod_inv(r_inv, r, len, key->n, len);
        if(rc == NOXTLS_RETURN_FAILED) { continue; }
        if(rc != NOXTLS_RETURN_SUCCESS) { break; }
        if(noxtls_bn_is_zero(r_inv, len) != 0) { rc = NOXTLS_RETURN_FAILED; continue; }

        /* blind = r^e mod n */
        rc = noxtls_bn_mod_exp(blind, r, key->e, len, key->n, len);
        /* blind = input * r^e mod n */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mul(wide, input, len, blind, len); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(blind, wide, len * 2U, key->n, len); }
        /* blind = (input * r^e)^d mod n = input^d * r mod n */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod_exp(blind, blind, key->d, len, key->n, len); }
        /* output = blind * r^-1 mod n = input^d mod n */
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mul(wide, blind, len, r_inv, len); }
        if(rc == NOXTLS_RETURN_SUCCESS) { rc = noxtls_bn_mod(output, wide, len * 2U, key->n, len); }
        break;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, (size_t)len);
    }

    NOXTLS_SECURE_FREE(r, len);
    NOXTLS_SECURE_FREE(r_inv, len);
    NOXTLS_SECURE_FREE(blind, len);
    NOXTLS_SECURE_FREE(wide, (size_t)len * 2U);
    return rc;
}

/**
 * @brief RSA Decryption
 */
noxtls_return_t noxtls_rsa_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    if((key == NULL) || (ciphertext == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    uint8_t *decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Blinded decryption: m = c^d mod n (NX-15). */
    if(rsa_private_mod_exp_blinded(key, ciphertext, decrypted) != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(decrypted, key->key_bytes);
        return NOXTLS_RETURN_FAILED;
    }

    /*
     * SECURITY (NX-03): constant-time PKCS#1 v1.5 type-2 unpad (RFC 8017).
     * The whole block is scanned without secret-dependent branches; padding
     * validity and the separator position are computed as masks so that the
     * time taken does not reveal WHERE the padding check failed
     * (Bleichenbacher oracle hardening).
     */
    {
        const uint32_t kb = (uint32_t)(key->key_bytes);
        uint32_t good;       /* 0xFFFFFFFFU when padding is valid, 0 otherwise */
        uint32_t found_sep;  /* all-ones once the 0x00U separator has been seen */
        uint32_t sep_index;  /* index of the separator byte */
        uint32_t data_len = 0U;
        uint32_t i = 0U;

        if(kb < 11U) {
            NOXTLS_SECURE_FREE(decrypted, kb);
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
            NOXTLS_SECURE_FREE(decrypted, kb);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(plaintext, (size_t)(data_len), &decrypted[sep_index + 1U], (size_t)(data_len));
        *plaintext_len = data_len;
        NOXTLS_SECURE_FREE(decrypted, kb);
        return NOXTLS_RETURN_SUCCESS;
    }
}

/**
 * @brief RSA decrypt using CRT path only (for unit testing).
 */
noxtls_return_t noxtls_rsa_decrypt_crt_only(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    if((key == NULL) || (ciphertext == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    if((key->p == NULL) || (key->q == NULL) || (key->dp == NULL) || (key->dq == NULL) || (key->qi == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t *decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(do_rsa_crt_decrypt(key, ciphertext, decrypted) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"[CRT] do_rsa_crt_decrypt returned FAILED\n");
        (void)noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }

    /* Debug: dump first bytes of CRT decrypted block */
    (void)noxtls_debug_printf((const uint8_t *)"[CRT] decrypted block (first 32 bytes): ");
    for(uint32_t k = 0U; (k < 32U) && (k < key->key_bytes); k += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02X ", decrypted[k]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Remove PKCS#1 v1.5 padding (strict RFC 8017 structure for type 2). */
    if((key->key_bytes >= 11U) && (decrypted[0] == 0x00U) && (decrypted[1] == 0x02U)) {
        uint32_t j = 2U;
        while((j < key->key_bytes) && (decrypted[j] != 0x00U)) {
            j += 1U;
        }
        if((j >= 10U) && (j < key->key_bytes)) {
            uint32_t data_len = (uint32_t)(key->key_bytes - j - 1U);
            if(data_len <= *plaintext_len) {
                noxtls_copy_u8(plaintext, (size_t)(data_len), &decrypted[j + 1U], (size_t)(data_len));
                *plaintext_len = data_len;
                (void)noxtls_free(decrypted);
                return NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    (void)noxtls_debug_printf((const uint8_t *)"[CRT] padding strip failed - no 0x00 0x02 ... 0x00 pattern; full block (hex): ");
    for(uint32_t k = 0U; k < key->key_bytes; k += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02X", decrypted[k]);
        if(((k + 1U) & 31U) == 0U) { (void)noxtls_debug_printf((const uint8_t *)"\n  "); }
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
    (void)noxtls_free(decrypted);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief RSA Signature Generation
 */
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(*signature_len < key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Hash the noxtls_message */
    uint8_t hash[64];
    uint32_t hash_len = 0U;
    noxtls_return_t rc = rsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Apply PKCS#1 v1.5 signature padding */
    uint8_t *padded = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(padded == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = rsa_pkcs1_v15_encode_digest(padded, key->key_bytes, hash, hash_len, hash_algo, 0U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(padded, key->key_bytes);
        (void)noxtls_free(padded);
        return rc;
    }
    
    /* Sign (blinded, NX-15): s = hash^d mod n */
    rc = rsa_private_mod_exp_blinded(key, padded, signature);
    (void)noxtls_free(padded);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    *signature_len = key->key_bytes;
    
    return NOXTLS_RETURN_SUCCESS;
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
    
    if(signature_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* RSAVP1 (RFC 8017 section 5.2.2): the signature representative must be < n. */
    if(noxtls_bn_cmp(signature, key->n, key->key_bytes) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify: EM = signature^e mod n */
    uint8_t *decrypted = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(decrypted == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *expected = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(expected == NULL) {
        (void)noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_return_t rc = noxtls_bn_mod_exp(decrypted, signature, key->e, key->key_bytes, key->n, key->key_bytes);

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

    noxtls_secure_zero(decrypted, key->key_bytes);
    noxtls_secure_zero(expected, key->key_bytes);
    (void)noxtls_free(decrypted);
    (void)noxtls_free(expected);
    /* Hash selection errors (NOT_SUPPORTED, INVALID_ALGORITHM) propagate; any
     * encoding mismatch has already been mapped to NOXTLS_RETURN_FAILED. */
    return rc;
}

/* --- RSA-PSS (RFC 8017) --- */

/** Hash for PSS: SHA-256, SHA-384, or SHA-512 (for TLS 1.3). */
static noxtls_return_t pss_hash_message(noxtls_hash_algos_t hash_algo, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *hash, uint32_t *hash_len)
{
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha256_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        *hash_len = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t ctx;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha512_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        *hash_len = 48U;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t ctx;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha512_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        *hash_len = 64U;
        return NOXTLS_RETURN_SUCCESS;
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

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

/** MGF1 (RFC 8017): mask = MGF1(seed, seed_len, mask_len). */
static noxtls_return_t mgf1(noxtls_hash_algos_t hash_algo, const uint8_t *seed, uint32_t seed_len, uint8_t *mask, uint32_t mask_len)
{
    uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t counter[4];
    uint32_t offset = 0U;
    uint8_t T_buf[64];
    uint8_t *input = NULL;

    if((seed == NULL) || ((mask == NULL) && (mask_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    if(h_len == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(seed_len > (uint32_t)(UINT32_MAX - 4U)) {
        return NOXTLS_RETURN_FAILED;
    }

    input = (uint8_t*)NOXTLS_CALLOC(seed_len + 4U, 1);
    if(input == NULL) { return NOXTLS_RETURN_FAILED; }
    noxtls_copy_u8(input, (size_t)seed_len, seed, (size_t)seed_len);

    while(offset < mask_len) {
        counter[0] = (uint8_t)((offset / h_len) >> 24U);
        counter[1] = (uint8_t)((offset / h_len) >> 16U);
        counter[2] = (uint8_t)((offset / h_len) >> 8U);
        counter[3] = (uint8_t)(offset / h_len);
        noxtls_copy_u8(&input[seed_len], 4U, counter, 4U);
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t ctx;
            (void)noxtls_sha256_init(&ctx, hash_algo);
            (void)noxtls_sha256_update(&ctx, input, seed_len + 4U);
            (void)noxtls_sha256_finish(&ctx, T_buf);
        } else {
            noxtls_sha512_ctx_t ctx;
            (void)noxtls_sha512_init(&ctx, hash_algo);
            (void)noxtls_sha512_update(&ctx, input, seed_len + 4U);
            (void)noxtls_sha512_finish(&ctx, T_buf);
        }
        uint32_t copy = (uint32_t)(mask_len - offset);
        if(copy > h_len) { copy = h_len; }
        noxtls_copy_u8(&mask[offset], (size_t)copy, T_buf, (size_t)copy);
        offset += copy;
    }
    (void)noxtls_free(input);
    return NOXTLS_RETURN_SUCCESS;
}

/** EMSA-PSS-ENCODE (RFC 8017). salt_len must equal h_len. */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t emsa_pss_encode(const uint8_t *m_hash, uint32_t h_len,
    uint32_t em_len, noxtls_hash_algos_t hash_algo, uint32_t salt_len,
    uint8_t *em)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((m_hash == NULL) || (em == NULL)) { return NOXTLS_RETURN_NULL; }
    if((h_len > 64U) || (salt_len > 64U)) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(h_len > (uint32_t)(UINT32_MAX - salt_len - 8U)) { return NOXTLS_RETURN_FAILED; }
    if(em_len < (h_len + salt_len + 2U)) { return NOXTLS_RETURN_FAILED; }
    uint32_t ps_len = (uint32_t)(em_len - salt_len - h_len - 2U);
    uint32_t db_len = (uint32_t)(em_len - h_len - 1U);

    uint8_t *salt = (uint8_t*)NOXTLS_CALLOC(salt_len, 1);
    if(salt == NULL) { return NOXTLS_RETURN_FAILED; }
    if(rsa_random_bytes(salt, salt_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(salt);
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t m_prime[8U +64U +64U];
    noxtls_secure_zero((m_prime), (size_t)(8));
    noxtls_copy_u8(&m_prime[8], sizeof(m_prime) - (size_t)(8), m_hash, (size_t)(h_len));
    noxtls_copy_u8(&m_prime[8U + h_len], sizeof(m_prime) - (size_t)(8U + h_len), salt, (size_t)(salt_len));
    uint32_t m_prime_len = (uint32_t)(8U + h_len + salt_len);

    uint8_t H[64];
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        (void)noxtls_sha256_init(&ctx, hash_algo);
        (void)noxtls_sha256_update(&ctx, m_prime, m_prime_len);
        (void)noxtls_sha256_finish(&ctx, H);
    } else {
        noxtls_sha512_ctx_t ctx;
        (void)noxtls_sha512_init(&ctx, hash_algo);
        (void)noxtls_sha512_update(&ctx, m_prime, m_prime_len);
        (void)noxtls_sha512_finish(&ctx, H);
    }
    noxtls_secure_zero((em), (size_t)(ps_len));
    em[ps_len] = 0x01U;
    noxtls_copy_u8(&em[ps_len + 1U], (size_t)salt_len, salt, (size_t)salt_len);
    (void)noxtls_free(salt);

    uint8_t *db_mask = (uint8_t*)NOXTLS_CALLOC(db_len, 1);
    if(db_mask == NULL) { return NOXTLS_RETURN_FAILED; }
    (void)mgf1(hash_algo, H, h_len, db_mask, db_len);
    for(uint32_t i = 0U; i < db_len; i += 1U) { em[i] ^= db_mask[i]; }
    (void)noxtls_free(db_mask);

    em[0] &= 0x7FU;
    noxtls_copy_u8(&em[db_len], (size_t)h_len, H, (size_t)h_len);
    em[em_len - 1U] = 0xbcU;
    return NOXTLS_RETURN_SUCCESS;
}

/* Set to 1 to trace PSS verify failures to stderr (e.g. for unit tests). */
#ifndef NOXTLS_DEBUG_PSS_VERIFY
#define NOXTLS_DEBUG_PSS_VERIFY 0
#endif

/** EMSA-PSS-VERIFY (RFC 8017). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t emsa_pss_verify(const uint8_t *m_hash, uint32_t h_len,
    const uint8_t *em, uint32_t em_len, noxtls_hash_algos_t hash_algo, uint32_t salt_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((m_hash == NULL) || (em == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((h_len > 64U) || (salt_len > 64U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
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

    const uint8_t *masked_db = em;
    const uint8_t *H = &em[db_len];

    uint8_t *db_mask = (uint8_t*)NOXTLS_CALLOC(db_len, 1);
    if(db_mask == NULL) { return NOXTLS_RETURN_FAILED; }
    (void)mgf1(hash_algo, H, h_len, db_mask, db_len);
    uint8_t *DB = (uint8_t*)NOXTLS_CALLOC(db_len, 1);
    if(DB == NULL) { (void)noxtls_free(db_mask); return NOXTLS_RETURN_FAILED; }
    for(uint32_t db_i = 0U; db_i < db_len; db_i += 1U) { DB[db_i] = masked_db[db_i] ^ db_mask[db_i]; }
    (void)noxtls_free(db_mask);

    /* Encoding set the leftmost bit of the first octet of maskedDB to zero (em[0] &= 0x7F); match that when verifying. */
    DB[0] &= 0x7FU;

    if((DB[0] & 0x80U) != 0U) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: DB[0] has high bit set (0x%02x)\n", (uint32_t)DB[0]);
#endif
        (void)noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] step: DB[0] high bit ok (0x%02x)\n", (uint32_t)DB[0]);
#endif

    /* Padding: ps_len_val zeros, then 0x01 (at index ps_len_val). */
    uint32_t i = 0U;
    for(i = 0U; (i < ps_len_val) && (DB[i] == 0U); i += 1U) { }
    if((i != ps_len_val) || (i >= db_len) || (DB[i] != 0x01U)) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: padding: i=%u ps_len_val=%u db_len=%u DB[i]=0x%02x (expect 0x01 at i==ps_len_val)\n",
            (uint32_t)i, (uint32_t)ps_len_val, (uint32_t)db_len, (uint32_t)(i < db_len ? DB[i] : 0));
#endif
        (void)noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }
    uint32_t salt_offset = (uint32_t)(i + 1U);
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] step: padding ok i=%u salt_offset=%u\n", (uint32_t)i, (uint32_t)salt_offset);
#endif
    if((salt_offset > db_len) || (salt_len > (db_len - salt_offset))) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)noxtls_debug_printf((const uint8_t *)"[PSS_VERIFY] fail: salt_offset+salt_len > db_len\n");
#endif
        (void)noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }

    uint8_t m_prime[8U +64U +64U];
    noxtls_secure_zero((m_prime), (size_t)(8));
    noxtls_copy_u8(&m_prime[8], sizeof(m_prime) - (size_t)(8), m_hash, (size_t)(h_len));
    noxtls_copy_u8(&m_prime[8U + h_len], sizeof(m_prime) - (size_t)(8U + h_len), &DB[salt_offset], (size_t)(salt_len));
    (void)noxtls_free(DB);
    uint32_t m_prime_len = (uint32_t)(8U + h_len + salt_len);

    uint8_t H_prime[64];
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        (void)noxtls_sha256_init(&ctx, hash_algo);
        (void)noxtls_sha256_update(&ctx, m_prime, m_prime_len);
        (void)noxtls_sha256_finish(&ctx, H_prime);
    } else {
        noxtls_sha512_ctx_t ctx;
        (void)noxtls_sha512_init(&ctx, hash_algo);
        (void)noxtls_sha512_update(&ctx, m_prime, m_prime_len);
        (void)noxtls_sha512_finish(&ctx, H_prime);
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
    if((hash_algo != NOXTLS_HASH_SHA_256) &&
       (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) { return NOXTLS_RETURN_INVALID_ALGORITHM; }
    if(*signature_len < key->key_bytes) { return NOXTLS_RETURN_FAILED; }

    uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t m_hash[64];
    if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }

    uint8_t *em = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(em == NULL) { return NOXTLS_RETURN_FAILED; }

    /* RFC 8017: noxtls_message representative m = OS2IP(EM) must be < n; otherwise retry with new salt. */
    unsigned retries = 0;
    const unsigned max_retries = 16;
    do {
        noxtls_return_t encode_rc = emsa_pss_encode(m_hash, h_len, key->key_bytes, hash_algo, h_len, em);
        if(encode_rc != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return encode_rc; }
        if(noxtls_bn_cmp(em, key->n, key->key_bytes) < 0) {
            break;
        }
        retries += 1U;
        if(retries >= max_retries) {
            (void)noxtls_free(em);
            return NOXTLS_RETURN_FAILED;
        }
    } while(1U == 1U);

    /* Sign (blinded, NX-15): s = em^d mod n */
    noxtls_return_t rc = rsa_private_mod_exp_blinded(key, em, signature);
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
noxtls_return_t noxtls_rsa_verify_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((key == NULL) || (noxtls_message == NULL) || (signature == NULL)) { return NOXTLS_RETURN_NULL; }
    if(signature_len != key->key_bytes) { return NOXTLS_RETURN_FAILED; }
    if((hash_algo != NOXTLS_HASH_SHA_256) &&
       (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) { return NOXTLS_RETURN_INVALID_ALGORITHM; }

    uint8_t *em = (uint8_t*)NOXTLS_CALLOC(key->key_bytes, 1);
    if(em == NULL) { return NOXTLS_RETURN_FAILED; }
    noxtls_return_t rc = noxtls_bn_mod_exp(em, signature, key->e, key->key_bytes, key->n, key->key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return rc; }

    uint32_t h_len = (uint32_t)(rsa_pss_digest_len(hash_algo));
    uint8_t m_hash[64];
    if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) { (void)noxtls_free(em); return NOXTLS_RETURN_FAILED; }

    rc = emsa_pss_verify(m_hash, h_len, em, key->key_bytes, hash_algo, h_len);
    (void)noxtls_free(em);
    return rc;
}
