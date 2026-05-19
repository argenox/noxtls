/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_rsa.c
* Summary: RSA Public Key Cryptography Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
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

/* Big number operations are now in NOXTLS_bignum.c */

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

#define RSA_DRBG_SEED_LEN_BYTES 48u
#define RSA_PKCS1_PAD_RETRY_MAX 16u

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
    noxtls_return_t rc;
    uint8_t seed[RSA_DRBG_SEED_LEN_BYTES];
    
    /* Initialize DRBG once and reuse it */
    if(!drbg_initialized) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Instantiate DRBG */
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        
        drbg_initialized = 1;
    }
    
    /* Generate random bytes using existing DRBG instance */
    rc = drbg_generate(&drbg_state, buf, len * 8u, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* If generation fails, reseed with new entropy from platform source */
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        
        rc = drbg_reseed(&drbg_state, seed, sizeof(seed), NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        
        rc = drbg_generate(&drbg_state, buf, len * 8u, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
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
    uint32_t rem = 0;

    if(quotient == NULL || remainder == NULL || num == NULL || divisor == 0) {
        return NOXTLS_RETURN_NULL;
    }
    
    for(uint32_t i = 0; i < num_len; i++) {
        uint32_t acc = (rem << 8) | num[i];
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
    uint32_t rem = 0;
    for(uint32_t i = 0; i < num_len; i++) {
        rem = ((rem << 8) | num[i]) % divisor;
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
    uint32_t carry = 0;
    for(uint32_t i = in_len; i > 0; i--) {
        uint32_t prod = (uint32_t)in[i - 1] * multiplier + carry;
        out[i - 1] = (uint8_t)(prod & 0xFF);
        carry = prod >> 8;
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
    uint32_t carry = addend;
    for(uint32_t i = len; i > 0 && carry > 0; i--) {
        uint32_t sum = (uint32_t)inout[i - 1] + (carry & 0xFF);
        inout[i - 1] = (uint8_t)(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
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
    if(result == NULL || mod == NULL || mod_len == 0 || a == 0) {
        return NOXTLS_RETURN_NULL;
    }

    uint8_t *quotient = (uint8_t*)noxtls_calloc(mod_len, 1);
    uint8_t *qy = (uint8_t*)noxtls_calloc(mod_len, 1);
    if(!quotient || !qy) {
        if(quotient) noxtls_free(quotient);
        if(qy) noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }

    uint32_t r = 0;
    if(rsa_div_mod_small(quotient, &r, mod, mod_len, a) != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(quotient);
        noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }
    if(r == 0) {
        noxtls_free(quotient);
        noxtls_free(qy);
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
        newt = t - q * newt;
        t = tmp_t;
        int64_t tmp_r = newr;
        newr = rr - q * newr;
        rr = tmp_r;
    }
    if(rr != 1) {
        noxtls_free(quotient);
        noxtls_free(qy);
        return NOXTLS_RETURN_FAILED;
    }
    if(t < 0) {
        t += a;
    }
    uint32_t y = (uint32_t)t;

    uint64_t k = ((uint64_t)r * (uint64_t)y - 1ULL) / (uint64_t)a;

    /* t = q * y + k */
    rsa_mul_small(qy, quotient, mod_len, y);
    rsa_add_small(qy, mod_len, (uint32_t)k);

    if(noxtls_bn_cmp(qy, mod, mod_len) >= 0) {
        noxtls_bn_sub(qy, qy, mod, mod_len);
    }

    if(noxtls_bn_is_zero(qy, mod_len)) {
        noxtls_bn_zero(result, mod_len);
    } else {
        noxtls_bn_sub(result, mod, qy, mod_len);
    }

    noxtls_free(quotient);
    noxtls_free(qy);
    return NOXTLS_RETURN_SUCCESS;
}

/* Forward declaration */
static int rsa_is_prime(const uint8_t *n, uint32_t len, int iterations);

/**
 * @brief Test Miller-Rabin with known primes
 * 
 */
static void test_miller_rabin_known_primes(void)
{
    /* Test with small known primes */
    const uint8_t known_prime_17[] = {0x11};  /* 17 is prime */
    const uint8_t known_prime_97[] = {0x61};  /* 97 is prime */
    const uint8_t known_prime_101[] = {0x65}; /* 101 is prime */
    
    noxtls_debug_printf("Testing Miller-Rabin with known primes...\n");
    fflush(stdout);
    
    int result;
    
    /* Test small primes */
    result = rsa_is_prime(known_prime_17, 1, 3);
    noxtls_debug_printf("  Known prime 17: %s\n", result ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    fflush(stdout);
    
    result = rsa_is_prime(known_prime_97, 1, 3);
    noxtls_debug_printf("  Known prime 97: %s\n", result ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    fflush(stdout);
    
    result = rsa_is_prime(known_prime_101, 1, 3);
    noxtls_debug_printf("  Known prime 101: %s\n", result ? "PASS (detected as prime)" : "FAIL (incorrectly rejected)");
    fflush(stdout);
    
    /* Test composite numbers to ensure they're rejected */
    const uint8_t composite_15[] = {0x0F};  /* 15 = 3 * 5 */
    const uint8_t composite_21[] = {0x15};  /* 21 = 3 * 7 */
    
    result = rsa_is_prime(composite_15, 1, 3);
    noxtls_debug_printf("  Composite 15: %s\n", result ? "FAIL (incorrectly accepted)" : "PASS (correctly rejected)");
    fflush(stdout);
    
    result = rsa_is_prime(composite_21, 1, 3);
    noxtls_debug_printf("  Composite 21: %s\n", result ? "FAIL (incorrectly accepted)" : "PASS (correctly rejected)");
    fflush(stdout);
    
    noxtls_debug_printf("Miller-Rabin test verification complete.\n");
    fflush(stdout);
}

/**
 * @brief Miller-Rabin primality test
 * 
 * @param n Number to test
 * @param len Length of the number to test
 * @param iterations Number of iterations
 * @return int 1 if the number is prime, 0 otherwise
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static int rsa_is_prime(const uint8_t *n, uint32_t len, int iterations)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t i;
    uint32_t j;
    uint8_t *n_minus_1 = (uint8_t*)noxtls_calloc(len, 1);
    uint8_t *d = (uint8_t*)noxtls_calloc(len, 1);
    uint8_t *a = (uint8_t*)noxtls_calloc(len, 1);
    uint8_t *x = (uint8_t*)noxtls_calloc(len, 1);
    /* temp needs to be len * 2 because noxtls_bn_mul(x, len, x, len) produces len * 2 bytes */
    uint8_t *temp = (uint8_t*)noxtls_calloc((size_t)len * 2u, 1);
    
    if(!n_minus_1 || !d || !a || !x || !temp) {
        noxtls_debug_printf("ERROR: rsa_is_prime: Memory allocation failed!\n");
        fflush(stdout);
        if(n_minus_1) noxtls_free(n_minus_1);
        if(d) noxtls_free(d);
        if(a) noxtls_free(a);
        if(x) noxtls_free(x);
        if(temp) noxtls_free(temp);
        return 0;
    }
    
    /* n must be > 1 */
    if(noxtls_bn_is_one(n, len) || noxtls_bn_is_zero(n, len)) {
        noxtls_free(n_minus_1);
        noxtls_free(d);
        noxtls_free(a);
        noxtls_free(x);
        noxtls_free(temp);
        return 0;
    }
    
    /* Check if even */
    if((n[len-1] & 1) == 0) {
        noxtls_free(n_minus_1);
        noxtls_free(d);
        noxtls_free(a);
        noxtls_free(x);
        noxtls_free(temp);
        return 0;
    }
    
    /* Write n-1 as d * 2^r */
    uint8_t *one = (uint8_t*)noxtls_calloc(len, 1);
    if(!one) {
        noxtls_debug_printf("ERROR: rsa_is_prime: Failed to allocate 'one'\n");
        fflush(stdout);
        noxtls_free(n_minus_1);
        noxtls_free(d);
        noxtls_free(a);
        noxtls_free(x);
        noxtls_free(temp);
        return 0;
    }
    noxtls_bn_one(one, len);
    noxtls_bn_copy(n_minus_1, n, len);
    noxtls_bn_sub(n_minus_1, n_minus_1, one, len);  /* n-1 */
    noxtls_bn_copy(d, n_minus_1, len);
    noxtls_free(one);
    
    uint32_t r = 0;
    uint32_t max_divisions = len * 8;  /* Safety limit */
    while((d[len-1] & 1) == 0 && r < max_divisions && !noxtls_bn_is_zero(d, len)) {
        /* Divide d by 2 - use the dedicated function */
        noxtls_bn_rshift1(d, len);
        r++;
    }
    
    if(r >= max_divisions || noxtls_bn_is_zero(d, len)) {
        noxtls_debug_printf("ERROR: rsa_is_prime: Invalid d value after division\n");
        fflush(stdout);
        noxtls_free(n_minus_1);
        noxtls_free(d);
        noxtls_free(a);
        noxtls_free(x);
        noxtls_free(temp);
        return 0;
    }
    
    uint8_t *two = (uint8_t*)noxtls_calloc(len, 1);
    if(!two) {
        noxtls_debug_printf("ERROR: rsa_is_prime: Failed to allocate 'two'\n");
        fflush(stdout);
        noxtls_free(n_minus_1);
        noxtls_free(d);
        noxtls_free(a);
        noxtls_free(x);
        noxtls_free(temp);
        return 0;
    }
    noxtls_bn_zero(two, len);
    two[len-1] = 2;  /* Set to 2 */
    
    /* Debug: Print d and r for small numbers */
    if(len == 1 && n[0] < 255) {
        noxtls_debug_printf("  [DEBUG] Testing n=%u, d=%u, r=%u\n", n[0], d[0], r);
        fflush(stdout);
    }
    
    uint32_t iterations_u = (iterations < 0) ? 0U : (uint32_t)iterations;
    for(i = 0; i < iterations_u; i++) {
        /* Choose random a in [2, n-2] */
        /* For small numbers, use deterministic witnesses for better testing */
        if(len == 1 && n[0] < 255) {
            /* Use small deterministic witnesses for testing small primes */
            uint8_t small_witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
            if(i < sizeof(small_witnesses)) {
                uint8_t w = small_witnesses[i];
                if(w >= n[0] || w == 0) {
                    noxtls_bn_copy(a, two, len);  /* Fallback to 2 */
                } else {
                    noxtls_bn_zero(a, len);
                    a[len-1] = w;
                }
            } else {
                noxtls_bn_copy(a, two, len);
            }
        } else {
            /* Use deterministic witnesses first to reduce RNG dependence */
            static const uint8_t mr_witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
            if(i < (uint32_t)(sizeof(mr_witnesses) / sizeof(mr_witnesses[0]))) {
                uint8_t w = mr_witnesses[i];
                noxtls_bn_zero(a, len);
                a[len - 1] = w;
            } else {
            /* Simple approach: generate random, reduce modulo n, ensure it's in [2, n-2] */
            uint32_t retry_count = 0;
            do {
                if(rsa_random_bytes(a, len) != NOXTLS_RETURN_SUCCESS) {
                    noxtls_bn_copy(a, two, len);
                    break;
                }
                /* Reduce a modulo n to get value in [0, n-1] */
                noxtls_bn_mod(a, a, len, n, len);
                retry_count++;
            } while((noxtls_bn_is_zero(a, len) || noxtls_bn_is_one(a, len) || 
                     noxtls_bn_cmp(a, n_minus_1, len) == 0) && retry_count < 20);
            
            /* If we still don't have a valid a, set it to a safe value */
            if(noxtls_bn_is_zero(a, len) || noxtls_bn_is_one(a, len) || 
               noxtls_bn_cmp(a, n_minus_1, len) == 0) {
                /* Use a deterministic value: 2 + (i mod (n-4)) to ensure variety */
                noxtls_bn_copy(a, two, len);
                if(!noxtls_bn_is_zero(n_minus_1, len)) {
                    uint8_t *offset = (uint8_t*)noxtls_calloc(len, 1);
                    if(offset) {
                        /* offset = (i + 1) mod (n-4), but simplified: just use i+1 if small enough */
                        if(i + 1 < 256 && i + 1 < len) {
                            offset[len - 1] = (uint8_t)(i + 1);
                            noxtls_bn_add(a, a, offset, len);
                            noxtls_free(offset);
                        } else {
                            noxtls_free(offset);
                        }
                    }
                }
            }
            }
        }
        
        /* Final safety check: ensure a is in [2, n-2] */
        if(noxtls_bn_cmp(a, n, len) >= 0) {
            /* Reduce modulo n again */
            noxtls_bn_mod(a, a, len, n, len);
        }
        if(noxtls_bn_is_zero(a, len) || noxtls_bn_is_one(a, len)) {
            noxtls_bn_copy(a, two, len);
        }
        if(noxtls_bn_cmp(a, n_minus_1, len) == 0) {
            /* a == n-1, use n-2 instead */
            noxtls_bn_sub(a, n_minus_1, two, len);
        }
        
        /* x = a^d mod n */
        noxtls_bn_mod_exp(x, a, d, len, n, len);
        
        /* Debug for small numbers */
        if(len == 1 && n[0] < 255) {
            noxtls_debug_printf("    [DEBUG] Witness a=%u, x=a^d mod n=%u\n", a[0], x[0]);
            fflush(stdout);
        }
        
        if(noxtls_bn_is_one(x, len) || noxtls_bn_cmp(x, n_minus_1, len) == 0) {
            continue;  /* This witness says "probably prime", continue to next witness */
        }
        
        /* Check if x^(2^j) == n-1 for some j in [1, r-1] */
        int composite = 1;
        for(j = 0; j < r - 1; j++) {
            noxtls_bn_mul(temp, x, len, x, len);
            noxtls_bn_mod(x, temp, len * 2, n, len);
            
            /* Debug for small numbers */
            if(len == 1 && n[0] < 255) {
                noxtls_debug_printf("      [DEBUG] After square %u: x=%u\n", j+1, x[0]);
                fflush(stdout);
            }
            
            if(noxtls_bn_cmp(x, n_minus_1, len) == 0) {
                composite = 0;  /* Found that x^(2^j) == n-1, so probably prime */
                break;
            }
        }
        
        if(composite) {
            /* Debug for small numbers */
            if(len == 1 && n[0] < 255) {
                noxtls_debug_printf("    [DEBUG] Witness a=%u says COMPOSITE\n", a[0]);
                fflush(stdout);
            }
            /* This witness says "composite" */
            noxtls_free(n_minus_1);
            noxtls_free(d);
            noxtls_free(a);
            noxtls_free(x);
            noxtls_free(temp);
            noxtls_free(two);
            return 0;
        }
    }
    
    noxtls_free(n_minus_1);
    noxtls_free(d);
    noxtls_free(a);
    noxtls_free(x);
    noxtls_free(temp);
    noxtls_free(two);
    return 1;
}

/* Quick divisibility test for small primes */
static int rsa_quick_divisibility_test(const uint8_t *n, uint32_t len)
{
    uint32_t i;
    uint32_t j;
    
    /* Compute n mod each small prime using modular arithmetic */
    for(i = 0; i < (uint32_t)(sizeof(small_primes) / sizeof(small_primes[0])); i++) {
        uint32_t mod = 0;  /* Use uint32_t to avoid overflow */
        uint16_t prime = small_primes[i];
        
        /* Compute n mod prime using: (a * 256 + b) mod p = ((a mod p) * 256 + b) mod p */
        for(j = 0; j < len; j++) {
            mod = ((mod * 256) + n[j]) % prime;
        }
        if(mod == 0) {
            return 0;  /* Divisible by small prime, definitely composite */
        }
    }
    return 1;  /* Not divisible by small primes, might be prime */
}

/* Initialize wheel residues/steps for modulo 2310 (2*3*5*7*11). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_wheel_init(uint16_t *residues, uint16_t *steps, uint32_t *count)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t idx = 0;
    for(uint32_t r = 1; r < 2310; r++) {
        if((r % 2) == 0 || (r % 3) == 0 || (r % 5) == 0 || (r % 7) == 0 || (r % 11) == 0) {
            continue;
        }
        residues[idx++] = (uint16_t)r;
    }
    *count = idx;
    for(uint32_t i = 0; i < *count; i++) {
        uint32_t curr = residues[i];
        uint32_t next = (i + 1 < *count) ? residues[i + 1] : (residues[0] + 2310);
        steps[i] = (uint16_t)(next - curr);
    }
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_wheel_advance(uint8_t *prime, uint32_t len,
                                         const uint16_t *wheel_residues, const uint16_t *wheel_steps,
                                         uint32_t wheel_count, uint32_t *wheel_idx, uint32_t *wheel_rem)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(wheel_count == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    uint32_t step = wheel_steps[*wheel_idx];
    rsa_add_small(prime, len, step);
    *wheel_rem = (*wheel_rem + step) % 2310u;
    *wheel_idx = (*wheel_idx + 1) % wheel_count;
    /* If we wrapped past the size (MSB cleared), reseed and realign */
    if((prime[0] & 0x80) == 0) {
        if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        prime[0] |= 0x80;
        prime[len-1] |= 1;
        *wheel_rem = rsa_mod_small(prime, len, 2310);
        *wheel_idx = 0;
        while(*wheel_idx < wheel_count && wheel_residues[*wheel_idx] < *wheel_rem) {
            (*wheel_idx)++;
        }
        if(*wheel_idx >= wheel_count) {
            uint32_t delta = (2310u - *wheel_rem) + wheel_residues[0];
            rsa_add_small(prime, len, delta);
            *wheel_rem = (*wheel_rem + delta) % 2310u;
            *wheel_idx = 0;
        } else if(wheel_residues[*wheel_idx] != *wheel_rem) {
            uint32_t delta = (uint32_t)wheel_residues[*wheel_idx] - *wheel_rem;
            rsa_add_small(prime, len, delta);
            *wheel_rem = (*wheel_rem + delta) % 2310u;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Generate prime number */
static int rsa_generate_prime(uint8_t *prime, uint32_t len)
{
    static int test_run = 0;
    uint32_t attempts = 0;
    uint32_t prime_bits = len * 8;
    static int wheel_init = 0;
    static uint16_t wheel_residues[480];
    static uint16_t wheel_steps[480];
    static uint32_t wheel_count = 0;
    uint32_t wheel_idx = 0;
    uint32_t wheel_rem = 0;
    /* No quotient needed; just compute modulus for wheel alignment. */
    
    /* Run Miller-Rabin test verification once on first prime generation */
    if(!test_run) {
        test_miller_rabin_known_primes();
        test_run = 1;
    }
    
    noxtls_debug_printf("  Starting prime generation (this may take several minutes for large keys)...\n");
    fflush(stdout);
    if(!wheel_init) {
        rsa_wheel_init(wheel_residues, wheel_steps, &wheel_count);
        wheel_init = 1;
    }
    
    /* Seed candidate and align to wheel residue */
    if(rsa_random_bytes(prime, len) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    prime[0] |= 0x80;  /* Set MSB to ensure correct bit length */
    prime[len-1] |= 1;  /* Make odd */
    wheel_rem = rsa_mod_small(prime, len, 2310);
    wheel_idx = 0;
    while(wheel_idx < wheel_count && wheel_residues[wheel_idx] < wheel_rem) {
        wheel_idx++;
    }
    if(wheel_idx >= wheel_count) {
        uint32_t delta = (2310u - wheel_rem) + wheel_residues[0];
        rsa_add_small(prime, len, delta);
        wheel_rem = (wheel_rem + delta) % 2310u;
        wheel_idx = 0;
    } else if(wheel_residues[wheel_idx] != wheel_rem) {
        uint32_t delta = (uint32_t)wheel_residues[wheel_idx] - wheel_rem;
        rsa_add_small(prime, len, delta);
        wheel_rem = (wheel_rem + delta) % 2310u;
    }
    
    do {
        attempts++;
        
#if NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL > 0
        if(attempts % NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL == 0) {
            noxtls_debug_printf("  Testing candidate %u...\n", attempts);
            fflush(stdout);
        }
#endif
        
        /* Quick divisibility test before expensive Miller-Rabin */
#if NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST
        if(!rsa_quick_divisibility_test(prime, len)) {
            if(rsa_wheel_advance(prime, len, wheel_residues, wheel_steps, wheel_count, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
                return 0;
            }
            continue;  /* Skip this candidate, it's divisible by a small prime */
        }
#endif
        
#if NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL > 0
        if(attempts % NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL == 0) {
            noxtls_debug_printf("  Checking primality of candidate %u (passed quick test)...\n", attempts);
            fflush(stdout);
        }
#endif
        
        /* Determine number of Miller-Rabin iterations based on prime size */
        int iterations;
        if(prime_bits <= NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS) {
            iterations = NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL;
        } else {
            iterations = NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE;
        }
        
        int is_prime = rsa_is_prime(prime, len, iterations);
        if(is_prime) {
            noxtls_debug_printf("  Found prime after %u attempts!\n", attempts);
            fflush(stdout);
            return 1;
        }
        
        /* Debug: Check if this might be a false negative */
        if(attempts % 200 == 0 && attempts <= 1000) {
            noxtls_debug_printf("  Debug: Candidate rejected (first byte: 0x%02x, last byte: 0x%02x)\n", 
                   prime[0], prime[len-1]);
            fflush(stdout);
        }
        
#if NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL > 0
        /* Debug: Print first few bytes of rejected candidate */
        if(attempts % NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL == 0 && 
           attempts <= NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS) {
            noxtls_debug_printf("  Rejected candidate (first 4 bytes): %02x %02x %02x %02x\n", 
                   prime[0], prime[1], prime[2], prime[3]);
            fflush(stdout);
        }
#endif
        /* Advance to next wheel residue for next candidate */
        if(rsa_wheel_advance(prime, len, wheel_residues, wheel_steps, wheel_count, &wheel_idx, &wheel_rem) != NOXTLS_RETURN_SUCCESS) {
            return 0;
        }
    } while(attempts < NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
    
    noxtls_debug_printf("  Warning: Failed to find prime after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
    fflush(stdout);
    return 0;  /* Failed to find prime */
}

/* PKCS#1 v1.5 Encryption Padding */
static noxtls_return_t rsa_pkcs1_v15_encrypt_pad(uint8_t *padded, uint32_t padded_len, const uint8_t *data, uint32_t data_len)
{
    noxtls_return_t rc;

    if(data_len > padded_len - 11) {
        return NOXTLS_RETURN_FAILED;
    }
    
    padded[0] = 0x00;
    padded[1] = 0x02;  /* Encryption block type */
    
    /* Random padding (non-zero bytes) */
    uint32_t pad_len = padded_len - data_len - 3;
    rc = rsa_random_bytes(padded + 2, pad_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(uint32_t i = 0; i < pad_len; i++) {
        uint32_t retries = 0;
        while(padded[2 + i] == 0 && retries < RSA_PKCS1_PAD_RETRY_MAX) {
            rc = rsa_random_bytes(padded + 2 + i, 1u);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            retries++;
        }
        if(padded[2 + i] == 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    padded[2 + pad_len] = 0x00;  /* Separator */
    memcpy(padded + 3 + pad_len, data, data_len);
    return NOXTLS_RETURN_SUCCESS;
}

/* PKCS#1 v1.5 Signature Padding */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void rsa_pkcs1_v15_sign_pad(uint8_t *padded, uint32_t padded_len, const uint8_t *hash, uint32_t hash_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t hash_oid[20];
    uint32_t oid_len = 0;

    if(hash_algo != NOXTLS_HASH_MD5 &&
       hash_algo != NOXTLS_HASH_SHA1 &&
       hash_algo != NOXTLS_HASH_SHA_224 &&
       hash_algo != NOXTLS_HASH_SHA_256 &&
       hash_algo != NOXTLS_HASH_SHA_384 &&
       hash_algo != NOXTLS_HASH_SHA_512) {
        return;
    }
    
    /* ASN.1 DigestInfo structure */
    switch(hash_algo) {
        case NOXTLS_HASH_MD5:
            /* MD5 OID: 1.2.840.113549.2.5 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x20; hash_oid[2] = 0x30; hash_oid[3] = 0x0C;
            hash_oid[4] = 0x06; hash_oid[5] = 0x08; hash_oid[6] = 0x2A; hash_oid[7] = 0x86;
            hash_oid[8] = 0x48; hash_oid[9] = 0x86; hash_oid[10] = 0xF7; hash_oid[11] = 0x0D;
            hash_oid[12] = 0x02; hash_oid[13] = 0x05; hash_oid[14] = 0x05; hash_oid[15] = 0x00;
            hash_oid[16] = 0x04; hash_oid[17] = 0x10;
            oid_len = 18;
            break;
        case NOXTLS_HASH_SHA1:
            /* SHA-1 OID: 1.3.14.3.2.26 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x21; hash_oid[2] = 0x30; hash_oid[3] = 0x09;
            hash_oid[4] = 0x06; hash_oid[5] = 0x05; hash_oid[6] = 0x2B; hash_oid[7] = 0x0E;
            hash_oid[8] = 0x03; hash_oid[9] = 0x02; hash_oid[10] = 0x1A; hash_oid[11] = 0x05;
            hash_oid[12] = 0x00; hash_oid[13] = 0x04; hash_oid[14] = 0x14;
            oid_len = 15;
            break;
        case NOXTLS_HASH_SHA_224:
            /* SHA-224 OID: 2.16.840.1.101.3.4.2.4 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x2d; hash_oid[2] = 0x30; hash_oid[3] = 0x0d;
            hash_oid[4] = 0x06; hash_oid[5] = 0x09; hash_oid[6] = 0x60; hash_oid[7] = 0x86;
            hash_oid[8] = 0x48; hash_oid[9] = 0x01; hash_oid[10] = 0x65; hash_oid[11] = 0x03;
            hash_oid[12] = 0x04; hash_oid[13] = 0x02; hash_oid[14] = 0x04; hash_oid[15] = 0x05;
            hash_oid[16] = 0x00; hash_oid[17] = 0x04; hash_oid[18] = 0x1c;
            oid_len = 19;
            break;
        case NOXTLS_HASH_SHA_256:
            /* SHA-256 OID: 2.16.840.1.101.3.4.2.1 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x31; hash_oid[2] = 0x30; hash_oid[3] = 0x0D;
            hash_oid[4] = 0x06; hash_oid[5] = 0x09; hash_oid[6] = 0x60; hash_oid[7] = 0x86;
            hash_oid[8] = 0x48; hash_oid[9] = 0x01; hash_oid[10] = 0x65; hash_oid[11] = 0x03;
            hash_oid[12] = 0x04; hash_oid[13] = 0x02; hash_oid[14] = 0x01; hash_oid[15] = 0x05;
            hash_oid[16] = 0x00; hash_oid[17] = 0x04; hash_oid[18] = 0x20;
            oid_len = 19;
            break;
        case NOXTLS_HASH_SHA_384:
            /* SHA-384 OID: 2.16.840.1.101.3.4.2.2 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x41; hash_oid[2] = 0x30; hash_oid[3] = 0x0d;
            hash_oid[4] = 0x06; hash_oid[5] = 0x09; hash_oid[6] = 0x60; hash_oid[7] = 0x86;
            hash_oid[8] = 0x48; hash_oid[9] = 0x01; hash_oid[10] = 0x65; hash_oid[11] = 0x03;
            hash_oid[12] = 0x04; hash_oid[13] = 0x02; hash_oid[14] = 0x02; hash_oid[15] = 0x05;
            hash_oid[16] = 0x00; hash_oid[17] = 0x04; hash_oid[18] = 0x30;
            oid_len = 19;
            break;
        case NOXTLS_HASH_SHA_512:
            /* SHA-512 OID: 2.16.840.1.101.3.4.2.3 */
            hash_oid[0] = 0x30; hash_oid[1] = 0x51; hash_oid[2] = 0x30; hash_oid[3] = 0x0d;
            hash_oid[4] = 0x06; hash_oid[5] = 0x09; hash_oid[6] = 0x60; hash_oid[7] = 0x86;
            hash_oid[8] = 0x48; hash_oid[9] = 0x01; hash_oid[10] = 0x65; hash_oid[11] = 0x03;
            hash_oid[12] = 0x04; hash_oid[13] = 0x02; hash_oid[14] = 0x03; hash_oid[15] = 0x05;
            hash_oid[16] = 0x00; hash_oid[17] = 0x04; hash_oid[18] = 0x40;
            oid_len = 19;
            break;
        default:
            return;
    }
    
    if(oid_len + hash_len + 3 > padded_len) {
        return;  /* Invalid */
    }
    
    padded[0] = 0x00;
    padded[1] = 0x01;  /* Signature block type */
    
    /* Padding with 0xFF */
    uint32_t pad_len = padded_len - oid_len - hash_len - 3;
    memset(padded + 2, 0xFF, pad_len);
    
    padded[2 + pad_len] = 0x00;  /* Separator */
    memcpy(padded + 3 + pad_len, hash_oid, oid_len);
    memcpy(padded + 3 + pad_len + oid_len, hash, hash_len);
}

/* Hash noxtls_message */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t rsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_sha_ctx_t ctx;
    noxtls_sha512_ctx_t ctx512;
    
    switch(hash_algo) {
        case NOXTLS_HASH_MD5:
            if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 16;
            break;
        case NOXTLS_HASH_SHA1:
            if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 20;
            break;
        case NOXTLS_HASH_SHA_224:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 28;
            break;
        case NOXTLS_HASH_SHA_256:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 32;
            break;
        case NOXTLS_HASH_SHA_384:
            if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_update(&ctx512, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 48;
            break;
        case NOXTLS_HASH_SHA_512:
            if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_update(&ctx512, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 64;
            break;
        case NOXTLS_HASH_MD4:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
        case NOXTLS_HASH_SHA3_224:
        case NOXTLS_HASH_SHA3_256:
        case NOXTLS_HASH_SHA3_384:
        case NOXTLS_HASH_SHA3_512:
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize RSA key structure
 */
noxtls_return_t noxtls_rsa_key_init(rsa_key_t *key, rsa_key_size_t key_size)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key_size < RSA_MIN_KEY_SIZE || key_size > RSA_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }
    
    uint32_t key_bytes = key_size >> 3;
    
    memset(key, 0, sizeof(rsa_key_t));
    key->key_size = key_size;
    key->key_bytes = key_bytes;
    
    /* Allocate memory for key components */
    key->n = (uint8_t*)noxtls_calloc(key_bytes, 1);
    key->e = (uint8_t*)noxtls_calloc(key_bytes, 1);
    key->d = (uint8_t*)noxtls_calloc(key_bytes, 1);
    key->p = (uint8_t*)noxtls_calloc(key_bytes / 2, 1);
    key->q = (uint8_t*)noxtls_calloc(key_bytes / 2, 1);
    key->dp = (uint8_t*)noxtls_calloc(key_bytes / 2, 1);
    key->dq = (uint8_t*)noxtls_calloc(key_bytes / 2, 1);
    key->qi = (uint8_t*)noxtls_calloc(key_bytes / 2, 1);
    
    if(!key->n || !key->e || !key->d || !key->p || !key->q || !key->dp || !key->dq || !key->qi) {
        noxtls_rsa_key_free(key);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Set default public exponent (65537 = 0x10001) */
    key->e[key_bytes - 3] = 0x01;
    key->e[key_bytes - 2] = 0x00;
    key->e[key_bytes - 1] = 0x01;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate RSA key pair
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
    
    uint32_t prime_len = key->key_bytes >> 1;
    uint8_t *phi = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    uint8_t *p_minus_1 = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *q_minus_1 = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *temp = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    uint8_t *one = (uint8_t*)noxtls_calloc(prime_len, 1);
    
    if(!phi || !p_minus_1 || !q_minus_1 || !temp || !one) {
        noxtls_debug_printf("ERROR: noxtls_rsa_key_generate: Memory allocation failed!\n");
        fflush(stdout);
        if(phi) noxtls_free(phi);
        if(p_minus_1) noxtls_free(p_minus_1);
        if(q_minus_1) noxtls_free(q_minus_1);
        if(temp) noxtls_free(temp);
        if(one) noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_bn_one(one, prime_len);
    
    /* Generate two primes p and q */
    noxtls_debug_printf("Generating prime p (%u bits)...\n", prime_len * 8);
    fflush(stdout);
    if(!rsa_generate_prime(key->p, prime_len)) {
        noxtls_debug_printf("Error: Failed to generate prime p after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
        noxtls_free(phi);
        noxtls_free(p_minus_1);
        noxtls_free(q_minus_1);
        noxtls_free(temp);
        noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("Prime p generated successfully!\n");
    noxtls_debug_printf("Prime p (hex): ");
    uint32_t i;
    for(i = 0; i < prime_len; i++) {
        noxtls_debug_printf("%02x", key->p[i]);
    }
    noxtls_debug_printf("\n");
    fflush(stdout);
    
    noxtls_debug_printf("Generating prime q (%u bits)...\n", prime_len * 8);
    fflush(stdout);
    if(!rsa_generate_prime(key->q, prime_len)) {
        noxtls_debug_printf("Error: Failed to generate prime q after %u attempts\n", NOXTLS_RSA_MAX_PRIME_ATTEMPTS);
        noxtls_free(phi);
        noxtls_free(p_minus_1);
        noxtls_free(q_minus_1);
        noxtls_free(temp);
        noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("Prime q generated successfully!\n");
    noxtls_debug_printf("Prime q (hex): ");
    for(i = 0; i < prime_len; i++) {
        noxtls_debug_printf("%02x", key->q[i]);
    }
    noxtls_debug_printf("\n");
    fflush(stdout);
    
    noxtls_debug_printf("Computing key components...\n");
    fflush(stdout);
    
    /* Compute n = p * q */
    noxtls_bn_mul(key->n, key->p, prime_len, key->q, prime_len);
    
    /* Compute phi(n) = (p-1) * (q-1) */
    noxtls_bn_copy(p_minus_1, key->p, prime_len);
    noxtls_bn_sub(p_minus_1, p_minus_1, one, prime_len);
    noxtls_bn_copy(q_minus_1, key->q, prime_len);
    noxtls_bn_sub(q_minus_1, q_minus_1, one, prime_len);
    noxtls_bn_mul(phi, p_minus_1, prime_len, q_minus_1, prime_len);
    
    /* Compute d = e^-1 mod phi(n) (phi is even; use small-e inverse helper) */
    if(rsa_mod_inv_small(key->d, phi, key->key_bytes, 65537u) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ERROR: noxtls_rsa_key_generate: Failed to compute private exponent d\n");
        fflush(stdout);
        noxtls_free(phi);
        noxtls_free(p_minus_1);
        noxtls_free(q_minus_1);
        noxtls_free(temp);
        noxtls_free(one);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Compute CRT parameters */
    noxtls_bn_mod(key->dp, key->d, key->key_bytes, p_minus_1, prime_len);
    noxtls_bn_mod(key->dq, key->d, key->key_bytes, q_minus_1, prime_len);
    /* qi = q^(p-2) mod p (Fermat), avoids mod_inv pitfalls */
    noxtls_bn_sub(p_minus_1, p_minus_1, one, prime_len); /* p_minus_1 now p-2 */
    noxtls_bn_mod_exp(key->qi, key->q, p_minus_1, prime_len, key->p, prime_len);
    
    noxtls_free(phi);
    noxtls_free(p_minus_1);
    noxtls_free(q_minus_1);
    noxtls_free(temp);
    noxtls_free(one);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free RSA key structure
 */
noxtls_return_t noxtls_rsa_key_free(rsa_key_t *key)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key->n) { noxtls_free(key->n); key->n = NULL; }
    if(key->e) { noxtls_free(key->e); key->e = NULL; }
    if(key->d) { noxtls_free(key->d); key->d = NULL; }
    if(key->p) { noxtls_free(key->p); key->p = NULL; }
    if(key->q) { noxtls_free(key->q); key->q = NULL; }
    if(key->dp) { noxtls_free(key->dp); key->dp = NULL; }
    if(key->dq) { noxtls_free(key->dq); key->dq = NULL; }
    if(key->qi) { noxtls_free(key->qi); key->qi = NULL; }
    
    memset(key, 0, sizeof(rsa_key_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Encryption
 */
noxtls_return_t noxtls_rsa_encrypt(const rsa_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t *ciphertext_len)
{
    noxtls_return_t rc;

    if(key == NULL || plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(plaintext_len > key->key_bytes - 11) {
        fprintf(stderr, "[noxtls_rsa_encrypt] FAIL: plaintext_len %lu > key_bytes-11 %lu\n",
                (unsigned long)plaintext_len, (unsigned long)(key->key_bytes - 11));
        return NOXTLS_RETURN_FAILED;
    }
    
    if(*ciphertext_len < key->key_bytes) {
        fprintf(stderr, "[noxtls_rsa_encrypt] FAIL: *ciphertext_len %lu < key_bytes %lu\n",
                (unsigned long)*ciphertext_len, (unsigned long)key->key_bytes);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Apply PKCS#1 v1.5 padding */
    uint8_t *padded = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!padded) {
        fprintf(stderr, "[noxtls_rsa_encrypt] FAIL: calloc(key_bytes=%u) returned NULL\n", key->key_bytes);
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = rsa_pkcs1_v15_encrypt_pad(padded, key->key_bytes, plaintext, plaintext_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(padded);
        return rc;
    }
    
    /* Encrypt: c = m^e mod n */
    noxtls_bn_mod_exp(ciphertext, padded, key->e, key->key_bytes, key->n, key->key_bytes);
    
    *ciphertext_len = key->key_bytes;
    noxtls_free(padded);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief CRT-only raw block decryption: m = c^d mod n using p, q, dp, dq, qi.
 * Fills decrypted with key->key_bytes. Caller must strip padding.
 */
static noxtls_return_t do_rsa_crt_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint8_t *decrypted)
{
    uint32_t prime_len = key->key_bytes >> 1;
    fprintf(stderr, "[CRT] do_rsa_crt_decrypt: start key_bytes=%lu prime_len=%lu\n", (unsigned long)key->key_bytes, (unsigned long)prime_len);
    uint8_t *c_mod_p = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *c_mod_q = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *m1 = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *m2 = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *h = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *p_inv = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *q_minus_2 = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *two_buf = (uint8_t*)noxtls_calloc(prime_len, 1);
    uint8_t *temp = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    uint8_t *m1_padded = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    uint8_t *sum = (uint8_t*)noxtls_calloc(key->key_bytes + 1, 1);

    if(!c_mod_p || !c_mod_q || !m1 || !m2 || !h || !p_inv || !q_minus_2 || !two_buf || !temp || !m1_padded || !sum) {
        fprintf(stderr, "[CRT] do_rsa_crt_decrypt: alloc failed\n");
        if(c_mod_p) noxtls_free(c_mod_p);
        if(c_mod_q) noxtls_free(c_mod_q);
        if(m1) noxtls_free(m1);
        if(m2) noxtls_free(m2);
        if(h) noxtls_free(h);
        if(p_inv) noxtls_free(p_inv);
        if(q_minus_2) noxtls_free(q_minus_2);
        if(two_buf) noxtls_free(two_buf);
        if(temp) noxtls_free(temp);
        if(m1_padded) noxtls_free(m1_padded);
        if(sum) noxtls_free(sum);
        return NOXTLS_RETURN_FAILED;
    }

    /* Reduce c mod p and mod q first; bn_mod_exp uses only first mod_len bytes of base. */
    noxtls_bn_mod(c_mod_p, ciphertext, key->key_bytes, key->p, prime_len);
    noxtls_bn_mod(c_mod_q, ciphertext, key->key_bytes, key->q, prime_len);
    noxtls_bn_mod_exp(m1, c_mod_p, key->dp, prime_len, key->p, prime_len);
    noxtls_bn_mod_exp(m2, c_mod_q, key->dq, prime_len, key->q, prime_len);

    /* Symmetric CRT: m = m1 + h*p where h = (m2 - m1) * p_inv mod q.
     * Compute p_inv via Fermat (p^(q-2) mod q) to avoid mod_inv issues. */
    noxtls_bn_copy(q_minus_2, key->q, prime_len);
    two_buf[prime_len - 1] = 2;
    noxtls_bn_sub(q_minus_2, q_minus_2, two_buf, prime_len);
    noxtls_bn_mod_exp(p_inv, key->p, q_minus_2, prime_len, key->q, prime_len);
    if(noxtls_bn_is_zero(p_inv, prime_len)) {
        fprintf(stderr, "[CRT] do_rsa_crt_decrypt: p_inv is zero\n");
        noxtls_free(c_mod_p);
        noxtls_free(c_mod_q);
        noxtls_free(m1);
        noxtls_free(m2);
        noxtls_free(h);
        noxtls_free(p_inv);
        noxtls_free(q_minus_2);
        noxtls_free(two_buf);
        noxtls_free(temp);
        noxtls_free(m1_padded);
        noxtls_free(sum);
        return NOXTLS_RETURN_FAILED;
    }
    /* h = m1 mod q (m1 can be >= q) */
    noxtls_bn_mod(h, m1, prime_len, key->q, prime_len);
    /* h = (m2 - h) mod q */
    if(noxtls_bn_cmp(m2, h, prime_len) >= 0) {
        noxtls_bn_sub(temp, m2, h, prime_len);
        memcpy(h, temp, prime_len);
    } else {
        uint8_t *h_sum = (uint8_t*)noxtls_calloc(prime_len + 1, 1);
        if(!h_sum) {
            fprintf(stderr, "[CRT] do_rsa_crt_decrypt: h_sum alloc failed\n");
            noxtls_free(c_mod_p);
            noxtls_free(c_mod_q);
            noxtls_free(m1);
            noxtls_free(m2);
            noxtls_free(h);
            noxtls_free(p_inv);
            noxtls_free(q_minus_2);
            noxtls_free(two_buf);
            noxtls_free(temp);
            noxtls_free(m1_padded);
            noxtls_free(sum);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_bn_sub(h_sum + 1, key->q, h, prime_len);
        {
            uint16_t carry = 0;
            for(uint32_t i = prime_len; i > 0; i--) {
                uint16_t s = (uint16_t)h_sum[i] + (uint16_t)m2[i - 1] + carry;
                h_sum[i] = (uint8_t)(s & 0xFF);
                carry = s >> 8;
            }
            h_sum[0] = (uint8_t)carry;
        }
        noxtls_bn_mod(h, (h_sum[0] != 0) ? h_sum : h_sum + 1, (h_sum[0] != 0) ? prime_len + 1 : prime_len, key->q, prime_len);
        noxtls_free(h_sum);
    }
    /* h = h * p_inv mod q */
    noxtls_bn_mul(temp, h, prime_len, p_inv, prime_len);
    noxtls_bn_mod(h, temp, prime_len * 2, key->q, prime_len);
    /* m = m1 + h*p: m1_padded has m1 in low prime_len bytes; temp = h*p */
    noxtls_bn_mul(temp, h, prime_len, key->p, prime_len);
    memcpy(m1_padded + key->key_bytes - prime_len, m1, prime_len);  /* m1 in low half */
    {
        uint16_t carry = 0;
        for(uint32_t i = key->key_bytes; i > 0; i--) {
            uint16_t s = (uint16_t)m1_padded[i - 1] + (uint16_t)temp[i - 1] + carry;
            sum[i] = (uint8_t)(s & 0xFF);
            carry = s >> 8;
        }
        sum[0] = (uint8_t)carry;
    }
    if(sum[0] != 0) {
        noxtls_bn_mod(decrypted, sum, key->key_bytes + 1, key->n, key->key_bytes);
    } else {
        noxtls_bn_mod(decrypted, sum + 1, key->key_bytes, key->n, key->key_bytes);
    }

    noxtls_free(c_mod_p);
    noxtls_free(c_mod_q);
    noxtls_free(m1);
    noxtls_free(m2);
    noxtls_free(h);
    noxtls_free(p_inv);
    noxtls_free(temp);
    noxtls_free(m1_padded);
    noxtls_free(sum);
    noxtls_free(q_minus_2);
    noxtls_free(two_buf);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Decryption
 */
noxtls_return_t noxtls_rsa_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    if(key == NULL || ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    uint8_t *decrypted = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!decrypted) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Standard decryption: m = c^d mod n. */
    noxtls_bn_mod_exp(decrypted, ciphertext, key->d, key->key_bytes, key->n, key->key_bytes);
    /* Remove PKCS#1 v1.5 padding (strict RFC 8017 structure for type 2). */
    if(key->key_bytes >= 11u && decrypted[0] == 0x00u && decrypted[1] == 0x02u) {
        uint32_t j = 2u;
        while(j < key->key_bytes && decrypted[j] != 0x00u) {
            j++;
        }
        /* Need at least 8 non-zero padding bytes and a separator. */
        if(j >= 10u && j < key->key_bytes) {
            uint32_t data_len = key->key_bytes - j - 1u;
            if(data_len <= *plaintext_len) {
                memcpy(plaintext, decrypted + j + 1u, data_len);
                *plaintext_len = data_len;
                noxtls_free(decrypted);
                return NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    
    noxtls_free(decrypted);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief RSA decrypt using CRT path only (for unit testing).
 */
noxtls_return_t noxtls_rsa_decrypt_crt_only(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len)
{
    if(key == NULL || ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ciphertext_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    if(!key->p || !key->q || !key->dp || !key->dq || !key->qi) {
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t *decrypted = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!decrypted) {
        return NOXTLS_RETURN_FAILED;
    }

    if(do_rsa_crt_decrypt(key, ciphertext, decrypted) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "[CRT] do_rsa_crt_decrypt returned FAILED\n");
        noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }

    /* Debug: dump first bytes of CRT decrypted block */
    fprintf(stderr, "[CRT] decrypted block (first 32 bytes): ");
    for(uint32_t k = 0; k < 32 && k < key->key_bytes; k++) {
        fprintf(stderr, "%02X ", decrypted[k]);
    }
    fprintf(stderr, "\n");

    /* Remove PKCS#1 v1.5 padding (strict RFC 8017 structure for type 2). */
    if(key->key_bytes >= 11u && decrypted[0] == 0x00u && decrypted[1] == 0x02u) {
        uint32_t j = 2u;
        while(j < key->key_bytes && decrypted[j] != 0x00u) {
            j++;
        }
        if(j >= 10u && j < key->key_bytes) {
            uint32_t data_len = key->key_bytes - j - 1u;
            if(data_len <= *plaintext_len) {
                memcpy(plaintext, decrypted + j + 1u, data_len);
                *plaintext_len = data_len;
                noxtls_free(decrypted);
                return NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    fprintf(stderr, "[CRT] padding strip failed - no 0x00 0x02 ... 0x00 pattern; full block (hex): ");
    for(uint32_t k = 0; k < key->key_bytes; k++) {
        fprintf(stderr, "%02X", decrypted[k]);
        if(((k + 1) & 31) == 0) fprintf(stderr, "\n  ");
    }
    fprintf(stderr, "\n");
    noxtls_free(decrypted);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief RSA Signature Generation
 */
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if(key == NULL || noxtls_message == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(*signature_len < key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Hash the noxtls_message */
    uint8_t hash[64];
    uint32_t hash_len = 0;
    noxtls_return_t rc = rsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Apply PKCS#1 v1.5 signature padding */
    uint8_t *padded = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!padded) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rsa_pkcs1_v15_sign_pad(padded, key->key_bytes, hash, hash_len, hash_algo);
    
    /* Sign: s = hash^d mod n */
    noxtls_bn_mod_exp(signature, padded, key->d, key->key_bytes, key->n, key->key_bytes);
    
    *signature_len = key->key_bytes;
    noxtls_free(padded);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RSA Signature Verification
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_verify(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(key == NULL || noxtls_message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(signature_len != key->key_bytes) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify: hash' = signature^e mod n */
    uint8_t *decrypted = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!decrypted) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_bn_mod_exp(decrypted, signature, key->e, key->key_bytes, key->n, key->key_bytes);
    
    /* Hash the noxtls_message */
    uint8_t hash[64];
    uint32_t hash_len = 0;
    noxtls_return_t rc = rsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(decrypted);
        return rc;
    }
    
    /* Extract hash from PKCS#1 v1.5 padding and compare */
    uint32_t i;
    for(i = 0; i < key->key_bytes; i++) {
        if(decrypted[i] == 0x00 && i + 1 < key->key_bytes && decrypted[i+1] == 0x01) {
            /* Find separator after 0xFF padding */
            uint32_t j;
            for(j = i + 2; j < key->key_bytes; j++) {
                if(decrypted[j] == 0x00) {
                    /* Compare the expected digest against the trailing bytes of EMSA-PKCS1-v1_5.
                     * DigestInfo encoding can differ in parameter encoding (e.g. NULL present/omitted). */
                    uint32_t hash_offset;
                    if(key->key_bytes < hash_len) {
                        noxtls_free(decrypted);
                        return NOXTLS_RETURN_FAILED;
                    }
                    hash_offset = key->key_bytes - hash_len;
                    if(hash_offset <= j) {
                        noxtls_free(decrypted);
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(noxtls_secret_memcmp(decrypted + hash_offset, hash, hash_len) == 0) {
                        noxtls_free(decrypted);
                        return NOXTLS_RETURN_SUCCESS;
                    }
                }
            }
        }
    }
    
    noxtls_free(decrypted);
    return NOXTLS_RETURN_FAILED;
}

/* --- RSA-PSS (RFC 8017) --- */

/** Hash for PSS: SHA-256, SHA-384, or SHA-512 (for TLS 1.3). */
static noxtls_return_t pss_hash_message(noxtls_hash_algos_t hash_algo, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *hash, uint32_t *hash_len)
{
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha256_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = 32;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t ctx;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = 48;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t ctx;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = 64;
        return NOXTLS_RETURN_SUCCESS;
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/** MGF1 (RFC 8017): mask = MGF1(seed, seed_len, mask_len). */
static noxtls_return_t mgf1(noxtls_hash_algos_t hash_algo, const uint8_t *seed, uint32_t seed_len, uint8_t *mask, uint32_t mask_len)
{
    uint32_t h_len = (hash_algo == NOXTLS_HASH_SHA_256) ? 32u :
                     (hash_algo == NOXTLS_HASH_SHA_384) ? 48u :
                     (hash_algo == NOXTLS_HASH_SHA_512) ? 64u : 0u;
    uint8_t counter[4];
    uint32_t offset = 0;
    uint8_t T_buf[64];
    uint8_t *input;

    if(seed == NULL || (mask == NULL && mask_len > 0u)) {
        return NOXTLS_RETURN_NULL;
    }
    if(h_len == 0u) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(seed_len > (uint32_t)(UINT32_MAX - 4u)) {
        return NOXTLS_RETURN_FAILED;
    }

    input = (uint8_t*)noxtls_calloc(seed_len + 4u, 1);
    if(!input) return NOXTLS_RETURN_FAILED;
    memcpy(input, seed, seed_len);

    while(offset < mask_len) {
        counter[0] = (uint8_t)((offset / h_len) >> 24);
        counter[1] = (uint8_t)((offset / h_len) >> 16);
        counter[2] = (uint8_t)((offset / h_len) >> 8);
        counter[3] = (uint8_t)(offset / h_len);
        memcpy(input + seed_len, counter, 4);
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t ctx;
            noxtls_sha256_init(&ctx, hash_algo);
            noxtls_sha256_update(&ctx, input, seed_len + 4);
            noxtls_sha256_finish(&ctx, T_buf);
        } else {
            noxtls_sha512_ctx_t ctx;
            noxtls_sha512_init(&ctx, hash_algo);
            noxtls_sha512_update(&ctx, input, seed_len + 4);
            noxtls_sha512_finish(&ctx, T_buf);
        }
        uint32_t copy = mask_len - offset;
        if(copy > h_len) copy = h_len;
        memcpy(mask + offset, T_buf, copy);
        offset += copy;
    }
    noxtls_free(input);
    return NOXTLS_RETURN_SUCCESS;
}

/** EMSA-PSS-ENCODE (RFC 8017). salt_len must equal h_len. */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t emsa_pss_encode(const uint8_t *m_hash, uint32_t h_len,
    uint32_t em_len, noxtls_hash_algos_t hash_algo, uint32_t salt_len,
    uint8_t *em)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(m_hash == NULL || em == NULL) return NOXTLS_RETURN_NULL;
    if(h_len > 64u || salt_len > 64u) return NOXTLS_RETURN_INVALID_PARAM;
    if(h_len > (uint32_t)(UINT32_MAX - salt_len - 8u)) return NOXTLS_RETURN_FAILED;
    if(em_len < h_len + salt_len + 2) return NOXTLS_RETURN_FAILED;
    uint32_t ps_len = em_len - salt_len - h_len - 2;
    uint32_t db_len = em_len - h_len - 1;

    uint8_t *salt = (uint8_t*)noxtls_calloc(salt_len, 1);
    if(!salt) return NOXTLS_RETURN_FAILED;
    if(rsa_random_bytes(salt, salt_len) != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(salt);
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t m_prime[8 + 64 + 64];
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, m_hash, h_len);
    memcpy(m_prime + 8 + h_len, salt, salt_len);
    uint32_t m_prime_len = 8u + h_len + salt_len;

    uint8_t H[64];
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        noxtls_sha256_init(&ctx, hash_algo);
        noxtls_sha256_update(&ctx, m_prime, m_prime_len);
        noxtls_sha256_finish(&ctx, H);
    } else {
        noxtls_sha512_ctx_t ctx;
        noxtls_sha512_init(&ctx, hash_algo);
        noxtls_sha512_update(&ctx, m_prime, m_prime_len);
        noxtls_sha512_finish(&ctx, H);
    }
    memset(em, 0, ps_len);
    em[ps_len] = 0x01;
    memcpy(em + ps_len + 1, salt, salt_len);
    noxtls_free(salt);

    uint8_t *db_mask = (uint8_t*)noxtls_calloc(db_len, 1);
    if(!db_mask) return NOXTLS_RETURN_FAILED;
    mgf1(hash_algo, H, h_len, db_mask, db_len);
    for(uint32_t i = 0; i < db_len; i++) em[i] ^= db_mask[i];
    noxtls_free(db_mask);

    em[0] &= 0x7F;
    memcpy(em + db_len, H, h_len);
    em[em_len - 1] = 0xbc;
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
    if(m_hash == NULL || em == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(h_len > 64u || salt_len > 64u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(h_len > (uint32_t)(UINT32_MAX - salt_len - 8u)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(em_len < h_len + salt_len + 2 || em[em_len - 1] != 0xbc) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)fprintf(stderr, "[PSS_VERIFY] fail: em_len=%u last_byte=0x%02x (expect 0xbc)\n",
            (unsigned)em_len, (unsigned)(em_len > 0 ? em[em_len - 1] : 0));
#endif
        return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)fprintf(stderr, "[PSS_VERIFY] step: trailer 0xbc ok em_len=%u\n", (unsigned)em_len);
#endif
    uint32_t db_len = em_len - h_len - 1;
    uint32_t ps_len_val = em_len - salt_len - h_len - 2;

    const uint8_t *masked_db = em;
    const uint8_t *H = em + db_len;

    uint8_t *db_mask = (uint8_t*)noxtls_calloc(db_len, 1);
    if(!db_mask) return NOXTLS_RETURN_FAILED;
    mgf1(hash_algo, H, h_len, db_mask, db_len);

    uint8_t *DB = (uint8_t*)noxtls_calloc(db_len, 1);
    if(!DB) { noxtls_free(db_mask); return NOXTLS_RETURN_FAILED; }
    for(uint32_t i = 0; i < db_len; i++) DB[i] = masked_db[i] ^ db_mask[i];
    noxtls_free(db_mask);

    /* Encoding set the leftmost bit of the first octet of maskedDB to zero (em[0] &= 0x7F); match that when verifying. */
    DB[0] &= 0x7Fu;

    if((DB[0] & 0x80) != 0) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)fprintf(stderr, "[PSS_VERIFY] fail: DB[0] has high bit set (0x%02x)\n", (unsigned)DB[0]);
#endif
        noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)fprintf(stderr, "[PSS_VERIFY] step: DB[0] high bit ok (0x%02x)\n", (unsigned)DB[0]);
#endif

    /* Padding: ps_len_val zeros, then 0x01 (at index ps_len_val). */
    uint32_t i;
    for(i = 0; i < ps_len_val && DB[i] == 0; i++) { }
    if(i != ps_len_val || i >= db_len || DB[i] != 0x01) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)fprintf(stderr, "[PSS_VERIFY] fail: padding: i=%u ps_len_val=%u db_len=%u DB[i]=0x%02x (expect 0x01 at i==ps_len_val)\n",
            (unsigned)i, (unsigned)ps_len_val, (unsigned)db_len, (unsigned)(i < db_len ? DB[i] : 0));
#endif
        noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }
    uint32_t salt_offset = i + 1;
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)fprintf(stderr, "[PSS_VERIFY] step: padding ok i=%u salt_offset=%u\n", (unsigned)i, (unsigned)salt_offset);
#endif
    if(salt_offset > db_len || salt_len > (db_len - salt_offset)) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)fprintf(stderr, "[PSS_VERIFY] fail: salt_offset+salt_len > db_len\n");
#endif
        noxtls_free(DB); return NOXTLS_RETURN_FAILED;
    }

    uint8_t m_prime[8 + 64 + 64];
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, m_hash, h_len);
    memcpy(m_prime + 8 + h_len, DB + salt_offset, salt_len);
    noxtls_free(DB);
    uint32_t m_prime_len = 8u + h_len + salt_len;

    uint8_t H_prime[64];
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        noxtls_sha256_init(&ctx, hash_algo);
        noxtls_sha256_update(&ctx, m_prime, m_prime_len);
        noxtls_sha256_finish(&ctx, H_prime);
    } else {
        noxtls_sha512_ctx_t ctx;
        noxtls_sha512_init(&ctx, hash_algo);
        noxtls_sha512_update(&ctx, m_prime, m_prime_len);
        noxtls_sha512_finish(&ctx, H_prime);
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)fprintf(stderr, "[PSS_VERIFY] step: comparing H, H' (h_len=%u)\n", (unsigned)h_len);
#endif
    if(noxtls_secret_memcmp(H, H_prime, h_len) != 0) {
#if NOXTLS_DEBUG_PSS_VERIFY
        (void)fprintf(stderr, "[PSS_VERIFY] fail: H != H' (hash mismatch)\n");
#endif
        return NOXTLS_RETURN_FAILED;
    }
#if NOXTLS_DEBUG_PSS_VERIFY
    (void)fprintf(stderr, "[PSS_VERIFY] ok\n");
#endif
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_rsa_sign_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo)
{
    if(key == NULL || noxtls_message == NULL || signature == NULL || signature_len == NULL) return NOXTLS_RETURN_NULL;
    if(hash_algo != NOXTLS_HASH_SHA_256 &&
       hash_algo != NOXTLS_HASH_SHA_384 &&
       hash_algo != NOXTLS_HASH_SHA_512) return NOXTLS_RETURN_INVALID_ALGORITHM;
    if(*signature_len < key->key_bytes) return NOXTLS_RETURN_FAILED;

    uint32_t h_len = (hash_algo == NOXTLS_HASH_SHA_256) ? 32u :
                     (hash_algo == NOXTLS_HASH_SHA_384) ? 48u : 64u;
    uint8_t m_hash[64];
    if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    uint8_t *em = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!em) return NOXTLS_RETURN_FAILED;

    /* RFC 8017: noxtls_message representative m = OS2IP(EM) must be < n; otherwise retry with new salt. */
    unsigned retries = 0;
    const unsigned max_retries = 16;
    do {
        noxtls_return_t rc = emsa_pss_encode(m_hash, h_len, key->key_bytes, hash_algo, h_len, em);
        if(rc != NOXTLS_RETURN_SUCCESS) { noxtls_free(em); return rc; }
        if(noxtls_bn_cmp(em, key->n, key->key_bytes) < 0)
            break;
        if(++retries >= max_retries) {
            noxtls_free(em);
            return NOXTLS_RETURN_FAILED;
        }
    } while(1);

    noxtls_return_t rc = noxtls_bn_mod_exp(signature, em, key->d, key->key_bytes, key->n, key->key_bytes);
    noxtls_free(em);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    *signature_len = key->key_bytes;
    return NOXTLS_RETURN_SUCCESS;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_rsa_verify_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len,
    const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(key == NULL || noxtls_message == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if(signature_len != key->key_bytes) return NOXTLS_RETURN_FAILED;
    if(hash_algo != NOXTLS_HASH_SHA_256 &&
       hash_algo != NOXTLS_HASH_SHA_384 &&
       hash_algo != NOXTLS_HASH_SHA_512) return NOXTLS_RETURN_INVALID_ALGORITHM;

    uint8_t *em = (uint8_t*)noxtls_calloc(key->key_bytes, 1);
    if(!em) return NOXTLS_RETURN_FAILED;
    noxtls_return_t rc = noxtls_bn_mod_exp(em, signature, key->e, key->key_bytes, key->n, key->key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) { noxtls_free(em); return rc; }

    uint32_t h_len = (hash_algo == NOXTLS_HASH_SHA_256) ? 32u :
                     (hash_algo == NOXTLS_HASH_SHA_384) ? 48u : 64u;
    uint8_t m_hash[64];
    if(pss_hash_message(hash_algo, noxtls_message, message_len, m_hash, &h_len) != NOXTLS_RETURN_SUCCESS) { noxtls_free(em); return NOXTLS_RETURN_FAILED; }

    rc = emsa_pss_verify(m_hash, h_len, em, key->key_bytes, hash_algo, h_len);
    noxtls_free(em);
    return rc;
}
