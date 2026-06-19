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
* File:    noxtls_ecdsa.c
* Summary: Elliptic Curve Digital Signature Algorithm (ECDSA) Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_ecdsa.h"
#include "noxtls_ecdsa_accel_port.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "pkc/rsa/noxtls_bn_platform.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "drbg/noxtls_drbg.h"
#if defined(ESP_PLATFORM)
#include "noxtls_esp_hw_crypto.h"
#endif
#if defined(__has_include)
#if defined(ESP_PLATFORM) && __has_include("esp_timer.h")
#include "esp_timer.h"
#endif
#endif

#ifndef NOXTLS_ECDSA_SIGN_SELF_VERIFY
#define NOXTLS_ECDSA_SIGN_SELF_VERIFY 0
#endif



static const uint8_t s_p256_order_be[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

static const uint32_t s_p256_order_words[8] = {
    0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu
};

static const uint32_t s_p256_order_mu_words[9] = {
    0xEEDF9BFEu, 0x012FFD85u, 0xDF1A6C21u, 0x43190552u,
    0xFFFFFFFFu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0x00000000u,
    0x00000001u
};

static noxtls_ecdsa_sign_timing_t s_ecdsa_last_sign_timing;

#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)

/**
 * @brief Print a hex string
 *
 * @param[in] label The label to print the hex string from
 * @param[in] buf The buffer to print the hex string from
 * @param[in] len The length of the buffer to print the hex string from
 * @return void
 */
static void ecdsa_debug_hex(const char *label, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    printf("[ecdsa_verify] %s (%u bytes): ", label, (unsigned)len);
    if(buf) {
        for(i = 0; i < len; i++) printf("%02X", buf[i]);
    } else {
        printf("(null)");
    }
    printf("\n");
    fflush(stdout);
}
#endif


/**
 * @brief Get the current time in microseconds
 *
 * @return The current time in microseconds
 */
static uint64_t ecdsa_profile_now_us(void)
{
#if defined(__has_include) && defined(ESP_PLATFORM) && __has_include("esp_timer.h")
    return (uint64_t)esp_timer_get_time();
#else
    clock_t now = clock();

    if(now <= (clock_t)0) {
        return 0U;
    }
    return ((uint64_t)now * 1000000u) / (uint64_t)CLOCKS_PER_SEC;
#endif
}

/**
 * @brief Get the elapsed time in microseconds
 *
 * @param[in] start_us The start time in microseconds
 * @return The elapsed time in microseconds
 */
static uint64_t ecdsa_profile_elapsed_us(uint64_t start_us)
{
    uint64_t now_us = ecdsa_profile_now_us();

    if(now_us < start_us) {
        return 0U;
    }
    return now_us - start_us;
}

/**
 * @brief Get the last sign timing
 *
 * @return The last sign timing
 */
const noxtls_ecdsa_sign_timing_t *noxtls_ecdsa_last_sign_timing(void)
{
    return &s_ecdsa_last_sign_timing;
}

/**
 * @brief Generate bits from the DRBG
 *
 * @param[out] out The output to generate the bits into
 * @param[in] requested_bits The number of bits to generate
 * @return The return code
 */
static noxtls_return_t ecdsa_drbg_generate_bits(uint8_t *out, uint32_t requested_bits)
{
    static drbg_state_t s_ecdsa_drbg_state;
    static int s_ecdsa_drbg_initialized = 0;
    uint8_t seed[DRBG_SEEDLEN_AES256];
    noxtls_return_t rc;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(!s_ecdsa_drbg_initialized) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = drbg_instantiate(&s_ecdsa_drbg_state, DRBG_AES256,
                              seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        s_ecdsa_drbg_initialized = 1;
    }

    rc = drbg_generate(&s_ecdsa_drbg_state, out, requested_bits, NULL, 0);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    memset(&s_ecdsa_drbg_state, 0, sizeof(s_ecdsa_drbg_state));
    s_ecdsa_drbg_initialized = 0;

    rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = drbg_instantiate(&s_ecdsa_drbg_state, DRBG_AES256,
                          seed, sizeof(seed), NULL, 0, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    s_ecdsa_drbg_initialized = 1;
    return drbg_generate(&s_ecdsa_drbg_state, out, requested_bits, NULL, 0);
}

/**
 * @brief Check if the order is P-256
 *
 * @param[in] mod The modulus to check if the order is P-256 from
 * @param[in] size The size of the modulus to check if the order is P-256 from
 * @return 1 if the order is P-256, 0 otherwise
 */
static int ecdsa_order_is_p256(const uint8_t *mod, uint32_t size)
{
    return mod != NULL && size == 32U && memcmp(mod, s_p256_order_be, 32U) == 0;
}

/**
 * @brief Convert words from big endian to little endian
 *
 * @param[out] out The output to convert the words from big endian to little endian into
 * @param[in] in The input to convert the words from big endian to little endian from
 * @return void
 */
static void p256_scalar_words_from_be(uint32_t out[8], const uint8_t in[32])
{
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint32_t off = 32U - ((i + 1U) * 4U);
        out[i] = ((uint32_t)in[off] << 24) |
                 ((uint32_t)in[off + 1U] << 16) |
                 ((uint32_t)in[off + 2U] << 8) |
                 ((uint32_t)in[off + 3U]);
    }
}

/**
 * @brief Convert words from little endian to big endian
 *
 * @param[out] out The output to convert the words from little endian to big endian into
 * @param[in] in The input to convert the words from little endian to big endian from
 * @return void
 */
static void p256_scalar_words_to_be(uint8_t out[32], const uint32_t in[8])
{
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint32_t w = in[i];
        uint32_t off = 32U - ((i + 1U) * 4U);
        out[off] = (uint8_t)(w >> 24);
        out[off + 1U] = (uint8_t)(w >> 16);
        out[off + 2U] = (uint8_t)(w >> 8);
        out[off + 3U] = (uint8_t)w;
    }
}

/**
 * @brief Compare two scalars
 *
 * @param[in] a The first scalar to compare
 * @param[in] b The second scalar to compare
 * @param[in] len The length of the scalars to compare
 * @return 1 if the first scalar is greater than the second scalar, -1 if the first scalar is less than the second scalar, 0 if the scalars are equal
 */
static int p256_scalar_cmp_words(const uint32_t *a, const uint32_t *b, uint32_t len)
{
    uint32_t i;

    for(i = len; i > 0U; i--) {
        if(a[i - 1U] > b[i - 1U]) {
            return 1;
        }
        if(a[i - 1U] < b[i - 1U]) {
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Check if the scalar is zero
 *
 * @param[in] a The scalar to check if the scalar is zero from
 * @return 1 if the scalar is zero, 0 otherwise
 */
static int p256_scalar_is_zero_words(const uint32_t a[8])
{
    uint32_t i;
    uint32_t acc = 0U;

    for(i = 0; i < 8U; i++) {
        acc |= a[i];
    }

    return acc == 0U;
}

/**
 * @brief Check if the scalar is one
 *
 * @param[in] a The scalar to check if the scalar is one from
 * @return 1 if the scalar is one, 0 otherwise
 */
static int p256_scalar_is_one_words(const uint32_t a[8])
{
    return a[0] == 1U &&
           a[1] == 0U &&
           a[2] == 0U &&
           a[3] == 0U &&
           a[4] == 0U &&
           a[5] == 0U &&
           a[6] == 0U &&
           a[7] == 0U;
}

/**
 * @brief Right shift a scalar by 1
 *
 * @param[in] a The scalar to right shift by 1 from
 * @return void
 */
static void p256_scalar_rshift1_words(uint32_t a[8])
{
    uint32_t i;
    uint32_t carry = 0U;

    for(i = 8U; i > 0U; i--) {
        uint32_t w = a[i - 1U];
        a[i - 1U] = (w >> 1) | (carry << 31);
        carry = w & 1U;
    }
}

/**
 * @brief Subtract two scalars
 *
 * @param[out] out The output to subtract the two scalars into
 * @param[in] a The first scalar to subtract from
 * @param[in] b The second scalar to subtract from
 * @param[in] len The length of the scalars to subtract
 * @return 1 if the first scalar is greater than the second scalar, -1 if the first scalar is less than the second scalar, 0 if the scalars are equal
 */
static uint32_t p256_scalar_sub_words(uint32_t *out,
                                      const uint32_t *a,
                                      const uint32_t *b,
                                      uint32_t len)
{
    uint64_t borrow = 0U;
    uint32_t i;

    for(i = 0; i < len; i++) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if(ai < bi) {
            out[i] = (uint32_t)(ai + (1ULL << 32) - bi);
            borrow = 1U;
        } else {
            out[i] = (uint32_t)(ai - bi);
            borrow = 0U;
        }
    }
    return (uint32_t)borrow;
}

/**
 * @brief Subtract two scalars modulo the order
 *
 * @param[out] out The output to subtract the two scalars modulo the order into
 * @param[in] a The first scalar to subtract from
 * @param[in] b The second scalar to subtract from
 * @return void
 */
static void p256_scalar_sub_mod_words(uint32_t out[8],
                                      const uint32_t a[8],
                                      const uint32_t b[8])
{
    if(p256_scalar_cmp_words(a, b, 8U) >= 0) {
        (void)p256_scalar_sub_words(out, a, b, 8U);
    } else {
        uint32_t diff[8];
        (void)p256_scalar_sub_words(diff, b, a, 8U);
        (void)p256_scalar_sub_words(out, s_p256_order_words, diff, 8U);
    }
}

/**
 * @brief Add the order and right shift a scalar by 1
 *
 * @param[out] out The output to add the order and right shift a scalar by 1 into
 * @param[in] in The scalar to add the order and right shift a scalar by 1 from
 * @return void
 */
static void p256_scalar_add_order_and_rshift1_words(uint32_t out[8], const uint32_t in[8])
{
    uint32_t sum[8];
    uint32_t i;
    uint32_t carry_word;
    uint64_t carry = 0U;

    for(i = 0; i < 8U; i++) {
        uint64_t t = (uint64_t)in[i] + (uint64_t)s_p256_order_words[i] + carry;
        sum[i] = (uint32_t)t;
        carry = t >> 32;
    }

    carry_word = (uint32_t)carry;
    for(i = 8U; i > 0U; i--) {
        uint32_t w = sum[i - 1U];
        out[i - 1U] = (w >> 1) | (carry_word << 31);
        carry_word = w & 1U;
    }
}

/**
 * @brief Multiply two scalars
 *
 * @param[out] out The output to multiply the two scalars into
 * @param[in] a The first scalar to multiply
 * @param[in] b The second scalar to multiply
 * @return void
 */
static void p256_scalar_mul_words(uint32_t out[16], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t i;
    uint32_t j;
    uint32_t k;

    memset(out, 0, 16U * sizeof(uint32_t));
    for(i = 0; i < 8U; i++) {
        uint64_t carry = 0U;
        for(j = 0; j < 8U; j++) {
            uint64_t t = (uint64_t)out[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        k = i + 8U;
        while(carry != 0U && k < 16U) {
            uint64_t t = (uint64_t)out[k] + carry;
            out[k] = (uint32_t)t;
            carry = t >> 32;
            k++;
        }
    }
}

/**
 * @brief Reduce a scalar using Barrett's algorithm
 *
 * @param[out] out The output to reduce the scalar using Barrett's algorithm into
 * @param[in] in The scalar to reduce using Barrett's algorithm from
 * @return void
 */
static void p256_scalar_reduce_barrett_words(uint32_t out[8], const uint32_t in[16])
{
    uint32_t q1[9];
    uint32_t q2[18];
    uint32_t q3[9];
    uint32_t r1[9];
    uint32_t r2_full[17];
    uint32_t r2[9];
    uint32_t r[9];
    uint32_t n9[9];
    uint32_t i;

    memset(q1, 0, sizeof(q1));
    memset(q2, 0, sizeof(q2));
    memset(q3, 0, sizeof(q3));
    memset(r1, 0, sizeof(r1));
    memset(r2_full, 0, sizeof(r2_full));
    memset(r2, 0, sizeof(r2));
    memset(r, 0, sizeof(r));
    memset(n9, 0, sizeof(n9));
    memcpy(n9, s_p256_order_words, 8U * sizeof(uint32_t));

    for(i = 0; i < 9U; i++) {
        q1[i] = in[i + 7U];
        r1[i] = in[i];
    }

    for(i = 0; i < 9U; i++) {
        uint64_t carry = 0U;
        uint32_t j;
        for(j = 0; j < 9U; j++) {
            uint64_t t = (uint64_t)q2[i + j] + ((uint64_t)q1[i] * (uint64_t)s_p256_order_mu_words[j]) + carry;
            q2[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        {
            uint32_t k = i + 9U;
            while(carry != 0U && k < 18U) {
                uint64_t t = (uint64_t)q2[k] + carry;
                q2[k] = (uint32_t)t;
                carry = t >> 32;
                k++;
            }
        }
    }

    for(i = 0; i < 9U; i++) {
        q3[i] = q2[i + 9U];
    }

    for(i = 0; i < 9U; i++) {
        uint64_t carry = 0U;
        uint32_t j;
        for(j = 0; j < 8U; j++) {
            uint64_t t = (uint64_t)r2_full[i + j] + ((uint64_t)q3[i] * (uint64_t)s_p256_order_words[j]) + carry;
            r2_full[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        {
            uint32_t k = i + 8U;
            while(carry != 0U && k < 17U) {
                uint64_t t = (uint64_t)r2_full[k] + carry;
                r2_full[k] = (uint32_t)t;
                carry = t >> 32;
                k++;
            }
        }
    }
    memcpy(r2, r2_full, 9U * sizeof(uint32_t));

    if(p256_scalar_sub_words(r, r1, r2, 9U) != 0U) {
        uint64_t carry = 0U;
        for(i = 0; i < 9U; i++) {
            uint64_t t = (uint64_t)r[i] + (uint64_t)n9[i] + carry;
            r[i] = (uint32_t)t;
            carry = t >> 32;
        }
    }

    while(r[8] != 0U || p256_scalar_cmp_words(r, s_p256_order_words, 8U) >= 0) {
        if(r[8] != 0U) {
            uint64_t borrow = 0U;
            for(i = 0; i < 8U; i++) {
                uint64_t bi = (uint64_t)s_p256_order_words[i] + borrow;
                if((uint64_t)r[i] < bi) {
                    r[i] = (uint32_t)((uint64_t)r[i] + (1ULL << 32) - bi);
                    borrow = 1U;
                } else {
                    r[i] = (uint32_t)((uint64_t)r[i] - bi);
                    borrow = 0U;
                }
            }
            r[8] = (uint32_t)((uint64_t)r[8] - borrow);
        } else {
            (void)p256_scalar_sub_words(r, r, s_p256_order_words, 8U);
        }
    }

    memcpy(out, r, 8U * sizeof(uint32_t));
}

/**
 * @brief Reduce a 32-bit scalar
 *
 * @param[out] out The output to reduce the 32-bit scalar into
 * @param[in] in The 32-bit scalar to reduce from
 * @return void
 */
static void p256_scalar_reduce32(uint8_t out[32], const uint8_t in[32])
{
    uint32_t words[8];

    p256_scalar_words_from_be(words, in);
    if(p256_scalar_cmp_words(words, s_p256_order_words, 8U) >= 0) {
        (void)p256_scalar_sub_words(words, words, s_p256_order_words, 8U);
    }
    p256_scalar_words_to_be(out, words);
}

/**
 * @brief Add two scalars modulo the order
 *
 * @param[out] out The output to add the two scalars modulo the order into
 * @param[in] a The first scalar to add
 * @param[in] b The second scalar to add
 * @return void
 */
static void p256_scalar_add_mod(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t sum[8];
    uint64_t carry = 0U;
    uint32_t i;

    p256_scalar_words_from_be(aw, a);
    p256_scalar_words_from_be(bw, b);
    for(i = 0; i < 8U; i++) {
        uint64_t t = (uint64_t)aw[i] + (uint64_t)bw[i] + carry;
        sum[i] = (uint32_t)t;
        carry = t >> 32;
    }
    if(carry != 0U || p256_scalar_cmp_words(sum, s_p256_order_words, 8U) >= 0) {
        (void)p256_scalar_sub_words(sum, sum, s_p256_order_words, 8U);
    }
    p256_scalar_words_to_be(out, sum);
}

/**
 * @brief Multiply two scalars modulo the order
 *
 * @param[out] out The output to multiply the two scalars modulo the order into
 * @param[in] a The first scalar to multiply
 * @param[in] b The second scalar to multiply
 * @return void
 */
static void p256_scalar_mul_mod(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t prod[16];
    uint32_t reduced[8];

    p256_scalar_words_from_be(aw, a);
    p256_scalar_words_from_be(bw, b);
    p256_scalar_mul_words(prod, aw, bw);
    p256_scalar_reduce_barrett_words(reduced, prod);
    p256_scalar_words_to_be(out, reduced);
}

/**
 * @brief Inverse a scalar modulo the order
 *
 * @param[out] out The output to inverse the scalar modulo the order into
 * @param[in] a The scalar to inverse from
 * @return The return code
 */
static noxtls_return_t p256_scalar_inv_mod(uint8_t out[32], const uint8_t a[32])
{
    uint32_t u[8];
    uint32_t v[8];
    uint32_t x1[8];
    uint32_t x2[8];
    uint8_t check[32];
    uint8_t one[32];
    uint32_t iter;
    const uint32_t max_iter = 4096u;

    memset(u, 0, sizeof(u));
    memset(v, 0, sizeof(v));
    memset(x1, 0, sizeof(x1));
    memset(x2, 0, sizeof(x2));
    memset(check, 0, sizeof(check));
    memset(one, 0, sizeof(one));

    p256_scalar_words_from_be(u, a);
    if(p256_scalar_cmp_words(u, s_p256_order_words, 8U) >= 0) {
        (void)p256_scalar_sub_words(u, u, s_p256_order_words, 8U);
    }
    if(p256_scalar_is_zero_words(u)) {
        return NOXTLS_RETURN_FAILED;
    }

    memcpy(v, s_p256_order_words, sizeof(v));
    x1[0] = 1U;

    for(iter = 0U; iter < max_iter; iter++) {
        while((u[0] & 1U) == 0U) {
            p256_scalar_rshift1_words(u);
            if((x1[0] & 1U) != 0U) {
                p256_scalar_add_order_and_rshift1_words(x1, x1);
            } else {
                p256_scalar_rshift1_words(x1);
            }
        }

        while((v[0] & 1U) == 0U) {
            p256_scalar_rshift1_words(v);
            if((x2[0] & 1U) != 0U) {
                p256_scalar_add_order_and_rshift1_words(x2, x2);
            } else {
                p256_scalar_rshift1_words(x2);
            }
        }

        if(p256_scalar_cmp_words(u, v, 8U) >= 0) {
            (void)p256_scalar_sub_words(u, u, v, 8U);
            p256_scalar_sub_mod_words(x1, x1, x2);
            if(p256_scalar_is_zero_words(u) || p256_scalar_is_one_words(u)) {
                break;
            }
        } else {
            (void)p256_scalar_sub_words(v, v, u, 8U);
            p256_scalar_sub_mod_words(x2, x2, x1);
            if(p256_scalar_is_zero_words(v) || p256_scalar_is_one_words(v)) {
                break;
            }
        }
    }

    if(p256_scalar_is_one_words(u)) {
        p256_scalar_words_to_be(out, x1);
    } else if(p256_scalar_is_one_words(v)) {
        p256_scalar_words_to_be(out, x2);
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    p256_scalar_mul_mod(check, a, out);
    one[31] = 0x01;
    if(memcmp(check, one, 32U) != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Helper function to hash a noxtls_message
 * 
 * @param hash Output hash
 * @param hash_len Length of the hash
 * @param noxtls_message Message to hash
 * @param message_len Length of the noxtls_message
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if hash is NULL
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecdsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_sha_ctx_t ctx;
    noxtls_sha512_ctx_t ctx512;
    
    if(hash == NULL || hash_len == NULL || noxtls_message == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(hash_algo) {
#if NOXTLS_FEATURE_MD5
        case NOXTLS_HASH_MD5:
            if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 16;
            break;
#endif
#if NOXTLS_FEATURE_SHA1
        case NOXTLS_HASH_SHA1:
            if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 20;
            break;
#endif
#if NOXTLS_FEATURE_SHA224
        case NOXTLS_HASH_SHA_224:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 28;
            break;
#endif
#if NOXTLS_FEATURE_SHA256
        case NOXTLS_HASH_SHA_256:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 32;
            break;
#endif
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
            if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_update(&ctx512, (uint8_t*)noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : 64;
            break;
#endif
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
 * @brief Modular inverse for prime modulus using Fermat: a^(p-2) mod p
 * 
 * @param result Result of the modular inverse
 * @param a Value to invert
 * @param mod Modulus
 * @param size Size of the modulus
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL
 */
static noxtls_return_t ecdsa_mod_inv_prime(uint8_t *result,
                                           const uint8_t *a,
                                           const uint8_t *mod,
                                           uint32_t size)
{
    uint8_t mod_minus_2[ECC_MAX_KEY_SIZE];
    uint8_t two[ECC_MAX_KEY_SIZE];
    uint8_t a_mod[ECC_MAX_KEY_SIZE];
    uint8_t prod[ECC_MAX_KEY_SIZE * 2];
    uint8_t check[ECC_MAX_KEY_SIZE];
    uint8_t one[ECC_MAX_KEY_SIZE];

    if(result == NULL || a == NULL || mod == NULL || size == 0) {
        return NOXTLS_RETURN_NULL;
    }
    if(size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    memset(mod_minus_2, 0, sizeof(mod_minus_2));
    memset(two, 0, sizeof(two));
    memset(a_mod, 0, sizeof(a_mod));
    memset(prod, 0, sizeof(prod));
    memset(check, 0, sizeof(check));
    memset(one, 0, sizeof(one));

    if(ecdsa_order_is_p256(mod, size)) {
        p256_scalar_reduce32(a_mod, a);
        if(noxtls_bn_is_zero(a_mod, size)) {
            return NOXTLS_RETURN_FAILED;
        }
        if(p256_scalar_inv_mod(result, a_mod) == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if(noxtls_bn_mod_inv(result, a_mod, size, mod, size) == NOXTLS_RETURN_SUCCESS) {
            p256_scalar_mul_mod(check, a_mod, result);
            one[31] = 0x01;
            if(memcmp(check, one, 32U) == 0) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        return NOXTLS_RETURN_FAILED;
    }

    /* a_mod = a mod p */
    if(noxtls_bn_cmp(a, mod, size) >= 0) {
        noxtls_bn_mod(a_mod, a, size, mod, size);
    } else {
        noxtls_bn_copy(a_mod, a, size);
    }
    if(noxtls_bn_is_zero(a_mod, size)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* mod_minus_2 = p - 2 */
    two[size - 1] = 0x02;
    one[size - 1] = 0x01;
    noxtls_bn_copy(mod_minus_2, mod, size);
    noxtls_bn_sub(mod_minus_2, mod_minus_2, two, size);

    /* Fast path: use generic modular inverse first. */
    if(noxtls_bn_mod_inv(result, a_mod, size, mod, size) == NOXTLS_RETURN_SUCCESS) {
        noxtls_bn_mul(prod, a_mod, size, result, size);
        noxtls_bn_mod(check, prod, size * 2U, mod, size);
        if(noxtls_bn_cmp(check, one, size) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* Fallback path: Fermat inverse for odd-prime orders. */
    noxtls_bn_mod_exp(result, a_mod, mod_minus_2, size, mod, size);
    noxtls_bn_mul(prod, a_mod, size, result, size);
    noxtls_bn_mod(check, prod, size * 2U, mod, size);
    if(noxtls_bn_cmp(check, one, size) != 0) {
        noxtls_return_t rc = noxtls_bn_mod_inv(result, a_mod, size, mod, size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_bn_mul(prod, a_mod, size, result, size);
        noxtls_bn_mod(check, prod, size * 2U, mod, size);
        if(noxtls_bn_cmp(check, one, size) != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize ECDSA signature structure
 * 
 * @param sig ECDSA signature structure
 * @param size Size of the signature
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if sig is NULL
 */
noxtls_return_t noxtls_ecdsa_signature_init(ecdsa_signature_t *sig, uint32_t size)
{
    if(sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    memset(sig->r, 0, ECC_MAX_KEY_SIZE);
    memset(sig->s, 0, ECC_MAX_KEY_SIZE);
    sig->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free ECDSA signature structure
 * 
 * @param sig ECDSA signature structure
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if sig is NULL
 */
noxtls_return_t noxtls_ecdsa_signature_free(ecdsa_signature_t *sig)
{
    if(sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    memset(sig->r, 0, ECC_MAX_KEY_SIZE);
    memset(sig->s, 0, ECC_MAX_KEY_SIZE);
    sig->size = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/* Minimal DER helpers for noxtls_ecdsa_signature_parse_der (no cert dependency) */
/**
 * @brief Get a length from a DER-encoded signature
 *
 * @param[in] p The pointer to the length to get from the DER-encoded signature
 * @param[in] e The end of the DER-encoded signature
 * @return The length of the length to get from the DER-encoded signature
 */
static uint32_t ecdsa_der_get_length(const uint8_t **p, const uint8_t *e)
{
    const uint8_t *q = *p;
    uint32_t len = 0;
    if(q >= e) return 0;
    if(*q & 0x80) {
        uint8_t n = *q & 0x7F;
        q++;
        if(n == 0 || n > 4 || q + n > e) return 0;
        for(; n; n--) len = (len << 8) | *q++;
    } else {
        len = *q & 0x7F;
        q++;
    }
    *p = q;
    return len;
}

/**
 * @brief Get a tag from a DER-encoded signature
 *
 * @param[in] p The pointer to the tag to get from the DER-encoded signature
 * @param[in] e The end of the DER-encoded signature
 * @param[in] expect The tag to expect
 * @return The return code
 */
static int ecdsa_der_get_tag(const uint8_t **p, const uint8_t *e, uint8_t expect)
{
    if(*p >= e || **p != expect) return -1;
    (*p)++;
    return 0;
}

/**
 * @brief Get an integer from a DER-encoded signature
 *
 * @param[in] p The pointer to the integer to get from the DER-encoded signature
 * @param[in] e The end of the DER-encoded signature
 * @param[out] buf The buffer to get the integer into
 * @param[in] buf_size The size of the buffer to get the integer into
 * @param[out] out_len The length of the integer to get from the DER-encoded signature
 * @return The return code
 */
static int ecdsa_der_get_integer(const uint8_t **p, const uint8_t *e, uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    if(*p >= e || *(*p)++ != 0x02) return -1;
    uint32_t len = ecdsa_der_get_length(p, e);
    if(len == 0 || *p + len > e || len > buf_size) return -1;
    *out_len = len;
    memcpy(buf, *p, len);
    *p += len;
    return 0;
}

/**
 * @brief Parse a DER-encoded ECDSA signature into fixed-width r and s (IEEE 1363 / X9.62 style layout).
 *
 * Expects ASN.1 SEQUENCE { r INTEGER, s INTEGER } as used in TLS and PKIX. Integers are normalized to
 * @p coord_size bytes each, big-endian, in @p out->r and @p out->s; @p out->size is set to @p coord_size.
 * Shorter INTEGER values are zero-padded on the left; longer values may be accepted only if leading
 * padding bytes are zero (otherwise BAD_DATA).
 *
 * @param[in] der DER-encoded signature bytes.
 * @param[in] der_len Length of @p der in bytes.
 * @param[out] out Receives r and s; any prior content is cleared.
 * @param[in] coord_size Field size in bytes for r and s (e.g. 32 for P-256, 48 for P-384); must be 1..ECC_MAX_KEY_SIZE.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if @p der or @p out is NULL, or @p coord_size is zero or larger than ECC_MAX_KEY_SIZE.
 * @return NOXTLS_RETURN_BAD_DATA if @p der is not a well-formed ECDSA signature SEQUENCE/INTEGERs or r/s do not fit @p coord_size.
 */
noxtls_return_t noxtls_ecdsa_signature_parse_der(const uint8_t *der, uint32_t der_len, ecdsa_signature_t *out, uint32_t coord_size)
{
    const uint8_t *ptr;
    const uint8_t *end;
    uint32_t seq_len;
    uint32_t r_len;
    uint32_t s_len;
    uint8_t r[ECC_MAX_KEY_SIZE];
    uint8_t s[ECC_MAX_KEY_SIZE];

    if(der == NULL || out == NULL || coord_size == 0 || coord_size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_NULL;
    }

    ptr = der;
    end = der + der_len;

    if(ptr >= end || ecdsa_der_get_tag(&ptr, end, 0x30) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    seq_len = ecdsa_der_get_length(&ptr, end);
    if(seq_len == 0 || (size_t)(end - ptr) < (size_t)seq_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        const uint8_t *seq_end = ptr + seq_len;
        if(ecdsa_der_get_integer(&ptr, seq_end, r, sizeof(r), &r_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(ecdsa_der_get_integer(&ptr, seq_end, s, sizeof(s), &s_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    memset(out, 0, sizeof(ecdsa_signature_t));
    out->size = coord_size;

    if(r_len <= coord_size) {
        memcpy(out->r + coord_size - r_len, r, r_len);
    } else {
        uint32_t skip = r_len - coord_size;
        uint32_t i;
        for(i = 0; i < skip; i++) {
            if(r[i] != 0) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        memcpy(out->r, r + skip, coord_size);
    }
    if(s_len <= coord_size) {
        memcpy(out->s + coord_size - s_len, s, s_len);
    } else {
        uint32_t skip = s_len - coord_size;
        uint32_t i;
        for(i = 0; i < skip; i++) {
            if(s[i] != 0) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        memcpy(out->s, s + skip, coord_size);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ECDSA Signature Generation
 * 
 * Algorithm:
 * 1. Hash the noxtls_message: h = HASH(noxtls_message)
 * 2. Generate random nonce k in [1, n-1]
 * 3. Compute (x, y) = k * G
 * 4. r = x mod n (if r == 0, go to step 2)
 * 5. s = k^-1 * (h + r * d) mod n (if s == 0, go to step 2)
 * 6. Signature is (r, s)
 *
 * @param key ECC key
 * @param noxtls_message Message to sign
 * @param message_len Length of the noxtls_message
 * @param signature ECDSA signature structure
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecdsa_sign(ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t hash_fast[64];
    uint8_t h_fast[ECC_MAX_KEY_SIZE];
    uint32_t hash_fast_len = 0;
    uint8_t *scratch = NULL;
    uint8_t *hash = NULL;
    uint8_t *k = NULL;
    uint8_t *k_inv = NULL;
    uint8_t *h = NULL;
    uint8_t *r_times_d = NULL;
    uint8_t *sum_tmp = NULL;
    uint8_t *h_plus_rd = NULL;
    uint8_t *s_product = NULL;  /* k_inv * h_plus_rd is 2*size bytes; must not write into signature->s */
    uint8_t *random_bytes = NULL;
    ecc_point_t kG;
    uint32_t size;
    uint32_t bits;
    uint32_t max_attempts = 100;
    uint32_t attempt;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint64_t sign_t0;
    uint64_t step_t0;
    
    if(key == NULL || noxtls_message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key->curve == NULL || key->d == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    size = key->curve->size;
    bits = size * 8;
    memset(hash_fast, 0, sizeof(hash_fast));
    memset(h_fast, 0, sizeof(h_fast));
    memset(&s_ecdsa_last_sign_timing, 0, sizeof(s_ecdsa_last_sign_timing));
    sign_t0 = ecdsa_profile_now_us();

    /* Step 1: hash once on stack so accelerator can bypass software allocations/loops. */
    step_t0 = ecdsa_profile_now_us();
    rc = ecdsa_hash_message(hash_fast, &hash_fast_len, noxtls_message, message_len, hash_algo);
    s_ecdsa_last_sign_timing.hash_prepare_us = ecdsa_profile_elapsed_us(step_t0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(hash_fast_len >= size) {
        memcpy(h_fast, hash_fast, size);
    } else {
        memcpy(h_fast + (size - hash_fast_len), hash_fast, hash_fast_len);
    }
    if(ecdsa_order_is_p256(key->curve->n, size)) {
        p256_scalar_reduce32(h_fast, h_fast);
    } else if(noxtls_bn_cmp(h_fast, key->curve->n, size) >= 0) {
        noxtls_bn_mod(h_fast, h_fast, size, key->curve->n, size);
    }

    /* Fast backend path (platform hook) before software math hot loop. */
    step_t0 = ecdsa_profile_now_us();
    rc = noxtls_ecdsa_sign_accel_port(key, h_fast, size, signature);
    s_ecdsa_last_sign_timing.accel_port_us = ecdsa_profile_elapsed_us(step_t0);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        s_ecdsa_last_sign_timing.total_us = ecdsa_profile_elapsed_us(sign_t0);
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Allocate one contiguous scratch block to reduce allocator overhead in hot path. */
    {
        const size_t scratch_len = 64U + ((size_t)size * 10U) + 2U;
        uint8_t *p;
        scratch = (uint8_t*)noxtls_calloc(scratch_len, 1);
        if(!scratch) {
            rc = NOXTLS_RETURN_FAILED;
            goto cleanup;
        }
        p = scratch;
        hash = p; p += 64U;
        k = p; p += size;
        k_inv = p; p += size;
        h = p; p += size;
        r_times_d = p; p += (size * 2U);
        sum_tmp = p; p += (size + 1U);
        /* h + r*d can be up to 2n-2, so we need size+1 bytes to avoid dropping carry in add */
        h_plus_rd = p; p += (size + 1U);
        s_product = p; p += (size * 2U);
        random_bytes = p;
    }

    if(!hash || !k || !k_inv || !h || !r_times_d || !sum_tmp || !h_plus_rd || !s_product || !random_bytes) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }

    /* Initialize signature structure */
    noxtls_ecc_point_init(&kG, size);
    memcpy(hash, hash_fast, sizeof(hash_fast));
    memcpy(h, h_fast, size);
    rc = NOXTLS_RETURN_SUCCESS;

    /* Step 2-5: Generate signature with retry if r or s is zero */
    for(attempt = 0; attempt < max_attempts; attempt++) {
        s_ecdsa_last_sign_timing.attempts = attempt + 1U;
        /* Step 2: Generate random nonce k in [1, n-1] */
        do {
            step_t0 = ecdsa_profile_now_us();
            rc = ecdsa_drbg_generate_bits(random_bytes, bits);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup;
            }

            /* Reduce mod n */
            if(ecdsa_order_is_p256(key->curve->n, size)) {
                p256_scalar_reduce32(k, random_bytes);
            } else {
                noxtls_bn_mod(k, random_bytes, size, key->curve->n, size);
            }
            s_ecdsa_last_sign_timing.nonce_generate_us += ecdsa_profile_elapsed_us(step_t0);

            /* Ensure k is not zero */
        } while(noxtls_bn_is_zero(k, size));

        /* Step 3: Compute (x, y) = k * G */
        step_t0 = ecdsa_profile_now_us();
        rc = noxtls_ecc_point_multiply(&kG, k, &key->curve->G, key->curve);
        s_ecdsa_last_sign_timing.base_point_mul_us += ecdsa_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
            
        /* Step 4: r = x mod n */
        step_t0 = ecdsa_profile_now_us();
        if(ecdsa_order_is_p256(key->curve->n, size)) {
            p256_scalar_reduce32(signature->r, kG.x);
        } else {
            noxtls_bn_mod(signature->r, kG.x, size, key->curve->n, size);
        }
        s_ecdsa_last_sign_timing.r_reduce_us += ecdsa_profile_elapsed_us(step_t0);

        /* If r == 0, retry */
        if(noxtls_bn_is_zero(signature->r, size)) {
            continue;
        }

        /* Step 5: s = k^-1 * (h + r * d) mod n */
        /* Compute k^-1 mod n */
        step_t0 = ecdsa_profile_now_us();
        rc = ecdsa_mod_inv_prime(k_inv, k, key->curve->n, size);
        s_ecdsa_last_sign_timing.nonce_inv_us += ecdsa_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            continue;
        }

        /* Compute r * d */
        step_t0 = ecdsa_profile_now_us();
        if(ecdsa_order_is_p256(key->curve->n, size)) {
            p256_scalar_mul_mod(r_times_d, signature->r, key->d);
            p256_scalar_add_mod(h_plus_rd, h, r_times_d);
            p256_scalar_mul_mod(signature->s, k_inv, h_plus_rd);
        } else {
            noxtls_bn_mul(r_times_d, signature->r, size, key->d, size);
            noxtls_bn_mod(r_times_d, r_times_d, size * 2, key->curve->n, size);

            /* Compute h + r * d with carry (can be size+1 bytes); then reduce mod n */
            {
                uint16_t carry = 0;
                uint32_t i;
                memset(sum_tmp, 0, size + 1U);
                for(i = 0; i < size; i++) {
                    uint32_t idx = size - 1 - i;
                    uint16_t sum = (uint16_t)h[idx] + (uint16_t)r_times_d[idx] + carry;
                    sum_tmp[idx + 1] = (uint8_t)(sum & 0xFF);
                    carry = sum >> 8;
                }
                sum_tmp[0] = (uint8_t)carry;
                {
                    uint32_t len = carry ? (size + 1) : size;
                    const uint8_t *src = carry ? sum_tmp : (sum_tmp + 1U);
                    noxtls_bn_mod(h_plus_rd, src, len, key->curve->n, size);
                }
            }

            /* Compute s = k^-1 * (h + r * d) mod n (product is 2*size bytes; use temp to avoid overwriting sig->size) */
            noxtls_bn_mul(s_product, k_inv, size, h_plus_rd, size);
            noxtls_bn_mod(signature->s, s_product, size * 2, key->curve->n, size);
        }
        s_ecdsa_last_sign_timing.s_compute_us += ecdsa_profile_elapsed_us(step_t0);

        /* If s == 0, retry */
        if(noxtls_bn_is_zero(signature->s, size)) {
            continue;
        }

#if NOXTLS_ECDSA_SIGN_SELF_VERIFY
        /* Optional sign-time verification hardening against faulted signatures. */
        {
            step_t0 = ecdsa_profile_now_us();
            noxtls_return_t verify_rc = noxtls_ecdsa_verify(key, noxtls_message, message_len, signature, hash_algo);
            s_ecdsa_last_sign_timing.self_verify_us += ecdsa_profile_elapsed_us(step_t0);
            if(verify_rc != NOXTLS_RETURN_SUCCESS) {
                continue;
            }
        }
#endif

        /* Success! */
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Failed after max attempts */
        rc = NOXTLS_RETURN_FAILED;
    }

cleanup:
    if(scratch) noxtls_free(scratch);
    s_ecdsa_last_sign_timing.total_us = ecdsa_profile_elapsed_us(sign_t0);
    
    return rc;
}

/**
 * @brief ECDSA Signature Verification
 * 
 * Algorithm:
 * 1. Verify r and s are in [1, n-1]
 * 2. Hash the noxtls_message: h = HASH(noxtls_message)
 * 3. u1 = s^-1 * h mod n
 * 4. u2 = s^-1 * r mod n
 * 5. Compute (x, y) = u1 * G + u2 * Q
 * 6. v = x mod n
 * 7. Accept if v == r
 *
 * @param key ECC key
 * @param noxtls_message Message to verify
 * @param message_len Length of the noxtls_message
 * @param signature ECDSA signature structure
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecdsa_verify(ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t hash_fast[64];
    uint8_t h_fast[ECC_MAX_KEY_SIZE];
    uint32_t hash_fast_len = 0;
    uint8_t *scratch = NULL;
    uint8_t *hash = NULL;
    uint8_t *h = NULL;
    uint8_t *s_inv = NULL;
    uint8_t *u1 = NULL;
    uint8_t *u2 = NULL;
    ecc_point_t u1G;
    ecc_point_t u2Q;
    ecc_point_t result;  /* keep on stack: single output point */
    uint8_t *v = NULL;
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(key == NULL || noxtls_message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key->curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_ecc_point_validate_public(&key->Q, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    size = key->curve->size;
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    printf("[ecdsa_verify] size=%u message_len=%u\n", (unsigned)size, (unsigned)message_len);
    fflush(stdout);
#endif

    /* Step 1: Verify r and s are in [1, n-1] */
    if(noxtls_bn_is_zero(signature->r, size) ||
       noxtls_bn_cmp(signature->r, key->curve->n, size) >= 0) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    if(noxtls_bn_is_zero(signature->s, size) ||
       noxtls_bn_cmp(signature->s, key->curve->n, size) >= 0) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    memset(hash_fast, 0, sizeof(hash_fast));
    memset(h_fast, 0, sizeof(h_fast));
    /* Step 2: Hash on stack first so accel path can avoid software allocations. */
    rc = ecdsa_hash_message(hash_fast, &hash_fast_len, noxtls_message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(hash_fast_len >= size) {
        memcpy(h_fast, hash_fast, size);
    } else {
        memcpy(h_fast + (size - hash_fast_len), hash_fast, hash_fast_len);
    }
    if(ecdsa_order_is_p256(key->curve->n, size)) {
        p256_scalar_reduce32(h_fast, h_fast);
    } else if(noxtls_bn_cmp(h_fast, key->curve->n, size) >= 0) {
        noxtls_bn_mod(h_fast, h_fast, size, key->curve->n, size);
    }

    /* Fast backend path (platform hook) before software verification math. */
    rc = noxtls_ecdsa_verify_accel_port(key, h_fast, size, signature);
    if(rc == NOXTLS_RETURN_SUCCESS || rc == NOXTLS_RETURN_FAILED) {
        return rc;
    }

    /* Allocate one contiguous scratch block to reduce allocator overhead in software path. */
    {
        const size_t scratch_len = 64U + ((size_t)size * 7U);
        uint8_t *p;
        scratch = (uint8_t*)noxtls_calloc(scratch_len, 1);
        if(!scratch) {
            rc = NOXTLS_RETURN_FAILED;
            goto cleanup_verify;
        }
        p = scratch;
        hash = p; p += 64U;
        h = p; p += size;
        s_inv = p; p += size;
        /* u1, u2 hold mul result (2*size bytes) before bn_mod; after mod, size-byte value in first bytes */
        u1 = p; p += (size * 2U);
        u2 = p; p += (size * 2U);
        v = p;
    }

    if(!hash || !h || !s_inv || !u1 || !u2 || !v) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    noxtls_ecc_point_init(&u1G, size);
    noxtls_ecc_point_init(&u2Q, size);
    noxtls_ecc_point_init(&result, size);
    memcpy(hash, hash_fast, sizeof(hash_fast));
    memcpy(h, h_fast, size);
    rc = NOXTLS_RETURN_SUCCESS;

#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    printf("[ecdsa_verify] hash_len=%u\n", (unsigned)hash_fast_len);
    fflush(stdout);
    ecdsa_debug_hex("h", h, size);
    ecdsa_debug_hex("signature->r", signature->r, size);
    ecdsa_debug_hex("signature->s", signature->s, size);
#endif

    /* Step 3: u1 = s^-1 * h mod n.
     * P-256 has a dedicated scalar inverse path that avoids the slower generic
     * big-number inverse used for larger/generic curves. */
    if(ecdsa_order_is_p256(key->curve->n, size)) {
        rc = ecdsa_mod_inv_prime(s_inv, signature->s, key->curve->n, size);
    } else {
        rc = noxtls_bn_mod_inv(s_inv, signature->s, size, key->curve->n, size);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }
    if(ecdsa_order_is_p256(key->curve->n, size)) {
        p256_scalar_mul_mod(u1, s_inv, h);
        p256_scalar_mul_mod(u2, s_inv, signature->r);
    } else {
        /* Mod into v (not in-place on the 2*size product) to match reference verify paths. */
        noxtls_bn_mul(u1, s_inv, size, h, size);
        noxtls_bn_mod(v, u1, size * 2, key->curve->n, size);
        memcpy(u1, v, size);

        /* Step 4: u2 = s^-1 * r mod n */
        noxtls_bn_mul(u2, s_inv, size, signature->r, size);
        noxtls_bn_mod(v, u2, size * 2, key->curve->n, size);
        memcpy(u2, v, size);
    }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("s_inv", s_inv, size);
    ecdsa_debug_hex("u1", u1, size);
    ecdsa_debug_hex("u2", u2, size);
#endif

    /* Step 5: Compute (x, y) = u1 * G + u2 * Q */
    if(size == 32U) {
        int use_hw_mul_path = 0;
#if defined(ESP_PLATFORM)
        use_hw_mul_path = noxtls_esp_hw_ecc_compiled_in();
#endif

        if(!use_hw_mul_path) {
            rc = noxtls_ecc_point_muladd(&result, u1, &key->curve->G, u2, &key->Q, key->curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup_verify;
            }
        } else {
        /*
         * Use two scalar multiplies plus one point add for P-256 verify.
         *
         * This keeps the path compatible with the platform point-multiply hook
         * (ESP ECC acceleration) and avoids depending on the software-only
         * muladd fast path for signature verification.
         */
        rc = noxtls_ecc_point_multiply(&u1G, u1, &key->curve->G, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }

        rc = noxtls_ecc_point_multiply(&u2Q, u2, &key->Q, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }

        rc = noxtls_ecc_point_add(&result, &u1G, &u2Q, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }
        }
    } else {
        rc = noxtls_ecc_point_multiply(&u1G, u1, &key->curve->G, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }

        rc = noxtls_ecc_point_multiply(&u2Q, u2, &key->Q, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }

        rc = noxtls_ecc_point_add(&result, &u1G, &u2Q, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup_verify;
        }
    }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("u1G.x", u1G.x, size);
    ecdsa_debug_hex("u1G.y", u1G.y, size);
    ecdsa_debug_hex("u2Q.x", u2Q.x, size);
    ecdsa_debug_hex("u2Q.y", u2Q.y, size);
    ecdsa_debug_hex("result.x", result.x, size);
    ecdsa_debug_hex("result.y", result.y, size);
#endif

    /* Step 6: v = x mod n */
    if(ecdsa_order_is_p256(key->curve->n, size)) {
        p256_scalar_reduce32(v, result.x);
    } else {
        noxtls_bn_mod(v, result.x, size, key->curve->n, size);
    }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("result.x (before mod n)", result.x, size);
    ecdsa_debug_hex("v", v, size);
    ecdsa_debug_hex("signature->r (compare)", signature->r, size);
    printf("[ecdsa_verify] v %s r (cmp=%d)\n",
           noxtls_bn_cmp(v, signature->r, size) == 0 ? "==" : "!=",
           noxtls_bn_cmp(v, signature->r, size));
    fflush(stdout);
#endif

    /* Step 7: Accept if v == r */
    if(noxtls_bn_cmp(v, signature->r, size) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    } else {
        rc = NOXTLS_RETURN_FAILED;
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
        {
            uint32_t i;
            uint8_t u1_plus_u2_buf[ECC_MAX_KEY_SIZE + 1];
            uint8_t u1_plus_u2_mod_n_buf[ECC_MAX_KEY_SIZE];
            uint8_t s_times_s_inv[ECC_MAX_KEY_SIZE * 2];
            uint8_t s_times_s_inv_mod_n[ECC_MAX_KEY_SIZE];
            uint16_t carry = 0;
            memset(u1_plus_u2_buf, 0, sizeof(u1_plus_u2_buf));
            memset(u1_plus_u2_mod_n_buf, 0, sizeof(u1_plus_u2_mod_n_buf));
            memset(s_times_s_inv, 0, sizeof(s_times_s_inv));
            memset(s_times_s_inv_mod_n, 0, sizeof(s_times_s_inv_mod_n));
            noxtls_bn_mul(s_times_s_inv, signature->s, size, s_inv, size);
            noxtls_bn_mod(s_times_s_inv_mod_n, s_times_s_inv, size * 2, key->curve->n, size);
            for(i = size; i > 0; i--) {
                uint16_t sum = (uint16_t)u1[i-1] + (uint16_t)u2[i-1] + carry;
                u1_plus_u2_buf[i] = (uint8_t)(sum & 0xFF);
                carry = sum >> 8;
            }
            u1_plus_u2_buf[0] = (uint8_t)carry;
            noxtls_bn_mod(u1_plus_u2_mod_n_buf, carry ? u1_plus_u2_buf : (u1_plus_u2_buf + 1), carry ? (size + 1) : size, key->curve->n, size);
            printf("[ecdsa_verify] FAILED v != r (size=%u)\n", (unsigned)size);
            printf("  s*s_inv mod n= ");
            for(i = 0; i < size; i++) printf("%02X", s_times_s_inv_mod_n[i]);
            printf("  (expect 00...01)\n");
            printf("  h            = ");
            for(i = 0; i < size; i++) printf("%02X", h[i]);
            printf("\n  signature->r = ");
            for(i = 0; i < size; i++) printf("%02X", signature->r[i]);
            printf("\n  signature->s = ");
            for(i = 0; i < size; i++) printf("%02X", signature->s[i]);
            printf("\n  s_inv        = ");
            for(i = 0; i < size; i++) printf("%02X", s_inv[i]);
            printf("\n  u1           = ");
            for(i = 0; i < size; i++) printf("%02X", u1[i]);
            printf("\n  u2           = ");
            for(i = 0; i < size; i++) printf("%02X", u2[i]);
            printf("\n  (u1+u2) mod n = ");
            for(i = 0; i < size; i++) printf("%02X", u1_plus_u2_mod_n_buf[i]);
            printf("  (expect 00...01 when u1+u2=1)\n");
            printf("  u1G.x        = ");
            for(i = 0; i < size; i++) printf("%02X", u1G.x[i]);
            printf("\n  u2Q.x        = ");
            for(i = 0; i < size; i++) printf("%02X", u2Q.x[i]);
            printf("\n  result.x     = ");
            for(i = 0; i < size; i++) printf("%02X", result.x[i]);
            printf("\n  v            = ");
            for(i = 0; i < size; i++) printf("%02X", v[i]);
            printf("\n");
            fflush(stdout);
        }
        {
            uint32_t i;
            printf("[ecdsa_verify] FAILED: v != r\n  v = ");
            for(i = 0; i < size; i++) printf("%02X", v[i]);
            printf("\n  r = ");
            for(i = 0; i < size; i++) printf("%02X", signature->r[i]);
            printf("\n");
            fflush(stdout);
        }
#endif
    }

cleanup_verify:
    if(scratch) noxtls_free(scratch);

    return rc;
}
