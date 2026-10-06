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
#include <string.h>
#include "common/noxtls_debug_printf.h"

#ifndef NOXTLS_ECDSA_PROFILE
#define NOXTLS_ECDSA_PROFILE 0
#endif
#if NOXTLS_ECDSA_PROFILE
#if defined(__has_include) && defined(ESP_PLATFORM) && __has_include("esp_timer.h")
#include "esp_timer.h"

#else
#include <time.h>
#endif
#endif

#include "common/noxtls_memory.h"
#include "noxtls_ct.h"
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
#ifdef ESP_PLATFORM
#include "noxtls_esp_hw_crypto.h"
#endif
#ifdef __has_include
#if defined(ESP_PLATFORM) && __has_include("esp_timer.h")
#include "esp_timer.h"
#endif
#endif

#ifndef NOXTLS_ECDSA_SIGN_SELF_VERIFY
#define NOXTLS_ECDSA_SIGN_SELF_VERIFY 0
#endif

#if NOXTLS_FEATURE_AES_256
#define NOXTLS_ECDSA_DRBG_TYPE     DRBG_AES256
#define NOXTLS_ECDSA_DRBG_SEEDLEN  DRBG_SEEDLEN_AES256
#else
/* P-256 ECDSA has a 128-bit security level, so the nRF52 AES-128 ECB
 * backend is sufficient when the size-constrained target excludes AES-256. */
#define NOXTLS_ECDSA_DRBG_TYPE     DRBG_AES128
#define NOXTLS_ECDSA_DRBG_SEEDLEN  DRBG_SEEDLEN_AES128
#endif


/**
 * @brief Bytes remaining between cursor and one-past-end (same object).
 */
static uint32_t ecdsa_shift_right(uint32_t value, uint32_t count)
{
    uint32_t result = 0U;
    switch(count) {
    case 0U: result = value >> 0U; break;
    case 1U: result = value >> 1U; break;
    case 2U: result = value >> 2U; break;
    case 3U: result = value >> 3U; break;
    case 4U: result = value >> 4U; break;
    case 5U: result = value >> 5U; break;
    case 6U: result = value >> 6U; break;
    case 7U: result = value >> 7U; break;
    case 8U: result = value >> 8U; break;
    case 9U: result = value >> 9U; break;
    case 10U: result = value >> 10U; break;
    case 11U: result = value >> 11U; break;
    case 12U: result = value >> 12U; break;
    case 13U: result = value >> 13U; break;
    case 14U: result = value >> 14U; break;
    case 15U: result = value >> 15U; break;
    case 16U: result = value >> 16U; break;
    case 17U: result = value >> 17U; break;
    case 18U: result = value >> 18U; break;
    case 19U: result = value >> 19U; break;
    case 20U: result = value >> 20U; break;
    case 21U: result = value >> 21U; break;
    case 22U: result = value >> 22U; break;
    case 23U: result = value >> 23U; break;
    case 24U: result = value >> 24U; break;
    case 25U: result = value >> 25U; break;
    case 26U: result = value >> 26U; break;
    case 27U: result = value >> 27U; break;
    case 28U: result = value >> 28U; break;
    case 29U: result = value >> 29U; break;
    case 30U: result = value >> 30U; break;
    case 31U: result = value >> 31U; break;
    default: result = 0U; break;
    }
    return result;
}

static size_t ecdsa_bytes_remaining(const uint8_t *ptr, const uint8_t *end)
{
    uintptr_t start_addr;
    uintptr_t end_addr;
    if((ptr == NULL) || (end == NULL)) {
        return 0U;
    }
    start_addr = (uintptr_t)ptr;
    end_addr = (uintptr_t)end;
    if(start_addr > end_addr) {
        return 0U;
    }
    return (size_t)(end_addr - start_addr);
}

static const uint32_t ecdsa_s_p256_order_words[8] = {
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
};

static noxtls_ecdsa_sign_timing_t s_ecdsa_last_sign_timing;

/* Retained for on-target commissioning diagnostics.  These describe the
 * last signer invocation without involving the radio/controller path. */
volatile int32_t noxtls_ecdsa_sign_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecdsa_sign_last_stage = 0U;

#ifdef NOXTLS_ECDSA_VERIFY_DEBUG



/**
 * @brief Print a hex string
 *
 * @param[in] label The label to print the hex string from
 * @param[in] buf The buffer to print the hex string from
 * @param[in] len The length of the buffer to print the hex string from
 * @return void
 */
static void ecdsa_debug_hex(const uint8_t *label, const uint8_t *buf, uint32_t len)
{
    uint32_t i = 0U;
    (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] %s (%u bytes): ", label, (uint32_t)len);
    if (buf != NULL) {
        for (i = 0U; i < len; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02X", buf[i]);
        }
    } else {
        (void)noxtls_debug_printf((const uint8_t *)"(null)");
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}
#endif

/**
 * @brief Get the current time in microseconds
 *
 * @return The current time in microseconds
 */
static uint64_t ecdsa_profile_now_us(void)
{
#if !NOXTLS_ECDSA_PROFILE
    return 0U;
#elif defined(__has_include) && defined(ESP_PLATFORM) && __has_include("esp_timer.h")
    return (uint64_t)esp_timer_get_time();
#else
    clock_t now = clock();

    if (now <= (clock_t)0) {
        return 0U;
    }
    return ((uint64_t)now * 1000000U) / (uint64_t)CLOCKS_PER_SEC;
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
    uint64_t now_us = (uint64_t)(ecdsa_profile_now_us());

    if (now_us < start_us) {
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
    uint8_t seed[NOXTLS_ECDSA_DRBG_SEEDLEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if (out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if (s_ecdsa_drbg_initialized == 0) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = drbg_instantiate(&s_ecdsa_drbg_state, NOXTLS_ECDSA_DRBG_TYPE,
                              seed, sizeof(seed), NULL, 0, NULL, 0);
        noxtls_secure_zero(seed, sizeof(seed));
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_drbg_uninstantiate(&s_ecdsa_drbg_state);
            return rc;
        }
        s_ecdsa_drbg_initialized = 1;
    }

    rc = drbg_generate(&s_ecdsa_drbg_state, out, requested_bits, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* Fail closed for this call and drop the instance: a failed generate
         * may have wiped the state, so the next call re-instantiates from
         * fresh entropy instead of failing forever. */
        (void)noxtls_drbg_uninstantiate(&s_ecdsa_drbg_state);
        s_ecdsa_drbg_initialized = 0;
        noxtls_secure_zero(out, (size_t)((requested_bits + 7U) / 8U));
    }
    return rc;
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
    static const uint8_t s_p256_order_be[32] = {
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
        0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U,
        0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
    };
    if(mod == NULL) {
        return 0;
    }
    if(size != 32U) {
        return 0;
    }
    if(noxtls_ct_equal(mod, s_p256_order_be, (size_t)32U) == 0) {
        return 0;
    }
    return 1;
}

/**
 * @brief Convert words from big endian to little endian
 *
 * @param[out] out The output to convert the words from big endian to little endian into
 * @param[in] in The input to convert the words from big endian to little endian from
 * @return void
 */
static void p256_scalar_words_from_be(uint32_t *out, const uint8_t *in)
{
    uint32_t i = 0U;

    for (i = 0U; i < 8U; i += 1U) {
        uint32_t off = (uint32_t)(32U - ((i + 1U) * 4U));
        out[i] = (((uint32_t)in[off]) << 24U) |
                 (((uint32_t)in[off + 1U]) << 16U) |
                 (((uint32_t)in[off + 2U]) << 8U) |
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
static void p256_scalar_words_to_be(uint8_t *out, const uint32_t *in)
{
    uint32_t i = 0U;

    for (i = 0U; i < 8U; i += 1U) {
        uint32_t w = (uint32_t)(in[i]);
        uint32_t off = (uint32_t)(32U - ((i + 1U) * 4U));
        out[off] = (uint8_t)(w >> 24U);
        out[off + 1U] = (uint8_t)(w >> 16U);
        out[off + 2U] = (uint8_t)(w >> 8U);
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
    uint32_t i = 0U;

    for (i = len; i > 0U; i -= 1U) {
        if (a[i - 1U] > b[i - 1U]) {
            return 1;
        }
        if (a[i - 1U] < b[i - 1U]) {
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
static int p256_scalar_is_zero_words(const uint32_t *a)
{
    uint32_t i = 0U;
    uint32_t acc = 0U;

    for (i = 0U; i < 8U; i += 1U) {
        acc |= a[i];
    }

    return (acc == 0U) ? 1 : 0;
}

/**
 * @brief Check if the scalar is one
 *
 * @param[in] a The scalar to check if the scalar is one from
 * @return 1 if the scalar is one, 0 otherwise
 */
static int p256_scalar_is_one_words(const uint32_t *a)
{
    return ((a[0] == 1U) &&
            (a[1] == 0U) &&
            (a[2] == 0U) &&
            (a[3] == 0U) &&
            (a[4] == 0U) &&
            (a[5] == 0U) &&
            (a[6] == 0U) &&
            (a[7] == 0U)) ? 1 : 0;
}

/**
 * @brief Right shift a scalar by 1
 *
 * @param[in] a The scalar to right shift by 1 from
 * @return void
 */
static void p256_scalar_rshift1_words(uint32_t *a)
{
    uint32_t i = 0U;
    uint32_t carry = 0U;

    for (i = 8U; i > 0U; i -= 1U) {
        uint32_t w = (uint32_t)(a[i - 1U]);
        a[i - 1U] = (w >> 1U) | (carry << 31U);
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
    uint32_t i = 0U;

    for (i = 0U; i < len; i += 1U) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if (ai < bi) {
            out[i] = (uint32_t)(ai + (1ULL << 32U) - bi);
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
static void p256_scalar_sub_mod_words(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    if (p256_scalar_cmp_words(a, b, 8U) >= 0) {
        (void)p256_scalar_sub_words(out, a, b, 8U);
    } else {
        uint32_t diff[8];
        (void)p256_scalar_sub_words(diff, b, a, 8U);
        (void)p256_scalar_sub_words(out, ecdsa_s_p256_order_words, diff, 8U);
    }
}

/**
 * @brief Add the order and right shift a scalar by 1
 *
 * @param[out] out The output to add the order and right shift a scalar by 1 into
 * @param[in] in The scalar to add the order and right shift a scalar by 1 from
 * @return void
 */
static void p256_scalar_add_order_and_rshift1_words(uint32_t *out, const uint32_t *in)
{
    uint32_t sum[8];
    uint32_t i = 0U;
    uint32_t carry_word = 0U;
    uint64_t carry = 0U;

    for (i = 0U; i < 8U; i += 1U) {
        uint64_t t = (uint64_t)in[i] + (uint64_t)ecdsa_s_p256_order_words[i] + carry;
        sum[i] = (uint32_t)t;
        carry = (uint32_t)(t >> 32U);
    }

    carry_word = (uint32_t)carry;
    for (i = 8U; i > 0U; i -= 1U) {
        uint32_t w = (uint32_t)(sum[i - 1U]);
        out[i - 1U] = (w >> 1U) | (carry_word << 31U);
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
static void p256_scalar_mul_words(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t k = 0U;

    noxtls_secure_zero((out), ((size_t)(16U * (sizeof(uint32_t)))));
    for (i = 0U; i < 8U; i += 1U) {
        uint64_t carry = 0U;
        for (j = 0U; j < 8U; j += 1U) {
            uint64_t t = (uint64_t)out[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            out[i + j] = (uint32_t)t;
            carry = (uint32_t)(t >> 32U);
        }
        k = i + 8U;
        while ((carry != 0U) && (k < 16U)) {
            uint64_t t = (uint64_t)out[k] + carry;
            out[k] = (uint32_t)t;
            carry = (uint32_t)(t >> 32U);
            k += 1U;
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
static void p256_scalar_reduce_barrett_words(uint32_t *out, const uint32_t *in)
{
    uint32_t remainder[9];
    uint32_t n9[9];
    uint32_t word_index;

    noxtls_secure_zero(remainder, (size_t)(sizeof(remainder)));
    noxtls_secure_zero(n9, (size_t)(sizeof(n9)));
    noxtls_copy_u8((uint8_t *)(void *)(n9), (size_t)(8U * sizeof(uint32_t)), (const uint8_t *)(const void *)(ecdsa_s_p256_order_words), (size_t)(8U * sizeof(uint32_t)));

    for(word_index = 16U; word_index > 0U; --word_index) {
        uint32_t bit_index;
        uint32_t word = in[word_index - 1U];

        for(bit_index = 32U; bit_index > 0U; --bit_index) {
            uint32_t limb_index;
            uint32_t carry = ecdsa_shift_right(word, bit_index - 1U) & 1U;

            for(limb_index = 0U; limb_index < 9U; ++limb_index) {
                uint32_t next_carry = remainder[limb_index] >> 31;
                remainder[limb_index] = (remainder[limb_index] << 1) | carry;
                carry = next_carry;
            }
            if(p256_scalar_cmp_words(remainder, n9, 9U) >= 0) {
                (void)p256_scalar_sub_words(remainder, remainder, n9, 9U);
            }
        }
    }
    noxtls_copy_u8((uint8_t *)(void *)(out), (size_t)(8U * sizeof(uint32_t)), (const uint8_t *)(const void *)(remainder), (size_t)(8U * sizeof(uint32_t)));
}

/**
 * @brief Reduce a 32-bit scalar
 *
 * @param[out] out The output to reduce the 32-bit scalar into
 * @param[in] in The 32-bit scalar to reduce from
 * @return void
 */
static void p256_scalar_reduce32(uint8_t *out, const uint8_t *in)
{
    uint32_t words[8];

    (void)p256_scalar_words_from_be(words, in);
    if (p256_scalar_cmp_words(words, ecdsa_s_p256_order_words, 8U) >= 0) {
        (void)p256_scalar_sub_words(words, words, ecdsa_s_p256_order_words, 8U);
    }
    (void)p256_scalar_words_to_be(out, words);
}

/**
 * @brief Add two scalars modulo the order
 *
 * @param[out] out The output to add the two scalars modulo the order into
 * @param[in] a The first scalar to add
 * @param[in] b The second scalar to add
 * @return void
 */
static void p256_scalar_add_mod(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t sum[9];
    uint32_t n9[9];
    uint64_t carry = 0U;
    uint32_t i = 0U;

    p256_scalar_words_from_be(aw, a);
    p256_scalar_words_from_be(bw, b);
    noxtls_secure_zero(sum, (size_t)(sizeof(sum)));
    noxtls_secure_zero(n9, (size_t)(sizeof(n9)));
    noxtls_copy_u8((uint8_t *)(void *)(n9), (size_t)(sizeof(aw)), (const uint8_t *)(const void *)(ecdsa_s_p256_order_words), (size_t)(sizeof(aw)));
    for(i = 0; i < 8U; i++) {
        uint64_t t = (uint64_t)aw[i] + (uint64_t)bw[i] + carry;
        sum[i] = (uint32_t)t;
        carry = (uint32_t)(t >> 32U);
    }
    sum[8] = (uint32_t)carry;
    if(p256_scalar_cmp_words(sum, n9, 9U) >= 0) {
        (void)p256_scalar_sub_words(sum, sum, n9, 9U);
    }
    (void)p256_scalar_words_to_be(out, sum);
}

/**
 * @brief Multiply two scalars modulo the order
 *
 * @param[out] out The output to multiply the two scalars modulo the order into
 * @param[in] a The first scalar to multiply
 * @param[in] b The second scalar to multiply
 * @return void
 */
static void p256_scalar_mul_mod(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t prod[16];
    uint32_t reduced[8];

    (void)p256_scalar_words_from_be(aw, a);
    (void)p256_scalar_words_from_be(bw, b);
    p256_scalar_mul_words(prod, aw, bw);
    p256_scalar_reduce_barrett_words(reduced, prod);
    (void)p256_scalar_words_to_be(out, reduced);
}

/**
 * @brief Inverse a scalar modulo the order
 *
 * @param[out] out The output to inverse the scalar modulo the order into
 * @param[in] a The scalar to inverse from
 * @return The return code
 */
static noxtls_return_t p256_scalar_inv_mod(uint8_t *out, const uint8_t *a)
{
    uint32_t u[8];
    uint32_t v[8];
    uint32_t x1[8];
    uint32_t x2[8];
    uint8_t check[32];
    uint8_t one[32];
    uint32_t iter = 0U;
    const uint32_t max_iter = 4096U;

    noxtls_secure_zero((u), sizeof(u));
    noxtls_secure_zero((v), sizeof(v));
    noxtls_secure_zero((x1), sizeof(x1));
    noxtls_secure_zero((x2), sizeof(x2));
    noxtls_secure_zero((check), sizeof(check));
    noxtls_secure_zero((one), sizeof(one));

    (void)p256_scalar_words_from_be(u, a);
    if (p256_scalar_cmp_words(u, ecdsa_s_p256_order_words, 8U) >= 0) {
        (void)p256_scalar_sub_words(u, u, ecdsa_s_p256_order_words, 8U);
    }
    if (p256_scalar_is_zero_words(u) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_copy_u8((uint8_t *)(void *)v, sizeof(v), (const uint8_t *)(const void *)ecdsa_s_p256_order_words, sizeof(v));
    x1[0] = 1U;

    uint8_t done = 0U;
    for (iter = 0U; iter < max_iter; iter += 1U) {
        while ((u[0] & 1U) == 0U) {
            (void)p256_scalar_rshift1_words(u);
            if ((x1[0] & 1U) != 0U) {
                p256_scalar_add_order_and_rshift1_words(x1, x1);
            } else {
                (void)p256_scalar_rshift1_words(x1);
            }
        }

        while ((v[0] & 1U) == 0U) {
            (void)p256_scalar_rshift1_words(v);
            if ((x2[0] & 1U) != 0U) {
                p256_scalar_add_order_and_rshift1_words(x2, x2);
            } else {
                (void)p256_scalar_rshift1_words(x2);
            }
        }

        if (p256_scalar_cmp_words(u, v, 8U) >= 0) {
            (void)p256_scalar_sub_words(u, u, v, 8U);
            (void)p256_scalar_sub_mod_words(x1, x1, x2);
            if ((p256_scalar_is_zero_words(u) != 0) || (p256_scalar_is_one_words(u) != 0)) {
                done = 1U;
            }
        } else {
            (void)p256_scalar_sub_words(v, v, u, 8U);
            (void)p256_scalar_sub_mod_words(x2, x2, x1);
            if ((p256_scalar_is_zero_words(v) != 0) || (p256_scalar_is_one_words(v) != 0)) {
                done = 1U;
            }
        }
        if (done != 0U) {
            break;
        }
    }

    if (p256_scalar_is_one_words(u) != 0) {
        (void)p256_scalar_words_to_be(out, x1);
    } else if (p256_scalar_is_one_words(v) != 0) {
        (void)p256_scalar_words_to_be(out, x2);
    } else {
         /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_FAILED;
    }

    (void)p256_scalar_mul_mod(check, a, out);
    one[31] = 0x01U;
    if (memcmp(check, one, (size_t)32U) != 0) {
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
#if NOXTLS_FEATURE_MD5
static noxtls_return_t ecdsa_hash_run_md5(uint8_t *hash, const uint8_t *msg, uint32_t len)
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_md5_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif
#if NOXTLS_FEATURE_SHA1
static noxtls_return_t ecdsa_hash_run_sha1(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha1_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
static noxtls_return_t ecdsa_hash_run_sha256(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha256_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
static noxtls_return_t ecdsa_hash_run_sha512(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha512_ctx_t ctx512;
    if (noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha512_update(&ctx512, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecdsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((hash == NULL) || (hash_len == NULL) || (noxtls_message == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    switch (hash_algo) {
#if NOXTLS_FEATURE_MD5
        case NOXTLS_HASH_MD5:
            rc = ecdsa_hash_run_md5(hash, noxtls_message, message_len);
            if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 16U;
            break;
#endif
#if NOXTLS_FEATURE_SHA1
        case NOXTLS_HASH_SHA1:
            rc = ecdsa_hash_run_sha1(hash, noxtls_message, message_len, hash_algo);
            if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 20U;
            break;
#endif
#if NOXTLS_FEATURE_SHA224
        case NOXTLS_HASH_SHA_224:
            rc = ecdsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
            if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 28U;
            break;
#endif
#if NOXTLS_FEATURE_SHA256
        case NOXTLS_HASH_SHA_256:
            rc = ecdsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
            if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = 32U;
            break;
#endif
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
            rc = ecdsa_hash_run_sha512(hash, noxtls_message, message_len, hash_algo);
            if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
            *hash_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 64U;
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
 * @brief Check that a * inv == 1 (mod m)
 *
 * @param[out] prod Scratch product buffer (2 * size bytes)
 * @param[out] check Scratch reduced buffer (size bytes)
 * @param[in] a The value
 * @param[in] inv The candidate inverse
 * @param[in] one The constant 1 (size bytes)
 * @param[in] mod The modulus
 * @param[in] size Length of the operands in bytes
 * @param[out] verified Set to 1 when the product is 1, 0 otherwise
 * @return NOXTLS_RETURN_SUCCESS when the check could be computed, or the bignum error
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecdsa_inverse_check(uint8_t *prod, uint8_t *check, const uint8_t *a,
                                           const uint8_t *inv, const uint8_t *one,
                                           const uint8_t *mod, uint32_t size, int *verified)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = noxtls_bn_mul(prod, a, size, inv, size);
    *verified = 0;
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_bn_mod(check, prod, size * 2U, mod, size);
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_cmp(check, one, size) == 0)) {
        *verified = 1;
    }
    return rc;
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
    uint8_t prod[ECC_MAX_KEY_SIZE * 2U];
    uint8_t check[ECC_MAX_KEY_SIZE];
    uint8_t one[ECC_MAX_KEY_SIZE];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    int verified = 0;

    if ((result == NULL) || (a == NULL) || (mod == NULL) || (size == 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if (size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero((mod_minus_2), sizeof(mod_minus_2));
    noxtls_secure_zero((two), sizeof(two));
    noxtls_secure_zero((a_mod), sizeof(a_mod));
    noxtls_secure_zero((prod), sizeof(prod));
    noxtls_secure_zero((check), sizeof(check));
    noxtls_secure_zero((one), sizeof(one));

    if (ecdsa_order_is_p256(mod, size) != 0) {
        p256_scalar_reduce32(a_mod, a);
        if (noxtls_bn_is_zero(a_mod, size) != 0) {
            return NOXTLS_RETURN_FAILED;
        }
        if (p256_scalar_inv_mod(result, a_mod) == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if (noxtls_bn_mod_inv(result, a_mod, size, mod, size) == NOXTLS_RETURN_SUCCESS) {
            (void)p256_scalar_mul_mod(check, a_mod, result);
            one[31] = 0x01U;
            if (memcmp(check, one, (size_t)32U) == 0) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        return NOXTLS_RETURN_FAILED;
    }

    /* a_mod = a mod p. Every bignum status below is checked: an allocation
     * failure must never be mistaken for a verified inverse. */
    if (noxtls_bn_cmp(a, mod, size) >= 0) {
        rc = noxtls_bn_mod(a_mod, a, size, mod, size);
    } else {
        /* MISRA 15.7: final else path */
        (void)noxtls_bn_copy(a_mod, a, size);
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(a_mod, size) != 0)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        /* mod_minus_2 = p - 2 */
        two[size - 1U] = 0x02U;
        one[size - 1U] = 0x01U;
        (void)noxtls_bn_copy(mod_minus_2, mod, size);
        (void)noxtls_bn_sub(mod_minus_2, mod_minus_2, two, size);

        /* Fast path: use generic modular inverse first. */
        if (noxtls_bn_mod_inv(result, a_mod, size, mod, size) == NOXTLS_RETURN_SUCCESS) {
            rc = ecdsa_inverse_check(prod, check, a_mod, result, one, mod, size, &verified);
        }
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
        /* Fallback path: Fermat inverse for odd-prime orders. */
        rc = noxtls_bn_mod_exp(result, a_mod, mod_minus_2, size, mod, size);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = ecdsa_inverse_check(prod, check, a_mod, result, one, mod, size, &verified);
        }
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
        rc = noxtls_bn_mod_inv(result, a_mod, size, mod, size);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = ecdsa_inverse_check(prod, check, a_mod, result, one, mod, size, &verified);
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }

    noxtls_secure_zero(a_mod, sizeof(a_mod));
    noxtls_secure_zero(prod, sizeof(prod));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(result, (size_t)size);
        if (rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    return rc;
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
    if (sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    noxtls_secure_zero((sig->r), (size_t)(ECC_MAX_KEY_SIZE));
    noxtls_secure_zero((sig->s), (size_t)(ECC_MAX_KEY_SIZE));
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
    if (sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    noxtls_secure_zero((sig->r), (size_t)(ECC_MAX_KEY_SIZE));
    noxtls_secure_zero((sig->s), (size_t)(ECC_MAX_KEY_SIZE));
    sig->size = 0U;
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
    const uint8_t *base = *p;
    size_t rem = 0U;
    uint32_t len = 0U;
    size_t idx = 0U;

    if ((base == NULL) || (e == NULL) || ((uintptr_t)base >= (uintptr_t)e)) {
        return 0U;
    }
    rem = ecdsa_bytes_remaining(base, e);
    if (((uint32_t)base[idx] & 0x80U) != 0U) {
        uint8_t n = (uint8_t)((uint32_t)base[idx] & 0x7FU);
        idx += 1U;
        if ((n == 0U) || (n > 4U) || ((idx + (size_t)n) > rem)) {
            return 0U;
        }
        while (n > 0U) {
            len = (len << 8U) | (uint32_t)base[idx];
            idx += 1U;
            n -= 1U;
        }
    } else {
        len = (uint32_t)base[idx] & 0x7FU;
        idx += 1U;
    }
    *p = &base[idx];
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
    const uint8_t *base = *p;

    if ((base == NULL) || (e == NULL) || ((uintptr_t)base >= (uintptr_t)e) || (base[0] != expect)) {
        return -1;
    }
    *p = &base[1];
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
    const uint8_t *base = *p;
    uint32_t len = 0U;
    size_t rem = 0U;

    if ((base == NULL) || (e == NULL) || (buf == NULL) || (out_len == NULL) || ((uintptr_t)base >= (uintptr_t)e)) {
        return -1;
    }
    if (base[0] != 0x02U) {
        return -1;
    }
    *p = &base[1];
    len = ecdsa_der_get_length(p, e);
    base = *p;
    if ((base == NULL) || (len == 0U) || (len > buf_size)) {
        return -1;
    }
    rem = ecdsa_bytes_remaining(base, e);
    if ((size_t)len > rem) {
        return -1;
    }
    *out_len = len;
    noxtls_copy_u8(buf, (size_t)buf_size, base, (size_t)(len));
    *p = &base[len];
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
    const uint8_t *ptr = NULL;
    const uint8_t *end = NULL;
    uint32_t seq_len = 0U;
    uint32_t r_len = 0U;
    uint32_t s_len = 0U;
    uint8_t r[ECC_MAX_KEY_SIZE];
    uint8_t s[ECC_MAX_KEY_SIZE];

    if ((der == NULL) || (out == NULL) || (coord_size == 0U) || (coord_size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_NULL;
    }

    ptr = der;
    end = &der[der_len];

    if ((uintptr_t)ptr >= (uintptr_t)end) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (ecdsa_der_get_tag(&ptr, end, 0x30U) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    seq_len = ecdsa_der_get_length(&ptr, end);
    if (seq_len == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (ecdsa_bytes_remaining(ptr, end) < (size_t)seq_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        const uint8_t *seq_end = &ptr[seq_len];
        if (ecdsa_der_get_integer(&ptr, seq_end, r, (uint32_t)sizeof(r), &r_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if (ecdsa_der_get_integer(&ptr, seq_end, s, (uint32_t)sizeof(s), &s_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    noxtls_secure_zero((out), sizeof(ecdsa_signature_t));
    out->size = coord_size;

    if (r_len <= coord_size) {
        noxtls_copy_u8(&out->r[coord_size - r_len], sizeof(out->r) - (size_t)(coord_size - r_len), r, (size_t)(r_len));
    } else {
        uint32_t skip = (uint32_t)(r_len - coord_size);
        uint32_t i = 0U;
        for (i = 0U; i < skip; i += 1U) {
            if (r[i] != 0U) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        noxtls_copy_u8(out->r, sizeof(out->s), &r[skip], (size_t)(coord_size));
    }
    if (s_len <= coord_size) {
        noxtls_copy_u8(&out->s[coord_size - s_len], sizeof(out->s) - (size_t)(coord_size - s_len), s, (size_t)(s_len));
    } else {
        uint32_t skip = (uint32_t)(s_len - coord_size);
        uint32_t i = 0U;
        for (i = 0U; i < skip; i += 1U) {
            if (s[i] != 0U) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        noxtls_copy_u8(out->s, sizeof(out->s), &s[skip], (size_t)(coord_size));
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Bit length of a big-endian unsigned integer
 *
 * @param[in] a The integer
 * @param[in] len Length of @p a in bytes
 * @return Number of significant bits (0 for zero)
 */
static uint32_t ecdsa_bit_length(const uint8_t *a, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t bits = 0U;

    for (i = 0U; (i < len) && (bits == 0U); i += 1U) {
        if (a[i] != 0U) {
            uint32_t top = (uint32_t)a[i];
            bits = (len - i) * 8U;
            while ((top & 0x80U) == 0U) {
                top <<= 1U;
                bits -= 1U;
            }
        }
    }
    return bits;
}

/**
 * @brief Convert a message digest to the ECDSA integer e, reduced mod n
 *
 * SEC 1 v2 section 4.1.3 step 5 / FIPS 186-5 section 6.4.1: e is the leftmost
 * bitlen(n) bits of the digest. For every supported curve except secp224k1 the
 * order fills its top byte, so this is plain byte truncation; secp224k1 has a
 * 225-bit order and needs the extra bit shift.
 *
 * @param[out] e Receives e mod n (@p nlen bytes, big-endian)
 * @param[in] digest The digest
 * @param[in] digest_len Length of @p digest in bytes
 * @param[in] n The group order
 * @param[in] nlen Length of @p n in bytes
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecdsa_digest_to_scalar(uint8_t *e, const uint8_t *digest, uint32_t digest_len,
                                              const uint8_t *n, uint32_t nlen)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    const uint32_t n_bits = ecdsa_bit_length(n, nlen);
    uint32_t take = digest_len;
    uint32_t shift = 0U;
    uint32_t i = 0U;

    noxtls_secure_zero(e, (size_t)nlen);
    if ((digest_len * 8U) > n_bits) {
        take = (n_bits + 7U) / 8U;
        shift = (take * 8U) - n_bits;
    }
    if (take > nlen) {
        take = nlen;
    }
    noxtls_copy_u8(&e[nlen - take], (size_t)take, digest, (size_t)take);
    for (i = 0U; i < shift; i += 1U) {
        (void)noxtls_bn_rshift1(e, nlen);
    }

    if (ecdsa_order_is_p256(n, nlen) != 0) {
        p256_scalar_reduce32(e, e);
    } else if (noxtls_bn_cmp(e, n, nlen) >= 0) {
        rc = noxtls_bn_mod(e, e, nlen, n, nlen);
    } else {
        /* MISRA 15.7: already reduced */
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(e, (size_t)nlen);
    }
    return rc;
}

/**
 * @brief result = u * P for a scalar u (0 <= u < n) of nlen bytes
 *
 * noxtls_ecc_point_multiply() takes a coordinate-sized scalar. When the order is
 * one byte longer than a coordinate (secp224k1) u can exceed 2^(8*size); then
 * u*P = -((n - u)*P), and n - u < 2^(8*size) because n < 2^(8*size + 1).
 *
 * @param[out] result The product
 * @param[in] u The scalar (@p nlen bytes, big-endian)
 * @param[in] nlen Length of the group order in bytes (>= curve->size)
 * @param[in] point The point
 * @param[in] curve The curve
 * @return NOXTLS_RETURN_SUCCESS on success, otherwise an error code
 */
static noxtls_return_t ecdsa_point_mul_order_scalar(ecc_point_t *result, const uint8_t *u, uint32_t nlen,
                                                    const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    const uint32_t extra = nlen - size;
    uint8_t neg_u[ECC_MAX_KEY_SIZE];
    uint8_t neg_y[ECC_MAX_KEY_SIZE];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((extra == 0U) || (noxtls_bn_is_zero(u, extra) != 0)) {
        return noxtls_ecc_point_multiply(result, &u[extra], point, curve);
    }

    noxtls_secure_zero(neg_u, sizeof(neg_u));
    noxtls_secure_zero(neg_y, sizeof(neg_y));
    (void)noxtls_bn_sub(neg_u, curve->n, u, nlen);
    if (noxtls_bn_is_zero(neg_u, extra) == 0) {
        /* u >= n or n >= 2^(8*size + 1): not a valid reduced scalar for this curve. */
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_ecc_point_multiply(result, &neg_u[extra], point, curve);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(result->y, size) == 0)) {
        (void)noxtls_bn_sub(neg_y, curve->p, result->y, size);
        noxtls_copy_u8(result->y, sizeof(result->y), neg_y, (size_t)size);
    }
    return rc;
}

/**
 * @brief Common exit for noxtls_ecdsa_sign()
 *
 * Wipes and frees the scratch block (it holds the nonce k and k^-1, either of
 * which reveals the private key together with the signature) and, on failure,
 * wipes the signature so a caller never sees a partial or invalid (r, s).
 *
 * @param[in] scratch The scratch block (may be NULL)
 * @param[in] scratch_len Length of @p scratch in bytes
 * @param[out] signature The signature output
 * @param[in] rc The result to report
 * @param[in] sign_t0 Start timestamp for timing diagnostics
 * @return @p rc
 */
static noxtls_return_t ecdsa_sign_finish(uint8_t *scratch, size_t scratch_len,
                                         ecdsa_signature_t *signature,
                                         noxtls_return_t rc, uint64_t sign_t0)
{
    if (scratch != NULL) {
        noxtls_secure_zero(scratch, scratch_len);
        (void)noxtls_free(scratch);
    }
    if ((rc != NOXTLS_RETURN_SUCCESS) && (signature != NULL)) {
        noxtls_secure_zero(signature->r, sizeof(signature->r));
        noxtls_secure_zero(signature->s, sizeof(signature->s));
    }
    noxtls_ecdsa_sign_last_rc = (int32_t)rc;
    s_ecdsa_last_sign_timing.total_us = ecdsa_profile_elapsed_us(sign_t0);
    return rc;
}

/**
 * @brief ECDSA Signature Generation
 * 
 * Algorithm:
 * 1. Hash the noxtls_message: h = HASH(noxtls_message)
 * 2. Generate random nonce k in [1, n-1]
 * 3. Compute (x, y) = k * G
 * 4. r = x mod n (if r == 0U, go to step 2)
 * 5. s = k^-1U * (h + r * d) mod n (if s == 0U, go to step 2)
 * 6. Signature is (r, s)
 *
 * @param key ECC key
 * @param noxtls_message Message to sign
 * @param message_len Length of the noxtls_message
 * @param signature ECDSA signature structure
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecdsa_sign(const ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t hash_fast[64];
    uint8_t h_fast[ECC_MAX_KEY_SIZE];
    uint32_t hash_fast_len = 0U;
    uint8_t *scratch = NULL;
    size_t scratch_len = 0U;
    uint8_t *hash = NULL;
    uint8_t *k = NULL;
    uint8_t *k_inv = NULL;
    uint8_t *h = NULL;
    uint8_t *r_w = NULL;        /* r as an nlen-byte value mod n */
    uint8_t *r_times_d = NULL;
    uint8_t *sum_tmp = NULL;
    uint8_t *h_plus_rd = NULL;
    uint8_t *s_product = NULL;  /* k_inv * h_plus_rd is 2*nlen bytes; must not write into signature->s */
    uint8_t *s_w = NULL;        /* s as an nlen-byte value mod n */
    uint8_t *random_bytes = NULL;
    ecc_point_t kG;
    uint32_t size = 0U;
    uint32_t nlen = 0U;         /* length of the order n (> size only for secp224k1) */
    uint32_t extra = 0U;        /* nlen - size */
    uint32_t bits = 0U;
    uint32_t max_attempts = 100U;
    uint32_t attempt = 0U;
    int is_p256 = 0;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint64_t sign_t0 = 0U;
    uint64_t step_t0 = 0U;
    noxtls_ecdsa_sign_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
    noxtls_ecdsa_sign_last_stage = 1U;

    if ((key == NULL) || (noxtls_message == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((key->curve == NULL) || (key->d == NULL) || (key->curve->n == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }

    size = key->curve->size;
    nlen = noxtls_ecc_curve_order_size(key->curve);
    if ((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (nlen < size) || (nlen > ECC_MAX_KEY_SIZE)) {
        noxtls_ecdsa_sign_last_rc = (int32_t)NOXTLS_RETURN_FAILED;
        return NOXTLS_RETURN_FAILED;
    }
    extra = nlen - size;
    bits = size * 8U;
    is_p256 = ecdsa_order_is_p256(key->curve->n, nlen);
    noxtls_secure_zero((hash_fast), sizeof(hash_fast));
    noxtls_secure_zero((h_fast), sizeof(h_fast));
    noxtls_secure_zero(&s_ecdsa_last_sign_timing, sizeof(s_ecdsa_last_sign_timing));
    sign_t0 = ecdsa_profile_now_us();

    /* Step 1: hash once on stack so accelerator can bypass software allocations/loops. */
    step_t0 = ecdsa_profile_now_us();
    rc = ecdsa_hash_message(hash_fast, &hash_fast_len, noxtls_message, message_len, hash_algo);
    s_ecdsa_last_sign_timing.hash_prepare_us = ecdsa_profile_elapsed_us(step_t0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecdsa_sign_last_rc = (int32_t)rc;
        return rc;
    }
    rc = ecdsa_digest_to_scalar(h_fast, hash_fast, hash_fast_len, key->curve->n, nlen);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return ecdsa_sign_finish(NULL, 0U, signature, rc, sign_t0);
    }

    /* Fast backend path (platform hook) before software math hot loop. */
    step_t0 = ecdsa_profile_now_us();
    rc = noxtls_ecdsa_sign_accel_port(key, h_fast, nlen, signature);
    s_ecdsa_last_sign_timing.accel_port_us = ecdsa_profile_elapsed_us(step_t0);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecdsa_sign_last_stage = 9U;
        s_ecdsa_last_sign_timing.total_us = ecdsa_profile_elapsed_us(sign_t0);
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Allocate one contiguous scratch block to reduce allocator overhead in hot path. */
    {
        size_t off = 0U;
        scratch_len = (size_t)(64U + ((size_t)nlen * 10U) + ((size_t)size * 2U) + 2U);
        scratch = (uint8_t *)NOXTLS_CALLOC(scratch_len, 1U);
        if (scratch == NULL) {
            noxtls_ecdsa_sign_last_stage = 2U;
            return ecdsa_sign_finish(NULL, 0U, signature, NOXTLS_RETURN_FAILED, sign_t0);
        }
        hash = &scratch[off];
        off += 64U;
        k = &scratch[off];
        off += (size_t)nlen;
        k_inv = &scratch[off];
        off += (size_t)nlen;
        h = &scratch[off];
        off += (size_t)nlen;
        r_w = &scratch[off];
        off += (size_t)nlen;
        r_times_d = &scratch[off];
        off += ((size_t)nlen + (size_t)size);
        sum_tmp = &scratch[off];
        off += ((size_t)nlen + 1U);
        /* h + r*d can be up to 2n-2, so we need nlen + 1U bytes to avoid dropping carry in add */
        h_plus_rd = &scratch[off];
        off += ((size_t)nlen + 1U);
        s_product = &scratch[off];
        off += ((size_t)nlen * 2U);
        s_w = &scratch[off];
        off += (size_t)nlen;
        random_bytes = &scratch[off];
        (void)off;
    }

    /* Initialize signature structure */
    (void)noxtls_ecc_point_init(&kG, size);
    noxtls_copy_u8((uint8_t *)(hash), sizeof(hash_fast), (const uint8_t *)(hash_fast), sizeof(hash_fast));
    noxtls_copy_u8(h, (size_t)nlen, h_fast, (size_t)(nlen));
    /* No valid (r, s) yet: exhausting the retry loop must report failure. */
    rc = NOXTLS_RETURN_FAILED;

    /* Step 2-5: Generate signature with retry if r or s is zero */
    for (attempt = 0U; attempt < max_attempts; attempt += 1U) {
        s_ecdsa_last_sign_timing.attempts = attempt + 1U;
        /* Step 2: Generate random nonce k in [1, n-1] */
        do {
            step_t0 = ecdsa_profile_now_us();
            rc = ecdsa_drbg_generate_bits(random_bytes, bits);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecdsa_sign_last_stage = 3U;
                return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
            }

            /* Reduce mod n */
            noxtls_secure_zero(k, (size_t)nlen);
            if (is_p256 != 0) {
                p256_scalar_reduce32(k, random_bytes);
            } else if (extra != 0U) {
                /* n > 2^(8*size) (secp224k1): a size-byte value is already below n.
                 * k is drawn from [1, 2^(8*size) - 1], which omits a 2^-111 fraction of
                 * [1, n-1] for secp224k1 (negligible bias), and k always fits the
                 * coordinate-sized scalar taken by noxtls_ecc_point_multiply(). */
                noxtls_copy_u8(&k[extra], (size_t)size, random_bytes, (size_t)size);
            } else {
                rc = noxtls_bn_mod(k, random_bytes, size, key->curve->n, nlen);
                if (rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecdsa_sign_last_stage = 3U;
                    return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
                }
            }
            s_ecdsa_last_sign_timing.nonce_generate_us += ecdsa_profile_elapsed_us(step_t0);

            /* Ensure k is not zero */
        } while (noxtls_bn_is_zero(k, nlen) != 0);

        /* Step 3: Compute (x, y) = k * G */
        step_t0 = ecdsa_profile_now_us();
        rc = noxtls_ecc_point_multiply(&kG, &k[extra], &key->curve->G, key->curve);
        s_ecdsa_last_sign_timing.base_point_mul_us += ecdsa_profile_elapsed_us(step_t0);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecdsa_sign_last_stage = 4U;
            return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
        }

        /* Step 4: r = x mod n */
        step_t0 = ecdsa_profile_now_us();
        if (is_p256 != 0) {
            p256_scalar_reduce32(r_w, kG.x);
        } else {
            rc = noxtls_bn_mod(r_w, kG.x, size, key->curve->n, nlen);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecdsa_sign_last_stage = 4U;
                return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
            }
        }
        s_ecdsa_last_sign_timing.r_reduce_us += ecdsa_profile_elapsed_us(step_t0);

        /* If r == 0U, retry (x < p < 2^(8*size), so r always fits a coordinate) */
        if ((noxtls_bn_is_zero(r_w, nlen) != 0) ||
            ((extra != 0U) && (noxtls_bn_is_zero(r_w, extra) == 0))) {
            rc = NOXTLS_RETURN_FAILED;
            continue;
        }

        /* Step 5: s = k^-1U * (h + r * d) mod n */
        /* Compute k^-1 mod n */
        step_t0 = ecdsa_profile_now_us();
        rc = ecdsa_mod_inv_prime(k_inv, k, key->curve->n, nlen);
        s_ecdsa_last_sign_timing.nonce_inv_us += ecdsa_profile_elapsed_us(step_t0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecdsa_sign_last_stage = 5U;
            noxtls_ecdsa_sign_last_rc = (int32_t)rc;
            if (rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
                return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
            }
            continue;
        }

        /* Compute r * d */
        step_t0 = ecdsa_profile_now_us();
        if (is_p256 != 0) {
            (void)p256_scalar_mul_mod(r_times_d, r_w, key->d);
            p256_scalar_add_mod(h_plus_rd, h, r_times_d);
            (void)p256_scalar_mul_mod(s_w, k_inv, h_plus_rd);
        } else {
            /* Each bignum step can fail (allocation): a wrong s must never be
             * released, so any failure aborts the signature. */
            rc = noxtls_bn_mul(r_times_d, r_w, nlen, key->d, size);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_bn_mod(r_times_d, r_times_d, nlen + size, key->curve->n, nlen);
            }

            /* Compute h + r * d with carry (can be nlen + 1U bytes); then reduce mod n */
            {
                uint16_t carry = 0U;
                uint32_t i = 0U;
                noxtls_secure_zero((sum_tmp), ((size_t)(nlen + 1U)));
                for (i = 0U; i < nlen; i += 1U) {
                    uint32_t idx = (uint32_t)(nlen - 1U - i);
                    uint16_t sum = (uint16_t)h[idx] + (uint16_t)r_times_d[idx] + carry;
                    sum_tmp[idx + 1U] = (uint8_t)(sum & 0xFFU);
                    {
                        uint32_t next_carry = (uint32_t)sum;
                        next_carry >>= 8U;
                        carry = (uint16_t)next_carry;
                    }
                }
                sum_tmp[0U] = (uint8_t)carry;
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    uint32_t len = (carry != 0U) ? (nlen + 1U) : nlen;
                    const uint8_t *src = (carry != 0U) ? sum_tmp : (&sum_tmp[1U]);
                    rc = noxtls_bn_mod(h_plus_rd, src, len, key->curve->n, nlen);
                }
            }

            /* Compute s = k^-1U * (h + r * d) mod n (product is 2*nlen bytes) */
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_bn_mul(s_product, k_inv, nlen, h_plus_rd, nlen);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_bn_mod(s_w, s_product, nlen * 2U, key->curve->n, nlen);
            }
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecdsa_sign_last_stage = 6U;
                return ecdsa_sign_finish(scratch, scratch_len, signature, rc, sign_t0);
            }
        }
        s_ecdsa_last_sign_timing.s_compute_us += ecdsa_profile_elapsed_us(step_t0);

        /* If s == 0U, retry. Also retry when s does not fit the coordinate-sized
         * signature field (only possible for secp224k1, probability ~2^-111). */
        if ((noxtls_bn_is_zero(s_w, nlen) != 0) ||
            ((extra != 0U) && (noxtls_bn_is_zero(s_w, extra) == 0))) {
            rc = NOXTLS_RETURN_FAILED;
            continue;
        }
        noxtls_copy_u8(signature->r, sizeof(signature->r), &r_w[extra], (size_t)size);
        noxtls_copy_u8(signature->s, sizeof(signature->s), &s_w[extra], (size_t)size);

#if NOXTLS_ECDSA_SIGN_SELF_VERIFY
        /* Optional sign-time verification hardening against faulted signatures. */
        {
            step_t0 = ecdsa_profile_now_us();
            noxtls_return_t verify_rc = noxtls_ecdsa_verify(key, noxtls_message, message_len, signature, hash_algo);
            s_ecdsa_last_sign_timing.self_verify_us += ecdsa_profile_elapsed_us(step_t0);
            if (verify_rc != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_FAILED;
                continue;
            }
        }
#endif

        /* Success! */
        noxtls_ecdsa_sign_last_stage = 9U;
        return ecdsa_sign_finish(scratch, scratch_len, signature, NOXTLS_RETURN_SUCCESS, sign_t0);
    }

    /* Retry budget exhausted without a valid (r, s): never report success. */
    (void)rc;
    return ecdsa_sign_finish(scratch, scratch_len, signature, NOXTLS_RETURN_FAILED, sign_t0);
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
noxtls_return_t noxtls_ecdsa_verify(const ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t hash_fast[64];
    uint8_t h_fast[ECC_MAX_KEY_SIZE];
    uint32_t hash_fast_len = 0U;
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
    uint8_t r_w[ECC_MAX_KEY_SIZE];  /* r and s widened to the order length */
    uint8_t s_w[ECC_MAX_KEY_SIZE];
    uint32_t size = 0U;
    uint32_t nlen = 0U;
    uint32_t extra = 0U;
    int is_p256 = 0;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if ((key == NULL) || (noxtls_message == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (key->curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_ecc_point_validate_public(&key->Q, key->curve);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    size = key->curve->size;
    nlen = noxtls_ecc_curve_order_size(key->curve);
    if ((key->curve->n == NULL) || (size == 0U) || (size > ECC_MAX_KEY_SIZE) || (nlen < size) || (nlen > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    extra = nlen - size;
    is_p256 = ecdsa_order_is_p256(key->curve->n, nlen);
    /* r and s are coordinate-sized; compare and compute with them as nlen-byte
     * values because n is one byte longer than a coordinate for secp224k1. */
    noxtls_secure_zero(r_w, sizeof(r_w));
    noxtls_secure_zero(s_w, sizeof(s_w));
    noxtls_copy_u8(&r_w[extra], (size_t)size, signature->r, (size_t)size);
    noxtls_copy_u8(&s_w[extra], (size_t)size, signature->s, (size_t)size);
#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
    (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] size=%u message_len=%u\n", (uint32_t)size, (uint32_t)message_len);
#endif

    /* Step 1: Verify r and s are in [1, n-1] */
    if ((noxtls_bn_is_zero(r_w, nlen) != 0) ||
       (noxtls_bn_cmp(r_w, key->curve->n, nlen) >= 0)) {
        rc = NOXTLS_RETURN_FAILED;
        if (scratch != NULL) { (void)noxtls_free(scratch); }

        return rc;
    }

    if ((noxtls_bn_is_zero(s_w, nlen) != 0) ||
       (noxtls_bn_cmp(s_w, key->curve->n, nlen) >= 0)) {
        rc = NOXTLS_RETURN_FAILED;
        if (scratch != NULL) { (void)noxtls_free(scratch); }

        return rc;
    }

    noxtls_secure_zero((hash_fast), sizeof(hash_fast));
    noxtls_secure_zero((h_fast), sizeof(h_fast));
    /* Step 2: Hash on stack first so accel path can avoid software allocations. */
    rc = ecdsa_hash_message(hash_fast, &hash_fast_len, noxtls_message, message_len, hash_algo);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = ecdsa_digest_to_scalar(h_fast, hash_fast, hash_fast_len, key->curve->n, nlen);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Fast backend path (platform hook) before software verification math. */
    rc = noxtls_ecdsa_verify_accel_port(key, h_fast, nlen, signature);
    if ((rc == NOXTLS_RETURN_SUCCESS) || (rc == NOXTLS_RETURN_FAILED)) {
        return rc;
    }

    /* Allocate one contiguous scratch block to reduce allocator overhead in software path. */
    {
        const size_t scratch_len = (size_t)(64U + ((size_t)nlen * 7U));
        size_t off = 0U;
        scratch = (uint8_t *)NOXTLS_CALLOC(scratch_len, 1U);
        if (scratch == NULL) {
            rc = NOXTLS_RETURN_FAILED;
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }
        hash = &scratch[off];
        off += 64U;
        h = &scratch[off];
        off += (size_t)nlen;
        s_inv = &scratch[off];
        off += (size_t)nlen;
        /* u1, u2 hold mul result (2*nlen bytes) before bn_mod; after mod, nlen-byte value in first bytes */
        u1 = &scratch[off];
        off += ((size_t)nlen * 2U);
        u2 = &scratch[off];
        off += ((size_t)nlen * 2U);
        v = &scratch[off];
        (void)off;
    }

    if ((hash == NULL) || (h == NULL) || (s_inv == NULL) || (u1 == NULL) || (u2 == NULL) || (v == NULL)) {
        rc = NOXTLS_RETURN_FAILED;
        if (scratch != NULL) { (void)noxtls_free(scratch); }

        return rc;
    }

    (void)noxtls_ecc_point_init(&u1G, size);
    (void)noxtls_ecc_point_init(&u2Q, size);
    (void)noxtls_ecc_point_init(&result, size);
    noxtls_copy_u8((uint8_t *)(hash), sizeof(hash_fast), (const uint8_t *)(hash_fast), sizeof(hash_fast));
    noxtls_copy_u8(h, (size_t)nlen, h_fast, (size_t)(nlen));

#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
    (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] hash_len=%u\n", (uint32_t)hash_fast_len);
    (void)ecdsa_debug_hex("h", h, size);
    (void)ecdsa_debug_hex("signature->r", signature->r, size);
    (void)ecdsa_debug_hex("signature->s", signature->s, size);
#endif

    /* Step 3: u1 = s^-1 * h mod n.
     * P-256 has a dedicated scalar inverse path that avoids the slower generic
     * big-number inverse used for larger/generic curves. */
    if (is_p256 != 0) {
        rc = ecdsa_mod_inv_prime(s_inv, s_w, key->curve->n, nlen);
    } else {
        rc = noxtls_bn_mod_inv(s_inv, s_w, nlen, key->curve->n, nlen);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (scratch != NULL) { (void)noxtls_free(scratch); }

        return rc;
    }
    if (is_p256 != 0) {
        (void)p256_scalar_mul_mod(u1, s_inv, h);
        (void)p256_scalar_mul_mod(u2, s_inv, r_w);
    } else {
        /* Mod into v (not in-place on the 2*nlen product) to match reference verify paths.
         * Every status is checked: a failed step yields an error, never a verdict
         * computed from garbage scalars. */
        rc = noxtls_bn_mul(u1, s_inv, nlen, h, nlen);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(v, u1, nlen * 2U, key->curve->n, nlen);
        }
        noxtls_copy_u8(u1, (size_t)nlen, v, (size_t)(nlen));

        /* Step 4: u2 = s^-1 * r mod n */
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mul(u2, s_inv, nlen, r_w, nlen);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(v, u2, nlen * 2U, key->curve->n, nlen);
        }
        noxtls_copy_u8(u2, (size_t)nlen, v, (size_t)(nlen));
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(scratch);
            return rc;
        }
    }
#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
    (void)ecdsa_debug_hex("s_inv", s_inv, size);
    (void)ecdsa_debug_hex("u1", u1, size);
    (void)ecdsa_debug_hex("u2", u2, size);
#endif

    /* Step 5: Compute (x, y) = u1 * G + u2 * Q */
    if ((size == 32U) && (extra == 0U)) {
#ifdef ESP_PLATFORM
        if (noxtls_esp_hw_ecc_compiled_in() != 0) {
        /*
         * Use two scalar multiplies plus one point add for P-256 verify.
         *
         * This keeps the path compatible with the platform point-multiply hook
         * (ESP ECC acceleration) and avoids depending on the software-only
         * muladd fast path for signature verification.
         */
        rc = noxtls_ecc_point_multiply(&u1G, u1, &key->curve->G, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }

        rc = noxtls_ecc_point_multiply(&u2Q, u2, &key->Q, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }

        rc = noxtls_ecc_point_add(&result, &u1G, &u2Q, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }
        } else
#endif
        {
            rc = noxtls_ecc_point_muladd(&result, u1, &key->curve->G, u2, &key->Q, key->curve);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                if (scratch != NULL) { (void)noxtls_free(scratch); }

                return rc;
            }
        }
    } else {
        /* u1, u2 are nlen-byte values mod n (may exceed a coordinate for secp224k1). */
        rc = ecdsa_point_mul_order_scalar(&u1G, u1, nlen, &key->curve->G, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }

        rc = ecdsa_point_mul_order_scalar(&u2Q, u2, nlen, &key->Q, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }

        rc = noxtls_ecc_point_add(&result, &u1G, &u2Q, key->curve);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (scratch != NULL) { (void)noxtls_free(scratch); }

            return rc;
        }
    }
#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
    (void)ecdsa_debug_hex("u1G.x", u1G.x, size);
    (void)ecdsa_debug_hex("u1G.y", u1G.y, size);
    (void)ecdsa_debug_hex("u2Q.x", u2Q.x, size);
    (void)ecdsa_debug_hex("u2Q.y", u2Q.y, size);
    (void)ecdsa_debug_hex("result.x", result.x, size);
    (void)ecdsa_debug_hex("result.y", result.y, size);
#endif

    /* Step 6: v = x mod n. u1*G + u2*Q == O (affine (0, 0)) must be rejected:
     * reducing its zero x would otherwise be compared against r. */
    if ((noxtls_bn_is_zero(result.x, size) != 0) && (noxtls_bn_is_zero(result.y, size) != 0)) {
        if (scratch != NULL) { (void)noxtls_free(scratch); }

        return NOXTLS_RETURN_FAILED;
    }
    if (is_p256 != 0) {
        p256_scalar_reduce32(v, result.x);
    } else {
        rc = noxtls_bn_mod(v, result.x, size, key->curve->n, nlen);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(scratch);
            return rc;
        }
    }
#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
    (void)ecdsa_debug_hex("result.x (before mod n)", result.x, size);
    (void)ecdsa_debug_hex("v", v, size);
    (void)ecdsa_debug_hex("signature->r (compare)", signature->r, size);
    (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] v %s r (cmp=%d)\n",
           (void)noxtls_bn_cmp(v, signature->r, size) == 0 ? "==" : "!=",
           noxtls_bn_cmp(v, signature->r, size));
#endif

    /* Step 7: Accept if v == r */
    if (noxtls_bn_cmp(v, r_w, nlen) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    } else {
        rc = NOXTLS_RETURN_FAILED;
#ifdef NOXTLS_ECDSA_VERIFY_DEBUG
        {
            uint32_t i = 0U;
            uint8_t u1_plus_u2_buf[ECC_MAX_KEY_SIZE + 1U];
            uint8_t u1_plus_u2_mod_n_buf[ECC_MAX_KEY_SIZE];
            uint8_t s_times_s_inv[ECC_MAX_KEY_SIZE * 2];
            uint8_t s_times_s_inv_mod_n[ECC_MAX_KEY_SIZE];
            uint16_t carry = 0U;
            noxtls_secure_zero((u1_plus_u2_buf), sizeof(u1_plus_u2_buf));
            noxtls_secure_zero((u1_plus_u2_mod_n_buf), sizeof(u1_plus_u2_mod_n_buf));
            noxtls_secure_zero((s_times_s_inv), sizeof(s_times_s_inv));
            noxtls_secure_zero((s_times_s_inv_mod_n), sizeof(s_times_s_inv_mod_n));
            (void)noxtls_bn_mul(s_times_s_inv, signature->s, size, s_inv, size);
            (void)noxtls_bn_mod(s_times_s_inv_mod_n, s_times_s_inv, size * 2U, key->curve->n, size);
            for (i = size; i > 0U; i -= 1U) {
                uint16_t sum = (uint16_t)u1[i-1] + (uint16_t)u2[i-1] + carry;
                u1_plus_u2_buf[i] = (uint8_t)(sum & 0xFFU);
                carry = (uint32_t)(sum >> 8U);
            }
            u1_plus_u2_buf[0] = (uint8_t)carry;
            {
                const uint8_t *sum_ptr = &u1_plus_u2_buf[1];
                uint32_t sum_len = (uint32_t)(size);
                if (carry != 0U) {
                    sum_ptr = u1_plus_u2_buf;
                    sum_len = size + 1U;
                }
                (void)noxtls_bn_mod(u1_plus_u2_mod_n_buf, sum_ptr, sum_len, key->curve->n, size);
            }
            (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] FAILED v != r (size=%u)\n", (uint32_t)size);
            (void)noxtls_debug_printf((const uint8_t *)"  s*s_inv mod n= ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", s_times_s_inv_mod_n[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"  (expect 00...01)\n");
            (void)noxtls_debug_printf((const uint8_t *)"  h            = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", h[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  signature->r = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", signature->r[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  signature->s = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", signature->s[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  s_inv        = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", s_inv[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  u1           = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", u1[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  u2           = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", u2[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  (u1+u2) mod n = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", u1_plus_u2_mod_n_buf[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"  (expect 00...01 when u1+u2=1)\n");
            (void)noxtls_debug_printf((const uint8_t *)"  u1G.x        = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", u1G.x[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  u2Q.x        = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", u2Q.x[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  result.x     = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", result.x[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  v            = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", v[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
        }
        {
            uint32_t i = 0U;
            (void)noxtls_debug_printf((const uint8_t *)"[ecdsa_verify] FAILED: v != r\n  v = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", v[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n  r = ");
            for (i = 0U; i < size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", signature->r[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
        }
#endif
    }

    if (scratch != NULL) { (void)noxtls_free(scratch); }

    return rc;
}
