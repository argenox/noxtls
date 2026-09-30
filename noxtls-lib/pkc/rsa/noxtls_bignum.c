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
* File:    noxtls_bignum.c
* Summary: Big Number Arithmetic Operations Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_bignum.h"
#include "noxtls_bn_platform.h"
#include "noxtls_ct.h"

/* Debug helpers for bn_mod / bn_mod_exp instrumentation. */
static int g_bn_debug_modexp_active = 0;
static uint32_t g_bn_debug_mod_calls = 0U;
static int g_bn_debug_div_trace = 0;
/* Set to 1 to trace bn_mod_2n_by_n_limb line-by-line (e.g. for 96/48 Gy^2 mod p). */
static int g_bn_debug_mod_2n_by_n = 0;
/* Temporary safety switch: keep 2n/n reducer disabled in noxtls_bn_mod dispatcher. */

/**
 * @brief Debug helper: print a labeled byte buffer (currently disabled).
 * @internal
 *
 * @param[in] label Label prefix (unused)
 * @param[in] buf Byte buffer
 * @param[in] len Buffer length in bytes
 * @return void
 */
static void bn_debug_print(const uint8_t *label, const uint8_t *buf, uint32_t len)
{
    if((buf == NULL) && (len > 0U)) {
        return;
    }
    (void)label;
    (void)buf;
    for(uint32_t i = 0U; i < len; i += 1U) {
    }
}

/**
 * @brief Debug helper: print 32-bit limbs to stderr when mod-2n debug is enabled.
 * @internal
 *
 * @param[in] label Label prefix
 * @param[in] limbs Little-endian limb array (limb 0 = LSW)
 * @param[in] limb_len Number of limbs
 * @return void
 */
static void bn_debug_limbs(const uint8_t *label, const uint32_t *limbs, uint32_t limb_len)
{
    uint32_t i = 0U;
    if((limbs == NULL) || (g_bn_debug_mod_2n_by_n == 0)) {
        return;
    }
    (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] %s (%u limbs):", label, (uint32_t)limb_len);
    for(i = 0U; i < limb_len; i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)" %08X", (uint32_t)limbs[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

/**
 * @brief Debug helper: print big-endian bytes to stderr when mod-2n debug is enabled.
 * @internal
 *
 * @param[in] label Label prefix
 * @param[in] buf Byte buffer (big-endian)
 * @param[in] len Total buffer length in bytes
 * @param[in] max_show Maximum bytes to print (0 = all)
 * @return void
 */
static void bn_debug_bytes(const uint8_t *label, const uint8_t *buf, uint32_t len, uint32_t max_show)
{
    uint32_t i = 0U;
    uint32_t n = (uint32_t)(((max_show != 0U) && (len > max_show)) ? max_show : len);
    if((buf == NULL) || (g_bn_debug_mod_2n_by_n == 0)) {
        return;
    }
    (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] %s (%u bytes):", label, (uint32_t)len);
    for(i = 0U; i < n; i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02X", buf[i]);
    }
    if((len > max_show) && (max_show != 0U)) {
        (void)noxtls_debug_printf((const uint8_t *)"...(%u more)", (uint32_t)(len - max_show));
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

/* ---- limb-based division removed; use in-house bn_div_remainder ---- */

/**
 * @brief Compare two big integers (byte arrays, big-endian)
 * @internal
 * @param a First big integer
 * @param b Second big integer
 * @param len Length of the big integers
 * @return int 1 if a > b, -1 if a < b, 0 if a == b
 */
int32_t noxtls_bn_cmp(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i = 0U;

    if((a == NULL) || (b == NULL)) {
        return 0; /* treat as equal on invalid params */
    }
    if(len == 0U) {
        return 0;
    }
    for(i = 0U; i < len; i += 1U) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

/* Check if big integer is zero */
/**
 * @brief Check if big integer is zero
 * 
 * @param a Big integer
 * @param len Length of the big integer
 * @return int 1 if the big integer is zero, 0 otherwise
 */
int32_t noxtls_bn_is_zero(const uint8_t *a, uint32_t len)
{
    uint32_t i = 0U;

    if((a == NULL) || (len == 0U)) {
        return 0; /* not zero on invalid params */
    }
    for(i = 0U; i < len; i += 1U) {
        if(a[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

/* Check if big integer is one */
/**
 * @brief Check if big integer is one
 * @internal
 * @param a Big integer
 * @param len Length of the big integer
 * @return int 1 if the big integer is one, 0 otherwise
 */
int32_t noxtls_bn_is_one(const uint8_t *a, uint32_t len)
{
    uint32_t i = 0U;

    if((a == NULL) || (len == 0U)) {
        return 0;
    }
    if(a[len - 1U] != 1U) {
        return 0;
    }
    for(i = 0U; i < (len - 1U); i += 1U) {
        if(a[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

/* Set big integer to zero */
/**
 * @brief Set big integer to zero
 * @internal
 * @param a Big integer
 * @param len Length of the big integer
 */
noxtls_return_t noxtls_bn_zero(uint8_t *a, uint32_t len)
{
    if(a == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero((a), (size_t)(len));
    return NOXTLS_RETURN_SUCCESS;
}

/* Set big integer to one */
/**
 * @brief Set big integer to one
 * @internal
 * @param a Big integer
 * @param len Length of the big integer
 */
noxtls_return_t noxtls_bn_one(uint8_t *a, uint32_t len)
{
    if(a == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero((a), (size_t)(len));
    a[len - 1U] = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/* Copy big integer */
/**
 * @brief Copy big integer
 * @internal
 * @param dst Destination big integer
 * @param src Source big integer
 * @param len Length of the big integer
 */
noxtls_return_t noxtls_bn_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    uint32_t i = 0U;

    if((dst == NULL) || (src == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(i = 0U; i < len; i += 1U) {
        dst[i] = src[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Add two big integers: result = a + b
 * @internal
 * @param result Result big integer
 * @param a First big integer
 * @param b Second big integer
 * @param len Length of the big integers
 */
noxtls_return_t noxtls_bn_add(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i = 0U;
    uint16_t carry = 0U;

    if((result == NULL) || (a == NULL) || (b == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(i = len; i > 0U; i -= 1U) {
        uint16_t sum = (uint16_t)a[i - 1U] + (uint16_t)b[i - 1U] + carry;
        result[i - 1U] = (uint8_t)(sum & 0xFFU);
        {
            uint32_t next_carry = (uint32_t)sum;
            next_carry >>= 8U;
            carry = (uint16_t)next_carry;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}


/**
 * @brief Subtract two big integers: result = a - b (assumes a >= b)
 * @internal
 * @param result Result big integer
 * @param a First big integer
 * @param b Second big integer
 * @param len Length of the big integers
 */
noxtls_return_t noxtls_bn_sub(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i = 0U;
    int borrow = 0;

    if((result == NULL) || (a == NULL) || (b == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(i = len; i > 0U; i -= 1U) {
        int diff = (int)a[i - 1U] - (int)b[i - 1U] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i - 1U] = (uint8_t)diff;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply-add with carry: r[0..n-1] += s[0..n-1] * d + carry_in.
 * @internal
 *
 * Output carry is stored in @p c. Uses 64-bit intermediates.
 *
 * @param[in] s Source limb array
 * @param[in] n Number of limbs
 * @param[in] d Multiplier limb
 * @param[in,out] r Destination limb array
 * @param[in,out] c Carry in/out
 * @return void
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): legacy limb helper signature mirrors mbedTLS-style call sites. */
static void bn_muladd_hlp(const uint32_t *s, uint32_t n, uint32_t d, uint32_t *r, uint32_t *c)
{
    uint32_t i = 0U;
    uint64_t carry = (uint64_t)*c;
    for(i = 0U; i < n; i += 1U) {
        uint64_t t = ((uint64_t)s[i] * (uint64_t)d) + (uint64_t)r[i] + carry;
        r[i] = (uint32_t)(t & 0xFFFFFFFFU);
        carry = (uint32_t)(t >> 32U);
    }
    *c = (uint32_t)carry;
}

/* Forward declarations for limb/byte conversion (defined in "32-bit limb helpers" below). */
static void bn_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len);
static void bn_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len);
static noxtls_return_t bn_sub_inplace(uint8_t *a, const uint8_t *b, uint32_t len);

/**
 * @brief Multiply two big integers: result = a * b (limb-based schoolbook)
 * @internal
 * Uses 32-bit limbs and 64-bit multiply-accumulate (MULADDC-style). Converts BE bytes
 * to LE limbs, runs one pass per limb of b (multiply a by b[i], add into result at offset i),
 * then converts result limbs back to BE bytes.
 *
 * @param result Result big integer (a_len + b_len bytes, big-endian)
 * @param a First big integer (big-endian)
 * @param a_len Length of the first big integer
 * @param b Second big integer (big-endian)
 * @param b_len Length of the second big integer
 */
noxtls_return_t noxtls_bn_mul(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    uint32_t n_limbs_a = 0U;
    uint32_t n_limbs_b = 0U;
    uint32_t n_limbs_r = 0U;
    uint32_t result_len = 0U;
    uint32_t *a_limbs = NULL;
    uint32_t *b_limbs = NULL;
    uint32_t *r_limbs = NULL;
    uint32_t i = 0U;
    uint32_t carry = 0U;

    if((result == NULL) || (a == NULL) || (b == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((a_len == 0U) || (b_len == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((a_len > (uint32_t)(UINT32_MAX - b_len)) ||
       (a_len > (uint32_t)(UINT32_MAX - 3U)) ||
       (b_len > (uint32_t)(UINT32_MAX - 3U))) {
        return NOXTLS_RETURN_FAILED;
    }

    result_len = a_len + b_len;
    n_limbs_a = (a_len + 3U) / 4U;
    n_limbs_b = (b_len + 3U) / 4U;
    if(n_limbs_a > (uint32_t)(UINT32_MAX - n_limbs_b)) {
        return NOXTLS_RETURN_FAILED;
    }
    n_limbs_r = n_limbs_a + n_limbs_b;

    if((a_len == 32U) && (b_len == 32U)) {
        uint32_t a_limbs32[8];
        uint32_t b_limbs32[8];
        uint32_t r_limbs32[16];

        noxtls_secure_zero((a_limbs32), sizeof(a_limbs32));
        noxtls_secure_zero((b_limbs32), sizeof(b_limbs32));
        noxtls_secure_zero((r_limbs32), sizeof(r_limbs32));

        bn_bytes_to_limbs_le(a_limbs32, 8U, a, 32U);
        bn_bytes_to_limbs_le(b_limbs32, 8U, b, 32U);

        /* This exact width is hit heavily by X25519 and P-256 scalar arithmetic. */
        for(i = 0U; i < 8U; i += 1U) {
            carry = 0U;
            bn_muladd_hlp(a_limbs32, 8U, b_limbs32[i], &r_limbs32[i], &carry);
            r_limbs32[i + 8U] = carry;
        }

        bn_limbs_to_bytes_be(result, result_len, r_limbs32, 16U);
        return NOXTLS_RETURN_SUCCESS;
    }

    a_limbs = (uint32_t*)NOXTLS_CALLOC(n_limbs_a, sizeof(uint32_t));
    b_limbs = (uint32_t*)NOXTLS_CALLOC(n_limbs_b, sizeof(uint32_t));
    r_limbs = (uint32_t*)NOXTLS_CALLOC(n_limbs_r, sizeof(uint32_t));
    if((a_limbs == NULL) || (b_limbs == NULL) || (r_limbs == NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: noxtls_bn_mul: Memory allocation failed!\n");
        if(a_limbs != NULL) { (void)noxtls_free(a_limbs); }
        if(b_limbs != NULL) { (void)noxtls_free(b_limbs); }
        if(r_limbs != NULL) { (void)noxtls_free(r_limbs); }
        noxtls_secure_zero((result), (size_t)(result_len));
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    bn_bytes_to_limbs_le(a_limbs, n_limbs_a, a, a_len);
    {
        uint32_t limb_len = n_limbs_b;
        uint32_t byte_len = b_len;
        bn_bytes_to_limbs_le(b_limbs, limb_len, b, byte_len);
    }

    /* For each limb of b: r[i..] += a[0..] * b[i]. */
    for(i = 0U; i < n_limbs_b; i += 1U) {
        carry = 0U;
        bn_muladd_hlp(a_limbs, n_limbs_a, b_limbs[i], &r_limbs[i], &carry);
        r_limbs[i + n_limbs_a] = carry;
    }

    bn_limbs_to_bytes_be(result, result_len, r_limbs, n_limbs_r);

    (void)noxtls_free(a_limbs);
    (void)noxtls_free(b_limbs);
    (void)noxtls_free(r_limbs);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Right shift big integer by one bit (divide by 2)
 * 
 * @param a Big integer
 * @param len Length of the big integer
 */
noxtls_return_t noxtls_bn_rshift1(uint8_t *a, uint32_t len)
{
    int32_t i = 0;
    uint8_t carry = 0U;

    if(a == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* Iterate from MSB to LSB for big-endian representation */
    for(i = 0; i < (int32_t)len; i += 1) {
        uint8_t byte = a[i];
        uint8_t lsb = (uint8_t)(byte & 1U);
        a[i] = (uint8_t)(((uint32_t)byte >> 1U) | (uint32_t)carry);
        carry = (lsb != 0U) ? 0x80U : 0U;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ---- Modular reduction helpers (big-endian) ---- */
/**
 * @brief Strip leading zeros from a big integer
 * 
 * @param a Big integer
 * @param len Length of the big integer
 * @return const uint8_t* Pointer to the big integer
 */
static const uint8_t *bn_strip_leading_zeros(const uint8_t *a, uint32_t *len)
{
    const uint8_t *ptr = a;
    if((ptr == NULL) || (len == NULL)) {
        return ptr;
    }
    while((*len > 0U) && (ptr[0] == 0U)) {
        ptr = &ptr[1];
        (*len)--;
    }
    return ptr;
}

/**
 * @brief Copy a big integer
 * 
 * @param dst Destination big integer
 * @param dst_len Length of the destination big integer
 * @param src Source big integer
 * @param src_len Length of the source big integer
 * @return NOXTLS_RETURN_SUCCESS on success, error code on null/invalid parameters
 */
static noxtls_return_t bn_copy_aligned(uint8_t *dst, uint32_t dst_len, const uint8_t *src, uint32_t src_len)
{
    if(dst == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(src == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(dst_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_secure_zero((dst), (size_t)(dst_len));
    if(src_len >= dst_len) {
        noxtls_copy_u8(dst, (size_t)dst_len, &src[(src_len - dst_len)], (size_t)dst_len);
    } else {
        /* MISRA 15.7: final else path */
        noxtls_copy_u8(&dst[(dst_len - src_len)], (size_t)dst_len, src, (size_t)src_len);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ---- 32-bit limb helpers (little-endian limbs) ---- */

/**
 * @brief Convert big-endian bytes to little-endian 32-bit limbs.
 * @internal
 *
 * @param[out] limbs Output limb array
 * @param[in] limb_len Capacity of @p limbs in 32-bit words
 * @param[in] bytes Input byte array (big-endian)
 * @param[in] byte_len Input length in bytes
 * @return void
 */
static void bn_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len)
{
    uint32_t i = 0U;
    if((limbs == NULL) || (limb_len == 0U)) {
        return;
    }
    noxtls_secure_zero((limbs), ((size_t)(limb_len * sizeof(uint32_t))));
    if((bytes == NULL) || (byte_len == 0U)) {
        return;
    }
    for(i = 0U; i < byte_len; i += 1U) {
        uint32_t limb_idx = (uint32_t)(i >> 2U);
        uint32_t b = (uint32_t)bytes[byte_len - 1U - i];
        if(limb_idx >= limb_len) {
            break;
        }
        switch(i & 3U) {
        case 0U: limbs[limb_idx] |= b; break;
        case 1U: limbs[limb_idx] |= (b << 8U); break;
        case 2U: limbs[limb_idx] |= (b << 16U); break;
        default: limbs[limb_idx] |= (b << 24U); break;
        }
    }
}

/**
 * @brief Convert little-endian 32-bit limbs to big-endian bytes.
 * @internal
 *
 * @param[out] out Output byte buffer (big-endian)
 * @param[in] out_len Output buffer length in bytes
 * @param[in] limbs Input limb array (little-endian)
 * @param[in] limb_len Number of input limbs
 * @return void
 */
static void bn_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len)
{
    uint32_t i = 0U;
    if((out == NULL) || (out_len == 0U)) {
        return;
    }
    noxtls_secure_zero((out), (size_t)(out_len));
    if((limbs == NULL) || (limb_len == 0U)) {
        return;
    }
    for(i = 0U; i < out_len; i += 1U) {
        uint32_t limb_idx = (uint32_t)(i >> 2U);
        uint8_t v = 0U;
        if(limb_idx < limb_len) {
            uint32_t limb = limbs[limb_idx];
            switch(i & 3U) {
            case 0U: v = (uint8_t)limb; break;
            case 1U: v = (uint8_t)(limb >> 8U); break;
            case 2U: v = (uint8_t)(limb >> 16U); break;
            default: v = (uint8_t)(limb >> 24U); break;
            }
        }
        out[out_len - 1U - i] = v;
    }
}

/**
 * @brief Compare two limb arrays: return 1 if a >= b, else 0.
 * @internal
 *
 * @param[in] a First limb array
 * @param[in] b Second limb array
 * @param[in] limb_len Number of limbs
 * @return 1 if @p a >= @p b, 0 otherwise
 */
static int bn_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    int32_t i = 0;
    if((a == NULL) || (b == NULL) || (limb_len == 0U)) {
        return 0;
    }
    for(i = (int32_t)limb_len - 1; i >= 0; i -= 1) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : 0;
        }
    }
    return 1;
}

/**
 * @brief In-place limb subtraction: a -= b.
 * @internal
 *
 * @param[in,out] a Minuend limb array (updated in place)
 * @param[in] b Subtrahend limb array
 * @param[in] limb_len Number of limbs
 * @return void
 */
static void bn_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    uint64_t borrow = 0;
    uint32_t i = 0U;
    if((a == NULL) || (b == NULL) || (limb_len == 0U)) {
        return;
    }
    for(i = 0U; i < limb_len; i += 1U) {
        uint64_t av = (uint64_t)a[i];
        uint64_t bv = (uint64_t)b[i] + borrow;
        if(av < bv) {
            a[i] = (uint32_t)((av + (1ULL << 32U)) - bv);
            borrow = 1;
        } else {
            a[i] = (uint32_t)(av - bv);
            borrow = 0;
        }
    }
}

/**
 * @brief Subtract @p b from @p a over @p n limbs.
 * @internal
 *
 * @param[in,out] a Minuend limb array (updated in place)
 * @param[in] b Subtrahend limb array
 * @param[in] n Number of limbs
 * @return 1 if borrow out, 0 otherwise
 */
static int bn_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n)
{
    uint64_t borrow = 0;
    uint32_t i = 0U;
    if((a == NULL) || (b == NULL) || (n == 0U)) {
        return 0;
    }
    for(i = 0U; i < n; i += 1U) {
        uint64_t av = (uint64_t)a[i];
        uint64_t bv = (uint64_t)b[i] + borrow;
        if(av < bv) {
            a[i] = (uint32_t)((av + (1ULL << 32U)) - bv);
            borrow = 1;
        } else {
            a[i] = (uint32_t)(av - bv);
            borrow = 0;
        }
    }
    return (int)borrow;
}

/**
 * @brief Left-shift a limb array by one bit in place.
 * @internal
 *
 * @param[in,out] a Limb array
 * @param[in] limb_len Number of limbs
 * @return void
 */
static void bn_lshift1_limbs(uint32_t *a, uint32_t limb_len)
{
    uint32_t i = 0U;
    uint32_t carry = 0U;
    if((a == NULL) || (limb_len == 0U)) {
        return;
    }
    for(i = 0U; i < limb_len; i += 1U) {
        uint32_t new_carry = (uint32_t)((a[(uint32_t)i] >> 31U) & 1U);
        a[i] = (a[i] << 1U) | carry;
        carry = new_carry;
    }
}

/**
 * @brief Count leading zero bits in a 32-bit word.
 * @internal
 *
 * @param[in] x Input value
 * @return Number of leading zero bits (32 if @p x is zero)
 */
static uint32_t bn_clz(uint32_t x)
{
    uint32_t v = x;
    uint32_t c = 0U;
    if(v == 0U) { return 32U; }
    while((v & 0x80000000U) == 0U) { c += 1U; v <<= 1U; }
    return c;
}

/**
 * @brief Left-shift limbs by @p k bits (0 <= k <= 31).
 * @internal
 *
 * @param[in,out] a Limb array
 * @param[in] len Number of limbs
 * @param[in] k Shift count in bits
 * @return void
 */
static void bn_limbs_shl(uint32_t *a, uint32_t len, uint32_t k)
{
    uint32_t step = 0U;
    if((a == NULL) || (len == 0U) || (k == 0U)) { return; }
    if(k > 31U) { return; }
    /* Repeat 1-bit shifts: avoids variable shift counts (12.2) and large switches (16.3). */
    for(step = 0U; step < k; step += 1U) {
        uint32_t i = 0U;
        uint32_t carry = 0U;
        for(i = 0U; i < len; i += 1U) {
            uint32_t v = a[i];
            a[i] = (uint32_t)((v << 1U) | carry);
            carry = (uint32_t)(v >> 31U);
        }
    }
}

/**
 * @brief Right-shift limbs by @p k bits (0 <= k <= 31).
 * @internal
 *
 * @param[in,out] a Limb array
 * @param[in] len Number of limbs
 * @param[in] k Shift count in bits
 * @return void
 */
static void bn_limbs_shr(uint32_t *a, uint32_t len, uint32_t k)
{
    uint32_t step = 0U;
    if((a == NULL) || (len == 0U) || (k == 0U)) { return; }
    if(k > 31U) { return; }
    for(step = 0U; step < k; step += 1U) {
        int32_t i = 0;
        uint32_t carry = 0U;
        for(i = (int32_t)len - 1; i >= 0; i -= 1) {
            uint32_t v = a[i];
            a[i] = (uint32_t)((v >> 1U) | carry);
            carry = (uint32_t)(v << 31U);
        }
    }
}

/**
 * @brief Knuth division step: subtract q*mod from rem[start..start+n].
 * @internal
 *
 * @param[in,out] rem Remainder limb buffer
 * @param[in] start Starting limb index
 * @param[in] q Quotient digit
 * @param[in] mod Divisor limbs
 * @param[in] n Divisor limb count
 * @return 1 if borrow out, 0 otherwise
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): subtraction kernel keeps Knuth D-layout (start,q,mod,n). */
static int bn_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q,
                          const uint32_t *mod, uint32_t n)
{
    uint64_t carry = 0U;
    uint64_t borrow = 0;
    uint32_t i = 0U;
    for(i = 0U; i < n; i += 1U) {
        const uint64_t prod = ((uint64_t)mod[i] * (uint64_t)q) + carry;
        const uint64_t sub = (uint64_t)(uint32_t)prod + borrow;
        const uint64_t rem_i = (uint64_t)rem[start + i];

        carry = (uint32_t)(prod >> 32U);
        if(rem_i < sub) {
            rem[start + i] = (uint32_t)(rem_i + (1ULL << 32U) - sub);
            borrow = 1;
        } else {
            rem[start + i] = (uint32_t)(rem_i - sub);
            borrow = 0;
        }
    }
    {
        const uint64_t k = (uint64_t)(carry + borrow);
        uint64_t rem_hi = (uint64_t)rem[start + n];
        uint64_t diff = (uint64_t)(rem_hi - k);
        rem[start + n] = (uint32_t)diff;
        return (rem_hi < k) ? 1 : 0;
    }
}

/**
 * @brief Add mod to rem[start..start+n]; return high carry.
 * @internal
 *
 * @param[in,out] rem Remainder limb buffer
 * @param[in] start Starting limb index
 * @param[in] mod Addend limbs (modulus)
 * @param[in] n Limb count
 * @return Carry out (0 or 1)
 */
static uint32_t bn_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n)
{
    uint64_t carry = 0U;
    uint32_t i = 0U;
    for(i = 0U; i < n; i += 1U) {
        uint64_t sum = (uint64_t)rem[start + i] + (uint64_t)mod[i] + carry;
        rem[start + i] = (uint32_t)sum;
        carry = (uint32_t)(sum >> 32U);
    }
    {
        uint64_t sum_hi = (uint64_t)rem[start + n] + carry;
        rem[start + n] = (uint32_t)sum_hi;
        return (uint32_t)(sum_hi >> 32U);
    }
}

/**
 * @brief Fast modular reduction when dividend length is exactly 2 * modulus length.
 * @internal
 *
 * Uses Knuth limb-digit division (O(n) steps). Typical ECDSA sizes: 64/32, 96/48, 132/66.
 *
 * @param[out] rem_out Remainder buffer (@p mod_len bytes, big-endian)
 * @param[in] mod_len Modulus length in bytes
 * @param[in] a Dividend (big-endian)
 * @param[in] a_len Dividend length in bytes
 * @param[in] mod Modulus (big-endian)
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
static noxtls_return_t bn_mod_2n_by_n_limb(uint8_t *rem_out, uint32_t mod_len,
                                           const uint8_t *a, uint32_t a_len, const uint8_t *mod)
{
    /* Stack path threshold for typical ECDSA moduli (P-521 -> 66B * 2). Keep macros
     * for the function only; do not #undef (MISRA 20.5). Unique BN_MOD_2N_ prefix. */
    const uint32_t bn_mod_2n_stack_max_mod_len = 132U;
    const uint32_t bn_mod_2n_stack_max_limbs = (132U + 3U) >> 2U;
    const uint32_t n = (uint32_t)((mod_len + 3U) >> 2U);  /* modulus limbs */
    const uint32_t m = (uint32_t)(n * 2U);               /* dividend limbs for 2n-byte input */
    uint32_t *u = NULL;                      /* dividend/remainder, n*2 + 1 limbs */
    uint32_t *v = NULL;                      /* modulus limbs */
    uint8_t *a_padded = NULL;
    uint8_t a_padded_stack[132U * 2U];
    uint32_t v_stack[(132U + 3U) >> 2U];
    uint32_t u_stack[(((132U + 3U) >> 2U) * 2U) + 1U];
    int use_stack = 0;
    const uint8_t *a_sig = a;
    uint32_t norm_shift = 0;
    uint32_t j = 0U;
    int do_trace = (((g_bn_debug_mod_2n_by_n != 0) && ((a_len == 96U) && (mod_len == 48U))) ? 1 : 0);
    uint32_t a_nbytes = a_len;

    if((rem_out == NULL) || (a == NULL) || (mod == NULL) || (mod_len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Always log entry when debug flag is on, so redirect 2> file gets something. */
    if(g_bn_debug_mod_2n_by_n != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] called: a_nbytes=%u mod_len=%u do_trace=%d\n",
                (uint32_t)a_nbytes, (uint32_t)mod_len, do_trace);
    }

    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"\n[bn_mod_2n_by_n] === ENTRY a_nbytes=%u mod_len=%u n=%u m=%u ===\n",
                (uint32_t)a_nbytes, (uint32_t)mod_len, (uint32_t)n, (uint32_t)m);
        bn_debug_bytes(NULL, a, a_nbytes, 8);
        bn_debug_bytes(NULL, &a[(a_nbytes - 8U)], 8U, 0U);
        bn_debug_bytes(NULL, mod, mod_len, 8);
        bn_debug_bytes(NULL, &mod[(mod_len - 8U)], 8U, 0U);
    }

    a_sig = bn_strip_leading_zeros(a_sig, &a_nbytes);
    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after strip_leading_zeros: a_nbytes=%u\n", (uint32_t)a_nbytes);
    }
    if(a_nbytes == 0U) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        int32_t a_lt_mod = 0;
        if(a_nbytes < mod_len) {
            a_lt_mod = 1;
        } else if(a_nbytes == mod_len) {
            if(noxtls_bn_cmp(a_sig, mod, mod_len) < 0) {
                a_lt_mod = 1;
            }
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }
        if(a_lt_mod != 0) {
            if(bn_copy_aligned(rem_out, mod_len, a_sig, a_nbytes) != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero((rem_out), (size_t)(mod_len));
                return NOXTLS_RETURN_FAILED;
            }
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    if(a_nbytes > (mod_len * 2U)) {
        return NOXTLS_RETURN_FAILED; /* caller should use general path */
    }
    if(mod_len > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(n > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }

    use_stack = (mod_len <= bn_mod_2n_stack_max_mod_len) ? 1 : 0;
    (void)bn_mod_2n_stack_max_limbs;
    if(use_stack != 0) {
        a_padded = a_padded_stack;
        v = v_stack;
        u = u_stack;
        noxtls_secure_zero((a_padded), ((size_t)mod_len * 2U));
        noxtls_secure_zero((v), ((size_t)n * sizeof(uint32_t)));
        noxtls_secure_zero((u), ((size_t)(m + 1U) * sizeof(uint32_t)));
    } else {
        a_padded = (uint8_t*)NOXTLS_CALLOC((size_t)mod_len * 2U, 1);
        v = (uint32_t*)NOXTLS_CALLOC(n, sizeof(uint32_t));
        u = (uint32_t*)NOXTLS_CALLOC(m + 1U, sizeof(uint32_t));
        if((a_padded == NULL) || (v == NULL) || (u == NULL)) {
            if(a_padded != NULL) { (void)noxtls_free(a_padded); }
            if(v != NULL) { (void)noxtls_free(v); }
            if(u != NULL) { (void)noxtls_free(u); }
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    noxtls_copy_u8(&a_padded[((mod_len * 2U) - a_nbytes)], (size_t)mod_len * 2U, a_sig, (size_t)a_nbytes);
    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] a_padded offset=%u (pad %u zero bytes)\n",
                (uint32_t)((mod_len * 2U) - a_nbytes), (uint32_t)((mod_len * 2U) - a_nbytes));
        bn_debug_bytes(NULL, a_padded, mod_len * 2U, 12);
        bn_debug_bytes(NULL, &a_padded[((mod_len * 2U) - 12U)], 12U, 0U);
    }

    bn_bytes_to_limbs_le(v, n, mod, mod_len);
    bn_bytes_to_limbs_le(u, m, a_padded, mod_len * 2U);
    u[m] = 0U; /* extra high limb used by normalization/subtraction */

    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after bytes_to_limbs_le:\n");
        bn_debug_limbs(NULL, v, n);
        bn_debug_limbs(NULL, u, m);
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] u[m]=u[%u]=%u\n", (uint32_t)m, (uint32_t)u[m]);
    }

    if(v[n - 1U] == 0U) {
        if(use_stack == 0) {
            (void)noxtls_free(a_padded);
            (void)noxtls_free(v);
            (void)noxtls_free(u);
        }
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return NOXTLS_RETURN_FAILED;
    }

    /* Knuth D1 normalization: ensure top divisor limb has MSB set. */
    norm_shift = bn_clz(v[n - 1U]);
    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] norm_shift = clz(v[n-1]) = %u\n", norm_shift);
    }
    if(norm_shift > 0U) {
        /* Shift u[0..m] left by norm_shift using 1-bit steps (Rule 12.2). */
        uint32_t step = 0U;
        for(step = 0U; step < norm_shift; step += 1U) {
            uint32_t carry = 0U;
            for(j = 0U; j <= m; j += 1U) {
                uint32_t vj = u[j];
                u[j] = (uint32_t)((vj << 1U) | carry);
                carry = (uint32_t)(vj >> 31U);
            }
        }
        bn_limbs_shl(v, n, norm_shift);
    }
    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after normalization:\n");
        bn_debug_limbs(NULL, v, n);
        bn_debug_limbs(NULL, u, m + 1U);
    }

    /* Knuth D2..D6 for m=2n, divisor length n. */
    for(j = m - n; (int32_t)j >= 0; j -= 1U) {
        uint64_t num = ((uint64_t)u[j + n] << 32U) | (uint64_t)u[j + n - 1U];
        uint64_t den = (uint64_t)v[n - 1U];
        uint64_t qhat64 = (uint64_t)(num / den);
        uint64_t rhat = (uint64_t)(num - (qhat64 * den));
        uint32_t qhat = 0U;

        if(qhat64 > 0xFFFFFFFFULL) {
            qhat = 0xFFFFFFFFU;
            /* Keep rhat consistent with clamped qhat. */
            rhat = num - ((uint64_t)qhat * den);
        } else {
            qhat = (uint32_t)qhat64;
        }

        if(n > 1U) {
            {
                uint8_t qhat_adj_done = 0U;
                while(qhat_adj_done == 0U) {
                    uint64_t lhs = (uint64_t)qhat * (uint64_t)v[n - 2U];
                    /* rhs = (rhat << 32U) + u[j+n-2] can exceed 64 bits if rhat>=2^32.
                     * Compare safely without overflowing 64-bit intermediates. */
                    if((rhat >> 32U) != 0U) {
                        qhat_adj_done = 1U;
                    } else {
                        uint64_t rhs = (uint64_t)((rhat << 32U) + (uint64_t)u[j + n - 2U]);
                        if(lhs <= rhs) {
                            qhat_adj_done = 1U;
                        } else {
                            qhat -= 1U;
                            rhat += den;
                        }
                    }
                }
            }
        }

        if(do_trace != 0) {
            (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] --- j=%u num=0x%016llX den=0x%08llX qhat64=%llu qhat=0x%08X rhat=%llu\n",
                    (uint32_t)j, (unsigned long long)num, (unsigned long long)den,
                    (unsigned long long)qhat64, (uint32_t)qhat, (unsigned long long)rhat);
            (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n]     u[j..j+n] before: u[%u]=0x%08X u[%u]=0x%08X ... u[%u]=0x%08X u[%u]=0x%08X\n",
                    (uint32_t)j, (uint32_t)u[j], (uint32_t)(j + 1U), (uint32_t)u[j + 1U],
                    (uint32_t)(j + n - 1U), (uint32_t)u[j + n - 1U], (uint32_t)(j + n), (uint32_t)u[j+n]);
        }

        if(qhat != 0U) {
            int borrow = 0;
            borrow = bn_limb_mul_sub(u, j, qhat, v, n);
            if(borrow != 0) {
                /* qhat was one too large: add divisor back (Knuth D6). */
                uint32_t carry_out = bn_limb_add_at(u, j, v, n);
                if((carry_out != 0U) && ((j + n + 1U) <= m)) {
                    u[j + n + 1U] += carry_out;
                }
                if(do_trace != 0) { (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n]     borrow=1 -> add v back\n"); }
            }
            if(do_trace != 0) {
                (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n]     u[j..j+n] after:  u[%u]=0x%08X u[%u]=0x%08X ... u[%u]=0x%08X u[%u]=0x%08X\n",
                        (uint32_t)j, (uint32_t)u[j], (uint32_t)(j + 1U), (uint32_t)u[j + 1U],
                        (uint32_t)(j + n - 1U), (uint32_t)u[j + n - 1U], (uint32_t)(j + n), (uint32_t)u[j+n]);
            }
        }
    }

    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after division loop:\n");
        bn_debug_limbs(NULL, u, n);
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] u[n]=u[%u]=%u  bn_ge_limbs(u,v,n)=%d\n",
                (uint32_t)n, (uint32_t)u[n], bn_ge_limbs(u, v, n));
    }

    /* Remainder is in u[0..n-1], possibly with u[n] > 0 or u[0..n-1] >= v if qhat was too small.
     * Reduce to u[0..n-1] < v (normalized) so unnormalization yields remainder < mod. */
    {
        uint32_t corr = 0U;
        while((u[n] != 0U) || (bn_ge_limbs(u, v, n) != 0)) {
            if(bn_sub_limbs_borrow(u, v, n) != 0) {
                if(u[n] != 0U) {
                    u[n]--;
                }
                else {
                    /* MISRA 15.7: final else path */
                    break;
                }
            }
            corr += 1U;
            if((do_trace != 0) && (corr <= 5U)) {
                (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] correction step %u: u[n]=%u\n", (uint32_t)corr, (uint32_t)u[n]);
            }
        }
        if((do_trace != 0) && (corr > 0U)) {
            (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] total correction steps: %u\n", (uint32_t)corr);
        }
    }

    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after correction loop:\n");
        bn_debug_limbs(NULL, u, n);
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] u[n]=%u\n", (uint32_t)u[n]);
    }

    /* D8 unnormalize remainder. */
    if(norm_shift > 0U) {
        bn_limbs_shr(u, n, norm_shift);
    }

    if(do_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] after unnormalize (shift right %u):\n", norm_shift);
        bn_debug_limbs(NULL, u, n);
    }

    bn_limbs_to_bytes_be(rem_out, mod_len, u, n);

    if(do_trace != 0) {
        bn_debug_bytes(NULL, rem_out, mod_len, 0);
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] cmp(rem_out, mod) = %d (>=0 means rem_out >= mod)\n",
                (void)noxtls_bn_cmp(rem_out, mod, mod_len));
    }

    if(use_stack == 0) {
        (void)noxtls_free(a_padded);
        (void)noxtls_free(v);
        (void)noxtls_free(u);
    }

    /* Final canonicalization to [0, mod). */
    if(noxtls_bn_cmp(rem_out, mod, mod_len) >= 0) {
        if(do_trace != 0) {
            (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] final: rem_out >= mod -> subtract mod\n");
        }
        if(bn_sub_inplace(rem_out, mod, mod_len) != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
        }
    }
    if(do_trace != 0) {
        bn_debug_bytes(NULL, rem_out, mod_len, 0);
        (void)noxtls_debug_printf((const uint8_t *)"[bn_mod_2n_by_n] === EXIT ===\n\n");
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Modular reduction via bitwise long division on 32-bit limbs.
 * @internal
 *
 * Computes rem = a mod b without byte-digit quotient estimation loops.
 *
 * @param[out] rem_out Remainder buffer (@p mod_len bytes, big-endian)
 * @param[in] mod_len Output modulus length in bytes
 * @param[in] a Dividend (big-endian)
 * @param[in] a_len Dividend length in bytes
 * @param[in] b Divisor/modulus (big-endian)
 * @param[in] b_len Divisor length in bytes
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
static uint32_t bn_u8_bit(uint8_t byte, uint32_t bit_index)
{
    static const uint8_t s_bit8[8] = {
        0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
    };
    return ((byte & s_bit8[bit_index & 7U]) != 0U) ? 1U : 0U;
}

static noxtls_return_t bn_div_remainder_limb(uint8_t *rem_out, uint32_t mod_len,
                                             const uint8_t *a, uint32_t a_len,
                                             const uint8_t *b, uint32_t b_len)
{
    uint32_t limb_len = 0U;
    uint32_t *mod_limbs = NULL;
    uint32_t *rem_limbs = NULL;
    const uint8_t *a_sig = a;
    const uint8_t *b_sig = b;
    uint32_t a_sig_len = a_len;
    uint32_t b_sig_len = b_len;

    if((rem_out == NULL) || (mod_len == 0U) || (a == NULL) || (b == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    a_sig = bn_strip_leading_zeros(a_sig, &a_sig_len);
    b_sig = bn_strip_leading_zeros(b_sig, &b_sig_len);

    if(b_sig_len == 0U) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(a_sig_len == 0U) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return NOXTLS_RETURN_SUCCESS;
    }
    {
        int32_t a_lt_b = 0;
        if(a_sig_len < b_sig_len) {
            a_lt_b = 1;
        } else if(a_sig_len == b_sig_len) {
            if(noxtls_bn_cmp(a_sig, b_sig, b_sig_len) < 0) {
                a_lt_b = 1;
            }
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }
        if(a_lt_b != 0) {
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
            noxtls_copy_u8(&rem_out[(mod_len - a_sig_len)], (size_t)mod_len, a_sig, (size_t)a_sig_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    limb_len = (b_sig_len + 3U) >> 2U;
    mod_limbs = (uint32_t*)NOXTLS_CALLOC(limb_len, sizeof(uint32_t));
    rem_limbs = (uint32_t*)NOXTLS_CALLOC(limb_len + 1U, sizeof(uint32_t));
    if((mod_limbs == NULL) || (rem_limbs == NULL)) {
        if(mod_limbs != NULL) { (void)noxtls_free(mod_limbs); }
        if(rem_limbs != NULL) { (void)noxtls_free(rem_limbs); }
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return NOXTLS_RETURN_FAILED;
    }

    bn_bytes_to_limbs_le(mod_limbs, limb_len, b_sig, b_sig_len);

    for(uint32_t byte_idx = 0U; byte_idx < a_sig_len; byte_idx += 1U) {
        uint8_t byte = a_sig[byte_idx];
        for(int bit = 7; bit >= 0; bit -= 1) {
            uint32_t in_bit = bn_u8_bit(byte, (uint32_t)bit);
            bn_lshift1_limbs(rem_limbs, limb_len + 1U);
            rem_limbs[0] |= in_bit;
            if((rem_limbs[limb_len] != 0U) || (bn_ge_limbs(rem_limbs, mod_limbs, limb_len) != 0)) {
                uint64_t hi = (uint64_t)rem_limbs[limb_len];
                bn_sub_limbs(rem_limbs, mod_limbs, limb_len);
                if(hi > 0U) {
                    rem_limbs[limb_len] = (uint32_t)(hi - 1U);
                }
            }
        }
    }

    bn_limbs_to_bytes_be(rem_out, mod_len, rem_limbs, limb_len);
    (void)noxtls_free(mod_limbs);
    (void)noxtls_free(rem_limbs);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Left-shift a big-endian byte buffer by one bit; LSB becomes @p bit.
 * @internal
 *
 * Processes from LSB (buf[len - 1U]) toward MSB (buf[0]).
 *
 * @param[in,out] buf Big-endian integer buffer
 * @param[in] len Buffer length in bytes
 * @param[in] bit New least significant bit (0 or 1)
 * @return void
 */
NOXTLS_UNUSED_ATTR
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): bit-shift helper uses canonical (buf,len,bit) ordering. */
static void bn_shift_l_one(uint8_t *buf, uint32_t len, uint8_t bit)
{
    uint8_t carry = bit;
    uint32_t i = len;

    if((buf == NULL) || (len == 0U)) {
        return;
    }
    while(i > 0U) {
        uint8_t byte = (uint8_t)(buf[i - 1U]);
        uint8_t new_carry = (uint8_t)(((uint32_t)byte >> 7U) & 1U);
        buf[i - 1U] = (uint8_t)(((uint32_t)byte << 1U) | (uint32_t)carry);
        carry = new_carry;
        i -= 1U;
    }
}

/* Unsigned compare: 1 if a >= b, 0 else. */
/**
 * @brief Unsigned compare: 1 if a >= b, 0 else.
 * 
 * @param a First big integer
 * @param b Second big integer
 * @param len Length of the big integers
 * @return int 1 if a >= b, 0 otherwise
 */
static int bn_ge(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i = 0U;

    if((a == NULL) || (b == NULL) || (len == 0U)) {
        return 0;
    }
    for(i = 0U; i < len; i += 1U) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : 0;
        }
    }
    return 1;
}

/* In-place a -= b (a,b same length). Borrow LSB to MSB. */
/**
 * @brief In-place a -= b (a,b same length). Borrow LSB to MSB.
 * 
 * @param a First big integer
 * @param b Second big integer
 * @param len Length of the big integers
 * @return NOXTLS_RETURN_SUCCESS on success, error code on null/invalid parameters
 */
static noxtls_return_t bn_sub_inplace(uint8_t *a, const uint8_t *b, uint32_t len)
{
    int borrow = 0;
    int i = 0;

    if(a == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(b == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    i = (int)len - 1;
    for(; i >= 0; i -= 1) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = (uint8_t)diff;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Strip leading zero bytes in place; update *len. */
/**
 * @brief Strip leading zero bytes in place; update *len.
 * 
 * @param buf Big integer
 * @param len Length of the big integer
 */

/**
 * @brief Overlap-safe byte move (memmove semantics) without <string.h>.
 * @param[out] dst Destination buffer.
 * @param[in] src Source buffer.
 * @param[in] n Number of bytes to move.
 */
static void bn_u8_move(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    uint32_t i = 0U;

    if((dst == NULL) || (src == NULL) || (n == 0U) || ((uintptr_t)dst == (uintptr_t)src)) {
        return;
    }
    if((uintptr_t)dst < (uintptr_t)src) {
        for(i = 0U; i < n; i += 1U) {
            dst[i] = src[i];
        }
    } else {
        i = n;
        while(i > 0U) {
            i -= 1U;
            dst[i] = src[i];
        }
    }
}


/**
 * @brief Left-shift one byte by a fixed 1..7 bit count (MISRA 12.2-safe).
 */
static uint8_t bn_shl_byte(uint8_t byte, uint32_t shift, uint8_t *carry_out, uint8_t carry_in)
{
    uint8_t out = 0U;
    uint8_t carry = 0U;
    switch(shift) {
    case 1U: out = (uint8_t)(((uint32_t)byte << 1U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 7U); break;
    case 2U: out = (uint8_t)(((uint32_t)byte << 2U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 6U); break;
    case 3U: out = (uint8_t)(((uint32_t)byte << 3U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 5U); break;
    case 4U: out = (uint8_t)(((uint32_t)byte << 4U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 4U); break;
    case 5U: out = (uint8_t)(((uint32_t)byte << 5U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 3U); break;
    case 6U: out = (uint8_t)(((uint32_t)byte << 6U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 2U); break;
    case 7U: out = (uint8_t)(((uint32_t)byte << 7U) | (uint32_t)carry_in); carry = (uint8_t)((uint32_t)byte >> 1U); break;
    default: out = byte; carry = 0U; break;
    }
    *carry_out = carry;
    return out;
}

/**
 * @brief Right-shift one byte by a fixed 1..7 bit count (MISRA 12.2-safe).
 */
static uint8_t bn_shr_byte(uint8_t byte, uint32_t shift, uint8_t *carry_out, uint8_t carry_in)
{
    uint8_t out = 0U;
    uint8_t carry = 0U;
    switch(shift) {
    case 1U: out = (uint8_t)(((uint32_t)byte >> 1U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x01U) << 7U); break;
    case 2U: out = (uint8_t)(((uint32_t)byte >> 2U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x03U) << 6U); break;
    case 3U: out = (uint8_t)(((uint32_t)byte >> 3U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x07U) << 5U); break;
    case 4U: out = (uint8_t)(((uint32_t)byte >> 4U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x0FU) << 4U); break;
    case 5U: out = (uint8_t)(((uint32_t)byte >> 5U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x1FU) << 3U); break;
    case 6U: out = (uint8_t)(((uint32_t)byte >> 6U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x3FU) << 2U); break;
    case 7U: out = (uint8_t)(((uint32_t)byte >> 7U) | (uint32_t)carry_in); carry = (uint8_t)(((uint32_t)byte & 0x7FU) << 1U); break;
    default: out = byte; carry = 0U; break;
    }
    *carry_out = carry;
    return out;
}


static void bn_strip_leading_zeros_inplace(uint8_t *buf, uint32_t *len)
{
    uint32_t start = 0U;

    if((buf == NULL) || (len == NULL)) {
        return;
    }
    while((start < *len) && (buf[start] == 0U)) {
        start += 1U;
    }
    if(start > 0U) {
        if(start >= *len) {
            *len = 0;
            return;
        }
        bn_u8_move(buf, &buf[start], (uint32_t)(*len - start));
        *len -= start;
    }
}

/* Return number of bits (position of top 1, 1..len*8; 0 if buf is zero). Big-endian. */
/**
 * @brief Return number of bits (position of top 1, 1..len*8; 0 if buf is zero). Big-endian.
 * 
 * @param buf Big integer
 * @param len Length of the big integer
 * @return uint32_t Number of bits
 */
static uint32_t bn_bitlen(const uint8_t *buf, uint32_t len)
{
    uint32_t i = 0U;
    uint8_t top = 0U;
    uint32_t bits = 0U;

    if((buf == NULL) || (len == 0U)) {
        return 0U;
    }
    while((i < len) && (buf[i] == 0U)) { i += 1U; }
    if(i >= len) {
        return 0U;
    }
    top = buf[i];
    bits = (len - i) << 3U;
    while(((top & 0x80U) == 0U) && (bits > 0U)) {
        top = (uint8_t)(top << 1U);
        bits -= 1U;
    }
    return bits;
}

/* Shift buf (big-endian, length *len) left by k bits (0 <= k <= 8). May grow *len by 1. */
/**
 * @brief Shift buf (big-endian, length *len) left by k bits (0 <= k <= 8). May grow *len by 1.
 * 
 * @param buf Big integer
 * @param len Length of the big integer
 * @param k Number of bits to shift
 */
static void bn_shift_l_bits(uint8_t *buf, uint32_t *len, uint32_t k)
{
    uint32_t n = 0U;
    uint8_t carry = 0U;
    uint32_t i = 0U;

    if((buf == NULL) || (len == NULL)) {
        return;
    }
    n = *len;
    if((n == 0U) || (k == 0U)) {
        return;
    }
    if(k >= 8U) {
        /* Left shift by 8 or more: shift by full bytes first, then remaining bits */
        uint32_t byte_shift = (uint32_t)k >> 3U;
        uint32_t bit_shift = k & 7U;
        /* Append zero bytes for full byte shifts */
        for(i = 0U; i < byte_shift; i += 1U) {
            buf[n + i] = 0;
        }
        *len = n + byte_shift;
        /* If there are remaining bits to shift, do a bit shift */
        if(bit_shift > 0U) {
            const uint32_t shift = bit_shift; /* 1..7 */
            carry = 0U;
            i = *len;
            while(i > 0U) {
                uint8_t byte = (uint8_t)(buf[i - 1U]);
                uint8_t next_carry = 0U;
                buf[i - 1U] = bn_shl_byte(byte, shift, &next_carry, carry);
                carry = next_carry;
                i -= 1U;
            }
            if(carry != 0U) {
                /* grow by one byte at the front */
                bn_u8_move(&buf[1], buf, *len);
                buf[0] = carry;
                *len = *len + 1U;
            }
        }
        return;
    }
    carry = 0U;
    i = n;
    {
        const uint32_t shift = k; /* 1..7 */
        while(i > 0U) {
            uint8_t byte = (uint8_t)(buf[i - 1U]);
            uint8_t next_carry = 0U;
            buf[i - 1U] = bn_shl_byte(byte, shift, &next_carry, carry);
            carry = next_carry;
            i -= 1U;
        }
    }
    if(carry != 0U) {
        /* grow by one byte at the front */
        bn_u8_move(&buf[1], buf, n);
        buf[0] = carry;
        *len = n + 1U;
    }
}

/* Shift buf (big-endian, length len) right by k bits (0 <= k <= 8). */
/**
 * @brief Shift buf (big-endian, length len) right by k bits (0 <= k <= 8).
 * 
 * @param buf Big integer
 * @param len Length of the big integer
 * @param k Number of bits to shift
 */
static void bn_shift_r_bits(uint8_t *buf, uint32_t len, uint32_t k)
{
    if((buf == NULL) || (len == 0U) || (k == 0U)) {
        return;
    }
    if(k >= 8U) {
        /* Right shift by 8 or more: shift by full bytes first, then remaining bits */
        uint32_t byte_shift = (uint32_t)k >> 3U;
        uint32_t bit_shift = k & 7U;
        /* For byte shifts: move bytes left (toward MSB), zero the LSB positions */
        if(byte_shift > 0U) {
            if(byte_shift >= len) {
                /* Shift by more bytes than we have - result is zero */
                noxtls_secure_zero((buf), (size_t)(len));
                return;
            }
            /* For right shift by byte_shift bytes: drop the LSB bytes, shift remaining bytes left, zero MSB positions.
             * byte_shift < len here, so new_len = len - byte_shift > 0U */
            uint32_t new_len = (uint32_t)(len - byte_shift);
            bn_u8_move(&buf[byte_shift], buf, new_len);
            noxtls_secure_zero((buf), (size_t)(byte_shift));
        }
        /* If there are remaining bits to shift, do a bit shift */
        if(bit_shift > 0U) {
            uint8_t carry = 0U;
            uint32_t j = 0U;
            const uint32_t shift = bit_shift; /* 1..7 */
            for(j = 0U; j < len; j += 1U) {
                uint8_t byte = buf[j];
                uint8_t next_carry = 0U;
                buf[j] = bn_shr_byte(byte, shift, &next_carry, carry);
                carry = next_carry;
            }
        }
        return;
    }
    /* Propagate from MSB to LSB: low k bits of each byte become high k bits of next. */
    {
        uint8_t carry = 0U;
        uint32_t i = 0U;
        const uint32_t shift = k; /* 1..7 */
        for(i = 0U; i < len; i += 1U) {
            uint8_t byte = buf[i];
            uint8_t next_carry = 0U;
            buf[i] = bn_shr_byte(byte, shift, &next_carry, carry);
            carry = next_carry;
        }
    }
}

#ifdef NOXTLS_BIGNUM_TEST_INTERNAL

/**
 * @brief Test-only wrapper for bn_shift_r_bits.
 * @internal
 *
 * @param[in,out] buf Big-endian buffer
 * @param[in] len Buffer length in bytes
 * @param[in] k Right shift count in bits
 * @return void
 */
void noxtls_bn_test_shift_r_bits(uint8_t *buf, uint32_t len, uint32_t k)
{
    if(buf == NULL) {
        return;
    }
    bn_shift_r_bits(buf, len, k);
}

/**
 * @brief Test-only wrapper for bn_shift_l_bits.
 * @internal
 *
 * @param[in,out] buf Big-endian buffer
 * @param[in,out] len Buffer length in bytes (may grow)
 * @param[in] k Left shift count in bits
 * @return void
 */
void noxtls_bn_test_shift_l_bits(uint8_t *buf, uint32_t *len, uint32_t k)
{
    if((buf == NULL) || (len == NULL)) {
        return;
    }
    bn_shift_l_bits(buf, len, k);
}

/**
 * @brief Test-only wrapper for bn_bytes_to_limbs_le.
 * @internal
 *
 * @param[out] limbs Output limb array
 * @param[in] limb_len Limb array capacity
 * @param[in] bytes Input bytes (big-endian)
 * @param[in] byte_len Input length in bytes
 * @return void
 */
void noxtls_bn_test_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len)
{
    bn_bytes_to_limbs_le(limbs, limb_len, bytes, byte_len);
}

/**
 * @brief Test-only wrapper for bn_limbs_to_bytes_be.
 * @internal
 *
 * @param[out] out Output bytes (big-endian)
 * @param[in] out_len Output length in bytes
 * @param[in] limbs Input limbs (little-endian)
 * @param[in] limb_len Number of input limbs
 * @return void
 */
void noxtls_bn_test_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len)
{
    bn_limbs_to_bytes_be(out, out_len, limbs, limb_len);
}

/**
 * @brief Test-only wrapper for bn_ge_limbs.
 * @internal
 *
 * @param[in] a First limb array
 * @param[in] b Second limb array
 * @param[in] limb_len Number of limbs
 * @return 1 if @p a >= @p b, 0 otherwise
 */
int noxtls_bn_test_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    return bn_ge_limbs(a, b, limb_len);
}

/**
 * @brief Test-only wrapper for bn_sub_limbs.
 * @internal
 *
 * @param[in,out] a Minuend limbs
 * @param[in] b Subtrahend limbs
 * @param[in] limb_len Number of limbs
 * @return void
 */
void noxtls_bn_test_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    bn_sub_limbs(a, b, limb_len);
}

/**
 * @brief Test-only wrapper for bn_sub_limbs_borrow.
 * @internal
 *
 * @param[in,out] a Minuend limbs
 * @param[in] b Subtrahend limbs
 * @param[in] n Number of limbs
 * @return 1 if borrow out, 0 otherwise
 */
int noxtls_bn_test_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n)
{
    return bn_sub_limbs_borrow(a, b, n);
}

/**
 * @brief Test-only wrapper for bn_limb_mul_sub.
 * @internal
 *
 * @param[in,out] rem Remainder limbs
 * @param[in] start Start index
 * @param[in] q Quotient digit
 * @param[in] mod Modulus limbs
 * @param[in] n Limb count
 * @return 1 if borrow out, 0 otherwise
 */
int noxtls_bn_test_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q, const uint32_t *mod, uint32_t n)
{
    return bn_limb_mul_sub(rem, start, q, mod, n);
}

/**
 * @brief Test-only wrapper for bn_limb_add_at.
 * @internal
 *
 * @param[in,out] rem Remainder limbs
 * @param[in] start Start index
 * @param[in] mod Modulus limbs
 * @param[in] n Limb count
 * @return Carry out (0 or 1)
 */
uint32_t noxtls_bn_test_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n)
{
    return bn_limb_add_at(rem, start, mod, n);
}

/**
 * @brief Test-only wrapper for bn_clz.
 * @internal
 *
 * @param[in] x Input value
 * @return Number of leading zero bits (32 if zero)
 */
uint32_t noxtls_bn_test_clz(uint32_t x)
{
    return bn_clz(x);
}

/**
 * @brief Test-only wrapper for bn_limbs_shl.
 * @internal
 *
 * @param[in,out] a Limb array
 * @param[in] len Number of limbs
 * @param[in] k Left shift in bits
 * @return void
 */
void noxtls_bn_test_limbs_shl(uint32_t *a, uint32_t len, uint32_t k)
{
    bn_limbs_shl(a, len, k);
}

/**
 * @brief Test-only wrapper for bn_limbs_shr.
 * @internal
 *
 * @param[in,out] a Limb array
 * @param[in] len Number of limbs
 * @param[in] k Right shift in bits
 * @return void
 */
void noxtls_bn_test_limbs_shr(uint32_t *a, uint32_t len, uint32_t k)
{
    bn_limbs_shr(a, len, k);
}

/**
 * @brief Run only the Knuth D2..D6 division loop on limb arrays (unit tests).
 * @internal
 *
 * @param[in,out] rem_limbs Dividend/remainder limbs (updated in place)
 * @param[in] mod_limbs Divisor/modulus limbs
 * @param[in] n Modulus limb count
 * @param[in] rem_limb_count Dividend limb count (0 = use 2*n)
 * @return void
 */
void noxtls_bn_test_division_loop_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count)
{
    uint32_t j = 0U;
    uint32_t in_count = 0U;
    uint32_t work_count = 0U;
    uint32_t *work = NULL;
    int used_temp = 0;
    const uint32_t two_n = (uint32_t)(n * 2U);

    if((rem_limbs == NULL) || (mod_limbs == NULL) || (n == 0U)) {
        return;
    }
    if(mod_limbs[n - 1U] == 0U) {
        return;
    }

    in_count = (rem_limb_count != 0U) ? rem_limb_count : two_n;
    if(in_count <= n) {
        return;
    }

    /*
     * Production bn_mod_2n_by_n_limb runs D2..D7 with a 2n+1 limb dividend buffer (u[m] overflow limb).
     * For tests that pass exactly 2n limbs, emulate that by using a temporary 2n+1 workspace.
     */
    if(in_count == two_n) {
        work = (uint32_t*)NOXTLS_CALLOC(two_n + 1U, sizeof(uint32_t));
        if(work == NULL) {
            return;
        }
        noxtls_copy_u8((uint8_t *)(void *)(work), (size_t)(two_n * sizeof(uint32_t)), (const uint8_t *)(const void *)(rem_limbs), (size_t)(two_n * sizeof(uint32_t)));
        work[two_n] = 0U;
        work_count = two_n + 1U;
        used_temp = 1;
    } else {
        work = rem_limbs;
        work_count = in_count;
    }

    {
        const uint32_t m = (uint32_t)(work_count - 1U);  /* dividend limbs before overflow; work_count is m + 1 */
        for(j = m - n; (int32_t)j >= 0; j -= 1U) {
            uint64_t num = ((uint64_t)work[j + n] << 32U) | (uint64_t)work[j + n - 1U];
            uint64_t den = (uint64_t)mod_limbs[n - 1U];
            uint64_t qhat64 = (uint64_t)(num / den);
            uint64_t rhat = (uint64_t)(num - qhat64 * den);
            uint32_t q_est = 0U;
            if(qhat64 > 0xFFFFFFFFU) {
                q_est = 0xFFFFFFFFU;
                /* Keep rhat consistent with clamped q_est. */
                rhat = num - (uint64_t)q_est * den;
            } else {
                q_est = (uint32_t)qhat64;
            }
            /* Knuth D3: correction step (n>=2) */
            while(n >= 2U) {
                uint64_t lhs = (uint64_t)q_est * (uint64_t)mod_limbs[n - 2U];
                if((rhat >> 32U) != 0U) {
                    break;
                }
                {
                    uint64_t rhs = (uint64_t)((rhat << 32U) + (uint64_t)work[j + n - 2U]);
                    if(lhs <= rhs) {
                        break;
                    }
                }
                q_est -= 1U;
                rhat += (uint64_t)mod_limbs[n - 1U];
            }
            if(q_est == 0U) {
                continue;
            }
            if(bn_limb_mul_sub(work, j, q_est, mod_limbs, n) != 0) {
                uint32_t carry_out = bn_limb_add_at(work, j, mod_limbs, n);
                if(carry_out != 0U && (j + n + 1U) < work_count) {
                    work[j + n + 1U] += carry_out;
                }
            }
        }
    }

    if(used_temp != 0) {
        noxtls_copy_u8((uint8_t *)(void *)(rem_limbs), (size_t)(two_n * sizeof(uint32_t)), (const uint8_t *)(const void *)(work), (size_t)(two_n * sizeof(uint32_t)));
        (void)noxtls_free(work);
    }
}

/**
 * @brief Normalize a limb remainder into [0, mod) by repeated subtraction (unit tests).
 * @internal
 *
 * @param[in,out] rem_limbs Remainder limbs
 * @param[in] mod_limbs Modulus limbs
 * @param[in] n Modulus limb count
 * @param[in] rem_limb_count Total remainder limb count (0 = use 2*n)
 * @return void
 */
void noxtls_bn_test_normalize_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count)
{
    uint32_t i = 0U;
    const uint32_t max_norm = (uint32_t)((n * 2U) + 8U);
    const uint32_t rem_high_end = (uint32_t)((rem_limb_count != 0U) ? rem_limb_count : (n * 2U));
    uint32_t k = 0U;
    if((rem_limbs == NULL) || (mod_limbs == NULL) || (n == 0U)) {
        return;
    }
    for(k = 0U; k < max_norm; k += 1U) {
        int high_nonzero = 0;
        for(i = n; i < rem_high_end; i += 1U) {
            if(rem_limbs[i] != 0U) { high_nonzero = 1; break; }
        }
        if((high_nonzero == 0) && (bn_ge_limbs(rem_limbs, mod_limbs, n) == 0)) {
            break;
        }
        if(bn_sub_limbs_borrow(rem_limbs, mod_limbs, n) != 0) {
            if(high_nonzero != 0) {
                for(i = n; i < rem_high_end; i += 1U) {
                    if(rem_limbs[i] != 0U) {
                        rem_limbs[i]--;
                        break;
                    }
                    rem_limbs[i] = 0xFFFFFFFFU;
                }
            } else {
                /* MISRA 15.7: final else path */
                (void)bn_limb_add_at(rem_limbs, 0, mod_limbs, n);
                break;
            }
        }
    }
}

/**
 * @brief Test-only wrapper for bn_mod_2n_by_n_limb.
 * @internal
 *
 * @param[out] rem_out Remainder output
 * @param[in] mod_len Modulus length in bytes
 * @param[in] a Dividend
 * @param[in] a_len Dividend length in bytes
 * @param[in] mod Modulus
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_bn_test_mod_2n_by_n_limb(uint8_t *rem_out, uint32_t mod_len,
                                                const uint8_t *a, uint32_t a_len, const uint8_t *mod)
{
    return bn_mod_2n_by_n_limb(rem_out, mod_len, a, a_len, mod);
}

/**
 * @brief Test-only wrapper for bn_div_remainder_limb.
 * @internal
 *
 * @param[out] rem_out Remainder output
 * @param[in] mod_len Output modulus length in bytes
 * @param[in] a Dividend
 * @param[in] a_len Dividend length in bytes
 * @param[in] b Divisor
 * @param[in] b_len Divisor length in bytes
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_bn_test_div_remainder_limb(uint8_t *rem_out, uint32_t mod_len,
                                                  const uint8_t *a, uint32_t a_len,
                                                  const uint8_t *b, uint32_t b_len)
{
    return bn_div_remainder_limb(rem_out, mod_len, a, a_len, b, b_len);
}
#endif


/**
 * @brief In-place a -= b where b is placed with its LSB at a[n-1-lsb_offset]. Returns 1 if borrow out.
 * 
 * @param a First big integer
 * @param n Length of the first big integer
 * @param lsb_offset Offset of the least significant bit
 * @param b Second big integer
 * @param m Length of the second big integer
 * @return int 1 if borrow out, 0 otherwise
 */
static int bn_sub_at(uint8_t *a, uint32_t n, uint32_t lsb_offset, const uint8_t *b, uint32_t m)
{
    int borrow = 0;
    int32_t j = 0;
    int32_t ai = 0;

    if((a == NULL) || (b == NULL) || (n == 0U) || (m == 0U)) {
        return 1; /* assume borrow on invalid params */
    }
    j = (int32_t)m - 1;
    ai = (int32_t)n - 1 - (int32_t)lsb_offset;
    for(; (j >= 0) && (ai >= 0); ) {
        int diff = (int)a[ai] - (int)b[j] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[ai] = (uint8_t)diff;
        j -= 1;
        ai -= 1;
    }
    while((borrow != 0) && (ai >= 0)) {
        int diff = (int)a[ai] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[ai] = (uint8_t)diff;
        ai -= 1;
    }
    return borrow;
}

/**
 * @brief Multiply byte q by big-endian bignum src (len bytes), result in dest (len+1 bytes).
 * 
 * @param dest Destination big integer
 * @param q Byte to multiply
 * @param src Source big integer
 * @param len Length of the big integer
 */
static void bn_mul_byte(uint8_t *dest, uint8_t q, const uint8_t *src, uint32_t len)
{
    uint16_t carry = 0U;
    uint32_t j = len;

    if((dest == NULL) || (src == NULL) || (len == 0U)) {
        return;
    }
    while(j > 0U) {
        j -= 1U;
        uint16_t prod = (uint16_t)(((uint16_t)src[j] * (uint16_t)q) + carry);
        dest[j + 1U] = (uint8_t)(prod & 0xFFU);
        {
            uint32_t next_carry = (uint32_t)prod;
            next_carry >>= 8U;
            carry = (uint16_t)next_carry;
        }
    }
    dest[0] = (uint8_t)(carry & 0xFFU);
}


/**
 * @brief In-place a += b where b is placed with its LSB at a[lsb_offset]. a length n, b length m.
 * 
 * @param a First big integer
 * @param n Length of the first big integer
 * @param lsb_offset Offset of the least significant bit
 * @param b Second big integer
 * @param m Length of the second big integer
 */
static void bn_add_at(uint8_t *a, uint32_t n, uint32_t lsb_offset, const uint8_t *b, uint32_t m)
{
    int carry = 0;
    int32_t j = 0;
    int32_t ai = 0;
    uint32_t carry_iter = 0U;
    uint32_t max_carry_iter = n;

    if((a == NULL) || (b == NULL) || (n == 0U) || (m == 0U)) {
        return;
    }
    j = ((int32_t)m - 1);
    ai = (((int32_t)n - 1) - (int32_t)lsb_offset);
    for(; (j >= 0) && (ai >= 0); ) {
        uint32_t usum = (uint32_t)a[ai];
        usum += (uint32_t)b[j];
        usum += (uint32_t)carry;
        a[ai] = (uint8_t)(usum & 0xFFU);
        {
            uint32_t usum_hi = (uint32_t)usum >> 8U;
            carry = (int)usum_hi;
        }
        j -= 1;
        ai -= 1;
    }
    /* Safety: limit iterations to prevent infinite loops */
    while((carry != 0) && (ai >= 0) && (carry_iter < max_carry_iter)) {
        uint32_t usum = (uint32_t)a[ai];
        usum += (uint32_t)carry;
        a[ai] = (uint8_t)(usum & 0xFFU);
        {
            uint32_t usum_hi = (uint32_t)usum >> 8U;
            carry = (int)usum_hi;
        }
        ai -= 1;
        carry_iter += 1U;
    }
    if((carry_iter >= max_carry_iter) && (carry != 0)) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: bn_add_at: Carry propagation timeout\n");
    }
}

/**
 * @brief Division with remainder: rem_out = a mod b (byte-wise long division).
 * @internal
 *
 * Requires @p a_len >= @p b_len for the main algorithm path.
 *
 * @param[out] rem_out Remainder buffer (@p mod_len bytes, big-endian)
 * @param[in] mod_len Output modulus length in bytes
 * @param[in] a Dividend (big-endian)
 * @param[in] a_len Dividend length in bytes
 * @param[in] b Divisor (big-endian)
 * @param[in] b_len Divisor length in bytes
 * @return void
 */
static void bn_div_remainder(uint8_t *rem_out, uint32_t mod_len,
                             const uint8_t *a, uint32_t a_len,
                             const uint8_t *b, uint32_t b_len)
{
    static int g_bn_debug_div_first = 1;
    int do_debug = g_bn_debug_div_first;

    if((rem_out == NULL) || (a == NULL) || (b == NULL) || (mod_len == 0U)) {
        if((rem_out != NULL) && (mod_len > 0U)) {
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
        }
        return;
    }
    if(g_bn_debug_div_first != 0) { g_bn_debug_div_first = 0; }
    if(g_bn_debug_div_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_div_remainder] start: a_len=%u b_len=%u mod_len=%u\n",
                            a_len, b_len, mod_len);
    }

    if(do_debug != 0) {
        if(a_len != 0U) { bn_debug_print(NULL, a, a_len); }
        if(b_len != 0U) { bn_debug_print(NULL, b, b_len); }
    }
    if(a_len < b_len) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        if(a_len > 0U) {
            noxtls_copy_u8(&rem_out[(mod_len - a_len)], (size_t)mod_len, a, (size_t)a_len);
        }
        if(do_debug != 0) { bn_debug_print(NULL, rem_out, mod_len); }
        return;
    }

    /* Compare |A| < |B| -> R = A */
    if(a_len == b_len) {
        if(noxtls_bn_cmp(a, b, b_len) < 0) {
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
            noxtls_copy_u8(&rem_out[(mod_len - a_len)], (size_t)mod_len, a, (size_t)a_len);
            if(do_debug != 0) { bn_debug_print(NULL, rem_out, mod_len); }
            return;
        }
    }

    /* Working buffers: X = copy of A, Y = copy of B; may grow by 1 byte after bit-shift. */
    uint32_t x_cap = 0U;
    uint32_t y_cap = 0U;
    if((a_len == UINT32_MAX) || (b_len == UINT32_MAX)) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return;
    }
    x_cap = a_len + 1U;
    y_cap = b_len + 1U;
    uint8_t *X = (uint8_t*)NOXTLS_CALLOC(x_cap, 1);
    uint8_t *Y = (uint8_t*)NOXTLS_CALLOC(y_cap, 1);
    uint8_t *Y_shifted = (uint8_t*)NOXTLS_CALLOC(x_cap, 1);
    if((X == NULL) || (Y == NULL) || (Y_shifted == NULL)) {
        if(g_bn_debug_div_trace != 0) {
            (void)noxtls_debug_printf((const uint8_t *)"[bn_div_remainder] alloc failed: X=%p Y=%p Y_shifted=%p\n",
                                (void*)X, (void*)Y, (void*)Y_shifted);
        }
        if(X != NULL) { (void)noxtls_free(X); }
        if(Y != NULL) { (void)noxtls_free(Y); }
        if(Y_shifted != NULL) { (void)noxtls_free(Y_shifted); }
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return;
    }

    noxtls_copy_u8(X, (size_t)x_cap, a, (size_t)(a_len));
    noxtls_copy_u8(Y, (size_t)y_cap, b, (size_t)(b_len));
    uint32_t x_len = a_len;
    uint32_t y_len = b_len;

    /* Strip leading zeros so quotient estimate uses significant bytes (fixes 64/32-style case) */
    bn_strip_leading_zeros_inplace(X, &x_len);
    bn_strip_leading_zeros_inplace(Y, &y_len);
    if(x_len == 0U) {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        (void)noxtls_free(X);
        (void)noxtls_free(Y);
        (void)noxtls_free(Y_shifted);
        return;
    }
    if(x_len < y_len) {
        /* Dividend < divisor: remainder is dividend, aligned to mod_len (x_len > 0U when x_len < y_len and y_len > 0U) */
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        noxtls_copy_u8(&rem_out[(mod_len - x_len)], (size_t)mod_len, X, (size_t)x_len);
        (void)noxtls_free(X);
        (void)noxtls_free(Y);
        (void)noxtls_free(Y_shifted);
        return;
    }

    if(do_debug != 0) {
        bn_debug_print(NULL, X, x_len);
        bn_debug_print(NULL, Y, y_len);
    }

    /* Normalize so Y has high bit set (k = bitlen(Y)%8, then k = 7-k, shift X,Y left by k). */
    uint32_t bitlen_y = bn_bitlen(Y, y_len);
    uint32_t k = 0U;
    if(bitlen_y > 0U) {
        k = (uint32_t)(bitlen_y & 7U);
        if(k < 7U) {
            k = 7U - k;
            bn_shift_l_bits(X, &x_len, k);
            bn_shift_l_bits(Y, &y_len, k);
                                    } else {
            k = 0U;
        }
    }

    if(do_debug != 0) {
        bn_debug_print(NULL, X, x_len);
        bn_debug_print(NULL, Y, y_len);
    }
    if(g_bn_debug_div_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_div_remainder] bitlen_y=%u k=%u x_len=%u y_len=%u\n",
                            bitlen_y, k, x_len, y_len);
    }

    uint32_t n = (uint32_t)(x_len - 1U);
    uint32_t t = (uint32_t)(y_len - 1U);

    /* Y_shifted = Y << (8U * (n-t)), same length as X for subtract.  */
    noxtls_secure_zero((Y_shifted), (size_t)(x_cap));
    noxtls_copy_u8(Y_shifted, (size_t)x_cap, Y, (size_t)(y_len));

    /*
     * Initial reduction: bring X below Y_shifted by subtracting multiples of Y_shifted.
     * The quotient digit at this position can be large (up to 255 when x_len==y_len+1).
     * Do not subtract one-at-a-time (would need up to 2^256 iterations for 64/32 byte).
     * Instead: estimate q0 = X / Y_shifted, subtract q0*Y_shifted in one step, repeat.
     */
    uint8_t *qY = (uint8_t*)NOXTLS_CALLOC(x_len + 1U, 1U);
    if(qY == NULL) {
        (void)noxtls_free(X);
        (void)noxtls_free(Y);
        (void)noxtls_free(Y_shifted);
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return;
    }
    uint32_t reduce_rounds = 0U;
    /* One quotient digit is 0..255, so we need at most 256 rounds when subtracting 1*Y_shifted each time */
    uint32_t max_reduce_rounds = 0U;
    if(x_len > (uint32_t)((UINT32_MAX / 32U) - 1U)) {
        (void)noxtls_free(X);
        (void)noxtls_free(Y);
        (void)noxtls_free(Y_shifted);
        (void)noxtls_free(qY);
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
        return;
    }
    max_reduce_rounds = (x_len + 1U) * 32U;
    if(max_reduce_rounds < 256U) { max_reduce_rounds = 256U; }
    while((bn_ge(X, Y_shifted, x_len) != 0) && (reduce_rounds < max_reduce_rounds)) {
        /* Estimate quotient digit: use top 2-3 bytes when both have same length */
        uint32_t q0 = 0U;
        if(Y_shifted[0] != 0U) {
            uint32_t num = ((uint32_t)X[0] << 8U) | (uint32_t)X[1];
            if(x_len > 2U) { num = (num << 8U) | (uint32_t)X[2]; }
            uint32_t den = (uint32_t)Y_shifted[0] + 1U;
            if((y_len > 1U) && (Y_shifted[1] != 0U)) { den = (((uint32_t)Y_shifted[0] << 8U) | (uint32_t)Y_shifted[1]) + 1U; }
            q0 = (den > 0U) ? (num / den) : 255U;
        } else {
            /* Y_shifted has leading zero byte(s): use first non-zero byte for denominator so q0 is not always 255 */
            uint32_t j = 1U;
            while((j < x_len) && (Y_shifted[j] == 0U)) { j += 1U; }
            uint32_t num = ((uint32_t)X[0] << 8U) | (uint32_t)X[1];
            if(x_len > 2U) { num = (num << 8U) | (uint32_t)X[2]; }
            uint32_t den = (uint32_t)((j < x_len) ? ((uint32_t)Y_shifted[j] + 1U) : 1U);
            q0 = (den > 0U) ? (num / den) : 255U;
        }
        if(q0 > 255U) { q0 = 255U; }
        if(q0 == 0U) { q0 = 1U; }

        bn_mul_byte(qY, (uint8_t)q0, Y_shifted, x_len);
        /* Refine: if qY > X, reduce q0 until qY <= X */
        while(q0 > 0U) {
            int32_t qy_gt_x = 0;
            if(qY[0] != 0U) {
                qy_gt_x = 1;
            } else if(noxtls_bn_cmp(&qY[1], X, x_len) > 0) {
                qy_gt_x = 1;
            }
             else {
                 /* MISRA 15.7: no remaining alternative */
             }
            if(qy_gt_x == 0) {
                break;
            }
            q0 -= 1U;
            bn_mul_byte(qY, (uint8_t)q0, Y_shifted, x_len);
        }
        if(q0 == 0U) { break; }
        (void)bn_sub_inplace(X, &qY[1], x_len);
        reduce_rounds += 1U;
    }
    (void)noxtls_free(qY);
    if(do_debug != 0) {
        bn_debug_print(NULL, X, x_len);
    }
    /* If we hit the round limit before X < Y_shifted, do bounded fallback (single subtracts) so we never return wrong remainder */
    if((reduce_rounds >= max_reduce_rounds) && (bn_ge(X, Y_shifted, x_len) != 0)) {
        uint32_t fallback = 0U;
        const uint32_t max_fallback = 256U; /* one digit max */
        while((fallback < max_fallback) && (bn_ge(X, Y_shifted, x_len) != 0)) {
            (void)bn_sub_inplace(X, Y_shifted, x_len);
            fallback += 1U;
        }
        if((fallback >= max_fallback) && (bn_ge(X, Y_shifted, x_len) != 0)) {
            (void)noxtls_debug_printf((const uint8_t *)"ERROR: bn_div_remainder: Initial reduction did not converge\n");
            (void)noxtls_free(X);
            (void)noxtls_free(Y);
            (void)noxtls_free(Y_shifted);
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
            return;
        }
    }

    /* For-loop: same n,t as after normalization. Use i > t (no x_len check). */
    for(uint32_t i = n; i > t; i -= 1U) {
        uint32_t idx = (uint32_t)(n - i);   /* our MSB index for "limb i" */
        uint8_t xi = (uint8_t)((idx < x_len) ? X[idx] : 0U);
        uint8_t xi1 = (uint8_t)(((idx + 1U) < x_len) ? X[idx + 1U] : 0U);
        uint8_t yt = Y[0];
        if((do_debug != 0) && ((i % 32U) == 0U)) {
            (void)noxtls_debug_printf((const uint8_t *)"[bn_div_remainder] step i=%u idx=%u xi=%02X xi1=%02X yt=%02X\n",
                                  i, idx, xi, xi1, yt);
        }

        uint32_t q = 0U;
        if(xi >= yt) {
            q = 255U;
        } else {
            uint32_t num = ((uint32_t)xi << 8U) | (uint32_t)xi1;
            q = (yt != 0U) ? (num / (uint32_t)yt) : 0U;
            if(q > 255U) { q = 255U; }
        }
        if(do_debug != 0) {
            uint8_t xi2_dbg = (uint8_t)(((idx + 2U) < x_len) ? X[idx + 2U] : 0U);
            (void)xi2_dbg;
                    //i, idx, xi, xi1, xi2_dbg, yt, q);
        }

        /* Refine q: match (Z.p[i-t-1]++, then do { Z--; T1 = (Y[t-1],Y[t])*q } while T1 > T2) */
        {
            uint8_t xi2 = (uint8_t)(((idx + 2U) < x_len) ? X[idx + 2U] : 0U);
            uint32_t T2 = ((uint32_t)xi << 16U) | ((uint32_t)xi1 << 8U) | (uint32_t)xi2;
            uint32_t yt1 = (uint32_t)((y_len >= 2U) ? (uint32_t)Y[1] : 0U);
            uint32_t T1_base = ((uint32_t)yt << 8U) | yt1;
            q += 1U;
            if(q > 255U) { q = 255U; }
            {
                uint32_t T1_val = (uint32_t)(T1_base * q);
                uint32_t refine_iter = 0U;
                uint32_t max_refine_iter = 256U; /* q is at most 255, so this is safe */
                while((q > 0U) && (T1_val > T2) && (refine_iter < max_refine_iter)) {
                    q -= 1U;
                    T1_val -= T1_base;
                    refine_iter += 1U;
                }
                if(refine_iter >= max_refine_iter) {
                    (void)noxtls_debug_printf((const uint8_t *)"ERROR: bn_div_remainder: Refinement loop timeout\n");
                    (void)noxtls_free(X);
                    (void)noxtls_free(Y);
                    (void)noxtls_free(Y_shifted);
                    noxtls_secure_zero((rem_out), (size_t)(mod_len));
                    return;
                }
            }
        }
        if(do_debug != 0) {
        }

        /* X -= q * (Y << (i-t-1)) */
        /* (Y * q) in at most y_len+1 bytes, placed with LSB at byte offset off */
        {
            uint32_t off = (uint32_t)(i - t - 1U);
            uint16_t carry = 0U;
            uint32_t tw = (uint32_t)(y_len + 1U);
            uint8_t *tmp = (uint8_t*)NOXTLS_CALLOC(tw, 1);
            if(tmp == NULL) {
                (void)noxtls_free(X);
                (void)noxtls_free(Y);
                (void)noxtls_free(Y_shifted);
                noxtls_secure_zero((rem_out), (size_t)(mod_len));
                return;
            }
            for(int32_t j = (int32_t)y_len - 1; j >= 0; j -= 1) {
                uint16_t prod = (uint16_t)(((uint16_t)Y[j] * (uint16_t)(uint8_t)q) + carry);
                tmp[(uint32_t)j + 1U] = (uint8_t)(prod & (uint16_t)0x00FFU);
                {
                    uint32_t next_carry = (uint32_t)prod;
                    next_carry >>= 8U;
                    carry = (uint16_t)next_carry;
                }
            }
            tmp[0] = (uint8_t)(carry & 0xFFU);
            bn_strip_leading_zeros_inplace(tmp, &tw);
            if((tw > 0U) && ((off + tw) <= x_len)) {
                if(bn_sub_at(X, x_len, off, tmp, tw) != 0) {
                    bn_add_at(X, x_len, off, Y, y_len);
                }
            }
            (void)noxtls_free(tmp);
        }
        if(do_debug != 0) {
            bn_debug_print(NULL, X, x_len);
        }

    }

    /* Remainder = X >> k */
    if(x_len > 0U) {
        bn_shift_r_bits(X, x_len, k);
        bn_strip_leading_zeros_inplace(X, &x_len);
        if(x_len >= mod_len) {
            noxtls_copy_u8(rem_out, (size_t)mod_len, &X[(x_len - mod_len)], (size_t)mod_len);
                                        } else {
            noxtls_secure_zero((rem_out), (size_t)(mod_len));
            noxtls_copy_u8(&rem_out[(mod_len - x_len)], (size_t)mod_len, X, (size_t)x_len);
        }
        if(do_debug != 0) { bn_debug_print(NULL, rem_out, mod_len); }
                                            } else {
        noxtls_secure_zero((rem_out), (size_t)(mod_len));
    }

    (void)noxtls_free(X);
    (void)noxtls_free(Y);
    (void)noxtls_free(Y_shifted);
    if(g_bn_debug_div_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[bn_div_remainder] done\n");
    }
}

/**
 * @brief Modulus operation: result = a mod mod
 * @internal
 * @param result Result big integer
 * @param a First big integer
 * @param a_len Length of the first big integer
 * @param mod Modulus big integer
 * @param mod_len Length of the modulus big integer
 */
noxtls_return_t noxtls_bn_mod(uint8_t *result, const uint8_t *a, uint32_t a_len,
                               const uint8_t *mod, uint32_t mod_len)
{
    static int g_bn_debug_mod_first = 1;
    int do_debug = g_bn_debug_mod_first;
    if(g_bn_debug_mod_first != 0) { g_bn_debug_mod_first = 0; }
    if(g_bn_debug_modexp_active != 0) {
        /* Always log during mod_exp for the first few calls. */
        if(g_bn_debug_mod_calls < 10U) {
            do_debug = 1;
        }
        g_bn_debug_mod_calls += 1U;
    }
    const uint8_t *a_src = a;
    uint32_t a_nbytes = a_len;
    uint8_t *a_copy = NULL;

    if(do_debug != 0) {
        if((a != NULL) && (a_nbytes != 0U)) { bn_debug_print(NULL, a, a_nbytes); }
        if((mod != NULL) && (mod_len != 0U)) { bn_debug_print(NULL, mod, mod_len); }
    }
    if(g_bn_debug_div_trace != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"[noxtls_bn_mod] start: a_nbytes=%u mod_len=%u\n", a_nbytes, mod_len);
    }

    if((result == NULL) || (a == NULL) || (mod == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(mod_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        int32_t mod_is_zero = noxtls_bn_is_zero(mod, mod_len);
        if((a_nbytes == 0U) || (mod_is_zero != 0)) {
            noxtls_secure_zero((result), (size_t)(mod_len));
            if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    {
        uintptr_t a_start = (uintptr_t)a;
        uintptr_t a_end;
        uintptr_t result_addr = (uintptr_t)result;
        if(a_nbytes > (uint32_t)(UINTPTR_MAX - a_start)) {
            return NOXTLS_RETURN_FAILED;
        }
        a_end = a_start + (uintptr_t)a_nbytes;
        if((result_addr >= a_start) && (result_addr < a_end)) {
            a_copy = (uint8_t*)NOXTLS_CALLOC(a_nbytes, 1);
            if(a_copy == NULL) {
                (void)noxtls_debug_printf((const uint8_t *)"[noxtls_bn_mod] a_copy alloc failed (a_nbytes=%u)\n", a_nbytes);
                noxtls_secure_zero((result), (size_t)(mod_len));
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8(a_copy, (size_t)a_nbytes, a, (size_t)(a_nbytes));
            a_src = a_copy;
        }
    }

    a_src = bn_strip_leading_zeros(a_src, &a_nbytes);
    if(a_nbytes == 0U) {
        noxtls_secure_zero((result), (size_t)(mod_len));
        if(a_copy != NULL) { (void)noxtls_free(a_copy); }
        if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_nbytes < mod_len) {
        if(bn_copy_aligned(result, mod_len, a_src, a_nbytes) != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero((result), (size_t)(mod_len));
            if(a_copy != NULL) { (void)noxtls_free(a_copy); }
            return NOXTLS_RETURN_FAILED;
        }
        /* Fixup: result may still be >= mod (e.g. 10 mod 10, 20 mod 10) */
        if(noxtls_bn_cmp(result, mod, mod_len) >= 0) {
            bn_div_remainder(result, mod_len, result, mod_len, mod, mod_len);
        }
        if(a_copy != NULL) { (void)noxtls_free(a_copy); }
        if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_nbytes == mod_len) {
        if(noxtls_bn_cmp(a_src, mod, mod_len) < 0) {
            noxtls_copy_u8(result, (size_t)mod_len, a_src, (size_t)mod_len);
            if(a_copy != NULL) { (void)noxtls_free(a_copy); }
            if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    if((a_nbytes <= 8U) && (mod_len <= 4U)) {
        uint64_t va = 0U;
        uint64_t vm = 0U;
        for(uint32_t i = 0U; i < a_nbytes; i += 1U) { va = (va << 8U) | (uint64_t)a_src[i]; }
        for(uint32_t i = 0U; i < mod_len; i += 1U) { vm = (vm << 8U) | (uint64_t)mod[i]; }
        if(vm == 0U) {
            noxtls_secure_zero((result), (size_t)(mod_len));
        } else {
            va %= vm;
            for(uint32_t i = mod_len; i > 0U; i -= 1U) {
                result[i - 1U] = (uint8_t)(va & 0xFFU);
                va >>= 8;
            }
        }
        if(a_copy != NULL) { (void)noxtls_free(a_copy); }
        if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
        return NOXTLS_RETURN_SUCCESS;
    }

    /*
     * On platforms with a 32-byte modular accelerator (ESP P-256 MPI), try it
     * first for the dominant ECC field/scalar products. This keeps the generic
     * 2n/n reducer as the fallback while allowing hardware-backed builds to
     * accelerate the exact 64-bytes mod 32-bytes shape used throughout P-256.
     */
    if((mod_len == 32U) && (a_nbytes == 64U)) {
        noxtls_return_t hw_rc = noxtls_bn_platform_try_mod(result, a_src, a_nbytes, mod, mod_len);
        if(hw_rc == NOXTLS_RETURN_SUCCESS) {
            if(a_copy != NULL) {
                (void)noxtls_free(a_copy);
            }
            if(do_debug != 0) {
                bn_debug_print(NULL, result, mod_len);
            }
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* Fast path: 2n-by-n limb reducer for ECDSA (P-256/P-384), RSA, and RFC 7919 FFDHE moduli. */
    if((mod_len == 32U || mod_len == 48U || mod_len == 64U || mod_len == 128U || mod_len == 256U ||
        mod_len == 384U || mod_len == 512U || mod_len == 768U || mod_len == 1024U) &&
       a_nbytes == mod_len * 2U) {
        noxtls_return_t fast_rc = bn_mod_2n_by_n_limb(result, mod_len, a_src, a_nbytes, mod);
        if(fast_rc == NOXTLS_RETURN_SUCCESS) {
            if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
            if(a_copy != NULL) { noxtls_free(a_copy); }
            return NOXTLS_RETURN_SUCCESS;
        }
        if(fast_rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            if(a_copy != NULL) { noxtls_free(a_copy); }
            return fast_rc;
        }
    }

    /* HW mod after fast paths: ECDSA uses many 2n reductions; mbedtls_mpi init per call is slower than limb code. */
    {
        noxtls_return_t hw_rc = noxtls_bn_platform_try_mod(result, a_src, a_nbytes, mod, mod_len);
        if(hw_rc == NOXTLS_RETURN_SUCCESS) {
            if(a_copy != NULL) {
                (void)noxtls_free(a_copy);
            }
            if(do_debug != 0) {
                bn_debug_print(NULL, result, mod_len);
            }
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* General limb path (bit-by-bit) for other operand sizes. */
    {
        noxtls_return_t limb_rc = bn_div_remainder_limb(result, mod_len, a_src, a_nbytes, mod, mod_len);
        if(limb_rc == NOXTLS_RETURN_SUCCESS) {
            if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
            if(a_copy != NULL) { noxtls_free(a_copy); }
            return NOXTLS_RETURN_SUCCESS;
        }
        if(limb_rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            if(a_copy != NULL) { noxtls_free(a_copy); }
            return limb_rc;
        }
    }

    /* In-house bn_div_remainder. */
    bn_div_remainder(result, mod_len, a_src, a_nbytes, mod, mod_len);
    
    /* at most one conditional subtract so result in [0, mod). */
    if(noxtls_bn_cmp(result, mod, mod_len) >= 0) {
        if(bn_sub_inplace(result, mod, mod_len) != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero((result), (size_t)(mod_len));
        }
    }
    if(a_copy != NULL) { (void)noxtls_free(a_copy); }
    if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Modular exponentiation: result = base ^ exp mod mod
 * @internal
 * @param result Result big integer
 * @param base Base big integer
 * @param exp Exponent big integer
 * @param exp_len Length of the exponent big integer
 * @param mod Modulus big integer
 * @param mod_len Length of the modulus big integer
 */
/**
 * @brief Constant-time conditional swap of two equal-length big-endian buffers.
 *
 * Swaps @p a and @p b byte-for-byte when @p swap is 1 and leaves them unchanged when
 * @p swap is 0, without a data-dependent branch. Used by the Montgomery powering ladder
 * so the secret exponent bit never selects a code path (NX-15).
 *
 * @param[in,out] a   First buffer.
 * @param[in,out] b   Second buffer.
 * @param[in]     len Length of both buffers in bytes.
 * @param[in]     swap 1 to swap, 0 to leave unchanged (only bit 0 is significant).
 */
static void bn_ct_cswap(uint8_t *a, uint8_t *b, uint32_t len, uint8_t swap)
{
    uint8_t mask = (uint8_t)(0U - (uint8_t)(swap & 1U));
    uint32_t i = 0U;
    for(i = 0U; i < len; i += 1U) {
        uint8_t d = (uint8_t)((a[i] ^ b[i]) & mask);
        a[i] ^= d;
        b[i] ^= d;
    }
}

/* ===================================================================== *
 *  Fast constant-time modular exponentiation (Montgomery + fixed window)
 *
 *  This is the preferred path for an ODD modulus (RSA n/p/q, DH prime p).
 *  It is both faster and constant-time:
 *    - Montgomery multiplication (CIOS) replaces the per-step long-division
 *      reduction with a fixed-count multiply-accumulate pass.
 *    - 32-bit limbs do 4x fewer iterations than the byte-wise fallback.
 *    - A fixed 4-bit window does w squarings + 1 multiply per w exponent
 *      bits, and the window's table entry is read by scanning ALL entries
 *      with arithmetic masks, so neither the branch nor the memory-access
 *      pattern depends on the secret exponent.
 *
 *  Timing depends only on mod_len and exp_len (both public), never on the
 *  secret exponent or base values.
 * ===================================================================== */

typedef uint32_t bn_limb_t;
#define BN_LIMB_BITS    32U
#define BN_MONT_WINDOW  4U
#define BN_MONT_TABLE   (1U << BN_MONT_WINDOW)  /* 16 */

/* Convert big-endian bytes to little-endian 32-bit limbs (out[0] = least significant). */
static void bn_be_to_limbs(bn_limb_t *out, uint32_t nlimbs, const uint8_t *be, uint32_t be_len)
{
    uint32_t i = 0U;
    noxtls_secure_zero((out), ((size_t)nlimbs * sizeof(bn_limb_t)));
    for(i = 0U; i < be_len; i += 1U) {
        uint32_t byte = (uint32_t)(be[be_len - 1U - i]);
        switch(i & 3U) {
        case 0U: out[i >> 2U] |= byte; break;
        case 1U: out[i >> 2U] |= (byte << 8U); break;
        case 2U: out[i >> 2U] |= (byte << 16U); break;
        default: out[i >> 2U] |= (byte << 24U); break;
        }
    }
}

/* Convert little-endian 32-bit limbs back to big-endian bytes. */
static void bn_limbs_to_be(uint8_t *be, uint32_t be_len, const bn_limb_t *in, uint32_t nlimbs)
{
    uint32_t i = 0U;
    (void)nlimbs;
    for(i = 0U; i < be_len; i += 1U) {
        uint32_t limb = (uint32_t)in[i >> 2U];
        uint8_t b = 0U;
        switch(i & 3U) {
        case 0U: b = (uint8_t)limb; break;
        case 1U: b = (uint8_t)(limb >> 8U); break;
        case 2U: b = (uint8_t)(limb >> 16U); break;
        default: b = (uint8_t)(limb >> 24U); break;
        }
        be[be_len - 1U - i] = b;
    }
}

/* r = a - b over n limbs; returns the final borrow (1 if a < b). Constant-time. */
static bn_limb_t bn_limbs_sub(bn_limb_t *r, const bn_limb_t *a, const bn_limb_t *b, uint32_t n)
{
    uint32_t i = 0U;
    uint64_t borrow = 0;
    for(i = 0U; i < n; i += 1U) {
        uint64_t d = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        r[i] = (bn_limb_t)d;
        borrow = (d >> 63U) & 1U;  /* 1 when the subtraction underflowed */
    }
    return (bn_limb_t)borrow;
}

/* n0inv = -m[0]^{-1} mod 2^32 (m must be odd). Newton iteration on a 3-bit seed. */
static bn_limb_t bn_mont_n0inv(bn_limb_t m0)
{
    bn_limb_t inv = m0;            /* correct mod 2^3 for odd m0 */
    uint32_t k = 0U;
    for(k = 0U; k < 4U; k += 1U) {      /* 3 -> 6 -> 12 -> 24 -> 48 (>= 32) bits */
        inv *= 2U - (m0 * inv);
    }
    return (bn_limb_t)(0U - inv);
}

/*
 * out = a * b * R^{-1} mod m, with R = 2^(32*n). CIOS form (Koc).
 * Reads a, b, m throughout and writes out only at the final reduction, so
 * out may alias a and/or b (needed for squaring). Constant-time.
 * t   : scratch of (n + 2) limbs.
 * tmp : scratch of n limbs.
 */
static void bn_mont_mul(bn_limb_t *out, const bn_limb_t *a, const bn_limb_t *b,
                        const bn_limb_t *m, uint32_t n, bn_limb_t n0inv,
                        bn_limb_t *t, bn_limb_t *tmp)
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    bn_limb_t extra;
    bn_limb_t borrow;
    bn_limb_t condsub;
    bn_limb_t mask;

    noxtls_secure_zero((t), ((size_t)(n + 2U) * sizeof(bn_limb_t)));

    for(i = 0U; i < n; i += 1U) {
        uint64_t carry = 0U;
        bn_limb_t mi;

        /* t += a * b[i] */
        for(j = 0U; j < n; j += 1U) {
            uint64_t s = (uint64_t)t[j] + ((uint64_t)a[j] * (uint64_t)b[i]) + carry;
            t[j] = (bn_limb_t)s;
            carry = s >> BN_LIMB_BITS;
        }
        {
            uint64_t s = (uint64_t)t[n] + carry;
            t[n] = (bn_limb_t)s;
            t[n + 1U] = (bn_limb_t)(s >> BN_LIMB_BITS);
        }

        /* m_ = t[0] * n0inv mod 2^32; t = (t + m_ * m) / 2^32 */
        mi = (bn_limb_t)((uint64_t)t[0] * (uint64_t)n0inv);
        {
            uint64_t s = (uint64_t)t[0] + ((uint64_t)mi * (uint64_t)m[0]);
            carry = s >> BN_LIMB_BITS;   /* low word of s is discarded (== 0) */
        }
        for(j = 1U; j < n; j += 1U) {
            uint64_t s = (uint64_t)t[j] + ((uint64_t)mi * (uint64_t)m[j]) + carry;
            t[j - 1U] = (bn_limb_t)s;
            carry = s >> BN_LIMB_BITS;
        }
        {
            uint64_t s = (uint64_t)t[n] + carry;
            t[n - 1U] = (bn_limb_t)s;
            t[n] = t[n + 1U] + (bn_limb_t)(s >> BN_LIMB_BITS);
        }
    }

    /* Final conditional subtraction: if extra carry set or t >= m, subtract m. */
    extra = t[n];
    borrow = bn_limbs_sub(tmp, t, m, n);
    condsub = (bn_limb_t)(((extra != 0U) ? 1U : 0U) | (1U - (uint32_t)borrow));
    mask = (bn_limb_t)(0U - condsub);
    for(j = 0U; j < n; j += 1U) {
        out[j] = (tmp[j] & mask) | (t[j] & ~mask);
    }
}

/* RR = R^2 mod m = 2^(2*32*n) mod m, by repeated doubling. One-time per call. */
static void bn_mont_RR(bn_limb_t *RR, const bn_limb_t *m, uint32_t n, bn_limb_t *tmp)
{
    uint32_t total = (uint32_t)(2U * BN_LIMB_BITS * n);
    uint32_t k = 0U;
    uint32_t j = 0U;

    noxtls_secure_zero((RR), ((size_t)n * sizeof(bn_limb_t)));
    RR[0] = 1U;

    for(k = 0U; k < total; k += 1U) {
        bn_limb_t carry = 0U;
        bn_limb_t borrow;
        bn_limb_t condsub;
        bn_limb_t mask;
        for(j = 0U; j < n; j += 1U) {
            bn_limb_t nc = RR[j] >> (BN_LIMB_BITS - 1U);
            RR[j] = (RR[j] << 1U) | carry;
            carry = nc;
        }
        borrow = bn_limbs_sub(tmp, RR, m, n);
        condsub = (bn_limb_t)(((carry != 0U) ? 1U : 0U) | (1U - (uint32_t)borrow));
        mask = (bn_limb_t)(0U - condsub);
        for(j = 0U; j < n; j += 1U) {
            RR[j] = (tmp[j] & mask) | (RR[j] & ~mask);
        }
    }
}

/*
 * Constant-time Montgomery + fixed-window modular exponentiation for ODD modulus.
 * Returns NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED if the modulus
 * is even or scratch allocation fails (caller then uses the ladder fallback).
 */
static noxtls_return_t bn_mod_exp_mont(uint8_t *result, const uint8_t *base,
                                       const uint8_t *exp, uint32_t exp_len,
                                       const uint8_t *mod, uint32_t mod_len)
{
    uint32_t n = (uint32_t)((mod_len + 3U) / 4U);
    uint32_t e_skip = 0U;
    uint32_t nb;          /* significant exponent bits (public, via byte length) */
    uint32_t nwin = 0U;
    uint32_t win_idx = 0U;
    bn_limb_t n0inv;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    bn_limb_t *m_l    = NULL;
    bn_limb_t *RR     = NULL;
    bn_limb_t *aR     = NULL;
    bn_limb_t *acc    = NULL;
    bn_limb_t *sel    = NULL;
    bn_limb_t *one_l  = NULL;
    bn_limb_t *t      = NULL;
    bn_limb_t *tmp    = NULL;
    bn_limb_t *table  = NULL;   /* BN_MONT_TABLE * n limbs */
    uint8_t   *base_red = NULL;

    if(n == 0U) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    m_l     = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    RR      = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    aR      = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    acc     = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    sel     = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    one_l   = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    t       = (bn_limb_t*)NOXTLS_CALLOC(n + 2U, sizeof(bn_limb_t));
    tmp     = (bn_limb_t*)NOXTLS_CALLOC(n, sizeof(bn_limb_t));
    table   = (bn_limb_t*)NOXTLS_CALLOC((size_t)BN_MONT_TABLE * n, sizeof(bn_limb_t));
    base_red = (uint8_t*)NOXTLS_CALLOC(mod_len, 1);

    if((m_l == NULL) || (RR == NULL) || (aR == NULL) || (acc == NULL) || (sel == NULL) || (one_l == NULL) || (t == NULL) || (tmp == NULL) || (table == NULL) || (base_red == NULL)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;  /* fall back to ladder */
        if(m_l != NULL) {   NOXTLS_SECURE_FREE(m_l,   (size_t)n * sizeof(bn_limb_t)); }
            if(RR != NULL) {    NOXTLS_SECURE_FREE(RR,    (size_t)n * sizeof(bn_limb_t)); }
            if(aR != NULL) {    NOXTLS_SECURE_FREE(aR,    (size_t)n * sizeof(bn_limb_t)); }
            if(acc != NULL) {   NOXTLS_SECURE_FREE(acc,   (size_t)n * sizeof(bn_limb_t)); }
            if(sel != NULL) {   NOXTLS_SECURE_FREE(sel,   (size_t)n * sizeof(bn_limb_t)); }
            if(one_l != NULL) { NOXTLS_SECURE_FREE(one_l, (size_t)n * sizeof(bn_limb_t)); }
            if(t != NULL) {     NOXTLS_SECURE_FREE(t,     (size_t)(n + 2U) * sizeof(bn_limb_t)); }
            if(tmp != NULL) {   NOXTLS_SECURE_FREE(tmp,   (size_t)n * sizeof(bn_limb_t)); }
            if(table != NULL) { NOXTLS_SECURE_FREE(table, (size_t)BN_MONT_TABLE * n * sizeof(bn_limb_t)); }
            if(base_red != NULL) { NOXTLS_SECURE_FREE(base_red, mod_len); }
            return rc;
    }

    bn_be_to_limbs(m_l, n, mod, mod_len);
    if((m_l[0] & 1U) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;  /* even modulus: Montgomery needs odd */
        if(m_l != NULL) {   NOXTLS_SECURE_FREE(m_l,   (size_t)n * sizeof(bn_limb_t)); }
    if(RR != NULL) {    NOXTLS_SECURE_FREE(RR,    (size_t)n * sizeof(bn_limb_t)); }
    if(aR != NULL) {    NOXTLS_SECURE_FREE(aR,    (size_t)n * sizeof(bn_limb_t)); }
    if(acc != NULL) {   NOXTLS_SECURE_FREE(acc,   (size_t)n * sizeof(bn_limb_t)); }
    if(sel != NULL) {   NOXTLS_SECURE_FREE(sel,   (size_t)n * sizeof(bn_limb_t)); }
    if(one_l != NULL) { NOXTLS_SECURE_FREE(one_l, (size_t)n * sizeof(bn_limb_t)); }
    if(t != NULL) {     NOXTLS_SECURE_FREE(t,     (size_t)(n + 2U) * sizeof(bn_limb_t)); }
    if(tmp != NULL) {   NOXTLS_SECURE_FREE(tmp,   (size_t)n * sizeof(bn_limb_t)); }
    if(table != NULL) { NOXTLS_SECURE_FREE(table, (size_t)BN_MONT_TABLE * n * sizeof(bn_limb_t)); }
    if(base_red != NULL) { NOXTLS_SECURE_FREE(base_red, mod_len); }
    return rc;
    }

    n0inv = bn_mont_n0inv(m_l[0]);
    bn_mont_RR(RR, m_l, n, tmp);

    /* one_l = 1 */
    one_l[0] = 1U;

    /* a = base mod m  ->  aR = a * R mod m */
    if(noxtls_bn_mod(base_red, base, mod_len, mod, mod_len) != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        if(m_l != NULL) {   NOXTLS_SECURE_FREE(m_l,   (size_t)n * sizeof(bn_limb_t)); }
    if(RR != NULL) {    NOXTLS_SECURE_FREE(RR,    (size_t)n * sizeof(bn_limb_t)); }
    if(aR != NULL) {    NOXTLS_SECURE_FREE(aR,    (size_t)n * sizeof(bn_limb_t)); }
    if(acc != NULL) {   NOXTLS_SECURE_FREE(acc,   (size_t)n * sizeof(bn_limb_t)); }
    if(sel != NULL) {   NOXTLS_SECURE_FREE(sel,   (size_t)n * sizeof(bn_limb_t)); }
    if(one_l != NULL) { NOXTLS_SECURE_FREE(one_l, (size_t)n * sizeof(bn_limb_t)); }
    if(t != NULL) {     NOXTLS_SECURE_FREE(t,     (size_t)(n + 2U) * sizeof(bn_limb_t)); }
    if(tmp != NULL) {   NOXTLS_SECURE_FREE(tmp,   (size_t)n * sizeof(bn_limb_t)); }
    if(table != NULL) { NOXTLS_SECURE_FREE(table, (size_t)BN_MONT_TABLE * n * sizeof(bn_limb_t)); }
    if(base_red != NULL) { NOXTLS_SECURE_FREE(base_red, mod_len); }
    return rc;
    }
    bn_be_to_limbs(aR, n, base_red, mod_len);          /* aR currently holds a */
    bn_mont_mul(aR, aR, RR, m_l, n, n0inv, t, tmp);    /* aR = a * R mod m */

    /* table[0] = R mod m (Montgomery 1); table[1] = aR; table[i] = table[i-1] * a */
    bn_mont_mul(&table[0], one_l, RR, m_l, n, n0inv, t, tmp);
    noxtls_copy_u8((uint8_t *)(void *)&table[(size_t)n], (size_t)n * sizeof(bn_limb_t), (const uint8_t *)(const void *)aR, (size_t)n * sizeof(bn_limb_t));
    {
        uint32_t idx = 0U;
        for(idx = 2U; idx < BN_MONT_TABLE; idx += 1U) {
            bn_mont_mul(&table[(size_t)idx * n], &table[(size_t)(idx - 1U) * n], aR,
                        m_l, n, n0inv, t, tmp);
        }
    }

    /* acc = Montgomery 1 */
    noxtls_copy_u8((uint8_t *)(void *)acc, (size_t)n * sizeof(bn_limb_t), (const uint8_t *)(const void *)&table[0], (size_t)n * sizeof(bn_limb_t));

    /* Trim leading zero bytes of the exponent (reveals only its public byte length). */
    e_skip = 0U;
    while((e_skip < exp_len) && (exp[e_skip] == 0U)) {
        e_skip += 1U;
    }
    nb = (exp_len - e_skip) * 8U;
    if(nb == 0U) {
        /* exponent == 0: x^0 mod m = 1 */
        (void)noxtls_bn_one(result, mod_len);
        rc = NOXTLS_RETURN_SUCCESS;
        if(m_l != NULL) {   NOXTLS_SECURE_FREE(m_l,   (size_t)n * sizeof(bn_limb_t)); }
    if(RR != NULL) {    NOXTLS_SECURE_FREE(RR,    (size_t)n * sizeof(bn_limb_t)); }
    if(aR != NULL) {    NOXTLS_SECURE_FREE(aR,    (size_t)n * sizeof(bn_limb_t)); }
    if(acc != NULL) {   NOXTLS_SECURE_FREE(acc,   (size_t)n * sizeof(bn_limb_t)); }
    if(sel != NULL) {   NOXTLS_SECURE_FREE(sel,   (size_t)n * sizeof(bn_limb_t)); }
    if(one_l != NULL) { NOXTLS_SECURE_FREE(one_l, (size_t)n * sizeof(bn_limb_t)); }
    if(t != NULL) {     NOXTLS_SECURE_FREE(t,     (size_t)(n + 2U) * sizeof(bn_limb_t)); }
    if(tmp != NULL) {   NOXTLS_SECURE_FREE(tmp,   (size_t)n * sizeof(bn_limb_t)); }
    if(table != NULL) { NOXTLS_SECURE_FREE(table, (size_t)BN_MONT_TABLE * n * sizeof(bn_limb_t)); }
    if(base_red != NULL) { NOXTLS_SECURE_FREE(base_red, mod_len); }
    return rc;
    }
    nwin = (nb + BN_MONT_WINDOW - 1U) / BN_MONT_WINDOW;

    for(win_idx = nwin; win_idx > 0U; win_idx -= 1U) {
        uint32_t bitbase = (uint32_t)((win_idx - 1U) * BN_MONT_WINDOW);
        uint32_t winval = 0U;
        uint32_t b = 0U;
        uint32_t idx = 0U;

        /* w squarings */
        for(b = 0U; b < BN_MONT_WINDOW; b += 1U) {
            bn_mont_mul(acc, acc, acc, m_l, n, n0inv, t, tmp);
        }

        /* extract the w-bit window (bit b is the b-th least-significant of the window) */
        for(b = 0U; b < BN_MONT_WINDOW; b += 1U) {
            uint32_t bp = (uint32_t)(bitbase + b);
            uint32_t bit = 0U;
            if(bp < nb) {
                uint8_t eb = exp[exp_len - 1U - (bp >> 3U)];
                bit = bn_u8_bit(eb, bp);
            }
            switch(b) {
            case 0U: winval |= bit; break;
            case 1U: winval |= (bit << 1U); break;
            case 2U: winval |= (bit << 2U); break;
            case 3U: winval |= (bit << 3U); break;
            default:
                /* Intentionally empty: BN_MONT_WINDOW constrains b to 0..3. */
                (void)0;
                break;
            }
        }

        /* constant-time gather of table[winval] */
        noxtls_secure_zero((sel), ((size_t)n * sizeof(bn_limb_t)));
        for(idx = 0U; idx < BN_MONT_TABLE; idx += 1U) {
            uint32_t d = (uint32_t)(idx ^ winval);
            uint32_t eq = (uint32_t)((d - 1U) >> 31U) & 1U;  /* 1 iff d == 0U (d in [0,15]) */
            bn_limb_t mask = (bn_limb_t)(0U - eq);
            uint32_t j = 0U;
            for(j = 0U; j < n; j += 1U) {
                sel[j] |= table[((size_t)idx * n) + j] & mask;
            }
        }

        bn_mont_mul(acc, acc, sel, m_l, n, n0inv, t, tmp);
    }

    /* Convert out of Montgomery domain: result = acc * R^{-1} mod m = acc * 1 (mont). */
    bn_mont_mul(acc, acc, one_l, m_l, n, n0inv, t, tmp);
    bn_limbs_to_be(result, mod_len, acc, n);
    rc = NOXTLS_RETURN_SUCCESS;

    if(m_l != NULL) {   NOXTLS_SECURE_FREE(m_l,   (size_t)n * sizeof(bn_limb_t)); }
    if(RR != NULL) {    NOXTLS_SECURE_FREE(RR,    (size_t)n * sizeof(bn_limb_t)); }
    if(aR != NULL) {    NOXTLS_SECURE_FREE(aR,    (size_t)n * sizeof(bn_limb_t)); }
    if(acc != NULL) {   NOXTLS_SECURE_FREE(acc,   (size_t)n * sizeof(bn_limb_t)); }
    if(sel != NULL) {   NOXTLS_SECURE_FREE(sel,   (size_t)n * sizeof(bn_limb_t)); }
    if(one_l != NULL) { NOXTLS_SECURE_FREE(one_l, (size_t)n * sizeof(bn_limb_t)); }
    if(t != NULL) {     NOXTLS_SECURE_FREE(t,     (size_t)(n + 2U) * sizeof(bn_limb_t)); }
    if(tmp != NULL) {   NOXTLS_SECURE_FREE(tmp,   (size_t)n * sizeof(bn_limb_t)); }
    if(table != NULL) { NOXTLS_SECURE_FREE(table, (size_t)BN_MONT_TABLE * n * sizeof(bn_limb_t)); }
    if(base_red != NULL) { NOXTLS_SECURE_FREE(base_red, mod_len); }
    return rc;
}

noxtls_return_t noxtls_bn_mod_exp(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len)
{
    int g_bn_debug_mod_compare_all = 0;
    int g_bn_debug_mod_first_mismatch_only = 1;

    static int g_bn_debug_modexp_first = 1;
    int do_debug = g_bn_debug_modexp_first;
    uint8_t *temp_result = NULL;
    uint8_t *temp_base = NULL;
    uint8_t *exp_copy = NULL;
    uint8_t *temp = NULL;
    uint32_t total_bits = 0U;
    uint32_t bit_index = 0U;
    uint32_t exp_alloc_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((result == NULL) || (base == NULL) || (exp == NULL) || (mod == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((mod_len == 0U) || (exp_len == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((mod_len > (uint32_t)(UINT32_MAX / 2U)) ||
       (exp_len > (uint32_t)(UINT32_MAX / 8U))) {
        return NOXTLS_RETURN_FAILED;
    }
    exp_alloc_len = exp_len;

    {
        noxtls_return_t hw_rc = noxtls_bn_platform_try_mod_exp(result, base, exp, exp_len, mod, mod_len);
        if(hw_rc == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    {
        noxtls_return_t mont_rc = bn_mod_exp_mont(result, base, exp, exp_len, mod, mod_len);
        if(mont_rc == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    if(g_bn_debug_modexp_first != 0) { g_bn_debug_modexp_first = 0; }
    g_bn_debug_modexp_active = 1;
    g_bn_debug_mod_calls = 0;
    g_bn_debug_mod_compare_all = 1;
    g_bn_debug_mod_first_mismatch_only = 1;
    temp_result = (uint8_t*)NOXTLS_CALLOC(mod_len, 1);
    temp_base = (uint8_t*)NOXTLS_CALLOC(mod_len, 1);
    exp_copy = (uint8_t*)NOXTLS_CALLOC(exp_len, 1);
    /* temp needs to be mod_len * 2 because multiplication of two mod_len numbers produces mod_len * 2 bytes */
    temp = (uint8_t*)NOXTLS_CALLOC((size_t)mod_len * 2U, 1);

    if((temp_result == NULL) || (temp_base == NULL) || (temp == NULL) || (exp_copy == NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"ERROR: noxtls_bn_mod_exp: Memory allocation failed!\n");
        if(temp_result != NULL) { (void)noxtls_free(temp_result); }
        if(temp_base != NULL) { (void)noxtls_free(temp_base); }
        if(exp_copy != NULL) { (void)noxtls_free(exp_copy); }
        if(temp != NULL) { (void)noxtls_free(temp); }
        (void)noxtls_bn_one(result, mod_len);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_bn_one(temp_result, mod_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }
    rc = noxtls_bn_mod(temp_base, base, mod_len, mod, mod_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }
    rc = noxtls_bn_copy(exp_copy, exp, exp_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }

    if(do_debug != 0) {
        bn_debug_print(NULL, base, mod_len);
        bn_debug_print(NULL, exp, exp_len);
        bn_debug_print(NULL, temp_result, mod_len);
    }

    /* Handle zero exponent */
    if(noxtls_bn_is_zero(exp_copy, exp_len) != 0) {
        rc = noxtls_bn_one(result, mod_len);
        (void)noxtls_free(temp_result);
        (void)noxtls_free(temp_base);
        (void)noxtls_free(exp_copy);
        (void)noxtls_free(temp);
        g_bn_debug_modexp_active = 0;
        g_bn_debug_mod_compare_all = 0;
        return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : rc;
    }

    /*
     * SECURITY (NX-15): constant-time Montgomery powering ladder.
     *
     * temp_result (R0) starts at 1, temp_base (R1) at base mod n. For every bit of the
     * exponent, from MSB to LSB, we perform exactly one multiply and one square with the
     * operands selected by a constant-time conditional swap. Unlike the previous
     * right-to-left square-and-multiply, there is no secret-bit-dependent multiply and no
     * early loop termination, so execution time and memory-access pattern are independent
     * of the (secret) exponent value. The loop always runs exp_len*8 iterations.
     */
    /*
     * Skip leading zero BYTES of the exponent. This reveals only the exponent's
     * byte-length: public exponents (e) are not secret, and secret exponents
     * (RSA d, DH x) occupy their full buffer, so no secret-dependent timing is
     * introduced while public-key operations keep their performance.
     */
    const uint8_t *exp_ptr = exp;
    uint32_t exp_bytes = exp_len;
    {
        uint32_t skip = 0U;
        while((skip < exp_bytes) && (exp_ptr[skip] == 0U)) {
            skip += 1U;
        }
        exp_ptr = &exp_ptr[skip];
        exp_bytes -= skip; /* exp_bytes >= 1: the all-zero exponent was handled above */
    }
    total_bits = exp_bytes * 8U;
    (void)bit_index;
    (void)do_debug;

    {
        uint32_t i = 0U;
        for(i = total_bits; i > 0U; i -= 1U) {
            uint32_t bitpos = (uint32_t)(i - 1U);
            uint8_t bit = (uint8_t)bn_u8_bit(exp_ptr[exp_bytes - 1U - (bitpos >> 3U)], bitpos);

            bn_ct_cswap(temp_result, temp_base, mod_len, bit);

            /* R1 = R0 * R1 mod n (uses old R0; R0 not yet modified this step) */
            rc = noxtls_bn_mul(temp, temp_result, mod_len, temp_base, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }
            rc = noxtls_bn_mod(temp_base, temp, mod_len * 2U, mod, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }

            /* R0 = R0 * R0 mod n */
            rc = noxtls_bn_mul(temp, temp_result, mod_len, temp_result, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }
            rc = noxtls_bn_mod(temp_result, temp, mod_len * 2U, mod, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_SECURE_FREE(temp_result, mod_len);
            NOXTLS_SECURE_FREE(temp_base, mod_len);
            NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
            NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
            g_bn_debug_modexp_active = 0;
            g_bn_debug_mod_compare_all = 0;
            if((result != NULL) && (mod_len > 0U)) {
                noxtls_secure_zero((result), (size_t)(mod_len));
            }
            return rc;
    }

            bn_ct_cswap(temp_result, temp_base, mod_len, bit);
        }
    }

    noxtls_copy_u8(result, (size_t)mod_len, temp_result, (size_t)mod_len);
    if(do_debug != 0) { bn_debug_print(NULL, result, mod_len); }
    /* Wipe intermediates that are derived from the secret exponent (NX-10/NX-15). */
    NOXTLS_SECURE_FREE(temp_result, mod_len);
    NOXTLS_SECURE_FREE(temp_base, mod_len);
    NOXTLS_SECURE_FREE(exp_copy, exp_alloc_len);
    NOXTLS_SECURE_FREE(temp, (size_t)mod_len * 2U);
    g_bn_debug_modexp_active = 0;
    g_bn_debug_mod_compare_all = 0;
    return NOXTLS_RETURN_SUCCESS;

}

/**
 * @brief Binary Extended Euclidean Algorithm: compute a^-1 mod m (much faster - no division!)
 * @internal
 * @param result Result big integer
 * @param a First big integer
 * @param a_len Length of the first big integer
 * @param m Modulus big integer
 * @param m_len Length of the modulus big integer
 */
noxtls_return_t noxtls_bn_mod_inv(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *m, uint32_t m_len)
{
    if((result == NULL) || (a == NULL) || (m == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(m_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* In-house extended GCD / Fermat fallback. */
    /* Fast, correct path for secp256r1 prime field: a^(p-2) mod p. */
    static const uint8_t secp256r1_p[32] = {
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
    };
    if(m_len == 32U && noxtls_bn_cmp(m, secp256r1_p, 32) == 0) {
        noxtls_return_t rc;
        /* Shared storage is opt-in and requires external serialization. */
#if NOXTLS_ECC_SHARED_SCRATCH
        static uint8_t m_minus_2[32];
        static uint8_t two_buf[32];
        static uint8_t a_mod_m_p256[32];
#else
        uint8_t m_minus_2[32];
        uint8_t two_buf[32];
        uint8_t a_mod_m_p256[32];
#endif

        noxtls_secure_zero(m_minus_2, (size_t)(sizeof(m_minus_2)));
        noxtls_secure_zero(two_buf, (size_t)(sizeof(two_buf)));
        noxtls_secure_zero(a_mod_m_p256, (size_t)(sizeof(a_mod_m_p256)));
        rc = noxtls_bn_mod(a_mod_m_p256, a, a_len, m, m_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_bn_zero(result, m_len);
            noxtls_secure_zero(a_mod_m_p256, sizeof(a_mod_m_p256));
            return rc;
        }
        if(noxtls_bn_is_zero(a_mod_m_p256, m_len) == 0) {
            two_buf[m_len - 1U] = 2U;
            (void)noxtls_bn_copy(m_minus_2, m, m_len);
            (void)noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
            rc = noxtls_bn_mod_exp(result, a_mod_m_p256, m_minus_2, m_len, m, m_len);
            noxtls_secure_zero(m_minus_2, sizeof(m_minus_2));
            noxtls_secure_zero(two_buf, sizeof(two_buf));
            noxtls_secure_zero(a_mod_m_p256, sizeof(a_mod_m_p256));
            return rc;
        }
        (void)noxtls_bn_zero(result, m_len);
        noxtls_secure_zero(a_mod_m_p256, sizeof(a_mod_m_p256));
        return NOXTLS_RETURN_FAILED;
    }

    /* Allocate all buffers once */
    uint8_t *u1 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    uint8_t *u3 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    uint8_t *v1 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    uint8_t *v3 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    uint8_t *temp = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    uint8_t *a_mod_m = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
    /* Wide buffers for shift step: &u1[m] can overflow m_len bytes (noxtls_bn_add drops carry) */
    const uint32_t m_wide = (uint32_t)(m_len + 1U);
    uint8_t *m_padded = (uint8_t*)NOXTLS_CALLOC(m_wide, 1);
    uint8_t *u1_wide = (uint8_t*)NOXTLS_CALLOC(m_wide, 1);
    uint8_t *v1_wide = (uint8_t*)NOXTLS_CALLOC(m_wide, 1);
    
    if((u1 == NULL) || (u3 == NULL) || (v1 == NULL) || (v3 == NULL) || (temp == NULL) || (a_mod_m == NULL) || (m_padded == NULL) || (u1_wide == NULL) || (v1_wide == NULL)) {
        if(u1 != NULL) { (void)noxtls_free(u1); }
        if(u3 != NULL) { (void)noxtls_free(u3); }
        if(v1 != NULL) { (void)noxtls_free(v1); }
        if(v3 != NULL) { (void)noxtls_free(v3); }
        if(temp != NULL) { (void)noxtls_free(temp); }
        if(a_mod_m != NULL) { (void)noxtls_free(a_mod_m); }
        if(m_padded != NULL) { (void)noxtls_free(m_padded); }
        if(u1_wide != NULL) { (void)noxtls_free(u1_wide); }
        if(v1_wide != NULL) { (void)noxtls_free(v1_wide); }
        noxtls_secure_zero((result), (size_t)(m_len));
        return NOXTLS_RETURN_FAILED;
    }
    m_padded[0] = 0;
    (void)noxtls_bn_copy(&m_padded[1], m, m_len);
    
    /* Initialize: u1 = 1, u3 = a mod m, v1 = 0, v3 = m */
    (void)noxtls_bn_one(u1, m_len);
    
    /* If a_len == m_len and a < m, we can just copy it directly */
    /* This avoids potential bugs in noxtls_bn_mod */
    if(a_len == m_len) {
        if(noxtls_bn_cmp(a, m, m_len) < 0) {
            (void)noxtls_bn_copy(u3, a, m_len);
            (void)noxtls_bn_copy(a_mod_m, a, m_len);
        } else {
            (void)noxtls_bn_mod(u3, a, a_len, m, m_len);  /* u3 = a mod m */
            (void)noxtls_bn_copy(a_mod_m, u3, m_len);
        }
    } else {
        (void)noxtls_bn_mod(u3, a, a_len, m, m_len);  /* u3 = a mod m */
        (void)noxtls_bn_copy(a_mod_m, u3, m_len);
    }
    
    /* Check if u3 is zero (no inverse exists) */
    if(noxtls_bn_is_zero(u3, m_len) != 0) {
        (void)noxtls_bn_zero(result, m_len);
        (void)noxtls_free(u1);
        (void)noxtls_free(u3);
        (void)noxtls_free(v1);
        (void)noxtls_free(v3);
        (void)noxtls_free(temp);
        (void)noxtls_free(a_mod_m);
        (void)noxtls_free(m_padded);
        (void)noxtls_free(u1_wide);
        (void)noxtls_free(v1_wide);
        return NOXTLS_RETURN_FAILED;
    }
    
    (void)noxtls_bn_zero(v1, m_len);
    (void)noxtls_bn_copy(v3, m, m_len);
    
    /* Binary extended Euclidean algorithm - uses only shifts and adds/subtracts (no division!) */
    uint32_t iter = 0U;
    uint32_t max_iter = (uint32_t)(m_len * 8U * 8U);  /* Increased safety limit for 256-bit (was 4x, now 8x) */
    
    {
    uint8_t inv_loop_done = 0U;
    while(inv_loop_done == 0U) {
        int32_t v3_nonzero;
        int32_t u3_nonzero;
        if(iter >= max_iter) {
            inv_loop_done = 1U;
            continue;
        }
        v3_nonzero = noxtls_bn_is_zero(v3, m_len);
        u3_nonzero = noxtls_bn_is_zero(u3, m_len);
        if((v3_nonzero != 0) || (u3_nonzero != 0)) {
            inv_loop_done = 1U;
            continue;
        }
        iter += 1U;
        
        /* Remove factors of 2 from u3 and v3 (check LSB - least significant byte) */
        /* Safety: limit iterations to prevent infinite loops */
        uint32_t shift_iter_u = 0U;
        uint32_t max_shift_iter = (uint32_t)(m_len * 8U * 2U); /* Allow more iterations for shift loops */
        {
            uint8_t u_shift_done = 0U;
            while((shift_iter_u < max_shift_iter) && (u_shift_done == 0U)) {
                int32_t u3_zero = noxtls_bn_is_zero(u3, m_len);
                if(((u3[m_len - 1U] & 1U) != 0U) || (u3_zero != 0)) {
                    u_shift_done = 1U;
                } else {
                    (void)noxtls_bn_rshift1(u3, m_len);
                    if((u1[m_len - 1U] & 1U) != 0U) {
                        /* u1 += m; use m_wide so carry is not lost (noxtls_bn_add drops carry) */
                        u1_wide[0] = 0;
                        (void)noxtls_bn_copy(&u1_wide[1], u1, m_len);
                        (void)noxtls_bn_add(u1_wide, u1_wide, m_padded, m_wide);
                        (void)noxtls_bn_rshift1(u1_wide, m_wide);
                        {
                            (void)noxtls_bn_mod(u1, u1_wide, m_wide, m, m_len);
                        }
                    } else {
                        (void)noxtls_bn_rshift1(u1, m_len);
                    }
                    shift_iter_u += 1U;
                }
            }
        }
        if(shift_iter_u >= max_shift_iter) {
            (void)noxtls_bn_zero(result, m_len);
            (void)noxtls_free(u1);
            (void)noxtls_free(u3);
            (void)noxtls_free(v1);
            (void)noxtls_free(v3);
            (void)noxtls_free(temp);
            (void)noxtls_free(a_mod_m);
            (void)noxtls_free(m_padded);
            (void)noxtls_free(u1_wide);
            (void)noxtls_free(v1_wide);
            return NOXTLS_RETURN_TIMEOUT;
        }
        
        uint32_t shift_iter_v = 0U;
        {
            uint8_t v_shift_done = 0U;
            while((shift_iter_v < max_shift_iter) && (v_shift_done == 0U)) {
                int32_t v3_zero = noxtls_bn_is_zero(v3, m_len);
                if(((v3[m_len - 1U] & 1U) != 0U) || (v3_zero != 0)) {
                    v_shift_done = 1U;
                } else {
                    (void)noxtls_bn_rshift1(v3, m_len);
                    if((v1[m_len - 1U] & 1U) != 0U) {
                        /* v1 += m; use m_wide so carry is not lost (noxtls_bn_add drops carry) */
                        v1_wide[0] = 0;
                        (void)noxtls_bn_copy(&v1_wide[1], v1, m_len);
                        (void)noxtls_bn_add(v1_wide, v1_wide, m_padded, m_wide);
                        (void)noxtls_bn_rshift1(v1_wide, m_wide);
                        {
                            (void)noxtls_bn_mod(v1, v1_wide, m_wide, m, m_len);
                        }
                    } else {
                        (void)noxtls_bn_rshift1(v1, m_len);
                    }
                    shift_iter_v += 1U;
                }
            }
        }
        if(shift_iter_v >= max_shift_iter) {
            (void)noxtls_bn_zero(result, m_len);
            (void)noxtls_free(u1);
            (void)noxtls_free(u3);
            (void)noxtls_free(v1);
            (void)noxtls_free(v3);
            (void)noxtls_free(temp);
            (void)noxtls_free(a_mod_m);
            (void)noxtls_free(m_padded);
            (void)noxtls_free(u1_wide);
            (void)noxtls_free(v1_wide);
            return NOXTLS_RETURN_TIMEOUT;
        }
        
        /* Check if either is zero before subtracting */
        {
            int32_t u3_zero = noxtls_bn_is_zero(u3, m_len);
            int32_t v3_zero = noxtls_bn_is_zero(v3, m_len);
            if((u3_zero != 0) || (v3_zero != 0)) {
                inv_loop_done = 1U;
                continue;
            }
        }
        
        /* Safety check: if u3 == v3 (but not zero), we've found the GCD */
        /* If GCD == 1, the inverse exists; if GCD != 1, no inverse exists */
        if(noxtls_bn_cmp(u3, v3, m_len) == 0) {
            if(noxtls_bn_is_one(u3, m_len) != 0) {
                /* GCD is 1, so the inverse exists - stop and use u1 as the result */
                inv_loop_done = 1U;
                continue;
            }
            /* GCD is not 1, so no inverse exists */
            (void)noxtls_bn_zero(result, m_len);
            (void)noxtls_free(u1);
            (void)noxtls_free(u3);
            (void)noxtls_free(v1);
            (void)noxtls_free(v3);
            (void)noxtls_free(temp);
            (void)noxtls_free(a_mod_m);
            (void)noxtls_free(m_padded);
            (void)noxtls_free(u1_wide);
            (void)noxtls_free(v1_wide);
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Subtract smaller from larger */
        if(noxtls_bn_cmp(u3, v3, m_len) >= 0) {
            (void)noxtls_bn_sub(u3, u3, v3, m_len);
            if(noxtls_bn_cmp(u1, v1, m_len) >= 0) {
                (void)noxtls_bn_sub(u1, u1, v1, m_len);
            } else {
                (void)noxtls_bn_sub(temp, m, v1, m_len);
                (void)noxtls_bn_add(u1, u1, temp, m_len);
                /* noxtls_bn_add drops carry; reduce so u1 is in [0, m). */
                (void)noxtls_bn_mod(u1, u1, m_len, m, m_len);
            }
            /* Reduce u1 mod m if needed (e.g. after subtract) */
            if(noxtls_bn_cmp(u1, m, m_len) >= 0) {
                (void)noxtls_bn_mod(u1, u1, m_len, m, m_len);
            }
            
            /* Debug: check if u1 might be "negative" (greater than m/2) */
            /* In modular arithmetic, we don't need to worry about negative numbers */
            /* as long as we reduce mod m properly */
        } else {
            (void)noxtls_bn_sub(v3, v3, u3, m_len);
            if(noxtls_bn_cmp(v1, u1, m_len) >= 0) {
                (void)noxtls_bn_sub(v1, v1, u1, m_len);
            } else {
                (void)noxtls_bn_sub(temp, m, u1, m_len);
                (void)noxtls_bn_add(v1, v1, temp, m_len);
                /* noxtls_bn_add drops carry; reduce so v1 is in [0, m). */
                (void)noxtls_bn_mod(v1, v1, m_len, m, m_len);
            }
            /* Reduce v1 mod m if needed (e.g. after subtract) */
            if(noxtls_bn_cmp(v1, m, m_len) >= 0) {
                (void)noxtls_bn_mod(v1, v1, m_len, m, m_len);
            }
        }
    }
    }
    
    if(iter >= max_iter) {
        (void)noxtls_bn_zero(result, m_len);
        (void)noxtls_free(u1);
        (void)noxtls_free(u3);
        (void)noxtls_free(v1);
        (void)noxtls_free(v3);
        (void)noxtls_free(temp);
        (void)noxtls_free(a_mod_m);
        (void)noxtls_free(m_padded);
        (void)noxtls_free(u1_wide);
        (void)noxtls_free(v1_wide);
        return NOXTLS_RETURN_TIMEOUT;
    }
    
    /* Determine which one is the GCD and get the result coefficient */
    /* In binary extended Euclidean algorithm: */
    /* - If u3 == 1, then u1 is the inverse (u1*a + 1*m = 1, so u1*a ≡ 1 mod m) */
    /* - If u3 == 0, then v3 is the GCD. If v3 == 1, then v1 is the inverse */
    /* - If v3 == 0, then u3 is the GCD. If u3 == 1, then u1 is the inverse */
    /* - If v3 == 1, then v1 is the inverse */
    
    const uint8_t *gcd = NULL;
    const uint8_t *result_coeff = NULL;
    int inverse_exists = 0;
    
    if(noxtls_bn_is_one(u3, m_len) != 0) {
        /* u3 == 1, so u1 is the inverse */
        gcd = u3;
        result_coeff = u1;
        inverse_exists = 1;
    } else if(noxtls_bn_is_zero(u3, m_len) != 0) {
        /* u3 == 0, so v3 is the GCD */
        gcd = v3;
        if(noxtls_bn_is_one(v3, m_len) != 0) {
            result_coeff = v1;
            inverse_exists = 1;
        }
    } else if(noxtls_bn_is_one(v3, m_len) != 0) {
        /* v3 == 1, so v1 is the inverse */
        gcd = v3;
        result_coeff = v1;
        inverse_exists = 1;
    } else if(noxtls_bn_is_zero(v3, m_len) != 0) {
        /* v3 == 0, so u3 is the GCD */
        gcd = u3;
        if(noxtls_bn_is_one(u3, m_len) != 0) {
            result_coeff = u1;
            inverse_exists = 1;
        }
    } else {
        /* Neither is 0 or 1, use the non-zero one as GCD */
        if((noxtls_bn_is_zero(u3, m_len) == 0)) {
            gcd = u3;
        } else {
            gcd = v3;
        }
    }
    (void)gcd; /* set for documentation; inverse_exists determines path */

    if(inverse_exists == 0) {
        /* For odd prime moduli, use Fermat: a^(-1) = a^(p-2) mod p.
         * The binary extended GCD can mis-terminate in some cases; this is a correct fallback. */
        if((m[m_len - 1U] & 1U) != 0U) {
            uint8_t *m_minus_2 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
            uint8_t *two_buf = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
            uint8_t *fermat_out = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
            if((m_minus_2 != NULL) && (two_buf != NULL) && (fermat_out != NULL)) {
                if((noxtls_bn_is_zero(a_mod_m, m_len) == 0)) {
                    two_buf[m_len - 1U] = 2U;
                    (void)noxtls_bn_copy(m_minus_2, m, m_len);
                    (void)noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
                    (void)noxtls_bn_mod_exp(fermat_out, a_mod_m, m_minus_2, m_len, m, m_len);
                    noxtls_copy_u8(result, (size_t)m_len, fermat_out, (size_t)m_len);
                } else {
                    (void)noxtls_bn_zero(result, m_len);
                }
            } else {
                (void)noxtls_bn_zero(result, m_len);
            }
            if(m_minus_2 != NULL) { (void)noxtls_free(m_minus_2); }
            if(two_buf != NULL) { (void)noxtls_free(two_buf); }
            if(fermat_out != NULL) { (void)noxtls_free(fermat_out); }
        } else {
            (void)noxtls_bn_zero(result, m_len);
        }
    } else {
        /* Result is result_coeff mod m */
        (void)noxtls_bn_mod(result, result_coeff, m_len, m, m_len);
        /* Verify: (a_mod_m * result) mod m == 1. If not, try Fermat fallback for odd moduli. */
        {
            uint8_t *prod = (uint8_t*)NOXTLS_CALLOC((size_t)m_len * 2U, 1);
            uint8_t *check = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
            uint8_t *one = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
            int ok = 0;
            if((prod != NULL) && (check != NULL) && (one != NULL)) {
                one[m_len - 1U] = 1U;
                (void)noxtls_bn_mul(prod, a_mod_m, m_len, result, m_len);
                (void)noxtls_bn_mod(check, prod, m_len * 2U, m, m_len);
                ok = (noxtls_bn_cmp(check, one, m_len) == 0) ? 1 : 0;
            }
            if(prod != NULL) { (void)noxtls_free(prod); }
            if(check != NULL) { (void)noxtls_free(check); }
            if(one != NULL) { (void)noxtls_free(one); }
            if((ok == 0) && ((m[m_len - 1U] & 1U) != 0U)) {
                uint8_t *m_minus_2 = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
                uint8_t *two_buf = (uint8_t*)NOXTLS_CALLOC(m_len, 1);
                if((m_minus_2 != NULL) && (two_buf != NULL)) {
                    two_buf[m_len - 1U] = 2U;
                    (void)noxtls_bn_copy(m_minus_2, m, m_len);
                    (void)noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
                    (void)noxtls_bn_mod_exp(result, a_mod_m, m_minus_2, m_len, m, m_len);
                } else {
                    (void)noxtls_bn_zero(result, m_len);
                }
                if(m_minus_2 != NULL) { (void)noxtls_free(m_minus_2); }
                if(two_buf != NULL) { (void)noxtls_free(two_buf); }
            }
        }
    }
    
    (void)noxtls_free(u1);
    (void)noxtls_free(u3);
    (void)noxtls_free(v1);
    (void)noxtls_free(v3);
    (void)noxtls_free(temp);
    (void)noxtls_free(a_mod_m);
    (void)noxtls_free(m_padded);
    (void)noxtls_free(u1_wide);
    (void)noxtls_free(v1_wide);
    return NOXTLS_RETURN_SUCCESS;
}

/* Build-config queries for tests removed (reference backend removed). */
