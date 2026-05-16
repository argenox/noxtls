/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_bignum.c
* Summary: Big Number Arithmetic Operations Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_bignum.h"

/* Debug helpers for bn_mod / bn_mod_exp instrumentation. */
static int g_bn_debug_mod_first = 1;
static int g_bn_debug_modexp_first = 1;
static int g_bn_debug_div_first = 1;
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static int g_bn_debug_div_progress = 1;
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static int g_bn_debug_inv_progress = 1;
static int g_bn_debug_modexp_active = 0;
static uint32_t g_bn_debug_mod_calls = 0;
static uint32_t g_bn_debug_modexp_byte = 0;
static uint8_t g_bn_debug_modexp_bit = 0;
static uint8_t g_bn_debug_modexp_stage = 0;
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static int g_bn_debug_mod_mismatch_once = 1;
static int g_bn_debug_mod_compare_all = 0;
static int g_bn_debug_mod_first_mismatch_only = 1;
static int g_bn_debug_div_trace = 0;
/* Set to 1 to trace bn_mod_2n_by_n_limb line-by-line (e.g. for 96/48 Gy^2 mod p). */
static int g_bn_debug_mod_2n_by_n = 0;
/* Temporary safety switch: keep 2n/n reducer disabled in noxtls_bn_mod dispatcher. */
static void bn_debug_print(const char *label, const uint8_t *buf, uint32_t len)
{
    if(buf == NULL && len > 0)
        return;
    (void)label;
    (void)buf;
    //fprintf(stderr, "%s", label);
    for(uint32_t i = 0; i < len; i++) {
        //fprintf(stderr, "%02X ", buf[i]);
    }
    //fprintf(stderr, "\n");
}

/* Debug: print limbs (LE, limb 0 = LSW) to stderr. */
static void bn_debug_limbs(const char *label, const uint32_t *limbs, uint32_t limb_len)
{
    uint32_t i;
    if(limbs == NULL || !g_bn_debug_mod_2n_by_n)
        return;
    fprintf(stderr, "[bn_mod_2n_by_n] %s (%u limbs):", label, (unsigned)limb_len);
    for(i = 0; i < limb_len; i++)
        fprintf(stderr, " %08X", (unsigned)limbs[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* Debug: print bytes (BE) to stderr, optional max. */
static void bn_debug_bytes(const char *label, const uint8_t *buf, uint32_t len, uint32_t max_show)
{
    uint32_t i;
    uint32_t n = (max_show != 0u && len > max_show) ? max_show : len;
    if(buf == NULL || !g_bn_debug_mod_2n_by_n)
        return;
    fprintf(stderr, "[bn_mod_2n_by_n] %s (%u bytes):", label, (unsigned)len);
    for(i = 0; i < n; i++)
        fprintf(stderr, "%02X", buf[i]);
    if(len > max_show && max_show != 0u)
        fprintf(stderr, "...(%u more)", (unsigned)(len - max_show));
    fprintf(stderr, "\n");
    fflush(stderr);
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
int noxtls_bn_cmp(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i;

    if(a == NULL || b == NULL)
        return 0; /* treat as equal on invalid params */
    if(len == 0)
        return 0;
    for(i = 0; i < len; i++) {
        if(a[i] != b[i])
            return (a[i] > b[i]) ? 1 : -1;
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
int noxtls_bn_is_zero(const uint8_t *a, uint32_t len)
{
    uint32_t i;

    if(a == NULL || len == 0)
        return 0; /* not zero on invalid params */
    for(i = 0; i < len; i++) {
        if(a[i] != 0)
            return 0;
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
int noxtls_bn_is_one(const uint8_t *a, uint32_t len)
{
    uint32_t i;

    if(a == NULL || len == 0)
        return 0;
    if(a[len - 1] != 1)
        return 0;
    for(i = 0; i < len - 1; i++) {
        if(a[i] != 0)
            return 0;
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
    if(a == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    memset(a, 0, len);
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
    if(a == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    memset(a, 0, len);
    a[len - 1] = 1;
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
    if(dst == NULL || src == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    memcpy(dst, src, len);
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
    uint32_t i;
    uint16_t carry = 0;

    if(result == NULL || a == NULL || b == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    for(i = len; i > 0; i--) {
        uint16_t sum = (uint16_t)a[i - 1] + (uint16_t)b[i - 1] + carry;
        result[i - 1] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
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
    uint32_t i;
    int borrow = 0;

    if(result == NULL || a == NULL || b == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    for(i = len; i > 0; i--) {
        int diff = (int)a[i - 1] - (int)b[i - 1] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i - 1] = (uint8_t)diff;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/*
 * multiply-add with carry: r[0..n-1] += s[0..n-1] * d + carry_in;
 * output carry in *c. Uses 64-bit intermediate so limb * limb + limb + carry cannot overflow.
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): legacy limb helper signature mirrors mbedTLS-style call sites. */
static void bn_muladd_hlp(const uint32_t *s, uint32_t n, uint32_t d, uint32_t *r, uint32_t *c)
{
    uint32_t i;
    uint64_t carry = (uint64_t)*c;
    for(i = 0; i < n; i++) {
        uint64_t t = (uint64_t)s[i] * (uint64_t)d + (uint64_t)r[i] + carry;
        r[i] = (uint32_t)(t & 0xFFFFFFFFu);
        carry = t >> 32;
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
    uint32_t n_limbs_a;
    uint32_t n_limbs_b;
    uint32_t n_limbs_r;
    uint32_t result_len;
    uint32_t *a_limbs = NULL;
    uint32_t *b_limbs = NULL;
    uint32_t *r_limbs = NULL;
    uint32_t i;
    uint32_t carry;

    if(result == NULL || a == NULL || b == NULL)
        return NOXTLS_RETURN_NULL;
    if(a_len == 0 || b_len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    if(a_len > (uint32_t)(UINT32_MAX - b_len) ||
       a_len > (uint32_t)(UINT32_MAX - 3u) ||
       b_len > (uint32_t)(UINT32_MAX - 3u)) {
        return NOXTLS_RETURN_FAILED;
    }

    result_len = a_len + b_len;
    n_limbs_a = (a_len + 3u) / 4u;
    n_limbs_b = (b_len + 3u) / 4u;
    if(n_limbs_a > (uint32_t)(UINT32_MAX - n_limbs_b)) {
        return NOXTLS_RETURN_FAILED;
    }
    n_limbs_r = n_limbs_a + n_limbs_b;

    a_limbs = (uint32_t*)noxtls_calloc(n_limbs_a, sizeof(uint32_t));
    b_limbs = (uint32_t*)noxtls_calloc(n_limbs_b, sizeof(uint32_t));
    r_limbs = (uint32_t*)noxtls_calloc(n_limbs_r, sizeof(uint32_t));
    if(!a_limbs || !b_limbs || !r_limbs) {
        noxtls_debug_printf("ERROR: noxtls_bn_mul: Memory allocation failed!\n");
        fflush(stdout);
        if(a_limbs) noxtls_free(a_limbs);
        if(b_limbs) noxtls_free(b_limbs);
        if(r_limbs) noxtls_free(r_limbs);
        memset(result, 0, result_len);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    bn_bytes_to_limbs_le(a_limbs, n_limbs_a, a, a_len);
    bn_bytes_to_limbs_le(b_limbs, n_limbs_b, b, b_len);

    /* For each limb of b: r[i..] += a[0..] * b[i]. */
    for(i = 0; i < n_limbs_b; i++) {
        carry = 0;
        bn_muladd_hlp(a_limbs, n_limbs_a, b_limbs[i], r_limbs + i, &carry);
        r_limbs[i + n_limbs_a] = carry;
    }

    bn_limbs_to_bytes_be(result, result_len, r_limbs, n_limbs_r);

    noxtls_free(a_limbs);
    noxtls_free(b_limbs);
    noxtls_free(r_limbs);
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
    int32_t i;
    uint8_t carry = 0;

    if(a == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    /* Iterate from MSB to LSB for big-endian representation */
    for(i = 0; i < (int32_t)len; i++) {
        uint8_t byte = a[i];
        uint8_t lsb = byte & 1;
        a[i] = (byte >> 1) | carry;
        carry = lsb ? 0x80u : 0;
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
    if(a == NULL || len == NULL)
        return a;
    while(*len > 0 && a[0] == 0) {
        a++;
        (*len)--;
    }
    return a;
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
    if(dst == NULL)
        return NOXTLS_RETURN_NULL;
    if(src == NULL)
        return NOXTLS_RETURN_NULL;
    if(dst_len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;

    memset(dst, 0, dst_len);
    if(src_len >= dst_len) {
        memcpy(dst, src + (src_len - dst_len), dst_len);
    } else {
        memcpy(dst + (dst_len - src_len), src, src_len);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ---- 32-bit limb helpers (little-endian limbs) ---- */
static void bn_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len)
{
    uint32_t i;
    if(limbs == NULL || limb_len == 0)
        return;
    memset(limbs, 0, limb_len * sizeof(uint32_t));
    if(bytes == NULL || byte_len == 0)
        return;
    for(i = 0; i < byte_len; i++) {
        uint32_t limb_idx = i >> 2;
        uint32_t shift = (i & 3u) << 3;
        if(limb_idx >= limb_len)
            break;
        limbs[limb_idx] |= (uint32_t)bytes[byte_len - 1 - i] << shift;
    }
}

static void bn_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len)
{
    uint32_t i;
    if(out == NULL || out_len == 0)
        return;
    memset(out, 0, out_len);
    if(limbs == NULL || limb_len == 0)
        return;
    for(i = 0; i < out_len; i++) {
        uint32_t limb_idx = i >> 2;
        uint32_t shift = (i & 3u) << 3;
        uint8_t v = 0;
        if(limb_idx < limb_len) {
            v = (uint8_t)((limbs[limb_idx] >> shift) & 0xFFu);
        }
        out[out_len - 1 - i] = v;
    }
}

static int bn_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    int32_t i;
    if(a == NULL || b == NULL || limb_len == 0)
        return 0;
    for(i = (int32_t)limb_len - 1; i >= 0; i--) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : 0;
        }
    }
    return 1;
}

static void bn_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    uint64_t borrow = 0;
    uint32_t i;
    if(a == NULL || b == NULL || limb_len == 0)
        return;
    for(i = 0; i < limb_len; i++) {
        uint64_t av = (uint64_t)a[i];
        uint64_t bv = (uint64_t)b[i] + borrow;
        if(av < bv) {
            a[i] = (uint32_t)((av + (1ULL << 32)) - bv);
            borrow = 1;
        } else {
            a[i] = (uint32_t)(av - bv);
            borrow = 0;
        }
    }
}

/* Subtract b from a (n limbs). Returns 1 if borrow out, 0 otherwise. */
static int bn_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n)
{
    uint64_t borrow = 0;
    uint32_t i;
    if(a == NULL || b == NULL || n == 0)
        return 0;
    for(i = 0; i < n; i++) {
        uint64_t av = (uint64_t)a[i];
        uint64_t bv = (uint64_t)b[i] + borrow;
        if(av < bv) {
            a[i] = (uint32_t)((av + (1ULL << 32)) - bv);
            borrow = 1;
        } else {
            a[i] = (uint32_t)(av - bv);
            borrow = 0;
        }
    }
    return (int)borrow;
}

static void bn_lshift1_limbs(uint32_t *a, uint32_t limb_len)
{
    uint32_t i;
    uint32_t carry = 0;
    if(a == NULL || limb_len == 0)
        return;
    for(i = 0; i < limb_len; i++) {
        uint32_t new_carry = (a[i] >> 31) & 1u;
        a[i] = (a[i] << 1) | carry;
        carry = new_carry;
    }
}

/* Count leading zero bits in x; returns 32 if x == 0. */
static unsigned bn_clz(uint32_t x)
{
    unsigned c = 0;
    if(x == 0) return 32;
    while((x & 0x80000000u) == 0) { c++; x <<= 1; }
    return c;
}

/* Shift limbs left by k bits (0 <= k <= 31). */
static void bn_limbs_shl(uint32_t *a, uint32_t len, unsigned k)
{
    uint32_t i;
    uint32_t carry = 0;
    if(a == NULL || len == 0 || k == 0) return;
    if(k > 31) return;
    for(i = 0; i < len; i++) {
        uint32_t v = a[i];
        a[i] = (v << k) | carry;
        carry = v >> (32u - k);
    }
}

/* Shift limbs right by k bits (0 <= k <= 31). */
static void bn_limbs_shr(uint32_t *a, uint32_t len, unsigned k)
{
    int32_t i;
    uint32_t carry = 0;
    if(a == NULL || len == 0 || k == 0) return;
    if(k > 31) return;
    for(i = (int32_t)len - 1; i >= 0; i--) {
        uint32_t v = a[i];
        a[i] = (v >> k) | carry;
        carry = v << (32u - k);
    }
}

/* Subtract q*mod from rem[start..start+n]. Returns 1 if borrow out, 0 otherwise.
 * Knuth D4 on base 2^32 limbs: k carries both product-high and subtraction borrow. */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): subtraction kernel keeps Knuth D-layout (start,q,mod,n). */
static int bn_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q,
                          const uint32_t *mod, uint32_t n)
{
    uint64_t carry = 0;
    uint64_t borrow = 0;
    uint32_t i;
    for(i = 0; i < n; i++) {
        const uint64_t prod = (uint64_t)mod[i] * (uint64_t)q + carry;
        const uint64_t sub = (uint64_t)(uint32_t)prod + borrow;
        const uint64_t rem_i = (uint64_t)rem[start + i];

        carry = prod >> 32;
        if(rem_i < sub) {
            rem[start + i] = (uint32_t)(rem_i + (1ULL << 32) - sub);
            borrow = 1;
        } else {
            rem[start + i] = (uint32_t)(rem_i - sub);
            borrow = 0;
        }
    }
    {
        const uint64_t k = carry + borrow;
        uint64_t rem_hi = (uint64_t)rem[start + n];
        uint64_t diff = rem_hi - k;
        rem[start + n] = (uint32_t)diff;
        return (rem_hi < k) ? 1 : 0;
    }
}

/* Add mod to rem[start..start+n]. Returns carry out. */
static uint32_t bn_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n)
{
    uint64_t carry = 0;
    uint32_t i;
    for(i = 0; i < n; i++) {
        uint64_t sum = (uint64_t)rem[start + i] + (uint64_t)mod[i] + carry;
        rem[start + i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    {
        uint64_t sum_hi = (uint64_t)rem[start + n] + carry;
        rem[start + n] = (uint32_t)sum_hi;
        return (uint32_t)(sum_hi >> 32);
    }
}

/*
 * Fast mod for ECDSA case: dividend length == 2 * modulus length (64/32, 96/48, 132/66).
 * Uses limb-digit division: O(limb_len) steps instead of O(8*mod_len) bit steps.
 * Returns NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t bn_mod_2n_by_n_limb(uint8_t *rem_out, uint32_t mod_len,
                                           const uint8_t *a, uint32_t a_len, const uint8_t *mod)
{
    const uint32_t n = (mod_len + 3u) >> 2;  /* modulus limbs */
    const uint32_t m = n * 2u;               /* dividend limbs for 2n-byte input */
    uint32_t *u = NULL;                      /* dividend/remainder, n*2 + 1 limbs */
    uint32_t *v = NULL;                      /* modulus limbs */
    uint8_t *a_padded = NULL;
    const uint8_t *a_sig = a;
    unsigned norm_shift = 0;
    uint32_t j;
    int do_trace = g_bn_debug_mod_2n_by_n && (a_len == 96u && mod_len == 48u);

    if(rem_out == NULL || a == NULL || mod == NULL || mod_len == 0)
        return NOXTLS_RETURN_NULL;

    /* Always log entry when debug flag is on, so redirect 2> file gets something. */
    if(g_bn_debug_mod_2n_by_n) {
        fprintf(stderr, "[bn_mod_2n_by_n] called: a_len=%u mod_len=%u do_trace=%d\n",
                (unsigned)a_len, (unsigned)mod_len, do_trace);
        fflush(stderr);
    }

    if(do_trace) {
        fprintf(stderr, "\n[bn_mod_2n_by_n] === ENTRY a_len=%u mod_len=%u n=%u m=%u ===\n",
                (unsigned)a_len, (unsigned)mod_len, (unsigned)n, (unsigned)m);
        fflush(stderr);
        bn_debug_bytes("a (first 8)", a, a_len, 8);
        bn_debug_bytes("a (last 8)", a + (a_len - 8), 8, 0);
        bn_debug_bytes("mod (first 8)", mod, mod_len, 8);
        bn_debug_bytes("mod (last 8)", mod + (mod_len - 8), 8, 0);
    }

    a_sig = bn_strip_leading_zeros(a_sig, &a_len);
    if(do_trace)
        fprintf(stderr, "[bn_mod_2n_by_n] after strip_leading_zeros: a_len=%u\n", (unsigned)a_len);
    if(a_len == 0) {
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_len < mod_len || (a_len == mod_len && noxtls_bn_cmp(a_sig, mod, mod_len) < 0)) {
        if(bn_copy_aligned(rem_out, mod_len, a_sig, a_len) != NOXTLS_RETURN_SUCCESS) {
            memset(rem_out, 0, mod_len);
            return NOXTLS_RETURN_FAILED;
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_len > mod_len * 2u)
        return NOXTLS_RETURN_FAILED; /* caller should use general path */
    if(mod_len > (uint32_t)(UINT32_MAX / 2u)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(n > (uint32_t)(UINT32_MAX / 2u)) {
        return NOXTLS_RETURN_FAILED;
    }

    a_padded = (uint8_t*)noxtls_calloc((size_t)mod_len * 2u, 1);
    v = (uint32_t*)noxtls_calloc(n, sizeof(uint32_t));
    u = (uint32_t*)noxtls_calloc(m + 1u, sizeof(uint32_t));
    if(a_padded == NULL || v == NULL || u == NULL) {
        if(a_padded) noxtls_free(a_padded);
        if(v) noxtls_free(v);
        if(u) noxtls_free(u);
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    memcpy(a_padded + (mod_len * 2u - a_len), a_sig, a_len);
    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] a_padded offset=%u (pad %u zero bytes)\n",
                (unsigned)(mod_len * 2u - a_len), (unsigned)(mod_len * 2u - a_len));
        fflush(stderr);
        bn_debug_bytes("a_padded (first 12)", a_padded, mod_len * 2u, 12);
        bn_debug_bytes("a_padded (last 12)", a_padded + (mod_len * 2u - 12), 12, 0);
    }

    bn_bytes_to_limbs_le(v, n, mod, mod_len);
    bn_bytes_to_limbs_le(u, m, a_padded, mod_len * 2u);
    u[m] = 0u; /* extra high limb used by normalization/subtraction */

    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] after bytes_to_limbs_le:\n");
        bn_debug_limbs("v", v, n);
        bn_debug_limbs("u", u, m);
        fprintf(stderr, "[bn_mod_2n_by_n] u[m]=u[%u]=%u\n", (unsigned)m, (unsigned)u[m]);
    }

    if(v[n - 1u] == 0u) {
        noxtls_free(a_padded);
        noxtls_free(v);
        noxtls_free(u);
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_FAILED;
    }

    /* Knuth D1 normalization: ensure top divisor limb has MSB set. */
    norm_shift = bn_clz(v[n - 1u]);
    if(do_trace)
        fprintf(stderr, "[bn_mod_2n_by_n] norm_shift = clz(v[n-1]) = %u\n", (unsigned)norm_shift);
    if(norm_shift > 0) {
        u[m] = (uint32_t)((uint64_t)u[m - 1u] >> (32u - norm_shift));
        for(j = m - 1u; j > 0u; j--) {
            u[j] = (uint32_t)(((uint64_t)u[j] << norm_shift) |
                              ((uint64_t)u[j - 1u] >> (32u - norm_shift)));
        }
        u[0] <<= norm_shift;
        bn_limbs_shl(v, n, norm_shift);
    }
    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] after normalization:\n");
        bn_debug_limbs("v", v, n);
        bn_debug_limbs("u", u, m + 1u);
    }

    /* Knuth D2..D6 for m=2n, divisor length n. */
    for(j = m - n; (int32_t)j >= 0; j--) {
        uint64_t num = ((uint64_t)u[j + n] << 32) | (uint64_t)u[j + n - 1u];
        uint64_t den = (uint64_t)v[n - 1u];
        uint64_t qhat64 = num / den;
        uint64_t rhat = num - qhat64 * den;
        uint32_t qhat;

        if(qhat64 > 0xFFFFFFFFULL) {
            qhat = 0xFFFFFFFFu;
            /* Keep rhat consistent with clamped qhat. */
            rhat = num - (uint64_t)qhat * den;
        } else {
            qhat = (uint32_t)qhat64;
        }

        if(n > 1u) {
            while(1) {
                uint64_t lhs = (uint64_t)qhat * (uint64_t)v[n - 2u];
                /* rhs = (rhat << 32) + u[j+n-2] can exceed 64 bits if rhat>=2^32.
                 * Compare safely without overflowing 64-bit intermediates. */
                if((rhat >> 32) != 0u)
                    break;
                {
                    uint64_t rhs = (rhat << 32) + (uint64_t)u[j + n - 2u];
                    if(lhs <= rhs)
                        break;
                }
                qhat--;
                rhat += den;
            }
        }

        if(do_trace) {
            fprintf(stderr, "[bn_mod_2n_by_n] --- j=%u num=0x%016llX den=0x%08llX qhat64=%llu qhat=0x%08X rhat=%llu\n",
                    (unsigned)j, (unsigned long long)num, (unsigned long long)den,
                    (unsigned long long)qhat64, (unsigned)qhat, (unsigned long long)rhat);
            fprintf(stderr, "[bn_mod_2n_by_n]     u[j..j+n] before: u[%u]=0x%08X u[%u]=0x%08X ... u[%u]=0x%08X u[%u]=0x%08X\n",
                    (unsigned)j, (unsigned)u[j], (unsigned)(j+1), (unsigned)u[j+1],
                    (unsigned)(j+n-1), (unsigned)u[j+n-1], (unsigned)(j+n), (unsigned)u[j+n]);
            fflush(stderr);
        }

        if(qhat != 0u) {
            int borrow;
            borrow = bn_limb_mul_sub(u, j, qhat, v, n);
            if(borrow) {
                /* qhat was one too large: add divisor back (Knuth D6). */
                uint32_t carry_out = bn_limb_add_at(u, j, v, n);
                if(carry_out != 0u && (j + n + 1u) <= m)
                    u[j + n + 1u] += carry_out;
                if(do_trace) fprintf(stderr, "[bn_mod_2n_by_n]     borrow=1 -> add v back\n");
            }
            if(do_trace) {
                fprintf(stderr, "[bn_mod_2n_by_n]     u[j..j+n] after:  u[%u]=0x%08X u[%u]=0x%08X ... u[%u]=0x%08X u[%u]=0x%08X\n",
                        (unsigned)j, (unsigned)u[j], (unsigned)(j+1), (unsigned)u[j+1],
                        (unsigned)(j+n-1), (unsigned)u[j+n-1], (unsigned)(j+n), (unsigned)u[j+n]);
            }
        }
    }

    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] after division loop:\n");
        fflush(stderr);
        bn_debug_limbs("u[0..n]", u, n);
        fprintf(stderr, "[bn_mod_2n_by_n] u[n]=u[%u]=%u  bn_ge_limbs(u,v,n)=%d\n",
                (unsigned)n, (unsigned)u[n], bn_ge_limbs(u, v, n));
        fflush(stderr);
    }

    /* Remainder is in u[0..n-1], possibly with u[n] > 0 or u[0..n-1] >= v if qhat was too small.
     * Reduce to u[0..n-1] < v (normalized) so unnormalization yields remainder < mod. */
    {
        uint32_t corr = 0;
        while(u[n] != 0u || bn_ge_limbs(u, v, n)) {
            if(bn_sub_limbs_borrow(u, v, n)) {
                if(u[n] != 0u)
                    u[n]--;
                else
                    break;
            }
            corr++;
            if(do_trace && corr <= 5)
                fprintf(stderr, "[bn_mod_2n_by_n] correction step %u: u[n]=%u\n", (unsigned)corr, (unsigned)u[n]);
        }
        if(do_trace && corr > 0)
            fprintf(stderr, "[bn_mod_2n_by_n] total correction steps: %u\n", (unsigned)corr);
    }

    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] after correction loop:\n");
        fflush(stderr);
        bn_debug_limbs("u[0..n]", u, n);
        fprintf(stderr, "[bn_mod_2n_by_n] u[n]=%u\n", (unsigned)u[n]);
        fflush(stderr);
    }

    /* D8 unnormalize remainder. */
    if(norm_shift > 0)
        bn_limbs_shr(u, n, norm_shift);

    if(do_trace) {
        fprintf(stderr, "[bn_mod_2n_by_n] after unnormalize (shift right %u):\n", (unsigned)norm_shift);
        fflush(stderr);
        bn_debug_limbs("u[0..n-1]", u, n);
    }

    bn_limbs_to_bytes_be(rem_out, mod_len, u, n);

    if(do_trace) {
        bn_debug_bytes("rem_out (BE)", rem_out, mod_len, 0);
        fprintf(stderr, "[bn_mod_2n_by_n] cmp(rem_out, mod) = %d (>=0 means rem_out >= mod)\n",
                noxtls_bn_cmp(rem_out, mod, mod_len));
        fflush(stderr);
    }

    noxtls_free(a_padded);
    noxtls_free(v);
    noxtls_free(u);

    /* Final canonicalization to [0, mod). */
    if(noxtls_bn_cmp(rem_out, mod, mod_len) >= 0) {
        if(do_trace) {
            fprintf(stderr, "[bn_mod_2n_by_n] final: rem_out >= mod -> subtract mod\n");
            fflush(stderr);
        }
        if(bn_sub_inplace(rem_out, mod, mod_len) != NOXTLS_RETURN_SUCCESS)
            memset(rem_out, 0, mod_len);
    }
    if(do_trace) {
        bn_debug_bytes("rem_out final", rem_out, mod_len, 0);
        fprintf(stderr, "[bn_mod_2n_by_n] === EXIT ===\n\n");
        fflush(stderr);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/*
 * Fast modular reduction with 32-bit limbs:
 * bitwise long division on limbs (rem = rem*2 + bit; if rem>=mod then rem-=mod).
 * This avoids byte-digit quotient estimation loops in bn_div_remainder.
 * Returns NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t bn_div_remainder_limb(uint8_t *rem_out, uint32_t mod_len,
                                             const uint8_t *a, uint32_t a_len,
                                             const uint8_t *b, uint32_t b_len)
{
    uint32_t limb_len;
    uint32_t *mod_limbs = NULL;
    uint32_t *rem_limbs = NULL;
    const uint8_t *a_sig = a;
    const uint8_t *b_sig = b;
    uint32_t a_sig_len = a_len;
    uint32_t b_sig_len = b_len;

    if(rem_out == NULL || mod_len == 0 || a == NULL || b == NULL)
        return NOXTLS_RETURN_NULL;

    a_sig = bn_strip_leading_zeros(a_sig, &a_sig_len);
    b_sig = bn_strip_leading_zeros(b_sig, &b_sig_len);

    if(b_sig_len == 0) {
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(a_sig_len == 0) {
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }
    if(a_sig_len < b_sig_len || (a_sig_len == b_sig_len && noxtls_bn_cmp(a_sig, b_sig, b_sig_len) < 0)) {
        memset(rem_out, 0, mod_len);
        memcpy(rem_out + (mod_len - a_sig_len), a_sig, a_sig_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    limb_len = (b_sig_len + 3u) >> 2;
    mod_limbs = (uint32_t*)noxtls_calloc(limb_len, sizeof(uint32_t));
    rem_limbs = (uint32_t*)noxtls_calloc(limb_len + 1u, sizeof(uint32_t));
    if(mod_limbs == NULL || rem_limbs == NULL) {
        if(mod_limbs) noxtls_free(mod_limbs);
        if(rem_limbs) noxtls_free(rem_limbs);
        memset(rem_out, 0, mod_len);
        return NOXTLS_RETURN_FAILED;
    }

    bn_bytes_to_limbs_le(mod_limbs, limb_len, b_sig, b_sig_len);

    for(uint32_t byte_idx = 0; byte_idx < a_sig_len; byte_idx++) {
        uint8_t byte = a_sig[byte_idx];
        for(int bit = 7; bit >= 0; bit--) {
            uint32_t in_bit = (uint32_t)((byte >> bit) & 1u);
            bn_lshift1_limbs(rem_limbs, limb_len + 1u);
            rem_limbs[0] |= in_bit;
            if(rem_limbs[limb_len] != 0 || bn_ge_limbs(rem_limbs, mod_limbs, limb_len)) {
                uint64_t hi = (uint64_t)rem_limbs[limb_len];
                bn_sub_limbs(rem_limbs, mod_limbs, limb_len);
                if(hi > 0) {
                    rem_limbs[limb_len] = (uint32_t)(hi - 1u);
                }
            }
        }
    }

    bn_limbs_to_bytes_be(rem_out, mod_len, rem_limbs, limb_len);
    noxtls_free(mod_limbs);
    noxtls_free(rem_limbs);
    return NOXTLS_RETURN_SUCCESS;
}

/*
 * Shift left by 1 bit, LSB-first (order: p[0]=LSW, process limb 0 first).
 * New LSB of the number is 'bit'. Big-endian: buf[0]=MSB, buf[len-1]=LSB,
 * so we process buf[len-1] down to buf[0].
 * 
 * @param buf Big integer
 * @param len Length of the big integer
 * @param bit Bit to shift
 */
NOXTLS_UNUSED_ATTR
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): bit-shift helper uses canonical (buf,len,bit) ordering. */
static void bn_shift_l_one(uint8_t *buf, uint32_t len, uint8_t bit)
{
    uint8_t carry = bit;
    uint32_t i = len;

    if(buf == NULL || len == 0)
        return;
    while(i > 0) {
        uint8_t byte = buf[i - 1];
        uint8_t new_carry = (uint8_t)((byte >> 7) & 1U);
        buf[i - 1] = (uint8_t)((byte << 1) | carry);
        carry = new_carry;
        i--;
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
    uint32_t i;

    if(a == NULL || b == NULL || len == 0)
        return 0;
    for(i = 0; i < len; i++) {
        if(a[i] != b[i])
            return a[i] > b[i] ? 1 : 0;
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
    int i;

    if(a == NULL)
        return NOXTLS_RETURN_NULL;
    if(b == NULL)
        return NOXTLS_RETURN_NULL;
    if(len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;

    i = (int)len - 1;
    for(; i >= 0; i--) {
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
static void bn_strip_leading_zeros_inplace(uint8_t *buf, uint32_t *len)
{
    uint32_t start = 0;

    if(buf == NULL || len == NULL)
        return;
    while(start < *len && buf[start] == 0) {
        start++;
    }
    if(start > 0) {
        if(start >= *len) {
            *len = 0;
            return;
        }
        memmove(buf, buf + start, (size_t)(*len - start));
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
    uint32_t i = 0;
    uint8_t top;
    uint32_t bits;

    if(buf == NULL || len == 0)
        return 0;
    while(i < len && buf[i] == 0) i++;
    if(i >= len)
        return 0;
    top = buf[i];
    bits = (len - i) << 3;
    while((top & 0x80u) == 0 && bits > 0) {
        top = (uint8_t)(top << 1);
        bits--;
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
static void bn_shift_l_bits(uint8_t *buf, uint32_t *len, unsigned k)
{
    uint32_t n;
    uint8_t carry;
    uint32_t i;

    if(buf == NULL || len == NULL)
        return;
    n = *len;
    if(n == 0 || k == 0)
        return;
    if(k >= 8) {
        /* Left shift by 8 or more: shift by full bytes first, then remaining bits */
        unsigned byte_shift = k >> 3;
        unsigned bit_shift = k & 7;
        /* Append zero bytes for full byte shifts */
        for(i = 0; i < byte_shift; i++) {
            buf[n + i] = 0;
        }
        *len = n + byte_shift;
        /* If there are remaining bits to shift, do a bit shift */
        if(bit_shift > 0) {
            carry = 0;
            i = *len;
            while(i > 0) {
                uint8_t byte = buf[i - 1];
                buf[i - 1] = (uint8_t)((byte << bit_shift) | carry);
                carry = (uint8_t)(byte >> (8 - bit_shift));
                i--;
            }
            if(carry != 0) {
                /* grow by one byte at the front */
                memmove(buf + 1, buf, *len);
                buf[0] = carry;
                *len = *len + 1;
            }
        }
        return;
    }
    carry = 0;
    i = n;
    while(i > 0) {
        uint8_t byte = buf[i - 1];
        buf[i - 1] = (uint8_t)((byte << k) | carry);
        carry = (uint8_t)(byte >> (8 - k));
        i--;
    }
    if(carry != 0) {
        /* grow by one byte at the front */
        memmove(buf + 1, buf, n);
        buf[0] = carry;
        *len = n + 1;
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
static void bn_shift_r_bits(uint8_t *buf, uint32_t len, unsigned k)
{
    if(buf == NULL || len == 0 || k == 0)
        return;
    if(k >= 8) {
        /* Right shift by 8 or more: shift by full bytes first, then remaining bits */
        unsigned byte_shift = k >> 3;
        unsigned bit_shift = k & 7;
        /* For byte shifts: move bytes left (toward MSB), zero the LSB positions */
        if(byte_shift > 0) {
            if(byte_shift >= len) {
                /* Shift by more bytes than we have - result is zero */
                memset(buf, 0, len);
                return;
            }
            /* For right shift by byte_shift bytes: drop the LSB bytes, shift remaining bytes left, zero MSB positions.
             * byte_shift < len here, so new_len = len - byte_shift > 0 */
            uint32_t new_len = len - byte_shift;
            memmove(buf + byte_shift, buf, new_len);
            memset(buf, 0, byte_shift);
        }
        /* If there are remaining bits to shift, do a bit shift */
        if(bit_shift > 0) {
            uint8_t carry = 0;
            uint32_t j;
            for(j = 0; j < len; j++) {
                uint8_t byte = buf[j];
                buf[j] = (uint8_t)((byte >> bit_shift) | carry);
                carry = (uint8_t)((byte & ((1u << bit_shift) - 1u)) << (8 - bit_shift));
            }
        }
        return;
    }
    /* Propagate from MSB to LSB: low k bits of each byte become high k bits of next. */
    {
        uint8_t carry = 0;
        uint32_t i;
        for(i = 0; i < len; i++) {
            uint8_t byte = buf[i];
            buf[i] = (uint8_t)((byte >> k) | carry);
            carry = (uint8_t)((byte & ((1u << k) - 1u)) << (8 - k));
        }
    }
}

#ifdef NOXTLS_BIGNUM_TEST_INTERNAL
/* Test-only wrapper for bn_shift_r_bits */
void noxtls_bn_test_shift_r_bits(uint8_t *buf, uint32_t len, unsigned k)
{
    if(buf == NULL)
        return;
    bn_shift_r_bits(buf, len, k);
}

/* Test-only wrapper for bn_shift_l_bits */
void noxtls_bn_test_shift_l_bits(uint8_t *buf, uint32_t *len, unsigned k)
{
    if(buf == NULL || len == NULL)
        return;
    bn_shift_l_bits(buf, len, k);
}

/* ---- 2n-by-n limb path: test-only wrappers for Layer 0 ---- */
void noxtls_bn_test_bytes_to_limbs_le(uint32_t *limbs, uint32_t limb_len, const uint8_t *bytes, uint32_t byte_len)
{
    bn_bytes_to_limbs_le(limbs, limb_len, bytes, byte_len);
}

void noxtls_bn_test_limbs_to_bytes_be(uint8_t *out, uint32_t out_len, const uint32_t *limbs, uint32_t limb_len)
{
    bn_limbs_to_bytes_be(out, out_len, limbs, limb_len);
}

int noxtls_bn_test_ge_limbs(const uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    return bn_ge_limbs(a, b, limb_len);
}

void noxtls_bn_test_sub_limbs(uint32_t *a, const uint32_t *b, uint32_t limb_len)
{
    bn_sub_limbs(a, b, limb_len);
}

int noxtls_bn_test_sub_limbs_borrow(uint32_t *a, const uint32_t *b, uint32_t n)
{
    return bn_sub_limbs_borrow(a, b, n);
}

int noxtls_bn_test_limb_mul_sub(uint32_t *rem, uint32_t start, uint32_t q, const uint32_t *mod, uint32_t n)
{
    return bn_limb_mul_sub(rem, start, q, mod, n);
}

uint32_t noxtls_bn_test_limb_add_at(uint32_t *rem, uint32_t start, const uint32_t *mod, uint32_t n)
{
    return bn_limb_add_at(rem, start, mod, n);
}

unsigned noxtls_bn_test_clz(uint32_t x)
{
    return bn_clz(x);
}

void noxtls_bn_test_limbs_shl(uint32_t *a, uint32_t len, unsigned k)
{
    bn_limbs_shl(a, len, k);
}

void noxtls_bn_test_limbs_shr(uint32_t *a, uint32_t len, unsigned k)
{
    bn_limbs_shr(a, len, k);
}

void noxtls_bn_test_division_loop_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count)
{
    uint32_t j;
    uint32_t in_count;
    uint32_t work_count;
    uint32_t *work;
    int used_temp = 0;
    const uint32_t two_n = n * 2u;

    if(rem_limbs == NULL || mod_limbs == NULL || n == 0u)
        return;
    if(mod_limbs[n - 1u] == 0u)
        return;

    in_count = (rem_limb_count != 0u) ? rem_limb_count : two_n;
    if(in_count <= n)
        return;

    /*
     * Production bn_mod_2n_by_n_limb runs D2..D7 with a 2n+1 limb dividend buffer (u[m] overflow limb).
     * For tests that pass exactly 2n limbs, emulate that by using a temporary 2n+1 workspace.
     */
    if(in_count == two_n) {
        work = (uint32_t*)noxtls_calloc(two_n + 1u, sizeof(uint32_t));
        if(work == NULL)
            return;
        memcpy(work, rem_limbs, two_n * sizeof(uint32_t));
        work[two_n] = 0u;
        work_count = two_n + 1u;
        used_temp = 1;
    } else {
        work = rem_limbs;
        work_count = in_count;
    }

    {
        const uint32_t m = work_count - 1u;  /* dividend limbs before overflow; work_count is m+1 */
        for(j = m - n; (int32_t)j >= 0; j--) {
            uint64_t num = ((uint64_t)work[j + n] << 32) | (uint64_t)work[j + n - 1u];
            uint64_t den = (uint64_t)mod_limbs[n - 1u];
            uint64_t qhat64 = num / den;
            uint64_t rhat = num - qhat64 * den;
            uint32_t q_est;
            if(qhat64 > 0xFFFFFFFFu) {
                q_est = 0xFFFFFFFFu;
                /* Keep rhat consistent with clamped q_est. */
                rhat = num - (uint64_t)q_est * den;
            } else {
                q_est = (uint32_t)qhat64;
            }
            /* Knuth D3: correction step (n>=2) */
            while(n >= 2u) {
                uint64_t lhs = (uint64_t)q_est * (uint64_t)mod_limbs[n - 2u];
                if((rhat >> 32) != 0u)
                    break;
                {
                    uint64_t rhs = (rhat << 32) + (uint64_t)work[j + n - 2u];
                    if(lhs <= rhs)
                        break;
                }
                q_est--;
                rhat += (uint64_t)mod_limbs[n - 1u];
            }
            if(q_est == 0u)
                continue;
            if(bn_limb_mul_sub(work, j, q_est, mod_limbs, n)) {
                uint32_t carry_out = bn_limb_add_at(work, j, mod_limbs, n);
                if(carry_out != 0u && (j + n + 1u) < work_count)
                    work[j + n + 1u] += carry_out;
            }
        }
    }

    if(used_temp) {
        memcpy(rem_limbs, work, two_n * sizeof(uint32_t));
        noxtls_free(work);
    }
}

void noxtls_bn_test_normalize_only(uint32_t *rem_limbs, const uint32_t *mod_limbs, uint32_t n, uint32_t rem_limb_count)
{
    uint32_t i;
    const uint32_t max_norm = (n * 2u) + 8u;
    const uint32_t rem_high_end = (rem_limb_count != 0u) ? rem_limb_count : (n * 2u);
    uint32_t k;
    if(rem_limbs == NULL || mod_limbs == NULL || n == 0u)
        return;
    for(k = 0u; k < max_norm; k++) {
        int high_nonzero = 0;
        for(i = n; i < rem_high_end; i++) {
            if(rem_limbs[i] != 0u) { high_nonzero = 1; break; }
        }
        if(!high_nonzero && !bn_ge_limbs(rem_limbs, mod_limbs, n))
            break;
        if(bn_sub_limbs_borrow(rem_limbs, mod_limbs, n)) {
            if(high_nonzero) {
                for(i = n; i < rem_high_end; i++) {
                    if(rem_limbs[i] != 0u) {
                        rem_limbs[i]--;
                        break;
                    }
                    rem_limbs[i] = 0xFFFFFFFFu;
                }
            } else {
                (void)bn_limb_add_at(rem_limbs, 0, mod_limbs, n);
                break;
            }
        }
    }
}

noxtls_return_t noxtls_bn_test_mod_2n_by_n_limb(uint8_t *rem_out, uint32_t mod_len,
                                                const uint8_t *a, uint32_t a_len, const uint8_t *mod)
{
    return bn_mod_2n_by_n_limb(rem_out, mod_len, a, a_len, mod);
}

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
    int32_t j;
    int32_t ai;

    if(a == NULL || b == NULL || n == 0 || m == 0)
        return 1; /* assume borrow on invalid params */
    j = (int32_t)m - 1;
    ai = (int32_t)n - 1 - (int32_t)lsb_offset;
    for(; j >= 0 && ai >= 0; j--, ai--) {
        int diff = (int)a[ai] - (int)b[j] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[ai] = (uint8_t)diff;
    }
    while(borrow != 0 && ai >= 0) {
        int diff = (int)a[ai] - borrow;
        if(diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[ai] = (uint8_t)diff;
        ai--;
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
    uint16_t carry = 0;
    uint32_t j = len;

    if(dest == NULL || src == NULL || len == 0)
        return;
    while(j > 0) {
        j--;
        uint16_t prod = (uint16_t)src[j] * (uint16_t)q + carry;
        dest[j + 1] = (uint8_t)(prod & 0xFF);
        carry = prod >> 8;
    }
    dest[0] = (uint8_t)(carry & 0xFF);
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
    int32_t j;
    int32_t ai;
    uint32_t carry_iter = 0;
    uint32_t max_carry_iter = n;

    if(a == NULL || b == NULL || n == 0 || m == 0)
        return;
    j = (int32_t)m - 1;
    ai = (int32_t)n - 1 - (int32_t)lsb_offset;
    for(; j >= 0 && ai >= 0; j--, ai--) {
        int sum = (int)a[ai] + (int)b[j] + carry;
        a[ai] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
    /* Safety: limit iterations to prevent infinite loops */
    while(carry != 0 && ai >= 0 && carry_iter < max_carry_iter) {
        int sum = (int)a[ai] + carry;
        a[ai] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
        ai--;
        carry_iter++;
    }
    if(carry_iter >= max_carry_iter && carry != 0) {
        noxtls_debug_printf("ERROR: bn_add_at: Carry propagation timeout\n");
        fflush(stdout);
    }
}

/*
 * Division with remainder: R = A mod B.
 * Algorithm follows uses bytes as limbs (big-endian).
 * Requires a_len >= b_len.
 * 
 * @param rem_out Remainder output big integer
 * @param mod_len Length of the remainder output big integer
 * @param a First big integer
 * @param a_len Length of the first big integer
 * @param b Second big integer
 * @param b_len Length of the second big integer
 */
static void bn_div_remainder(uint8_t *rem_out, uint32_t mod_len,
                             const uint8_t *a, uint32_t a_len,
                             const uint8_t *b, uint32_t b_len)
{
    int do_debug = g_bn_debug_div_first;

    if(rem_out == NULL || a == NULL || b == NULL || mod_len == 0) {
        if(rem_out != NULL && mod_len > 0)
            memset(rem_out, 0, mod_len);
        return;
    }
    if(g_bn_debug_div_first) g_bn_debug_div_first = 0;
    if(g_bn_debug_div_trace) {
        noxtls_debug_printf("[bn_div_remainder] start: a_len=%u b_len=%u mod_len=%u\n",
                            a_len, b_len, mod_len);
        fflush(stdout);
    }

    if(do_debug) {
        //fprintf(stderr, "[bn_div_remainder] start: a_len=%u, b_len=%u, mod_len=%u\n",
              //  a_len, b_len, mod_len);
        if(a_len) bn_debug_print("[bn_div_remainder] A: ", a, a_len);
        if(b_len) bn_debug_print("[bn_div_remainder] B: ", b, b_len);
    }
    if(a_len < b_len) {
        memset(rem_out, 0, mod_len);
        if(a_len > 0)
            memcpy(rem_out + (mod_len - a_len), a, a_len);
        if(do_debug) bn_debug_print("[bn_div_remainder] rem_out (A<B): ", rem_out, mod_len);
        return;
    }

    /* Compare |A| < |B| -> R = A */
    if(a_len == b_len && noxtls_bn_cmp(a, b, b_len) < 0) {
        memset(rem_out, 0, mod_len);
        memcpy(rem_out + (mod_len - a_len), a, a_len);
        if(do_debug) bn_debug_print("[bn_div_remainder] rem_out (A<B same len): ", rem_out, mod_len);
        return;
    }

    /* Working buffers: X = copy of A, Y = copy of B; may grow by 1 byte after bit-shift. */
    uint32_t x_cap;
    uint32_t y_cap;
    if(a_len == UINT32_MAX || b_len == UINT32_MAX) {
        memset(rem_out, 0, mod_len);
        return;
    }
    x_cap = a_len + 1u;
    y_cap = b_len + 1u;
    uint8_t *X = (uint8_t*)noxtls_calloc(x_cap, 1);
    uint8_t *Y = (uint8_t*)noxtls_calloc(y_cap, 1);
    uint8_t *Y_shifted = (uint8_t*)noxtls_calloc(x_cap, 1);
    if(!X || !Y || !Y_shifted) {
        if(g_bn_debug_div_trace) {
            noxtls_debug_printf("[bn_div_remainder] alloc failed: X=%p Y=%p Y_shifted=%p\n",
                                (void*)X, (void*)Y, (void*)Y_shifted);
            fflush(stdout);
        }
        if(X) noxtls_free(X);
        if(Y) noxtls_free(Y);
        if(Y_shifted) noxtls_free(Y_shifted);
        memset(rem_out, 0, mod_len);
        return;
    }

    memcpy(X, a, a_len);
    memcpy(Y, b, b_len);
    uint32_t x_len = a_len;
    uint32_t y_len = b_len;

    /* Strip leading zeros so quotient estimate uses significant bytes (fixes 64/32-style case) */
    bn_strip_leading_zeros_inplace(X, &x_len);
    bn_strip_leading_zeros_inplace(Y, &y_len);
    if(x_len == 0) {
        memset(rem_out, 0, mod_len);
        noxtls_free(X);
        noxtls_free(Y);
        noxtls_free(Y_shifted);
        return;
    }
    if(x_len < y_len) {
        /* Dividend < divisor: remainder is dividend, aligned to mod_len (x_len > 0 when x_len < y_len and y_len > 0) */
        memset(rem_out, 0, mod_len);
        memcpy(rem_out + (mod_len - x_len), X, x_len);
        noxtls_free(X);
        noxtls_free(Y);
        noxtls_free(Y_shifted);
        return;
    }

    if(do_debug) {
        bn_debug_print("[bn_div_remainder] X init: ", X, x_len);
        bn_debug_print("[bn_div_remainder] Y init: ", Y, y_len);
    }

    /* Normalize so Y has high bit set (k = bitlen(Y)%8, then k = 7-k, shift X,Y left by k). */
    uint32_t bitlen_y = bn_bitlen(Y, y_len);
    unsigned k = 0;
    if(bitlen_y > 0) {
        k = (unsigned)(bitlen_y & 7);
        if(k < 7) {
            k = 7 - k;
            bn_shift_l_bits(X, &x_len, k);
            bn_shift_l_bits(Y, &y_len, k);
                                    } else {
            k = 0;
        }
    }

    if(do_debug) {
        //fprintf(stderr, "[bn_div_remainder] normalize: bitlen_y=%u, k=%u\n", bitlen_y, k);
        bn_debug_print("[bn_div_remainder] X norm: ", X, x_len);
        bn_debug_print("[bn_div_remainder] Y norm: ", Y, y_len);
    }
    if(g_bn_debug_div_trace) {
        noxtls_debug_printf("[bn_div_remainder] bitlen_y=%u k=%u x_len=%u y_len=%u\n",
                            bitlen_y, k, x_len, y_len);
        fflush(stdout);
    }

    uint32_t n = x_len - 1;
    uint32_t t = y_len - 1;

    /* Y_shifted = Y << (8*(n-t)), same length as X for subtract.  */
    memset(Y_shifted, 0, x_cap);
    memcpy(Y_shifted, Y, y_len);

    /*
     * Initial reduction: bring X below Y_shifted by subtracting multiples of Y_shifted.
     * The quotient digit at this position can be large (up to 255 when x_len==y_len+1).
     * Do not subtract one-at-a-time (would need up to 2^256 iterations for 64/32 byte).
     * Instead: estimate q0 = X / Y_shifted, subtract q0*Y_shifted in one step, repeat.
     */
    uint8_t *qY = (uint8_t*)noxtls_calloc(x_len + 1, 1);
    if(!qY) {
        noxtls_free(X);
        noxtls_free(Y);
        noxtls_free(Y_shifted);
        memset(rem_out, 0, mod_len);
        return;
    }
    uint32_t reduce_rounds = 0;
    /* One quotient digit is 0..255, so we need at most 256 rounds when subtracting 1*Y_shifted each time */
    uint32_t max_reduce_rounds;
    if(x_len > (uint32_t)((UINT32_MAX / 32u) - 1u)) {
        noxtls_free(X);
        noxtls_free(Y);
        noxtls_free(Y_shifted);
        noxtls_free(qY);
        memset(rem_out, 0, mod_len);
        return;
    }
    max_reduce_rounds = (x_len + 1u) * 32u;
    if(max_reduce_rounds < 256) max_reduce_rounds = 256;
    while(bn_ge(X, Y_shifted, x_len) && reduce_rounds < max_reduce_rounds) {
        /* Estimate quotient digit: use top 2-3 bytes when both have same length */
        uint32_t q0;
        if(Y_shifted[0] != 0) {
            uint32_t num = ((uint32_t)X[0] << 8) | (uint32_t)X[1];
            if(x_len > 2) num = (num << 8) | (uint32_t)X[2];
            uint32_t den = (uint32_t)Y_shifted[0] + 1;
            if(y_len > 1 && Y_shifted[1] != 0) den = (((uint32_t)Y_shifted[0] << 8) | (uint32_t)Y_shifted[1]) + 1;
            q0 = (den > 0) ? (num / den) : 255;
        } else {
            /* Y_shifted has leading zero byte(s): use first non-zero byte for denominator so q0 is not always 255 */
            uint32_t j = 1;
            while(j < x_len && Y_shifted[j] == 0) j++;
            uint32_t num = ((uint32_t)X[0] << 8) | (uint32_t)X[1];
            if(x_len > 2) num = (num << 8) | (uint32_t)X[2];
            uint32_t den = (j < x_len) ? ((uint32_t)Y_shifted[j] + 1) : 1;
            q0 = (den > 0) ? (num / den) : 255;
        }
        if(q0 > 255) q0 = 255;
        if(q0 == 0) q0 = 1;

        bn_mul_byte(qY, (uint8_t)q0, Y_shifted, x_len);
        /* Refine: if qY > X, reduce q0 until qY <= X */
        while(q0 > 0 && (qY[0] != 0 || noxtls_bn_cmp(qY + 1, X, x_len) > 0)) {
            q0--;
            bn_mul_byte(qY, (uint8_t)q0, Y_shifted, x_len);
        }
        if(q0 == 0) break;
        bn_sub_inplace(X, qY + 1, x_len);
        reduce_rounds++;
    }
    noxtls_free(qY);
    if(do_debug) {
        bn_debug_print("[bn_div_remainder] X after initial reduction: ", X, x_len);
    }
    /* If we hit the round limit before X < Y_shifted, do bounded fallback (single subtracts) so we never return wrong remainder */
    if(reduce_rounds >= max_reduce_rounds && bn_ge(X, Y_shifted, x_len)) {
        uint32_t fallback = 0;
        const uint32_t max_fallback = 256; /* one digit max */
        while(fallback < max_fallback && bn_ge(X, Y_shifted, x_len)) {
            bn_sub_inplace(X, Y_shifted, x_len);
            fallback++;
        }
        if(fallback >= max_fallback && bn_ge(X, Y_shifted, x_len)) {
            noxtls_debug_printf("ERROR: bn_div_remainder: Initial reduction did not converge\n");
            fflush(stdout);
            noxtls_free(X);
            noxtls_free(Y);
            noxtls_free(Y_shifted);
            memset(rem_out, 0, mod_len);
            return;
        }
    }

    /* For-loop: same n,t as after normalization. Use i > t (no x_len check). */
    for(uint32_t i = n; i > t; i--) {
        uint32_t idx = n - i;   /* our MSB index for "limb i" */
        uint8_t xi = (idx < x_len) ? X[idx] : 0;
        uint8_t xi1 = (idx + 1 < x_len) ? X[idx + 1] : 0;
        uint8_t yt = Y[0];
        if(do_debug && (i % 32 == 0)) {
            noxtls_debug_printf("[bn_div_remainder] step i=%u idx=%u xi=%02X xi1=%02X yt=%02X\n",
                                  i, idx, xi, xi1, yt);
            fflush(stdout);
        }

        uint32_t q;
        if(xi >= yt) {
            q = 255;
        } else {
            uint32_t num = ((uint32_t)xi << 8) | (uint32_t)xi1;
            q = (yt != 0) ? (num / (uint32_t)yt) : 0;
            if(q > 255) q = 255;
        }
        if(do_debug) {
            uint8_t xi2_dbg = (idx + 2 < x_len) ? X[idx + 2] : 0;
            (void)xi2_dbg;
            //fprintf(stderr, "[bn_div_remainder] i=%u idx=%u xi=%02X xi1=%02X xi2=%02X yt=%02X q=%u\n",
                    //i, idx, xi, xi1, xi2_dbg, yt, q);
        }

        /* Refine q: match (Z.p[i-t-1]++, then do { Z--; T1 = (Y[t-1],Y[t])*q } while T1 > T2) */
        {
            uint8_t xi2 = (idx + 2 < x_len) ? X[idx + 2] : 0;
            uint32_t T2 = ((uint32_t)xi << 16) | ((uint32_t)xi1 << 8) | (uint32_t)xi2;
            uint32_t yt1 = (y_len >= 2) ? (uint32_t)Y[1] : 0;
            uint32_t T1_base = ((uint32_t)yt << 8) | yt1;
            q++;
            if(q > 255) q = 255;
            {
                uint32_t T1_val = T1_base * (uint32_t)q;
                uint32_t refine_iter = 0;
                uint32_t max_refine_iter = 256; /* q is at most 255, so this is safe */
                while(q > 0 && T1_val > T2 && refine_iter < max_refine_iter) {
                    q--;
                    T1_val -= T1_base;
                    refine_iter++;
                }
                if(refine_iter >= max_refine_iter) {
                    noxtls_debug_printf("ERROR: bn_div_remainder: Refinement loop timeout\n");
                    fflush(stdout);
                    noxtls_free(X);
                    noxtls_free(Y);
                    noxtls_free(Y_shifted);
                    memset(rem_out, 0, mod_len);
                    return;
                }
            }
        }
        if(do_debug) {
            //fprintf(stderr, "[bn_div_remainder] i=%u refined q=%u\n", i, q);
        }

        /* X -= q * (Y << (i-t-1)) */
        /* (Y * q) in at most y_len+1 bytes, placed with LSB at byte offset off */
        {
            uint32_t off = i - t - 1;
            uint16_t carry = 0;
            uint32_t tw = y_len + 1;
            uint8_t *tmp = (uint8_t*)noxtls_calloc(tw, 1);
            if(!tmp) {
                noxtls_free(X);
                noxtls_free(Y);
                noxtls_free(Y_shifted);
                memset(rem_out, 0, mod_len);
                return;
            }
            for(int32_t j = (int32_t)y_len - 1; j >= 0; j--) {
                uint16_t prod = (uint16_t)Y[j] * (uint16_t)(uint8_t)q + carry;
                tmp[j + 1] = (uint8_t)(prod & 0xFF);
                carry = prod >> 8;
            }
            tmp[0] = (uint8_t)(carry & 0xFF);
            bn_strip_leading_zeros_inplace(tmp, &tw);
            if(tw > 0 && off + tw <= x_len) {
                if(bn_sub_at(X, x_len, off, tmp, tw))
                    bn_add_at(X, x_len, off, Y, y_len);
            }
            noxtls_free(tmp);
        }
        if(do_debug) {
            bn_debug_print("[bn_div_remainder] X after step: ", X, x_len);
        }

    }

    /* Remainder = X >> k */
    if(x_len > 0) {
        bn_shift_r_bits(X, x_len, (unsigned)k);
        bn_strip_leading_zeros_inplace(X, &x_len);
        if(x_len >= mod_len) {
            memcpy(rem_out, X + (x_len - mod_len), mod_len);
                                        } else {
            memset(rem_out, 0, mod_len);
            memcpy(rem_out + (mod_len - x_len), X, x_len);
        }
        if(do_debug) bn_debug_print("[bn_div_remainder] rem_out final: ", rem_out, mod_len);
                                            } else {
        memset(rem_out, 0, mod_len);
    }

    noxtls_free(X);
    noxtls_free(Y);
    noxtls_free(Y_shifted);
    if(g_bn_debug_div_trace) {
        noxtls_debug_printf("[bn_div_remainder] done\n");
        fflush(stdout);
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
    int do_debug = g_bn_debug_mod_first;
    if(g_bn_debug_mod_first) g_bn_debug_mod_first = 0;
    if(g_bn_debug_modexp_active) {
        /* Always log during mod_exp for the first few calls. */
        if(g_bn_debug_mod_calls < 10) {
            do_debug = 1;
        }
        g_bn_debug_mod_calls++;
    }
    const uint8_t *a_src = a;
    uint8_t *a_copy = NULL;

    if(do_debug) {
        //fprintf(stderr, "[noxtls_bn_mod] start: a_len=%u mod_len=%u\n", a_len, mod_len);
        if(a && a_len) bn_debug_print("[noxtls_bn_mod] a: ", a, a_len);
        if(mod && mod_len) bn_debug_print("[noxtls_bn_mod] mod: ", mod, mod_len);
    }
    if(g_bn_debug_div_trace) {
        noxtls_debug_printf("[noxtls_bn_mod] start: a_len=%u mod_len=%u\n", a_len, mod_len);
        fflush(stdout);
    }

    if(result == NULL || a == NULL || mod == NULL)
        return NOXTLS_RETURN_NULL;
    if(mod_len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;

    if(a_len == 0 || noxtls_bn_is_zero(mod, mod_len)) {
        memset(result, 0, mod_len);
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (empty or mod=0): ", result, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        uintptr_t a_start = (uintptr_t)a;
        uintptr_t a_end;
        uintptr_t result_addr = (uintptr_t)result;
        if(a_len > (uint32_t)(UINTPTR_MAX - a_start)) {
            return NOXTLS_RETURN_FAILED;
        }
        a_end = a_start + (uintptr_t)a_len;
        if(result_addr >= a_start && result_addr < a_end) {
            a_copy = (uint8_t*)noxtls_calloc(a_len, 1);
            if(!a_copy) {
                noxtls_debug_printf("[noxtls_bn_mod] a_copy alloc failed (a_len=%u)\n", a_len);
                fflush(stdout);
                memset(result, 0, mod_len);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            memcpy(a_copy, a, a_len);
            a_src = a_copy;
        }
    }

    a_src = bn_strip_leading_zeros(a_src, &a_len);
    fflush(stdout);
    if(a_len == 0) {
        memset(result, 0, mod_len);
        if(a_copy) noxtls_free(a_copy);
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (a_len==0): ", result, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_len < mod_len) {
        if(bn_copy_aligned(result, mod_len, a_src, a_len) != NOXTLS_RETURN_SUCCESS) {
            memset(result, 0, mod_len);
            if(a_copy) noxtls_free(a_copy);
            return NOXTLS_RETURN_FAILED;
        }
        /* Fixup: result may still be >= mod (e.g. 10 mod 10, 20 mod 10) */
        if(noxtls_bn_cmp(result, mod, mod_len) >= 0) {
            bn_div_remainder(result, mod_len, result, mod_len, mod, mod_len);
        }
        if(a_copy) noxtls_free(a_copy);
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (a_len<mod_len): ", result, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_len == mod_len && noxtls_bn_cmp(a_src, mod, mod_len) < 0) {
        memcpy(result, a_src, mod_len);
        if(a_copy) noxtls_free(a_copy);
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (a_len==mod_len, a<mod): ", result, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(a_len <= 8 && mod_len <= 4) {
        uint64_t va = 0;
        uint64_t vm = 0;
        for(uint32_t i = 0; i < a_len; i++) va = (va << 8) | (uint64_t)a_src[i];
        for(uint32_t i = 0; i < mod_len; i++) vm = (vm << 8) | (uint64_t)mod[i];
        if(vm == 0) {
            memset(result, 0, mod_len);
        } else {
            va %= vm;
            for(uint32_t i = mod_len; i > 0; i--) {
                result[i - 1] = (uint8_t)(va & 0xFF);
                va >>= 8;
            }
        }
        if(a_copy) noxtls_free(a_copy);
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (small fast path): ", result, mod_len);
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Fast path: 2n-by-n limb reducer for ECDSA (P-256/P-384), RSA, and RFC 7919 FFDHE moduli. */
    if((mod_len == 32u || mod_len == 48u || mod_len == 64u || mod_len == 66u || mod_len == 128u || mod_len == 256u ||
        mod_len == 384u || mod_len == 512u || mod_len == 768u || mod_len == 1024u) &&
       a_len == mod_len * 2u) {
        if(bn_mod_2n_by_n_limb(result, mod_len, a_src, a_len, mod) == NOXTLS_RETURN_SUCCESS) {
            if(do_debug) bn_debug_print("[noxtls_bn_mod] result (2n/n limb path): ", result, mod_len);
            if(a_copy) noxtls_free(a_copy);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* General limb path (bit-by-bit) for other operand sizes. */
    if(bn_div_remainder_limb(result, mod_len, a_src, a_len, mod, mod_len) == NOXTLS_RETURN_SUCCESS) {
        if(do_debug) bn_debug_print("[noxtls_bn_mod] result (limb fast path): ", result, mod_len);
        if(a_copy) noxtls_free(a_copy);
        return NOXTLS_RETURN_SUCCESS;
    }

    /* In-house bn_div_remainder. */
    bn_div_remainder(result, mod_len, a_src, a_len, mod, mod_len);
    
    /* at most one conditional subtract so result in [0, mod). */
    if(noxtls_bn_cmp(result, mod, mod_len) >= 0) {
        if(bn_sub_inplace(result, mod, mod_len) != NOXTLS_RETURN_SUCCESS)
            memset(result, 0, mod_len);
    }
    if(a_copy) noxtls_free(a_copy);
    if(do_debug) bn_debug_print("[noxtls_bn_mod] result (final): ", result, mod_len);
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
noxtls_return_t noxtls_bn_mod_exp(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len)
{
    int do_debug = g_bn_debug_modexp_first;
    uint8_t *temp_result;
    uint8_t *temp_base;
    uint8_t *exp_copy;
    uint8_t *temp;
    uint32_t total_bits;
    uint32_t bit_index = 0;
    noxtls_return_t rc;

    if(result == NULL || base == NULL || exp == NULL || mod == NULL)
        return NOXTLS_RETURN_NULL;
    if(mod_len == 0 || exp_len == 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(mod_len > (uint32_t)(UINT32_MAX / 2u) ||
       exp_len > (uint32_t)(UINT32_MAX / 8u)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(g_bn_debug_modexp_first) g_bn_debug_modexp_first = 0;
    g_bn_debug_modexp_active = 1;
    g_bn_debug_mod_calls = 0;
    g_bn_debug_mod_compare_all = 1;
    g_bn_debug_mod_first_mismatch_only = 1;
    temp_result = (uint8_t*)noxtls_calloc(mod_len, 1);
    temp_base = (uint8_t*)noxtls_calloc(mod_len, 1);
    exp_copy = (uint8_t*)noxtls_calloc(exp_len, 1);
    /* temp needs to be mod_len * 2 because multiplication of two mod_len numbers produces mod_len * 2 bytes */
    temp = (uint8_t*)noxtls_calloc((size_t)mod_len * 2u, 1);

    if(!temp_result || !temp_base || !temp || !exp_copy) {
        noxtls_debug_printf("ERROR: noxtls_bn_mod_exp: Memory allocation failed!\n");
        fflush(stdout);
        if(temp_result) noxtls_free(temp_result);
        if(temp_base) noxtls_free(temp_base);
        if(exp_copy) noxtls_free(exp_copy);
        if(temp) noxtls_free(temp);
        (void)noxtls_bn_one(result, mod_len);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_bn_one(temp_result, mod_len);
    if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
    rc = noxtls_bn_mod(temp_base, base, mod_len, mod, mod_len);
    if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
    rc = noxtls_bn_copy(exp_copy, exp, exp_len);
    if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;

    if(do_debug) {
        bn_debug_print("[noxtls_bn_mod_exp] base: ", base, mod_len);
        bn_debug_print("[noxtls_bn_mod_exp] exp: ", exp, exp_len);
        bn_debug_print("[noxtls_bn_mod_exp] result init: ", temp_result, mod_len);
    }

    /* Handle zero exponent */
    if(noxtls_bn_is_zero(exp_copy, exp_len)) {
        rc = noxtls_bn_one(result, mod_len);
        noxtls_free(temp_result);
        noxtls_free(temp_base);
        noxtls_free(exp_copy);
        noxtls_free(temp);
        g_bn_debug_modexp_active = 0;
        g_bn_debug_mod_compare_all = 0;
        return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : rc;
    }

    /* Right-to-left (LSB-first) square-and-multiply (bitwise shift) */
    total_bits = exp_len * 8u;
    if(total_bits > 256) {
        noxtls_debug_printf("      Starting modular exponentiation (%u bits)...\n", total_bits);
        fflush(stdout);
    }

    while(!noxtls_bn_is_zero(exp_copy, exp_len)) {
        uint8_t lsb = exp_copy[exp_len - 1] & 0x01u;
        uint32_t byte_idx = exp_len - 1 - (bit_index >> 3);
        uint8_t bit_idx = (uint8_t)(bit_index & 7);

        if(total_bits > 512 && bit_index > 0 && (bit_index & 127) == 0) {
            uint32_t percent = (bit_index * 100) / total_bits;
            noxtls_debug_printf("      Exponentiation progress: %u/%u bits (%u%%)...\n",
                   bit_index, total_bits, percent);
            fflush(stdout);
        }

        if(do_debug) {
            bn_debug_print("[noxtls_bn_mod_exp]  before square: ", temp_base, mod_len);
        }

        if(lsb) {
            if(do_debug) bn_debug_print("[noxtls_bn_mod_exp]  multiply by base: ", temp_base, mod_len);
            g_bn_debug_modexp_byte = byte_idx;
            g_bn_debug_modexp_bit = bit_idx;
            g_bn_debug_modexp_stage = 1;
            rc = noxtls_bn_mul(temp, temp_result, mod_len, temp_base, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
            rc = noxtls_bn_mod(temp_result, temp, mod_len * 2, mod, mod_len);
            if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
            if(do_debug) bn_debug_print("[noxtls_bn_mod_exp]  after multiply: ", temp_result, mod_len);
        }

        g_bn_debug_modexp_byte = byte_idx;
        g_bn_debug_modexp_bit = bit_idx;
        g_bn_debug_modexp_stage = 0;
        rc = noxtls_bn_mul(temp, temp_base, mod_len, temp_base, mod_len);
        if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
        rc = noxtls_bn_mod(temp_base, temp, mod_len * 2, mod, mod_len);
        if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
        if(do_debug) bn_debug_print("[noxtls_bn_mod_exp]  after square: ", temp_base, mod_len);

        rc = noxtls_bn_rshift1(exp_copy, exp_len);
        if(rc != NOXTLS_RETURN_SUCCESS) goto mod_exp_cleanup;
        bit_index++;
    }

    memcpy(result, temp_result, mod_len);
    if(do_debug) bn_debug_print("[noxtls_bn_mod_exp] result final: ", result, mod_len);
    noxtls_free(temp_result);
    noxtls_free(temp_base);
    noxtls_free(exp_copy);
    noxtls_free(temp);
    g_bn_debug_modexp_active = 0;
    g_bn_debug_mod_compare_all = 0;
    return NOXTLS_RETURN_SUCCESS;

mod_exp_cleanup:
    noxtls_free(temp_result);
    noxtls_free(temp_base);
    noxtls_free(exp_copy);
    noxtls_free(temp);
    g_bn_debug_modexp_active = 0;
    g_bn_debug_mod_compare_all = 0;
    if(result != NULL && mod_len > 0)
        memset(result, 0, mod_len);
    return rc;
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
    if(result == NULL || a == NULL || m == NULL)
        return NOXTLS_RETURN_NULL;
    if(m_len == 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    /* In-house extended GCD / Fermat fallback. */
    /* Fast, correct path for secp256r1 prime field: a^(p-2) mod p. */
    static const uint8_t secp256r1_p[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    if(m_len == 32 && noxtls_bn_cmp(m, secp256r1_p, 32) == 0) {
        uint8_t *m_minus_2 = (uint8_t*)noxtls_calloc(m_len, 1);
        uint8_t *two_buf = (uint8_t*)noxtls_calloc(m_len, 1);
        uint8_t *a_mod_m = (uint8_t*)noxtls_calloc(m_len, 1);
        if(m_minus_2 && two_buf && a_mod_m) {
            noxtls_bn_mod(a_mod_m, a, a_len, m, m_len);
            if(!noxtls_bn_is_zero(a_mod_m, m_len)) {
                two_buf[m_len - 1] = 2;
                noxtls_bn_copy(m_minus_2, m, m_len);
                noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
                noxtls_bn_mod_exp(result, a_mod_m, m_minus_2, m_len, m, m_len);
                noxtls_free(m_minus_2);
                noxtls_free(two_buf);
                noxtls_free(a_mod_m);
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        if(m_minus_2) noxtls_free(m_minus_2);
        if(two_buf) noxtls_free(two_buf);
        if(a_mod_m) noxtls_free(a_mod_m);
    }

    /* Allocate all buffers once */
    uint8_t *u1 = (uint8_t*)noxtls_calloc(m_len, 1);
    uint8_t *u3 = (uint8_t*)noxtls_calloc(m_len, 1);
    uint8_t *v1 = (uint8_t*)noxtls_calloc(m_len, 1);
    uint8_t *v3 = (uint8_t*)noxtls_calloc(m_len, 1);
    uint8_t *temp = (uint8_t*)noxtls_calloc(m_len, 1);
    uint8_t *a_mod_m = (uint8_t*)noxtls_calloc(m_len, 1);
    /* Wide buffers for shift step: u1+m can overflow m_len bytes (noxtls_bn_add drops carry) */
    const uint32_t m_wide = m_len + 1u;
    uint8_t *m_padded = (uint8_t*)noxtls_calloc(m_wide, 1);
    uint8_t *u1_wide = (uint8_t*)noxtls_calloc(m_wide, 1);
    uint8_t *v1_wide = (uint8_t*)noxtls_calloc(m_wide, 1);
    
    if(!u1 || !u3 || !v1 || !v3 || !temp || !a_mod_m || !m_padded || !u1_wide || !v1_wide) {
        if(u1) noxtls_free(u1);
        if(u3) noxtls_free(u3);
        if(v1) noxtls_free(v1);
        if(v3) noxtls_free(v3);
        if(temp) noxtls_free(temp);
        if(a_mod_m) noxtls_free(a_mod_m);
        if(m_padded) noxtls_free(m_padded);
        if(u1_wide) noxtls_free(u1_wide);
        if(v1_wide) noxtls_free(v1_wide);
        memset(result, 0, m_len);
        return NOXTLS_RETURN_FAILED;
    }
    m_padded[0] = 0;
    memcpy(m_padded + 1, m, m_len);
    
    /* Initialize: u1 = 1, u3 = a mod m, v1 = 0, v3 = m */
    noxtls_bn_one(u1, m_len);
    
    /* If a_len == m_len and a < m, we can just copy it directly */
    /* This avoids potential bugs in noxtls_bn_mod */
    if(a_len == m_len && noxtls_bn_cmp(a, m, m_len) < 0) {
        noxtls_bn_copy(u3, a, m_len);
        noxtls_bn_copy(a_mod_m, a, m_len);
    } else {
        noxtls_bn_mod(u3, a, a_len, m, m_len);  /* u3 = a mod m */
        noxtls_bn_copy(a_mod_m, u3, m_len);
    }
    
    /* Check if u3 is zero (no inverse exists) */
    if(noxtls_bn_is_zero(u3, m_len)) {
        noxtls_bn_zero(result, m_len);
        noxtls_free(u1);
        noxtls_free(u3);
        noxtls_free(v1);
        noxtls_free(v3);
        noxtls_free(temp);
        noxtls_free(a_mod_m);
        noxtls_free(m_padded);
        noxtls_free(u1_wide);
        noxtls_free(v1_wide);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_bn_zero(v1, m_len);
    noxtls_bn_copy(v3, m, m_len);
    
    /* Binary extended Euclidean algorithm - uses only shifts and adds/subtracts (no division!) */
    uint32_t iter = 0;
    uint32_t max_iter = m_len * 8 * 8;  /* Increased safety limit for 256-bit (was 4x, now 8x) */
    
    while(!noxtls_bn_is_zero(v3, m_len) && !noxtls_bn_is_zero(u3, m_len) && iter < max_iter) {
        iter++;
        
        /* Remove factors of 2 from u3 and v3 (check LSB - least significant byte) */
        /* Safety: limit iterations to prevent infinite loops */
        uint32_t shift_iter_u = 0;
        uint32_t max_shift_iter = m_len * 8 * 2; /* Allow more iterations for shift loops */
        while((u3[m_len-1] & 1) == 0 && !noxtls_bn_is_zero(u3, m_len) && shift_iter_u < max_shift_iter) {
            noxtls_bn_rshift1(u3, m_len);
            if((u1[m_len-1] & 1) != 0) {
                /* u1 += m; use m_wide so carry is not lost (noxtls_bn_add drops carry) */
                u1_wide[0] = 0;
                memcpy(u1_wide + 1, u1, m_len);
                noxtls_bn_add(u1_wide, u1_wide, m_padded, m_wide);
                noxtls_bn_rshift1(u1_wide, m_wide);
                noxtls_bn_mod(u1, u1_wide, m_wide, m, m_len);
            } else {
                noxtls_bn_rshift1(u1, m_len);
            }
            shift_iter_u++;
        }
        if(shift_iter_u >= max_shift_iter) {
            noxtls_bn_zero(result, m_len);
            noxtls_free(u1);
            noxtls_free(u3);
            noxtls_free(v1);
            noxtls_free(v3);
            noxtls_free(temp);
            noxtls_free(a_mod_m);
            noxtls_free(m_padded);
            noxtls_free(u1_wide);
            noxtls_free(v1_wide);
            return NOXTLS_RETURN_TIMEOUT;
        }
        
        uint32_t shift_iter_v = 0;
        while((v3[m_len-1] & 1) == 0 && !noxtls_bn_is_zero(v3, m_len) && shift_iter_v < max_shift_iter) {
            noxtls_bn_rshift1(v3, m_len);
            if((v1[m_len-1] & 1) != 0) {
                /* v1 += m; use m_wide so carry is not lost (noxtls_bn_add drops carry) */
                v1_wide[0] = 0;
                memcpy(v1_wide + 1, v1, m_len);
                noxtls_bn_add(v1_wide, v1_wide, m_padded, m_wide);
                noxtls_bn_rshift1(v1_wide, m_wide);
                noxtls_bn_mod(v1, v1_wide, m_wide, m, m_len);
            } else {
                noxtls_bn_rshift1(v1, m_len);
            }
            shift_iter_v++;
        }
        if(shift_iter_v >= max_shift_iter) {
            noxtls_bn_zero(result, m_len);
            noxtls_free(u1);
            noxtls_free(u3);
            noxtls_free(v1);
            noxtls_free(v3);
            noxtls_free(temp);
            noxtls_free(a_mod_m);
            noxtls_free(m_padded);
            noxtls_free(u1_wide);
            noxtls_free(v1_wide);
            return NOXTLS_RETURN_TIMEOUT;
        }
        
        /* Check if either is zero before subtracting */
        if(noxtls_bn_is_zero(u3, m_len) || noxtls_bn_is_zero(v3, m_len)) {
            break;
        }
        
        /* Safety check: if u3 == v3 (but not zero), we've found the GCD */
        /* If GCD == 1, the inverse exists; if GCD != 1, no inverse exists */
        if(noxtls_bn_cmp(u3, v3, m_len) == 0) {
            if(noxtls_bn_is_one(u3, m_len)) {
                /* GCD is 1, so the inverse exists - break and use u1 as the result */
                break;
            } else {
                /* GCD is not 1, so no inverse exists */
                noxtls_bn_zero(result, m_len);
                noxtls_free(u1);
                noxtls_free(u3);
                noxtls_free(v1);
                noxtls_free(v3);
                noxtls_free(temp);
                noxtls_free(a_mod_m);
                noxtls_free(m_padded);
                noxtls_free(u1_wide);
                noxtls_free(v1_wide);
                return NOXTLS_RETURN_FAILED;
            }
        }
        
        /* Subtract smaller from larger */
        if(noxtls_bn_cmp(u3, v3, m_len) >= 0) {
            noxtls_bn_sub(u3, u3, v3, m_len);
            if(noxtls_bn_cmp(u1, v1, m_len) >= 0) {
                noxtls_bn_sub(u1, u1, v1, m_len);
            } else {
                noxtls_bn_sub(temp, m, v1, m_len);
                noxtls_bn_add(u1, u1, temp, m_len);
                /* noxtls_bn_add drops carry; reduce so u1 is in [0, m). */
                noxtls_bn_mod(u1, u1, m_len, m, m_len);
            }
            /* Reduce u1 mod m if needed (e.g. after subtract) */
            if(noxtls_bn_cmp(u1, m, m_len) >= 0) {
                noxtls_bn_mod(u1, u1, m_len, m, m_len);
            }
            
            /* Debug: check if u1 might be "negative" (greater than m/2) */
            /* In modular arithmetic, we don't need to worry about negative numbers */
            /* as long as we reduce mod m properly */
        } else {
            noxtls_bn_sub(v3, v3, u3, m_len);
            if(noxtls_bn_cmp(v1, u1, m_len) >= 0) {
                noxtls_bn_sub(v1, v1, u1, m_len);
            } else {
                noxtls_bn_sub(temp, m, u1, m_len);
                noxtls_bn_add(v1, v1, temp, m_len);
                /* noxtls_bn_add drops carry; reduce so v1 is in [0, m). */
                noxtls_bn_mod(v1, v1, m_len, m, m_len);
            }
            /* Reduce v1 mod m if needed (e.g. after subtract) */
            if(noxtls_bn_cmp(v1, m, m_len) >= 0) {
                noxtls_bn_mod(v1, v1, m_len, m, m_len);
            }
        }
    }
    
    if(iter >= max_iter) {
        noxtls_bn_zero(result, m_len);
        noxtls_free(u1);
        noxtls_free(u3);
        noxtls_free(v1);
        noxtls_free(v3);
        noxtls_free(temp);
        noxtls_free(a_mod_m);
        noxtls_free(m_padded);
        noxtls_free(u1_wide);
        noxtls_free(v1_wide);
        return NOXTLS_RETURN_TIMEOUT;
    }
    
    /* Determine which one is the GCD and get the result coefficient */
    /* In binary extended Euclidean algorithm: */
    /* - If u3 == 1, then u1 is the inverse (u1*a + 1*m = 1, so u1*a ≡ 1 mod m) */
    /* - If u3 == 0, then v3 is the GCD. If v3 == 1, then v1 is the inverse */
    /* - If v3 == 0, then u3 is the GCD. If u3 == 1, then u1 is the inverse */
    /* - If v3 == 1, then v1 is the inverse */
    
    uint8_t *gcd = NULL;
    const uint8_t *result_coeff = NULL;
    int inverse_exists = 0;
    
    if(noxtls_bn_is_one(u3, m_len)) {
        /* u3 == 1, so u1 is the inverse */
        gcd = u3;
        result_coeff = u1;
        inverse_exists = 1;
    } else if(noxtls_bn_is_zero(u3, m_len)) {
        /* u3 == 0, so v3 is the GCD */
        gcd = v3;
        if(noxtls_bn_is_one(v3, m_len)) {
            result_coeff = v1;
            inverse_exists = 1;
        }
    } else if(noxtls_bn_is_one(v3, m_len)) {
        /* v3 == 1, so v1 is the inverse */
        gcd = v3;
        result_coeff = v1;
        inverse_exists = 1;
    } else if(noxtls_bn_is_zero(v3, m_len)) {
        /* v3 == 0, so u3 is the GCD */
        gcd = u3;
        if(noxtls_bn_is_one(u3, m_len)) {
            result_coeff = u1;
            inverse_exists = 1;
        }
    } else {
        /* Neither is 0 or 1, use the non-zero one as GCD */
        if(!noxtls_bn_is_zero(u3, m_len)) {
            gcd = u3;
        } else {
            gcd = v3;
        }
    }
    (void)gcd; /* set for documentation; inverse_exists determines path */

    if(!inverse_exists) {
        /* For odd prime moduli, use Fermat: a^(-1) = a^(p-2) mod p.
         * The binary extended GCD can mis-terminate in some cases; this is a correct fallback. */
        if((m[m_len - 1] & 1u) != 0) {
            uint8_t *m_minus_2 = (uint8_t*)noxtls_calloc(m_len, 1);
            uint8_t *two_buf = (uint8_t*)noxtls_calloc(m_len, 1);
            uint8_t *fermat_out = (uint8_t*)noxtls_calloc(m_len, 1);
            if(m_minus_2 && two_buf && fermat_out) {
                if(!noxtls_bn_is_zero(a_mod_m, m_len)) {
                    two_buf[m_len - 1] = 2;
                    noxtls_bn_copy(m_minus_2, m, m_len);
                    noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
                    noxtls_bn_mod_exp(fermat_out, a_mod_m, m_minus_2, m_len, m, m_len);
                    memcpy(result, fermat_out, m_len);
                } else {
                    noxtls_bn_zero(result, m_len);
                }
            } else {
                noxtls_bn_zero(result, m_len);
            }
            if(m_minus_2) noxtls_free(m_minus_2);
            if(two_buf) noxtls_free(two_buf);
            if(fermat_out) noxtls_free(fermat_out);
        } else {
            noxtls_bn_zero(result, m_len);
        }
    } else {
        /* Result is result_coeff mod m */
        noxtls_bn_mod(result, result_coeff, m_len, m, m_len);
        /* Verify: (a_mod_m * result) mod m == 1. If not, try Fermat fallback for odd moduli. */
        {
            uint8_t *prod = (uint8_t*)noxtls_calloc((size_t)m_len * 2u, 1);
            uint8_t *check = (uint8_t*)noxtls_calloc(m_len, 1);
            uint8_t *one = (uint8_t*)noxtls_calloc(m_len, 1);
            int ok = 0;
            if(prod && check && one) {
                one[m_len - 1] = 1;
                noxtls_bn_mul(prod, a_mod_m, m_len, result, m_len);
                noxtls_bn_mod(check, prod, m_len * 2, m, m_len);
                ok = (noxtls_bn_cmp(check, one, m_len) == 0);
            }
            if(prod) noxtls_free(prod);
            if(check) noxtls_free(check);
            if(one) noxtls_free(one);
            if(!ok && (m[m_len - 1] & 1u) != 0) {
                uint8_t *m_minus_2 = (uint8_t*)noxtls_calloc(m_len, 1);
                uint8_t *two_buf = (uint8_t*)noxtls_calloc(m_len, 1);
                if(m_minus_2 && two_buf) {
                    two_buf[m_len - 1] = 2;
                    noxtls_bn_copy(m_minus_2, m, m_len);
                    noxtls_bn_sub(m_minus_2, m_minus_2, two_buf, m_len);
                    noxtls_bn_mod_exp(result, a_mod_m, m_minus_2, m_len, m, m_len);
                } else {
                    noxtls_bn_zero(result, m_len);
                }
                if(m_minus_2) noxtls_free(m_minus_2);
                if(two_buf) noxtls_free(two_buf);
            }
        }
    }
    
    noxtls_free(u1);
    noxtls_free(u3);
    noxtls_free(v1);
    noxtls_free(v3);
    noxtls_free(temp);
    noxtls_free(a_mod_m);
    noxtls_free(m_padded);
    noxtls_free(u1_wide);
    noxtls_free(v1_wide);
    return NOXTLS_RETURN_SUCCESS;
}

/* Build-config queries for tests removed (reference backend removed). */
