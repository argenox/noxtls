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
* File:    noxtls_aria.c
* Summary: ARIA Block Cipher Algorithm Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <string.h>

/* Includes */
#include "common/noxtls_memory.h"
#include "noxtls_aria.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_ARIA

/* ARIA S-boxes (S1, S2, inverse S1, inverse S2) */
static const uint8_t aria_s1[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

static const uint8_t aria_s2[256] = {
    0xe2U, 0x4eU, 0x54U, 0xfcU, 0x94U, 0xc2U, 0x4aU, 0xccU, 0x62U, 0x0dU, 0x6aU, 0x46U, 0x3cU, 0x4dU, 0x8bU, 0xd1U,
    0x5eU, 0xfaU, 0x64U, 0xcbU, 0xb4U, 0x97U, 0xbeU, 0x2bU, 0xbcU, 0x77U, 0x2eU, 0x03U, 0xd3U, 0x19U, 0x59U, 0xc1U,
    0x1dU, 0x06U, 0x41U, 0x6bU, 0x55U, 0xf0U, 0x99U, 0x69U, 0xeaU, 0x9cU, 0x18U, 0xaeU, 0x63U, 0xdfU, 0xe7U, 0xbbU,
    0x00U, 0x73U, 0x66U, 0xfbU, 0x96U, 0x4cU, 0x85U, 0xe4U, 0x3aU, 0x09U, 0x45U, 0xaaU, 0x0fU, 0xeeU, 0x10U, 0xebU,
    0x2dU, 0x7fU, 0xf4U, 0x29U, 0xacU, 0xcfU, 0xadU, 0x91U, 0x8dU, 0x78U, 0xc8U, 0x95U, 0xf9U, 0x2fU, 0xceU, 0xcdU,
    0x08U, 0x7aU, 0x88U, 0x38U, 0x5cU, 0x83U, 0x2aU, 0x28U, 0x47U, 0xdbU, 0xb8U, 0xc7U, 0x93U, 0xa4U, 0x12U, 0x53U,
    0xffU, 0x87U, 0x0eU, 0x31U, 0x36U, 0x21U, 0x58U, 0x48U, 0x01U, 0x8eU, 0x37U, 0x74U, 0x32U, 0xcaU, 0xe9U, 0xb1U,
    0xb7U, 0xabU, 0x0cU, 0xd7U, 0xc4U, 0x56U, 0x42U, 0x26U, 0x07U, 0x98U, 0x60U, 0xd9U, 0xb6U, 0xb9U, 0x11U, 0x40U,
    0xecU, 0x20U, 0x8cU, 0xbdU, 0xa0U, 0xc9U, 0x84U, 0x04U, 0x49U, 0x23U, 0xf1U, 0x4fU, 0x50U, 0x1fU, 0x13U, 0xdcU,
    0xd8U, 0xc0U, 0x9eU, 0x57U, 0xe3U, 0xc3U, 0x7bU, 0x65U, 0x3bU, 0x02U, 0x8fU, 0x3eU, 0xe8U, 0x25U, 0x92U, 0xe5U,
    0x15U, 0xddU, 0xfdU, 0x17U, 0xa9U, 0xbfU, 0xd4U, 0x9aU, 0x7eU, 0xc5U, 0x39U, 0x67U, 0xfeU, 0x76U, 0x9dU, 0x43U,
    0xa7U, 0xe1U, 0xd0U, 0xf5U, 0x68U, 0xf2U, 0x1bU, 0x34U, 0x70U, 0x05U, 0xa3U, 0x8aU, 0xd5U, 0x79U, 0x86U, 0xa8U,
    0x30U, 0xc6U, 0x51U, 0x4bU, 0x1eU, 0xa6U, 0x27U, 0xf6U, 0x35U, 0xd2U, 0x6eU, 0x24U, 0x16U, 0x82U, 0x5fU, 0xdaU,
    0xe6U, 0x75U, 0xa2U, 0xefU, 0x2cU, 0xb2U, 0x1cU, 0x9fU, 0x5dU, 0x6fU, 0x80U, 0x0aU, 0x72U, 0x44U, 0x9bU, 0x6cU,
    0x90U, 0x0bU, 0x5bU, 0x33U, 0x7dU, 0x5aU, 0x52U, 0xf3U, 0x61U, 0xa1U, 0xf7U, 0xb0U, 0xd6U, 0x3fU, 0x7cU, 0x6dU,
    0xedU, 0x14U, 0xe0U, 0xa5U, 0x3dU, 0x22U, 0xb3U, 0xf8U, 0x89U, 0xdeU, 0x71U, 0x1aU, 0xafU, 0xbaU, 0xb5U, 0x81U
};

/* Diffusion layer (DL) - multiplication by constant matrix */
/**
 * @brief The diffusion layer.
 *
 * @param[in] state The state value.
 * @return void
 */
static void aria_diffusion_layer(uint8_t *state)
{
    uint8_t temp[16];

    /* DL transformation */
    temp[0] = state[3] ^ state[4] ^ state[6] ^ state[8] ^ state[9] ^ state[13] ^ state[14];
    temp[1] = state[2] ^ state[5] ^ state[7] ^ state[8] ^ state[9] ^ state[12] ^ state[15];
    temp[2] = state[1] ^ state[4] ^ state[6] ^ state[10] ^ state[11] ^ state[12] ^ state[15];
    temp[3] = state[0] ^ state[5] ^ state[7] ^ state[10] ^ state[11] ^ state[13] ^ state[14];
    temp[4] = state[0] ^ state[2] ^ state[5] ^ state[8] ^ state[11] ^ state[14] ^ state[15];
    temp[5] = state[1] ^ state[3] ^ state[4] ^ state[9] ^ state[10] ^ state[14] ^ state[15];
    temp[6] = state[0] ^ state[2] ^ state[7] ^ state[9] ^ state[10] ^ state[12] ^ state[13];
    temp[7] = state[1] ^ state[3] ^ state[6] ^ state[8] ^ state[11] ^ state[12] ^ state[13];
    temp[8] = state[0] ^ state[1] ^ state[4] ^ state[7] ^ state[10] ^ state[13] ^ state[15];
    temp[9] = state[0] ^ state[1] ^ state[5] ^ state[6] ^ state[11] ^ state[12] ^ state[14];
    temp[10] = state[2] ^ state[3] ^ state[5] ^ state[6] ^ state[8] ^ state[13] ^ state[15];
    temp[11] = state[2] ^ state[3] ^ state[4] ^ state[7] ^ state[9] ^ state[12] ^ state[14];
    temp[12] = state[1] ^ state[2] ^ state[6] ^ state[7] ^ state[9] ^ state[11] ^ state[12];
    temp[13] = state[0] ^ state[3] ^ state[6] ^ state[7] ^ state[8] ^ state[10] ^ state[13];
    temp[14] = state[0] ^ state[3] ^ state[4] ^ state[5] ^ state[9] ^ state[11] ^ state[14];
    temp[15] = state[1] ^ state[2] ^ state[4] ^ state[5] ^ state[8] ^ state[10] ^ state[15];

    noxtls_copy_u8((uint8_t *)(void *)(state), 16U, (const uint8_t *)(const void *)(temp), 16U);
}

/**
 * @brief The substitution layer 1.
 *
 * @param[in] state The state value.
 * @return void
 */
static void aria_sl1(uint8_t *state)
{
    static uint8_t inv_s1[256];
    static uint8_t inv_s2[256];
    static int inv_init = 0;
    const uint8_t *sb1 = aria_s1;
    const uint8_t *sb2 = aria_s2;
    const uint8_t *sb3 = inv_s1;
    const uint8_t *sb4 = inv_s2;

    if (inv_init == 0) {
        uint32_t i = 0U;
        for (i = 0U; i < 256U; i += 1U) {
            inv_s1[aria_s1[i]] = (uint8_t)i;
            inv_s2[aria_s2[i]] = (uint8_t)i;
        }
        inv_init = 1;
    }

    state[0]  = sb1[state[0]];  state[1]  = sb2[state[1]];  state[2]  = sb3[state[2]];  state[3]  = sb4[state[3]];
    state[4]  = sb1[state[4]];  state[5]  = sb2[state[5]];  state[6]  = sb3[state[6]];  state[7]  = sb4[state[7]];
    state[8]  = sb1[state[8]];  state[9]  = sb2[state[9]];  state[10] = sb3[state[10]]; state[11] = sb4[state[11]];
    state[12] = sb1[state[12]]; state[13] = sb2[state[13]]; state[14] = sb3[state[14]]; state[15] = sb4[state[15]];
}

/**
 * @brief The substitution layer 2.
 *
 * @param[in] state The state value.
 * @return void
 */
static void aria_sl2(uint8_t *state)
{
    static uint8_t inv_s1[256];
    static uint8_t inv_s2[256];
    static int inv_init = 0;
    const uint8_t *sb1 = aria_s1;
    const uint8_t *sb2 = aria_s2;
    const uint8_t *sb3 = inv_s1;
    const uint8_t *sb4 = inv_s2;

    if (inv_init == 0) {
        uint32_t i = 0U;
        for (i = 0U; i < 256U; i += 1U) {
            inv_s1[aria_s1[i]] = (uint8_t)i;
            inv_s2[aria_s2[i]] = (uint8_t)i;
        }
        inv_init = 1;
    }

    state[0]  = sb3[state[0]];  state[1]  = sb4[state[1]];  state[2]  = sb1[state[2]];  state[3]  = sb2[state[3]];
    state[4]  = sb3[state[4]];  state[5]  = sb4[state[5]];  state[6]  = sb1[state[6]];  state[7]  = sb2[state[7]];
    state[8]  = sb3[state[8]];  state[9]  = sb4[state[9]];  state[10] = sb1[state[10]]; state[11] = sb2[state[11]];
    state[12] = sb3[state[12]]; state[13] = sb4[state[13]]; state[14] = sb1[state[14]]; state[15] = sb2[state[15]];
}

/**
 * @brief The XOR block.
 *
 * @param[out] out The out value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 * @return void
 */
static void aria_xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t i = 0U;
    for (i = 0U; i < 16U; i += 1U) {
        out[i] = a[i] ^ b[i];
    }
}

/**
 * @brief The load BE 64.
 *
 * @param[in] p The p value.
 * @return The return value.
 */
static uint64_t aria_load_be64(const uint8_t *p)
{
    return (((uint64_t)p[0]) << 56U)
         | (((uint64_t)p[1]) << 48U)
         | (((uint64_t)p[2]) << 40U)
         | (((uint64_t)p[3]) << 32U)
         | (((uint64_t)p[4]) << 24U)
         | (((uint64_t)p[5]) << 16U)
         | (((uint64_t)p[6]) << 8U)
         | ((uint64_t)p[7]);
}

/**
 * @brief The store BE 64.
 *
 * @param[out] p The p value.
 * @param[in] v The v value.
 * @return void
 */
static void aria_store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56U);
    p[1] = (uint8_t)(v >> 48U);
    p[2] = (uint8_t)(v >> 40U);
    p[3] = (uint8_t)(v >> 32U);
    p[4] = (uint8_t)(v >> 24U);
    p[5] = (uint8_t)(v >> 16U);
    p[6] = (uint8_t)(v >> 8U);
    p[7] = (uint8_t)v;
}

/**
 * @brief The rotate right.
 *
 * @param[in] in The in value.
 * @param[out] out The out value.
 * @param[in] bits The bits value.
 * @return void
 */
static void aria_rotate_right(const uint8_t *in, uint8_t *out, uint32_t bits)
{
    uint64_t hi = (uint64_t)(aria_load_be64(&in[0]));
    uint64_t lo = (uint64_t)(aria_load_be64(&in[8]));
    uint64_t new_hi = 0U;
    uint64_t new_lo = 0U;

    /*
     * Key schedule only uses fixed rotate distances (19/31 and left-61/31/19
     * which map to right-67/97/109). Hard-code those shifts for MISRA 12.2.
     */
    switch(bits) {
    case 0U:
        new_hi = hi;
        new_lo = lo;
        break;
    case 19U:
        new_hi = (uint64_t)((hi >> 19U) | (lo << 45U));
        new_lo = (uint64_t)((lo >> 19U) | (hi << 45U));
        break;
    case 31U:
        new_hi = (uint64_t)((hi >> 31U) | (lo << 33U));
        new_lo = (uint64_t)((lo >> 31U) | (hi << 33U));
        break;
    case 64U:
        new_hi = lo;
        new_lo = hi;
        break;
    case 67U: /* left-61 */
        new_hi = (uint64_t)((lo >> 3U) | (hi << 61U));
        new_lo = (uint64_t)((hi >> 3U) | (lo << 61U));
        break;
    case 97U: /* left-31 */
        new_hi = (uint64_t)((lo >> 33U) | (hi << 31U));
        new_lo = (uint64_t)((hi >> 33U) | (lo << 31U));
        break;
    case 109U: /* left-19 */
        new_hi = (uint64_t)((lo >> 45U) | (hi << 19U));
        new_lo = (uint64_t)((hi >> 45U) | (lo << 19U));
        break;
    default:
        /* Unsupported distance: leave output unchanged (callers use fixed amounts). */
        new_hi = hi;
        new_lo = lo;
        break;
    }
    (void)aria_store_be64(&out[0], new_hi);
    (void)aria_store_be64(&out[8], new_lo);
}

/**
 * @brief The rotate left.
 *
 * @param[in] in The in value.
 * @param[out] out The out value.
 * @param[in] bits The bits value.
 * @return void
 */
static void aria_rotate_left(const uint8_t *in, uint8_t *out, uint32_t bits)
{
    uint32_t right_bits = 0U;

    switch(bits) {
    case 19U:
        right_bits = 109U;
        break;
    case 31U:
        right_bits = 97U;
        break;
    case 61U:
        right_bits = 67U;
        break;
    default:
        right_bits = 0U;
        break;
    }
    (void)aria_rotate_right(in, out, right_bits);
}

/**
 * @brief The FO function
 * 
 * @param[out] out The out value.
 * @param[in] in The in value.
 * @param[in] rk The rk value.
 * @return void
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void aria_fo(uint8_t *out, const uint8_t *in, const uint8_t *rk)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_copy_u8((uint8_t *)(void *)(out), 16U, (const uint8_t *)(const void *)(in), 16U);
    (void)aria_xor_block(out, out, rk);
    aria_sl1(out);
    (void)aria_diffusion_layer(out);
}

/**
 * @brief The FE function
 * 
 * @param[out] out The out value.
 * @param[in] in The in value.
 * @param[in] rk The rk value.
 * @return void
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void aria_fe(uint8_t *out, const uint8_t *in, const uint8_t *rk)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_copy_u8((uint8_t *)(void *)(out), 16U, (const uint8_t *)(const void *)(in), 16U);
    (void)aria_xor_block(out, out, rk);
    (void)aria_sl2(out);
    (void)aria_diffusion_layer(out);
}

/**
 * @brief Check that an ARIA key type identifier is supported.
 *
 * @param[in] key_type The key type value.
 * @return NOXTLS_RETURN_SUCCESS for 128/192/256-bit keys, otherwise
 *         NOXTLS_RETURN_INVALID_KEY_SIZE.
 */
static noxtls_return_t aria_check_key_type(noxtls_aria_type_t key_type)
{
    noxtls_return_t rc = NOXTLS_RETURN_INVALID_KEY_SIZE;

    if ((key_type == NOXTLS_ARIA_128_BIT) ||
        (key_type == NOXTLS_ARIA_192_BIT) ||
        (key_type == NOXTLS_ARIA_256_BIT)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }
    return rc;
}

/**
 * @brief Check that a key schedule carries a supported round count.
 *
 * @param[in] key The key schedule.
 * @return 1U when the round count is 12, 14 or 16, otherwise 0U.
 */
static uint8_t aria_rounds_valid(const noxtls_aria_key_t *key)
{
    uint8_t valid = 0U;

    if ((key->rounds == NOXTLS_ARIA_128_ROUNDS) ||
        (key->rounds == NOXTLS_ARIA_192_ROUNDS) ||
        (key->rounds == NOXTLS_ARIA_256_ROUNDS)) {
        valid = 1U;
    }
    return valid;
}

/* Key schedule generation */
/**
 * @brief The key schedule generation.
 *
 * @param[in] user_key The user key value.
 * @param[in] key_type The key type value.
 * @param[out] key The key value.
 * @return void
 */
static void aria_key_schedule(const uint8_t *user_key, noxtls_aria_type_t key_type, noxtls_aria_key_t *key)
{
    const uint8_t c1[16] = {0x51U, 0x7cU, 0xc1U, 0xb7U, 0x27U, 0x22U, 0x0aU, 0x94U, 0xfeU, 0x13U, 0xabU, 0xe8U, 0xfaU, 0x9aU, 0x6eU, 0xe0U};
    const uint8_t c2[16] = {0x6dU, 0xb1U, 0x4aU, 0xccU, 0x9eU, 0x21U, 0xc8U, 0x20U, 0xffU, 0x28U, 0xb1U, 0xd5U, 0xefU, 0x5dU, 0xe2U, 0xb0U};
    const uint8_t c3[16] = {0xdbU, 0x92U, 0x37U, 0x1dU, 0x21U, 0x26U, 0xe9U, 0x70U, 0x03U, 0x24U, 0x97U, 0x75U, 0x04U, 0xe8U, 0xc9U, 0x0eU};
    const uint8_t *ck1 = NULL;
    const uint8_t *ck2 = NULL;
    const uint8_t *ck3 = NULL;
    uint8_t kl[16];
    uint8_t kr[16];
    uint8_t w0[16];
    uint8_t w1[16];
    uint8_t w2[16];
    uint8_t w3[16];
    uint8_t rot[16];
    uint8_t ek[17][16];
    uint32_t i = 0U;

    {
        uint32_t key_type_u = (uint32_t)key_type;
        switch (key_type_u) {
        case (uint32_t)NOXTLS_ARIA_128_BIT:
            key->rounds = NOXTLS_ARIA_128_ROUNDS;
            ck1 = c1; ck2 = c2; ck3 = c3;
            break;
        case (uint32_t)NOXTLS_ARIA_192_BIT:
            key->rounds = NOXTLS_ARIA_192_ROUNDS;
            ck1 = c2; ck2 = c3; ck3 = c1;
            break;
        case (uint32_t)NOXTLS_ARIA_256_BIT:
            key->rounds = NOXTLS_ARIA_256_ROUNDS;
            ck1 = c3; ck2 = c1; ck3 = c2;
            break;
        default:
            return;
    }
    }

    noxtls_copy_u8((uint8_t *)(void *)(kl), 16U, (const uint8_t *)(const void *)(user_key), 16U);
    if (key_type == NOXTLS_ARIA_128_BIT) {
        noxtls_secure_zero((kr), (size_t)(16U));
    } else if (key_type == NOXTLS_ARIA_192_BIT) {
        noxtls_copy_u8(kr, sizeof(kr), &user_key[16], (size_t)(8U));
        noxtls_secure_zero((&kr[8]), (size_t)(8U));
    } else {
        noxtls_copy_u8((uint8_t *)(void *)(kr), 16U, (const uint8_t *)(const void *)(&user_key[16]), 16U);
    }

    noxtls_copy_u8((uint8_t *)(void *)(w0), 16U, (const uint8_t *)(const void *)(kl), 16U);
    (void)aria_fo(w1, w0, ck1);
    (void)aria_xor_block(w1, w1, kr);
    (void)aria_fe(w2, w1, ck2);
    (void)aria_xor_block(w2, w2, w0);
    (void)aria_fo(w3, w2, ck3);
    (void)aria_xor_block(w3, w3, w1);

    aria_rotate_right(w1, rot, 19U); aria_xor_block(ek[0], w0, rot);
    aria_rotate_right(w2, rot, 19U); aria_xor_block(ek[1], w1, rot);
    aria_rotate_right(w3, rot, 19U); aria_xor_block(ek[2], w2, rot);
    aria_rotate_right(w0, rot, 19U); aria_xor_block(ek[3], rot, w3);

    aria_rotate_right(w1, rot, 31U); aria_xor_block(ek[4], w0, rot);
    aria_rotate_right(w2, rot, 31U); aria_xor_block(ek[5], w1, rot);
    aria_rotate_right(w3, rot, 31U); aria_xor_block(ek[6], w2, rot);
    aria_rotate_right(w0, rot, 31U); aria_xor_block(ek[7], rot, w3);

    aria_rotate_left(w1, rot, 61U); aria_xor_block(ek[8], w0, rot);
    aria_rotate_left(w2, rot, 61U); aria_xor_block(ek[9], w1, rot);
    aria_rotate_left(w3, rot, 61U); aria_xor_block(ek[10], w2, rot);
    aria_rotate_left(w0, rot, 61U); aria_xor_block(ek[11], rot, w3);

    aria_rotate_left(w1, rot, 31U); aria_xor_block(ek[12], w0, rot);
    aria_rotate_left(w2, rot, 31U); aria_xor_block(ek[13], w1, rot);
    aria_rotate_left(w3, rot, 31U); aria_xor_block(ek[14], w2, rot);
    aria_rotate_left(w0, rot, 31U); aria_xor_block(ek[15], rot, w3);

    aria_rotate_left(w1, rot, 19U); aria_xor_block(ek[16], w0, rot);

    for (i = 0U; i <= (uint32_t)key->rounds; i += 1U) {
        noxtls_copy_u8((uint8_t *)(void *)(key->round_key[i]), 16U, (const uint8_t *)(const void *)(ek[i]), 16U);
    }
}

/**
 * @brief Set ARIA encryption key
 *
 * @param[in] user_key The user key value.
 * @param[in] key_type The key type value.
 * @param[out] key The key value.
 * @return The return value.
 */
noxtls_return_t noxtls_aria_set_encrypt_key(const uint8_t *user_key, noxtls_aria_type_t key_type, noxtls_aria_key_t *key)
{
    if ((user_key == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* Reject unsupported key types before the schedule is touched. */
    if (aria_check_key_type(key_type) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    key->key_type = key_type;
    (void)aria_key_schedule(user_key, key_type, key);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set ARIA decryption key
 *
 * @param[in] user_key The user key value.
 * @param[in] key_type The key type value.
 * @param[out] key The key value.
 * @return The return value.
 */
noxtls_return_t noxtls_aria_set_decrypt_key(const uint8_t *user_key, noxtls_aria_type_t key_type, noxtls_aria_key_t *key)
{
    uint32_t i = 0U;
    uint8_t temp_keys[17][16];
    noxtls_secure_zero((temp_keys), sizeof(temp_keys));

    if ((user_key == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* Reject unsupported key types: key->rounds would otherwise be left
     * unset and index temp_keys[] out of bounds below. */
    if (aria_check_key_type(key_type) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    key->key_type = key_type;
    (void)aria_key_schedule(user_key, key_type, key);

    for (i = 0U; i <= (uint32_t)key->rounds; i += 1U) {
        noxtls_copy_u8((uint8_t *)(void *)(temp_keys[i]), 16U, (const uint8_t *)(const void *)(key->round_key[i]), 16U);
    }

    noxtls_copy_u8((uint8_t *)(void *)(key->round_key[0]), 16U, (const uint8_t *)(const void *)(temp_keys[key->rounds]), 16U);
    for (i = 1U; i < (uint32_t)key->rounds; i += 1U) {
        noxtls_copy_u8((uint8_t *)(void *)(key->round_key[i]), 16U, (const uint8_t *)(const void *)(temp_keys[(uint32_t)key->rounds - i]), 16U);
        (void)aria_diffusion_layer(key->round_key[i]);
    }
    noxtls_copy_u8((uint8_t *)(void *)(key->round_key[key->rounds]), 16U, (const uint8_t *)(const void *)(temp_keys[0]), 16U);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA block encryption
 *
 * @param[in] key The key value.
 * @param[in] in The in value.
 * @param[out] out The out value.
 * @return void
 */
void noxtls_aria_encrypt_block(const noxtls_aria_key_t *key, const uint8_t *in, uint8_t *out)
{
    uint8_t state[16];
    uint32_t round = 0U;

    if ((key == NULL) || (in == NULL) || (out == NULL)) {
        return;
    }
    if (aria_rounds_valid(key) == 0U) {
        return;
    }

    /* Copy input to state */
    noxtls_copy_u8((uint8_t *)(void *)(state), 16U, (const uint8_t *)(const void *)(in), 16U);

    for (round = 1U; round < (uint32_t)key->rounds; round += 1U) {
        if (((round & 1U) != 0U)) {
            (void)aria_fo(state, state, key->round_key[round - 1U]);
        } else {
            (void)aria_fe(state, state, key->round_key[round - 1U]);
        }
    }

    (void)aria_xor_block(state, state, key->round_key[key->rounds - 1]);
    (void)aria_sl2(state);
    (void)aria_xor_block(state, state, key->round_key[key->rounds]);

    /* Copy state to output */
    noxtls_copy_u8((uint8_t *)(void *)(out), 16U, (const uint8_t *)(const void *)(state), 16U);
}

/**
 * @brief ARIA block decryption
 *
 * @param[in] key The key value.
 * @param[in] in The in value.
 * @param[out] out The out value.
 * @return void
 */
void noxtls_aria_decrypt_block(const noxtls_aria_key_t *key, const uint8_t *in, uint8_t *out)
{
    uint8_t state[16];
    uint32_t round = 0U;

    if ((key == NULL) || (in == NULL) || (out == NULL)) {
        return;
    }
    if (aria_rounds_valid(key) == 0U) {
        return;
    }

    /* Copy input to state */
    noxtls_copy_u8((uint8_t *)(void *)(state), 16U, (const uint8_t *)(const void *)(in), 16U);

    for (round = 1U; round < (uint32_t)key->rounds; round += 1U) {
        if (((round & 1U) != 0U)) {
            (void)aria_fo(state, state, key->round_key[round - 1U]);
        } else {
            (void)aria_fe(state, state, key->round_key[round - 1U]);
        }
    }

    (void)aria_xor_block(state, state, key->round_key[key->rounds - 1]);
    (void)aria_sl2(state);
    (void)aria_xor_block(state, state, key->round_key[key->rounds]);

    /* Copy state to output */
    noxtls_copy_u8((uint8_t *)(void *)(out), 16U, (const uint8_t *)(const void *)(state), 16U);
}

/* Mode entry points are declared in noxtls_aria.h. */

/**
 * @brief ARIA Encrypt Data
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[in] data_len The data length value.
 * @param[in] iv The iv value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @return The return value.
 * @note The data length must be a multiple of the block size.
 * @note The data length must be greater than 0.
 * @note The data length must be less than the block size.
 * @note The data length must be less than the data length.
 * @note The data length must be less than the data length.
 * @note The data length must be less than the data length.
*/
noxtls_return_t noxtls_aria_encrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      noxtls_aria_type_t type,
                      noxtls_aria_mode_t mode)
{
    {
        /* Widen so the default arm stays reachable for Rule 2.1. */
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
            case (uint32_t)NOXTLS_ARIA_ECB:
                return noxtls_aria_encrypt_ecb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CBC:
                return noxtls_aria_encrypt_cbc(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CTR:
                return noxtls_aria_encrypt_ctr(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CFB:
                return noxtls_aria_encrypt_cfb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_OFB:
                return noxtls_aria_encrypt_ofb(key, data, data_len, iv, output, type);
            default:
                return NOXTLS_RETURN_INVALID_MODE;
        }
    }
}

/**
 * @brief ARIA Decrypt Data
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[in] data_len The data length value.
 * @param[in] iv The iv value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @return The return value.
 * @note The data length must be a multiple of the block size.
 * @note The data length must be greater than 0.
 * @note The data length must be less than the block size.
 * @note The data length must be less than the data length.
 * @note The data length must be less than the data length.
 */
noxtls_return_t noxtls_aria_decrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      noxtls_aria_type_t type,
                      noxtls_aria_mode_t mode)
{
    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
            case (uint32_t)NOXTLS_ARIA_ECB:
                return noxtls_aria_decrypt_ecb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CBC:
                return noxtls_aria_decrypt_cbc(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CTR:
                return noxtls_aria_decrypt_ctr(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_CFB:
                return noxtls_aria_decrypt_cfb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_ARIA_OFB:
                return noxtls_aria_decrypt_ofb(key, data, data_len, iv, output, type);
            default:
                return NOXTLS_RETURN_INVALID_MODE;
        }
    }
}

/**
 * @brief The key size bytes.
 *
 * @param[in] type The type value.
 * @return The return value.
 */
static uint8_t aria_key_size_bytes(noxtls_aria_type_t type)
{
    {
        uint32_t type_u = (uint32_t)type;
        switch (type_u) {
        case (uint32_t)NOXTLS_ARIA_128_BIT:
            return 16;
        case (uint32_t)NOXTLS_ARIA_192_BIT:
            return 24;
        case (uint32_t)NOXTLS_ARIA_256_BIT:
            return 32;
        default:
            return 0U;
    }
    }
}

/**
 * @brief The counter increment.
 *
 * @param[in] counter The counter value.
 * @return void
 */
static void aria_counter_inc(uint8_t *counter)
{
    int i = 0;
    for (i = (int)NOXTLS_ARIA_BLOCK_LENGTH - 1; i >= 0; i -= 1) {
        counter[i] = (uint8_t)(counter[i] + 1U);
        if (counter[i] != 0U) {
            break;
        }
    }
}

/**
 * @brief The ARIA init.
 *
 * @param[in] ctx The ctx value.
 * @param[in] key The key value.
 * @param[in] iv The iv value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @param[in] op The op value.
 * @return The return value.
 */
noxtls_return_t noxtls_aria_init(noxtls_aria_context_t *ctx,
              const uint8_t *key,
              const uint8_t *iv,
              noxtls_aria_type_t type,
              noxtls_aria_mode_t mode,
              noxtls_aria_operation_t op)
{
    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    ctx->type = type;
    ctx->mode = mode;
    ctx->op = op;
    ctx->key_len = aria_key_size_bytes(type);

    if (ctx->key_len == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)(ctx->key_len));

    {
        noxtls_return_t r = noxtls_aria_set_encrypt_key(ctx->key, type, &ctx->enc_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }
    {
        noxtls_return_t r = noxtls_aria_set_decrypt_key(ctx->key, type, &ctx->dec_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_ARIA_ECB:
            break;
        case (uint32_t)NOXTLS_ARIA_CBC:
            if (iv != NULL) {
                noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
            } else {
                /* MISRA 15.7: final else path */
                noxtls_secure_zero((ctx->feedback), (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
            }
            break;
        case (uint32_t)NOXTLS_ARIA_CTR:
        case (uint32_t)NOXTLS_ARIA_CFB:
        case (uint32_t)NOXTLS_ARIA_OFB:
            if (iv == NULL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
            ctx->partial_len = NOXTLS_ARIA_BLOCK_LENGTH;
            break;
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief The ARIA update.
 *
 * @param[in] ctx The ctx value.
 * @param[in] input The input value.
 * @param[in] input_len The input length value.
 * @param[out] output The output value.
 * @param[out] output_len The output length value.
 * @return The return value.
 */
noxtls_return_t noxtls_aria_update(noxtls_aria_context_t *ctx,
                const uint8_t *input,
                uint32_t input_len,
                uint8_t *output,
                uint32_t *output_len)
{
    uint32_t produced = 0U;
    uint32_t i = 0U;
    const uint8_t *in_ptr = input;
    uint32_t in_left = input_len;

    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if ((in_left > 0U) && ((in_ptr == NULL) || (output == NULL))) {
        return NOXTLS_RETURN_NULL;
    }
    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if ((ctx->mode == NOXTLS_ARIA_ECB) || (ctx->mode == NOXTLS_ARIA_CBC)) {
            while (in_left > 0U) {
                uint32_t need = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (uint32_t)((in_left < need) ? in_left : need);
                noxtls_copy_u8(&ctx->partial[ctx->partial_len], sizeof(ctx->partial) - (size_t)(ctx->partial_len), in_ptr, (size_t)(take));
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                in_ptr = &in_ptr[take];
                in_left -= take;

                if (ctx->partial_len == NOXTLS_ARIA_BLOCK_LENGTH) {
                    if (ctx->mode == NOXTLS_ARIA_ECB) {
                        if (ctx->op == NOXTLS_ARIA_OP_ENCRYPT) {
                            (void)noxtls_aria_encrypt_block(&ctx->enc_key, ctx->partial, &output[produced]);
                        } else {
                            (void)noxtls_aria_decrypt_block(&ctx->dec_key, ctx->partial, &output[produced]);
                        }
                    } else {
                        if (ctx->op == NOXTLS_ARIA_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_ARIA_BLOCK_LENGTH];
                            for (i = 0U; i < NOXTLS_ARIA_BLOCK_LENGTH; i += 1U) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            (void)noxtls_aria_encrypt_block(&ctx->enc_key, block, &output[produced]);
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), &output[produced], (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
                        } else {
                            uint8_t block[NOXTLS_ARIA_BLOCK_LENGTH];
                            (void)noxtls_aria_decrypt_block(&ctx->dec_key, ctx->partial, block);
                            for (i = 0U; i < NOXTLS_ARIA_BLOCK_LENGTH; i += 1U) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
                        }
                    }
                    produced += NOXTLS_ARIA_BLOCK_LENGTH;
                    ctx->partial_len = 0U;
                }
            }
    } else if ((ctx->mode == NOXTLS_ARIA_CTR) || (ctx->mode == NOXTLS_ARIA_CFB) || (ctx->mode == NOXTLS_ARIA_OFB)) {
            while (in_left > 0U) {
                if (ctx->partial_len == NOXTLS_ARIA_BLOCK_LENGTH) {
                    if (ctx->mode == NOXTLS_ARIA_CTR) {
                        (void)noxtls_aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                        aria_counter_inc(ctx->feedback);
                    } else if (ctx->mode == NOXTLS_ARIA_CFB) {
                        (void)noxtls_aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                    } else {
                        (void)noxtls_aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                        noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_ARIA_BLOCK_LENGTH));
                    }
                    ctx->partial_len = 0U;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (uint32_t)((in_left < available) ? in_left : available);
                    for (i = 0U; i < take; i += 1U) {
                        uint8_t out_byte = (uint8_t)(in_ptr[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if (ctx->mode == NOXTLS_ARIA_CFB) {
                            noxtls_move_u8(ctx->feedback, sizeof(ctx->feedback), &ctx->feedback[1], (size_t)(NOXTLS_ARIA_BLOCK_LENGTH - 1U));
                            ctx->feedback[NOXTLS_ARIA_BLOCK_LENGTH - 1U] = (ctx->op == NOXTLS_ARIA_OP_ENCRYPT) ? out_byte : in_ptr[i];
                        }
                    }
                    in_ptr = &in_ptr[take];
                    in_left -= take;
                    produced += take;
                    ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                }
            }
    } else {
         /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
    }

    *output_len = produced;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief The ARIA final.
 *
 * @param[in] ctx The ctx value.
 * @param[out] output The output value.
 * @param[out] output_len The output length value.
 * @return The return value.
 */
noxtls_return_t noxtls_aria_final(noxtls_aria_context_t *ctx,
               uint8_t *output,
               uint32_t *output_len)
{
    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if ((ctx->mode == NOXTLS_ARIA_CTR) || (ctx->mode == NOXTLS_ARIA_CFB) || (ctx->mode == NOXTLS_ARIA_OFB)) {
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->op == NOXTLS_ARIA_OP_DECRYPT) {
        if (ctx->partial_len != 0U) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->partial_len > 0U) {
        uint8_t block[NOXTLS_ARIA_BLOCK_LENGTH];
        uint8_t pad_value = (uint8_t)(NOXTLS_ARIA_BLOCK_LENGTH - ctx->partial_len);
        uint32_t i = 0U;

        if (output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        noxtls_copy_u8(block, sizeof(block), ctx->partial, (size_t)(ctx->partial_len));
        for (i = ctx->partial_len; i < NOXTLS_ARIA_BLOCK_LENGTH; i += 1U) {
            block[i] = pad_value;
        }

        if (ctx->mode == NOXTLS_ARIA_ECB) {
            (void)noxtls_aria_encrypt_block(&ctx->enc_key, block, output);
        } else if (ctx->mode == NOXTLS_ARIA_CBC) {
            for (i = 0U; i < NOXTLS_ARIA_BLOCK_LENGTH; i += 1U) {
                block[i] ^= ctx->feedback[i];
            }
            (void)noxtls_aria_encrypt_block(&ctx->enc_key, block, output);
        } else {
             /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
        }
        *output_len = NOXTLS_ARIA_BLOCK_LENGTH;
    }

    ctx->initialized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Self Test
 *
 * @return result code
 */
noxtls_return_t noxtls_aria_self_test(void)
{
    /* RFC 5794 A.1 test vector */
    const uint8_t key128[16] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU
    };
    uint8_t plaintext[16] = {
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
        0x88U, 0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU
    };
    const uint8_t expected[16] = {
        0xd7U, 0x18U, 0xfbU, 0xd6U, 0xabU, 0x64U, 0x4cU, 0x73U,
        0x9dU, 0xa9U, 0x5fU, 0x3bU, 0xe6U, 0x45U, 0x17U, 0x78U
    };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    noxtls_aria_key_t enc_key;
    noxtls_aria_key_t dec_key;

    /* Test encryption */
    if (noxtls_aria_set_encrypt_key(key128, NOXTLS_ARIA_128_BIT, &enc_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    (void)noxtls_aria_encrypt_block(&enc_key, plaintext, ciphertext);
    if (memcmp(ciphertext, expected, (size_t)16U) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Test decryption */
    if (noxtls_aria_set_decrypt_key(key128, NOXTLS_ARIA_128_BIT, &dec_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    (void)noxtls_aria_decrypt_block(&dec_key, ciphertext, decrypted);

    if (memcmp(plaintext, decrypted, (size_t)16U) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_ARIA */
