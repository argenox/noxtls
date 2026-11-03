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
* File:    aes.c
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Includes */
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_AES

#ifndef NOXTLS_PORT_AES_ACCEL
#define NOXTLS_PORT_AES_ACCEL 0
#endif
#ifndef NOXTLS_FEATURE_STM32_HW_AES_ONLY
#define NOXTLS_FEATURE_STM32_HW_AES_ONLY 0
#endif
#ifndef NOXTLS_FEATURE_NRF52_HW_AES_ONLY
#define NOXTLS_FEATURE_NRF52_HW_AES_ONLY 0
#endif
/* Table placement knobs are documented in noxtls_config.h. */
#ifndef NOXTLS_AES_ROM_TABLES
#define NOXTLS_AES_ROM_TABLES 1
#endif
#ifndef NOXTLS_AES_COMPACT_TABLES
#define NOXTLS_AES_COMPACT_TABLES 0
#endif
/* Software core selection is documented in noxtls_config.h. */
#ifndef NOXTLS_AES_CONSTANT_TIME
#if defined(NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE)
#define NOXTLS_AES_CONSTANT_TIME 0
#else
#define NOXTLS_AES_CONSTANT_TIME 1
#endif
#endif
#if (NOXTLS_AES_CONSTANT_TIME != 0) && (NOXTLS_AES_CONSTANT_TIME != 1)
#error "NOXTLS_AES_CONSTANT_TIME must be 0 or 1"
#endif

/* Clear the dead frame of the software block core after every block. The
 * core keeps the round state in automatic variables that compilers spill to
 * the stack (Cortex-M0+ at -O2, any target at -O0); a stale pre-final-round
 * state plus the public output gives the last round key. C cannot clear spill
 * slots from inside the function, so the core runs in its own frame and a
 * second, larger frame is written over it afterwards. */
#ifndef NOXTLS_AES_STACK_BURN
#define NOXTLS_AES_STACK_BURN 1
#endif
/* Bytes cleared below the caller; each must exceed the deepest frame chain it
 * covers (measured with -fstack-usage). Key schedule (aes_subword() and the
 * bitsliced S-box): about 660 B at -O0 on Cortex-M0+/M4, 740 B on arm64.
 * Constant-time block core: the same chain plus about 130 B. Table block
 * core: under 260 B at -O0 (decrypt with InvMixColumns), under 100 B at -O2. */
#ifndef NOXTLS_AES_STACK_BURN_BYTES
#define NOXTLS_AES_STACK_BURN_BYTES 1024U
#endif
#ifndef NOXTLS_AES_BLOCK_BURN_BYTES
#if NOXTLS_AES_CONSTANT_TIME
#define NOXTLS_AES_BLOCK_BURN_BYTES 1024U
#else
#define NOXTLS_AES_BLOCK_BURN_BYTES 384U
#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_AES_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOXTLS_AES_NOINLINE __declspec(noinline)
#else
#define NOXTLS_AES_NOINLINE
#endif

/* The software fallback needs the expanded schedule kept in the context. */
#define NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK (NOXTLS_AES_CTX_SOFTWARE_SCHEDULE)

#if !NOXTLS_AES_CTX_RAW_KEY && (NOXTLS_PORT_AES_ACCEL || NOXTLS_FEATURE_AES_ACCEL_NI || NOXTLS_FEATURE_AES_ACCEL_APPLE || \
                                 !NOXTLS_AES_CTX_SOFTWARE_SCHEDULE)
#error "AES accelerator backends need NOXTLS_AES_CTX_RAW_KEY=1 (raw key kept in noxtls_aes_context_t)"
#endif

#if !NOXTLS_AES_CONSTANT_TIME
/** AES Substitution Box (table core only; indexed with secret state bytes) */
static const uint8_t aes_sub_box[16][16] =
{
    {0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U},
    {0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U},
    {0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U},
    {0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U},
    {0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U},
    {0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU},
    {0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U},
    {0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U},
    {0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U},
    {0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU},
    {0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U},
    {0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U},
    {0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU},
    {0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU},
    {0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU},
    {0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U}
};

#if NOXTLS_AES_ROM_TABLES
#include "noxtls_aes_rom_tables.h"
#else
static uint32_t aes_enc_te0[256];
#if !NOXTLS_AES_COMPACT_TABLES
static uint32_t aes_enc_te1[256];
static uint32_t aes_enc_te2[256];
static uint32_t aes_enc_te3[256];
#endif
#endif

/* Te1..Te3 are byte rotations of Te0; the compact mode derives them on lookup. */
#if NOXTLS_AES_COMPACT_TABLES
#define AES_TE0(i) (aes_enc_te0[(i)])
#define AES_TE1(i) (NOXTLS_AES_ROTR(aes_enc_te0[(i)], 8U))
#define AES_TE2(i) (NOXTLS_AES_ROTR(aes_enc_te0[(i)], 16U))
#define AES_TE3(i) (NOXTLS_AES_ROTR(aes_enc_te0[(i)], 24U))
#else
#define AES_TE0(i) (aes_enc_te0[(i)])
#define AES_TE1(i) (aes_enc_te1[(i)])
#define AES_TE2(i) (aes_enc_te2[(i)])
#define AES_TE3(i) (aes_enc_te3[(i)])
#endif
#endif /* !NOXTLS_AES_CONSTANT_TIME */

static uint32_t aes_rotword(uint32_t w);
static uint32_t aes_subword(uint32_t w);
static uint32_t rcon(uint8_t in);
static uint8_t aes_xtime_byte(uint8_t x);
#if !NOXTLS_AES_CONSTANT_TIME
static uint8_t aes_sbox_lookup(uint8_t x);
static uint32_t aes_load_be32(const uint8_t *src);
static void aes_store_be32(uint8_t *dst, uint32_t word);
static void aes_software_init_encrypt_tables(void);
#endif
#if NOXTLS_AES_STACK_BURN
static NOXTLS_AES_NOINLINE void aes_stack_burn(void);
static NOXTLS_AES_NOINLINE void aes_stack_burn_block(void);
#endif
static void aes_ct_sub_bytes(uint32_t s[4], uint32_t inverse);

static noxtls_return_t noxtls_aes_encrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
static noxtls_return_t noxtls_aes_encrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output);
static noxtls_return_t noxtls_aes_decrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output);
#if !NOXTLS_AES_CONSTANT_TIME
/**
 * @brief Copy an AES state matrix to a contiguous output block.
 *
 * @param state AES state matrix in column-major order.
 * @param output Output buffer that receives NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return 0 on success.
 */
static int copy_state_to_buffer(const uint8_t *state_bytes, uint8_t* output)
{
    uint32_t row = 0U;
    uint32_t col = 0U;
    uint32_t cnt = 0U;
    for (col = 0U; col < 4U; col += 1U)
    {
        for (row = 0U; row < 4U; row += 1U)
        {
            output[cnt] = state_bytes[(row * 4U) + col];
            cnt += 1U;
        }
    }

    return 0;
}
#endif

/**
 * @brief Multiply an AES field element by x in GF(2^8).
 *
 * @param x Field element to multiply.
 * @return Result of multiplying @p x by x modulo the AES polynomial.
 */
static uint8_t aes_xtime_byte(uint8_t x)
{
    /* Reduction selected by a mask, not a branch, so state bytes do not
     * steer control flow (Cortex-M0+ compiles the if-form to a branch). */
    uint8_t hi_mask = (uint8_t)(0U - (uint32_t)((uint32_t)x >> 7U));
    return (uint8_t)((uint8_t)(x << 1U) ^ (uint8_t)(hi_mask & 0x1BU));
}

/**
 * @brief Swap bit groups between two words (one stage of the bit transpose).
 *
 * @param x First word, keeps the bits selected by @p cl.
 * @param y Second word, keeps the bits selected by @p ch.
 * @param cl Mask of the low bit group.
 * @param ch Mask of the high bit group.
 * @param s Distance between the groups.
 * @return None.
 */
static void aes_ct_swapn(uint32_t *x, uint32_t *y, uint32_t cl, uint32_t ch, uint32_t s)
{
    uint32_t a = *x;
    uint32_t b = *y;
    *x = (a & cl) | ((b & cl) << s);
    *y = ((a & ch) >> s) | (b & ch);
}

/**
 * @brief Transpose eight words so that word i holds bit i of every byte.
 *
 * The transform is an involution: applying it twice restores the input.
 *
 * @param q Eight words transposed in place.
 * @return None.
 */
static void aes_ct_ortho(uint32_t q[8])
{
    aes_ct_swapn(&q[0], &q[1], 0x55555555U, 0xAAAAAAAAU, 1U);
    aes_ct_swapn(&q[2], &q[3], 0x55555555U, 0xAAAAAAAAU, 1U);
    aes_ct_swapn(&q[4], &q[5], 0x55555555U, 0xAAAAAAAAU, 1U);
    aes_ct_swapn(&q[6], &q[7], 0x55555555U, 0xAAAAAAAAU, 1U);
    aes_ct_swapn(&q[0], &q[2], 0x33333333U, 0xCCCCCCCCU, 2U);
    aes_ct_swapn(&q[1], &q[3], 0x33333333U, 0xCCCCCCCCU, 2U);
    aes_ct_swapn(&q[4], &q[6], 0x33333333U, 0xCCCCCCCCU, 2U);
    aes_ct_swapn(&q[5], &q[7], 0x33333333U, 0xCCCCCCCCU, 2U);
    aes_ct_swapn(&q[0], &q[4], 0x0F0F0F0FU, 0xF0F0F0F0U, 4U);
    aes_ct_swapn(&q[1], &q[5], 0x0F0F0F0FU, 0xF0F0F0F0U, 4U);
    aes_ct_swapn(&q[2], &q[6], 0x0F0F0F0FU, 0xF0F0F0F0U, 4U);
    aes_ct_swapn(&q[3], &q[7], 0x0F0F0F0FU, 0xF0F0F0F0U, 4U);
}

/**
 * @brief Bitsliced AES S-box on 32 bytes at once.
 *
 * Boyar-Peralta circuit ("A new combinational logic minimization technique
 * with applications to cryptology", 2009): 32 XOR/XNOR and 32 AND gates for
 * GF(2^8) inversion plus the affine map, with no table and no branch. Word i
 * of @p q holds bit i of every byte (see aes_ct_ortho()).
 *
 * @param q Eight bit-plane words, substituted in place.
 * @return None.
 */
static void aes_ct_sbox(uint32_t q[8])
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
    uint32_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
    uint32_t y20, y21;
    uint32_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
    uint32_t z10, z11, z12, z13, z14, z15, z16, z17;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    uint32_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
    uint32_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
    uint32_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
    uint32_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
    uint32_t t60, t61, t62, t63, t64, t65, t66, t67;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;

    /* The circuit numbers bits from the most significant (x0) down. */
    x0 = q[7];
    x1 = q[6];
    x2 = q[5];
    x3 = q[4];
    x4 = q[3];
    x5 = q[2];
    x6 = q[1];
    x7 = q[0];

    /* Top linear transformation. */
    y14 = x3 ^ x5;
    y13 = x0 ^ x6;
    y9 = x0 ^ x3;
    y8 = x0 ^ x5;
    t0 = x1 ^ x2;
    y1 = t0 ^ x7;
    y4 = y1 ^ x3;
    y12 = y13 ^ y14;
    y2 = y1 ^ x0;
    y5 = y1 ^ x6;
    y3 = y5 ^ y8;
    t1 = x4 ^ y12;
    y15 = t1 ^ x5;
    y20 = t1 ^ x1;
    y6 = y15 ^ x7;
    y10 = y15 ^ t0;
    y11 = y20 ^ y9;
    y7 = x7 ^ y11;
    y17 = y10 ^ y11;
    y19 = y10 ^ y8;
    y16 = t0 ^ y11;
    y21 = y13 ^ y16;
    y18 = x0 ^ y16;

    /* Non-linear section (inversion in GF(2^8) via GF(2^4)). */
    t2 = y12 & y15;
    t3 = y3 & y6;
    t4 = t3 ^ t2;
    t5 = y4 & x7;
    t6 = t5 ^ t2;
    t7 = y13 & y16;
    t8 = y5 & y1;
    t9 = t8 ^ t7;
    t10 = y2 & y7;
    t11 = t10 ^ t7;
    t12 = y9 & y11;
    t13 = y14 & y17;
    t14 = t13 ^ t12;
    t15 = y8 & y10;
    t16 = t15 ^ t12;
    t17 = t4 ^ t14;
    t18 = t6 ^ t16;
    t19 = t9 ^ t14;
    t20 = t11 ^ t16;
    t21 = t17 ^ y20;
    t22 = t18 ^ y19;
    t23 = t19 ^ y21;
    t24 = t20 ^ y18;

    t25 = t21 ^ t22;
    t26 = t21 & t23;
    t27 = t24 ^ t26;
    t28 = t25 & t27;
    t29 = t28 ^ t22;
    t30 = t23 ^ t24;
    t31 = t22 ^ t26;
    t32 = t31 & t30;
    t33 = t32 ^ t24;
    t34 = t23 ^ t33;
    t35 = t27 ^ t33;
    t36 = t24 & t35;
    t37 = t36 ^ t34;
    t38 = t27 ^ t36;
    t39 = t29 & t38;
    t40 = t25 ^ t39;

    t41 = t40 ^ t37;
    t42 = t29 ^ t33;
    t43 = t29 ^ t40;
    t44 = t33 ^ t37;
    t45 = t42 ^ t41;
    z0 = t44 & y15;
    z1 = t37 & y6;
    z2 = t33 & x7;
    z3 = t43 & y16;
    z4 = t40 & y1;
    z5 = t29 & y7;
    z6 = t42 & y11;
    z7 = t45 & y17;
    z8 = t41 & y10;
    z9 = t44 & y12;
    z10 = t37 & y3;
    z11 = t33 & y4;
    z12 = t43 & y13;
    z13 = t40 & y5;
    z14 = t29 & y2;
    z15 = t42 & y9;
    z16 = t45 & y14;
    z17 = t41 & y8;

    /* Bottom linear transformation (includes the affine constant 0x63). */
    t46 = z15 ^ z16;
    t47 = z10 ^ z11;
    t48 = z5 ^ z13;
    t49 = z9 ^ z10;
    t50 = z2 ^ z12;
    t51 = z2 ^ z5;
    t52 = z7 ^ z8;
    t53 = z0 ^ z3;
    t54 = z6 ^ z7;
    t55 = z16 ^ z17;
    t56 = z12 ^ t48;
    t57 = t50 ^ t53;
    t58 = z4 ^ t46;
    t59 = z3 ^ t54;
    t60 = t46 ^ t57;
    t61 = z14 ^ t57;
    t62 = t52 ^ t58;
    t63 = t49 ^ t58;
    t64 = z4 ^ t59;
    t65 = t61 ^ t62;
    t66 = z1 ^ t63;
    s0 = t59 ^ t63;
    s6 = t56 ^ ~t62;
    s7 = t48 ^ ~t60;
    t67 = t64 ^ t65;
    s3 = t53 ^ t66;
    s4 = t51 ^ t66;
    s5 = t47 ^ t65;
    s1 = t64 ^ ~s3;
    s2 = t55 ^ ~t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/**
 * @brief Inverse of the AES affine map on bit planes.
 *
 * Byte form: rotl(y,1) ^ rotl(y,3) ^ rotl(y,6) ^ 0x05. Applied before and
 * after the forward S-box it yields the inverse S-box, because GF(2^8)
 * inversion is its own inverse.
 *
 * @param q Eight bit-plane words, transformed in place.
 * @return None.
 */
static void aes_ct_inv_affine(uint32_t q[8])
{
    uint32_t q0 = q[0];
    uint32_t q1 = q[1];
    uint32_t q2 = q[2];
    uint32_t q3 = q[3];
    uint32_t q4 = q[4];
    uint32_t q5 = q[5];
    uint32_t q6 = q[6];
    uint32_t q7 = q[7];

    q[0] = ~(q7 ^ q5 ^ q2);
    q[1] = q0 ^ q6 ^ q3;
    q[2] = ~(q1 ^ q7 ^ q4);
    q[3] = q2 ^ q0 ^ q5;
    q[4] = q3 ^ q1 ^ q6;
    q[5] = q4 ^ q2 ^ q7;
    q[6] = q5 ^ q3 ^ q0;
    q[7] = q6 ^ q4 ^ q1;
}

/**
 * @brief Constant-time SubBytes or InvSubBytes on 16 packed bytes.
 *
 * @param s Four words of packed state bytes (any byte order), in place.
 * @param inverse 0 for the S-box, 1 for the inverse S-box (public selector).
 * @return None.
 */
static void aes_ct_sub_bytes(uint32_t s[4], uint32_t inverse)
{
    uint32_t q[8];

    q[0] = s[0];
    q[1] = s[1];
    q[2] = s[2];
    q[3] = s[3];
    q[4] = 0U;
    q[5] = 0U;
    q[6] = 0U;
    q[7] = 0U;
    aes_ct_ortho(q);
    if (inverse != 0U) {
        aes_ct_inv_affine(q);
    }
    aes_ct_sbox(q);
    if (inverse != 0U) {
        aes_ct_inv_affine(q);
    }
    aes_ct_ortho(q);
    s[0] = q[0];
    s[1] = q[1];
    s[2] = q[2];
    s[3] = q[3];
}

#if NOXTLS_AES_STACK_BURN
/**
 * @brief Overwrite the dead stack below the caller.
 *
 * Called right after a non-inlined block core returns, from the same frame,
 * so this frame covers the core's spill slots.
 *
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_stack_burn(void)
{
    volatile uint32_t burn[NOXTLS_AES_STACK_BURN_BYTES / 4U];
    uint32_t i = 0U;

    for (i = 0U; i < (uint32_t)(sizeof(burn) / sizeof(burn[0])); i += 1U) {
        burn[i] = 0U;
    }
}

/**
 * @brief Overwrite the dead stack below the caller after one block.
 *
 * Sized for the selected block core (NOXTLS_AES_BLOCK_BURN_BYTES), so the
 * per-block cost stays small for the table core.
 *
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_stack_burn_block(void)
{
    volatile uint32_t burn[NOXTLS_AES_BLOCK_BURN_BYTES / 4U];
    uint32_t i = 0U;

    for (i = 0U; i < (uint32_t)(sizeof(burn) / sizeof(burn[0])); i += 1U) {
        burn[i] = 0U;
    }
}
#endif

#if NOXTLS_AES_CONSTANT_TIME
/**
 * @brief Load a little-endian 32-bit word (one state column, row 0 lowest).
 *
 * @param src Source buffer containing at least 4 bytes.
 * @return Decoded word.
 */
static uint32_t aes_load_le32(const uint8_t *src)
{
    return (uint32_t)src[0] |
           ((uint32_t)src[1] << 8U) |
           ((uint32_t)src[2] << 16U) |
           ((uint32_t)src[3] << 24U);
}

/**
 * @brief Store a 32-bit word in little-endian order.
 *
 * @param dst Destination buffer that receives 4 bytes.
 * @param word Word to encode.
 * @return None.
 */
static void aes_store_le32(uint8_t *dst, uint32_t word)
{
    dst[0] = (uint8_t)word;
    dst[1] = (uint8_t)(word >> 8U);
    dst[2] = (uint8_t)(word >> 16U);
    dst[3] = (uint8_t)(word >> 24U);
}

/**
 * @brief Byte-swap a schedule word (big-endian schedule to packed column).
 *
 * @param w Word to swap.
 * @return Byte-swapped word.
 */
static uint32_t aes_bswap32(uint32_t w)
{
    return (w >> 24U) | ((w >> 8U) & 0x0000FF00U) | ((w << 8U) & 0x00FF0000U) | (w << 24U);
}

/**
 * @brief Multiply each of four packed bytes by x in GF(2^8), without branches.
 *
 * @param x Four packed field elements.
 * @return Four packed products.
 */
static uint32_t aes_ct_xtime32(uint32_t x)
{
    uint32_t m = (x >> 7U) & 0x01010101U;
    return ((x & 0x7F7F7F7FU) << 1U) ^ (m << 4U) ^ (m << 3U) ^ (m << 1U) ^ m;
}

/**
 * @brief MixColumns on one packed column (row r in byte lane r).
 *
 * @param w Column word.
 * @return Mixed column word.
 */
static uint32_t aes_ct_mix_column(uint32_t w)
{
    uint32_t r1 = (w >> 8U) | (w << 24U);
    uint32_t a = w ^ r1;
    return aes_ct_xtime32(a) ^ r1 ^ ((a >> 16U) | (a << 16U));
}

/**
 * @brief InvMixColumns on one packed column.
 *
 * Uses the factorisation InvMixColumns = MixColumns o (a_i ^= 4(a_i ^ a_{i+2})).
 *
 * @param w Column word.
 * @return Inverse-mixed column word.
 */
static uint32_t aes_ct_inv_mix_column(uint32_t w)
{
    uint32_t u = aes_ct_xtime32(aes_ct_xtime32(w ^ ((w >> 16U) | (w << 16U))));
    return aes_ct_mix_column(w ^ u);
}

/**
 * @brief Constant-time AES block encryption with an expanded schedule.
 *
 * Table-free: SubBytes uses the bitsliced circuit, MixColumns uses masked
 * packed arithmetic, so no memory index or branch depends on key or data.
 *
 * @param round_keys Expanded round keys (big-endian words).
 * @param rounds Number of rounds (10, 12 or 14).
 * @param data Input block.
 * @param output Output block (may alias @p data).
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_block_encrypt_core(const uint32_t *round_keys,
                                                       uint8_t rounds,
                                                       const uint8_t *data,
                                                       uint8_t *output)
{
    uint32_t s[4];
    uint32_t t[4];
    uint32_t r = 0U;
    uint32_t c = 0U;

    for (c = 0U; c < 4U; c += 1U) {
        s[c] = aes_load_le32(&data[c * 4U]) ^ aes_bswap32(round_keys[c]);
    }
    for (r = 1U; r <= (uint32_t)rounds; r += 1U) {
        aes_ct_sub_bytes(s, 0U);
        /* ShiftRows: row m of column c comes from column c + m. */
        for (c = 0U; c < 4U; c += 1U) {
            t[c] = (s[c] & 0x000000FFU) |
                   (s[(c + 1U) & 3U] & 0x0000FF00U) |
                   (s[(c + 2U) & 3U] & 0x00FF0000U) |
                   (s[(c + 3U) & 3U] & 0xFF000000U);
        }
        for (c = 0U; c < 4U; c += 1U) {
            uint32_t col = (r < (uint32_t)rounds) ? aes_ct_mix_column(t[c]) : t[c];
            s[c] = col ^ aes_bswap32(round_keys[(r * 4U) + c]);
        }
    }
    for (c = 0U; c < 4U; c += 1U) {
        aes_store_le32(&output[c * 4U], s[c]);
    }
    noxtls_secure_zero(s, sizeof(s));
    noxtls_secure_zero(t, sizeof(t));
}

/**
 * @brief Constant-time AES block decryption with an expanded schedule.
 *
 * Straight inverse cipher over the encryption schedule.
 *
 * @param round_keys Expanded round keys (big-endian words).
 * @param rounds Number of rounds (10, 12 or 14).
 * @param data Input block.
 * @param output Output block (may alias @p data).
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_block_decrypt_core(const uint32_t *round_keys,
                                                       uint8_t rounds,
                                                       const uint8_t *data,
                                                       uint8_t *output)
{
    uint32_t s[4];
    uint32_t t[4];
    uint32_t r = 0U;
    uint32_t c = 0U;

    for (c = 0U; c < 4U; c += 1U) {
        s[c] = aes_load_le32(&data[c * 4U]) ^ aes_bswap32(round_keys[((uint32_t)rounds * 4U) + c]);
    }
    for (r = (uint32_t)rounds; r >= 1U; r -= 1U) {
        /* InvShiftRows: row m of column c comes from column c - m. */
        for (c = 0U; c < 4U; c += 1U) {
            t[c] = (s[c] & 0x000000FFU) |
                   (s[(c + 3U) & 3U] & 0x0000FF00U) |
                   (s[(c + 2U) & 3U] & 0x00FF0000U) |
                   (s[(c + 1U) & 3U] & 0xFF000000U);
        }
        aes_ct_sub_bytes(t, 1U);
        for (c = 0U; c < 4U; c += 1U) {
            uint32_t col = t[c] ^ aes_bswap32(round_keys[((r - 1U) * 4U) + c]);
            s[c] = (r > 1U) ? aes_ct_inv_mix_column(col) : col;
        }
    }
    for (c = 0U; c < 4U; c += 1U) {
        aes_store_le32(&output[c * 4U], s[c]);
    }
    noxtls_secure_zero(s, sizeof(s));
    noxtls_secure_zero(t, sizeof(t));
}
#else
/**
 * @brief Look up one byte in the AES S-box (table core only).
 *
 * @param x Input byte value.
 * @return S-box substitution for @p x.
 */
static uint8_t aes_sbox_lookup(uint8_t x)
{
    return aes_sub_box[(((uint32_t)x >> 4U) & 0x0FU)][x & 0x0FU];
}

/**
 * @brief Load a big-endian 32-bit word from a byte buffer.
 *
 * @param src Source buffer containing at least 4 bytes.
 * @return 32-bit word decoded from @p src.
 */
static uint32_t aes_load_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] <<24U) |
           ((uint32_t)src[1] <<16U) |
           ((uint32_t)src[2] <<8U) |
           (uint32_t)src[3];
}

/**
 * @brief Store a 32-bit word to a byte buffer in big-endian order.
 *
 * @param dst Destination buffer that receives 4 bytes.
 * @param word 32-bit word to encode.
 * @return None.
 */
static void aes_store_be32(uint8_t *dst, uint32_t word)
{
    dst[0] = (uint8_t)(word >>24U);
    dst[1] = (uint8_t)(word >>16U);
    dst[2] = (uint8_t)(word >>8U);
    dst[3] = (uint8_t)word;
}

/**
 * @brief Initialize table-driven AES encrypt round tables on first use.
 *
 * @param None.
 * @return None.
 */
static void aes_software_init_encrypt_tables(void)
{
#if !NOXTLS_AES_ROM_TABLES
    /* AES enc table ready flag (Rule 8.9). */
    static uint8_t aes_enc_tables_ready = 0U;


    uint32_t x = 0U;

    if (aes_enc_tables_ready != 0U) {
        return;
    }

    for (x = 0U; x < 256U; x += 1U) {
        uint8_t s = (uint8_t)(aes_sbox_lookup((uint8_t)x));
        uint8_t s2 = (uint8_t)(aes_xtime_byte(s));
        uint8_t s3 = (uint8_t)(s2 ^ s);
        uint32_t te0 = ((uint32_t)s2 <<24U) |
                       ((uint32_t)s <<16U) |
                       ((uint32_t)s <<8U) |
                       (uint32_t)s3;

        aes_enc_te0[x] = te0;
#if !NOXTLS_AES_COMPACT_TABLES
        aes_enc_te1[x] = (te0 >>8U) | (te0 <<24U);
        aes_enc_te2[x] = (te0 >>16U) | (te0 <<16U);
        aes_enc_te3[x] = (te0 >>24U) | (te0 <<8U);
#endif
    }

    aes_enc_tables_ready = 1U;
#endif
}

/**
 * @brief T-table AES block encryption with an expanded schedule.
 *
 * Indexes Te0..Te3 and the S-box with state bytes: not constant-time on CPUs
 * with data caches. Selected only with NOXTLS_AES_CONSTANT_TIME=0.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_block_encrypt_core(const uint32_t *round_keys,
                                                       uint8_t rounds,
                                                       const uint8_t *data,
                                                       uint8_t *output)
{
    uint32_t s0 = 0U;
    uint32_t s1 = 0U;
    uint32_t s2 = 0U;
    uint32_t s3 = 0U;
    uint32_t t0 = 0U;
    uint32_t t1 = 0U;
    uint32_t t2 = 0U;
    uint32_t t3 = 0U;
    uint8_t cur_round = 0U;

    s0 = aes_load_be32(data) ^ round_keys[0];
    s1 = aes_load_be32(&data[4]) ^ round_keys[1];
    s2 = aes_load_be32(&data[8]) ^ round_keys[2];
    s3 = aes_load_be32(&data[12]) ^ round_keys[3];

    for (cur_round = 1U; cur_round <= (uint8_t)(rounds - 1U); cur_round += 1U)
    {
        size_t rk = (size_t)cur_round * 4U;

        t0 = AES_TE0((s0 >>24U) & 0xFFU) ^
             AES_TE1((s1 >>16U) & 0xFFU) ^
             AES_TE2((s2 >>8U) & 0xFFU) ^
             AES_TE3(s3 & 0xFFU) ^
             round_keys[rk + 0U];
        t1 = AES_TE0((s1 >>24U) & 0xFFU) ^
             AES_TE1((s2 >>16U) & 0xFFU) ^
             AES_TE2((s3 >>8U) & 0xFFU) ^
             AES_TE3(s0 & 0xFFU) ^
             round_keys[rk + 1U];
        t2 = AES_TE0((s2 >>24U) & 0xFFU) ^
             AES_TE1((s3 >>16U) & 0xFFU) ^
             AES_TE2((s0 >>8U) & 0xFFU) ^
             AES_TE3(s1 & 0xFFU) ^
             round_keys[rk + 2U];
        t3 = AES_TE0((s3 >>24U) & 0xFFU) ^
             AES_TE1((s0 >>16U) & 0xFFU) ^
             AES_TE2((s1 >>8U) & 0xFFU) ^
             AES_TE3(s2 & 0xFFU) ^
             round_keys[rk + 3U];

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    t0 = ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s3) ^
         round_keys[((size_t)rounds * 4U) + 0U];
    t1 = ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s0) ^
         round_keys[((size_t)rounds * 4U) + 1U];
    t2 = ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s1) ^
         round_keys[((size_t)rounds * 4U) + 2U];
    t3 = ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s2) ^
         round_keys[((size_t)rounds * 4U) + 3U];

    (void)aes_store_be32(output, t0);
    (void)aes_store_be32(&output[4], t1);
    (void)aes_store_be32(&output[8], t2);
    (void)aes_store_be32(&output[12], t3);
}

static void aes_inv_sub_bytes(uint8_t state[4][4]);
static void aes_inv_shift_rows(uint8_t state[4][4]);
static void aes_inv_mix_columns(uint8_t state[4][4]);

/**
 * @brief Table AES block decryption with an expanded schedule.
 *
 * Indexes the inverse S-box with state bytes: not constant-time on CPUs with
 * data caches. Selected only with NOXTLS_AES_CONSTANT_TIME=0.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return None.
 */
static NOXTLS_AES_NOINLINE void aes_block_decrypt_core(const uint32_t *round_keys,
                                                       uint8_t rounds,
                                                       const uint8_t *data,
                                                       uint8_t *output)
{
    uint8_t state[4][4];
    int32_t cur_round = 0;

    (void)noxtls_aes_init_block(state, data);
    (void)noxtls_aes_add_round_key(state, &round_keys[(size_t)rounds * 4U]);

    for (cur_round = (int)rounds - 1; cur_round >= 1; cur_round -= 1)
    {
        (void)aes_inv_shift_rows(state);
        (void)aes_inv_sub_bytes(state);
        (void)noxtls_aes_add_round_key(state, &round_keys[(size_t)cur_round * 4U]);
        (void)aes_inv_mix_columns(state);
    }

    (void)aes_inv_shift_rows(state);
    (void)aes_inv_sub_bytes(state);
    (void)noxtls_aes_add_round_key(state, &round_keys[0]);
    (void)copy_state_to_buffer(&state[0][0], output);
    /* The final state is the plaintext block (for key unwrap: A || key bytes). */
    noxtls_secure_zero(state, sizeof(state));
}
#endif /* NOXTLS_AES_CONSTANT_TIME */

/* Mode entry points (ECB/CBC/CTR/CFB/OFB/XTS) are declared in noxtls_aes.h. */

/**
 * @brief Encrypt data with the selected AES mode.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Plaintext length in bytes.
 * @param iv Initialization vector or nonce for modes that require one.
 * @param output Output buffer for ciphertext.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_INVALID_MODE for unknown modes,
 *         NOXTLS_RETURN_NOT_SUPPORTED for disabled modes, or a mode-specific error code.
 */
noxtls_return_t noxtls_aes_encrypt_data(const uint8_t* key, 
                     const uint8_t* data, 
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output, 
                     noxtls_aes_type_t type,
                     noxtls_aes_mode_t mode)
{
    /* Route to appropriate mode-specific implementation */
    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            return noxtls_aes_encrypt_ecb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            return noxtls_aes_encrypt_cbc(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
            return noxtls_aes_encrypt_ctr(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
            return noxtls_aes_encrypt_cfb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
            return noxtls_aes_encrypt_ofb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_XTS:
#if NOXTLS_FEATURE_AES_XTS
            return noxtls_aes_encrypt_xts(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_GCM:
            /* AES-GCM requires tag handling; use noxtls_aes_gcm_encrypt() directly. */
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_MODE; /* Unknown mode */
    }
    }
}

/**
 * @brief Map an AES key size selector to round-count and key-layout metadata.
 *
 * @param type AES key size selector.
 * @param rounds Output number of AES rounds for @p type.
 * @param key_words Output number of 32-bit key words for @p type.
 * @param key_len Output key length in bytes for @p type.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t aes_type_params(noxtls_aes_type_t type, uint8_t *rounds, uint8_t *key_words, uint8_t *key_len)
{
    if ((rounds == NULL) || (key_words == NULL) || (key_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        /* Widen so a defensive default remains reachable (Rule 2.1). */
        uint32_t type_u = (uint32_t)type;
        switch (type_u)
        {
        case (uint32_t)NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            *rounds = NOXTLS_AES_128_ROUNDS;
            *key_words = 4;
            *key_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            *rounds = NOXTLS_AES_192_ROUNDS;
            *key_words = 6;
            *key_len = 24U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            *rounds = NOXTLS_AES_256_ROUNDS;
            *key_words = 8;
            *key_len = 32U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
        }
    }
}

/**
 * @brief Prepare an AES context with key metadata and expanded round keys.
 *
 * @param ctx AES context to populate.
 * @param key AES key bytes for the selected key size.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_prepare_context(noxtls_aes_context_t *ctx, const uint8_t *key, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t rounds = 0U;
    uint8_t key_words = 0U;
    uint8_t key_len = 0U;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = aes_type_params(type, &rounds, &key_words, &key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->rounds = rounds;
    ctx->type = (uint8_t)type;
#if NOXTLS_AES_CTX_RAW_KEY
    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)(key_len));
#endif
#if NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
#if !NOXTLS_AES_CONSTANT_TIME
    (void)aes_software_init_encrypt_tables();
#endif
    rc = noxtls_aes_key_expansion(key, ctx->round_keys, (int)key_words, (int)rounds);
#if NOXTLS_AES_STACK_BURN
    aes_stack_burn(); /* the expansion frame held schedule words in scalars */
#endif
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }
    ctx->round_keys_ready = 1U;
#else
    ctx->round_keys_ready = 0U;
#endif
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Increment a 128-bit AES counter block in big-endian order.
 *
 * @param counter Counter block to increment in place.
 * @return None.
 */
static void aes_counter_inc(uint8_t counter[NOXTLS_AES_BLOCK_LENGTH])
{
    int32_t i = 0;
    for (i = (int)NOXTLS_AES_BLOCK_LENGTH - 1; i >= 0; i -= 1) {
        counter[i] = (uint8_t)(counter[i] + 1U);
        if (counter[i] != 0U) {
            break;
        }
    }
}

/**
 * @brief Initialize AES feedback state with a required IV.
 *
 * @param iv Initialization vector of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param ctx AES context whose feedback state is initialized.
 * @return NOXTLS_RETURN_SUCCESS on success or NOXTLS_RETURN_INVALID_PARAM when iv is NULL.
 */
static noxtls_return_t aes_init_iv_required(const uint8_t *iv, noxtls_aes_context_t *ctx)
{
    if (iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
    ctx->partial_len = NOXTLS_AES_BLOCK_LENGTH;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize an AES streaming context for the selected mode.
 *
 * @param ctx AES context to initialize.
 * @param key AES key bytes for the selected key size.
 * @param iv Initialization vector, nonce, or feedback block for the selected mode.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @param op AES encrypt/decrypt operation selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_init(noxtls_aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             noxtls_aes_type_t type,
             noxtls_aes_mode_t mode,
             noxtls_aes_operation_t op)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    ctx->mode = (uint8_t)mode;
    ctx->op = (uint8_t)op;
    rc = noxtls_aes_prepare_context(ctx, key, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }

    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            break;
#else
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            if (iv != NULL) {
                noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
            } else {
                /* MISRA 15.7: final else path */
                noxtls_secure_zero((ctx->feedback), (size_t)(NOXTLS_AES_BLOCK_LENGTH));
            }
            break;
#else
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                /* The schedule is already in ctx: do not leave it behind. */
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return ir;
            }
        }
            break;
#else
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                /* The schedule is already in ctx: do not leave it behind. */
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return ir;
            }
        }
            break;
#else
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                /* The schedule is already in ctx: do not leave it behind. */
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return ir;
            }
        }
            break;
#else
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_INVALID_MODE;
    }
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update AES context with input data and produce output.
 *
 * @param ctx AES context.
 * @param input Input data buffer.
 * @param input_len Input data length in bytes.
 * @param output Output buffer.
 * @param output_len Output length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_INITIALIZED for uninitialized context,
 *         NOXTLS_RETURN_INVALID_BLOCK_SIZE for invalid block size,
 *         or NOXTLS_RETURN_INVALID_MODE for unknown mode.
 */
noxtls_return_t noxtls_aes_update(noxtls_aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len)
{
    uint32_t produced = 0U;
    uint32_t output_span = 0U;
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

    if ((ctx->partial_len > NOXTLS_AES_BLOCK_LENGTH) ||
        (in_left > (UINT32_MAX - (uint32_t)ctx->partial_len))) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    /* The API permits complete buffered block output in addition to input.
     * Round block modes down before wiping; stream modes produce input_len. */
    if (((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_ECB) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CBC)) {
        output_span = ((in_left + (uint32_t)ctx->partial_len) / NOXTLS_AES_BLOCK_LENGTH) * NOXTLS_AES_BLOCK_LENGTH;
    } else {
        output_span = in_left;
    }

    if (((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_ECB) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CBC)) {
            while (in_left > 0U) {
                uint32_t need = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (uint32_t)((in_left < need) ? in_left : need);
                noxtls_copy_u8(&ctx->partial[ctx->partial_len], sizeof(ctx->partial) - (size_t)(ctx->partial_len), in_ptr, (size_t)(take));
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                in_ptr = &in_ptr[take];
                in_left -= take;

                if (ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_ECB) {
                        if ((noxtls_aes_operation_t)ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            noxtls_return_t r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->partial, &output[produced]);
                            if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            }
                        } else {
                            /* MISRA 15.7: final else path */
                            noxtls_return_t r = noxtls_aes_decrypt_block_ctx_internal(ctx, ctx->partial, &output[produced]);
                            if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            }
                        }
                    } else {
                        if ((noxtls_aes_operation_t)ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            { noxtls_return_t r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, &output[produced]);
                            noxtls_secure_zero(block, sizeof(block)); /* plaintext ^ IV */
                            if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            } }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), &output[produced], (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                        } else {
                            /* MISRA 15.7: final else path */
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            { noxtls_return_t r = noxtls_aes_decrypt_block_ctx_internal(ctx, ctx->partial, block);
                            if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(block, sizeof(block));
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            } }
                            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            noxtls_secure_zero(block, sizeof(block)); /* plaintext ^ IV */
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                        }
                    }

                    produced += NOXTLS_AES_BLOCK_LENGTH;
                    ctx->partial_len = 0U;
                }
            }
    } else if (((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CTR) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CFB) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_OFB)) {
            while (in_left > 0U) {
                if (ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    noxtls_return_t r = NOXTLS_RETURN_FAILED;
                    if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CTR) {
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            }
                        (void)aes_counter_inc(ctx->feedback);
                    } else if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CFB) {
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            }
                    } else {
                        /* MISRA 15.7: final else path */
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) {
                                noxtls_secure_zero(output, (size_t)output_span);
                                noxtls_secure_zero(ctx, sizeof(*ctx));
                                return r;
                            }
                        noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                    }
                    ctx->partial_len = 0U;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (uint32_t)((in_left < available) ? in_left : available);
                    for (i = 0U; i < take; i += 1U) {
                        uint8_t in_byte = in_ptr[i]; /* read before output may overwrite it (in-place) */
                        uint8_t out_byte = (uint8_t)(in_byte ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CFB) {
                            noxtls_move_u8(ctx->feedback, sizeof(ctx->feedback), &ctx->feedback[1], (size_t)(NOXTLS_AES_BLOCK_LENGTH - 1U));
                            ctx->feedback[NOXTLS_AES_BLOCK_LENGTH - 1U] = ((noxtls_aes_operation_t)ctx->op == NOXTLS_AES_OP_ENCRYPT) ? out_byte : in_byte;
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
 * @brief Finalize AES streaming operation and flush buffered data.
 *
 * @param ctx AES context.
 * @param output Output buffer for any final bytes.
 * @param output_len Bytes produced in finalization.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_INITIALIZED for uninitialized context,
 *         or NOXTLS_RETURN_INVALID_BLOCK_SIZE for invalid block size.
 */
noxtls_return_t noxtls_aes_final(noxtls_aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len)
{
    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        /* A context left by a failed init or update may still hold a schedule. */
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CTR) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CFB) || ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_OFB)) {
        noxtls_secure_zero(ctx, sizeof(*ctx)); /* done: drop key schedule and feedback */
        return NOXTLS_RETURN_SUCCESS;
    }

    if ((noxtls_aes_operation_t)ctx->op == NOXTLS_AES_OP_DECRYPT) {
        if (ctx->partial_len != 0U) {
            /* Truncated ciphertext ends the operation: drop the schedule. */
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        noxtls_secure_zero(ctx, sizeof(*ctx)); /* done: drop key schedule and feedback */
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->partial_len > 0U) {
        uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
        uint32_t i = 0U;
        noxtls_return_t r = NOXTLS_RETURN_FAILED;

        if (output == NULL) {
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_NULL;
        }

        noxtls_secure_zero((block), sizeof(block));
        noxtls_copy_u8(block, sizeof(block), ctx->partial, (size_t)(ctx->partial_len));

        if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_ECB) {
            r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, output);
            if (r != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(block, sizeof(block));
                noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return r;
            }
        } else if ((noxtls_aes_mode_t)ctx->mode == NOXTLS_AES_CBC) {
            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                block[i] ^= ctx->feedback[i];
            }
            r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, output);
            if (r != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(block, sizeof(block));
                noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return r;
            }
        } else {
             /* MISRA 15.7: final else path */
            noxtls_secure_zero(block, sizeof(block));
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return NOXTLS_RETURN_INVALID_MODE;
        }
        noxtls_secure_zero(block, sizeof(block));

        *output_len = NOXTLS_AES_BLOCK_LENGTH;
    }

    noxtls_secure_zero(ctx, sizeof(*ctx)); /* done: drop key schedule and feedback */
    return NOXTLS_RETURN_SUCCESS;
}
    
/**
 * @brief Wipe an AES streaming context without finishing the operation.
 *
 * @param ctx AES context to wipe (NULL is ignored).
 * @return None.
 */
void noxtls_aes_free(noxtls_aes_context_t *ctx)
{
    if (ctx != NULL) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
}

/**
 * @brief Initialize Block
 * @internal
 *
 * @param state is the AES state
 * @param data is a pointer to the data to put in the state
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_init_block(uint8_t state[4][4], const uint8_t* data)
{
    uint32_t col = 0U;
    uint32_t row = 0U;

    if ((state == NULL) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (col = 0U; col < 4U; col += 1U)
    {
        for (row = 0U; row < 4U; row += 1U)
        {
            state[row][col] = data[row + (col * 4U)];
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief AES Encrypt Block
 * @internal
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192.256
 *
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    rc = noxtls_aes_accel_port_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif

#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software(key, data, output, type);
#endif
}

/**
 * @brief Encrypt one AES block using a prepared AES context.
 *
 * @param ctx Prepared AES context containing expanded round keys.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_ctx_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

#if NOXTLS_AES_CTX_RAW_KEY
    rc = noxtls_aes_accel_port_encrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_encrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_encrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

noxtls_return_t noxtls_aes_encrypt_block_ctx_software_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

/**
 * @brief Report the AES block backend selected for the current build.
 *
 * @return NOXTLS_AES_ACCEL_BACKEND_PORT when a platform AES backend is enabled,
 *         NOXTLS_AES_ACCEL_BACKEND_NI when AES-NI is compiled in,
 *         NOXTLS_AES_ACCEL_BACKEND_APPLE when ARMv8 AES is compiled in,
 *         or NOXTLS_AES_ACCEL_BACKEND_SOFTWARE otherwise.
 */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void)
{
#if NOXTLS_PORT_AES_ACCEL
    return NOXTLS_AES_ACCEL_BACKEND_PORT;
#elif NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    return NOXTLS_AES_ACCEL_BACKEND_NI;
#elif NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    return NOXTLS_AES_ACCEL_BACKEND_APPLE;
#else
    return NOXTLS_AES_ACCEL_BACKEND_SOFTWARE;
#endif
}

/**
 * @brief Encrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_SUPPORTED for disabled key sizes, or
 *         NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
static noxtls_return_t noxtls_aes_encrypt_block_software(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type)
{
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0U;
    uint8_t key_words = 0U;
    uint8_t key_length = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = aes_type_params(type, &rounds, &key_words, &key_length);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_aes_key_expansion(key, w, (int)key_words, (int)rounds);
#if NOXTLS_AES_STACK_BURN
    aes_stack_burn(); /* the expansion frame held schedule words in scalars */
#endif
    if (rc == NOXTLS_RETURN_SUCCESS) {
#if !NOXTLS_AES_CONSTANT_TIME
        (void)aes_software_init_encrypt_tables();
#endif
        rc = noxtls_aes_encrypt_block_software_expanded(w, rounds, data, output);
    }
    /* Key-based entry point: the schedule is rebuilt per call and never kept. */
    noxtls_secure_zero(w, sizeof(w));
    return rc;
}

/**
 * @brief Encrypt one AES block with pre-expanded software round keys.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_encrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output)
{
    if ((round_keys == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    aes_block_encrypt_core(round_keys, rounds, data, output);
#if NOXTLS_AES_STACK_BURN
    aes_stack_burn_block();
#endif
    return NOXTLS_RETURN_SUCCESS;
}

    
/**
 * @brief Adds round key
 * @internal
 *
 * @param state is the current state
 * @param w is the key for this round from the key expansion
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_add_round_key(uint8_t state[4][4], const uint32_t * w)
{
    uint8_t row = 0U;

    if ((state == NULL) || (w == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (row = 0U; row < 4U; row += 1U)
    {
        uint32_t val1 = ((uint32_t)state[0][row] <<24U) |
                        ((uint32_t)state[1][row] <<16U) |
                        ((uint32_t)state[2][row] <<8U) |
                        (uint32_t)state[3][row];
        
        
        uint32_t temp = (uint32_t)(val1 ^ w[row]);
        
        
        state[0][row] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[1][row] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[2][row] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[3][row] = (uint8_t)(temp & 0x000000FFU);
        
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Performs AES Key expansion
 * @internal
 *
 * Uses AES provided key to generate the key schedules used to mix with the
 * state
 * @param key AES key bytes.
 * @param w Output key schedule words.
 * @param nk Number of 32-bit words in the AES key.
 * @param rounds Number of AES rounds for the selected key size.
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_aes_key_expansion(const uint8_t * key, uint32_t * w, int nk, int rounds)
{
    uint32_t i = 0U;
    uint32_t nk_u = 0U;
    uint32_t rounds_u = 0U;

    if ((key == NULL) || (w == NULL) || (nk <= 0) || (rounds <= 0)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    nk_u = (uint32_t)nk;
    rounds_u = (uint32_t)rounds;

    for (i = 0U; i < nk_u; i += 1U)
    {
        size_t off = (size_t)i * 4U;
        w[i] = ((uint32_t)key[off] <<24U) |
               ((uint32_t)key[off + 1U] <<16U) |
               ((uint32_t)key[off + 2U] <<8U) |
               (uint32_t)key[off + 3U];
    }

    for (i = nk_u; i < (4U * (rounds_u + 1U)); i += 1U)
    {
        uint32_t temp = (uint32_t)(w[i - 1U]);
        if ((i % nk_u) == 0U)
        {
            uint32_t arot = (uint32_t)(aes_rotword(temp));
            uint32_t asub = (uint32_t)(aes_subword(arot));
            temp = asub ^ rcon((uint8_t)(i / nk_u));
        }
        else if ((nk_u > 6U) && ((i % nk_u) == 4U))
        {
            temp = aes_subword(temp);
        }
        else {
            /* MISRA 15.7: no remaining alternative */
        }
        w[i] = w[i - nk_u] ^ temp;
    }
#if NOXTLS_AES_STACK_BURN
    /* aes_subword() frames held S-box inputs and outputs (key words). */
    aes_stack_burn();
#endif

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Calculate the rcon used in key expansion
 * @internal

 * @param in is the parameter on which to calculate RCON
 *
 * @return RCON word for the requested key-expansion round.
 */
static uint32_t rcon(uint8_t in)
{
    uint8_t rounds = in;
    unsigned char c = 1;
    if (rounds == 0U) {
        return 0U;
    }
    while (rounds != 1U) {
        unsigned char b;
        b = c & 0x80U;
        c <<= 1U;
        if (b == 0x80U) {
            c ^= 0x1bU;
        }
        rounds -= 1U;
    }
    return ((uint32_t)c <<24U);
}

/**
 * @brief Rotate Word
 * @internal
 *
 * @param w is the word to rotate
 *
 * @return Rotated AES key schedule word.
 */
static uint32_t aes_rotword(uint32_t w)
{
    uint32_t word = 0U;

    word = w <<8U;
    word |= ((w & 0xFF000000U) >>24U);

    return word;
}

/**
 * @brief Finds the subword 
 * @internal
 *
 * @param w is the word to sub
 *
 * @return the subword
 */
static uint32_t aes_subword(uint32_t w)
{
    /* Constant-time S-box: key expansion indexes no table with key bytes. */
    uint32_t s[4];
    uint32_t word = 0U;

    s[0] = w;
    s[1] = 0U;
    s[2] = 0U;
    s[3] = 0U;
    aes_ct_sub_bytes(s, 0U);
    word = s[0];
    noxtls_secure_zero(s, sizeof(s));
    return word;
}

/**
 * @brief Perform AES Sub bytes
 * @internal
 *
 * @param state is the current AES state
 *
 * @return None.
 */
void noxtls_aes_sub_bytes(uint8_t state[4][4])
{
    uint32_t s[4];
    uint32_t i = 0U;
    uint32_t j = 0U;

    if (state == NULL) {
        return;
    }
    for (i = 0U; i < 4U; i += 1U)
    {
        s[i] = (uint32_t)state[i][0] |
               ((uint32_t)state[i][1] << 8U) |
               ((uint32_t)state[i][2] << 16U) |
               ((uint32_t)state[i][3] << 24U);
    }
    aes_ct_sub_bytes(s, 0U);
    for (i = 0U; i < 4U; i += 1U)
    {
        for (j = 0U; j < 4U; j += 1U)
        {
            state[i][j] = (uint8_t)(s[i] >> (j * 8U));
        }
    }
    noxtls_secure_zero(s, sizeof(s));
}
    

/**
 * @brief Shift Rows
 * @internal
 *
 * @param state is the state to print
 *
 * @return None.
 */
void noxtls_aes_shift_rows(uint8_t state[4][4])
{
    /* Shift second row by one,
     Shift third row by two
     Shift fourth row by three */
    uint32_t row = 0U;

    for (row = 1U; row < 4U; row += 1U)
    {
        
        uint32_t val1 = ((uint32_t)state[row][0] <<24U) |
                        ((uint32_t)state[row][1] <<16U) |
                        ((uint32_t)state[row][2] <<8U) |
                        (uint32_t)state[row][3];
                
        uint32_t temp = 0U;
            switch(row) {
            case 0U: temp = val1; break;
            case 1U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 8U)); break;
            case 2U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 16U)); break;
            case 3U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 24U)); break;
            default: temp = val1; break;
            }
        
        state[row][0] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[row][1] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[row][2] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[row][3] = (uint8_t)(temp & 0x000000FFU);
    }
}

/**
 * @brief AES Mix Columns
 * @internal
 *
 * @param state is the state to print
 *
 * @return None.
 */
void noxtls_aes_mix_columns(uint8_t state[4][4])
{
    uint8_t a[4];
    uint8_t b[4];
    uint32_t i = 0U;
    uint32_t j = 0U;

    // row x col
    /* Iterate through all columns*/
    for (j = 0U; j < 4U; j += 1U)
    {

        for (i = 0U; i < 4U; i += 1U)
        {
            a[i] = state[i][j];
            b[i] = aes_xtime_byte(state[i][j]);
        }

        state[0][j] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        state[1][j] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        state[2][j] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        state[3][j] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

#if !NOXTLS_AES_CONSTANT_TIME
/**
 * @brief Perform AES Inverse Sub bytes
 * @internal
 *
 * @param state is the current AES state
 *
 * @return None.
 */
static void aes_inv_sub_bytes(uint8_t state[4][4])
{
    /* AES inv S-box (Rule 8.9). */
    /** AES Inverse Substitution Box */
    static const uint8_t aes_inv_sub_box[16][16] =
    {
        {0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U, 0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU},
        {0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U, 0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU},
        {0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU, 0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU},
        {0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U, 0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U},
        {0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, 0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U},
        {0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU, 0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U},
        {0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU, 0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U},
        {0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U, 0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU},
        {0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU, 0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U},
        {0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U, 0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU},
        {0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U, 0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU},
        {0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U, 0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U},
        {0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U, 0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU},
        {0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU, 0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU},
        {0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U, 0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U},
        {0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U, 0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU}
    };


    uint32_t i = 0U;
    uint32_t j = 0U;
    uint8_t row = 0U;
    uint8_t col = 0U;
    for (i = 0U; i < 4U; i += 1U)
    {
        for (j = 0U; j < 4U; j += 1U)
        {
            row = (state[i][j] & 0xF0U) >>4U;
            col = (state[i][j] & 0x0FU);
            state[i][j] = aes_inv_sub_box[row][col];
        }
    }
}

/**
 * @brief Inverse Shift Rows
 * @internal    
 *
 * @param state is the state to shift
 *
 * @return None.
 */
static void aes_inv_shift_rows(uint8_t state[4][4])
{
    /* Inverse shift: second row by one right, third by two, fourth by three */
    uint32_t row = 0U;   

    for (row = 1U; row < 4U; row += 1U)
    {
        uint32_t val1 = ((uint32_t)state[row][0] <<24U) | ((uint32_t)state[row][1] <<16U) |
                        ((uint32_t)state[row][2] <<8U) | (uint32_t)state[row][3];
        uint32_t temp = 0U;
            switch(row) {
            case 0U: temp = val1; break;
            case 1U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 8U)); break;
            case 2U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 16U)); break;
            case 3U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 24U)); break;
            default: temp = val1; break;
            }
        
        state[row][0] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[row][1] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[row][2] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[row][3] = (uint8_t)(temp & 0x000000FFU);
    }
}

/**
 * @brief AES Galois Field Multiply
 * @internal
 *
 * @param a is the first operand
 * @param b is the second operand
 *
 * @return the result of the multiplication
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Multiply two AES field elements in GF(2^8).
 *
 * @param a First field element.
 * @param b Second field element.
 * @return Product of @p a and @p b in the AES field.
 */
static uint8_t aes_gf_mul(uint8_t a, uint8_t b)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    /* Masks instead of branches: a carries secret state bytes, and Cortex-M0+
     * compiles a conditional reduction to a data-dependent branch. */
    uint8_t aa = a;
    uint8_t bb = b;
    uint8_t p = 0U;
    for (uint32_t i = 0U; i < 8U; i += 1U) {
        uint8_t take = (uint8_t)(0U - (uint32_t)(bb & 1U));
        p ^= (uint8_t)(aa & take);
        aa = aes_xtime_byte(aa);
        bb >>= 1U;
    }
    return p;
}

/**
 * @brief AES Inverse Mix Columns
 * @internal
 *
 * @param state is the state to mix
 *
 * @return None.
 */
static void aes_inv_mix_columns(uint8_t state[4][4])
{
    for (uint32_t j = 0U; j < 4U; j += 1U) {
        uint8_t a0 = (uint8_t)(state[0][j]);
        uint8_t a1 = (uint8_t)(state[1][j]);
        uint8_t a2 = (uint8_t)(state[2][j]);
        uint8_t a3 = (uint8_t)(state[3][j]);

        state[0][j] = (uint8_t)(aes_gf_mul(a0, 0x0EU) ^ aes_gf_mul(a1, 0x0BU) ^
                                 aes_gf_mul(a2, 0x0DU) ^ aes_gf_mul(a3, 0x09U));
        state[1][j] = (uint8_t)(aes_gf_mul(a0, 0x09U) ^ aes_gf_mul(a1, 0x0EU) ^
                                 aes_gf_mul(a2, 0x0BU) ^ aes_gf_mul(a3, 0x0DU));
        state[2][j] = (uint8_t)(aes_gf_mul(a0, 0x0DU) ^ aes_gf_mul(a1, 0x09U) ^
                                 aes_gf_mul(a2, 0x0EU) ^ aes_gf_mul(a3, 0x0BU));
        state[3][j] = (uint8_t)(aes_gf_mul(a0, 0x0BU) ^ aes_gf_mul(a1, 0x0DU) ^
                                 aes_gf_mul(a2, 0x09U) ^ aes_gf_mul(a3, 0x0EU));
    }
}

#endif /* !NOXTLS_AES_CONSTANT_TIME */

/**
 * @brief AES Decrypt Block
 * @internal
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param output is the output buffer where the decrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 *
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    rc = noxtls_aes_accel_port_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif

#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_decrypt_block_software(key, data, output, type);
#endif
}

/**
 * @brief Decrypt one AES block using a prepared AES context.
 *
 * @param ctx Prepared AES context containing expanded round keys.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_block_ctx_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

#if NOXTLS_AES_CTX_RAW_KEY
    rc = noxtls_aes_accel_port_decrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_decrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_decrypt_block(ctx->key, data, output, (noxtls_aes_type_t)ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(output, NOXTLS_AES_BLOCK_LENGTH);
        return rc;
    }
#endif

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_decrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

/**
 * @brief Decrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED for disabled key sizes,
 *         or NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Decrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0U;
    uint8_t key_words = 0U;
    uint8_t key_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = aes_type_params(type, &rounds, &key_words, &key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_aes_key_expansion(key, w, (int)key_words, (int)rounds);
#if NOXTLS_AES_STACK_BURN
    aes_stack_burn(); /* the expansion frame held schedule words in scalars */
#endif
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_aes_decrypt_block_software_expanded(w, rounds, data, output);
    }
    noxtls_secure_zero(w, sizeof(w));
    return rc;
}

/**
 * @brief Decrypt one AES block with pre-expanded software round keys.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_decrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output)
{
    if ((round_keys == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    aes_block_decrypt_core(round_keys, rounds, data, output);
#if NOXTLS_AES_STACK_BURN
    aes_stack_burn_block();
#endif
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_AES */
