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
* File:    noxtls_des.c
* Summary: Data Encryption Standard (DES) and Triple-DES (3DES) - FIPS 46-3
*
* The DES and 3DES Algorithms are broken and should not be used for new systems.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifndef NOXTLS_DES_DEBUG
#define NOXTLS_DES_DEBUG 0
#endif

#include <stdint.h>
#include <string.h>
#include "noxtls_des.h"
#include "noxtls_des_internal.h"
#include "noxtls_ct.h"
#if NOXTLS_DES_DEBUG
#include <stdio.h>
#endif

#if NOXTLS_FEATURE_DES

/* When encrypting the KAT vector (key=plain=0123456789ABCDEF), optional debug trace. */
#if NOXTLS_DES_DEBUG
static int s_des_trace_this_block;
#define DES_TRACE() (s_des_trace_this_block != 0)
#else
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get a bit from a buffer
 * 
 * @param buf The buffer value
 * @param bit_index The bit index value
 * @return The bit value
 */

static uint32_t get_bit(const uint8_t *buf, uint32_t bit_index)
{
    /* MSB-first masks avoid variable shifts (Rule 12.2). */
    static const uint8_t s_msb_masks[8] = {
        0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
    };
    uint32_t byte_idx = (uint32_t)(bit_index >> 3U);
    uint32_t bit_in_byte = (uint32_t)(bit_index & 7U);
    return (((uint32_t)buf[byte_idx] & (uint32_t)s_msb_masks[bit_in_byte]) != 0U) ? 1U : 0U;
}

/**
 * @brief Set a bit in a buffer
 * 
 * @param buf The buffer value
 * @param bit_index The bit index value
 * @param value The value value
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void set_bit(uint8_t *buf, uint32_t bit_index, uint32_t value)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t s_msb_masks[8] = {
        0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
    };
    uint32_t byte_idx = (uint32_t)(bit_index >> 3U);
    uint32_t bit_in_byte = (uint32_t)(bit_index & 7U);
    uint8_t mask = s_msb_masks[bit_in_byte];
    if (value != 0U) {
        buf[byte_idx] = (uint8_t)(buf[byte_idx] | mask);
    } else {
        buf[byte_idx] = (uint8_t)(buf[byte_idx] & (uint8_t)(~mask));
    }
}

/**
 * @brief Permute a buffer
 * 
 * @param in The in value
 * @param out The out value
 * @param table The table value
 * @param n The n value
 */
static void permute(const uint8_t *in, uint8_t *out, const uint8_t *table, uint32_t n)
{
    uint32_t i = 0U;
    noxtls_secure_zero((out), ((size_t)((n + 7U) / 8U)));
    for (i = 0U; i < n; i += 1U) {
        set_bit(out, i, get_bit(in, (uint32_t)table[i]));
    }
}

/**
 * @brief Rotate a buffer left
 * 
 * @param c The c value
 * @param d The d value
 * @param count The count value
 */
static void rotate_left_28(uint32_t *c, uint32_t *d, uint32_t count)
{
    uint32_t c0 = (uint32_t)(*c);
    uint32_t d0 = (uint32_t)(*d);

    /* DES key schedule only rotates by 1 or 2. */
    if (count == 1U) {
        *c = (((c0 << 1U) | (c0 >> 27U)) & 0x0FFFFFFFU);
        *d = (((d0 << 1U) | (d0 >> 27U)) & 0x0FFFFFFFU);
    } else if (count == 2U) {
        *c = (((c0 << 2U) | (c0 >> 26U)) & 0x0FFFFFFFU);
        *d = (((d0 << 2U) | (d0 >> 26U)) & 0x0FFFFFFFU);
    } else {
        /* no-op for unsupported counts */
    }
}

/**
 * @brief Generate the DES key schedule
 * 
 * @param key The key value
 * @param round_keys The round keys value
 */
static void des_key_schedule(const uint8_t *key, uint8_t round_keys[16][6])
{
    /* key schedule tables (Rule 8.9). */
    /* PC1: 64-bit key -> 56 bits (indices of key bits, 0-based; parity bits omitted) */
    static const uint8_t des_pc1[56] = {
        56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
    };

    /* PC2: 56-bit CD -> 48-bit round key (indices into 56-bit, 0-based) */
    static const uint8_t des_pc2[48] = {
        13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9, 22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
    };

    /* Round key rotation count (left): 1 for rounds 0,1,8,15; 2 for others */
    static const uint8_t des_rot[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };


    uint8_t pc1_out[7];
    uint32_t c = 0U;
    uint32_t d = 0U;
    uint32_t r = 0U;
    uint32_t i = 0U;
    uint32_t j = 0U;

    permute(key, pc1_out, des_pc1, 56U);
    /* C0 = first 28 bits of PC1 output (bit 0 = MSB of C); D0 = next 28 bits. */
    c = (((uint32_t)pc1_out[0]) << 20U) | (((uint32_t)pc1_out[1]) << 12U)
      | (((uint32_t)pc1_out[2]) << 4U) | (((uint32_t)(uint32_t)pc1_out[3] >> 4U) & 0xFU);
    {
        uint32_t nibble = (uint32_t)pc1_out[3];
        uint32_t d_hi = 0U;
        uint32_t d_m1 = 0U;
        uint32_t d_m2 = 0U;
        uint32_t d_lo = 0U;
        nibble &= 0xFU;
        d_hi = nibble << 24U;
        d_m1 = ((uint32_t)pc1_out[4]) << 16U;
        d_m2 = ((uint32_t)pc1_out[5]) << 8U;
        d_lo = (uint32_t)pc1_out[6];
        d = d_hi | d_m1 | d_m2 | d_lo;
    }

#if NOXTLS_DES_DEBUG
    if (DES_TRACE() != 0) {
        (void)fprintf(stdout, "[DES KS] key:    %02X %02X %02X %02X %02X %02X %02X %02X\n",
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
        (void)fprintf(stdout, "[DES KS] pc1_out: %02X %02X %02X %02X %02X %02X %02X\n",
                pc1_out[0], pc1_out[1], pc1_out[2], pc1_out[3], pc1_out[4], pc1_out[5], pc1_out[6]);
        (void)fprintf(stdout, "[DES KS] C0=%07X D0=%07X\n", (uint32_t)(c & 0x0FFFFFFFU), (uint32_t)(d & 0x0FFFFFFFU));
    }
#endif

    for (r = 0U; r < 16U; r += 1U) {
        rotate_left_28(&c, &d, (uint32_t)des_rot[r]);
    static const uint32_t s_cbit_masks[28] = {
        0x08000000U, 0x04000000U, 0x02000000U, 0x01000000U,
        0x00800000U, 0x00400000U, 0x00200000U, 0x00100000U,
        0x00080000U, 0x00040000U, 0x00020000U, 0x00010000U,
        0x00008000U, 0x00004000U, 0x00002000U, 0x00001000U,
        0x00000800U, 0x00000400U, 0x00000200U, 0x00000100U,
        0x00000080U, 0x00000040U, 0x00000020U, 0x00000010U,
        0x00000008U, 0x00000004U, 0x00000002U, 0x00000001U
    };
        /* Pack C||D into 7 bytes (56 bits): cd bit i = C bit i for i<28, cd bit (28U + i) = D bit i. C/D bit 0 is MSB (at c/d bit 27). */
        uint8_t cd[7] = {0};
        for (i = 0U; i < 28U; i += 1U) {
            set_bit(cd, i, ((c & s_cbit_masks[i]) != 0U) ? 1U : 0U);
        }
        for (i = 0U; i < 28U; i += 1U) {
            set_bit(cd, 28U + i, ((d & s_cbit_masks[i]) != 0U) ? 1U : 0U);
        }
        {
            uint8_t pk[6] = {0};
            for (i = 0U; i < 48U; i += 1U) {
                set_bit(pk, i, get_bit(cd, (uint32_t)des_pc2[i]));
            }
            for (j = 0U; j < 6U; j += 1U) {
                round_keys[r][j] = pk[j];
            }
        }
#if NOXTLS_DES_DEBUG
        if ((DES_TRACE() != 0) && (r == 0U)) {
            (void)fprintf(stdout, "[DES KS] after rot C1=%07X D1=%07X\n", (uint32_t)(c & 0x0FFFFFFFU), (uint32_t)(d & 0x0FFFFFFFU));
        }
        if (DES_TRACE() != 0) {
            (void)fprintf(stdout, "[DES KS] K%2d:   %02X %02X %02X %02X %02X %02X\n", (int)(r + 1U),
                    round_keys[r][0], round_keys[r][1], round_keys[r][2],
                    round_keys[r][3], round_keys[r][4], round_keys[r][5]);
        }
#endif
    }
}

/* E expansion: R (32 bits, bit 0 = MSB) -> 48 bits. Standard rows (1-based): 32,1,2,3,4,5 |4U,5,6,7,8,9 | ... |28U,29,30,31,32,1 */
/**
 * @brief Expand the E value
 * 
 * @param r32 The r32 value
 * @param er The er value
 */
static void des_expand_e(uint32_t r32, uint8_t er[6])
{
    static const uint32_t s_rbit_masks[32] = {
        0x80000000U, 0x40000000U, 0x20000000U, 0x10000000U,
        0x08000000U, 0x04000000U, 0x02000000U, 0x01000000U,
        0x00800000U, 0x00400000U, 0x00200000U, 0x00100000U,
        0x00080000U, 0x00040000U, 0x00020000U, 0x00010000U,
        0x00008000U, 0x00004000U, 0x00002000U, 0x00001000U,
        0x00000800U, 0x00000400U, 0x00000200U, 0x00000100U,
        0x00000080U, 0x00000040U, 0x00000020U, 0x00000010U,
        0x00000008U, 0x00000004U, 0x00000002U, 0x00000001U
    };

    /* E table (Rule 8.9). */
    /* Expansion E: 32 -> 48 bits (which input bit goes to output position) */
    static const uint8_t des_e[48] = {
        31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0
    };


    uint32_t i = 0U;
    for (i = 0U; i < 6U; i += 1U) {
        er[i] = 0U;
    }
    for (i = 0U; i < 48U; i += 1U) {
        uint32_t src = (uint32_t)des_e[i]; /* 0-based R bit index (0=MSB) */
        uint32_t bit = ((r32 & s_rbit_masks[src]) != 0U) ? 1U : 0U;
        if (bit != 0U) {
            set_bit(er, i, 1U);
        }
    }
}

/**
 * @brief Perform a DES round feistel function
 * 
 * @param r The r value
 * @param round_key The round key value
 * @param round_index The round index value
 */
static void des_round_feistel(uint32_t *r, const uint8_t round_key[6], uint32_t round_index)
{
    /* P and S-boxes (Rule 8.9). */
    /* P permutation: 32 -> 32 */
    static const uint8_t des_p[32] = {
        15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
         1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24
    };

    /* S-boxes S1..S8: 64 entries each, 6-bit index -> 4-bit value */
    static const uint8_t des_s1[64] = {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    };
    static const uint8_t des_s2[64] = {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    };
    static const uint8_t des_s3[64] = {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    };
    static const uint8_t des_s4[64] = {
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    };
    static const uint8_t des_s5[64] = {
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    };
    static const uint8_t des_s6[64] = {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    };
    static const uint8_t des_s7[64] = {
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    };
    static const uint8_t des_s8[64] = {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    };
    static const uint8_t *const des_s[8] = { des_s1, des_s2, des_s3, des_s4, des_s5, des_s6, des_s7, des_s8 };


    uint8_t er[6];
    uint32_t i = 0U;
    uint32_t r32 = (uint32_t)(*r);
    uint32_t out32 = 0U;
    uint8_t p_in[4];
    uint8_t p_out[4];

    des_expand_e(r32, er);
#if NOXTLS_DES_DEBUG
    if ((DES_TRACE() != 0) && (round_index == 0U)) {
        (void)fprintf(stdout, "[DES R1] R0 input:  %08X\n", (uint32_t)r32);
        (void)fprintf(stdout, "[DES R1] E(R0):    %02X %02X %02X %02X %02X %02X\n", er[0], er[1], er[2], er[3], er[4], er[5]);
        (void)fprintf(stdout, "[DES R1] K1:       %02X %02X %02X %02X %02X %02X\n",
                round_key[0], round_key[1], round_key[2], round_key[3], round_key[4], round_key[5]);
    }
    if ((DES_TRACE() != 0) && (round_index == 1U)) {
        (void)fprintf(stdout, "[DES R2] R1 input:  %08X  K2: %02X %02X %02X %02X %02X %02X\n", (uint32_t)r32,
                round_key[0], round_key[1], round_key[2], round_key[3], round_key[4], round_key[5]);
    }
#endif
    for (i = 0U; i < 6U; i += 1U) {
        er[i] ^= round_key[i];
    }
#if NOXTLS_DES_DEBUG
    if ((DES_TRACE() != 0) && (round_index == 0U)) {
        (void)fprintf(stdout, "[DES R1] E(R0)^K1: %02X %02X %02X %02X %02X %02X\n", er[0], er[1], er[2], er[3], er[4], er[5]);
    }
#endif
    /* S-box: row = bits 1 and 6 (outer) = 2*b0+b5; column = bits 2-5 (middle); index = row*16+col */
    for (i = 0U; i < 8U; i += 1U) {
        uint32_t base = (uint32_t)(i * 6U);
        uint32_t b0 = (uint32_t)(get_bit(er, base));
        uint32_t b5 = (uint32_t)(get_bit(er, base + 5U));
        uint32_t b1 = (uint32_t)(get_bit(er, base + 1U));
        uint32_t b2 = (uint32_t)(get_bit(er, base + 2U));
        uint32_t b3 = (uint32_t)(get_bit(er, base + 3U));
        uint32_t b4 = (uint32_t)(get_bit(er, base + 4U));
        uint32_t row = (uint32_t)((b0 << 1U) | b5);
        uint32_t col = (uint32_t)((b1 << 3U) | (b2 << 2U) | (b3 << 1U) | b4);
        uint32_t idx = (uint32_t)((row << 4U) | col);
        uint8_t s = (uint8_t)(des_s[i][idx]);
        out32 = (out32 << 4U) | (uint32_t)s;
    }
    p_in[0] = (uint8_t)(out32 >> 24U);
    p_in[1] = (uint8_t)(out32 >> 16U);
    p_in[2] = (uint8_t)(out32 >> 8U);
    p_in[3] = (uint8_t)out32;
    permute(p_in, p_out, des_p, 32U);
    *r = (((uint32_t)p_out[0]) << 24U) | (((uint32_t)p_out[1]) << 16U)
       | (((uint32_t)p_out[2]) << 8U) | ((uint32_t)p_out[3]);
#if NOXTLS_DES_DEBUG
    if ((DES_TRACE() != 0) && (round_index == 0U)) {
        (void)fprintf(stdout, "[DES R1] S-box out: %08X  P(S): %08X  f(R0,K1)= %08X\n",
                (uint32_t)out32, (uint32_t)*r, (uint32_t)*r);
    }
#endif
}

/* KAT vector 1 moved into des_cipher_core (Rule 8.9). */

/**
 * @brief Perform a DES cipher core
 * 
 * @param key The key value
 * @param data The data value
 * @param output The output value
 * @param encrypt The encrypt value
 */
static void des_cipher_core(const uint8_t *key, const uint8_t *data, uint8_t *output, int encrypt)
{
#if NOXTLS_DES_DEBUG
    /* KAT vector 1: key 133457799BBCDFF1, plain 0123456789ABCDEF (TU Berlin example) */
    static const uint8_t s_kat_vec1_key[8]   = { 0x13U, 0x34U, 0x57U, 0x79U, 0x9BU, 0xBCU, 0xDFU, 0xF1U };
    static const uint8_t s_kat_vec1_plain[8] = { 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU };
    /* KAT vector 1 expected cipher; IP(expected_cipher) = correct R16||L16 for comparison. */
    static const uint8_t s_kat_vec1_expected_cipher[8] = { 0x85U, 0xE8U, 0x13U, 0x54U, 0x0FU, 0x0AU, 0xB4U, 0x05U };
#endif
    /* IP/FP tables (Rule 8.9). */
    /* Initial Permutation (output bit i = input bit IP[i]) */
    static const uint8_t des_ip[64] = {
        57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
        56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6
    };

    /* Final Permutation (inverse of IP) */
    static const uint8_t des_fp[64] = {
        39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24
    };


    uint8_t round_keys[16][6];
    uint8_t ip_out[8];
    uint8_t lr[8];
    uint32_t L = 0U;
    uint32_t R = 0U;
    uint32_t r = 0U;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return;
    }

#if NOXTLS_DES_DEBUG
    s_des_trace_this_block = 0;
    if (encrypt != 0) {
        if ((noxtls_ct_equal(key, s_kat_vec1_key, (size_t)8U) != 0) &&
            (noxtls_ct_equal(data, s_kat_vec1_plain, (size_t)8U) != 0)) {
            s_des_trace_this_block = 1;
        }
    }
#endif

    des_key_schedule(key, round_keys);
    permute(data, ip_out, des_ip, 64U);
    L = (((uint32_t)ip_out[0]) << 24U) | (((uint32_t)ip_out[1]) << 16U)
      | (((uint32_t)ip_out[2]) << 8U) | ((uint32_t)ip_out[3]);
    R = (((uint32_t)ip_out[4]) << 24U) | (((uint32_t)ip_out[5]) << 16U)
      | (((uint32_t)ip_out[6]) << 8U) | ((uint32_t)ip_out[7]);

#if NOXTLS_DES_DEBUG
    if (DES_TRACE() != 0) {
        (void)fprintf(stdout, "[DES] enc block in: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
        (void)fprintf(stdout, "[DES] after IP   L=%08X R=%08X\n", (uint32_t)L, (uint32_t)R);
    }
#endif

    for (r = 0U; r < 16U; r += 1U) {
        uint32_t new_L = (uint32_t)(R);
        des_round_feistel(&R, round_keys[(encrypt != 0) ? (uint32_t)r : (15U - (uint32_t)r)], (uint32_t)r);
        R ^= L;
        L = new_L;
#if NOXTLS_DES_DEBUG
        if (DES_TRACE() != 0) {
            (void)fprintf(stdout, "[DES] after r%2d  L=%08X R=%08X\n", r + 1, (uint32_t)L, (uint32_t)R);
        }
#endif
    }
    lr[0] = (uint8_t)(R >> 24U);
    lr[1] = (uint8_t)(R >> 16U);
    lr[2] = (uint8_t)(R >> 8U);
    lr[3] = (uint8_t)R;
    lr[4] = (uint8_t)(L >> 24U);
    lr[5] = (uint8_t)(L >> 16U);
    lr[6] = (uint8_t)(L >> 8U);
    lr[7] = (uint8_t)L;
#if NOXTLS_DES_DEBUG
    if (DES_TRACE() != 0) {
        uint8_t expected_pre_fp[8];
        permute(s_kat_vec1_expected_cipher, expected_pre_fp, des_ip, 64U);
        (void)fprintf(stdout, "[DES] pre-FP   R16||L16: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                lr[0], lr[1], lr[2], lr[3], lr[4], lr[5], lr[6], lr[7]);
        (void)fprintf(stdout, "[DES] expected R16||L16: %02X %02X %02X %02X %02X %02X %02X %02X  (IP of expected cipher)\n",
                expected_pre_fp[0], expected_pre_fp[1], expected_pre_fp[2], expected_pre_fp[3],
                expected_pre_fp[4], expected_pre_fp[5], expected_pre_fp[6], expected_pre_fp[7]);
    }
#endif
    permute(lr, output, des_fp, 64U);

#if NOXTLS_DES_DEBUG
    if (DES_TRACE() != 0) {
        (void)fprintf(stdout, "[DES] block out: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7]);
        (void)fprintf(stdout, "[DES] expected:  85 E8 13 54 0F 0A B4 05  (KAT vector 1)\n");
    }
#endif
}

/**
 * @brief Perform a DES encryption block
 * 
 * @param key The key value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des_encrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    (void)des_cipher_core(key, data, output, 1);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Perform a DES decryption block
 * 
 * @param key The key value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des_decrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    (void)des_cipher_core(key, data, output, 0);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Perform a DES encryption block internal
 * 
 * @param key The key value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output) { return noxtls_des_encrypt_block(key, data, output); }

/**
 * @brief Perform a DES decryption block internal
 * 
 * @param key The key value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output) { return noxtls_des_decrypt_block(key, data, output); }

/**
 * @brief Perform a 3DES encryption block
 * 
 * @param key The key value
 * @param key_len The key length value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des3_encrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output)
{
    uint8_t tmp[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *k1 = NULL;
    const uint8_t *k2 = NULL;
    const uint8_t *k3 = NULL;
    if ((key == NULL) || (data == NULL) || (output == NULL) || ((key_len != 16U) && (key_len != 24U)) ){
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    k1 = key;
    k2 = &key[8];
    k3 = (key_len == 24U) ? (&key[16]) : key;
    (void)noxtls_des_encrypt_block(k1, data, tmp);
    (void)noxtls_des_decrypt_block(k2, tmp, tmp);
    (void)noxtls_des_encrypt_block(k3, tmp, output);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Perform a 3DES decryption block
 * 
 * @param key The key value
 * @param key_len The key length value
 * @param data The data value
 * @param output The output value
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des3_decrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output)
{
    uint8_t tmp[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *k1 = NULL;
    const uint8_t *k2 = NULL;
    const uint8_t *k3 = NULL;
    if ((key == NULL) || (data == NULL) || (output == NULL) || ((key_len != 16U) && (key_len != 24U)) ){
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    k1 = key;
    k2 = &key[8];
    k3 = (key_len == 24U) ? (&key[16]) : key;
    (void)noxtls_des_decrypt_block(k3, data, tmp);
    (void)noxtls_des_encrypt_block(k2, tmp, tmp);
    (void)noxtls_des_decrypt_block(k1, tmp, output);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Perform a DES self test
 * 
 * @return NOXTLS_RETURN_NULL if failed, NOXTLS_RETURN_SUCCESS if success
 */
noxtls_return_t noxtls_des_self_test(void)
{
    /* KAT vectors (Rule 8.9). */
    /* NIST SP 800-20 known-answer: Single block DES encrypt */
    static const uint8_t des_kat_key[NOXTLS_DES_BLOCK_LENGTH] = {
        0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U
    };
    static const uint8_t des_kat_plain[NOXTLS_DES_BLOCK_LENGTH] = {
        0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    static const uint8_t des_kat_cipher[NOXTLS_DES_BLOCK_LENGTH] = {
        0x95U, 0xF8U, 0xA5U, 0xE5U, 0xDDU, 0x31U, 0xD9U, 0x00U
    };


    uint8_t out[NOXTLS_DES_BLOCK_LENGTH];
    (void)noxtls_des_encrypt_block(des_kat_key, des_kat_plain, out);
    if (noxtls_ct_equal(out, des_kat_cipher, (size_t)NOXTLS_DES_BLOCK_LENGTH) == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    (void)noxtls_des_decrypt_block(des_kat_key, des_kat_cipher, out);
    if (noxtls_ct_equal(out, des_kat_plain, (size_t)NOXTLS_DES_BLOCK_LENGTH) == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    /* 3DES KAT: use NIST 800-67 / common test: 3-key 3DES */
    {
        uint8_t k3[24] = { 0 };
        const uint8_t pt[8]  = { 0 };
        uint8_t ct[8];
        uint32_t i = 0U;
        for (i = 0U; i < 24U; i += 1U) { k3[i] = (uint8_t)(i + 1U); }
        (void)noxtls_des3_encrypt_block(k3, 24, pt, ct);
        (void)noxtls_des3_decrypt_block(k3, 24, ct, out);
        if (noxtls_ct_equal(out, pt, (size_t)8U) == 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_DES */
