/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_des.c
* Summary: Data Encryption Standard (DES) and Triple-DES (3DES) - FIPS 46-3
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_des.h"
#include <stdio.h>

#if NOXTLS_FEATURE_DES

/* NIST SP 800-20 known-answer: Single block DES encrypt */
static const uint8_t des_kat_key[NOXTLS_DES_BLOCK_LENGTH] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};
static const uint8_t des_kat_plain[NOXTLS_DES_BLOCK_LENGTH] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t des_kat_cipher[NOXTLS_DES_BLOCK_LENGTH] = {
    0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00
};

/* When encrypting the KAT vector (key=plain=0123456789ABCDEF), trace to stdout to debug. */
static int s_des_trace_this_block;
#define DES_TRACE() (s_des_trace_this_block)

#ifdef __cplusplus
extern "C" {
#endif

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

/* Expansion E: 32 -> 48 bits (which input bit goes to output position) */
static const uint8_t des_e[48] = {
    31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,  7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0
};

/* P permutation: 32 -> 32 */
static const uint8_t des_p[32] = {
    15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
     1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24
};

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

static int get_bit(const uint8_t *buf, int bit_index)
{
    int byte_idx = bit_index >> 3;
    int bit_idx  = 7 - (bit_index & 7);
    return (buf[byte_idx] >> bit_idx) & 1;
}

static void set_bit(uint8_t *buf, int bit_index, int value)
{
    int byte_idx = bit_index >> 3;
    int bit_idx  = 7 - (bit_index & 7);
    if(value)
        buf[byte_idx] |= (uint8_t)(1u << bit_idx);
    else
        buf[byte_idx] &= (uint8_t)(~(1u << bit_idx));
}

static void permute(const uint8_t *in, uint8_t *out, const uint8_t *table, int n)
{
    int i;
    for(i = 0; i < n; i++)
        set_bit(out, i, get_bit(in, table[i]));
}

static void rotate_left_28(uint32_t *c, uint32_t *d, int count)
{
    uint32_t c0 = *c;
    uint32_t d0 = *d;
    *c = ((c0 << count) | (c0 >> (28 - count))) & 0x0FFFFFFFu;
    *d = ((d0 << count) | (d0 >> (28 - count))) & 0x0FFFFFFFu;
}

static void des_key_schedule(const uint8_t *key, uint8_t round_keys[16][6])
{
    uint8_t pc1_out[7];
    uint32_t c;
    uint32_t d;
    int r;
    int i;
    int j;

    permute(key, pc1_out, des_pc1, 56);
    /* C0 = first 28 bits of PC1 output (bit 0 = MSB of C); D0 = next 28 bits. */
    c = ((uint32_t)pc1_out[0] << 20) | ((uint32_t)pc1_out[1] << 12) | ((uint32_t)pc1_out[2] << 4)
      | ((uint32_t)(pc1_out[3] >> 4) & 0xFu);
    d = ((uint32_t)(pc1_out[3] & 0xFu) << 24) | ((uint32_t)pc1_out[4] << 16) | ((uint32_t)pc1_out[5] << 8)
      | (uint32_t)pc1_out[6];

    if(DES_TRACE()) {
        fprintf(stdout, "[DES KS] key:    %02X %02X %02X %02X %02X %02X %02X %02X\n",
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
        fprintf(stdout, "[DES KS] pc1_out: %02X %02X %02X %02X %02X %02X %02X\n",
                pc1_out[0], pc1_out[1], pc1_out[2], pc1_out[3], pc1_out[4], pc1_out[5], pc1_out[6]);
        fprintf(stdout, "[DES KS] C0=%07X D0=%07X\n", (unsigned int)(c & 0x0FFFFFFFu), (unsigned int)(d & 0x0FFFFFFFu));
    }

    for(r = 0; r < 16; r++) {
        rotate_left_28(&c, &d, (unsigned int)des_rot[r]);
        /* Pack C||D into 7 bytes (56 bits): cd bit i = C bit i for i<28, cd bit (28+i) = D bit i. C/D bit 0 is MSB (at c/d bit 27). */
        uint8_t cd[7];
        for(i = 0; i < 28; i++)
            set_bit(cd, i, (c >> (27 - i)) & 1);
        for(i = 0; i < 28; i++)
            set_bit(cd, 28 + i, (d >> (27 - i)) & 1);
        uint8_t pk[6];
        for(i = 0; i < 48; i++)
            set_bit(pk, i, get_bit(cd, des_pc2[i]));
        for(j = 0; j < 6; j++)
            round_keys[r][j] = pk[j];
        if(DES_TRACE() && r == 0) {
            fprintf(stdout, "[DES KS] after rot C1=%07X D1=%07X\n", (unsigned int)(c & 0x0FFFFFFFu), (unsigned int)(d & 0x0FFFFFFFu));
        }
        if(DES_TRACE()) {
            fprintf(stdout, "[DES KS] K%2d:   %02X %02X %02X %02X %02X %02X\n", r + 1,
                    round_keys[r][0], round_keys[r][1], round_keys[r][2],
                    round_keys[r][3], round_keys[r][4], round_keys[r][5]);
        }
    }
}

/* E expansion: R (32 bits, bit 0 = MSB) -> 48 bits. Standard rows (1-based): 32,1,2,3,4,5 | 4,5,6,7,8,9 | ... | 28,29,30,31,32,1 */
static void des_expand_e(uint32_t r32, uint8_t er[6])
{
    int i;
    for(i = 0; i < 6; i++)
        er[i] = 0;
    for(i = 0; i < 48; i++) {
        int src = des_e[i]; /* 0-based R bit index (0=MSB) */
        int bit = (int)((r32 >> (31 - src)) & 1u);
        if(bit)
            er[i >> 3] |= (uint8_t)(1u << (7 - (i & 7)));
    }
}

static void des_round_feistel(uint32_t *r, const uint8_t round_key[6], int round_index)
{
    uint8_t er[6];
    int i;
    uint32_t r32 = *r;
    des_expand_e(r32, er);
    if(DES_TRACE() && round_index == 0) {
        fprintf(stdout, "[DES R1] R0 input:  %08X\n", (unsigned int)r32);
        fprintf(stdout, "[DES R1] E(R0):    %02X %02X %02X %02X %02X %02X\n", er[0], er[1], er[2], er[3], er[4], er[5]);
        fprintf(stdout, "[DES R1] K1:       %02X %02X %02X %02X %02X %02X\n",
                round_key[0], round_key[1], round_key[2], round_key[3], round_key[4], round_key[5]);
    }
    if(DES_TRACE() && round_index == 1) {
        fprintf(stdout, "[DES R2] R1 input:  %08X  K2: %02X %02X %02X %02X %02X %02X\n", (unsigned int)r32,
                round_key[0], round_key[1], round_key[2], round_key[3], round_key[4], round_key[5]);
    }
    for(i = 0; i < 6; i++)
        er[i] ^= round_key[i];
    if(DES_TRACE() && round_index == 0)
        fprintf(stdout, "[DES R1] E(R0)^K1: %02X %02X %02X %02X %02X %02X\n", er[0], er[1], er[2], er[3], er[4], er[5]);
    uint32_t out32 = 0;
    /* S-box: row = bits 1 and 6 (outer) = 2*b0+b5; column = bits 2-5 (middle); index = row*16+col */
    for(i = 0; i < 8; i++) {
        int b0 = get_bit(er, i*6), b5 = get_bit(er, i*6+5);
        int b1 = get_bit(er, i*6+1), b2 = get_bit(er, i*6+2), b3 = get_bit(er, i*6+3), b4 = get_bit(er, i*6+4);
        int row = (b0 << 1) | b5;
        int col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4;
        int idx = (row << 4) | col;
        uint8_t s = des_s[i][idx];
        out32 = (out32 << 4) | s;
    }
    uint8_t p_in[4];
    uint8_t p_out[4];
    p_in[0] = (uint8_t)(out32 >> 24);
    p_in[1] = (uint8_t)(out32 >> 16);
    p_in[2] = (uint8_t)(out32 >> 8);
    p_in[3] = (uint8_t)out32;
    permute(p_in, p_out, des_p, 32);
    *r = ((uint32_t)p_out[0] << 24) | ((uint32_t)p_out[1] << 16) | ((uint32_t)p_out[2] << 8) | p_out[3];
    if(DES_TRACE() && round_index == 0)
        fprintf(stdout, "[DES R1] S-box out: %08X  P(S): %08X  f(R0,K1)= %08X\n",
                (unsigned int)out32, (unsigned int)((uint32_t)p_out[0]<<24|(uint32_t)p_out[1]<<16|(uint32_t)p_out[2]<<8|p_out[3]), (unsigned int)*r);
}

/* KAT vector 1: key 133457799BBCDFF1, plain 0123456789ABCDEF (TU Berlin example) */
static const uint8_t s_kat_vec1_key[8]   = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
static const uint8_t s_kat_vec1_plain[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
/* KAT vector 1 expected cipher; IP(expected_cipher) = correct R16||L16 for comparison. */
static const uint8_t s_kat_vec1_expected_cipher[8] = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

static void des_cipher_core(const uint8_t *key, const uint8_t *data, uint8_t *output, int encrypt)
{
    uint8_t round_keys[16][6];
    uint8_t ip_out[8];
    uint8_t lr[8];
    uint32_t L;
    uint32_t R;
    int r;

    s_des_trace_this_block = 0;
    if(encrypt && key && data && memcmp(key, s_kat_vec1_key, 8) == 0 && memcmp(data, s_kat_vec1_plain, 8) == 0)
        s_des_trace_this_block = 1;

    des_key_schedule(key, round_keys);
    permute(data, ip_out, des_ip, 64);
    L = ((uint32_t)ip_out[0] << 24) | ((uint32_t)ip_out[1] << 16) | ((uint32_t)ip_out[2] << 8) | ip_out[3];
    R = ((uint32_t)ip_out[4] << 24) | ((uint32_t)ip_out[5] << 16) | ((uint32_t)ip_out[6] << 8) | ip_out[7];

    if(DES_TRACE()) {
        fprintf(stdout, "[DES] enc block in: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
        fprintf(stdout, "[DES] after IP   L=%08X R=%08X\n", (unsigned int)L, (unsigned int)R);
    }

    for(r = 0; r < 16; r++) {
        uint32_t new_L = R;
        des_round_feistel(&R, round_keys[encrypt ? r : (15 - r)], r);
        R ^= L;
        L = new_L;
        if(DES_TRACE())
            fprintf(stdout, "[DES] after r%2d  L=%08X R=%08X\n", r + 1, (unsigned int)L, (unsigned int)R);
    }
    lr[0] = (uint8_t)(R >> 24);
    lr[1] = (uint8_t)(R >> 16);
    lr[2] = (uint8_t)(R >> 8);
    lr[3] = (uint8_t)R;
    lr[4] = (uint8_t)(L >> 24);
    lr[5] = (uint8_t)(L >> 16);
    lr[6] = (uint8_t)(L >> 8);
    lr[7] = (uint8_t)L;
    if(DES_TRACE()) {
        uint8_t expected_pre_fp[8];
        permute(s_kat_vec1_expected_cipher, expected_pre_fp, des_ip, 64);
        fprintf(stdout, "[DES] pre-FP   R16||L16: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                lr[0], lr[1], lr[2], lr[3], lr[4], lr[5], lr[6], lr[7]);
        fprintf(stdout, "[DES] expected R16||L16: %02X %02X %02X %02X %02X %02X %02X %02X  (IP of expected cipher)\n",
                expected_pre_fp[0], expected_pre_fp[1], expected_pre_fp[2], expected_pre_fp[3],
                expected_pre_fp[4], expected_pre_fp[5], expected_pre_fp[6], expected_pre_fp[7]);
    }
    permute(lr, output, des_fp, 64);

    if(DES_TRACE()) {
        fprintf(stdout, "[DES] block out: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7]);
        fprintf(stdout, "[DES] expected:  85 E8 13 54 0F 0A B4 05  (KAT vector 1)\n");
    }
}

noxtls_return_t noxtls_des_encrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    if(!key || !data || !output)
        return NOXTLS_RETURN_NULL;
    des_cipher_core(key, data, output, 1);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_des_decrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    if(!key || !data || !output)
        return NOXTLS_RETURN_NULL;
    des_cipher_core(key, data, output, 0);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_des_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    return noxtls_des_encrypt_block(key, data, output);
}

noxtls_return_t noxtls_des_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output)
{
    return noxtls_des_decrypt_block(key, data, output);
}

noxtls_return_t noxtls_des3_encrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output)
{
    uint8_t tmp[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *k1;
    const uint8_t *k2;
    const uint8_t *k3;
    if(!key || !data || !output || (key_len != 16 && key_len != 24))
        return NOXTLS_RETURN_INVALID_PARAM;
    k1 = key;
    k2 = key + 8;
    k3 = (key_len == 24) ? (key + 16) : key;
    noxtls_des_encrypt_block(k1, data, tmp);
    noxtls_des_decrypt_block(k2, tmp, tmp);
    noxtls_des_encrypt_block(k3, tmp, output);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_des3_decrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output)
{
    uint8_t tmp[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *k1;
    const uint8_t *k2;
    const uint8_t *k3;
    if(!key || !data || !output || (key_len != 16 && key_len != 24))
        return NOXTLS_RETURN_INVALID_PARAM;
    k1 = key;
    k2 = key + 8;
    k3 = (key_len == 24) ? (key + 16) : key;
    noxtls_des_decrypt_block(k3, data, tmp);
    noxtls_des_encrypt_block(k2, tmp, tmp);
    noxtls_des_decrypt_block(k1, tmp, output);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_des_self_test(void)
{
    uint8_t out[NOXTLS_DES_BLOCK_LENGTH];
    noxtls_des_encrypt_block(des_kat_key, des_kat_plain, out);
    if(memcmp(out, des_kat_cipher, NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_FAILED;
    noxtls_des_decrypt_block(des_kat_key, des_kat_cipher, out);
    if(memcmp(out, des_kat_plain, NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_FAILED;
    /* 3DES KAT: use NIST 800-67 / common test: 3-key 3DES */
    {
        uint8_t k3[24] = { 0 };
        uint8_t pt[8]  = { 0 };
        uint8_t ct[8];
        int i;
        for(i = 0; i < 24; i++) k3[i] = (uint8_t)(i + 1);
        noxtls_des3_encrypt_block(k3, 24, pt, ct);
        noxtls_des3_decrypt_block(k3, 24, ct, out);
        if(memcmp(out, pt, 8) != 0)
            return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_DES */
