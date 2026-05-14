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
* File:    noxtls_camellia.c
* Summary: Camellia Cipher Algorithm Implementation (RFC 3713)
*
*/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Includes */
#include "noxtls_camellia.h"
#include "noxtls_camellia_internal.h"

#if NOXTLS_FEATURE_CAMELLIA

/* RFC 3713 Sigma constants (64-bit) */
static const uint64_t sigma1 = 0xA09E667F3BCC908BULL;
static const uint64_t sigma2 = 0xB67AE8584CAA73B2ULL;
static const uint64_t sigma3 = 0xC6EF372FE94F82BEULL;
static const uint64_t sigma4 = 0x54FF53A5F1D36F1CULL;
static const uint64_t sigma5 = 0x10E527FADE682D1DULL;
static const uint64_t sigma6 = 0xB05688C2B3E6C1FDULL;

/* Forward declarations for mode-specific functions */
extern noxtls_return_t noxtls_camellia_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_encrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_encrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_encrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_encrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_decrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_decrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_decrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_decrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);
extern noxtls_return_t noxtls_camellia_decrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_camellia_type_t type);

/* RFC 3713 SBOX1 (8-bit in/out) */
static const uint8_t camellia_sbox1[256] = {
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
};

/* RFC 3713: SBOX2[x] = SBOX1[x] <<< 1, SBOX3[x] = SBOX1[x] <<< 7, SBOX4[x] = SBOX1[x <<< 1] */
static uint8_t camellia_sbox2[256];
static uint8_t camellia_sbox3[256];
static uint8_t camellia_sbox4[256];
static int camellia_sboxes_initialized;

static void camellia_init_sboxes(void)
{
    int i;
    if(camellia_sboxes_initialized) return;
    for(i = 0; i < 256; i++) {
        camellia_sbox2[i] = (uint8_t)((camellia_sbox1[i] << 1) | (camellia_sbox1[i] >> 7));
        camellia_sbox3[i] = (uint8_t)((camellia_sbox1[i] << 7) | (camellia_sbox1[i] >> 1));
        camellia_sbox4[i] = camellia_sbox1[(uint8_t)((i << 1) | (i >> 7))];
    }
    camellia_sboxes_initialized = 1;
}

/* RFC 3713 F-function: 64-bit input, 64-bit subkey, 64-bit output */
static uint64_t camellia_f64(uint64_t F_IN, uint64_t KE)
{
    uint64_t x = F_IN ^ KE;
    uint8_t t1;
    uint8_t t2;
    uint8_t t3;
    uint8_t t4;
    uint8_t t5;
    uint8_t t6;
    uint8_t t7;
    uint8_t t8;
    uint8_t y1;
    uint8_t y2;
    uint8_t y3;
    uint8_t y4;
    uint8_t y5;
    uint8_t y6;
    uint8_t y7;
    uint8_t y8;

    t1 = (uint8_t)(x >> 56);
    t2 = (uint8_t)(x >> 48);
    t3 = (uint8_t)(x >> 40);
    t4 = (uint8_t)(x >> 32);
    t5 = (uint8_t)(x >> 24);
    t6 = (uint8_t)(x >> 16);
    t7 = (uint8_t)(x >> 8);
    t8 = (uint8_t)x;

    t1 = camellia_sbox1[t1];
    t2 = camellia_sbox2[t2];
    t3 = camellia_sbox3[t3];
    t4 = camellia_sbox4[t4];
    t5 = camellia_sbox2[t5];
    t6 = camellia_sbox3[t6];
    t7 = camellia_sbox4[t7];
    t8 = camellia_sbox1[t8];

    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    return ((uint64_t)y1 << 56) | ((uint64_t)y2 << 48) | ((uint64_t)y3 << 40) | ((uint64_t)y4 << 32)
         | ((uint64_t)y5 << 24) | ((uint64_t)y6 << 16) | ((uint64_t)y7 << 8) | (uint64_t)y8;
}

/* 128-bit rotate left by r bits (0 <= r < 128); output high 64 and low 64 */
static void rotl128(uint64_t hi, uint64_t lo, int r, uint64_t *out_hi, uint64_t *out_lo)
{
    uint64_t nhi;
    uint64_t nlo;
    if(r == 0) {
        *out_hi = hi;
        *out_lo = lo;
        return;
    }
    if(r >= 64) {
        rotl128(lo, hi, r - 64, out_hi, out_lo);
        return;
    }
    nhi = (hi << r) | (lo >> (64 - r));
    nlo = (lo << r) | (hi >> (64 - r));
    *out_hi = nhi;
    *out_lo = nlo;
}

/**
 * @brief Camellia Key Schedule (RFC 3713)
 * kw: 4 x 64-bit (pre/post whitening), ke: 6 x 64-bit (FL/FLINV), k: 24 x 64-bit (round keys)
 */
noxtls_return_t noxtls_camellia_key_schedule(const uint8_t* key, uint64_t* kw, uint64_t* ke, uint64_t* k, noxtls_camellia_type_t type)
{
    uint64_t kl_hi;
    uint64_t kl_lo;
    uint64_t kr_hi;
    uint64_t kr_lo;
    uint64_t ka_hi;
    uint64_t ka_lo;
    uint64_t kb_hi;
    uint64_t kb_lo;
    uint64_t d1;
    uint64_t d2;
    int key_bytes = (type == NOXTLS_CAMELLIA_128_BIT) ? 16 : 32;

    camellia_init_sboxes();

    /* Load KL (left 128 bits of key), big-endian */
    kl_hi = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) | ((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32)
          | ((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) | ((uint64_t)key[6] << 8) | (uint64_t)key[7];
    kl_lo = ((uint64_t)key[8] << 56) | ((uint64_t)key[9] << 48) | ((uint64_t)key[10] << 40) | ((uint64_t)key[11] << 32)
          | ((uint64_t)key[12] << 24) | ((uint64_t)key[13] << 16) | ((uint64_t)key[14] << 8) | (uint64_t)key[15];

    if(type == NOXTLS_CAMELLIA_128_BIT) {
        kr_hi = 0;
        kr_lo = 0;
    } else if(type == NOXTLS_CAMELLIA_192_BIT) {
        /* KR = (rightmost 64 bits of K) || (~(rightmost 64 bits of K)); high 64 of KR = key[16..23], low 64 = ~ */
        kr_hi = ((uint64_t)key[16] << 56) | ((uint64_t)key[17] << 48) | ((uint64_t)key[18] << 40) | ((uint64_t)key[19] << 32)
              | ((uint64_t)key[20] << 24) | ((uint64_t)key[21] << 16) | ((uint64_t)key[22] << 8) | (uint64_t)key[23];
        kr_lo = ~kr_hi;
    } else {
        kr_hi = ((uint64_t)key[16] << 56) | ((uint64_t)key[17] << 48) | ((uint64_t)key[18] << 40) | ((uint64_t)key[19] << 32)
              | ((uint64_t)key[20] << 24) | ((uint64_t)key[21] << 16) | ((uint64_t)key[22] << 8) | (uint64_t)key[23];
        kr_lo = ((uint64_t)key[24] << 56) | ((uint64_t)key[25] << 48) | ((uint64_t)key[26] << 40) | ((uint64_t)key[27] << 32)
              | ((uint64_t)key[28] << 24) | ((uint64_t)key[29] << 16) | ((uint64_t)key[30] << 8) | (uint64_t)key[31];
    }

    /* KA from KL, KR and Sigma1..4 */
    d1 = kl_hi ^ kr_hi;
    d2 = kl_lo ^ kr_lo;
    d2 ^= camellia_f64(d1, sigma1);
    d1 ^= camellia_f64(d2, sigma2);
    d1 ^= kl_hi;
    d2 ^= kl_lo;
    d2 ^= camellia_f64(d1, sigma3);
    d1 ^= camellia_f64(d2, sigma4);
    ka_hi = d1;
    ka_lo = d2;

    if(type != NOXTLS_CAMELLIA_128_BIT) {
        d1 = ka_hi ^ kr_hi;
        d2 = ka_lo ^ kr_lo;
        d2 ^= camellia_f64(d1, sigma5);
        d1 ^= camellia_f64(d2, sigma6);
        kb_hi = d1;
        kb_lo = d2;
    }

    if(type == NOXTLS_CAMELLIA_128_BIT) {
        uint64_t h;
        /* kw1, kw2 */
        rotl128(kl_hi, kl_lo, 0, &kw[0], &kw[1]);
        /* k1..k18, ke1..ke4, kw3, kw4. Note: k9=(KA<<<45)>>64, k10=(KL<<<60)&MASK64 (different rotations). */
        rotl128(ka_hi, ka_lo, 0, &k[0], &k[1]);
        rotl128(kl_hi, kl_lo, 15, &k[2], &k[3]);
        rotl128(ka_hi, ka_lo, 15, &k[4], &k[5]);
        rotl128(ka_hi, ka_lo, 30, &ke[0], &ke[1]);
        rotl128(kl_hi, kl_lo, 45, &k[6], &k[7]);
        rotl128(ka_hi, ka_lo, 45, &k[8], &h);           /* k[8]=k9; discard low(KA<<<45) */
        rotl128(kl_hi, kl_lo, 60, &h, &k[9]);          /* k[9]=k10=low(KL<<<60) */
        rotl128(ka_hi, ka_lo, 60, &k[10], &k[11]);      /* k[10]=k11, k[11]=k12 */
        rotl128(kl_hi, kl_lo, 77, &ke[2], &ke[3]);
        rotl128(kl_hi, kl_lo, 94, &k[12], &k[13]);      /* k13, k14 */
        rotl128(ka_hi, ka_lo, 94, &k[14], &k[15]);      /* k15, k16 */
        rotl128(kl_hi, kl_lo, 111, &k[16], &k[17]);     /* k17, k18 */
        rotl128(ka_hi, ka_lo, 111, &kw[2], &kw[3]);
        (void)h;
    } else {
        /* 192/256: kw1,kw2 from KL; k1..k24, ke1..ke6, kw3,kw4 from KB/KR/KA/KL */
        rotl128(kl_hi, kl_lo, 0, &kw[0], &kw[1]);
        rotl128(kb_hi, kb_lo, 0, &k[0], &k[1]);
        rotl128(kr_hi, kr_lo, 15, &k[2], &k[3]);
        rotl128(ka_hi, ka_lo, 15, &k[4], &k[5]);
        rotl128(kr_hi, kr_lo, 30, &ke[0], &ke[1]);
        rotl128(kb_hi, kb_lo, 30, &k[6], &k[7]);
        rotl128(kl_hi, kl_lo, 45, &k[8], &k[9]);
        rotl128(ka_hi, ka_lo, 45, &k[10], &k[11]);
        rotl128(kl_hi, kl_lo, 60, &ke[2], &ke[3]);
        rotl128(kr_hi, kr_lo, 60, &k[12], &k[13]);
        rotl128(kb_hi, kb_lo, 60, &k[14], &k[15]);
        rotl128(kl_hi, kl_lo, 77, &k[16], &k[17]);
        rotl128(ka_hi, ka_lo, 77, &ke[4], &ke[5]);
        rotl128(kr_hi, kr_lo, 94, &k[18], &k[19]);
        rotl128(ka_hi, ka_lo, 94, &k[20], &k[21]);
        rotl128(kl_hi, kl_lo, 111, &k[22], &k[23]);
        rotl128(kb_hi, kb_lo, 111, &kw[2], &kw[3]);
    }
    (void)key_bytes;
    return NOXTLS_RETURN_SUCCESS;
}

/* FL: 64-bit input, 64-bit key KE */
static uint64_t camellia_fl(uint64_t FL_IN, uint64_t KE)
{
    uint32_t x1 = (uint32_t)(FL_IN >> 32);
    uint32_t x2 = (uint32_t)(FL_IN & 0xFFFFFFFFULL);
    uint32_t k1 = (uint32_t)(KE >> 32);
    uint32_t k2 = (uint32_t)(KE & 0xFFFFFFFFULL);
    x2 ^= (uint32_t)(((uint64_t)(x1 & k1) << 1) | ((uint64_t)(x1 & k1) >> 31));
    x1 ^= (x2 | k2);
    return ((uint64_t)x1 << 32) | (uint64_t)x2;
}

/* FLINV: inverse of FL */
static uint64_t camellia_flinv(uint64_t FLINV_IN, uint64_t KE)
{
    uint32_t y1 = (uint32_t)(FLINV_IN >> 32);
    uint32_t y2 = (uint32_t)(FLINV_IN & 0xFFFFFFFFULL);
    uint32_t k1 = (uint32_t)(KE >> 32);
    uint32_t k2 = (uint32_t)(KE & 0xFFFFFFFFULL);
    y1 ^= (y2 | k2);
    y2 ^= (uint32_t)(((uint64_t)(y1 & k1) << 1) | ((uint64_t)(y1 & k1) >> 31));
    return ((uint64_t)y1 << 32) | (uint64_t)y2;
}

/* Load 128-bit block from big-endian bytes into D1 (high 64), D2 (low 64) */
static void load_block_be(const uint8_t* data, uint64_t* D1, uint64_t* D2)
{
    *D1 = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32)
        | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | (uint64_t)data[7];
    *D2 = ((uint64_t)data[8] << 56) | ((uint64_t)data[9] << 48) | ((uint64_t)data[10] << 40) | ((uint64_t)data[11] << 32)
        | ((uint64_t)data[12] << 24) | ((uint64_t)data[13] << 16) | ((uint64_t)data[14] << 8) | (uint64_t)data[15];
}

/* Store D2 (high 64), D1 (low 64) to big-endian bytes (C = (D2<<64)|D1) */
static void store_block_be(uint8_t* output, uint64_t D1, uint64_t D2)
{
    output[0] = (uint8_t)(D2 >> 56);
    output[1] = (uint8_t)(D2 >> 48);
    output[2] = (uint8_t)(D2 >> 40);
    output[3] = (uint8_t)(D2 >> 32);
    output[4] = (uint8_t)(D2 >> 24);
    output[5] = (uint8_t)(D2 >> 16);
    output[6] = (uint8_t)(D2 >> 8);
    output[7] = (uint8_t)D2;
    output[8] = (uint8_t)(D1 >> 56);
    output[9] = (uint8_t)(D1 >> 48);
    output[10] = (uint8_t)(D1 >> 40);
    output[11] = (uint8_t)(D1 >> 32);
    output[12] = (uint8_t)(D1 >> 24);
    output[13] = (uint8_t)(D1 >> 16);
    output[14] = (uint8_t)(D1 >> 8);
    output[15] = (uint8_t)D1;
}

static void camellia_print_block_hex(const char *label, const uint8_t *block)
{
    int i;
    if(label != NULL) {
        (void)printf("%s", label);
    }
    for(i = 0; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i++) {
        (void)printf("%02x", block[i]);
    }
    (void)printf("\n");
}

/**
 * @brief Camellia Encrypt Block (RFC 3713)
 */
noxtls_return_t noxtls_camellia_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type)
{
    uint64_t kw[4];
    uint64_t ke[6];
    uint64_t k[24];
    uint64_t D1;
    uint64_t D2;

    noxtls_camellia_key_schedule(key, kw, ke, k, type);
    load_block_be(data, &D1, &D2);

    D1 ^= kw[0];
    D2 ^= kw[1];

    if(type == NOXTLS_CAMELLIA_128_BIT) {
        D2 ^= camellia_f64(D1, k[0]);
        D1 ^= camellia_f64(D2, k[1]);
        D2 ^= camellia_f64(D1, k[2]);
        D1 ^= camellia_f64(D2, k[3]);
        D2 ^= camellia_f64(D1, k[4]);
        D1 ^= camellia_f64(D2, k[5]);
        D1 = camellia_fl(D1, ke[0]);
        D2 = camellia_flinv(D2, ke[1]);
        D2 ^= camellia_f64(D1, k[6]);
        D1 ^= camellia_f64(D2, k[7]);
        D2 ^= camellia_f64(D1, k[8]);
        D1 ^= camellia_f64(D2, k[9]);
        D2 ^= camellia_f64(D1, k[10]);
        D1 ^= camellia_f64(D2, k[11]);
        D1 = camellia_fl(D1, ke[2]);
        D2 = camellia_flinv(D2, ke[3]);
        D2 ^= camellia_f64(D1, k[12]);
        D1 ^= camellia_f64(D2, k[13]);
        D2 ^= camellia_f64(D1, k[14]);
        D1 ^= camellia_f64(D2, k[15]);
        D2 ^= camellia_f64(D1, k[16]);   /* round 17: k17 */
        D1 ^= camellia_f64(D2, k[17]);   /* round 18: k18 */
    } else {
        D2 ^= camellia_f64(D1, k[0]);
        D1 ^= camellia_f64(D2, k[1]);
        D2 ^= camellia_f64(D1, k[2]);
        D1 ^= camellia_f64(D2, k[3]);
        D2 ^= camellia_f64(D1, k[4]);
        D1 ^= camellia_f64(D2, k[5]);
        D1 = camellia_fl(D1, ke[0]);
        D2 = camellia_flinv(D2, ke[1]);
        D2 ^= camellia_f64(D1, k[6]);
        D1 ^= camellia_f64(D2, k[7]);
        D2 ^= camellia_f64(D1, k[8]);
        D1 ^= camellia_f64(D2, k[9]);
        D2 ^= camellia_f64(D1, k[10]);
        D1 ^= camellia_f64(D2, k[11]);
        D1 = camellia_fl(D1, ke[2]);
        D2 = camellia_flinv(D2, ke[3]);
        D2 ^= camellia_f64(D1, k[12]);
        D1 ^= camellia_f64(D2, k[13]);
        D2 ^= camellia_f64(D1, k[14]);
        D1 ^= camellia_f64(D2, k[15]);
        D2 ^= camellia_f64(D1, k[16]);
        D1 ^= camellia_f64(D2, k[17]);
        D1 = camellia_fl(D1, ke[4]);
        D2 = camellia_flinv(D2, ke[5]);
        D2 ^= camellia_f64(D1, k[18]);
        D1 ^= camellia_f64(D2, k[19]);
        D2 ^= camellia_f64(D1, k[20]);
        D1 ^= camellia_f64(D2, k[21]);
        D2 ^= camellia_f64(D1, k[22]);
        D1 ^= camellia_f64(D2, k[23]);
    }

    D2 ^= kw[2];
    D1 ^= kw[3];
    store_block_be(output, D1, D2);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt Block (RFC 3713: reverse subkey order)
 */
noxtls_return_t noxtls_camellia_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type)
{
    uint64_t kw[4];
    uint64_t ke[6];
    uint64_t k[24];
    uint64_t D1;
    uint64_t D2;
    uint64_t kw_dec[4];
    uint64_t ke_dec[6];
    uint64_t k_dec[24];
    int i;

    noxtls_camellia_key_schedule(key, kw, ke, k, type);

    /* Decryption: swap subkeys per RFC 2.3.3 */
    kw_dec[0] = kw[2];
    kw_dec[1] = kw[3];
    kw_dec[2] = kw[0];
    kw_dec[3] = kw[1];
    if(type == NOXTLS_CAMELLIA_128_BIT) {
        ke_dec[0] = ke[3];
        ke_dec[1] = ke[2];
        ke_dec[2] = ke[1];
        ke_dec[3] = ke[0];
        for(i = 0; i < 18; i++) k_dec[i] = k[17 - i];  /* k1<->k18: k_dec[0]=k18, k_dec[17]=k1 */
    } else {
        ke_dec[0] = ke[5];
        ke_dec[1] = ke[4];
        ke_dec[2] = ke[3];
        ke_dec[3] = ke[2];
        ke_dec[4] = ke[1];
        ke_dec[5] = ke[0];
        for(i = 0; i < 24; i++) k_dec[i] = k[23 - i];
    }

    load_block_be(data, &D1, &D2);
    D1 ^= kw_dec[0];
    D2 ^= kw_dec[1];

    if(type == NOXTLS_CAMELLIA_128_BIT) {
        D2 ^= camellia_f64(D1, k_dec[0]);
        D1 ^= camellia_f64(D2, k_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[2]);
        D1 ^= camellia_f64(D2, k_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[4]);
        D1 ^= camellia_f64(D2, k_dec[5]);
        D1 = camellia_fl(D1, ke_dec[0]);
        D2 = camellia_flinv(D2, ke_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[6]);
        D1 ^= camellia_f64(D2, k_dec[7]);
        D2 ^= camellia_f64(D1, k_dec[8]);
        D1 ^= camellia_f64(D2, k_dec[9]);
        D2 ^= camellia_f64(D1, k_dec[10]);
        D1 ^= camellia_f64(D2, k_dec[11]);
        D1 = camellia_fl(D1, ke_dec[2]);
        D2 = camellia_flinv(D2, ke_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[12]);
        D1 ^= camellia_f64(D2, k_dec[13]);
        D2 ^= camellia_f64(D1, k_dec[14]);
        D1 ^= camellia_f64(D2, k_dec[15]);
        D2 ^= camellia_f64(D1, k_dec[16]);
        D1 ^= camellia_f64(D2, k_dec[17]);
    } else {
        D2 ^= camellia_f64(D1, k_dec[0]);
        D1 ^= camellia_f64(D2, k_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[2]);
        D1 ^= camellia_f64(D2, k_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[4]);
        D1 ^= camellia_f64(D2, k_dec[5]);
        D1 = camellia_fl(D1, ke_dec[0]);
        D2 = camellia_flinv(D2, ke_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[6]);
        D1 ^= camellia_f64(D2, k_dec[7]);
        D2 ^= camellia_f64(D1, k_dec[8]);
        D1 ^= camellia_f64(D2, k_dec[9]);
        D2 ^= camellia_f64(D1, k_dec[10]);
        D1 ^= camellia_f64(D2, k_dec[11]);
        D1 = camellia_fl(D1, ke_dec[2]);
        D2 = camellia_flinv(D2, ke_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[12]);
        D1 ^= camellia_f64(D2, k_dec[13]);
        D2 ^= camellia_f64(D1, k_dec[14]);
        D1 ^= camellia_f64(D2, k_dec[15]);
        D2 ^= camellia_f64(D1, k_dec[16]);
        D1 ^= camellia_f64(D2, k_dec[17]);
        D1 = camellia_fl(D1, ke_dec[4]);
        D2 = camellia_flinv(D2, ke_dec[5]);
        D2 ^= camellia_f64(D1, k_dec[18]);
        D1 ^= camellia_f64(D2, k_dec[19]);
        D2 ^= camellia_f64(D1, k_dec[20]);
        D1 ^= camellia_f64(D2, k_dec[21]);
        D2 ^= camellia_f64(D1, k_dec[22]);
        D1 ^= camellia_f64(D2, k_dec[23]);
    }

    D2 ^= kw_dec[2];
    D1 ^= kw_dec[3];
    store_block_be(output, D1, D2);
    
    return 0;
}

/**
 * @brief Camellia Encrypt Data
 */
noxtls_return_t noxtls_camellia_encrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode)
{
    switch(mode) {
        case NOXTLS_CAMELLIA_ECB:
            return noxtls_camellia_encrypt_ecb(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CBC:
            return noxtls_camellia_encrypt_cbc(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CTR:
            return noxtls_camellia_encrypt_ctr(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CFB:
            return noxtls_camellia_encrypt_cfb(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_OFB:
            return noxtls_camellia_encrypt_ofb(key, data, data_len, iv, output, type);
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
}

/**
 * @brief Camellia Decrypt Data
 */
noxtls_return_t noxtls_camellia_decrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode)
{
    switch(mode) {
        case NOXTLS_CAMELLIA_ECB:
            return noxtls_camellia_decrypt_ecb(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CBC:
            return noxtls_camellia_decrypt_cbc(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CTR:
            return noxtls_camellia_decrypt_ctr(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_CFB:
            return noxtls_camellia_decrypt_cfb(key, data, data_len, iv, output, type);
        case NOXTLS_CAMELLIA_OFB:
            return noxtls_camellia_decrypt_ofb(key, data, data_len, iv, output, type);
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
}

static uint8_t camellia_key_size_bytes(noxtls_camellia_type_t type)
{
    switch(type) {
        case NOXTLS_CAMELLIA_128_BIT:
            return 16;
        case NOXTLS_CAMELLIA_192_BIT:
            return 24;
        case NOXTLS_CAMELLIA_256_BIT:
            return 32;
        default:
            return 0;
    }
}

static void camellia_counter_inc(uint8_t counter[NOXTLS_CAMELLIA_BLOCK_LENGTH])
{
    int i;
    for(i = NOXTLS_CAMELLIA_BLOCK_LENGTH - 1; i >= 0; i--) {
        counter[i]++;
        if(counter[i] != 0) {
            break;
        }
    }
}

noxtls_return_t noxtls_camellia_init(noxtls_camellia_context_t *ctx,
                  const uint8_t *key,
                  const uint8_t *iv,
                  noxtls_camellia_type_t type,
                  noxtls_camellia_mode_t mode,
                  noxtls_camellia_operation_t op)
{
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    ctx->mode = mode;
    ctx->op = op;
    ctx->key_len = camellia_key_size_bytes(type);
    if(ctx->key_len == 0) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    memcpy(ctx->key, key, ctx->key_len);

    switch(mode) {
        case NOXTLS_CAMELLIA_ECB:
            break;
        case NOXTLS_CAMELLIA_CBC:
            if(iv != NULL) {
                memcpy(ctx->feedback, iv, NOXTLS_CAMELLIA_BLOCK_LENGTH);
            } else {
                memset(ctx->feedback, 0, NOXTLS_CAMELLIA_BLOCK_LENGTH);
            }
            break;
        case NOXTLS_CAMELLIA_CTR:
        case NOXTLS_CAMELLIA_CFB:
        case NOXTLS_CAMELLIA_OFB:
            if(iv == NULL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            memcpy(ctx->feedback, iv, NOXTLS_CAMELLIA_BLOCK_LENGTH);
            ctx->partial_len = NOXTLS_CAMELLIA_BLOCK_LENGTH;
            break;
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }

    ctx->initialized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_camellia_update(noxtls_camellia_context_t *ctx,
                    const uint8_t *input,
                    uint32_t input_len,
                    uint8_t *output,
                    uint32_t *output_len)
{
    uint32_t produced = 0;
    uint32_t i;

    if(ctx == NULL || output_len == NULL) {
        return -1;
    }
    *output_len = 0;

    if(!ctx->initialized) {
        return -1;
    }
    if(input_len > 0 && (input == NULL || output == NULL)) {
        return -1;
    }
    if(input_len == 0) {
        return 0;
    }

    switch(ctx->mode) {
        case NOXTLS_CAMELLIA_ECB:
        case NOXTLS_CAMELLIA_CBC:
            while(input_len > 0) {
                uint32_t need = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (input_len < need) ? input_len : need;
                memcpy(ctx->partial + ctx->partial_len, input, take);
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                input += take;
                input_len -= take;

                if(ctx->partial_len == NOXTLS_CAMELLIA_BLOCK_LENGTH) {
                    if(ctx->mode == NOXTLS_CAMELLIA_ECB) {
                        if(ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) {
                            if(noxtls_camellia_encrypt_block_internal(ctx->key, ctx->partial, output + produced, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return -1;
                            }
                        } else {
                            if(noxtls_camellia_decrypt_block_internal(ctx->key, ctx->partial, output + produced, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                        }
                    } else {
                        if(ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
                            for(i = 0; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i++) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            if(noxtls_camellia_encrypt_block_internal(ctx->key, block, output + produced, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                            memcpy(ctx->feedback, output + produced, NOXTLS_CAMELLIA_BLOCK_LENGTH);
                        } else {
                            uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
                            if(noxtls_camellia_decrypt_block_internal(ctx->key, ctx->partial, block, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return -1;
                            }
                            for(i = 0; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i++) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            memcpy(ctx->feedback, ctx->partial, NOXTLS_CAMELLIA_BLOCK_LENGTH);
                        }
                    }
                    produced += NOXTLS_CAMELLIA_BLOCK_LENGTH;
                    ctx->partial_len = 0;
                }
            }
            break;

        case NOXTLS_CAMELLIA_CTR:
        case NOXTLS_CAMELLIA_CFB:
        case NOXTLS_CAMELLIA_OFB:
            while(input_len > 0) {
                if(ctx->partial_len == NOXTLS_CAMELLIA_BLOCK_LENGTH) {
                    if(ctx->mode == NOXTLS_CAMELLIA_CTR) {
                        if(noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        camellia_counter_inc(ctx->feedback);
                    } else if(ctx->mode == NOXTLS_CAMELLIA_CFB) {
                        if(noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return -1;
                        }
                    } else {
                        if(noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return -1;
                        }
                        memcpy(ctx->feedback, ctx->partial, NOXTLS_CAMELLIA_BLOCK_LENGTH);
                    }
                    ctx->partial_len = 0;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (input_len < available) ? input_len : available;
                    for(i = 0; i < take; i++) {
                        uint8_t out_byte = (uint8_t)(input[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if(ctx->mode == NOXTLS_CAMELLIA_CFB) {
                            memmove(ctx->feedback, ctx->feedback + 1, NOXTLS_CAMELLIA_BLOCK_LENGTH - 1);
                            ctx->feedback[NOXTLS_CAMELLIA_BLOCK_LENGTH - 1] = (ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) ? out_byte : input[i];
                        }
                    }
                    input += take;
                    input_len -= take;
                    produced += take;
                    ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                }
            }
            break;

        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }

    *output_len = produced;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_camellia_final(noxtls_camellia_context_t *ctx,
                   uint8_t *output,
                   uint32_t *output_len)
{
    if(ctx == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0;

    if(!ctx->initialized) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if(ctx->mode == NOXTLS_CAMELLIA_CTR || ctx->mode == NOXTLS_CAMELLIA_CFB || ctx->mode == NOXTLS_CAMELLIA_OFB) {
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->op == NOXTLS_CAMELLIA_OP_DECRYPT) {
        if(ctx->partial_len != 0) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->partial_len > 0) {
        uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
        uint32_t i;

        if(output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        memset(block, 0, sizeof(block));
        memcpy(block, ctx->partial, ctx->partial_len);

        if(ctx->mode == NOXTLS_CAMELLIA_ECB) {
            if(noxtls_camellia_encrypt_block_internal(ctx->key, block, output, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else if(ctx->mode == NOXTLS_CAMELLIA_CBC) {
            for(i = 0; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i++) {
                block[i] ^= ctx->feedback[i];
            }
            if(noxtls_camellia_encrypt_block_internal(ctx->key, block, output, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            return NOXTLS_RETURN_INVALID_MODE;
        }

        *output_len = NOXTLS_CAMELLIA_BLOCK_LENGTH;
    }

    ctx->initialized = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Self Test (RFC 3713 Appendix A vectors)
 */
noxtls_return_t noxtls_camellia_self_test(void)
{
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t out[16];
    uint8_t dec[16];

    /* 128-bit key */
    (void)memset(key, 0, sizeof(key));
    key[0] = 0x01; key[1] = 0x23; key[2] = 0x45; key[3] = 0x67;
    key[4] = 0x89; key[5] = 0xab; key[6] = 0xcd; key[7] = 0xef;
    key[8] = 0xfe; key[9] = 0xdc; key[10] = 0xba; key[11] = 0x98;
    key[12] = 0x76; key[13] = 0x54; key[14] = 0x32; key[15] = 0x10;
    memcpy(pt, key, 16);
    noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_128_BIT);
    ct[0] = 0x67; ct[1] = 0x67; ct[2] = 0x31; ct[3] = 0x38;
    ct[4] = 0x54; ct[5] = 0x96; ct[6] = 0x69; ct[7] = 0x73;
    ct[8] = 0x08; ct[9] = 0x57; ct[10] = 0x06; ct[11] = 0x56;
    ct[12] = 0x48; ct[13] = 0xea; ct[14] = 0xbe; ct[15] = 0x43;
    if(memcmp(out, ct, 16) != 0) {
        camellia_print_block_hex("noxtls_camellia_self_test 128 expected: ", ct);
        camellia_print_block_hex("noxtls_camellia_self_test 128 actual  : ", out);
        return NOXTLS_RETURN_FAILED;
    }

    /* 192-bit key */
    key[16] = 0x00; key[17] = 0x11; key[18] = 0x22; key[19] = 0x33;
    key[20] = 0x44; key[21] = 0x55; key[22] = 0x66; key[23] = 0x77;
    noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_192_BIT);
    ct[0] = 0xb4; ct[1] = 0x99; ct[2] = 0x34; ct[3] = 0x01;
    ct[4] = 0xb3; ct[5] = 0xe9; ct[6] = 0x96; ct[7] = 0xf8;
    ct[8] = 0x4e; ct[9] = 0xe5; ct[10] = 0xce; ct[11] = 0xe7;
    ct[12] = 0xd7; ct[13] = 0x9b; ct[14] = 0x09; ct[15] = 0xb9;
    if(memcmp(out, ct, 16) != 0) {
        camellia_print_block_hex("noxtls_camellia_self_test 192 expected: ", ct);
        camellia_print_block_hex("noxtls_camellia_self_test 192 actual  : ", out);
        return -1;
    }

    /* 256-bit key */
    key[24] = 0x88; key[25] = 0x99; key[26] = 0xaa; key[27] = 0xbb;
    key[28] = 0xcc; key[29] = 0xdd; key[30] = 0xee; key[31] = 0xff;
    noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_256_BIT);
    ct[0] = 0x9a; ct[1] = 0xcc; ct[2] = 0x23; ct[3] = 0x7d;
    ct[4] = 0xff; ct[5] = 0x16; ct[6] = 0xd7; ct[7] = 0x6c;
    ct[8] = 0x20; ct[9] = 0xef; ct[10] = 0x7c; ct[11] = 0x91;
    ct[12] = 0x9e; ct[13] = 0x3a; ct[14] = 0x75; ct[15] = 0x09;
    if(memcmp(out, ct, 16) != 0) {
        camellia_print_block_hex("noxtls_camellia_self_test 256 expected: ", ct);
        camellia_print_block_hex("noxtls_camellia_self_test 256 actual  : ", out);
        return NOXTLS_RETURN_FAILED;
    }

    /* Decrypt roundtrip: decrypt 256-bit ciphertext and compare to original plaintext */
    noxtls_camellia_decrypt_block_internal(key, out, dec, NOXTLS_CAMELLIA_256_BIT);
    if(memcmp(dec, pt, 16) != 0) {
        camellia_print_block_hex("noxtls_camellia_self_test dec expected: ", pt);
        camellia_print_block_hex("noxtls_camellia_self_test dec actual  : ", dec);
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_CAMELLIA */
