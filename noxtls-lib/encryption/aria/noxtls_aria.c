/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_aria.c
* Summary: ARIA Block Cipher Algorithm Implementation
*
* ARIA is a block cipher developed in South Korea, standardized in RFC 5794.
* This implementation follows the ARIA specification.
*
*/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Includes */
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_aria.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_ARIA

/* ARIA S-boxes (S1, S2, inverse S1, inverse S2) */
static const uint8_t aria_s1[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aria_s2[256] = {
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
};

/* Diffusion layer (DL) - multiplication by constant matrix */
static void aria_diffusion_layer(uint8_t state[16])
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
    
    memcpy(state, temp, 16);
}

static void aria_sl1(uint8_t state[16])
{
    static uint8_t inv_s1[256];
    static uint8_t inv_s2[256];
    static int inv_init = 0;
    const uint8_t *sb1 = aria_s1;
    const uint8_t *sb2 = aria_s2;
    const uint8_t *sb3 = inv_s1;
    const uint8_t *sb4 = inv_s2;

    if(!inv_init) {
        int i;
        for(i = 0; i < 256; i++) {
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

static void aria_sl2(uint8_t state[16])
{
    static uint8_t inv_s1[256];
    static uint8_t inv_s2[256];
    static int inv_init = 0;
    const uint8_t *sb1 = aria_s1;
    const uint8_t *sb2 = aria_s2;
    const uint8_t *sb3 = inv_s1;
    const uint8_t *sb4 = inv_s2;

    if(!inv_init) {
        int i;
        for(i = 0; i < 256; i++) {
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

static void aria_xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    int i;
    for(i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static uint64_t aria_load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           ((uint64_t)p[7]);
}

static void aria_store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

static void aria_rotate_right(const uint8_t in[16], uint8_t out[16], int bits)
{
    uint64_t hi = aria_load_be64(in);
    uint64_t lo = aria_load_be64(in + 8);
    int b = bits & 127;

    if(b == 0) {
        aria_store_be64(out, hi);
        aria_store_be64(out + 8, lo);
        return;
    }

    if(b < 64) {
        uint64_t new_hi = (hi >> b) | (lo << (64 - b));
        uint64_t new_lo = (lo >> b) | (hi << (64 - b));
        aria_store_be64(out, new_hi);
        aria_store_be64(out + 8, new_lo);
    } else if(b == 64) {
        aria_store_be64(out, lo);
        aria_store_be64(out + 8, hi);
    } else {
        int s = b - 64;
        uint64_t new_hi = (lo >> s) | (hi << (64 - s));
        uint64_t new_lo = (hi >> s) | (lo << (64 - s));
        aria_store_be64(out, new_hi);
        aria_store_be64(out + 8, new_lo);
    }
}

static void aria_rotate_left(const uint8_t in[16], uint8_t out[16], int bits)
{
    aria_rotate_right(in, out, 128 - (bits & 127));
}

static void aria_fo(uint8_t out[16], const uint8_t in[16], const uint8_t rk[16])
{
    memcpy(out, in, 16);
    aria_xor_block(out, out, rk);
    aria_sl1(out);
    aria_diffusion_layer(out);
}

static void aria_fe(uint8_t out[16], const uint8_t in[16], const uint8_t rk[16])
{
    memcpy(out, in, 16);
    aria_xor_block(out, out, rk);
    aria_sl2(out);
    aria_diffusion_layer(out);
}

/* Key schedule generation */
static void aria_key_schedule(const uint8_t *user_key, aria_type_t key_type, aria_key_t *key)
{
    const uint8_t c1[16] = {0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0};
    const uint8_t c2[16] = {0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0};
    const uint8_t c3[16] = {0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e};
    const uint8_t *ck1 = NULL;
    const uint8_t *ck2 = NULL;
    const uint8_t *ck3 = NULL;
    uint8_t kl[16], kr[16];
    uint8_t w0[16], w1[16], w2[16], w3[16];
    uint8_t rot[16];
    uint8_t ek[17][16];
    int i;

    switch(key_type) {
        case ARIA_128_BIT:
            key->rounds = ARIA_128_ROUNDS;
            ck1 = c1; ck2 = c2; ck3 = c3;
            break;
        case ARIA_192_BIT:
            key->rounds = ARIA_192_ROUNDS;
            ck1 = c2; ck2 = c3; ck3 = c1;
            break;
        case ARIA_256_BIT:
            key->rounds = ARIA_256_ROUNDS;
            ck1 = c3; ck2 = c1; ck3 = c2;
            break;
        default:
            return;
    }

    memcpy(kl, user_key, 16);
    if(key_type == ARIA_128_BIT) {
        memset(kr, 0, 16);
    } else if(key_type == ARIA_192_BIT) {
        memcpy(kr, user_key + 16, 8);
        memset(kr + 8, 0, 8);
    } else {
        memcpy(kr, user_key + 16, 16);
    }

    memcpy(w0, kl, 16);
    aria_fo(w1, w0, ck1);
    aria_xor_block(w1, w1, kr);
    aria_fe(w2, w1, ck2);
    aria_xor_block(w2, w2, w0);
    aria_fo(w3, w2, ck3);
    aria_xor_block(w3, w3, w1);

    aria_rotate_right(w1, rot, 19); aria_xor_block(ek[0], w0, rot);
    aria_rotate_right(w2, rot, 19); aria_xor_block(ek[1], w1, rot);
    aria_rotate_right(w3, rot, 19); aria_xor_block(ek[2], w2, rot);
    aria_rotate_right(w0, rot, 19); aria_xor_block(ek[3], rot, w3);

    aria_rotate_right(w1, rot, 31); aria_xor_block(ek[4], w0, rot);
    aria_rotate_right(w2, rot, 31); aria_xor_block(ek[5], w1, rot);
    aria_rotate_right(w3, rot, 31); aria_xor_block(ek[6], w2, rot);
    aria_rotate_right(w0, rot, 31); aria_xor_block(ek[7], rot, w3);

    aria_rotate_left(w1, rot, 61); aria_xor_block(ek[8], w0, rot);
    aria_rotate_left(w2, rot, 61); aria_xor_block(ek[9], w1, rot);
    aria_rotate_left(w3, rot, 61); aria_xor_block(ek[10], w2, rot);
    aria_rotate_left(w0, rot, 61); aria_xor_block(ek[11], rot, w3);

    aria_rotate_left(w1, rot, 31); aria_xor_block(ek[12], w0, rot);
    aria_rotate_left(w2, rot, 31); aria_xor_block(ek[13], w1, rot);
    aria_rotate_left(w3, rot, 31); aria_xor_block(ek[14], w2, rot);
    aria_rotate_left(w0, rot, 31); aria_xor_block(ek[15], rot, w3);

    aria_rotate_left(w1, rot, 19); aria_xor_block(ek[16], w0, rot);

    for(i = 0; i <= key->rounds; i++) {
        memcpy(key->round_key[i], ek[i], 16);
    }
}

/**
 * @brief Set ARIA encryption key
 */
noxtls_return_t aria_set_encrypt_key(const uint8_t *user_key, aria_type_t key_type, aria_key_t *key)
{
    if(user_key == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    key->key_type = key_type;
    aria_key_schedule(user_key, key_type, key);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set ARIA decryption key
 */
noxtls_return_t aria_set_decrypt_key(const uint8_t *user_key, aria_type_t key_type, aria_key_t *key)
{
    int i;
    uint8_t temp_keys[17][16] = {{0}};

    if(user_key == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    key->key_type = key_type;
    aria_key_schedule(user_key, key_type, key);

    for(i = 0; i <= key->rounds; i++) {
        memcpy(temp_keys[i], key->round_key[i], 16);
    }

    memcpy(key->round_key[0], temp_keys[key->rounds], 16);
    for(i = 1; i < key->rounds; i++) {
        memcpy(key->round_key[i], temp_keys[key->rounds - i], 16);
        aria_diffusion_layer(key->round_key[i]);
    }
    memcpy(key->round_key[key->rounds], temp_keys[0], 16);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA block encryption
 */
void aria_encrypt_block(const aria_key_t *key, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    int round;
    
    if(key == NULL || in == NULL || out == NULL) {
        return;
    }
    
    /* Copy input to state */
    memcpy(state, in, 16);
    
    for(round = 1; round < key->rounds; round++) {
        if((round & 1) != 0) {
            aria_fo(state, state, key->round_key[round - 1]);
        } else {
            aria_fe(state, state, key->round_key[round - 1]);
        }
    }

    aria_xor_block(state, state, key->round_key[key->rounds - 1]);
    aria_sl2(state);
    aria_xor_block(state, state, key->round_key[key->rounds]);
    
    /* Copy state to output */
    memcpy(out, state, 16);
}

/**
 * @brief ARIA block decryption
 */
void aria_decrypt_block(const aria_key_t *key, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    int round;
    
    if(key == NULL || in == NULL || out == NULL) {
        return;
    }
    
    /* Copy input to state */
    memcpy(state, in, 16);
    
    for(round = 1; round < key->rounds; round++) {
        if((round & 1) != 0) {
            aria_fo(state, state, key->round_key[round - 1]);
        } else {
            aria_fe(state, state, key->round_key[round - 1]);
        }
    }

    aria_xor_block(state, state, key->round_key[key->rounds - 1]);
    aria_sl2(state);
    aria_xor_block(state, state, key->round_key[key->rounds]);
    
    /* Copy state to output */
    memcpy(out, state, 16);
}

/* Forward declarations for mode-specific functions */
extern noxtls_return_t aria_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_encrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_encrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_encrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_encrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);

extern noxtls_return_t aria_decrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_decrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_decrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_decrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);
extern noxtls_return_t aria_decrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, aria_type_t type);

/**
 * @brief ARIA Encrypt Data
 */
noxtls_return_t aria_encrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      aria_type_t type,
                      aria_mode_t mode)
{
    switch(mode) {
        case ARIA_ECB:
            return aria_encrypt_ecb(key, data, data_len, iv, output, type);
        case ARIA_CBC:
            return aria_encrypt_cbc(key, data, data_len, iv, output, type);
        case ARIA_CTR:
            return aria_encrypt_ctr(key, data, data_len, iv, output, type);
        case ARIA_CFB:
            return aria_encrypt_cfb(key, data, data_len, iv, output, type);
        case ARIA_OFB:
            return aria_encrypt_ofb(key, data, data_len, iv, output, type);
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
}

/**
 * @brief ARIA Decrypt Data
 */
noxtls_return_t aria_decrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      aria_type_t type,
                      aria_mode_t mode)
{
    switch(mode) {
        case ARIA_ECB:
            return aria_decrypt_ecb(key, data, data_len, iv, output, type);
        case ARIA_CBC:
            return aria_decrypt_cbc(key, data, data_len, iv, output, type);
        case ARIA_CTR:
            return aria_decrypt_ctr(key, data, data_len, iv, output, type);
        case ARIA_CFB:
            return aria_decrypt_cfb(key, data, data_len, iv, output, type);
        case ARIA_OFB:
            return aria_decrypt_ofb(key, data, data_len, iv, output, type);
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
}

static uint8_t aria_key_size_bytes(aria_type_t type)
{
    switch(type) {
        case ARIA_128_BIT:
            return 16;
        case ARIA_192_BIT:
            return 24;
        case ARIA_256_BIT:
            return 32;
        default:
            return 0;
    }
}

static void aria_counter_inc(uint8_t counter[ARIA_BLOCK_LENGTH])
{
    int i;
    for(i = ARIA_BLOCK_LENGTH - 1; i >= 0; i--) {
        counter[i]++;
        if(counter[i] != 0) {
            break;
        }
    }
}

noxtls_return_t aria_init(aria_context_t *ctx,
              const uint8_t *key,
              const uint8_t *iv,
              aria_type_t type,
              aria_mode_t mode,
              aria_operation_t op)
{
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    ctx->mode = mode;
    ctx->op = op;
    ctx->key_len = aria_key_size_bytes(type);
    if(ctx->key_len == 0) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    memcpy(ctx->key, key, ctx->key_len);

    { noxtls_return_t r = aria_set_encrypt_key(ctx->key, type, &ctx->enc_key);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }
    { noxtls_return_t r = aria_set_decrypt_key(ctx->key, type, &ctx->dec_key);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }

    switch(mode) {
        case ARIA_ECB:
            break;
        case ARIA_CBC:
            if(iv != NULL) {
                memcpy(ctx->feedback, iv, ARIA_BLOCK_LENGTH);
            } else {
                memset(ctx->feedback, 0, ARIA_BLOCK_LENGTH);
            }
            break;
        case ARIA_CTR:
        case ARIA_CFB:
        case ARIA_OFB:
            if(iv == NULL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            memcpy(ctx->feedback, iv, ARIA_BLOCK_LENGTH);
            ctx->partial_len = ARIA_BLOCK_LENGTH;
            break;
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }

    ctx->initialized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t aria_update(aria_context_t *ctx,
                const uint8_t *input,
                uint32_t input_len,
                uint8_t *output,
                uint32_t *output_len)
{
    uint32_t produced = 0;
    uint32_t i;

    if(ctx == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0;

    if(!ctx->initialized) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(input_len > 0 && (input == NULL || output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(input_len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    switch(ctx->mode) {
        case ARIA_ECB:
        case ARIA_CBC:
            while(input_len > 0) {
                uint32_t need = (uint32_t)ARIA_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (input_len < need) ? input_len : need;
                memcpy(ctx->partial + ctx->partial_len, input, take);
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                input += take;
                input_len -= take;

                if(ctx->partial_len == ARIA_BLOCK_LENGTH) {
                    if(ctx->mode == ARIA_ECB) {
                        if(ctx->op == ARIA_OP_ENCRYPT) {
                            aria_encrypt_block(&ctx->enc_key, ctx->partial, output + produced);
                        } else {
                            aria_decrypt_block(&ctx->dec_key, ctx->partial, output + produced);
                        }
                    } else {
                        if(ctx->op == ARIA_OP_ENCRYPT) {
                            uint8_t block[ARIA_BLOCK_LENGTH];
                            for(i = 0; i < ARIA_BLOCK_LENGTH; i++) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            aria_encrypt_block(&ctx->enc_key, block, output + produced);
                            memcpy(ctx->feedback, output + produced, ARIA_BLOCK_LENGTH);
                        } else {
                            uint8_t block[ARIA_BLOCK_LENGTH];
                            aria_decrypt_block(&ctx->dec_key, ctx->partial, block);
                            for(i = 0; i < ARIA_BLOCK_LENGTH; i++) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            memcpy(ctx->feedback, ctx->partial, ARIA_BLOCK_LENGTH);
                        }
                    }
                    produced += ARIA_BLOCK_LENGTH;
                    ctx->partial_len = 0;
                }
            }
            break;

        case ARIA_CTR:
        case ARIA_CFB:
        case ARIA_OFB:
            while(input_len > 0) {
                if(ctx->partial_len == ARIA_BLOCK_LENGTH) {
                    if(ctx->mode == ARIA_CTR) {
                        aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                        aria_counter_inc(ctx->feedback);
                    } else if(ctx->mode == ARIA_CFB) {
                        aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                    } else {
                        aria_encrypt_block(&ctx->enc_key, ctx->feedback, ctx->partial);
                        memcpy(ctx->feedback, ctx->partial, ARIA_BLOCK_LENGTH);
                    }
                    ctx->partial_len = 0;
                }

                {
                    uint32_t available = (uint32_t)ARIA_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (input_len < available) ? input_len : available;
                    for(i = 0; i < take; i++) {
                        uint8_t out_byte = (uint8_t)(input[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if(ctx->mode == ARIA_CFB) {
                            memmove(ctx->feedback, ctx->feedback + 1, ARIA_BLOCK_LENGTH - 1);
                            ctx->feedback[ARIA_BLOCK_LENGTH - 1] = (ctx->op == ARIA_OP_ENCRYPT) ? out_byte : input[i];
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

noxtls_return_t aria_final(aria_context_t *ctx,
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

    if(ctx->mode == ARIA_CTR || ctx->mode == ARIA_CFB || ctx->mode == ARIA_OFB) {
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->op == ARIA_OP_DECRYPT) {
        if(ctx->partial_len != 0) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->partial_len > 0) {
        uint8_t block[ARIA_BLOCK_LENGTH];
        uint8_t pad_value = (uint8_t)(ARIA_BLOCK_LENGTH - ctx->partial_len);
        uint32_t i;

        if(output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        memcpy(block, ctx->partial, ctx->partial_len);
        for(i = ctx->partial_len; i < ARIA_BLOCK_LENGTH; i++) {
            block[i] = pad_value;
        }

        if(ctx->mode == ARIA_ECB) {
            aria_encrypt_block(&ctx->enc_key, block, output);
        } else if(ctx->mode == ARIA_CBC) {
            for(i = 0; i < ARIA_BLOCK_LENGTH; i++) {
                block[i] ^= ctx->feedback[i];
            }
            aria_encrypt_block(&ctx->enc_key, block, output);
        } else {
            return NOXTLS_RETURN_INVALID_MODE;
        }
        *output_len = ARIA_BLOCK_LENGTH;
    }

    ctx->initialized = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Self Test
 */
noxtls_return_t aria_self_test(void)
{
    /* RFC 5794 A.1 test vector */
    const uint8_t key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t expected[16] = {
        0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73,
        0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78
    };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    aria_key_t enc_key, dec_key;
    
    /* Test encryption */
    if(aria_set_encrypt_key(key128, ARIA_128_BIT, &enc_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    aria_encrypt_block(&enc_key, plaintext, ciphertext);
    if(memcmp(ciphertext, expected, 16) != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Test decryption */
    if(aria_set_decrypt_key(key128, ARIA_128_BIT, &dec_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    aria_decrypt_block(&dec_key, ciphertext, decrypted);
    
    if(memcmp(plaintext, decrypted, 16) != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_ARIA */
