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
* File:    ut_nrf54_ref.c
* Summary: Reference AES / SHA-2 / GCM / CCM used as the oracle of the CRACEN mock
*
*****************************************************************************/


/**
 * @file ut_nrf54_ref.c
 * @brief Reference AES (FIPS 197) and SHA-2 (FIPS 180-4) for the CRACEN mock.
 * @ingroup noxtls_nrf54_ut
 *
 * The AES S-box is computed from its definition (multiplicative inverse in
 * GF(2^8) followed by the affine transform, FIPS 197 §5.1.1) instead of being
 * typed in, so a transcription error cannot hide in a table.
 */

#include <stdint.h>
#include <string.h>

#include "ut_nrf54_ref.h"

/** AES S-box (built on first use). */
static uint8_t s_sbox[256];
/** AES inverse S-box. */
static uint8_t s_isbox[256];
/** Non-zero once the boxes are built. */
static uint8_t s_boxes_ready;

/** SHA-256 round constants (FIPS 180-4 §4.2.2). */
static const uint32_t s_k256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

/** SHA-512 round constants (FIPS 180-4 §4.2.3). */
static const uint64_t s_k512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/** FIPS 180-4 §5.3 initial hash values. */
static const uint32_t s_iv224[8] = { 0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U,
                                     0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U };
static const uint32_t s_iv256[8] = { 0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                     0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U };
static const uint64_t s_iv384[8] = { 0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
                                     0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                                     0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL };
static const uint64_t s_iv512[8] = { 0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                                     0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                                     0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL };

/**
 * @brief GF(2^8) multiplication modulo x^8 + x^4 + x^3 + x + 1.
 * @internal
 *
 * @param[in] a Operand.
 * @param[in] b Operand.
 *
 * @return Product.
 */
static uint8_t ut_gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0U;
    uint8_t x = a;
    uint8_t y = b;

    while (y != 0U) {
        if ((y & 1U) != 0U) {
            p ^= x;
        }
        x = (uint8_t)((x << 1) ^ (((x & 0x80U) != 0U) ? 0x1BU : 0U));
        y >>= 1;
    }
    return p;
}

/**
 * @brief Build the S-boxes from their definition.
 * @internal
 */
static void ut_aes_boxes(void)
{
    uint32_t i;

    if (s_boxes_ready == 0U) {
        for (i = 0U; i < 256U; i++) {
            uint8_t inv = 0U;
            uint8_t s;
            uint32_t j;

            for (j = 1U; (i != 0U) && (j < 256U); j++) {
                if (ut_gmul((uint8_t)i, (uint8_t)j) == 1U) {
                    inv = (uint8_t)j;
                }
            }
            s = inv;
            for (j = 1U; j < 5U; j++) {
                s ^= (uint8_t)((inv << j) | (inv >> (8U - j)));
            }
            s ^= 0x63U;
            s_sbox[i] = s;
            s_isbox[s] = (uint8_t)i;
        }
        s_boxes_ready = 1U;
    }
}

int ut_aes_setkey(ut_aes_key_t * k, const uint8_t * key, uint32_t key_len)
{
    uint32_t nk = key_len / 4U;
    uint32_t total;
    uint32_t i;
    uint8_t rcon = 1U;

    if ((key_len != 16U) && (key_len != 24U) && (key_len != 32U)) {
        return -1;
    }
    ut_aes_boxes();
    k->rounds = nk + 6U;
    total = 4U * (k->rounds + 1U);
    for (i = 0U; i < nk; i++) {
        k->rk[i] = ((uint32_t)key[4U * i] << 24) | ((uint32_t)key[(4U * i) + 1U] << 16) |
                   ((uint32_t)key[(4U * i) + 2U] << 8) | (uint32_t)key[(4U * i) + 3U];
    }
    for (i = nk; i < total; i++) {
        uint32_t t = k->rk[i - 1U];

        if ((i % nk) == 0U) {
            t = (t << 8) | (t >> 24);
            t = ((uint32_t)s_sbox[t >> 24] << 24) | ((uint32_t)s_sbox[(t >> 16) & 0xFFU] << 16) |
                ((uint32_t)s_sbox[(t >> 8) & 0xFFU] << 8) | (uint32_t)s_sbox[t & 0xFFU];
            t ^= (uint32_t)rcon << 24;
            rcon = ut_gmul(rcon, 2U);
        } else if ((nk > 6U) && ((i % nk) == 4U)) {
            t = ((uint32_t)s_sbox[t >> 24] << 24) | ((uint32_t)s_sbox[(t >> 16) & 0xFFU] << 16) |
                ((uint32_t)s_sbox[(t >> 8) & 0xFFU] << 8) | (uint32_t)s_sbox[t & 0xFFU];
        } else {
            /* Plain word. */
        }
        k->rk[i] = k->rk[i - nk] ^ t;
    }
    return 0;
}

/**
 * @brief XOR a round key into the column-major state.
 * @internal
 *
 * @param[in,out] s     State (16 bytes, s[c * 4 + r]).
 * @param[in]     k     Expanded key.
 * @param[in]     round Round number.
 */
static void ut_aes_addkey(uint8_t * s, const ut_aes_key_t * k, uint32_t round)
{
    uint32_t c;

    for (c = 0U; c < 4U; c++) {
        uint32_t w = k->rk[(round * 4U) + c];

        s[c * 4U] ^= (uint8_t)(w >> 24);
        s[(c * 4U) + 1U] ^= (uint8_t)(w >> 16);
        s[(c * 4U) + 2U] ^= (uint8_t)(w >> 8);
        s[(c * 4U) + 3U] ^= (uint8_t)w;
    }
}

void ut_aes_encrypt(const ut_aes_key_t * k, const uint8_t * in, uint8_t * out)
{
    uint8_t s[16];
    uint8_t t[16];
    uint32_t r;
    uint32_t c;
    uint32_t i;

    (void)memcpy(s, in, 16U);
    ut_aes_addkey(s, k, 0U);
    for (r = 1U; r <= k->rounds; r++) {
        for (i = 0U; i < 16U; i++) {
            s[i] = s_sbox[s[i]];
        }
        for (c = 0U; c < 4U; c++) {
            for (i = 0U; i < 4U; i++) {
                t[(c * 4U) + i] = s[(((c + i) % 4U) * 4U) + i]; /* ShiftRows. */
            }
        }
        if (r != k->rounds) {
            for (c = 0U; c < 4U; c++) {
                const uint8_t * a = &t[c * 4U];

                s[c * 4U] = (uint8_t)(ut_gmul(a[0], 2U) ^ ut_gmul(a[1], 3U) ^ a[2] ^ a[3]);
                s[(c * 4U) + 1U] = (uint8_t)(a[0] ^ ut_gmul(a[1], 2U) ^ ut_gmul(a[2], 3U) ^ a[3]);
                s[(c * 4U) + 2U] = (uint8_t)(a[0] ^ a[1] ^ ut_gmul(a[2], 2U) ^ ut_gmul(a[3], 3U));
                s[(c * 4U) + 3U] = (uint8_t)(ut_gmul(a[0], 3U) ^ a[1] ^ a[2] ^ ut_gmul(a[3], 2U));
            }
        } else {
            (void)memcpy(s, t, 16U);
        }
        ut_aes_addkey(s, k, r);
    }
    (void)memcpy(out, s, 16U);
}

void ut_aes_decrypt(const ut_aes_key_t * k, const uint8_t * in, uint8_t * out)
{
    uint8_t s[16];
    uint8_t t[16];
    uint32_t r;
    uint32_t c;
    uint32_t i;

    (void)memcpy(s, in, 16U);
    ut_aes_addkey(s, k, k->rounds);
    for (r = k->rounds; r > 0U; r--) {
        for (c = 0U; c < 4U; c++) {
            for (i = 0U; i < 4U; i++) {
                t[(((c + i) % 4U) * 4U) + i] = s[(c * 4U) + i]; /* InvShiftRows. */
            }
        }
        for (i = 0U; i < 16U; i++) {
            t[i] = s_isbox[t[i]];
        }
        (void)memcpy(s, t, 16U);
        ut_aes_addkey(s, k, r - 1U);
        if (r != 1U) {
            for (c = 0U; c < 4U; c++) {
                uint8_t a[4];

                (void)memcpy(a, &s[c * 4U], 4U);
                s[c * 4U] = (uint8_t)(ut_gmul(a[0], 14U) ^ ut_gmul(a[1], 11U) ^ ut_gmul(a[2], 13U) ^ ut_gmul(a[3], 9U));
                s[(c * 4U) + 1U] = (uint8_t)(ut_gmul(a[0], 9U) ^ ut_gmul(a[1], 14U) ^ ut_gmul(a[2], 11U) ^ ut_gmul(a[3], 13U));
                s[(c * 4U) + 2U] = (uint8_t)(ut_gmul(a[0], 13U) ^ ut_gmul(a[1], 9U) ^ ut_gmul(a[2], 14U) ^ ut_gmul(a[3], 11U));
                s[(c * 4U) + 3U] = (uint8_t)(ut_gmul(a[0], 11U) ^ ut_gmul(a[1], 13U) ^ ut_gmul(a[2], 9U) ^ ut_gmul(a[3], 14U));
            }
        }
    }
    (void)memcpy(out, s, 16U);
}

uint32_t ut_sha_iv(uint32_t bits, uint8_t * state)
{
    uint32_t i;
    uint32_t j;
    uint32_t size = 0U;

    if ((bits == 224U) || (bits == 256U)) {
        const uint32_t * iv = (bits == 224U) ? s_iv224 : s_iv256;

        for (i = 0U; i < 8U; i++) {
            for (j = 0U; j < 4U; j++) {
                state[(i * 4U) + j] = (uint8_t)(iv[i] >> (24U - (8U * j)));
            }
        }
        size = 32U;
    } else if ((bits == 384U) || (bits == 512U)) {
        const uint64_t * iv = (bits == 384U) ? s_iv384 : s_iv512;

        for (i = 0U; i < 8U; i++) {
            for (j = 0U; j < 8U; j++) {
                state[(i * 8U) + j] = (uint8_t)(iv[i] >> (56U - (8U * j)));
            }
        }
        size = 64U;
    } else {
        /* Unknown. */
    }
    return size;
}

/** @brief 32-bit right rotation. */
#define UT_ROR32(x, n) (((x) >> (n)) | ((x) << (32U - (n))))
/** @brief 64-bit right rotation. */
#define UT_ROR64(x, n) (((x) >> (n)) | ((x) << (64U - (n))))

void ut_sha256_block(uint8_t * state, const uint8_t * block)
{
    uint32_t w[64];
    uint32_t h[8];
    uint32_t v[8];
    uint32_t i;

    for (i = 0U; i < 8U; i++) {
        h[i] = ((uint32_t)state[4U * i] << 24) | ((uint32_t)state[(4U * i) + 1U] << 16) |
               ((uint32_t)state[(4U * i) + 2U] << 8) | (uint32_t)state[(4U * i) + 3U];
        v[i] = h[i];
    }
    for (i = 0U; i < 16U; i++) {
        w[i] = ((uint32_t)block[4U * i] << 24) | ((uint32_t)block[(4U * i) + 1U] << 16) |
               ((uint32_t)block[(4U * i) + 2U] << 8) | (uint32_t)block[(4U * i) + 3U];
    }
    for (i = 16U; i < 64U; i++) {
        uint32_t s0 = UT_ROR32(w[i - 15U], 7U) ^ UT_ROR32(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
        uint32_t s1 = UT_ROR32(w[i - 2U], 17U) ^ UT_ROR32(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);

        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    for (i = 0U; i < 64U; i++) {
        uint32_t S1 = UT_ROR32(v[4], 6U) ^ UT_ROR32(v[4], 11U) ^ UT_ROR32(v[4], 25U);
        uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint32_t t1 = v[7] + S1 + ch + s_k256[i] + w[i];
        uint32_t S0 = UT_ROR32(v[0], 2U) ^ UT_ROR32(v[0], 13U) ^ UT_ROR32(v[0], 22U);
        uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint32_t t2 = S0 + maj;

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3] + t1;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = t1 + t2;
    }
    for (i = 0U; i < 8U; i++) {
        h[i] += v[i];
        state[4U * i] = (uint8_t)(h[i] >> 24);
        state[(4U * i) + 1U] = (uint8_t)(h[i] >> 16);
        state[(4U * i) + 2U] = (uint8_t)(h[i] >> 8);
        state[(4U * i) + 3U] = (uint8_t)h[i];
    }
}

void ut_sha512_block(uint8_t * state, const uint8_t * block)
{
    uint64_t w[80];
    uint64_t h[8];
    uint64_t v[8];
    uint32_t i;
    uint32_t j;

    for (i = 0U; i < 8U; i++) {
        h[i] = 0U;
        for (j = 0U; j < 8U; j++) {
            h[i] = (h[i] << 8) | (uint64_t)state[(8U * i) + j];
        }
        v[i] = h[i];
    }
    for (i = 0U; i < 16U; i++) {
        w[i] = 0U;
        for (j = 0U; j < 8U; j++) {
            w[i] = (w[i] << 8) | (uint64_t)block[(8U * i) + j];
        }
    }
    for (i = 16U; i < 80U; i++) {
        uint64_t s0 = UT_ROR64(w[i - 15U], 1U) ^ UT_ROR64(w[i - 15U], 8U) ^ (w[i - 15U] >> 7);
        uint64_t s1 = UT_ROR64(w[i - 2U], 19U) ^ UT_ROR64(w[i - 2U], 61U) ^ (w[i - 2U] >> 6);

        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    for (i = 0U; i < 80U; i++) {
        uint64_t S1 = UT_ROR64(v[4], 14U) ^ UT_ROR64(v[4], 18U) ^ UT_ROR64(v[4], 41U);
        uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint64_t t1 = v[7] + S1 + ch + s_k512[i] + w[i];
        uint64_t S0 = UT_ROR64(v[0], 28U) ^ UT_ROR64(v[0], 34U) ^ UT_ROR64(v[0], 39U);
        uint64_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint64_t t2 = S0 + maj;

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3] + t1;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = t1 + t2;
    }
    for (i = 0U; i < 8U; i++) {
        h[i] += v[i];
        for (j = 0U; j < 8U; j++) {
            state[(8U * i) + j] = (uint8_t)(h[i] >> (56U - (8U * j)));
        }
    }
}

void ut_sha(uint32_t bits, const uint8_t * msg, uint32_t len, uint8_t * digest)
{
    uint8_t state[64];
    uint8_t block[128];
    uint32_t bsz = ((bits == 384U) || (bits == 512U)) ? 128U : 64U;
    uint32_t lenfield = (bsz == 128U) ? 16U : 8U;
    uint32_t off = 0U;
    uint64_t total_bits = (uint64_t)len * 8U;
    uint32_t rem;
    uint32_t i;

    (void)ut_sha_iv(bits, state);
    while ((len - off) >= bsz) {
        if (bsz == 64U) {
            ut_sha256_block(state, &msg[off]);
        } else {
            ut_sha512_block(state, &msg[off]);
        }
        off += bsz;
    }
    rem = len - off;
    (void)memset(block, 0, sizeof(block));
    (void)memcpy(block, &msg[off], rem);
    block[rem] = 0x80U;
    if ((rem + 1U) > (bsz - lenfield)) {
        if (bsz == 64U) {
            ut_sha256_block(state, block);
        } else {
            ut_sha512_block(state, block);
        }
        (void)memset(block, 0, sizeof(block));
    }
    for (i = 0U; i < 8U; i++) {
        block[bsz - 1U - i] = (uint8_t)(total_bits >> (8U * i));
    }
    if (bsz == 64U) {
        ut_sha256_block(state, block);
    } else {
        ut_sha512_block(state, block);
    }
    (void)memcpy(digest, state, bits / 8U);
}

/**
 * @brief Value of one hex digit.
 * @internal
 *
 * @param[in] c Character.
 *
 * @return 0..15, or 16 for a non-hex character.
 */
static uint32_t ut_nibble(char c)
{
    uint32_t v = 16U;

    if ((c >= '0') && (c <= '9')) {
        v = (uint32_t)(c - '0');
    } else if ((c >= 'a') && (c <= 'f')) {
        v = (uint32_t)(c - 'a') + 10U;
    } else if ((c >= 'A') && (c <= 'F')) {
        v = (uint32_t)(c - 'A') + 10U;
    } else {
        /* Separator. */
    }
    return v;
}

uint32_t ut_hex(const char * hex, uint8_t * out, uint32_t max)
{
    uint32_t n = 0U;
    uint32_t hi = 16U;

    while ((*hex != '\0') && (n < max)) {
        uint32_t v = ut_nibble(*hex);

        if (v < 16U) {
            if (hi == 16U) {
                hi = v;
            } else {
                out[n] = (uint8_t)((hi << 4) | v);
                n++;
                hi = 16U;
            }
        }
        hex++;
    }
    return n;
}

/**
 * @brief GF(2^128) multiplication X = X * H (SP 800-38D §6.3, Algorithm 1).
 * @internal
 *
 * @param[in,out] x Block X.
 * @param[in]     h Block H.
 */
static void ut_gf128_mul(uint8_t * x, const uint8_t * h)
{
    uint8_t z[16] = { 0 };
    uint8_t v[16];
    uint32_t i;
    uint32_t j;

    (void)memcpy(v, h, 16U);
    for (i = 0U; i < 128U; i++) {
        uint8_t lsb = (uint8_t)(v[15] & 1U);

        if (((x[i / 8U] >> (7U - (i % 8U))) & 1U) != 0U) {
            for (j = 0U; j < 16U; j++) {
                z[j] ^= v[j];
            }
        }
        for (j = 15U; j > 0U; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | (uint8_t)(v[j - 1U] << 7));
        }
        v[0] >>= 1;
        if (lsb != 0U) {
            v[0] ^= 0xE1U;
        }
    }
    (void)memcpy(x, z, 16U);
}

/**
 * @brief GHASH update over zero-padded data (SP 800-38D §6.4).
 * @internal
 *
 * @param[in,out] y   Hash state.
 * @param[in]     h   Hash subkey.
 * @param[in]     d   Data.
 * @param[in]     len Bytes.
 */
static void ut_ghash(uint8_t * y, const uint8_t * h, const uint8_t * d, uint32_t len)
{
    uint32_t off;

    for (off = 0U; off < len; off += 16U) {
        uint32_t n = ((len - off) < 16U) ? (len - off) : 16U;
        uint32_t i;

        for (i = 0U; i < n; i++) {
            y[i] ^= d[off + i];
        }
        ut_gf128_mul(y, h);
    }
}

void ut_gcm(const uint8_t * key, uint32_t key_len, const uint8_t * iv, const uint8_t * aad, uint32_t aad_len,
            const uint8_t * in, uint32_t len, uint8_t * out, uint8_t dec, uint8_t * tag)
{
    ut_aes_key_t k;
    uint8_t h[16] = { 0 };
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t y[16] = { 0 };
    uint8_t lens[16];
    uint32_t off;
    uint32_t i;

    (void)ut_aes_setkey(&k, key, key_len);
    ut_aes_encrypt(&k, h, h);
    (void)memcpy(j0, iv, 12U);
    j0[12] = 0U;
    j0[13] = 0U;
    j0[14] = 0U;
    j0[15] = 1U;
    ut_ghash(y, h, aad, aad_len);
    if (dec != 0U) {
        ut_ghash(y, h, in, len);
    }
    (void)memcpy(ctr, j0, 16U);
    for (off = 0U; off < len; off += 16U) {
        uint8_t ks[16];
        uint32_t n = ((len - off) < 16U) ? (len - off) : 16U;

        for (i = 15U; i >= 12U; i--) {
            ctr[i]++;
            if (ctr[i] != 0U) {
                break;
            }
        }
        ut_aes_encrypt(&k, ctr, ks);
        for (i = 0U; i < n; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
    }
    if (dec == 0U) {
        ut_ghash(y, h, out, len);
    }
    for (i = 0U; i < 8U; i++) {
        lens[7U - i] = (uint8_t)(((uint64_t)aad_len * 8U) >> (8U * i));
        lens[15U - i] = (uint8_t)(((uint64_t)len * 8U) >> (8U * i));
    }
    ut_ghash(y, h, lens, 16U);
    ut_aes_encrypt(&k, j0, tag);
    for (i = 0U; i < 16U; i++) {
        tag[i] ^= y[i];
    }
}

/**
 * @brief CBC-MAC update over zero-padded data (SP 800-38C §6.1 step 4).
 * @internal
 *
 * @param[in]     k   Key.
 * @param[in,out] x   MAC state.
 * @param[in]     d   Data.
 * @param[in]     len Bytes.
 */
static void ut_cbcmac(const ut_aes_key_t * k, uint8_t * x, const uint8_t * d, uint32_t len)
{
    uint32_t off;

    for (off = 0U; off < len; off += 16U) {
        uint32_t n = ((len - off) < 16U) ? (len - off) : 16U;
        uint32_t i;

        for (i = 0U; i < n; i++) {
            x[i] ^= d[off + i];
        }
        ut_aes_encrypt(k, x, x);
    }
}

void ut_ccm(const uint8_t * key, uint32_t key_len, const uint8_t * hdr, uint32_t hdr_len,
            const uint8_t * in, uint32_t len, uint8_t * out, uint8_t dec, uint8_t * tag)
{
    ut_aes_key_t k;
    uint8_t x[16] = { 0 };
    uint8_t a[16] = { 0 };
    uint32_t q = (uint32_t)(hdr[0] & 7U) + 1U;
    uint32_t off;
    uint32_t i;

    (void)ut_aes_setkey(&k, key, key_len);
    ut_cbcmac(&k, x, hdr, hdr_len);
    a[0] = (uint8_t)(q - 1U);
    (void)memcpy(&a[1], &hdr[1], 15U - q);
    if (dec == 0U) {
        ut_cbcmac(&k, x, in, len);
    }
    for (off = 0U; off < len; off += 16U) {
        uint8_t ks[16];
        uint32_t n = ((len - off) < 16U) ? (len - off) : 16U;
        uint32_t ctr = (off / 16U) + 1U;

        for (i = 0U; (i < 4U) && (i < q); i++) {
            a[15U - i] = (uint8_t)(ctr >> (8U * i));
        }
        ut_aes_encrypt(&k, a, ks);
        for (i = 0U; i < n; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
    }
    if (dec != 0U) {
        ut_cbcmac(&k, x, out, len);
    }
    for (i = 0U; i < q; i++) {
        a[15U - i] = 0U;
    }
    ut_aes_encrypt(&k, a, tag);
    for (i = 0U; i < 16U; i++) {
        tag[i] ^= x[i];
    }
}
