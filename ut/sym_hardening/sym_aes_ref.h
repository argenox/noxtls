/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_aes_ref.h
* Summary: Independent byte-oriented reference AES for the sym_hardening tests.
*
* The S-box is derived from GF(2^8) inversion and the affine map at start-up
* (ref_build_sbox()), so it shares nothing with the library under test.
*****************************************************************************/
#ifndef SYM_AES_REF_H_
#define SYM_AES_REF_H_

#include <stdint.h>
#include <string.h>

/* ---- independent reference AES (byte-oriented, test-only) ---- */

static uint8_t g_sbox[256];
static uint8_t g_inv_sbox[256];

static uint8_t ref_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x & 0x80U) != 0U) ? 0x1BU : 0x00U));
}

static uint8_t ref_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0U;
    while (b != 0U) {
        if ((b & 1U) != 0U) {
            p ^= a;
        }
        a = ref_xtime(a);
        b >>= 1;
    }
    return p;
}

static void ref_build_sbox(void)
{
    uint32_t x;
    for (x = 0U; x < 256U; x += 1U) {
        uint8_t inv = 0U;
        uint8_t b;
        uint32_t y;
        if (x != 0U) {
            for (y = 1U; y < 256U; y += 1U) {
                if (ref_mul((uint8_t)x, (uint8_t)y) == 1U) {
                    inv = (uint8_t)y;
                    break;
                }
            }
        }
        b = inv;
        b = (uint8_t)(b ^ (uint8_t)((b << 1) | (b >> 7)) ^ (uint8_t)((b << 2) | (b >> 6)) ^
                      (uint8_t)((b << 3) | (b >> 5)) ^ (uint8_t)((b << 4) | (b >> 4)) ^ 0x63U);
        g_sbox[x] = b;
        g_inv_sbox[b] = (uint8_t)x;
    }
}

static void ref_expand(const uint8_t *key, uint32_t nk, uint32_t rounds, uint8_t rk[15][16])
{
    uint8_t w[60][4];
    uint8_t rcon = 1U;
    uint32_t i;
    for (i = 0U; i < nk; i += 1U) {
        memcpy(w[i], &key[4U * i], 4U);
    }
    for (i = nk; i < 4U * (rounds + 1U); i += 1U) {
        uint8_t t[4];
        memcpy(t, w[i - 1U], 4U);
        if ((i % nk) == 0U) {
            uint8_t t0 = t[0];
            t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[t0];
            rcon = ref_xtime(rcon);
        } else if ((nk > 6U) && ((i % nk) == 4U)) {
            t[0] = g_sbox[t[0]];
            t[1] = g_sbox[t[1]];
            t[2] = g_sbox[t[2]];
            t[3] = g_sbox[t[3]];
        }
        w[i][0] = (uint8_t)(w[i - nk][0] ^ t[0]);
        w[i][1] = (uint8_t)(w[i - nk][1] ^ t[1]);
        w[i][2] = (uint8_t)(w[i - nk][2] ^ t[2]);
        w[i][3] = (uint8_t)(w[i - nk][3] ^ t[3]);
    }
    for (i = 0U; i < 4U * (rounds + 1U); i += 1U) {
        memcpy(&rk[i / 4U][4U * (i % 4U)], w[i], 4U);
    }
}

/* State in FIPS 197 byte order: s[r + 4c]. */
/* Optional trace of every intermediate state (after each AddRoundKey and after
 * each SubBytes/ShiftRows step); used by the stack-residue tests. */
static uint8_t (*g_ref_trace)[16];
static uint32_t g_ref_trace_n;

static void ref_trace(const uint8_t st[16])
{
    if (g_ref_trace != NULL) {
        memcpy(g_ref_trace[g_ref_trace_n], st, 16U);
        g_ref_trace_n += 1U;
    }
}

static void ref_encrypt(const uint8_t *key, uint32_t nk, const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[15][16];
    uint8_t s[16];
    uint8_t t[16];
    uint32_t rounds = nk + 6U;
    uint32_t r;
    uint32_t i;
    ref_expand(key, nk, rounds, rk);
    for (i = 0U; i < 16U; i += 1U) {
        s[i] = (uint8_t)(in[i] ^ rk[0][i]);
    }
    ref_trace(s);
    for (r = 1U; r <= rounds; r += 1U) {
        uint32_t c;
        for (i = 0U; i < 16U; i += 1U) {
            uint32_t row = i % 4U;
            uint32_t col = i / 4U;
            t[i] = g_sbox[s[row + 4U * ((col + row) % 4U)]];
        }
        ref_trace(t);
        if (r < rounds) {
            for (c = 0U; c < 4U; c += 1U) {
                uint8_t a0 = t[4U * c];
                uint8_t a1 = t[4U * c + 1U];
                uint8_t a2 = t[4U * c + 2U];
                uint8_t a3 = t[4U * c + 3U];
                t[4U * c] = (uint8_t)(ref_mul(a0, 2U) ^ ref_mul(a1, 3U) ^ a2 ^ a3);
                t[4U * c + 1U] = (uint8_t)(a0 ^ ref_mul(a1, 2U) ^ ref_mul(a2, 3U) ^ a3);
                t[4U * c + 2U] = (uint8_t)(a0 ^ a1 ^ ref_mul(a2, 2U) ^ ref_mul(a3, 3U));
                t[4U * c + 3U] = (uint8_t)(ref_mul(a0, 3U) ^ a1 ^ a2 ^ ref_mul(a3, 2U));
            }
        }
        for (i = 0U; i < 16U; i += 1U) {
            s[i] = (uint8_t)(t[i] ^ rk[r][i]);
        }
        if (r < rounds) {
            ref_trace(s);
        }
    }
    memcpy(out, s, 16U);
}

static void ref_decrypt(const uint8_t *key, uint32_t nk, const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[15][16];
    uint8_t s[16];
    uint8_t t[16];
    uint32_t rounds = nk + 6U;
    uint32_t r;
    uint32_t i;
    ref_expand(key, nk, rounds, rk);
    for (i = 0U; i < 16U; i += 1U) {
        s[i] = (uint8_t)(in[i] ^ rk[rounds][i]);
    }
    ref_trace(s);
    for (r = rounds; r >= 1U; r -= 1U) {
        uint32_t c;
        for (i = 0U; i < 16U; i += 1U) {
            uint32_t row = i % 4U;
            uint32_t col = i / 4U;
            t[row + 4U * ((col + row) % 4U)] = g_inv_sbox[s[i]];
        }
        ref_trace(t);
        for (i = 0U; i < 16U; i += 1U) {
            t[i] = (uint8_t)(t[i] ^ rk[r - 1U][i]);
        }
        if (r > 1U) {
            ref_trace(t);
        }
        if (r > 1U) {
            for (c = 0U; c < 4U; c += 1U) {
                uint8_t a0 = t[4U * c];
                uint8_t a1 = t[4U * c + 1U];
                uint8_t a2 = t[4U * c + 2U];
                uint8_t a3 = t[4U * c + 3U];
                t[4U * c] = (uint8_t)(ref_mul(a0, 14U) ^ ref_mul(a1, 11U) ^ ref_mul(a2, 13U) ^ ref_mul(a3, 9U));
                t[4U * c + 1U] = (uint8_t)(ref_mul(a0, 9U) ^ ref_mul(a1, 14U) ^ ref_mul(a2, 11U) ^ ref_mul(a3, 13U));
                t[4U * c + 2U] = (uint8_t)(ref_mul(a0, 13U) ^ ref_mul(a1, 9U) ^ ref_mul(a2, 14U) ^ ref_mul(a3, 11U));
                t[4U * c + 3U] = (uint8_t)(ref_mul(a0, 11U) ^ ref_mul(a1, 13U) ^ ref_mul(a2, 9U) ^ ref_mul(a3, 14U));
            }
        }
        memcpy(s, t, 16U);
    }
    memcpy(out, s, 16U);
}


#endif /* SYM_AES_REF_H_ */
