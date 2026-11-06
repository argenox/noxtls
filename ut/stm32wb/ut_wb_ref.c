/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_ref.c
* Summary: Independent AES / GHASH / big-number reference used by the STM32WB peripheral model
*****************************************************************************/

/**
 * @file ut_wb_ref.c
 * @brief Test-only reference primitives (FIPS 197 AES, GCM GF(2^128) product, modular arithmetic).
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_ref.h"

#include <string.h>

/** Forward and inverse S-boxes, built on first use. */
static uint8_t s_sbox[256];
static uint8_t s_inv_sbox[256];
static uint8_t s_ready;

/**
 * @brief Build the S-box from the GF(2^8) inverse and the affine transform (FIPS 197 5.1.1).
 */
static void ut_ref_init(void)
{
    uint8_t p = 1U;
    uint8_t q = 1U;
    uint8_t x;
    uint32_t i;

    if (s_ready != 0U) {
        return;
    }
    do {
        p = (uint8_t)(p ^ (uint8_t)(p << 1) ^ (((p & 0x80U) != 0U) ? 0x1BU : 0U));
        q = (uint8_t)(q ^ (uint8_t)(q << 1));
        q = (uint8_t)(q ^ (uint8_t)(q << 2));
        q = (uint8_t)(q ^ (uint8_t)(q << 4));
        if ((q & 0x80U) != 0U) {
            q = (uint8_t)(q ^ 0x09U);
        }
        x = (uint8_t)(q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^
                      (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4)));
        s_sbox[p] = (uint8_t)(x ^ 0x63U);
    } while (p != 1U);
    s_sbox[0] = 0x63U;
    for (i = 0U; i < 256U; i++) {
        s_inv_sbox[s_sbox[i]] = (uint8_t)i;
    }
    s_ready = 1U;
}

/** xtime: multiply by x in GF(2^8). */
static uint8_t xt(uint8_t v)
{
    return (uint8_t)((v << 1) ^ (((v & 0x80U) != 0U) ? 0x1BU : 0U));
}

/** GF(2^8) multiply. */
static uint8_t gm(uint8_t a, uint8_t b)
{
    uint8_t r = 0U;

    while (b != 0U) {
        if ((b & 1U) != 0U) {
            r = (uint8_t)(r ^ a);
        }
        a = xt(a);
        b = (uint8_t)(b >> 1);
    }
    return r;
}

void ut_ref_aes_set_key(ut_ref_aes_t *ctx, const uint8_t *key, uint32_t key_len)
{
    uint32_t nk = key_len / 4U;
    uint32_t total;
    uint32_t i;
    uint8_t t[4];
    uint8_t rcon = 1U;
    uint8_t tmp;

    ut_ref_init();
    ctx->rounds = (uint8_t)(nk + 6U);
    total = 4U * ((uint32_t)ctx->rounds + 1U);
    memcpy(ctx->rk, key, key_len);
    for (i = nk; i < total; i++) {
        memcpy(t, &ctx->rk[(i - 1U) * 4U], 4U);
        if ((i % nk) == 0U) {
            tmp = t[0];
            t[0] = (uint8_t)(s_sbox[t[1]] ^ rcon);
            t[1] = s_sbox[t[2]];
            t[2] = s_sbox[t[3]];
            t[3] = s_sbox[tmp];
            rcon = xt(rcon);
        } else if ((nk > 6U) && ((i % nk) == 4U)) {
            t[0] = s_sbox[t[0]];
            t[1] = s_sbox[t[1]];
            t[2] = s_sbox[t[2]];
            t[3] = s_sbox[t[3]];
        } else {
            /* No transform. */
        }
        for (tmp = 0U; tmp < 4U; tmp++) {
            ctx->rk[i * 4U + tmp] = (uint8_t)(ctx->rk[(i - nk) * 4U + tmp] ^ t[tmp]);
        }
    }
}

/** AddRoundKey. */
static void ark(uint8_t *s, const uint8_t *rk)
{
    uint32_t i;

    for (i = 0U; i < 16U; i++) {
        s[i] = (uint8_t)(s[i] ^ rk[i]);
    }
}

void ut_ref_aes_enc(const ut_ref_aes_t *ctx, const uint8_t *in, uint8_t *out)
{
    uint8_t s[16];
    uint8_t t[16];
    uint32_t r;
    uint32_t i;
    uint32_t c;

    ut_ref_init();
    memcpy(s, in, 16U);
    ark(s, ctx->rk);
    for (r = 1U; r <= ctx->rounds; r++) {
        for (i = 0U; i < 16U; i++) {
            t[i] = s_sbox[s[i]];
        }
        /* ShiftRows: byte (row, col) = s[row + 4 * col]. */
        for (c = 0U; c < 4U; c++) {
            for (i = 0U; i < 4U; i++) {
                s[i + 4U * c] = t[i + 4U * ((c + i) % 4U)];
            }
        }
        if (r != ctx->rounds) {
            for (c = 0U; c < 4U; c++) {
                uint8_t *col = &s[4U * c];
                uint8_t a0 = col[0];
                uint8_t a1 = col[1];
                uint8_t a2 = col[2];
                uint8_t a3 = col[3];

                col[0] = (uint8_t)(xt(a0) ^ (uint8_t)(xt(a1) ^ a1) ^ a2 ^ a3);
                col[1] = (uint8_t)(a0 ^ xt(a1) ^ (uint8_t)(xt(a2) ^ a2) ^ a3);
                col[2] = (uint8_t)(a0 ^ a1 ^ xt(a2) ^ (uint8_t)(xt(a3) ^ a3));
                col[3] = (uint8_t)((uint8_t)(xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3));
            }
        }
        ark(s, &ctx->rk[16U * r]);
    }
    memcpy(out, s, 16U);
}

void ut_ref_aes_dec(const ut_ref_aes_t *ctx, const uint8_t *in, uint8_t *out)
{
    uint8_t s[16];
    uint8_t t[16];
    uint32_t r;
    uint32_t i;
    uint32_t c;

    ut_ref_init();
    memcpy(s, in, 16U);
    ark(s, &ctx->rk[16U * ctx->rounds]);
    for (r = ctx->rounds; r >= 1U; r--) {
        /* InvShiftRows. */
        for (c = 0U; c < 4U; c++) {
            for (i = 0U; i < 4U; i++) {
                t[i + 4U * ((c + i) % 4U)] = s[i + 4U * c];
            }
        }
        for (i = 0U; i < 16U; i++) {
            s[i] = s_inv_sbox[t[i]];
        }
        ark(s, &ctx->rk[16U * (r - 1U)]);
        if (r != 1U) {
            for (c = 0U; c < 4U; c++) {
                uint8_t *col = &s[4U * c];
                uint8_t a0 = col[0];
                uint8_t a1 = col[1];
                uint8_t a2 = col[2];
                uint8_t a3 = col[3];

                col[0] = (uint8_t)(gm(a0, 14U) ^ gm(a1, 11U) ^ gm(a2, 13U) ^ gm(a3, 9U));
                col[1] = (uint8_t)(gm(a0, 9U) ^ gm(a1, 14U) ^ gm(a2, 11U) ^ gm(a3, 13U));
                col[2] = (uint8_t)(gm(a0, 13U) ^ gm(a1, 9U) ^ gm(a2, 14U) ^ gm(a3, 11U));
                col[3] = (uint8_t)(gm(a0, 11U) ^ gm(a1, 13U) ^ gm(a2, 9U) ^ gm(a3, 14U));
            }
        }
    }
    memcpy(out, s, 16U);
}

void ut_ref_gf_mul(uint8_t *x, const uint8_t *h)
{
    uint8_t z[16] = { 0 };
    uint8_t v[16];
    uint32_t i;
    uint32_t j;
    uint8_t lsb;

    memcpy(v, h, 16U);
    for (i = 0U; i < 128U; i++) {
        if (((x[i / 8U] >> (7U - (i % 8U))) & 1U) != 0U) {
            for (j = 0U; j < 16U; j++) {
                z[j] = (uint8_t)(z[j] ^ v[j]);
            }
        }
        lsb = (uint8_t)(v[15] & 1U);
        for (j = 15U; j > 0U; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1U] << 7));
        }
        v[0] = (uint8_t)(v[0] >> 1);
        if (lsb != 0U) {
            v[0] = (uint8_t)(v[0] ^ 0xE1U);
        }
    }
    memcpy(x, z, 16U);
}

/** r = (r + a) mod m, with r, a < m. */
static void bn_addmod(uint8_t *r, const uint8_t *a, const uint8_t *m, uint32_t len)
{
    uint32_t carry = 0U;
    uint32_t i;
    uint32_t v;
    int ge = 1;
    uint8_t borrow = 0U;
    int32_t d;

    for (i = len; i > 0U; i--) {
        v = (uint32_t)r[i - 1U] + (uint32_t)a[i - 1U] + carry;
        r[i - 1U] = (uint8_t)v;
        carry = v >> 8;
    }
    if (carry == 0U) {
        ge = 0;
        for (i = 0U; i < len; i++) {
            if (r[i] != m[i]) {
                ge = (r[i] > m[i]) ? 1 : 0;
                break;
            }
            if (i == (len - 1U)) {
                ge = 1;
            }
        }
    }
    if (ge != 0) {
        for (i = len; i > 0U; i--) {
            d = (int32_t)r[i - 1U] - (int32_t)m[i - 1U] - (int32_t)borrow;
            borrow = (d < 0) ? 1U : 0U;
            r[i - 1U] = (uint8_t)d;
        }
    }
}

void ut_ref_mulmod(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *m, uint32_t len)
{
    uint8_t acc[400] = { 0 };
    uint32_t i;
    int bit;

    for (i = 0U; i < len * 8U; i++) {
        bn_addmod(acc, acc, m, len);
        bit = (b[i / 8U] >> (7U - (i % 8U))) & 1;
        if (bit != 0) {
            bn_addmod(acc, a, m, len);
        }
    }
    memcpy(out, acc, len);
}

void ut_ref_modexp(uint8_t *out, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *m,
                   uint32_t len)
{
    uint8_t res[400] = { 0 };
    uint8_t tmp[400];
    uint32_t i;
    int bit;

    res[len - 1U] = 1U;
    for (i = 0U; i < exp_len * 8U; i++) {
        ut_ref_mulmod(tmp, res, res, m, len);
        memcpy(res, tmp, len);
        bit = (exp[i / 8U] >> (7U - (i % 8U))) & 1;
        if (bit != 0) {
            ut_ref_mulmod(tmp, res, base, m, len);
            memcpy(res, tmp, len);
        }
    }
    memcpy(out, res, len);
}
