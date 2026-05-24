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
* File:    noxtls_mlkem.c
* Summary: ML-KEM implementation (runtime-parametric, schoolbook core).
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "noxtls_mlkem.h"
#include "common/noxtls_ct.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"

static const uint8_t *g_mlkem_test_random_seq = NULL;
static uint32_t g_mlkem_test_random_seq_len = 0U;
static uint32_t g_mlkem_test_random_seq_off = 0U;

static void mlkem_poly_add(mlkem_poly_t *r, const mlkem_poly_t *a, const mlkem_poly_t *b);
static void mlkem_polyvec_add(mlkem_polyvec_t *r, const mlkem_polyvec_t *a, const mlkem_polyvec_t *b, uint8_t k);

static const int16_t mlkem_zetas[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
};

/**
 * @brief Get the parameters for the ML-KEM parameter set.
 *
 * @param[in] param The parameter set.
 * @param[out] p The parameters.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_get_params(noxtls_mlkem_param_t param, mlkem_params_t *p)
{
    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(p, 0, sizeof(*p));
    switch(param) {
        case NOXTLS_MLKEM_512:
            p->k = 2U; p->eta1 = 3U; p->eta2 = 2U; p->du = 10U; p->dv = 4U;
            p->public_key_len = 800u; p->secret_key_len = 1632u; p->ciphertext_len = 768u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLKEM_768:
            p->k = 3U; p->eta1 = 2U; p->eta2 = 2U; p->du = 10U; p->dv = 4U;
            p->public_key_len = 1184u; p->secret_key_len = 2400u; p->ciphertext_len = 1088u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLKEM_1024:
            p->k = 4U; p->eta1 = 2U; p->eta2 = 2U; p->du = 11U; p->dv = 5U;
            p->public_key_len = 1568u; p->secret_key_len = 3168u; p->ciphertext_len = 1568u;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Modulo q operation.
 *
 * @param[in] x The input value.
 * @return The modulo q value.
 */
static int16_t mlkem_mod_q(int32_t x)
{
    int32_t r = x % MLKEM_Q;
    if(r < 0) {
        r += MLKEM_Q;
    }
    return (int16_t)r;
}

/**
 * @brief Montgomery reduction.
 *
 * @param[in] a The input value.
 * @return The Montgomery reduction value.
 */
static int16_t mlkem_montgomery_reduce(int32_t a)
{
    int16_t t = (int16_t)(a * (int32_t)MLKEM_QINV);
    return (int16_t)((a - ((int32_t)t * MLKEM_Q)) >> 16);
}

/**
 * @brief Barrett reduction.
 *
 * @param[in] a The input value.
 * @return The Barrett reduction value.
 */
static int16_t mlkem_barrett_reduce(int16_t a)
{
    const int32_t v = ((1 << 26) + (MLKEM_Q / 2)) / MLKEM_Q;
    int32_t t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= MLKEM_Q;
    return (int16_t)(a - t);
}

/**
 * @brief Field multiplication.
 *
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 * @return The field multiplication value.
 */
static int16_t mlkem_fqmul(int16_t a, int16_t b)
{
    return mlkem_montgomery_reduce((int32_t)a * b);
}

/**
 * @brief Base multiplication.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 * @param[in] zeta The zeta value.
 */
static void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = mlkem_fqmul(a[1], b[1]);
    r[0] = mlkem_fqmul(r[0], zeta);
    r[0] = (int16_t)((int32_t)r[0] + mlkem_fqmul(a[0], b[0]));
    r[1] = (int16_t)((int32_t)mlkem_fqmul(a[0], b[1]) + mlkem_fqmul(a[1], b[0]));
}

/**
 * @brief Polynomial NTT.
 *
 * @param[out] r The output value.
 */
static void mlkem_poly_ntt(mlkem_poly_t *r)
{
    uint8_t k = 1U;
    uint32_t len;
    uint32_t start;
    uint32_t j;
    for(len = 128U; len >= 2U; len >>= 1U) {
        for(start = 0U; start < MLKEM_N; start = j + len) {
            int16_t zeta = mlkem_zetas[k++];
            for(j = start; j < start + len; j++) {
                int16_t t = mlkem_fqmul(zeta, r->c[j + len]);
                r->c[j + len] = (int16_t)((int32_t)r->c[j] - t);
                r->c[j] = (int16_t)((int32_t)r->c[j] + t);
            }
        }
    }
}

/**
 * @brief Polynomial inverse NTT to Montgomery.
 *
 * @param[out] r The output value.
 */
static void mlkem_poly_invntt_tomont(mlkem_poly_t *r)
{
    uint8_t k = 127u;
    uint32_t len;
    uint32_t start;
    uint32_t j;
    const int16_t f = 1441;
    for(len = 2U; len <= 128U; len <<= 1U) {
        for(start = 0U; start < MLKEM_N; start = j + len) {
            int16_t zeta = mlkem_zetas[k--];
            for(j = start; j < start + len; j++) {
                int16_t t = r->c[j];
                r->c[j] = mlkem_barrett_reduce((int16_t)((int32_t)t + r->c[j + len]));
                r->c[j + len] = (int16_t)((int32_t)t - r->c[j + len]);
                r->c[j + len] = mlkem_fqmul(zeta, r->c[j + len]);
            }
        }
    }
    for(j = 0U; j < MLKEM_N; j++) {
        r->c[j] = mlkem_fqmul(r->c[j], f);
    }
}

/**
 * @brief Polynomial base multiplication in Montgomery domain.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 */
static void mlkem_poly_basemul_montgomery(mlkem_poly_t *r, const mlkem_poly_t *a, const mlkem_poly_t *b)
{
    uint32_t i;
    for(i = 0U; i < (MLKEM_N / 4U); i++) {
        mlkem_basemul(&r->c[4U * i], &a->c[4U * i], &b->c[4U * i], mlkem_zetas[64U + i]);
        mlkem_basemul(&r->c[4U * i + 2U], &a->c[4U * i + 2U], &b->c[4U * i + 2U], (int16_t)-mlkem_zetas[64U + i]);
    }
}

/**
 * @brief Polynomial to Montgomery domain.
 *
 * @param[out] r The output value.
 */
static void mlkem_poly_tomont(mlkem_poly_t *r)
{
    uint32_t i;
    const int16_t f = 1353;
    for(i = 0U; i < MLKEM_N; i++) {
        r->c[i] = mlkem_fqmul(r->c[i], f);
    }
}

/**
 * @brief Polynomial reduction.
 *
 * @param[out] r The output value.
 */
static void mlkem_poly_reduce(mlkem_poly_t *r)
{
    uint32_t i;
    for(i = 0U; i < MLKEM_N; i++) {
        r->c[i] = mlkem_barrett_reduce(r->c[i]);
    }
}

/**
 * @brief Polynomial vector NTT.
 *
 * @param[out] v The output value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_ntt(mlkem_polyvec_t *v, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_ntt(&v->v[i]);
    }
}

/**
 * @brief Polynomial vector inverse NTT to Montgomery.
 *
 * @param[out] v The output value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_invntt_tomont(mlkem_polyvec_t *v, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_invntt_tomont(&v->v[i]);
    }
}

/**
 * @brief Polynomial vector reduction.
 *
 * @param[out] v The output value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_reduce(mlkem_polyvec_t *v, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_reduce(&v->v[i]);
    }
}

/**
 * @brief Polynomial vector base multiplication in Montgomery domain.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_basemul_acc_montgomery(mlkem_poly_t *r, const mlkem_polyvec_t *a, const mlkem_polyvec_t *b, uint8_t k)
{
    uint8_t i;
    mlkem_poly_t t;
    mlkem_poly_basemul_montgomery(r, &a->v[0], &b->v[0]);
    for(i = 1; i < k; i++) {
        mlkem_poly_basemul_montgomery(&t, &a->v[i], &b->v[i]);
        mlkem_poly_add(r, r, &t);
    }
}

/**
 * @brief SHAKE256 expand.
 *
 * @param[in] seed The input seed.
 * @param[in] seed_len The length of the input seed.
 * @param[out] out The output buffer.
 * @param[in] out_len The length of the output buffer.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_shake_expand(const uint8_t *seed, uint32_t seed_len, uint8_t *out, uint32_t out_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc;
    rc = noxtls_shake256_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&ctx, seed, seed_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_final(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_shake256_squeeze(&ctx, out, out_len);
}

/**
 * @brief SHA3-256.
 *
 * @param[in] in The input value.
 * @param[in] in_len The length of the input value.
 * @param[out] out The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_sha3_256(const uint8_t *in, uint32_t in_len, uint8_t out[32])
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha3_256_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha3_update(&ctx, in, in_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_sha3_finish(&ctx, out);
}

/**
 * @brief SHA3-512.
 *
 * @param[in] in The input value.
 * @param[in] in_len The length of the input value.
 * @param[out] out The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_sha3_512(const uint8_t *in, uint32_t in_len, uint8_t out[64])
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha3_512_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha3_update(&ctx, in, in_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_sha3_finish(&ctx, out);
}

/**
 * @brief Polynomial addition.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 */
static void mlkem_poly_add(mlkem_poly_t *r, const mlkem_poly_t *a, const mlkem_poly_t *b)
{
    uint32_t i;
    for(i = 0; i < MLKEM_N; i++) {
        r->c[i] = mlkem_mod_q((int32_t)a->c[i] + (int32_t)b->c[i]);
    }
}

/**
 * @brief Polynomial subtraction.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 */
static void mlkem_poly_sub(mlkem_poly_t *r, const mlkem_poly_t *a, const mlkem_poly_t *b)
{
    uint32_t i;
    for(i = 0; i < MLKEM_N; i++) {
        r->c[i] = mlkem_mod_q((int32_t)a->c[i] - (int32_t)b->c[i]);
    }
}

/**
 * @brief Polynomial vector addition.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_add(mlkem_polyvec_t *r, const mlkem_polyvec_t *a, const mlkem_polyvec_t *b, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_add(&r->v[i], &a->v[i], &b->v[i]);
    }
}

/**
 * @brief Polynomial multiplication.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 */
static void mlkem_poly_mul(mlkem_poly_t *r, const mlkem_poly_t *a, const mlkem_poly_t *b)
{
    int32_t tmp[MLKEM_N * 2];
    uint32_t i;
    uint32_t j;
    memset(tmp, 0, sizeof(tmp));
    for(i = 0; i < MLKEM_N; i++) {
        for(j = 0; j < MLKEM_N; j++) {
            tmp[i + j] += (int32_t)a->c[i] * (int32_t)b->c[j];
        }
    }
    for(i = 0; i < MLKEM_N; i++) {
        tmp[i] -= tmp[i + MLKEM_N];
    }
    for(i = 0; i < MLKEM_N; i++) {
        r->c[i] = mlkem_mod_q(tmp[i]);
    }
}

/**
 * @brief Polynomial vector dot product.
 *
 * @param[out] r The output value.
 * @param[in] a The first input value.
 * @param[in] b The second input value.
 * @param[in] k The number of polynomials.
 */
static void mlkem_polyvec_dot(mlkem_poly_t *r, const mlkem_polyvec_t *a, const mlkem_polyvec_t *b, uint8_t k)
{
    mlkem_poly_t t;
    uint8_t i;
    memset(r, 0, sizeof(*r));
    for(i = 0; i < k; i++) {
        mlkem_poly_mul(&t, &a->v[i], &b->v[i]);
        mlkem_poly_add(r, r, &t);
    }
}

/**
 * @brief PRF.
 *
 * @param[out] out The output value.
 * @param[in] out_len The length of the output value.
 * @param[in] seed The input seed.
 * @param[in] nonce The nonce.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_prf(uint8_t *out, uint32_t out_len, const uint8_t seed[32], uint8_t nonce)
{
    uint8_t in[33];
    memcpy(in, seed, 32U);
    in[32] = nonce;
    return mlkem_shake_expand(in, sizeof(in), out, out_len);
}

/**
 * @brief XOF expand 128.
 *
 * @param[in] seed The input seed.
 * @param[in] seed_len The length of the input seed.
 * @param[out] out The output value.
 * @param[in] out_len The length of the output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_xof_expand128(const uint8_t *seed, uint32_t seed_len, uint8_t *out, uint32_t out_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc;
    rc = noxtls_shake128_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake128_update(&ctx, seed, seed_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake128_final(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_shake128_squeeze(&ctx, out, out_len);
}

/**
 * @brief Sample uniform polynomial.
 *
 * @param[out] p The output value.
 * @param[in] rho The rho value.
 * @param[in] i The i value.
 * @param[in] j The j value.
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_NULL if the input or output is NULL
 *         NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_sample_uniform(mlkem_poly_t *p, const uint8_t rho[32], uint8_t i, uint8_t j)
{
    uint8_t seed[34];
    uint8_t buf[672];
    uint32_t pos = 0;
    uint32_t ctr = 0;
    noxtls_return_t rc;

    memcpy(seed, rho, 32U);
    seed[32] = j;
    seed[33] = i;
    rc = mlkem_xof_expand128(seed, sizeof(seed), buf, sizeof(buf));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    while(ctr < MLKEM_N && (pos + 2U) < sizeof(buf)) {
        uint16_t v0 = ((uint16_t)buf[pos]) | (((uint16_t)buf[pos + 1] & 0x0Fu) << 8);
        uint16_t v1 = (((uint16_t)buf[pos + 1]) >> 4) | (((uint16_t)buf[pos + 2]) << 4);
        pos += 3U;
        if(v0 < MLKEM_Q) {
            p->c[ctr++] = (int16_t)v0;
        }
        if(ctr < MLKEM_N && v1 < MLKEM_Q) {
            p->c[ctr++] = (int16_t)v1;
        }
    }
    if(ctr != MLKEM_N) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Popcount u32.
 *
 * @param[in] x The input value.
 * @return The popcount of the input value.
 */
static uint8_t mlkem_popcount_u32(uint32_t x)
{
    uint8_t c = 0;
    while(x != 0U) {
        c = (uint8_t)(c + (uint8_t)(x & 1U));
        x >>= 1U;
    }
    return c;
}

/**
 * @brief Sample CBD.
 *
 * @param[out] p The output value.
 * @param[in] buf The input buffer.
 * @param[in] eta The eta value.
 */
static void mlkem_sample_cbd(mlkem_poly_t *p, const uint8_t *buf, uint8_t eta)
{
    uint32_t i;
    if(eta == 2U) {
        for(i = 0U; i < (MLKEM_N / 8U); i++) {
            uint32_t t = ((uint32_t)buf[4U * i + 0U]) |
                         ((uint32_t)buf[4U * i + 1U] << 8) |
                         ((uint32_t)buf[4U * i + 2U] << 16) |
                         ((uint32_t)buf[4U * i + 3U] << 24);
            uint32_t d = t & 0x55555555u;
            d += (t >> 1) & 0x55555555u;
            {
                uint32_t j;
                for(j = 0U; j < 8U; j++) {
                    uint32_t a = (d >> (4U * j + 0U)) & 0x3u;
                    uint32_t b = (d >> (4U * j + 2U)) & 0x3u;
                    p->c[8U * i + j] = (int16_t)((int16_t)a - (int16_t)b);
                }
            }
        }
        return;
    }
    if(eta == 3U) {
        for(i = 0U; i < (MLKEM_N / 4U); i++) {
            uint32_t t = ((uint32_t)buf[3U * i + 0U]) |
                         ((uint32_t)buf[3U * i + 1U] << 8) |
                         ((uint32_t)buf[3U * i + 2U] << 16);
            uint32_t d = t & 0x00249249u;
            d += (t >> 1) & 0x00249249u;
            d += (t >> 2) & 0x00249249u;
            {
                uint32_t j;
                for(j = 0U; j < 4U; j++) {
                    uint32_t a = (d >> (6U * j + 0U)) & 0x7u;
                    uint32_t b = (d >> (6U * j + 3U)) & 0x7u;
                    p->c[4U * i + j] = (int16_t)((int16_t)a - (int16_t)b);
                }
            }
        }
        return;
    }
    for(i = 0U; i < MLKEM_N; i++) {
        p->c[i] = 0;
    }
}

/**
 * @brief Sample noise eta.
 *
 * @param[out] p The output value.
 * @param[in] sigma The sigma value.
 * @param[in] nonce The nonce value.
 * @param[in] eta The eta value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_sample_noise_eta(mlkem_poly_t *p, const uint8_t sigma[32], uint8_t nonce, uint8_t eta)
{
    uint32_t bytes = ((uint32_t)MLKEM_N * (uint32_t)eta * 2U) / 8U;
    uint8_t buf[192];
    noxtls_return_t rc;
    if(bytes > sizeof(buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = mlkem_prf(buf, bytes, sigma, nonce);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_sample_cbd(p, buf, eta);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Polynomial to bytes 12.
 *
 * @param[out] out The output value.
 * @param[in] p The input value.
 */
static void mlkem_poly_tobytes12(uint8_t out[MLKEM_POLY12_BYTES], const mlkem_poly_t *p)
{
    uint32_t i;
    for(i = 0; i < (MLKEM_N / 2U); i++) {
        uint16_t t0 = (uint16_t)mlkem_mod_q(p->c[2U * i]);
        uint16_t t1 = (uint16_t)mlkem_mod_q(p->c[2U * i + 1U]);
        out[3U * i + 0U] = (uint8_t)(t0 & 0xFFu);
        out[3U * i + 1U] = (uint8_t)((t0 >> 8) | ((t1 & 0x0Fu) << 4));
        out[3U * i + 2U] = (uint8_t)(t1 >> 4);
    }
}

/**
 * @brief Polynomial from bytes 12.
 *
 * @param[out] p The output value.
 * @param[in] in The input value.
 */
static void mlkem_poly_frombytes12(mlkem_poly_t *p, const uint8_t in[MLKEM_POLY12_BYTES])
{
    uint32_t i;
    for(i = 0; i < (MLKEM_N / 2U); i++) {
        uint16_t t0 = ((uint16_t)in[3U * i + 0U]) | (((uint16_t)in[3U * i + 1U] & 0x0Fu) << 8);
        uint16_t t1 = (((uint16_t)in[3U * i + 1U]) >> 4) | (((uint16_t)in[3U * i + 2U]) << 4);
        p->c[2U * i] = (int16_t)(t0 % MLKEM_Q);
        p->c[2U * i + 1U] = (int16_t)(t1 % MLKEM_Q);
    }
}

/**
 * @brief Polynomial compress bits.
 *
 * @param[out] out The output value.
 * @param[in] p The input value.
 * @param[in] bits The bits value.
 */
static void mlkem_poly_compress_bits(uint8_t *out, const mlkem_poly_t *p, uint8_t bits)
{
    uint32_t i;
    uint32_t bitpos = 0;
    memset(out, 0, ((uint32_t)MLKEM_N * bits) / 8U);
    for(i = 0; i < MLKEM_N; i++) {
        uint32_t v = (uint32_t)mlkem_mod_q(p->c[i]);
        uint32_t t = ((v << bits) + (MLKEM_Q / 2U)) / MLKEM_Q;
        uint32_t j;
        t &= ((1U << bits) - 1U);
        for(j = 0; j < bits; j++) {
            if((t >> j) & 1U) {
                out[(bitpos + j) >> 3] |= (uint8_t)(1U << ((bitpos + j) & 7U));
            }
        }
        bitpos += bits;
    }
}

/**
 * @brief Polynomial decompress bits.
 *
 * @param[out] p The output value.
 * @param[in] in The input value.
 * @param[in] bits The bits value.
 */
static void mlkem_poly_decompress_bits(mlkem_poly_t *p, const uint8_t *in, uint8_t bits)
{
    uint32_t i;
    uint32_t bitpos = 0;
    for(i = 0; i < MLKEM_N; i++) {
        uint32_t t = 0;
        uint32_t j;
        for(j = 0; j < bits; j++) {
            uint32_t bit = (uint32_t)((in[(bitpos + j) >> 3] >> ((bitpos + j) & 7U)) & 1U);
            t |= (bit << j);
        }
        p->c[i] = (int16_t)(((t * MLKEM_Q) + (1U << (bits - 1U))) >> bits);
        bitpos += bits;
    }
}

/**
 * @brief Message to polynomial.
 *
 * @param[out] p The output value.
 * @param[in] msg The input value.
 */
static void mlkem_msg_to_poly(mlkem_poly_t *p, const uint8_t msg[32])
{
    uint32_t i;
    for(i = 0; i < MLKEM_N; i++) {
        uint8_t bit = (uint8_t)((msg[i >> 3] >> (i & 7U)) & 1U);
        p->c[i] = bit ? (MLKEM_Q + 1) / 2 : 0;
    }
}

/**
 * @brief Polynomial to message.
 *
 * @param[out] msg The output value.
 * @param[in] p The input value.
 */
static void mlkem_poly_to_msg(uint8_t msg[32], const mlkem_poly_t *p)
{
    uint32_t i;
    memset(msg, 0, 32U);
    for(i = 0; i < MLKEM_N; i++) {
        uint16_t t = (uint16_t)mlkem_mod_q(p->c[i]);
        uint8_t bit = (uint8_t)((((uint32_t)t * 2U + (MLKEM_Q / 2U)) / MLKEM_Q) & 1U);
        msg[i >> 3] |= (uint8_t)(bit << (i & 7U));
    }
}

/**
 * @brief Generate matrix.
 *
 * @param[out] a The output value.
 * @param[in] p The input value.
 * @param[in] rho The rho value.
 * @param[in] transposed The transposed value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_gen_matrix(mlkem_poly_t a[MLKEM_MAX_K][MLKEM_MAX_K], const mlkem_params_t *p, const uint8_t rho[32], uint8_t transposed)
{
    uint8_t i;
    uint8_t j;
    for(i = 0; i < p->k; i++) {
        for(j = 0; j < p->k; j++) {
            noxtls_return_t rc = mlkem_sample_uniform(&a[i][j], rho, transposed ? j : i, transposed ? i : j);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Pack public key.
 *
 * @param[out] pk The output value.
 * @param[in] t The input value.
 * @param[in] rho The rho value.
 * @param[in] k The k value.
 */
static void mlkem_pack_pk(uint8_t *pk, const mlkem_polyvec_t *t, const uint8_t rho[32], uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_tobytes12(pk + ((uint32_t)i * MLKEM_POLY12_BYTES), &t->v[i]);
    }
    memcpy(pk + ((uint32_t)k * MLKEM_POLY12_BYTES), rho, 32U);
}

/**
 * @brief Unpack public key.
 *
 * @param[out] t The output value.
 * @param[in] rho The rho value.
 * @param[in] pk The input value.
 * @param[in] k The k value.
 */
static void mlkem_unpack_pk(mlkem_polyvec_t *t, uint8_t rho[32], const uint8_t *pk, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_frombytes12(&t->v[i], pk + ((uint32_t)i * MLKEM_POLY12_BYTES));
    }
    memcpy(rho, pk + ((uint32_t)k * MLKEM_POLY12_BYTES), 32U);
}

/**
 * @brief Pack secret key.
 *
 * @param[out] sk The output value.
 * @param[in] s The input value.
 * @param[in] pk The input value.
 * @param[in] pk_len The pk_len value.
 * @param[in] hpk The hpk value.
 * @param[in] z The z value.
 * @param[in] k The k value.
 */
static void mlkem_pack_sk(uint8_t *sk, const mlkem_polyvec_t *s, const uint8_t *pk, uint32_t pk_len, const uint8_t hpk[32], const uint8_t z[32], uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_tobytes12(sk + ((uint32_t)i * MLKEM_POLY12_BYTES), &s->v[i]);
    }
    memcpy(sk + ((uint32_t)k * MLKEM_POLY12_BYTES), pk, pk_len);
    memcpy(sk + ((uint32_t)k * MLKEM_POLY12_BYTES) + pk_len, hpk, 32U);
    memcpy(sk + ((uint32_t)k * MLKEM_POLY12_BYTES) + pk_len + 32U, z, 32U);
}

/**
 * @brief Unpack secret key.
 *
 * @param[out] s The output value.
 * @param[in] pk The input value.
 * @param[in] pk_len The pk_len value.
 * @param[in] hpk The hpk value.
 * @param[in] z The z value.
 * @param[in] sk The input value.
 * @param[in] k The k value.
 */
static void mlkem_unpack_sk(mlkem_polyvec_t *s, uint8_t *pk, uint32_t pk_len, uint8_t hpk[32], uint8_t z[32], const uint8_t *sk, uint8_t k)
{
    uint8_t i;
    for(i = 0; i < k; i++) {
        mlkem_poly_frombytes12(&s->v[i], sk + ((uint32_t)i * MLKEM_POLY12_BYTES));
    }
    memcpy(pk, sk + ((uint32_t)k * MLKEM_POLY12_BYTES), pk_len);
    memcpy(hpk, sk + ((uint32_t)k * MLKEM_POLY12_BYTES) + pk_len, 32U);
    memcpy(z, sk + ((uint32_t)k * MLKEM_POLY12_BYTES) + pk_len + 32U, 32U);
}

/**
 * @brief Pack ciphertext.
 *
 * @param[out] ct The output value.
 * @param[in] u The input value.
 * @param[in] v The input value.
 * @param[in] p The input value.
 */
static void mlkem_pack_ct(uint8_t *ct, const mlkem_polyvec_t *u, const mlkem_poly_t *v, const mlkem_params_t *p)
{
    uint8_t i;
    uint32_t off = 0;
    uint32_t u_bytes = ((uint32_t)MLKEM_N * p->du) / 8U;
    uint32_t v_bytes = ((uint32_t)MLKEM_N * p->dv) / 8U;
    for(i = 0; i < p->k; i++) {
        mlkem_poly_compress_bits(ct + off, &u->v[i], p->du);
        off += u_bytes;
    }
    mlkem_poly_compress_bits(ct + off, v, p->dv);
    off += v_bytes;
    if(off < p->ciphertext_len) {
        memset(ct + off, 0, p->ciphertext_len - off);
    }
}

/**
 * @brief Unpack ciphertext.
 *
 * @param[out] u The output value.
 * @param[out] v The output value.
 * @param[in] ct The input value.
 * @param[in] p The input value.
 */
static void mlkem_unpack_ct(mlkem_polyvec_t *u, mlkem_poly_t *v, const uint8_t *ct, const mlkem_params_t *p)
{
    uint8_t i;
    uint32_t off = 0;
    uint32_t u_bytes = ((uint32_t)MLKEM_N * p->du) / 8U;
    for(i = 0; i < p->k; i++) {
        mlkem_poly_decompress_bits(&u->v[i], ct + off, p->du);
        off += u_bytes;
    }
    mlkem_poly_decompress_bits(v, ct + off, p->dv);
}

/**
 * @brief IND-CPA keypair.
 *
 * @param[in] p The input value.
 * @param[in] d The input value.
 * @param[out] s The output value.
 * @param[out] t The output value.
 * @param[out] rho The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_indcpa_keypair(const mlkem_params_t *p, const uint8_t d[32], mlkem_polyvec_t *s, mlkem_polyvec_t *t, uint8_t rho[32])
{
    mlkem_poly_t a[MLKEM_MAX_K][MLKEM_MAX_K];
    mlkem_polyvec_t e;
    uint8_t g_in[33];
    uint8_t g_out[64];
    uint8_t sigma[32];
    uint8_t i;
    uint8_t nonce = 0;
    noxtls_return_t rc;

    memcpy(g_in, d, 32U);
    g_in[32] = p->k;
    rc = mlkem_sha3_512(g_in, sizeof(g_in), g_out);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(rho, g_out, 32U);
    memcpy(sigma, g_out + 32U, 32U);
    rc = mlkem_gen_matrix(a, p, rho, 0U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0; i < p->k; i++) {
        rc = mlkem_sample_noise_eta(&s->v[i], sigma, nonce++, p->eta1);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0; i < p->k; i++) {
        rc = mlkem_sample_noise_eta(&e.v[i], sigma, nonce++, p->eta1);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    mlkem_polyvec_ntt(s, p->k);
    mlkem_polyvec_ntt(&e, p->k);
    for(i = 0; i < p->k; i++) {
        mlkem_polyvec_basemul_acc_montgomery(&t->v[i], (const mlkem_polyvec_t *)&a[i], s, p->k);
        mlkem_poly_tomont(&t->v[i]);
        mlkem_poly_add(&t->v[i], &t->v[i], &e.v[i]);
    }
    mlkem_polyvec_reduce(t, p->k);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief IND-CPA encrypt.
 *
 * @param[in] p The input value.
 * @param[in] t The input value.
 * @param[in] rho The input value.
 * @param[in] m The input value.
 * @param[in] coins The input value.
 * @param[out] u The output value.
 * @param[out] v The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_indcpa_enc(const mlkem_params_t *p,
                                        const mlkem_polyvec_t *t,
                                        const uint8_t rho[32],
                                        const uint8_t m[32],
                                        const uint8_t coins[32],
                                        mlkem_polyvec_t *u,
                                        mlkem_poly_t *v)
{
    mlkem_poly_t a[MLKEM_MAX_K][MLKEM_MAX_K];
    mlkem_polyvec_t r;
    mlkem_polyvec_t e1;
    mlkem_poly_t e2;
    mlkem_poly_t mp;
    uint8_t i;
    uint8_t nonce = 0;
    noxtls_return_t rc;

    rc = mlkem_gen_matrix(a, p, rho, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0; i < p->k; i++) {
        rc = mlkem_sample_noise_eta(&r.v[i], coins, nonce++, p->eta1);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0; i < p->k; i++) {
        rc = mlkem_sample_noise_eta(&e1.v[i], coins, nonce++, p->eta2);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    rc = mlkem_sample_noise_eta(&e2, coins, nonce++, p->eta2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    mlkem_polyvec_ntt(&r, p->k);
    for(i = 0; i < p->k; i++) {
        mlkem_polyvec_basemul_acc_montgomery(&u->v[i], (const mlkem_polyvec_t *)&a[i], &r, p->k);
    }
    mlkem_polyvec_invntt_tomont(u, p->k);
    mlkem_polyvec_add(u, u, &e1, p->k);
    mlkem_polyvec_reduce(u, p->k);

    mlkem_polyvec_basemul_acc_montgomery(v, t, &r, p->k);
    mlkem_poly_invntt_tomont(v);
    mlkem_poly_add(v, v, &e2);
    mlkem_msg_to_poly(&mp, m);
    mlkem_poly_add(v, v, &mp);
    mlkem_poly_reduce(v);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief IND-CPA decrypt.
 *
 * @param[in] p The input value.
 * @param[in] s The input value.
 * @param[in] u The input value.
 * @param[in] v The input value.
 * @param[out] m The output value.
 */
static void mlkem_indcpa_dec(const mlkem_params_t *p,
                             const mlkem_polyvec_t *s,
                             const mlkem_polyvec_t *u,
                             const mlkem_poly_t *v,
                             uint8_t m[32])
{
    mlkem_polyvec_t up;
    mlkem_poly_t mp;
    mlkem_poly_t r;
    up = *u;
    mlkem_polyvec_ntt(&up, p->k);
    mlkem_polyvec_basemul_acc_montgomery(&mp, s, &up, p->k);
    mlkem_poly_invntt_tomont(&mp);
    mlkem_poly_sub(&r, v, &mp);
    mlkem_poly_reduce(&r);
    mlkem_poly_to_msg(m, &r);
}

/**
 * @brief Generate random 32 bytes.
 *
 * @param[out] out The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t mlkem_gen_random32(uint8_t out[32])
{
    if(g_mlkem_test_random_seq != NULL &&
       (g_mlkem_test_random_seq_off + 32U) <= g_mlkem_test_random_seq_len) {
        memcpy(out, g_mlkem_test_random_seq + g_mlkem_test_random_seq_off, 32U);
        g_mlkem_test_random_seq_off += 32U;
        return NOXTLS_RETURN_SUCCESS;
    }
    drbg_state_t drbg;
    noxtls_return_t rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return drbg_generate(&drbg, out, 32U * 8U, NULL, 0);
}

/**
 * @brief Set test random sequence.
 *
 * @param[in] bytes The input value.
 * @param[in] byte_len The byte_len value.
 */
void noxtls_mlkem_set_test_random_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    g_mlkem_test_random_seq = bytes;
    g_mlkem_test_random_seq_len = byte_len;
    g_mlkem_test_random_seq_off = 0U;
}

/**
 * @brief Get public key length.
 *
 * @param[in] param The input value.
 * @return The public key length.
 */
uint32_t noxtls_mlkem_public_key_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.public_key_len : 0U;
}

/**
 * @brief Get secret key length.
 *
 * @param[in] param The input value.
 * @return The secret key length.
 */
uint32_t noxtls_mlkem_secret_key_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.secret_key_len : 0U;
}

/**
 * @brief Get ciphertext length.
 *
 * @param[in] param The input value.
 * @return The ciphertext length.
 */
uint32_t noxtls_mlkem_ciphertext_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.ciphertext_len : 0U;
}

/**
 * @brief Generate key pair.
 *
 * @param[in] param The input value.
 * @param[out] public_key The output value.
 * @param[out] secret_key The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
noxtls_return_t noxtls_mlkem_keygen(noxtls_mlkem_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    mlkem_params_t p;
    mlkem_polyvec_t s;
    mlkem_polyvec_t t;
    uint8_t rho[32];
    uint8_t seed[32];
    uint8_t hpk[32];
    uint8_t z[32];
    noxtls_return_t rc;

    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = mlkem_gen_random32(seed);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_indcpa_keypair(&p, seed, &s, &t, rho);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_pack_pk(public_key, &t, rho, p.k);
    rc = mlkem_sha3_256(public_key, p.public_key_len, hpk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_gen_random32(z);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_pack_sk(secret_key, &s, public_key, p.public_key_len, hpk, z, p.k);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encapsulate to peer public key.
 *
 * @param[in] param The input value.
 * @param[in] public_key The input value.
 * @param[out] ciphertext The output value.
 * @param[out] shared_secret_32 The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
noxtls_return_t noxtls_mlkem_encaps(noxtls_mlkem_param_t param, const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret_32)
{
    mlkem_params_t p;
    mlkem_polyvec_t t;
    mlkem_polyvec_t u;
    mlkem_poly_t v;
    uint8_t rho[32];
    uint8_t m[32];
    uint8_t m_rand[32];
    uint8_t hpk[32];
    uint8_t mh[64];
    uint8_t keymat[64];
    uint8_t hc[32];
    uint8_t ss_in[64];
    noxtls_return_t rc;

    if(public_key == NULL || ciphertext == NULL || shared_secret_32 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_unpack_pk(&t, rho, public_key, p.k);
    rc = mlkem_gen_random32(m_rand);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_sha3_256(m_rand, sizeof(m_rand), m);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_sha3_256(public_key, p.public_key_len, hpk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(mh, m, 32U);
    memcpy(mh + 32U, hpk, 32U);
    rc = mlkem_sha3_512(mh, sizeof(mh), keymat);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_indcpa_enc(&p, &t, rho, m, keymat + 32U, &u, &v);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_pack_ct(ciphertext, &u, &v, &p);
    rc = mlkem_sha3_256(ciphertext, p.ciphertext_len, hc);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(ss_in, keymat, 32U);
    memcpy(ss_in + 32U, hc, 32U);
    return mlkem_shake_expand(ss_in, sizeof(ss_in), shared_secret_32, NOXTLS_MLKEM_SHARED_SECRET_LEN);
}

/**
 * @brief Decapsulate ciphertext with local secret key and recover the 32-byte shared secret.
 *
 * @param[in] param The input value.
 * @param[in] public_key The input value.
 * @param[in] secret_key The input value.
 * @param[in] ciphertext The input value.
 * @param[out] shared_secret_32 The output value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
noxtls_return_t noxtls_mlkem_decaps(noxtls_mlkem_param_t param, const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ciphertext, uint8_t *shared_secret_32)
{
    mlkem_params_t p;
    mlkem_polyvec_t s;
    mlkem_polyvec_t t;
    mlkem_polyvec_t u;
    mlkem_poly_t v;
    uint8_t rho[32];
    uint8_t pk2[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
    uint8_t hpk[32];
    uint8_t z[32];
    uint8_t m[32];
    uint8_t keymat[64];
    uint8_t ct_cmp[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];
    uint8_t hc[32];
    uint8_t ss_in[64];
    noxtls_return_t rc;

    if(public_key == NULL || secret_key == NULL || ciphertext == NULL || shared_secret_32 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(noxtls_secret_memcmp(public_key, secret_key + ((uint32_t)p.k * MLKEM_POLY12_BYTES), p.public_key_len) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    mlkem_unpack_sk(&s, pk2, p.public_key_len, hpk, z, secret_key, p.k);
    mlkem_unpack_pk(&t, rho, pk2, p.k);
    mlkem_unpack_ct(&u, &v, ciphertext, &p);
    mlkem_indcpa_dec(&p, &s, &u, &v, m);

    memcpy(ss_in, m, 32U);
    memcpy(ss_in + 32U, hpk, 32U);
    rc = mlkem_sha3_512(ss_in, sizeof(ss_in), keymat);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_indcpa_enc(&p, &t, rho, m, keymat + 32U, &u, &v);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    mlkem_pack_ct(ct_cmp, &u, &v, &p);

    if(noxtls_secret_memcmp(ciphertext, ct_cmp, p.ciphertext_len) != 0) {
        memcpy(keymat, z, 32U);
    }
    rc = mlkem_sha3_256(ciphertext, p.ciphertext_len, hc);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(ss_in, keymat, 32U);
    memcpy(ss_in + 32U, hc, 32U);
    return mlkem_shake_expand(ss_in, sizeof(ss_in), shared_secret_32, NOXTLS_MLKEM_SHARED_SECRET_LEN);
}
