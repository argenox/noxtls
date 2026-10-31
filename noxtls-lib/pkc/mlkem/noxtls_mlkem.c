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
* Summary: ML-KEM (NIST FIPS 203) key encapsulation, low-RAM streaming core.
*
* Design notes:
*  - Matrix entries A[i][j] are generated on demand (never stored).
*  - NTT-domain vectors (s^, t^, r^) are kept 12-bit packed and decoded two
*    coefficients at a time inside the base multiplication, so at most two
*    full polynomials are live at once; every entry point runs in a few KB of
*    stack and uses no heap.
*  - Decapsulation re-encrypts and compares the ciphertext on the fly and
*    selects between K' and the implicit-rejection key J(z||c) in constant
*    time.  Compression uses multiply/shift instead of division (no
*    secret-dependent UDIV timing, cf. KyberSlash).
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "noxtls_mlkem.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_ML_KEM

#define MLKEM_SYM_BYTES 32U
#define MLKEM_POLY_BYTES MLKEM_POLY12_BYTES
/* SampleNTT squeezes in chunks of 24 bytes (8 candidate pairs; divides the rate). */
#define MLKEM_SAMPLE_CHUNK 24U
/* ceil(2^35 / q): floor(x / q) == (x * MLKEM_DIV_Q_MUL) >> 35 for 0 <= x < 2^23. */
#define MLKEM_DIV_Q_MUL 10321340ULL
#define MLKEM_HALF_Q_FLOOR 1664U
#define MLKEM_MONT_R2 1353
#define MLKEM_INV_N_MONT 1441

static const uint8_t *g_mlkem_test_random_seq = NULL;
static uint32_t g_mlkem_test_random_seq_len = 0U;
static uint32_t g_mlkem_test_random_seq_off = 0U;

/** Zetas in Montgomery form, bit-reversed order (FIPS 203 Appendix A). */
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
 * @brief Resolve the FIPS 203 parameter set.
 *
 * @param[in] param ML-KEM parameter selector.
 * @param[out] p Parameter structure.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
static noxtls_return_t mlkem_get_params(noxtls_mlkem_param_t param, mlkem_params_t *p)
{
    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((p), sizeof(*(p)));
    switch(param) {
        case NOXTLS_MLKEM_512:
            p->k = 2U; p->eta1 = 3U; p->eta2 = 2U; p->du = 10U; p->dv = 4U;
            p->public_key_len = 800U; p->secret_key_len = 1632U; p->ciphertext_len = 768U;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLKEM_768:
            p->k = 3U; p->eta1 = 2U; p->eta2 = 2U; p->du = 10U; p->dv = 4U;
            p->public_key_len = 1184U; p->secret_key_len = 2400U; p->ciphertext_len = 1088U;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLKEM_1024:
            p->k = 4U; p->eta1 = 2U; p->eta2 = 2U; p->du = 11U; p->dv = 5U;
            p->public_key_len = 1568U; p->secret_key_len = 3168U; p->ciphertext_len = 1568U;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/* ------------------------------------------------------------------------ */
/* Modular arithmetic (constant time)                                        */
/* ------------------------------------------------------------------------ */

/**
 * @brief Montgomery reduction: returns a * 2^-16 mod q in (-q, q).
 * @param[in] a Input with |a| < q * 2^15.
 * @return Reduced value.
 */
static int16_t mlkem_montgomery_reduce(int32_t a)
{
    int16_t t = (int16_t)(a * (int32_t)MLKEM_QINV);
    return (int16_t)((a - ((int32_t)t * MLKEM_Q)) >> 16);
}

/**
 * @brief Barrett reduction to the centred range [-(q-1)/2, (q-1)/2].
 * @param[in] a Input value.
 * @return Reduced value congruent to a mod q.
 */
static int16_t mlkem_barrett_reduce(int16_t a)
{
    const int32_t v = ((1 << 26) + (MLKEM_Q / 2)) / MLKEM_Q;
    int32_t t = ((v * (int32_t)a) + (1 << 25)) >> 26;
    t *= MLKEM_Q;
    return (int16_t)((int32_t)a - t);
}

/**
 * @brief Map a value in (-q, q) to the canonical range [0, q) without branching.
 * @param[in] a Input value.
 * @return Canonical representative.
 */
static uint16_t mlkem_canonical(int16_t a)
{
    int32_t x = (int32_t)a;
    x += (int32_t)((uint32_t)(x >> 31) & (uint32_t)MLKEM_Q);
    return (uint16_t)x;
}

/**
 * @brief Fully reduce any int16 value to [0, q).
 * @param[in] a Input value.
 * @return Canonical representative.
 */
static uint16_t mlkem_freeze(int16_t a)
{
    return mlkem_canonical(mlkem_barrett_reduce(a));
}

/**
 * @brief Montgomery multiplication a * b * 2^-16 mod q.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @return Product in (-q, q).
 */
static int16_t mlkem_fqmul(int16_t a, int16_t b)
{
    return mlkem_montgomery_reduce((int32_t)a * (int32_t)b);
}

/* ------------------------------------------------------------------------ */
/* Polynomial operations                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @brief Barrett-reduce every coefficient.
 * @param[in,out] r Polynomial.
 */
static void mlkem_poly_reduce(mlkem_poly_t *r)
{
    uint32_t i = 0U;
    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        r->c[i] = mlkem_barrett_reduce(r->c[i]);
    }
}

/**
 * @brief Forward NTT (FIPS 203 Alg. 9), output Barrett-reduced, normal order.
 * @param[in,out] r Polynomial.
 */
static void mlkem_poly_ntt(mlkem_poly_t *r)
{
    uint32_t k = 1U;
    uint32_t len = 0U;
    uint32_t start = 0U;
    uint32_t j = 0U;

    for(len = 128U; len >= 2U; len >>= 1U) {
        for(start = 0U; start < (uint32_t)MLKEM_N; start = j + len) {
            int16_t zeta = mlkem_zetas[k];
            k += 1U;
            for(j = start; j < (start + len); j += 1U) {
                int16_t t = mlkem_fqmul(zeta, r->c[j + len]);
                r->c[j + len] = (int16_t)((int32_t)r->c[j] - (int32_t)t);
                r->c[j] = (int16_t)((int32_t)r->c[j] + (int32_t)t);
            }
        }
    }
    mlkem_poly_reduce(r);
}

/**
 * @brief Inverse NTT (FIPS 203 Alg. 10) with multiplication by the Montgomery factor.
 * @param[in,out] r Polynomial.
 */
static void mlkem_poly_invntt_tomont(mlkem_poly_t *r)
{
    uint32_t k = 127U;
    uint32_t len = 0U;
    uint32_t start = 0U;
    uint32_t j = 0U;

    for(len = 2U; len <= 128U; len <<= 1U) {
        for(start = 0U; start < (uint32_t)MLKEM_N; start = j + len) {
            int16_t zeta = mlkem_zetas[k];
            k -= 1U;
            for(j = start; j < (start + len); j += 1U) {
                int16_t t = r->c[j];
                r->c[j] = mlkem_barrett_reduce((int16_t)((int32_t)t + (int32_t)r->c[j + len]));
                r->c[j + len] = (int16_t)((int32_t)r->c[j + len] - (int32_t)t);
                r->c[j + len] = mlkem_fqmul(zeta, r->c[j + len]);
            }
        }
    }
    for(j = 0U; j < (uint32_t)MLKEM_N; j += 1U) {
        r->c[j] = mlkem_fqmul(r->c[j], (int16_t)MLKEM_INV_N_MONT);
    }
}

/**
 * @brief Multiply by the Montgomery factor 2^16 mod q.
 * @param[in,out] r Polynomial.
 */
static void mlkem_poly_tomont(mlkem_poly_t *r)
{
    uint32_t i = 0U;
    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        r->c[i] = mlkem_fqmul(r->c[i], (int16_t)MLKEM_MONT_R2);
    }
}

/**
 * @brief r += a (no reduction; callers keep |coefficients| bounded).
 * @param[in,out] r Accumulator.
 * @param[in] a Addend.
 */
static void mlkem_poly_add(mlkem_poly_t *r, const mlkem_poly_t *a)
{
    uint32_t i = 0U;
    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        r->c[i] = (int16_t)((int32_t)r->c[i] + (int32_t)a->c[i]);
    }
}

/**
 * @brief r = a - r (no reduction).
 * @param[in,out] r Subtrahend on input, difference on output.
 * @param[in] a Minuend.
 */
static void mlkem_poly_rsub(mlkem_poly_t *r, const mlkem_poly_t *a)
{
    uint32_t i = 0U;
    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        r->c[i] = (int16_t)((int32_t)a->c[i] - (int32_t)r->c[i]);
    }
}

/**
 * @brief Decode coefficients 2i and 2i+1 from a 12-bit packed polynomial.
 * @param[in] in Packed polynomial (384 bytes).
 * @param[in] i Pair index (0..127).
 * @param[out] c Two decoded coefficients (12-bit values, not reduced).
 */
static void mlkem_unpack12_pair(const uint8_t *in, uint32_t i, int16_t c[2])
{
    uint32_t b0 = (uint32_t)in[3U * i];
    uint32_t b1 = (uint32_t)in[(3U * i) + 1U];
    uint32_t b2 = (uint32_t)in[(3U * i) + 2U];
    c[0] = (int16_t)(b0 | ((b1 & 0x0FU) << 8U));
    c[1] = (int16_t)((b1 >> 4U) | (b2 << 4U));
}

/**
 * @brief Accumulate the NTT-domain product r += a o b, with b given 12-bit packed.
 *
 * Products carry the Montgomery factor 2^-16 like the reference
 * basemul_montgomery; the accumulated value stays below k*q in magnitude.
 *
 * @param[in,out] r Accumulator.
 * @param[in] a NTT-domain polynomial (|coefficients| < q).
 * @param[in] b_packed NTT-domain polynomial, ByteEncode12 form.
 */
static void mlkem_poly_basemul_acc_packed(mlkem_poly_t *r, const mlkem_poly_t *a, const uint8_t *b_packed)
{
    uint32_t i = 0U;

    for(i = 0U; i < ((uint32_t)MLKEM_N / 2U); i += 1U) {
        int16_t b[2];
        int16_t zeta = mlkem_zetas[64U + (i >> 1U)];
        int16_t r0 = 0;
        int16_t r1 = 0;
        const int16_t *ap = &a->c[2U * i];

        if((i & 1U) != 0U) {
            zeta = (int16_t)(-zeta);
        }
        mlkem_unpack12_pair(b_packed, i, b);
        r0 = mlkem_fqmul(mlkem_fqmul(ap[1], b[1]), zeta);
        r0 = (int16_t)((int32_t)r0 + (int32_t)mlkem_fqmul(ap[0], b[0]));
        r1 = (int16_t)((int32_t)mlkem_fqmul(ap[0], b[1]) + (int32_t)mlkem_fqmul(ap[1], b[0]));
        r->c[2U * i] = (int16_t)((int32_t)r->c[2U * i] + (int32_t)r0);
        r->c[(2U * i) + 1U] = (int16_t)((int32_t)r->c[(2U * i) + 1U] + (int32_t)r1);
        noxtls_secure_zero(b, sizeof(b));
    }
}

/**
 * @brief ByteEncode12 of the canonical representatives.
 * @param[out] out 384-byte output.
 * @param[in] p Polynomial.
 */
static void mlkem_poly_tobytes(uint8_t *out, const mlkem_poly_t *p)
{
    uint32_t i = 0U;
    for(i = 0U; i < ((uint32_t)MLKEM_N / 2U); i += 1U) {
        uint32_t t0 = (uint32_t)mlkem_freeze(p->c[2U * i]);
        uint32_t t1 = (uint32_t)mlkem_freeze(p->c[(2U * i) + 1U]);
        out[3U * i] = (uint8_t)(t0 & 0xFFU);
        out[(3U * i) + 1U] = (uint8_t)((t0 >> 8U) | ((t1 & 0x0FU) << 4U));
        out[(3U * i) + 2U] = (uint8_t)(t1 >> 4U);
    }
}

/**
 * @brief ByteDecode12 (12-bit values, not reduced).
 * @param[out] p Output polynomial.
 * @param[in] in 384-byte packed input.
 */
static void mlkem_poly_frombytes(mlkem_poly_t *p, const uint8_t *in)
{
    uint32_t i = 0U;
    for(i = 0U; i < ((uint32_t)MLKEM_N / 2U); i += 1U) {
        mlkem_unpack12_pair(in, i, &p->c[2U * i]);
    }
}

/**
 * @brief Streaming byte packer used for compressed output and on-the-fly comparison.
 */
typedef struct
{
    uint8_t *out;        /**< Output bytes, or NULL. */
    const uint8_t *cmp;  /**< Expected bytes to compare against, or NULL. */
    uint32_t pos;        /**< Bytes emitted so far. */
    uint32_t acc;        /**< Pending bits (LSB first). */
    uint32_t nbits;      /**< Number of pending bits. */
    uint8_t diff;        /**< OR of all byte differences against cmp. */
} mlkem_packer_t;

/**
 * @brief Append bits to the packer and flush complete bytes.
 * @param[in,out] pk Packer state.
 * @param[in] value Bits to append (LSB first).
 * @param[in] bits Number of bits (<= 12).
 */
static void mlkem_packer_put(mlkem_packer_t *pk, uint32_t value, uint32_t bits)
{
    pk->acc |= value << pk->nbits;
    pk->nbits += bits;
    while(pk->nbits >= 8U) {
        uint8_t byte = (uint8_t)(pk->acc & 0xFFU);
        if(pk->out != NULL) {
            pk->out[pk->pos] = byte;
        }
        if(pk->cmp != NULL) {
            pk->diff |= (uint8_t)(byte ^ pk->cmp[pk->pos]);
        }
        pk->pos += 1U;
        pk->acc >>= 8U;
        pk->nbits -= 8U;
    }
}

/**
 * @brief Compress_d each coefficient and stream it into the packer (constant time).
 * @param[in,out] pk Packer state.
 * @param[in] p Polynomial (any int16 values; reduced internally).
 * @param[in] d Bit width (1, 4, 5, 10 or 11).
 */
static void mlkem_poly_compress(mlkem_packer_t *pk, const mlkem_poly_t *p, uint32_t d)
{
    uint32_t i = 0U;
    uint32_t mask = (1UL << d) - 1U;

    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        uint64_t n = (uint64_t)((((uint32_t)mlkem_freeze(p->c[i])) << d) + MLKEM_HALF_Q_FLOOR);
        uint32_t t = (uint32_t)((n * MLKEM_DIV_Q_MUL) >> 35U) & mask;
        mlkem_packer_put(pk, t, d);
    }
}

/**
 * @brief ByteDecode_d followed by Decompress_d.
 * @param[out] p Output polynomial (coefficients in [0, q]).
 * @param[in] in Packed input (32*d bytes).
 * @param[in] d Bit width.
 */
static void mlkem_poly_decompress(mlkem_poly_t *p, const uint8_t *in, uint32_t d)
{
    uint32_t i = 0U;
    uint32_t acc = 0U;
    uint32_t nbits = 0U;
    uint32_t pos = 0U;
    uint32_t mask = (1UL << d) - 1U;

    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        uint32_t t = 0U;
        while(nbits < d) {
            acc |= ((uint32_t)in[pos]) << nbits;
            pos += 1U;
            nbits += 8U;
        }
        t = acc & mask;
        acc >>= d;
        nbits -= d;
        p->c[i] = (int16_t)(((t * (uint32_t)MLKEM_Q) + (1UL << (d - 1U))) >> d);
    }
}

/**
 * @brief Decompress_1(ByteDecode_1(msg)) in constant time.
 * @param[out] p Output polynomial.
 * @param[in] msg 32-byte message.
 */
static void mlkem_poly_frommsg(mlkem_poly_t *p, const uint8_t *msg)
{
    uint32_t i = 0U;
    for(i = 0U; i < (uint32_t)MLKEM_N; i += 1U) {
        uint32_t bit = ((uint32_t)msg[i >> 3U] >> (i & 7U)) & 1U;
        p->c[i] = (int16_t)((0U - bit) & (((uint32_t)MLKEM_Q + 1U) / 2U));
    }
}

/**
 * @brief ByteEncode_1(Compress_1(p)) in constant time.
 * @param[out] msg 32-byte output.
 * @param[in] p Polynomial.
 */
static void mlkem_poly_tomsg(uint8_t *msg, const mlkem_poly_t *p)
{
    mlkem_packer_t pk;

    noxtls_secure_zero(&pk, sizeof(pk));
    pk.out = msg;
    mlkem_poly_compress(&pk, p, 1U);
    noxtls_secure_zero(&pk, sizeof(pk));
}

/**
 * @brief SamplePolyCBD_eta for eta in {2, 3} (FIPS 203 Alg. 8).
 * @param[out] p Output polynomial.
 * @param[in] buf 64*eta bytes of PRF output.
 * @param[in] eta Noise parameter.
 */
static void mlkem_sample_cbd(mlkem_poly_t *p, const uint8_t *buf, uint32_t eta)
{
    uint32_t i = 0U;
    uint32_t j = 0U;

    if(eta == 2U) {
        for(i = 0U; i < ((uint32_t)MLKEM_N / 8U); i += 1U) {
            uint32_t t = ((uint32_t)buf[4U * i]) |
                         ((uint32_t)buf[(4U * i) + 1U] << 8U) |
                         ((uint32_t)buf[(4U * i) + 2U] << 16U) |
                         ((uint32_t)buf[(4U * i) + 3U] << 24U);
            uint32_t d = t & 0x55555555U;
            d += (t >> 1U) & 0x55555555U;
            for(j = 0U; j < 8U; j += 1U) {
                uint32_t a = (d >> (4U * j)) & 0x3U;
                uint32_t b = (d >> ((4U * j) + 2U)) & 0x3U;
                p->c[(8U * i) + j] = (int16_t)((int32_t)a - (int32_t)b);
            }
        }
    } else {
        for(i = 0U; i < ((uint32_t)MLKEM_N / 4U); i += 1U) {
            uint32_t t = ((uint32_t)buf[3U * i]) |
                         ((uint32_t)buf[(3U * i) + 1U] << 8U) |
                         ((uint32_t)buf[(3U * i) + 2U] << 16U);
            uint32_t d = t & 0x00249249U;
            d += (t >> 1U) & 0x00249249U;
            d += (t >> 2U) & 0x00249249U;
            for(j = 0U; j < 4U; j += 1U) {
                uint32_t a = (d >> (6U * j)) & 0x7U;
                uint32_t b = (d >> ((6U * j) + 3U)) & 0x7U;
                p->c[(4U * i) + j] = (int16_t)((int32_t)a - (int32_t)b);
            }
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Symmetric primitives (FIPS 203 §4.1)                                     */
/* ------------------------------------------------------------------------ */

/**
 * @brief SHA3-256 (function H).
 * @param[in] in Input.
 * @param[in] in_len Input length.
 * @param[out] out 32-byte digest.
 * @return Hash status.
 */
static noxtls_return_t mlkem_hash_h(const uint8_t *in, uint32_t in_len, uint8_t *out)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha3_256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha3_update(&ctx, in, in_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha3_finish(&ctx, out);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief SHA3-512 of a || b (function G).
 * @param[in] a First input.
 * @param[in] a_len First input length.
 * @param[in] b Second input (may be NULL when b_len is 0).
 * @param[in] b_len Second input length.
 * @param[out] out 64-byte digest.
 * @return Hash status.
 */
static noxtls_return_t mlkem_hash_g(const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len, uint8_t *out)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha3_512_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha3_update(&ctx, a, a_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (b_len != 0U)) {
        rc = noxtls_sha3_update(&ctx, b, b_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha3_finish(&ctx, out);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief SHAKE256(a || b, out_len) (functions J and PRF).
 * @param[in] a First input.
 * @param[in] a_len First input length.
 * @param[in] b Second input.
 * @param[in] b_len Second input length.
 * @param[out] out Output.
 * @param[in] out_len Output length.
 * @return Hash status.
 */
static noxtls_return_t mlkem_shake256(const uint8_t *a, uint32_t a_len,
                                      const uint8_t *b, uint32_t b_len,
                                      uint8_t *out, uint32_t out_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_shake256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, a, a_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (b_len != 0U)) {
        rc = noxtls_shake256_update(&ctx, b, b_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, out, out_len);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief Sample a CBD noise polynomial: SamplePolyCBD_eta(PRF_eta(seed, nonce)).
 * @param[out] p Output polynomial.
 * @param[in] seed 32-byte seed (sigma or r).
 * @param[in] nonce PRF counter byte.
 * @param[in] eta Noise parameter (2 or 3).
 * @return Hash status.
 */
static noxtls_return_t mlkem_sample_noise(mlkem_poly_t *p, const uint8_t *seed, uint8_t nonce, uint32_t eta)
{
    uint8_t buf[3U * 64U];
    noxtls_return_t rc = mlkem_shake256(seed, MLKEM_SYM_BYTES, &nonce, 1U, buf, 64U * eta);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        mlkem_sample_cbd(p, buf, eta);
    }
    noxtls_secure_zero(buf, sizeof(buf));
    return rc;
}

/**
 * @brief SampleNTT(rho || b0 || b1) (FIPS 203 Alg. 7), streaming SHAKE128.
 * @param[out] p Output NTT-domain polynomial.
 * @param[in] rho 32-byte public seed.
 * @param[in] b0 First index byte.
 * @param[in] b1 Second index byte.
 * @return Hash status.
 */
static noxtls_return_t mlkem_sample_ntt(mlkem_poly_t *p, const uint8_t *rho, uint8_t b0, uint8_t b1)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t idx[2];
    uint8_t buf[MLKEM_SAMPLE_CHUNK];
    uint32_t ctr = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    idx[0] = b0;
    idx[1] = b1;
    rc = noxtls_shake128_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_update(&ctx, rho, MLKEM_SYM_BYTES);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_update(&ctx, idx, 2U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_final(&ctx);
    }
    while((rc == NOXTLS_RETURN_SUCCESS) && (ctr < (uint32_t)MLKEM_N)) {
        uint32_t pos = 0U;
        rc = noxtls_shake128_squeeze(&ctx, buf, MLKEM_SAMPLE_CHUNK);
        while((rc == NOXTLS_RETURN_SUCCESS) && (pos < MLKEM_SAMPLE_CHUNK) && (ctr < (uint32_t)MLKEM_N)) {
            uint32_t d1 = (uint32_t)buf[pos] | (((uint32_t)buf[pos + 1U] & 0x0FU) << 8U);
            uint32_t d2 = ((uint32_t)buf[pos + 1U] >> 4U) | ((uint32_t)buf[pos + 2U] << 4U);
            pos += 3U;
            if(d1 < (uint32_t)MLKEM_Q) {
                p->c[ctr] = (int16_t)d1;
                ctr += 1U;
            }
            if((d2 < (uint32_t)MLKEM_Q) && (ctr < (uint32_t)MLKEM_N)) {
                p->c[ctr] = (int16_t)d2;
                ctr += 1U;
            }
        }
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/* ------------------------------------------------------------------------ */
/* K-PKE (FIPS 203 §5)                                                       */
/* ------------------------------------------------------------------------ */

/**
 * @brief Working storage shared by the K-PKE routines.  It lives in the frame
 *        of the public entry point so that nested helpers do not each add
 *        their own polynomial buffers to the worst-case stack depth.
 */
typedef struct
{
    mlkem_poly_t acc;                                  /**< Accumulator. */
    mlkem_poly_t a;                                    /**< Scratch polynomial. */
} mlkem_work_t;

/** Packed NTT(r) used by K-PKE.Encrypt (12-bit encoded, k polynomials). */
typedef struct
{
    uint8_t b[MLKEM_MAX_K * MLKEM_POLY_BYTES];
} mlkem_rhat_t;

/**
 * @brief K-PKE.KeyGen(d) writing ek_pke into ek and dk_pke into dk.
 * @param[in] p Parameters.
 * @param[in] d 32-byte seed.
 * @param[out] ek Encryption key (384k + 32 bytes).
 * @param[out] dk Decryption key (384k bytes).
 * @param[in,out] w Working storage (wiped on return).
 * @return Status.
 */
static noxtls_return_t mlkem_pke_keygen(const mlkem_params_t *p, const uint8_t *d, uint8_t *ek, uint8_t *dk, mlkem_work_t *w)
{
    uint8_t g_in[MLKEM_SYM_BYTES + 1U];
    uint8_t g_out[2U * MLKEM_SYM_BYTES];
    const uint8_t *rho = g_out;
    const uint8_t *sigma = &g_out[MLKEM_SYM_BYTES];
    uint32_t i = 0U;
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(g_in, sizeof(g_in), d, MLKEM_SYM_BYTES);
    g_in[MLKEM_SYM_BYTES] = p->k;
    rc = mlkem_hash_g(g_in, (uint32_t)sizeof(g_in), NULL, 0U, g_out);
    /* s^ = NTT(s), stored packed in dk. */
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < (uint32_t)p->k); i += 1U) {
        rc = mlkem_sample_noise(&w->a, sigma, (uint8_t)i, (uint32_t)p->eta1);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_ntt(&w->a);
            mlkem_poly_tobytes(&dk[i * MLKEM_POLY_BYTES], &w->a);
        }
    }
    /* t^_i = sum_j A[i][j] o s^_j + e^_i. */
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < (uint32_t)p->k); i += 1U) {
        noxtls_secure_zero(&w->acc, sizeof(w->acc));
        for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < (uint32_t)p->k); j += 1U) {
            rc = mlkem_sample_ntt(&w->a, rho, (uint8_t)j, (uint8_t)i);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                mlkem_poly_basemul_acc_packed(&w->acc, &w->a, &dk[j * MLKEM_POLY_BYTES]);
            }
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_reduce(&w->acc);
            mlkem_poly_tomont(&w->acc);
            rc = mlkem_sample_noise(&w->a, sigma, (uint8_t)((uint32_t)p->k + i), (uint32_t)p->eta1);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_ntt(&w->a);
            mlkem_poly_add(&w->acc, &w->a);
            mlkem_poly_tobytes(&ek[i * MLKEM_POLY_BYTES], &w->acc);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(&ek[(uint32_t)p->k * MLKEM_POLY_BYTES], MLKEM_SYM_BYTES, rho, MLKEM_SYM_BYTES);
    }
    noxtls_secure_zero(&w->acc, sizeof(w->acc));
    noxtls_secure_zero(&w->a, sizeof(w->a));
    noxtls_secure_zero(g_in, sizeof(g_in));
    noxtls_secure_zero(g_out, sizeof(g_out));
    return rc;
}

/**
 * @brief K-PKE.Encrypt(ek, m, r), writing and/or comparing the ciphertext.
 *
 * When @p ct_cmp is non-NULL the produced ciphertext is compared with it in
 * constant time and *diff receives a non-zero value on mismatch.
 *
 * @param[in] p Parameters.
 * @param[in] ek Encryption key (assumed modulus-checked or produced by keygen).
 * @param[in] m 32-byte message.
 * @param[in] r 32-byte randomness.
 * @param[out] ct_out Ciphertext output, or NULL.
 * @param[in] ct_cmp Ciphertext to compare against, or NULL.
 * @param[out] diff Comparison result (0 when equal), may be NULL when ct_cmp is NULL.
 * @param[in,out] w Working storage (wiped on return).
 * @param[in,out] rh Packed NTT(r) storage (wiped on return).
 * @return Status.
 */
static noxtls_return_t mlkem_pke_encrypt(const mlkem_params_t *p,
                                         const uint8_t *ek,
                                         const uint8_t *m,
                                         const uint8_t *r,
                                         uint8_t *ct_out,
                                         const uint8_t *ct_cmp,
                                         uint8_t *diff,
                                         mlkem_work_t *w,
                                         mlkem_rhat_t *rh)
{
    mlkem_packer_t pk;
    const uint8_t *rho = &ek[(uint32_t)p->k * MLKEM_POLY_BYTES];
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint8_t nonce = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_secure_zero(&pk, sizeof(pk));
    pk.out = ct_out;
    pk.cmp = ct_cmp;
    /* r^ = NTT(r), packed. */
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < (uint32_t)p->k); i += 1U) {
        rc = mlkem_sample_noise(&w->a, r, nonce, (uint32_t)p->eta1);
        nonce = (uint8_t)(nonce + 1U);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_ntt(&w->a);
            mlkem_poly_tobytes(&rh->b[i * MLKEM_POLY_BYTES], &w->a);
        }
    }
    /* u_i = NTT^-1(sum_j A[j][i] o r^_j) + e1_i. */
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < (uint32_t)p->k); i += 1U) {
        noxtls_secure_zero(&w->acc, sizeof(w->acc));
        for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < (uint32_t)p->k); j += 1U) {
            rc = mlkem_sample_ntt(&w->a, rho, (uint8_t)i, (uint8_t)j);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                mlkem_poly_basemul_acc_packed(&w->acc, &w->a, &rh->b[j * MLKEM_POLY_BYTES]);
            }
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_reduce(&w->acc);
            mlkem_poly_invntt_tomont(&w->acc);
            rc = mlkem_sample_noise(&w->a, r, (uint8_t)((uint32_t)p->k + i), (uint32_t)p->eta2);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            mlkem_poly_add(&w->acc, &w->a);
            mlkem_poly_compress(&pk, &w->acc, (uint32_t)p->du);
        }
    }
    /* v = NTT^-1(t^ o r^) + e2 + Decompress_1(m). */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(&w->acc, sizeof(w->acc));
        for(j = 0U; j < (uint32_t)p->k; j += 1U) {
            /* t^_j is public: decode it and multiply with the packed r^_j. */
            mlkem_poly_frombytes(&w->a, &ek[j * MLKEM_POLY_BYTES]);
            mlkem_poly_basemul_acc_packed(&w->acc, &w->a, &rh->b[j * MLKEM_POLY_BYTES]);
        }
        mlkem_poly_reduce(&w->acc);
        mlkem_poly_invntt_tomont(&w->acc);
        rc = mlkem_sample_noise(&w->a, r, (uint8_t)(2U * (uint32_t)p->k), (uint32_t)p->eta2);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        mlkem_poly_add(&w->acc, &w->a);
        mlkem_poly_frommsg(&w->a, m);
        mlkem_poly_add(&w->acc, &w->a);
        mlkem_poly_compress(&pk, &w->acc, (uint32_t)p->dv);
        if(diff != NULL) {
            *diff = pk.diff;
        }
    }
    noxtls_secure_zero(&w->acc, sizeof(w->acc));
    noxtls_secure_zero(&w->a, sizeof(w->a));
    noxtls_secure_zero(rh, sizeof(*rh));
    noxtls_secure_zero(&pk, sizeof(pk));
    return rc;
}

/**
 * @brief K-PKE.Decrypt(dk, c).
 * @param[in] p Parameters.
 * @param[in] dk Decryption key (packed s^).
 * @param[in] ct Ciphertext.
 * @param[out] m 32-byte message.
 * @param[in,out] w Working storage (wiped on return).
 */
static void mlkem_pke_decrypt(const mlkem_params_t *p, const uint8_t *dk, const uint8_t *ct, uint8_t *m, mlkem_work_t *w)
{
    uint32_t j = 0U;
    uint32_t u_bytes = 32U * (uint32_t)p->du;

    noxtls_secure_zero(&w->acc, sizeof(w->acc));
    for(j = 0U; j < (uint32_t)p->k; j += 1U) {
        mlkem_poly_decompress(&w->a, &ct[j * u_bytes], (uint32_t)p->du);
        mlkem_poly_ntt(&w->a);
        mlkem_poly_basemul_acc_packed(&w->acc, &w->a, &dk[j * MLKEM_POLY_BYTES]);
    }
    mlkem_poly_reduce(&w->acc);
    mlkem_poly_invntt_tomont(&w->acc);
    mlkem_poly_decompress(&w->a, &ct[(uint32_t)p->k * u_bytes], (uint32_t)p->dv);
    mlkem_poly_rsub(&w->acc, &w->a);
    mlkem_poly_reduce(&w->acc);
    mlkem_poly_tomsg(m, &w->acc);
    noxtls_secure_zero(&w->acc, sizeof(w->acc));
    noxtls_secure_zero(&w->a, sizeof(w->a));
}

/* ------------------------------------------------------------------------ */
/* Randomness and input checks                                               */
/* ------------------------------------------------------------------------ */

/**
 * @brief Draw 32 random bytes from the DRBG (or the test sequence hook).
 * @param[out] out 32-byte output.
 * @return Status.
 */
static noxtls_return_t mlkem_gen_random32(uint8_t *out)
{
    drbg_state_t drbg;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((g_mlkem_test_random_seq != NULL) &&
       ((g_mlkem_test_random_seq_off + MLKEM_SYM_BYTES) <= g_mlkem_test_random_seq_len)) {
        noxtls_copy_u8(out, MLKEM_SYM_BYTES, &g_mlkem_test_random_seq[g_mlkem_test_random_seq_off], MLKEM_SYM_BYTES);
        g_mlkem_test_random_seq_off += MLKEM_SYM_BYTES;
        return NOXTLS_RETURN_SUCCESS;
    }
    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&drbg, out, MLKEM_SYM_BYTES * 8U, NULL, 0U);
    }
    noxtls_secure_zero(&drbg, sizeof(drbg));
    return rc;
}

/**
 * @brief Encapsulation-key modulus check (FIPS 203 §7.2): every 12-bit
 *        coefficient of ek must be < q, i.e. ByteEncode12(ByteDecode12(ek)) == ek.
 * @param[in] p Parameters.
 * @param[in] ek Encapsulation key.
 * @return NOXTLS_RETURN_SUCCESS when valid, NOXTLS_RETURN_BAD_DATA otherwise.
 */
static noxtls_return_t mlkem_check_ek(const mlkem_params_t *p, const uint8_t *ek)
{
    uint32_t i = 0U;
    uint32_t bad = 0U;
    uint32_t pairs = (uint32_t)p->k * ((uint32_t)MLKEM_N / 2U);

    for(i = 0U; i < pairs; i += 1U) {
        int16_t c[2];
        mlkem_unpack12_pair(ek, i, c);
        /* (q - 1 - c) has its sign bit set iff c >= q. */
        bad |= ((uint32_t)((int32_t)MLKEM_Q - 1 - (int32_t)c[0]) >> 31U);
        bad |= ((uint32_t)((int32_t)MLKEM_Q - 1 - (int32_t)c[1]) >> 31U);
    }
    return (bad == 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_BAD_DATA;
}

/**
 * @brief Decapsulation-key hash check (FIPS 203 §7.3): H(ek) stored in dk must match.
 * @param[in] p Parameters.
 * @param[in] dk Decapsulation key.
 * @return NOXTLS_RETURN_SUCCESS when valid, NOXTLS_RETURN_BAD_DATA on mismatch.
 */
static noxtls_return_t mlkem_check_dk(const mlkem_params_t *p, const uint8_t *dk)
{
    uint8_t h[MLKEM_SYM_BYTES];
    uint32_t off = (uint32_t)p->k * MLKEM_POLY_BYTES;
    noxtls_return_t rc = mlkem_hash_h(&dk[off], p->public_key_len, h);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(noxtls_ct_memcmp(h, &dk[off + p->public_key_len], MLKEM_SYM_BYTES) != 0) {
            rc = NOXTLS_RETURN_BAD_DATA;
        }
    }
    noxtls_secure_zero(h, sizeof(h));
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @brief Set a test-only deterministic random byte sequence (32 bytes per draw).
 *
 * Keygen consumes d then z, encaps consumes m.  When the sequence is exhausted
 * (or NULL) the DRBG is used again.  Production code must never call this;
 * prefer noxtls_mlkem_keygen_derand / noxtls_mlkem_encaps_derand in tests.
 *
 * @param[in] bytes Sequence (kept by reference) or NULL to disable.
 * @param[in] byte_len Sequence length in bytes.
 */
void noxtls_mlkem_set_test_random_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    g_mlkem_test_random_seq = bytes;
    g_mlkem_test_random_seq_len = byte_len;
    g_mlkem_test_random_seq_off = 0U;
}

/**
 * @brief Get the encapsulation (public) key length.
 * @param[in] param Parameter set.
 * @return Length in bytes, or 0 for an unsupported parameter set.
 */
uint32_t noxtls_mlkem_public_key_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.public_key_len : 0U;
}

/**
 * @brief Get the decapsulation (secret) key length.
 * @param[in] param Parameter set.
 * @return Length in bytes, or 0 for an unsupported parameter set.
 */
uint32_t noxtls_mlkem_secret_key_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.secret_key_len : 0U;
}

/**
 * @brief Get the ciphertext length.
 * @param[in] param Parameter set.
 * @return Length in bytes, or 0 for an unsupported parameter set.
 */
uint32_t noxtls_mlkem_ciphertext_len(noxtls_mlkem_param_t param)
{
    mlkem_params_t p;
    return (mlkem_get_params(param, &p) == NOXTLS_RETURN_SUCCESS) ? p.ciphertext_len : 0U;
}

/**
 * @brief Deterministic ML-KEM.KeyGen_internal(d, z) (FIPS 203 Alg. 16).
 *
 * @param[in] param Parameter set.
 * @param[in] d 32-byte seed d.
 * @param[in] z 32-byte implicit-rejection seed z.
 * @param[out] public_key Encapsulation key (noxtls_mlkem_public_key_len bytes).
 * @param[out] secret_key Decapsulation key (noxtls_mlkem_secret_key_len bytes).
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM or a hash error.
 */
noxtls_return_t noxtls_mlkem_keygen_derand(noxtls_mlkem_param_t param,
                                           const uint8_t *d,
                                           const uint8_t *z,
                                           uint8_t *public_key,
                                           uint8_t *secret_key)
{
    mlkem_params_t p;
    mlkem_work_t w;
    uint32_t off = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((d == NULL) || (z == NULL) || (public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_pke_keygen(&p, d, public_key, secret_key, &w);
    off = (uint32_t)p.k * MLKEM_POLY_BYTES;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(&secret_key[off], p.public_key_len, public_key, p.public_key_len);
        off += p.public_key_len;
        rc = mlkem_hash_h(public_key, p.public_key_len, &secret_key[off]);
        off += MLKEM_SYM_BYTES;
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(&secret_key[off], MLKEM_SYM_BYTES, z, MLKEM_SYM_BYTES);
    } else {
        noxtls_secure_zero(secret_key, p.secret_key_len);
    }
    return rc;
}

/**
 * @brief Generate an ML-KEM key pair (FIPS 203 ML-KEM.KeyGen, Alg. 19).
 *
 * @param[in] param Parameter set.
 * @param[out] public_key Encapsulation key.
 * @param[out] secret_key Decapsulation key.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM or an entropy/hash error.
 */
noxtls_return_t noxtls_mlkem_keygen(noxtls_mlkem_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    uint8_t dz[2U * MLKEM_SYM_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_mlkem_public_key_len(param) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = mlkem_gen_random32(dz);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_gen_random32(&dz[MLKEM_SYM_BYTES]);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mlkem_keygen_derand(param, dz, &dz[MLKEM_SYM_BYTES], public_key, secret_key);
    }
    noxtls_secure_zero(dz, sizeof(dz));
    return rc;
}

/**
 * @brief Check an encapsulation key (FIPS 203 §7.2 modulus check).
 * @param[in] param Parameter set.
 * @param[in] public_key Encapsulation key (noxtls_mlkem_public_key_len bytes).
 * @return NOXTLS_RETURN_SUCCESS when valid, NOXTLS_RETURN_BAD_DATA when the modulus check fails.
 */
noxtls_return_t noxtls_mlkem_check_public_key(noxtls_mlkem_param_t param, const uint8_t *public_key)
{
    mlkem_params_t p;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mlkem_check_ek(&p, public_key);
}

/**
 * @brief Check a decapsulation key (FIPS 203 §7.3 hash check H(ek) == h).
 * @param[in] param Parameter set.
 * @param[in] secret_key Decapsulation key (noxtls_mlkem_secret_key_len bytes).
 * @return NOXTLS_RETURN_SUCCESS when valid, NOXTLS_RETURN_BAD_DATA on mismatch.
 */
noxtls_return_t noxtls_mlkem_check_secret_key(noxtls_mlkem_param_t param, const uint8_t *secret_key)
{
    mlkem_params_t p;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mlkem_check_dk(&p, secret_key);
}

/**
 * @brief Deterministic ML-KEM.Encaps_internal(ek, m) (FIPS 203 Alg. 17) with
 *        the §7.2 encapsulation-key modulus check.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Encapsulation key.
 * @param[in] m 32-byte message (randomness).
 * @param[out] ciphertext Ciphertext (noxtls_mlkem_ciphertext_len bytes).
 * @param[out] shared_secret_32 32-byte shared secret K.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_BAD_DATA (modulus check failed) or a hash error.
 */
noxtls_return_t noxtls_mlkem_encaps_derand(noxtls_mlkem_param_t param,
                                           const uint8_t *public_key,
                                           const uint8_t *m,
                                           uint8_t *ciphertext,
                                           uint8_t *shared_secret_32)
{
    mlkem_params_t p;
    mlkem_work_t w;
    mlkem_rhat_t rh;
    uint8_t h[MLKEM_SYM_BYTES];
    uint8_t kr[2U * MLKEM_SYM_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (m == NULL) || (ciphertext == NULL) || (shared_secret_32 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mlkem_check_ek(&p, public_key);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_hash_h(public_key, p.public_key_len, h);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_hash_g(m, MLKEM_SYM_BYTES, h, MLKEM_SYM_BYTES, kr);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_pke_encrypt(&p, public_key, m, &kr[MLKEM_SYM_BYTES], ciphertext, NULL, NULL, &w, &rh);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(shared_secret_32, NOXTLS_MLKEM_SHARED_SECRET_LEN, kr, MLKEM_SYM_BYTES);
    }
    noxtls_secure_zero(h, sizeof(h));
    noxtls_secure_zero(kr, sizeof(kr));
    return rc;
}

/**
 * @brief Encapsulate to a peer encapsulation key (FIPS 203 ML-KEM.Encaps, Alg. 20).
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Peer encapsulation key (modulus-checked).
 * @param[out] ciphertext Ciphertext.
 * @param[out] shared_secret_32 32-byte shared secret.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_BAD_DATA (invalid key) or an entropy/hash error.
 */
noxtls_return_t noxtls_mlkem_encaps(noxtls_mlkem_param_t param, const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret_32)
{
    uint8_t m[MLKEM_SYM_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (ciphertext == NULL) || (shared_secret_32 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_mlkem_public_key_len(param) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = mlkem_gen_random32(m);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mlkem_encaps_derand(param, public_key, m, ciphertext, shared_secret_32);
    }
    noxtls_secure_zero(m, sizeof(m));
    return rc;
}

/**
 * @brief Decapsulate (FIPS 203 ML-KEM.Decaps, Alg. 21 / Decaps_internal Alg. 18).
 *
 * Performs the §7.3 decapsulation-key hash check, requires @p public_key to
 * equal the encapsulation key embedded in @p secret_key, and applies implicit
 * rejection in constant time: on a re-encryption mismatch the returned key is
 * J(z || c) and the function still returns NOXTLS_RETURN_SUCCESS.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Own encapsulation key.
 * @param[in] secret_key Own decapsulation key.
 * @param[in] ciphertext Ciphertext (noxtls_mlkem_ciphertext_len bytes).
 * @param[out] shared_secret_32 32-byte shared secret.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_FAILED (public key mismatch), NOXTLS_RETURN_BAD_DATA
 *         (decapsulation-key check failed) or a hash error.
 */
noxtls_return_t noxtls_mlkem_decaps(noxtls_mlkem_param_t param, const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ciphertext, uint8_t *shared_secret_32)
{
    mlkem_params_t p;
    mlkem_work_t w;
    mlkem_rhat_t rh;
    uint8_t m_h[2U * MLKEM_SYM_BYTES];
    uint8_t kr[2U * MLKEM_SYM_BYTES];
    uint8_t k_bar[MLKEM_SYM_BYTES];
    uint8_t diff = 0U;
    uint8_t mask = 0U;
    uint32_t i = 0U;
    const uint8_t *ek = NULL;
    const uint8_t *h = NULL;
    const uint8_t *z = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_32 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mlkem_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ek = &secret_key[(uint32_t)p.k * MLKEM_POLY_BYTES];
    h = &ek[p.public_key_len];
    z = &h[MLKEM_SYM_BYTES];
    if(noxtls_ct_memcmp(public_key, ek, (size_t)p.public_key_len) != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = mlkem_check_dk(&p, secret_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    mlkem_pke_decrypt(&p, secret_key, ciphertext, m_h, &w);
    noxtls_copy_u8(&m_h[MLKEM_SYM_BYTES], MLKEM_SYM_BYTES, h, MLKEM_SYM_BYTES);
    rc = mlkem_hash_g(m_h, (uint32_t)sizeof(m_h), NULL, 0U, kr);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_shake256(z, MLKEM_SYM_BYTES, ciphertext, p.ciphertext_len, k_bar, MLKEM_SYM_BYTES);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mlkem_pke_encrypt(&p, ek, m_h, &kr[MLKEM_SYM_BYTES], NULL, ciphertext, &diff, &w, &rh);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        /* mask = 0xFF when the ciphertexts differ, 0x00 otherwise. */
        mask = (uint8_t)(0U - (((uint32_t)diff + 0xFFU) >> 8U));
        for(i = 0U; i < MLKEM_SYM_BYTES; i += 1U) {
            shared_secret_32[i] = (uint8_t)((kr[i] & (uint8_t)~mask) | (k_bar[i] & mask));
        }
    }
    noxtls_secure_zero(m_h, sizeof(m_h));
    noxtls_secure_zero(kr, sizeof(kr));
    noxtls_secure_zero(k_bar, sizeof(k_bar));
    return rc;
}

#endif /* NOXTLS_FEATURE_ML_KEM */
