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
* File:    noxtls_falcon_internal.c
* Summary: Falcon (round-3 specification) backend.
*
* Contents:
*   - parameter sets, key / signature encodings (specification section 3.11);
*   - hash-to-point (SHAKE-256);
*   - NTT modulo q = 12289 (verification, public key, private-key completion);
*   - binary64 FFT in the "FFT representation" of the reference design
*     (n/2 complex evaluations, bit-reversed order);
*   - SamplerZ (BaseSampler RCDT table, BerExp with the integer polynomial
*     ApproxExp of the specification) driven by a ChaCha20-based PRNG seeded
*     from SHAKE-256 (same construction as the reference implementation, so
*     signatures are reproducible from the NIST KAT seeds);
*   - fast-Fourier sampling over a dynamically recomputed LDL tree
*     (72*n bytes of working storage, no stored tree);
*   - NTRUGen: discrete-Gaussian (f, g), norm checks and an exact NTRUSolve
*     (field norms, extended GCD and Babai reduction over arbitrary-precision
*     integers held in a caller-provided arena).
*
* Floating-point note: all real arithmetic is IEEE-754 binary64 with
* round-to-nearest; expression contraction (FMA) is disabled below so the
* results are bit-identical across hosts.  On FPU-less cores (Cortex-M4 has a
* single-precision FPU only) binary64 is provided by the compiler runtime,
* whose timing may depend on operand values.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include <math.h>

#include "noxtls_common.h"

#if NOXTLS_FEATURE_FALCON

#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_ct.h"
#include "noxtls_falcon_internal.h"

#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#elif defined(__GNUC__)
#pragma GCC optimize ("fp-contract=off")
#endif

#include "noxtls_falcon_tables.inc"

/* ------------------------------------------------------------------------- */
/* Constants                                                                 */
/* ------------------------------------------------------------------------- */

/** 1/sigma per log2(n) (signing standard deviation). */
static const double falcon_inv_sigma[11] = {
    0.0,
    0.0069054793295940891952143765991630516,
    0.0068102267767177975961393730687908629,
    0.0067188101910722710707826117910434131,
    0.0065883354370073665545865037227681924,
    0.0064651781207602900738053897763485516,
    0.0063486788828078995327741182928037856,
    0.0062382586529084374473367528433697537,
    0.0061334065020930261548984001431770281,
    0.0060336696681577241031668062510953022,
    0.0059386453095331159950250124336477482
};

/** sigma_min per log2(n). */
static const double falcon_sigma_min[11] = {
    0.0,
    1.1165085072329102588881898380334015,
    1.1321247692325272405718031785357108,
    1.1475285353733668684571123112513188,
    1.1702540788534828939713084716509250,
    1.1925466358390344011122170489094133,
    1.2144300507766139921088487776957699,
    1.2359260567719808790104525941706723,
    1.2570545284063214162779743112075080,
    1.2778336969128335860256340575729042,
    1.2982803343442918539708792538826807
};

/** 2^(1 - logn): inverse-FFT normalisation for the n/2-point representation. */
static const double falcon_p2_tab[11] = {
    2.0, 1.0, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.015625,
    0.0078125, 0.00390625, 0.001953125
};

#define FALCON_INV_2SQRSIGMA0  (0.150865048875372721532312163019)
#define FALCON_INV_LOG2        (1.4426950408889634073599246810)
#define FALCON_LOG2            (0.69314718055994530941723212146)
#define FALCON_PTWO63          (9223372036854775808.0)
#define FALCON_INV_Q           (1.0 / 12289.0)
#define FALCON_Q_DOUBLE        (12289.0)
/** Squared bound (1.17^2 * q) on ||(g, -f)|| and the orthogonalized vector. */
#define FALCON_KEYGEN_NORM_MAX (16822.4121)
/** Maximum number of in-place signing attempts (fresh PRNG per attempt). */
#define FALCON_SIGN_DYN_MAX_ATTEMPTS 64U

/* ------------------------------------------------------------------------- */
/* Parameter sets                                                            */
/* ------------------------------------------------------------------------- */

noxtls_return_t noxtls_falcon_internal_get_param_spec(noxtls_falcon_param_t param,
                                                      noxtls_falcon_param_spec_t *spec)
{
    if(spec == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(spec, sizeof(*spec));
    switch(param) {
        case NOXTLS_FALCON_512:
            spec->param = param;
            spec->logn = 9U;
            spec->n = 512U;
            spec->fg_bits = 6U;
            spec->F_bits = 8U;
            spec->public_key_len = 897U;
            spec->secret_key_len = 1281U;
            spec->signature_len = 666U;
            spec->l2bound = 34034726U;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_FALCON_1024:
            spec->param = param;
            spec->logn = 10U;
            spec->n = 1024U;
            spec->fg_bits = 5U;
            spec->F_bits = 8U;
            spec->public_key_len = 1793U;
            spec->secret_key_len = 2305U;
            spec->signature_len = 1280U;
            spec->l2bound = 70265242U;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/* ------------------------------------------------------------------------- */
/* Bit streams and encodings                                                 */
/* ------------------------------------------------------------------------- */

static void falcon_bit_writer_init(falcon_bit_writer_t *bw, uint8_t *buf, uint32_t buf_len)
{
    noxtls_secure_zero(buf, (size_t)buf_len);
    bw->buf = buf;
    bw->bit_len = buf_len * 8U;
    bw->bit_pos = 0U;
}

static noxtls_return_t falcon_bit_write(falcon_bit_writer_t *bw, uint32_t value, uint32_t bits)
{
    uint32_t i = 0U;

    if((bw->bit_pos + bits) > bw->bit_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    for(i = 0U; i < bits; i += 1U) {
        uint32_t bit = (value >> (bits - 1U - i)) & 1U;
        uint32_t byte_index = bw->bit_pos >> 3U;
        uint32_t bit_index = bw->bit_pos & 7U;

        bw->buf[byte_index] = (uint8_t)(bw->buf[byte_index] | (uint8_t)(bit << (7U - bit_index)));
        bw->bit_pos += 1U;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void falcon_bit_reader_init(falcon_bit_reader_t *br, const uint8_t *buf, uint32_t buf_len)
{
    br->buf = buf;
    br->bit_len = buf_len * 8U;
    br->bit_pos = 0U;
}

static noxtls_return_t falcon_bit_read(falcon_bit_reader_t *br, uint32_t bits, uint32_t *value)
{
    uint32_t i = 0U;
    uint32_t acc = 0U;

    if((br->bit_pos + bits) > br->bit_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    for(i = 0U; i < bits; i += 1U) {
        uint32_t byte_index = br->bit_pos >> 3U;
        uint32_t bit_index = br->bit_pos & 7U;

        acc = (acc << 1U) | (((uint32_t)br->buf[byte_index] >> (7U - bit_index)) & 1U);
        br->bit_pos += 1U;
    }
    *value = acc;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t falcon_bit_reader_check_tail_zero(const falcon_bit_reader_t *br)
{
    uint32_t pos = 0U;

    for(pos = br->bit_pos; pos < br->bit_len; pos += 1U) {
        if((((uint32_t)br->buf[pos >> 3U] >> (7U - (pos & 7U))) & 1U) != 0U) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_falcon_encode_public_key(const noxtls_falcon_param_spec_t *spec,
                                                const uint16_t *h,
                                                uint8_t *encoded,
                                                uint32_t encoded_len)
{
    falcon_bit_writer_t bw;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (h == NULL) || (encoded == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(encoded_len != spec->public_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    encoded[0] = (uint8_t)(NOXTLS_FALCON_PUBLIC_KEY_HDR | spec->logn);
    falcon_bit_writer_init(&bw, &encoded[1U], encoded_len - 1U);
    for(i = 0U; i < spec->n; i += 1U) {
        if(h[i] >= NOXTLS_FALCON_Q) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = falcon_bit_write(&bw, h[i], 14U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_falcon_decode_public_key(const noxtls_falcon_param_spec_t *spec,
                                                const uint8_t *encoded,
                                                uint32_t encoded_len,
                                                uint16_t *h)
{
    falcon_bit_reader_t br;
    uint32_t i = 0U;
    uint32_t value = 0U;

    if((spec == NULL) || (encoded == NULL) || (h == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(encoded_len != spec->public_key_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(encoded[0] != (uint8_t)(NOXTLS_FALCON_PUBLIC_KEY_HDR | spec->logn)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    falcon_bit_reader_init(&br, &encoded[1U], encoded_len - 1U);
    for(i = 0U; i < spec->n; i += 1U) {
        if(falcon_bit_read(&br, 14U, &value) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(value >= NOXTLS_FALCON_Q) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        h[i] = (uint16_t)value;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t falcon_encode_small(falcon_bit_writer_t *bw,
                                           const int8_t *x,
                                           uint32_t n,
                                           uint32_t bits)
{
    int32_t lim = (int32_t)(1U << (bits - 1U)) - 1;
    uint32_t mask = (1U << bits) - 1U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    for(i = 0U; i < n; i += 1U) {
        int32_t v = (int32_t)x[i];

        if((v < -lim) || (v > lim)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = falcon_bit_write(bw, (uint32_t)v & mask, bits);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t falcon_decode_small(falcon_bit_reader_t *br,
                                           int8_t *x,
                                           uint32_t n,
                                           uint32_t bits)
{
    uint32_t sign_bit = 1U << (bits - 1U);
    uint32_t i = 0U;
    uint32_t raw = 0U;

    for(i = 0U; i < n; i += 1U) {
        int32_t v = 0;

        if(falcon_bit_read(br, bits, &raw) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(raw == sign_bit) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        v = (int32_t)raw;
        if((raw & sign_bit) != 0U) {
            v -= (int32_t)(1U << bits);
        }
        x[i] = (int8_t)v;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_falcon_encode_private_key(const noxtls_falcon_param_spec_t *spec,
                                                 const int8_t *f,
                                                 const int8_t *g,
                                                 const int8_t *F,
                                                 uint8_t *encoded,
                                                 uint32_t encoded_len)
{
    falcon_bit_writer_t bw;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (f == NULL) || (g == NULL) || (F == NULL) || (encoded == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(encoded_len != spec->secret_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    encoded[0] = (uint8_t)(NOXTLS_FALCON_PRIVATE_KEY_HDR | spec->logn);
    falcon_bit_writer_init(&bw, &encoded[1U], encoded_len - 1U);
    rc = falcon_encode_small(&bw, f, spec->n, spec->fg_bits);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = falcon_encode_small(&bw, g, spec->n, spec->fg_bits);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = falcon_encode_small(&bw, F, spec->n, spec->F_bits);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(encoded, (size_t)encoded_len);
    }
    return rc;
}

noxtls_return_t noxtls_falcon_decode_private_key(const noxtls_falcon_param_spec_t *spec,
                                                 const uint8_t *encoded,
                                                 uint32_t encoded_len,
                                                 int8_t *f,
                                                 int8_t *g,
                                                 int8_t *F)
{
    falcon_bit_reader_t br;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (encoded == NULL) || (f == NULL) || (g == NULL) || (F == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(encoded_len != spec->secret_key_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(encoded[0] != (uint8_t)(NOXTLS_FALCON_PRIVATE_KEY_HDR | spec->logn)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    falcon_bit_reader_init(&br, &encoded[1U], encoded_len - 1U);
    rc = falcon_decode_small(&br, f, spec->n, spec->fg_bits);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = falcon_decode_small(&br, g, spec->n, spec->fg_bits);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = falcon_decode_small(&br, F, spec->n, spec->F_bits);
    }
    return rc;
}

noxtls_return_t noxtls_falcon_comp_encode(const int16_t *s2,
                                          uint32_t coeff_count,
                                          uint8_t *encoded,
                                          uint32_t encoded_len,
                                          uint32_t *used_len)
{
    falcon_bit_writer_t bw;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((s2 == NULL) || (encoded == NULL) || (used_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    falcon_bit_writer_init(&bw, encoded, encoded_len);
    for(i = 0U; i < coeff_count; i += 1U) {
        int32_t v = (int32_t)s2[i];
        uint32_t mag = (uint32_t)((v < 0) ? -v : v);

        if(mag > 2047U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = falcon_bit_write(&bw, ((v < 0) ? 0x80U : 0U) | (mag & 0x7FU), 8U);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            /* High part in unary: (mag >> 7) zeros followed by a one. */
            rc = falcon_bit_write(&bw, 1U, (mag >> 7U) + 1U);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    *used_len = (bw.bit_pos + 7U) >> 3U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_falcon_comp_decode(const uint8_t *encoded,
                                          uint32_t encoded_len,
                                          int16_t *s2,
                                          uint32_t coeff_count)
{
    falcon_bit_reader_t br;
    uint32_t i = 0U;

    if((encoded == NULL) || (s2 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    falcon_bit_reader_init(&br, encoded, encoded_len);
    for(i = 0U; i < coeff_count; i += 1U) {
        uint32_t low = 0U;
        uint32_t stop = 0U;
        uint32_t high = 0U;
        uint32_t mag = 0U;

        if(falcon_bit_read(&br, 8U, &low) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        for(;;) {
            if(falcon_bit_read(&br, 1U, &stop) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            if(stop != 0U) {
                break;
            }
            high += 1U;
            if(high > 15U) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        mag = (high << 7U) | (low & 0x7FU);
        if(((low & 0x80U) != 0U) && (mag == 0U)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        s2[i] = (int16_t)(((low & 0x80U) != 0U) ? -(int32_t)mag : (int32_t)mag);
    }
    return falcon_bit_reader_check_tail_zero(&br);
}

/* ------------------------------------------------------------------------- */
/* Hash to point                                                             */
/* ------------------------------------------------------------------------- */

static noxtls_return_t falcon_hash_init(noxtls_sha3_ctx_t *shake,
                                        const uint8_t *salt,
                                        const uint8_t *message,
                                        uint32_t message_len)
{
    noxtls_return_t rc = noxtls_shake256_init(shake);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(shake, salt, NOXTLS_FALCON_SALT_LEN);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (message_len != 0U)) {
        rc = noxtls_shake256_update(shake, message, message_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(shake);
    }
    return rc;
}

/** Next hash-to-point coefficient (rejection sampling on 16-bit words < 61445). */
static noxtls_return_t falcon_hash_next(noxtls_sha3_ctx_t *shake, uint16_t *out)
{
    for(;;) {
        uint8_t buf[2];
        uint32_t w = 0U;
        noxtls_return_t rc = noxtls_shake256_squeeze(shake, buf, 2U);

        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        w = ((uint32_t)buf[0] << 8U) | (uint32_t)buf[1];
        if(w < 61445U) {
            *out = (uint16_t)(w % NOXTLS_FALCON_Q);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
}

noxtls_return_t noxtls_falcon_hash_to_point(const uint8_t *salt,
                                            const uint8_t *message,
                                            uint32_t message_len,
                                            uint16_t *c,
                                            uint32_t n)
{
    noxtls_sha3_ctx_t shake;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((salt == NULL) || (c == NULL) || ((message == NULL) && (message_len != 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    rc = falcon_hash_init(&shake, salt, message, message_len);
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < n); i += 1U) {
        rc = falcon_hash_next(&shake, &c[i]);
    }
    noxtls_secure_zero(&shake, sizeof(shake));
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Arithmetic modulo q and NTT                                               */
/* ------------------------------------------------------------------------- */

static uint32_t falcon_mq_add(uint32_t a, uint32_t b)
{
    uint32_t r = a + b - NOXTLS_FALCON_Q;

    r += NOXTLS_FALCON_Q & (0U - (r >> 31U));
    return r;
}

static uint32_t falcon_mq_sub(uint32_t a, uint32_t b)
{
    uint32_t r = a - b;

    r += NOXTLS_FALCON_Q & (0U - (r >> 31U));
    return r;
}

static uint32_t falcon_mq_mul(uint32_t a, uint32_t b)
{
    return (a * b) % NOXTLS_FALCON_Q;
}

/** x^(q-2) mod q (fixed exponent, so the operation sequence is data independent). */
static uint32_t falcon_mq_inv(uint32_t x)
{
    uint32_t r = 1U;
    uint32_t b = x;
    uint32_t e = NOXTLS_FALCON_Q - 2U;

    while(e != 0U) {
        uint32_t t = falcon_mq_mul(r, b);
        uint32_t m = 0U - (e & 1U);

        r = (t & m) | (r & ~m);
        b = falcon_mq_mul(b, b);
        e >>= 1U;
    }
    return r;
}

/** Map a signed small value into [0, q). */
static uint32_t falcon_mq_from_signed(int32_t v)
{
    uint32_t w = (uint32_t)v;

    w += NOXTLS_FALCON_Q & (0U - (w >> 31U));
    return w;
}

static void falcon_mq_ntt(uint16_t *a, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t len = 0U;
    uint32_t k = 1U;

    for(len = n >> 1U; len > 0U; len >>= 1U) {
        uint32_t start = 0U;

        for(start = 0U; start < n; start += (len << 1U)) {
            uint32_t zeta = falcon_ntt_zetas[k];
            uint32_t j = 0U;

            k += 1U;
            for(j = start; j < (start + len); j += 1U) {
                uint32_t t = falcon_mq_mul(zeta, a[j + len]);

                a[j + len] = (uint16_t)falcon_mq_sub(a[j], t);
                a[j] = (uint16_t)falcon_mq_add(a[j], t);
            }
        }
    }
}

static void falcon_mq_intt(uint16_t *a, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t len = 0U;
    uint32_t ninv = falcon_mq_inv(n);
    uint32_t i = 0U;

    for(len = 1U; len < n; len <<= 1U) {
        uint32_t k = n / (len << 1U);
        uint32_t start = 0U;

        for(start = 0U; start < n; start += (len << 1U)) {
            uint32_t zi = falcon_ntt_izetas[k];
            uint32_t j = 0U;

            k += 1U;
            for(j = start; j < (start + len); j += 1U) {
                uint32_t x = a[j];
                uint32_t y = a[j + len];

                a[j] = (uint16_t)falcon_mq_add(x, y);
                a[j + len] = (uint16_t)falcon_mq_mul(falcon_mq_sub(x, y), zi);
            }
        }
    }
    for(i = 0U; i < n; i += 1U) {
        a[i] = (uint16_t)falcon_mq_mul(a[i], ninv);
    }
}

noxtls_return_t noxtls_falcon_internal_compute_public(const noxtls_falcon_param_spec_t *spec,
                                                      const int8_t *f,
                                                      const int8_t *g,
                                                      uint16_t *h,
                                                      uint16_t *tmp)
{
    uint32_t n = spec->n;
    uint32_t i = 0U;
    uint32_t zero = 0U;

    for(i = 0U; i < n; i += 1U) {
        tmp[i] = (uint16_t)falcon_mq_from_signed((int32_t)f[i]);
        h[i] = (uint16_t)falcon_mq_from_signed((int32_t)g[i]);
    }
    falcon_mq_ntt(tmp, spec->logn);
    falcon_mq_ntt(h, spec->logn);
    for(i = 0U; i < n; i += 1U) {
        zero |= (uint32_t)(tmp[i] == 0U);
        h[i] = (uint16_t)falcon_mq_mul(h[i], falcon_mq_inv(tmp[i]));
    }
    falcon_mq_intt(h, spec->logn);
    noxtls_secure_zero(tmp, (size_t)n * sizeof(uint16_t));
    return (zero != 0U) ? NOXTLS_RETURN_FAILED : NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_falcon_internal_complete_private(const noxtls_falcon_param_spec_t *spec,
                                                        const int8_t *f,
                                                        const int8_t *g,
                                                        const int8_t *F,
                                                        int8_t *G,
                                                        uint16_t *tmp)
{
    uint32_t n = spec->n;
    uint16_t *t1 = tmp;
    uint16_t *t2 = &tmp[n];
    uint32_t i = 0U;
    uint32_t bad = 0U;

    for(i = 0U; i < n; i += 1U) {
        t1[i] = (uint16_t)falcon_mq_from_signed((int32_t)g[i]);
        t2[i] = (uint16_t)falcon_mq_from_signed((int32_t)F[i]);
    }
    falcon_mq_ntt(t1, spec->logn);
    falcon_mq_ntt(t2, spec->logn);
    for(i = 0U; i < n; i += 1U) {
        t1[i] = (uint16_t)falcon_mq_mul(t1[i], t2[i]);
        t2[i] = (uint16_t)falcon_mq_from_signed((int32_t)f[i]);
    }
    falcon_mq_ntt(t2, spec->logn);
    for(i = 0U; i < n; i += 1U) {
        bad |= (uint32_t)(t2[i] == 0U);
        t1[i] = (uint16_t)falcon_mq_mul(t1[i], falcon_mq_inv(t2[i]));
    }
    falcon_mq_intt(t1, spec->logn);
    for(i = 0U; i < n; i += 1U) {
        int32_t w = (int32_t)t1[i];

        w -= (int32_t)(NOXTLS_FALCON_Q & (0U - (((NOXTLS_FALCON_Q >> 1U) - (uint32_t)w) >> 31U)));
        bad |= (uint32_t)((w < -127) || (w > 127));
        G[i] = (int8_t)w;
    }
    noxtls_secure_zero(tmp, (size_t)n * 2U * sizeof(uint16_t));
    return (bad != 0U) ? NOXTLS_RETURN_BAD_DATA : NOXTLS_RETURN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Floating-point helpers and FFT                                            */
/* ------------------------------------------------------------------------- */

/** Round to nearest (ties to even) without relying on libm rounding functions. */
static int64_t falcon_fpr_rint(double x)
{
    int64_t sx = (int64_t)(x - 1.0);
    int64_t tx = (int64_t)x;
    int64_t rp = (int64_t)(x + 4503599627370496.0) - 4503599627370496;
    int64_t rn = (int64_t)(x - 4503599627370496.0) + 4503599627370496;
    int64_t m = 0;
    uint32_t ub = 0U;

    m = (int64_t)((uint64_t)sx >> 63U);
    m = -m;
    rn &= m;
    rp &= ~m;
    ub = (uint32_t)((uint64_t)tx >> 52U);
    m = -(int64_t)(((((ub + 1U) & 0xFFFU) - 2U) >> 31U));
    rp &= m;
    rn &= m;
    tx &= ~m;
    return tx | rn | rp;
}

static int64_t falcon_fpr_floor(double x)
{
    int64_t r = (int64_t)x;

    return r - (int64_t)(x < (double)r);
}

typedef struct
{
    double re;
    double im;
} falcon_cpx_t;

static falcon_cpx_t falcon_cmul(double a_re, double a_im, double b_re, double b_im)
{
    falcon_cpx_t d;

    d.re = (a_re * b_re) - (a_im * b_im);
    d.im = (a_re * b_im) + (a_im * b_re);
    return d;
}

static falcon_cpx_t falcon_cdiv(double a_re, double a_im, double b_re, double b_im)
{
    double m = (b_re * b_re) + (b_im * b_im);
    double br = 0.0;
    double bi = 0.0;

    m = 1.0 / m;
    br = b_re * m;
    bi = (-b_im) * m;
    return falcon_cmul(a_re, a_im, br, bi);
}

static void falcon_fft(double *f, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t hn = n >> 1U;
    uint32_t t = hn;
    uint32_t u = 0U;
    uint32_t m = 2U;

    for(u = 1U; u < logn; u += 1U) {
        uint32_t ht = t >> 1U;
        uint32_t hm = m >> 1U;
        uint32_t i1 = 0U;
        uint32_t j1 = 0U;

        for(i1 = 0U; i1 < hm; i1 += 1U) {
            double s_re = falcon_gm_tab[((m + i1) << 1U)];
            double s_im = falcon_gm_tab[((m + i1) << 1U) + 1U];
            uint32_t j = 0U;

            for(j = j1; j < (j1 + ht); j += 1U) {
                double x_re = f[j];
                double x_im = f[j + hn];
                falcon_cpx_t y = falcon_cmul(f[j + ht], f[j + ht + hn], s_re, s_im);

                f[j] = x_re + y.re;
                f[j + hn] = x_im + y.im;
                f[j + ht] = x_re - y.re;
                f[j + ht + hn] = x_im - y.im;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1U;
    }
}

static void falcon_ifft(double *f, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t hn = n >> 1U;
    uint32_t t = 1U;
    uint32_t m = n;
    uint32_t u = 0U;

    for(u = logn; u > 1U; u -= 1U) {
        uint32_t hm = m >> 1U;
        uint32_t dt = t << 1U;
        uint32_t i1 = 0U;
        uint32_t j1 = 0U;

        for(j1 = 0U; j1 < hn; j1 += dt) {
            double s_re = falcon_gm_tab[((hm + i1) << 1U)];
            double s_im = -falcon_gm_tab[((hm + i1) << 1U) + 1U];
            uint32_t j = 0U;

            for(j = j1; j < (j1 + t); j += 1U) {
                double x_re = f[j];
                double x_im = f[j + hn];
                double y_re = f[j + t];
                double y_im = f[j + t + hn];
                falcon_cpx_t z;

                f[j] = x_re + y_re;
                f[j + hn] = x_im + y_im;
                z = falcon_cmul(x_re - y_re, x_im - y_im, s_re, s_im);
                f[j + t] = z.re;
                f[j + t + hn] = z.im;
            }
            i1 += 1U;
        }
        t = dt;
        m = hm;
    }
    if(logn > 0U) {
        double ni = falcon_p2_tab[logn];
        uint32_t i = 0U;

        for(i = 0U; i < n; i += 1U) {
            f[i] = f[i] * ni;
        }
    }
}

static void falcon_poly_add(double *a, const double *b, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t u = 0U;

    for(u = 0U; u < n; u += 1U) {
        a[u] = a[u] + b[u];
    }
}

static void falcon_poly_sub(double *a, const double *b, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t u = 0U;

    for(u = 0U; u < n; u += 1U) {
        a[u] = a[u] - b[u];
    }
}

static void falcon_poly_neg(double *a, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t u = 0U;

    for(u = 0U; u < n; u += 1U) {
        a[u] = -a[u];
    }
}

static void falcon_poly_mul_fft(double *a, const double *b, uint32_t logn)
{
    uint32_t hn = (1U << logn) >> 1U;
    uint32_t u = 0U;

    for(u = 0U; u < hn; u += 1U) {
        falcon_cpx_t d = falcon_cmul(a[u], a[u + hn], b[u], b[u + hn]);

        a[u] = d.re;
        a[u + hn] = d.im;
    }
}

static void falcon_poly_muladj_fft(double *a, const double *b, uint32_t logn)
{
    uint32_t hn = (1U << logn) >> 1U;
    uint32_t u = 0U;

    for(u = 0U; u < hn; u += 1U) {
        falcon_cpx_t d = falcon_cmul(a[u], a[u + hn], b[u], -b[u + hn]);

        a[u] = d.re;
        a[u + hn] = d.im;
    }
}

static void falcon_poly_mulselfadj_fft(double *a, uint32_t logn)
{
    uint32_t hn = (1U << logn) >> 1U;
    uint32_t u = 0U;

    for(u = 0U; u < hn; u += 1U) {
        double a_re = a[u];
        double a_im = a[u + hn];

        a[u] = (a_re * a_re) + (a_im * a_im);
        a[u + hn] = 0.0;
    }
}

static void falcon_poly_mulconst(double *a, double x, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t u = 0U;

    for(u = 0U; u < n; u += 1U) {
        a[u] = a[u] * x;
    }
}

static void falcon_poly_ldl_fft(const double *g00, double *g01, double *g11, uint32_t logn)
{
    uint32_t hn = (1U << logn) >> 1U;
    uint32_t u = 0U;

    for(u = 0U; u < hn; u += 1U) {
        falcon_cpx_t mu = falcon_cdiv(g01[u], g01[u + hn], g00[u], g00[u + hn]);
        falcon_cpx_t t = falcon_cmul(mu.re, mu.im, g01[u], -g01[u + hn]);

        g11[u] = g11[u] - t.re;
        g11[u + hn] = g11[u + hn] - t.im;
        g01[u] = mu.re;
        g01[u + hn] = -mu.im;
    }
}

static void falcon_poly_split_fft(double *f0, double *f1, const double *f, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t hn = n >> 1U;
    uint32_t qn = hn >> 1U;
    uint32_t u = 0U;

    f0[0] = f[0];
    f1[0] = f[hn];
    for(u = 0U; u < qn; u += 1U) {
        double a_re = f[(u << 1U)];
        double a_im = f[(u << 1U) + hn];
        double b_re = f[(u << 1U) + 1U];
        double b_im = f[(u << 1U) + 1U + hn];
        falcon_cpx_t t;

        f0[u] = (a_re + b_re) * 0.5;
        f0[u + qn] = (a_im + b_im) * 0.5;
        t = falcon_cmul(a_re - b_re, a_im - b_im,
                        falcon_gm_tab[((u + hn) << 1U)],
                        -falcon_gm_tab[((u + hn) << 1U) + 1U]);
        f1[u] = t.re * 0.5;
        f1[u + qn] = t.im * 0.5;
    }
}

static void falcon_poly_merge_fft(double *f, const double *f0, const double *f1, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t hn = n >> 1U;
    uint32_t qn = hn >> 1U;
    uint32_t u = 0U;

    f[0] = f0[0];
    f[hn] = f1[0];
    for(u = 0U; u < qn; u += 1U) {
        double a_re = f0[u];
        double a_im = f0[u + qn];
        falcon_cpx_t b = falcon_cmul(f1[u], f1[u + qn],
                                     falcon_gm_tab[((u + hn) << 1U)],
                                     falcon_gm_tab[((u + hn) << 1U) + 1U]);

        f[(u << 1U)] = a_re + b.re;
        f[(u << 1U) + hn] = a_im + b.im;
        f[(u << 1U) + 1U] = a_re - b.re;
        f[(u << 1U) + 1U + hn] = a_im - b.im;
    }
}

static void falcon_smallints_to_fpr(double *r, const int8_t *t, uint32_t logn)
{
    uint32_t n = 1U << logn;
    uint32_t u = 0U;

    for(u = 0U; u < n; u += 1U) {
        r[u] = (double)t[u];
    }
}

/* ------------------------------------------------------------------------- */
/* ChaCha20-based PRNG (seeded from SHAKE-256) and SamplerZ                  */
/* ------------------------------------------------------------------------- */

typedef struct
{
    uint8_t buf[512];
    uint32_t st[12];
    uint64_t cc;
    uint32_t ptr;
} falcon_prng_t;

typedef struct
{
    falcon_prng_t p;
    double sigma_min;
} falcon_sampler_ctx_t;

static uint32_t falcon_rotl32(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32U - n));
}

static void falcon_chacha_qround(uint32_t *s, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    s[a] += s[b];
    s[d] = falcon_rotl32(s[d] ^ s[a], 16U);
    s[c] += s[d];
    s[b] = falcon_rotl32(s[b] ^ s[c], 12U);
    s[a] += s[b];
    s[d] = falcon_rotl32(s[d] ^ s[a], 8U);
    s[c] += s[d];
    s[b] = falcon_rotl32(s[b] ^ s[c], 7U);
}

static void falcon_prng_refill(falcon_prng_t *p)
{
    static const uint32_t cw[4] = { 0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U };
    uint64_t cc = p->cc;
    uint32_t u = 0U;

    for(u = 0U; u < 8U; u += 1U) {
        uint32_t state[16];
        uint32_t v = 0U;
        uint32_t i = 0U;

        for(v = 0U; v < 4U; v += 1U) {
            state[v] = cw[v];
        }
        for(v = 0U; v < 12U; v += 1U) {
            state[v + 4U] = p->st[v];
        }
        state[14] ^= (uint32_t)cc;
        state[15] ^= (uint32_t)(cc >> 32U);
        for(i = 0U; i < 10U; i += 1U) {
            falcon_chacha_qround(state, 0U, 4U, 8U, 12U);
            falcon_chacha_qround(state, 1U, 5U, 9U, 13U);
            falcon_chacha_qround(state, 2U, 6U, 10U, 14U);
            falcon_chacha_qround(state, 3U, 7U, 11U, 15U);
            falcon_chacha_qround(state, 0U, 5U, 10U, 15U);
            falcon_chacha_qround(state, 1U, 6U, 11U, 12U);
            falcon_chacha_qround(state, 2U, 7U, 8U, 13U);
            falcon_chacha_qround(state, 3U, 4U, 9U, 14U);
        }
        for(v = 0U; v < 4U; v += 1U) {
            state[v] += cw[v];
        }
        for(v = 4U; v < 14U; v += 1U) {
            state[v] += p->st[v - 4U];
        }
        state[14] += p->st[10] ^ (uint32_t)cc;
        state[15] += p->st[11] ^ (uint32_t)(cc >> 32U);
        cc += 1U;
        /* Interleaved output layout of the reference (8 parallel blocks). */
        for(v = 0U; v < 16U; v += 1U) {
            uint32_t base = (u << 2U) + (v << 5U);

            p->buf[base] = (uint8_t)state[v];
            p->buf[base + 1U] = (uint8_t)(state[v] >> 8U);
            p->buf[base + 2U] = (uint8_t)(state[v] >> 16U);
            p->buf[base + 3U] = (uint8_t)(state[v] >> 24U);
        }
        noxtls_secure_zero(state, sizeof(state));
    }
    p->cc = cc;
    p->ptr = 0U;
}

static noxtls_return_t falcon_prng_init(falcon_prng_t *p, noxtls_sha3_ctx_t *src)
{
    uint8_t tmp[56];
    uint32_t w[14];
    uint32_t i = 0U;
    noxtls_return_t rc = noxtls_shake256_squeeze(src, tmp, (uint32_t)sizeof(tmp));

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < 14U; i += 1U) {
        w[i] = (uint32_t)tmp[(i << 2U)]
             | ((uint32_t)tmp[(i << 2U) + 1U] << 8U)
             | ((uint32_t)tmp[(i << 2U) + 2U] << 16U)
             | ((uint32_t)tmp[(i << 2U) + 3U] << 24U);
    }
    for(i = 0U; i < 12U; i += 1U) {
        p->st[i] = w[i];
    }
    p->cc = (uint64_t)w[12] | ((uint64_t)w[13] << 32U);
    noxtls_secure_zero(tmp, sizeof(tmp));
    noxtls_secure_zero(w, sizeof(w));
    falcon_prng_refill(p);
    return NOXTLS_RETURN_SUCCESS;
}

static uint64_t falcon_prng_get_u64(falcon_prng_t *p)
{
    uint32_t u = p->ptr;
    uint64_t r = 0U;
    uint32_t i = 0U;

    if(u >= ((uint32_t)sizeof(p->buf) - 9U)) {
        falcon_prng_refill(p);
        u = 0U;
    }
    p->ptr = u + 8U;
    for(i = 0U; i < 8U; i += 1U) {
        r |= (uint64_t)p->buf[u + i] << (8U * i);
    }
    return r;
}

static uint32_t falcon_prng_get_u8(falcon_prng_t *p)
{
    uint32_t v = p->buf[p->ptr];

    p->ptr += 1U;
    if(p->ptr == (uint32_t)sizeof(p->buf)) {
        falcon_prng_refill(p);
    }
    return v;
}

/** Half-Gaussian base sampler (RCDT table of the specification, 72-bit precision). */
static int32_t falcon_gaussian0(falcon_prng_t *p)
{
    static const uint32_t dist[54] = {
        10745844U,  3068844U,  3741698U,
         5559083U,  1580863U,  8248194U,
         2260429U, 13669192U,  2736639U,
          708981U,  4421575U, 10046180U,
          169348U,  7122675U,  4136815U,
           30538U, 13063405U,  7650655U,
            4132U, 14505003U,  7826148U,
             417U, 16768101U, 11363290U,
              31U,  8444042U,  8086568U,
               1U, 12844466U,   265321U,
               0U,  1232676U, 13644283U,
               0U,    38047U,  9111839U,
               0U,      870U,  6138264U,
               0U,       14U, 12545723U,
               0U,        0U,  3104126U,
               0U,        0U,    28824U,
               0U,        0U,      198U,
               0U,        0U,        1U
    };
    uint64_t lo = falcon_prng_get_u64(p);
    uint32_t hi = falcon_prng_get_u8(p);
    uint32_t v0 = (uint32_t)lo & 0xFFFFFFU;
    uint32_t v1 = (uint32_t)(lo >> 24U) & 0xFFFFFFU;
    uint32_t v2 = (uint32_t)(lo >> 48U) | (hi << 16U);
    int32_t z = 0;
    uint32_t u = 0U;

    for(u = 0U; u < 54U; u += 3U) {
        uint32_t cc = (v0 - dist[u + 2U]) >> 31U;

        cc = (v1 - dist[u + 1U] - cc) >> 31U;
        cc = (v2 - dist[u] - cc) >> 31U;
        z += (int32_t)cc;
    }
    return z;
}

/** High 64 bits of the 128-bit product (32-bit multiplications only). */
static uint64_t falcon_mulhi64(uint64_t z, uint64_t y)
{
    uint64_t z0 = (uint32_t)z;
    uint64_t z1 = z >> 32U;
    uint64_t y0 = (uint32_t)y;
    uint64_t y1 = y >> 32U;
    uint64_t a = (z0 * y1) + ((z0 * y0) >> 32U);
    uint64_t b = z1 * y0;
    uint64_t c = (a >> 32U) + (b >> 32U);

    c += (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32U);
    c += z1 * y1;
    return c;
}

uint64_t noxtls_falcon_internal_expm_p63(double x, double ccs)
{
    /* ApproxExp polynomial coefficients (Falcon specification, Algorithm 13). */
    static const uint64_t C[13] = {
        0x00000004741183A3ULL, 0x00000036548CFC06ULL, 0x0000024FDCBF140AULL,
        0x0000171D939DE045ULL, 0x0000D00CF58F6F84ULL, 0x000680681CF796E3ULL,
        0x002D82D8305B0FEAULL, 0x011111110E066FD0ULL, 0x0555555555070F00ULL,
        0x155555555581FF00ULL, 0x400000000002B400ULL, 0x7FFFFFFFFFFF4800ULL,
        0x8000000000000000ULL
    };
    uint64_t y = C[0];
    uint64_t z = (uint64_t)(int64_t)(x * FALCON_PTWO63) << 1U;
    uint32_t u = 0U;

    for(u = 1U; u < 13U; u += 1U) {
        y = C[u] - falcon_mulhi64(z, y);
    }
    z = (uint64_t)(int64_t)(ccs * FALCON_PTWO63) << 1U;
    return falcon_mulhi64(z, y);
}

static int32_t falcon_berexp(falcon_prng_t *p, double x, double ccs)
{
    int32_t s = (int32_t)(int64_t)(x * FALCON_INV_LOG2);
    double r = x - ((double)s * FALCON_LOG2);
    uint32_t sw = (uint32_t)s;
    uint64_t z = 0U;
    uint32_t i = 64U;
    uint32_t w = 0U;

    sw ^= (sw ^ 63U) & (0U - ((63U - sw) >> 31U));
    z = ((noxtls_falcon_internal_expm_p63(r, ccs) << 1U) - 1U) >> sw;
    do {
        i -= 8U;
        w = falcon_prng_get_u8(p) - ((uint32_t)(z >> i) & 0xFFU);
    } while((w == 0U) && (i > 0U));
    return (int32_t)(w >> 31U);
}

static int32_t falcon_sampler(falcon_sampler_ctx_t *spc, double mu, double isigma)
{
    int32_t s = (int32_t)falcon_fpr_floor(mu);
    double r = mu - (double)s;
    double dss = (isigma * isigma) * 0.5;
    double ccs = isigma * spc->sigma_min;

    for(;;) {
        int32_t z0 = falcon_gaussian0(&spc->p);
        int32_t b = (int32_t)(falcon_prng_get_u8(&spc->p) & 1U);
        int32_t z = b + (((2 * b) - 1) * z0);
        double x = ((double)z - r);

        x = (x * x) * dss;
        x = x - ((double)(z0 * z0) * FALCON_INV_2SQRSIGMA0);
        if(falcon_berexp(&spc->p, x, ccs) != 0) {
            return s + z;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Fast Fourier sampling over the dynamic LDL tree                           */
/* ------------------------------------------------------------------------- */

static void falcon_ffsampling_dyn(falcon_sampler_ctx_t *spc,
                                  double *t0, double *t1,
                                  double *g00, double *g01, double *g11,
                                  uint32_t orig_logn, uint32_t logn, double *tmp)
{
    uint32_t n = 0U;
    uint32_t hn = 0U;
    double *z0 = NULL;
    double *z1 = NULL;

    if(logn == 0U) {
        double leaf = sqrt(g00[0]) * falcon_inv_sigma[orig_logn];

        t0[0] = (double)falcon_sampler(spc, t0[0], leaf);
        t1[0] = (double)falcon_sampler(spc, t1[0], leaf);
        return;
    }
    n = 1U << logn;
    hn = n >> 1U;

    falcon_poly_ldl_fft(g00, g01, g11, logn);
    falcon_poly_split_fft(tmp, &tmp[hn], g00, logn);
    (void)memcpy(g00, tmp, (size_t)n * sizeof(double));
    falcon_poly_split_fft(tmp, &tmp[hn], g11, logn);
    (void)memcpy(g11, tmp, (size_t)n * sizeof(double));
    (void)memcpy(tmp, g01, (size_t)n * sizeof(double));
    (void)memcpy(g01, g00, (size_t)hn * sizeof(double));
    (void)memcpy(&g01[hn], g11, (size_t)hn * sizeof(double));

    z1 = &tmp[n];
    falcon_poly_split_fft(z1, &z1[hn], t1, logn);
    falcon_ffsampling_dyn(spc, z1, &z1[hn], g11, &g11[hn], &g01[hn], orig_logn, logn - 1U, &z1[n]);
    falcon_poly_merge_fft(&tmp[n << 1U], z1, &z1[hn], logn);

    (void)memcpy(z1, t1, (size_t)n * sizeof(double));
    falcon_poly_sub(z1, &tmp[n << 1U], logn);
    (void)memcpy(t1, &tmp[n << 1U], (size_t)n * sizeof(double));
    falcon_poly_mul_fft(tmp, z1, logn);
    falcon_poly_add(t0, tmp, logn);

    z0 = tmp;
    falcon_poly_split_fft(z0, &z0[hn], t0, logn);
    falcon_ffsampling_dyn(spc, z0, &z0[hn], g00, &g00[hn], g01, orig_logn, logn - 1U, &z0[n]);
    falcon_poly_merge_fft(t0, z0, &z0[hn], logn);
}

/** Basis B = [[g, -f], [G, -F]] in FFT form into tmp[0..4n). */
static void falcon_load_basis(double *tmp, const int8_t *f, const int8_t *g,
                              const int8_t *F, const int8_t *G, uint32_t logn)
{
    uint32_t n = 1U << logn;
    double *b00 = tmp;
    double *b01 = &tmp[n];
    double *b10 = &tmp[2U * n];
    double *b11 = &tmp[3U * n];

    falcon_smallints_to_fpr(b01, f, logn);
    falcon_smallints_to_fpr(b00, g, logn);
    falcon_smallints_to_fpr(b11, F, logn);
    falcon_smallints_to_fpr(b10, G, logn);
    falcon_fft(b01, logn);
    falcon_fft(b00, logn);
    falcon_fft(b11, logn);
    falcon_fft(b10, logn);
    falcon_poly_neg(b01, logn);
    falcon_poly_neg(b11, logn);
}

/** One signing attempt; returns 1 when (s1, s2) is short enough (s2 then written). */
static uint32_t falcon_do_sign_dyn(falcon_sampler_ctx_t *spc, int16_t *s2,
                                   const int8_t *f, const int8_t *g,
                                   const int8_t *F, const int8_t *G,
                                   const uint16_t *hm, uint32_t logn,
                                   uint32_t l2bound, double *tmp)
{
    uint32_t n = 1U << logn;
    double *b00 = tmp;
    double *b01 = &tmp[n];
    double *b10 = &tmp[2U * n];
    double *b11 = &tmp[3U * n];
    double *t0 = &tmp[4U * n];
    double *t1 = &tmp[5U * n];
    double *tx = NULL;
    double *ty = NULL;
    double *g00 = NULL;
    double *g01 = NULL;
    double *g11 = NULL;
    int16_t *s1tmp = NULL;
    int16_t *s2tmp = NULL;
    uint32_t sqn = 0U;
    uint32_t ng = 0U;
    uint32_t u = 0U;

    falcon_load_basis(tmp, f, g, F, G, logn);

    /* Gram matrix (upper triangle), keeping b01 and b11 for the target. */
    (void)memcpy(t0, b01, (size_t)n * sizeof(double));
    falcon_poly_mulselfadj_fft(t0, logn);
    (void)memcpy(t1, b00, (size_t)n * sizeof(double));
    falcon_poly_muladj_fft(t1, b10, logn);
    falcon_poly_mulselfadj_fft(b00, logn);
    falcon_poly_add(b00, t0, logn);
    (void)memcpy(t0, b01, (size_t)n * sizeof(double));
    falcon_poly_muladj_fft(b01, b11, logn);
    falcon_poly_add(b01, t1, logn);
    falcon_poly_mulselfadj_fft(b10, logn);
    (void)memcpy(t1, b11, (size_t)n * sizeof(double));
    falcon_poly_mulselfadj_fft(t1, logn);
    falcon_poly_add(b10, t1, logn);

    g00 = b00;
    g01 = b01;
    g11 = b10;
    b01 = t0;
    t0 = &b01[n];
    t1 = &t0[n];
    /* Layout: g00 g01 g11 b11 b01 t0 t1 */

    for(u = 0U; u < n; u += 1U) {
        t0[u] = (double)hm[u];
    }
    falcon_fft(t0, logn);
    (void)memcpy(t1, t0, (size_t)n * sizeof(double));
    falcon_poly_mul_fft(t1, b01, logn);
    falcon_poly_mulconst(t1, -FALCON_INV_Q, logn);
    falcon_poly_mul_fft(t0, b11, logn);
    falcon_poly_mulconst(t0, FALCON_INV_Q, logn);

    (void)memcpy(b11, t0, (size_t)n * 2U * sizeof(double));
    t0 = &g11[n];
    t1 = &t0[n];
    /* Layout: g00 g01 g11 t0 t1 */

    falcon_ffsampling_dyn(spc, t0, t1, g00, g01, g11, logn, logn, &t1[n]);

    /* Back to: b00 b01 b10 b11 t0 t1 tx ty */
    b00 = tmp;
    b01 = &b00[n];
    b10 = &b01[n];
    b11 = &b10[n];
    (void)memmove(&b11[n], t0, (size_t)n * 2U * sizeof(double));
    t0 = &b11[n];
    t1 = &t0[n];
    falcon_load_basis(tmp, f, g, F, G, logn);
    tx = &t1[n];
    ty = &tx[n];

    (void)memcpy(tx, t0, (size_t)n * sizeof(double));
    (void)memcpy(ty, t1, (size_t)n * sizeof(double));
    falcon_poly_mul_fft(tx, b00, logn);
    falcon_poly_mul_fft(ty, b10, logn);
    falcon_poly_add(tx, ty, logn);
    (void)memcpy(ty, t0, (size_t)n * sizeof(double));
    falcon_poly_mul_fft(ty, b01, logn);

    (void)memcpy(t0, tx, (size_t)n * sizeof(double));
    falcon_poly_mul_fft(t1, b11, logn);
    falcon_poly_add(t1, ty, logn);
    falcon_ifft(t0, logn);
    falcon_ifft(t1, logn);

    s1tmp = (int16_t *)(void *)tx;
    for(u = 0U; u < n; u += 1U) {
        int32_t z = (int32_t)hm[u] - (int32_t)falcon_fpr_rint(t0[u]);

        sqn += (uint32_t)(z * z);
        ng |= sqn;
        s1tmp[u] = (int16_t)z;
    }
    sqn |= 0U - (ng >> 31U);

    s2tmp = (int16_t *)(void *)tmp;
    for(u = 0U; u < n; u += 1U) {
        s2tmp[u] = (int16_t)(-falcon_fpr_rint(t1[u]));
    }
    /* is_short_half */
    ng = 0U - (sqn >> 31U);
    for(u = 0U; u < n; u += 1U) {
        int32_t z = (int32_t)s2tmp[u];

        sqn += (uint32_t)(z * z);
        ng |= sqn;
    }
    sqn |= 0U - (ng >> 31U);
    if(sqn <= l2bound) {
        (void)memcpy(s2, s2tmp, (size_t)n * sizeof(int16_t));
        return 1U;
    }
    return 0U;
}

noxtls_return_t noxtls_falcon_internal_sign_dyn(const noxtls_falcon_param_spec_t *spec,
                                                noxtls_sha3_ctx_t *rng,
                                                const int8_t *f,
                                                const int8_t *g,
                                                const int8_t *F,
                                                const int8_t *G,
                                                const uint16_t *hm,
                                                int16_t *s2,
                                                void *ws)
{
    falcon_sampler_ctx_t *spc = NULL;
    uint32_t attempt = 0U;
    uint32_t ok = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (rng == NULL) || (f == NULL) || (g == NULL) || (F == NULL) ||
       (G == NULL) || (hm == NULL) || (s2 == NULL) || (ws == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* The sampler state (ChaCha20 buffer) lives in the workspace tail, not on the stack. */
    spc = (falcon_sampler_ctx_t *)(void *)&((uint8_t *)ws)[80U * (uint32_t)spec->n];
    for(attempt = 0U; (attempt < FALCON_SIGN_DYN_MAX_ATTEMPTS) && (ok == 0U); attempt += 1U) {
        spc->sigma_min = falcon_sigma_min[spec->logn];
        rc = falcon_prng_init(&spc->p, rng);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }
        ok = falcon_do_sign_dyn(spc, s2, f, g, F, G, hm, spec->logn, spec->l2bound, (double *)ws);
    }
    noxtls_secure_zero(spc, sizeof(*spc));
    noxtls_secure_zero(ws, (size_t)spec->n * 72U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return (ok != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/* ------------------------------------------------------------------------- */
/* Workspace layouts                                                         */
/* ------------------------------------------------------------------------- */

/*
 * Signing workspace (bytes, n = 2^logn):
 *   [0, 72n)        binary64 scratch (9n doubles; also NTT scratch for G)
 *   [72n, 76n)      f, g, F, G (int8)
 *   [76n, 78n)      hm (uint16)
 *   [78n, 80n)      s2 (int16)
 *   [80n, 80n+S)    sampler state (S = sizeof(falcon_sampler_ctx_t) rounded to 8)
 */
#define FALCON_SAMPLER_WS_LEN ((uint32_t)((sizeof(falcon_sampler_ctx_t) + 7U) & ~(size_t)7U))

uint32_t noxtls_falcon_internal_sign_ws_len(uint8_t logn)
{
    return (80U * (1U << logn)) + FALCON_SAMPLER_WS_LEN;
}

/* Verification workspace: h (2n) | s2 / product (2n) | spare (2n). */
uint32_t noxtls_falcon_internal_verify_ws_len(uint8_t logn)
{
    return 6U * (1U << logn);
}

noxtls_return_t noxtls_falcon_internal_sign_seeded(const noxtls_falcon_param_spec_t *spec,
                                                   const uint8_t *secret_key,
                                                   const uint8_t *message,
                                                   uint32_t message_len,
                                                   const uint8_t *salt,
                                                   const uint8_t *seed,
                                                   uint32_t seed_len,
                                                   uint8_t *comp,
                                                   uint32_t comp_cap,
                                                   uint32_t *comp_len,
                                                   void *ws)
{
    uint32_t n = 0U;
    uint8_t *w8 = (uint8_t *)ws;
    int8_t *f = NULL;
    int8_t *g = NULL;
    int8_t *F = NULL;
    int8_t *G = NULL;
    uint16_t *hm = NULL;
    int16_t *s2 = NULL;
    noxtls_sha3_ctx_t rng;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (secret_key == NULL) || (salt == NULL) || (seed == NULL) ||
       (comp == NULL) || (comp_len == NULL) || (ws == NULL) ||
       ((message == NULL) && (message_len != 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    n = spec->n;
    f = (int8_t *)(void *)&w8[72U * n];
    g = &f[n];
    F = &g[n];
    G = &F[n];
    hm = (uint16_t *)(void *)&w8[76U * n];
    s2 = (int16_t *)(void *)&w8[78U * n];

    rc = noxtls_falcon_decode_private_key(spec, secret_key, spec->secret_key_len, f, g, F);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_internal_complete_private(spec, f, g, F, G, (uint16_t *)ws);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_hash_to_point(salt, message, message_len, hm, n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_init(&rng);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&rng, seed, seed_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&rng);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_internal_sign_dyn(spec, &rng, f, g, F, G, hm, s2, ws);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_comp_encode(s2, n, comp, comp_cap, comp_len);
    }
    noxtls_secure_zero(&rng, sizeof(rng));
    noxtls_secure_zero(ws, (size_t)noxtls_falcon_internal_sign_ws_len(spec->logn));
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Verification                                                              */
/* ------------------------------------------------------------------------- */

noxtls_return_t noxtls_falcon_internal_verify(const noxtls_falcon_param_spec_t *spec,
                                              const uint8_t *public_key,
                                              const uint8_t *salt,
                                              const uint8_t *message,
                                              uint32_t message_len,
                                              const int16_t *s2,
                                              void *ws)
{
    uint32_t n = 0U;
    uint16_t *h = (uint16_t *)ws;
    uint16_t *tt = NULL;
    noxtls_sha3_ctx_t shake;
    uint32_t sqn = 0U;
    uint32_t ng = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (public_key == NULL) || (salt == NULL) || (s2 == NULL) || (ws == NULL) ||
       ((message == NULL) && (message_len != 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    n = spec->n;
    tt = &h[n];
    rc = noxtls_falcon_decode_public_key(spec, public_key, spec->public_key_len, h);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < n; i += 1U) {
        int32_t z = (int32_t)s2[i];

        sqn += (uint32_t)(z * z);
        ng |= sqn;
        tt[i] = (uint16_t)falcon_mq_from_signed(z);
    }
    falcon_mq_ntt(h, spec->logn);
    falcon_mq_ntt(tt, spec->logn);
    for(i = 0U; i < n; i += 1U) {
        tt[i] = (uint16_t)falcon_mq_mul(tt[i], h[i]);
    }
    falcon_mq_intt(tt, spec->logn);

    rc = falcon_hash_init(&shake, salt, message, message_len);
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < n); i += 1U) {
        uint16_t c = 0U;
        int32_t w = 0;

        rc = falcon_hash_next(&shake, &c);
        /* s1 = c - s2*h mod q, centered into [-q/2, q/2]. */
        w = (int32_t)falcon_mq_sub(c, tt[i]);
        w -= (int32_t)(NOXTLS_FALCON_Q & (0U - (((NOXTLS_FALCON_Q >> 1U) - (uint32_t)w) >> 31U)));
        sqn += (uint32_t)(w * w);
        ng |= sqn;
    }
    noxtls_secure_zero(&shake, sizeof(shake));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    sqn |= 0U - (ng >> 31U);
    return (sqn <= spec->l2bound) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/* ------------------------------------------------------------------------- */
/* Key generation: arbitrary-precision helpers                               */
/* ------------------------------------------------------------------------- */

/*
 * Integers are little-endian arrays of 32-bit limbs in two's complement.  A
 * polynomial with m coefficients of L limbs occupies m*L consecutive words.
 * All storage comes from a bump arena inside the caller's workspace.
 */

typedef struct
{
    uint32_t *base;
    uint32_t cap;   /* words */
    uint32_t used;  /* words */
    uint32_t peak;  /* words */
} falcon_arena_t;

typedef struct
{
    uint32_t *d;
    uint32_t m;
    uint32_t L;
} falcon_bpoly_t;

static uint32_t *falcon_arena_alloc(falcon_arena_t *a, uint32_t words)
{
    uint32_t *p = NULL;

    words = (words + 1U) & ~1U; /* keep 8-byte alignment for doubles */
    if((a->cap - a->used) < words) {
        return NULL;
    }
    p = &a->base[a->used];
    a->used += words;
    if(a->used > a->peak) {
        a->peak = a->used;
    }
    return p;
}

static uint32_t falcon_bn_sign(const uint32_t *x, uint32_t L)
{
    return x[L - 1U] >> 31U;
}

/** Signed bit length: bits needed besides the sign bit. */
static uint32_t falcon_bn_sbitlen(const uint32_t *x, uint32_t L)
{
    uint32_t m = 0U - falcon_bn_sign(x, L);
    uint32_t i = L;

    while(i > 0U) {
        uint32_t w = x[i - 1U] ^ m;

        if(w != 0U) {
            uint32_t b = 32U;

            while((w & 0x80000000U) == 0U) {
                w <<= 1U;
                b -= 1U;
            }
            return ((i - 1U) * 32U) + b;
        }
        i -= 1U;
    }
    return 0U;
}

static uint32_t falcon_bpoly_sbitlen(const falcon_bpoly_t *p)
{
    uint32_t mx = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < p->m; i += 1U) {
        uint32_t b = falcon_bn_sbitlen(&p->d[i * p->L], p->L);

        if(b > mx) {
            mx = b;
        }
    }
    return mx;
}

/** Repack a polynomial in place to the minimal limb count. */
static void falcon_bpoly_shrink(falcon_bpoly_t *p)
{
    uint32_t nl = (falcon_bpoly_sbitlen(p) + 1U + 31U) >> 5U;
    uint32_t i = 0U;
    uint32_t k = 0U;

    if(nl == 0U) {
        nl = 1U;
    }
    if(nl >= p->L) {
        return;
    }
    for(i = 0U; i < p->m; i += 1U) {
        for(k = 0U; k < nl; k += 1U) {
            p->d[(i * nl) + k] = p->d[(i * p->L) + k];
        }
    }
    p->L = nl;
}

/** x[0..Lx) += sign-extended y[0..Ly) (Ly <= Lx), or -= when neg != 0. */
static void falcon_bn_addsub(uint32_t *x, uint32_t Lx, const uint32_t *y, uint32_t Ly, uint32_t neg)
{
    uint32_t ext = 0U - falcon_bn_sign(y, Ly);
    uint32_t nm = 0U - (neg & 1U);
    uint64_t carry = (uint64_t)(neg & 1U);
    uint32_t i = 0U;

    for(i = 0U; i < Lx; i += 1U) {
        uint32_t yw = (i < Ly) ? y[i] : ext;
        uint64_t s = (uint64_t)x[i] + (uint64_t)(yw ^ nm) + carry;

        x[i] = (uint32_t)s;
        carry = s >> 32U;
    }
}

/** t[0..La+Lb) = a * b (signed two's complement operands). */
static void falcon_bn_mul_signed(uint32_t *t, const uint32_t *a, uint32_t La,
                                 const uint32_t *b, uint32_t Lb)
{
    uint32_t i = 0U;
    uint32_t j = 0U;

    for(i = 0U; i < (La + Lb); i += 1U) {
        t[i] = 0U;
    }
    for(i = 0U; i < La; i += 1U) {
        uint64_t carry = 0U;

        for(j = 0U; j < Lb; j += 1U) {
            uint64_t s = ((uint64_t)a[i] * (uint64_t)b[j]) + (uint64_t)t[i + j] + carry;

            t[i + j] = (uint32_t)s;
            carry = s >> 32U;
        }
        t[i + Lb] = (uint32_t)carry;
    }
    /* Signed corrections: subtract b << 32La if a < 0, a << 32Lb if b < 0. */
    if(falcon_bn_sign(a, La) != 0U) {
        uint64_t br = 0U;

        for(j = 0U; j < Lb; j += 1U) {
            uint64_t s = (uint64_t)t[La + j] - (uint64_t)b[j] - br;

            t[La + j] = (uint32_t)s;
            br = (s >> 32U) & 1U;
        }
    }
    if(falcon_bn_sign(b, Lb) != 0U) {
        uint64_t br = 0U;

        for(i = 0U; i < La; i += 1U) {
            uint64_t s = (uint64_t)t[Lb + i] - (uint64_t)a[i] - br;

            t[Lb + i] = (uint32_t)s;
            br = (s >> 32U) & 1U;
        }
    }
}

/**
 * out (degree h, Lo limbs, zero-initialised by caller) +=/-= x^shift * A(x^astep) * B'(x)
 * in Z[x]/(x^h + 1), where A has acnt coefficients taken at index aoff + aidx*i of src A,
 * B similarly; bconj multiplies b_j by (-1)^j.
 */
typedef struct
{
    const uint32_t *d;
    uint32_t L;
    uint32_t cnt;
    uint32_t step; /* source index step */
    uint32_t off;  /* source index offset */
} falcon_bview_t;

static void falcon_bpoly_muladd(falcon_bpoly_t *out,
                                const falcon_bview_t *a, uint32_t aspread,
                                const falcon_bview_t *b, uint32_t bconj,
                                uint32_t shift, uint32_t neg, uint32_t *t)
{
    uint32_t h = out->m;
    uint32_t i = 0U;
    uint32_t j = 0U;

    for(i = 0U; i < a->cnt; i += 1U) {
        const uint32_t *ai = &a->d[(a->off + (i * a->step)) * a->L];

        for(j = 0U; j < b->cnt; j += 1U) {
            const uint32_t *bj = &b->d[(b->off + (j * b->step)) * b->L];
            uint32_t idx = (i * aspread) + j + shift;
            uint32_t sgn = neg;

            if((bconj != 0U) && ((j & 1U) != 0U)) {
                sgn ^= 1U;
            }
            while(idx >= h) {
                idx -= h;
                sgn ^= 1U;
            }
            falcon_bn_mul_signed(t, ai, a->L, bj, b->L);
            falcon_bn_addsub(&out->d[idx * out->L], out->L, t, a->L + b->L, sgn);
        }
    }
}

/** Arithmetic right shift by sh bits, saturated into an int64 (|result| < 2^62 expected). */
static int64_t falcon_bn_shr_i64(const uint32_t *x, uint32_t L, uint32_t sh)
{
    uint32_t ext = 0U - falcon_bn_sign(x, L);
    uint32_t w = sh >> 5U;
    uint32_t b = sh & 31U;
    uint32_t lo = (w < L) ? x[w] : ext;
    uint32_t mid = ((w + 1U) < L) ? x[w + 1U] : ext;
    uint32_t hi = ((w + 2U) < L) ? x[w + 2U] : ext;
    uint64_t r = 0U;

    if(b == 0U) {
        r = (uint64_t)lo | ((uint64_t)mid << 32U);
    } else {
        r = ((uint64_t)lo >> b) | ((uint64_t)mid << (32U - b)) | ((uint64_t)hi << (64U - b));
    }
    return (int64_t)r;
}

/** x[0..L) -= (y[0..Ly) << sh) modulo 2^(32L), y signed. */
static void falcon_bn_sub_shifted(uint32_t *x, uint32_t L, const uint32_t *y, uint32_t Ly, uint32_t sh)
{
    uint32_t ext = 0U - falcon_bn_sign(y, Ly);
    uint32_t w = sh >> 5U;
    uint32_t b = sh & 31U;
    uint64_t br = 0U;
    uint32_t i = 0U;

    for(i = w; i < L; i += 1U) {
        uint32_t k = i - w;
        uint32_t cur = (k < Ly) ? y[k] : ext;
        uint32_t prev = (k == 0U) ? 0U : (((k - 1U) < Ly) ? y[k - 1U] : ext);
        uint32_t yw = (b == 0U) ? cur : ((cur << b) | (prev >> (32U - b)));
        uint64_t s = (uint64_t)x[i] - (uint64_t)yw - br;

        x[i] = (uint32_t)s;
        br = (s >> 32U) & 1U;
    }
}

/* ------------------------------------------------------------------------- */
/* Key generation: NTRUSolve                                                 */
/* ------------------------------------------------------------------------- */

/** Field norm N(f)(x) = f0(x)^2 - x*f1(x)^2 for f = f0(x^2) + x*f1(x^2). */
static noxtls_return_t falcon_field_norm(falcon_arena_t *ar, const falcon_bpoly_t *f,
                                         falcon_bpoly_t *out)
{
    uint32_t h = f->m >> 1U;
    uint32_t Lo = (2U * f->L) + 1U;
    uint32_t *t = NULL;
    uint32_t i = 0U;
    falcon_bview_t v0;
    falcon_bview_t v1;
    uint32_t mark = ar->used;

    out->d = falcon_arena_alloc(ar, h * Lo);
    out->m = h;
    out->L = Lo;
    if(out->d == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    t = falcon_arena_alloc(ar, 2U * f->L);
    if(t == NULL) {
        ar->used = mark;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    for(i = 0U; i < (h * Lo); i += 1U) {
        out->d[i] = 0U;
    }
    v0.d = f->d;
    v0.L = f->L;
    v0.cnt = h;
    v0.step = 2U;
    v0.off = 0U;
    v1 = v0;
    v1.off = 1U;
    falcon_bpoly_muladd(out, &v0, 1U, &v0, 0U, 0U, 0U, t);
    falcon_bpoly_muladd(out, &v1, 1U, &v1, 0U, 1U, 1U, t);
    ar->used = mark + (((h * Lo) + 1U) & ~1U);
    falcon_bpoly_shrink(out);
    ar->used = mark + (((h * out->L) + 1U) & ~1U);
    return NOXTLS_RETURN_SUCCESS;
}

static uint32_t falcon_bn_is_zero(const uint32_t *x, uint32_t L)
{
    uint32_t acc = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < L; i += 1U) {
        acc |= x[i];
    }
    return (uint32_t)(acc == 0U);
}

/** Arithmetic shift right by one bit. */
static void falcon_bn_sar1(uint32_t *x, uint32_t L)
{
    uint32_t i = 0U;

    for(i = 0U; i < (L - 1U); i += 1U) {
        x[i] = (x[i] >> 1U) | (x[i + 1U] << 31U);
    }
    x[L - 1U] = (uint32_t)((int32_t)x[L - 1U] >> 1);
}

/** Unsigned compare of non-negative values: 1 if a >= b. */
static uint32_t falcon_bn_ge(const uint32_t *a, const uint32_t *b, uint32_t L)
{
    uint32_t i = L;

    while(i > 0U) {
        i -= 1U;
        if(a[i] != b[i]) {
            return (uint32_t)(a[i] > b[i]);
        }
    }
    return 1U;
}

/**
 * Binary extended GCD (HAC 14.61) for x, y > 0 (L limbs, top bit clear):
 * finds A, B with A*x + B*y = gcd(x, y).  Returns 1 when gcd == 1.
 * A, B are written with L limbs (|A| <= y, |B| <= x).
 */
static uint32_t falcon_bn_xgcd(falcon_arena_t *ar, const uint32_t *x, const uint32_t *y,
                               uint32_t L, uint32_t *Aout, uint32_t *Bout)
{
    uint32_t *u = falcon_arena_alloc(ar, L);
    uint32_t *v = falcon_arena_alloc(ar, L);
    uint32_t *A = falcon_arena_alloc(ar, L);
    uint32_t *B = falcon_arena_alloc(ar, L);
    uint32_t *C = falcon_arena_alloc(ar, L);
    uint32_t *D = falcon_arena_alloc(ar, L);
    uint32_t i = 0U;
    uint32_t guard = 0U;
    uint32_t ok = 0U;

    if((D == NULL) || (((x[0] | y[0]) & 1U) == 0U)) {
        return 0U;
    }
    for(i = 0U; i < L; i += 1U) {
        u[i] = x[i];
        v[i] = y[i];
        A[i] = 0U;
        B[i] = 0U;
        C[i] = 0U;
        D[i] = 0U;
    }
    A[0] = 1U;
    D[0] = 1U;
    for(guard = 0U; guard < (L * 32U * 4U); guard += 1U) {
        while((u[0] & 1U) == 0U) {
            falcon_bn_sar1(u, L);
            if(((A[0] | B[0]) & 1U) != 0U) {
                falcon_bn_addsub(A, L, y, L, 0U);
                falcon_bn_addsub(B, L, x, L, 1U);
            }
            falcon_bn_sar1(A, L);
            falcon_bn_sar1(B, L);
        }
        while((v[0] & 1U) == 0U) {
            falcon_bn_sar1(v, L);
            if(((C[0] | D[0]) & 1U) != 0U) {
                falcon_bn_addsub(C, L, y, L, 0U);
                falcon_bn_addsub(D, L, x, L, 1U);
            }
            falcon_bn_sar1(C, L);
            falcon_bn_sar1(D, L);
        }
        if(falcon_bn_ge(u, v, L) != 0U) {
            falcon_bn_addsub(u, L, v, L, 1U);
            falcon_bn_addsub(A, L, C, L, 1U);
            falcon_bn_addsub(B, L, D, L, 1U);
        } else {
            falcon_bn_addsub(v, L, u, L, 1U);
            falcon_bn_addsub(C, L, A, L, 1U);
            falcon_bn_addsub(D, L, B, L, 1U);
        }
        if(falcon_bn_is_zero(u, L) != 0U) {
            /* gcd = v; require v == 1 */
            uint32_t one = (uint32_t)(v[0] == 1U);

            for(i = 1U; i < L; i += 1U) {
                one &= (uint32_t)(v[i] == 0U);
            }
            ok = one;
            for(i = 0U; i < L; i += 1U) {
                Aout[i] = C[i];
                Bout[i] = D[i];
            }
            break;
        }
    }
    noxtls_secure_zero(u, (size_t)L * 6U * sizeof(uint32_t));
    return ok;
}

/** Load the top 53 bits of each coefficient, shifted right by sh, as doubles. */
static void falcon_bpoly_to_fpr(double *r, const falcon_bpoly_t *p, uint32_t sh)
{
    uint32_t i = 0U;

    for(i = 0U; i < p->m; i += 1U) {
        r[i] = (double)falcon_bn_shr_i64(&p->d[i * p->L], p->L, sh);
    }
}

/**
 * Babai reduction of (F, G) against (f, g) in Z[x]/(x^m + 1).
 *
 * (f, g) and (F, G) are approximated by their top 53 bits as binary64; the
 * quotient k = (F adj(f) + G adj(g)) / (f adj(f) + g adj(g)) is evaluated in
 * the FFT domain and scaled by a power of two so that |k| <= 2^30 (well
 * inside the floating-point accuracy), then (F, G) -= (k f, k g) << t.  Each
 * round removes ~30 - log2(m) bits until the exact Babai step (t = 0) leaves
 * k = 0.
 */
static noxtls_return_t falcon_reduce(falcon_arena_t *ar,
                                     const falcon_bpoly_t *f, const falcon_bpoly_t *g,
                                     falcon_bpoly_t *F, falcon_bpoly_t *G, uint32_t logm)
{
    uint32_t m = f->m;
    uint32_t hm = m >> 1U;
    uint32_t mark = ar->used;
    uint32_t Lf = (f->L > g->L) ? f->L : g->L;
    double *fa = (double *)(void *)falcon_arena_alloc(ar, 2U * m);
    double *ga = (double *)(void *)falcon_arena_alloc(ar, 2U * m);
    double *Fa = (double *)(void *)falcon_arena_alloc(ar, 2U * m);
    double *Ga = (double *)(void *)falcon_arena_alloc(ar, 2U * m);
    uint32_t Lt = Lf + 2U;
    uint32_t *acc = falcon_arena_alloc(ar, Lt);
    uint32_t *t = falcon_arena_alloc(ar, Lf + 1U);
    int32_t *k = NULL;
    uint32_t sf = 0U;
    uint32_t sz = 0U;
    uint32_t iter = 0U;
    uint32_t i = 0U;
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(t == NULL) {
        ar->used = mark;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    k = (int32_t *)(void *)Ga;
    sz = falcon_bpoly_sbitlen(f);
    sf = falcon_bpoly_sbitlen(g);
    if(sz > sf) {
        sf = sz;
    }
    sf = (sf > 53U) ? (sf - 53U) : 0U;
    falcon_bpoly_to_fpr(fa, f, sf);
    falcon_bpoly_to_fpr(ga, g, sf);
    if(logm > 0U) {
        falcon_fft(fa, logm);
        falcon_fft(ga, logm);
        /* fa <- adj(fa) / (fa*adj(fa) + ga*adj(ga)), ga likewise. */
        for(i = 0U; i < hm; i += 1U) {
            double den = (fa[i] * fa[i]) + (fa[i + hm] * fa[i + hm])
                       + (ga[i] * ga[i]) + (ga[i + hm] * ga[i + hm]);
            double inv = 0.0;

            if(!(den > 0.0)) {
                ar->used = mark;
                return NOXTLS_RETURN_FAILED;
            }
            inv = 1.0 / den;
            fa[i] = fa[i] * inv;
            fa[i + hm] = -fa[i + hm] * inv;
            ga[i] = ga[i] * inv;
            ga[i + hm] = -ga[i + hm] * inv;
        }
    } else {
        double den = (fa[0] * fa[0]) + (ga[0] * ga[0]);

        if(!(den > 0.0)) {
            ar->used = mark;
            return NOXTLS_RETURN_FAILED;
        }
        fa[0] = fa[0] / den;
        ga[0] = ga[0] / den;
    }

    for(iter = 0U; iter < 20000U; iter += 1U) {
        uint32_t sF = 0U;
        uint32_t nz = 0U;
        int32_t d = 0;
        int32_t sh = 0;
        int ex = 0;
        double M = 0.0;

        sz = falcon_bpoly_sbitlen(F);
        sF = falcon_bpoly_sbitlen(G);
        if(sz > sF) {
            sF = sz;
        }
        sF = (sF > 53U) ? (sF - 53U) : 0U;
        falcon_bpoly_to_fpr(Fa, F, sF);
        falcon_bpoly_to_fpr(Ga, G, sF);
        if(logm > 0U) {
            falcon_fft(Fa, logm);
            falcon_fft(Ga, logm);
            for(i = 0U; i < hm; i += 1U) {
                falcon_cpx_t x = falcon_cmul(Fa[i], Fa[i + hm], fa[i], fa[i + hm]);
                falcon_cpx_t y = falcon_cmul(Ga[i], Ga[i + hm], ga[i], ga[i + hm]);

                Fa[i] = x.re + y.re;
                Fa[i + hm] = x.im + y.im;
            }
            falcon_ifft(Fa, logm);
        } else {
            Fa[0] = (Fa[0] * fa[0]) + (Ga[0] * ga[0]);
        }
        for(i = 0U; i < m; i += 1U) {
            double a = (Fa[i] < 0.0) ? -Fa[i] : Fa[i];

            if(!(a < 1.0e300)) {
                ar->used = mark;
                return NOXTLS_RETURN_FAILED;
            }
            if(a > M) {
                M = a;
            }
        }
        /* True quotient is Fa * 2^d; scale to |k| <= 2^30, shift by t = d - scale >= 0. */
        d = (int32_t)sF - (int32_t)sf;
        (void)frexp(M, &ex);
        sh = (d - 30) + (int32_t)ex;
        if(sh < 0) {
            sh = 0;
        }
        for(i = 0U; i < m; i += 1U) {
            k[i] = (int32_t)falcon_fpr_rint(ldexp(Fa[i], (int)(d - sh)));
            nz |= (uint32_t)(k[i] != 0);
        }
        if(nz == 0U) {
            rc = NOXTLS_RETURN_SUCCESS;
            break;
        }
        /* F -= (f*k) << sh, G -= (g*k) << sh. */
        for(i = 0U; i < m; i += 1U) {
            uint32_t w = 0U;

            for(w = 0U; w < 2U; w += 1U) {
                const falcon_bpoly_t *src = (w == 0U) ? f : g;
                falcon_bpoly_t *dst = (w == 0U) ? F : G;

                for(j = 0U; j < Lt; j += 1U) {
                    acc[j] = 0U;
                }
                for(j = 0U; j < m; j += 1U) {
                    uint32_t idx = (i >= j) ? (i - j) : ((i + m) - j);
                    uint32_t sgn = (uint32_t)(i < j);
                    uint32_t kw = (uint32_t)k[idx];

                    falcon_bn_mul_signed(t, &src->d[j * src->L], src->L, &kw, 1U);
                    falcon_bn_addsub(acc, Lt, t, src->L + 1U, sgn);
                }
                falcon_bn_sub_shifted(&dst->d[i * dst->L], dst->L, acc, Lt, (uint32_t)sh);
            }
        }
    }
    noxtls_secure_zero(&ar->base[mark], (size_t)(ar->used - mark) * sizeof(uint32_t));
    ar->used = mark;
    return rc;
}

/**
 * Solve f*G - g*F = q for (F, G) given (f, g) at depth 0 (degree n = 2^logn).
 * F and G are returned as int8 (fails if any |coefficient| > 127).
 */
static noxtls_return_t falcon_ntru_solve(falcon_arena_t *ar, const int8_t *f8, const int8_t *g8,
                                         uint32_t logn, int8_t *F8, int8_t *G8)
{
    falcon_bpoly_t fl[NOXTLS_FALCON_MAX_LOGN + 1U];
    falcon_bpoly_t gl[NOXTLS_FALCON_MAX_LOGN + 1U];
    falcon_bpoly_t F;
    falcon_bpoly_t G;
    uint32_t n = 1U << logn;
    uint32_t d = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    fl[0].m = n;
    fl[0].L = 1U;
    fl[0].d = falcon_arena_alloc(ar, n);
    gl[0].m = n;
    gl[0].L = 1U;
    gl[0].d = falcon_arena_alloc(ar, n);
    if(gl[0].d == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    for(i = 0U; i < n; i += 1U) {
        fl[0].d[i] = (uint32_t)(int32_t)f8[i];
        gl[0].d[i] = (uint32_t)(int32_t)g8[i];
    }
    for(d = 0U; d < logn; d += 1U) {
        rc = falcon_field_norm(ar, &fl[d], &fl[d + 1U]);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = falcon_field_norm(ar, &gl[d], &gl[d + 1U]);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    /* Depth logn: integers. f_D, g_D > 0 (norms of norms). */
    {
        uint32_t L = ((fl[logn].L > gl[logn].L) ? fl[logn].L : gl[logn].L) + 1U;
        uint32_t *x = falcon_arena_alloc(ar, L);
        uint32_t *y = falcon_arena_alloc(ar, L);
        uint32_t *A = NULL;
        uint32_t *B = NULL;
        uint32_t mark = 0U;

        if(y == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        for(i = 0U; i < L; i += 1U) {
            x[i] = (i < fl[logn].L) ? fl[logn].d[i] : 0U;
            y[i] = (i < gl[logn].L) ? gl[logn].d[i] : 0U;
        }
        if((falcon_bn_sign(x, L) != 0U) || (falcon_bn_sign(y, L) != 0U)) {
            return NOXTLS_RETURN_FAILED;
        }
        F.m = 1U;
        G.m = 1U;
        F.L = L + 1U;
        G.L = L + 1U;
        F.d = falcon_arena_alloc(ar, F.L);
        G.d = falcon_arena_alloc(ar, G.L);
        mark = ar->used;
        A = falcon_arena_alloc(ar, L);
        B = falcon_arena_alloc(ar, L);
        if(B == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        if(falcon_bn_xgcd(ar, x, y, L, A, B) == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        /* A*f + B*g = 1  =>  G = q*A, F = -q*B. */
        for(i = 0U; i < F.L; i += 1U) {
            F.d[i] = 0U;
            G.d[i] = 0U;
        }
        {
            uint32_t *tq = falcon_arena_alloc(ar, L + 2U);
            uint32_t qw2[2] = { NOXTLS_FALCON_Q, 0U };

            if(tq == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            falcon_bn_mul_signed(tq, B, L, qw2, 2U);
            falcon_bn_addsub(F.d, F.L, tq, L + 2U, 1U);
            falcon_bn_mul_signed(tq, A, L, qw2, 2U);
            falcon_bn_addsub(G.d, G.L, tq, L + 2U, 0U);
        }
        noxtls_secure_zero(&ar->base[mark], (size_t)(ar->used - mark) * sizeof(uint32_t));
        ar->used = mark;
        rc = falcon_reduce(ar, &fl[logn], &gl[logn], &F, &G, 0U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        falcon_bpoly_shrink(&F);
        falcon_bpoly_shrink(&G);
    }

    /* Climb back: F_d = lift(F_{d+1}) * g_d(-x), G_d = lift(G_{d+1}) * f_d(-x). */
    d = logn;
    while(d > 0U) {
        falcon_bpoly_t Fn;
        falcon_bpoly_t Gn;
        falcon_bview_t va;
        falcon_bview_t vb;
        uint32_t *t = NULL;
        uint32_t base = 0U;
        uint32_t Lmax = 0U;

        d -= 1U;
        Fn.m = fl[d].m;
        Gn.m = fl[d].m;
        Fn.L = F.L + gl[d].L + 1U;
        Gn.L = G.L + fl[d].L + 1U;
        Fn.d = falcon_arena_alloc(ar, Fn.m * Fn.L);
        Gn.d = falcon_arena_alloc(ar, Gn.m * Gn.L);
        Lmax = ((F.L > G.L) ? F.L : G.L) + ((fl[d].L > gl[d].L) ? fl[d].L : gl[d].L);
        t = falcon_arena_alloc(ar, Lmax);
        if((Fn.d == NULL) || (Gn.d == NULL) || (t == NULL)) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        for(i = 0U; i < (Fn.m * Fn.L); i += 1U) {
            Fn.d[i] = 0U;
        }
        for(i = 0U; i < (Gn.m * Gn.L); i += 1U) {
            Gn.d[i] = 0U;
        }
        va.d = F.d;
        va.L = F.L;
        va.cnt = F.m;
        va.step = 1U;
        va.off = 0U;
        vb.d = gl[d].d;
        vb.L = gl[d].L;
        vb.cnt = gl[d].m;
        vb.step = 1U;
        vb.off = 0U;
        falcon_bpoly_muladd(&Fn, &va, 2U, &vb, 1U, 0U, 0U, t);
        va.d = G.d;
        va.L = G.L;
        va.cnt = G.m;
        vb.d = fl[d].d;
        vb.L = fl[d].L;
        vb.cnt = fl[d].m;
        falcon_bpoly_muladd(&Gn, &va, 2U, &vb, 1U, 0U, 0U, t);
        ar->used = (uint32_t)(t - ar->base);

        rc = falcon_reduce(ar, &fl[d], &gl[d], &Fn, &Gn, logn - d);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        falcon_bpoly_shrink(&Fn);
        falcon_bpoly_shrink(&Gn);

        /* Compact: move Fn, Gn down over f_{d+1} (everything above is now dead). */
        base = (uint32_t)(fl[d + 1U].d - ar->base);
        (void)memmove(&ar->base[base], Fn.d, (size_t)Fn.m * Fn.L * sizeof(uint32_t));
        F.d = &ar->base[base];
        F.m = Fn.m;
        F.L = Fn.L;
        base += ((Fn.m * Fn.L) + 1U) & ~1U;
        (void)memmove(&ar->base[base], Gn.d, (size_t)Gn.m * Gn.L * sizeof(uint32_t));
        G.d = &ar->base[base];
        G.m = Gn.m;
        G.L = Gn.L;
        base += ((Gn.m * Gn.L) + 1U) & ~1U;
        noxtls_secure_zero(&ar->base[base], (size_t)(ar->used - base) * sizeof(uint32_t));
        ar->used = base;
    }

    /* Depth 0: coefficients must fit int8 with |x| <= 127. */
    for(i = 0U; i < n; i += 1U) {
        int64_t fv = falcon_bn_shr_i64(&F.d[i * F.L], F.L, 0U);
        int64_t gv = falcon_bn_shr_i64(&G.d[i * G.L], G.L, 0U);

        if((F.L > 2U) || (G.L > 2U) || (fv < -127) || (fv > 127) || (gv < -127) || (gv > 127)) {
            return NOXTLS_RETURN_FAILED;
        }
        F8[i] = (int8_t)fv;
        G8[i] = (int8_t)gv;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Key generation driver                                                     */
/* ------------------------------------------------------------------------- */

#if defined(NOXTLS_FALCON_KEYGEN_STATS)
/* Development instrumentation: arena high-water mark of the last NTRUSolve. */
uint32_t noxtls_falcon_keygen_stats_peak_words = 0U;
uint32_t noxtls_falcon_keygen_stats_rc = 0U;
#endif

/* Arena budget (32-bit words) per log2(n): measured NTRUSolve peaks are 9222 (n = 512)
 * and 18438 (n = 1024) words over 300 / 100 keys; a candidate needing more is rejected. */
static uint32_t falcon_keygen_arena_words(uint8_t logn)
{
#if defined(NOXTLS_FALCON_KEYGEN_ARENA_WORDS)
    (void)logn;
    return NOXTLS_FALCON_KEYGEN_ARENA_WORDS;
#else
    return (logn >= 10U) ? 20480U : 10240U;
#endif
}

uint32_t noxtls_falcon_internal_keygen_ws_len(uint8_t logn)
{
    return falcon_keygen_arena_words(logn) * 4U;
}

/** Sample n coefficients from D_{Z,sigma_fg} using the generated CDT table. */
static noxtls_return_t falcon_keygen_gauss(noxtls_sha3_ctx_t *rng, uint32_t logn, int8_t *out)
{
    const uint64_t *cdt = (logn >= 10U) ? falcon_keygen_cdt_1024 : falcon_keygen_cdt_512;
    uint32_t cdt_len = (logn >= 10U) ? (uint32_t)(sizeof(falcon_keygen_cdt_1024) / sizeof(uint64_t))
                                     : (uint32_t)(sizeof(falcon_keygen_cdt_512) / sizeof(uint64_t));
    uint32_t n = 1U << logn;
    uint32_t i = 0U;

    for(i = 0U; i < n; i += 1U) {
        uint8_t b[8];
        uint64_t v = 0U;
        uint64_t u = 0U;
        uint32_t a = 0U;
        uint32_t s = 0U;
        uint32_t k = 0U;
        noxtls_return_t rc = noxtls_shake256_squeeze(rng, b, 8U);

        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        for(k = 0U; k < 8U; k += 1U) {
            v |= (uint64_t)b[k] << (8U * k);
        }
        s = (uint32_t)(v >> 63U);
        u = v & 0x7FFFFFFFFFFFFFFFULL;
        for(k = 0U; k < cdt_len; k += 1U) {
            a += (uint32_t)((u - cdt[k]) >> 63U);
        }
        out[i] = (int8_t)(int32_t)((a ^ (0U - s)) + s);
        noxtls_secure_zero(b, sizeof(b));
    }
    return NOXTLS_RETURN_SUCCESS;
}

static uint32_t falcon_sum_parity(const int8_t *x, uint32_t n)
{
    uint32_t s = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < n; i += 1U) {
        s += (uint32_t)(int32_t)x[i];
    }
    return s & 1U;
}

noxtls_return_t noxtls_falcon_internal_keygen(const noxtls_falcon_param_spec_t *spec,
                                              noxtls_sha3_ctx_t *rng,
                                              int8_t *f,
                                              int8_t *g,
                                              int8_t *F,
                                              int8_t *G,
                                              uint16_t *h,
                                              void *ws,
                                              uint32_t ws_len)
{
    uint32_t n = 0U;
    uint32_t logn = 0U;
    uint32_t i = 0U;
    int32_t norm = 0;
    double *rt1 = NULL;
    double *rt2 = NULL;
    double bnorm = 0.0;
    falcon_arena_t ar;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((spec == NULL) || (rng == NULL) || (f == NULL) || (g == NULL) || (F == NULL) ||
       (G == NULL) || (h == NULL) || (ws == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    n = spec->n;
    logn = spec->logn;
    if(ws_len < noxtls_falcon_internal_keygen_ws_len(spec->logn)) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    /* f and g with odd coefficient sums (otherwise Res(., x^n+1) is even). */
    do {
        rc = falcon_keygen_gauss(rng, logn, f);
    } while((rc == NOXTLS_RETURN_SUCCESS) && (falcon_sum_parity(f, n) == 0U));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        do {
            rc = falcon_keygen_gauss(rng, logn, g);
        } while((rc == NOXTLS_RETURN_SUCCESS) && (falcon_sum_parity(g, n) == 0U));
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* ||(g, -f)||^2 bound. */
    for(i = 0U; i < n; i += 1U) {
        norm += ((int32_t)f[i] * (int32_t)f[i]) + ((int32_t)g[i] * (int32_t)g[i]);
    }
    if(norm >= 16823) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Orthogonalized vector norm: q * (adj(f), adj(g)) / (f*adj(f) + g*adj(g)). */
    rt1 = (double *)ws;
    rt2 = &rt1[n];
    falcon_smallints_to_fpr(rt1, f, logn);
    falcon_smallints_to_fpr(rt2, g, logn);
    falcon_fft(rt1, logn);
    falcon_fft(rt2, logn);
    for(i = 0U; i < (n >> 1U); i += 1U) {
        double a_re = rt1[i];
        double a_im = rt1[i + (n >> 1U)];
        double b_re = rt2[i];
        double b_im = rt2[i + (n >> 1U)];
        double inv = 1.0 / ((a_re * a_re) + (a_im * a_im) + (b_re * b_re) + (b_im * b_im));

        inv = inv * FALCON_Q_DOUBLE;
        rt1[i] = a_re * inv;
        rt1[i + (n >> 1U)] = -a_im * inv;
        rt2[i] = b_re * inv;
        rt2[i + (n >> 1U)] = -b_im * inv;
    }
    falcon_ifft(rt1, logn);
    falcon_ifft(rt2, logn);
    for(i = 0U; i < n; i += 1U) {
        bnorm = bnorm + (rt1[i] * rt1[i]) + (rt2[i] * rt2[i]);
    }
    noxtls_secure_zero(ws, (size_t)n * 2U * sizeof(double));
    if(!(bnorm < FALCON_KEYGEN_NORM_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Public key (fails when f is not invertible mod q). */
    rc = noxtls_falcon_internal_compute_public(spec, f, g, h, (uint16_t *)ws);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ar.base = (uint32_t *)ws;
    ar.cap = falcon_keygen_arena_words(spec->logn);
    ar.used = 0U;
    ar.peak = 0U;
    rc = falcon_ntru_solve(&ar, f, g, logn, F, G);
#if defined(NOXTLS_FALCON_KEYGEN_STATS)
    noxtls_falcon_keygen_stats_peak_words = ar.peak;
    noxtls_falcon_keygen_stats_rc = (uint32_t)rc;
#endif
    noxtls_secure_zero(ws, (size_t)ar.peak * sizeof(uint32_t));
    if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        rc = NOXTLS_RETURN_FAILED;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Exact check of the NTRU equation f*G - g*F = q (mod x^n + 1). */
    {
        uint32_t u = 0U;
        uint32_t bad = 0U;

        for(i = 0U; i < n; i += 1U) {
            int32_t acc = 0;

            for(u = 0U; u < n; u += 1U) {
                uint32_t j = (i >= u) ? (i - u) : ((i + n) - u);
                int32_t t = ((int32_t)f[u] * (int32_t)G[j]) - ((int32_t)g[u] * (int32_t)F[j]);

                acc += (i >= u) ? t : -t;
            }
            bad |= (uint32_t)(acc != ((i == 0U) ? (int32_t)NOXTLS_FALCON_Q : 0));
        }
        if(bad != 0U) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

#else /* !NOXTLS_FEATURE_FALCON */

typedef int noxtls_falcon_internal_unused_t;

#endif /* NOXTLS_FEATURE_FALCON */
