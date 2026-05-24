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
* Summary: Falcon/FN-DSA internal helpers derived from the public specification.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include <math.h>

#include "common/noxtls_memory.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "noxtls_falcon_internal.h"

/** Falcon inverse-sigma constants indexed by `log2(n)`. */
static const double falcon_inv_sigma_by_logn[] = {
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

/** Falcon minimum sigma values indexed by `log2(n)`. */
static const double falcon_sigma_min_by_logn[] = {
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

/** Falcon sampler constant `1 / (2 * sigma0^2)` for sigma0 = 1.8205. */
static const double falcon_inv_2sqrsigma0 = 0.150865048875372721532312163019;

/** Maximum number of `(f, g)` keygen candidate resampling attempts per seed. */
#define NOXTLS_FALCON_KEYGEN_MAX_FG_ATTEMPTS 4096u

/**
 * @brief Initialize a Falcon bit writer over a caller-provided byte buffer.
 *
 * @param[out] bw Writer state to initialize.
 * @param[out] buf Backing byte buffer to clear and use.
 * @param[in] buf_len Length of `buf` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
static noxtls_return_t falcon_bit_writer_init(falcon_bit_writer_t *bw,
                                              uint8_t *buf,
                                              uint32_t buf_len)
{
    if(bw == NULL || buf == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(buf, 0, buf_len);
    bw->buf = buf;
    bw->bit_len = buf_len * 8U;
    bw->bit_pos = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check whether a Falcon transform length is a supported power of two.
 *
 * @param[in] n Transform size.
 * @return `1` if supported, otherwise `0`.
 */
static uint8_t falcon_is_supported_power_of_two(uint16_t n)
{
    return (uint8_t)(n >= 2U && n <= NOXTLS_FALCON_MAX_N && (n & (uint16_t)(n - 1U)) == 0U);
}

/**
 * @brief Reverse the low `logn` bits of a Falcon transform index.
 *
 * @param[in] x Input index.
 * @param[in] logn Number of active bits.
 * @return Bit-reversed index.
 */
static uint16_t falcon_bit_reverse_u16(uint16_t x, uint8_t logn)
{
    uint16_t r = 0U;
    uint8_t i;

    for(i = 0U; i < logn; i++) {
        r = (uint16_t)((r << 1) | (x & 1U));
        x >>= 1;
    }
    return r;
}

/**
 * @brief Multiply two Falcon complex values.
 *
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @return Complex product `a * b`.
 */
static noxtls_falcon_complex_t falcon_complex_mul(noxtls_falcon_complex_t a,
                                                  noxtls_falcon_complex_t b)
{
    noxtls_falcon_complex_t out;
    out.re = (a.re * b.re) - (a.im * b.im);
    out.im = (a.re * b.im) + (a.im * b.re);
    return out;
}

/**
 * @brief Add two Falcon complex values.
 *
 * @param[in] a First addend.
 * @param[in] b Second addend.
 * @return Complex sum `a + b`.
 */
static noxtls_falcon_complex_t falcon_complex_add(noxtls_falcon_complex_t a,
                                                  noxtls_falcon_complex_t b)
{
    noxtls_falcon_complex_t out;
    out.re = a.re + b.re;
    out.im = a.im + b.im;
    return out;
}

/**
 * @brief Subtract one Falcon complex value from another.
 *
 * @param[in] a Minuend.
 * @param[in] b Subtrahend.
 * @return Complex difference `a - b`.
 */
static noxtls_falcon_complex_t falcon_complex_sub(noxtls_falcon_complex_t a,
                                                  noxtls_falcon_complex_t b)
{
    noxtls_falcon_complex_t out;
    out.re = a.re - b.re;
    out.im = a.im - b.im;
    return out;
}

/**
 * @brief Conjugate a Falcon complex value.
 *
 * @param[in] a Input value.
 * @return Complex conjugate of `a`.
 */
static noxtls_falcon_complex_t falcon_complex_conj(noxtls_falcon_complex_t a)
{
    a.im = -a.im;
    return a;
}

/**
 * @brief Return the squared magnitude of a Falcon complex value.
 *
 * @param[in] a Input value.
 * @return `|a|^2`.
 */
static double falcon_complex_norm_sq(noxtls_falcon_complex_t a)
{
    return (a.re * a.re) + (a.im * a.im);
}

/**
 * @brief Return the absolute value of a floating-point quantity.
 *
 * @param[in] x Input value.
 * @return `|x|`.
 */
static double falcon_abs_double(double x)
{
    return x < 0.0 ? -x : x;
}

/**
 * @brief Return the maximum encodable absolute value for Falcon `f/g` coefficients.
 *
 * @param[in] spec Resolved Falcon parameter-set constants.
 * @return Maximum allowed absolute value for serialized `f/g` coefficients.
 */
static int32_t falcon_fg_limit_from_spec(const noxtls_falcon_param_spec_t *spec)
{
    return (int32_t)((1U << (spec->fg_bits - 1U)) - 1U);
}

/**
 * @brief Run an in-place radix-2 complex FFT.
 *
 * @param[in,out] vec Complex vector to transform.
 * @param[in] n Transform length.
 * @param[in] inverse Non-zero for inverse FFT, zero for forward FFT.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_fft_radix2(noxtls_falcon_complex_t *vec,
                                         uint16_t n,
                                         uint8_t inverse);

/**
 * @brief Resolve `log2(n)` for a supported Falcon degree.
 *
 * @param[in] n Polynomial degree.
 * @param[out] logn Output binary logarithm.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_get_logn(uint16_t n, uint8_t *logn)
{
    uint8_t out = 0U;
    uint16_t t;

    if(logn == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        *logn = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(t = n; t > 1U; t >>= 1) {
        out++;
    }
    *logn = out;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Squeeze one byte from a Falcon sampler context.
 *
 * @param[in,out] ctx Sampler context.
 * @param[out] value Output byte.
 * @return `NOXTLS_RETURN_SUCCESS` on success or an error code on failure.
 */
static noxtls_return_t falcon_sampler_get_u8(noxtls_falcon_sampler_ctx_t *ctx,
                                             uint8_t *value)
{
    if(ctx == NULL || value == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_shake256_squeeze(&ctx->shake, value, 1U);
}

/**
 * @brief Squeeze one 64-bit little-endian word from a Falcon sampler context.
 *
 * @param[in,out] ctx Sampler context.
 * @param[out] value Output 64-bit word.
 * @return `NOXTLS_RETURN_SUCCESS` on success or an error code on failure.
 */
static noxtls_return_t falcon_sampler_get_u64(noxtls_falcon_sampler_ctx_t *ctx,
                                              uint64_t *value)
{
    uint8_t buf[8];
    uint64_t out = 0U;
    uint32_t i;
    noxtls_return_t rc;

    if(ctx == NULL || value == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_shake256_squeeze(&ctx->shake, buf, sizeof(buf));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < sizeof(buf); i++) {
        out |= (uint64_t)buf[i] << (8U * i);
    }
    *value = out;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map a real Falcon polynomial into the negacyclic complex FFT domain without coefficient rounding.
 *
 * @param[in] poly Input real coefficients.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] fft Output complex FFT samples.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_poly_forward_fft_real(const double *poly,
                                                    uint16_t n,
                                                    noxtls_falcon_complex_t *fft)
{
    uint16_t i;
    noxtls_return_t rc;

    if(poly == NULL || fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        fft[0].re = poly[0];
        fft[0].im = 0.0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        double angle = NOXTLS_FALCON_PI * (double)i / (double)n;
        double c = cos(angle);
        double s = sin(angle);
        fft[i].re = poly[i] * c;
        fft[i].im = poly[i] * s;
    }

    rc = falcon_fft_radix2(fft, n, 0U);
    return rc;
}

/**
 * @brief Map a negacyclic complex FFT vector back to real Falcon coefficients without rounding.
 *
 * @param[in] fft Input complex FFT samples.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] poly Output real coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_poly_inverse_fft_real(const noxtls_falcon_complex_t *fft,
                                                    uint16_t n,
                                                    double *poly)
{
    noxtls_falcon_complex_t tmp[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(fft == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        poly[0] = fft[0].re;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(tmp, fft, (size_t)n * sizeof(*fft));
    rc = falcon_fft_radix2(tmp, n, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < n; i++) {
        double angle = NOXTLS_FALCON_PI * (double)i / (double)n;
        double c = cos(angle);
        double s = sin(angle);
        poly[i] = (tmp[i].re * c) + (tmp[i].im * s);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map a complex-coefficient Falcon polynomial into the negacyclic complex FFT domain.
 *
 * @param[in] poly Input complex coefficients.
 * @param[in] n Polynomial degree. Must be `1` or a supported power of two.
 * @param[out] fft Output complex FFT samples.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_poly_forward_fft_complex(const noxtls_falcon_complex_t *poly,
                                                       uint16_t n,
                                                       noxtls_falcon_complex_t *fft)
{
    uint16_t i;
    noxtls_return_t rc;

    if(poly == NULL || fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        fft[0] = poly[0];
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        noxtls_falcon_complex_t twist;
        double angle = NOXTLS_FALCON_PI * (double)i / (double)n;

        twist.re = cos(angle);
        twist.im = sin(angle);
        fft[i] = falcon_complex_mul(poly[i], twist);
    }

    rc = falcon_fft_radix2(fft, n, 0U);
    return rc;
}

/**
 * @brief Map a negacyclic complex FFT vector back to complex Falcon coefficients.
 *
 * @param[in] fft Input complex FFT samples.
 * @param[in] n Polynomial degree. Must be `1` or a supported power of two.
 * @param[out] poly Output complex coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_poly_inverse_fft_complex(const noxtls_falcon_complex_t *fft,
                                                       uint16_t n,
                                                       noxtls_falcon_complex_t *poly)
{
    noxtls_falcon_complex_t tmp[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(fft == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        poly[0] = fft[0];
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(tmp, fft, (size_t)n * sizeof(*fft));
    rc = falcon_fft_radix2(tmp, n, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < n; i++) {
        noxtls_falcon_complex_t untwist;
        double angle = NOXTLS_FALCON_PI * (double)i / (double)n;

        untwist.re = cos(angle);
        untwist.im = -sin(angle);
        poly[i] = falcon_complex_mul(tmp[i], untwist);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Run an in-place radix-2 complex FFT.
 *
 * @param[in,out] vec Complex vector to transform.
 * @param[in] n Transform length.
 * @param[in] inverse Non-zero for inverse FFT, zero for forward FFT.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_fft_radix2(noxtls_falcon_complex_t *vec,
                                         uint16_t n,
                                         uint8_t inverse)
{
    uint8_t logn = 0U;
    uint16_t i;
    uint16_t len;

    if(vec == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(len = n; len > 1U; len >>= 1) {
        logn++;
    }

    for(i = 0U; i < n; i++) {
        uint16_t j = falcon_bit_reverse_u16(i, logn);
        if(j > i) {
            noxtls_falcon_complex_t tmp = vec[i];
            vec[i] = vec[j];
            vec[j] = tmp;
        }
    }

    for(len = 2U; len <= n; len <<= 1) {
        uint16_t half = (uint16_t)(len >> 1);
        double angle = (inverse != 0U ? 2.0 : -2.0) * NOXTLS_FALCON_PI / (double)len;
        noxtls_falcon_complex_t wlen;
        wlen.re = cos(angle);
        wlen.im = sin(angle);

        for(i = 0U; i < n; i = (uint16_t)(i + len)) {
            uint16_t j;
            noxtls_falcon_complex_t w;
            w.re = 1.0;
            w.im = 0.0;

            for(j = 0U; j < half; j++) {
                noxtls_falcon_complex_t u = vec[i + j];
                noxtls_falcon_complex_t v = falcon_complex_mul(vec[i + j + half], w);
                vec[i + j].re = u.re + v.re;
                vec[i + j].im = u.im + v.im;
                vec[i + j + half].re = u.re - v.re;
                vec[i + j + half].im = u.im - v.im;
                w = falcon_complex_mul(w, wlen);
            }
        }
    }

    if(inverse != 0U) {
        double scale = 1.0 / (double)n;
        for(i = 0U; i < n; i++) {
            vec[i].re *= scale;
            vec[i].im *= scale;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Round a floating-point value to the nearest signed 32-bit integer.
 *
 * @param[in] x Input value.
 * @return Rounded integer.
 */
static int32_t falcon_round_to_i32(double x)
{
    return (int32_t)(x >= 0.0 ? floor(x + 0.5) : ceil(x - 0.5));
}

/**
 * @brief Append a big-endian bit field to the active Falcon bit stream.
 *
 * @param[in,out] bw Writer state.
 * @param[in] value Value to append.
 * @param[in] bits Number of high-to-low bits to write from `value`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
static noxtls_return_t falcon_bit_write(falcon_bit_writer_t *bw, uint32_t value, uint8_t bits)
{
    uint8_t i;

    if(bw == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(bits > 24U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((bw->bit_pos + bits) > bw->bit_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    for(i = 0U; i < bits; i++) {
        uint8_t shift = (uint8_t)(bits - 1U - i);
        uint32_t bit = (value >> shift) & 1U;
        uint32_t byte_index = bw->bit_pos >> 3;
        uint8_t bit_index = (uint8_t)(bw->bit_pos & 7U);

        if(bit != 0U) {
            bw->buf[byte_index] = (uint8_t)(bw->buf[byte_index] | (uint8_t)(0x80u >> bit_index));
        }
        bw->bit_pos++;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Consume the remaining write capacity as zero padding.
 *
 * @param[in,out] bw Writer state.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
static noxtls_return_t falcon_bit_writer_pad_zero(falcon_bit_writer_t *bw)
{
    if(bw == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    bw->bit_pos = bw->bit_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize a Falcon bit reader over a serialized byte buffer.
 *
 * @param[out] br Reader state to initialize.
 * @param[in] buf Serialized bytes to read.
 * @param[in] buf_len Length of `buf` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
static noxtls_return_t falcon_bit_reader_init(falcon_bit_reader_t *br,
                                              const uint8_t *buf,
                                              uint32_t buf_len)
{
    if(br == NULL || buf == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    br->buf = buf;
    br->bit_len = buf_len * 8U;
    br->bit_pos = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Read a big-endian bit field from a Falcon bit stream.
 *
 * @param[in,out] br Reader state.
 * @param[in] bits Number of bits to read.
 * @param[out] value Decoded bit field.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
static noxtls_return_t falcon_bit_read(falcon_bit_reader_t *br, uint8_t bits, uint32_t *value)
{
    uint8_t i;
    uint32_t acc = 0U;

    if(br == NULL || value == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(bits > 24U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((br->bit_pos + bits) > br->bit_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    for(i = 0U; i < bits; i++) {
        uint32_t byte_index = br->bit_pos >> 3;
        uint8_t bit_index = (uint8_t)(br->bit_pos & 7U);
        uint32_t bit = (uint32_t)((br->buf[byte_index] >> (7U - bit_index)) & 1U);
        acc = (acc << 1) | bit;
        br->bit_pos++;
    }

    *value = acc;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify that all unread trailing bits are zero.
 *
 * @param[in] br Reader state after decoding.
 * @return `NOXTLS_RETURN_SUCCESS` if the unread tail is zero-filled, otherwise `NOXTLS_RETURN_BAD_DATA`.
 */
static noxtls_return_t falcon_bit_reader_check_tail_zero(const falcon_bit_reader_t *br)
{
    uint32_t bit_pos;

    if(br == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(bit_pos = br->bit_pos; bit_pos < br->bit_len; bit_pos++) {
        uint32_t byte_index = bit_pos >> 3;
        uint8_t bit_index = (uint8_t)(bit_pos & 7U);
        if(((br->buf[byte_index] >> (7U - bit_index)) & 1U) != 0U) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode a two's-complement-like signed value with one reserved invalid code.
 *
 * @param[in,out] br Reader state.
 * @param[in] bits Encoded bit width.
 * @param[out] value Decoded signed value.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
static noxtls_return_t falcon_decode_signed_bits(falcon_bit_reader_t *br,
                                                 uint8_t bits,
                                                 int16_t *value)
{
    uint32_t raw;
    uint32_t sign_mask;
    int32_t decoded;
    noxtls_return_t rc;

    if(value == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = falcon_bit_read(br, bits, &raw);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    sign_mask = 1U << (bits - 1U);
    if(raw == sign_mask) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    if((raw & sign_mask) != 0U) {
        decoded = (int32_t)raw - (int32_t)(1U << bits);
    } else {
        decoded = (int32_t)raw;
    }

    *value = (int16_t)decoded;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encode a bounded signed value into the Falcon packed-key bit stream.
 *
 * @param[in,out] bw Writer state.
 * @param[in] value Signed value to encode.
 * @param[in] bits Encoded bit width.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
static noxtls_return_t falcon_encode_signed_bits(falcon_bit_writer_t *bw, int16_t value, uint8_t bits)
{
    int32_t min_allowed = -((int32_t)(1U << (bits - 1U)) - 1);
    int32_t max_allowed = (int32_t)((1U << (bits - 1U)) - 1U);
    uint32_t raw;

    if(value < min_allowed || value > max_allowed) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(value < 0) {
        raw = (uint32_t)((1U << bits) + value);
    } else {
        raw = (uint32_t)value;
    }
    return falcon_bit_write(bw, raw, bits);
}

/**
 * @brief Resolve the fixed constants for a supported Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[out] spec Output specification record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` if `spec` is `NULL`,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_internal_get_param_spec(noxtls_falcon_param_t param,
                                                      noxtls_falcon_param_spec_t *spec)
{
    if(spec == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(spec, 0, sizeof(*spec));

    switch(param) {
        case NOXTLS_FALCON_NONE:
            return NOXTLS_RETURN_INVALID_PARAM;
        case NOXTLS_FALCON_512:
            spec->param = param;
            spec->logn = 9U;
            spec->n = 512U;
            spec->fg_bits = 6U;
            spec->F_bits = 8U;
            spec->public_key_len = 897u;
            spec->secret_key_len = 1281u;
            spec->signature_len = 666u;
            spec->signature_comp_max_len = 752u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_FALCON_1024:
            spec->param = param;
            spec->logn = 10U;
            spec->n = 1024U;
            spec->fg_bits = 5U;
            spec->F_bits = 8U;
            spec->public_key_len = 1793u;
            spec->secret_key_len = 2305u;
            spec->signature_len = 1280u;
            spec->signature_comp_max_len = 1462u;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Reduce a signed 32-bit integer into the canonical Falcon residue range `[0, q)`.
 *
 * @param[in] value Signed value to reduce.
 * @return Reduced residue modulo `q`.
 */
uint16_t noxtls_falcon_mod_q_reduce_i32(int32_t value)
{
    int32_t reduced = value % (int32_t)NOXTLS_FALCON_Q;
    if(reduced < 0) {
        reduced += (int32_t)NOXTLS_FALCON_Q;
    }
    return (uint16_t)reduced;
}

/**
 * @brief Add two Falcon residues modulo `q`.
 *
 * @param[in] a First addend in `[0, q)`.
 * @param[in] b Second addend in `[0, q)`.
 * @return `(a + b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_add(uint16_t a, uint16_t b)
{
    uint32_t sum = (uint32_t)a + (uint32_t)b;
    if(sum >= NOXTLS_FALCON_Q) {
        sum -= NOXTLS_FALCON_Q;
    }
    return (uint16_t)sum;
}

/**
 * @brief Subtract two Falcon residues modulo `q`.
 *
 * @param[in] a Minuend in `[0, q)`.
 * @param[in] b Subtrahend in `[0, q)`.
 * @return `(a - b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_sub(uint16_t a, uint16_t b)
{
    if(a >= b) {
        return (uint16_t)(a - b);
    }
    return (uint16_t)(NOXTLS_FALCON_Q + (uint32_t)a - (uint32_t)b);
}

/**
 * @brief Multiply two Falcon residues modulo `q`.
 *
 * @param[in] a First factor in `[0, q)`.
 * @param[in] b Second factor in `[0, q)`.
 * @return `(a * b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_mul(uint16_t a, uint16_t b)
{
    uint32_t product = (uint32_t)a * (uint32_t)b;
    return (uint16_t)(product % NOXTLS_FALCON_Q);
}

/**
 * @brief Map a Falcon residue into the centered signed representative interval.
 *
 * @param[in] value Residue in `[0, q)`.
 * @return Centered representative in `[-q/2, q/2]`.
 */
int16_t noxtls_falcon_mod_q_center(uint16_t value)
{
    if(value > (NOXTLS_FALCON_Q / 2U)) {
        return (int16_t)((int32_t)value - (int32_t)NOXTLS_FALCON_Q);
    }
    return (int16_t)value;
}

/**
 * @brief Compute the multiplicative inverse of a non-zero Falcon residue.
 *
 * @param[in] value Residue in `[0, q)`.
 * @return Multiplicative inverse modulo `q`, or `0` if `value` is `0`.
 */
static uint16_t falcon_mod_q_inv(uint16_t value)
{
    int32_t t = 0;
    int32_t new_t = 1;
    int32_t r = (int32_t)NOXTLS_FALCON_Q;
    int32_t new_r = (int32_t)value;

    if(value == 0U) {
        return 0U;
    }

    while(new_r != 0) {
        int32_t quotient = r / new_r;
        int32_t tmp_t = t - quotient * new_t;
        int32_t tmp_r = r - quotient * new_r;

        t = new_t;
        new_t = tmp_t;
        r = new_r;
        new_r = tmp_r;
    }

    if(r != 1) {
        return 0U;
    }
    if(t < 0) {
        t += (int32_t)NOXTLS_FALCON_Q;
    }
    return (uint16_t)t;
}

/**
 * @brief Get the degree of a Falcon polynomial over `Zq`.
 *
 * @param[in] poly Polynomial coefficients.
 * @param[in] len Number of coefficients available in `poly`.
 * @return Highest non-zero coefficient index, or `-1` for the zero polynomial.
 */
static int32_t falcon_poly_degree(const uint16_t *poly, uint16_t len)
{
    int32_t i;

    if(poly == NULL) {
        return -1;
    }

    for(i = (int32_t)len - 1; i >= 0; i--) {
        if(poly[i] != 0U) {
            return i;
        }
    }

    return -1;
}

/**
 * @brief Set a Falcon polynomial buffer to zero.
 *
 * @param[out] poly Polynomial buffer to clear.
 * @param[in] len Number of coefficients in `poly`.
 */
static void falcon_poly_zero(uint16_t *poly, uint16_t len)
{
    if(poly == NULL) {
        return;
    }
    memset(poly, 0, (size_t)len * sizeof(*poly));
}

/**
 * @brief Copy Falcon polynomial coefficients between equally sized buffers.
 *
 * @param[out] dst Destination polynomial buffer.
 * @param[in] src Source polynomial buffer.
 * @param[in] len Number of coefficients to copy.
 */
static void falcon_poly_copy(uint16_t *dst, const uint16_t *src, uint16_t len)
{
    if(dst == NULL || src == NULL) {
        return;
    }
    memcpy(dst, src, (size_t)len * sizeof(*dst));
}

/**
 * @brief Reduce a polynomial into `Zq[x]/(x^n + 1)`.
 *
 * @param[out] out Output polynomial of degree less than `n`.
 * @param[in] in Input polynomial coefficients.
 * @param[in] in_len Number of coefficients in `in`.
 * @param[in] n Falcon ring degree.
 */
static void falcon_poly_reduce_xn1_mod_q(uint16_t *out,
                                         const uint16_t *in,
                                         uint16_t in_len,
                                         uint16_t n)
{
    uint16_t i;

    if(out == NULL || in == NULL) {
        return;
    }
    falcon_poly_zero(out, n);

    for(i = 0U; i < in_len; i++) {
        if(i < n) {
            out[i] = noxtls_falcon_mod_q_add(out[i], in[i]);
        } else {
            out[i - n] = noxtls_falcon_mod_q_sub(out[i - n], in[i]);
        }
    }
}

/**
 * @brief Multiply two Falcon polynomials and reduce modulo `x^n + 1` and `q`.
 *
 * @param[out] out Output polynomial in `Zq[x]/(x^n + 1)`.
 * @param[in] a First factor coefficients modulo `q`.
 * @param[in] a_len Number of coefficients in `a`.
 * @param[in] b Second factor coefficients modulo `q`.
 * @param[in] b_len Number of coefficients in `b`.
 * @param[in] n Falcon ring degree.
 */
static void falcon_poly_mul_xn1_mod_q(uint16_t *out,
                                      const uint16_t *a,
                                      uint16_t a_len,
                                      const uint16_t *b,
                                      uint16_t b_len,
                                      uint16_t n)
{
    int64_t raw[2U * NOXTLS_FALCON_MAX_N] = {0};
    uint16_t i;
    uint16_t j;
    uint16_t raw_len;

    if(out == NULL || a == NULL || b == NULL || n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return;
    }

    raw_len = (uint16_t)(a_len + b_len - 1U);
    for(i = 0U; i < a_len; i++) {
        for(j = 0U; j < b_len; j++) {
            raw[i + j] += (int64_t)a[i] * (int64_t)b[j];
        }
    }

    for(i = 0U; i < n; i++) {
        int64_t folded = raw[i];
        if((uint16_t)(i + n) < raw_len) {
            folded -= raw[i + n];
        }
        out[i] = noxtls_falcon_mod_q_reduce_i32((int32_t)(folded % (int64_t)NOXTLS_FALCON_Q));
    }
}

/**
 * @brief Multiply two signed polynomials in the negacyclic Falcon ring over the integers.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[in] n Falcon ring degree.
 */
static void falcon_poly_mul_xn1_i32(int32_t *out,
                                    const int16_t *a,
                                    const int16_t *b,
                                    uint16_t n)
{
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL || n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return;
    }

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < n; i++) {
        int32_t ai = (int32_t)a[i];
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int32_t term = ai * (int32_t)b[j];
            if(idx < n) {
                out[idx] += term;
            } else {
                out[idx - n] -= term;
            }
        }
    }
}

/**
 * @brief Divide two Falcon polynomials over `Zq`.
 *
 * @param[out] quotient Output quotient polynomial.
 * @param[out] remainder Output remainder polynomial.
 * @param[in] dividend Dividend polynomial.
 * @param[in] divisor Divisor polynomial.
 * @param[in] len Common polynomial buffer length for all operands.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or `NOXTLS_RETURN_FAILED` if the divisor is zero.
 */
static noxtls_return_t falcon_poly_divmod(uint16_t *quotient,
                                          uint16_t *remainder,
                                          const uint16_t *dividend,
                                          const uint16_t *divisor,
                                          uint16_t len)
{
    int32_t divisor_deg;
    uint16_t divisor_lead_inv;

    if(quotient == NULL || remainder == NULL || dividend == NULL || divisor == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    divisor_deg = falcon_poly_degree(divisor, len);
    if(divisor_deg < 0) {
        return NOXTLS_RETURN_FAILED;
    }
    divisor_lead_inv = falcon_mod_q_inv(divisor[divisor_deg]);
    if(divisor_lead_inv == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    falcon_poly_zero(quotient, len);
    falcon_poly_copy(remainder, dividend, len);

    for(;;) {
        int32_t remainder_deg = falcon_poly_degree(remainder, len);
        uint16_t scale;
        uint16_t shift;
        uint16_t i;

        if(remainder_deg < divisor_deg) {
            break;
        }

        shift = (uint16_t)(remainder_deg - divisor_deg);
        scale = noxtls_falcon_mod_q_mul(remainder[remainder_deg], divisor_lead_inv);
        quotient[shift] = noxtls_falcon_mod_q_add(quotient[shift], scale);
        for(i = 0U; i <= (uint16_t)divisor_deg; i++) {
            uint16_t product = noxtls_falcon_mod_q_mul(scale, divisor[i]);
            remainder[i + shift] = noxtls_falcon_mod_q_sub(remainder[i + shift], product);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Invert a Falcon polynomial in the ring `Zq[x]/(x^n + 1)`.
 *
 * @param[out] inverse Output inverse polynomial modulo `x^n + 1` and `q`.
 * @param[in] f Input polynomial coefficients modulo `q`.
 * @param[in] n Falcon ring degree.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_FAILED` if `f` is not invertible.
 */
static noxtls_return_t falcon_poly_invert_xn1_mod_q(uint16_t *inverse,
                                                    const uint16_t *f,
                                                    uint16_t n)
{
    uint16_t r0[NOXTLS_FALCON_MAX_N + 1U];
    uint16_t r1[NOXTLS_FALCON_MAX_N + 1U];
    uint16_t r2[NOXTLS_FALCON_MAX_N + 1U];
    uint16_t qpoly[NOXTLS_FALCON_MAX_N + 1U];
    uint16_t qring[NOXTLS_FALCON_MAX_N];
    uint16_t t0[NOXTLS_FALCON_MAX_N];
    uint16_t t1[NOXTLS_FALCON_MAX_N];
    uint16_t t2[NOXTLS_FALCON_MAX_N];
    uint16_t product[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(inverse == NULL || f == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    falcon_poly_zero(r0, (uint16_t)(n + 1U));
    falcon_poly_zero(r1, (uint16_t)(n + 1U));
    falcon_poly_zero(t0, n);
    falcon_poly_zero(t1, n);
    r0[0] = 1U;
    r0[n] = 1U;
    for(i = 0U; i < n; i++) {
        r1[i] = f[i];
    }
    t1[0] = 1U;

    while(falcon_poly_degree(r1, (uint16_t)(n + 1U)) > 0) {
        rc = falcon_poly_divmod(qpoly, r2, r0, r1, (uint16_t)(n + 1U));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        falcon_poly_reduce_xn1_mod_q(qring, qpoly, (uint16_t)(n + 1U), n);
        falcon_poly_mul_xn1_mod_q(product, qring, n, t1, n, n);
        for(i = 0U; i < n; i++) {
            t2[i] = noxtls_falcon_mod_q_sub(t0[i], product[i]);
        }

        falcon_poly_copy(r0, r1, (uint16_t)(n + 1U));
        falcon_poly_copy(r1, r2, (uint16_t)(n + 1U));
        falcon_poly_copy(t0, t1, n);
        falcon_poly_copy(t1, t2, n);
    }

    if(falcon_poly_degree(r1, (uint16_t)(n + 1U)) != 0 || r1[0] == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    {
        uint16_t scalar_inv = falcon_mod_q_inv(r1[0]);
        if(scalar_inv == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        for(i = 0U; i < n; i++) {
            inverse[i] = noxtls_falcon_mod_q_mul(t1[i], scalar_inv);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Hash arbitrary input bytes into Falcon challenge coefficients with SHAKE256.
 *
 * @param[in] input Message to hash. May be `NULL` only when `input_len` is `0`.
 * @param[in] input_len Length of `input` in bytes.
 * @param[out] coeffs Output coefficient array.
 * @param[in] coeff_count Number of coefficients to generate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or a SHAKE error code.
 */
noxtls_return_t noxtls_falcon_hash_to_point(const uint8_t *input,
                                            uint32_t input_len,
                                            uint16_t *coeffs,
                                            uint32_t coeff_count)
{
    noxtls_sha3_ctx_t shake;
    uint8_t block[2];
    uint32_t i = 0U;
    uint32_t k;
    uint32_t limit;
    noxtls_return_t rc;

    if(coeffs == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(input == NULL && input_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }

    k = 65536u / NOXTLS_FALCON_Q;
    limit = k * NOXTLS_FALCON_Q;

    rc = noxtls_shake256_init(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, input, input_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_final(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    while(i < coeff_count) {
        uint32_t t;

        rc = noxtls_shake256_squeeze(&shake, block, sizeof(block));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        t = ((uint32_t)block[0] << 8) | (uint32_t)block[1];
        if(t < limit) {
            coeffs[i++] = (uint16_t)(t % NOXTLS_FALCON_Q);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Recompute the missing Falcon secret polynomial `G` from `f`, `g`, and `F`.
 *
 * This reconstructs the centered small-coefficient solution `G` such that
 * `fG - gF = q` in the negacyclic ring `Z[x] / (x^n + 1)`.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] G Output reconstructed polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if no valid small `G` can be reconstructed.
 */
noxtls_return_t noxtls_falcon_complete_private_key(noxtls_falcon_param_t param,
                                                   const int16_t *f,
                                                   const int16_t *g,
                                                   const int16_t *F,
                                                   int16_t *G)
{
    noxtls_falcon_param_spec_t spec;
    double f_real[NOXTLS_FALCON_MAX_N];
    double rhs_real[NOXTLS_FALCON_MAX_N];
    double g_real[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t f_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t rhs_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g_fft[NOXTLS_FALCON_MAX_N];
    int32_t fG[NOXTLS_FALCON_MAX_N];
    int32_t gF[NOXTLS_FALCON_MAX_N];
    int32_t rounded;
    uint16_t i;
    noxtls_return_t rc;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    falcon_poly_mul_xn1_i32(gF, g, F, spec.n);
    for(i = 0U; i < spec.n; i++) {
        rhs_real[i] = (double)gF[i];
        if(i == 0U) {
            rhs_real[i] += (double)NOXTLS_FALCON_Q;
        }
        f_real[i] = (double)f[i];
    }

    rc = falcon_poly_forward_fft_real(f_real, spec.n, f_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_poly_forward_fft_real(rhs_real, spec.n, rhs_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        double denom = falcon_complex_norm_sq(f_fft[i]);

        if(denom <= 1e-18) {
            return NOXTLS_RETURN_FAILED;
        }
        g_fft[i] = falcon_complex_mul(rhs_fft[i], falcon_complex_conj(f_fft[i]));
        g_fft[i].re /= denom;
        g_fft[i].im /= denom;
    }

    rc = falcon_poly_inverse_fft_real(g_fft, spec.n, g_real);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        rounded = falcon_round_to_i32(g_real[i]);
        if(falcon_abs_double(g_real[i] - (double)rounded) > 1e-6) {
            return NOXTLS_RETURN_FAILED;
        }
        if(rounded < -127 || rounded > 127) {
            return NOXTLS_RETURN_FAILED;
        }
        G[i] = (int16_t)rounded;
    }

    falcon_poly_mul_xn1_i32(fG, f, G, spec.n);
    for(i = 0U; i < spec.n; i++) {
        int32_t expected = (i == 0U) ? (int32_t)NOXTLS_FALCON_Q : 0;
        if((fG[i] - gF[i]) != expected) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Expand a complete Falcon private key into signing-basis form.
 *
 * This validates `(f, g, F)` by recomputing `G`, derives the public polynomial `h`,
 * and fills the conventional basis rows `[[g, -f], [G, -F]]`.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] expanded Output expanded-key record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if the secret key is mathematically invalid.
 */
noxtls_return_t noxtls_falcon_expand_complete_private_key(noxtls_falcon_param_t param,
                                                          const int16_t *f,
                                                          const int16_t *g,
                                                          const int16_t *F,
                                                          noxtls_falcon_expanded_key_t *expanded)
{
    uint16_t i;
    noxtls_return_t rc;

    if(f == NULL || g == NULL || F == NULL || expanded == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &expanded->spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memcpy(expanded->f, f, (size_t)expanded->spec.n * sizeof(*f));
    memcpy(expanded->g, g, (size_t)expanded->spec.n * sizeof(*g));
    memcpy(expanded->F, F, (size_t)expanded->spec.n * sizeof(*F));

    rc = noxtls_falcon_complete_private_key(param, f, g, F, expanded->G);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_compute_public(param, f, g, expanded->h);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < expanded->spec.n; i++) {
        expanded->b00[i] = expanded->g[i];
        expanded->b01[i] = (int16_t)(-expanded->f[i]);
        expanded->b10[i] = expanded->G[i];
        expanded->b11[i] = (int16_t)(-expanded->F[i]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Expand a serialized Falcon secret key into signing-basis form.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] secret_key_len Length of `secret_key` in bytes.
 * @param[out] expanded Output expanded-key record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the serialized secret key is malformed or invalid.
 */
noxtls_return_t noxtls_falcon_expand_private_key(noxtls_falcon_param_t param,
                                                 const uint8_t *secret_key,
                                                 uint32_t secret_key_len,
                                                 noxtls_falcon_expanded_key_t *expanded)
{
    int16_t f[NOXTLS_FALCON_MAX_N];
    int16_t g[NOXTLS_FALCON_MAX_N];
    int16_t F[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    if(secret_key == NULL || expanded == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_decode_private_key(param, secret_key, secret_key_len, f, g, F);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_expand_complete_private_key(param, f, g, F, expanded);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return rc;
}

/**
 * @brief Map a signed Falcon polynomial into the negacyclic complex FFT domain.
 *
 * @param[in] poly Input polynomial coefficients.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] fft Output complex FFT samples.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_poly_forward_fft(const int16_t *poly,
                                               uint16_t n,
                                               noxtls_falcon_complex_t *fft)
{
    double real_poly[NOXTLS_FALCON_MAX_N];
    uint16_t i;

    if(poly == NULL || fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        real_poly[i] = (double)poly[i];
    }
    return falcon_poly_forward_fft_real(real_poly, n, fft);
}

/**
 * @brief Map a negacyclic complex FFT vector back to signed Falcon coefficients.
 *
 * @param[in] fft Input complex FFT samples.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] poly Output rounded signed coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if a reconstructed coefficient falls outside the signed 16-bit range.
 */
noxtls_return_t noxtls_falcon_poly_inverse_fft(const noxtls_falcon_complex_t *fft,
                                               uint16_t n,
                                               int16_t *poly)
{
    double real_poly[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(fft == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = falcon_poly_inverse_fft_real(fft, n, real_poly);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < n; i++) {
        int32_t rounded = falcon_round_to_i32(real_poly[i]);
        if(rounded < -32768 || rounded > 32767) {
            return NOXTLS_RETURN_FAILED;
        }
        poly[i] = (int16_t)rounded;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply two Falcon FFT vectors pointwise.
 *
 * @param[in] a First FFT vector.
 * @param[in] b Second FFT vector.
 * @param[in] n Number of coefficients.
 * @param[out] out Output FFT vector.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_fft_pointwise_mul(const noxtls_falcon_complex_t *a,
                                                const noxtls_falcon_complex_t *b,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *out)
{
    uint16_t i;

    if(a == NULL || b == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        out[i] = falcon_complex_mul(a[i], b[i]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Transform the expanded Falcon lattice basis into the FFT domain.
 *
 * The output rows correspond to the basis `[[g, -f], [G, -F]]`.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] b00_fft FFT of `g`.
 * @param[out] b01_fft FFT of `-f`.
 * @param[out] b10_fft FFT of `G`.
 * @param[out] b11_fft FFT of `-F`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if the embedded degree is unsupported.
 */
noxtls_return_t noxtls_falcon_expand_basis_fft(const noxtls_falcon_expanded_key_t *expanded,
                                               noxtls_falcon_complex_t *b00_fft,
                                               noxtls_falcon_complex_t *b01_fft,
                                               noxtls_falcon_complex_t *b10_fft,
                                               noxtls_falcon_complex_t *b11_fft)
{
    noxtls_return_t rc;

    if(expanded == NULL || b00_fft == NULL || b01_fft == NULL || b10_fft == NULL || b11_fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_poly_forward_fft(expanded->b00, expanded->spec.n, b00_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_poly_forward_fft(expanded->b01, expanded->spec.n, b01_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_poly_forward_fft(expanded->b10, expanded->spec.n, b10_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_falcon_poly_forward_fft(expanded->b11, expanded->spec.n, b11_fft);
}

/**
 * @brief Compute the Falcon basis Gram matrix in the FFT domain.
 *
 * The returned Hermitian matrix is `G = B * adj(B)` for the conventional basis
 * `B = [[g, -f], [G, -F]]`.
 *
 * @param[in] b00_fft FFT of `g`.
 * @param[in] b01_fft FFT of `-f`.
 * @param[in] b10_fft FFT of `G`.
 * @param[in] b11_fft FFT of `-F`.
 * @param[in] n Number of FFT samples.
 * @param[out] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[out] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[out] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[out] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_compute_gram_fft(const noxtls_falcon_complex_t *b00_fft,
                                               const noxtls_falcon_complex_t *b01_fft,
                                               const noxtls_falcon_complex_t *b10_fft,
                                               const noxtls_falcon_complex_t *b11_fft,
                                               uint16_t n,
                                               noxtls_falcon_complex_t *g00_fft,
                                               noxtls_falcon_complex_t *g01_fft,
                                               noxtls_falcon_complex_t *g10_fft,
                                               noxtls_falcon_complex_t *g11_fft)
{
    uint16_t i;

    if(b00_fft == NULL || b01_fft == NULL || b10_fft == NULL || b11_fft == NULL ||
       g00_fft == NULL || g01_fft == NULL || g10_fft == NULL || g11_fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        g00_fft[i] = falcon_complex_add(falcon_complex_mul(b00_fft[i], falcon_complex_conj(b00_fft[i])),
                                        falcon_complex_mul(b01_fft[i], falcon_complex_conj(b01_fft[i])));
        g01_fft[i] = falcon_complex_add(falcon_complex_mul(b00_fft[i], falcon_complex_conj(b10_fft[i])),
                                        falcon_complex_mul(b01_fft[i], falcon_complex_conj(b11_fft[i])));
        g10_fft[i] = falcon_complex_add(falcon_complex_mul(b10_fft[i], falcon_complex_conj(b00_fft[i])),
                                        falcon_complex_mul(b11_fft[i], falcon_complex_conj(b01_fft[i])));
        g11_fft[i] = falcon_complex_add(falcon_complex_mul(b10_fft[i], falcon_complex_conj(b10_fft[i])),
                                        falcon_complex_mul(b11_fft[i], falcon_complex_conj(b11_fft[i])));
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute a pointwise Falcon LDL decomposition of a Hermitian Gram matrix.
 *
 * For each FFT sample, this decomposes the 2x2 Hermitian matrix
 * `[[g00, g01], [g10, g11]]` into `L * D * adj(L)` with
 * `L = [[1, 0], [l10, 1]]` and diagonal `D = diag(d00, d11)`.
 *
 * @param[in] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[in] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[in] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[in] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @param[in] n Number of FFT samples.
 * @param[out] d00_fft FFT samples of the first diagonal entry.
 * @param[out] l10_fft FFT samples of the lower-triangular entry.
 * @param[out] d11_fft FFT samples of the second diagonal entry.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if the Gram matrix is not numerically positive definite.
 */
noxtls_return_t noxtls_falcon_ldl_decompose_fft(const noxtls_falcon_complex_t *g00_fft,
                                                const noxtls_falcon_complex_t *g01_fft,
                                                const noxtls_falcon_complex_t *g10_fft,
                                                const noxtls_falcon_complex_t *g11_fft,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *d00_fft,
                                                noxtls_falcon_complex_t *l10_fft,
                                                noxtls_falcon_complex_t *d11_fft)
{
    uint16_t i;

    if(g00_fft == NULL || g01_fft == NULL || g10_fft == NULL || g11_fft == NULL ||
       d00_fft == NULL || l10_fft == NULL || d11_fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        double d00 = g00_fft[i].re;
        double d11;

        if(d00 <= 0.0 || falcon_abs_double(g00_fft[i].im) > 1e-7 ||
           falcon_abs_double(g11_fft[i].im) > 1e-7 ||
           falcon_abs_double(g10_fft[i].re - g01_fft[i].re) > 1e-7 ||
           falcon_abs_double(g10_fft[i].im + g01_fft[i].im) > 1e-7) {
            return NOXTLS_RETURN_FAILED;
        }

        l10_fft[i].re = g10_fft[i].re / d00;
        l10_fft[i].im = g10_fft[i].im / d00;

        d11 = g11_fft[i].re - (falcon_complex_norm_sq(g10_fft[i]) / d00);
        if(d11 <= 0.0) {
            return NOXTLS_RETURN_FAILED;
        }

        d00_fft[i].re = d00;
        d00_fft[i].im = 0.0;
        d11_fft[i].re = d11;
        d11_fft[i].im = 0.0;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Split a real Falcon FFT polynomial into even and odd half-size FFT polynomials.
 *
 * This applies the algebraic decomposition
 * `f(x) = f0(x^2) + x f1(x^2)` by mapping the input FFT back to real coefficients,
 * separating even and odd coefficients, and transforming the halves back to the FFT domain.
 *
 * @param[in] fft Input FFT polynomial of degree `n`.
 * @param[in] n Input polynomial degree. Must be an even supported power of two.
 * @param[out] fft0 Output FFT polynomial for the even part.
 * @param[out] fft1 Output FFT polynomial for the odd part.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_split_fft_real(const noxtls_falcon_complex_t *fft,
                                             uint16_t n,
                                             noxtls_falcon_complex_t *fft0,
                                             noxtls_falcon_complex_t *fft1)
{
    double coeffs[NOXTLS_FALCON_MAX_N];
    double coeff0[NOXTLS_FALCON_MAX_N / 2U];
    double coeff1[NOXTLS_FALCON_MAX_N / 2U];
    uint16_t i;
    uint16_t half;
    noxtls_return_t rc;

    if(fft == NULL || fft0 == NULL || fft1 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    rc = falcon_poly_inverse_fft_real(fft, n, coeffs);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < half; i++) {
        coeff0[i] = coeffs[(uint16_t)(i << 1)];
        coeff1[i] = coeffs[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_poly_forward_fft_real(coeff0, half, fft0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return falcon_poly_forward_fft_real(coeff1, half, fft1);
}

/**
 * @brief Merge even and odd half-size real Falcon FFT polynomials into a full-size FFT polynomial.
 *
 * This inverts `noxtls_falcon_split_fft_real()` by reconstructing
 * `f(x) = f0(x^2) + x f1(x^2)` in the coefficient domain and transforming it back to the FFT domain.
 *
 * @param[in] fft0 Input FFT polynomial for the even part.
 * @param[in] fft1 Input FFT polynomial for the odd part.
 * @param[in] n Output polynomial degree. Must be an even supported power of two.
 * @param[out] fft Output merged FFT polynomial of degree `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_merge_fft_real(const noxtls_falcon_complex_t *fft0,
                                             const noxtls_falcon_complex_t *fft1,
                                             uint16_t n,
                                             noxtls_falcon_complex_t *fft)
{
    double coeffs[NOXTLS_FALCON_MAX_N];
    double coeff0[NOXTLS_FALCON_MAX_N / 2U];
    double coeff1[NOXTLS_FALCON_MAX_N / 2U];
    uint16_t i;
    uint16_t half;
    noxtls_return_t rc;

    if(fft0 == NULL || fft1 == NULL || fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    rc = falcon_poly_inverse_fft_real(fft0, half, coeff0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_poly_inverse_fft_real(fft1, half, coeff1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < half; i++) {
        coeffs[(uint16_t)(i << 1)] = coeff0[i];
        coeffs[(uint16_t)((i << 1) + 1U)] = coeff1[i];
    }
    return falcon_poly_forward_fft_real(coeffs, n, fft);
}

/**
 * @brief Split a complex Falcon FFT polynomial into even and odd half-size FFT polynomials.
 *
 * This applies `f(x) = f0(x^2) + x f1(x^2)` over complex coefficients by
 * inverting the current FFT representation, separating even and odd coefficients,
 * and transforming each half back into the Falcon FFT domain.
 *
 * @param[in] fft Input FFT polynomial of degree `n`.
 * @param[in] n Input polynomial degree. Must be an even supported power of two.
 * @param[out] fft0 Output FFT polynomial for the even part.
 * @param[out] fft1 Output FFT polynomial for the odd part.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_split_fft_complex(const noxtls_falcon_complex_t *fft,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *fft0,
                                                noxtls_falcon_complex_t *fft1)
{
    noxtls_falcon_complex_t coeffs[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t coeff0[NOXTLS_FALCON_MAX_N / 2U];
    noxtls_falcon_complex_t coeff1[NOXTLS_FALCON_MAX_N / 2U];
    uint16_t i;
    uint16_t half;
    noxtls_return_t rc;

    if(fft == NULL || fft0 == NULL || fft1 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    rc = falcon_poly_inverse_fft_complex(fft, n, coeffs);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < half; i++) {
        coeff0[i] = coeffs[(uint16_t)(i << 1)];
        coeff1[i] = coeffs[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_poly_forward_fft_complex(coeff0, half, fft0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return falcon_poly_forward_fft_complex(coeff1, half, fft1);
}

/**
 * @brief Merge even and odd half-size complex Falcon FFT polynomials into a full-size FFT polynomial.
 *
 * This inverts `falcon_split_fft_complex()` by reconstructing
 * `f(x) = f0(x^2) + x f1(x^2)` over complex coefficients and transforming the
 * resulting polynomial back into the Falcon FFT domain.
 *
 * @param[in] fft0 Input FFT polynomial for the even part.
 * @param[in] fft1 Input FFT polynomial for the odd part.
 * @param[in] n Output polynomial degree. Must be an even supported power of two.
 * @param[out] fft Output merged FFT polynomial of degree `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
static noxtls_return_t falcon_merge_fft_complex(const noxtls_falcon_complex_t *fft0,
                                                const noxtls_falcon_complex_t *fft1,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *fft)
{
    noxtls_falcon_complex_t coeffs[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t coeff0[NOXTLS_FALCON_MAX_N / 2U];
    noxtls_falcon_complex_t coeff1[NOXTLS_FALCON_MAX_N / 2U];
    uint16_t i;
    uint16_t half;
    noxtls_return_t rc;

    if(fft0 == NULL || fft1 == NULL || fft == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    rc = falcon_poly_inverse_fft_complex(fft0, half, coeff0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_poly_inverse_fft_complex(fft1, half, coeff1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < half; i++) {
        coeffs[(uint16_t)(i << 1)] = coeff0[i];
        coeffs[(uint16_t)((i << 1) + 1U)] = coeff1[i];
    }
    return falcon_poly_forward_fft_complex(coeffs, n, fft);
}

/**
 * @brief Return the number of complex FFT entries needed to store a recursive Falcon LDL tree.
 *
 * The storage layout used by Falcon stores `n` samples at each internal node and one sample at each leaf,
 * for a total of `n * (log2(n) + 1)` complex values when `n` is a supported power of two.
 *
 * @param[in] n Polynomial degree.
 * @return Required complex-entry count, or `0` if `n` is unsupported.
 */
uint32_t noxtls_falcon_ldl_tree_complex_len(uint16_t n)
{
    uint32_t logn = 0U;
    uint16_t t;

    if(n == 1U) {
        return 1U;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return 0U;
    }

    for(t = n; t > 1U; t >>= 1) {
        logn++;
    }
    return (uint32_t)n * (logn + 1U);
}

/**
 * @brief Recursively build an unnormalized Falcon LDL subtree from the first row of a self-adjoint matrix.
 *
 * The input matrix is `[[g0, g1], [adj(g1), g0]]`, where `g0` is self-adjoint.
 *
 * @param[in] g0_fft FFT samples of the diagonal entry.
 * @param[in] g1_fft FFT samples of the upper-right entry.
 * @param[in] n Polynomial degree.
 * @param[out] tree Output subtree buffer.
 * @param[in,out] tmp Scratch polynomial buffer of length `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or a numerical/parameter error code.
 */
static noxtls_return_t falcon_build_ldl_tree_selfadjoint(const noxtls_falcon_complex_t *g0_fft,
                                                         const noxtls_falcon_complex_t *g1_fft,
                                                         uint16_t n,
                                                         noxtls_falcon_complex_t *tree,
                                                         noxtls_falcon_complex_t *tmp)
{
    noxtls_falcon_complex_t *g0 = (noxtls_falcon_complex_t *)g0_fft;
    noxtls_falcon_complex_t *g1 = (noxtls_falcon_complex_t *)g1_fft;
    uint16_t half;
    uint16_t i;
    uint32_t child_len;

    if(g0_fft == NULL || g1_fft == NULL || tree == NULL || tmp == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        if(falcon_abs_double(g0_fft[0].im) > 1e-7) {
            return NOXTLS_RETURN_FAILED;
        }
        tree[0].re = g0_fft[0].re;
        tree[0].im = 0.0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    child_len = noxtls_falcon_ldl_tree_complex_len(half);
    for(i = 0U; i < n; i++) {
        double d00 = g0[i].re;

        if(d00 <= 0.0 || falcon_abs_double(g0[i].im) > 1e-7) {
            return NOXTLS_RETURN_FAILED;
        }
        tree[i].re = g1[i].re / d00;
        tree[i].im = -g1[i].im / d00;
        tmp[i].re = d00 - (falcon_complex_norm_sq(g1[i]) / d00);
        tmp[i].im = 0.0;
        if(tmp[i].re <= 0.0) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    if(noxtls_falcon_split_fft_real(g0, n, g1, g1 + half) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_falcon_split_fft_real(tmp, n, g0, g0 + half) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    if(falcon_build_ldl_tree_selfadjoint(g1, g1 + half, half, tree + n, tmp) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return falcon_build_ldl_tree_selfadjoint(g0, g0 + half, half, tree + n + child_len, tmp);
}

/**
 * @brief Build an unnormalized Falcon LDL tree from a Gram matrix in the FFT domain.
 *
 * The tree layout matches the Falcon reference recursion: each internal node stores the
 * `L10` polynomial for the current matrix, followed by the left subtree derived from `D00`
 * and the right subtree derived from `D11`.
 *
 * @param[in] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[in] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[in] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[in] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @param[in] n Polynomial degree.
 * @param[out] tree Output flattened LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the Gram matrix is not numerically valid.
 */
noxtls_return_t noxtls_falcon_build_ldl_tree_fft(const noxtls_falcon_complex_t *g00_fft,
                                                 const noxtls_falcon_complex_t *g01_fft,
                                                 const noxtls_falcon_complex_t *g10_fft,
                                                 const noxtls_falcon_complex_t *g11_fft,
                                                 uint16_t n,
                                                 noxtls_falcon_complex_t *tree,
                                                 uint32_t tree_len)
{
    noxtls_falcon_complex_t tmp0[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t tmp1[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t tmp2[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t *d00_fft;
    noxtls_falcon_complex_t *d11_fft;
    noxtls_falcon_complex_t *tmp;
    uint16_t half;
    uint32_t child_len;

    if(g00_fft == NULL || g01_fft == NULL || g10_fft == NULL || g11_fft == NULL || tree == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        if(tree_len < 1U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        if(falcon_abs_double(g00_fft[0].im) > 1e-7) {
            return NOXTLS_RETURN_FAILED;
        }
        tree[0].re = g00_fft[0].re;
        tree[0].im = 0.0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n) || tree_len < noxtls_falcon_ldl_tree_complex_len(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    d00_fft = tmp0;
    d11_fft = tmp1;
    tmp = tmp2;
    half = (uint16_t)(n >> 1);
    child_len = noxtls_falcon_ldl_tree_complex_len(half);
    memcpy(d00_fft, g00_fft, (size_t)n * sizeof(*d00_fft));
    if(noxtls_falcon_ldl_decompose_fft(g00_fft, g01_fft, g10_fft, g11_fft, n, d00_fft, tree, d11_fft)
       != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_falcon_split_fft_real(d00_fft, n, tmp, tmp + half) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_falcon_split_fft_real(d11_fft, n, d00_fft, d00_fft + half) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(d11_fft, tmp, (size_t)n * sizeof(*tmp));

    if(falcon_build_ldl_tree_selfadjoint(d11_fft, d11_fft + half, half, tree + n, tmp)
       != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return falcon_build_ldl_tree_selfadjoint(d00_fft, d00_fft + half, half, tree + n + child_len, tmp);
}

/**
 * @brief Build an unnormalized Falcon LDL tree directly from an expanded private key.
 *
 * This transforms the expanded basis to the FFT domain, computes its Gram matrix,
 * and then builds the recursive LDL tree needed by the Falcon sampler.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] tree Output flattened LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the expanded basis is numerically invalid.
 */
noxtls_return_t noxtls_falcon_build_expanded_key_ldl_tree(const noxtls_falcon_expanded_key_t *expanded,
                                                          noxtls_falcon_complex_t *tree,
                                                          uint32_t tree_len)
{
    noxtls_falcon_complex_t b00_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b01_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b10_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t b11_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g00_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g01_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g10_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g11_fft[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    if(expanded == NULL || tree == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(tree_len < noxtls_falcon_ldl_tree_complex_len(expanded->spec.n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_falcon_expand_basis_fft(expanded, b00_fft, b01_fft, b10_fft, b11_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_compute_gram_fft(b00_fft, b01_fft, b10_fft, b11_fft, expanded->spec.n,
                                        g00_fft, g01_fft, g10_fft, g11_fft);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_falcon_build_ldl_tree_fft(g00_fft, g01_fft, g10_fft, g11_fft,
                                            expanded->spec.n, tree, tree_len);
}

/**
 * @brief Recursively normalize the leaves of a Falcon LDL tree in place.
 *
 * @param[in,out] tree Flattened LDL tree.
 * @param[in] orig_logn Binary logarithm of the original tree degree.
 * @param[in] logn Binary logarithm of the current subtree degree.
 * @return `NOXTLS_RETURN_SUCCESS` on success or a numerical/parameter error code.
 */
static noxtls_return_t falcon_normalize_ldl_tree_inner(noxtls_falcon_complex_t *tree,
                                                       uint8_t orig_logn,
                                                       uint8_t logn)
{
    uint16_t n = (uint16_t)(1U << logn);
    uint32_t child_len;

    if(tree == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(logn == 0U) {
        if(falcon_abs_double(tree[0].im) > 1e-7 || tree[0].re <= 0.0) {
            return NOXTLS_RETURN_FAILED;
        }
        tree[0].re = sqrt(tree[0].re) * falcon_inv_sigma_by_logn[orig_logn];
        tree[0].im = 0.0;
        return NOXTLS_RETURN_SUCCESS;
    }

    child_len = noxtls_falcon_ldl_tree_complex_len((uint16_t)(n >> 1));
    if(falcon_normalize_ldl_tree_inner(tree + n, orig_logn, (uint8_t)(logn - 1U)) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return falcon_normalize_ldl_tree_inner(tree + n + child_len, orig_logn, (uint8_t)(logn - 1U));
}

/**
 * @brief Normalize a Falcon LDL tree in place for sampler use.
 *
 * Only the leaves are modified. Each leaf value `x` is replaced with the inverse
 * standard deviation term `sqrt(x) / sigma`, using the Falcon parameter-set `sigma`
 * attached to the original top-level degree.
 *
 * @param[in,out] tree Flattened LDL tree to normalize.
 * @param[in] n Original top-level polynomial degree for the tree.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if a leaf is non-real or non-positive.
 */
noxtls_return_t noxtls_falcon_normalize_ldl_tree(noxtls_falcon_complex_t *tree,
                                                 uint16_t n)
{
    uint8_t logn;
    noxtls_return_t rc;

    if(tree == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = falcon_get_logn(n, &logn);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(logn >= (sizeof(falcon_inv_sigma_by_logn) / sizeof(falcon_inv_sigma_by_logn[0]))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return falcon_normalize_ldl_tree_inner(tree, logn, logn);
}

/**
 * @brief Build a normalized Falcon LDL tree directly from an expanded private key.
 *
 * This is the sampler-ready form derived by building the unnormalized tree from the expanded
 * basis Gram matrix and then normalizing its leaves with the Falcon parameter-set sigma.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] tree Output flattened normalized LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the expanded basis is numerically invalid.
 */
noxtls_return_t noxtls_falcon_build_normalized_expanded_key_ldl_tree(const noxtls_falcon_expanded_key_t *expanded,
                                                                     noxtls_falcon_complex_t *tree,
                                                                     uint32_t tree_len)
{
    noxtls_return_t rc;

    if(expanded == NULL || tree == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_falcon_build_expanded_key_ldl_tree(expanded, tree, tree_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_falcon_normalize_ldl_tree(tree, expanded->spec.n);
}

/**
 * @brief Initialize a Falcon sampler context from a seed and parameter set.
 *
 * The context uses SHAKE256 as a deterministic byte stream and records the
 * Falcon `sigma_min` value for the selected degree.
 *
 * @param[out] ctx Sampler context to initialize.
 * @param[in] param Falcon parameter selector.
 * @param[in] seed Seed bytes for the deterministic sampler stream.
 * @param[in] seed_len Length of `seed` in bytes. May be `0`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null context
 *         or invalid seed pointer, or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_sampler_init(noxtls_falcon_sampler_ctx_t *ctx,
                                           noxtls_falcon_param_t param,
                                           const uint8_t *seed,
                                           uint32_t seed_len)
{
    noxtls_falcon_param_spec_t spec;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(seed == NULL && seed_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_init(&ctx->shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(seed_len != 0U) {
        rc = noxtls_shake256_update(&ctx->shake, seed, seed_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    rc = noxtls_shake256_final(&ctx->shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->sigma_min = falcon_sigma_min_by_logn[spec.logn];
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sample Falcon's half-Gaussian base distribution from an explicit 72-bit value.
 *
 * @param[in] v0 Low 24 bits of the sampled 72-bit value.
 * @param[in] v1 Middle 24 bits of the sampled 72-bit value.
 * @param[in] v2 High 24 bits of the sampled 72-bit value.
 * @return Non-negative sampled integer.
 */
int noxtls_falcon_gaussian0_sample_from_u72(uint32_t v0,
                                            uint32_t v1,
                                            uint32_t v2)
{
    static const uint32_t dist[] = {
        10745844u,  3068844u,  3741698u,
         5559083u,  1580863u,  8248194u,
         2260429u, 13669192u,  2736639u,
          708981u,  4421575u, 10046180u,
          169348u,  7122675u,  4136815u,
           30538u, 13063405u,  7650655u,
            4132u, 14505003u,  7826148u,
             417u, 16768101u, 11363290u,
              31U,  8444042u,  8086568u,
               1U, 12844466u,   265321u,
               0U,  1232676u, 13644283u,
               0U,    38047u,  9111839u,
               0U,      870u,  6138264u,
               0U,       14U, 12545723u,
               0U,        0U,  3104126u,
               0U,        0U,    28824u,
               0U,        0U,      198u,
               0U,        0U,        1U
    };
    size_t u;
    int z = 0;

    v0 &= 0xFFFFFFu;
    v1 &= 0xFFFFFFu;
    v2 &= 0xFFFFFFu;
    for(u = 0U; u < (sizeof(dist) / sizeof(dist[0])); u += 3U) {
        uint32_t w0 = dist[u + 2U];
        uint32_t w1 = dist[u + 1U];
        uint32_t w2 = dist[u + 0U];
        uint32_t cc = (v0 - w0) >> 31;
        cc = (v1 - w1 - cc) >> 31;
        cc = (v2 - w2 - cc) >> 31;
        z += (int)cc;
    }
    return z;
}

/**
 * @brief Sample Falcon's half-Gaussian base distribution from the sampler context.
 *
 * @param[in,out] ctx Sampler context.
 * @param[out] sample Output sampled integer.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
noxtls_return_t noxtls_falcon_sampler_gaussian0(noxtls_falcon_sampler_ctx_t *ctx,
                                                int *sample)
{
    uint64_t lo;
    uint8_t hi;
    noxtls_return_t rc;

    if(ctx == NULL || sample == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = falcon_sampler_get_u64(ctx, &lo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_sampler_get_u8(ctx, &hi);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    *sample = noxtls_falcon_gaussian0_sample_from_u72((uint32_t)lo & 0xFFFFFFu,
                                                      (uint32_t)(lo >> 24) & 0xFFFFFFu,
                                                      ((uint32_t)(lo >> 48) | ((uint32_t)hi << 16)) & 0xFFFFFFu);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sample a Bernoulli bit with probability `exp(-x)`.
 *
 * The acceptance scale `ccs` should be `sigma_min / sigma` for the surrounding
 * Falcon rejection sampler.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] x Non-negative exponent argument.
 * @param[in] ccs Falcon acceptance scale.
 * @param[out] bit Output sampled bit, `0` or `1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `ccs` is non-positive.
 */
noxtls_return_t noxtls_falcon_sampler_ber_exp(noxtls_falcon_sampler_ctx_t *ctx,
                                              double x,
                                              double ccs,
                                              int *bit)
{
    double s_real;
    double r;
    uint64_t z;
    uint32_t sw;
    int s;
    int i;
    uint32_t w = 0U;
    noxtls_return_t rc;

    if(ctx == NULL || bit == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ccs <= 0.0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(x < 0.0) {
        x = 0.0;
    }

    s_real = floor(x / log(2.0));
    s = (int)s_real;
    r = x - ((double)s * log(2.0));
    sw = (uint32_t)s;
    if(sw > 63u) {
        sw = 63u;
    }
    s = (int)sw;

    z = ((((uint64_t)(exp(-r) * ccs * 9223372036854775808.0)) << 1) - 1U) >> s;
    i = 64;
    do {
        uint8_t rb;
        rc = falcon_sampler_get_u8(ctx, &rb);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        i -= 8;
        w = (uint32_t)rb - ((uint32_t)(z >> i) & 0xFFu);
    } while(w == 0U && i > 0);

    *bit = (int)(w >> 31);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sample a discrete Gaussian integer centered on `mu` with inverse sigma `isigma`.
 *
 * This is Falcon's one-dimensional sampler used inside the recursive FFT sampler.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] mu Gaussian center.
 * @param[in] isigma Inverse standard deviation `1/sigma`.
 * @param[out] sample Output sampled integer.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `isigma` is non-positive or otherwise
 *         outside Falcon's supported range.
 */
noxtls_return_t noxtls_falcon_sampler_z(noxtls_falcon_sampler_ctx_t *ctx,
                                        double mu,
                                        double isigma,
                                        int32_t *sample)
{
    int s;
    double r;
    double dss;
    double ccs;

    if(ctx == NULL || sample == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(isigma <= 0.0 || isigma > 1.0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    s = (int)floor(mu);
    r = mu - (double)s;
    dss = 0.5 * isigma * isigma;
    ccs = ctx->sigma_min * isigma;
    for(;;) {
        int z0;
        uint8_t rb;
        int b;
        int z;
        double x;
        int keep;
        noxtls_return_t rc;

        rc = noxtls_falcon_sampler_gaussian0(ctx, &z0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_sampler_get_u8(ctx, &rb);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        b = (int)(rb & 1U);
        z = b + ((b << 1) - 1) * z0;
        x = ((double)z - r);
        x = (x * x) * dss;
        x -= ((double)(z0 * z0)) * falcon_inv_2sqrsigma0;
        rc = noxtls_falcon_sampler_ber_exp(ctx, x, ccs, &keep);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(keep != 0) {
            *sample = (int32_t)(s + z);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
}

/**
 * @brief Sample one small Falcon secret polynomial for key generation.
 *
 * Coefficients are drawn from a symmetric discrete distribution derived from
 * Falcon's half-Gaussian sampler and rejected until they fit the serialized
 * `f/g` coefficient range for the selected parameter set.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] param Falcon parameter selector.
 * @param[out] poly Output coefficient array of length `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_sample_short_poly(noxtls_falcon_sampler_ctx_t *ctx,
                                                       noxtls_falcon_param_t param,
                                                       int16_t *poly)
{
    noxtls_falcon_param_spec_t spec;
    int32_t limit;
    uint16_t i;
    noxtls_return_t rc;

    if(ctx == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    limit = falcon_fg_limit_from_spec(&spec);

    for(i = 0U; i < spec.n; i++) {
        for(;;) {
            int sample;
            uint8_t rb;
            int32_t value;

            rc = noxtls_falcon_sampler_gaussian0(ctx, &sample);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(sample > limit) {
                continue;
            }
            rc = falcon_sampler_get_u8(ctx, &rb);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            value = (rb & 1U) != 0U ? -(int32_t)sample : (int32_t)sample;
            poly[i] = (int16_t)value;
            break;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check whether a sampled Falcon `(f, g)` candidate passes keygen preconditions.
 *
 * This enforces the serialized `f/g` coefficient bounds, rejects the impossible
 * mod-2 case where both polynomials are divisible by `x + 1`, and checks that
 * `f` is invertible modulo `q` so a public key `h = g/f mod (x^n + 1, q)` exists.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Candidate secret polynomial `f`.
 * @param[in] g Candidate secret polynomial `g`.
 * @return `NOXTLS_RETURN_SUCCESS` if the candidate passes these prechecks,
 *         `NOXTLS_RETURN_NULL` on a null pointer, `NOXTLS_RETURN_INVALID_PARAM`
 *         on an unsupported parameter or out-of-range coefficient, or
 *         `NOXTLS_RETURN_FAILED` if the candidate is mathematically invalid.
 */
noxtls_return_t noxtls_falcon_keygen_check_fg(noxtls_falcon_param_t param,
                                              const int16_t *f,
                                              const int16_t *g)
{
    noxtls_falcon_param_spec_t spec;
    int32_t limit;
    uint32_t parity_f = 0U;
    uint32_t parity_g = 0U;
    uint16_t h[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(f == NULL || g == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    limit = falcon_fg_limit_from_spec(&spec);

    for(i = 0U; i < spec.n; i++) {
        if(f[i] < -limit || f[i] > limit || g[i] < -limit || g[i] > limit) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        parity_f ^= ((uint32_t)f[i] & 1U);
        parity_g ^= ((uint32_t)g[i] & 1U);
    }
    if((parity_f | parity_g) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_falcon_compute_public(param, f, g, h);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_FAILED;
    }
    return rc;
}

/**
 * @brief Sample Falcon keygen candidates until a prechecked `(f, g)` pair is found.
 *
 * This repeatedly samples short `f` and `g` polynomials and applies
 * @ref noxtls_falcon_keygen_check_fg to reject invalid candidates before the
 * later NTRU-solving stage.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] param Falcon parameter selector.
 * @param[out] f Output prechecked secret polynomial `f`.
 * @param[out] g Output prechecked secret polynomial `g`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported parameter, or
 *         `NOXTLS_RETURN_FAILED` if no acceptable candidate is found in the bounded
 *         number of sampling attempts.
 */
noxtls_return_t noxtls_falcon_keygen_sample_prechecked_fg(noxtls_falcon_sampler_ctx_t *ctx,
                                                          noxtls_falcon_param_t param,
                                                          int16_t *f,
                                                          int16_t *g)
{
    uint32_t attempt;
    noxtls_return_t rc;

    if(ctx == NULL || f == NULL || g == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(attempt = 0U; attempt < NOXTLS_FALCON_KEYGEN_MAX_FG_ATTEMPTS; attempt++) {
        rc = noxtls_falcon_keygen_sample_short_poly(ctx, param, f);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_keygen_sample_short_poly(ctx, param, g);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_keygen_check_fg(param, f, g);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if(rc != NOXTLS_RETURN_FAILED) {
            return rc;
        }
    }

    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Split a signed polynomial into even and odd coefficient halves.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be even.
 * @param[out] even Even-index coefficients packed into length `n/2`.
 * @param[out] odd Odd-index coefficients packed into length `n/2`.
 */
static void falcon_poly_split_i16(const int16_t *src,
                                  uint16_t n,
                                  int16_t *even,
                                  int16_t *odd)
{
    uint16_t i;
    uint16_t half = (uint16_t)(n >> 1);

    for(i = 0U; i < half; i++) {
        even[i] = src[(uint16_t)(i << 1)];
        odd[i] = src[(uint16_t)((i << 1) + 1U)];
    }
}

/**
 * @brief Compute the extended GCD of two signed 32-bit integers.
 *
 * @param[in] a First integer.
 * @param[in] b Second integer.
 * @param[out] x B\'ezout coefficient for `a`.
 * @param[out] y B\'ezout coefficient for `b`.
 * @return Non-negative greatest common divisor.
 */
static int32_t falcon_i32_xgcd(int32_t a,
                               int32_t b,
                               int32_t *x,
                               int32_t *y)
{
    int64_t old_r = a;
    int64_t r = b;
    int64_t old_s = 1;
    int64_t s = 0;
    int64_t old_t = 0;
    int64_t t = 1;

    while(r != 0) {
        int64_t q = old_r / r;
        int64_t tmp;

        tmp = old_r - q * r;
        old_r = r;
        r = tmp;

        tmp = old_s - q * s;
        old_s = s;
        s = tmp;

        tmp = old_t - q * t;
        old_t = t;
        t = tmp;
    }

    if(old_r < 0) {
        old_r = -old_r;
        old_s = -old_s;
        old_t = -old_t;
    }
    if(x != NULL) {
        *x = (int32_t)old_s;
    }
    if(y != NULL) {
        *y = (int32_t)old_t;
    }
    return (int32_t)old_r;
}

static int falcon_checked_mul_i64(int64_t a,
                                  int64_t b,
                                  int64_t *out);

static int falcon_checked_sub_i64(int64_t a,
                                  int64_t b,
                                  int64_t *out);

/**
 * @brief Compute the extended GCD of two signed 64-bit integers with overflow checks.
 *
 * @param[in] a First integer.
 * @param[in] b Second integer.
 * @param[out] x B\'ezout coefficient for `a`.
 * @param[out] y B\'ezout coefficient for `b`.
 * @return `1` on success or `0` if an intermediate step exceeds signed 64 bits.
 */
static int falcon_i64_xgcd(int64_t a,
                           int64_t b,
                           int64_t *x,
                           int64_t *y)
{
    int64_t old_r = a;
    int64_t r = b;
    int64_t old_s = 1;
    int64_t s = 0;
    int64_t old_t = 0;
    int64_t t = 1;

    while(r != 0) {
        int64_t q = old_r / r;
        int64_t prod;
        int64_t tmp;

        if(!falcon_checked_mul_i64(q, r, &prod) ||
           !falcon_checked_sub_i64(old_r, prod, &tmp)) {
            return 0;
        }
        old_r = r;
        r = tmp;

        if(!falcon_checked_mul_i64(q, s, &prod) ||
           !falcon_checked_sub_i64(old_s, prod, &tmp)) {
            return 0;
        }
        old_s = s;
        s = tmp;

        if(!falcon_checked_mul_i64(q, t, &prod) ||
           !falcon_checked_sub_i64(old_t, prod, &tmp)) {
            return 0;
        }
        old_t = t;
        t = tmp;
    }

    if(old_r < 0) {
        old_r = -old_r;
        old_s = -old_s;
        old_t = -old_t;
    }
    if(x != NULL) {
        *x = old_s;
    }
    if(y != NULL) {
        *y = old_t;
    }
    return 1;
}

/**
 * @brief Encode a small unsigned scalar into a fixed-width big-endian magnitude buffer.
 *
 * @param[out] out Destination magnitude buffer.
 * @param[in] len Length of `out` in bytes.
 * @param[in] value Unsigned value to encode.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `value` does not fit in `len` bytes.
 */
static noxtls_return_t falcon_bn_store_small(uint8_t *out,
                                             uint32_t len,
                                             uint32_t value)
{
    uint32_t i;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(out, 0, len);
    for(i = 0U; i < len && value != 0U; i++) {
        out[len - 1U - i] = (uint8_t)(value & 0xFFu);
        value >>= 8;
    }
    return (value == 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief Return the bit value at the specified least-significant-bit index in a big-endian magnitude.
 *
 * @param[in] a Input magnitude bytes.
 * @param[in] len Length of `a` in bytes.
 * @param[in] bit_index Bit index counted from the least-significant bit.
 * @return `0` or `1` for the requested bit.
 */
static uint8_t falcon_bn_get_bit(const uint8_t *a,
                                 uint32_t len,
                                 uint32_t bit_index)
{
    uint32_t byte_from_end;
    uint32_t byte_index;
    uint32_t bit_in_byte;

    if(a == NULL || bit_index >= (len << 3)) {
        return 0U;
    }
    byte_from_end = (uint32_t)(bit_index >> 3);
    byte_index = (uint32_t)(len - 1U - byte_from_end);
    bit_in_byte = bit_index & 7U;
    return (uint8_t)((a[byte_index] >> bit_in_byte) & 1U);
}

/**
 * @brief Set a bit at the specified least-significant-bit index in a big-endian magnitude.
 *
 * @param[in,out] a Magnitude bytes to modify.
 * @param[in] len Length of `a` in bytes.
 * @param[in] bit_index Bit index counted from the least-significant bit.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `bit_index` lies outside the buffer.
 */
static noxtls_return_t falcon_bn_set_bit(uint8_t *a,
                                         uint32_t len,
                                         uint32_t bit_index)
{
    uint32_t byte_from_end;
    uint32_t byte_index;
    uint32_t bit_in_byte;

    if(a == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(bit_index >= (len << 3)) {
        return NOXTLS_RETURN_FAILED;
    }
    byte_from_end = (uint32_t)(bit_index >> 3);
    byte_index = (uint32_t)(len - 1U - byte_from_end);
    bit_in_byte = bit_index & 7U;
    a[byte_index] = (uint8_t)(a[byte_index] | (uint8_t)(1U << bit_in_byte));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return the significant bit length of a non-negative big-endian magnitude.
 *
 * @param[in] a Input magnitude bytes.
 * @param[in] len Length of `a` in bytes.
 * @return Significant bit length, or `0` if the magnitude is zero.
 */
static uint32_t falcon_bn_bit_length(const uint8_t *a,
                                     uint32_t len)
{
    uint32_t i;

    if(a == NULL) {
        return 0U;
    }
    for(i = 0U; i < len; i++) {
        if(a[i] != 0U) {
            uint8_t byte = a[i];
            uint32_t bits = 0U;

            while(byte != 0U) {
                bits++;
                byte >>= 1;
            }
            return (uint32_t)(((len - 1U - i) << 3) + bits);
        }
    }
    return 0U;
}

static uint64_t falcon_abs_i64_to_u64(int64_t x);
static noxtls_return_t falcon_bn_shift_left_bits(uint8_t *dst,
                                                 uint32_t dst_len,
                                                 const uint8_t *src,
                                                 uint32_t src_len,
                                                 uint32_t shift_bits);

/**
 * @brief Convert a signed big-endian magnitude to a finite double approximation.
 *
 * This extracts the value after a shared logical right shift and keeps at most
 * the top 55 significant bits in the returned double. It is intended only for
 * the FFT-based nearest-plane approximation inside Falcon keygen reduction.
 *
 * @param[in] mag Input magnitude bytes.
 * @param[in] negative Non-zero if the signed value is negative.
 * @param[in] len Length of `mag` in bytes.
 * @param[in] shift_bits Logical right shift applied before approximation.
 * @return Approximate signed floating-point value.
 */
static double falcon_bn_signed_to_double_approx(const uint8_t *mag,
                                                uint8_t negative,
                                                uint32_t len,
                                                uint32_t shift_bits)
{
    uint32_t bits;
    uint32_t kept_bits;
    uint32_t j;
    uint64_t mant = 0U;
    double value;

    if(mag == NULL) {
        return 0.0;
    }
    bits = falcon_bn_bit_length(mag, len);
    if(bits <= shift_bits) {
        return 0.0;
    }
    bits -= shift_bits;
    kept_bits = (bits > 55u) ? 55u : bits;
    for(j = 0U; j < kept_bits; j++) {
        uint32_t source_bit = (uint32_t)(shift_bits + bits - 1U - j);

        mant = (mant << 1) | (uint64_t)falcon_bn_get_bit(mag, len, source_bit);
    }
    value = ldexp((double)mant, (int)(bits - kept_bits));
    return (negative != 0U) ? -value : value;
}

/**
 * @brief Encode a signed 16-bit polynomial as fixed-width signed magnitudes.
 *
 * @param[in] src Source polynomial.
 * @param[in] n Polynomial degree.
 * @param[out] mag Output coefficient magnitudes.
 * @param[out] negative Output sign flags.
 * @param[in] coeff_len Width of each encoded coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `coeff_len` is too short.
 */
static noxtls_return_t falcon_bn_poly_from_i16(const int16_t *src,
                                               uint16_t n,
                                               uint8_t *mag,
                                               uint8_t *negative,
                                               uint32_t coeff_len)
{
    uint16_t i;

    if(src == NULL || mag == NULL || negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len < 2U) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(mag, 0, (size_t)n * coeff_len);
    memset(negative, 0, n);
    for(i = 0U; i < n; i++) {
        int32_t value = src[i];
        uint32_t base = (uint32_t)i * coeff_len;

        if(value < 0) {
            negative[i] = 1U;
            value = -value;
        }
        mag[base + coeff_len - 2U] = (uint8_t)(((uint32_t)value >> 8) & 0xFFu);
        mag[base + coeff_len - 1U] = (uint8_t)((uint32_t)value & 0xFFu);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encode a signed 64-bit polynomial as fixed-width signed magnitudes.
 *
 * @param[in] src Source polynomial.
 * @param[in] n Polynomial degree.
 * @param[out] mag Output coefficient magnitudes.
 * @param[out] negative Output sign flags.
 * @param[in] coeff_len Width of each encoded coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `coeff_len` is too short.
 */
static noxtls_return_t falcon_bn_poly_from_i64(const int64_t *src,
                                               uint16_t n,
                                               uint8_t *mag,
                                               uint8_t *negative,
                                               uint32_t coeff_len)
{
    uint16_t i;

    if(src == NULL || mag == NULL || negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len < 8U) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(mag, 0, (size_t)n * coeff_len);
    memset(negative, 0, n);
    for(i = 0U; i < n; i++) {
        uint64_t value;
        uint32_t base = (uint32_t)i * coeff_len;
        uint32_t j;

        if(src[i] < 0) {
            negative[i] = 1U;
            value = falcon_abs_i64_to_u64(src[i]);
        } else {
            value = (uint64_t)src[i];
        }
        for(j = 0U; j < 8U; j++) {
            mag[base + coeff_len - 1U - j] = (uint8_t)(value & 0xFFu);
            value >>= 8;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encode a signed 64-bit polynomial as left-shifted fixed-width signed magnitudes.
 *
 * @param[in] src Source polynomial.
 * @param[in] n Polynomial degree.
 * @param[out] mag Output coefficient magnitudes.
 * @param[out] negative Output sign flags.
 * @param[in] coeff_len Width of each encoded coefficient magnitude.
 * @param[in] shift_bits Logical left shift applied to every encoded coefficient.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if any shifted coefficient does not fit.
 */
static noxtls_return_t falcon_bn_poly_from_i64_shifted(const int64_t *src,
                                                       uint16_t n,
                                                       uint8_t *mag,
                                                       uint8_t *negative,
                                                       uint32_t coeff_len,
                                                       uint32_t shift_bits)
{
    uint16_t i;
    uint32_t byte_shift;
    uint32_t bit_shift;

    if(src == NULL || mag == NULL || negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len < 8U) {
        return NOXTLS_RETURN_FAILED;
    }

    byte_shift = (uint32_t)(shift_bits >> 3);
    bit_shift = shift_bits & 7U;
    memset(mag, 0, (size_t)n * coeff_len);
    memset(negative, 0, n);
    for(i = 0U; i < n; i++) {
        uint8_t *dst = mag + ((uint32_t)i * coeff_len);
        uint64_t value;
        uint32_t j;

        if(src[i] < 0) {
            negative[i] = 1U;
            value = falcon_abs_i64_to_u64(src[i]);
        } else {
            value = (uint64_t)src[i];
        }
        if(value == 0U) {
            continue;
        }
        if(byte_shift >= coeff_len) {
            return NOXTLS_RETURN_FAILED;
        }
        for(j = 0U; j < 8U && value != 0U; j++) {
            uint8_t byte = (uint8_t)(value & 0xFFu);
            int64_t dst_index = (int64_t)coeff_len - 1ll - (int64_t)byte_shift - (int64_t)j;

            value >>= 8;
            if(dst_index < 0ll) {
                if(byte != 0U) {
                    return NOXTLS_RETURN_FAILED;
                }
                continue;
            }
            dst[(uint32_t)dst_index] = (uint8_t)(dst[(uint32_t)dst_index] | (uint8_t)(byte << bit_shift));
            if(bit_shift != 0U) {
                uint8_t carry = (uint8_t)(byte >> (8U - bit_shift));

                if(carry != 0U) {
                    if(dst_index == 0ll) {
                        return NOXTLS_RETURN_FAILED;
                    }
                    dst[(uint32_t)(dst_index - 1ll)] =
                        (uint8_t)(dst[(uint32_t)(dst_index - 1ll)] | carry);
                }
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return the maximum absolute coefficient magnitude from two signed-magnitude polynomials.
 *
 * @param[in] A_mag First polynomial magnitudes.
 * @param[in] B_mag Second polynomial magnitudes.
 * @param[in] n Polynomial degree.
 * @param[in] coeff_len Width of each coefficient magnitude.
 * @param[out] out_mag Output buffer for the maximum magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
static noxtls_return_t falcon_bn_poly_pair_maxabs_copy(const uint8_t *A_mag,
                                                       const uint8_t *B_mag,
                                                       uint16_t n,
                                                       uint32_t coeff_len,
                                                       uint8_t *out_mag)
{
    const uint8_t *max_ptr;
    uint16_t i;

    if(A_mag == NULL || B_mag == NULL || out_mag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    max_ptr = A_mag;
    if(noxtls_bn_cmp(B_mag, max_ptr, coeff_len) > 0) {
        max_ptr = B_mag;
    }
    for(i = 1U; i < n; i++) {
        const uint8_t *a_ptr = A_mag + ((uint32_t)i * coeff_len);
        const uint8_t *b_ptr = B_mag + ((uint32_t)i * coeff_len);

        if(noxtls_bn_cmp(a_ptr, max_ptr, coeff_len) > 0) {
            max_ptr = a_ptr;
        }
        if(noxtls_bn_cmp(b_ptr, max_ptr, coeff_len) > 0) {
            max_ptr = b_ptr;
        }
    }
    return noxtls_bn_copy(out_mag, max_ptr, coeff_len);
}

/**
 * @brief Return a coarse total absolute-size score for two signed-magnitude polynomials.
 *
 * The score is the sum of the significant bit lengths of all coefficient magnitudes.
 * It is used only as a secondary tie-breaker when the maximum coefficient magnitude
 * does not change during Falcon keygen reduction.
 *
 * @param[in] A_mag First polynomial magnitudes.
 * @param[in] B_mag Second polynomial magnitudes.
 * @param[in] n Polynomial degree.
 * @param[in] coeff_len Width of each coefficient magnitude.
 * @return Sum of significant bit lengths.
 */
static uint64_t falcon_bn_poly_pair_abs_score(const uint8_t *A_mag,
                                              const uint8_t *B_mag,
                                              uint16_t n,
                                              uint32_t coeff_len)
{
    uint64_t score = 0U;
    uint16_t i;

    if(A_mag == NULL || B_mag == NULL) {
        return 0U;
    }
    for(i = 0U; i < n; i++) {
        score += (uint64_t)falcon_bn_bit_length(A_mag + ((uint32_t)i * coeff_len), coeff_len);
        score += (uint64_t)falcon_bn_bit_length(B_mag + ((uint32_t)i * coeff_len), coeff_len);
    }
    return score;
}

/**
 * @brief Convert a reduced signed-magnitude polynomial to signed 32-bit coefficients.
 *
 * @param[in] mag Input coefficient magnitudes.
 * @param[in] negative Input sign flags.
 * @param[in] n Polynomial degree.
 * @param[in] coeff_len Width of each coefficient magnitude.
 * @param[out] out Output signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if any coefficient does not fit in signed 32 bits.
 */
static noxtls_return_t falcon_bn_poly_to_i32_checked(const uint8_t *mag,
                                                     const uint8_t *negative,
                                                     uint16_t n,
                                                     uint32_t coeff_len,
                                                     int32_t *out)
{
    uint16_t i;

    if(mag == NULL || negative == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len < 4U) {
        return NOXTLS_RETURN_FAILED;
    }

    for(i = 0U; i < n; i++) {
        const uint8_t *coeff = mag + ((uint32_t)i * coeff_len);
        uint32_t j;
        uint32_t value;

        for(j = 0U; j < (coeff_len - 4U); j++) {
            if(coeff[j] != 0U) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        value = ((uint32_t)coeff[coeff_len - 4U] << 24) |
                ((uint32_t)coeff[coeff_len - 3U] << 16) |
                ((uint32_t)coeff[coeff_len - 2U] << 8) |
                (uint32_t)coeff[coeff_len - 1U];
        if(negative[i] != 0U) {
            if(value > 0x80000000u) {
                return NOXTLS_RETURN_FAILED;
            }
            out[i] = (value == 0x80000000u) ? INT32_MIN : -(int32_t)value;
        } else {
            if(value > 0x7FFFFFFFu) {
                return NOXTLS_RETURN_FAILED;
            }
            out[i] = (int32_t)value;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Shift a big-endian magnitude left by an arbitrary number of bits.
 *
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Length of `dst` in bytes.
 * @param[in] src Source magnitude.
 * @param[in] src_len Length of `src` in bytes.
 * @param[in] shift Number of bits to shift left.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
static noxtls_return_t falcon_bn_shift_left_bits(uint8_t *dst,
                                                 uint32_t dst_len,
                                                 const uint8_t *src,
                                                 uint32_t src_len,
                                                 uint32_t shift)
{
    uint32_t src_bits;
    uint32_t i;

    if(dst == NULL || src == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(dst, 0, dst_len);
    src_bits = falcon_bn_bit_length(src, src_len);
    for(i = 0U; i < src_bits; i++) {
        if(falcon_bn_get_bit(src, src_len, i) != 0U) {
            uint32_t dst_bit = i + shift;

            if(dst_bit < (dst_len << 3)) {
                falcon_bn_set_bit(dst, dst_len, dst_bit);
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Divide a non-negative big-endian magnitude exactly by another positive magnitude.
 *
 * @param[out] quotient Output quotient magnitude.
 * @param[in] quotient_len Length of `quotient` in bytes.
 * @param[in] numerator Numerator magnitude.
 * @param[in] numerator_len Length of `numerator` in bytes.
 * @param[in] denominator Positive denominator magnitude.
 * @param[in] denominator_len Length of `denominator` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the division is inexact or the quotient
 *         does not fit in `quotient_len` bytes.
 */
static noxtls_return_t falcon_bn_exact_div_positive(uint8_t *quotient,
                                                    uint32_t quotient_len,
                                                    const uint8_t *numerator,
                                                    uint32_t numerator_len,
                                                    const uint8_t *denominator,
                                                    uint32_t denominator_len)
{
    uint8_t *remainder;
    uint8_t *shifted;
    uint8_t *qwide;
    uint32_t num_bits;
    uint32_t den_bits;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int64_t shift;

    if(quotient == NULL || numerator == NULL || denominator == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(denominator_len == 0U || noxtls_bn_is_zero(denominator, denominator_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    remainder = (uint8_t*)noxtls_calloc(numerator_len, 1U);
    shifted = (uint8_t*)noxtls_calloc(numerator_len, 1U);
    qwide = (uint8_t*)noxtls_calloc(numerator_len, 1U);
    if(remainder == NULL || shifted == NULL || qwide == NULL) {
        goto cleanup;
    }

    noxtls_bn_copy(remainder, numerator, numerator_len);
    num_bits = falcon_bn_bit_length(numerator, numerator_len);
    den_bits = falcon_bn_bit_length(denominator, denominator_len);
    if(num_bits == 0U) {
        noxtls_bn_zero(quotient, quotient_len);
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }
    if(den_bits == 0U || num_bits < den_bits) {
        goto cleanup;
    }

    for(shift = (int64_t)(num_bits - den_bits); shift >= 0; shift--) {
        falcon_bn_shift_left_bits(shifted, numerator_len, denominator, denominator_len, (uint32_t)shift);
        if(noxtls_bn_cmp(remainder, shifted, numerator_len) >= 0) {
            noxtls_bn_sub(remainder, remainder, shifted, numerator_len);
            falcon_bn_set_bit(qwide, numerator_len, (uint32_t)shift);
        }
    }
    if(!noxtls_bn_is_zero(remainder, numerator_len)) {
        goto cleanup;
    }
    if(quotient_len > numerator_len) {
        goto cleanup;
    }
    if(!noxtls_bn_is_zero(qwide, numerator_len - quotient_len)) {
        goto cleanup;
    }
    noxtls_bn_copy(quotient, qwide + (numerator_len - quotient_len), quotient_len);
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(remainder != NULL) {
        noxtls_free(remainder);
    }
    if(shifted != NULL) {
        noxtls_free(shifted);
    }
    if(qwide != NULL) {
        noxtls_free(qwide);
    }
    return rc;
}

/**
 * @brief Add two non-negative big-endian magnitudes into a wider destination buffer.
 *
 * The operands are right-aligned in the `out_len`-byte accumulation space.
 *
 * @param[out] out Output sum magnitude.
 * @param[in] out_len Length of `out` in bytes.
 * @param[in] a First addend magnitude.
 * @param[in] a_len Length of `a` in bytes.
 * @param[in] b Second addend magnitude.
 * @param[in] b_len Length of `b` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the exact sum does not fit in `out_len` bytes.
 */
static noxtls_return_t falcon_bn_add_wide(uint8_t *out,
                                          uint32_t out_len,
                                          const uint8_t *a,
                                          uint32_t a_len,
                                          const uint8_t *b,
                                          uint32_t b_len)
{
    int64_t out_idx;
    int64_t a_idx;
    int64_t b_idx;
    uint16_t carry = 0U;

    if(out == NULL || a == NULL || b == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(out, 0, out_len);

    out_idx = (int64_t)out_len - 1;
    a_idx = (int64_t)a_len - 1;
    b_idx = (int64_t)b_len - 1;
    while(out_idx >= 0) {
        uint16_t sum = carry;

        if(a_idx >= 0) {
            sum = (uint16_t)(sum + a[a_idx]);
            a_idx--;
        }
        if(b_idx >= 0) {
            sum = (uint16_t)(sum + b[b_idx]);
            b_idx--;
        }
        out[out_idx] = (uint8_t)(sum & 0xFFu);
        carry = (uint16_t)(sum >> 8);
        out_idx--;
    }
    if(carry != 0U || a_idx >= 0 || b_idx >= 0) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply two non-negative big-endian magnitudes into a right-aligned wider buffer.
 *
 * @param[out] out Output product magnitude.
 * @param[in] out_len Length of `out` in bytes.
 * @param[in] a First factor magnitude.
 * @param[in] a_len Length of `a` in bytes.
 * @param[in] b Second factor magnitude.
 * @param[in] b_len Length of `b` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the exact product does not fit in `out_len` bytes.
 */
static noxtls_return_t falcon_bn_mul_to_len(uint8_t *out,
                                            uint32_t out_len,
                                            const uint8_t *a,
                                            uint32_t a_len,
                                            const uint8_t *b,
                                            uint32_t b_len)
{
    uint8_t *prod;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(out == NULL || a == NULL || b == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    prod = (uint8_t*)noxtls_calloc(a_len + b_len, 1U);
    if(prod == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_bn_mul(prod, a, a_len, b, b_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    if(out_len < (a_len + b_len)) {
        goto cleanup;
    }
    memset(out, 0, out_len);
    noxtls_bn_copy(out + (out_len - (a_len + b_len)), prod, a_len + b_len);
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(prod != NULL) {
        noxtls_free(prod);
    }
    return rc;
}

/**
 * @brief Multiply signed big-endian magnitudes and emit a signed-magnitude result.
 *
 * @param[in] a_mag First factor magnitude.
 * @param[in] a_negative Non-zero if the first factor is negative.
 * @param[in] a_len Length of `a_mag` in bytes.
 * @param[in] b_mag Second factor magnitude.
 * @param[in] b_negative Non-zero if the second factor is negative.
 * @param[in] b_len Length of `b_mag` in bytes.
 * @param[in] extra_negative Additional sign flip to apply after multiplication.
 * @param[out] out_mag Output product magnitude.
 * @param[out] out_negative Output sign flag.
 * @param[in] out_len Length of `out_mag` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the exact product does not fit in `out_len` bytes.
 */
static noxtls_return_t falcon_bn_signed_mul_to_len(const uint8_t *a_mag,
                                                   uint8_t a_negative,
                                                   uint32_t a_len,
                                                   const uint8_t *b_mag,
                                                   uint8_t b_negative,
                                                   uint32_t b_len,
                                                   uint8_t extra_negative,
                                                   uint8_t *out_mag,
                                                   uint8_t *out_negative,
                                                   uint32_t out_len)
{
    noxtls_return_t rc;
    uint8_t neg;

    if(a_mag == NULL || b_mag == NULL || out_mag == NULL || out_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = falcon_bn_mul_to_len(out_mag, out_len, a_mag, a_len, b_mag, b_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    neg = (uint8_t)(((a_negative != 0U) ^ (b_negative != 0U) ^ (extra_negative != 0U)) != 0U);
    *out_negative = (uint8_t)(neg != 0U && !noxtls_bn_is_zero(out_mag, out_len));
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t falcon_bn_add_wide(uint8_t *out,
                                          uint32_t out_len,
                                          const uint8_t *a,
                                          uint32_t a_len,
                                          const uint8_t *b,
                                          uint32_t b_len);

static noxtls_return_t falcon_bn_poly_mul_xn1_signed_to_len(const uint8_t *a_mag,
                                                            const uint8_t *a_negative,
                                                            uint32_t a_coeff_len,
                                                            const uint8_t *b_mag,
                                                            const uint8_t *b_negative,
                                                            uint32_t b_coeff_len,
                                                            uint16_t n,
                                                            uint8_t *out_mag,
                                                            uint8_t *out_negative,
                                                            uint32_t out_coeff_len);

/**
 * @brief Add two signed big-endian magnitudes into a wider signed-magnitude destination.
 *
 * @param[in] a_mag First addend magnitude.
 * @param[in] a_negative Non-zero if the first addend is negative.
 * @param[in] a_len Length of `a_mag` in bytes.
 * @param[in] b_mag Second addend magnitude.
 * @param[in] b_negative Non-zero if the second addend is negative.
 * @param[in] b_len Length of `b_mag` in bytes.
 * @param[out] out_mag Output sum magnitude.
 * @param[out] out_negative Output sign flag.
 * @param[in] out_len Length of `out_mag` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the aligned operands do not fit in `out_len` bytes.
 */
static noxtls_return_t falcon_bn_signed_add_to_len(const uint8_t *a_mag,
                                                   uint8_t a_negative,
                                                   uint32_t a_len,
                                                   const uint8_t *b_mag,
                                                   uint8_t b_negative,
                                                   uint32_t b_len,
                                                   uint8_t *out_mag,
                                                   uint8_t *out_negative,
                                                   uint32_t out_len)
{
    uint8_t *awide;
    uint8_t *bwide;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int cmp;

    if(a_mag == NULL || b_mag == NULL || out_mag == NULL || out_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(out_len < a_len || out_len < b_len) {
        return NOXTLS_RETURN_FAILED;
    }

    awide = (uint8_t*)noxtls_calloc(out_len, 1U);
    bwide = (uint8_t*)noxtls_calloc(out_len, 1U);
    if(awide == NULL || bwide == NULL) {
        goto cleanup;
    }

    rc = noxtls_bn_copy(awide + (out_len - a_len), a_mag, a_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_copy(bwide + (out_len - b_len), b_mag, b_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    if((a_negative != 0U) == (b_negative != 0U)) {
        rc = falcon_bn_add_wide(out_mag, out_len, awide, out_len, bwide, out_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        *out_negative = (uint8_t)((a_negative != 0U) && !noxtls_bn_is_zero(out_mag, out_len));
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }

    cmp = noxtls_bn_cmp(awide, bwide, out_len);
    if(cmp == 0) {
        noxtls_bn_zero(out_mag, out_len);
        *out_negative = 0U;
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }
    if(cmp > 0) {
        rc = noxtls_bn_copy(out_mag, awide, out_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        noxtls_bn_sub(out_mag, out_mag, bwide, out_len);
        *out_negative = (uint8_t)((a_negative != 0U) && !noxtls_bn_is_zero(out_mag, out_len));
    } else {
        rc = noxtls_bn_copy(out_mag, bwide, out_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        noxtls_bn_sub(out_mag, out_mag, awide, out_len);
        *out_negative = (uint8_t)((b_negative != 0U) && !noxtls_bn_is_zero(out_mag, out_len));
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(awide != NULL) {
        noxtls_free(awide);
    }
    if(bwide != NULL) {
        noxtls_free(bwide);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-2 signed polynomial on big-endian magnitudes.
 *
 * For `f(x) = a0 + a1*x` in `Z[x]/(x^2 + 1)`, the field norm is `a0^2 + a1^2`.
 *
 * @param[in] a0_mag Magnitude of coefficient `a0`.
 * @param[in] a1_mag Magnitude of coefficient `a1`.
 * @param[in] len Byte length of each input magnitude.
 * @param[out] norm_mag Output norm magnitude.
 * @param[in] norm_len Length of `norm_mag` in bytes. Must be at least `2*len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the output buffer is too short.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n2(const uint8_t *a0_mag,
                                                      const uint8_t *a1_mag,
                                                      uint32_t len,
                                                      uint8_t *norm_mag,
                                                      uint32_t norm_len)
{
    uint8_t *sq0;
    uint8_t *sq1;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a0_mag == NULL || a1_mag == NULL || norm_mag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(norm_len < ((len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    sq0 = (uint8_t*)noxtls_calloc(len << 1, 1U);
    sq1 = (uint8_t*)noxtls_calloc(len << 1, 1U);
    if(sq0 == NULL || sq1 == NULL) {
        goto cleanup;
    }

    rc = noxtls_bn_mul(sq0, a0_mag, len, a0_mag, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(sq1, a1_mag, len, a1_mag, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_add_wide(norm_mag, norm_len, sq0, len << 1, sq1, len << 1);

cleanup:
    if(sq0 != NULL) {
        noxtls_free(sq0);
    }
    if(sq1 != NULL) {
        noxtls_free(sq1);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-4 signed polynomial on big-endian coefficients.
 *
 * For `f(x) = a0 + a1*x + a2*x^2 + a3*x^3`, this returns the degree-2 signed
 * norm polynomial `N(f)` such that `N(f)(x^2) = f(x) * f(-x) mod (x^4 + 1)`.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || a2 || a3]`.
 * @param[in] a_negative Input sign flags for the four coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1]`.
 * @param[out] norm_negative Output sign flags for `n0` and `n1`.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n4(const uint8_t *a_mag,
                                                      const uint8_t *a_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *norm_mag,
                                                      uint8_t *norm_negative,
                                                      uint32_t norm_len)
{
    uint32_t prod_len;
    const uint8_t *a0_mag;
    const uint8_t *a1_mag;
    const uint8_t *a2_mag;
    const uint8_t *a3_mag;
    uint8_t *sq0;
    uint8_t *sq1;
    uint8_t *sq2;
    uint8_t *sq3;
    uint8_t *p02;
    uint8_t *p13;
    uint8_t *term0;
    uint8_t *term1;
    uint8_t term0_neg = 0U;
    uint8_t term1_neg = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    prod_len = coeff_len << 1;
    a0_mag = a_mag;
    a1_mag = a_mag + coeff_len;
    a2_mag = a_mag + (coeff_len << 1);
    a3_mag = a_mag + (coeff_len * 3U);
    sq0 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    sq1 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    sq2 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    sq3 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    p02 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    p13 = (uint8_t*)noxtls_calloc(prod_len, 1U);
    term0 = (uint8_t*)noxtls_calloc(norm_len, 1U);
    term1 = (uint8_t*)noxtls_calloc(norm_len, 1U);
    if(sq0 == NULL || sq1 == NULL || sq2 == NULL || sq3 == NULL ||
       p02 == NULL || p13 == NULL || term0 == NULL || term1 == NULL) {
        goto cleanup;
    }

    rc = noxtls_bn_mul(sq0, a0_mag, coeff_len, a0_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(sq1, a1_mag, coeff_len, a1_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(sq2, a2_mag, coeff_len, a2_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(sq3, a3_mag, coeff_len, a3_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(p02, a0_mag, coeff_len, a2_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mul(p13, a1_mag, coeff_len, a3_mag, coeff_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(sq0, 0U, prod_len, sq2, 1U, prod_len, term0, &term0_neg, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_shift_left_bits(term1, norm_len, p13, prod_len, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    term1_neg = (uint8_t)((a_negative[1] != 0U) ^ (a_negative[3] != 0U));
    rc = falcon_bn_signed_add_to_len(term0,
                                     term0_neg,
                                     norm_len,
                                     term1,
                                     term1_neg,
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_shift_left_bits(term0, norm_len, p02, prod_len, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    term0_neg = (uint8_t)((a_negative[0] != 0U) ^ (a_negative[2] != 0U));
    rc = falcon_bn_signed_add_to_len(sq3, 0U, prod_len, sq1, 1U, prod_len, term1, &term1_neg, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_signed_add_to_len(term0,
                                     term0_neg,
                                     norm_len,
                                     term1,
                                     term1_neg,
                                     norm_len,
                                     norm_mag + norm_len,
                                     &norm_negative[1],
                                     norm_len);

cleanup:
    if(sq0 != NULL) {
        noxtls_free(sq0);
    }
    if(sq1 != NULL) {
        noxtls_free(sq1);
    }
    if(sq2 != NULL) {
        noxtls_free(sq2);
    }
    if(sq3 != NULL) {
        noxtls_free(sq3);
    }
    if(p02 != NULL) {
        noxtls_free(p02);
    }
    if(p13 != NULL) {
        noxtls_free(p13);
    }
    if(term0 != NULL) {
        noxtls_free(term0);
    }
    if(term1 != NULL) {
        noxtls_free(term1);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-8 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^4 + 1)`, then recombines them into the degree-4 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a7]`.
 * @param[in] a_negative Input sign flags for the eight coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || n2 || n3]`.
 * @param[out] norm_negative Output sign flags for the four norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n8(const uint8_t *a_mag,
                                                      const uint8_t *a_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *norm_mag,
                                                      uint8_t *norm_negative,
                                                      uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[4];
    uint8_t odd_negative[4];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[4];
    uint8_t oo_negative[4];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 4U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 4U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 4U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 4U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 4U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              4U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              4U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 3U),
                                     oo_negative[3],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 4U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-16 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^8 + 1)`, then recombines them into the degree-8 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a15]`.
 * @param[in] a_negative Input sign flags for the sixteen coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n7]`.
 * @param[out] norm_negative Output sign flags for the eight norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n16(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[8];
    uint8_t odd_negative[8];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[8];
    uint8_t oo_negative[8];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 8U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 8U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 8U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 8U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 8U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              8U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              8U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 7U),
                                     oo_negative[7],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 8U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-32 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^16 + 1)`, then recombines them into the degree-16 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a31]`.
 * @param[in] a_negative Input sign flags for the thirty-two coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n15]`.
 * @param[out] norm_negative Output sign flags for the sixteen norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n32(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[16];
    uint8_t odd_negative[16];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[16];
    uint8_t oo_negative[16];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 16U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 16U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 16U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 16U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 16U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              16U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              16U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 15U),
                                     oo_negative[15],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 16U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-64 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^32 + 1)`, then recombines them into the degree-32 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a63]`.
 * @param[in] a_negative Input sign flags for the sixty-four coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n31]`.
 * @param[out] norm_negative Output sign flags for the thirty-two norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n64(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[32];
    uint8_t odd_negative[32];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[32];
    uint8_t oo_negative[32];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 32U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 32U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 32U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 32U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 32U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              32U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              32U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 31U),
                                     oo_negative[31],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 32U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-128 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^64 + 1)`, then recombines them into the degree-64 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a127]`.
 * @param[in] a_negative Input sign flags for the one hundred twenty-eight coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n63]`.
 * @param[out] norm_negative Output sign flags for the sixty-four norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n128(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[64];
    uint8_t odd_negative[64];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[64];
    uint8_t oo_negative[64];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 64U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 64U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 64U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 64U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 64U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              64U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              64U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 63u),
                                     oo_negative[63],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 64U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-256 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^128 + 1)`, then recombines them into the degree-128 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a255]`.
 * @param[in] a_negative Input sign flags for the two hundred fifty-six coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n127]`.
 * @param[out] norm_negative Output sign flags for the one hundred twenty-eight norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n256(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[128];
    uint8_t odd_negative[128];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[128];
    uint8_t oo_negative[128];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 128U, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 128U, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 128U, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 128U, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 128U; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              128U,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              128U,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 127u),
                                     oo_negative[127],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 128U; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Compute the Falcon keygen field norm for a degree-512 signed polynomial on big-endian coefficients.
 *
 * This splits the polynomial into even and odd halves, squares each half in
 * `Z[x]/(x^256 + 1)`, then recombines them into the degree-256 norm polynomial.
 *
 * @param[in] a_mag Input coefficient magnitudes `[a0 || a1 || ... || a511]`.
 * @param[in] a_negative Input sign flags for the five hundred twelve coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes `[n0 || n1 || ... || n255]`.
 * @param[out] norm_negative Output sign flags for the two hundred fifty-six norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an exact intermediate does not fit.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n512(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len)
{
    uint8_t *even_mag;
    uint8_t *odd_mag;
    uint8_t even_negative[256];
    uint8_t odd_negative[256];
    uint8_t *ee_mag;
    uint8_t *oo_mag;
    uint8_t ee_negative[256];
    uint8_t oo_negative[256];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || norm_mag == NULL || norm_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || norm_len < ((coeff_len << 1) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    even_mag = (uint8_t*)noxtls_calloc(coeff_len * 256u, 1U);
    odd_mag = (uint8_t*)noxtls_calloc(coeff_len * 256u, 1U);
    ee_mag = (uint8_t*)noxtls_calloc(norm_len * 256u, 1U);
    oo_mag = (uint8_t*)noxtls_calloc(norm_len * 256u, 1U);
    if(even_mag == NULL || odd_mag == NULL || ee_mag == NULL || oo_mag == NULL) {
        goto cleanup;
    }

    memset(even_negative, 0, sizeof(even_negative));
    memset(odd_negative, 0, sizeof(odd_negative));
    memset(ee_negative, 0, sizeof(ee_negative));
    memset(oo_negative, 0, sizeof(oo_negative));

    for(i = 0U; i < 256u; i++) {
        rc = noxtls_bn_copy(even_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(i << 1) * coeff_len),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(odd_mag + ((uint32_t)i * coeff_len),
                            a_mag + ((uint32_t)(((i << 1) + 1U) * coeff_len)),
                            coeff_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        even_negative[i] = a_negative[(uint16_t)(i << 1)];
        odd_negative[i] = a_negative[(uint16_t)((i << 1) + 1U)];
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(even_mag,
                                              even_negative,
                                              coeff_len,
                                              even_mag,
                                              even_negative,
                                              coeff_len,
                                              256u,
                                              ee_mag,
                                              ee_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              odd_mag,
                                              odd_negative,
                                              coeff_len,
                                              256u,
                                              oo_mag,
                                              oo_negative,
                                              norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_add_to_len(ee_mag,
                                     ee_negative[0],
                                     norm_len,
                                     oo_mag + (norm_len * 255u),
                                     oo_negative[255],
                                     norm_len,
                                     norm_mag,
                                     &norm_negative[0],
                                     norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    for(i = 1U; i < 256u; i++) {
        rc = falcon_bn_signed_add_to_len(ee_mag + ((uint32_t)i * norm_len),
                                         ee_negative[i],
                                         norm_len,
                                         oo_mag + ((uint32_t)(i - 1U) * norm_len),
                                         (uint8_t)(oo_negative[i - 1U] == 0U),
                                         norm_len,
                                         norm_mag + ((uint32_t)i * norm_len),
                                         &norm_negative[i],
                                         norm_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(even_mag != NULL) {
        noxtls_free(even_mag);
    }
    if(odd_mag != NULL) {
        noxtls_free(odd_mag);
    }
    if(ee_mag != NULL) {
        noxtls_free(ee_mag);
    }
    if(oo_mag != NULL) {
        noxtls_free(oo_mag);
    }
    return rc;
}

/**
 * @brief Multiply two signed-magnitude polynomials in `Z[x]/(x^n + 1)` into a wider signed-magnitude result.
 *
 * The input coefficient arrays are laid out contiguously as `[c0 || c1 || ...]`,
 * with separate sign-flag arrays. The output uses the same layout, with each
 * coefficient widened to `out_coeff_len` bytes.
 *
 * @param[in] a_mag Input magnitudes for the first polynomial.
 * @param[in] a_negative Input sign flags for the first polynomial.
 * @param[in] a_coeff_len Byte length of each coefficient magnitude in `a_mag`.
 * @param[in] b_mag Input magnitudes for the second polynomial.
 * @param[in] b_negative Input sign flags for the second polynomial.
 * @param[in] b_coeff_len Byte length of each coefficient magnitude in `b_mag`.
 * @param[in] n Falcon ring degree.
 * @param[out] out_mag Output coefficient magnitudes.
 * @param[out] out_negative Output sign flags.
 * @param[in] out_coeff_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if any exact intermediate product or sum does
 *         not fit in the requested output width.
 */
static noxtls_return_t falcon_bn_poly_mul_xn1_signed_to_len(const uint8_t *a_mag,
                                                            const uint8_t *a_negative,
                                                            uint32_t a_coeff_len,
                                                            const uint8_t *b_mag,
                                                            const uint8_t *b_negative,
                                                            uint32_t b_coeff_len,
                                                            uint16_t n,
                                                            uint8_t *out_mag,
                                                            uint8_t *out_negative,
                                                            uint32_t out_coeff_len)
{
    uint8_t *term_mag;
    uint8_t *sum_mag;
    uint8_t term_negative = 0U;
    uint8_t sum_negative = 0U;
    uint16_t i;
    uint16_t j;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(a_mag == NULL || a_negative == NULL || b_mag == NULL || b_negative == NULL ||
       out_mag == NULL || out_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || out_coeff_len < a_coeff_len || out_coeff_len < b_coeff_len) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(out_mag, 0, (size_t)n * out_coeff_len);
    memset(out_negative, 0, n);
    term_mag = (uint8_t*)noxtls_calloc(out_coeff_len, 1U);
    sum_mag = (uint8_t*)noxtls_calloc(out_coeff_len, 1U);
    if(term_mag == NULL || sum_mag == NULL) {
        goto cleanup;
    }

    for(i = 0U; i < n; i++) {
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            uint16_t dst_idx;
            uint8_t extra_negative;

            if(idx < n) {
                dst_idx = idx;
                extra_negative = 0U;
            } else {
                dst_idx = (uint16_t)(idx - n);
                extra_negative = 1U;
            }

            rc = falcon_bn_signed_mul_to_len(a_mag + ((uint32_t)i * a_coeff_len),
                                             a_negative[i],
                                             a_coeff_len,
                                             b_mag + ((uint32_t)j * b_coeff_len),
                                             b_negative[j],
                                             b_coeff_len,
                                             extra_negative,
                                             term_mag,
                                             &term_negative,
                                             out_coeff_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup;
            }
            rc = falcon_bn_signed_add_to_len(out_mag + ((uint32_t)dst_idx * out_coeff_len),
                                             out_negative[dst_idx],
                                             out_coeff_len,
                                             term_mag,
                                             term_negative,
                                             out_coeff_len,
                                             sum_mag,
                                             &sum_negative,
                                             out_coeff_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup;
            }
            rc = noxtls_bn_copy(out_mag + ((uint32_t)dst_idx * out_coeff_len), sum_mag, out_coeff_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup;
            }
            out_negative[dst_idx] = sum_negative;
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(term_mag != NULL) {
        noxtls_free(term_mag);
    }
    if(sum_mag != NULL) {
        noxtls_free(sum_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 2` on signed big-endian coefficients.
 *
 * This computes the scalar field norms of `f` and `g`, solves the child `n = 1`
 * Falcon equation on big-endian magnitudes, then lifts the child result back to
 * the degree-2 parent through the exact formulas:
 * `F = F' * g(-x)` and `G = G' * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n2(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len)
{
    uint32_t norm_len;
    uint8_t *f_norm;
    uint8_t *g_norm;
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative = 0U;
    uint8_t Gp_negative = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 3U) + 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    f_norm = (uint8_t*)noxtls_calloc(norm_len, 1U);
    g_norm = (uint8_t*)noxtls_calloc(norm_len, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(norm_len, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(norm_len, 1U);
    if(f_norm == NULL || g_norm == NULL || Fp_mag == NULL || Gp_mag == NULL) {
        goto cleanup;
    }

    rc = noxtls_falcon_keygen_field_norm_bn_n2(f_mag, f_mag + coeff_len, coeff_len, f_norm, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n2(g_mag, g_mag + coeff_len, coeff_len, g_norm, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_base_bn(f_norm,
                                                 0U,
                                                 g_norm,
                                                 0U,
                                                 norm_len,
                                                 Fp_mag,
                                                 &Fp_negative,
                                                 Gp_mag,
                                                 &Gp_negative);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = falcon_bn_signed_mul_to_len(Fp_mag,
                                     Fp_negative,
                                     norm_len,
                                     g_mag,
                                     g_negative[0],
                                     coeff_len,
                                     0U,
                                     F_mag,
                                     &F_negative[0],
                                     result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_signed_mul_to_len(Fp_mag,
                                     Fp_negative,
                                     norm_len,
                                     g_mag + coeff_len,
                                     g_negative[1],
                                     coeff_len,
                                     1U,
                                     F_mag + result_len,
                                     &F_negative[1],
                                     result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_signed_mul_to_len(Gp_mag,
                                     Gp_negative,
                                     norm_len,
                                     f_mag,
                                     f_negative[0],
                                     coeff_len,
                                     0U,
                                     G_mag,
                                     &G_negative[0],
                                     result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_signed_mul_to_len(Gp_mag,
                                     Gp_negative,
                                     norm_len,
                                     f_mag + coeff_len,
                                     f_negative[1],
                                     coeff_len,
                                     1U,
                                     G_mag + result_len,
                                     &G_negative[1],
                                     result_len);

cleanup:
    if(f_norm != NULL) {
        noxtls_free(f_norm);
    }
    if(g_norm != NULL) {
        noxtls_free(g_norm);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 4` on signed big-endian coefficients.
 *
 * This computes the degree-2 signed field norms of `f` and `g`, solves the child
 * `n = 2` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-4 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n4(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[2];
    uint8_t g_norm_negative[2];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[2];
    uint8_t Gp_negative[2];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[4];
    uint8_t Gp_lift_negative[4];
    uint8_t g_negx_negative[4];
    uint8_t f_negx_negative[4];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 7U) + 4U)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 3U) + 1U);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 2U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 2U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 2U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 2U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 4U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 4U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n4(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n4(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n2(f_norm_mag,
                                               f_norm_negative,
                                               g_norm_mag,
                                               g_norm_negative,
                                               norm_len,
                                               Fp_mag,
                                               Fp_negative,
                                               Gp_mag,
                                               Gp_negative,
                                               child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = noxtls_bn_copy(Fp_lift_mag, Fp_mag, child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_copy(Fp_lift_mag + (child_len << 1), Fp_mag + child_len, child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_copy(Gp_lift_mag, Gp_mag, child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_copy(Gp_lift_mag + (child_len << 1), Gp_mag + child_len, child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    Fp_lift_negative[0] = Fp_negative[0];
    Fp_lift_negative[2] = Fp_negative[1];
    Gp_lift_negative[0] = Gp_negative[0];
    Gp_lift_negative[2] = Gp_negative[1];

    for(i = 0U; i < 4U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              4U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              4U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 8` on signed big-endian coefficients.
 *
 * This computes the degree-4 signed field norms of `f` and `g`, solves the child
 * `n = 4` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-8 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n8(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[4];
    uint8_t g_norm_negative[4];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[4];
    uint8_t Gp_negative[4];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[8];
    uint8_t Gp_lift_negative[8];
    uint8_t g_negx_negative[8];
    uint8_t f_negx_negative[8];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 15U) + 11U)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 7U) + 4U);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 4U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 4U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 4U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 4U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 8U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 8U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n8(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n8(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n4(f_norm_mag,
                                               f_norm_negative,
                                               g_norm_mag,
                                               g_norm_negative,
                                               norm_len,
                                               Fp_mag,
                                               Fp_negative,
                                               Gp_mag,
                                               Gp_negative,
                                               child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 4U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 8U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              8U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              8U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 16` on signed big-endian coefficients.
 *
 * This computes the degree-8 signed field norms of `f` and `g`, solves the child
 * `n = 8` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-16 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n16(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[8];
    uint8_t g_norm_negative[8];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[8];
    uint8_t Gp_negative[8];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[16];
    uint8_t Gp_lift_negative[16];
    uint8_t g_negx_negative[16];
    uint8_t f_negx_negative[16];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 31U) + 26U)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 15U) + 11U);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 8U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 8U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 8U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 8U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 16U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 16U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n16(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n16(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n8(f_norm_mag,
                                               f_norm_negative,
                                               g_norm_mag,
                                               g_norm_negative,
                                               norm_len,
                                               Fp_mag,
                                               Fp_negative,
                                               Gp_mag,
                                               Gp_negative,
                                               child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 8U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 16U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              16U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              16U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 32` on signed big-endian coefficients.
 *
 * This computes the degree-16 signed field norms of `f` and `g`, solves the child
 * `n = 16` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-32 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n32(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[16];
    uint8_t g_norm_negative[16];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[16];
    uint8_t Gp_negative[16];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[32];
    uint8_t Gp_lift_negative[32];
    uint8_t g_negx_negative[32];
    uint8_t f_negx_negative[32];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 63u) + 57u)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 31U) + 26U);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 16U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 16U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 16U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 16U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 32U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 32U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n32(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n32(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n16(f_norm_mag,
                                                f_norm_negative,
                                                g_norm_mag,
                                                g_norm_negative,
                                                norm_len,
                                                Fp_mag,
                                                Fp_negative,
                                                Gp_mag,
                                                Gp_negative,
                                                child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 16U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 32U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              32U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              32U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 64` on signed big-endian coefficients.
 *
 * This computes the degree-32 signed field norms of `f` and `g`, solves the child
 * `n = 32` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-64 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n64(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[32];
    uint8_t g_norm_negative[32];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[32];
    uint8_t Gp_negative[32];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[64];
    uint8_t Gp_lift_negative[64];
    uint8_t g_negx_negative[64];
    uint8_t f_negx_negative[64];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 127u) + 120u)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 63u) + 57u);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 32U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 32U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 32U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 32U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 64U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 64U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n64(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n64(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n32(f_norm_mag,
                                                f_norm_negative,
                                                g_norm_mag,
                                                g_norm_negative,
                                                norm_len,
                                                Fp_mag,
                                                Fp_negative,
                                                Gp_mag,
                                                Gp_negative,
                                                child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 32U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 64U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              64U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              64U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 128` on signed big-endian coefficients.
 *
 * This computes the degree-64 signed field norms of `f` and `g`, solves the child
 * `n = 64` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-128 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n128(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[64];
    uint8_t g_norm_negative[64];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[64];
    uint8_t Gp_negative[64];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[128];
    uint8_t Gp_lift_negative[128];
    uint8_t g_negx_negative[128];
    uint8_t f_negx_negative[128];
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 255u) + 247u)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 127u) + 120u);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 64U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 64U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 64U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 64U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 128U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 128U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n128(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n128(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n64(f_norm_mag,
                                                f_norm_negative,
                                                g_norm_mag,
                                                g_norm_negative,
                                                norm_len,
                                                Fp_mag,
                                                Fp_negative,
                                                Gp_mag,
                                                Gp_negative,
                                                child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 64U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + (i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 128U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              128U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              128U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 256` on signed big-endian coefficients.
 *
 * This computes the degree-128 signed field norms of `f` and `g`, solves the child
 * `n = 128` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-256 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n256(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[128];
    uint8_t g_norm_negative[128];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[128];
    uint8_t Gp_negative[128];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[256];
    uint8_t Gp_lift_negative[256];
    uint8_t g_negx_negative[256];
    uint8_t f_negx_negative[256];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 511u) + 502u)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 255u) + 247u);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 128U, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 128U, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 128U, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 128U, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 256u, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 256u, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n256(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n256(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n128(f_norm_mag,
                                                 f_norm_negative,
                                                 g_norm_mag,
                                                 g_norm_negative,
                                                 norm_len,
                                                 Fp_mag,
                                                 Fp_negative,
                                                 Gp_mag,
                                                 Gp_negative,
                                                 child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 128U; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + ((uint32_t)i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + ((uint32_t)i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 256u; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              256u,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              256u,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 512` on signed big-endian coefficients.
 *
 * This computes the degree-256 signed field norms of `f` and `g`, solves the child
 * `n = 256` Falcon equation on big-endian signed coefficients, then lifts the child
 * result back to the degree-512 parent through the exact formulas
 * `F = F'(x^2) * g(-x)` and `G = G'(x^2) * f(-x)`.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n512(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len)
{
    uint32_t norm_len;
    uint32_t child_len;
    uint8_t *f_norm_mag;
    uint8_t *g_norm_mag;
    uint8_t f_norm_negative[256];
    uint8_t g_norm_negative[256];
    uint8_t *Fp_mag;
    uint8_t *Gp_mag;
    uint8_t Fp_negative[256];
    uint8_t Gp_negative[256];
    uint8_t *Fp_lift_mag;
    uint8_t *Gp_lift_mag;
    uint8_t Fp_lift_negative[512];
    uint8_t Gp_lift_negative[512];
    uint8_t g_negx_negative[512];
    uint8_t f_negx_negative[512];
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || f_negative == NULL || g_mag == NULL || g_negative == NULL ||
       F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(coeff_len == 0U || result_len < ((coeff_len * 1023u) + 1013u)) {
        return NOXTLS_RETURN_FAILED;
    }

    norm_len = (uint32_t)((coeff_len << 1) + 1U);
    child_len = (uint32_t)((norm_len * 511u) + 502u);
    f_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 256u, 1U);
    g_norm_mag = (uint8_t*)noxtls_calloc(norm_len * 256u, 1U);
    Fp_mag = (uint8_t*)noxtls_calloc(child_len * 256u, 1U);
    Gp_mag = (uint8_t*)noxtls_calloc(child_len * 256u, 1U);
    Fp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 512U, 1U);
    Gp_lift_mag = (uint8_t*)noxtls_calloc(child_len * 512U, 1U);
    if(f_norm_mag == NULL || g_norm_mag == NULL || Fp_mag == NULL || Gp_mag == NULL ||
       Fp_lift_mag == NULL || Gp_lift_mag == NULL) {
        goto cleanup;
    }

    memset(f_norm_negative, 0, sizeof(f_norm_negative));
    memset(g_norm_negative, 0, sizeof(g_norm_negative));
    memset(Fp_negative, 0, sizeof(Fp_negative));
    memset(Gp_negative, 0, sizeof(Gp_negative));
    memset(Fp_lift_negative, 0, sizeof(Fp_lift_negative));
    memset(Gp_lift_negative, 0, sizeof(Gp_lift_negative));
    memset(g_negx_negative, 0, sizeof(g_negx_negative));
    memset(f_negx_negative, 0, sizeof(f_negx_negative));

    rc = noxtls_falcon_keygen_field_norm_bn_n512(f_mag, f_negative, coeff_len, f_norm_mag, f_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_field_norm_bn_n512(g_mag, g_negative, coeff_len, g_norm_mag, g_norm_negative, norm_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_falcon_keygen_solve_ntru_bn_n256(f_norm_mag,
                                                 f_norm_negative,
                                                 g_norm_mag,
                                                 g_norm_negative,
                                                 norm_len,
                                                 Fp_mag,
                                                 Fp_negative,
                                                 Gp_mag,
                                                 Gp_negative,
                                                 child_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(i = 0U; i < 256u; i++) {
        rc = noxtls_bn_copy(Fp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Fp_mag + ((uint32_t)i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_copy(Gp_lift_mag + (((uint32_t)(i << 1)) * child_len),
                            Gp_mag + ((uint32_t)i * child_len),
                            child_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        Fp_lift_negative[(uint16_t)(i << 1)] = Fp_negative[i];
        Gp_lift_negative[(uint16_t)(i << 1)] = Gp_negative[i];
    }

    for(i = 0U; i < 512U; i++) {
        g_negx_negative[i] = (uint8_t)(((g_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
        f_negx_negative[i] = (uint8_t)(((f_negative[i] != 0U) ^ ((i & 1U) != 0U)) != 0U);
    }

    rc = falcon_bn_poly_mul_xn1_signed_to_len(Fp_lift_mag,
                                              Fp_lift_negative,
                                              child_len,
                                              g_mag,
                                              g_negx_negative,
                                              coeff_len,
                                              512U,
                                              F_mag,
                                              F_negative,
                                              result_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_mul_xn1_signed_to_len(Gp_lift_mag,
                                              Gp_lift_negative,
                                              child_len,
                                              f_mag,
                                              f_negx_negative,
                                              coeff_len,
                                              512U,
                                              G_mag,
                                              G_negative,
                                              result_len);

cleanup:
    if(f_norm_mag != NULL) {
        noxtls_free(f_norm_mag);
    }
    if(g_norm_mag != NULL) {
        noxtls_free(g_norm_mag);
    }
    if(Fp_mag != NULL) {
        noxtls_free(Fp_mag);
    }
    if(Gp_mag != NULL) {
        noxtls_free(Gp_mag);
    }
    if(Fp_lift_mag != NULL) {
        noxtls_free(Fp_lift_mag);
    }
    if(Gp_lift_mag != NULL) {
        noxtls_free(Gp_lift_mag);
    }
    return rc;
}

/**
 * @brief Compute the first Falcon keygen field norm reduction for a signed polynomial.
 *
 * For an even power-of-two degree `n`, this returns the half-degree polynomial
 * `N(f)` such that `N(f)(x^2) = f(x) * f(-x) mod (x^n + 1)`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be an even supported power of two.
 * @param[out] norm Output norm polynomial of degree `n/2`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm(const int16_t *src,
                                                uint16_t n,
                                                int32_t *norm)
{
    int16_t even[NOXTLS_FALCON_MAX_N];
    int16_t odd[NOXTLS_FALCON_MAX_N];
    int32_t ee[NOXTLS_FALCON_MAX_N];
    int32_t oo[NOXTLS_FALCON_MAX_N];
    uint16_t half;
    uint16_t i;

    if(src == NULL || norm == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    falcon_poly_split_i16(src, n, even, odd);
    falcon_poly_mul_xn1_i32(ee, even, even, half);
    falcon_poly_mul_xn1_i32(oo, odd, odd, half);

    norm[0] = ee[0] + oo[half - 1U];
    for(i = 1U; i < half; i++) {
        norm[i] = ee[i] - oo[i - 1U];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Solve the exact `n = 1` Falcon NTRU base case with B\'ezout coefficients.
 *
 * This finds integers `F` and `G` such that `f*G - g*F = q` when `gcd(f, g) = 1`.
 *
 * @param[in] f Scalar secret coefficient `f`.
 * @param[in] g Scalar secret coefficient `g`.
 * @param[out] F Output scalar `F`.
 * @param[out] G Output scalar `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `f` and `g` are not coprime.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_base(int32_t f,
                                                     int32_t g,
                                                     int32_t *F,
                                                     int32_t *G)
{
    int32_t u;
    int32_t v;

    if(F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(falcon_i32_xgcd(f, g, &u, &v) != 1) {
        return NOXTLS_RETURN_FAILED;
    }

    *F = (int32_t)(-(int64_t)v * (int64_t)NOXTLS_FALCON_Q);
    *G = (int32_t)((int64_t)u * (int64_t)NOXTLS_FALCON_Q);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Solve the exact `n = 1` Falcon NTRU base case on signed big-endian magnitudes.
 *
 * The positive-magnitude core computes `|f|*G' - |g|*F' = q`, then applies the
 * signs of `f` and `g` to recover a solution for the original signed scalars.
 *
 * @param[in] f_mag Magnitude of scalar `f` in big-endian bytes.
 * @param[in] f_negative Non-zero if scalar `f` is negative.
 * @param[in] g_mag Magnitude of scalar `g` in big-endian bytes.
 * @param[in] g_negative Non-zero if scalar `g` is negative.
 * @param[in] len Byte length of all input and output magnitudes.
 * @param[out] F_mag Output magnitude of scalar `F`.
 * @param[out] F_negative Output sign flag for scalar `F`.
 * @param[out] G_mag Output magnitude of scalar `G`.
 * @param[out] G_negative Output sign flag for scalar `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the scalars are not coprime or the exact
 *         signed result does not fit in `len` bytes.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_base_bn(const uint8_t *f_mag,
                                                        uint8_t f_negative,
                                                        const uint8_t *g_mag,
                                                        uint8_t g_negative,
                                                        uint32_t len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative)
{
    uint8_t *q_buf;
    uint8_t *inv_f;
    uint8_t *prod;
    uint8_t *g_abs;
    uint8_t *g_term;
    uint8_t *numerator;
    uint8_t *numerator_abs;
    uint8_t Fneg_local = 0U;
    uint8_t Gneg_local = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f_mag == NULL || g_mag == NULL || F_mag == NULL || F_negative == NULL || G_mag == NULL || G_negative == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0U || noxtls_bn_is_zero(f_mag, len) || noxtls_bn_is_zero(g_mag, len)) {
        return NOXTLS_RETURN_FAILED;
    }

    q_buf = (uint8_t*)noxtls_calloc(len, 1U);
    inv_f = (uint8_t*)noxtls_calloc(len, 1U);
    prod = (uint8_t*)noxtls_calloc(len * 2U, 1U);
    g_abs = (uint8_t*)noxtls_calloc(len, 1U);
    g_term = (uint8_t*)noxtls_calloc(len * 2U, 1U);
    numerator = (uint8_t*)noxtls_calloc(len * 2U, 1U);
    numerator_abs = (uint8_t*)noxtls_calloc(len * 2U, 1U);
    if(q_buf == NULL || inv_f == NULL || prod == NULL || g_abs == NULL ||
       g_term == NULL || numerator == NULL || numerator_abs == NULL) {
        goto cleanup;
    }

    rc = falcon_bn_store_small(q_buf, len, NOXTLS_FALCON_Q);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    if(noxtls_bn_is_one(g_mag, len)) {
        rc = noxtls_bn_copy(F_mag, q_buf, len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        rc = noxtls_bn_zero(G_mag, len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        *F_negative = (uint8_t)(1U ^ (g_negative != 0U));
        *G_negative = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = noxtls_bn_mod_inv(inv_f, f_mag, len, g_mag, len);
    if(rc != NOXTLS_RETURN_SUCCESS || noxtls_bn_is_zero(inv_f, len)) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }

    rc = noxtls_bn_mul(prod, q_buf, len, inv_f, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = noxtls_bn_mod(G_mag, prod, len * 2U, g_mag, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    rc = noxtls_bn_mul(g_term, f_mag, len, G_mag, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    memset(numerator, 0, len * 2U);
    noxtls_bn_copy(numerator + len, q_buf, len);
    if(noxtls_bn_cmp(g_term, numerator, len * 2U) >= 0) {
        noxtls_bn_copy(numerator_abs, g_term, len * 2U);
        noxtls_bn_sub(numerator_abs, numerator_abs, numerator, len * 2U);
    } else {
        noxtls_bn_copy(numerator_abs, numerator, len * 2U);
        noxtls_bn_sub(numerator_abs, numerator_abs, g_term, len * 2U);
        Fneg_local = 1U;
    }

    noxtls_bn_copy(g_abs, g_mag, len);
    rc = falcon_bn_exact_div_positive(F_mag, len, numerator_abs, len * 2U, g_abs, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    Gneg_local = 0U;
    *F_negative = (uint8_t)((Fneg_local ^ (g_negative != 0U)) != 0U && !noxtls_bn_is_zero(F_mag, len));
    *G_negative = (uint8_t)((Gneg_local ^ (f_negative != 0U)) != 0U && !noxtls_bn_is_zero(G_mag, len));
    rc = NOXTLS_RETURN_SUCCESS;

cleanup:
    if(q_buf != NULL) {
        noxtls_free(q_buf);
    }
    if(inv_f != NULL) {
        noxtls_free(inv_f);
    }
    if(prod != NULL) {
        noxtls_free(prod);
    }
    if(g_abs != NULL) {
        noxtls_free(g_abs);
    }
    if(g_term != NULL) {
        noxtls_free(g_term);
    }
    if(numerator != NULL) {
        noxtls_free(numerator);
    }
    if(numerator_abs != NULL) {
        noxtls_free(numerator_abs);
    }
    return rc;
}

/**
 * @brief Solve the exact `n = 1` Falcon NTRU base case with signed 64-bit coefficients.
 *
 * This finds integers `F` and `G` such that `f*G - g*F = q` when `gcd(f, g) = 1`,
 * while rejecting any intermediate or final value that exceeds signed 64 bits.
 *
 * @param[in] f Scalar secret coefficient `f`.
 * @param[in] g Scalar secret coefficient `g`.
 * @param[out] F Output scalar `F`.
 * @param[out] G Output scalar `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `f` and `g` are not coprime or the result
 *         does not fit in signed 64 bits.
 */
static noxtls_return_t falcon_keygen_solve_ntru_base_i64(int64_t f,
                                                         int64_t g,
                                                         int64_t *F,
                                                         int64_t *G)
{
    int64_t u;
    int64_t v;
    int64_t value;

    if(F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_i64_xgcd(f, g, &u, &v) || (u == 0 && v == 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(!falcon_checked_mul_i64(-v, (int64_t)NOXTLS_FALCON_Q, &value)) {
        return NOXTLS_RETURN_FAILED;
    }
    *F = value;
    if(!falcon_checked_mul_i64(u, (int64_t)NOXTLS_FALCON_Q, &value)) {
        return NOXTLS_RETURN_FAILED;
    }
    *G = value;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply two signed 32-bit polynomials in the negacyclic Falcon ring.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[in] n Falcon ring degree.
 */
static void falcon_poly_mul_xn1_i32x32(int32_t *out,
                                       const int32_t *a,
                                       const int32_t *b,
                                       uint16_t n)
{
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL || n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return;
    }

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < n; i++) {
        int64_t ai = (int64_t)a[i];
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int64_t term = ai * (int64_t)b[j];
            if(idx < n) {
                out[idx] = (int32_t)((int64_t)out[idx] + term);
            } else {
                out[idx - n] = (int32_t)((int64_t)out[idx - n] - term);
            }
        }
    }
}

/**
 * @brief Multiply two signed 32-bit polynomials with overflow checking.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[in] n Falcon ring degree.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad size, or `NOXTLS_RETURN_FAILED`
 *         if an intermediate coefficient does not fit in signed 32 bits.
 */
static noxtls_return_t falcon_poly_mul_xn1_i32x32_checked(int32_t *out,
                                                          const int32_t *a,
                                                          const int32_t *b,
                                                          uint16_t n)
{
    int64_t accum[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(accum, 0, sizeof(accum));
    for(i = 0U; i < n; i++) {
        int64_t ai = (int64_t)a[i];
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int64_t term = ai * (int64_t)b[j];
            if(idx < n) {
                accum[idx] += term;
            } else {
                accum[idx - n] -= term;
            }
        }
    }
    for(i = 0U; i < n; i++) {
        if(accum[i] < (int64_t)INT32_MIN || accum[i] > (int64_t)INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        out[i] = (int32_t)accum[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply two signed 32-bit polynomials into a 64-bit negacyclic product.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[in] n Falcon ring degree.
 */
static void falcon_poly_mul_xn1_i32x32_i64(int64_t *out,
                                           const int32_t *a,
                                           const int32_t *b,
                                           uint16_t n)
{
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL || n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return;
    }

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < n; i++) {
        int64_t ai = (int64_t)a[i];
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int64_t term = ai * (int64_t)b[j];
            if(idx < n) {
                out[idx] += term;
            } else {
                out[idx - n] -= term;
            }
        }
    }
}

/**
 * @brief Evaluate a signed Falcon keygen polynomial at `-x`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree.
 * @param[out] out Output polynomial `src(-x)` with 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_apply_negx(const int16_t *src,
                                                uint16_t n,
                                                int32_t *out)
{
    uint16_t i;

    if(src == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        out[i] = ((i & 1U) != 0U) ? -(int32_t)src[i] : (int32_t)src[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Lift a half-degree signed polynomial into the full Falcon ring through `x^2`.
 *
 * @param[in] src Source polynomial of degree `n/2`.
 * @param[in] n Target full degree. Must be an even supported power of two.
 * @param[out] out Output polynomial `src(x^2)` with 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_lift_x2(const int32_t *src,
                                             uint16_t n,
                                             int32_t *out)
{
    uint16_t i;
    uint16_t half;

    if(src == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < half; i++) {
        out[(uint16_t)(i << 1)] = src[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Lift a child Falcon NTRU solution back to the parent degree.
 *
 * Given a degree-`n/2` solution `(Fp, Gp)` for the field norms of `(f, g)`,
 * this computes the unreduced parent-degree candidate:
 * `F = Fp(x^2) * g(-x)` and `G = Gp(x^2) * f(-x)`.
 *
 * @param[in] f Parent secret polynomial `f`.
 * @param[in] g Parent secret polynomial `g`.
 * @param[in] n Parent degree. Must be an even supported power of two.
 * @param[in] Fp Child solution polynomial `F'` of degree `n/2`.
 * @param[in] Gp Child solution polynomial `G'` of degree `n/2`.
 * @param[out] F Output parent candidate `F`.
 * @param[out] G Output parent candidate `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_combine_from_child(const int16_t *f,
                                                        const int16_t *g,
                                                        uint16_t n,
                                                        const int32_t *Fp,
                                                        const int32_t *Gp,
                                                        int32_t *F,
                                                        int32_t *G)
{
    int32_t Fp_lift[NOXTLS_FALCON_MAX_N];
    int32_t Gp_lift[NOXTLS_FALCON_MAX_N];
    int32_t f_neg[NOXTLS_FALCON_MAX_N];
    int32_t g_neg[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    if(f == NULL || g == NULL || Fp == NULL || Gp == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_falcon_keygen_lift_x2(Fp, n, Fp_lift);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_keygen_lift_x2(Gp, n, Gp_lift);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_keygen_apply_negx(f, n, f_neg);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_falcon_keygen_apply_negx(g, n, g_neg);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    falcon_poly_mul_xn1_i32x32(F, Fp_lift, g_neg, n);
    falcon_poly_mul_xn1_i32x32(G, Gp_lift, f_neg, n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Split a signed 32-bit polynomial into even and odd coefficient halves.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be even.
 * @param[out] even Even-index coefficients packed into length `n/2`.
 * @param[out] odd Odd-index coefficients packed into length `n/2`.
 */
static void falcon_poly_split_i32(const int32_t *src,
                                  uint16_t n,
                                  int32_t *even,
                                  int32_t *odd)
{
    uint16_t i;
    uint16_t half = (uint16_t)(n >> 1);

    for(i = 0U; i < half; i++) {
        even[i] = src[(uint16_t)(i << 1)];
        odd[i] = src[(uint16_t)((i << 1) + 1U)];
    }
}

/**
 * @brief Compute the first Falcon keygen field norm reduction for a 32-bit polynomial.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be an even supported power of two.
 * @param[out] norm Output norm polynomial of degree `n/2`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_INVALID_PARAM` on bad size.
 */
static noxtls_return_t falcon_keygen_field_norm_i32(const int32_t *src,
                                                    uint16_t n,
                                                    int32_t *norm)
{
    int32_t even[NOXTLS_FALCON_MAX_N];
    int32_t odd[NOXTLS_FALCON_MAX_N];
    int32_t ee[NOXTLS_FALCON_MAX_N];
    int32_t oo[NOXTLS_FALCON_MAX_N];
    uint16_t half;
    uint16_t i;

    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    falcon_poly_split_i32(src, n, even, odd);
    falcon_poly_mul_xn1_i32x32(ee, even, even, half);
    falcon_poly_mul_xn1_i32x32(oo, odd, odd, half);

    norm[0] = ee[0] + oo[half - 1U];
    for(i = 1U; i < half; i++) {
        norm[i] = ee[i] - oo[i - 1U];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Evaluate a signed 32-bit polynomial at `-x`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree.
 * @param[out] out Output polynomial `src(-x)`.
 */
static void falcon_keygen_apply_negx_i32(const int32_t *src,
                                         uint16_t n,
                                         int32_t *out)
{
    uint16_t i;

    for(i = 0U; i < n; i++) {
        out[i] = ((i & 1U) != 0U) ? -src[i] : src[i];
    }
}

/**
 * @brief Lift a half-degree 32-bit polynomial into the full ring through `x^2`.
 *
 * @param[in] src Source polynomial of degree `n/2`.
 * @param[in] n Target full degree.
 * @param[out] out Output polynomial `src(x^2)`.
 */
static void falcon_keygen_lift_x2_i32(const int32_t *src,
                                      uint16_t n,
                                      int32_t *out)
{
    uint16_t i;
    uint16_t half = (uint16_t)(n >> 1);

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < half; i++) {
        out[(uint16_t)(i << 1)] = src[i];
    }
}

/**
 * @brief Lift a child exact NTRU solution back to the parent degree for 32-bit polynomials.
 *
 * @param[in] f Parent secret polynomial `f`.
 * @param[in] g Parent secret polynomial `g`.
 * @param[in] n Parent degree.
 * @param[in] Fp Child solution `F'`.
 * @param[in] Gp Child solution `G'`.
 * @param[out] F Output parent candidate `F`.
 * @param[out] G Output parent candidate `G`.
 */
static noxtls_return_t falcon_keygen_combine_from_child_i32(const int32_t *f,
                                                            const int32_t *g,
                                                            uint16_t n,
                                                            const int32_t *Fp,
                                                            const int32_t *Gp,
                                                            int32_t *F,
                                                            int32_t *G)
{
    int32_t Fp_lift[NOXTLS_FALCON_MAX_N];
    int32_t Gp_lift[NOXTLS_FALCON_MAX_N];
    int32_t f_neg[NOXTLS_FALCON_MAX_N];
    int32_t g_neg[NOXTLS_FALCON_MAX_N];

    falcon_keygen_lift_x2_i32(Fp, n, Fp_lift);
    falcon_keygen_lift_x2_i32(Gp, n, Gp_lift);
    falcon_keygen_apply_negx_i32(f, n, f_neg);
    falcon_keygen_apply_negx_i32(g, n, g_neg);
    falcon_poly_mul_xn1_i32x32(F, Fp_lift, g_neg, n);
    falcon_poly_mul_xn1_i32x32(G, Gp_lift, f_neg, n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return the maximum absolute coefficient in a signed 32-bit polynomial.
 *
 * @param[in] poly Input polynomial.
 * @param[in] n Polynomial degree.
 * @return Maximum absolute coefficient.
 */
static int32_t falcon_poly_maxabs_i32(const int32_t *poly,
                                      uint16_t n)
{
    int32_t maxv = 0;
    uint16_t i;

    for(i = 0U; i < n; i++) {
        int32_t v = poly[i] < 0 ? -poly[i] : poly[i];
        if(v > maxv) {
            maxv = v;
        }
    }
    return maxv;
}

/**
 * @brief Return the maximum absolute coefficient in a signed 64-bit polynomial.
 *
 * @param[in] poly Input polynomial.
 * @param[in] n Polynomial degree.
 * @return Maximum absolute coefficient.
 */
static int64_t falcon_poly_maxabs_i64(const int64_t *poly,
                                      uint16_t n)
{
    int64_t maxv = 0;
    uint16_t i;

    for(i = 0U; i < n; i++) {
        int64_t v = poly[i] < 0 ? -poly[i] : poly[i];
        if(v > maxv) {
            maxv = v;
        }
    }
    return maxv;
}

/**
 * @brief Convert a signed 64-bit polynomial to signed 32-bit coefficients with range checks.
 *
 * @param[in] src Source polynomial with signed 64-bit coefficients.
 * @param[in] n Polynomial degree.
 * @param[out] dst Output polynomial with signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if any coefficient does not fit in signed 32 bits.
 */
static noxtls_return_t falcon_poly_cast_i64_to_i32_checked(const int64_t *src,
                                                           uint16_t n,
                                                           int32_t *dst)
{
    uint16_t i;

    if(src == NULL || dst == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < n; i++) {
        if(src[i] < (int64_t)INT32_MIN || src[i] > (int64_t)INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        dst[i] = (int32_t)src[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return the absolute value of a signed 64-bit integer as an unsigned magnitude.
 *
 * @param[in] x Input signed value.
 * @return Absolute value of `x` as an unsigned 64-bit integer.
 */
static uint64_t falcon_abs_i64_to_u64(int64_t x)
{
    return (x < 0) ? ((uint64_t)(-(x + 1)) + 1U) : (uint64_t)x;
}

/**
 * @brief Multiply two signed 64-bit integers with overflow checking.
 *
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[out] out Output product on success.
 * @return `1` on success or `0` if the exact product does not fit in signed 64 bits.
 */
static int falcon_checked_mul_i64(int64_t a,
                                  int64_t b,
                                  int64_t *out)
{
    uint64_t abs_a;
    uint64_t abs_b;
    uint64_t limit;
    uint64_t prod;
    int negative;

    if(out == NULL) {
        return 0;
    }
    if(a == 0 || b == 0) {
        *out = 0;
        return 1;
    }

    negative = ((a < 0) != (b < 0));
    abs_a = falcon_abs_i64_to_u64(a);
    abs_b = falcon_abs_i64_to_u64(b);
    limit = negative ? (UINT64_C(1) << 63) : (uint64_t)INT64_MAX;
    if(abs_a > (limit / abs_b)) {
        return 0;
    }

    prod = abs_a * abs_b;
    if(negative) {
        if(prod == (UINT64_C(1) << 63)) {
            *out = INT64_MIN;
        } else {
            *out = -(int64_t)prod;
        }
    } else {
        *out = (int64_t)prod;
    }
    return 1;
}

/**
 * @brief Add two signed 64-bit integers with overflow checking.
 *
 * @param[in] a First operand.
 * @param[in] b Second operand.
 * @param[out] out Output sum on success.
 * @return `1` on success or `0` on signed 64-bit overflow.
 */
static int falcon_checked_add_i64(int64_t a,
                                  int64_t b,
                                  int64_t *out)
{
    if(out == NULL) {
        return 0;
    }
    if((b > 0 && a > (INT64_MAX - b)) ||
       (b < 0 && a < (INT64_MIN - b))) {
        return 0;
    }
    *out = a + b;
    return 1;
}

/**
 * @brief Subtract two signed 64-bit integers with overflow checking.
 *
 * @param[in] a Minuend.
 * @param[in] b Subtrahend.
 * @param[out] out Output difference on success.
 * @return `1` on success or `0` on signed 64-bit overflow.
 */
static int falcon_checked_sub_i64(int64_t a,
                                  int64_t b,
                                  int64_t *out)
{
    if(out == NULL) {
        return 0;
    }
    if((b > 0 && a < (INT64_MIN + b)) ||
       (b < 0 && a > (INT64_MAX + b))) {
        return 0;
    }
    *out = a - b;
    return 1;
}

/**
 * @brief Split a signed 64-bit polynomial into even and odd coefficient halves.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be even.
 * @param[out] even Even-index coefficients packed into length `n/2`.
 * @param[out] odd Odd-index coefficients packed into length `n/2`.
 */
static void falcon_poly_split_i64(const int64_t *src,
                                  uint16_t n,
                                  int64_t *even,
                                  int64_t *odd)
{
    uint16_t i;
    uint16_t half = (uint16_t)(n >> 1);

    for(i = 0U; i < half; i++) {
        even[i] = src[(uint16_t)(i << 1)];
        odd[i] = src[(uint16_t)((i << 1) + 1U)];
    }
}

/**
 * @brief Multiply two signed 64-bit polynomials in the negacyclic Falcon ring with overflow checks.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 * @param[in] n Falcon ring degree.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad size, or `NOXTLS_RETURN_FAILED`
 *         if an intermediate coefficient does not fit in signed 64 bits.
 */
static noxtls_return_t falcon_poly_mul_xn1_i64x64_checked(int64_t *out,
                                                          const int64_t *a,
                                                          const int64_t *b,
                                                          uint16_t n)
{
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < n; i++) {
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int64_t term;

            if(!falcon_checked_mul_i64(a[i], b[j], &term)) {
                return NOXTLS_RETURN_FAILED;
            }
            if(idx < n) {
                if(!falcon_checked_add_i64(out[idx], term, &out[idx])) {
                    return NOXTLS_RETURN_FAILED;
                }
            } else {
                if(!falcon_checked_sub_i64(out[idx - n], term, &out[idx - n])) {
                    return NOXTLS_RETURN_FAILED;
                }
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply a signed 32-bit polynomial by a signed 64-bit polynomial with overflow checks.
 *
 * @param[out] out Output polynomial coefficients in `Z[x]/(x^n + 1)`.
 * @param[in] a First factor with signed 32-bit coefficients.
 * @param[in] b Second factor with signed 64-bit coefficients.
 * @param[in] n Falcon ring degree.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_FAILED` if an exact
 *         intermediate coefficient exceeds signed 64 bits.
 */
static noxtls_return_t falcon_poly_mul_xn1_i32x64_checked(int64_t *out,
                                                          const int32_t *a,
                                                          const int64_t *b,
                                                          uint16_t n)
{
    uint16_t i;
    uint16_t j;

    if(out == NULL || a == NULL || b == NULL || n == 0U || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_NULL;
    }

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < n; i++) {
        for(j = 0U; j < n; j++) {
            uint16_t idx = (uint16_t)(i + j);
            int64_t term;

            if(!falcon_checked_mul_i64((int64_t)a[i], b[j], &term)) {
                return NOXTLS_RETURN_FAILED;
            }
            if(idx < n) {
                if(!falcon_checked_add_i64(out[idx], term, &out[idx])) {
                    return NOXTLS_RETURN_FAILED;
                }
            } else {
                if(!falcon_checked_sub_i64(out[idx - n], term, &out[idx - n])) {
                    return NOXTLS_RETURN_FAILED;
                }
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Evaluate a signed 64-bit polynomial at `-x`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree.
 * @param[out] out Output polynomial `src(-x)`.
 */
static void falcon_keygen_apply_negx_i64(const int64_t *src,
                                         uint16_t n,
                                         int64_t *out)
{
    uint16_t i;

    for(i = 0U; i < n; i++) {
        out[i] = ((i & 1U) != 0U) ? -src[i] : src[i];
    }
}

/**
 * @brief Lift a half-degree 64-bit polynomial into the full ring through `x^2`.
 *
 * @param[in] src Source polynomial of degree `n/2`.
 * @param[in] n Target full degree.
 * @param[out] out Output polynomial `src(x^2)`.
 */
static void falcon_keygen_lift_x2_i64(const int64_t *src,
                                      uint16_t n,
                                      int64_t *out)
{
    uint16_t i;
    uint16_t half = (uint16_t)(n >> 1);

    memset(out, 0, (size_t)n * sizeof(*out));
    for(i = 0U; i < half; i++) {
        out[(uint16_t)(i << 1)] = src[i];
    }
}

/**
 * @brief Compute the first Falcon keygen field norm reduction for a 64-bit polynomial.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be an even supported power of two.
 * @param[out] norm Output norm polynomial of degree `n/2`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or an error if the intermediate exact
 *         arithmetic overflows signed 64 bits.
 */
static noxtls_return_t falcon_keygen_field_norm_i64(const int64_t *src,
                                                    uint16_t n,
                                                    int64_t *norm)
{
    int64_t even[NOXTLS_FALCON_MAX_N];
    int64_t odd[NOXTLS_FALCON_MAX_N];
    int64_t ee[NOXTLS_FALCON_MAX_N];
    int64_t oo[NOXTLS_FALCON_MAX_N];
    uint16_t half;
    uint16_t i;
    noxtls_return_t rc;

    if(src == NULL || norm == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!falcon_is_supported_power_of_two(n) || n < 2U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    falcon_poly_split_i64(src, n, even, odd);
    rc = falcon_poly_mul_xn1_i64x64_checked(ee, even, even, half);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_poly_mul_xn1_i64x64_checked(oo, odd, odd, half);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(!falcon_checked_add_i64(ee[0], oo[half - 1U], &norm[0])) {
        return NOXTLS_RETURN_FAILED;
    }
    for(i = 1U; i < half; i++) {
        if(!falcon_checked_sub_i64(ee[i], oo[i - 1U], &norm[i])) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Lift a child exact NTRU solution back to the parent degree for 64-bit polynomials.
 *
 * @param[in] f Parent secret polynomial `f`.
 * @param[in] g Parent secret polynomial `g`.
 * @param[in] n Parent degree.
 * @param[in] Fp Child solution `F'`.
 * @param[in] Gp Child solution `G'`.
 * @param[out] F Output parent candidate `F`.
 * @param[out] G Output parent candidate `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_FAILED` if the exact
 *         checked negacyclic products exceed signed 64 bits.
 */
static noxtls_return_t falcon_keygen_combine_from_child_i64_full(const int64_t *f,
                                                                 const int64_t *g,
                                                                 uint16_t n,
                                                                 const int64_t *Fp,
                                                                 const int64_t *Gp,
                                                                 int64_t *F,
                                                                 int64_t *G)
{
    int64_t Fp_lift[NOXTLS_FALCON_MAX_N];
    int64_t Gp_lift[NOXTLS_FALCON_MAX_N];
    int64_t f_neg[NOXTLS_FALCON_MAX_N];
    int64_t g_neg[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    falcon_keygen_lift_x2_i64(Fp, n, Fp_lift);
    falcon_keygen_lift_x2_i64(Gp, n, Gp_lift);
    falcon_keygen_apply_negx_i64(f, n, f_neg);
    falcon_keygen_apply_negx_i64(g, n, g_neg);
    rc = falcon_poly_mul_xn1_i64x64_checked(F, Fp_lift, g_neg, n);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return falcon_poly_mul_xn1_i64x64_checked(G, Gp_lift, f_neg, n);
}

/**
 * @brief Reduce a signed 32-bit Falcon NTRU solution by subtracting lattice multiples.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[in,out] F Solution polynomial `F` to reduce in place.
 * @param[in,out] G Solution polynomial `G` to reduce in place.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad degree, or `NOXTLS_RETURN_FAILED`
 *         if an intermediate coefficient overflows signed 32 bits.
 */
static noxtls_return_t falcon_keygen_reduce_solution_i32(const int32_t *f,
                                                         const int32_t *g,
                                                         uint16_t n,
                                                         int32_t *F,
                                                         int32_t *G)
{
    double f_real[NOXTLS_FALCON_MAX_N];
    double g_real[NOXTLS_FALCON_MAX_N];
    double F_real[NOXTLS_FALCON_MAX_N];
    double G_real[NOXTLS_FALCON_MAX_N];
    double k_real[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t f_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t F_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t G_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t k_fft[NOXTLS_FALCON_MAX_N];
    int32_t k_poly[NOXTLS_FALCON_MAX_N];
    int32_t step_poly[NOXTLS_FALCON_MAX_N];
    int32_t kf[NOXTLS_FALCON_MAX_N];
    int32_t kg[NOXTLS_FALCON_MAX_N];
    int32_t F_try[NOXTLS_FALCON_MAX_N];
    int32_t G_try[NOXTLS_FALCON_MAX_N];
    uint32_t iter;
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || (n != 1U && !falcon_is_supported_power_of_two(n)) || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(n == 1U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    for(iter = 0U; iter < 1024U; iter++) {
        int32_t before;
        int any_nonzero = 0;

        before = falcon_poly_maxabs_i32(F, n);
        if(falcon_poly_maxabs_i32(G, n) > before) {
            before = falcon_poly_maxabs_i32(G, n);
        }
        for(i = 0U; i < n; i++) {
            f_real[i] = (double)f[i];
            g_real[i] = (double)g[i];
            F_real[i] = (double)F[i];
            G_real[i] = (double)G[i];
        }
        if(falcon_poly_forward_fft_real(f_real, n, f_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(g_real, n, g_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(F_real, n, F_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(G_real, n, G_fft) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        for(i = 0U; i < n; i++) {
            noxtls_falcon_complex_t num = falcon_complex_add(
                falcon_complex_mul(F_fft[i], falcon_complex_conj(f_fft[i])),
                falcon_complex_mul(G_fft[i], falcon_complex_conj(g_fft[i])));
            double den = falcon_complex_norm_sq(f_fft[i]) + falcon_complex_norm_sq(g_fft[i]);

            if(den <= 1e-18) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            k_fft[i].re = num.re / den;
            k_fft[i].im = num.im / den;
        }
        if(falcon_poly_inverse_fft_real(k_fft, n, k_real) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        for(i = 0U; i < n; i++) {
            k_poly[i] = falcon_round_to_i32(k_real[i]);
            if(k_poly[i] != 0) {
                any_nonzero = 1;
            }
        }
        if(!any_nonzero) {
            return NOXTLS_RETURN_SUCCESS;
        }

        {
            uint32_t shift;
            int improved = 0;

            for(shift = 0U; shift < 8U; shift++) {
                int step_nonzero = 0;
                int32_t after;

                for(i = 0U; i < n; i++) {
                    step_poly[i] = k_poly[i] / (int32_t)(1U << shift);
                    if(step_poly[i] != 0) {
                        step_nonzero = 1;
                    }
                }
                if(!step_nonzero) {
                    break;
                }

                falcon_poly_mul_xn1_i32x32(kf, step_poly, f, n);
                falcon_poly_mul_xn1_i32x32(kg, step_poly, g, n);
                for(i = 0U; i < n; i++) {
                    F_try[i] = F[i] - kf[i];
                    G_try[i] = G[i] - kg[i];
                }

                after = falcon_poly_maxabs_i32(F_try, n);
                if(falcon_poly_maxabs_i32(G_try, n) > after) {
                    after = falcon_poly_maxabs_i32(G_try, n);
                }
                if(after < before) {
                    memcpy(F, F_try, (size_t)n * sizeof(*F));
                    memcpy(G, G_try, (size_t)n * sizeof(*G));
                    improved = 1;
                    break;
                }
            }

            if(!improved) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }

        if(falcon_poly_maxabs_i32(F, n) >= before && falcon_poly_maxabs_i32(G, n) >= before) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reduce a signed 64-bit Falcon NTRU solution and cast it back to signed 32 bits.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[in,out] F64 Solution polynomial `F` in signed 64-bit form.
 * @param[in,out] G64 Solution polynomial `G` in signed 64-bit form.
 * @param[out] F Output reduced polynomial `F` in signed 32-bit form.
 * @param[out] G Output reduced polynomial `G` in signed 32-bit form.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad degree, or `NOXTLS_RETURN_FAILED`
 *         if the reduced result still does not fit in signed 32 bits.
 */
static noxtls_return_t falcon_keygen_reduce_solution_i64_to_i32(const int32_t *f,
                                                                const int32_t *g,
                                                                uint16_t n,
                                                                int64_t *F64,
                                                                int64_t *G64,
                                                                int32_t *F,
                                                                int32_t *G)
{
    double f_real[NOXTLS_FALCON_MAX_N];
    double g_real[NOXTLS_FALCON_MAX_N];
    double F_real[NOXTLS_FALCON_MAX_N];
    double G_real[NOXTLS_FALCON_MAX_N];
    double k_real[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t f_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t F_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t G_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t k_fft[NOXTLS_FALCON_MAX_N];
    int32_t k_poly[NOXTLS_FALCON_MAX_N];
    int32_t step_poly[NOXTLS_FALCON_MAX_N];
    int64_t kf[NOXTLS_FALCON_MAX_N];
    int64_t kg[NOXTLS_FALCON_MAX_N];
    int64_t F_try[NOXTLS_FALCON_MAX_N];
    int64_t G_try[NOXTLS_FALCON_MAX_N];
    uint32_t iter;
    uint16_t i;

    if(f == NULL || g == NULL || F64 == NULL || G64 == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || (n != 1U && !falcon_is_supported_power_of_two(n)) || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(n == 1U) {
        if(F64[0] < (int64_t)INT32_MIN || F64[0] > (int64_t)INT32_MAX ||
           G64[0] < (int64_t)INT32_MIN || G64[0] > (int64_t)INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        F[0] = (int32_t)F64[0];
        G[0] = (int32_t)G64[0];
        return NOXTLS_RETURN_SUCCESS;
    }

    for(iter = 0U; iter < 1024U; iter++) {
        int64_t before;
        int any_nonzero = 0;

        before = falcon_poly_maxabs_i64(F64, n);
        if(falcon_poly_maxabs_i64(G64, n) > before) {
            before = falcon_poly_maxabs_i64(G64, n);
        }
        for(i = 0U; i < n; i++) {
            f_real[i] = (double)f[i];
            g_real[i] = (double)g[i];
            F_real[i] = (double)F64[i];
            G_real[i] = (double)G64[i];
        }
        if(falcon_poly_forward_fft_real(f_real, n, f_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(g_real, n, g_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(F_real, n, F_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(G_real, n, G_fft) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(i = 0U; i < n; i++) {
            noxtls_falcon_complex_t num = falcon_complex_add(
                falcon_complex_mul(F_fft[i], falcon_complex_conj(f_fft[i])),
                falcon_complex_mul(G_fft[i], falcon_complex_conj(g_fft[i])));
            double den = falcon_complex_norm_sq(f_fft[i]) + falcon_complex_norm_sq(g_fft[i]);

            if(den <= 1e-18) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            k_fft[i].re = num.re / den;
            k_fft[i].im = num.im / den;
        }
        if(falcon_poly_inverse_fft_real(k_fft, n, k_real) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(i = 0U; i < n; i++) {
            k_poly[i] = falcon_round_to_i32(k_real[i]);
            if(k_poly[i] != 0) {
                any_nonzero = 1;
            }
        }
        if(!any_nonzero) {
            break;
        }

        {
            uint32_t shift;
            int improved = 0;

            for(shift = 0U; shift < 8U; shift++) {
                int step_nonzero = 0;
                int64_t after;

                for(i = 0U; i < n; i++) {
                    step_poly[i] = k_poly[i] / (int32_t)(1U << shift);
                    if(step_poly[i] != 0) {
                        step_nonzero = 1;
                    }
                }
                if(!step_nonzero) {
                    break;
                }

                falcon_poly_mul_xn1_i32x32_i64(kf, step_poly, f, n);
                falcon_poly_mul_xn1_i32x32_i64(kg, step_poly, g, n);
                for(i = 0U; i < n; i++) {
                    F_try[i] = F64[i] - kf[i];
                    G_try[i] = G64[i] - kg[i];
                }

                after = falcon_poly_maxabs_i64(F_try, n);
                if(falcon_poly_maxabs_i64(G_try, n) > after) {
                    after = falcon_poly_maxabs_i64(G_try, n);
                }
                if(after < before) {
                    memcpy(F64, F_try, (size_t)n * sizeof(*F64));
                    memcpy(G64, G_try, (size_t)n * sizeof(*G64));
                    improved = 1;
                    break;
                }
            }

            if(!improved) {
                break;
            }
        }
        if(falcon_poly_maxabs_i64(F64, n) >= before && falcon_poly_maxabs_i64(G64, n) >= before) {
            break;
        }
    }

    for(i = 0U; i < n; i++) {
        if(F64[i] < (int64_t)INT32_MIN || F64[i] > (int64_t)INT32_MAX ||
           G64[i] < (int64_t)INT32_MIN || G64[i] > (int64_t)INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        F[i] = (int32_t)F64[i];
        G[i] = (int32_t)G64[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reduce a signed 64-bit Falcon NTRU solution in place by subtracting lattice multiples.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[in,out] F Solution polynomial `F` in signed 64-bit form.
 * @param[in,out] G Solution polynomial `G` in signed 64-bit form.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad degree, or `NOXTLS_RETURN_FAILED`
 *         if the exact correction step exceeds signed 64 bits.
 */
static noxtls_return_t falcon_keygen_reduce_solution_i64(const int64_t *f,
                                                         const int64_t *g,
                                                         uint16_t n,
                                                         int64_t *F,
                                                         int64_t *G)
{
    double f_real[NOXTLS_FALCON_MAX_N];
    double g_real[NOXTLS_FALCON_MAX_N];
    double F_real[NOXTLS_FALCON_MAX_N];
    double G_real[NOXTLS_FALCON_MAX_N];
    double k_real[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t f_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t F_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t G_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t k_fft[NOXTLS_FALCON_MAX_N];
    int32_t k_poly[NOXTLS_FALCON_MAX_N];
    int32_t step_poly[NOXTLS_FALCON_MAX_N];
    int64_t kf[NOXTLS_FALCON_MAX_N];
    int64_t kg[NOXTLS_FALCON_MAX_N];
    int64_t F_try[NOXTLS_FALCON_MAX_N];
    int64_t G_try[NOXTLS_FALCON_MAX_N];
    uint32_t iter;
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || (n != 1U && !falcon_is_supported_power_of_two(n)) || n > NOXTLS_FALCON_MAX_N) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(n == 1U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    for(iter = 0U; iter < 1024U; iter++) {
        int64_t before;
        int any_nonzero = 0;
        noxtls_return_t rc;

        before = falcon_poly_maxabs_i64(F, n);
        if(falcon_poly_maxabs_i64(G, n) > before) {
            before = falcon_poly_maxabs_i64(G, n);
        }
        for(i = 0U; i < n; i++) {
            f_real[i] = (double)f[i];
            g_real[i] = (double)g[i];
            F_real[i] = (double)F[i];
            G_real[i] = (double)G[i];
        }
        if(falcon_poly_forward_fft_real(f_real, n, f_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(g_real, n, g_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(F_real, n, F_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(G_real, n, G_fft) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(i = 0U; i < n; i++) {
            noxtls_falcon_complex_t num = falcon_complex_add(
                falcon_complex_mul(F_fft[i], falcon_complex_conj(f_fft[i])),
                falcon_complex_mul(G_fft[i], falcon_complex_conj(g_fft[i])));
            double den = falcon_complex_norm_sq(f_fft[i]) + falcon_complex_norm_sq(g_fft[i]);

            if(den <= 1e-18) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            k_fft[i].re = num.re / den;
            k_fft[i].im = num.im / den;
        }
        if(falcon_poly_inverse_fft_real(k_fft, n, k_real) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(i = 0U; i < n; i++) {
            k_poly[i] = falcon_round_to_i32(k_real[i]);
            if(k_poly[i] != 0) {
                any_nonzero = 1;
            }
        }
        if(!any_nonzero) {
            return NOXTLS_RETURN_SUCCESS;
        }

        {
            uint32_t shift;
            int improved = 0;

            for(shift = 0U; shift < 8U; shift++) {
                int step_nonzero = 0;
                int64_t after;

                for(i = 0U; i < n; i++) {
                    step_poly[i] = k_poly[i] / (int32_t)(1U << shift);
                    if(step_poly[i] != 0) {
                        step_nonzero = 1;
                    }
                }
                if(!step_nonzero) {
                    break;
                }

                rc = falcon_poly_mul_xn1_i32x64_checked(kf, step_poly, f, n);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    return rc;
                }
                rc = falcon_poly_mul_xn1_i32x64_checked(kg, step_poly, g, n);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    return rc;
                }
                for(i = 0U; i < n; i++) {
                    if(!falcon_checked_sub_i64(F[i], kf[i], &F_try[i]) ||
                       !falcon_checked_sub_i64(G[i], kg[i], &G_try[i])) {
                        return NOXTLS_RETURN_FAILED;
                    }
                }

                after = falcon_poly_maxabs_i64(F_try, n);
                if(falcon_poly_maxabs_i64(G_try, n) > after) {
                    after = falcon_poly_maxabs_i64(G_try, n);
                }
                if(after < before) {
                    memcpy(F, F_try, (size_t)n * sizeof(*F));
                    memcpy(G, G_try, (size_t)n * sizeof(*G));
                    improved = 1;
                    break;
                }
            }

            if(!improved) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        if(falcon_poly_maxabs_i64(F, n) >= before && falcon_poly_maxabs_i64(G, n) >= before) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Recursively solve and reduce the Falcon NTRU equation with signed 64-bit arithmetic.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a failure code if the widened
 *         recursive solve exceeds signed 64-bit arithmetic.
 */
static noxtls_return_t falcon_keygen_solve_ntru_reduced_i64(const int64_t *f,
                                                            const int64_t *g,
                                                            uint16_t n,
                                                            int64_t *F,
                                                            int64_t *G)
{
    if(n == 1U) {
        return falcon_keygen_solve_ntru_base_i64(f[0], g[0], F, G);
    } else {
        uint16_t half = (uint16_t)(n >> 1);
        int64_t fp[NOXTLS_FALCON_MAX_N];
        int64_t gp[NOXTLS_FALCON_MAX_N];
        int64_t Fp[NOXTLS_FALCON_MAX_N];
        int64_t Gp[NOXTLS_FALCON_MAX_N];
        noxtls_return_t rc;

        rc = falcon_keygen_field_norm_i64(f, n, fp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_field_norm_i64(g, n, gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_solve_ntru_reduced_i64(fp, gp, half, Fp, Gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_combine_from_child_i64_full(f, g, n, Fp, Gp, F, G);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return falcon_keygen_reduce_solution_i64(f, g, n, F, G);
    }
}

/**
 * @brief Reduce a signed-magnitude exact Falcon NTRU solution and cast it to signed 32 bits.
 *
 * This uses the same FFT-domain nearest-plane approximation as the 32-bit and 64-bit
 * reducers, but applies accepted correction steps exactly in signed-magnitude space.
 * The correction polynomial is currently bounded to signed 64-bit coefficients.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[in,out] F_mag Solution polynomial `F` magnitudes to reduce in place.
 * @param[in,out] F_negative Solution polynomial `F` sign flags to reduce in place.
 * @param[in,out] G_mag Solution polynomial `G` magnitudes to reduce in place.
 * @param[in,out] G_negative Solution polynomial `G` sign flags to reduce in place.
 * @param[in] coeff_len Width of each exact signed-magnitude coefficient.
 * @param[out] F Output reduced polynomial `F` in signed 32-bit form.
 * @param[out] G Output reduced polynomial `G` in signed 32-bit form.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on a bad degree, or `NOXTLS_RETURN_FAILED`
 *         if an exact correction or final cast fails.
 */
static noxtls_return_t falcon_keygen_reduce_solution_bn_to_i32(const int16_t *f,
                                                               const int16_t *g,
                                                               uint16_t n,
                                                               uint8_t *F_mag,
                                                               uint8_t *F_negative,
                                                               uint8_t *G_mag,
                                                               uint8_t *G_negative,
                                                               uint32_t coeff_len,
                                                               int32_t *F,
                                                               int32_t *G)
{
    double f_real[NOXTLS_FALCON_MAX_N];
    double g_real[NOXTLS_FALCON_MAX_N];
    double F_real[NOXTLS_FALCON_MAX_N];
    double G_real[NOXTLS_FALCON_MAX_N];
    double k_real[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t f_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t g_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t F_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t G_fft[NOXTLS_FALCON_MAX_N];
    noxtls_falcon_complex_t k_fft[NOXTLS_FALCON_MAX_N];
    int64_t k_poly[NOXTLS_FALCON_MAX_N];
    int64_t step_poly[NOXTLS_FALCON_MAX_N];
    uint8_t *f_mag;
    uint8_t *g_mag;
    uint8_t *f_negative;
    uint8_t *g_negative;
    uint8_t *k_mag;
    uint8_t *k_negative;
    uint8_t *kf_mag;
    uint8_t *kg_mag;
    uint8_t *kf_negative;
    uint8_t *kg_negative;
    uint8_t *F_try_mag;
    uint8_t *G_try_mag;
    uint8_t *F_try_negative;
    uint8_t *G_try_negative;
    uint8_t *before_max;
    uint8_t *after_max;
    uint32_t approx_shift_bits;
    uint32_t iter;
    uint16_t i;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(f == NULL || g == NULL || F_mag == NULL || F_negative == NULL ||
       G_mag == NULL || G_negative == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || !falcon_is_supported_power_of_two(n) || n > NOXTLS_FALCON_MAX_N || coeff_len < 4U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    f_mag = (uint8_t*)noxtls_calloc((size_t)n * 2U, 1U);
    g_mag = (uint8_t*)noxtls_calloc((size_t)n * 2U, 1U);
    f_negative = (uint8_t*)noxtls_calloc(n, 1U);
    g_negative = (uint8_t*)noxtls_calloc(n, 1U);
    k_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    k_negative = (uint8_t*)noxtls_calloc(n, 1U);
    kf_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    kg_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    kf_negative = (uint8_t*)noxtls_calloc(n, 1U);
    kg_negative = (uint8_t*)noxtls_calloc(n, 1U);
    F_try_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    G_try_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    F_try_negative = (uint8_t*)noxtls_calloc(n, 1U);
    G_try_negative = (uint8_t*)noxtls_calloc(n, 1U);
    before_max = (uint8_t*)noxtls_calloc(coeff_len, 1U);
    after_max = (uint8_t*)noxtls_calloc(coeff_len, 1U);
    if(f_mag == NULL || g_mag == NULL || f_negative == NULL || g_negative == NULL ||
       k_mag == NULL || k_negative == NULL || kf_mag == NULL || kg_mag == NULL ||
       kf_negative == NULL || kg_negative == NULL || F_try_mag == NULL || G_try_mag == NULL ||
       F_try_negative == NULL || G_try_negative == NULL || before_max == NULL || after_max == NULL) {
        goto cleanup;
    }

    rc = falcon_bn_poly_from_i16(f, n, f_mag, f_negative, 2U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_from_i16(g, n, g_mag, g_negative, 2U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    for(iter = 0U; iter < 1024U; iter++) {
        int any_nonzero = 0;
        uint64_t before_score;

        rc = falcon_bn_poly_pair_maxabs_copy(F_mag, G_mag, n, coeff_len, before_max);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
        approx_shift_bits = 0U;
        if(falcon_bn_bit_length(before_max, coeff_len) > 55u) {
            approx_shift_bits = (uint32_t)(falcon_bn_bit_length(before_max, coeff_len) - 55u);
        }
        before_score = falcon_bn_poly_pair_abs_score(F_mag, G_mag, n, coeff_len);
        for(i = 0U; i < n; i++) {
            f_real[i] = (double)f[i];
            g_real[i] = (double)g[i];
            F_real[i] = falcon_bn_signed_to_double_approx(F_mag + ((uint32_t)i * coeff_len),
                                                          F_negative[i],
                                                          coeff_len,
                                                          approx_shift_bits);
            G_real[i] = falcon_bn_signed_to_double_approx(G_mag + ((uint32_t)i * coeff_len),
                                                          G_negative[i],
                                                          coeff_len,
                                                          approx_shift_bits);
        }
        if(falcon_poly_forward_fft_real(f_real, n, f_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(g_real, n, g_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(F_real, n, F_fft) != NOXTLS_RETURN_SUCCESS ||
           falcon_poly_forward_fft_real(G_real, n, G_fft) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            goto cleanup;
        }
        for(i = 0U; i < n; i++) {
            noxtls_falcon_complex_t num = falcon_complex_add(
                falcon_complex_mul(F_fft[i], falcon_complex_conj(f_fft[i])),
                falcon_complex_mul(G_fft[i], falcon_complex_conj(g_fft[i])));
            double den = falcon_complex_norm_sq(f_fft[i]) + falcon_complex_norm_sq(g_fft[i]);

            if(den <= 1e-18) {
                rc = NOXTLS_RETURN_INVALID_PARAM;
                goto cleanup;
            }
            k_fft[i].re = num.re / den;
            k_fft[i].im = num.im / den;
        }
        if(falcon_poly_inverse_fft_real(k_fft, n, k_real) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            goto cleanup;
        }
        for(i = 0U; i < n; i++) {
            double rounded = nearbyint(k_real[i]);

            if(rounded < (double)INT64_MIN || rounded > (double)INT64_MAX) {
                rc = NOXTLS_RETURN_FAILED;
                goto cleanup;
            }
            k_poly[i] = (int64_t)rounded;
            if(k_poly[i] != 0) {
                any_nonzero = 1;
            }
        }
        if(!any_nonzero) {
            break;
        }

        {
            uint32_t shift;
            int improved = 0;

            for(shift = 0U; shift < 16U; shift++) {
                int step_nonzero = 0;

                for(i = 0U; i < n; i++) {
                    step_poly[i] = k_poly[i] / (int64_t)(1U << shift);
                    if(step_poly[i] != 0) {
                        step_nonzero = 1;
                    }
                }
                if(!step_nonzero) {
                    break;
                }

                rc = falcon_bn_poly_from_i64_shifted(step_poly,
                                                     n,
                                                     k_mag,
                                                     k_negative,
                                                     coeff_len,
                                                     approx_shift_bits);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    goto cleanup;
                }
                rc = falcon_bn_poly_mul_xn1_signed_to_len(k_mag,
                                                          k_negative,
                                                          coeff_len,
                                                          f_mag,
                                                          f_negative,
                                                          2U,
                                                          n,
                                                          kf_mag,
                                                          kf_negative,
                                                          coeff_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    goto cleanup;
                }
                rc = falcon_bn_poly_mul_xn1_signed_to_len(k_mag,
                                                          k_negative,
                                                          coeff_len,
                                                          g_mag,
                                                          g_negative,
                                                          2U,
                                                          n,
                                                          kg_mag,
                                                          kg_negative,
                                                          coeff_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    goto cleanup;
                }
                for(i = 0U; i < n; i++) {
                    rc = falcon_bn_signed_add_to_len(F_mag + ((uint32_t)i * coeff_len),
                                                     F_negative[i],
                                                     coeff_len,
                                                     kf_mag + ((uint32_t)i * coeff_len),
                                                     (uint8_t)(kf_negative[i] == 0U),
                                                     coeff_len,
                                                     F_try_mag + ((uint32_t)i * coeff_len),
                                                     &F_try_negative[i],
                                                     coeff_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        goto cleanup;
                    }
                    rc = falcon_bn_signed_add_to_len(G_mag + ((uint32_t)i * coeff_len),
                                                     G_negative[i],
                                                     coeff_len,
                                                     kg_mag + ((uint32_t)i * coeff_len),
                                                     (uint8_t)(kg_negative[i] == 0U),
                                                     coeff_len,
                                                     G_try_mag + ((uint32_t)i * coeff_len),
                                                     &G_try_negative[i],
                                                     coeff_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        goto cleanup;
                    }
                }
                rc = falcon_bn_poly_pair_maxabs_copy(F_try_mag, G_try_mag, n, coeff_len, after_max);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    goto cleanup;
                }
                {
                    int cmp = noxtls_bn_cmp(after_max, before_max, coeff_len);
                    uint64_t after_score = falcon_bn_poly_pair_abs_score(F_try_mag, G_try_mag, n, coeff_len);

                    if(cmp < 0 || (cmp == 0 && after_score < before_score)) {
                        rc = noxtls_bn_copy(F_mag, F_try_mag, (uint32_t)n * coeff_len);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            goto cleanup;
                        }
                        rc = noxtls_bn_copy(G_mag, G_try_mag, (uint32_t)n * coeff_len);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            goto cleanup;
                        }
                        memcpy(F_negative, F_try_negative, n);
                        memcpy(G_negative, G_try_negative, n);
                        improved = 1;
                        break;
                    }
                }
            }

            if(!improved) {
                break;
            }
        }
    }

    rc = falcon_bn_poly_to_i32_checked(F_mag, F_negative, n, coeff_len, F);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_bn_poly_to_i32_checked(G_mag, G_negative, n, coeff_len, G);

cleanup:
    if(f_mag != NULL) {
        noxtls_free(f_mag);
    }
    if(g_mag != NULL) {
        noxtls_free(g_mag);
    }
    if(f_negative != NULL) {
        noxtls_free(f_negative);
    }
    if(g_negative != NULL) {
        noxtls_free(g_negative);
    }
    if(k_mag != NULL) {
        noxtls_free(k_mag);
    }
    if(k_negative != NULL) {
        noxtls_free(k_negative);
    }
    if(kf_mag != NULL) {
        noxtls_free(kf_mag);
    }
    if(kg_mag != NULL) {
        noxtls_free(kg_mag);
    }
    if(kf_negative != NULL) {
        noxtls_free(kf_negative);
    }
    if(kg_negative != NULL) {
        noxtls_free(kg_negative);
    }
    if(F_try_mag != NULL) {
        noxtls_free(F_try_mag);
    }
    if(G_try_mag != NULL) {
        noxtls_free(G_try_mag);
    }
    if(F_try_negative != NULL) {
        noxtls_free(F_try_negative);
    }
    if(G_try_negative != NULL) {
        noxtls_free(G_try_negative);
    }
    if(before_max != NULL) {
        noxtls_free(before_max);
    }
    if(after_max != NULL) {
        noxtls_free(after_max);
    }
    return rc;
}

/**
 * @brief Recursively solve the exact Falcon NTRU equation on small degrees with 32-bit inputs.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_FAILED` on failure.
 */
static noxtls_return_t falcon_keygen_solve_ntru_exact_small_i32(const int32_t *f,
                                                                const int32_t *g,
                                                                uint16_t n,
                                                                int32_t *F,
                                                                int32_t *G)
{
    if(n == 1U) {
        return noxtls_falcon_keygen_solve_ntru_base(f[0], g[0], F, G);
    } else {
        uint16_t half = (uint16_t)(n >> 1);
        int32_t fp[NOXTLS_FALCON_MAX_N];
        int32_t gp[NOXTLS_FALCON_MAX_N];
        int32_t Fp[NOXTLS_FALCON_MAX_N];
        int32_t Gp[NOXTLS_FALCON_MAX_N];
        noxtls_return_t rc;

        rc = falcon_keygen_field_norm_i32(f, n, fp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_field_norm_i32(g, n, gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_solve_ntru_exact_small_i32(fp, gp, half, Fp, Gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return falcon_keygen_combine_from_child_i32(f, g, n, Fp, Gp, F, G);
    }
}

/**
 * @brief Recursively solve the exact Falcon NTRU equation on small power-of-two degrees.
 *
 * This clean-room validation path uses field norms, the exact `n = 1` base case,
 * and child-to-parent lifting without coefficient reduction. It is intentionally
 * bounded to small degrees that fit comfortably in signed 32-bit coefficients.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `16`.
 * @param[out] F Output polynomial `F` with signed 32-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact solution exists.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_exact_small(const int16_t *f,
                                                            const int16_t *g,
                                                            uint16_t n,
                                                            int32_t *F,
                                                            int32_t *G)
{
    int32_t fi[NOXTLS_FALCON_MAX_N];
    int32_t gi[NOXTLS_FALCON_MAX_N];
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > 16U || (n != 1U && !falcon_is_supported_power_of_two(n))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < n; i++) {
        fi[i] = f[i];
        gi[i] = g[i];
    }
    return falcon_keygen_solve_ntru_exact_small_i32(fi, gi, n, F, G);
}

/**
 * @brief Recursively solve the exact Falcon NTRU equation on bounded 64-bit inputs.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or an error if the exact checked
 *         arithmetic exceeds signed 64 bits.
 */
static noxtls_return_t falcon_keygen_solve_ntru_exact_i64(const int64_t *f,
                                                          const int64_t *g,
                                                          uint16_t n,
                                                          int64_t *F,
                                                          int64_t *G)
{
    if(n == 1U) {
        return falcon_keygen_solve_ntru_base_i64(f[0], g[0], F, G);
    } else {
        uint16_t half = (uint16_t)(n >> 1);
        int64_t fp[NOXTLS_FALCON_MAX_N];
        int64_t gp[NOXTLS_FALCON_MAX_N];
        int64_t Fp[NOXTLS_FALCON_MAX_N];
        int64_t Gp[NOXTLS_FALCON_MAX_N];
        noxtls_return_t rc;

        rc = falcon_keygen_field_norm_i64(f, n, fp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_field_norm_i64(g, n, gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_solve_ntru_exact_i64(fp, gp, half, Fp, Gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return falcon_keygen_combine_from_child_i64_full(f, g, n, Fp, Gp, F, G);
    }
}

/**
 * @brief Solve the exact Falcon NTRU equation with a widened 64-bit output substrate.
 *
 * This clean-room validation path extends the exact recursive norm/lift solve one
 * level beyond @ref noxtls_falcon_keygen_solve_ntru_exact_small by keeping the
 * parent-degree result in signed 64-bit coefficients. It is currently bounded to
 * supported power-of-two degrees no more than `512`.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `512`.
 * @param[out] F Output polynomial `F` with signed 64-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 64-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact solution exists.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_exact_wide(const int16_t *f,
                                                           const int16_t *g,
                                                           uint16_t n,
                                                           int64_t *F,
                                                           int64_t *G)
{
    int64_t fi[NOXTLS_FALCON_MAX_N];
    int64_t gi[NOXTLS_FALCON_MAX_N];
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > 512U || (n != 1U && !falcon_is_supported_power_of_two(n))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(n <= 16U) {
        int32_t F32[NOXTLS_FALCON_MAX_N];
        int32_t G32[NOXTLS_FALCON_MAX_N];
        noxtls_return_t rc = noxtls_falcon_keygen_solve_ntru_exact_small(f, g, n, F32, G32);

        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        for(i = 0U; i < n; i++) {
            F[i] = F32[i];
            G[i] = G32[i];
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    for(i = 0U; i < n; i++) {
        fi[i] = f[i];
        gi[i] = g[i];
    }
    return falcon_keygen_solve_ntru_exact_i64(fi, gi, n, F, G);
}

/**
 * @brief Reduce an exact small-degree Falcon NTRU solution by subtracting lattice multiples.
 *
 * This keeps the exact equation `fG - gF = q` unchanged while heuristically shrinking
 * `F` and `G` through FFT-based nearest-plane rounding. It is intended for the same
 * bounded validation degrees as @ref noxtls_falcon_keygen_solve_ntru_exact_small.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `16`.
 * @param[in,out] F Solution polynomial `F` to reduce in place.
 * @param[in,out] G Solution polynomial `G` to reduce in place.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree.
 */
noxtls_return_t noxtls_falcon_keygen_reduce_solution_small(const int16_t *f,
                                                           const int16_t *g,
                                                           uint16_t n,
                                                           int32_t *F,
                                                           int32_t *G)
{
    int32_t fi[NOXTLS_FALCON_MAX_N];
    int32_t gi[NOXTLS_FALCON_MAX_N];
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > 16U || (n != 1U && !falcon_is_supported_power_of_two(n))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(n == 1U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    for(i = 0U; i < n; i++) {
        fi[i] = f[i];
        gi[i] = g[i];
    }
    return falcon_keygen_reduce_solution_i32(fi, gi, n, F, G);
}

/**
 * @brief Recursively solve and reduce the Falcon NTRU equation with signed 32-bit arithmetic.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/failure code if the
 *         reduced validation path cannot keep the solution in signed 32 bits.
 */
static noxtls_return_t falcon_keygen_solve_ntru_reduced_i32(const int32_t *f,
                                                            const int32_t *g,
                                                            uint16_t n,
                                                            int32_t *F,
                                                            int32_t *G)
{
    if(n <= 16U) {
        return falcon_keygen_solve_ntru_exact_small_i32(f, g, n, F, G);
    }
    if(n == 1U) {
        return noxtls_falcon_keygen_solve_ntru_base(f[0], g[0], F, G);
    } else {
        uint16_t half = (uint16_t)(n >> 1);
        int32_t fp[NOXTLS_FALCON_MAX_N];
        int32_t gp[NOXTLS_FALCON_MAX_N];
        int32_t Fp[NOXTLS_FALCON_MAX_N];
        int32_t Gp[NOXTLS_FALCON_MAX_N];
        int32_t Fp_lift[NOXTLS_FALCON_MAX_N];
        int32_t Gp_lift[NOXTLS_FALCON_MAX_N];
        int32_t f_neg[NOXTLS_FALCON_MAX_N];
        int32_t g_neg[NOXTLS_FALCON_MAX_N];
        int64_t F64[NOXTLS_FALCON_MAX_N];
        int64_t G64[NOXTLS_FALCON_MAX_N];
        noxtls_return_t rc;

        rc = falcon_keygen_field_norm_i32(f, n, fp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_field_norm_i32(g, n, gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_keygen_solve_ntru_reduced_i32(fp, gp, half, Fp, Gp);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        falcon_keygen_lift_x2_i32(Fp, n, Fp_lift);
        falcon_keygen_lift_x2_i32(Gp, n, Gp_lift);
        falcon_keygen_apply_negx_i32(f, n, f_neg);
        falcon_keygen_apply_negx_i32(g, n, g_neg);
        falcon_poly_mul_xn1_i32x32_i64(F64, Fp_lift, g_neg, n);
        falcon_poly_mul_xn1_i32x32_i64(G64, Gp_lift, f_neg, n);
        rc = falcon_keygen_reduce_solution_i64_to_i32(f, g, n, F64, G64, F, G);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return NOXTLS_RETURN_SUCCESS;
    }
}

/**
 * @brief Recursively solve and reduce the Falcon NTRU equation on supported power-of-two degrees.
 *
 * This clean-room path exposes a general recursive norm/lift/reduce interface
 * that mirrors Falcon's `NTRUSolve` structure while still failing closed if
 * coefficient growth exceeds the signed 32-bit validation substrate.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two no more than
 *            `NOXTLS_FALCON_MAX_N`.
 * @param[out] F Output polynomial `F` with signed 32-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact reduced solution is found within the
 *         signed 32-bit validation path.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_reduced(const int16_t *f,
                                                        const int16_t *g,
                                                        uint16_t n,
                                                        int32_t *F,
                                                        int32_t *G)
{
    uint8_t *F_bn_mag = NULL;
    uint8_t *G_bn_mag = NULL;
    uint8_t *F_bn_negative = NULL;
    uint8_t *G_bn_negative = NULL;
    int64_t F64[NOXTLS_FALCON_MAX_N];
    int64_t G64[NOXTLS_FALCON_MAX_N];
    int32_t fi[NOXTLS_FALCON_MAX_N];
    int32_t gi[NOXTLS_FALCON_MAX_N];
    int64_t fi64[NOXTLS_FALCON_MAX_N];
    int64_t gi64[NOXTLS_FALCON_MAX_N];
    uint32_t coeff_len;
    noxtls_return_t rc;
    uint16_t i;

    if(f == NULL || g == NULL || F == NULL || G == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 0U || n > NOXTLS_FALCON_MAX_N || (n != 1U && !falcon_is_supported_power_of_two(n))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(n <= 16U) {
        rc = noxtls_falcon_keygen_solve_ntru_exact_small(f, g, n, F, G);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return noxtls_falcon_keygen_reduce_solution_small(f, g, n, F, G);
    }
    if(n <= 128U) {
        for(i = 0U; i < n; i++) {
            fi[i] = f[i];
            gi[i] = g[i];
            fi64[i] = f[i];
            gi64[i] = g[i];
        }
        rc = falcon_keygen_solve_ntru_reduced_i64(fi64, gi64, n, F64, G64);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return falcon_keygen_reduce_solution_i64_to_i32(fi, gi, n, F64, G64, F, G);
    }
    coeff_len = (n == 256u) ? 1524u : 3059u;
    F_bn_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    G_bn_mag = (uint8_t*)noxtls_calloc((size_t)n * coeff_len, 1U);
    F_bn_negative = (uint8_t*)noxtls_calloc(n, 1U);
    G_bn_negative = (uint8_t*)noxtls_calloc(n, 1U);
    if(F_bn_mag == NULL || G_bn_mag == NULL || F_bn_negative == NULL || G_bn_negative == NULL) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }
    {
        uint8_t *f_mag;
        uint8_t *g_mag;
        uint8_t *f_negative;
        uint8_t *g_negative;

        f_mag = (uint8_t*)noxtls_calloc((size_t)n * 2U, 1U);
        g_mag = (uint8_t*)noxtls_calloc((size_t)n * 2U, 1U);
        f_negative = (uint8_t*)noxtls_calloc(n, 1U);
        g_negative = (uint8_t*)noxtls_calloc(n, 1U);
        if(f_mag == NULL || g_mag == NULL || f_negative == NULL || g_negative == NULL) {
            if(f_mag != NULL) {
                noxtls_free(f_mag);
            }
            if(g_mag != NULL) {
                noxtls_free(g_mag);
            }
            if(f_negative != NULL) {
                noxtls_free(f_negative);
            }
            if(g_negative != NULL) {
                noxtls_free(g_negative);
            }
            rc = NOXTLS_RETURN_FAILED;
            goto cleanup;
        }
        rc = falcon_bn_poly_from_i16(f, n, f_mag, f_negative, 2U);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = falcon_bn_poly_from_i16(g, n, g_mag, g_negative, 2U);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(n == 256u) {
                rc = noxtls_falcon_keygen_solve_ntru_bn_n256(f_mag,
                                                             f_negative,
                                                             g_mag,
                                                             g_negative,
                                                             2U,
                                                             F_bn_mag,
                                                             F_bn_negative,
                                                             G_bn_mag,
                                                             G_bn_negative,
                                                             coeff_len);
            } else {
                rc = noxtls_falcon_keygen_solve_ntru_bn_n512(f_mag,
                                                             f_negative,
                                                             g_mag,
                                                             g_negative,
                                                             2U,
                                                             F_bn_mag,
                                                             F_bn_negative,
                                                             G_bn_mag,
                                                             G_bn_negative,
                                                             coeff_len);
            }
        }
        noxtls_free(f_mag);
        noxtls_free(g_mag);
        noxtls_free(f_negative);
        noxtls_free(g_negative);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }
    rc = falcon_keygen_reduce_solution_bn_to_i32(f,
                                                 g,
                                                 n,
                                                 F_bn_mag,
                                                 F_bn_negative,
                                                 G_bn_mag,
                                                 G_bn_negative,
                                                 coeff_len,
                                                 F,
                                                 G);

cleanup:
    if(F_bn_mag != NULL) {
        noxtls_free(F_bn_mag);
    }
    if(G_bn_mag != NULL) {
        noxtls_free(G_bn_mag);
    }
    if(F_bn_negative != NULL) {
        noxtls_free(F_bn_negative);
    }
    if(G_bn_negative != NULL) {
        noxtls_free(G_bn_negative);
    }
    return rc;
}

/**
 * @brief Compute the extended GCD of two signed 32-bit integers.
 *
 * @param[in] a First integer.
 * @param[in] b Second integer.
 * @param[out] x Bézout coefficient for `a`.
 * @param[out] y Bézout coefficient for `b`.
 * @return Non-negative greatest common divisor.
 */
/**
 * @brief Return the maximum absolute coefficient in a signed 32-bit polynomial.
 *
 * @param[in] poly Input polynomial.
 * @param[in] n Polynomial degree.
 * @return Maximum absolute coefficient.
 */
/**
 * @brief Reduce a small NTRU solution `(F, G)` against `(f, g)` with FFT-based rounding.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[in,out] F First solution polynomial to reduce.
 * @param[in,out] G Second solution polynomial to reduce.
 */
/**
 * @brief Recursively solve the Falcon NTRU equation on small degrees with 32-bit coefficients.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_FAILED` on failure.
 */
/**
 * @brief Solve the Falcon NTRU equation exactly for small power-of-two degrees.
 *
 * This implements the recursive norm/lift/reduce structure of Falcon's
 * `NTRUSolve` for small degrees that fit comfortably in 32-bit signed
 * coefficients. It is intended as a clean-room validation step toward the
 * full big-integer/RNS key-generation path.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `16`.
 * @param[out] F Output polynomial `F`.
 * @param[out] G Output polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if the NTRU equation has no valid solution.
 */
/**
 * @brief Recursively sample a Falcon FFT target vector from a normalized LDL tree.
 *
 * The flattened tree layout is `[L, T0, T1]`, where `T0` is the left subtree and
 * `T1` is the right subtree. The sampler consumes the right subtree first, then
 * folds the result through `L` before recursing on the left subtree.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] tree Normalized Falcon LDL tree for the current subtree.
 * @param[in] t0 First FFT-domain target for the current subtree.
 * @param[in] t1 Second FFT-domain target for the current subtree.
 * @param[in] n Current subtree degree.
 * @param[out] z0 Output sampled FFT-domain vector for the first component.
 * @param[out] z1 Output sampled FFT-domain vector for the second component.
 * @param[in,out] scratch Scratch buffer of at least `4*n - 4` complex values for the top-level call.
 * @param[in] scratch_len Number of complex entries available in `scratch`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized scratch buffer,
 *         or a numerical/sampler error code.
 */
static noxtls_return_t falcon_sample_fft_tree_inner(noxtls_falcon_sampler_ctx_t *ctx,
                                                    const noxtls_falcon_complex_t *tree,
                                                    const noxtls_falcon_complex_t *t0,
                                                    const noxtls_falcon_complex_t *t1,
                                                    uint16_t n,
                                                    noxtls_falcon_complex_t *z0,
                                                    noxtls_falcon_complex_t *z1,
                                                    noxtls_falcon_complex_t *scratch,
                                                    uint32_t scratch_len)
{
    uint16_t half;
    uint16_t i;
    uint32_t child_len;
    noxtls_falcon_complex_t *split0;
    noxtls_falcon_complex_t *split1;
    noxtls_falcon_complex_t *tb0;
    noxtls_return_t rc;

    if(ctx == NULL || tree == NULL || t0 == NULL || t1 == NULL || z0 == NULL || z1 == NULL || scratch == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n == 1U) {
        int32_t s0;
        int32_t s1;

        if(falcon_abs_double(tree[0].im) > 1e-7 ||
           falcon_abs_double(t0[0].im) > 1e-7 ||
           falcon_abs_double(t1[0].im) > 1e-7) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_falcon_sampler_z(ctx, t0[0].re, tree[0].re, &s0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_falcon_sampler_z(ctx, t1[0].re, tree[0].re, &s1);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        z0[0].re = (double)s0;
        z0[0].im = 0.0;
        z1[0].re = (double)s1;
        z1[0].im = 0.0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(scratch_len < ((uint32_t)(n << 1))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half = (uint16_t)(n >> 1);
    child_len = noxtls_falcon_ldl_tree_complex_len(half);
    split0 = scratch;
    split1 = scratch + half;
    tb0 = scratch + n;

    rc = falcon_split_fft_complex(t1, n, split0, split1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_sample_fft_tree_inner(ctx, tree + n + child_len, split0, split1, half,
                                      split0, split1, tb0, scratch_len - (uint32_t)(n << 1));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_merge_fft_complex(split0, split1, n, z1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < n; i++) {
        tb0[i] = falcon_complex_add(t0[i], falcon_complex_mul(falcon_complex_sub(t1[i], z1[i]), tree[i]));
    }

    rc = falcon_split_fft_complex(tb0, n, split0, split1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = falcon_sample_fft_tree_inner(ctx, tree + n, split0, split1, half,
                                      split0, split1, tb0, scratch_len - (uint32_t)(n << 1));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return falcon_merge_fft_complex(split0, split1, n, z0);
}

/**
 * @brief Sample an FFT-domain Falcon vector from a normalized LDL tree and FFT targets.
 *
 * The inputs `t0` and `t1` are FFT-domain targets. The outputs `z0` and `z1`
 * are FFT-domain sampled vectors corresponding to real integer coefficient polynomials.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] tree Normalized Falcon LDL tree.
 * @param[in] t0 First FFT-domain target.
 * @param[in] t1 Second FFT-domain target.
 * @param[in] n Polynomial degree.
 * @param[out] z0 Output sampled FFT-domain vector for the first component.
 * @param[out] z1 Output sampled FFT-domain vector for the second component.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size, or a sampler/numerical error code.
 */
noxtls_return_t noxtls_falcon_sample_fft_tree(noxtls_falcon_sampler_ctx_t *ctx,
                                              const noxtls_falcon_complex_t *tree,
                                              const noxtls_falcon_complex_t *t0,
                                              const noxtls_falcon_complex_t *t1,
                                              uint16_t n,
                                              noxtls_falcon_complex_t *z0,
                                              noxtls_falcon_complex_t *z1)
{
    noxtls_falcon_complex_t scratch[NOXTLS_FALCON_MAX_N * 4U];

    if(ctx == NULL || tree == NULL || t0 == NULL || t1 == NULL || z0 == NULL || z1 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(n != 1U && !falcon_is_supported_power_of_two(n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return falcon_sample_fft_tree_inner(ctx, tree, t0, t1, n, z0, z1, scratch, (uint32_t)(n << 2));
}

/**
 * @brief Compute a Falcon public polynomial from secret polynomials `f` and `g`.
 *
 * This computes `h = g / f mod (x^n + 1, q)` for a supported Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[out] h Output public polynomial coefficients modulo `q`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if `f` is not invertible in the Falcon ring.
 */
noxtls_return_t noxtls_falcon_compute_public(noxtls_falcon_param_t param,
                                             const int16_t *f,
                                             const int16_t *g,
                                             uint16_t *h)
{
    noxtls_falcon_param_spec_t spec;
    uint16_t f_mod[NOXTLS_FALCON_MAX_N];
    uint16_t g_mod[NOXTLS_FALCON_MAX_N];
    uint16_t f_inv[NOXTLS_FALCON_MAX_N];
    uint16_t i;
    noxtls_return_t rc;

    if(f == NULL || g == NULL || h == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        f_mod[i] = noxtls_falcon_mod_q_reduce_i32(f[i]);
        g_mod[i] = noxtls_falcon_mod_q_reduce_i32(g[i]);
    }

    rc = falcon_poly_invert_xn1_mod_q(f_inv, f_mod, spec.n);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    falcon_poly_mul_xn1_mod_q(h, g_mod, spec.n, f_inv, spec.n, spec.n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive and encode a Falcon public key from a serialized Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] secret_key_len Length of `secret_key` in bytes.
 * @param[out] public_key Output buffer for the serialized public key.
 * @param[in] public_key_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the secret key is malformed or mathematically invalid.
 */
noxtls_return_t noxtls_falcon_derive_public_key_from_secret_key(noxtls_falcon_param_t param,
                                                                const uint8_t *secret_key,
                                                                uint32_t secret_key_len,
                                                                uint8_t *public_key,
                                                                uint32_t public_key_len)
{
    int16_t f[NOXTLS_FALCON_MAX_N];
    int16_t g[NOXTLS_FALCON_MAX_N];
    int16_t F[NOXTLS_FALCON_MAX_N];
    int16_t G[NOXTLS_FALCON_MAX_N];
    uint16_t h[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    rc = noxtls_falcon_decode_private_key(param, secret_key, secret_key_len, f, g, F);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_falcon_complete_private_key(param, f, g, F, G);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_falcon_compute_public(param, f, g, h);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return noxtls_falcon_encode_public_key(param, h, public_key, public_key_len);
}

/**
 * @brief Build serialized Falcon secret and public keys from secret polynomials.
 *
 * This validates the secret triple `(f, g, F)` by reconstructing the missing
 * `G`, derives the public polynomial `h`, then emits the serialized secret and
 * public key encodings for the selected parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] secret_key Output serialized Falcon secret key.
 * @param[in] secret_key_len Exact output length in bytes.
 * @param[out] public_key Output serialized Falcon public key.
 * @param[in] public_key_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the secret polynomials are malformed or
 *         mathematically invalid.
 */
noxtls_return_t noxtls_falcon_build_keypair_from_secret_components(noxtls_falcon_param_t param,
                                                                   const int16_t *f,
                                                                   const int16_t *g,
                                                                   const int16_t *F,
                                                                   uint8_t *secret_key,
                                                                   uint32_t secret_key_len,
                                                                   uint8_t *public_key,
                                                                   uint32_t public_key_len)
{
    noxtls_falcon_param_spec_t spec;
    int16_t G[NOXTLS_FALCON_MAX_N];
    uint16_t h[NOXTLS_FALCON_MAX_N];
    noxtls_return_t rc;

    if(f == NULL || g == NULL || F == NULL || secret_key == NULL || public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(secret_key_len != spec.secret_key_len || public_key_len != spec.public_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    rc = noxtls_falcon_complete_private_key(param, f, g, F, G);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_falcon_compute_public(param, f, g, h);
    if(rc == NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_falcon_encode_private_key(param, f, g, F, secret_key, secret_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_falcon_encode_public_key(param, h, public_key, public_key_len);
}

/**
 * @brief Serialize a Falcon public key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] h Public-key polynomial coefficients modulo `q`.
 * @param[out] encoded Output buffer for the serialized key.
 * @param[in] encoded_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_encode_public_key(noxtls_falcon_param_t param,
                                                const uint16_t *h,
                                                uint8_t *encoded,
                                                uint32_t encoded_len)
{
    noxtls_falcon_param_spec_t spec;
    falcon_bit_writer_t bw;
    uint32_t i;
    noxtls_return_t rc;

    if(h == NULL || encoded == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(encoded_len != spec.public_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    encoded[0] = (uint8_t)(NOXTLS_FALCON_PUBLIC_KEY_HDR | spec.logn);
    rc = falcon_bit_writer_init(&bw, encoded + 1U, encoded_len - 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
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

/**
 * @brief Parse a serialized Falcon public key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] encoded Serialized key bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] h Output public-key polynomial coefficients modulo `q`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_decode_public_key(noxtls_falcon_param_t param,
                                                const uint8_t *encoded,
                                                uint32_t encoded_len,
                                                uint16_t *h)
{
    noxtls_falcon_param_spec_t spec;
    falcon_bit_reader_t br;
    uint32_t i;
    uint32_t value;
    noxtls_return_t rc;

    if(encoded == NULL || h == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(encoded_len != spec.public_key_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if((encoded[0] & 0xF0u) != NOXTLS_FALCON_PUBLIC_KEY_HDR || (encoded[0] & 0x0Fu) != spec.logn) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    rc = falcon_bit_reader_init(&br, encoded + 1U, encoded_len - 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        rc = falcon_bit_read(&br, 14U, &value);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(value >= NOXTLS_FALCON_Q) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        h[i] = (uint16_t)value;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Serialize the `f`, `g`, and `F` polynomials of a Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret-key polynomial `f`.
 * @param[in] g Secret-key polynomial `g`.
 * @param[in] F Secret-key polynomial `F`.
 * @param[out] encoded Output buffer for the serialized key.
 * @param[in] encoded_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_encode_private_key(noxtls_falcon_param_t param,
                                                 const int16_t *f,
                                                 const int16_t *g,
                                                 const int16_t *F,
                                                 uint8_t *encoded,
                                                 uint32_t encoded_len)
{
    noxtls_falcon_param_spec_t spec;
    falcon_bit_writer_t bw;
    uint32_t i;
    noxtls_return_t rc;

    if(f == NULL || g == NULL || F == NULL || encoded == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(encoded_len != spec.secret_key_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    encoded[0] = (uint8_t)(NOXTLS_FALCON_PRIVATE_KEY_HDR | spec.logn);
    rc = falcon_bit_writer_init(&bw, encoded + 1U, encoded_len - 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        rc = falcon_encode_signed_bits(&bw, f[i], spec.fg_bits);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0U; i < spec.n; i++) {
        rc = falcon_encode_signed_bits(&bw, g[i], spec.fg_bits);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0U; i < spec.n; i++) {
        rc = falcon_encode_signed_bits(&bw, F[i], spec.F_bits);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse the `f`, `g`, and `F` polynomials from a serialized Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] encoded Serialized key bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] f Output polynomial `f`.
 * @param[out] g Output polynomial `g`.
 * @param[out] F Output polynomial `F`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_decode_private_key(noxtls_falcon_param_t param,
                                                 const uint8_t *encoded,
                                                 uint32_t encoded_len,
                                                 int16_t *f,
                                                 int16_t *g,
                                                 int16_t *F)
{
    noxtls_falcon_param_spec_t spec;
    falcon_bit_reader_t br;
    uint32_t i;
    noxtls_return_t rc;

    if(encoded == NULL || f == NULL || g == NULL || F == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_falcon_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(encoded_len != spec.secret_key_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if((encoded[0] & 0xF0u) != NOXTLS_FALCON_PRIVATE_KEY_HDR || (encoded[0] & 0x0Fu) != spec.logn) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    rc = falcon_bit_reader_init(&br, encoded + 1U, encoded_len - 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < spec.n; i++) {
        rc = falcon_decode_signed_bits(&br, spec.fg_bits, &f[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0U; i < spec.n; i++) {
        rc = falcon_decode_signed_bits(&br, spec.fg_bits, &g[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    for(i = 0U; i < spec.n; i++) {
        rc = falcon_decode_signed_bits(&br, spec.F_bits, &F[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Serialize a Falcon `s2` signature vector in compressed form.
 *
 * @param[in] s2 Signed coefficients to encode.
 * @param[in] coeff_count Number of coefficients in `s2`.
 * @param[out] encoded Output byte buffer.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_comp_encode(const int16_t *s2,
                                          uint32_t coeff_count,
                                          uint8_t *encoded,
                                          uint32_t encoded_len)
{
    falcon_bit_writer_t bw;
    uint32_t i;
    noxtls_return_t rc;

    if(s2 == NULL || encoded == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = falcon_bit_writer_init(&bw, encoded, encoded_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < coeff_count; i++) {
        int32_t value = s2[i];
        uint32_t mag = (uint32_t)(value < 0 ? -value : value);
        uint32_t unary_zeros;

        rc = falcon_bit_write(&bw, (value < 0) ? 1U : 0U, 1U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_bit_write(&bw, mag & 0x7Fu, 7U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        unary_zeros = mag >> 7;
        while(unary_zeros > 0U) {
            rc = falcon_bit_write(&bw, 0U, 1U);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            unary_zeros--;
        }
        rc = falcon_bit_write(&bw, 1U, 1U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return falcon_bit_writer_pad_zero(&bw);
}

/**
 * @brief Parse a compressed Falcon `s2` signature vector.
 *
 * @param[in] encoded Serialized bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] s2 Output signed coefficients.
 * @param[in] coeff_count Number of coefficients to decode.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_comp_decode(const uint8_t *encoded,
                                          uint32_t encoded_len,
                                          int16_t *s2,
                                          uint32_t coeff_count)
{
    falcon_bit_reader_t br;
    uint32_t i;
    noxtls_return_t rc;

    if(encoded == NULL || s2 == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = falcon_bit_reader_init(&br, encoded, encoded_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0U; i < coeff_count; i++) {
        uint32_t sign;
        uint32_t low;
        uint32_t stop;
        uint32_t high = 0U;
        uint32_t mag;

        rc = falcon_bit_read(&br, 1U, &sign);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = falcon_bit_read(&br, 7U, &low);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        do {
            rc = falcon_bit_read(&br, 1U, &stop);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(stop == 0U) {
                high++;
            }
        } while(stop == 0U);

        if(high > 255u) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        mag = (high << 7) | low;
        if(sign != 0U && mag == 0U) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(mag > 32767u) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        s2[i] = (int16_t)(sign != 0U ? -(int32_t)mag : (int32_t)mag);
    }

    return falcon_bit_reader_check_tail_zero(&br);
}
