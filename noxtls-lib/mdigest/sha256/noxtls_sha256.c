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
* File:    noxtls_sha256.c
* Summary: SHA-256 Hash Implementation
* Based on FIPS 180-4
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

static const uint8_t s_u8txt_noxtls_sha256_82[] = { (uint8_t)'S', (uint8_t)'W', (uint8_t)'-', (uint8_t)'C', 0 };


#include "noxtls_common.h"
#include "common/noxtls_accel_port.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha256_accel_port.h"
#include "noxtls_sha256.h"
#include "noxtls_sha256_backend.h"
#include "noxtls_ct.h"

#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)

#ifndef NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
#define NOXTLS_FEATURE_STM32_HW_SHA256_ONLY 0
#endif
#ifndef NOXTLS_FEATURE_SHA256_CORTEXM7
#define NOXTLS_FEATURE_SHA256_CORTEXM7 0
#endif
#ifndef NOXTLS_SHA256_UNROLL_8
#define NOXTLS_SHA256_UNROLL_8 1
#endif
#if NOXTLS_FEATURE_SHA256_CORTEXM7 && (defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__))
#define NOXTLS_SHA256_CORTEXM7_AVAILABLE 1
#else
#define NOXTLS_SHA256_CORTEXM7_AVAILABLE 0
#endif

/* Module Debug Level */
static uint8_t sha256_debug_lvl = 0U;

/* SHA-256 Operations */
#define SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define SHA_ROTR(X, N)      (((X) >> (N)) | ((X) << (32U - (N))))
#define SHA_SUM_FROM_0(X)   (SHA_ROTR((X), 2U)  ^ SHA_ROTR((X), 13U) ^ SHA_ROTR((X), 22U))
#define SHA_SUM_FROM_1(X)   (SHA_ROTR((X), 6U)  ^ SHA_ROTR((X), 11U) ^ SHA_ROTR((X), 25U))
#define SHA_SIGMA_FROM_0(X) (SHA_ROTR((X), 7U)  ^ SHA_ROTR((X), 18U) ^ ((X) >> 3U))
#define SHA_SIGMA_FROM_1(X) (SHA_ROTR((X), 17U) ^ SHA_ROTR((X), 19U) ^ ((X) >> 10U))

static noxtls_return_t noxtls_sha256_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);
static noxtls_return_t noxtls_sha256_round_software(noxtls_sha_ctx_t * ctx, const uint8_t * input);
static noxtls_return_t noxtls_sha256_blocks_software(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t block_count);
static noxtls_return_t noxtls_sha256_pad(const uint8_t * data, uint32_t zero_pad, uint32_t len);

#if NOXTLS_SHA256_CORTEXM7_AVAILABLE
static uint8_t s_sha256_cortexm7_enabled = 1U;
#endif

static const uint8_t s_u8txt_sha256_sw_m7[] = { (uint8_t)'S', (uint8_t)'W', (uint8_t)'-', (uint8_t)'M', (uint8_t)'7', 0 };

const uint8_t *noxtls_sha256_backend_name(void)
{
#if NOXTLS_SHA256_CORTEXM7_AVAILABLE
    if (s_sha256_cortexm7_enabled != 0U) {
        return s_u8txt_sha256_sw_m7;
    }
#endif
    return s_u8txt_noxtls_sha256_82;
}

uint8_t noxtls_sha256_backend_is_cortexm7(void)
{
#if NOXTLS_SHA256_CORTEXM7_AVAILABLE
    return s_sha256_cortexm7_enabled;
#else
    return 0U;
#endif
}

void noxtls_sha256_backend_set_cortexm7_enabled(uint8_t enabled)
{
#if NOXTLS_SHA256_CORTEXM7_AVAILABLE
    s_sha256_cortexm7_enabled = (enabled != 0U) ? 1U : 0U;
#else
    (void)enabled;
#endif
}

/**
 * @brief Set the debug level
 * 
 * @param lvl The debug level
 * @return void
 */
void noxtls_sha256_set_debug(uint8_t lvl)
{
    sha256_debug_lvl = lvl;
}

/**
 * @brief Initialize SHA-256
 * 
 * @param ctx SHA-256 context
 * @param algo Algorithm to use
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha256_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if (ctx->algo == NOXTLS_HASH_SHA_256) {
        ctx->h[0] = 0x6a09e667U;
        ctx->h[1] = 0xbb67ae85U;
        ctx->h[2] = 0x3c6ef372U;
        ctx->h[3] = 0xa54ff53aU;
        ctx->h[4] = 0x510e527fU;
        ctx->h[5] = 0x9b05688cU;
        ctx->h[6] = 0x1f83d9abU;
        ctx->h[7] = 0x5be0cd19U;
    }
    else if (ctx->algo == NOXTLS_HASH_SHA_224)
    {
        ctx->h[0] = 0xc1059ed8U;
        ctx->h[1] = 0x367cd507U;
        ctx->h[2] = 0x3070dd17U;
        ctx->h[3] = 0xf70e5939U;
        ctx->h[4] = 0xffc00b31U;
        ctx->h[5] = 0x68581511U;
        ctx->h[6] = 0x64f98fa7U;
        ctx->h[7] = 0xbefa4fa4U;
    }
    else
    {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    noxtls_secure_zero((&ctx->data), (size_t)(SHA256_BLOCK_SIZE_BYTES));
    ctx->data_len = 0U;
    ctx->length = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */
/** 
 * @brief Update SHA-256
 * 
 * @param ctx SHA-256 context
 * @param data Data to update
 * @param len Length of data to update
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha256_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    uint32_t offset = 0U;
    uint32_t in_left = len;

    /* Fill existing buffer if present */
    if (ctx->data_len > 0U) {
        uint32_t to_copy = SHA256_BLOCK_SIZE_BYTES;
        to_copy -= (uint32_t)ctx->data_len;
        if (to_copy > in_left) {
            to_copy = in_left;
        }
        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), data, (size_t)to_copy);
        ctx->data_len = (uint8_t)(ctx->data_len + to_copy);
        offset += to_copy;
        in_left -= to_copy;
        if (ctx->data_len == SHA256_BLOCK_SIZE_BYTES) {
            noxtls_return_t rc = noxtls_sha256_round(ctx, ctx->data);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += SHA256_BLOCK_SIZE_BYTES;
            ctx->data_len = 0U;
        }
    }

    /* Process full blocks directly from data */
    if (in_left >= SHA256_BLOCK_SIZE_BYTES) {
        uint32_t full_blocks = (uint32_t)(in_left / SHA256_BLOCK_SIZE_BYTES);
        uint32_t full_bytes = (uint32_t)(full_blocks * SHA256_BLOCK_SIZE_BYTES);
        noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

#if (defined(NOXTLS_FEATURE_HASH_ACCEL_STM32) && (NOXTLS_FEATURE_HASH_ACCEL_STM32)) || NOXTLS_PORT_SHA256_ACCEL || NOXTLS_FEATURE_NOXV_HW_ACCEL
        rc = noxtls_sha256_blocks_accel_port(ctx, &data[offset], full_blocks);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            ctx->length += full_bytes;
            offset += full_bytes;
            in_left -= full_bytes;
        } else
#endif
        {
#if NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
            return rc;
#else
            rc = noxtls_sha256_blocks_software(ctx, &data[offset], full_blocks);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += full_bytes;
            offset += full_bytes;
            in_left -= full_bytes;
#endif
        }
    }

    /* Store remainder */
    if (in_left > 0U) {
        noxtls_copy_u8(ctx->data, sizeof(ctx->data), &data[offset], (size_t)in_left);
        ctx->data_len = (uint8_t)in_left;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Accepts only 512-bit input data */
/** 
 * @brief SHA-256 round
 * 
 * @param ctx SHA-256 context
 * @param data Data to round
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
static noxtls_return_t noxtls_sha256_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	if ((ctx == NULL) || (input == NULL)) {
		return NOXTLS_RETURN_NULL;
	}

#if (defined(NOXTLS_FEATURE_HASH_ACCEL_STM32) && (NOXTLS_FEATURE_HASH_ACCEL_STM32)) || NOXTLS_PORT_SHA256_ACCEL || NOXTLS_FEATURE_NOXV_HW_ACCEL
    {
        noxtls_return_t rc = noxtls_sha256_blocks_accel_port(ctx, input, 1U);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_round_accel_port(ctx, input);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
#if NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
        return rc;
#endif
    }
#elif NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
#if !NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
    return noxtls_sha256_round_software(ctx, input);
#endif
}

static noxtls_return_t noxtls_sha256_round_software(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
    /* SHA-224/256 K constants (block scope for MISRA 8.9). */
    /* SHA-224 / SHA-256 round constants K[0..63] (FIPS 180-4); count matches SHA256_ROUND_COUNT. */
    static const uint32_t sha224_256_k[SHA256_ROUND_COUNT] =
    {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

	uint32_t t = 0U;
	uint32_t w[SHA256_WORDS_PER_BLOCK];

    uint32_t a = 0U;
    uint32_t b = 0U;
    uint32_t c = 0U;
    uint32_t d = 0U;
    uint32_t e = 0U;
    uint32_t f = 0U;
    uint32_t g = 0U;
    uint32_t h = 0U;
    
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    if (input == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* Copy the noxtls_message to the first 16 words */    
    for (t = 0U; t < SHA256_WORDS_PER_BLOCK; t += 1U) {
        size_t in_off = (size_t)t * (size_t)SHA256_WORD_BYTES;
        w[t] =
            ((uint32_t)input[in_off] <<24U) |
            ((uint32_t)input[in_off + 1U] <<16U) |
            ((uint32_t)input[in_off + 2U] <<8U) |
            ((uint32_t)input[in_off + 3U]);
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];
    
#if NOXTLS_SHA256_UNROLL_8
    for (t = 0U; t < SHA256_ROUND_COUNT; t += 8U)
    {
        uint32_t wt0 = 0U;
        uint32_t wt1 = 0U;
        uint32_t wt2 = 0U;
        uint32_t wt3 = 0U;
        uint32_t wt4 = 0U;
        uint32_t wt5 = 0U;
        uint32_t wt6 = 0U;
        uint32_t wt7 = 0U;

        if (t < SHA256_WORDS_PER_BLOCK) {
            wt0 = w[(t + 0U) & 0x0FU];
            wt1 = w[(t + 1U) & 0x0FU];
            wt2 = w[(t + 2U) & 0x0FU];
            wt3 = w[(t + 3U) & 0x0FU];
            wt4 = w[(t + 4U) & 0x0FU];
            wt5 = w[(t + 5U) & 0x0FU];
            wt6 = w[(t + 6U) & 0x0FU];
            wt7 = w[(t + 7U) & 0x0FU];
        } else {
            wt0 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t - 2U) & 0x0FU]) + w[(t - 7U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 15U) & 0x0FU]) + w[(t + 0U) & 0x0FU]);
            w[(t + 0U) & 0x0FU] = wt0;
            wt1 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t - 1U) & 0x0FU]) + w[(t - 6U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 14U) & 0x0FU]) + w[(t + 1U) & 0x0FU]);
            w[(t + 1U) & 0x0FU] = wt1;
            wt2 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 0U) & 0x0FU]) + w[(t - 5U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 13U) & 0x0FU]) + w[(t + 2U) & 0x0FU]);
            w[(t + 2U) & 0x0FU] = wt2;
            wt3 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 1U) & 0x0FU]) + w[(t - 4U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 12U) & 0x0FU]) + w[(t + 3U) & 0x0FU]);
            w[(t + 3U) & 0x0FU] = wt3;
            wt4 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 2U) & 0x0FU]) + w[(t - 3U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 11U) & 0x0FU]) + w[(t + 4U) & 0x0FU]);
            w[(t + 4U) & 0x0FU] = wt4;
            wt5 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 3U) & 0x0FU]) + w[(t - 2U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 10U) & 0x0FU]) + w[(t + 5U) & 0x0FU]);
            w[(t + 5U) & 0x0FU] = wt5;
            wt6 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 4U) & 0x0FU]) + w[(t - 1U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 9U) & 0x0FU]) + w[(t + 6U) & 0x0FU]);
            w[(t + 6U) & 0x0FU] = wt6;
            wt7 = (uint32_t)(SHA_SIGMA_FROM_1(w[(t + 5U) & 0x0FU]) + w[(t + 0U) & 0x0FU] +
                  SHA_SIGMA_FROM_0(w[(t - 8U) & 0x0FU]) + w[(t + 7U) & 0x0FU]);
            w[(t + 7U) & 0x0FU] = wt7;
        }

#define SHA256_SOFT_STEP(A, B, C, D, E, F, G, H, WT, KT) do { \
            uint32_t t1 = (uint32_t)((H) + SHA_SUM_FROM_1(E) + SHA_CH((E), (F), (G)) + (KT) + (WT)); \
            uint32_t t2 = (uint32_t)(SHA_SUM_FROM_0(A) + SHA_MAJ((A), (B), (C))); \
            (D) += t1; \
            (H) = t1 + t2; \
        } while (0 == 1)

        SHA256_SOFT_STEP(a, b, c, d, e, f, g, h, wt0, sha224_256_k[t + 0U]);
        SHA256_SOFT_STEP(h, a, b, c, d, e, f, g, wt1, sha224_256_k[t + 1U]);
        SHA256_SOFT_STEP(g, h, a, b, c, d, e, f, wt2, sha224_256_k[t + 2U]);
        SHA256_SOFT_STEP(f, g, h, a, b, c, d, e, wt3, sha224_256_k[t + 3U]);
        SHA256_SOFT_STEP(e, f, g, h, a, b, c, d, wt4, sha224_256_k[t + 4U]);
        SHA256_SOFT_STEP(d, e, f, g, h, a, b, c, wt5, sha224_256_k[t + 5U]);
        SHA256_SOFT_STEP(c, d, e, f, g, h, a, b, wt6, sha224_256_k[t + 6U]);
        SHA256_SOFT_STEP(b, c, d, e, f, g, h, a, wt7, sha224_256_k[t + 7U]);
    }
#else
    for (t = 0U; t < SHA256_ROUND_COUNT; t += 1U)
    {
        uint32_t wt = 0U;
        if (t < SHA256_WORDS_PER_BLOCK) {
            wt = w[t];
        } else {
            uint32_t wi = (uint32_t)(t & 0x0FU);
            wt = (uint32_t)(SHA_SIGMA_FROM_1(w[(t - 2U) & 0x0FU]) +
                 w[(t - 7U) & 0x0FU] +
                 SHA_SIGMA_FROM_0(w[(t - 15U) & 0x0FU]) +
                 w[wi]);
            w[wi] = wt;
        }
        uint32_t t1 = (uint32_t)(h + SHA_SUM_FROM_1(e) + SHA_CH(e, f, g) + sha224_256_k[t] + wt);
        uint32_t t2 = (uint32_t)(SHA_SUM_FROM_0(a) + SHA_MAJ(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
#endif
    
    /* Computer the ith internmediate hash value H(i) */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
    
    
	    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_sha256_blocks_software(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t block_count)
{
    uint32_t i = 0U;

    if ((ctx == NULL) || (input == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

#if NOXTLS_SHA256_CORTEXM7_AVAILABLE
    if (s_sha256_cortexm7_enabled != 0U) {
        noxtls_return_t rc = noxtls_sha256_blocks_cortexm7(ctx, input, block_count);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
#endif

    for (i = 0U; i < block_count; i += 1U) {
        noxtls_return_t rc = noxtls_sha256_round_software(ctx, &input[((size_t)i * (size_t)SHA256_BLOCK_SIZE_BYTES)]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finish SHA-256 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha256_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    uint32_t len = 0U;
    uint8_t * data = NULL;    
    uint32_t total_length = 0U;
    uint32_t i = 0U;
    
    uint8_t temp[SHA256_BLOCK_SIZE_BYTES] = {0};
    /* Process any pending data or */
    if (ctx->data_len > 0U)
    {
        len = ctx->data_len;
        data = ctx->data;
        noxtls_secure_zero((temp), sizeof(temp));
        noxtls_copy_u8(temp, sizeof(temp), ctx->data, (size_t)(len));
        total_length = ctx->length + ctx->data_len;
    }
    else
    {
        noxtls_secure_zero((ctx->data), (size_t)(SHA256_BLOCK_SIZE_BYTES));
        data = ctx->data;
        total_length = ctx->length;
    }
    
    uint32_t block_size = (uint32_t)(SHA256_BLOCK_SIZE_BYTES);
    uint8_t length_size = (uint8_t)(SHA256_LENGTH_FIELD_BYTES); /* Size of length in bytes 8 bytes / 64-bit */
    
    uint32_t space_occupied = (uint32_t)((len % block_size));
    uint32_t space_left = (uint32_t)(block_size - space_occupied);
    
    
    if (len == 0U) {
        space_occupied = 0U;
        space_left = block_size;
    }
        
    if (space_left >= 1U) {
        temp[space_occupied] = SHA256_PAD_BYTE;
    }
    
    if (space_left >= (uint32_t)(SHA256_LENGTH_FIELD_BYTES + 1U)) {
        (void)noxtls_add_padding_length(temp, block_size, total_length, length_size);
    }

    if (sha256_debug_lvl > 0U){
        
        for (i = 0U; i < block_size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02x ", temp[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
        
        (void)noxtls_debug_printf((const uint8_t *)"Process here the current block\n");
    }
    
    rc = noxtls_sha256_round(ctx, temp);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        ctx->length += SHA256_BLOCK_SIZE_BYTES;
    }
    
    /* A second padding block is only processed when the first compression
     * succeeded, so its status can never mask an earlier failure. */
    if ((rc == NOXTLS_RETURN_SUCCESS) && (space_left < (uint32_t)(SHA256_LENGTH_FIELD_BYTES + 1U)))
    {
        noxtls_secure_zero((temp), (size_t)(block_size));
        if (space_left == 0U) {
            /* not previously set */
            data[0] = SHA256_PAD_BYTE;
        }
        
        (void)noxtls_add_padding_length(temp, block_size, total_length, length_size);
            
        if (sha256_debug_lvl > 0U) {
            for (i = 0U; i < block_size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02x", temp[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
            (void)noxtls_debug_printf((const uint8_t *)"Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_sha256_round(ctx, temp);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            ctx->length += SHA256_BLOCK_SIZE_BYTES;
        }
        
    }
    
    uint8_t alg_sz = (uint8_t)(SHA256_STATE_WORDS);
    if (ctx->algo == NOXTLS_HASH_SHA_224) {
        alg_sz = (uint8_t)SHA224_STATE_WORDS;
    }
    noxtls_secure_zero((temp), sizeof(temp));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* Never release a partial digest: wipe the output and the state. */
        noxtls_secure_zero(hash, (size_t)alg_sz * 4U);
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }
    for (i = 0U; i < alg_sz; i += 1U)
    {
        hash[(i << 2U)]       = (uint8_t)((ctx->h[i] & 0xFF000000U) >>24U);
        hash[(i << 2U) + 1U] = (uint8_t)((ctx->h[i] & 0x00FF0000U) >>16U);
        hash[(i * 4U) + 2U] = (uint8_t)((ctx->h[i] & 0x0000FF00U) >>8U);
        hash[(i << 2U) + 3U] = (uint8_t)(ctx->h[i] & 0x000000FFU);
    }

	return rc;
}

/**
 * @brief Finish SHA-256 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] data is the HCI controller sink
 * @param[in] zero_pad is the Host Callback
 * @param[in] len is the BT HCI Callback
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t noxtls_sha256_pad(const uint8_t * data, uint32_t zero_pad, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)data;
    (void)zero_pad;
    (void)len;
    
    

    return rc;
}

/**
 * @brief Verify SHA-256
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha256_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA256_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_return_t hrc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    if (hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_sha256_update(&ctx, data, len);
    }
    if (hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_sha256_finish(&ctx, hash);
    }
    
    /* Fail closed: a hashing error is never reported as a match. */
    if ((hrc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_equal(hash, expected, sizeof(hash)) != 0)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

/**
 * @brief Verify SHA-224
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha224_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA256_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_return_t hrc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_224);
    if (hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_sha256_update(&ctx, data, len);
    }
    if (hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_sha256_finish(&ctx, hash);
    }
    
    /* Fail closed: a hashing error is never reported as a match. */
    if ((hrc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_equal(hash, expected, (size_t)HASH_SHA224_OUT_LEN) != 0)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256 */
