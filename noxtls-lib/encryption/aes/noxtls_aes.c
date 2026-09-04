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
* File:    aes.c
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Includes */
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_AES

#ifndef NOXTLS_PORT_AES_ACCEL
#define NOXTLS_PORT_AES_ACCEL 0
#endif
#ifndef NOXTLS_FEATURE_STM32_HW_AES_ONLY
#define NOXTLS_FEATURE_STM32_HW_AES_ONLY 0
#endif
#ifndef NOXTLS_FEATURE_NRF52_HW_AES_ONLY
#define NOXTLS_FEATURE_NRF52_HW_AES_ONLY 0
#endif

#if NOXTLS_FEATURE_STM32_HW_AES_ONLY || NOXTLS_FEATURE_NRF52_HW_AES_ONLY
#define NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK 0
#else
#define NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK 1
#endif

/** AES Substitution Box */
static const uint8_t aes_sub_box[16][16] =
{
    {0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U},
    {0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U},
    {0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U},
    {0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U},
    {0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U},
    {0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU},
    {0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U},
    {0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U},
    {0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U},
    {0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU},
    {0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U},
    {0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U},
    {0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU},
    {0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU},
    {0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU},
    {0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U}
};

static uint32_t aes_enc_te0[256];
static uint32_t aes_enc_te1[256];
static uint32_t aes_enc_te2[256];
static uint32_t aes_enc_te3[256];
static uint32_t aes_rotword(uint32_t w);;
static uint32_t aes_subword(uint32_t w);
static uint32_t rcon(uint8_t in);
static uint8_t aes_xtime_byte(uint8_t x);
static uint8_t aes_sbox_lookup(uint8_t x);
static uint32_t aes_load_be32(const uint8_t *src);
static void aes_store_be32(uint8_t *dst, uint32_t word);
static void aes_software_init_encrypt_tables(void);

static noxtls_return_t noxtls_aes_encrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
static noxtls_return_t noxtls_aes_encrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output);
static noxtls_return_t noxtls_aes_decrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output);
static noxtls_return_t noxtls_aes_decrypt_block_ctx_internal(const noxtls_aes_context_t *ctx,
                                                            const uint8_t *data,
                                                            uint8_t *output);
/**
 * @brief Copy an AES state matrix to a contiguous output block.
 *
 * @param state AES state matrix in column-major order.
 * @param output Output buffer that receives NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return 0 on success.
 */
static int copy_state_to_buffer(const uint8_t *state_bytes, uint8_t* output)
{
    uint32_t row = 0U;
    uint32_t col = 0U;
    uint32_t cnt = 0U;
    for (col = 0U; col < 4U; col += 1U)
    {
        for (row = 0U; row < 4U; row += 1U)
        {
            output[cnt] = state_bytes[(row * 4U) + col];
            cnt += 1U;
        }
    }

    return 0;
}

/**
 * @brief Multiply an AES field element by x in GF(2^8).
 *
 * @param x Field element to multiply.
 * @return Result of multiplying @p x by x modulo the AES polynomial.
 */
static uint8_t aes_xtime_byte(uint8_t x)
{
    uint8_t v = x;
    uint8_t hi = (uint8_t)(v & 0x80U);
    v = (uint8_t)(v << 1U);
    if (hi != 0U) {
        v = (uint8_t)(v ^ 0x1BU);
    }
    return v;
}

/**
 * @brief Look up one byte in the AES S-box.
 *
 * @param x Input byte value.
 * @return S-box substitution for @p x.
 */
static uint8_t aes_sbox_lookup(uint8_t x)
{
    return aes_sub_box[(((uint32_t)x >> 4U) & 0x0FU)][x & 0x0FU];
}

/**
 * @brief Load a big-endian 32-bit word from a byte buffer.
 *
 * @param src Source buffer containing at least 4 bytes.
 * @return 32-bit word decoded from @p src.
 */
static uint32_t aes_load_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] <<24U) |
           ((uint32_t)src[1] <<16U) |
           ((uint32_t)src[2] <<8U) |
           (uint32_t)src[3];
}

/**
 * @brief Store a 32-bit word to a byte buffer in big-endian order.
 *
 * @param dst Destination buffer that receives 4 bytes.
 * @param word 32-bit word to encode.
 * @return None.
 */
static void aes_store_be32(uint8_t *dst, uint32_t word)
{
    dst[0] = (uint8_t)(word >>24U);
    dst[1] = (uint8_t)(word >>16U);
    dst[2] = (uint8_t)(word >>8U);
    dst[3] = (uint8_t)word;
}

/**
 * @brief Initialize table-driven AES encrypt round tables on first use.
 *
 * @param None.
 * @return None.
 */
static void aes_software_init_encrypt_tables(void)
{
    /* AES enc table ready flag (Rule 8.9). */
    static uint8_t aes_enc_tables_ready = 0U;


    uint32_t x = 0U;

    if (aes_enc_tables_ready != 0U) {
        return;
    }

    for (x = 0U; x < 256U; x += 1U) {
        uint8_t s = (uint8_t)(aes_sbox_lookup((uint8_t)x));
        uint8_t s2 = (uint8_t)(aes_xtime_byte(s));
        uint8_t s3 = (uint8_t)(s2 ^ s);
        uint32_t te0 = ((uint32_t)s2 <<24U) |
                       ((uint32_t)s <<16U) |
                       ((uint32_t)s <<8U) |
                       (uint32_t)s3;

        aes_enc_te0[x] = te0;
        aes_enc_te1[x] = (te0 >>8U) | (te0 <<24U);
        aes_enc_te2[x] = (te0 >>16U) | (te0 <<16U);
        aes_enc_te3[x] = (te0 >>24U) | (te0 <<8U);
    }

    aes_enc_tables_ready = 1U;
}

/* Mode entry points (ECB/CBC/CTR/CFB/OFB/XTS) are declared in noxtls_aes.h. */

/**
 * @brief Encrypt data with the selected AES mode.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Plaintext length in bytes.
 * @param iv Initialization vector or nonce for modes that require one.
 * @param output Output buffer for ciphertext.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_INVALID_MODE for unknown modes,
 *         NOXTLS_RETURN_NOT_SUPPORTED for disabled modes, or a mode-specific error code.
 */
noxtls_return_t noxtls_aes_encrypt_data(const uint8_t* key, 
                     const uint8_t* data, 
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output, 
                     noxtls_aes_type_t type,
                     noxtls_aes_mode_t mode)
{
    /* Route to appropriate mode-specific implementation */
    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            return noxtls_aes_encrypt_ecb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            return noxtls_aes_encrypt_cbc(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
            return noxtls_aes_encrypt_ctr(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
            return noxtls_aes_encrypt_cfb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
            return noxtls_aes_encrypt_ofb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_XTS:
#if NOXTLS_FEATURE_AES_XTS
            return noxtls_aes_encrypt_xts(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_GCM:
            /* AES-GCM requires tag handling; use noxtls_aes_gcm_encrypt() directly. */
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_MODE; /* Unknown mode */
    }
    }
}

/**
 * @brief Map an AES key size selector to round-count and key-layout metadata.
 *
 * @param type AES key size selector.
 * @param rounds Output number of AES rounds for @p type.
 * @param key_words Output number of 32-bit key words for @p type.
 * @param key_len Output key length in bytes for @p type.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t aes_type_params(noxtls_aes_type_t type, uint8_t *rounds, uint8_t *key_words, uint8_t *key_len)
{
    if ((rounds == NULL) || (key_words == NULL) || (key_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        /* Widen so a defensive default remains reachable (Rule 2.1). */
        uint32_t type_u = (uint32_t)type;
        switch (type_u)
        {
        case (uint32_t)NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            *rounds = NOXTLS_AES_128_ROUNDS;
            *key_words = 4;
            *key_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            *rounds = NOXTLS_AES_192_ROUNDS;
            *key_words = 6;
            *key_len = 24U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            *rounds = NOXTLS_AES_256_ROUNDS;
            *key_words = 8;
            *key_len = 32U;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
        }
    }
}

/**
 * @brief Prepare an AES context with key metadata and expanded round keys.
 *
 * @param ctx AES context to populate.
 * @param key AES key bytes for the selected key size.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_prepare_context(noxtls_aes_context_t *ctx, const uint8_t *key, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = aes_type_params(type, &ctx->rounds, &ctx->key_words, &ctx->key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->type = type;
    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)(ctx->key_len));
#if NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    (void)aes_software_init_encrypt_tables();
    rc = noxtls_aes_key_expansion(key, ctx->round_keys, (int)ctx->key_words, (int)ctx->rounds);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->round_keys_ready = 1U;
#else
    ctx->round_keys_ready = 0U;
#endif
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Increment a 128-bit AES counter block in big-endian order.
 *
 * @param counter Counter block to increment in place.
 * @return None.
 */
static void aes_counter_inc(uint8_t counter[NOXTLS_AES_BLOCK_LENGTH])
{
    int32_t i = 0;
    for (i = (int)NOXTLS_AES_BLOCK_LENGTH - 1; i >= 0; i -= 1) {
        counter[i] = (uint8_t)(counter[i] + 1U);
        if (counter[i] != 0U) {
            break;
        }
    }
}

/**
 * @brief Initialize AES feedback state with a required IV.
 *
 * @param iv Initialization vector of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param ctx AES context whose feedback state is initialized.
 * @return NOXTLS_RETURN_SUCCESS on success or NOXTLS_RETURN_INVALID_PARAM when iv is NULL.
 */
static noxtls_return_t aes_init_iv_required(const uint8_t *iv, noxtls_aes_context_t *ctx)
{
    if (iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
    ctx->partial_len = NOXTLS_AES_BLOCK_LENGTH;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize an AES streaming context for the selected mode.
 *
 * @param ctx AES context to initialize.
 * @param key AES key bytes for the selected key size.
 * @param iv Initialization vector, nonce, or feedback block for the selected mode.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @param op AES encrypt/decrypt operation selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_init(noxtls_aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             noxtls_aes_type_t type,
             noxtls_aes_mode_t mode,
             noxtls_aes_operation_t op)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    ctx->mode = mode;
    ctx->op = op;
    rc = noxtls_aes_prepare_context(ctx, key, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            if (iv != NULL) {
                noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
            } else {
                /* MISRA 15.7: final else path */
                noxtls_secure_zero((ctx->feedback), (size_t)(NOXTLS_AES_BLOCK_LENGTH));
            }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                return ir;
            }
        }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                return ir;
            }
        }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case (uint32_t)NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if (ir != NOXTLS_RETURN_SUCCESS) {
                return ir;
            }
        }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update AES context with input data and produce output.
 *
 * @param ctx AES context.
 * @param input Input data buffer.
 * @param input_len Input data length in bytes.
 * @param output Output buffer.
 * @param output_len Output length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_INITIALIZED for uninitialized context,
 *         NOXTLS_RETURN_INVALID_BLOCK_SIZE for invalid block size,
 *         or NOXTLS_RETURN_INVALID_MODE for unknown mode.
 */
noxtls_return_t noxtls_aes_update(noxtls_aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len)
{
    uint32_t produced = 0U;
    uint32_t i = 0U;
    const uint8_t *in_ptr = input;
    uint32_t in_left = input_len;

    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if ((in_left > 0U) && ((in_ptr == NULL) || (output == NULL))) {
        return NOXTLS_RETURN_NULL;
    }
    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if ((ctx->mode == NOXTLS_AES_ECB) || (ctx->mode == NOXTLS_AES_CBC)) {
            while (in_left > 0U) {
                uint32_t need = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (uint32_t)((in_left < need) ? in_left : need);
                noxtls_copy_u8(&ctx->partial[ctx->partial_len], sizeof(ctx->partial) - (size_t)(ctx->partial_len), in_ptr, (size_t)(take));
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                in_ptr = &in_ptr[take];
                in_left -= take;

                if (ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    if (ctx->mode == NOXTLS_AES_ECB) {
                        if (ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            noxtls_return_t r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->partial, &output[produced]);
                            if (r != NOXTLS_RETURN_SUCCESS) { return r; }
                        } else {
                            /* MISRA 15.7: final else path */
                            noxtls_return_t r = noxtls_aes_decrypt_block_ctx_internal(ctx, ctx->partial, &output[produced]);
                            if (r != NOXTLS_RETURN_SUCCESS) { return r; }
                        }
                    } else {
                        if (ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            { noxtls_return_t r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, &output[produced]);
                            if (r != NOXTLS_RETURN_SUCCESS) { return r; } }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), &output[produced], (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                        } else {
                            /* MISRA 15.7: final else path */
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            { noxtls_return_t r = noxtls_aes_decrypt_block_ctx_internal(ctx, ctx->partial, block);
                            if (r != NOXTLS_RETURN_SUCCESS) { return r; } }
                            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                        }
                    }

                    produced += NOXTLS_AES_BLOCK_LENGTH;
                    ctx->partial_len = 0U;
                }
            }
    } else if ((ctx->mode == NOXTLS_AES_CTR) || (ctx->mode == NOXTLS_AES_CFB) || (ctx->mode == NOXTLS_AES_OFB)) {
            while (in_left > 0U) {
                if (ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    noxtls_return_t r = NOXTLS_RETURN_FAILED;
                    if (ctx->mode == NOXTLS_AES_CTR) {
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) { return r; }
                        (void)aes_counter_inc(ctx->feedback);
                    } else if (ctx->mode == NOXTLS_AES_CFB) {
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) { return r; }
                    } else {
                        /* MISRA 15.7: final else path */
                        r = noxtls_aes_encrypt_block_ctx_internal(ctx, ctx->feedback, ctx->partial);
                        if (r != NOXTLS_RETURN_SUCCESS) { return r; }
                        noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
                    }
                    ctx->partial_len = 0U;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (uint32_t)((in_left < available) ? in_left : available);
                    for (i = 0U; i < take; i += 1U) {
                        uint8_t out_byte = (uint8_t)(in_ptr[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if (ctx->mode == NOXTLS_AES_CFB) {
                            noxtls_move_u8(ctx->feedback, sizeof(ctx->feedback), &ctx->feedback[1], (size_t)(NOXTLS_AES_BLOCK_LENGTH - 1U));
                            ctx->feedback[NOXTLS_AES_BLOCK_LENGTH - 1U] = (ctx->op == NOXTLS_AES_OP_ENCRYPT) ? out_byte : in_ptr[i];
                        }
                    }
                    in_ptr = &in_ptr[take];
                    in_left -= take;
                    produced += take;
                    ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                }
            }
    } else {
         /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
    }

    *output_len = produced;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize AES streaming operation and flush buffered data.
 *
 * @param ctx AES context.
 * @param output Output buffer for any final bytes.
 * @param output_len Bytes produced in finalization.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_INITIALIZED for uninitialized context,
 *         or NOXTLS_RETURN_INVALID_BLOCK_SIZE for invalid block size.
 */
noxtls_return_t noxtls_aes_final(noxtls_aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len)
{
    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if ((ctx->mode == NOXTLS_AES_CTR) || (ctx->mode == NOXTLS_AES_CFB) || (ctx->mode == NOXTLS_AES_OFB)) {
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->op == NOXTLS_AES_OP_DECRYPT) {
        if (ctx->partial_len != 0U) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->partial_len > 0U) {
        uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
        uint32_t i = 0U;
        noxtls_return_t r = NOXTLS_RETURN_FAILED;

        if (output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        noxtls_secure_zero((block), sizeof(block));
        noxtls_copy_u8(block, sizeof(block), ctx->partial, (size_t)(ctx->partial_len));

        if (ctx->mode == NOXTLS_AES_ECB) {
            r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, output);
            if (r != NOXTLS_RETURN_SUCCESS) { return r; }
        } else if (ctx->mode == NOXTLS_AES_CBC) {
            for (i = 0U; i < NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
                block[i] ^= ctx->feedback[i];
            }
            r = noxtls_aes_encrypt_block_ctx_internal(ctx, block, output);
            if (r != NOXTLS_RETURN_SUCCESS) { return r; }
        } else {
             /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
        }

        *output_len = NOXTLS_AES_BLOCK_LENGTH;
    }

    ctx->initialized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}
    
/**
 * @brief Initialize Block
 * @internal
 *
 * @param state is the AES state
 * @param data is a pointer to the data to put in the state
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_init_block(uint8_t state[4][4], const uint8_t* data)
{
    uint32_t col = 0U;
    uint32_t row = 0U;

    if ((state == NULL) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (col = 0U; col < 4U; col += 1U)
    {
        for (row = 0U; row < 4U; row += 1U)
        {
            state[row][col] = data[row + (col * 4U)];
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief AES Encrypt Block
 * @internal
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192.256
 *
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    rc = noxtls_aes_accel_port_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_encrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software(key, data, output, type);
#endif
}

/**
 * @brief Encrypt one AES block using a prepared AES context.
 *
 * @param ctx Prepared AES context containing expanded round keys.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_ctx_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_port_encrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_encrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_encrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

noxtls_return_t noxtls_aes_encrypt_block_ctx_software_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_encrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

/**
 * @brief Report the AES block backend selected for the current build.
 *
 * @return NOXTLS_AES_ACCEL_BACKEND_PORT when a platform AES backend is enabled,
 *         NOXTLS_AES_ACCEL_BACKEND_NI when AES-NI is compiled in,
 *         NOXTLS_AES_ACCEL_BACKEND_APPLE when ARMv8 AES is compiled in,
 *         or NOXTLS_AES_ACCEL_BACKEND_SOFTWARE otherwise.
 */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void)
{
#if NOXTLS_PORT_AES_ACCEL
    return NOXTLS_AES_ACCEL_BACKEND_PORT;
#elif NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    return NOXTLS_AES_ACCEL_BACKEND_NI;
#elif NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    return NOXTLS_AES_ACCEL_BACKEND_APPLE;
#else
    return NOXTLS_AES_ACCEL_BACKEND_SOFTWARE;
#endif
}

/**
 * @brief Encrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_SUPPORTED for disabled key sizes, or
 *         NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
static noxtls_return_t noxtls_aes_encrypt_block_software(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type)
{
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0U;
    uint8_t key_words = 0U;
    uint8_t key_length = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = aes_type_params(type, &rounds, &key_words, &key_length);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_aes_key_expansion(key, w, (int)key_words, (int)rounds);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)aes_software_init_encrypt_tables();
    return noxtls_aes_encrypt_block_software_expanded(w, rounds, data, output);
}

/**
 * @brief Encrypt one AES block with pre-expanded software round keys.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_encrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output)
{
    uint32_t s0 = 0U;
    uint32_t s1 = 0U;
    uint32_t s2 = 0U;
    uint32_t s3 = 0U;
    uint32_t t0 = 0U;
    uint32_t t1 = 0U;
    uint32_t t2 = 0U;
    uint32_t t3 = 0U;
    uint8_t cur_round = 0U;

    if ((round_keys == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    s0 = aes_load_be32(data) ^ round_keys[0];
    s1 = aes_load_be32(&data[4]) ^ round_keys[1];
    s2 = aes_load_be32(&data[8]) ^ round_keys[2];
    s3 = aes_load_be32(&data[12]) ^ round_keys[3];

    for (cur_round = 1U; cur_round <= (uint8_t)(rounds - 1U); cur_round += 1U)
    {
        size_t rk = (size_t)cur_round * 4U;

        t0 = aes_enc_te0[(s0 >>24U) & 0xFFU] ^
             aes_enc_te1[(s1 >>16U) & 0xFFU] ^
             aes_enc_te2[(s2 >>8U) & 0xFFU] ^
             aes_enc_te3[s3 & 0xFFU] ^
             round_keys[rk + 0U];
        t1 = aes_enc_te0[(s1 >>24U) & 0xFFU] ^
             aes_enc_te1[(s2 >>16U) & 0xFFU] ^
             aes_enc_te2[(s3 >>8U) & 0xFFU] ^
             aes_enc_te3[s0 & 0xFFU] ^
             round_keys[rk + 1U];
        t2 = aes_enc_te0[(s2 >>24U) & 0xFFU] ^
             aes_enc_te1[(s3 >>16U) & 0xFFU] ^
             aes_enc_te2[(s0 >>8U) & 0xFFU] ^
             aes_enc_te3[s1 & 0xFFU] ^
             round_keys[rk + 2U];
        t3 = aes_enc_te0[(s3 >>24U) & 0xFFU] ^
             aes_enc_te1[(s0 >>16U) & 0xFFU] ^
             aes_enc_te2[(s1 >>8U) & 0xFFU] ^
             aes_enc_te3[s2 & 0xFFU] ^
             round_keys[rk + 3U];

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    t0 = ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s3) ^
         round_keys[((size_t)rounds * 4U) + 0U];
    t1 = ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s0) ^
         round_keys[((size_t)rounds * 4U) + 1U];
    t2 = ((uint32_t)aes_sbox_lookup((uint8_t)(s2 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s1) ^
         round_keys[((size_t)rounds * 4U) + 2U];
    t3 = ((uint32_t)aes_sbox_lookup((uint8_t)(s3 >>24U)) <<24U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s0 >>16U)) <<16U) ^
         ((uint32_t)aes_sbox_lookup((uint8_t)(s1 >>8U)) <<8U) ^
         (uint32_t)aes_sbox_lookup((uint8_t)s2) ^
         round_keys[((size_t)rounds * 4U) + 3U];

    (void)aes_store_be32(output, t0);
    (void)aes_store_be32(&output[4], t1);
    (void)aes_store_be32(&output[8], t2);
    (void)aes_store_be32(&output[12], t3);
    return NOXTLS_RETURN_SUCCESS;
}

    
/**
 * @brief Adds round key
 * @internal
 *
 * @param state is the current state
 * @param w is the key for this round from the key expansion
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_add_round_key(uint8_t state[4][4], const uint32_t * w)
{
    uint8_t row = 0U;

    if ((state == NULL) || (w == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (row = 0U; row < 4U; row += 1U)
    {
        uint32_t val1 = ((uint32_t)state[0][row] <<24U) |
                        ((uint32_t)state[1][row] <<16U) |
                        ((uint32_t)state[2][row] <<8U) |
                        (uint32_t)state[3][row];
        
        
        uint32_t temp = (uint32_t)(val1 ^ w[row]);
        
        
        state[0][row] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[1][row] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[2][row] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[3][row] = (uint8_t)(temp & 0x000000FFU);
        
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Performs AES Key expansion
 * @internal
 *
 * Uses AES provided key to generate the key schedules used to mix with the
 * state
 * @param key AES key bytes.
 * @param w Output key schedule words.
 * @param nk Number of 32-bit words in the AES key.
 * @param rounds Number of AES rounds for the selected key size.
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_aes_key_expansion(const uint8_t * key, uint32_t * w, int nk, int rounds)
{
    uint32_t i = 0U;
    uint32_t nk_u = 0U;
    uint32_t rounds_u = 0U;

    if ((key == NULL) || (w == NULL) || (nk <= 0) || (rounds <= 0)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    nk_u = (uint32_t)nk;
    rounds_u = (uint32_t)rounds;

    for (i = 0U; i < nk_u; i += 1U)
    {
        size_t off = (size_t)i * 4U;
        w[i] = ((uint32_t)key[off] <<24U) |
               ((uint32_t)key[off + 1U] <<16U) |
               ((uint32_t)key[off + 2U] <<8U) |
               (uint32_t)key[off + 3U];
    }

    for (i = nk_u; i < (4U * (rounds_u + 1U)); i += 1U)
    {
        uint32_t temp = (uint32_t)(w[i - 1U]);
        if ((i % nk_u) == 0U)
        {
            uint32_t arot = (uint32_t)(aes_rotword(temp));
            uint32_t asub = (uint32_t)(aes_subword(arot));
            temp = asub ^ rcon((uint8_t)(i / nk_u));
        }
        else if ((nk_u > 6U) && ((i % nk_u) == 4U))
        {
            temp = aes_subword(temp);
        }
        else {
            /* MISRA 15.7: no remaining alternative */
        }
        w[i] = w[i - nk_u] ^ temp;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Calculate the rcon used in key expansion
 * @internal

 * @param in is the parameter on which to calculate RCON
 *
 * @return RCON word for the requested key-expansion round.
 */
static uint32_t rcon(uint8_t in)
{
    uint8_t rounds = in;
    unsigned char c = 1;
    if (rounds == 0U) {
        return 0U;
    }
    while (rounds != 1U) {
        unsigned char b;
        b = c & 0x80U;
        c <<= 1U;
        if (b == 0x80U) {
            c ^= 0x1bU;
        }
        rounds -= 1U;
    }
    return ((uint32_t)c <<24U);
}

/**
 * @brief Rotate Word
 * @internal
 *
 * @param w is the word to rotate
 *
 * @return Rotated AES key schedule word.
 */
static uint32_t aes_rotword(uint32_t w)
{
    uint32_t word = 0U;

    word = w <<8U;
    word |= ((w & 0xFF000000U) >>24U);

    return word;
}

/**
 * @brief Finds the subword 
 * @internal
 *
 * @param w is the word to sub
 *
 * @return the subword
 */
static uint32_t aes_subword(uint32_t w)
{
    uint32_t word = 0U;
    const uint8_t * ptr = (const uint8_t * )&w;
    uint8_t row = 0U;
    uint8_t col = 0U;

    row = (uint8_t)((ptr[0] & 0xF0U) >> 4U);
    col = (uint8_t)(ptr[0] & 0x0FU);
    word |= (uint32_t)aes_sub_box[row][col];
    row = (uint8_t)((ptr[1] & 0xF0U) >> 4U);
    col = (uint8_t)(ptr[1] & 0x0FU);
    word |= (uint32_t)((uint32_t)aes_sub_box[row][col] << 8U);
    row = (uint8_t)((ptr[2] & 0xF0U) >> 4U);
    col = (uint8_t)(ptr[2] & 0x0FU);
    word |= (uint32_t)((uint32_t)aes_sub_box[row][col] << 16U);
    row = (uint8_t)((ptr[3] & 0xF0U) >> 4U);
    col = (uint8_t)(ptr[3] & 0x0FU);
    word |= (uint32_t)((uint32_t)aes_sub_box[row][col] << 24U);
    return word;
}

/**
 * @brief Perform AES Sub bytes
 * @internal
 *
 * @param state is the current AES state
 *
 * @return None.
 */
void noxtls_aes_sub_bytes(uint8_t state[4][4])
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint8_t row = 0U;
    uint8_t col = 0U;
    for (i = 0U; i < 4U; i += 1U)
    {
        for (j = 0U; j < 4U; j += 1U)
        {
            row = (state[i][j] & 0xF0U) >>4U;
            col = (state[i][j] & 0x0FU);
            state[i][j] = aes_sub_box[row][col];
        }

    }
}
    

/**
 * @brief Shift Rows
 * @internal
 *
 * @param state is the state to print
 *
 * @return None.
 */
void noxtls_aes_shift_rows(uint8_t state[4][4])
{
    /* Shift second row by one,
     Shift third row by two
     Shift fourth row by three */
    uint32_t row = 0U;

    for (row = 1U; row < 4U; row += 1U)
    {
        
        uint32_t val1 = ((uint32_t)state[row][0] <<24U) |
                        ((uint32_t)state[row][1] <<16U) |
                        ((uint32_t)state[row][2] <<8U) |
                        (uint32_t)state[row][3];
                
        uint32_t temp = 0U;
            switch(row) {
            case 0U: temp = val1; break;
            case 1U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 8U)); break;
            case 2U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 16U)); break;
            case 3U: temp = (uint32_t)(NOXTLS_AES_ROTL(val1, 24U)); break;
            default: temp = val1; break;
            }
        
        state[row][0] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[row][1] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[row][2] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[row][3] = (uint8_t)(temp & 0x000000FFU);
    }
}

/**
 * @brief AES Mix Columns
 * @internal
 *
 * @param state is the state to print
 *
 * @return None.
 */
void noxtls_aes_mix_columns(uint8_t state[4][4])
{
    uint8_t a[4];
    uint8_t b[4];
    uint32_t i = 0U;
    uint32_t j = 0U;

    // row x col
    /* Iterate through all columns*/
    for (j = 0U; j < 4U; j += 1U)
    {

        for (i = 0U; i < 4U; i += 1U)
        {
            a[i] = state[i][j];
            b[i] = aes_xtime_byte(state[i][j]);
        }

        state[0][j] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        state[1][j] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        state[2][j] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        state[3][j] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

/**
 * @brief Perform AES Inverse Sub bytes
 * @internal
 *
 * @param state is the current AES state
 *
 * @return None.
 */
static void aes_inv_sub_bytes(uint8_t state[4][4])
{
    /* AES inv S-box (Rule 8.9). */
    /** AES Inverse Substitution Box */
    static const uint8_t aes_inv_sub_box[16][16] =
    {
        {0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U, 0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU},
        {0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U, 0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU},
        {0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU, 0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU},
        {0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U, 0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U},
        {0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, 0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U},
        {0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU, 0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U},
        {0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU, 0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U},
        {0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U, 0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU},
        {0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU, 0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U},
        {0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U, 0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU},
        {0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U, 0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU},
        {0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U, 0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U},
        {0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U, 0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU},
        {0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU, 0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU},
        {0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U, 0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U},
        {0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U, 0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU}
    };


    uint32_t i = 0U;
    uint32_t j = 0U;
    uint8_t row = 0U;
    uint8_t col = 0U;
    for (i = 0U; i < 4U; i += 1U)
    {
        for (j = 0U; j < 4U; j += 1U)
        {
            row = (state[i][j] & 0xF0U) >>4U;
            col = (state[i][j] & 0x0FU);
            state[i][j] = aes_inv_sub_box[row][col];
        }
    }
}

/**
 * @brief Inverse Shift Rows
 * @internal    
 *
 * @param state is the state to shift
 *
 * @return None.
 */
static void aes_inv_shift_rows(uint8_t state[4][4])
{
    /* Inverse shift: second row by one right, third by two, fourth by three */
    uint32_t row = 0U;   

    for (row = 1U; row < 4U; row += 1U)
    {
        uint32_t val1 = ((uint32_t)state[row][0] <<24U) | ((uint32_t)state[row][1] <<16U) |
                        ((uint32_t)state[row][2] <<8U) | (uint32_t)state[row][3];
        uint32_t temp = 0U;
            switch(row) {
            case 0U: temp = val1; break;
            case 1U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 8U)); break;
            case 2U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 16U)); break;
            case 3U: temp = (uint32_t)(NOXTLS_AES_ROTR(val1, 24U)); break;
            default: temp = val1; break;
            }
        
        state[row][0] = (uint8_t)((temp & 0xFF000000U) >>24U);
        state[row][1] = (uint8_t)((temp & 0x00FF0000U) >>16U);
        state[row][2] = (uint8_t)((temp & 0x0000FF00U) >>8U);
        state[row][3] = (uint8_t)(temp & 0x000000FFU);
    }
}

/**
 * @brief AES Galois Field Multiply
 * @internal
 *
 * @param a is the first operand
 * @param b is the second operand
 *
 * @return the result of the multiplication
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Multiply two AES field elements in GF(2^8).
 *
 * @param a First field element.
 * @param b Second field element.
 * @return Product of @p a and @p b in the AES field.
 */
static uint8_t aes_gf_mul(uint8_t a, uint8_t b)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t aa = a;
    uint8_t bb = b;
    uint8_t p = 0U;
    for (uint32_t i = 0U; i < 8U; i += 1U) {
        if ((bb & 1U) != 0U) {
            p ^= aa;
        }
        uint8_t hi_bit = (uint8_t)(aa & 0x80U);
        aa <<= 1U;
        if (hi_bit != 0U) {
            aa ^= 0x1BU;
        }
        bb >>= 1U;
    }
    return p;
}

/**
 * @brief AES Inverse Mix Columns
 * @internal
 *
 * @param state is the state to mix
 *
 * @return None.
 */
static void aes_inv_mix_columns(uint8_t state[4][4])
{
    for (uint32_t j = 0U; j < 4U; j += 1U) {
        uint8_t a0 = (uint8_t)(state[0][j]);
        uint8_t a1 = (uint8_t)(state[1][j]);
        uint8_t a2 = (uint8_t)(state[2][j]);
        uint8_t a3 = (uint8_t)(state[3][j]);

        state[0][j] = (uint8_t)(aes_gf_mul(a0, 0x0EU) ^ aes_gf_mul(a1, 0x0BU) ^
                                 aes_gf_mul(a2, 0x0DU) ^ aes_gf_mul(a3, 0x09U));
        state[1][j] = (uint8_t)(aes_gf_mul(a0, 0x09U) ^ aes_gf_mul(a1, 0x0EU) ^
                                 aes_gf_mul(a2, 0x0BU) ^ aes_gf_mul(a3, 0x0DU));
        state[2][j] = (uint8_t)(aes_gf_mul(a0, 0x0DU) ^ aes_gf_mul(a1, 0x09U) ^
                                 aes_gf_mul(a2, 0x0EU) ^ aes_gf_mul(a3, 0x0BU));
        state[3][j] = (uint8_t)(aes_gf_mul(a0, 0x0BU) ^ aes_gf_mul(a1, 0x0DU) ^
                                 aes_gf_mul(a2, 0x09U) ^ aes_gf_mul(a3, 0x0EU));
    }
}

/**
 * @brief AES Decrypt Block
 * @internal
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param output is the output buffer where the decrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 *
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_block_internal(const uint8_t *key, const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    rc = noxtls_aes_accel_port_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_decrypt_block(key, data, output, type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_decrypt_block_software(key, data, output, type);
#endif
}

/**
 * @brief Decrypt one AES block using a prepared AES context.
 *
 * @param ctx Prepared AES context containing expanded round keys.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_decrypt_block_ctx_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    (void)rc;

    if ((ctx == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_port_decrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_decrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_decrypt_block(ctx->key, data, output, ctx->type);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

    if ((NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK != 0) && (ctx->round_keys_ready == 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
#if !NOXTLS_FEATURE_AES_SOFTWARE_FALLBACK
    return NOXTLS_RETURN_NOT_SUPPORTED;
#else
    return noxtls_aes_decrypt_block_software_expanded(ctx->round_keys, ctx->rounds, data, output);
#endif
}

/**
 * @brief Decrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED for disabled key sizes,
 *         or NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Decrypt one AES block with the portable software implementation.
 *
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0U;
    uint8_t key_words = 0U;
    uint8_t key_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = aes_type_params(type, &rounds, &key_words, &key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_aes_key_expansion(key, w, (int)key_words, (int)rounds);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_aes_decrypt_block_software_expanded(w, rounds, data, output);
}

/**
 * @brief Decrypt one AES block with pre-expanded software round keys.
 *
 * @param round_keys Expanded AES round keys.
 * @param rounds Number of AES rounds for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
static noxtls_return_t noxtls_aes_decrypt_block_software_expanded(const uint32_t *round_keys,
                                                           uint8_t rounds,
                                                           const uint8_t *data,
                                                           uint8_t *output)
{
    uint8_t state[4][4];
    int32_t cur_round = 0;

    if ((round_keys == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    (void)noxtls_aes_init_block(state, data);
    (void)noxtls_aes_add_round_key(state, &round_keys[(size_t)rounds * 4U]);

    for (cur_round = (int)rounds - 1; cur_round >= 1; cur_round -= 1)
    {
        (void)aes_inv_shift_rows(state);
        (void)aes_inv_sub_bytes(state);
        (void)noxtls_aes_add_round_key(state, &round_keys[(size_t)cur_round * 4U]);
        (void)aes_inv_mix_columns(state);
    }

    (void)aes_inv_shift_rows(state);
    (void)aes_inv_sub_bytes(state);
    (void)noxtls_aes_add_round_key(state, &round_keys[0]);
    (void)copy_state_to_buffer(&state[0][0], output);
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_AES */
