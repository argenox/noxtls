/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    aes.c
* Summary: Advanced Encryption Standard (AES) Algorithm
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
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES



/** AES Substitution Box */
static const uint8_t aes_sub_box[16][16] =
{
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

/** AES Inverse Substitution Box */
static const uint8_t aes_inv_sub_box[16][16] =
{
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};


static uint32_t aes_rotword(uint32_t w);;
static uint32_t aes_subword(uint32_t w);
static uint32_t rcon(uint8_t in);
static noxtls_return_t noxtls_aes_encrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type);
/* Make encrypt block accessible to mode implementations */
noxtls_return_t noxtls_aes_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_decrypt_block_internal(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type);

    
/**
 * @brief Copy an AES state matrix to a contiguous output block.
 * @param state AES state matrix in column-major order.
 * @param output Output buffer that receives NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return 0 on success.
 */
static int copy_state_to_buffer(uint8_t state[4][4], uint8_t* output)
{
    int row;
    int col;
    int cnt = 0;
    for(col = 0; col< 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            output[cnt++] = state[row][col];
        }
    }

    return 0;
}

/* Forward declarations for mode-specific functions */
#if NOXTLS_FEATURE_AES_ECB
extern noxtls_return_t noxtls_aes_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif
#if NOXTLS_FEATURE_AES_CBC
extern noxtls_return_t noxtls_aes_encrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif
#if NOXTLS_FEATURE_AES_CTR
extern noxtls_return_t noxtls_aes_encrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif
#if NOXTLS_FEATURE_AES_CFB
extern noxtls_return_t noxtls_aes_encrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif
#if NOXTLS_FEATURE_AES_OFB
extern noxtls_return_t noxtls_aes_encrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif
#if NOXTLS_FEATURE_AES_XTS
extern noxtls_return_t noxtls_aes_encrypt_xts(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
#endif

/**
 * @brief Encrypt data with the selected AES mode.
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
    switch(mode) {
        case NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            return noxtls_aes_encrypt_ecb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            return noxtls_aes_encrypt_cbc(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
            return noxtls_aes_encrypt_ctr(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
            return noxtls_aes_encrypt_cfb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
            return noxtls_aes_encrypt_ofb(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_XTS:
#if NOXTLS_FEATURE_AES_XTS
            return noxtls_aes_encrypt_xts(key, data, data_len, iv, output, type);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_GCM:
            /* AES-GCM requires tag handling; use noxtls_aes_gcm_encrypt() directly. */
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_MODE; /* Unknown mode */
    }
}

/**
 * @brief Return the key size in bytes for an AES key size selector.
 * @param type AES key size selector.
 * @return Key size in bytes, or 0 for an invalid selector.
 */
static uint8_t aes_key_size_bytes(noxtls_aes_type_t type)
{
    switch(type) {
        case NOXTLS_AES_128_BIT:
            return 16;
        case NOXTLS_AES_192_BIT:
            return 24;
        case NOXTLS_AES_256_BIT:
            return 32;
        default:
            return 0;
    }
}

/**
 * @brief Increment a 128-bit AES counter block in big-endian order.
 * @param counter Counter block to increment in place.
 * @return None.
 */
static void aes_counter_inc(uint8_t counter[NOXTLS_AES_BLOCK_LENGTH])
{
    int i;
    for(i = NOXTLS_AES_BLOCK_LENGTH - 1; i >= 0; i--) {
        counter[i]++;
        if(counter[i] != 0) {
            break;
        }
    }
}

/**
 * @brief Initialize AES feedback state with a required IV.
 * @param iv Initialization vector of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param ctx AES context whose feedback state is initialized.
 * @return NOXTLS_RETURN_SUCCESS on success or NOXTLS_RETURN_INVALID_PARAM when iv is NULL.
 */
static noxtls_return_t aes_init_iv_required(const uint8_t *iv, noxtls_aes_context_t *ctx)
{
    if(iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    memcpy(ctx->feedback, iv, NOXTLS_AES_BLOCK_LENGTH);
    ctx->partial_len = NOXTLS_AES_BLOCK_LENGTH;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_init(noxtls_aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             noxtls_aes_type_t type,
             noxtls_aes_mode_t mode,
             noxtls_aes_operation_t op)
{
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    ctx->mode = mode;
    ctx->op = op;
    ctx->key_len = aes_key_size_bytes(type);
    if(ctx->key_len == 0) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    memcpy(ctx->key, key, ctx->key_len);

    switch(mode) {
        case NOXTLS_AES_ECB:
#if NOXTLS_FEATURE_AES_ECB
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CBC:
#if NOXTLS_FEATURE_AES_CBC
            if(iv != NULL) {
                memcpy(ctx->feedback, iv, NOXTLS_AES_BLOCK_LENGTH);
            } else {
                memset(ctx->feedback, 0, NOXTLS_AES_BLOCK_LENGTH);
            }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CTR:
#if NOXTLS_FEATURE_AES_CTR
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if(ir != NOXTLS_RETURN_SUCCESS) {
                return ir;
            }
        }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_CFB:
#if NOXTLS_FEATURE_AES_CFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if(ir != NOXTLS_RETURN_SUCCESS) {
                return ir;
            }
        }
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_OFB:
#if NOXTLS_FEATURE_AES_OFB
        {
            noxtls_return_t ir = aes_init_iv_required(iv, ctx);
            if(ir != NOXTLS_RETURN_SUCCESS) {
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

    ctx->initialized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_update(noxtls_aes_context_t *ctx,
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
        case NOXTLS_AES_ECB:
        case NOXTLS_AES_CBC:
            while(input_len > 0) {
                uint32_t need = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (input_len < need) ? input_len : need;
                memcpy(ctx->partial + ctx->partial_len, input, take);
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                input += take;
                input_len -= take;

                if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    if(ctx->mode == NOXTLS_AES_ECB) {
                        if(ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            noxtls_return_t r = noxtls_aes_encrypt_block_internal(ctx->key, ctx->partial, output + produced, ctx->type);
                            if(r != NOXTLS_RETURN_SUCCESS) return r;
                        } else {
                            noxtls_return_t r = noxtls_aes_decrypt_block_internal(ctx->key, ctx->partial, output + produced, ctx->type);
                            if(r != NOXTLS_RETURN_SUCCESS) return r;
                        }
                    } else {
                        if(ctx->op == NOXTLS_AES_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            for(i = 0; i < NOXTLS_AES_BLOCK_LENGTH; i++) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            { noxtls_return_t r = noxtls_aes_encrypt_block_internal(ctx->key, block, output + produced, ctx->type);
                            if(r != NOXTLS_RETURN_SUCCESS) return r; }
                            memcpy(ctx->feedback, output + produced, NOXTLS_AES_BLOCK_LENGTH);
                        } else {
                            uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
                            { noxtls_return_t r = noxtls_aes_decrypt_block_internal(ctx->key, ctx->partial, block, ctx->type);
                            if(r != NOXTLS_RETURN_SUCCESS) return r; }
                            for(i = 0; i < NOXTLS_AES_BLOCK_LENGTH; i++) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            memcpy(ctx->feedback, ctx->partial, NOXTLS_AES_BLOCK_LENGTH);
                        }
                    }

                    produced += NOXTLS_AES_BLOCK_LENGTH;
                    ctx->partial_len = 0;
                }
            }
            break;

        case NOXTLS_AES_CTR:
        case NOXTLS_AES_CFB:
        case NOXTLS_AES_OFB:
            while(input_len > 0) {
                if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH) {
                    noxtls_return_t r;
                    if(ctx->mode == NOXTLS_AES_CTR) {
                        r = noxtls_aes_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type);
                        if(r != NOXTLS_RETURN_SUCCESS) return r;
                        aes_counter_inc(ctx->feedback);
                    } else if(ctx->mode == NOXTLS_AES_CFB) {
                        r = noxtls_aes_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type);
                        if(r != NOXTLS_RETURN_SUCCESS) return r;
                    } else {
                        r = noxtls_aes_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type);
                        if(r != NOXTLS_RETURN_SUCCESS) return r;
                        memcpy(ctx->feedback, ctx->partial, NOXTLS_AES_BLOCK_LENGTH);
                    }
                    ctx->partial_len = 0;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_AES_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (input_len < available) ? input_len : available;
                    for(i = 0; i < take; i++) {
                        uint8_t out_byte = (uint8_t)(input[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if(ctx->mode == NOXTLS_AES_CFB) {
                            memmove(ctx->feedback, ctx->feedback + 1, NOXTLS_AES_BLOCK_LENGTH - 1);
                            ctx->feedback[NOXTLS_AES_BLOCK_LENGTH - 1] = (ctx->op == NOXTLS_AES_OP_ENCRYPT) ? out_byte : input[i];
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

noxtls_return_t noxtls_aes_final(noxtls_aes_context_t *ctx,
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

    if(ctx->mode == NOXTLS_AES_CTR || ctx->mode == NOXTLS_AES_CFB || ctx->mode == NOXTLS_AES_OFB) {
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->op == NOXTLS_AES_OP_DECRYPT) {
        if(ctx->partial_len != 0) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->partial_len > 0) {
        uint8_t block[NOXTLS_AES_BLOCK_LENGTH];
        uint32_t i;
        noxtls_return_t r;

        if(output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        memset(block, 0, sizeof(block));
        memcpy(block, ctx->partial, ctx->partial_len);

        if(ctx->mode == NOXTLS_AES_ECB) {
            r = noxtls_aes_encrypt_block_internal(ctx->key, block, output, ctx->type);
            if(r != NOXTLS_RETURN_SUCCESS) return r;
        } else if(ctx->mode == NOXTLS_AES_CBC) {
            for(i = 0; i < NOXTLS_AES_BLOCK_LENGTH; i++) {
                block[i] ^= ctx->feedback[i];
            }
            r = noxtls_aes_encrypt_block_internal(ctx->key, block, output, ctx->type);
            if(r != NOXTLS_RETURN_SUCCESS) return r;
        } else {
            return NOXTLS_RETURN_INVALID_MODE;
        }

        *output_len = NOXTLS_AES_BLOCK_LENGTH;
    }

    ctx->initialized = 0;
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
    int col;
    int row;

    if(state == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(col = 0; col < 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            state[row][col] = data[row + (col * 4)];
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

#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_encrypt_block(key, data, output, type);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_encrypt_block(key, data, output, type);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

    return noxtls_aes_encrypt_block_software(key, data, output, type);
}

/**
 * @brief Report the AES block backend selected for the current build.
 * @return NOXTLS_AES_ACCEL_BACKEND_NI when AES-NI is compiled in,
 *         NOXTLS_AES_ACCEL_BACKEND_APPLE when ARMv8 AES is compiled in,
 *         or NOXTLS_AES_ACCEL_BACKEND_SOFTWARE otherwise.
 */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void)
{
#if NOXTLS_FEATURE_AES_ACCEL_NI && \
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
    uint8_t state[4][4];
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0;
    uint8_t cur_round = 0;
    uint8_t key_length = 0;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type)
    {
    case NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
        rounds = NOXTLS_AES_128_ROUNDS;
        key_length = 4;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
        rounds = NOXTLS_AES_192_ROUNDS;
        key_length = 6;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
        rounds = NOXTLS_AES_256_ROUNDS;
        key_length = 8;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    default:
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
        break;
    }

    /* Copy to state */
    
    noxtls_aes_init_block(state, data);
    
    /* Perform Key Expansion */
    noxtls_aes_key_expansion(key, w, key_length, rounds);

    
    /* Add initial round key */
    noxtls_aes_add_round_key(state, &w[0]);

    /* Iterate through rounds */
    for(cur_round = 1; cur_round <= rounds - 1; cur_round++)
    {
        noxtls_aes_sub_bytes(state);
        noxtls_aes_shift_rows(state);
        noxtls_aes_mix_columns(state);
        noxtls_aes_add_round_key(state, &w[(size_t)cur_round * 4u]);
    }

    noxtls_aes_sub_bytes(state);
    noxtls_aes_shift_rows(state);
    noxtls_aes_add_round_key(state, &w[(size_t)rounds * 4u]);    
    
    /* Copy output */
    copy_state_to_buffer(state, output);

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
    uint8_t row = 0;

    if(state == NULL || w == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(row = 0; row < 4; row++)
    {
        uint32_t val1 = ((uint32_t)state[0][row] << 24) |
                        ((uint32_t)state[1][row] << 16) |
                        ((uint32_t)state[2][row] << 8) |
                        (uint32_t)state[3][row];
        
        
        uint32_t temp = val1 ^ w[row];
        
        //printf(" %x ^ %x = %x\n",val1,w[row],temp);
        
        state[0][row] = (uint8_t)((temp & 0xFF000000) >> 24);
        state[1][row] = (uint8_t)((temp & 0x00FF0000) >> 16);
        state[2][row] = (uint8_t)((temp & 0x0000FF00) >> 8);
        state[3][row] = (uint8_t)(temp & 0x000000FF);
        
        //printf(" %x %x %x %x\n",state[row][0], state[row][1], state[row][2],  state[row][3]);
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
    int i = 0;

    if(key == NULL || w == NULL || nk <= 0 || rounds <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0; i < nk; i++)
    {
        size_t off = (size_t)i * 4u;
        w[i] = ((uint32_t)key[off] << 24) |
               ((uint32_t)key[off + 1u] << 16) |
               ((uint32_t)key[off + 2u] << 8) |
               (uint32_t)key[off + 3u];
    }

    for(i = nk; i < (4 * (rounds + 1)); i++)
    {
        uint32_t temp = w[i - 1];
        if((i % nk) == 0)
        {
            uint32_t arot = aes_rotword(temp);
            uint32_t asub = aes_subword(arot);
            temp = asub ^ rcon((uint8_t)(i / nk));
        }
        else if(nk > 6 && ((i % nk) == 4))
        {
            temp = aes_subword(temp);
        }
        w[i] = w[i - nk] ^ temp;
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
    unsigned char c = 1;
    if(in == 0)
        return 0;
    while(in != 1) {
        unsigned char b;
        b = c & 0x80;
        c <<= 1;
        if(b == 0x80) {
            c ^= 0x1b;
        }
        in--;
    }
    return ((uint32_t)c << 24);
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
    uint32_t word = 0;

    word = w << 8;
    word |= ((w & 0xFF000000) >> 24);


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
    uint32_t word = 0;
    const uint8_t * ptr = (const uint8_t * )&w;
    int i;

    for(i = 0; i < 4; i++)
    {
        uint8_t row = (ptr[i] & 0xF0) >> 4;
        uint8_t col = (ptr[i] & 0x0F);
        word |= ((uint32_t)aes_sub_box[row][col]) << (i * 8);
    }
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
    int i;
    int j;
    uint8_t row;
    uint8_t col;
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            row = (state[i][j] & 0xF0) >> 4;
            col = (state[i][j] & 0x0F);
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
    int row;

    for(row = 1; row < 4; row++)
    {
        
        uint32_t val1 = ((uint32_t)state[row][0] << 24) |
                        ((uint32_t)state[row][1] << 16) |
                        ((uint32_t)state[row][2] << 8) |
                        (uint32_t)state[row][3];
                
        uint32_t temp = NOXTLS_AES_ROTL(val1, 8*row);
        
        state[row][0] = (uint8_t)((temp & 0xFF000000) >> 24);
        state[row][1] = (uint8_t)((temp & 0x00FF0000) >> 16);
        state[row][2] = (uint8_t)((temp & 0x0000FF00) >> 8);
        state[row][3] = (uint8_t)(temp & 0x000000FF);
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
    int i;
    uint8_t h;
    int j;

    // row x col
    /* Iterate through all columns*/
    for(j = 0; j < 4; j++)
    {

        for(i = 0; i < 4; i++)
        {
            a[i] = state[i][j];

            h = (uint8_t)((int8_t)state[i][j] >> 7);
            b[i] = state[i][j] << 1;
            b[i] ^= 0x1B & h;
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
    int i;
    int j;
    uint8_t row;
    uint8_t col;
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            row = (state[i][j] & 0xF0) >> 4;
            col = (state[i][j] & 0x0F);
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
    int row = 0;   

    for(row = 1; row < 4; row++)
    {
        uint32_t val1 = ((uint32_t)state[row][0] << 24) | ((uint32_t)state[row][1] << 16) |
                        ((uint32_t)state[row][2] << 8) | (uint32_t)state[row][3];
        uint32_t temp = NOXTLS_AES_ROTR(val1, 8*row);
        
        state[row][0] = (uint8_t)((temp & 0xFF000000) >> 24);
        state[row][1] = (uint8_t)((temp & 0x00FF0000) >> 16);
        state[row][2] = (uint8_t)((temp & 0x0000FF00) >> 8);
        state[row][3] = (uint8_t)(temp & 0x000000FF);
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
static uint8_t aes_gf_mul(uint8_t a, uint8_t b)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t p = 0;
    for(int i = 0; i < 8; i++) {
        if(b & 1) {
            p ^= a;
        }
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if(hi_bit) {
            a ^= 0x1B;
        }
        b >>= 1;
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
    for(int j = 0; j < 4; j++) {
        uint8_t a0 = state[0][j];
        uint8_t a1 = state[1][j];
        uint8_t a2 = state[2][j];
        uint8_t a3 = state[3][j];

        state[0][j] = (uint8_t)(aes_gf_mul(a0, 0x0E) ^ aes_gf_mul(a1, 0x0B) ^
                                 aes_gf_mul(a2, 0x0D) ^ aes_gf_mul(a3, 0x09));
        state[1][j] = (uint8_t)(aes_gf_mul(a0, 0x09) ^ aes_gf_mul(a1, 0x0E) ^
                                 aes_gf_mul(a2, 0x0B) ^ aes_gf_mul(a3, 0x0D));
        state[2][j] = (uint8_t)(aes_gf_mul(a0, 0x0D) ^ aes_gf_mul(a1, 0x09) ^
                                 aes_gf_mul(a2, 0x0E) ^ aes_gf_mul(a3, 0x0B));
        state[3][j] = (uint8_t)(aes_gf_mul(a0, 0x0B) ^ aes_gf_mul(a1, 0x0D) ^
                                 aes_gf_mul(a2, 0x09) ^ aes_gf_mul(a3, 0x0E));
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

#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    rc = noxtls_aes_accel_ni_decrypt_block(key, data, output, type);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)
    rc = noxtls_aes_accel_apple_decrypt_block(key, data, output, type);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#endif

    return noxtls_aes_decrypt_block_software(key, data, output, type);
}

/**
 * @brief Decrypt one AES block with the portable software implementation.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED for disabled key sizes,
 *         or NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t noxtls_aes_decrypt_block_software(const uint8_t * key, const uint8_t * data, uint8_t * output, noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t state[4][4];
    uint32_t w[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t rounds = 0;
    uint8_t cur_round = 0;
    uint8_t key_length = 0;

    switch(type)
    {
    case NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
        rounds = NOXTLS_AES_128_ROUNDS;
        key_length = 4;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
        rounds = NOXTLS_AES_192_ROUNDS;
        key_length = 6;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
        rounds = NOXTLS_AES_256_ROUNDS;
        key_length = 8;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    default:
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
        break;
    }

    /* Copy to state */
    noxtls_aes_init_block(state, data);
    
    /* Perform Key Expansion */
    noxtls_aes_key_expansion(key, w, key_length, rounds);

    /* Add initial round key (last round key for decryption) */
    noxtls_aes_add_round_key(state, &w[(size_t)rounds * 4u]);

    /* Iterate through inverse rounds */
    for(cur_round = rounds - 1; cur_round >= 1; cur_round--)
    {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        noxtls_aes_add_round_key(state, &w[(size_t)cur_round * 4u]);
        aes_inv_mix_columns(state);
    }

    /* Final round (no mix columns) */
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    noxtls_aes_add_round_key(state, &w[0]);
    
    /* Copy output */
    copy_state_to_buffer(state, output);

    return NOXTLS_RETURN_SUCCESS;
}



#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_AES */
