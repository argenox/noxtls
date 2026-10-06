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
* File:    noxtls_aes_cmac.c
* Summary: AES-CMAC (RFC 4493 / NIST SP 800-38B).
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_aes_cmac.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_AES_CMAC

/** Rb from RFC 4493: 0x87 for 128-bit block */
#define NOXTLS_AES_CMAC_RB  0x87U

/**
 * @brief Left-shift by one bit of a 16-byte block (MSB first).
 */
static void cmac_shift_left(uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    uint32_t i = 0U;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    for (i = 0U; i < (block_sz - 1U); i += 1U) {
        block[i] = (uint8_t)((((uint32_t)block[i] << 1U)
                              | (((uint32_t)block[i + 1U]) >> 7U)));
    }
    block[block_sz - 1U] = (uint8_t)(((uint32_t)block[block_sz - 1U]) << 1U);
}

/**
 * @brief XOR two blocks into destination.
 */
static void cmac_xor_block(uint8_t dst[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t a[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t b[NOXTLS_AES_BLOCK_LENGTH])
{
    uint32_t i = 0U;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    for (i = 0U; i < block_sz; i += 1U) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/**
 * @brief Resolve AES key length from type.
 */
static noxtls_return_t cmac_key_len_from_type(noxtls_aes_type_t type,
                                              uint8_t *key_len)
{
    if (key_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch (type)
    {
        case NOXTLS_AES_128_BIT:
            *key_len = 16U;
            break;
        case NOXTLS_AES_192_BIT:
            *key_len = 24U;
            break;
        case NOXTLS_AES_256_BIT:
            *key_len = 32U;
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Absorb one complete CMAC block into context state.
 */
static noxtls_return_t cmac_absorb_block(noxtls_aes_cmac_context_t *ctx,
                                         const uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    uint8_t state_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t input_block[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_copy_u8(state_block, sizeof(state_block), ctx->state, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
    noxtls_copy_u8(input_block, sizeof(input_block), block, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
    cmac_xor_block(state_block, state_block, input_block);
    {
        noxtls_return_t rc = noxtls_aes_encrypt_block_internal(ctx->key, state_block, state_block,
                                                              ctx->type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    noxtls_copy_u8(ctx->state, sizeof(ctx->state), state_block, (size_t)(NOXTLS_AES_BLOCK_LENGTH));
    return NOXTLS_RETURN_SUCCESS;
}

/* Streaming CMAC API; extents follow AES block size and caller lengths. */
noxtls_return_t noxtls_aes_cmac_init(noxtls_aes_cmac_context_t *ctx,
                                     const uint8_t *key,
                                     noxtls_aes_type_t type)
{
    uint8_t l[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    ctx->type = type;
    rc = cmac_key_len_from_type(type, &ctx->key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }
    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)(ctx->key_len));

    noxtls_secure_zero((l), sizeof(l));
    rc = noxtls_aes_encrypt_block_internal(ctx->key, l, l, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }

    noxtls_copy_u8(ctx->subkey1, sizeof(ctx->subkey1), l, (size_t)(block_sz));
    cmac_shift_left(ctx->subkey1);
    if ((l[0] & 0x80U) != 0U) {
        ctx->subkey1[block_sz - 1U] ^= (uint8_t)NOXTLS_AES_CMAC_RB;
    }

    noxtls_copy_u8(ctx->subkey2, sizeof(ctx->subkey2), ctx->subkey1, (size_t)(block_sz));
    cmac_shift_left(ctx->subkey2);
    if ((ctx->subkey1[0] & 0x80U) != 0U) {
        ctx->subkey2[block_sz - 1U] ^= (uint8_t)NOXTLS_AES_CMAC_RB;
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_update(noxtls_aes_cmac_context_t *ctx,
                                       const uint8_t *msg,
                                       uint32_t msg_len)
{
    uint32_t offset = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if ((msg_len > 0U) && (msg == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (msg_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Fill any partial block first. */
    if (ctx->partial_len > 0U)
    {
        uint32_t need = (uint32_t)(block_sz - (uint32_t)ctx->partial_len);
        uint32_t take = (uint32_t)((msg_len < need) ? msg_len : need);
        noxtls_copy_u8(&ctx->partial[ctx->partial_len], sizeof(ctx->partial) - (size_t)(ctx->partial_len), msg, (size_t)(take));
        ctx->partial_len = (uint8_t)(ctx->partial_len + take);
        offset += take;

        /* Keep a full block buffered until we know more data follows. */
        if ((ctx->partial_len == (uint8_t)block_sz) && (offset < msg_len))
        {
            {
                uint8_t full_block[NOXTLS_AES_BLOCK_LENGTH];
                noxtls_copy_u8(full_block, sizeof(full_block), ctx->partial, (size_t)(block_sz));
                rc = cmac_absorb_block(ctx, full_block);
            }
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(ctx, sizeof(*ctx));
                return rc;
            }
            ctx->partial_len = 0U;
        }
    }

    while ((msg_len - offset) > block_sz)
    {
        uint8_t full_block[NOXTLS_AES_BLOCK_LENGTH];
        noxtls_copy_u8(full_block, sizeof(full_block), &msg[offset], (size_t)(block_sz));
        rc = cmac_absorb_block(ctx, full_block);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return rc;
        }
        offset += block_sz;
    }

    if (offset < msg_len)
    {
        uint32_t rem = (uint32_t)(msg_len - offset);
        noxtls_copy_u8(ctx->partial, sizeof(ctx->partial), &msg[offset], (size_t)(rem));
        ctx->partial_len = (uint8_t)rem;
    }

    ctx->total_len += msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_final(noxtls_aes_cmac_context_t *ctx,
                                      uint8_t *mac)
{
    uint8_t final_block[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    if ((ctx == NULL) || (mac == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    noxtls_secure_zero((final_block), sizeof(final_block));

    if (ctx->total_len == 0U)
    {
        final_block[0] = 0x80U;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }
    else if (ctx->partial_len == (uint8_t)block_sz)
    {
        noxtls_copy_u8(final_block, sizeof(final_block), ctx->partial, (size_t)(block_sz));
        cmac_xor_block(final_block, final_block, ctx->subkey1);
    }
    else
    {
        noxtls_copy_u8(final_block, sizeof(final_block), ctx->partial, (size_t)(ctx->partial_len));
        final_block[ctx->partial_len] = 0x80U;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }

    rc = cmac_absorb_block(ctx, final_block);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(final_block, sizeof(final_block));
        noxtls_secure_zero(mac, NOXTLS_AES_BLOCK_LENGTH);
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }

    noxtls_copy_u8(mac, (size_t)block_sz, ctx->state, (size_t)(block_sz));
    ctx->initialized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute AES-CMAC over a message (RFC 4493).
 */
noxtls_return_t noxtls_aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         noxtls_aes_type_t type)
{
    noxtls_aes_cmac_context_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_aes_cmac_init(&ctx, key, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(mac, NOXTLS_AES_BLOCK_LENGTH);
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return rc;
    }

    rc = noxtls_aes_cmac_update(&ctx, msg, msg_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(mac, NOXTLS_AES_BLOCK_LENGTH);
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return rc;
    }

    rc = noxtls_aes_cmac_final(&ctx, mac);
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* NOXTLS_FEATURE_AES_CMAC */
