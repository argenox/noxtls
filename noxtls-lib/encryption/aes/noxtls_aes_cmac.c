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

#if NOXTLS_FEATURE_AES_CMAC

/** Rb from RFC 4493: 0x87 for 128-bit block */
#define NOXTLS_AES_CMAC_RB  0x87U

/**
 * @brief Left-shift by one bit of a 16-byte block (MSB first).
 *
 * @param block  In/out 16-byte block
 * @return None.
 */
static void cmac_shift_left(uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    int i;
    for(i = 0; i < (int)NOXTLS_AES_BLOCK_LENGTH - 1; i++) {
        block[i] = (uint8_t)((block[i] << 1) | (block[i + 1] >> 7));
    }
    block[NOXTLS_AES_BLOCK_LENGTH - 1] = (uint8_t)(block[NOXTLS_AES_BLOCK_LENGTH - 1] << 1);
}

/**
 * @brief XOR subkey into the last block (for final block).
 *
 * @param dst  Destination buffer
 * @param a    First source buffer
 * @param b    Second source buffer
 *
 * @return None.
 */
static void cmac_xor_block(uint8_t dst[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t a[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t b[NOXTLS_AES_BLOCK_LENGTH])
{
    uint32_t i;
    for(i = 0; i < NOXTLS_AES_BLOCK_LENGTH; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/**
 * @brief Resolve AES key length from type.
 */
static noxtls_return_t cmac_key_len_from_type(noxtls_aes_type_t type,
                                              uint8_t *key_len)
{
    if(key_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type)
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
    cmac_xor_block(ctx->state, ctx->state, block);
    return noxtls_aes_encrypt_block_internal(ctx->key, ctx->state, ctx->state,
                                             ctx->type);
}

noxtls_return_t noxtls_aes_cmac_init(noxtls_aes_cmac_context_t *ctx,
                                     const uint8_t *key,
                                     noxtls_aes_type_t type)
{
    uint8_t l[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc;

    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    rc = cmac_key_len_from_type(type, &ctx->key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memcpy(ctx->key, key, ctx->key_len);

    memset(l, 0, sizeof(l));
    rc = noxtls_aes_encrypt_block_internal(ctx->key, l, l, type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memcpy(ctx->subkey1, l, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(ctx->subkey1);
    if(l[0] & 0x80U) {
        ctx->subkey1[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;
    }

    memcpy(ctx->subkey2, ctx->subkey1, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(ctx->subkey2);
    if(ctx->subkey1[0] & 0x80U) {
        ctx->subkey2[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_update(noxtls_aes_cmac_context_t *ctx,
                                       const uint8_t *msg,
                                       uint32_t msg_len)
{
    uint32_t offset = 0U;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(msg_len > 0U && msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(msg_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Fill any partial block first. */
    if(ctx->partial_len > 0U)
    {
        uint32_t need = NOXTLS_AES_BLOCK_LENGTH - (uint32_t)ctx->partial_len;
        uint32_t take = (msg_len < need) ? msg_len : need;
        memcpy(&ctx->partial[ctx->partial_len], msg, take);
        ctx->partial_len = (uint8_t)(ctx->partial_len + take);
        offset += take;

        /* Keep a full block buffered until we know more data follows. */
        if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH && offset < msg_len)
        {
            rc = cmac_absorb_block(ctx, ctx->partial);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->partial_len = 0U;
        }
    }

    while((msg_len - offset) > NOXTLS_AES_BLOCK_LENGTH)
    {
        rc = cmac_absorb_block(ctx, &msg[offset]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        offset += NOXTLS_AES_BLOCK_LENGTH;
    }

    if(offset < msg_len)
    {
        uint32_t rem = msg_len - offset;
        memcpy(ctx->partial, &msg[offset], rem);
        ctx->partial_len = (uint8_t)rem;
    }

    ctx->total_len += msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_final(noxtls_aes_cmac_context_t *ctx,
                                      uint8_t *mac)
{
    uint8_t final_block[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc;

    if(ctx == NULL || mac == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    memset(final_block, 0, sizeof(final_block));

    if(ctx->total_len == 0U)
    {
        final_block[0] = 0x80U;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }
    else if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH)
    {
        memcpy(final_block, ctx->partial, NOXTLS_AES_BLOCK_LENGTH);
        cmac_xor_block(final_block, final_block, ctx->subkey1);
    }
    else
    {
        memcpy(final_block, ctx->partial, ctx->partial_len);
        final_block[ctx->partial_len] = 0x80U;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }

    rc = cmac_absorb_block(ctx, final_block);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memcpy(mac, ctx->state, NOXTLS_AES_BLOCK_LENGTH);
    ctx->initialized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Resolve AES key length from type.
 */
static noxtls_return_t cmac_key_len_from_type(noxtls_aes_type_t type,
                                              uint8_t *key_len)
{
    if(key_len == NULL)
        return NOXTLS_RETURN_NULL;

    switch(type)
    {
        case NOXTLS_AES_128_BIT:
            *key_len = 16u;
            break;
        case NOXTLS_AES_192_BIT:
            *key_len = 24u;
            break;
        case NOXTLS_AES_256_BIT:
            *key_len = 32u;
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
    cmac_xor_block(ctx->state, ctx->state, block);
    return noxtls_aes_encrypt_block_internal(ctx->key, ctx->state, ctx->state,
                                             ctx->type);
}

noxtls_return_t noxtls_aes_cmac_init(noxtls_aes_cmac_context_t *ctx,
                                     const uint8_t *key,
                                     noxtls_aes_type_t type)
{
    uint8_t l[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc;

    if(ctx == NULL || key == NULL)
        return NOXTLS_RETURN_NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    rc = cmac_key_len_from_type(type, &ctx->key_len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return rc;
    memcpy(ctx->key, key, ctx->key_len);

    memset(l, 0, sizeof(l));
    rc = noxtls_aes_encrypt_block_internal(ctx->key, l, l, type);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return rc;

    memcpy(ctx->subkey1, l, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(ctx->subkey1);
    if(l[0] & 0x80u)
        ctx->subkey1[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;

    memcpy(ctx->subkey2, ctx->subkey1, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(ctx->subkey2);
    if(ctx->subkey1[0] & 0x80u)
        ctx->subkey2[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;

    ctx->initialized = 1u;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_update(noxtls_aes_cmac_context_t *ctx,
                                       const uint8_t *msg,
                                       uint32_t msg_len)
{
    uint32_t offset = 0u;
    noxtls_return_t rc;

    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;
    if(ctx->initialized == 0u)
        return NOXTLS_RETURN_NOT_INITIALIZED;
    if(msg_len > 0u && msg == NULL)
        return NOXTLS_RETURN_NULL;

    if(msg_len == 0u)
        return NOXTLS_RETURN_SUCCESS;

    /* Fill any partial block first. */
    if(ctx->partial_len > 0u)
    {
        uint32_t need = NOXTLS_AES_BLOCK_LENGTH - (uint32_t)ctx->partial_len;
        uint32_t take = (msg_len < need) ? msg_len : need;
        memcpy(&ctx->partial[ctx->partial_len], msg, take);
        ctx->partial_len = (uint8_t)(ctx->partial_len + take);
        offset += take;

        /* Keep a full block buffered until we know more data follows. */
        if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH && offset < msg_len)
        {
            rc = cmac_absorb_block(ctx, ctx->partial);
            if(rc != NOXTLS_RETURN_SUCCESS)
                return rc;
            ctx->partial_len = 0u;
        }
    }

    while((msg_len - offset) > NOXTLS_AES_BLOCK_LENGTH)
    {
        rc = cmac_absorb_block(ctx, &msg[offset]);
        if(rc != NOXTLS_RETURN_SUCCESS)
            return rc;
        offset += NOXTLS_AES_BLOCK_LENGTH;
    }

    if(offset < msg_len)
    {
        uint32_t rem = msg_len - offset;
        memcpy(ctx->partial, &msg[offset], rem);
        ctx->partial_len = (uint8_t)rem;
    }

    ctx->total_len += msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_cmac_final(noxtls_aes_cmac_context_t *ctx,
                                      uint8_t *mac)
{
    uint8_t final_block[NOXTLS_AES_BLOCK_LENGTH];
    noxtls_return_t rc;

    if(ctx == NULL || mac == NULL)
        return NOXTLS_RETURN_NULL;
    if(ctx->initialized == 0u)
        return NOXTLS_RETURN_NOT_INITIALIZED;

    memset(final_block, 0, sizeof(final_block));

    if(ctx->total_len == 0u)
    {
        final_block[0] = 0x80u;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }
    else if(ctx->partial_len == NOXTLS_AES_BLOCK_LENGTH)
    {
        memcpy(final_block, ctx->partial, NOXTLS_AES_BLOCK_LENGTH);
        cmac_xor_block(final_block, final_block, ctx->subkey1);
    }
    else
    {
        memcpy(final_block, ctx->partial, ctx->partial_len);
        final_block[ctx->partial_len] = 0x80u;
        cmac_xor_block(final_block, final_block, ctx->subkey2);
    }

    rc = cmac_absorb_block(ctx, final_block);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return rc;

    memcpy(mac, ctx->state, NOXTLS_AES_BLOCK_LENGTH);
    ctx->initialized = 0u;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute AES-CMAC over a message (RFC 4493).
 *
 * @param key    AES key (16 bytes for AES-128)
 * @param msg    Message to authenticate
 * @param msg_len Message length in bytes
 * @param mac    Output buffer for 16-byte MAC
 * @param type   AES key type (NOXTLS_AES_128_BIT recommended)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_aes_cmac_context_t ctx;
    noxtls_return_t rc;

    rc = noxtls_aes_cmac_init(&ctx, key, type);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return rc;

    rc = noxtls_aes_cmac_update(&ctx, msg, msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return rc;

    return noxtls_aes_cmac_final(&ctx, mac);
}

#endif /* NOXTLS_FEATURE_AES_CMAC */
