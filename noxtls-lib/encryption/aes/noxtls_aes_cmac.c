/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    noxtls_aes_cmac.c
* Summary: AES-CMAC (RFC 4493 / NIST SP 800-38B).
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_aes_cmac.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES_CMAC

/** Rb from RFC 4493: 0x87 for 128-bit block */
#define AES_CMAC_RB  0x87u

/**
 * @brief Left-shift by one bit of a 16-byte block (MSB first).
 * @param block  In/out 16-byte block
 */
static void cmac_shift_left(uint8_t block[AES_BLOCK_LENGTH])
{
    int i;
    for (i = 0; i < (int)AES_BLOCK_LENGTH - 1; i++)
        block[i] = (uint8_t)((block[i] << 1) | (block[i + 1] >> 7));
    block[AES_BLOCK_LENGTH - 1] = (uint8_t)(block[AES_BLOCK_LENGTH - 1] << 1);
}

/**
 * @brief XOR subkey into the last block (for final block).
 */
static void cmac_xor_block(uint8_t dst[AES_BLOCK_LENGTH],
                           const uint8_t a[AES_BLOCK_LENGTH],
                           const uint8_t b[AES_BLOCK_LENGTH])
{
    uint32_t i;
    for (i = 0; i < AES_BLOCK_LENGTH; i++)
        dst[i] = (uint8_t)(a[i] ^ b[i]);
}

noxtls_return_t aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         aes_type_t type)
{
    uint8_t L[AES_BLOCK_LENGTH];
    uint8_t K1[AES_BLOCK_LENGTH];
    uint8_t K2[AES_BLOCK_LENGTH];
    uint8_t state[AES_BLOCK_LENGTH];
    uint32_t n_blocks;
    uint32_t i;
    noxtls_return_t r;

    if (key == NULL || mac == NULL)
        return NOXTLS_RETURN_NULL;
    if (msg_len > 0 && msg == NULL)
        return NOXTLS_RETURN_NULL;

    memset(L, 0, sizeof(L));
    r = aes_encrypt_block_internal(key, L, L, type);
    if (r != NOXTLS_RETURN_SUCCESS)
        return r;

    /* K1 = L << 1; if MSB(L) then K1 ^= Rb */
    memcpy(K1, L, AES_BLOCK_LENGTH);
    cmac_shift_left(K1);
    if (L[0] & 0x80u)
        K1[AES_BLOCK_LENGTH - 1] ^= AES_CMAC_RB;

    /* K2 = K1 << 1; if MSB(K1) then K2 ^= Rb */
    memcpy(K2, K1, AES_BLOCK_LENGTH);
    cmac_shift_left(K2);
    if (K1[0] & 0x80u)
        K2[AES_BLOCK_LENGTH - 1] ^= AES_CMAC_RB;

    n_blocks = msg_len / AES_BLOCK_LENGTH;
    memset(state, 0, AES_BLOCK_LENGTH);

    if (msg_len == 0)
    {
        /* Empty message: last "block" is 10...0 XOR K2 */
        memset(state, 0, AES_BLOCK_LENGTH);
        state[0] = 0x80u;
        cmac_xor_block(state, state, K2);
        return aes_encrypt_block_internal(key, state, mac, type);
    }

    /* Process all full blocks except the last */
    for (i = 0; i + 1 < n_blocks; i++)
    {
        cmac_xor_block(state, state, &msg[i * AES_BLOCK_LENGTH]);
        r = aes_encrypt_block_internal(key, state, state, type);
        if (r != NOXTLS_RETURN_SUCCESS)
            return r;
    }

    if (msg_len % AES_BLOCK_LENGTH != 0)
    {
        /* Incomplete last block: pad with 10...0 and XOR K2 */
        uint32_t last_off = n_blocks * AES_BLOCK_LENGTH;
        uint32_t last_len = msg_len - last_off;
        uint8_t padded[AES_BLOCK_LENGTH];
        memset(padded, 0, AES_BLOCK_LENGTH);
        memcpy(padded, &msg[last_off], last_len);
        padded[last_len] = 0x80u;
        cmac_xor_block(state, state, padded);
        cmac_xor_block(state, state, K2);
    }
    else
    {
        /* Complete last block: XOR with K1 */
        cmac_xor_block(state, state, &msg[(n_blocks - 1) * AES_BLOCK_LENGTH]);
        cmac_xor_block(state, state, K1);
    }

    return aes_encrypt_block_internal(key, state, mac, type);
}

#endif /* NOXTLS_FEATURE_AES_CMAC */
