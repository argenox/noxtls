/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
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
#define NOXTLS_AES_CMAC_RB  0x87u

/**
 * @brief Left-shift by one bit of a 16-byte block (MSB first).
 * @param block  In/out 16-byte block
 * @return None.
 */
static void cmac_shift_left(uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    int i;
    for(i = 0; i < (int)NOXTLS_AES_BLOCK_LENGTH - 1; i++)
        block[i] = (uint8_t)((block[i] << 1) | (block[i + 1] >> 7));
    block[NOXTLS_AES_BLOCK_LENGTH - 1] = (uint8_t)(block[NOXTLS_AES_BLOCK_LENGTH - 1] << 1);
}

/**
 * @brief XOR subkey into the last block (for final block).
 */
static void cmac_xor_block(uint8_t dst[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t a[NOXTLS_AES_BLOCK_LENGTH],
                           const uint8_t b[NOXTLS_AES_BLOCK_LENGTH])
{
    uint32_t i;
    for(i = 0; i < NOXTLS_AES_BLOCK_LENGTH; i++)
        dst[i] = (uint8_t)(a[i] ^ b[i]);
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t L[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t K1[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t K2[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t state[NOXTLS_AES_BLOCK_LENGTH];
    uint32_t n_blocks;
    uint32_t i;
    noxtls_return_t r;

    if(key == NULL || mac == NULL)
        return NOXTLS_RETURN_NULL;
    if(msg_len > 0 && msg == NULL)
        return NOXTLS_RETURN_NULL;

    memset(L, 0, sizeof(L));
    r = noxtls_aes_encrypt_block_internal(key, L, L, type);
    if(r != NOXTLS_RETURN_SUCCESS)
        return r;

    /* K1 = L << 1; if MSB(L) then K1 ^= Rb */
    memcpy(K1, L, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(K1);
    if(L[0] & 0x80u)
        K1[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;

    /* K2 = K1 << 1; if MSB(K1) then K2 ^= Rb */
    memcpy(K2, K1, NOXTLS_AES_BLOCK_LENGTH);
    cmac_shift_left(K2);
    if(K1[0] & 0x80u)
        K2[NOXTLS_AES_BLOCK_LENGTH - 1] ^= NOXTLS_AES_CMAC_RB;

    n_blocks = msg_len / NOXTLS_AES_BLOCK_LENGTH;
    memset(state, 0, NOXTLS_AES_BLOCK_LENGTH);

    if(msg_len == 0)
    {
        /* Empty noxtls_message: last "block" is 10...0 XOR K2 */
        memset(state, 0, NOXTLS_AES_BLOCK_LENGTH);
        state[0] = 0x80u;
        cmac_xor_block(state, state, K2);
        return noxtls_aes_encrypt_block_internal(key, state, mac, type);
    }

    /* Process all full blocks except the last */
    for(i = 0; i + 1 < n_blocks; i++)
    {
        cmac_xor_block(state, state, &msg[(size_t)i * NOXTLS_AES_BLOCK_LENGTH]);
        r = noxtls_aes_encrypt_block_internal(key, state, state, type);
        if(r != NOXTLS_RETURN_SUCCESS)
            return r;
    }

    if(msg_len % NOXTLS_AES_BLOCK_LENGTH != 0)
    {
        /* Incomplete last block: pad with 10...0 and XOR K2 */
        uint32_t last_off = n_blocks * NOXTLS_AES_BLOCK_LENGTH;
        uint32_t last_len = msg_len - last_off;
        uint8_t padded[NOXTLS_AES_BLOCK_LENGTH];
        memset(padded, 0, NOXTLS_AES_BLOCK_LENGTH);
        memcpy(padded, &msg[last_off], last_len);
        padded[last_len] = 0x80u;
        cmac_xor_block(state, state, padded);
        cmac_xor_block(state, state, K2);
    }
    else
    {
        /* Complete last block: XOR with K1 */
        cmac_xor_block(state, state, &msg[(size_t)(n_blocks - 1u) * NOXTLS_AES_BLOCK_LENGTH]);
        cmac_xor_block(state, state, K1);
    }

    return noxtls_aes_encrypt_block_internal(key, state, mac, type);
}

#endif /* NOXTLS_FEATURE_AES_CMAC */
