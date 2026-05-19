/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_aes_ccm.c
* Summary: AES-CCM (Counter with CBC-MAC) - NIST SP 800-38C / RFC 3610
*/

/** @addtogroup noxtls_encryption */

#include <string.h>
#include "noxtls_aes_ccm.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES_CCM

/**
 * @brief Compute the MAC
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param B0 is the B0 to use
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param payload is the payload to use
 * @param payload_len is the length of the payload
 * @param mac_state is the MAC state to use
 *
 */
static void ccm_compute_mac(const uint8_t *key, noxtls_aes_type_t type,
                            const uint8_t *B0,
                            const uint8_t *aad, uint32_t aad_len,
                            const uint8_t *payload, uint32_t payload_len,
                            uint8_t *mac_state);

/**
 * @brief Validate an AES-CCM authentication tag length.
 * @param tag_len Tag length in bytes.
 * @return 1 when tag_len is one of 4, 6, 8, 10, 12, 14, or 16; 0 otherwise.
 */
static int tag_len_valid(uint32_t tag_len)
{
    return (tag_len >= 4U && tag_len <= 16U && (tag_len & 1U) == 0);
}

/* Nonce length 7..13 -> L = 15 - nonce_len in 2..8 */
/**
 * @brief Validate the nonce length
 *
 * @param nonce_len is the length of the nonce
 *
 * @return 1 if the nonce length is valid, 0 otherwise
 */
static int nonce_len_valid(uint32_t nonce_len)
{
    return (nonce_len >= 7U && nonce_len <= 13U);
}

/* Increment L-byte big-endian counter at the end of block (offset 16-L) */
/**
 * @brief Increment the counter
 *
 * @param block is the block to increment
 * @param L is the length of the block
 *
 * @return None.
 */
static void ccm_inc_counter(uint8_t *block, uint32_t L)
{
    uint32_t i = 15;
    uint32_t stop = 16 - L;
    for(; i >= stop && i <= 15; i--) {
        block[i]++;
        if(block[i] != 0) break;
    }
}

/* CBC-MAC one block: out = E(xor(block, state)); state updated in place */
/**
 * @brief CBC-MAC one block
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param block is the block to use
 * @param state is the state to use
 */
static void ccm_cbc_mac_block(const uint8_t *key, noxtls_aes_type_t type,
                             const uint8_t *block, uint8_t *state)
{
    for(uint32_t i = 0; i < NOXTLS_AES_BLOCK; i++)
        state[i] ^= block[i];
    noxtls_aes_encrypt_block_internal(key, state, state, type);
}

/**
 * @brief AES-CCM encrypt
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param nonce is the nonce to use
 * @param nonce_len is the length of the nonce
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param plaintext is the plaintext to use
 * @param plaintext_len is the length of the plaintext
 * @param ciphertext is the ciphertext to use
 * @param tag is the tag to use
 * @param tag_len is the length of the tag
 *
 * @return 0 on success, -1 on failure
 */
noxtls_return_t noxtls_aes_ccm_encrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce, uint32_t nonce_len,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag, uint32_t tag_len)
{
    uint32_t L = 15 - nonce_len;
    uint8_t B0[NOXTLS_AES_BLOCK];
    uint8_t mac_state[NOXTLS_AES_BLOCK];
    uint8_t ctr_block[NOXTLS_AES_BLOCK];
    uint8_t keystream[NOXTLS_AES_BLOCK];
    uint32_t i;

    if(!key || !nonce || !plaintext || !ciphertext || !tag)
        return NOXTLS_RETURN_NULL;
    if(!nonce_len_valid(nonce_len) || !tag_len_valid(tag_len))
        return NOXTLS_RETURN_INVALID_PARAM;
    if(plaintext_len > (1UL << (L * 8)) - 1UL)
        return NOXTLS_RETURN_INVALID_PARAM;

    /* B0: Flags | Nonce | Q */
    B0[0] = (uint8_t)((aad_len > 0 ? 0x40 : 0) | (((tag_len - 2) >> 1) << 3) | (L - 1));
    memcpy(B0 + 1, nonce, nonce_len);
    for(i = 0; i < L; i++)
        B0[16 - L + i] = (uint8_t)((plaintext_len >> (8 * (L - 1 - i))) & 0xff);

    ccm_compute_mac(key, type, B0, aad, aad_len, plaintext, plaintext_len, mac_state);

    /* CTR: counter block = [L-1] [nonce] [counter]; start at 0 for tag */
    memset(ctr_block, 0, NOXTLS_AES_BLOCK);
    ctr_block[0] = (uint8_t)(L - 1);
    memcpy(ctr_block + 1, nonce, nonce_len);
    /* counter at ctr_block + 1 + nonce_len = 16 - L bytes at end */

    noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
    for(i = 0; i < tag_len; i++)
        tag[i] = mac_state[i] ^ keystream[i];

    /* CTR encrypt payload: counter 1, 2, ... */
    ccm_inc_counter(ctr_block, L);
    for(i = 0; i < plaintext_len; i += NOXTLS_AES_BLOCK) {
        noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
        uint32_t take = plaintext_len - i;
        if(take > NOXTLS_AES_BLOCK) take = NOXTLS_AES_BLOCK;
        for(uint32_t j = 0; j < take; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        ccm_inc_counter(ctr_block, L);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Compute CCM CBC-MAC over B0, AAD, and payload (plaintext). Used by both encrypt and decrypt. */
/**
 * @brief Compute the MAC
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param B0 is the B0 to use
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param payload is the payload to use
 * @param payload_len is the length of the payload
 * @param mac_state is the MAC state to use
 *
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ccm_compute_mac(const uint8_t *key, noxtls_aes_type_t type,
                            const uint8_t *B0,
                            const uint8_t *aad, uint32_t aad_len,
                            const uint8_t *payload, uint32_t payload_len,
                            uint8_t *mac_state)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t i;
    uint32_t n_blocks;
    uint8_t aad_buf[18];

    memset(mac_state, 0, NOXTLS_AES_BLOCK);
    ccm_cbc_mac_block(key, type, B0, mac_state);

    if(aad_len > 0) {
        uint32_t aad_enc_len;
        const uint8_t *aad_enc;

        if(aad_len < 0xFF00U) {
            aad_buf[0] = (uint8_t)(aad_len >> 8);
            aad_buf[1] = (uint8_t)(aad_len & 0xff);
            aad_enc = aad_buf;
            aad_enc_len = 2;
        } else {
            aad_buf[0] = 0xff;
            aad_buf[1] = 0xfe;
            aad_buf[2] = (uint8_t)(aad_len >> 24);
            aad_buf[3] = (uint8_t)(aad_len >> 16);
            aad_buf[4] = (uint8_t)(aad_len >> 8);
            aad_buf[5] = (uint8_t)(aad_len & 0xff);
            aad_enc = aad_buf;
            aad_enc_len = 6;
        }
        n_blocks = (aad_enc_len + aad_len + (NOXTLS_AES_BLOCK - 1)) / NOXTLS_AES_BLOCK;
        for(i = 0; i < n_blocks; i++) {
            uint8_t block[NOXTLS_AES_BLOCK];
            memset(block, 0, NOXTLS_AES_BLOCK);
            uint32_t off = i * NOXTLS_AES_BLOCK;
            if(off < aad_enc_len) {
                uint32_t copy = NOXTLS_AES_BLOCK;
                uint32_t from_enc = aad_enc_len - off;
                if(from_enc < copy) copy = from_enc;
                memcpy(block, aad_enc + off, copy);
                if(copy < NOXTLS_AES_BLOCK) {
                    uint32_t from_aad = NOXTLS_AES_BLOCK - copy;
                    if(from_aad > aad_len) from_aad = aad_len;
                    memcpy(block + copy, aad, from_aad);
                }
            } else {
                uint32_t aad_off = off - aad_enc_len;
                if(aad_off < aad_len) {
                    uint32_t from_aad = aad_len - aad_off;
                    if(from_aad > NOXTLS_AES_BLOCK) from_aad = NOXTLS_AES_BLOCK;
                    memcpy(block, aad + aad_off, from_aad);
                }
            }
            ccm_cbc_mac_block(key, type, block, mac_state);
        }
    }

    n_blocks = (payload_len + (NOXTLS_AES_BLOCK - 1)) / NOXTLS_AES_BLOCK;
    for(i = 0; i < n_blocks; i++) {
        uint8_t block[NOXTLS_AES_BLOCK];
        memset(block, 0, NOXTLS_AES_BLOCK);
        uint32_t off = i * NOXTLS_AES_BLOCK;
        uint32_t copy = payload_len - off;
        if(copy > NOXTLS_AES_BLOCK) copy = NOXTLS_AES_BLOCK;
        memcpy(block, payload + off, copy);
        ccm_cbc_mac_block(key, type, block, mac_state);
    }
}

/**
 * @brief AES-CCM decrypt
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param nonce is the nonce to use
 * @param nonce_len is the length of the nonce
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param ciphertext is the ciphertext to use
 * @param ciphertext_len is the length of the ciphertext
 * @param tag is the tag to use
 * @param tag_len is the length of the tag
 * @param plaintext is the plaintext to use
 *
 * @return 0 on success, -1 on failure
 */
noxtls_return_t noxtls_aes_ccm_decrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce, uint32_t nonce_len,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t *tag, uint32_t tag_len,
                    uint8_t *plaintext)
{
    uint32_t L = 15 - nonce_len;
    uint8_t B0[NOXTLS_AES_BLOCK];
    uint8_t mac_state[NOXTLS_AES_BLOCK];
    uint8_t ctr_block[NOXTLS_AES_BLOCK];
    uint8_t keystream[NOXTLS_AES_BLOCK];
    uint32_t i;
    uint8_t diff;

    if(!key || !nonce || !ciphertext || !tag || !plaintext)
        return NOXTLS_RETURN_NULL;
    if(!nonce_len_valid(nonce_len) || !tag_len_valid(tag_len))
        return NOXTLS_RETURN_INVALID_PARAM;
    if(ciphertext_len > (1UL << (L * 8)) - 1UL)
        return NOXTLS_RETURN_INVALID_PARAM;

    /* 1) CTR decrypt to get plaintext (counter 0 = tag mask, 1,2,... = payload) */
    memset(ctr_block, 0, NOXTLS_AES_BLOCK);
    ctr_block[0] = (uint8_t)(L - 1);
    memcpy(ctr_block + 1, nonce, nonce_len);

    noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
    ccm_inc_counter(ctr_block, L);

    for(i = 0; i < ciphertext_len; i += NOXTLS_AES_BLOCK) {
        noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
        uint32_t take = ciphertext_len - i;
        if(take > NOXTLS_AES_BLOCK) take = NOXTLS_AES_BLOCK;
        for(uint32_t j = 0; j < take; j++)
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        ccm_inc_counter(ctr_block, L);
    }

    /* 2) B0 and compute MAC over B0, AAD, plaintext */
    B0[0] = (uint8_t)((aad_len > 0 ? 0x40 : 0) | (((tag_len - 2) >> 1) << 3) | (L - 1));
    memcpy(B0 + 1, nonce, nonce_len);
    for(i = 0; i < L; i++)
        B0[16 - L + i] = (uint8_t)((ciphertext_len >> (8 * (L - 1 - i))) & 0xff);

    ccm_compute_mac(key, type, B0, aad, aad_len, plaintext, ciphertext_len, mac_state);

    /* 3) Tag = MAC XOR E(CTR_0). We have E(CTR_0) in keystream from first block - but we overwrote it. Recompute counter 0 keystream. */
    memset(ctr_block, 0, NOXTLS_AES_BLOCK);
    ctr_block[0] = (uint8_t)(L - 1);
    memcpy(ctr_block + 1, nonce, nonce_len);
    noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);

    diff = 0;
    for(i = 0; i < tag_len; i++)
        diff |= (tag[i] ^ (mac_state[i] ^ keystream[i]));
    if(diff != 0)
        return NOXTLS_RETURN_BAD_DATA;
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CCM */
