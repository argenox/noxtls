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
* File:    noxtls_aes_ccm.c
* Summary: AES-CCM (Counter with CBC-MAC) - NIST SP 800-38C / RFC 3610
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <string.h>
#include "noxtls_aes_ccm.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "common/noxtls_ct.h"
#include "noxtls_ct.h"

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
static uint8_t tag_len_valid(uint32_t tag_len) { return (uint8_t)(((tag_len >= 4U) && (tag_len <= 16U) && ((tag_len & 1U) == 0U)) ? 1U : 0U); }

/* Nonce length 7..13 -> L = 15 - nonce_len in 2..8 */
/**
 * @brief Validate the nonce length
 *
 * @param nonce_len is the length of the nonce
 *
 * @return 1 if the nonce length is valid, 0 otherwise
 */
static uint8_t nonce_len_valid(uint32_t nonce_len) { return (uint8_t)(((nonce_len >= 7U) && (nonce_len <= 13U)) ? 1U : 0U); }

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
    uint32_t i = 15U;
    const uint32_t stop = 16U - L;
    uint32_t done = 0U;
    for (; (done == 0U) && (i >= stop) && (i <= 15U); i -= 1U) {
        block[i] = (uint8_t)(block[i] + 1U);
        if ((block[i] != 0U) || (i == 0U)) {
            done = 1U;
        }
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
    uint32_t i = 0U;
    for (i = 0U; i < (uint32_t)NOXTLS_AES_BLOCK; i += 1U) {
        state[i] ^= block[i];
    }
    (void)noxtls_aes_encrypt_block_internal(key, state, state, type);
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
    uint32_t L = (uint32_t)(15U - nonce_len);
    uint8_t B0[NOXTLS_AES_BLOCK];
    uint8_t mac_state[NOXTLS_AES_BLOCK];
    uint8_t ctr_block[NOXTLS_AES_BLOCK];
    uint8_t keystream[NOXTLS_AES_BLOCK];
    uint32_t i = 0U;

    if ((key == NULL) || (nonce == NULL) || (plaintext == NULL) || (ciphertext == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((nonce_len_valid(nonce_len) == 0U) || (tag_len_valid(tag_len) == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    {
        /* L in 2..8; bound plaintext length for L=2 (16-bit Q) and L=3 (24-bit Q). */
        if (L == 2U) {
            if (plaintext_len > 0xFFFFUL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
        } else if (L == 3U) {
            if (plaintext_len > 0xFFFFFFUL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }
    }

    /* B0: Flags | Nonce | Q */
    B0[0] = (uint8_t)(((aad_len > 0U) ? 0x40U : 0U) | ((((tag_len - 2U) >>1U) <<3U) | (L - 1U)));
    noxtls_copy_u8(&B0[1], sizeof(B0) - (size_t)(1), nonce, (size_t)(nonce_len));
    for (i = 0U; i < L; i += 1U) {
        uint32_t pos = (uint32_t)(L - 1U - i);
        uint8_t b = 0U;
        switch(pos) {
        case 0U: b = (uint8_t)(plaintext_len); break;
        case 1U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 8U); break;
        case 2U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 16U); break;
        case 3U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 24U); break;
        case 4U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 32U); break;
        case 5U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 40U); break;
        case 6U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 48U); break;
        case 7U: b = (uint8_t)((uint64_t)(uint32_t)plaintext_len >> 56U); break;
        default: b = 0U; break;
        }
        B0[16U - L + i] = b;
    }

    ccm_compute_mac(key, type, B0, aad, aad_len, plaintext, plaintext_len, mac_state);

    /* CTR: counter block = [L-1] [nonce] [counter]; start at 0 for tag */
    noxtls_secure_zero((ctr_block), (size_t)(NOXTLS_AES_BLOCK));
    ctr_block[0] = (uint8_t)(L - 1U);
    noxtls_copy_u8(&ctr_block[1], sizeof(ctr_block) - (size_t)(1), nonce, (size_t)(nonce_len));

    (void)noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
    for (i = 0U; i < tag_len; i += 1U) {
        tag[i] = (uint8_t)(mac_state[i] ^ keystream[i]);
    }

    /* CTR encrypt payload: counter 1, 2, ... */
    ccm_inc_counter(ctr_block, L);
    for (i = 0U; i < plaintext_len; i += (uint32_t)NOXTLS_AES_BLOCK) {
        uint32_t take = 0U;
        uint32_t j = 0U;
        (void)noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
        take = plaintext_len - i;
        if (take > (uint32_t)NOXTLS_AES_BLOCK) {
            take = (uint32_t)NOXTLS_AES_BLOCK;
        }
        for (j = 0U; j < take; j += 1U) {
            ciphertext[i + j] = (uint8_t)(plaintext[i + j] ^ keystream[j]);
        }
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
    uint32_t i = 0U;
    uint32_t n_blocks = 0U;
    uint8_t aad_buf[18];

    noxtls_secure_zero((mac_state), (size_t)(NOXTLS_AES_BLOCK));
    ccm_cbc_mac_block(key, type, B0, mac_state);

    if (aad_len > 0U) {
        uint32_t aad_enc_len = 0U;
        const uint8_t *aad_enc = NULL;

        if (aad_len < 0xFF00U) {
            aad_buf[0] = (uint8_t)(aad_len >>8U);
            aad_buf[1] = (uint8_t)(aad_len & 0xffU);
            aad_enc = aad_buf;
            aad_enc_len = 2U;
        } else {
            aad_buf[0] = 0xffU;
            aad_buf[1] = 0xfeU;
            aad_buf[2] = (uint8_t)(aad_len >>24U);
            aad_buf[3] = (uint8_t)(aad_len >>16U);
            aad_buf[4] = (uint8_t)(aad_len >>8U);
            aad_buf[5] = (uint8_t)(aad_len & 0xffU);
            aad_enc = aad_buf;
            aad_enc_len = 6U;
        }
        n_blocks = (aad_enc_len + aad_len + ((uint32_t)NOXTLS_AES_BLOCK - 1U)) / (uint32_t)NOXTLS_AES_BLOCK;
        for (i = 0U; i < n_blocks; i += 1U) {
            uint8_t block[NOXTLS_AES_BLOCK];
            uint32_t off = 0U;
            noxtls_secure_zero((block), (size_t)(NOXTLS_AES_BLOCK));
            off = i * (uint32_t)NOXTLS_AES_BLOCK;
            if (off < aad_enc_len) {
                uint32_t copy = (uint32_t)NOXTLS_AES_BLOCK;
                uint32_t from_enc = (uint32_t)(aad_enc_len - off);
                if (from_enc < copy) {
                    copy = from_enc;
                }
                noxtls_copy_u8(block, sizeof(block), &aad_enc[off], (size_t)(copy));
                if (copy < (uint32_t)NOXTLS_AES_BLOCK) {
                    uint32_t from_aad = (uint32_t)NOXTLS_AES_BLOCK - copy;
                    if (from_aad > aad_len) {
                        from_aad = aad_len;
                    }
                    noxtls_copy_u8(&block[copy], sizeof(block) - (size_t)(copy), aad, (size_t)(from_aad));
                }
            } else {
                uint32_t aad_off = (uint32_t)(off - aad_enc_len);
                if (aad_off < aad_len) {
                    uint32_t from_aad = (uint32_t)(aad_len - aad_off);
                    if (from_aad > (uint32_t)NOXTLS_AES_BLOCK) {
                        from_aad = (uint32_t)NOXTLS_AES_BLOCK;
                    }
                    noxtls_copy_u8(block, sizeof(block), &aad[aad_off], (size_t)(from_aad));
                }
            }
            ccm_cbc_mac_block(key, type, block, mac_state);
        }
    }

    n_blocks = (payload_len + ((uint32_t)NOXTLS_AES_BLOCK - 1U)) / (uint32_t)NOXTLS_AES_BLOCK;
    for (i = 0U; i < n_blocks; i += 1U) {
        uint8_t block[NOXTLS_AES_BLOCK];
        uint32_t off = 0U;
        uint32_t copy = 0U;
        noxtls_secure_zero((block), (size_t)(NOXTLS_AES_BLOCK));
        off = i * (uint32_t)NOXTLS_AES_BLOCK;
        copy = payload_len - off;
        if (copy > (uint32_t)NOXTLS_AES_BLOCK) {
            copy = (uint32_t)NOXTLS_AES_BLOCK;
        }
        noxtls_copy_u8(block, sizeof(block), &payload[off], (size_t)(copy));
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
    uint32_t L = (uint32_t)(15U - nonce_len);
    uint8_t B0[NOXTLS_AES_BLOCK];
    uint8_t mac_state[NOXTLS_AES_BLOCK];
    uint8_t ctr_block[NOXTLS_AES_BLOCK];
    uint8_t keystream[NOXTLS_AES_BLOCK];
    uint32_t i = 0U;
    uint8_t diff = 0U;

    if ((key == NULL) || (nonce == NULL) || (ciphertext == NULL) || (tag == NULL) || (plaintext == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((nonce_len_valid(nonce_len) == 0U) || (tag_len_valid(tag_len) == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if (L == 2U) {
        if (ciphertext_len > 0xFFFFUL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    } else if (L == 3U) {
        if (ciphertext_len > 0xFFFFFFUL) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }

    /* 1) CTR decrypt to get plaintext (counter 0 = tag mask, 1,2,... = payload) */
    noxtls_secure_zero((ctr_block), (size_t)(NOXTLS_AES_BLOCK));
    ctr_block[0] = (uint8_t)(L - 1U);
    noxtls_copy_u8(&ctr_block[1], sizeof(ctr_block) - (size_t)(1), nonce, (size_t)(nonce_len));

    (void)noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
    ccm_inc_counter(ctr_block, L);

    for (i = 0U; i < ciphertext_len; i += (uint32_t)NOXTLS_AES_BLOCK) {
        uint32_t take = 0U;
        uint32_t j = 0U;
        (void)noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);
        take = ciphertext_len - i;
        if (take > (uint32_t)NOXTLS_AES_BLOCK) {
            take = (uint32_t)NOXTLS_AES_BLOCK;
        }
        for (j = 0U; j < take; j += 1U) {
            plaintext[i + j] = (uint8_t)(ciphertext[i + j] ^ keystream[j]);
        }
        ccm_inc_counter(ctr_block, L);
    }

    /* 2) B0 and compute MAC over B0, AAD, plaintext */
    B0[0] = (uint8_t)(((aad_len > 0U) ? 0x40U : 0U) | ((((tag_len - 2U) >>1U) <<3U) | (L - 1U)));
    noxtls_copy_u8(&B0[1], sizeof(B0) - (size_t)(1), nonce, (size_t)(nonce_len));
    for (i = 0U; i < L; i += 1U) {
        uint32_t pos = (uint32_t)(L - 1U - i);
        uint8_t b = 0U;
        switch(pos) {
        case 0U: b = (uint8_t)(ciphertext_len); break;
        case 1U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 8U); break;
        case 2U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 16U); break;
        case 3U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 24U); break;
        case 4U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 32U); break;
        case 5U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 40U); break;
        case 6U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 48U); break;
        case 7U: b = (uint8_t)((uint64_t)(uint32_t)ciphertext_len >> 56U); break;
        default: b = 0U; break;
        }
        B0[16U - L + i] = b;
    }

    ccm_compute_mac(key, type, B0, aad, aad_len, plaintext, ciphertext_len, mac_state);

    /* 3) Tag = MAC XOR E(CTR_0). Recompute counter 0 keystream. */
    noxtls_secure_zero((ctr_block), (size_t)(NOXTLS_AES_BLOCK));
    ctr_block[0] = (uint8_t)(L - 1U);
    noxtls_copy_u8(&ctr_block[1], sizeof(ctr_block) - (size_t)(1), nonce, (size_t)(nonce_len));
    (void)noxtls_aes_encrypt_block_internal(key, ctr_block, keystream, type);

    diff = 0U;
    for (i = 0U; i < tag_len; i += 1U) {
        diff |= (uint8_t)(tag[i] ^ (mac_state[i] ^ keystream[i]));
    }
    if (diff != 0U) {
        /* SECURITY (NX-06): never expose unauthenticated plaintext to the caller. */
        (void)noxtls_secure_zero(plaintext, ciphertext_len);
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CCM */
