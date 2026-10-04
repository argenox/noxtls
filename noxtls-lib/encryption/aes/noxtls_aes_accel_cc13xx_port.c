/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_cc13xx_port.c
* Summary: Synchronous original CC13xx callback AES block port
*****************************************************************************/
/**
 * @file noxtls_aes_accel_cc13xx_port.c
 * @brief Stage AES block outputs and propagate native accelerator failures.
 * @ingroup noxtls_cc13xx_crypto
 */
#include "noxtls_aes_accel.h"
#include "noxtls_cc13xx_crypto.h"
#include "noxtls_memory.h"
#include "noxtls_ct.h"
#include <string.h>

/**
 * @brief Map FIPS 197 (2023) Section 3 key sizes without truncation.
 * @internal
 *
 * @param[in] type Existing AES key type.
 *
 * @return Key bytes or zero for an invalid selector.
 */
static uint32_t cc13xx_key_length(noxtls_aes_type_t type)
{
    switch (type) {
        case NOXTLS_AES_128_BIT:
            return NOXTLS_CC13XX_AES128_KEY_BYTES;
        case NOXTLS_AES_192_BIT:
            return NOXTLS_CC13XX_AES192_KEY_BYTES;
        case NOXTLS_AES_256_BIT:
            return NOXTLS_CC13XX_AES256_KEY_BYTES;
        default:
            return 0U;
    }
}

/**
 * @brief Copy one block only after callback success, then erase staging.
 * @internal
 *
 * @param[in] decrypt True for decryption.
 * @param[in] key AES key bytes.
 * @param[in] input Readable input block; exact in-place operation is allowed.
 * @param[out] output Output block, unchanged on callback failure.
 * @param[in] type AES key type.
 *
 * @return Actual callback status or malformed-input status.
 */
static noxtls_return_t cc13xx_block(bool decrypt, const uint8_t *key,
    const uint8_t *input, uint8_t *output, noxtls_aes_type_t type)
{
    uint8_t staged[NOXTLS_CC13XX_AES_BLOCK_BYTES] = {0};
    const uint32_t key_length = cc13xx_key_length(type);
    noxtls_return_t result;
    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (key_length == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    result = noxtls_cc13xx_aes_block(decrypt, key, key_length, input, staged);
    if (result == NOXTLS_RETURN_SUCCESS) {
        (void)memcpy(output, staged, sizeof(staged));
    }

    noxtls_secure_zero(staged, sizeof(staged));
    return result;
}

/** @copydoc noxtls_aes_accel_port_encrypt_block */
noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
    const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    return cc13xx_block(false, key, data, output, type);
}

/** @copydoc noxtls_aes_accel_port_decrypt_block */
noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
    const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    return cc13xx_block(true, key, data, output, type);
}

/** @copydoc noxtls_aes_accel_port_encrypt_blocks */
noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
    const uint8_t *input, uint8_t *output, uint32_t block_count, noxtls_aes_type_t type)
{
    uint32_t index;
    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (cc13xx_key_length(type) == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    if (block_count > NOXTLS_CC13XX_AES_MAX_BLOCKS) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    for (index = 0U; index < block_count; ++index) {
        const uint32_t offset = index * NOXTLS_CC13XX_AES_BLOCK_BYTES;
        const noxtls_return_t result = cc13xx_block(false, key,
            input + offset, output + offset, type);
        if (result != NOXTLS_RETURN_SUCCESS) {
            if ((result == NOXTLS_RETURN_NOT_SUPPORTED) && (index == 0U)) {
                return result;
            }

            noxtls_secure_zero(output, block_count * NOXTLS_CC13XX_AES_BLOCK_BYTES);
            /* In-place input may already have changed: never invite fallback. */
            return result == NOXTLS_RETURN_NOT_SUPPORTED ? NOXTLS_RETURN_FAILED : result;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/** @copydoc noxtls_aes_gcm_encrypt_accel_port */
noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t nonce[12], const uint8_t *aad,
    uint32_t aad_len, const uint8_t *plaintext, uint32_t plaintext_len,
    uint8_t *ciphertext, uint8_t tag[16])
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    /* GCM composition remains software, using the accelerated block path. */
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/** @copydoc noxtls_aes_gcm_decrypt_accel_port */
noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t nonce[12], const uint8_t *aad,
    uint32_t aad_len, const uint8_t *ciphertext, uint32_t ciphertext_len,
    const uint8_t tag[16], uint8_t *plaintext)
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
