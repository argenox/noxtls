/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cc13xx_crypto.c
* Summary: Serialized injected CC13xx accelerator ownership
*****************************************************************************/
/**
 * @file noxtls_cc13xx_crypto.c
 * @brief Copy idle callback bindings and reject active reentry.
 * @ingroup noxtls_cc13xx_crypto
 */
#include "noxtls_cc13xx_crypto.h"
#include <stddef.h>

static noxtls_cc13xx_crypto_binding_t s_binding;
static bool s_active;

/** @copydoc noxtls_cc13xx_crypto_has_p256 */
bool noxtls_cc13xx_crypto_has_p256(void)
{
    return s_binding.p256_multiply != NULL;
}

/** @copydoc noxtls_cc13xx_crypto_bind */
noxtls_return_t noxtls_cc13xx_crypto_bind(const noxtls_cc13xx_crypto_binding_t *binding)
{
    if (s_active) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (binding == NULL) {
        s_binding = (noxtls_cc13xx_crypto_binding_t){0};
        return NOXTLS_RETURN_SUCCESS;
    }

    if ((binding->aes_block == NULL) && (binding->p256_multiply == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    s_binding = *binding;
    return NOXTLS_RETURN_SUCCESS;
}

/** @copydoc noxtls_cc13xx_aes_block */
noxtls_return_t noxtls_cc13xx_aes_block(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES])
{
    noxtls_return_t result;
    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((key_length != NOXTLS_CC13XX_AES128_KEY_BYTES) &&
        (key_length != NOXTLS_CC13XX_AES192_KEY_BYTES) &&
        (key_length != NOXTLS_CC13XX_AES256_KEY_BYTES)) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    if (s_active) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (s_binding.aes_block == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    s_active = true;
    result = s_binding.aes_block(s_binding.context, decrypt, key, key_length, input, output);
    s_active = false;
    return result;
}

/** @copydoc noxtls_cc13xx_p256_multiply */
noxtls_return_t noxtls_cc13xx_p256_multiply(
    const uint8_t scalar[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t x[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t y[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_x[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_y[NOXTLS_CC13XX_P256_BYTES])
{
    noxtls_return_t result;
    if ((scalar == NULL) || (x == NULL) || (y == NULL) ||
        (result_x == NULL) || (result_y == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (s_active) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (s_binding.p256_multiply == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    s_active = true;
    result = s_binding.p256_multiply(s_binding.context, scalar, x, y, result_x, result_y);
    s_active = false;
    return result;
}
