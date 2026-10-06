/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cc13xx_crypto.c
* Summary: Per-engine guarded injected CC13xx accelerator ownership
*****************************************************************************/
/**
 * @file noxtls_cc13xx_crypto.c
 * @brief Copy idle callback bindings and serialize each engine independently.
 * @ingroup noxtls_cc13xx_crypto
 *
 * The AES engine and the PKA each have one atomic busy guard. A request that
 * cannot take its engine's guard returns NOXTLS_RETURN_NOT_SUPPORTED so the
 * caller computes it in software; nothing ever waits for an engine.
 */
#include "noxtls_cc13xx_crypto.h"
#include "noxtls_cc13xx_crypto_atomic.h"
#include "noxtls_ct.h"
#include <stddef.h>
#include <string.h>

static noxtls_cc13xx_crypto_binding_t s_binding;
static noxtls_cc13xx_guard_t s_aes_guard = NOXTLS_CC13XX_GUARD_IDLE;
static noxtls_cc13xx_guard_t s_pka_guard = NOXTLS_CC13XX_GUARD_IDLE;

/**
 * @brief Check an AES key width from FIPS 197 (2023), Section 3.
 * @internal
 *
 * @param[in] key_length Key bytes.
 *
 * @return True for 16, 24 or 32 bytes.
 */
static bool aes_key_length_ok(uint32_t key_length)
{
    return (key_length == NOXTLS_CC13XX_AES128_KEY_BYTES) ||
        (key_length == NOXTLS_CC13XX_AES192_KEY_BYTES) ||
        (key_length == NOXTLS_CC13XX_AES256_KEY_BYTES);
}

/** @copydoc noxtls_cc13xx_crypto_has_p256 */
bool noxtls_cc13xx_crypto_has_p256(void)
{
    return s_binding.p256_multiply != NULL;
}

/** @copydoc noxtls_cc13xx_crypto_bind */
noxtls_return_t noxtls_cc13xx_crypto_bind(const noxtls_cc13xx_crypto_binding_t *binding)
{
    noxtls_return_t result = NOXTLS_RETURN_SUCCESS;
    /* Owning both guards excludes every in-flight or new callback invocation. */
    if (!noxtls_cc13xx_guard_try_acquire(&s_aes_guard)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (!noxtls_cc13xx_guard_try_acquire(&s_pka_guard)) {
        noxtls_cc13xx_guard_release(&s_aes_guard);
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (binding == NULL) {
        s_binding = (noxtls_cc13xx_crypto_binding_t){0};
    } else if ((binding->aes_block == NULL) && (binding->p256_multiply == NULL)) {
        result = NOXTLS_RETURN_INVALID_PARAM;
    } else {
        s_binding = *binding;
    }

    noxtls_cc13xx_guard_release(&s_pka_guard);
    noxtls_cc13xx_guard_release(&s_aes_guard);
    return result;
}

/** @copydoc noxtls_cc13xx_aes_block */
noxtls_return_t noxtls_cc13xx_aes_block(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES])
{
    noxtls_return_t result = NOXTLS_RETURN_NOT_SUPPORTED;
    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (!aes_key_length_ok(key_length)) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    /* A busy engine is a capability gap for this request, not a failure. */
    if (!noxtls_cc13xx_guard_try_acquire(&s_aes_guard)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (s_binding.aes_block != NULL) {
        result = s_binding.aes_block(s_binding.context, decrypt, key, key_length, input, output);
    }

    noxtls_cc13xx_guard_release(&s_aes_guard);
    return result;
}

/** @copydoc noxtls_cc13xx_aes_blocks */
noxtls_return_t noxtls_cc13xx_aes_blocks(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t *input, uint8_t *output, uint32_t block_count)
{
    uint8_t staged[NOXTLS_CC13XX_AES_BLOCK_BYTES] = {0};
    noxtls_return_t result = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t index;
    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (!aes_key_length_ok(key_length)) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    if (block_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if (block_count > NOXTLS_CC13XX_AES_MAX_BLOCKS) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (!noxtls_cc13xx_guard_try_acquire(&s_aes_guard)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (s_binding.aes_block != NULL) {
        for (index = 0U; index < block_count; ++index) {
            const uint32_t offset = index * NOXTLS_CC13XX_AES_BLOCK_BYTES;
            result = s_binding.aes_block(s_binding.context, decrypt, key, key_length,
                input + offset, staged);
            if (result != NOXTLS_RETURN_SUCCESS) {
                break;
            }

            (void)memcpy(output + offset, staged, sizeof(staged));
        }

        if ((result != NOXTLS_RETURN_SUCCESS) &&
            ((result != NOXTLS_RETURN_NOT_SUPPORTED) || (index != 0U))) {
            noxtls_secure_zero(output, (size_t)block_count * NOXTLS_CC13XX_AES_BLOCK_BYTES);
            /* In-place input may already have changed: never invite fallback. */
            if (result == NOXTLS_RETURN_NOT_SUPPORTED) {
                result = NOXTLS_RETURN_FAILED;
            }
        }
    }

    noxtls_cc13xx_guard_release(&s_aes_guard);
    noxtls_secure_zero(staged, sizeof(staged));
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
    noxtls_return_t result = NOXTLS_RETURN_NOT_SUPPORTED;
    if ((scalar == NULL) || (x == NULL) || (y == NULL) ||
        (result_x == NULL) || (result_y == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* The PKA is independent of the AES engine; only PKA reentry falls back. */
    if (!noxtls_cc13xx_guard_try_acquire(&s_pka_guard)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (s_binding.p256_multiply != NULL) {
        result = s_binding.p256_multiply(s_binding.context, scalar, x, y, result_x, result_y);
    }

    noxtls_cc13xx_guard_release(&s_pka_guard);
    return result;
}
