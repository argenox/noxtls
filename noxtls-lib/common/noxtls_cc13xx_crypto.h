/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cc13xx_crypto.h
* Summary: OS-independent injected CC13xx accelerator binding
*****************************************************************************/
/**
 * @file noxtls_cc13xx_crypto.h
 * @brief Synchronous callback boundary for an application-owned accelerator.
 * @defgroup noxtls_cc13xx_crypto CC13xx accelerator callbacks
 * @brief Original NoxTLS binding with no TI SDK, driver, or scheduler dependency.
 *
 * All calls and binding changes require caller-serialized ownership, including
 * complete surrounding cipher operations. The active flag detects reentry; it
 * is not a lock and does not make concurrent callers safe. Bind/unbind only
 * while the library and accelerator are idle. The copied context must remain
 * valid until idle unbind. Callbacks are synchronous and may yield to higher
 * priority work; they must not disable interrupts or reenter this interface.
 * They must finish or cancel all hardware work before returning any result.
 * Only NOT_SUPPORTED permits software fallback. Keys and intermediate state
 * remain private; neither this interface nor callbacks may log them.
 */
#ifndef NOXTLS_CC13XX_CRYPTO_H
#define NOXTLS_CC13XX_CRYPTO_H

#include <stdbool.h>
#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_cc13xx_crypto_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Application-owned synchronous AES block operation. */
typedef noxtls_return_t (*noxtls_cc13xx_aes_callback_t)(void *context,
    bool decrypt, const uint8_t *key, uint32_t key_length,
    const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES]);

/** @brief Optional secp256r1 multiplication with fixed-width big-endian fields. */
typedef noxtls_return_t (*noxtls_cc13xx_p256_callback_t)(void *context,
    const uint8_t scalar[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t x[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t y[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_x[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_y[NOXTLS_CC13XX_P256_BYTES]);

/** @brief Copied callback values; context lifetime remains with the caller. */
typedef struct
{
    void *context;
    noxtls_cc13xx_aes_callback_t aes_block;
    noxtls_cc13xx_p256_callback_t p256_multiply;
} noxtls_cc13xx_crypto_binding_t;

/**
 * @brief Copy an idle binding, or unbind when binding is NULL.
 *
 * @param[in] binding Optional new callbacks, with at least one non-NULL callback.
 *
 * @return SUCCESS when copied; INVALID_PARAM for an empty binding;
 * NOT_INITIALIZED for reentrant changes during an active operation.
 */
noxtls_return_t noxtls_cc13xx_crypto_bind(const noxtls_cc13xx_crypto_binding_t *binding);

/**
 * @brief Query copied callback availability, not hardware or validation success.
 *
 * @return True if an optional P-256 callback is bound; caller must serialize.
 */
bool noxtls_cc13xx_crypto_has_p256(void);

/**
 * @brief Invoke the bound synchronous AES callback with validated byte widths.
 *
 * @param[in] decrypt True for decryption.
 * @param[in] key Key with key_length readable bytes.
 * @param[in] key_length Exactly 16, 24, or 32 bytes.
 * @param[in] input One readable AES block.
 * @param[out] output One output block; callback failure is not success.
 *
 * @return Actual callback result; NOT_SUPPORTED for no callback;
 * NULL/INVALID_KEY_SIZE for malformed arguments; NOT_INITIALIZED for reentry.
 */
noxtls_return_t noxtls_cc13xx_aes_block(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES]);

/**
 * @brief Invoke the optional bound secp256r1 callback with fixed-width fields.
 *
 * @param[in] scalar Big-endian 32-byte scalar; port must validate its range.
 * @param[in] x Big-endian 32-byte input x; port must validate the point.
 * @param[in] y Big-endian 32-byte input y.
 * @param[out] result_x Big-endian 32-byte output x.
 * @param[out] result_y Big-endian 32-byte output y.
 *
 * @return Actual callback result; NOT_SUPPORTED for no callback;
 * NULL for malformed pointers; NOT_INITIALIZED for reentry.
 */
noxtls_return_t noxtls_cc13xx_p256_multiply(
    const uint8_t scalar[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t x[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t y[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_x[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_y[NOXTLS_CC13XX_P256_BYTES]);

#ifdef __cplusplus
}
#endif
#endif
