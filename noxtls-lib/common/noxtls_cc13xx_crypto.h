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
 * @brief Original NoxTLS binding with no vendor SDK, driver, or scheduler dependency.
 *
 * @par Build selection
 * NOXTLS_FEATURE_CC13XX_AES_ACCEL compiles the AES block port and
 * NOXTLS_FEATURE_CC13XX_P256_ACCEL compiles the secp256r1 port. The umbrella
 * NOXTLS_FEATURE_CC13XX_HW_ACCEL enables both. This binding is compiled when
 * either port is. A callback for an engine whose port is not compiled is
 * accepted by noxtls_cc13xx_crypto_bind() but never invoked.
 *
 * @par Engines and concurrency
 * The AES engine and the public-key accelerator (PKA) are independent. Each
 * has its own atomic busy guard, so an AES block may run while a P-256
 * multiplication is in progress (for example from another task, or from
 * inside a yielding P-256 callback). The same engine is never reentered: a
 * request that finds its engine busy returns NOXTLS_RETURN_NOT_SUPPORTED
 * without invoking the callback, and the AES and ECC cores then compute that
 * request in software. Guards are C11 test-and-set flags (or the equivalent
 * compiler primitive), so concurrent tasks and interrupt handlers can never
 * enter one engine twice. No call blocks waiting for an engine.
 *
 * @par Callback contract
 * Callbacks are synchronous: they return only after the hardware work has
 * finished or has been cancelled. They may block or yield to other tasks
 * while waiting; NoxTLS holds no lock other than the engine guard across the
 * call. They must not disable interrupts for the duration of the operation.
 * A callback may call into NoxTLS (a nested request for its own engine falls
 * back to software; a request for the other engine may use the hardware).
 * Return codes:
 * - NOXTLS_RETURN_SUCCESS: the output is complete and is adopted (P-256
 *   outputs are validated as on-curve points first).
 * - NOXTLS_RETURN_NOT_SUPPORTED: the request was not started and no output
 *   was produced; the caller falls back to software. Use it only when the
 *   operation is not attempted (for example a key size the hardware lacks).
 * - Any other value: a hard failure (fault, timeout, cancelled job). It is
 *   propagated to the caller as-is; output is erased and no software result
 *   is substituted.
 *
 * @par Threads and interrupts
 * Requests may come from any task. From an interrupt handler a request is
 * safe (it either runs or falls back), but a callback that blocks must not
 * be reached from interrupt context; that is the application's choice of
 * callback. Bind and unbind succeed only while both engines are idle;
 * otherwise noxtls_cc13xx_crypto_bind() returns NOXTLS_RETURN_NOT_INITIALIZED
 * and leaves the binding unchanged. While a bind is in progress, requests fall
 * back to software. The copied context must remain valid until it is
 * unbound. Keys and intermediate state remain private; neither this
 * interface nor callbacks may log them.
 * @{
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

/**
 * @brief Application-owned synchronous AES block operation.
 *
 * May block or yield until the AES engine finishes. Never called again for
 * the AES engine until it returns.
 */
typedef noxtls_return_t (*noxtls_cc13xx_aes_callback_t)(void *context,
    bool decrypt, const uint8_t *key, uint32_t key_length,
    const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES]);

/**
 * @brief Optional secp256r1 multiplication with fixed-width big-endian fields.
 *
 * May block or yield until the PKA finishes. Never called again for the PKA
 * until it returns; AES requests may run meanwhile.
 */
typedef noxtls_return_t (*noxtls_cc13xx_p256_callback_t)(void *context,
    const uint8_t scalar[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t x[NOXTLS_CC13XX_P256_BYTES],
    const uint8_t y[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_x[NOXTLS_CC13XX_P256_BYTES],
    uint8_t result_y[NOXTLS_CC13XX_P256_BYTES]);

/** @brief Copied callback values; context lifetime remains with the caller. */
typedef struct
{
    void *context;                               /**< Passed to both callbacks. */
    noxtls_cc13xx_aes_callback_t aes_block;      /**< AES engine, or NULL for software AES. */
    noxtls_cc13xx_p256_callback_t p256_multiply; /**< PKA, or NULL for software P-256. */
} noxtls_cc13xx_crypto_binding_t;

/**
 * @brief Copy a binding while both engines are idle, or unbind when binding is NULL.
 *
 * @param[in] binding Optional new callbacks, with at least one non-NULL callback.
 *
 * @return NOXTLS_RETURN_SUCCESS when copied; NOXTLS_RETURN_INVALID_PARAM for
 * an empty binding; NOXTLS_RETURN_NOT_INITIALIZED, with the binding
 * unchanged, while either engine is in use (including from inside a callback).
 */
noxtls_return_t noxtls_cc13xx_crypto_bind(const noxtls_cc13xx_crypto_binding_t *binding);

/**
 * @brief Query copied callback availability, not hardware or validation success.
 *
 * A bound engine can still be busy; the request then falls back to software.
 *
 * @return True if an optional P-256 callback is bound; not ordered against a
 * concurrent noxtls_cc13xx_crypto_bind().
 */
bool noxtls_cc13xx_crypto_has_p256(void);

/**
 * @brief Run one block on the AES engine, or report that software must do it.
 *
 * @param[in] decrypt True for decryption.
 * @param[in] key Key with key_length readable bytes.
 * @param[in] key_length Exactly 16, 24, or 32 bytes.
 * @param[in] input One readable AES block.
 * @param[out] output One output block; written only by the callback.
 *
 * @return Actual callback result; NOXTLS_RETURN_NOT_SUPPORTED, without calling
 * anything, when no AES callback is bound or the AES engine is busy;
 * NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_KEY_SIZE for malformed arguments.
 */
noxtls_return_t noxtls_cc13xx_aes_block(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t input[NOXTLS_CC13XX_AES_BLOCK_BYTES],
    uint8_t output[NOXTLS_CC13XX_AES_BLOCK_BYTES]);

/**
 * @brief Run a bounded batch of blocks while holding the AES engine throughout.
 *
 * Each block is staged and copied to output only after callback success, so
 * exact in-place operation (input == output) is allowed. Because the engine is
 * held for the whole batch, a busy engine can only be reported before any
 * block is processed.
 *
 * @param[in] decrypt True for decryption.
 * @param[in] key Key with key_length readable bytes.
 * @param[in] key_length Exactly 16, 24, or 32 bytes.
 * @param[in] input block_count readable blocks.
 * @param[out] output block_count writable blocks.
 * @param[in] block_count Number of blocks, at most NOXTLS_CC13XX_AES_MAX_BLOCKS.
 *
 * @return NOXTLS_RETURN_SUCCESS (also for zero blocks); NOXTLS_RETURN_NOT_SUPPORTED,
 * with output untouched, when no callback is bound, the engine is busy, the
 * batch exceeds the bound, or the first block's callback declines; otherwise
 * the first callback error with the whole output erased, where a later
 * NOT_SUPPORTED becomes NOXTLS_RETURN_FAILED because in-place input may
 * already be overwritten; NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_KEY_SIZE
 * for malformed arguments.
 */
noxtls_return_t noxtls_cc13xx_aes_blocks(bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t *input, uint8_t *output, uint32_t block_count);

/**
 * @brief Run one secp256r1 multiplication on the PKA, or report software fallback.
 *
 * @param[in] scalar Big-endian 32-byte scalar; port must validate its range.
 * @param[in] x Big-endian 32-byte input x; port must validate the point.
 * @param[in] y Big-endian 32-byte input y.
 * @param[out] result_x Big-endian 32-byte output x.
 * @param[out] result_y Big-endian 32-byte output y.
 *
 * @return Actual callback result; NOXTLS_RETURN_NOT_SUPPORTED, without calling
 * anything, when no P-256 callback is bound or the PKA is busy;
 * NOXTLS_RETURN_NULL for malformed pointers.
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
/** @} */
