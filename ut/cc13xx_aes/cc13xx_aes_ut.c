/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
* File:    cc13xx_aes_ut.c
* Summary: Injected CC13xx binding ownership and bounded AES port contracts
*****************************************************************************/
/** @file cc13xx_aes_ut.c
 * @brief Tests actual binding and port code without peripheral or OS dependencies.
 * @ingroup noxtls_cc13xx_crypto
 */
#include "noxtls_config.h"
#include "noxtls_cc13xx_crypto.h"
#include "noxtls_aes_accel.h"
#include "test_assert.h"
#include "runner.h"
#include <string.h>

static uint8_t s_key[32];
static uint8_t s_input[NOXTLS_CC13XX_AES_MAX_BLOCKS * NOXTLS_CC13XX_AES_BLOCK_BYTES];
static uint8_t s_output[sizeof(s_input) + 1U];

#if NOXTLS_FEATURE_CC13XX_HW_ACCEL
static uint32_t s_calls, s_key_length, s_fail_at;
static bool s_decrypt, s_reenter;
static noxtls_return_t s_failure;
static noxtls_return_t s_nested_aes, s_nested_p256, s_nested_bind;
static unsigned s_context;

/** @brief Fill test staging, optionally fail or attempt forbidden reentry. */
static noxtls_return_t aes_callback(void *context, bool decrypt,
    const uint8_t *key, uint32_t key_length, const uint8_t input[16], uint8_t output[16])
{
    uint32_t i;
    (void)key;
    if (context != &s_context) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ++s_calls;
    s_decrypt = decrypt;
    s_key_length = key_length;
    if (s_reenter) {
        s_nested_bind = noxtls_cc13xx_crypto_bind(NULL);
        s_nested_aes = noxtls_cc13xx_aes_block(false, s_key, 16U, s_input, s_output);
        s_nested_p256 = noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_key, s_key);
    }
    for (i = 0U; i < 16U; ++i) {
        output[i] = (uint8_t)(input[i] ^ 0x5AU);
    }
    return s_calls == s_fail_at ? s_failure : NOXTLS_RETURN_SUCCESS;
}

/** @brief P-256 wrapper fixture, not an elliptic-curve implementation. */
static noxtls_return_t p256_callback(void *context, const uint8_t scalar[32],
    const uint8_t x[32], const uint8_t y[32], uint8_t result_x[32], uint8_t result_y[32])
{
    (void)context;
    (void)scalar;
    if (s_reenter) {
        s_nested_bind = noxtls_cc13xx_crypto_bind(NULL);
        s_nested_aes = noxtls_cc13xx_aes_block(false, s_key, 16U, s_input, s_output);
        s_nested_p256 = noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_key, s_key);
    }
    memcpy(result_x, x, 32U);
    memcpy(result_y, y, 32U);
    return s_failure;
}

/** @brief Establish one serialized fixture binding and deterministic inputs. */
static void reset_binding(void)
{
    noxtls_cc13xx_crypto_binding_t binding = {&s_context, aes_callback, p256_callback};
    s_calls = 0U;
    s_fail_at = 0U;
    s_failure = NOXTLS_RETURN_SUCCESS;
    s_reenter = false;
    memset(s_input, 0x36, sizeof(s_input));
    memset(s_output, 0xA5, sizeof(s_output));
    (void)noxtls_cc13xx_crypto_bind(&binding);
}

/** @brief Verify an exact output span without printing test buffer contents. */
static bool filled(const uint8_t *data, size_t length, uint8_t byte)
{
    size_t i;
    for (i = 0U; i < length; ++i) {
        if (data[i] != byte) {
            return false;
        }
    }
    return true;
}

REGISTER_TEST(test_idle_binding_and_missing_callbacks)
{
    noxtls_cc13xx_crypto_binding_t binding = {&s_context, aes_callback, p256_callback};
    reset_binding();
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_has_p256(), false);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 16U, s_input, s_output), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_key, s_key), NOXTLS_RETURN_NOT_SUPPORTED);
    binding.aes_block = NULL;
    binding.p256_multiply = NULL;
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(&binding), NOXTLS_RETURN_INVALID_PARAM);
    binding.aes_block = aes_callback;
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(&binding), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_has_p256(), false);
    binding.aes_block = NULL;
    binding.p256_multiply = p256_callback;
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(&binding), NOXTLS_RETURN_SUCCESS);
    binding.p256_multiply = NULL; /* Caller storage changes cannot mutate the copy. */
    UTNOX_EQUALS(noxtls_cc13xx_crypto_has_p256(), true);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 16U, s_input, s_output), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_pointer_and_key_admission)
{
    reset_binding();
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, NULL, 16U, s_input, s_output), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 16U, NULL, s_output), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 16U, s_input, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 0U, s_input, s_output), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_cc13xx_aes_block(false, s_key, 17U, s_input, s_output), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(NULL, s_input, s_output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, NULL, s_output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(s_key, s_input, NULL, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, s_input, s_output, (noxtls_aes_type_t)99), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(NULL, s_key, s_key, s_key, s_key), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, NULL, s_key, s_key, s_key), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, NULL, s_key, s_key), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, NULL, s_key), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_key, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(filled(s_output, sizeof(s_output), 0xA5U), true);
    return 0;
}

REGISTER_TEST(test_exact_widths_staging_and_in_place)
{
    const noxtls_aes_type_t types[] = {NOXTLS_AES_128_BIT, NOXTLS_AES_192_BIT, NOXTLS_AES_256_BIT};
    const uint32_t widths[] = {16U, 24U, 32U};
    unsigned i;
    for (i = 0U; i < 3U; ++i) {
        reset_binding();
        UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, s_input, s_output, types[i]), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_key_length, widths[i]);
        UTNOX_EQUALS(s_decrypt, false);
        UTNOX_EQUALS(filled(s_output, 16U, 0x6CU), true);
        UTNOX_EQUALS(s_output[16], 0xA5U);
        UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(s_key, s_input, s_input, types[i]), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_decrypt, true);
        UTNOX_EQUALS(filled(s_input, 16U, 0x6CU), true);
        s_fail_at = s_calls + 1U;
        s_failure = NOXTLS_RETURN_TIMEOUT;
        UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, s_input, s_output, types[i]), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(filled(s_output, 16U, 0x6CU), true); /* Partial staging never escapes. */
    }
    return 0;
}

REGISTER_TEST(test_active_reentry_and_error_recovery)
{
    reset_binding();
    s_reenter = true;
    s_fail_at = 1U;
    s_failure = NOXTLS_RETURN_TIMEOUT;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, s_input, s_output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(s_nested_bind, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(s_nested_aes, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(s_nested_p256, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    reset_binding();
    s_reenter = true;
    s_failure = NOXTLS_RETURN_BAD_DATA;
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_input, s_output), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(s_nested_bind, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(s_nested_aes, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(s_nested_p256, NOXTLS_RETURN_NOT_INITIALIZED);
    s_reenter = false;
    s_failure = NOXTLS_RETURN_SUCCESS;
    UTNOX_EQUALS(noxtls_cc13xx_p256_multiply(s_key, s_key, s_key, s_input, s_output), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_batch_bounds_and_actual_error_wipe)
{
    unsigned at;
    reset_binding();
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, 0U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(NULL, s_input, s_output, 1U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, NULL, s_output, 1U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, NULL, 1U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, 1U, (noxtls_aes_type_t)99), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, NOXTLS_CC13XX_AES_MAX_BLOCKS + 1U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(filled(s_output, sizeof(s_output), 0xA5U), true);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, NOXTLS_CC13XX_AES_MAX_BLOCKS, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, NOXTLS_CC13XX_AES_MAX_BLOCKS);
    UTNOX_EQUALS(filled(s_output, sizeof(s_input), 0x6CU), true);
    UTNOX_EQUALS(s_output[sizeof(s_input)], 0xA5U);
    for (at = 1U; at <= 3U; ++at) {
        reset_binding();
        s_fail_at = at;
        s_failure = NOXTLS_RETURN_TIMEOUT;
        UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(s_calls, at);
        UTNOX_EQUALS(filled(s_output, 48U, 0U), true);
        UTNOX_EQUALS(s_output[48], 0xA5U);
    }
    return 0;
}

REGISTER_TEST(test_unsupported_is_only_safe_before_progress)
{
    reset_binding();
    s_fail_at = 1U;
    s_failure = NOXTLS_RETURN_NOT_SUPPORTED;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_output, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(filled(s_output, sizeof(s_output), 0xA5U), true);
    reset_binding();
    s_fail_at = 2U;
    s_failure = NOXTLS_RETURN_NOT_SUPPORTED;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(s_key, s_input, s_input, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(filled(s_input, 48U, 0U), true);
    UTNOX_EQUALS(s_input[48], 0x36U);
    return 0;
}

REGISTER_TEST(test_native_gcm_declines_without_output)
{
    reset_binding();
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(s_key, NOXTLS_AES_128_BIT,
        s_input, NULL, 0U, s_input, 16U, s_output, s_output + 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(s_key, NOXTLS_AES_128_BIT,
        s_input, NULL, 0U, s_input, 16U, s_input, s_output), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(filled(s_output, sizeof(s_output), 0xA5U), true);
    return 0;
}
#else
REGISTER_TEST(test_disabled_default_port_remains_unsupported)
{
    memset(s_output, 0xA5, sizeof(s_output));
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(s_key, s_input, s_output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(s_key, s_input, s_output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_output[0], 0xA5U);
    return 0;
}
#endif

#if defined(_MSC_VER) && !defined(__cplusplus)
/** @brief Register the enabled fixture for MSVC-compatible C builds. */
void utnox_register_tests(void)
{
#if NOXTLS_FEATURE_CC13XX_HW_ACCEL
    register_test("test_idle_binding_and_missing_callbacks", test_idle_binding_and_missing_callbacks);
    register_test("test_pointer_and_key_admission", test_pointer_and_key_admission);
    register_test("test_exact_widths_staging_and_in_place", test_exact_widths_staging_and_in_place);
    register_test("test_active_reentry_and_error_recovery", test_active_reentry_and_error_recovery);
    register_test("test_batch_bounds_and_actual_error_wipe", test_batch_bounds_and_actual_error_wipe);
    register_test("test_unsupported_is_only_safe_before_progress", test_unsupported_is_only_safe_before_progress);
    register_test("test_native_gcm_declines_without_output", test_native_gcm_declines_without_output);
#else
    register_test("test_disabled_default_port_remains_unsupported", test_disabled_default_port_remains_unsupported);
#endif
}
#endif
