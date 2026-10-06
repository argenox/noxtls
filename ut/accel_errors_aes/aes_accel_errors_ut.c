/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
* File:    aes_accel_errors_ut.c
* Summary: Actual AES mode error propagation with an injected port fixture
*****************************************************************************/
/** @file aes_accel_errors_ut.c
 * @brief Real cipher paths, software vectors, and failed-accelerator cleanup.
 * @ingroup noxtls_encryption
 */
#include "aes_accel_errors_fixture.h"
#include "noxtls_aes_internal.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_ccm.h"
#include "noxtls_aes_gcm.h"
#include "noxtls_aes_cmac.h"
#include "noxtls_drbg.h"
#include "test_assert.h"
#include "runner.h"
#include <stdbool.h>
#include <string.h>

static unsigned s_calls;
static unsigned s_fail_at;
static bool s_software;
static noxtls_return_t s_failure;
static noxtls_return_t s_batch;
static noxtls_return_t s_aead;
static uint8_t s_first_input[NOXTLS_AES_BLOCK_LENGTH];
static const uint8_t s_key[32] = {0};
static const uint8_t s_data[AES_ERROR_TEST_BYTES] = {0};
static const uint8_t s_iv[16] = {0};

/** @brief Reset only test-owned port behavior. */
static void reset_port(void)
{
    s_calls = 0U;
    s_fail_at = 0U;
    s_failure = NOXTLS_RETURN_TIMEOUT;
    s_batch = NOXTLS_RETURN_NOT_SUPPORTED;
    s_aead = NOXTLS_RETURN_NOT_SUPPORTED;
    s_software = false;
    memset(s_first_input, 0, sizeof(s_first_input));
}

/** @brief Test-only port: genuine library software handles successful blocks.
 * @param[in] decrypt Operation selection.
 * @param[in] key Key bytes.
 * @param[in] data Block bytes.
 * @param[out] output Block output; faults deliberately dirty this writable span.
 * @param[in] type Key size.
 * @return Controlled failure, unsupported, or actual software block result. */
static noxtls_return_t mock_block(bool decrypt, const uint8_t *key,
    const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    noxtls_return_t result;
    if (s_software) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    ++s_calls;
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (s_calls == 1U) {
        memcpy(s_first_input, data, sizeof(s_first_input));
    }

    if (s_calls == s_fail_at) {
        if (s_failure != NOXTLS_RETURN_NOT_SUPPORTED) {
            memset(output, 0xD5, NOXTLS_AES_BLOCK_LENGTH);
        }
        return s_failure;
    }

    s_software = true;
    result = decrypt ? noxtls_aes_decrypt_block_internal(key, data, output, type) :
        noxtls_aes_encrypt_block_internal(key, data, output, type);
    s_software = false;
    return result;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
    const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    return mock_block(false, key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
    const uint8_t *data, uint8_t *output, noxtls_aes_type_t type)
{
    return mock_block(true, key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
    const uint8_t *input, uint8_t *output, uint32_t count, noxtls_aes_type_t type)
{
    (void)key; (void)input; (void)type;
    if (s_batch != NOXTLS_RETURN_NOT_SUPPORTED) {
        memset(output, 0xA6, (size_t)count * NOXTLS_AES_BLOCK_LENGTH);
    }

    return s_batch;
}

noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t nonce[12], const uint8_t *aad,
    uint32_t aad_len, const uint8_t *input, uint32_t length, uint8_t *output, uint8_t tag[16])
{
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len; (void)input;
    if (s_aead != NOXTLS_RETURN_NOT_SUPPORTED) {
        memset(output, 0xA6, length);
        memset(tag, 0xA6, 16U);
    }

    return s_aead;
}

noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t nonce[12], const uint8_t *aad,
    uint32_t aad_len, const uint8_t *input, uint32_t length, const uint8_t tag[16], uint8_t *output)
{
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len; (void)input; (void)tag;
    if (s_aead != NOXTLS_RETURN_NOT_SUPPORTED) {
        memset(output, 0xA6, length);
    }

    return s_aead;
}

/** @brief Check every byte of a bounded output span, not only its first block.
 * @param[in] bytes Span to inspect.
 * @param[in] length Span byte count.
 * @return True only if the complete span is erased. */
static bool erased(const void *bytes, size_t length)
{
    const uint8_t *cursor = bytes;
    size_t index;
    for (index = 0U; index < length; ++index) {
        if (cursor[index] != 0U) {
            return false;
        }
    }

    return true;
}

REGISTER_TEST(test_block_failure_and_context_contract)
{
    uint8_t output[16];
    noxtls_aes_context_t ctx = {0};
    const noxtls_return_t errors[] = {NOXTLS_RETURN_FAILED, NOXTLS_RETURN_TIMEOUT,
        NOXTLS_RETURN_INVALID_PARAM, NOXTLS_RETURN_NOT_INITIALIZED};
    unsigned index;
    for (index = 0U; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        reset_port(); s_failure = errors[index]; s_fail_at = 1U;
        UTNOX_EQUALS(noxtls_aes_encrypt_block_internal(s_key, s_data, output, NOXTLS_AES_128_BIT), errors[index]);
        UTNOX_EQUALS(erased(output, sizeof(output)), true);
        reset_port(); s_failure = errors[index]; s_fail_at = 1U;
        UTNOX_EQUALS(noxtls_aes_decrypt_block_internal(s_key, s_data, output, NOXTLS_AES_128_BIT), errors[index]);
        UTNOX_EQUALS(erased(output, sizeof(output)), true);
        UTNOX_EQUALS(noxtls_aes_prepare_context(&ctx, s_key, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        reset_port(); s_failure = errors[index]; s_fail_at = 1U;
        UTNOX_EQUALS(noxtls_aes_encrypt_block_ctx_internal(&ctx, s_data, output), errors[index]);
        UTNOX_EQUALS(erased(output, sizeof(output)), true);
        reset_port(); s_failure = errors[index]; s_fail_at = 1U;
        UTNOX_EQUALS(noxtls_aes_decrypt_block_ctx_internal(&ctx, s_data, output), errors[index]);
        UTNOX_EQUALS(erased(output, sizeof(output)), true);
    }

    return 0;
}

#if !NOXTLS_FEATURE_STM32_HW_AES_ONLY && !NOXTLS_FEATURE_NRF52_HW_AES_ONLY
REGISTER_TEST(test_fips197_software_fallback_vectors)
{
    const uint8_t expected[3][16] = {
        {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A},
        {0xDD,0xA9,0x7C,0xA4,0x86,0x4C,0xDF,0xE0,0x6E,0xAF,0x70,0xA0,0xEC,0x0D,0x71,0x91},
        {0x8E,0xA2,0xB7,0xCA,0x51,0x67,0x45,0xBF,0xEA,0xFC,0x49,0x90,0x4B,0x49,0x60,0x89}};
    uint8_t key[32], plain[16], cipher[16], decoded[16];
    unsigned index, type;
    for (index = 0U; index < sizeof(key); ++index) { key[index] = (uint8_t)index; }
    for (index = 0U; index < sizeof(plain); ++index) { plain[index] = (uint8_t)(index * 17U); }
    for (type = 0U; type < 3U; ++type) {
        reset_port();
        UTNOX_EQUALS(noxtls_aes_encrypt_block_internal(key, plain, cipher, (noxtls_aes_type_t)type), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(cipher, expected[type], sizeof(cipher)), 0);
        UTNOX_EQUALS(noxtls_aes_decrypt_block_internal(key, cipher, decoded, (noxtls_aes_type_t)type), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(decoded, plain, sizeof(plain)), 0);
    }

    return 0;
}

REGISTER_TEST(test_direct_mode_each_failure_position)
{
    const aes_error_mode_t modes[] = {noxtls_aes_encrypt_ecb, noxtls_aes_decrypt_ecb,
        noxtls_aes_encrypt_cbc, noxtls_aes_decrypt_cbc, noxtls_aes_encrypt_ctr,
        noxtls_aes_encrypt_cfb, noxtls_aes_encrypt_ofb, noxtls_aes_encrypt_xts};
    uint8_t output[AES_ERROR_TEST_BYTES];
    unsigned mode, count, at;
    for (mode = 0U; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
        reset_port();
        UTNOX_EQUALS(modes[mode](s_key, s_data, sizeof(s_data), s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        count = s_calls;
        for (at = 1U; at <= count; ++at) {
            reset_port(); s_fail_at = at;
            memset(output, 0x55, sizeof(output));
            UTNOX_EQUALS(modes[mode](s_key, s_data, sizeof(s_data), s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
            UTNOX_EQUALS(erased(output, sizeof(output)), true);
            UTNOX_EQUALS(s_calls, at);
        }

        UTNOX_EQUALS(modes[mode](NULL, s_data, sizeof(s_data), s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
        UTNOX_EQUALS(modes[mode](s_key, NULL, sizeof(s_data), s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
        UTNOX_EQUALS(modes[mode](s_key, s_data, sizeof(s_data), s_iv, NULL, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    }

    return 0;
}

REGISTER_TEST(test_ccm_gcm_each_failure_and_roundtrip)
{
    uint8_t cipher[32], tag[16], output[32];
    unsigned kind, count, at;
    for (kind = 0U; kind < 2U; ++kind) {
        reset_port();
        UTNOX_EQUALS(kind == 0U ? noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
            s_data, 5U, s_data, sizeof(s_data), cipher, tag, 4U) :
            noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, s_data, 5U, s_data, sizeof(s_data), cipher, tag), NOXTLS_RETURN_SUCCESS);
        count = s_calls;
        for (at = 1U; at <= count; ++at) {
            reset_port(); s_fail_at = at;
            memset(output, 0x55, sizeof(output));
            memset(tag, 0x55, sizeof(tag));
            UTNOX_EQUALS(kind == 0U ? noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
                s_data, 5U, s_data, sizeof(s_data), output, tag, 4U) :
                noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, s_data, 5U, s_data, sizeof(s_data), output, tag), NOXTLS_RETURN_TIMEOUT);
            UTNOX_EQUALS(erased(output, sizeof(output)), true);
            UTNOX_EQUALS(erased(tag, kind == 0U ? 4U : 16U), true);
        }

        reset_port();
        UTNOX_EQUALS(kind == 0U ? noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
            s_data, 5U, s_data, sizeof(s_data), cipher, tag, 4U) :
            noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, s_data, 5U, s_data, sizeof(s_data), cipher, tag), NOXTLS_RETURN_SUCCESS);
        reset_port();
        UTNOX_EQUALS(kind == 0U ? noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
            s_data, 5U, cipher, sizeof(cipher), tag, 4U, output) :
            noxtls_aes_gcm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, s_data, 5U, cipher, sizeof(cipher), tag, output), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(output, s_data, sizeof(output)), 0);
        count = s_calls;
        for (at = 1U; at <= count; ++at) {
            reset_port(); s_fail_at = at; memset(output, 0x55, sizeof(output));
            UTNOX_EQUALS(kind == 0U ? noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
                s_data, 5U, cipher, sizeof(cipher), tag, 4U, output) :
                noxtls_aes_gcm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, s_data, 5U, cipher, sizeof(cipher), tag, output), NOXTLS_RETURN_TIMEOUT);
            UTNOX_EQUALS(erased(output, sizeof(output)), true);
        }
    }

    return 0;
}

REGISTER_TEST(test_drbg_batch_fallback_counter_and_errors)
{
    drbg_state_t state;
    const uint8_t seed[DRBG_SEEDLEN_AES128] = {1U};
    uint8_t output[32], expected_counter[16];
    reset_port();
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES128, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    memcpy(expected_counter, state.V, sizeof(expected_counter));
    reset_port();
    UTNOX_EQUALS(drbg_generate(&state, output, sizeof(output) * 8U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(s_first_input, expected_counter, sizeof(expected_counter)), 0);
    reset_port();
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES128, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    reset_port(); s_batch = NOXTLS_RETURN_TIMEOUT;
    memset(output, 0x55, sizeof(output));
    UTNOX_EQUALS(drbg_generate(&state, output, sizeof(output) * 8U, NULL, 0U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(output, sizeof(output)), true);
    UTNOX_EQUALS(erased(&state, sizeof(state)), true);
    UTNOX_EQUALS(s_calls, 0U);
    reset_port(); s_fail_at = 1U;
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES128, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(&state, sizeof(state)), true);
    return 0;
}

REGISTER_TEST(test_stream_context_failure_and_partial_bounds)
{
    noxtls_aes_context_t ctx, before;
    uint8_t output[32];
    uint32_t length;
    unsigned mode, op, at;
    for (mode = NOXTLS_AES_ECB; mode <= NOXTLS_AES_OFB; ++mode) {
        for (op = NOXTLS_AES_OP_ENCRYPT; op <= NOXTLS_AES_OP_DECRYPT; ++op) {
            for (at = 1U; at <= 2U; ++at) {
                reset_port();
                UTNOX_EQUALS(noxtls_aes_init(&ctx, s_key, s_iv, NOXTLS_AES_128_BIT,
                    (noxtls_aes_mode_t)mode, (noxtls_aes_operation_t)op), NOXTLS_RETURN_SUCCESS);
                s_fail_at = at;
                memset(output, 0x55, sizeof(output)); length = UINT32_MAX;
                UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, sizeof(s_data), output, &length), NOXTLS_RETURN_TIMEOUT);
                UTNOX_EQUALS(length, 0U);
                UTNOX_EQUALS(erased(output, sizeof(output)), true);
                UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
            }
        }
    }

    reset_port();
    UTNOX_EQUALS(noxtls_aes_init(&ctx, s_key, s_iv, NOXTLS_AES_128_BIT,
        NOXTLS_AES_ECB, NOXTLS_AES_OP_ENCRYPT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, 1U, output, &length), NOXTLS_RETURN_SUCCESS);
    s_fail_at = 1U;
    UTNOX_EQUALS(noxtls_aes_final(&ctx, output, &length), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(length, 0U);
    UTNOX_EQUALS(erased(output, NOXTLS_AES_BLOCK_LENGTH), true);
    UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
    reset_port();
    UTNOX_EQUALS(noxtls_aes_init(&ctx, s_key, s_iv, NOXTLS_AES_128_BIT,
        NOXTLS_AES_CBC, NOXTLS_AES_OP_ENCRYPT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, 1U, output, &length), NOXTLS_RETURN_SUCCESS);
    s_fail_at = 1U;
    UTNOX_EQUALS(noxtls_aes_final(&ctx, output, &length), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
    reset_port();
    UTNOX_EQUALS(noxtls_aes_init(&ctx, s_key, s_iv, NOXTLS_AES_128_BIT,
        NOXTLS_AES_ECB, NOXTLS_AES_OP_ENCRYPT), NOXTLS_RETURN_SUCCESS);
    /* Synthetic lengths must be rejected before reading the small input or
     * mutating the context/output. MAX - partial + 1 is the first overflow. */
    for (at = 1U; at <= NOXTLS_AES_BLOCK_LENGTH; ++at) {
        ctx.partial_len = (uint8_t)at;
        before = ctx;
        memset(output, 0x55, sizeof(output));
        length = UINT32_MAX;
        UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, UINT32_MAX - at + 1U,
            output, &length), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
        UTNOX_EQUALS(length, 0U);
        UTNOX_EQUALS(memcmp(&before, &ctx, sizeof(ctx)), 0);
        UTNOX_EQUALS(output[0], 0x55U);
        UTNOX_EQUALS(output[sizeof(output) - 1U], 0x55U);
        UTNOX_EQUALS(s_calls, 0U);
    }
    ctx.partial_len = NOXTLS_AES_BLOCK_LENGTH + 1U;
    UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, 1U, output, &length), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    return 0;
}

REGISTER_TEST(test_cmac_each_failure_invalidates_state)
{
    noxtls_aes_cmac_context_t ctx;
    uint8_t mac[16];
    unsigned count, at;
    reset_port();
    UTNOX_EQUALS(noxtls_aes_cmac(s_key, s_data, sizeof(s_data), mac, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    count = s_calls;
    for (at = 1U; at <= count; ++at) {
        reset_port(); s_fail_at = at; memset(mac, 0x55, sizeof(mac));
        UTNOX_EQUALS(noxtls_aes_cmac(s_key, s_data, sizeof(s_data), mac, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(erased(mac, sizeof(mac)), true);
    }

    reset_port();
    UTNOX_EQUALS(noxtls_aes_cmac_init(&ctx, s_key, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    s_fail_at = s_calls + 1U;
    UTNOX_EQUALS(noxtls_aes_cmac_update(&ctx, s_data, sizeof(s_data)), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
    UTNOX_EQUALS(noxtls_aes_cmac_final(&ctx, mac), NOXTLS_RETURN_NOT_INITIALIZED);
    return 0;
}

REGISTER_TEST(test_drbg_each_scalar_failure_invalidates_state)
{
    drbg_state_t state;
    const uint8_t seed[DRBG_SEEDLEN_AES256] = {1U};
    uint8_t output[33];
    unsigned count, at;
    reset_port();
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES256, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    reset_port();
    UTNOX_EQUALS(drbg_generate(&state, output, sizeof(output) * 8U, s_data, sizeof(s_data)), NOXTLS_RETURN_SUCCESS);
    count = s_calls;
    for (at = 1U; at <= count; ++at) {
        reset_port();
        UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES256, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        reset_port(); s_fail_at = at; memset(output, 0x55, sizeof(output));
        UTNOX_EQUALS(drbg_generate(&state, output, sizeof(output) * 8U, s_data, sizeof(s_data)), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(erased(output, sizeof(output)), true);
        UTNOX_EQUALS(erased(&state, sizeof(state)), true);
    }

    reset_port();
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES256, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    reset_port(); s_fail_at = 1U;
    UTNOX_EQUALS(drbg_reseed(&state, seed, sizeof(seed), NULL, 0U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(&state, sizeof(state)), true);
    return 0;
}

REGISTER_TEST(test_ccm_nonce_and_block_boundaries)
{
    uint8_t output[32], cipher[32], tag[16];
    unsigned length;
    for (length = 7U; length <= 13U; ++length) {
        reset_port();
        UTNOX_EQUALS(noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, length,
            NULL, 0U, s_data, sizeof(s_data), cipher, tag, 4U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, length,
            NULL, 0U, cipher, sizeof(cipher), tag, 4U, output), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(output, s_data, sizeof(output)), 0);
    }

    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
        NULL, 1U, s_data, sizeof(s_data), cipher, tag, 4U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
        NULL, 1U, cipher, sizeof(cipher), tag, 4U, output), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(s_key, s_data, 17U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    UTNOX_EQUALS(noxtls_aes_decrypt_ecb(s_key, s_data, 17U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    reset_port();
    UTNOX_EQUALS(noxtls_aes_encrypt_cbc(s_key, s_data, 17U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    reset_port(); s_fail_at = 2U; memset(output, 0x55, sizeof(output));
    UTNOX_EQUALS(noxtls_aes_encrypt_cbc(s_key, s_data, 17U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(output, sizeof(output)), true);
    UTNOX_EQUALS(noxtls_aes_encrypt_cbc(s_key, s_data, UINT32_MAX, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    UTNOX_EQUALS(noxtls_aes_decrypt_cbc(s_key, s_data, 17U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
        NULL, 0U, s_data, 65536U, cipher, tag, 4U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, 13U,
        NULL, 0U, cipher, 65536U, tag, 4U, output), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(s_key, s_data, 0U, NULL, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_unsupported_context_and_final_success)
{
    noxtls_aes_context_t ctx;
    uint8_t output[32];
    uint32_t length;
    unsigned mode;
    reset_port();
    UTNOX_EQUALS(noxtls_aes_prepare_context(&ctx, s_key, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    s_fail_at = 1U; s_failure = NOXTLS_RETURN_NOT_SUPPORTED;
    UTNOX_EQUALS(noxtls_aes_encrypt_block_ctx_internal(&ctx, s_data, output), NOXTLS_RETURN_SUCCESS);
    reset_port(); s_fail_at = 1U; s_failure = NOXTLS_RETURN_NOT_SUPPORTED;
    UTNOX_EQUALS(noxtls_aes_decrypt_block_ctx_internal(&ctx, s_data, output), NOXTLS_RETURN_SUCCESS);
    for (mode = NOXTLS_AES_ECB; mode <= NOXTLS_AES_CBC; ++mode) {
        reset_port();
        UTNOX_EQUALS(noxtls_aes_init(&ctx, s_key, s_iv, NOXTLS_AES_128_BIT,
            (noxtls_aes_mode_t)mode, NOXTLS_AES_OP_ENCRYPT), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_aes_update(&ctx, s_data, 1U, output, &length), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_aes_final(&ctx, output, &length), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(length, (uint32_t)NOXTLS_AES_BLOCK_LENGTH);
    }

    return 0;
}

REGISTER_TEST(test_xts_partial_and_cmac_partial_failures)
{
    noxtls_aes_cmac_context_t ctx;
    uint8_t output[32];
    unsigned at;
    reset_port();
    UTNOX_EQUALS(noxtls_aes_encrypt_xts(s_key, s_data, 17U, s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    for (at = 1U; at <= 4U; ++at) {
        reset_port(); s_fail_at = at; memset(output, 0x55, sizeof(output));
        UTNOX_EQUALS(noxtls_aes_encrypt_xts(s_key, s_data, 17U, s_iv, output, NOXTLS_AES_128_BIT), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(erased(output, 17U), true);
        UTNOX_EQUALS(output[17], 0x55U);
    }

    UTNOX_EQUALS(noxtls_aes_cmac_init(&ctx, s_key, (noxtls_aes_type_t)9), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
    reset_port();
    UTNOX_EQUALS(noxtls_aes_cmac_init(&ctx, s_key, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_cmac_update(&ctx, s_data, 8U), NOXTLS_RETURN_SUCCESS);
    s_fail_at = s_calls + 1U;
    UTNOX_EQUALS(noxtls_aes_cmac_update(&ctx, s_data, sizeof(s_data)), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(&ctx, sizeof(ctx)), true);
    return 0;
}

REGISTER_TEST(test_gcm_auth_failure_and_reseed_success)
{
    drbg_state_t state;
    const uint8_t seed[DRBG_SEEDLEN_AES128] = {1U};
    uint8_t cipher[32], output[32], tag[16];
    reset_port();
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        s_data, sizeof(s_data), cipher, tag), NOXTLS_RETURN_SUCCESS);
    tag[0] ^= 1U;
    memset(output, 0x55, sizeof(output));
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        cipher, sizeof(cipher), tag, output), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(erased(output, sizeof(output)), true);
    reset_port();
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES128, seed, sizeof(seed), NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(drbg_reseed(&state, seed, sizeof(seed), NULL, 0U), NOXTLS_RETURN_SUCCESS);
    return 0;
}
#endif

REGISTER_TEST(test_gcm_native_aead_errors)
{
    uint8_t output[32], tag[16];
    reset_port(); s_aead = NOXTLS_RETURN_TIMEOUT;
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        s_data, sizeof(s_data), output, tag), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(erased(output, sizeof(output)), true);
    UTNOX_EQUALS(erased(tag, sizeof(tag)), true);
    UTNOX_EQUALS(s_calls, 0U);
    reset_port(); s_aead = NOXTLS_RETURN_BAD_DATA;
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        s_data, sizeof(s_data), tag, output), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(erased(output, sizeof(output)), true);
    UTNOX_EQUALS(s_calls, 0U);
    reset_port(); s_aead = NOXTLS_RETURN_SUCCESS;
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        s_data, sizeof(s_data), output, tag), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt(s_key, NOXTLS_AES_128_BIT, s_iv, NULL, 0U,
        s_data, sizeof(s_data), tag, output), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, 0U);
    return 0;
}

#ifdef _MSC_VER
/** @brief Register the same deterministic cases on MSVC's C runner. */
void utnox_register_tests(void)
{
    register_test("test_block_failure_and_context_contract", test_block_failure_and_context_contract);
    register_test("test_gcm_native_aead_errors", test_gcm_native_aead_errors);
#if !NOXTLS_FEATURE_STM32_HW_AES_ONLY && !NOXTLS_FEATURE_NRF52_HW_AES_ONLY
    register_test("test_fips197_software_fallback_vectors", test_fips197_software_fallback_vectors);
    register_test("test_direct_mode_each_failure_position", test_direct_mode_each_failure_position);
    register_test("test_ccm_gcm_each_failure_and_roundtrip", test_ccm_gcm_each_failure_and_roundtrip);
    register_test("test_drbg_batch_fallback_counter_and_errors", test_drbg_batch_fallback_counter_and_errors);
    register_test("test_stream_context_failure_and_partial_bounds", test_stream_context_failure_and_partial_bounds);
    register_test("test_cmac_each_failure_invalidates_state", test_cmac_each_failure_invalidates_state);
    register_test("test_drbg_each_scalar_failure_invalidates_state", test_drbg_each_scalar_failure_invalidates_state);
    register_test("test_ccm_nonce_and_block_boundaries", test_ccm_nonce_and_block_boundaries);
    register_test("test_unsupported_context_and_final_success", test_unsupported_context_and_final_success);
    register_test("test_xts_partial_and_cmac_partial_failures", test_xts_partial_and_cmac_partial_failures);
    register_test("test_gcm_auth_failure_and_reseed_success", test_gcm_auth_failure_and_reseed_success);
#endif
}
#endif
