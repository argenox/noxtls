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
static bool s_batch_real;
static uint32_t s_batch_blocks;
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
    s_batch_real = false;
    s_batch_blocks = 0U;
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
    if (s_batch_real) {
        /* A working batch backend: real AES (library software) on every block. */
        noxtls_return_t result = NOXTLS_RETURN_SUCCESS;
        uint32_t i;
        s_batch_blocks += count;
        s_software = true;
        for (i = 0U; (i < count) && (result == NOXTLS_RETURN_SUCCESS); ++i) {
            result = noxtls_aes_encrypt_block_internal(key, &input[i * NOXTLS_AES_BLOCK_LENGTH],
                &output[i * NOXTLS_AES_BLOCK_LENGTH], type);
        }
        s_software = false;
        return result;
    }
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
    /* SP 800-90A 10.2.1.5.2 step 4.1: V = V + 1 before the first output block. */
    memcpy(expected_counter, state.V, sizeof(expected_counter));
    expected_counter[15] = (uint8_t)(expected_counter[15] + 1U);
    UTNOX_EQUALS(expected_counter[15] != 0U, true); /* no carry for this seed */
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

/** @brief Hex digit pairs to bytes (test vectors only). */
static size_t ut_hex(const char *hex, uint8_t *out)
{
    size_t n = 0U;
    while ((hex[0] != '\0') && (hex[1] != '\0')) {
        unsigned v = 0U;
        int i;
        for (i = 0; i < 2; ++i) {
            char c = hex[i];
            v = (v << 4) | (unsigned)((c <= '9') ? (c - '0') : ((c | 0x20) - 'a' + 10));
        }
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

/** @brief One NIST CAVP flow (pr_false: instantiate, reseed, generate x2); returns the last output. */
static int drbg_cavp_flow(uint8_t *output, size_t out_len, uint8_t *big, size_t big_len)
{
    /* NIST CAVP CTR_DRBG.rsp (CAVS 14.3) drbgvectors_pr_false [AES-256 use df], COUNT = 0. */
    static const char *const k_hex[] = {
        "174b46250051a9e3d80c56ae7163dafe7e54481a56cafd3b8625f99bbb29c442",
        "98ffd99c466e0e94a45da7e0e82dbc6b",
        "7095268e99938b3e042734b9176c9aa051f00a5f8d2a89ada214b89beef18ebf",
        "e88be1967c5503f65d23867bbc891bd679db03b4878663f6c877592df25f0d9a",
        "cdf6ad549e45b6aa5cd67d024931c33cd133d52d5ae500c3015020beb30da063",
        "c7228e90c62f896a09e11684530102f926ec90a3255f6c21b857883c75800143",
        "76a94f224178fe4cbf9e2b8acc53c9dc3e50bb613aac8936601453cda3293b17",
    };
    uint8_t v[7][32];
    size_t l[7];
    drbg_state_t state;
    size_t i;
    for (i = 0U; i < 7U; ++i) {
        l[i] = ut_hex(k_hex[i], v[i]);
    }
    UTNOX_EQUALS(drbg_instantiate(&state, DRBG_AES256, v[0], (uint32_t)l[0], v[1], (uint32_t)l[1], v[2],
        (uint32_t)l[2]), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(drbg_reseed(&state, v[3], (uint32_t)l[3], v[4], (uint32_t)l[4]), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(drbg_generate(&state, output, (uint32_t)out_len * 8U, v[5], (uint32_t)l[5]), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(drbg_generate(&state, output, (uint32_t)out_len * 8U, v[6], (uint32_t)l[6]), NOXTLS_RETURN_SUCCESS);
    /* A long request with a partial last block (batch chunks + tail). */
    UTNOX_EQUALS(drbg_generate(&state, big, (uint32_t)big_len * 8U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    (void)noxtls_drbg_uninstantiate(&state);
    return 0;
}

REGISTER_TEST(test_drbg_batch_hook_matches_block_path_and_cavp)
{
    static const char k_expected[] =
        "1a6d8dbd642076d13916e5e23038b60b26061f13dd4e006277e0268698ffb2c87e453bae1251631ac90c701a9849d933"
        "995e8b0221fe9aca1985c546c2079027";
    uint8_t expected[64], batch_out[64], block_out[64];
    static uint8_t batch_big[1000], block_big[1000];
    (void)ut_hex(k_expected, expected);

    reset_port(); s_batch_real = true;
    UTNOX_EQUALS(drbg_cavp_flow(batch_out, sizeof(batch_out), batch_big, sizeof(batch_big)), 0);
    UTNOX_EQUALS(s_batch_blocks > 60U, true);  /* the batch hook served the keystream */
    reset_port();
    UTNOX_EQUALS(drbg_cavp_flow(block_out, sizeof(block_out), block_big, sizeof(block_big)), 0);
    UTNOX_EQUALS(s_batch_blocks, 0U);
    UTNOX_EQUALS(memcmp(batch_out, expected, sizeof(expected)), 0);
    UTNOX_EQUALS(memcmp(block_out, expected, sizeof(expected)), 0);
    UTNOX_EQUALS(memcmp(batch_big, block_big, sizeof(batch_big)), 0);
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
