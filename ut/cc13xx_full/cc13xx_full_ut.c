/*****************************************************************************
 * Copyright (c) [2019] - [2026], Argenox Technologies LLC
 * All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 * File:    cc13xx_full_ut.c
 * Summary: Injected CC13xx binding ownership and bounded AES port contracts
 *****************************************************************************/
/** @file cc13xx_full_ut.c
 * @brief Exercise actual CCM, SHA and X25519 cores through the shared guards.
 * @ingroup noxtls_cc13xx_crypto
 */
#include "common/noxtls_cc13xx_crypto.h"
#include "encryption/aes/noxtls_aes_ccm.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "pkc/x25519/noxtls_x25519.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>
static uint32_t calls;
static unsigned token;
static bool fail;
static noxtls_return_t nested_bind;

/** @brief Reenter actual software CCM while the native AES/SHA guard is held.
 * @param[in,out] context Expected token.
 * @param[in] r Cipher request.
 * @return Actual software result or injected admitted failure.
 */
static noxtls_return_t ccm(void *context, const noxtls_cc13xx_ccm_request_t *r)
{
    ++calls;
    if (context != &token) {
        return NOXTLS_RETURN_FAILED;
    }
    nested_bind = noxtls_cc13xx_crypto_bind_sha256(NULL, NULL);
    if (fail) {
        memset(r->data.output, 0xA5, r->data.length);
        return NOXTLS_RETURN_FAILED;
    }
    const noxtls_cc13xx_gcm_request_t *q = &r->data;
    if (q->decrypt) {
        return noxtls_aes_ccm_decrypt(q->key, NOXTLS_AES_128_BIT, q->nonce, r->nonce_length, q->aad,
                                      q->aad_length, q->input, q->length, q->expected_tag,
                                      r->tag_length, q->output);
    }
    return noxtls_aes_ccm_encrypt(q->key, NOXTLS_AES_128_BIT, q->nonce, r->nonce_length, q->aad,
                                  q->aad_length, q->input, q->length, q->output, q->tag,
                                  r->tag_length);
}

/** @brief Reenter actual software SHA while the native AES/SHA guard is held.
 * @param[in,out] context Expected token.
 * @param[in,out] state Candidate chaining state.
 * @param[in] input Complete blocks.
 * @param[in] blocks Block count.
 * @return Actual software result or injected admitted failure.
 */
static noxtls_return_t sha(void *context, uint32_t state[8], const uint8_t *input, uint32_t blocks)
{
    ++calls;
    if (context != &token) {
        return NOXTLS_RETURN_FAILED;
    }
    nested_bind = noxtls_cc13xx_crypto_bind_ccm(NULL, NULL);
    if (fail) {
        state[0] = 0U;
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_sha_ctx_t temp = {0};
    temp.algo = NOXTLS_HASH_SHA_256;
    memcpy(temp.h, state, sizeof(temp.h));
    const noxtls_return_t rc = noxtls_sha256_update(&temp, input, blocks * 64U);
    memcpy(state, temp.h, sizeof(temp.h));
    return rc;
}

/** @brief Reenter actual software X25519 under the shared PKA guard.
 * @param[in,out] context Expected token.
 * @param[in] scalar Scalar bytes.
 * @param[in] u Coordinate bytes.
 * @param[out] output Result bytes.
 * @return Actual software result or injected admitted failure.
 */
static noxtls_return_t curve(void *context, const uint8_t scalar[32], const uint8_t u[32],
                             uint8_t output[32])
{
    ++calls;
    if (context != &token) {
        return NOXTLS_RETURN_FAILED;
    }
    nested_bind = noxtls_cc13xx_crypto_bind_p256(NULL, NULL);
    if (fail) {
        memset(output, 0xA5, 32U);
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_x25519_shared_secret(scalar, u, output);
}

/** @brief All three callbacks share the right guard, preserve context and support exact in-place
 * use. */
REGISTER_TEST(test_full_cc13xx_dispatch)
{
    uint8_t key[32] = {0}, nonce[13] = {0}, plain[64] = {0}, data[64], tag[4], digest[32],
            expected[32];
    calls = 0U;
    fail = false;
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind_ccm(ccm, &token), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, nonce, 13U, plain, 64U,
                                        data, tag, 4U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(calls, 1U);
    UTNOX_EQUALS(nested_bind, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, nonce, 13U, data, 64U,
                                        tag, 4U, data),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(data, plain, 64U), 0);
    tag[0] ^= 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, nonce, 13U, data, 64U,
                                        tag, 4U, data),
                 NOXTLS_RETURN_BAD_DATA);
    for (uint32_t i = 0U; i < 64U; ++i) {
        UTNOX_EQUALS(data[i], 0U);
    }
    noxtls_sha_ctx_t ctx;
    UTNOX_EQUALS(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_sha256_update(&ctx, plain, 64U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_sha256_finish(&ctx, expected), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind_sha256(sha, &token), NOXTLS_RETURN_SUCCESS);
    calls = 0U;
    UTNOX_EQUALS(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_sha256_update(&ctx, plain, 64U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_sha256_finish(&ctx, digest), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(digest, expected, 32U), 0);
    UTNOX_EQUALS(calls, 2U);
    UTNOX_EQUALS(nested_bind, NOXTLS_RETURN_NOT_INITIALIZED);
    uint8_t u[32] = {9};
    UTNOX_EQUALS(noxtls_x25519_shared_secret(key, u, expected), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind_x25519(curve, &token), NOXTLS_RETURN_SUCCESS);
    calls = 0U;
    UTNOX_EQUALS(noxtls_x25519_public_key(key, digest), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(digest, expected, 32U), 0);
    UTNOX_EQUALS(calls, 1U);
    UTNOX_EQUALS(nested_bind, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_sha256_blocks(ctx.h, plain, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    return 0;
}

/** @brief Admitted errors propagate through the actual algorithm cores, with no software
 * substitution. */
REGISTER_TEST(test_full_cc13xx_errors)
{
    uint8_t key[32] = {0}, nonce[13] = {0}, plain[64] = {0}, data[64], tag[4], output[32];
    noxtls_sha_ctx_t ctx;
    fail = true;
    (void)noxtls_cc13xx_crypto_bind_ccm(ccm, &token);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, NULL, 0U, plain, 64U,
                                        data, tag, 4U),
                 NOXTLS_RETURN_FAILED);
    for (uint32_t i = 0U; i < 64U; ++i) {
        UTNOX_EQUALS(data[i], 0U);
    }
    for (uint32_t i = 0U; i < 4U; ++i) {
        UTNOX_EQUALS(tag[i], 0U);
    }
    (void)noxtls_cc13xx_crypto_bind_sha256(sha, &token);
    (void)noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    uint32_t initial = ctx.h[0];
    UTNOX_EQUALS(noxtls_sha256_update(&ctx, plain, 64U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(ctx.h[0], initial);
    UTNOX_EQUALS(noxtls_sha256_finish(&ctx, output), NOXTLS_RETURN_FAILED);
    for (uint32_t i = 0U; i < 32U; ++i) {
        UTNOX_EQUALS(output[i], 0U);
    }
    (void)noxtls_cc13xx_crypto_bind_x25519(curve, &token);
    UTNOX_EQUALS(noxtls_x25519_public_key(key, output), NOXTLS_RETURN_FAILED);
    for (uint32_t i = 0U; i < 32U; ++i) {
        UTNOX_EQUALS(output[i], 0U);
    }
    fail = false;
    (void)noxtls_cc13xx_crypto_bind(NULL);
    UTNOX_EQUALS(noxtls_cc13xx_aes_ccm(NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_sha256_blocks(NULL, plain, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_cc13xx_sha256_blocks(ctx.h, plain, 0U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_cc13xx_x25519(NULL, key, output), NOXTLS_RETURN_NULL);
    return 0;
}

#if defined(_MSC_VER) && !defined(__cplusplus)
/** @brief Register all cases with the Windows UTNox runner. */
void utnox_register_tests(void)
{
    register_test("test_full_cc13xx_dispatch", test_full_cc13xx_dispatch);
    register_test("test_full_cc13xx_errors", test_full_cc13xx_errors);
}
#endif
