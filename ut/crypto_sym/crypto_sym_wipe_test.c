/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_wipe_test.c
* Summary: Zeroization promises of the symmetric APIs (public API only).
*
* Only behaviour that a header comment or the implementation explicitly
* promises is asserted (base commit f8b407a):
*
*  PROMISED (asserted here)
*  - noxtls_hmac_free(): wipes the whole noxtls_hmac_context_t (key, ipad,
*    opad, length, algorithm, hash_ctx pointer) and releases the inner hash
*    state; valid after init, after update, after final, and after a failed
*    init ("a context whose init failed is still safe to pass to
*    noxtls_hmac_free()").
*  - noxtls_drbg_uninstantiate(): "clear state" (header) / "securely wipe
*    DRBG secret state" (NX-10): every byte of drbg_state_t is zero.
*  - noxtls_aes_cmac_init(): clears the context first and again when it fails
*    (unsupported key type), so a failed init leaves no key material.
*  - noxtls_pbkdf2_hmac(): "dk ... erased on failure" (header), e.g. zero
*    iterations or an unsupported PRF (only with NOXTLS_FEATURE_PBKDF2).
*  - noxtls_aes_key_unwrap(): "plain ... cleared on failure" (header).
*  - noxtls_aes_gcm_decrypt() / noxtls_aes_ccm_decrypt(): authentication
*    failure zeroes the plaintext buffer (code: GCM, CCM "NX-06: never expose
*    unauthenticated plaintext"). noxtls_chacha20_poly1305_decrypt(): "don't
*    decrypt" on failure, i.e. the output buffer is left untouched.
*
*  NOT PROMISED (deliberately not asserted; listed for the refactor)
*  - noxtls_aes_final(): only clears `initialized`; key, round keys and
*    feedback stay in noxtls_aes_context_t (contexts are wiped only on error).
*  - noxtls_aes_cmac_final(): now wipes the whole context on success too
*    (asserted in test_cmac_final_wipes()).
*  - noxtls_sha_finish() and the per-algorithm *_finish() functions: the
*    context is zeroed only on failure.
*  - noxtls_hmac_final(): success leaves key/ipad/opad until noxtls_hmac_free();
*    failure wipes them (not triggerable through the public API).
*  - noxtls_hkdf_expand(): "never release a partial OKM" only for failures
*    inside the HMAC loop (not triggerable through the public API).
*  - noxtls_poly1305_final(), noxtls_chacha20_* , noxtls_aria_final(),
*    noxtls_camellia_final(): no wipe and no free/finish API.
*  - XTS header: "(output is zeroed on failure)" next to key-size / block
*    cipher errors is ambiguous; key-size errors return before touching output.
*  - Library-internal residue (fixed by the refactor, not observable through
*    the API): AES-GCM no longer keeps H or its table in a static cache and
*    wipes its per-call AES context.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mac/noxtls_hmac.h"
#include "drbg/noxtls_drbg.h"
#include "encryption/aes/noxtls_aes.h"
#if NOXTLS_FEATURE_AES_CMAC
#include "encryption/aes/noxtls_aes_cmac.h"
#endif
#if NOXTLS_FEATURE_AES_ECB
#include "encryption/aes/noxtls_aes_keywrap.h"
#endif
#if NOXTLS_FEATURE_AES_GCM
#include "encryption/aes/noxtls_aes_gcm.h"
#endif
#if NOXTLS_FEATURE_AES_CCM
#include "encryption/aes/noxtls_aes_ccm.h"
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
#include "encryption/chacha20/noxtls_chacha20_poly1305.h"
#endif
#if NOXTLS_FEATURE_PBKDF2
#include "kdf/noxtls_pbkdf.h"
#endif

#include "crypto_sym_test_util.h"

static uint8_t g_key[200];
static uint8_t g_msg[300];
static uint8_t g_out[300];

static void test_hmac_free(void)
{
    static const noxtls_hash_algos_t k_algs[] = {
#if NOXTLS_FEATURE_SHA1
        NOXTLS_HASH_SHA1,
#endif
#if NOXTLS_FEATURE_SHA256
        NOXTLS_HASH_SHA_256,
#endif
#if NOXTLS_FEATURE_SHA384
        NOXTLS_HASH_SHA_384,
#endif
#if NOXTLS_FEATURE_SHA512
        NOXTLS_HASH_SHA_512,
#endif
    };
    static noxtls_hmac_context_t ctx;
    static const uint32_t k_klens[] = { 1U, 32U, 64U, 129U, 200U };
    uint8_t mac[64];
    uint32_t mac_len;
    uint32_t a;
    uint32_t k;

    cs_fill(g_key, sizeof(g_key), 0x4B4B4B4BU);
    cs_fill(g_msg, sizeof(g_msg), 0x4D4D4D4DU);
    for (a = 0U; a < (uint32_t)(sizeof(k_algs) / sizeof(k_algs[0])); a += 1U) {
        for (k = 0U; k < (uint32_t)(sizeof(k_klens) / sizeof(k_klens[0])); k += 1U) {
            cs_section("noxtls_hmac_free after init");
            CHECK_RC(noxtls_hmac_init(&ctx, k_algs[a], g_key, k_klens[k]), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_zero(&ctx, sizeof(ctx)));

            cs_section("noxtls_hmac_free after update");
            CHECK_RC(noxtls_hmac_init(&ctx, k_algs[a], g_key, k_klens[k]), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_hmac_update(&ctx, g_msg, sizeof(g_msg)), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_zero(&ctx, sizeof(ctx)));

            cs_section("noxtls_hmac_free after final");
            CHECK_RC(noxtls_hmac_init(&ctx, k_algs[a], g_key, k_klens[k]), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_hmac_update(&ctx, g_msg, 77U), NOXTLS_RETURN_SUCCESS);
            mac_len = sizeof(mac);
            CHECK_RC(noxtls_hmac_final(&ctx, mac, &mac_len), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_zero(&ctx, sizeof(ctx)));
        }
    }
    cs_section("noxtls_hmac_free after failed init");
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK(noxtls_hmac_init(&ctx, (noxtls_hash_algos_t)NOXTLS_HASH_RIPEMD160, g_key, 16U) != NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK(noxtls_hmac_init(&ctx, (noxtls_hash_algos_t)250U, g_key, 16U) != NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
}

static void test_drbg_uninstantiate(void)
{
    static drbg_state_t st;
    static const drbg_aes_type_t k_types[] = {
#if NOXTLS_FEATURE_AES_128
        DRBG_AES128,
#endif
#if NOXTLS_FEATURE_AES_192
        DRBG_AES192,
#endif
#if NOXTLS_FEATURE_AES_256
        DRBG_AES256,
#endif
    };
    uint8_t entropy[48];
    uint32_t i;

    cs_fill(entropy, sizeof(entropy), 0xE7E7E7E7U);
    for (i = 0U; i < (uint32_t)(sizeof(k_types) / sizeof(k_types[0])); i += 1U) {
        cs_section("noxtls_drbg_uninstantiate after generate");
        CHECK_RC(drbg_instantiate(&st, k_types[i], entropy, sizeof(entropy), entropy, 8U, entropy, 5U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_generate(&st, g_out, 8U * 100U, entropy, 3U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_drbg_uninstantiate(&st), NOXTLS_RETURN_SUCCESS);
        CHECK(cs_all_zero(&st, sizeof(st)));
        CHECK(drbg_generate(&st, g_out, 128U, NULL, 0U) != NOXTLS_RETURN_SUCCESS);

        cs_section("noxtls_drbg_uninstantiate on a garbage-filled state");
        (void)memset(&st, 0x5A, sizeof(st));
        CHECK_RC(noxtls_drbg_uninstantiate(&st), NOXTLS_RETURN_SUCCESS);
        CHECK(cs_all_zero(&st, sizeof(st)));
    }
}

static void test_cmac_failed_init(void)
{
#if NOXTLS_FEATURE_AES_CMAC
    static noxtls_aes_cmac_context_t ctx;
    cs_section("noxtls_aes_cmac_init failure clears the context");
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK(noxtls_aes_cmac_init(&ctx, g_key, (noxtls_aes_type_t)7U) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
#endif
}

/* After the memory-reduction refactor these also wipe their whole context. */
static void test_cmac_final_wipes(void)
{
#if NOXTLS_FEATURE_AES_CMAC
    static noxtls_aes_cmac_context_t ctx;
    uint8_t mac[16];
    uint32_t len;
    cs_section("noxtls_aes_cmac_final wipes the context");
    for (len = 0U; len <= 40U; len += 20U) {
        (void)memset(&ctx, 0xA5, sizeof(ctx));
        CHECK_RC(noxtls_aes_cmac_init(&ctx, g_key, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_cmac_update(&ctx, g_key, len), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_cmac_final(&ctx, mac), NOXTLS_RETURN_SUCCESS);
        CHECK(cs_all_zero(&ctx, sizeof(ctx)));
        CHECK_RC(noxtls_aes_cmac_final(&ctx, mac), NOXTLS_RETURN_NOT_INITIALIZED);
    }
#endif
}

static void test_pbkdf2_failure(void)
{
#if NOXTLS_FEATURE_PBKDF2
    uint8_t dk[40];
    cs_section("noxtls_pbkdf2_hmac failure erases dk");
    (void)memset(dk, 0xA5, sizeof(dk));
    CHECK(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, (const uint8_t *)"password", 8U, (const uint8_t *)"salt", 4U, 0U, dk,
                             sizeof(dk)) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(dk, sizeof(dk)));
    (void)memset(dk, 0xA5, sizeof(dk));
    CHECK(noxtls_pbkdf2_hmac(NOXTLS_HASH_MD5, (const uint8_t *)"password", 8U, (const uint8_t *)"salt", 4U, 2U, dk,
                             sizeof(dk)) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(dk, sizeof(dk)));
#endif
}

static void test_unwrap_failure(void)
{
#if NOXTLS_FEATURE_AES_ECB && NOXTLS_FEATURE_AES_128
    uint8_t kek[16];
    uint8_t plain[32];
    uint8_t wrapped[40];
    uint8_t out[32];
    cs_section("noxtls_aes_key_unwrap failure clears plain");
    cs_fill(kek, sizeof(kek), 0x11111111U);
    cs_fill(plain, sizeof(plain), 0x22222222U);
    CHECK_RC(noxtls_aes_key_wrap(kek, NOXTLS_AES_128_BIT, plain, 32U, wrapped), NOXTLS_RETURN_SUCCESS);
    wrapped[20] ^= 0x04U;
    (void)memset(out, 0xA5, sizeof(out));
    CHECK(noxtls_aes_key_unwrap(kek, NOXTLS_AES_128_BIT, wrapped, 40U, out) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(out, sizeof(out)));
#endif
}

static void test_aead_failure_output(void)
{
    uint8_t key[32];
    uint8_t nonce[13];
    uint8_t tag[16];
    uint8_t pt[100];
    uint8_t ct[100];

    cs_fill(key, sizeof(key), 0x33333333U);
    cs_fill(nonce, sizeof(nonce), 0x44444444U);
    cs_fill(pt, sizeof(pt), 0x55555555U);
#if NOXTLS_FEATURE_AES_GCM && NOXTLS_FEATURE_AES_128
    cs_section("noxtls_aes_gcm_decrypt failure zeroes plaintext");
    CHECK_RC(noxtls_aes_gcm_encrypt(key, NOXTLS_AES_128_BIT, nonce, NULL, 0U, pt, sizeof(pt), ct, tag), NOXTLS_RETURN_SUCCESS);
    tag[3] ^= 0x10U;
    (void)memset(g_out, 0xA5, sizeof(g_out));
    CHECK_RC(noxtls_aes_gcm_decrypt(key, NOXTLS_AES_128_BIT, nonce, NULL, 0U, ct, sizeof(ct), tag, g_out),
             NOXTLS_RETURN_BAD_DATA);
    CHECK(cs_all_zero(g_out, sizeof(pt)));
#endif
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_128
    cs_section("noxtls_aes_ccm_decrypt failure zeroes plaintext");
    CHECK_RC(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, NULL, 0U, pt, sizeof(pt), ct, tag, 16U),
             NOXTLS_RETURN_SUCCESS);
    ct[99] ^= 0x10U;
    (void)memset(g_out, 0xA5, sizeof(g_out));
    CHECK_RC(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, NULL, 0U, ct, sizeof(ct), tag, 16U, g_out),
             NOXTLS_RETURN_BAD_DATA);
    CHECK(cs_all_zero(g_out, sizeof(pt)));
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    cs_section("noxtls_chacha20_poly1305_decrypt failure does not decrypt");
    CHECK_RC(noxtls_chacha20_poly1305_encrypt(key, nonce, NULL, 0U, pt, sizeof(pt), ct, tag), NOXTLS_RETURN_SUCCESS);
    tag[15] ^= 0x01U;
    (void)memset(g_out, 0xA5, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(key, nonce, NULL, 0U, ct, sizeof(ct), tag, g_out), NOXTLS_RETURN_BAD_DATA);
    CHECK(cs_all_byte(g_out, sizeof(pt), 0xA5U) || cs_all_zero(g_out, sizeof(pt)));
#endif
    (void)key;
    (void)nonce;
    (void)tag;
    (void)pt;
    (void)ct;
}

int main(void)
{
    test_hmac_free();
    test_drbg_uninstantiate();
    test_cmac_failed_init();
    test_cmac_final_wipes();
    test_pbkdf2_failure();
    test_unwrap_failure();
    test_aead_failure_output();
    return cs_finish("crypto_sym_wipe_test");
}
