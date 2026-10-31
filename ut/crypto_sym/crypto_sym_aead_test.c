/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_aead_test.c
* Summary: AEAD regression tests (public API only).
*
*  - AES-GCM: McGrew-Viega / SP 800-38D test cases with 96-bit IVs (the API
*    takes a fixed 12-byte nonce, so TC5/6/11/12/17/18 with 64/480-bit IVs are
*    not applicable): TC1-4 (AES-128), TC7-10 (AES-192), TC13-16 (AES-256),
*    run forward and backward so the key (and the GHASH table cache) changes
*    between calls;
*  - AES-CCM: SP 800-38C C.1-C.3 and RFC 3610 packets #1, #2, #13 (nonce 7..13,
*    tag 4/6/8);
*  - ChaCha20 / Poly1305 / ChaCha20-Poly1305: RFC 8439 2.4.2, 2.5.2, 2.6.2 (the
*    one-time key is not exposed; it is checked as ChaCha20 block 0), 2.8.2 and
*    A.5 (decryption), ChaCha20 and Poly1305 streaming with odd chunks;
*  - every AEAD decrypt must reject a modified tag, ciphertext or AAD with
*    NOXTLS_RETURN_BAD_DATA and must not release plaintext. Base behaviour:
*    AES-GCM and AES-CCM zero the plaintext buffer, ChaCha20-Poly1305 leaves it
*    untouched; the test accepts either (it only forbids plaintext);
*  - IN-PLACE (output == input, exact aliasing) encrypt and decrypt for AES-GCM
*    (128/256), AES-CCM (nonce 13/tag 16, nonce 7/tag 4) and ChaCha20-Poly1305
*    for lengths 0, 1, 15, 16, 17, 31, 64, 100, 1000, compared with the
*    out-of-place result and with Python-computed tags;
*  - a TLS 1.2 AES-128-CBC + HMAC-SHA-256 record (MAC-then-encrypt) decrypted
*    in place with noxtls_aes_decrypt_cbc and with the streaming API, then the
*    padding and the MAC verified.
* Built twice: CRYPTO_SYM_PART=0 -> crypto_sym_aead_test (all AEAD checks,
*   including in-place AEAD), CRYPTO_SYM_PART=1 -> crypto_sym_tls_cbc_inplace_test
*   (the TLS 1.2 CBC record only).
* Expected values: crypto_sym_aead_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "encryption/aes/noxtls_aes.h"
#if NOXTLS_FEATURE_AES_GCM
#include "encryption/aes/noxtls_aes_gcm.h"
#endif
#if NOXTLS_FEATURE_AES_CCM
#include "encryption/aes/noxtls_aes_ccm.h"
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
#include "encryption/chacha20/noxtls_chacha20.h"
#include "encryption/chacha20/noxtls_chacha20_poly1305.h"
#endif
#include "mdigest/noxtls_hash.h"
#include "mac/noxtls_hmac.h"

#include "crypto_sym_test_util.h"
#include "crypto_sym_aead_vectors.h"

#ifndef CRYPTO_SYM_PART
#define CRYPTO_SYM_PART 0
#endif

#define CS_ARRAY_LEN(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))
#define CS_BUF (1100U)

static uint8_t g_key[32];
static uint8_t g_nonce[16];
static uint8_t g_aad[64];
static uint8_t g_pt[CS_BUF];
static uint8_t g_ct[CS_BUF];
static uint8_t g_out[CS_BUF];
static uint8_t g_buf[CS_BUF];
static uint8_t g_tag[16];
static uint8_t g_tag2[16];

/* After a failed decrypt: the output must be all zero or untouched (fill byte). */
static int no_plaintext_released(const uint8_t *out, uint32_t len, uint8_t fill)
{
    return ((cs_all_zero(out, len) != 0) || (cs_all_byte(out, len, fill) != 0)) ? 1 : 0;
}

/* Same after a failed in-place decrypt: zero, or the ciphertext left unchanged. */
static int no_plaintext_in_place(const uint8_t *buf, const uint8_t *ct, uint32_t len)
{
    return ((cs_all_zero(buf, len) != 0) || (memcmp(buf, ct, len) == 0)) ? 1 : 0;
}

/* ------------------------------------------------------------------------- */
/* AES-GCM                                                                    */
/* ------------------------------------------------------------------------- */
#if NOXTLS_FEATURE_AES_GCM
static int aes_type_for_len(uint32_t klen, noxtls_aes_type_t *type)
{
    if ((klen == 16U) && (NOXTLS_FEATURE_AES_128 != 0)) {
        *type = NOXTLS_AES_128_BIT;
        return 1;
    }
    if ((klen == 24U) && (NOXTLS_FEATURE_AES_192 != 0)) {
        *type = NOXTLS_AES_192_BIT;
        return 1;
    }
    if ((klen == 32U) && (NOXTLS_FEATURE_AES_256 != 0)) {
        *type = NOXTLS_AES_256_BIT;
        return 1;
    }
    return 0;
}

static void gcm_vector(const cs_gcm_case_t *tc, uint32_t pass)
{
    char what[64];
    noxtls_aes_type_t type;
    uint32_t kl = cs_hex(tc->key, g_key, sizeof(g_key));
    uint32_t al;
    uint32_t pl;

    if (aes_type_for_len(kl, &type) == 0) {
        return;
    }
    (void)cs_hex(tc->iv, g_nonce, sizeof(g_nonce));
    al = cs_hex(tc->aad, g_aad, sizeof(g_aad));
    pl = cs_hex(tc->pt, g_pt, CS_BUF);
    (void)cs_hex(tc->ct, g_ct, CS_BUF);
    (void)snprintf(what, sizeof(what), "GCM TC%u (pass %u)", (unsigned)tc->tc, (unsigned)pass);
    cs_section(what);

    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_aes_gcm_encrypt(g_key, type, g_nonce, (al != 0U) ? g_aad : NULL, al, g_pt, pl, g_out, g_tag),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("ciphertext", g_out, g_ct, pl);
    (void)EXPECT_HEX("tag", g_tag, 16U, tc->tag);
    CHECK(g_out[pl] == 0xEEU);

    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_aes_gcm_decrypt(g_key, type, g_nonce, (al != 0U) ? g_aad : NULL, al, g_ct, pl, g_tag, g_out),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("plaintext", g_out, g_pt, pl);

    /* Modified tag / ciphertext / AAD must be rejected without releasing plaintext. */
    g_tag[15] ^= 0x01U;
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_aes_gcm_decrypt(g_key, type, g_nonce, g_aad, al, g_ct, pl, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
    CHECK(no_plaintext_released(g_out, pl, 0xEEU));
    g_tag[15] ^= 0x01U;
    if (pl > 0U) {
        g_ct[pl - 1U] ^= 0x80U;
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_gcm_decrypt(g_key, type, g_nonce, g_aad, al, g_ct, pl, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_released(g_out, pl, 0xEEU));
        g_ct[pl - 1U] ^= 0x80U;
    }
    if (al > 0U) {
        g_aad[0] ^= 0x01U;
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_gcm_decrypt(g_key, type, g_nonce, g_aad, al, g_ct, pl, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_released(g_out, pl, 0xEEU));
        g_aad[0] ^= 0x01U;
    } else {
        /* Adding AAD that was not authenticated must fail too. */
        CHECK_RC(noxtls_aes_gcm_decrypt(g_key, type, g_nonce, (const uint8_t *)"x", 1U, g_ct, pl, g_tag, g_out),
                 NOXTLS_RETURN_BAD_DATA);
    }
}

static void test_gcm(void)
{
    uint32_t i;
    for (i = 0U; i < CS_ARRAY_LEN(k_gcm); i += 1U) {
        gcm_vector(&k_gcm[i], 0U);
    }
    for (i = CS_ARRAY_LEN(k_gcm); i > 0U; i -= 1U) {
        gcm_vector(&k_gcm[i - 1U], 1U);
    }
    for (i = 0U; i < CS_ARRAY_LEN(k_gcm); i += 1U) {
        /* Alternate two keys on every call. */
        gcm_vector(&k_gcm[i], 2U);
        gcm_vector(&k_gcm[(i + (CS_ARRAY_LEN(k_gcm) / 2U)) % CS_ARRAY_LEN(k_gcm)], 2U);
    }
}
#endif /* NOXTLS_FEATURE_AES_GCM */

/* ------------------------------------------------------------------------- */
/* AES-CCM                                                                    */
/* ------------------------------------------------------------------------- */
#if NOXTLS_FEATURE_AES_CCM
static void test_ccm_vectors(void)
{
    uint32_t i;
    for (i = 0U; i < CS_ARRAY_LEN(k_ccm); i += 1U) {
        const cs_ccm_case_t *tc = &k_ccm[i];
        uint32_t kl = cs_hex(tc->key, g_key, sizeof(g_key));
        uint32_t nl = cs_hex(tc->nonce, g_nonce, sizeof(g_nonce));
        uint32_t al = cs_hex(tc->aad, g_aad, sizeof(g_aad));
        uint32_t pl = cs_hex(tc->pt, g_pt, CS_BUF);
        uint32_t tl = tc->tag_len;
        (void)kl;
        (void)cs_hex(tc->ct_tag, g_ct, CS_BUF);
        cs_section(tc->name);
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_ccm_encrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_pt, pl, g_out, g_tag, tl),
                 NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("ciphertext", g_out, g_ct, pl);
        (void)EXPECT_MEM("tag", g_tag, &g_ct[pl], tl);
        CHECK(g_out[pl] == 0xEEU);
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_ct, pl, &g_ct[pl], tl, g_out),
                 NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("plaintext", g_out, g_pt, pl);
        /* Tampering. */
        g_ct[pl] ^= 0x01U;
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_ct, pl, &g_ct[pl], tl, g_out),
                 NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_released(g_out, pl, 0xEEU));
        g_ct[pl] ^= 0x01U;
        g_ct[0] ^= 0x01U;
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_ct, pl, &g_ct[pl], tl, g_out),
                 NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_released(g_out, pl, 0xEEU));
        g_ct[0] ^= 0x01U;
        g_aad[al - 1U] ^= 0x01U;
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_ct, pl, &g_ct[pl], tl, g_out),
                 NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_released(g_out, pl, 0xEEU));
        g_aad[al - 1U] ^= 0x01U;
        /* A shorter tag than the one used for encryption must not verify. */
        if (tl > 4U) {
            CHECK(noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, nl, g_aad, al, g_ct, pl, &g_ct[pl], tl - 2U,
                                         g_out) != NOXTLS_RETURN_SUCCESS);
        }
    }
}
#endif

/* ------------------------------------------------------------------------- */
/* ChaCha20 / Poly1305 / ChaCha20-Poly1305                                    */
/* ------------------------------------------------------------------------- */
#if NOXTLS_FEATURE_CHACHA20_POLY1305
static const char k_sunscreen[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

static void test_chacha20(void)
{
    static noxtls_chacha20_context_t ctx;
    uint32_t len = (uint32_t)strlen(k_sunscreen);
    uint32_t start;
    uint8_t zero[32];

    (void)memcpy(g_pt, k_sunscreen, len);
    (void)cs_hex(k_sunscreen_ct_2_4_2, g_ct, CS_BUF);
    (void)cs_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", g_key, sizeof(g_key));
    (void)cs_hex("000000000000004a00000000", g_nonce, sizeof(g_nonce));

    cs_section("RFC 8439 2.4.2 ChaCha20 one-shot");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_encrypt(g_key, g_nonce, 1U, g_pt, len, g_out), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("encrypt", g_out, g_ct, len);
    CHECK(g_out[len] == 0xEEU);
    CHECK_RC(noxtls_chacha20_decrypt(g_key, g_nonce, 1U, g_ct, len, g_out), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("decrypt", g_out, g_pt, len);

    cs_section("RFC 8439 2.4.2 ChaCha20 in place");
    (void)memcpy(g_buf, g_pt, len);
    CHECK_RC(noxtls_chacha20_encrypt(g_key, g_nonce, 1U, g_buf, len, g_buf), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("in-place encrypt", g_buf, g_ct, len);

    for (start = 0U; start < 5U; start += 1U) {
        uint32_t off = 0U;
        uint32_t idx = start;
        cs_section("RFC 8439 2.4.2 ChaCha20 streaming (in place)");
        (void)memcpy(g_buf, g_pt, len);
        CHECK_RC(noxtls_chacha20_init(&ctx, g_key, g_nonce, 1U), NOXTLS_RETURN_SUCCESS);
        while (off < len) {
            uint32_t n = cs_chunk(idx);
            idx += 1U;
            if (n > (len - off)) {
                n = len - off;
            }
            (void)CHECK_RC(noxtls_chacha20_process(&ctx, &g_buf[off], &g_buf[off], n), NOXTLS_RETURN_SUCCESS);
            off += n;
        }
        (void)EXPECT_MEM("streaming", g_buf, g_ct, len);
    }

    /* RFC 8439 2.6.2: Poly1305 one-time key = first 32 bytes of block 0. */
    cs_section("RFC 8439 2.6.2 Poly1305 key generation");
    (void)cs_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", g_key, sizeof(g_key));
    (void)cs_hex("000000000001020304050607", g_nonce, sizeof(g_nonce));
    (void)memset(zero, 0, sizeof(zero));
    CHECK_RC(noxtls_chacha20_encrypt(g_key, g_nonce, 0U, zero, 32U, g_out), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("poly1305 key", g_out, 32U, k_polykey_2_6_2);
}

static void test_poly1305(void)
{
    static noxtls_poly1305_context_t ctx;
    static const char k_msg[] = "Cryptographic Forum Research Group";
    uint32_t len = (uint32_t)strlen(k_msg);
    uint8_t key[32];
    uint32_t i;
    uint32_t j;

    (void)cs_hex(k_poly1305_key_2_5_2, key, sizeof(key));
    cs_section("RFC 8439 2.5.2 Poly1305 one-shot");
    CHECK_RC(noxtls_poly1305_mac(key, (const uint8_t *)k_msg, len, g_tag), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("tag", g_tag, 16U, k_poly1305_tag_2_5_2);
    cs_section("RFC 8439 2.5.2 Poly1305 split points");
    for (i = 0U; i <= len; i += 1U) {
        for (j = i; j <= len; j += 5U) {
            CHECK_RC(noxtls_poly1305_init(&ctx, key), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_poly1305_update(&ctx, (const uint8_t *)k_msg, i), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_poly1305_update(&ctx, NULL, 0U), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_poly1305_update(&ctx, (const uint8_t *)&k_msg[i], j - i), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_poly1305_update(&ctx, (const uint8_t *)&k_msg[j], len - j), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_poly1305_final(&ctx, g_tag), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX("tag", g_tag, 16U, k_poly1305_tag_2_5_2);
        }
    }
}

static void test_chachapoly_vectors(void)
{
    uint32_t len = (uint32_t)strlen(k_sunscreen);
    uint32_t a5_len;
    uint8_t a5_key[32];
    uint8_t a5_nonce[12];
    uint8_t a5_aad[12];
    uint8_t a5_tag[16];

    (void)memcpy(g_pt, k_sunscreen, len);
    (void)cs_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", g_key, sizeof(g_key));
    (void)cs_hex("070000004041424344454647", g_nonce, sizeof(g_nonce));
    (void)cs_hex("50515253c0c1c2c3c4c5c6c7", g_aad, sizeof(g_aad));
    (void)cs_hex(k_aead_ct_2_8_2, g_ct, CS_BUF);
    cs_section("RFC 8439 2.8.2 AEAD encrypt");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_encrypt(g_key, g_nonce, g_aad, 12U, g_pt, len, g_out, g_tag), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("ciphertext", g_out, g_ct, len);
    (void)EXPECT_HEX("tag", g_tag, 16U, k_aead_tag_2_8_2);
    CHECK(g_out[len] == 0xEEU);
    cs_section("RFC 8439 2.8.2 AEAD decrypt");
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, g_aad, 12U, g_ct, len, g_tag, g_out), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("plaintext", g_out, g_pt, len);
    cs_section("RFC 8439 2.8.2 AEAD tampering");
    g_tag[0] ^= 0x01U;
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, g_aad, 12U, g_ct, len, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
    CHECK(no_plaintext_released(g_out, len, 0xEEU));
    g_tag[0] ^= 0x01U;
    g_ct[50] ^= 0x01U;
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, g_aad, 12U, g_ct, len, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
    CHECK(no_plaintext_released(g_out, len, 0xEEU));
    g_ct[50] ^= 0x01U;
    g_aad[11] ^= 0x01U;
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, g_aad, 12U, g_ct, len, g_tag, g_out), NOXTLS_RETURN_BAD_DATA);
    CHECK(no_plaintext_released(g_out, len, 0xEEU));
    g_aad[11] ^= 0x01U;

    cs_section("RFC 8439 A.5 AEAD decryption");
    (void)cs_hex(k_a5_key, a5_key, sizeof(a5_key));
    (void)cs_hex(k_a5_nonce, a5_nonce, sizeof(a5_nonce));
    (void)cs_hex(k_a5_aad, a5_aad, sizeof(a5_aad));
    (void)cs_hex(k_a5_tag, a5_tag, sizeof(a5_tag));
    a5_len = cs_hex(k_a5_ct, g_ct, CS_BUF);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(a5_key, a5_nonce, a5_aad, 12U, g_ct, a5_len, a5_tag, g_out),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("A.5 plaintext", g_out, a5_len, k_a5_pt);
    /* Re-encrypting the plaintext reproduces the vector (in place). */
    (void)memcpy(g_buf, g_out, a5_len);
    CHECK_RC(noxtls_chacha20_poly1305_encrypt(a5_key, a5_nonce, a5_aad, 12U, g_buf, a5_len, g_buf, g_tag),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("A.5 re-encrypt", g_buf, g_ct, a5_len);
    (void)EXPECT_MEM("A.5 tag", g_tag, a5_tag, 16U);

    cs_section("ChaCha20-Poly1305 empty plaintext with NULL pointers");
    CHECK_RC(noxtls_chacha20_poly1305_encrypt(g_key, g_nonce, NULL, 0U, NULL, 0U, NULL, g_tag), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, NULL, 0U, NULL, 0U, g_tag, NULL), NOXTLS_RETURN_SUCCESS);
}
#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */

/* ------------------------------------------------------------------------- */
/* In-place AEAD                                                              */
/* ------------------------------------------------------------------------- */
typedef enum { AEAD_GCM128, AEAD_GCM256, AEAD_CCM128_N13_T16, AEAD_CCM256_N7_T4, AEAD_CHACHAPOLY } cs_aead_t;

static noxtls_return_t aead_encrypt(cs_aead_t alg, const uint8_t *in, uint32_t len, uint8_t *out, uint8_t *tag)
{
    (void)in;
    (void)len;
    (void)out;
    (void)tag;
    switch (alg) {
#if NOXTLS_FEATURE_AES_GCM
    case AEAD_GCM128:
        return noxtls_aes_gcm_encrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, out, tag);
    case AEAD_GCM256:
        return noxtls_aes_gcm_encrypt(g_key, NOXTLS_AES_256_BIT, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, out, tag);
#endif
#if NOXTLS_FEATURE_AES_CCM
    case AEAD_CCM128_N13_T16:
        return noxtls_aes_ccm_encrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, 13U, g_aad, CS_INPLACE_AAD_LEN, in, len, out, tag, 16U);
    case AEAD_CCM256_N7_T4:
        return noxtls_aes_ccm_encrypt(g_key, NOXTLS_AES_256_BIT, g_nonce, 7U, g_aad, CS_INPLACE_AAD_LEN, in, len, out, tag, 4U);
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    case AEAD_CHACHAPOLY:
        return noxtls_chacha20_poly1305_encrypt(g_key, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, out, tag);
#endif
    default:
        break;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static noxtls_return_t aead_decrypt(cs_aead_t alg, const uint8_t *in, uint32_t len, const uint8_t *tag, uint8_t *out)
{
    (void)in;
    (void)len;
    (void)out;
    (void)tag;
    switch (alg) {
#if NOXTLS_FEATURE_AES_GCM
    case AEAD_GCM128:
        return noxtls_aes_gcm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, tag, out);
    case AEAD_GCM256:
        return noxtls_aes_gcm_decrypt(g_key, NOXTLS_AES_256_BIT, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, tag, out);
#endif
#if NOXTLS_FEATURE_AES_CCM
    case AEAD_CCM128_N13_T16:
        return noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_128_BIT, g_nonce, 13U, g_aad, CS_INPLACE_AAD_LEN, in, len, tag, 16U, out);
    case AEAD_CCM256_N7_T4:
        return noxtls_aes_ccm_decrypt(g_key, NOXTLS_AES_256_BIT, g_nonce, 7U, g_aad, CS_INPLACE_AAD_LEN, in, len, tag, 4U, out);
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    case AEAD_CHACHAPOLY:
        return noxtls_chacha20_poly1305_decrypt(g_key, g_nonce, g_aad, CS_INPLACE_AAD_LEN, in, len, tag, out);
#endif
    default:
        break;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static void in_place_suite(const char *name, cs_aead_t alg, uint32_t tag_len, const char *const *tags)
{
    char what[96];
    uint32_t i;

    cs_fill(g_key, 32U, CS_INPLACE_KEY_SEED);
    cs_fill(g_nonce, 13U, CS_INPLACE_NONCE_SEED);
    cs_fill(g_aad, CS_INPLACE_AAD_LEN, CS_INPLACE_AAD_SEED);
    for (i = 0U; i < CS_INPLACE_LEN_COUNT; i += 1U) {
        uint32_t len = k_inplace_lens[i];
        cs_fill(g_pt, len, CS_INPLACE_MSG_SEED);

        (void)snprintf(what, sizeof(what), "%s out-of-place len %u", name, (unsigned)len);
        cs_section(what);
        (void)memset(g_ct, 0xEE, sizeof(g_ct));
        CHECK_RC(aead_encrypt(alg, g_pt, len, g_ct, g_tag), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("tag", g_tag, tag_len, tags[i]);
        CHECK(g_ct[len] == 0xEEU);

        (void)snprintf(what, sizeof(what), "%s in-place encrypt len %u", name, (unsigned)len);
        cs_section(what);
        (void)memcpy(g_buf, g_pt, len);
        (void)memset(g_tag2, 0, sizeof(g_tag2));
        CHECK_RC(aead_encrypt(alg, g_buf, len, g_buf, g_tag2), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("in-place ciphertext", g_buf, g_ct, len);
        (void)EXPECT_MEM("in-place tag", g_tag2, g_tag, tag_len);

        (void)snprintf(what, sizeof(what), "%s in-place decrypt len %u", name, (unsigned)len);
        cs_section(what);
        (void)memcpy(g_buf, g_ct, len);
        CHECK_RC(aead_decrypt(alg, g_buf, len, g_tag, g_buf), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("in-place plaintext", g_buf, g_pt, len);

        (void)snprintf(what, sizeof(what), "%s in-place decrypt bad tag len %u", name, (unsigned)len);
        cs_section(what);
        (void)memcpy(g_buf, g_ct, len);
        g_tag[0] ^= 0x01U;
        CHECK_RC(aead_decrypt(alg, g_buf, len, g_tag, g_buf), NOXTLS_RETURN_BAD_DATA);
        CHECK(no_plaintext_in_place(g_buf, g_ct, len));
        g_tag[0] ^= 0x01U;

        /* Out-of-place decrypt for the same data (reference path). */
        (void)snprintf(what, sizeof(what), "%s out-of-place decrypt len %u", name, (unsigned)len);
        cs_section(what);
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(aead_decrypt(alg, g_ct, len, g_tag, g_out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("plaintext", g_out, g_pt, len);
        CHECK(g_out[len] == 0xEEU);
    }
}

static void test_in_place(void)
{
#if NOXTLS_FEATURE_AES_GCM && NOXTLS_FEATURE_AES_128
    in_place_suite("AES-128-GCM", AEAD_GCM128, 16U, k_inplace_gcm128_tag);
#endif
#if NOXTLS_FEATURE_AES_GCM && NOXTLS_FEATURE_AES_256
    in_place_suite("AES-256-GCM", AEAD_GCM256, 16U, k_inplace_gcm256_tag);
#endif
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_128
    in_place_suite("AES-128-CCM n13 t16", AEAD_CCM128_N13_T16, 16U, k_inplace_ccm_n13_t16_tag);
#endif
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_256
    in_place_suite("AES-256-CCM n7 t4", AEAD_CCM256_N7_T4, 4U, k_inplace_ccm256_n7_t4_tag);
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    in_place_suite("ChaCha20-Poly1305", AEAD_CHACHAPOLY, 16U, k_inplace_chachapoly_tag);
#endif
}

/* ------------------------------------------------------------------------- */
/* TLS 1.2 CBC record decrypted in place                                     */
/* ------------------------------------------------------------------------- */
#if NOXTLS_FEATURE_AES_CBC && NOXTLS_FEATURE_AES_128 && NOXTLS_FEATURE_SHA256
static void tls_record_verify(const char *what, const uint8_t *rec, uint32_t rec_len, const uint8_t *mac_key,
                              const uint8_t *frag)
{
    uint8_t mac_in[13U + CS_TLS_FRAG_LEN];
    uint8_t mac[32];
    uint32_t mac_len = sizeof(mac);
    uint32_t pad = rec[rec_len - 1U];
    uint32_t i;

    cs_section(what);
    if (CHECK((CS_TLS_FRAG_LEN + 32U + pad + 1U) == rec_len) != 0) {
        for (i = rec_len - 1U - pad; i < rec_len; i += 1U) {
            (void)CHECK(rec[i] == pad);
        }
    }
    (void)EXPECT_MEM("fragment", rec, frag, CS_TLS_FRAG_LEN);
    (void)cs_hex("0000000000000007170303", mac_in, sizeof(mac_in));
    mac_in[11] = (uint8_t)(CS_TLS_FRAG_LEN >> 8);
    mac_in[12] = (uint8_t)CS_TLS_FRAG_LEN;
    (void)memcpy(&mac_in[13], rec, CS_TLS_FRAG_LEN);
    CHECK_RC(noxtls_hmac_compute(NOXTLS_HASH_SHA_256, mac_key, 32U, mac_in, sizeof(mac_in), mac, &mac_len),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("record MAC", &rec[CS_TLS_FRAG_LEN], mac, 32U);
}

static void test_tls_cbc_in_place(void)
{
    static noxtls_aes_context_t ctx;
    uint8_t mac_key[32];
    uint8_t enc_key[16];
    uint8_t iv[16];
    uint8_t frag[CS_TLS_FRAG_LEN];
    uint32_t rec_len = cs_hex_len(k_tls_cbc_record);
    uint32_t off;
    uint32_t olen;
    uint32_t total;

    cs_fill(mac_key, 32U, CS_TLS_MAC_KEY_SEED);
    cs_fill(enc_key, 16U, CS_TLS_ENC_KEY_SEED);
    cs_fill(iv, 16U, CS_TLS_IV_SEED);
    cs_fill(frag, CS_TLS_FRAG_LEN, CS_TLS_FRAG_SEED);
    (void)cs_hex(k_tls_cbc_record, g_ct, CS_BUF);

    /* Out-of-place reference decrypt. */
    cs_section("TLS CBC record out-of-place decrypt");
    CHECK_RC(noxtls_aes_decrypt_cbc(enc_key, g_ct, rec_len, iv, g_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    tls_record_verify("TLS CBC record out-of-place verify", g_out, rec_len, mac_key, frag);

    /* One-shot decrypt in place. */
    cs_section("TLS CBC record in-place one-shot decrypt");
    (void)memcpy(g_buf, g_ct, rec_len);
    CHECK_RC(noxtls_aes_decrypt_cbc(enc_key, g_buf, rec_len, iv, g_buf, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    tls_record_verify("TLS CBC record in-place one-shot verify", g_buf, rec_len, mac_key, frag);

    /* Streaming decrypt in place: whole record in one update, then 16-byte updates. */
    cs_section("TLS CBC record in-place streaming decrypt (one update)");
    (void)memcpy(g_buf, g_ct, rec_len);
    CHECK_RC(noxtls_aes_init(&ctx, enc_key, iv, NOXTLS_AES_128_BIT, NOXTLS_AES_CBC, NOXTLS_AES_OP_DECRYPT),
             NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_aes_update(&ctx, g_buf, rec_len, g_buf, &olen), NOXTLS_RETURN_SUCCESS);
    total = olen;
    CHECK_RC(noxtls_aes_final(&ctx, &g_buf[total], &olen), NOXTLS_RETURN_SUCCESS);
    total += olen;
    CHECK(total == rec_len);
    tls_record_verify("TLS CBC record in-place streaming verify (one update)", g_buf, rec_len, mac_key, frag);

    cs_section("TLS CBC record in-place streaming decrypt (16-byte updates)");
    (void)memcpy(g_buf, g_ct, rec_len);
    CHECK_RC(noxtls_aes_init(&ctx, enc_key, iv, NOXTLS_AES_128_BIT, NOXTLS_AES_CBC, NOXTLS_AES_OP_DECRYPT),
             NOXTLS_RETURN_SUCCESS);
    total = 0U;
    for (off = 0U; off < rec_len; off += 16U) {
        CHECK_RC(noxtls_aes_update(&ctx, &g_buf[off], 16U, &g_buf[total], &olen), NOXTLS_RETURN_SUCCESS);
        total += olen;
    }
    CHECK_RC(noxtls_aes_final(&ctx, &g_buf[total], &olen), NOXTLS_RETURN_SUCCESS);
    total += olen;
    CHECK(total == rec_len);
    tls_record_verify("TLS CBC record in-place streaming verify (16-byte updates)", g_buf, rec_len, mac_key, frag);

    /* Encrypt side reproduces the record (in place). */
    cs_section("TLS CBC record in-place encrypt");
    (void)memcpy(g_buf, g_out, rec_len);
    CHECK_RC(noxtls_aes_encrypt_cbc(enc_key, g_buf, rec_len, iv, g_buf, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("record", g_buf, g_ct, rec_len);
}
#endif

typedef struct {
    uint32_t part;
    void (*fn)(void);
} cs_test_entry_t;

/* CRYPTO_SYM_PART 0: crypto_sym_aead_test, 1: crypto_sym_tls_cbc_inplace_test. */
static const cs_test_entry_t k_tests[] = {
#if NOXTLS_FEATURE_AES_GCM
    { 0U, test_gcm },
#endif
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_128
    { 0U, test_ccm_vectors },
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    { 0U, test_chacha20 },
    { 0U, test_poly1305 },
    { 0U, test_chachapoly_vectors },
#endif
    { 0U, test_in_place },
#if NOXTLS_FEATURE_AES_CBC && NOXTLS_FEATURE_AES_128 && NOXTLS_FEATURE_SHA256
    { 1U, test_tls_cbc_in_place },
#endif
};

int main(void)
{
    uint32_t i;
    for (i = 0U; i < CS_ARRAY_LEN(k_tests); i += 1U) {
        if (k_tests[i].part == (uint32_t)CRYPTO_SYM_PART) {
            k_tests[i].fn();
        }
    }
    return cs_finish((CRYPTO_SYM_PART == 0) ? "crypto_sym_aead_test" : "crypto_sym_tls_cbc_inplace_test");
}
