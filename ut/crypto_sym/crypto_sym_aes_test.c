/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_aes_test.c
* Summary: AES block-mode regression tests (public API only).
*
*  - NIST SP 800-38A F.1-F.5 (ECB, CBC, CFB128, OFB, CTR) for AES-128/192/256
*    through the one-shot APIs (noxtls_aes_encrypt_<mode>, noxtls_aes_decrypt_
*    <mode> where it exists, noxtls_aes_encrypt_data) and the streaming API
*    (noxtls_aes_init/update/final) with irregular chunk sizes, both ways;
*  - AES-256 over ~1 KiB pseudo-random data (CTR counter carrying across the
*    64-bit boundary), compared with Python `cryptography`;
*  - IN-PLACE (output pointer == input pointer): one-shot encrypt/decrypt for
*    ECB/CBC/CTR/CFB/OFB and streaming encrypt/decrypt (16-byte multiple chunks
*    for ECB/CBC, where the API may emit more bytes than it consumed in one call
*    when data is buffered, so only aligned chunking can alias; any chunking for
*    the stream modes), compared with the out-of-place result;
*  - RFC 3394 key wrap/unwrap 4.1-4.6, unwrap integrity failure (output must be
*    cleared, as the header promises);
*  - XTS-AES: IEEE 1619-2007 vectors 1 and 2, ciphertext stealing lengths
*    17/31/47 and 512 bytes for XTS-AES-128/256, in-place (documented as allowed);
*  - AES-CMAC: SP 800-38B D.1-D.3 (AES-128/192/256, lengths 0/16/40/64) one-shot
*    and streaming with every 2-way and many 3-way split points, plus all lengths
*    0..80 for AES-256 (extends ut/cmac_rfc4493_test.c, which covers AES-128).
* Built twice: CRYPTO_SYM_PART=0 -> crypto_sym_aes_test (everything except
*   in-place), CRYPTO_SYM_PART=1 -> crypto_sym_aes_inplace_test (in-place only).
* Expected values: crypto_sym_aes_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "encryption/aes/noxtls_aes.h"
#if NOXTLS_FEATURE_AES_ECB
#include "encryption/aes/noxtls_aes_keywrap.h"
#endif
#if NOXTLS_FEATURE_AES_CMAC
#include "encryption/aes/noxtls_aes_cmac.h"
#endif

#include "crypto_sym_test_util.h"
#include "crypto_sym_aes_vectors.h"

#ifndef CRYPTO_SYM_PART
#define CRYPTO_SYM_PART 0
#endif

#define CS_ARRAY_LEN(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))
#define CS_BUF (2048U)

typedef noxtls_return_t (*cs_aes_fn_t)(const uint8_t *key, const uint8_t *data, uint32_t data_len,
                                       const uint8_t *iv, uint8_t *output, noxtls_aes_type_t type);

typedef struct {
    const char *name;
    noxtls_aes_mode_t mode;
    cs_aes_fn_t enc;
    cs_aes_fn_t dec;         /* NULL: no one-shot decrypt in the API (CFB) */
    int block_mode;          /* 1: ECB/CBC (whole blocks), 0: stream mode */
    const char *iv_hex;      /* SP 800-38A IV / initial counter */
    const char *sp38a_ct[3]; /* AES-128/192/256 ciphertexts of k_sp38a_pt */
    const char *long_head;
    const char *long_tail;
} cs_mode_t;

static const cs_mode_t k_modes[] = {
#if NOXTLS_FEATURE_AES_ECB
    { "ECB", NOXTLS_AES_ECB, noxtls_aes_encrypt_ecb, noxtls_aes_decrypt_ecb, 1, NULL,
      { k_sp38a_ecb128, k_sp38a_ecb192, k_sp38a_ecb256 }, k_long_ecb_head, k_long_ecb_tail },
#endif
#if NOXTLS_FEATURE_AES_CBC
    { "CBC", NOXTLS_AES_CBC, noxtls_aes_encrypt_cbc, noxtls_aes_decrypt_cbc, 1, k_sp38a_iv,
      { k_sp38a_cbc128, k_sp38a_cbc192, k_sp38a_cbc256 }, k_long_cbc_head, k_long_cbc_tail },
#endif
#if NOXTLS_FEATURE_AES_CFB
    { "CFB128", NOXTLS_AES_CFB, noxtls_aes_encrypt_cfb, NULL, 0, k_sp38a_iv,
      { k_sp38a_cfb128, k_sp38a_cfb192, k_sp38a_cfb256 }, k_long_cfb_head, k_long_cfb_tail },
#endif
#if NOXTLS_FEATURE_AES_OFB
    { "OFB", NOXTLS_AES_OFB, noxtls_aes_encrypt_ofb, noxtls_aes_encrypt_ofb, 0, k_sp38a_iv,
      { k_sp38a_ofb128, k_sp38a_ofb192, k_sp38a_ofb256 }, k_long_ofb_head, k_long_ofb_tail },
#endif
#if NOXTLS_FEATURE_AES_CTR
    { "CTR", NOXTLS_AES_CTR, noxtls_aes_encrypt_ctr, noxtls_aes_encrypt_ctr, 0, k_sp38a_ctr,
      { k_sp38a_ctr128, k_sp38a_ctr192, k_sp38a_ctr256 }, k_long_ctr_head, k_long_ctr_tail },
#endif
};

typedef struct {
    const char *name;
    noxtls_aes_type_t type;
    uint32_t idx;
    const char *key_hex;
} cs_keysize_t;

static const cs_keysize_t k_keysizes[] = {
#if NOXTLS_FEATURE_AES_128
    { "AES-128", NOXTLS_AES_128_BIT, 0U, k_sp38a_key128 },
#endif
#if NOXTLS_FEATURE_AES_192
    { "AES-192", NOXTLS_AES_192_BIT, 1U, k_sp38a_key192 },
#endif
#if NOXTLS_FEATURE_AES_256
    { "AES-256", NOXTLS_AES_256_BIT, 2U, k_sp38a_key256 },
#endif
};

static uint8_t g_pt[CS_BUF];
static uint8_t g_ct[CS_BUF];
static uint8_t g_out[CS_BUF];
static uint8_t g_buf[CS_BUF];

/*
 * Streaming AES over in[0..len) into out. aligned != 0: chunks are 16-byte
 * multiples (needed when out == in for ECB/CBC). Returns the total number of
 * bytes produced by update + final, or 0xFFFFFFFF on any API error.
 */
static uint32_t aes_stream(const uint8_t *key, const uint8_t *iv, noxtls_aes_type_t type, noxtls_aes_mode_t mode,
                           noxtls_aes_operation_t op, const uint8_t *in, uint8_t *out, uint32_t len, int aligned,
                           uint32_t chunk_start)
{
    static noxtls_aes_context_t ctx;
    uint32_t off = 0U;
    uint32_t produced = 0U;
    uint32_t idx = chunk_start;
    uint32_t olen = 0U;

    if (noxtls_aes_init(&ctx, key, iv, type, mode, op) != NOXTLS_RETURN_SUCCESS) {
        return 0xFFFFFFFFU;
    }
    while (off < len) {
        uint32_t n = cs_chunk(idx);
        idx += 1U;
        if (aligned != 0) {
            n = 16U * ((n % 5U) + 1U);
        }
        if (n > (len - off)) {
            n = len - off;
        }
        if (noxtls_aes_update(&ctx, &in[off], n, &out[produced], &olen) != NOXTLS_RETURN_SUCCESS) {
            return 0xFFFFFFFFU;
        }
        off += n;
        produced += olen;
        if (produced > off) {
            return 0xFFFFFFFFU; /* never more output than input for whole-block data */
        }
    }
    if (noxtls_aes_final(&ctx, &out[produced], &olen) != NOXTLS_RETURN_SUCCESS) {
        return 0xFFFFFFFFU;
    }
    return produced + olen;
}

static void test_sp800_38a(void)
{
    uint8_t key[32];
    uint8_t iv[16];
    char what[96];
    uint32_t m;
    uint32_t k;
    uint32_t start;

    (void)cs_hex(k_sp38a_pt, g_pt, CS_BUF);
    for (m = 0U; m < CS_ARRAY_LEN(k_modes); m += 1U) {
        const cs_mode_t *md = &k_modes[m];
        const uint8_t *ivp = NULL;
        if (md->iv_hex != NULL) {
            (void)cs_hex(md->iv_hex, iv, sizeof(iv));
            ivp = iv;
        }
        for (k = 0U; k < CS_ARRAY_LEN(k_keysizes); k += 1U) {
            const cs_keysize_t *ks = &k_keysizes[k];
            const char *ct_hex = md->sp38a_ct[ks->idx];
            (void)cs_hex(ks->key_hex, key, sizeof(key));
            (void)cs_hex(ct_hex, g_ct, CS_BUF);

            (void)snprintf(what, sizeof(what), "SP 800-38A %s-%s one-shot encrypt", ks->name, md->name);
            cs_section(what);
            (void)memset(g_out, 0xEE, sizeof(g_out));
            CHECK_RC(md->enc(key, g_pt, 64U, ivp, g_out, ks->type), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX(what, g_out, 64U, ct_hex);
            CHECK(g_out[64] == 0xEEU);

            (void)snprintf(what, sizeof(what), "SP 800-38A %s-%s encrypt_data", ks->name, md->name);
            cs_section(what);
            (void)memset(g_out, 0xEE, sizeof(g_out));
            CHECK_RC(noxtls_aes_encrypt_data(key, g_pt, 64U, ivp, g_out, ks->type, md->mode), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX(what, g_out, 64U, ct_hex);

            if (md->dec != NULL) {
                (void)snprintf(what, sizeof(what), "SP 800-38A %s-%s one-shot decrypt", ks->name, md->name);
                cs_section(what);
                (void)memset(g_out, 0xEE, sizeof(g_out));
                CHECK_RC(md->dec(key, g_ct, 64U, ivp, g_out, ks->type), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM(what, g_out, g_pt, 64U);
            }
            for (start = 0U; start < 6U; start += 1U) {
                (void)snprintf(what, sizeof(what), "SP 800-38A %s-%s streaming encrypt (schedule %u)", ks->name, md->name,
                               (unsigned)start);
                cs_section(what);
                (void)memset(g_out, 0xEE, sizeof(g_out));
                CHECK(aes_stream(key, ivp, ks->type, md->mode, NOXTLS_AES_OP_ENCRYPT, g_pt, g_out, 64U, 0, start) == 64U);
                (void)EXPECT_HEX(what, g_out, 64U, ct_hex);
                (void)snprintf(what, sizeof(what), "SP 800-38A %s-%s streaming decrypt (schedule %u)", ks->name, md->name,
                               (unsigned)start);
                cs_section(what);
                (void)memset(g_out, 0xEE, sizeof(g_out));
                CHECK(aes_stream(key, ivp, ks->type, md->mode, NOXTLS_AES_OP_DECRYPT, g_ct, g_out, 64U, 0, start) == 64U);
                (void)EXPECT_MEM(what, g_out, g_pt, 64U);
            }
        }
    }
}

#if NOXTLS_FEATURE_AES_256
static void long_key_iv(uint8_t key[32], uint8_t iv[16], const cs_mode_t *md)
{
    cs_fill(key, 32U, CS_AES_LONG_KEY_SEED);
    if (md->mode == NOXTLS_AES_CTR) {
        (void)cs_hex(k_ctr_carry_iv, iv, 16U);
    } else {
        cs_fill(iv, 16U, CS_AES_LONG_IV_SEED);
    }
}

static void test_long_messages(void)
{
    uint8_t key[32];
    uint8_t iv[16];
    char what[96];
    uint32_t m;

    for (m = 0U; m < CS_ARRAY_LEN(k_modes); m += 1U) {
        const cs_mode_t *md = &k_modes[m];
        uint32_t len = (md->block_mode != 0) ? 1008U : 1003U;
        const uint8_t *ivp = (md->mode == NOXTLS_AES_ECB) ? NULL : iv;
        long_key_iv(key, iv, md);
        cs_fill(g_pt, len, CS_AES_LONG_MSG_SEED);

        (void)snprintf(what, sizeof(what), "AES-256-%s %u bytes one-shot", md->name, (unsigned)len);
        cs_section(what);
        CHECK_RC(md->enc(key, g_pt, len, ivp, g_ct, NOXTLS_AES_256_BIT), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("head", g_ct, 48U, md->long_head);
        (void)EXPECT_HEX("tail", &g_ct[len - 48U], 48U, md->long_tail);
        if (md->dec != NULL) {
            CHECK_RC(md->dec(key, g_ct, len, ivp, g_out, NOXTLS_AES_256_BIT), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_MEM("decrypt", g_out, g_pt, len);
        }
        (void)snprintf(what, sizeof(what), "AES-256-%s %u bytes streaming", md->name, (unsigned)len);
        cs_section(what);
        CHECK(aes_stream(key, ivp, NOXTLS_AES_256_BIT, md->mode, NOXTLS_AES_OP_ENCRYPT, g_pt, g_out, len, 0, 3U) == len);
        (void)EXPECT_MEM("streaming encrypt", g_out, g_ct, len);
        CHECK(aes_stream(key, ivp, NOXTLS_AES_256_BIT, md->mode, NOXTLS_AES_OP_DECRYPT, g_ct, g_out, len, 0, 7U) == len);
        (void)EXPECT_MEM("streaming decrypt", g_out, g_pt, len);
    }
}

/* Output pointer == input pointer, compared with the out-of-place result. */
static void test_in_place(void)
{
    static const uint32_t k_block_lens[] = { 16U, 64U, 1008U };
    static const uint32_t k_stream_lens[] = { 1U, 15U, 17U, 64U, 100U, 1003U };
    uint8_t key[32];
    uint8_t iv[16];
    char what[112];
    uint32_t m;
    uint32_t i;

    for (m = 0U; m < CS_ARRAY_LEN(k_modes); m += 1U) {
        const cs_mode_t *md = &k_modes[m];
        const uint32_t *lens = (md->block_mode != 0) ? k_block_lens : k_stream_lens;
        uint32_t nlens = (md->block_mode != 0) ? CS_ARRAY_LEN(k_block_lens) : CS_ARRAY_LEN(k_stream_lens);
        const uint8_t *ivp = (md->mode == NOXTLS_AES_ECB) ? NULL : iv;
        long_key_iv(key, iv, md);
        for (i = 0U; i < nlens; i += 1U) {
            uint32_t len = lens[i];
            cs_fill(g_pt, len, CS_AES_LONG_MSG_SEED + len);
            (void)md->enc(key, g_pt, len, ivp, g_ct, NOXTLS_AES_256_BIT); /* out-of-place reference */

            (void)snprintf(what, sizeof(what), "in-place one-shot %s encrypt len %u", md->name, (unsigned)len);
            cs_section(what);
            (void)memcpy(g_buf, g_pt, len);
            CHECK_RC(md->enc(key, g_buf, len, ivp, g_buf, NOXTLS_AES_256_BIT), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_MEM(what, g_buf, g_ct, len);

            if (md->dec != NULL) {
                (void)snprintf(what, sizeof(what), "in-place one-shot %s decrypt len %u", md->name, (unsigned)len);
                cs_section(what);
                (void)memcpy(g_buf, g_ct, len);
                CHECK_RC(md->dec(key, g_buf, len, ivp, g_buf, NOXTLS_AES_256_BIT), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM(what, g_buf, g_pt, len);
            }

            (void)snprintf(what, sizeof(what), "in-place streaming %s encrypt len %u", md->name, (unsigned)len);
            cs_section(what);
            (void)memcpy(g_buf, g_pt, len);
            CHECK(aes_stream(key, ivp, NOXTLS_AES_256_BIT, md->mode, NOXTLS_AES_OP_ENCRYPT, g_buf, g_buf, len,
                             md->block_mode, 1U) == len);
            (void)EXPECT_MEM(what, g_buf, g_ct, len);

            (void)snprintf(what, sizeof(what), "in-place streaming %s decrypt len %u", md->name, (unsigned)len);
            cs_section(what);
            (void)memcpy(g_buf, g_ct, len);
            CHECK(aes_stream(key, ivp, NOXTLS_AES_256_BIT, md->mode, NOXTLS_AES_OP_DECRYPT, g_buf, g_buf, len,
                             md->block_mode, 2U) == len);
            (void)EXPECT_MEM(what, g_buf, g_pt, len);
        }
    }
}
#endif /* NOXTLS_FEATURE_AES_256 */

#if NOXTLS_FEATURE_AES_ECB
static void test_keywrap(void)
{
    static const noxtls_aes_type_t k_types[3] = { NOXTLS_AES_128_BIT, NOXTLS_AES_192_BIT, NOXTLS_AES_256_BIT };
    uint8_t kek[32];
    uint8_t plain[40];
    uint8_t wrapped[48];
    uint8_t out[48];
    char what[64];
    uint32_t i;

    for (i = 0U; i < CS_ARRAY_LEN(k_rfc3394); i += 1U) {
        const cs_kw_case_t *tc = &k_rfc3394[i];
        uint32_t kl = cs_hex(tc->kek, kek, sizeof(kek));
        uint32_t pl = cs_hex(tc->plain, plain, sizeof(plain));
        uint32_t wl = cs_hex(tc->wrapped, wrapped, sizeof(wrapped));
        noxtls_aes_type_t t = k_types[(kl / 8U) - 2U];
        if (((t == NOXTLS_AES_128_BIT) && (NOXTLS_FEATURE_AES_128 == 0)) ||
            ((t == NOXTLS_AES_192_BIT) && (NOXTLS_FEATURE_AES_192 == 0)) ||
            ((t == NOXTLS_AES_256_BIT) && (NOXTLS_FEATURE_AES_256 == 0))) {
            continue;
        }
        (void)snprintf(what, sizeof(what), "RFC 3394 4.%u (KEK %u, data %u)", (unsigned)(i + 1U), (unsigned)(kl * 8U),
                       (unsigned)(pl * 8U));
        cs_section(what);
        (void)memset(out, 0xEE, sizeof(out));
        CHECK_RC(noxtls_aes_key_wrap(kek, t, plain, pl, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("wrap", out, wrapped, wl);
        CHECK(cs_all_byte(&out[wl], sizeof(out) - wl, 0xEEU));
        (void)memset(out, 0xEE, sizeof(out));
        CHECK_RC(noxtls_aes_key_unwrap(kek, t, wrapped, wl, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("unwrap", out, plain, pl);
        /* Integrity failure: rejected and (header promise) output cleared. */
        wrapped[wl - 1U] ^= 0x01U;
        (void)memset(out, 0xEE, sizeof(out));
        CHECK_RC(noxtls_aes_key_unwrap(kek, t, wrapped, wl, out), NOXTLS_RETURN_FAILED);
        CHECK(cs_all_zero(out, pl));
        wrapped[wl - 1U] ^= 0x01U;
        wrapped[3] ^= 0x80U; /* corrupt the integrity check value */
        CHECK_RC(noxtls_aes_key_unwrap(kek, t, wrapped, wl, out), NOXTLS_RETURN_FAILED);
        CHECK(cs_all_zero(out, pl));
    }
    cs_section("RFC 3394 invalid lengths");
    CHECK_RC(noxtls_aes_key_wrap(kek, NOXTLS_AES_128_BIT, plain, 8U, out), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(noxtls_aes_key_wrap(kek, NOXTLS_AES_128_BIT, plain, 20U, out), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(noxtls_aes_key_unwrap(kek, NOXTLS_AES_128_BIT, wrapped, 16U, out), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(noxtls_aes_keywrap_self_test(), NOXTLS_RETURN_SUCCESS);
}
#endif

#if NOXTLS_FEATURE_AES_XTS
static void xts_case(const char *what, const uint8_t *k1, const uint8_t *k2, const uint8_t *tweak,
                     noxtls_aes_type_t type, const uint8_t *pt, uint32_t len, const char *ct_hex)
{
    cs_section(what);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(noxtls_aes_xts_encrypt(k1, k2, pt, len, tweak, g_out, type), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("XTS encrypt", g_out, len, ct_hex);
    CHECK(g_out[len] == 0xEEU);
    (void)cs_hex(ct_hex, g_ct, CS_BUF);
    CHECK_RC(noxtls_aes_xts_decrypt(k1, k2, g_ct, len, tweak, g_out, type), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("XTS decrypt", g_out, pt, len);
    /* In place (documented as allowed). */
    (void)memcpy(g_buf, pt, len);
    CHECK_RC(noxtls_aes_xts_encrypt(k1, k2, g_buf, len, tweak, g_buf, type), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("XTS in-place encrypt", g_buf, g_ct, len);
    CHECK_RC(noxtls_aes_xts_decrypt(k1, k2, g_buf, len, tweak, g_buf, type), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_MEM("XTS in-place decrypt", g_buf, pt, len);
}

static void test_xts(void)
{
    static const uint32_t k_lens[] = { 16U, 17U, 31U, 32U, 47U, 512U };
    static const char *const k_ct128[] = { k_xts128_len16, k_xts128_len17, k_xts128_len31, k_xts128_len32,
                                           k_xts128_len47, k_xts128_len512 };
    static const char *const k_ct256[] = { k_xts256_len16, k_xts256_len17, k_xts256_len31, k_xts256_len32,
                                           k_xts256_len47, k_xts256_len512 };
    uint8_t k1[32];
    uint8_t k2[32];
    uint8_t tweak[16];
    uint8_t pt[512];
    char what[64];
    uint32_t i;

#if NOXTLS_FEATURE_AES_128
    /* IEEE 1619-2007 vector 1: K1 = K2 = 0, tweak 0, 32 zero bytes. */
    (void)memset(k1, 0, sizeof(k1));
    (void)memset(tweak, 0, sizeof(tweak));
    (void)memset(pt, 0, 32U);
    xts_case("IEEE 1619 vector 1", k1, k1, tweak, NOXTLS_AES_128_BIT, pt, 32U, k_xts_v1_ct);
    cs_section("IEEE 1619 vector 1 single-key API");
    CHECK_RC(noxtls_aes_encrypt_xts(k1, pt, 32U, tweak, g_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("noxtls_aes_encrypt_xts", g_out, 32U, k_xts_v1_ct);
    (void)cs_hex(k_xts_v1_ct, g_ct, CS_BUF);
    CHECK_RC(noxtls_aes_decrypt_xts(k1, g_ct, 32U, tweak, g_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(g_out, 32U));
    /* Vector 2: K1 = 11.., K2 = 22.., data unit 0x3333333333, 32 x 0x44. */
    (void)memset(k1, 0x11, 16U);
    (void)memset(k2, 0x22, 16U);
    (void)memset(tweak, 0, sizeof(tweak));
    (void)memset(tweak, 0x33, 5U);
    (void)memset(pt, 0x44, 32U);
    xts_case("IEEE 1619 vector 2", k1, k2, tweak, NOXTLS_AES_128_BIT, pt, 32U, k_xts_v2_ct);
#endif
    cs_fill(k1, 32U, CS_XTS_K1_SEED);
    cs_fill(k2, 32U, CS_XTS_K2_SEED);
    cs_fill(tweak, 16U, CS_XTS_TWEAK_SEED);
    for (i = 0U; i < CS_ARRAY_LEN(k_lens); i += 1U) {
        cs_fill(pt, k_lens[i], CS_XTS_MSG_SEED);
#if NOXTLS_FEATURE_AES_128
        (void)snprintf(what, sizeof(what), "XTS-AES-128 len %u", (unsigned)k_lens[i]);
        xts_case(what, k1, k2, tweak, NOXTLS_AES_128_BIT, pt, k_lens[i], k_ct128[i]);
#endif
#if NOXTLS_FEATURE_AES_256
        (void)snprintf(what, sizeof(what), "XTS-AES-256 len %u", (unsigned)k_lens[i]);
        xts_case(what, k1, k2, tweak, NOXTLS_AES_256_BIT, pt, k_lens[i], k_ct256[i]);
#endif
    }
    (void)k_ct128;
    (void)k_ct256;
    (void)what;
    cs_section("XTS short data unit");
    CHECK_RC(noxtls_aes_xts_encrypt(k1, k2, pt, 15U, tweak, g_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
}
#endif

#if NOXTLS_FEATURE_AES_CMAC
static void cmac_check_all_splits(const uint8_t *key, noxtls_aes_type_t type, const uint8_t *msg, uint32_t len,
                                  const char *mac_hex, int three_way)
{
    static noxtls_aes_cmac_context_t ctx;
    uint8_t mac[16];
    uint32_t i;
    uint32_t j;

    for (i = 0U; i <= len; i += 1U) {
        CHECK_RC(noxtls_aes_cmac_init(&ctx, key, type), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_cmac_update(&ctx, msg, i), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_cmac_update(&ctx, &msg[i], len - i), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_cmac_final(&ctx, mac), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("CMAC 2-way split", mac, 16U, mac_hex);
        if (three_way == 0) {
            continue;
        }
        for (j = i; j <= len; j += 7U) {
            CHECK_RC(noxtls_aes_cmac_init(&ctx, key, type), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_aes_cmac_update(&ctx, msg, i), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_aes_cmac_update(&ctx, &msg[i], j - i), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_aes_cmac_update(&ctx, &msg[j], len - j), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_aes_cmac_final(&ctx, mac), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX("CMAC 3-way split", mac, 16U, mac_hex);
        }
    }
}

static void test_cmac(void)
{
    static const uint32_t k_lens[4] = { 0U, 16U, 40U, 64U };
    static const char *const *const k_tables[3] = { k_cmac128_sp38b, k_cmac192_sp38b, k_cmac256_sp38b };
    uint8_t key[32];
    uint8_t msg[80];
    uint8_t mac[16];
    char what[64];
    uint32_t k;
    uint32_t i;

    (void)cs_hex(k_sp38a_pt, msg, sizeof(msg));
    for (k = 0U; k < CS_ARRAY_LEN(k_keysizes); k += 1U) {
        const cs_keysize_t *ks = &k_keysizes[k];
        (void)cs_hex(ks->key_hex, key, sizeof(key));
        for (i = 0U; i < 4U; i += 1U) {
            const char *mac_hex = k_tables[ks->idx][i];
            (void)snprintf(what, sizeof(what), "SP 800-38B %s-CMAC len %u", ks->name, (unsigned)k_lens[i]);
            cs_section(what);
            CHECK_RC(noxtls_aes_cmac(key, msg, k_lens[i], mac, ks->type), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX("one-shot", mac, 16U, mac_hex);
            cmac_check_all_splits(key, ks->type, msg, k_lens[i], mac_hex, 1);
        }
    }
#if NOXTLS_FEATURE_AES_256
    (void)cs_hex(k_sp38a_key256, key, sizeof(key));
    cs_fill(msg, 80U, CS_CMAC_MSG_SEED);
    for (i = 0U; i <= 80U; i += 1U) {
        (void)snprintf(what, sizeof(what), "AES-256-CMAC PRNG len %u", (unsigned)i);
        cs_section(what);
        CHECK_RC(noxtls_aes_cmac(key, msg, i, mac, NOXTLS_AES_256_BIT), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("one-shot", mac, 16U, k_cmac256_prng[i]);
        cmac_check_all_splits(key, NOXTLS_AES_256_BIT, msg, i, k_cmac256_prng[i], 0);
    }
#endif
}
#endif

typedef struct {
    uint32_t part;
    void (*fn)(void);
} cs_test_entry_t;

/* CRYPTO_SYM_PART 0: crypto_sym_aes_test, 1: crypto_sym_aes_inplace_test. */
static const cs_test_entry_t k_tests[] = {
    { 0U, test_sp800_38a },
#if NOXTLS_FEATURE_AES_256
    { 0U, test_long_messages },
    { 1U, test_in_place },
#endif
#if NOXTLS_FEATURE_AES_ECB
    { 0U, test_keywrap },
#endif
#if NOXTLS_FEATURE_AES_XTS
    { 0U, test_xts },
#endif
#if NOXTLS_FEATURE_AES_CMAC
    { 0U, test_cmac },
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
    return cs_finish((CRYPTO_SYM_PART == 0) ? "crypto_sym_aes_test" : "crypto_sym_aes_inplace_test");
}
