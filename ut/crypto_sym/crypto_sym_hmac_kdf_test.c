/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_hmac_kdf_test.c
* Summary: HMAC, HKDF and PBKDF2 regression tests (public API only).
*
*  - RFC 4231 test cases 1-7 (case 5 truncated to 128 bits) for HMAC-SHA-224/
*    256/384/512 and RFC 2202 HMAC-SHA-1 / HMAC-MD5, via noxtls_hmac_compute
*    and via init / update (irregular chunks) / final / free.
*    Digests that noxtls_hmac does not offer (SHA-224 and MD5 at the base
*    commit) are reported as "SKIP" when the API rejects them; if the API
*    accepts them the MAC must be correct.
*  - one noxtls_hmac_context_t reused for many keys/messages/algorithms, with
*    and without noxtls_hmac_free between uses, keys of 0..200 bytes
*    (shorter than, equal to and longer than the block size);
*  - RFC 5869 HKDF test cases 1-7 (SHA-256 and SHA-1), long expand up to
*    255 * HashLen with a 1000-byte info, odd OKM lengths, the 255-block limit;
*  - PBKDF2 (only when NOXTLS_FEATURE_PBKDF2): RFC 6070 SHA-1 vectors (without
*    the 16777216-iteration one), SHA-256/384/512 values, the self test.
* Expected values: crypto_sym_hmac_kdf_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#if NOXTLS_FEATURE_PBKDF2
#include "kdf/noxtls_pbkdf.h"
#endif

#include "crypto_sym_test_util.h"
#include "crypto_sym_hmac_kdf_vectors.h"

#define CS_ARRAY_LEN(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

static uint8_t g_key[256];
static uint8_t g_msg[4096];
static uint8_t g_mac[128];
static uint32_t g_skips;

/* Streaming HMAC with the cs_chunk() schedule; returns the final() status. */
static noxtls_return_t hmac_stream(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t alg,
                                   const uint8_t *key, uint32_t klen,
                                   const uint8_t *msg, uint32_t mlen, uint32_t chunk_start,
                                   uint8_t *mac, uint32_t *mac_len)
{
    uint32_t off = 0U;
    uint32_t idx = chunk_start;
    noxtls_return_t rc = noxtls_hmac_init(ctx, alg, key, klen);

    while ((rc == NOXTLS_RETURN_SUCCESS) && (off < mlen)) {
        uint32_t n = cs_chunk(idx);
        idx += 1U;
        if (n > (mlen - off)) {
            n = mlen - off;
        }
        rc = noxtls_hmac_update(ctx, &msg[off], n);
        off += n;
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_final(ctx, mac, mac_len);
    }
    return rc;
}

/* Check one (algorithm, key, data) -> expected MAC both one-shot and streaming. */
static void hmac_case(const char *what, noxtls_hash_algos_t alg, uint32_t dlen, int supported_required,
                      const char *key_hex, const char *data_hex, uint32_t trunc, const char *mac_hex)
{
    static noxtls_hmac_context_t ctx;
    uint32_t klen = cs_hex(key_hex, g_key, (uint32_t)sizeof(g_key));
    uint32_t mlen = cs_hex(data_hex, g_msg, (uint32_t)sizeof(g_msg));
    uint32_t cmp = (trunc != 0U) ? trunc : dlen;
    uint32_t mac_len = (uint32_t)sizeof(g_mac);
    noxtls_return_t rc;

    cs_section(what);
    (void)memset(g_mac, 0xEE, sizeof(g_mac));
    rc = noxtls_hmac_compute(alg, g_key, klen, g_msg, mlen, g_mac, &mac_len);
    if ((rc != NOXTLS_RETURN_SUCCESS) && (supported_required == 0)) {
        if (g_skips < 100U) {
            (void)printf("SKIP %s: noxtls_hmac_compute rejects this digest (rc %u)\n", what, (unsigned)rc);
        }
        g_skips += 1U;
        return;
    }
    if (CHECK_RC(rc, NOXTLS_RETURN_SUCCESS) != 0) {
        CHECK(mac_len == dlen);
        (void)EXPECT_HEX(what, g_mac, cmp, mac_hex);
        CHECK(cs_all_byte(&g_mac[dlen], sizeof(g_mac) - dlen, 0xEEU));
    }

    (void)memset(g_mac, 0xEE, sizeof(g_mac));
    mac_len = (uint32_t)sizeof(g_mac);
    if (CHECK_RC(hmac_stream(&ctx, alg, g_key, klen, g_msg, mlen, 0U, g_mac, &mac_len), NOXTLS_RETURN_SUCCESS) != 0) {
        CHECK(mac_len == dlen);
        (void)EXPECT_HEX(what, g_mac, cmp, mac_hex);
    }
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);

    /* Same again with single-byte updates. */
    if (CHECK_RC(noxtls_hmac_init(&ctx, alg, g_key, klen), NOXTLS_RETURN_SUCCESS) != 0) {
        uint32_t i;
        for (i = 0U; i < mlen; i += 1U) {
            (void)CHECK_RC(noxtls_hmac_update(&ctx, &g_msg[i], 1U), NOXTLS_RETURN_SUCCESS);
        }
        mac_len = (uint32_t)sizeof(g_mac);
        CHECK_RC(noxtls_hmac_final(&ctx, g_mac, &mac_len), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(what, g_mac, cmp, mac_hex);
    }
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
}

static void test_rfc4231(void)
{
    char what[64];
    uint32_t i;

    for (i = 0U; i < CS_ARRAY_LEN(k_rfc4231); i += 1U) {
        const cs_rfc4231_case_t *tc = &k_rfc4231[i];
        (void)snprintf(what, sizeof(what), "RFC 4231 TC%u HMAC-SHA-224", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_SHA_224, 28U, 0, tc->key, tc->data, tc->trunc, tc->sha224);
#if NOXTLS_FEATURE_SHA256
        (void)snprintf(what, sizeof(what), "RFC 4231 TC%u HMAC-SHA-256", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_SHA_256, 32U, 1, tc->key, tc->data, tc->trunc, tc->sha256);
#endif
#if NOXTLS_FEATURE_SHA384
        (void)snprintf(what, sizeof(what), "RFC 4231 TC%u HMAC-SHA-384", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_SHA_384, 48U, 1, tc->key, tc->data, tc->trunc, tc->sha384);
#endif
#if NOXTLS_FEATURE_SHA512
        (void)snprintf(what, sizeof(what), "RFC 4231 TC%u HMAC-SHA-512", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_SHA_512, 64U, 1, tc->key, tc->data, tc->trunc, tc->sha512);
#endif
    }
}

static void test_rfc2202(void)
{
    char what[64];
    uint32_t i;

    for (i = 0U; i < CS_ARRAY_LEN(k_rfc2202_sha1); i += 1U) {
#if NOXTLS_FEATURE_SHA1
        (void)snprintf(what, sizeof(what), "RFC 2202 TC%u HMAC-SHA-1", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_SHA1, 20U, 1, k_rfc2202_sha1[i].key, k_rfc2202_sha1[i].data, 0U, k_rfc2202_sha1[i].mac);
#endif
        (void)snprintf(what, sizeof(what), "RFC 2202 TC%u HMAC-MD5", (unsigned)(i + 1U));
        hmac_case(what, NOXTLS_HASH_MD5, 16U, 0, k_rfc2202_md5[i].key, k_rfc2202_md5[i].data, 0U, k_rfc2202_md5[i].mac);
    }
}

typedef struct {
    const char *name;
    noxtls_hash_algos_t id;
    uint32_t dlen;
    const char *const *long_macs;
} cs_hmac_alg_t;

static const cs_hmac_alg_t k_hmac_algs[] = {
#if NOXTLS_FEATURE_SHA1
    { "HMAC-SHA-1", NOXTLS_HASH_SHA1, 20U, k_hmac_long_sha1 },
#endif
#if NOXTLS_FEATURE_SHA256
    { "HMAC-SHA-256", NOXTLS_HASH_SHA_256, 32U, k_hmac_long_sha256 },
#endif
#if NOXTLS_FEATURE_SHA384
    { "HMAC-SHA-384", NOXTLS_HASH_SHA_384, 48U, k_hmac_long_sha384 },
#endif
#if NOXTLS_FEATURE_SHA512
    { "HMAC-SHA-512", NOXTLS_HASH_SHA_512, 64U, k_hmac_long_sha512 },
#endif
};

/* One context, many (algorithm, key length) combinations and lifetimes. */
static void test_hmac_reuse(void)
{
    static noxtls_hmac_context_t ctx;
    uint32_t mac_len;
    uint32_t a;
    uint32_t k;
    uint32_t round;
    char what[96];

    cs_fill(g_msg, CS_HMAC_LONG_MSG_LEN, CS_HMAC_LONG_MSG_SEED);
    (void)memset(&ctx, 0x77, sizeof(ctx));
    for (round = 0U; round < 3U; round += 1U) {
        for (k = 0U; k < CS_ARRAY_LEN(k_hmac_long_klens); k += 1U) {
            for (a = 0U; a < CS_ARRAY_LEN(k_hmac_algs); a += 1U) {
                const cs_hmac_alg_t *alg = &k_hmac_algs[(a + round) % CS_ARRAY_LEN(k_hmac_algs)];
                uint32_t klen = k_hmac_long_klens[k];
                (void)snprintf(what, sizeof(what), "reuse round %u %s klen %u", (unsigned)round, alg->name, (unsigned)klen);
                cs_section(what);
                cs_fill(g_key, klen, 0x5EED0000U + klen);
                if (round == 2U) {
                    /* Abandon a started computation, free, then re-init. */
                    CHECK_RC(noxtls_hmac_init(&ctx, alg->id, g_key, klen), NOXTLS_RETURN_SUCCESS);
                    CHECK_RC(noxtls_hmac_update(&ctx, g_msg, 77U), NOXTLS_RETURN_SUCCESS);
                    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
                }
                mac_len = alg->dlen; /* exact-size output buffer */
                (void)memset(g_mac, 0xEE, sizeof(g_mac));
                CHECK_RC(hmac_stream(&ctx, alg->id, g_key, klen, g_msg, CS_HMAC_LONG_MSG_LEN, k + a, g_mac, &mac_len),
                         NOXTLS_RETURN_SUCCESS);
                CHECK(mac_len == alg->dlen);
                (void)EXPECT_HEX(what, g_mac, alg->dlen, alg->long_macs[k]);
                CHECK(cs_all_byte(&g_mac[alg->dlen], sizeof(g_mac) - alg->dlen, 0xEEU));
                if (round != 1U) {
                    /* round 1 re-inits a finalised context without free. */
                    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
                }
            }
        }
    }
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS); /* double free of a freed context is harmless */

    /* Output buffer too small: rejected, required size reported. */
    cs_section("HMAC short output buffer");
    for (a = 0U; a < CS_ARRAY_LEN(k_hmac_algs); a += 1U) {
        mac_len = k_hmac_algs[a].dlen - 1U;
        CHECK_RC(noxtls_hmac_compute(k_hmac_algs[a].id, g_key, 16U, g_msg, 16U, g_mac, &mac_len), NOXTLS_RETURN_FAILED);
        CHECK(mac_len == k_hmac_algs[a].dlen);
    }
    /* Empty message through compute with NULL data. */
    cs_section("HMAC empty message");
    for (a = 0U; a < CS_ARRAY_LEN(k_hmac_algs); a += 1U) {
        uint8_t ref[64];
        uint32_t ref_len = (uint32_t)sizeof(ref);
        mac_len = (uint32_t)sizeof(g_mac);
        CHECK_RC(noxtls_hmac_compute(k_hmac_algs[a].id, g_key, 20U, NULL, 0U, g_mac, &mac_len), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_hmac_init(&ctx, k_hmac_algs[a].id, g_key, 20U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_hmac_final(&ctx, ref, &ref_len), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
        CHECK(ref_len == mac_len);
        (void)EXPECT_MEM("empty message", g_mac, ref, mac_len);
    }
}

/* noxtls_hmac_reset(): new MAC under the same key without re-keying. */
static void test_hmac_reset(void)
{
    static noxtls_hmac_context_t ctx;
    uint8_t ref[64];
    uint32_t ref_len;
    uint32_t mac_len;
    uint32_t a;
    uint32_t m;

    cs_section("HMAC reset");
    cs_fill(g_key, 200U, 0xA11CE5U);
    cs_fill(g_msg, 1000U, 0xB0B5U);
    (void)memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(noxtls_hmac_reset(NULL), NOXTLS_RETURN_NULL);
    CHECK_RC(noxtls_hmac_reset(&ctx), NOXTLS_RETURN_FAILED); /* never keyed */
    for (a = 0U; a < CS_ARRAY_LEN(k_hmac_algs); a += 1U) {
        const cs_hmac_alg_t *alg = &k_hmac_algs[a];
        /* short and long (hashed) keys */
        uint32_t klen = (a & 1U) ? 200U : 17U;
        CHECK_RC(noxtls_hmac_init(&ctx, alg->id, g_key, klen), NOXTLS_RETURN_SUCCESS);
        for (m = 0U; m < 6U; m += 1U) {
            uint32_t mlen = (m * 173U) % 1000U;
            ref_len = (uint32_t)sizeof(ref);
            CHECK_RC(noxtls_hmac_compute(alg->id, g_key, klen, g_msg, mlen, ref, &ref_len), NOXTLS_RETURN_SUCCESS);
            if (m == 3U) {
                /* abandon a partial MAC: reset must discard it */
                CHECK_RC(noxtls_hmac_update(&ctx, g_msg, 99U), NOXTLS_RETURN_SUCCESS);
                CHECK_RC(noxtls_hmac_reset(&ctx), NOXTLS_RETURN_SUCCESS);
            }
            if (mlen > 0U) {
                CHECK_RC(noxtls_hmac_update(&ctx, g_msg, mlen / 3U), NOXTLS_RETURN_SUCCESS);
                CHECK_RC(noxtls_hmac_update(&ctx, &g_msg[mlen / 3U], mlen - (mlen / 3U)), NOXTLS_RETURN_SUCCESS);
            }
            mac_len = (uint32_t)sizeof(g_mac);
            CHECK_RC(noxtls_hmac_final(&ctx, g_mac, &mac_len), NOXTLS_RETURN_SUCCESS);
            CHECK(mac_len == ref_len);
            (void)EXPECT_MEM("reset MAC", g_mac, ref, ref_len);
            /* finished: no more data until reset */
            CHECK_RC(noxtls_hmac_update(&ctx, g_msg, 1U), NOXTLS_RETURN_FAILED);
            mac_len = (uint32_t)sizeof(g_mac);
            CHECK_RC(noxtls_hmac_final(&ctx, g_mac, &mac_len), NOXTLS_RETURN_FAILED);
            CHECK_RC(noxtls_hmac_reset(&ctx), NOXTLS_RETURN_SUCCESS);
        }
        CHECK_RC(noxtls_hmac_free(&ctx), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_hmac_reset(&ctx), NOXTLS_RETURN_FAILED); /* freed */
    }
}

/* ------------------------------------------------------------------------- */
/* HKDF                                                                       */
/* ------------------------------------------------------------------------- */
static uint32_t hash_len_of(noxtls_hash_algos_t alg)
{
    switch (alg) {
    case NOXTLS_HASH_SHA1: return 20U;
    case NOXTLS_HASH_SHA_256: return 32U;
    case NOXTLS_HASH_SHA_384: return 48U;
    case NOXTLS_HASH_SHA_512: return 64U;
    default: return 0U;
    }
}

static int hkdf_alg_enabled(noxtls_hash_algos_t alg)
{
    switch (alg) {
    case NOXTLS_HASH_SHA1: return NOXTLS_FEATURE_SHA1;
    case NOXTLS_HASH_SHA_256: return NOXTLS_FEATURE_SHA256;
    case NOXTLS_HASH_SHA_384: return NOXTLS_FEATURE_SHA384;
    case NOXTLS_HASH_SHA_512: return NOXTLS_FEATURE_SHA512;
    default: return 0;
    }
}

static void test_rfc5869(void)
{
    static uint8_t ikm[128];
    static uint8_t salt[128];
    static uint8_t info[256];
    static uint8_t prk[64];
    static uint8_t okm[128];
    char what[64];
    uint32_t i;

    for (i = 0U; i < CS_ARRAY_LEN(k_rfc5869); i += 1U) {
        const cs_hkdf_case_t *tc = &k_rfc5869[i];
        uint32_t hl = hash_len_of(tc->hash_algo);
        uint32_t ikm_len = cs_hex(tc->ikm, ikm, (uint32_t)sizeof(ikm));
        uint32_t salt_len = cs_hex(tc->salt, salt, (uint32_t)sizeof(salt));
        uint32_t info_len = cs_hex(tc->info, info, (uint32_t)sizeof(info));
        uint32_t prk_len = (uint32_t)sizeof(prk);
        if (hkdf_alg_enabled(tc->hash_algo) == 0) {
            continue;
        }
        (void)snprintf(what, sizeof(what), "RFC 5869 TC%u", (unsigned)tc->rfc_case);
        cs_section(what);
        (void)memset(okm, 0xEE, sizeof(okm));
        CHECK_RC(noxtls_hkdf_extract(tc->hash_algo, (tc->salt == NULL) ? NULL : salt, salt_len, ikm, ikm_len, prk, &prk_len),
                 NOXTLS_RETURN_SUCCESS);
        CHECK(prk_len == hl);
        (void)EXPECT_HEX("PRK", prk, hl, tc->prk);
        CHECK_RC(noxtls_hkdf_expand(tc->hash_algo, prk, prk_len, (info_len == 0U) ? NULL : info, info_len, okm, tc->okm_len),
                 NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("OKM", okm, tc->okm_len, tc->okm);
        CHECK(cs_all_byte(&okm[tc->okm_len], sizeof(okm) - tc->okm_len, 0xEEU));
        if (info_len == 0U) {
            /* Empty info given as a non-NULL pointer must be identical. */
            CHECK_RC(noxtls_hkdf_expand(tc->hash_algo, prk, prk_len, info, 0U, okm, tc->okm_len), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX("OKM (non-NULL empty info)", okm, tc->okm_len, tc->okm);
        }
        /* PRK output buffer one byte short: rejected with the required size. */
        prk_len = hl - 1U;
        CHECK_RC(noxtls_hkdf_extract(tc->hash_algo, salt, salt_len, ikm, ikm_len, prk, &prk_len), NOXTLS_RETURN_FAILED);
        CHECK(prk_len == hl);
    }
}

typedef struct {
    const char *name;
    noxtls_hash_algos_t id;
    const char *prk;
    uint32_t okm_max;
    const char *head;
    const char *tail;
    const char *const *odd;
} cs_hkdf_long_t;

static const cs_hkdf_long_t k_hkdf_long[] = {
#if NOXTLS_FEATURE_SHA256
    { "HKDF-SHA-256", NOXTLS_HASH_SHA_256, k_hkdf_long_prk_256, CS_HKDF_LONG_OKM_LEN_256,
      k_hkdf_long_head_256, k_hkdf_long_tail_256, k_hkdf_odd_256 },
#endif
#if NOXTLS_FEATURE_SHA384
    { "HKDF-SHA-384", NOXTLS_HASH_SHA_384, k_hkdf_long_prk_384, CS_HKDF_LONG_OKM_LEN_384,
      k_hkdf_long_head_384, k_hkdf_long_tail_384, k_hkdf_odd_384 },
#endif
#if NOXTLS_FEATURE_SHA512
    { "HKDF-SHA-512", NOXTLS_HASH_SHA_512, k_hkdf_long_prk_512, CS_HKDF_LONG_OKM_LEN_512,
      k_hkdf_long_head_512, k_hkdf_long_tail_512, k_hkdf_odd_512 },
#endif
};

static void test_hkdf_long(void)
{
    static uint8_t info[CS_HKDF_LONG_INFO_LEN];
    static uint8_t full[255U * 64U + 16U];
    static uint8_t part[255U * 64U + 16U];
    uint8_t prk[64];
    uint32_t i;

    cs_fill(info, CS_HKDF_LONG_INFO_LEN, CS_HKDF_LONG_INFO_SEED);
    for (i = 0U; i < CS_ARRAY_LEN(k_hkdf_long); i += 1U) {
        const cs_hkdf_long_t *v = &k_hkdf_long[i];
        uint32_t prk_len = cs_hex(v->prk, prk, (uint32_t)sizeof(prk));
        uint32_t lens[5];
        uint32_t j;

        lens[0] = 1U;
        lens[1] = 31U;
        lens[2] = 33U;
        lens[3] = 100U;
        lens[4] = v->okm_max - 1U;
        cs_section(v->name);
        (void)memset(full, 0xEE, sizeof(full));
        CHECK_RC(noxtls_hkdf_expand(v->id, prk, prk_len, info, CS_HKDF_LONG_INFO_LEN, full, v->okm_max), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX("OKM head", full, 100U, v->head);
        (void)EXPECT_HEX("OKM tail", &full[v->okm_max - 100U], 100U, v->tail);
        CHECK(cs_all_byte(&full[v->okm_max], sizeof(full) - v->okm_max, 0xEEU));
        for (j = 0U; j < 5U; j += 1U) {
            uint32_t n = lens[j];
            uint32_t tail = (n < 16U) ? n : 16U;
            (void)memset(part, 0xEE, sizeof(part));
            CHECK_RC(noxtls_hkdf_expand(v->id, prk, prk_len, info, CS_HKDF_LONG_INFO_LEN, part, n), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX("odd-length OKM tail", &part[n - tail], tail, v->odd[j]);
            (void)EXPECT_MEM("odd-length OKM is a prefix", part, full, n);
            CHECK(part[n] == 0xEEU);
        }
        /* RFC 5869: L <= 255 * HashLen. */
        CHECK_RC(noxtls_hkdf_expand(v->id, prk, prk_len, info, 16U, part, v->okm_max + 1U), NOXTLS_RETURN_INVALID_PARAM);
    }
}

#if NOXTLS_FEATURE_PBKDF2
static void test_pbkdf2(void)
{
    static uint8_t pass[64];
    static uint8_t salt[64];
    static uint8_t dk[160];
    char what[64];
    uint32_t i;

    for (i = 0U; i < CS_ARRAY_LEN(k_pbkdf2); i += 1U) {
        const cs_pbkdf2_case_t *tc = &k_pbkdf2[i];
        uint32_t pl = cs_hex(tc->password, pass, (uint32_t)sizeof(pass));
        uint32_t sl = cs_hex(tc->salt, salt, (uint32_t)sizeof(salt));
        if (hkdf_alg_enabled(tc->hash_algo) == 0) {
            continue;
        }
        (void)snprintf(what, sizeof(what), "PBKDF2 case %u (c=%u, dkLen=%u)", (unsigned)i, (unsigned)tc->iterations,
                       (unsigned)tc->dk_len);
        cs_section(what);
        (void)memset(dk, 0xEE, sizeof(dk));
        CHECK_RC(noxtls_pbkdf2_hmac(tc->hash_algo, pass, pl, salt, sl, tc->iterations, dk, tc->dk_len), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(what, dk, tc->dk_len, tc->dk);
        CHECK(cs_all_byte(&dk[tc->dk_len], sizeof(dk) - tc->dk_len, 0xEEU));
    }
    cs_section("PBKDF2 self test");
    CHECK_RC(noxtls_pbkdf2_self_test(), NOXTLS_RETURN_SUCCESS);
}
#endif

int main(void)
{
    test_rfc4231();
    test_rfc2202();
    test_hmac_reuse();
    test_hmac_reset();
    test_rfc5869();
    test_hkdf_long();
#if NOXTLS_FEATURE_PBKDF2
    test_pbkdf2();
#else
    (void)printf("SKIP PBKDF2: NOXTLS_FEATURE_PBKDF2 is off in this build\n");
#endif
    if (g_skips != 0U) {
        (void)printf("note: %u HMAC cases skipped because the digest is not offered by noxtls_hmac\n", (unsigned)g_skips);
    }
    return cs_finish("crypto_sym_hmac_kdf_test");
}
