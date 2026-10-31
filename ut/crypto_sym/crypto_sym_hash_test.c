/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_hash_test.c
* Summary: Message digest regression tests (public API only).
*
* Covers, for every digest compiled into the build:
*  - FIPS 180-4 / FIPS 202 / RFC 1320 / RFC 1321 / RIPEMD-160 / RFC 7693
*    messages ("", "abc", 448-bit, 896-bit, 1,000,000 x 'a', 1600-bit 0xa3,
*    the RFC 1321 suite) plus a 4099-byte pseudo-random message,
*    through BOTH the generic dispatcher (noxtls_sha_init/update/finish) and the
*    per-algorithm APIs (noxtls_sha256_*, noxtls_sha512_*, noxtls_sha3_*, ...);
*  - multi-part updates with an irregular chunk schedule (1, 3, 7, 13, 0, 63,
*    64, 65, 127, 128, 129, 135..137, 143..145, 167..169, ...), which must equal
*    the one-shot digest;
*  - zero-length updates (non-NULL pointer everywhere; NULL pointer for the
*    per-algorithm APIs whose code accepts (NULL, 0));
*  - one noxtls_sha_ctx_t reused across every algorithm (union/layout reuse),
*    including abandoned partial computations and a garbage-filled context;
*  - SHAKE128/SHAKE256 with 721-byte outputs squeezed in odd pieces spanning
*    several rate blocks.
* Expected values: crypto_sym_hash_vectors.h (gen_crypto_sym_vectors.py).
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/noxtls_sha.h"
#if NOXTLS_FEATURE_MD4
#include "mdigest/md4/noxtls_md4.h"
#endif
#if NOXTLS_FEATURE_MD5
#include "mdigest/md5/noxtls_md5.h"
#endif
#if NOXTLS_FEATURE_SHA1
#include "mdigest/sha1/noxtls_sha1.h"
#endif
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
#include "mdigest/sha256/noxtls_sha256.h"
#endif
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
#include "mdigest/sha512/noxtls_sha512.h"
#endif
#if NOXTLS_FEATURE_RIPEMD160
#include "mdigest/ripemd160/noxtls_ripemd160.h"
#endif

#include "crypto_sym_test_util.h"
#include "crypto_sym_hash_vectors.h"

/* Order must match HASH_MSGS in gen_crypto_sym_vectors.py. */
enum cs_hash_msg {
    MSG_EMPTY = 0,
    MSG_ABC,
    MSG_448,
    MSG_896,
    MSG_MILLION_A,
    MSG_A3_1600,
    MSG_A,
    MSG_MESSAGE_DIGEST,
    MSG_ALPHA,
    MSG_ALNUM,
    MSG_DIGITS,
    MSG_PRNG,
    MSG_COUNT
};

static const char *const k_msg_names[MSG_COUNT] = {
    "empty", "abc", "448-bit", "896-bit", "1M x a", "1600-bit 0xa3", "a",
    "message digest", "a..z", "A..Za..z0..9", "8 x 1234567890", "PRNG(4099)"
};

#define CS_MSG_MAX (1000000U)
static uint8_t g_msg[CS_MSG_MAX];

static uint32_t build_msg(uint32_t id)
{
    static const char *const k_text[MSG_COUNT] = {
        "", "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        NULL, NULL, "a", "message digest", "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        NULL
    };
    uint32_t len = 0U;

    if (id == (uint32_t)MSG_MILLION_A) {
        (void)memset(g_msg, 'a', CS_MSG_MAX);
        len = CS_MSG_MAX;
    } else if (id == (uint32_t)MSG_A3_1600) {
        (void)memset(g_msg, 0xa3, 200U);
        len = 200U;
    } else if (id == (uint32_t)MSG_PRNG) {
        cs_fill(g_msg, CS_HASH_MSG_PRNG_LEN, CS_HASH_MSG_PRNG_SEED);
        len = CS_HASH_MSG_PRNG_LEN;
    } else {
        len = (uint32_t)strlen(k_text[id]);
        (void)memcpy(g_msg, k_text[id], len);
    }
    return len;
}

typedef struct {
    const char *name;
    noxtls_hash_algos_t id;
    uint32_t dlen;
    uint8_t direct_null_ok; /* per-algorithm update accepts (NULL, 0) */
    const char *const *expect;
} cs_alg_t;

static const cs_alg_t k_algs[] = {
#if NOXTLS_FEATURE_MD4
    { "MD4", NOXTLS_HASH_MD4, 16U, 0U, k_hash_md4 },
#endif
#if NOXTLS_FEATURE_MD5
    { "MD5", NOXTLS_HASH_MD5, 16U, 1U, k_hash_md5 },
#endif
#if NOXTLS_FEATURE_SHA1
    { "SHA-1", NOXTLS_HASH_SHA1, 20U, 0U, k_hash_sha1 },
#endif
#if NOXTLS_FEATURE_SHA224
    { "SHA-224", NOXTLS_HASH_SHA_224, 28U, 1U, k_hash_sha224 },
#endif
#if NOXTLS_FEATURE_SHA256
    { "SHA-256", NOXTLS_HASH_SHA_256, 32U, 1U, k_hash_sha256 },
#endif
#if NOXTLS_FEATURE_SHA384
    { "SHA-384", NOXTLS_HASH_SHA_384, 48U, 1U, k_hash_sha384 },
#endif
#if NOXTLS_FEATURE_SHA512
    { "SHA-512", NOXTLS_HASH_SHA_512, 64U, 1U, k_hash_sha512 },
    { "SHA-512/224", NOXTLS_HASH_SHA_512_224, 28U, 1U, k_hash_sha512_224 },
    { "SHA-512/256", NOXTLS_HASH_SHA_512_256, 32U, 1U, k_hash_sha512_256 },
#endif
#if NOXTLS_FEATURE_SHA3
    { "SHA3-224", NOXTLS_HASH_SHA3_224, 28U, 1U, k_hash_sha3_224 },
    { "SHA3-256", NOXTLS_HASH_SHA3_256, 32U, 1U, k_hash_sha3_256 },
    { "SHA3-384", NOXTLS_HASH_SHA3_384, 48U, 1U, k_hash_sha3_384 },
    { "SHA3-512", NOXTLS_HASH_SHA3_512, 64U, 1U, k_hash_sha3_512 },
#endif
#if NOXTLS_FEATURE_RIPEMD160
    { "RIPEMD-160", NOXTLS_HASH_RIPEMD160, 20U, 1U, k_hash_ripemd160 },
#endif
#if NOXTLS_FEATURE_BLAKE2
    { "BLAKE2s-256", NOXTLS_HASH_BLAKE2S_256, 32U, 1U, k_hash_blake2s_256 },
    { "BLAKE2b-512", NOXTLS_HASH_BLAKE2B_512, 64U, 1U, k_hash_blake2b_512 },
#endif
};
#define CS_ALG_COUNT ((uint32_t)(sizeof(k_algs) / sizeof(k_algs[0])))

/* ------------------------------------------------------------------------- */
/* Per-algorithm ("direct") API wrapper                                       */
/* ------------------------------------------------------------------------- */
typedef struct {
    noxtls_sha_ctx_t sha;
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    noxtls_sha512_ctx_t s512;
#endif
    noxtls_sha3_ctx_t s3;
    noxtls_blake2_ctx_t b2;
} cs_direct_ctx_t;

static noxtls_return_t direct_init(cs_direct_ctx_t *c, noxtls_hash_algos_t id)
{
    switch (id) {
#if NOXTLS_FEATURE_MD4
    case NOXTLS_HASH_MD4: return noxtls_md4_init(&c->sha);
#endif
#if NOXTLS_FEATURE_MD5
    case NOXTLS_HASH_MD5: return noxtls_md5_init(&c->sha);
#endif
#if NOXTLS_FEATURE_SHA1
    case NOXTLS_HASH_SHA1: return noxtls_sha1_init(&c->sha, id);
#endif
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
    case NOXTLS_HASH_SHA_224:
    case NOXTLS_HASH_SHA_256: return noxtls_sha256_init(&c->sha, id);
#endif
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    case NOXTLS_HASH_SHA_384:
    case NOXTLS_HASH_SHA_512:
    case NOXTLS_HASH_SHA_512_224:
    case NOXTLS_HASH_SHA_512_256: return noxtls_sha512_init(&c->s512, id);
#endif
#if NOXTLS_FEATURE_SHA3
    case NOXTLS_HASH_SHA3_224: return noxtls_sha3_224_init(&c->s3);
    case NOXTLS_HASH_SHA3_256: return noxtls_sha3_256_init(&c->s3);
    case NOXTLS_HASH_SHA3_384: return noxtls_sha3_384_init(&c->s3);
    case NOXTLS_HASH_SHA3_512: return noxtls_sha3_512_init(&c->s3);
#endif
#if NOXTLS_FEATURE_RIPEMD160
    case NOXTLS_HASH_RIPEMD160: return noxtls_ripemd160_init(&c->sha);
#endif
#if NOXTLS_FEATURE_BLAKE2
    case NOXTLS_HASH_BLAKE2S_256: return noxtls_blake2s_256_init(&c->b2);
    case NOXTLS_HASH_BLAKE2B_512: return noxtls_blake2b_512_init(&c->b2);
#endif
    default: break;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static noxtls_return_t direct_update(cs_direct_ctx_t *c, noxtls_hash_algos_t id, const uint8_t *d, uint32_t n)
{
    (void)d;
    (void)n;
    switch (id) {
#if NOXTLS_FEATURE_MD4
    case NOXTLS_HASH_MD4: return noxtls_md4_update(&c->sha, d, n);
#endif
#if NOXTLS_FEATURE_MD5
    case NOXTLS_HASH_MD5: return noxtls_md5_update(&c->sha, d, n);
#endif
#if NOXTLS_FEATURE_SHA1
    case NOXTLS_HASH_SHA1: return noxtls_sha1_update(&c->sha, d, n);
#endif
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
    case NOXTLS_HASH_SHA_224:
    case NOXTLS_HASH_SHA_256: return noxtls_sha256_update(&c->sha, d, n);
#endif
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    case NOXTLS_HASH_SHA_384:
    case NOXTLS_HASH_SHA_512:
    case NOXTLS_HASH_SHA_512_224:
    case NOXTLS_HASH_SHA_512_256: return noxtls_sha512_update(&c->s512, d, n);
#endif
#if NOXTLS_FEATURE_SHA3
    case NOXTLS_HASH_SHA3_224:
    case NOXTLS_HASH_SHA3_256:
    case NOXTLS_HASH_SHA3_384:
    case NOXTLS_HASH_SHA3_512: return noxtls_sha3_update(&c->s3, d, n);
#endif
#if NOXTLS_FEATURE_RIPEMD160
    case NOXTLS_HASH_RIPEMD160: return noxtls_ripemd160_update(&c->sha, d, n);
#endif
#if NOXTLS_FEATURE_BLAKE2
    case NOXTLS_HASH_BLAKE2S_256:
    case NOXTLS_HASH_BLAKE2B_512: return noxtls_blake2_update(&c->b2, d, n);
#endif
    default: break;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static noxtls_return_t direct_finish(cs_direct_ctx_t *c, noxtls_hash_algos_t id, uint8_t *out)
{
    (void)out;
    switch (id) {
#if NOXTLS_FEATURE_MD4
    case NOXTLS_HASH_MD4: return noxtls_md4_finish(&c->sha, out);
#endif
#if NOXTLS_FEATURE_MD5
    case NOXTLS_HASH_MD5: return noxtls_md5_finish(&c->sha, out);
#endif
#if NOXTLS_FEATURE_SHA1
    case NOXTLS_HASH_SHA1: return noxtls_sha1_finish(&c->sha, out);
#endif
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
    case NOXTLS_HASH_SHA_224:
    case NOXTLS_HASH_SHA_256: return noxtls_sha256_finish(&c->sha, out);
#endif
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    case NOXTLS_HASH_SHA_384:
    case NOXTLS_HASH_SHA_512:
    case NOXTLS_HASH_SHA_512_224:
    case NOXTLS_HASH_SHA_512_256: return noxtls_sha512_finish(&c->s512, out);
#endif
#if NOXTLS_FEATURE_SHA3
    case NOXTLS_HASH_SHA3_224:
    case NOXTLS_HASH_SHA3_256:
    case NOXTLS_HASH_SHA3_384:
    case NOXTLS_HASH_SHA3_512: return noxtls_sha3_finish(&c->s3, out);
#endif
#if NOXTLS_FEATURE_RIPEMD160
    case NOXTLS_HASH_RIPEMD160: return noxtls_ripemd160_finish(&c->sha, out);
#endif
#if NOXTLS_FEATURE_BLAKE2
    case NOXTLS_HASH_BLAKE2S_256:
    case NOXTLS_HASH_BLAKE2B_512: return noxtls_blake2_finish(&c->b2, out);
#endif
    default: break;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/* ------------------------------------------------------------------------- */
/* Hash drivers                                                               */
/* ------------------------------------------------------------------------- */
typedef enum { API_DISPATCH = 0, API_DIRECT = 1 } cs_api_t;

static noxtls_sha_ctx_t g_disp;    /* dispatcher context (static: large) */
static cs_direct_ctx_t g_direct;   /* per-algorithm contexts */

static noxtls_return_t api_init(cs_api_t api, noxtls_hash_algos_t id)
{
    return (api == API_DISPATCH) ? noxtls_sha_init(&g_disp, id) : direct_init(&g_direct, id);
}

static noxtls_return_t api_update(cs_api_t api, noxtls_hash_algos_t id, const uint8_t *d, uint32_t n)
{
    return (api == API_DISPATCH) ? noxtls_sha_update(&g_disp, d, n) : direct_update(&g_direct, id, d, n);
}

static noxtls_return_t api_finish(cs_api_t api, noxtls_hash_algos_t id, uint8_t *out)
{
    return (api == API_DISPATCH) ? noxtls_sha_finish(&g_disp, out) : direct_finish(&g_direct, id, out);
}

/*
 * Hash msg[0..len) with the given API. chunked == 0: one update of the whole
 * message (a zero-length update with a non-NULL pointer for the empty message).
 * chunked != 0: cs_chunk() schedule. Returns 1 when every call succeeded.
 */
static int hash_msg(cs_api_t api, const cs_alg_t *alg, const uint8_t *msg, uint32_t len, int chunked, uint8_t *out)
{
    uint32_t off = 0U;
    uint32_t idx = 0U;
    int ok = 1;

    if (api_init(api, alg->id) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    if (chunked == 0) {
        ok = (api_update(api, alg->id, msg, len) == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
    } else {
        while ((ok != 0) && (off < len)) {
            uint32_t n = cs_chunk(idx);
            idx += 1U;
            if (n > (len - off)) {
                n = len - off;
            }
            /* Zero-length chunks keep a valid, non-NULL pointer. */
            ok = (api_update(api, alg->id, &msg[off], n) == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
            off += n;
        }
    }
    if ((ok != 0) && (api_finish(api, alg->id, out) != NOXTLS_RETURN_SUCCESS)) {
        ok = 0;
    }
    return ok;
}

static void test_known_answers(void)
{
    static const char *const k_api_names[2] = { "dispatcher", "direct" };
    uint8_t out[64];
    char what[128];
    uint32_t m;
    uint32_t a;
    int api;

    for (m = 0U; m < (uint32_t)MSG_COUNT; m += 1U) {
        uint32_t len = build_msg(m);
        for (a = 0U; a < CS_ALG_COUNT; a += 1U) {
            const cs_alg_t *alg = &k_algs[a];
            for (api = 0; api < 2; api += 1) {
                int chunked;
                for (chunked = 0; chunked < 2; chunked += 1) {
                    (void)snprintf(what, sizeof(what), "%s %s %s %s", alg->name, k_api_names[api],
                                   (chunked != 0) ? "chunked" : "one-shot", k_msg_names[m]);
                    cs_section(what);
                    (void)memset(out, 0xEE, sizeof(out));
                    if (CHECK(hash_msg((cs_api_t)api, alg, g_msg, len, chunked, out) != 0)) {
                        (void)EXPECT_HEX(what, out, alg->dlen, alg->expect[m]);
                    }
                    /* Digest must not write past its length. */
                    CHECK(cs_all_byte(&out[alg->dlen], sizeof(out) - alg->dlen, 0xEEU));
                }
            }
        }
    }
}

/* Per-algorithm APIs that accept (NULL, 0): interleave such updates. */
static void test_null_zero_updates(void)
{
    uint8_t out[64];
    uint32_t len = build_msg(MSG_896);
    uint32_t a;

    cs_section("direct (NULL, 0) updates");
    for (a = 0U; a < CS_ALG_COUNT; a += 1U) {
        const cs_alg_t *alg = &k_algs[a];
        if (alg->direct_null_ok == 0U) {
            continue;
        }
        CHECK_RC(direct_init(&g_direct, alg->id), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, g_msg, 5U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, &g_msg[5], len - 5U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_finish(&g_direct, alg->id, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(alg->name, out, alg->dlen, alg->expect[MSG_896]);

        /* Empty message made only of (NULL, 0) updates. */
        CHECK_RC(direct_init(&g_direct, alg->id), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_finish(&g_direct, alg->id, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(alg->name, out, alg->dlen, alg->expect[MSG_EMPTY]);
    }
}

/*
 * One noxtls_sha_ctx_t reused for every algorithm, in forward and reverse
 * order, starting from a garbage-filled context and abandoning a partial
 * computation of the previous algorithm before each init.
 */
static void test_context_reuse(void)
{
    static noxtls_sha_ctx_t ctx;
    uint8_t out[64];
    uint32_t len = build_msg(MSG_PRNG);
    uint32_t pass;
    uint32_t step;
    char what[96];

    (void)memset(&ctx, 0xA5, sizeof(ctx));
    for (pass = 0U; pass < 3U; pass += 1U) {
        for (step = 0U; step < CS_ALG_COUNT; step += 1U) {
            /* pass 0: forward, pass 1: reverse, pass 2: stride 5 (cross-family jumps). */
            uint32_t a = (pass == 0U) ? step : ((pass == 1U) ? (CS_ALG_COUNT - 1U - step) : ((step * 5U) % CS_ALG_COUNT));
            const cs_alg_t *alg = &k_algs[a];
            const cs_alg_t *prev = &k_algs[(a + 1U) % CS_ALG_COUNT];
            uint32_t off = 0U;
            uint32_t idx = pass;

            (void)snprintf(what, sizeof(what), "reuse pass %u %s", (unsigned)pass, alg->name);
            cs_section(what);
            /* Abandon a partial computation of a different algorithm. */
            CHECK_RC(noxtls_sha_init(&ctx, prev->id), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_sha_update(&ctx, g_msg, 333U), NOXTLS_RETURN_SUCCESS);

            CHECK_RC(noxtls_sha_init(&ctx, alg->id), NOXTLS_RETURN_SUCCESS);
            while (off < len) {
                uint32_t n = cs_chunk(idx);
                idx += 1U;
                if (n > (len - off)) {
                    n = len - off;
                }
                (void)CHECK_RC(noxtls_sha_update(&ctx, &g_msg[off], n), NOXTLS_RETURN_SUCCESS);
                off += n;
            }
            CHECK_RC(noxtls_sha_finish(&ctx, out), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX(what, out, alg->dlen, alg->expect[MSG_PRNG]);

            /* Re-init the same algorithm after finish and reuse. */
            CHECK_RC(noxtls_sha_init(&ctx, alg->id), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_sha_update(&ctx, (const uint8_t *)"abc", 3U), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_sha_finish(&ctx, out), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX(what, out, alg->dlen, alg->expect[MSG_ABC]);
        }
    }

    /* Each algorithm initialised directly on a garbage-filled context. */
    for (step = 0U; step < CS_ALG_COUNT; step += 1U) {
        const cs_alg_t *alg = &k_algs[step];
        (void)snprintf(what, sizeof(what), "garbage-filled init %s", alg->name);
        cs_section(what);
        (void)memset(&ctx, 0x5A + (int)step, sizeof(ctx));
        CHECK_RC(noxtls_sha_init(&ctx, alg->id), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_sha_update(&ctx, (const uint8_t *)"abc", 3U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_sha_finish(&ctx, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(what, out, alg->dlen, alg->expect[MSG_ABC]);

        (void)memset(&g_direct, 0x3C + (int)step, sizeof(g_direct));
        CHECK_RC(direct_init(&g_direct, alg->id), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_update(&g_direct, alg->id, (const uint8_t *)"abc", 3U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(direct_finish(&g_direct, alg->id, out), NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_HEX(what, out, alg->dlen, alg->expect[MSG_ABC]);
    }
}

/* Algorithms compiled out must be rejected by the dispatcher. */
static void test_disabled_algorithms(void)
{
    static noxtls_sha_ctx_t ctx;
    cs_section("disabled algorithms");
    (void)ctx;
#if !NOXTLS_FEATURE_SHA3
    CHECK_RC(noxtls_sha_init(&ctx, NOXTLS_HASH_SHA3_256), NOXTLS_RETURN_NOT_SUPPORTED);
#endif
#if !NOXTLS_FEATURE_BLAKE2
    CHECK_RC(noxtls_sha_init(&ctx, NOXTLS_HASH_BLAKE2B_512), NOXTLS_RETURN_NOT_SUPPORTED);
#endif
#if !NOXTLS_FEATURE_MD4
    CHECK_RC(noxtls_sha_init(&ctx, NOXTLS_HASH_MD4), NOXTLS_RETURN_NOT_SUPPORTED);
#endif
    CHECK_RC(noxtls_sha_init(&ctx, (noxtls_hash_algos_t)200U), NOXTLS_RETURN_NOT_SUPPORTED);
}

#if NOXTLS_FEATURE_SHA3
typedef noxtls_return_t (*cs_xof_init_t)(noxtls_sha3_ctx_t *);
typedef noxtls_return_t (*cs_xof_update_t)(noxtls_sha3_ctx_t *, const uint8_t *, uint32_t);
typedef noxtls_return_t (*cs_xof_final_t)(noxtls_sha3_ctx_t *);
typedef noxtls_return_t (*cs_xof_squeeze_t)(noxtls_sha3_ctx_t *, uint8_t *, uint32_t);

typedef struct {
    const char *name;
    cs_xof_init_t init;
    cs_xof_update_t update;
    cs_xof_final_t final_fn;
    cs_xof_squeeze_t squeeze;
} cs_xof_t;

static const cs_xof_t k_shake128 = { "SHAKE128", noxtls_shake128_init, noxtls_shake128_update,
                                     noxtls_shake128_final, noxtls_shake128_squeeze };
static const cs_xof_t k_shake256 = { "SHAKE256", noxtls_shake256_init, noxtls_shake256_update,
                                     noxtls_shake256_final, noxtls_shake256_squeeze };

/* Absorb msg (chunked or not), then squeeze according to pieces[] (sum = total). */
static void xof_run(const cs_xof_t *x, const uint8_t *msg, uint32_t len, int chunked,
                    const uint32_t *pieces, uint32_t npieces, const char *expect_hex, const char *what)
{
    static noxtls_sha3_ctx_t ctx;
    static uint8_t out[CS_SHAKE_LONG_LEN];
    uint32_t off = 0U;
    uint32_t i;
    uint32_t idx = 0U;

    cs_section(what);
    (void)memset(&ctx, 0xC3, sizeof(ctx));
    (void)memset(out, 0, sizeof(out));
    CHECK_RC(x->init(&ctx), NOXTLS_RETURN_SUCCESS);
    if (chunked == 0) {
        CHECK_RC(x->update(&ctx, msg, len), NOXTLS_RETURN_SUCCESS);
    } else {
        CHECK_RC(x->update(&ctx, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        while (off < len) {
            uint32_t n = cs_chunk(idx);
            idx += 1U;
            if (n > (len - off)) {
                n = len - off;
            }
            (void)CHECK_RC(x->update(&ctx, &msg[off], n), NOXTLS_RETURN_SUCCESS);
            off += n;
        }
    }
    CHECK_RC(x->final_fn(&ctx), NOXTLS_RETURN_SUCCESS);
    off = 0U;
    for (i = 0U; i < npieces; i += 1U) {
        CHECK_RC(x->squeeze(&ctx, &out[off], pieces[i]), NOXTLS_RETURN_SUCCESS);
        off += pieces[i];
    }
    (void)EXPECT_HEX(what, out, off, expect_hex);
}

static void test_shake(void)
{
    static const uint32_t k_one[] = { 721U };
    static const uint32_t k_odd[] = { 1U, 7U, 200U, 513U };
    static const uint32_t k_rate128[] = { 0U, 168U, 1U, 167U, 168U, 217U };
    static const uint32_t k_rate256[] = { 136U, 136U, 1U, 135U, 313U };
    static const uint32_t k_32[] = { 32U };
    static const uint32_t k_64[] = { 13U, 51U };
    static const uint32_t k_300[] = { 299U, 1U };
    uint8_t a3[200];
    uint32_t len;

    (void)memset(a3, 0xa3, sizeof(a3));
    xof_run(&k_shake128, (const uint8_t *)"", 0U, 0, k_one, 1U, k_shake128_empty_721, "SHAKE128('') 721 one squeeze");
    xof_run(&k_shake128, (const uint8_t *)"", 0U, 0, k_odd, 4U, k_shake128_empty_721, "SHAKE128('') squeeze 1,7,200,513");
    xof_run(&k_shake128, (const uint8_t *)"", 0U, 0, k_rate128, 6U, k_shake128_empty_721, "SHAKE128('') squeeze on rate edges");
    xof_run(&k_shake256, a3, 200U, 0, k_one, 1U, k_shake256_a3_721, "SHAKE256(0xa3*200) 721 one squeeze");
    xof_run(&k_shake256, a3, 200U, 1, k_odd, 4U, k_shake256_a3_721, "SHAKE256(0xa3*200) chunked, squeeze 1,7,200,513");
    xof_run(&k_shake256, a3, 200U, 1, k_rate256, 5U, k_shake256_a3_721, "SHAKE256(0xa3*200) squeeze on rate edges");
    xof_run(&k_shake128, (const uint8_t *)"abc", 3U, 0, k_32, 1U, k_shake128_abc_32, "SHAKE128(abc)");
    xof_run(&k_shake256, (const uint8_t *)"abc", 3U, 0, k_64, 2U, k_shake256_abc_64, "SHAKE256(abc)");
    len = build_msg(MSG_PRNG);
    xof_run(&k_shake128, g_msg, len, 1, k_300, 2U, k_shake128_prng_300, "SHAKE128(PRNG) chunked");
    xof_run(&k_shake256, g_msg, len, 1, k_300, 2U, k_shake256_prng_300, "SHAKE256(PRNG) chunked");
}
#endif /* NOXTLS_FEATURE_SHA3 */

int main(void)
{
    test_known_answers();
    test_null_zero_updates();
    test_context_reuse();
    test_disabled_algorithms();
#if NOXTLS_FEATURE_SHA3
    test_shake();
#endif
    return cs_finish("crypto_sym_hash_test");
}
