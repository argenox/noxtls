/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_hygiene_test.c
* Summary: Regressions for symmetric-cipher and digest length handling,
*          context wipes and dead-stack residue.
*
*  - AES-CCM rejects AAD and payload lengths whose CBC-MAC block count or CTR
*    cursor would wrap (aad_len >= 0xFFFFFFEB used to skip the AAD entirely).
*  - noxtls_aes_init() failures, noxtls_aes_final() errors and noxtls_aes_free()
*    leave no key schedule in the caller's context.
*  - MD5, SHA-1, SHA-256, SHA-512 and RIPEMD-160 encode the message length
*    past 2^32 bytes: a context that has absorbed 2^32 - B bytes is advanced
*    over the 4 GiB boundary and its digest is compared with one computed from
*    the same chaining value and an explicitly built padding block.
*  - Dead-stack residue: the stack below the caller is painted, one public
*    call runs, and the dead region is searched for secrets the call must not
*    leave behind (AES round keys and round states, CMAC subkey, Poly1305 r/s,
*    RC4 permutation, HMAC key pads, hashed secrets, SHA-3 state, ARIA and
*    Camellia keys). Under AddressSanitizer with fake stacks the frames live
*    elsewhere and these checks pass trivially; the plain build is the
*    meaningful run.
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/noxtls_sha.h"
#if NOXTLS_FEATURE_MD5
#include "mdigest/md5/noxtls_md5.h"
#endif
#if NOXTLS_FEATURE_SHA1
#include "mdigest/sha1/noxtls_sha1.h"
#endif
#if NOXTLS_FEATURE_SHA256
#include "mdigest/sha256/noxtls_sha256.h"
#endif
#if NOXTLS_FEATURE_SHA512
#include "mdigest/sha512/noxtls_sha512.h"
#endif
#if NOXTLS_FEATURE_RIPEMD160
#include "mdigest/ripemd160/noxtls_ripemd160.h"
#endif
#if NOXTLS_FEATURE_SHA3
#include "mdigest/sha3/noxtls_sha3.h"
#endif
#if NOXTLS_FEATURE_HMAC
#include "mac/noxtls_hmac.h"
#endif
#if NOXTLS_FEATURE_AES
#include "encryption/aes/noxtls_aes.h"
#endif
#if NOXTLS_FEATURE_AES_CCM
#include "encryption/aes/noxtls_aes_ccm.h"
#endif
#if NOXTLS_FEATURE_AES_CMAC
#include "encryption/aes/noxtls_aes_cmac.h"
#endif
#if NOXTLS_FEATURE_AES_GCM
#include "encryption/aes/noxtls_aes_gcm.h"
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
#include "encryption/chacha20/noxtls_chacha20.h"
#include "encryption/chacha20/noxtls_chacha20_poly1305.h"
#endif
#if NOXTLS_FEATURE_RC4
#include "encryption/rc4/noxtls_rc4.h"
#endif
#if NOXTLS_FEATURE_ARIA
#include "encryption/aria/noxtls_aria.h"
#endif
#if NOXTLS_FEATURE_CAMELLIA
#include "encryption/camellia/noxtls_camellia.h"
#endif

#include "crypto_sym_test_util.h"
#if NOXTLS_FEATURE_AES
#include "sym_aes_ref.h"
#endif

#if defined(__GNUC__) || defined(__clang__)
#define SH_NOINLINE __attribute__((noinline))
#else
#define SH_NOINLINE
#endif

/* ------------------------------------------------------------------------ */
/* Dead-stack residue scanner                                                */
/* ------------------------------------------------------------------------ */

/* AddressSanitizer pads every frame with unwritten redzones and may move
 * locals to fake stacks, so the library's stack burns (sized for real frames)
 * cannot be judged there; the residue checks run only in uninstrumented
 * builds and are reported as skipped otherwise. */
#if defined(__SANITIZE_ADDRESS__)
#define SH_RESIDUE_CHECKS 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SH_RESIDUE_CHECKS 0
#endif
#endif
#ifndef SH_RESIDUE_CHECKS
#define SH_RESIDUE_CHECKS 1
#endif

#define SH_SCAN_BYTES (16384U)
static uint8_t g_snap[SH_SCAN_BYTES];
static uint32_t g_residue_hits;

/** Fill the stack region below the caller with a marker. */
static SH_NOINLINE void sh_paint(void)
{
    volatile uint8_t b[SH_SCAN_BYTES];
    uint32_t i;
    for (i = 0U; i < SH_SCAN_BYTES; i += 1U) {
        b[i] = 0xA5U;
    }
}

/** Copy the (dead) stack region below the caller into g_snap. */
static SH_NOINLINE void sh_snapshot(void)
{
    volatile uint8_t b[SH_SCAN_BYTES];
    uint32_t i;
    for (i = 0U; i < SH_SCAN_BYTES; i += 1U) {
        g_snap[i] = b[i];
    }
}

static int sh_find(const uint8_t *pat, uint32_t len)
{
    uint32_t i;
    if (len == 0U) {
        return -1;
    }
    for (i = 0U; (i + len) <= SH_SCAN_BYTES; i += 1U) {
        if (memcmp(&g_snap[i], pat, len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/** Report a residue hit for pattern pat (len bytes) labelled what. */
static void sh_expect_absent(const char *what, const uint8_t *pat, uint32_t len)
{
    int at = -1;
    if (SH_RESIDUE_CHECKS == 0) {
        return;
    }
    at = sh_find(pat, len);
    g_cs_checks += 1U;
    if (at >= 0) {
        g_cs_failures += 1U;
        g_residue_hits += 1U;
        (void)fprintf(stderr, "FAIL [%s] residue: %s found in dead stack at offset %d\n",
                      g_cs_section, what, at);
        cs_dump("pattern", pat, len);
    }
}

/** Check every 4-byte word of buf, in memory order and byte-reversed. */
static void sh_expect_words_absent(const char *what, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    for (i = 0U; (i + 4U) <= len; i += 4U) {
        uint8_t rev[4];
        int all_same = 1;
        uint32_t k;
        for (k = 1U; k < 4U; k += 1U) {
            if (buf[i + k] != buf[i]) {
                all_same = 0;
            }
        }
        if (all_same != 0) {
            continue; /* uninformative pattern */
        }
        rev[0] = buf[i + 3U];
        rev[1] = buf[i + 2U];
        rev[2] = buf[i + 1U];
        rev[3] = buf[i];
        sh_expect_absent(what, &buf[i], 4U);
        sh_expect_absent(what, rev, 4U);
    }
}

/** Check a 32-bit value as stored in native memory order and byte-reversed. */
static void sh_expect_u32_absent(const char *what, uint32_t v)
{
    uint8_t b[4];
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    sh_expect_words_absent(what, b, 4U);
}

/* ------------------------------------------------------------------------ */
/* AES-CCM length limits (issue: AAD block count wrap)                      */
/* ------------------------------------------------------------------------ */
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_128
static void test_ccm_length_limits(void)
{
    uint8_t key[16];
    uint8_t nonce[13];
    uint8_t aad[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[16];
    static const uint32_t bad_aad[] = { 0xFFFFFFEBU, 0xFFFFFFF0U, 0xFFFFFFFAU, 0xFFFFFFFBU, 0xFFFFFFFFU };
    uint32_t i;

    cs_section("AES-CCM AAD/payload length limits");
    cs_fill(key, sizeof(key), 0x11U);
    cs_fill(nonce, sizeof(nonce), 0x12U);
    cs_fill(aad, sizeof(aad), 0x13U);
    cs_fill(pt, sizeof(pt), 0x14U);
    for (i = 0U; i < (uint32_t)(sizeof(bad_aad) / sizeof(bad_aad[0])); i += 1U) {
        /* The AAD buffer is only 16 bytes: a correct implementation must
         * reject the length before touching it. */
        CHECK_RC(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, aad, bad_aad[i],
                                        pt, sizeof(pt), ct, tag, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
        CHECK_RC(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, aad, bad_aad[i],
                                        ct, sizeof(ct), tag, 16U, pt),
                 NOXTLS_RETURN_INVALID_PARAM);
    }
    /* Payload past UINT32_MAX - 15 (L = 4 allows a 32-bit length). */
    CHECK_RC(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 11U, aad, 4U,
                                    pt, 0xFFFFFFF1U, ct, tag, 16U),
             NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 11U, aad, 4U,
                                    ct, 0xFFFFFFF1U, tag, 16U, pt),
             NOXTLS_RETURN_INVALID_PARAM);
    /* Normal lengths still round-trip. */
    CHECK_RC(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, aad, sizeof(aad),
                                    pt, sizeof(pt), ct, tag, 16U), NOXTLS_RETURN_SUCCESS);
    {
        uint8_t back[16];
        CHECK_RC(noxtls_aes_ccm_decrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, aad, sizeof(aad),
                                        ct, sizeof(ct), tag, 16U, back), NOXTLS_RETURN_SUCCESS);
        EXPECT_MEM("ccm round trip", back, pt, 16U);
    }
}
#endif

/* ------------------------------------------------------------------------ */
/* AES streaming context wipes                                               */
/* ------------------------------------------------------------------------ */
#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_128
static void test_aes_context_wipes(void)
{
    static noxtls_aes_context_t ctx;
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t buf[32];
    uint8_t out[48];
    uint32_t olen = 0U;

    cs_section("AES context wiped on init/final errors");
    cs_fill(key, sizeof(key), 0x21U);
    cs_fill(iv, sizeof(iv), 0x22U);
    cs_fill(buf, sizeof(buf), 0x23U);
#if NOXTLS_FEATURE_AES_CTR
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK_RC(noxtls_aes_init(&ctx, key, NULL, NOXTLS_AES_128_BIT, NOXTLS_AES_CTR, NOXTLS_AES_OP_ENCRYPT),
             NOXTLS_RETURN_INVALID_PARAM);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
#endif
#if NOXTLS_FEATURE_AES_OFB
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK(noxtls_aes_init(&ctx, key, NULL, NOXTLS_AES_128_BIT, NOXTLS_AES_OFB, NOXTLS_AES_OP_ENCRYPT)
          != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
#endif
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    CHECK(noxtls_aes_init(&ctx, key, iv, NOXTLS_AES_128_BIT, (noxtls_aes_mode_t)77U, NOXTLS_AES_OP_ENCRYPT)
          != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
#if NOXTLS_FEATURE_AES_CBC
    /* Truncated ciphertext: final reports the error and drops the schedule. */
    CHECK_RC(noxtls_aes_init(&ctx, key, iv, NOXTLS_AES_128_BIT, NOXTLS_AES_CBC, NOXTLS_AES_OP_DECRYPT),
             NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_aes_update(&ctx, buf, 20U, out, &olen), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_aes_final(&ctx, out, &olen), NOXTLS_RETURN_INVALID_BLOCK_SIZE);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
    /* Abandoned context: noxtls_aes_free(). */
    CHECK_RC(noxtls_aes_init(&ctx, key, iv, NOXTLS_AES_128_BIT, NOXTLS_AES_CBC, NOXTLS_AES_OP_ENCRYPT),
             NOXTLS_RETURN_SUCCESS);
    CHECK(!cs_all_zero(&ctx, sizeof(ctx)));
    noxtls_aes_free(&ctx);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
    noxtls_aes_free(NULL);
#endif
    /* Final on a context whose init failed: still wiped. */
    (void)memset(&ctx, 0xA5, sizeof(ctx));
    ctx.initialized = 0U;
    CHECK_RC(noxtls_aes_final(&ctx, out, &olen), NOXTLS_RETURN_NOT_INITIALIZED);
    CHECK(cs_all_zero(&ctx, sizeof(ctx)));
}
#endif

/* ------------------------------------------------------------------------ */
/* Message length beyond 2^32 bytes                                         */
/* ------------------------------------------------------------------------ */

/* Serialise chaining words as a digest. */
static void sh_words_out(const uint32_t *h, uint32_t n, int big_endian, uint8_t *out)
{
    uint32_t i;
    for (i = 0U; i < n; i += 1U) {
        if (big_endian != 0) {
            out[4U * i] = (uint8_t)(h[i] >> 24);
            out[4U * i + 1U] = (uint8_t)(h[i] >> 16);
            out[4U * i + 2U] = (uint8_t)(h[i] >> 8);
            out[4U * i + 3U] = (uint8_t)h[i];
        } else {
            out[4U * i] = (uint8_t)h[i];
            out[4U * i + 1U] = (uint8_t)(h[i] >> 8);
            out[4U * i + 2U] = (uint8_t)(h[i] >> 16);
            out[4U * i + 3U] = (uint8_t)(h[i] >> 24);
        }
    }
}

/*
 * MD-family check: X absorbs a 64-byte block after claiming 2^32 - 64 bytes,
 * plus a 3-byte tail, so its total is 2^32 + 3 bytes. Y absorbs the same
 * block and then an explicit final block tail || 0x80 || 0 || bitlen(2^32+3).
 */
static void sh_md32_length_case(const char *name, noxtls_hash_algos_t algo, uint32_t words,
                                int big_endian_words, int big_endian_len)
{
    static noxtls_sha_ctx_t x;
    static noxtls_sha_ctx_t y;
    uint8_t block[64];
    uint8_t tail[3];
    uint8_t pad[64];
    uint8_t got[64];
    uint8_t exp[64];
    uint64_t bits = ((uint64_t)1U << 32) * 8U + 3U * 8U;
    uint32_t i;

    cs_section(name);
    cs_fill(block, sizeof(block), 0x31U + (uint32_t)algo);
    cs_fill(tail, sizeof(tail), 0x41U + (uint32_t)algo);

    CHECK_RC(noxtls_sha_init(&x, algo), NOXTLS_RETURN_SUCCESS);
    x.u.md32.length = (uint64_t)0xFFFFFFC0U; /* 2^32 - 64 bytes already absorbed */
    CHECK_RC(noxtls_sha_update(&x, block, 64U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_sha_update(&x, tail, 3U), NOXTLS_RETURN_SUCCESS);
    CHECK(x.u.md32.length == ((uint64_t)1U << 32));
    CHECK_RC(noxtls_sha_finish(&x, got), NOXTLS_RETURN_SUCCESS);

    CHECK_RC(noxtls_sha_init(&y, algo), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_sha_update(&y, block, 64U), NOXTLS_RETURN_SUCCESS);
    (void)memset(pad, 0, sizeof(pad));
    memcpy(pad, tail, 3U);
    pad[3] = 0x80U;
    for (i = 0U; i < 8U; i += 1U) {
        uint8_t b = (uint8_t)(bits >> (8U * i));
        if (big_endian_len != 0) {
            pad[63U - i] = b;
        } else {
            pad[56U + i] = b;
        }
    }
    CHECK_RC(noxtls_sha_update(&y, pad, 64U), NOXTLS_RETURN_SUCCESS);
    sh_words_out(y.u.md32.h, words, big_endian_words, exp);
    EXPECT_MEM("digest past 4 GiB", got, exp, 4U * words);
}

#if NOXTLS_FEATURE_SHA512
static void test_sha512_length(void)
{
    static noxtls_sha512_ctx_t x;
    static noxtls_sha512_ctx_t y;
    uint8_t block[128];
    uint8_t tail[5];
    uint8_t pad[128];
    uint8_t got[64];
    uint8_t exp[64];
    uint64_t bits = ((uint64_t)1U << 32) * 8U + 5U * 8U;
    uint32_t i;

    cs_section("SHA-512 length past 4 GiB");
    cs_fill(block, sizeof(block), 0x51U);
    cs_fill(tail, sizeof(tail), 0x52U);
    CHECK_RC(noxtls_sha512_init(&x, NOXTLS_HASH_SHA_512), NOXTLS_RETURN_SUCCESS);
    x.length = (uint64_t)0xFFFFFF80U; /* 2^32 - 128 */
    CHECK_RC(noxtls_sha512_update(&x, block, 128U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_sha512_update(&x, tail, 5U), NOXTLS_RETURN_SUCCESS);
    CHECK(x.length == ((uint64_t)1U << 32));
    CHECK_RC(noxtls_sha512_finish(&x, got), NOXTLS_RETURN_SUCCESS);

    CHECK_RC(noxtls_sha512_init(&y, NOXTLS_HASH_SHA_512), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_sha512_update(&y, block, 128U), NOXTLS_RETURN_SUCCESS);
    (void)memset(pad, 0, sizeof(pad));
    memcpy(pad, tail, 5U);
    pad[5] = 0x80U;
    for (i = 0U; i < 8U; i += 1U) {
        pad[127U - i] = (uint8_t)(bits >> (8U * i));
    }
    CHECK_RC(noxtls_sha512_update(&y, pad, 128U), NOXTLS_RETURN_SUCCESS);
    for (i = 0U; i < 64U; i += 1U) {
        exp[i] = (uint8_t)(y.h[i / 8U] >> (56U - 8U * (i % 8U)));
    }
    EXPECT_MEM("digest past 4 GiB", got, exp, 64U);
}
#endif

static void test_md_lengths(void)
{
#if NOXTLS_FEATURE_MD5
    sh_md32_length_case("MD5 length past 4 GiB", NOXTLS_HASH_MD5, 4U, 0, 0);
#endif
#if NOXTLS_FEATURE_SHA1
    sh_md32_length_case("SHA-1 length past 4 GiB", NOXTLS_HASH_SHA1, 5U, 1, 1);
#endif
#if NOXTLS_FEATURE_SHA256
    sh_md32_length_case("SHA-256 length past 4 GiB", NOXTLS_HASH_SHA_256, 8U, 1, 1);
#endif
#if NOXTLS_FEATURE_RIPEMD160
    sh_md32_length_case("RIPEMD-160 length past 4 GiB", NOXTLS_HASH_RIPEMD160, 5U, 0, 0);
#endif
#if NOXTLS_FEATURE_SHA512
    test_sha512_length();
#endif
}

/* ------------------------------------------------------------------------ */
/* Dead-stack residue                                                        */
/* ------------------------------------------------------------------------ */

#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_ECB && NOXTLS_FEATURE_AES_128
static uint8_t g_trace[40][16];

static void sh_expect_aes_schedule_absent(const char *what, const uint8_t *key, uint32_t nk)
{
    uint8_t rk[15][16];
    uint32_t r;
    ref_expand(key, nk, nk + 6U, rk);
    for (r = 0U; r <= nk + 6U; r += 1U) {
        sh_expect_words_absent(what, rk[r], 16U);
    }
}

static void test_residue_aes(void)
{
    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t exp[16];
    uint32_t i;

    cs_section("residue: AES-128 ECB encrypt (round keys, round states)");
    cs_fill(key, sizeof(key), 0x61U);
    cs_fill(pt, sizeof(pt), 0x62U);
    g_ref_trace = g_trace;
    g_ref_trace_n = 0U;
    ref_encrypt(key, 4U, pt, exp);
    g_ref_trace = NULL;
    sh_paint();
    (void)noxtls_aes_encrypt_ecb(key, pt, 16U, NULL, ct, NOXTLS_AES_128_BIT);
    sh_snapshot();
    EXPECT_MEM("ecb encrypt", ct, exp, 16U);
    sh_expect_aes_schedule_absent("AES-128 round key word", key, 4U);
    for (i = 0U; i < g_ref_trace_n; i += 1U) {
        sh_expect_words_absent("AES-128 encrypt round state", g_trace[i], 16U);
    }

    cs_section("residue: AES-128 ECB decrypt (round keys, round states)");
    g_ref_trace = g_trace;
    g_ref_trace_n = 0U;
    ref_decrypt(key, 4U, ct, exp);
    g_ref_trace = NULL;
    sh_paint();
    (void)noxtls_aes_decrypt_ecb(key, ct, 16U, NULL, pt, NOXTLS_AES_128_BIT);
    sh_snapshot();
    EXPECT_MEM("ecb decrypt", pt, exp, 16U);
    sh_expect_aes_schedule_absent("AES-128 round key word", key, 4U);
    for (i = 0U; i < g_ref_trace_n; i += 1U) {
        sh_expect_words_absent("AES-128 decrypt round state", g_trace[i], 16U);
    }

#if NOXTLS_FEATURE_AES_256
    {
        uint8_t key256[32];
        cs_section("residue: AES-256 ECB encrypt (raw key, round keys)");
        cs_fill(key256, sizeof(key256), 0x63U);
        sh_paint();
        (void)noxtls_aes_encrypt_ecb(key256, pt, 16U, NULL, ct, NOXTLS_AES_256_BIT);
        sh_snapshot();
        sh_expect_aes_schedule_absent("AES-256 round key word", key256, 8U);
    }
#endif

#if NOXTLS_FEATURE_AES_GCM
    {
        uint8_t nonce[12];
        uint8_t msg[37];
        uint8_t out[37];
        uint8_t tag[16];
        cs_section("residue: AES-128-GCM encrypt (round keys)");
        cs_fill(nonce, sizeof(nonce), 0x64U);
        cs_fill(msg, sizeof(msg), 0x65U);
        sh_paint();
        (void)noxtls_aes_gcm_encrypt(key, NOXTLS_AES_128_BIT, nonce, NULL, 0U, msg, sizeof(msg), out, tag);
        sh_snapshot();
        sh_expect_aes_schedule_absent("AES-128 round key word", key, 4U);
    }
#endif
}
#endif

#if NOXTLS_FEATURE_AES_CMAC && NOXTLS_FEATURE_AES_128 && NOXTLS_FEATURE_AES_ECB
static void test_residue_cmac(void)
{
    uint8_t key[16];
    uint8_t msg[16];
    uint8_t zero[16];
    uint8_t l[16];
    uint8_t k1[16];
    uint8_t masked[16];
    uint8_t mac[16];
    uint32_t i;

    cs_section("residue: AES-CMAC one block (K1, M ^ K1)");
    cs_fill(key, sizeof(key), 0x71U);
    cs_fill(msg, sizeof(msg), 0x72U);
    (void)memset(zero, 0, sizeof(zero));
    ref_encrypt(key, 4U, zero, l);
    for (i = 0U; i < 16U; i += 1U) {
        k1[i] = (uint8_t)((l[i] << 1) | ((i < 15U) ? (l[i + 1U] >> 7) : 0U));
    }
    if ((l[0] & 0x80U) != 0U) {
        k1[15] ^= 0x87U;
    }
    for (i = 0U; i < 16U; i += 1U) {
        masked[i] = (uint8_t)(msg[i] ^ k1[i]);
    }
    sh_paint();
    (void)noxtls_aes_cmac(key, msg, 16U, mac, NOXTLS_AES_128_BIT);
    sh_snapshot();
    for (i = 0U; i < 16U; i += 8U) {
        sh_expect_absent("CMAC subkey K1", &k1[i], 8U);
        sh_expect_absent("CMAC M_last ^ K1", &masked[i], 8U);
        sh_expect_absent("CMAC L = E(K, 0)", &l[i], 8U);
    }
}
#endif

#if NOXTLS_FEATURE_CHACHA20_POLY1305
static uint32_t sh_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* r limbs, 5*r limbs and s words of a Poly1305 one-time key. */
static void sh_expect_poly_key_absent(const uint8_t *k)
{
    uint32_t r[5];
    uint32_t i;
    r[0] = sh_le32(&k[0]) & 0x3ffffffU;
    r[1] = (sh_le32(&k[3]) >> 2) & 0x3ffff03U;
    r[2] = (sh_le32(&k[6]) >> 4) & 0x3ffc0ffU;
    r[3] = (sh_le32(&k[9]) >> 6) & 0x3f03fffU;
    r[4] = (sh_le32(&k[12]) >> 8) & 0x00fffffU;
    for (i = 0U; i < 5U; i += 1U) {
        sh_expect_u32_absent("Poly1305 r limb", r[i]);
        if (i > 0U) {
            sh_expect_u32_absent("Poly1305 5*r limb", r[i] * 5U);
        }
    }
    for (i = 0U; i < 4U; i += 1U) {
        sh_expect_u32_absent("Poly1305 s word", sh_le32(&k[16U + 4U * i]));
    }
}

static void test_residue_poly1305(void)
{
    uint8_t key[32];
    uint8_t msg[100];
    uint8_t tag[16];

    cs_section("residue: noxtls_poly1305_mac (r, 5r, s)");
    cs_fill(key, sizeof(key), 0x81U);
    cs_fill(msg, sizeof(msg), 0x82U);
    sh_paint();
    (void)noxtls_poly1305_mac(key, msg, sizeof(msg), tag);
    sh_snapshot();
    sh_expect_poly_key_absent(key);

    {
        uint8_t akey[32];
        uint8_t nonce[12];
        uint8_t zeros[32];
        uint8_t otk[32];
        uint8_t ct[100];
        cs_section("residue: ChaCha20-Poly1305 encrypt (one-time key r, 5r, s)");
        cs_fill(akey, sizeof(akey), 0x83U);
        cs_fill(nonce, sizeof(nonce), 0x84U);
        (void)memset(zeros, 0, sizeof(zeros));
        CHECK_RC(noxtls_chacha20_encrypt(akey, nonce, 0U, zeros, 32U, otk), NOXTLS_RETURN_SUCCESS);
        sh_paint();
        (void)noxtls_chacha20_poly1305_encrypt(akey, nonce, msg, 13U, msg, sizeof(msg), ct, tag);
        sh_snapshot();
        sh_expect_poly_key_absent(otk);
    }
}
#endif

#if NOXTLS_FEATURE_RC4
static void test_residue_rc4(void)
{
    static noxtls_rc4_context_t ref;
    uint8_t key[16];
    uint8_t msg[40];
    uint8_t out[40];
    uint8_t scratch[40];
    uint32_t i;

    cs_section("residue: RC4 one-shot (final permutation)");
    cs_fill(key, sizeof(key), 0x91U);
    cs_fill(msg, sizeof(msg), 0x92U);
    CHECK_RC(noxtls_rc4_init(&ref, key, sizeof(key)), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_rc4_process(&ref, msg, scratch, sizeof(msg)), NOXTLS_RETURN_SUCCESS);
    sh_paint();
    (void)noxtls_rc4_encrypt(key, sizeof(key), msg, sizeof(msg), out);
    sh_snapshot();
    EXPECT_MEM("rc4 output", out, scratch, sizeof(out));
    for (i = 0U; i < 256U; i += 16U) {
        sh_expect_absent("RC4 permutation window", &ref.S[i], 16U);
    }
}
#endif

#if NOXTLS_FEATURE_HMAC
static void sh_hmac_case(const char *name, noxtls_hash_algos_t algo, uint32_t block_len)
{
    uint8_t key[32];
    uint8_t msg[50];
    uint8_t mac[64];
    uint8_t ipad[32];
    uint8_t opad[32];
    uint32_t mac_len = sizeof(mac);
    uint32_t i;

    (void)block_len;
    cs_section(name);
    cs_fill(key, sizeof(key), 0xA1U + (uint32_t)algo);
    cs_fill(msg, sizeof(msg), 0xA2U);
    for (i = 0U; i < 32U; i += 1U) {
        ipad[i] = (uint8_t)(key[i] ^ 0x36U);
        opad[i] = (uint8_t)(key[i] ^ 0x5CU);
    }
    sh_paint();
    (void)noxtls_hmac_compute(algo, key, sizeof(key), msg, sizeof(msg), mac, &mac_len);
    sh_snapshot();
    sh_expect_words_absent("HMAC key ^ ipad (message schedule)", ipad, 32U);
    sh_expect_words_absent("HMAC key ^ opad (message schedule)", opad, 32U);
}

static void test_residue_hmac(void)
{
#if NOXTLS_FEATURE_SHA256
    sh_hmac_case("residue: HMAC-SHA256 key pads", NOXTLS_HASH_SHA_256, 64U);
#endif
#if NOXTLS_FEATURE_SHA1
    sh_hmac_case("residue: HMAC-SHA1 key pads", NOXTLS_HASH_SHA1, 64U);
#endif
#if NOXTLS_FEATURE_SHA512
    sh_hmac_case("residue: HMAC-SHA512 key pads", NOXTLS_HASH_SHA_512, 128U);
#endif
#if NOXTLS_FEATURE_MD5
    sh_hmac_case("residue: HMAC-MD5 key pads", NOXTLS_HASH_MD5, 64U);
#endif
}
#endif

static void test_residue_digests(void)
{
    uint8_t secret[64];
    uint8_t digest[64];

    cs_fill(secret, sizeof(secret), 0xB1U);
    (void)memset(digest, 0x5A, sizeof(digest));
#if NOXTLS_FEATURE_MD5
    cs_section("residue: noxtls_md5_verify on a secret block");
    sh_paint();
    (void)noxtls_md5_verify(secret, sizeof(secret), digest);
    sh_snapshot();
    sh_expect_words_absent("MD5 message word", secret, sizeof(secret));
#endif
#if NOXTLS_FEATURE_RIPEMD160
    cs_section("residue: noxtls_ripemd160_verify on a secret block");
    sh_paint();
    (void)noxtls_ripemd160_verify(secret, sizeof(secret), digest);
    sh_snapshot();
    sh_expect_words_absent("RIPEMD-160 message word", secret, sizeof(secret));
#endif
#if NOXTLS_FEATURE_SHA256
    cs_section("residue: noxtls_sha256_verify on a secret block");
    sh_paint();
    (void)noxtls_sha256_verify(secret, sizeof(secret), digest);
    sh_snapshot();
    sh_expect_words_absent("SHA-256 message schedule word", secret, sizeof(secret));
#endif
#if NOXTLS_FEATURE_SHA1
    cs_section("residue: noxtls_sha1_verify on a secret block");
    sh_paint();
    (void)noxtls_sha1_verify(secret, sizeof(secret), digest);
    sh_snapshot();
    sh_expect_words_absent("SHA-1 message schedule word", secret, sizeof(secret));
#endif
#if NOXTLS_FEATURE_BLAKE2
    {
        static noxtls_sha_ctx_t b2;
        cs_section("residue: BLAKE2s over a secret block");
        sh_paint();
        (void)noxtls_sha_init(&b2, NOXTLS_HASH_BLAKE2S_256);
        (void)noxtls_sha_update(&b2, secret, sizeof(secret));
        (void)noxtls_sha_update(&b2, secret, 1U);
        sh_snapshot();
        sh_expect_words_absent("BLAKE2s message word", secret, sizeof(secret));
    }
#endif
#if NOXTLS_FEATURE_SHA3
    {
        static noxtls_sha3_ctx_t ref;
        uint8_t h[32];
        uint32_t i;
        cs_section("residue: noxtls_sha3_verify (Keccak state)");
        CHECK_RC(noxtls_sha3_256_init(&ref), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_sha3_update(&ref, secret, 32U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_sha3_finish(&ref, h), NOXTLS_RETURN_SUCCESS);
        sh_paint();
        (void)noxtls_sha3_verify(secret, 32U, digest, NOXTLS_HASH_SHA3_256);
        sh_snapshot();
        for (i = 0U; i < 25U; i += 1U) {
            uint8_t lane[8];
            uint32_t k;
            for (k = 0U; k < 8U; k += 1U) {
                lane[k] = (uint8_t)(ref.state[i] >> (8U * k));
            }
            sh_expect_absent("SHA3-256 state lane", lane, 8U);
        }
    }
#endif
}

#if NOXTLS_FEATURE_ARIA || NOXTLS_FEATURE_CAMELLIA
static void sh_expect_key_absent(const char *what, const uint8_t *key, uint32_t len)
{
    uint32_t i;
    for (i = 0U; (i + 8U) <= len; i += 8U) {
        uint8_t rev[8];
        uint32_t k;
        for (k = 0U; k < 8U; k += 1U) {
            rev[k] = key[i + 7U - k];
        }
        sh_expect_absent(what, &key[i], 8U);
        sh_expect_absent(what, rev, 8U);
    }
}

static void test_residue_legacy(void)
{
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct[16];

    cs_fill(key, sizeof(key), 0xC1U);
    cs_fill(pt, sizeof(pt), 0xC2U);
#if NOXTLS_FEATURE_ARIA
    cs_section("residue: ARIA-256 ECB (raw key)");
    sh_paint();
    (void)noxtls_aria_encrypt_ecb(key, pt, 16U, NULL, ct, NOXTLS_ARIA_256_BIT);
    sh_snapshot();
    sh_expect_key_absent("ARIA-256 key", key, 32U);
#endif
#if NOXTLS_FEATURE_CAMELLIA
    cs_section("residue: Camellia-256 ECB (raw key words)");
    sh_paint();
    (void)noxtls_camellia_encrypt_ecb(key, pt, 16U, NULL, ct, NOXTLS_CAMELLIA_256_BIT);
    sh_snapshot();
    sh_expect_key_absent("Camellia-256 key", key, 32U);
#endif
}
#endif

int main(void)
{
#if NOXTLS_FEATURE_AES
    ref_build_sbox();
#endif
#if NOXTLS_FEATURE_AES_CCM && NOXTLS_FEATURE_AES_128
    test_ccm_length_limits();
#endif
#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_128
    test_aes_context_wipes();
#endif
    test_md_lengths();
#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_ECB && NOXTLS_FEATURE_AES_128
    test_residue_aes();
#endif
#if NOXTLS_FEATURE_AES_CMAC && NOXTLS_FEATURE_AES_128 && NOXTLS_FEATURE_AES_ECB
    test_residue_cmac();
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    test_residue_poly1305();
#endif
#if NOXTLS_FEATURE_RC4
    test_residue_rc4();
#endif
#if NOXTLS_FEATURE_HMAC
    test_residue_hmac();
#endif
    test_residue_digests();
#if NOXTLS_FEATURE_ARIA || NOXTLS_FEATURE_CAMELLIA
    test_residue_legacy();
#endif
    if (SH_RESIDUE_CHECKS == 0) {
        (void)printf("sym_hygiene_test: dead-stack residue checks skipped (AddressSanitizer build)\n");
    }
    (void)printf("sym_hygiene_test: %u checks, %u failures (%u residue hits)\n",
                 (unsigned)g_cs_checks, (unsigned)g_cs_failures, (unsigned)g_residue_hits);
    return (g_cs_failures == 0U) ? 0 : 1;
}
