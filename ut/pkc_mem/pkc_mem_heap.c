/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    pkc_mem_heap.c
* Summary: Heap-peak regression gate for the classic PKC operations
*
*****************************************************************************/

/*
 * pkc_mem_heap: per-operation heap peak / held / leak gate.
 *
 * How the numbers are obtained
 *   The executable compiles its own copy of noxtls-lib/common/noxtls_memory.c with
 *   NOXTLS_USE_STATIC_BUFFERS=1 and NOXTLS_STATIC_ALLOCATOR_MODE=0 (the LEGACY first-fit
 *   pool, the same allocator the PKC audit numbers were taken with), so "bytes in use" is
 *   the pool's payload accounting (noxtls_mem_get_stats total_used; block headers are not
 *   counted). That copy is built with its public allocation entry points renamed to
 *   pkc_mem_pool_* (see CMakeLists.txt) and this file provides noxtls_malloc_at /
 *   noxtls_calloc_at / noxtls_free / ... as thin wrappers around them. The wrappers read
 *   total_used after every allocation, which yields a resettable per-operation high-water
 *   mark and allocation counters without re-initializing the pool between operations
 *   (re-initializing would corrupt any state a library cache might still hold).
 *   The PKC libraries are the normal ones from the build: nothing in them depends on
 *   NOXTLS_USE_STATIC_BUFFERS.
 *
 * Per operation (each runs twice; the larger figures are kept):
 *   peak       highest bytes in use during the operation, relative to the start
 *   held       bytes in use just before the operation releases its keys (what a caller
 *              keeps while it holds the key, e.g. an ephemeral ECDHE key in TLS)
 *   live_after bytes still in use after everything was freed: must be 0
 *   allocs     number of successful allocations (pass 1), largest = largest request
 * The test fails if an operation fails, leaks, has no threshold, or exceeds its
 * peak/held threshold. Thresholds live in g_thresholds below (measured + 10 %, rounded
 * up). Regenerate them with `pkc_mem_heap --print-thresholds`, which prints the rows
 * ready to paste (thresholds are then not enforced). Operations of features or curves
 * that are compiled out are skipped; table rows for them are ignored.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "mdigest/noxtls_hash.h"
#include "pkc_mem_data.h"

#if PKC_MEM_HAVE_ECC
#include "pkc/ecc/noxtls_ecc.h"
#endif
#if PKC_MEM_HAVE_ECDSA
#include "pkc/ecdsa/noxtls_ecdsa.h"
#endif
#if PKC_MEM_HAVE_ECDH
#include "pkc/ecdh/noxtls_ecdh.h"
#endif
#if PKC_MEM_HAVE_RSA
#include "pkc/rsa/noxtls_rsa.h"
#endif
#if PKC_MEM_HAVE_X25519
#include "pkc/x25519/noxtls_x25519.h"
#endif
#if PKC_MEM_HAVE_X448
#include "pkc/x448/noxtls_x448.h"
#endif
#if PKC_MEM_HAVE_ED25519
#include "pkc/ed25519/noxtls_ed25519.h"
#endif
#if PKC_MEM_HAVE_DH
#include "pkc/dh/noxtls_dh.h"
#endif

/* With the opt-in global ECC precompute cache (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE=1) the
 * library deliberately retains tables after ECC operations: ECC rows are then reported but
 * not gated (the thresholds describe the default, cache-off configuration). */
#if PKC_MEM_HAVE_ECC && defined(NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE) && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define PKC_MEM_ECC_CACHE_RETAINS 1
#else
#define PKC_MEM_ECC_CACHE_RETAINS 0
#endif

/** @brief 1 for operations that exercise the short Weierstrass ECC code. */
static int is_ecc_op(const char *name)
{
    return ((strncmp(name, "p256", 4U) == 0) || (strncmp(name, "p384", 4U) == 0) ||
            (strncmp(name, "p521", 4U) == 0) || (strncmp(name, "tls_", 4U) == 0)) ? 1 : 0;
}

/* ------------------------------------------------------------------ thresholds */
typedef struct
{
    const char *name;
    uint32_t peak_max;  /**< bytes */
    uint32_t held_max;  /**< bytes */
} pkc_mem_threshold_t;

/* Measured + 10 % (rounded up); regenerate with `pkc_mem_heap --print-thresholds`.
 * Baseline: default host configuration (x86_64, every curve enabled so ECC_MAX_KEY_SIZE 66,
 * read-only P-256 tables, no global ECC precompute cache). Values are payload bytes of the
 * static pool; builds with fewer curves (smaller ECC_MAX_KEY_SIZE) measure less. */
static const pkc_mem_threshold_t g_thresholds[] = {
    { "p256_ecdsa_verify", 2262U, 36U },
    { "p256_keygen", 819U, 36U },
    { "p256_keygen_ecdh", 3072U, 36U },
    { "p256_ecdsa_sign", 1320U, 36U },
    { "tls_p256_eph_ecdh_2verify", 3072U, 36U },
    { "p384_ecdsa_verify", 3872U, 53U },
    { "p384_keygen", 3432U, 53U },
    { "p384_keygen_ecdh", 3432U, 53U },
    { "p384_ecdsa_sign", 4145U, 53U },
    { "p521_ecdsa_verify", 1364U, 80U },
    { "p521_keygen", 80U, 80U },
    { "p521_keygen_ecdh", 80U, 80U },
    { "p521_ecdsa_sign", 1734U, 80U },
    { "rsa2048_verify", 3529U, 1549U },
    { "rsa2048_verify_pubkey", 2271U, 291U },
    { "rsa2048_sign", 5782U, 1549U },
    { "rsa2048_sign_nocrt", 8598U, 1549U },
    { "rsa2048_sign_pss", 5782U, 1549U },
    { "rsa2048_verify_pss", 2271U, 291U },
    { "rsa2048_decrypt", 5782U, 1549U },
    { "rsa2048_decrypt_crt_only", 5782U, 1549U },
    { "rsa3072_verify", 5289U, 2324U },
    { "rsa3072_verify_pubkey", 3397U, 432U },
    { "rsa3072_sign", 8668U, 2324U },
    { "rsa3072_sign_nocrt", 12892U, 2324U },
    { "rsa3072_sign_pss", 8668U, 2324U },
    { "rsa3072_verify_pss", 3397U, 432U },
    { "rsa3072_decrypt", 8668U, 2324U },
    { "rsa3072_decrypt_crt_only", 8668U, 2324U },
    { "rsa4096_verify", 7049U, 3098U },
    { "rsa4096_verify_pubkey", 4524U, 572U },
    { "rsa4096_sign", 11555U, 3098U },
    { "rsa4096_sign_nocrt", 17187U, 3098U },
    { "rsa4096_sign_pss", 11555U, 3098U },
    { "rsa4096_verify_pss", 4524U, 572U },
    { "rsa4096_decrypt", 11555U, 3098U },
    { "rsa4096_decrypt_crt_only", 11555U, 3098U },
    { "x25519_2keygen_shared", 0U, 0U },
    { "x448_2keygen_shared", 0U, 0U },
    { "ed25519_keygen", 0U, 0U },
    { "ed25519_sign", 0U, 0U },
    { "ed25519_verify", 0U, 0U },
    { "ffdhe2048_keygen", 6768U, 0U },
    { "ffdhe2048_shared", 6486U, 0U },
};

/* ------------------------------------------------------------------ allocator wrappers */
void *pkc_mem_pool_malloc_at(size_t size, const char *file, uint32_t line, const char *function);
void *pkc_mem_pool_malloc(size_t size);
void *pkc_mem_pool_calloc_at(size_t nmemb, size_t size, const char *file, uint32_t line, const char *function);
void *pkc_mem_pool_calloc(size_t nmemb, size_t size);
void *pkc_mem_pool_realloc_at(void *ptr, size_t size, const char *file, uint32_t line, const char *function);
void *pkc_mem_pool_realloc(void *ptr, size_t size);
void pkc_mem_pool_free(void *ptr);

static uint64_t g_pool[(512U * 1024U) / sizeof(uint64_t)];
static size_t g_peak;     /* high-water mark of total_used since the last reset */
static size_t g_allocs;   /* successful allocations since the last reset */
static size_t g_largest;  /* largest request since the last reset */

/** @brief Bytes currently in use in the pool. */
static size_t pool_used(void)
{
    size_t used = 0U;
    (void)noxtls_mem_get_stats(NULL, &used, NULL);
    return used;
}

/** @brief Account one allocation result. */
static void *note_alloc(void *p, size_t request)
{
    if(p != NULL) {
        const size_t used = pool_used();
        g_allocs++;
        if(request > g_largest) {
            g_largest = request;
        }
        if(used > g_peak) {
            g_peak = used;
        }
    }
    return p;
}

void *noxtls_malloc_at(size_t size, const char *file, uint32_t line, const char *function)
{
    return note_alloc(pkc_mem_pool_malloc_at(size, file, line, function), size);
}

void *noxtls_malloc(size_t size)
{
    return note_alloc(pkc_mem_pool_malloc(size), size);
}

void *noxtls_calloc_at(size_t nmemb, size_t size, const char *file, uint32_t line, const char *function)
{
    return note_alloc(pkc_mem_pool_calloc_at(nmemb, size, file, line, function), nmemb * size);
}

void *noxtls_calloc(size_t nmemb, size_t size)
{
    return note_alloc(pkc_mem_pool_calloc(nmemb, size), nmemb * size);
}

void *noxtls_realloc_at(void *ptr, size_t size, const char *file, uint32_t line, const char *function)
{
    /* A moving realloc briefly holds both blocks: count that transient as well. */
    const size_t before = pool_used();
    void *p = pkc_mem_pool_realloc_at(ptr, size, file, line, function);
    if((p != NULL) && ((before + size) > g_peak)) {
        g_peak = before + size;
    }
    return note_alloc(p, size);
}

void *noxtls_realloc(void *ptr, size_t size)
{
    return noxtls_realloc_at(ptr, size, NULL, 0U, NULL);
}

void noxtls_free(void *ptr)
{
    pkc_mem_pool_free(ptr);
}

/* ------------------------------------------------------------------ measurement */
typedef int (*pkc_mem_op_fn_t)(void);

typedef struct
{
    const char *name;
    size_t peak;
    size_t held;
    size_t live_after;
    size_t allocs;
    size_t largest;
    int ok;
} pkc_mem_result_t;

#define MAX_RESULTS 64U
static pkc_mem_result_t g_results[MAX_RESULTS];
static uint32_t g_result_count;

#if PKC_MEM_HAVE_ANY
static size_t g_base;      /* bytes in use when the current operation started */
static size_t g_held;      /* bytes in use at the operation's mark_held() point */

#if PKC_MEM_HAVE_ECC_CURVES || PKC_MEM_HAVE_RSA
/** @brief Called by an operation right before it releases its keys. */
static void mark_held(void)
{
    const size_t used = pool_used();
    g_held = (used > g_base) ? (used - g_base) : 0U;
}
#endif

/** @brief Run @p fn twice and record the larger peak / held figures. */
static void run_op(const char *name, pkc_mem_op_fn_t fn)
{
    pkc_mem_result_t *r;
    uint32_t pass;

    if(g_result_count >= MAX_RESULTS) {
        fprintf(stderr, "too many operations\n");
        exit(2);
    }
    r = &g_results[g_result_count];
    g_result_count++;
    (void)memset(r, 0, sizeof(*r));
    r->name = name;
    r->ok = 1;
    for(pass = 0U; pass < 2U; pass++) {
        size_t after;
        g_base = pool_used();
        g_peak = g_base;
        g_allocs = 0U;
        g_largest = 0U;
        g_held = 0U;
        if(fn() == 0) {
            r->ok = 0;
        }
        after = pool_used();
        if((g_peak - g_base) > r->peak) {
            r->peak = g_peak - g_base;
        }
        if(g_held > r->held) {
            r->held = g_held;
        }
        if((after > g_base) && ((after - g_base) > r->live_after)) {
            r->live_after = after - g_base;
        }
        if(pass == 0U) {
            r->allocs = g_allocs;
        }
        if(g_largest > r->largest) {
            r->largest = g_largest;
        }
    }
}

#endif /* PKC_MEM_HAVE_ANY */

/* ------------------------------------------------------------------ ECC operations */
#if PKC_MEM_HAVE_ECC_CURVES
typedef struct
{
    const char *tag;       /* threshold-name prefix */
    ecc_curve_t id;
    uint32_t size;
    uint32_t bits;
    const pkc_mem_ecc_keypair_t *kp;
    const pkc_mem_ecdsa_kat_t *sig;  /* RFC 6979 SHA-256 "sample" */
} heap_curve_t;

static heap_curve_t g_curve;      /* curve of the operation being run */
static uint8_t g_d[66];
static uint8_t g_qx[66];
static uint8_t g_qy[66];
static uint8_t g_r[66];
static uint8_t g_s[66];

/** @brief Select a curve and decode its RFC 6979 key and SHA-256 "sample" signature. */
static int curve_setup(const char *tag, ecc_curve_t id, uint32_t size, uint32_t bits)
{
    uint32_t i;
    (void)memset(&g_curve, 0, sizeof(g_curve));
    g_curve.tag = tag;
    g_curve.id = id;
    g_curve.size = size;
    g_curve.bits = bits;
    for(i = 0U; i < PKC_MEM_RFC6979_KEY_COUNT; i++) {
        if(pkc_mem_rfc6979_keys[i].curve_bits == bits) {
            g_curve.kp = &pkc_mem_rfc6979_keys[i];
        }
    }
    for(i = 0U; i < PKC_MEM_ECDSA_KAT_COUNT; i++) {
        const pkc_mem_ecdsa_kat_t *v = &pkc_mem_ecdsa_kats[i];
        if((g_curve.sig == NULL) && (v->curve_bits == bits) && (v->hash_bits == 256U) && (v->expect_valid != 0U) &&
           (strcmp(v->msg, "73616d706c65") == 0)) {
            g_curve.sig = v;
        }
    }
    return (g_curve.kp != NULL) && (g_curve.sig != NULL) &&
           pkc_mem_unhex_fixed(g_d, size, g_curve.kp->d) && pkc_mem_unhex_fixed(g_qx, size, g_curve.kp->qx) &&
           pkc_mem_unhex_fixed(g_qy, size, g_curve.kp->qy) && pkc_mem_unhex_fixed(g_r, size, g_curve.sig->r) &&
           pkc_mem_unhex_fixed(g_s, size, g_curve.sig->s);
}

#if PKC_MEM_HAVE_ECDSA
static const uint8_t g_sample[6] = { 's', 'a', 'm', 'p', 'l', 'e' };

/** @brief Certificate-style verify: fresh public key, verify, free. */
static int verify_fresh_key(int mark)
{
    ecc_key_t key;
    ecdsa_signature_t sig;
    int ok = (noxtls_ecc_key_init(&key, g_curve.id) == NOXTLS_RETURN_SUCCESS);
    if(ok) {
        (void)memcpy(key.Q.x, g_qx, g_curve.size);
        (void)memcpy(key.Q.y, g_qy, g_curve.size);
        key.Q.size = g_curve.size;
        (void)noxtls_ecdsa_signature_init(&sig, g_curve.size);
        (void)memcpy(sig.r, g_r, g_curve.size);
        (void)memcpy(sig.s, g_s, g_curve.size);
        ok = (noxtls_ecdsa_verify(&key, g_sample, 6U, &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        if(mark != 0) {
            mark_held();
        }
    }
    (void)noxtls_ecc_key_free(&key);
    return ok;
}

static int op_ecdsa_verify(void)
{
    return verify_fresh_key(1);
}

static int op_ecdsa_sign(void)
{
    ecc_key_t key;
    ecdsa_signature_t sig;
    int ok;
    (void)memset(&key, 0, sizeof(key));
    ok = (noxtls_ecc_key_import_private(&key, g_curve.id, g_d, g_curve.size) == NOXTLS_RETURN_SUCCESS);
    if(ok) {
        (void)noxtls_ecdsa_signature_init(&sig, g_curve.size);
        ok = (noxtls_ecdsa_sign(&key, g_sample, 6U, &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        mark_held();
    }
    (void)noxtls_ecc_key_free(&key);
    return ok;
}
#endif

static int op_keygen(void)
{
    ecc_key_t key;
    int ok;
    (void)memset(&key, 0, sizeof(key));
    ok = (noxtls_ecc_key_generate(&key, g_curve.id) == NOXTLS_RETURN_SUCCESS);
    mark_held();
    (void)noxtls_ecc_key_free(&key);
    return ok;
}

#if PKC_MEM_HAVE_ECDH
/** @brief Ephemeral key + ECDH with the RFC 6979 public key; optionally keep the key. */
static int keygen_ecdh(ecc_key_t *eph)
{
    ecc_point_t peer;
    uint8_t z[66];
    uint32_t zl = (uint32_t)sizeof(z);
    (void)memset(eph, 0, sizeof(*eph));
    (void)memset(&peer, 0, sizeof(peer));
    (void)memcpy(peer.x, g_qx, g_curve.size);
    (void)memcpy(peer.y, g_qy, g_curve.size);
    peer.size = g_curve.size;
    if(noxtls_ecc_key_generate(eph, g_curve.id) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    return noxtls_ecdh_compute_shared_secret(eph, &peer, z, &zl) == NOXTLS_RETURN_SUCCESS;
}

static int op_keygen_ecdh(void)
{
    ecc_key_t eph;
    int ok = keygen_ecdh(&eph);
    mark_held();
    (void)noxtls_ecc_key_free(&eph);
    return ok;
}

#if PKC_MEM_HAVE_ECDSA && PKC_MEM_HAVE_P256
/** @brief TLS 1.3 client-like: ephemeral P-256 key alive across ECDH and two certificate verifies. */
static int op_tls_like(void)
{
    ecc_key_t eph;
    int ok = keygen_ecdh(&eph);
    ok = verify_fresh_key(0) && ok;
    ok = verify_fresh_key(0) && ok;
    mark_held();
    (void)noxtls_ecc_key_free(&eph);
    return ok;
}
#endif
#endif /* PKC_MEM_HAVE_ECDH */
#endif /* PKC_MEM_HAVE_ECC_CURVES */

/* ------------------------------------------------------------------ RSA operations */
#if PKC_MEM_HAVE_RSA
static const pkc_mem_rsa_kat_t *g_rsa;
static uint8_t g_rsa_msg[128];
static uint32_t g_rsa_msg_len;
static uint8_t g_rsa_s1[PKC_MEM_MAX_BYTES];
static uint8_t g_rsa_ps[PKC_MEM_MAX_BYTES];
static uint8_t g_rsa_ct[PKC_MEM_MAX_BYTES];
static uint8_t g_rsa_n[PKC_MEM_MAX_BYTES];
static uint8_t g_rsa_d[PKC_MEM_MAX_BYTES];
static uint8_t g_rsa_crt[5][PKC_MEM_MAX_BYTES / 2U];
static uint8_t g_rsa_out[PKC_MEM_MAX_BYTES];
static noxtls_hash_algos_t g_rsa_h1;
static noxtls_hash_algos_t g_rsa_hp;

static int rsa_setup(const pkc_mem_rsa_kat_t *v)
{
    const uint32_t kb = v->bits / 8U;
    const uint32_t hb = kb / 2U;
    g_rsa = v;
    g_rsa_msg_len = pkc_mem_unhex(g_rsa_msg, (uint32_t)sizeof(g_rsa_msg), v->msg);
    g_rsa_h1 = (v->pkcs1_hash_bits == 256U) ? NOXTLS_HASH_SHA_256 : ((v->pkcs1_hash_bits == 384U) ? NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_512);
    g_rsa_hp = (v->pss_hash_bits == 256U) ? NOXTLS_HASH_SHA_256 : ((v->pss_hash_bits == 384U) ? NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_512);
    return (g_rsa_msg_len != 0U) && pkc_mem_unhex_fixed(g_rsa_s1, kb, v->pkcs1_sig) && pkc_mem_unhex_fixed(g_rsa_ps, kb, v->pss_sig) &&
           pkc_mem_unhex_fixed(g_rsa_ct, kb, v->ct) && pkc_mem_unhex_fixed(g_rsa_n, kb, v->n) && pkc_mem_unhex_fixed(g_rsa_d, kb, v->d) &&
           pkc_mem_unhex_fixed(g_rsa_crt[0], hb, v->p) && pkc_mem_unhex_fixed(g_rsa_crt[1], hb, v->q) &&
           pkc_mem_unhex_fixed(g_rsa_crt[2], hb, v->dp) && pkc_mem_unhex_fixed(g_rsa_crt[3], hb, v->dq) &&
           pkc_mem_unhex_fixed(g_rsa_crt[4], hb, v->qi);
}

#define RSA_KEY_PUBLIC_FULL 0U  /* noxtls_rsa_key_init (all 8 buffers), n and e only */
#define RSA_KEY_PUBLIC_ONLY 1U  /* noxtls_rsa_key_init_public */
#define RSA_KEY_D_ONLY      2U  /* full key, d but no CRT components */
#define RSA_KEY_CRT         3U  /* full key with d and CRT components */

static int rsa_key(rsa_key_t *k, uint32_t kind)
{
    static const uint8_t e[3] = { 0x01U, 0x00U, 0x01U };
    const uint32_t kb = g_rsa->bits / 8U;
    const uint32_t hb = kb / 2U;
    if(kind == RSA_KEY_PUBLIC_ONLY) {
        return noxtls_rsa_key_init_public(k, g_rsa->bits, g_rsa_n, kb, e, 3U) == NOXTLS_RETURN_SUCCESS;
    }
    if(noxtls_rsa_key_init(k, g_rsa->bits) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    (void)memcpy(k->n, g_rsa_n, kb);  /* e = 65537 is the noxtls_rsa_key_init default */
    if(kind >= RSA_KEY_D_ONLY) {
        (void)memcpy(k->d, g_rsa_d, kb);
    }
    if(kind == RSA_KEY_CRT) {
        (void)memcpy(k->p, g_rsa_crt[0], hb);
        (void)memcpy(k->q, g_rsa_crt[1], hb);
        (void)memcpy(k->dp, g_rsa_crt[2], hb);
        (void)memcpy(k->dq, g_rsa_crt[3], hb);
        (void)memcpy(k->qi, g_rsa_crt[4], hb);
    }
    return 1;
}

static int rsa_verify_with(uint32_t kind)
{
    rsa_key_t k;
    int ok = rsa_key(&k, kind);
    if(ok) {
        ok = noxtls_rsa_verify(&k, g_rsa_msg, g_rsa_msg_len, g_rsa_s1, g_rsa->bits / 8U, g_rsa_h1) == NOXTLS_RETURN_SUCCESS;
        mark_held();
        (void)noxtls_rsa_key_free(&k);
    }
    return ok;
}

static int op_rsa_verify(void) { return rsa_verify_with(RSA_KEY_PUBLIC_FULL); }
static int op_rsa_verify_pub(void) { return rsa_verify_with(RSA_KEY_PUBLIC_ONLY); }

static int rsa_sign_with(uint32_t kind, int pss)
{
    rsa_key_t k;
    uint32_t ol = (uint32_t)sizeof(g_rsa_out);
    int ok = rsa_key(&k, kind);
    if(ok) {
        if(pss != 0) {
            ok = noxtls_rsa_sign_pss(&k, g_rsa_msg, g_rsa_msg_len, g_rsa_out, &ol, g_rsa_hp) == NOXTLS_RETURN_SUCCESS;
        } else {
            ok = (noxtls_rsa_sign(&k, g_rsa_msg, g_rsa_msg_len, g_rsa_out, &ol, g_rsa_h1) == NOXTLS_RETURN_SUCCESS) &&
                 (memcmp(g_rsa_out, g_rsa_s1, g_rsa->bits / 8U) == 0);
        }
        mark_held();
        (void)noxtls_rsa_key_free(&k);
    }
    return ok;
}

static int op_rsa_sign(void) { return rsa_sign_with(RSA_KEY_CRT, 0); }
static int op_rsa_sign_nocrt(void) { return rsa_sign_with(RSA_KEY_D_ONLY, 0); }
static int op_rsa_sign_pss(void) { return rsa_sign_with(RSA_KEY_CRT, 1); }

static int op_rsa_verify_pss(void)
{
    rsa_key_t k;
    int ok = rsa_key(&k, RSA_KEY_PUBLIC_ONLY);
    if(ok) {
        ok = noxtls_rsa_verify_pss(&k, g_rsa_msg, g_rsa_msg_len, g_rsa_ps, g_rsa->bits / 8U, g_rsa_hp) == NOXTLS_RETURN_SUCCESS;
        mark_held();
        (void)noxtls_rsa_key_free(&k);
    }
    return ok;
}

static int rsa_decrypt_with(int crt_only)
{
    rsa_key_t k;
    uint32_t ol = (uint32_t)sizeof(g_rsa_out);
    int ok = rsa_key(&k, RSA_KEY_CRT);
    if(ok) {
        if(crt_only != 0) {
            ok = noxtls_rsa_decrypt_crt_only(&k, g_rsa_ct, g_rsa->bits / 8U, g_rsa_out, &ol) == NOXTLS_RETURN_SUCCESS;
        } else {
            ok = noxtls_rsa_decrypt(&k, g_rsa_ct, g_rsa->bits / 8U, g_rsa_out, &ol) == NOXTLS_RETURN_SUCCESS;
        }
        mark_held();
        (void)noxtls_rsa_key_free(&k);
    }
    return ok;
}

static int op_rsa_decrypt(void) { return rsa_decrypt_with(0); }
static int op_rsa_decrypt_crt_only(void) { return rsa_decrypt_with(1); }
#endif /* PKC_MEM_HAVE_RSA */

/* ------------------------------------------------------------------ X25519 / X448 / Ed25519 / FFDHE */
#if PKC_MEM_HAVE_X25519
static int op_x25519(void)
{
    uint8_t a[32];
    uint8_t pa[32];
    uint8_t b[32];
    uint8_t pb[32];
    uint8_t z[32];
    int ok = (noxtls_x25519_generate_key(a, pa) == NOXTLS_RETURN_SUCCESS) && (noxtls_x25519_generate_key(b, pb) == NOXTLS_RETURN_SUCCESS) &&
             (noxtls_x25519_shared_secret(a, pb, z) == NOXTLS_RETURN_SUCCESS);
    noxtls_secure_zero(a, sizeof(a));
    noxtls_secure_zero(b, sizeof(b));
    return ok;
}
#endif

#if PKC_MEM_HAVE_X448
static int op_x448(void)
{
    uint8_t a[56];
    uint8_t pa[56];
    uint8_t b[56];
    uint8_t pb[56];
    uint8_t z[56];
    int ok = (noxtls_x448_generate_key(a, pa) == NOXTLS_RETURN_SUCCESS) && (noxtls_x448_generate_key(b, pb) == NOXTLS_RETURN_SUCCESS) &&
             (noxtls_x448_shared_secret(a, pb, z) == NOXTLS_RETURN_SUCCESS);
    noxtls_secure_zero(a, sizeof(a));
    noxtls_secure_zero(b, sizeof(b));
    return ok;
}
#endif

#if PKC_MEM_HAVE_ED25519
static uint8_t g_ed_sk[32];
static uint8_t g_ed_pk[32];
static uint8_t g_ed_msg[2];
static uint8_t g_ed_sig[64];
static uint8_t g_ed_out[64];

static int op_ed25519_keygen(void)
{
    uint8_t sk[32];
    uint8_t pk[32];
    int ok = noxtls_ed25519_generate_key(sk, pk) == NOXTLS_RETURN_SUCCESS;
    noxtls_secure_zero(sk, sizeof(sk));
    return ok;
}

static int op_ed25519_sign(void)
{
    return (noxtls_ed25519_sign(g_ed_sk, g_ed_msg, 2U, g_ed_out) == NOXTLS_RETURN_SUCCESS) && (memcmp(g_ed_out, g_ed_sig, 64U) == 0);
}

static int op_ed25519_verify(void)
{
    return noxtls_ed25519_verify(g_ed_pk, g_ed_msg, 2U, g_ed_sig) == NOXTLS_RETURN_SUCCESS;
}
#endif

#if PKC_MEM_HAVE_DH
#define PKC_MEM_FFDHE2048 ((uint16_t)0x0100U) /* TLS NamedGroup ffdhe2048 (RFC 7919) */
static uint8_t g_dh_x[256];
static uint8_t g_dh_y[256];
static uint8_t g_dh_peer_x[256];
static uint8_t g_dh_peer_y[256];
static uint8_t g_dh_z[256];

static int op_ffdhe_keygen(void)
{
    return noxtls_dh_ffdhe_generate_ephemeral(PKC_MEM_FFDHE2048, g_dh_x, g_dh_y) == NOXTLS_RETURN_SUCCESS;
}

static int op_ffdhe_shared(void)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t pl = 0U;
    return (noxtls_dh_ffdhe_params(PKC_MEM_FFDHE2048, &p, &g, &pl) == NOXTLS_RETURN_SUCCESS) &&
           (noxtls_dh_ffdhe_validate_client_key_share(PKC_MEM_FFDHE2048, g_dh_peer_y, pl) == NOXTLS_RETURN_SUCCESS) &&
           (noxtls_dh_shared_secret(g_dh_x, pl, g_dh_peer_y, pl, p, pl, g_dh_z) == NOXTLS_RETURN_SUCCESS);
}
#endif

/* ------------------------------------------------------------------ driver */
static const pkc_mem_threshold_t *find_threshold(const char *name)
{
    size_t i;
    for(i = 0U; i < (sizeof(g_thresholds) / sizeof(g_thresholds[0])); i++) {
        if(strcmp(g_thresholds[i].name, name) == 0) {
            return &g_thresholds[i];
        }
    }
    return NULL;
}

/** @brief measured + 10 %, rounded up. */
static uint32_t with_margin(size_t v)
{
    return (uint32_t)(((v * 11U) + 9U) / 10U);
}

#if PKC_MEM_HAVE_ECC_CURVES || PKC_MEM_HAVE_RSA
static char g_names[MAX_RESULTS][48];
static uint32_t g_name_count;

/** @brief Stable "<tag>_<op>" name for a per-curve / per-key-size operation. */
static const char *op_name(const char *tag, const char *op)
{
    char *n = g_names[g_name_count % MAX_RESULTS];
    g_name_count++;
    (void)snprintf(n, sizeof(g_names[0]), "%s_%s", tag, op);
    return n;
}
#endif

#if PKC_MEM_HAVE_ECC_CURVES
static void run_curve(const char *tag, ecc_curve_t id, uint32_t size, uint32_t bits)
{
    if(curve_setup(tag, id, size, bits) == 0) {
        fprintf(stderr, "FAIL: %s vector setup\n", tag);
        exit(1);
    }
#if PKC_MEM_HAVE_ECDSA
    run_op(op_name(tag, "ecdsa_verify"), op_ecdsa_verify);
#endif
    run_op(op_name(tag, "keygen"), op_keygen);
#if PKC_MEM_HAVE_ECDH
    run_op(op_name(tag, "keygen_ecdh"), op_keygen_ecdh);
#endif
#if PKC_MEM_HAVE_ECDSA
    run_op(op_name(tag, "ecdsa_sign"), op_ecdsa_sign);
#endif
}
#endif

int main(int argc, char **argv)
{
    const int print_thresholds = (argc > 1) && (strcmp(argv[1], "--print-thresholds") == 0);
    uint32_t i;
    int failed = 0;

    if((argc > 1) && (print_thresholds == 0)) {
        fprintf(stderr, "usage: %s [--print-thresholds]\n", argv[0]);
        return 2;
    }
    if(noxtls_mem_init((uint8_t *)(void *)g_pool, sizeof(g_pool)) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "noxtls_mem_init failed (static allocator not compiled in?)\n");
        return 2;
    }

#if PKC_MEM_HAVE_ECC_CURVES
#if PKC_MEM_HAVE_P256
    run_curve("p256", NOXTLS_ECC_SECP256R1, 32U, 256U);
#if PKC_MEM_HAVE_ECDH && PKC_MEM_HAVE_ECDSA
    run_op("tls_p256_eph_ecdh_2verify", op_tls_like);
#endif
#endif
#if PKC_MEM_HAVE_P384
    run_curve("p384", NOXTLS_ECC_SECP384R1, 48U, 384U);
#endif
#if PKC_MEM_HAVE_P521
    run_curve("p521", NOXTLS_ECC_SECP521R1, 66U, 521U);
#endif
#endif
#if PKC_MEM_HAVE_RSA
    for(i = 0U; i < PKC_MEM_RSA_KAT_COUNT; i++) {
        static char tags[PKC_MEM_RSA_KAT_COUNT][16];
        const pkc_mem_rsa_kat_t *v = &pkc_mem_rsa_kats[i];
        if((v->bits > RSA_MAX_KEY_SIZE) || (((v->pkcs1_hash_bits == 384U) || (v->pss_hash_bits == 384U)) && !PKC_MEM_HAVE_SHA384) ||
           (((v->pkcs1_hash_bits == 512U) || (v->pss_hash_bits == 512U)) && !PKC_MEM_HAVE_SHA512)) {
            continue;
        }
        if(rsa_setup(v) == 0) {
            fprintf(stderr, "FAIL: RSA-%u vector setup\n", (unsigned)v->bits);
            return 1;
        }
        (void)snprintf(tags[i], sizeof(tags[i]), "rsa%u", (unsigned)v->bits);
        run_op(op_name(tags[i], "verify"), op_rsa_verify);
        run_op(op_name(tags[i], "verify_pubkey"), op_rsa_verify_pub);
        run_op(op_name(tags[i], "sign"), op_rsa_sign);
        run_op(op_name(tags[i], "sign_nocrt"), op_rsa_sign_nocrt);
        run_op(op_name(tags[i], "sign_pss"), op_rsa_sign_pss);
        run_op(op_name(tags[i], "verify_pss"), op_rsa_verify_pss);
        run_op(op_name(tags[i], "decrypt"), op_rsa_decrypt);
        run_op(op_name(tags[i], "decrypt_crt_only"), op_rsa_decrypt_crt_only);
    }
#endif
#if PKC_MEM_HAVE_X25519
    run_op("x25519_2keygen_shared", op_x25519);
#endif
#if PKC_MEM_HAVE_X448
    run_op("x448_2keygen_shared", op_x448);
#endif
#if PKC_MEM_HAVE_ED25519
    if((pkc_mem_unhex(g_ed_sk, 32U, pkc_mem_ed25519_t3_sk) != 32U) || (pkc_mem_unhex(g_ed_pk, 32U, pkc_mem_ed25519_t3_pk) != 32U) ||
       (pkc_mem_unhex(g_ed_msg, 2U, pkc_mem_ed25519_t3_msg) != 2U) || (pkc_mem_unhex(g_ed_sig, 64U, pkc_mem_ed25519_t3_sig) != 64U)) {
        return 1;
    }
    run_op("ed25519_keygen", op_ed25519_keygen);
    run_op("ed25519_sign", op_ed25519_sign);
    run_op("ed25519_verify", op_ed25519_verify);
#endif
#if PKC_MEM_HAVE_DH
    if(noxtls_dh_ffdhe_generate_ephemeral(PKC_MEM_FFDHE2048, g_dh_peer_x, g_dh_peer_y) != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }
    run_op("ffdhe2048_keygen", op_ffdhe_keygen);
    run_op("ffdhe2048_shared", op_ffdhe_shared);
#endif

    printf("%-28s %8s %8s %10s %8s %8s %9s %9s  %s\n", "operation", "peak", "held", "live_after", "allocs", "largest",
           "peak_max", "held_max", "status");
    for(i = 0U; i < g_result_count; i++) {
        const pkc_mem_result_t *r = &g_results[i];
        const pkc_mem_threshold_t *t = find_threshold(r->name);
        const char *status = "ok";
        if(r->ok == 0) {
            status = "FAIL (operation failed)";
        } else if((PKC_MEM_ECC_CACHE_RETAINS != 0) && (is_ecc_op(r->name) != 0)) {
            status = "info (ECC cache retains tables)";
        } else if(r->live_after != 0U) {
            status = "FAIL (leak)";
        } else if(print_thresholds != 0) {
            status = "-";
        } else if(t == NULL) {
            status = "FAIL (no threshold)";
        } else if(r->peak > (size_t)t->peak_max) {
            status = "FAIL (peak over threshold)";
        } else if(r->held > (size_t)t->held_max) {
            status = "FAIL (held over threshold)";
        } else {
            /* within thresholds */
        }
        if(status[0] == 'F') {
            failed = 1;
        }
        printf("%-28s %8lu %8lu %10lu %8lu %8lu ", r->name, (unsigned long)r->peak, (unsigned long)r->held,
               (unsigned long)r->live_after, (unsigned long)r->allocs, (unsigned long)r->largest);
        if(t != NULL) {
            printf("%9u %9u  %s\n", (unsigned)t->peak_max, (unsigned)t->held_max, status);
        } else {
            printf("%9s %9s  %s\n", "-", "-", status);
        }
    }
    if(print_thresholds != 0) {
        printf("\n/* Measured + 10 %% (rounded up); regenerate with `pkc_mem_heap --print-thresholds`. */\n");
        printf("static const pkc_mem_threshold_t g_thresholds[] = {\n");
        for(i = 0U; i < g_result_count; i++) {
            printf("    { \"%s\", %uU, %uU },\n", g_results[i].name, (unsigned)with_margin(g_results[i].peak),
                   (unsigned)with_margin(g_results[i].held));
        }
        printf("};\n");
    }
    (void)noxtls_mem_cleanup();
    printf("pkc_mem_heap: %u operations, %s\n", (unsigned)g_result_count, (failed != 0) ? "FAILED" : "passed");
    return (failed != 0) ? 1 : 0;
}
