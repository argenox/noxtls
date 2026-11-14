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
* File:    ecc_hardening_test.c
* Summary: Regression gate for the regular scalar multiplication, rejection-sampled
*          scalars and the shared-DRBG lock hook
*
*****************************************************************************/

/*
 * ecc_hardening_test checks, on every enabled curve:
 *   - scalar multiplication after the fixed-length recoding (ladder, window and comb
 *     paths) against independent group relations: k*G == (k-1)*G + G, 2^j*G by repeated
 *     doubling, (n-1)*G == -G, (n-k)*G == -(k*G), (a+b)*P == a*P + b*P for a variable
 *     base, and a non-canonical scalar n + 3 == 3;
 *   - noxtls_ecc_random_scalar(): range 0 < k < n and, on brainpoolP256r1, no modulo bias
 *     (the single-width reduction gave P(k < 2^256 - n) = 0.67 instead of 0.51);
 *   - ECDSA sign / verify round trips with the rejection-sampled nonce;
 *   - noxtls_drbg_set_lock_callbacks(): argument checks, balanced non-nested lock use,
 *     and concurrent draws from several threads returning no duplicate output;
 *   - strict DER parsing of ECDSA signatures;
 *   - EC-JPAKE (when compiled in): concurrent scalar draws with no shared DRBG state.
 * Exit code 0 = all checks passed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "pkc/noxtls_pkc_rng.h"
#if NOXTLS_FEATURE_ECDSA
#include "pkc/ecdsa/noxtls_ecdsa.h"
#endif
#if defined(ECC_HARDENING_HAVE_ECJPAKE)
#include "pake/noxtls_ecjpake_internal.h"
#endif

static unsigned s_failures = 0U;
static unsigned s_checks = 0U;

#define CHECK(cond, ...) do { \
    s_checks += 1U; \
    if (!(cond)) { \
        s_failures += 1U; \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

typedef struct {
    ecc_curve_t id;
    const char *name;
} curve_entry_t;

static const curve_entry_t s_curves[] = {
    { NOXTLS_ECC_SECP192R1, "secp192r1" },
    { NOXTLS_ECC_SECP224R1, "secp224r1" },
    { NOXTLS_ECC_SECP256R1, "secp256r1" },
    { NOXTLS_ECC_SECP384R1, "secp384r1" },
    { NOXTLS_ECC_SECP521R1, "secp521r1" },
    { NOXTLS_ECC_BP256R1,   "brainpoolP256r1" },
    { NOXTLS_ECC_BP384R1,   "brainpoolP384r1" },
    { NOXTLS_ECC_BP512R1,   "brainpoolP512r1" },
    { NOXTLS_ECC_SECP192K1, "secp192k1" },
    { NOXTLS_ECC_SECP224K1, "secp224k1" },
    { NOXTLS_ECC_SECP256K1, "secp256k1" },
};

/* ------------------------------------------------------------------------------------- */
/* Small big-endian helpers (test only).                                                  */
/* ------------------------------------------------------------------------------------- */

static uint32_t be_bit_length(const uint8_t *a, uint32_t len)
{
    uint32_t i;
    for (i = 0U; i < len; i++) {
        if (a[i] != 0U) {
            uint32_t bits = (len - i) * 8U;
            uint8_t top = a[i];
            while ((top & 0x80U) == 0U) {
                top = (uint8_t)(top << 1U);
                bits--;
            }
            return bits;
        }
    }
    return 0U;
}

/* a += v (small), returns carry out */
static uint32_t be_add_small(uint8_t *a, uint32_t len, uint32_t v)
{
    uint32_t i = len;
    uint32_t carry = v;
    while ((i > 0U) && (carry != 0U)) {
        uint32_t s = (uint32_t)a[i - 1U] + (carry & 0xFFU);
        a[i - 1U] = (uint8_t)s;
        carry = (carry >> 8U) + (s >> 8U);
        i--;
    }
    return carry;
}

/* Keep only bits below 'bits'. */
static void be_mask_bits(uint8_t *a, uint32_t len, uint32_t bits)
{
    uint32_t i;
    for (i = 0U; i < len; i++) {
        uint32_t bit_lo = (len - 1U - i) * 8U;
        if (bit_lo >= bits) {
            a[i] = 0U;
        } else if ((bit_lo + 8U) > bits) {
            a[i] = (uint8_t)(a[i] & (uint8_t)((1U << (bits - bit_lo)) - 1U));
        }
    }
}

static int point_eq(const ecc_point_t *a, const ecc_point_t *b, uint32_t size)
{
    return (memcmp(a->x, b->x, size) == 0) && (memcmp(a->y, b->y, size) == 0);
}

static int point_is_neg(const ecc_point_t *a, const ecc_point_t *b, const ecc_curve_params_t *c)
{
    uint8_t neg_y[ECC_MAX_KEY_SIZE];
    (void)noxtls_bn_sub(neg_y, c->p, b->y, c->size);
    return (memcmp(a->x, b->x, c->size) == 0) && (memcmp(a->y, neg_y, c->size) == 0);
}

static int mul(ecc_point_t *r, const uint8_t *k, const ecc_point_t *p, const ecc_curve_params_t *c)
{
    (void)noxtls_ecc_point_init(r, c->size);
    return noxtls_ecc_point_multiply(r, k, p, c) == NOXTLS_RETURN_SUCCESS;
}

static void scalar_small(uint8_t *k, uint32_t size, uint32_t v)
{
    memset(k, 0, size);
    (void)be_add_small(k, size, v);
}

static int random_bytes(uint8_t *out, uint32_t len)
{
    return noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, len * 8U) == NOXTLS_RETURN_SUCCESS;
}

/* ------------------------------------------------------------------------------------- */
/* Scalar multiplication relations                                                       */
/* ------------------------------------------------------------------------------------- */

static void test_curve_mul(const curve_entry_t *e)
{
    const ecc_curve_params_t *c = noxtls_ecc_curve_get(e->id);
    uint32_t size;
    uint32_t nlen;
    uint32_t n_bits;
    uint8_t k[ECC_MAX_KEY_SIZE];
    uint8_t k1[ECC_MAX_KEY_SIZE];
    uint8_t a[ECC_MAX_KEY_SIZE];
    uint8_t b[ECC_MAX_KEY_SIZE];
    ecc_point_t G1;
    ecc_point_t R;
    ecc_point_t S;
    ecc_point_t T;
    ecc_point_t P;
    uint32_t i;
    static const uint32_t small[] = { 2U, 3U, 5U, 15U, 16U, 17U, 31U, 32U, 255U, 256U, 4097U };

    if (c == NULL) {
        printf("skip %s (disabled)\n", e->name);
        return;
    }
    size = c->size;
    nlen = noxtls_ecc_curve_order_size(c);
    n_bits = be_bit_length(c->n, nlen);

    /* 1 * G */
    scalar_small(k, size, 1U);
    CHECK(mul(&G1, k, &c->G, c), "%s: 1*G", e->name);
    CHECK(point_eq(&G1, &c->G, size), "%s: 1*G != G", e->name);

    /* k*G == (k-1)*G + G for small k (all-zero leading bytes, zero windows) */
    for (i = 0U; i < (uint32_t)(sizeof(small) / sizeof(small[0])); i++) {
        scalar_small(k, size, small[i]);
        scalar_small(k1, size, small[i] - 1U);
        CHECK(mul(&R, k, &c->G, c), "%s: %u*G", e->name, small[i]);
        CHECK(mul(&S, k1, &c->G, c), "%s: %u*G", e->name, small[i] - 1U);
        (void)noxtls_ecc_point_init(&T, size);
        CHECK(noxtls_ecc_point_add(&T, &S, &c->G, c) == NOXTLS_RETURN_SUCCESS, "%s: add", e->name);
        CHECK(point_eq(&R, &T, size), "%s: %u*G != %u*G + G", e->name, small[i], small[i] - 1U);
    }

    /* 2^j * G by repeated doubling, for leading-zero-heavy scalars */
    {
        ecc_point_t D;
        uint32_t j;
        uint32_t targets[4];
        uint32_t t = 0U;
        targets[0] = 1U;
        targets[1] = 8U;
        targets[2] = 100U;
        targets[3] = ((n_bits - 1U) < (size * 8U)) ? (n_bits - 1U) : ((size * 8U) - 1U);
        D = c->G;
        for (j = 1U; j <= targets[3]; j++) {
            ecc_point_t D2;
            (void)noxtls_ecc_point_init(&D2, size);
            (void)noxtls_ecc_point_double(&D2, &D, c);
            D = D2;
            if ((t < 4U) && (j == targets[t])) {
                memset(k, 0, size);
                k[size - 1U - (j >> 3U)] = (uint8_t)(1U << (j & 7U));
                CHECK(mul(&R, k, &c->G, c), "%s: 2^%u*G", e->name, j);
                CHECK(point_eq(&R, &D, size), "%s: 2^%u*G mismatch", e->name, j);
                t++;
            }
        }
    }

    if (nlen == size) {
        /* (n-1)*G == -G, (n-2)*G == -(2G) */
        (void)noxtls_bn_copy(k, c->n, size);
        k[size - 1U] = (uint8_t)(k[size - 1U] - 1U);  /* n is odd: no borrow */
        CHECK(mul(&R, k, &c->G, c), "%s: (n-1)*G", e->name);
        CHECK(point_is_neg(&R, &c->G, c), "%s: (n-1)*G != -G", e->name);
        k[size - 1U] = (uint8_t)(k[size - 1U] - 1U);
        scalar_small(k1, size, 2U);
        CHECK(mul(&R, k, &c->G, c), "%s: (n-2)*G", e->name);
        CHECK(mul(&S, k1, &c->G, c), "%s: 2*G", e->name);
        CHECK(point_is_neg(&R, &S, c), "%s: (n-2)*G != -(2G)", e->name);

        /* Non-canonical scalar: (n + 3)*G == 3*G when n + 3 fits the coordinate size */
        (void)noxtls_bn_copy(k, c->n, size);
        if (be_add_small(k, size, 3U) == 0U) {
            scalar_small(k1, size, 3U);
            CHECK(mul(&R, k, &c->G, c), "%s: (n+3)*G", e->name);
            CHECK(mul(&S, k1, &c->G, c), "%s: 3*G", e->name);
            CHECK(point_eq(&R, &S, size), "%s: (n+3)*G != 3*G", e->name);
        }

        /* Random k: (n-k)*G == -(k*G) */
        for (i = 0U; i < 4U; i++) {
            CHECK(noxtls_ecc_random_scalar(k, c, NOXTLS_PKC_RNG_SLOT_ECC) == NOXTLS_RETURN_SUCCESS,
                  "%s: random scalar", e->name);
            (void)noxtls_bn_sub(k1, c->n, k, size);
            CHECK(mul(&R, k, &c->G, c), "%s: k*G", e->name);
            CHECK(mul(&S, k1, &c->G, c), "%s: (n-k)*G", e->name);
            CHECK(point_is_neg(&R, &S, c), "%s: (n-k)*G != -(k*G)", e->name);
        }
    }

    /* Variable base: P = k*G, then (a+b)*P == a*P + b*P with a + b < n */
    CHECK(random_bytes(k, size), "%s: rng", e->name);
    be_mask_bits(k, size, n_bits - 1U);
    k[size - 1U] |= 1U;
    CHECK(mul(&P, k, &c->G, c), "%s: P = k*G", e->name);
    for (i = 0U; i < 3U; i++) {
        CHECK(random_bytes(a, size) && random_bytes(b, size), "%s: rng", e->name);
        be_mask_bits(a, size, n_bits - 2U);
        be_mask_bits(b, size, n_bits - 2U);
        if (i == 1U) {
            /* many leading zero bits in one operand */
            be_mask_bits(a, size, 40U);
        }
        (void)noxtls_bn_add(k1, a, b, size);
        CHECK(mul(&R, a, &P, c), "%s: a*P", e->name);
        CHECK(mul(&S, b, &P, c), "%s: b*P", e->name);
        (void)noxtls_ecc_point_init(&T, size);
        CHECK(noxtls_ecc_point_add(&T, &R, &S, c) == NOXTLS_RETURN_SUCCESS, "%s: a*P + b*P", e->name);
        CHECK(mul(&R, k1, &P, c), "%s: (a+b)*P", e->name);
        CHECK(point_eq(&R, &T, size), "%s: (a+b)*P != a*P + b*P (case %u)", e->name, i);
    }
}

/* ------------------------------------------------------------------------------------- */
/* Rejection-sampled scalars and ECDSA                                                    */
/* ------------------------------------------------------------------------------------- */

static void test_random_scalar(const curve_entry_t *e)
{
    const ecc_curve_params_t *c = noxtls_ecc_curve_get(e->id);
    uint8_t k[ECC_MAX_KEY_SIZE];
    uint32_t nlen;
    uint32_t i;

    if (c == NULL) {
        return;
    }
    nlen = noxtls_ecc_curve_order_size(c);
    for (i = 0U; i < 200U; i++) {
        CHECK(noxtls_ecc_random_scalar(k, c, NOXTLS_PKC_RNG_SLOT_ECDSA) == NOXTLS_RETURN_SUCCESS,
              "%s: random scalar", e->name);
        CHECK(noxtls_bn_is_zero(k, nlen) == 0, "%s: zero scalar", e->name);
        CHECK(noxtls_bn_cmp(k, c->n, nlen) < 0, "%s: scalar >= n", e->name);
    }
    CHECK(noxtls_ecc_random_scalar(NULL, c, NOXTLS_PKC_RNG_SLOT_ECDSA) == NOXTLS_RETURN_NULL,
          "%s: NULL out", e->name);
}

static void test_bp256_bias(void)
{
#if NOXTLS_ECC_ENABLE_BP256R1
    const ecc_curve_params_t *c = noxtls_ecc_curve_get(NOXTLS_ECC_BP256R1);
    uint8_t threshold[32];
    uint8_t k[32];
    uint8_t zero[32];
    uint32_t below = 0U;
    uint32_t i;
    const uint32_t draws = 4000U;
    double frac;

    if (c == NULL) {
        return;
    }
    /* threshold = 2^256 - n; uniform P(k < threshold) = threshold / n = 0.506,
     * single-width reduction gives 2 * threshold / 2^256 = 0.672. */
    memset(zero, 0, sizeof(zero));
    (void)noxtls_bn_sub(threshold, zero, c->n, 32U);
    for (i = 0U; i < draws; i++) {
        (void)noxtls_ecc_random_scalar(k, c, NOXTLS_PKC_RNG_SLOT_ECDSA);
        if (noxtls_bn_cmp(k, threshold, 32U) < 0) {
            below++;
        }
    }
    frac = (double)below / (double)draws;
    printf("brainpoolP256r1 P(k < 2^256 - n) = %.4f (uniform 0.506, biased 0.672)\n", frac);
    CHECK((frac > 0.46) && (frac < 0.56), "brainpoolP256r1 nonce distribution biased: %.4f", frac);
#endif
}

#if NOXTLS_FEATURE_ECDSA
static void test_ecdsa(const curve_entry_t *e)
{
    const ecc_curve_params_t *c = noxtls_ecc_curve_get(e->id);
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint8_t digest[32];
    uint32_t i;

    if (c == NULL) {
        return;
    }
    memset(&key, 0, sizeof(key));
    CHECK(noxtls_ecc_key_generate(&key, e->id) == NOXTLS_RETURN_SUCCESS, "%s: keygen", e->name);
    for (i = 0U; i < 3U; i++) {
        memset(digest, (int)(0x30U + i), sizeof(digest));
        (void)noxtls_ecdsa_signature_init(&sig, c->size);
        CHECK(noxtls_ecdsa_sign_digest(&key, digest, sizeof(digest), &sig) == NOXTLS_RETURN_SUCCESS,
              "%s: sign", e->name);
        CHECK(noxtls_ecdsa_verify_digest(&key, digest, sizeof(digest), &sig) == NOXTLS_RETURN_SUCCESS,
              "%s: verify", e->name);
        digest[0] ^= 1U;
        CHECK(noxtls_ecdsa_verify_digest(&key, digest, sizeof(digest), &sig) != NOXTLS_RETURN_SUCCESS,
              "%s: verify of a modified digest", e->name);
        (void)noxtls_ecdsa_signature_free(&sig);
    }
    (void)noxtls_ecc_key_free(&key);
}
#endif


#if NOXTLS_FEATURE_ECDSA
/* Strict DER for noxtls_ecdsa_signature_parse_der() (completes issue 116). */
static void test_ecdsa_der_strict(void)
{
    static const uint8_t ok_min[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    static const uint8_t ok_pad[] = { 0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02 };
    static const uint8_t trailing[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00 };
    static const uint8_t nonmin_int[] = { 0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02 };
    static const uint8_t negative[] = { 0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02 };
    static const uint8_t long_len[] = { 0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    static const uint8_t three_ints[] = { 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03 };
    static const uint8_t short_seq[] = { 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    ecdsa_signature_t sig;

    CHECK(noxtls_ecdsa_signature_parse_der(ok_min, sizeof(ok_min), &sig, 32U) == NOXTLS_RETURN_SUCCESS,
          "DER: minimal signature rejected");
    CHECK((sig.r[31] == 1U) && (sig.s[31] == 2U), "DER: r/s decoded wrongly");
    CHECK(noxtls_ecdsa_signature_parse_der(ok_pad, sizeof(ok_pad), &sig, 32U) == NOXTLS_RETURN_SUCCESS,
          "DER: sign-octet 0x00 before 0x80 rejected");
    CHECK(sig.r[31] == 0x80U, "DER: padded r decoded wrongly");
    CHECK(noxtls_ecdsa_signature_parse_der(trailing, sizeof(trailing), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: trailing octet accepted");
    CHECK(noxtls_ecdsa_signature_parse_der(nonmin_int, sizeof(nonmin_int), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: non-minimal INTEGER accepted");
    CHECK(noxtls_ecdsa_signature_parse_der(negative, sizeof(negative), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: negative INTEGER accepted");
    CHECK(noxtls_ecdsa_signature_parse_der(long_len, sizeof(long_len), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: non-minimal length accepted");
    CHECK(noxtls_ecdsa_signature_parse_der(three_ints, sizeof(three_ints), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: third INTEGER accepted");
    CHECK(noxtls_ecdsa_signature_parse_der(short_seq, sizeof(short_seq), &sig, 32U) != NOXTLS_RETURN_SUCCESS,
          "DER: truncated SEQUENCE accepted");
}
#endif

/* ------------------------------------------------------------------------------------- */
/* Lock hook                                                                              */
/* ------------------------------------------------------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_mutex_t stats_mutex;
    unsigned locks;
    unsigned unlocks;
    int depth;
    int max_depth;
} lock_state_t;

static lock_state_t s_lock = {
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, 0U, 0U, 0, 0
};

static void test_lock(void *user)
{
    lock_state_t *l = (lock_state_t *)user;
    (void)pthread_mutex_lock(&l->mutex);
    (void)pthread_mutex_lock(&l->stats_mutex);
    l->locks++;
    l->depth++;
    if (l->depth > l->max_depth) {
        l->max_depth = l->depth;
    }
    (void)pthread_mutex_unlock(&l->stats_mutex);
}

static void test_unlock(void *user)
{
    lock_state_t *l = (lock_state_t *)user;
    (void)pthread_mutex_lock(&l->stats_mutex);
    l->unlocks++;
    l->depth--;
    (void)pthread_mutex_unlock(&l->stats_mutex);
    (void)pthread_mutex_unlock(&l->mutex);
}

#define THREADS 4
#define DRAWS_PER_THREAD 400

static uint8_t s_outputs[THREADS * DRAWS_PER_THREAD][32];

typedef struct {
    int index;
    int failed;
} worker_t;

static void *pkc_worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    int i;
    for (i = 0; i < DRAWS_PER_THREAD; i++) {
        if (noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECDSA,
                                    s_outputs[(w->index * DRAWS_PER_THREAD) + i], 256U) != NOXTLS_RETURN_SUCCESS) {
            w->failed = 1;
        }
    }
    return NULL;
}

static int cmp32(const void *a, const void *b)
{
    return memcmp(a, b, 32U);
}

static unsigned count_duplicates(void)
{
    unsigned dups = 0U;
    unsigned i;
    qsort(s_outputs, (size_t)(THREADS * DRAWS_PER_THREAD), 32U, cmp32);
    for (i = 1U; i < (unsigned)(THREADS * DRAWS_PER_THREAD); i++) {
        if (memcmp(s_outputs[i - 1U], s_outputs[i], 32U) == 0) {
            dups++;
        }
    }
    return dups;
}

static void run_threads(void *(*fn)(void *), const char *what)
{
    pthread_t th[THREADS];
    worker_t w[THREADS];
    int i;

    memset(s_outputs, 0, sizeof(s_outputs));
    for (i = 0; i < THREADS; i++) {
        w[i].index = i;
        w[i].failed = 0;
        CHECK(pthread_create(&th[i], NULL, fn, &w[i]) == 0, "%s: pthread_create", what);
    }
    for (i = 0; i < THREADS; i++) {
        (void)pthread_join(th[i], NULL);
        CHECK(w[i].failed == 0, "%s: worker %d failed", what, i);
    }
    CHECK(count_duplicates() == 0U, "%s: duplicate outputs across threads", what);
}

static void test_lock_hook(void)
{
    uint8_t out[32];

    /* Exactly one NULL callback is rejected. */
    CHECK(noxtls_drbg_set_lock_callbacks(test_lock, NULL, &s_lock) == NOXTLS_RETURN_INVALID_PARAM,
          "lock without unlock accepted");
    CHECK(noxtls_drbg_set_lock_callbacks(NULL, test_unlock, &s_lock) == NOXTLS_RETURN_INVALID_PARAM,
          "unlock without lock accepted");

    CHECK(noxtls_drbg_set_lock_callbacks(test_lock, test_unlock, &s_lock) == NOXTLS_RETURN_SUCCESS,
          "install lock");
    CHECK(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 256U) == NOXTLS_RETURN_SUCCESS,
          "generate under lock");
    CHECK(s_lock.locks > 0U, "lock not taken");

    run_threads(pkc_worker, "pkc drbg with lock");

#if NOXTLS_FEATURE_ECDSA && NOXTLS_ECC_ENABLE_SECP256R1
    test_ecdsa(&s_curves[2]);
#endif
    CHECK(s_lock.locks == s_lock.unlocks, "unbalanced lock use: %u locks, %u unlocks",
          s_lock.locks, s_lock.unlocks);
    CHECK(s_lock.max_depth == 1, "lock nested (depth %d)", s_lock.max_depth);

    CHECK(noxtls_drbg_set_lock_callbacks(NULL, NULL, NULL) == NOXTLS_RETURN_SUCCESS, "remove lock");
    {
        unsigned before = s_lock.locks;
        CHECK(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 256U) == NOXTLS_RETURN_SUCCESS,
              "generate without lock");
        CHECK(s_lock.locks == before, "removed lock still called");
    }
}

#if defined(ECC_HARDENING_HAVE_ECJPAKE)
static void *ecjpake_worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    int i;
    for (i = 0; i < DRAWS_PER_THREAD; i++) {
        if (noxtls_ecjpake_random_scalar(s_outputs[(w->index * DRAWS_PER_THREAD) + i]) != NOXTLS_RETURN_SUCCESS) {
            w->failed = 1;
        }
    }
    return NULL;
}
#endif

int main(void)
{
    uint32_t i;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0U; i < (uint32_t)(sizeof(s_curves) / sizeof(s_curves[0])); i++) {
        printf("curve %s\n", s_curves[i].name);
        test_curve_mul(&s_curves[i]);
        test_random_scalar(&s_curves[i]);
#if NOXTLS_FEATURE_ECDSA
        test_ecdsa(&s_curves[i]);
#endif
    }
    test_bp256_bias();
#if NOXTLS_FEATURE_ECDSA
    test_ecdsa_der_strict();
#endif
    printf("lock hook\n");
    test_lock_hook();
#if defined(ECC_HARDENING_HAVE_ECJPAKE)
    /* No lock installed: EC-JPAKE keeps no shared DRBG state. */
    run_threads(ecjpake_worker, "ecjpake scalars without lock");
#endif

    printf("ecc_hardening_test: %u checks, %u failures\n", s_checks, s_failures);
    return (s_failures == 0U) ? 0 : 1;
}
