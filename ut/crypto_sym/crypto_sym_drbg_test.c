/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_drbg_test.c
* Summary: CTR_DRBG regression tests (public API only).
*
* Pins the output of drbg_instantiate_ex / drbg_generate / drbg_reseed for fully
* deterministic inputs (caller-supplied entropy, so the platform entropy source
* is never consulted) against the SP 800-90A Rev.1 CTR_DRBG model in
* tools/sp800_90a_ctr_drbg.py, which tools/gen_drbg_cavp_vectors.py validates
* against all 4320 AES vectors of the NIST CAVP CTR_DRBG files. The NIST
* vectors themselves are checked by crypto_sym_drbg_sp800_90a_test.
*
* These cases add what CAVP does not exercise: output sizes 16, 64, 100 and
* 1000 bytes, a 12-bit request (leftmost bits), entropy input and nonce
* lengths other than the CAVP ones, personalization and additional input
* longer than seedlen (df variant), reseed with and without additional input,
* AES-128/192/256 with the derivation function and without (DRBG_FLAG_NO_DF).
* Also: noxtls_drbg_uninstantiate zeroes every byte of drbg_state_t and
* drbg_generate / drbg_reseed fail afterwards.
* Expected values: crypto_sym_drbg_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"

#include "crypto_sym_test_util.h"
#include "crypto_sym_drbg_vectors.h"

#define CS_ARRAY_LEN(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

static uint8_t g_out[1100];

/* PRNG(len, seed) into buf; returns buf, or NULL for len 0 (the API gets NULL). */
static const uint8_t *opt_buf(uint8_t *buf, uint32_t len, uint32_t seed)
{
    if (len == 0U) {
        return NULL;
    }
    cs_fill(buf, len, seed);
    return buf;
}

static uint32_t seedlen_of(uint32_t aes_type)
{
    return (aes_type == DRBG_AES128) ? 32U : ((aes_type == DRBG_AES192) ? 40U : 48U);
}

static int aes_type_enabled(uint32_t aes_type)
{
    if (aes_type == DRBG_AES128) {
        return NOXTLS_FEATURE_AES_128;
    }
    if (aes_type == DRBG_AES192) {
        return NOXTLS_FEATURE_AES_192;
    }
    return NOXTLS_FEATURE_AES_256;
}

static void check_output(const char *what, const uint8_t *out, uint32_t nbits, const char *head, const char *tail)
{
    uint32_t nbytes = (nbits + 7U) / 8U;
    uint32_t n = (nbytes < 64U) ? nbytes : 64U;
    (void)EXPECT_HEX(what, out, n, head);
    (void)EXPECT_HEX(what, &out[nbytes - n], n, tail);
    CHECK(out[nbytes] == 0xEEU);
}

static void test_cases(void)
{
    static drbg_state_t st;
    uint8_t entropy[64];
    uint8_t nonce[32];
    uint8_t pers[128];
    uint8_t add[128];
    uint32_t i;
    int run;

    for (i = 0U; i < CS_ARRAY_LEN(k_drbg_cases); i += 1U) {
        const cs_drbg_case_t *tc = &k_drbg_cases[i];
        if (aes_type_enabled(tc->aes_type) == 0) {
            continue;
        }
        /* run 0: fresh zeroed state; run 1: state reused after uninstantiate of a different instance. */
        for (run = 0; run < 2; run += 1) {
            cs_section(tc->name);
            if (run == 0) {
                (void)memset(&st, 0, sizeof(st));
            } else {
                (void)memset(&st, 0xA5, sizeof(st));
            }
            CHECK_RC(drbg_instantiate_ex(&st, tc->aes_type, tc->flags,
                                         opt_buf(entropy, tc->entropy_len, tc->entropy_seed), tc->entropy_len,
                                         opt_buf(nonce, tc->nonce_len, tc->nonce_seed), tc->nonce_len,
                                         opt_buf(pers, tc->pers_len, tc->pers_seed), tc->pers_len),
                     NOXTLS_RETURN_SUCCESS);
            (void)memset(g_out, 0xEE, sizeof(g_out));
            CHECK_RC(drbg_generate(&st, g_out, tc->gen1_bits, opt_buf(add, tc->add1_len, tc->add1_seed), tc->add1_len),
                     NOXTLS_RETURN_SUCCESS);
            check_output("generate #1", g_out, tc->gen1_bits, tc->out1_head, tc->out1_tail);
            CHECK_RC(drbg_reseed(&st, opt_buf(entropy, seedlen_of(tc->aes_type), tc->reseed_entropy_seed),
                                 seedlen_of(tc->aes_type), opt_buf(add, tc->reseed_add_len, tc->reseed_add_seed),
                                 tc->reseed_add_len),
                     NOXTLS_RETURN_SUCCESS);
            (void)memset(g_out, 0xEE, sizeof(g_out));
            CHECK_RC(drbg_generate(&st, g_out, tc->gen2_bits, opt_buf(add, tc->add2_len, tc->add2_seed), tc->add2_len),
                     NOXTLS_RETURN_SUCCESS);
            check_output("generate #2", g_out, tc->gen2_bits, tc->out2_head, tc->out2_tail);

            /* Uninstantiate: every byte of the state is zero, further use fails. */
            CHECK_RC(noxtls_drbg_uninstantiate(&st), NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_zero(&st, sizeof(st)));
            (void)memset(g_out, 0xEE, sizeof(g_out));
            CHECK(drbg_generate(&st, g_out, 128U, NULL, 0U) != NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_byte(g_out, 16U, 0xEEU) || cs_all_zero(g_out, 16U));
            CHECK(drbg_reseed(&st, entropy, sizeof(entropy), NULL, 0U) != NOXTLS_RETURN_SUCCESS);
            CHECK(cs_all_zero(&st, sizeof(st)));
        }
    }
}

/* Two instances interleaved must not influence each other. */
static void test_independent_instances(void)
{
#if NOXTLS_FEATURE_AES_256 && NOXTLS_FEATURE_AES_128
    static drbg_state_t a;
    static drbg_state_t b;
    const cs_drbg_case_t *ta = &k_drbg_cases[0];
    const cs_drbg_case_t *tb = &k_drbg_cases[3];
    uint8_t entropy[64];
    uint8_t out_b[16];

    cs_section("interleaved instances");
    CHECK_RC(drbg_instantiate(&a, ta->aes_type, opt_buf(entropy, ta->entropy_len, ta->entropy_seed), ta->entropy_len,
                              NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_instantiate(&b, tb->aes_type, opt_buf(entropy, tb->entropy_len, tb->entropy_seed), tb->entropy_len,
                              NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&b, out_b, tb->gen1_bits, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(drbg_generate(&a, g_out, ta->gen1_bits, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    check_output("instance A", g_out, ta->gen1_bits, ta->out1_head, ta->out1_tail);
    (void)EXPECT_HEX("instance B", out_b, 16U, tb->out1_head);
    CHECK_RC(noxtls_drbg_uninstantiate(&a), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(noxtls_drbg_uninstantiate(&b), NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&a, sizeof(a)));
    CHECK(cs_all_zero(&b, sizeof(b)));
#endif
}

int main(void)
{
    test_cases();
    test_independent_instances();
    return cs_finish("crypto_sym_drbg_test");
}
