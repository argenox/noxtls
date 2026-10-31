/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_drbg_sp800_90a_test.c
* Summary: CTR_DRBG conformance with NIST SP 800-90A Rev.1 (CAVP vectors).
*
* 1. NIST CAVP CTR_DRBG vectors (CAVS 14.3; AES-128/192/256, use df and no df,
*    with and without personalization string and additional input, from
*    drbgvectors_no_reseed, _pr_false and _pr_true): the subset in
*    crypto_sym_drbg_cavp_vectors.h (see tools/gen_drbg_cavp_vectors.py for
*    provenance). Every vector is run three ways:
*      a. explicit inputs through drbg_instantiate_ex / drbg_reseed /
*         drbg_generate (prediction resistance as reseed + generate, 9.3.1);
*      b. pr_true vectors: an instance with DRBG_FLAG_PREDICTION_RESISTANCE whose
*         entropy source (custom callback) serves EntropyInputPR, checking the
*         lengths the library requests (security strength, or seedlen without df);
*      c. when entropy_input || nonce is 3/2 x security strength (df) or seedlen
*         (no df): instantiate (and reseed) with entropy drawn from the source.
*    With .rsp paths on the command line the complete files are parsed and
*    run instead (4320 AES vectors for the three CAVS 14.3 files).
* 2. SP 800-90A limits and states: reseed counter, reseed interval (automatic
*    reseed, 9.3.1), max_number_of_bits_per_request, input length rules for the
*    df and no-df variants, entropy-source failure, leftmost-bits truncation,
*    uninstantiate.
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"

#include "crypto_sym_test_util.h"
#include "crypto_sym_drbg_cavp_vectors.h"

#define CS_ARRAY_LEN(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))
#define CAVP_MAX (128U)

typedef struct {
    uint32_t aes_type;
    uint32_t no_df;
    uint32_t mode; /* 0 no_reseed, 1 pr_false, 2 pr_true */
    uint32_t returned_bits;
    uint8_t entropy[CAVP_MAX]; uint32_t entropy_len;
    uint8_t nonce[CAVP_MAX]; uint32_t nonce_len;
    uint8_t pers[CAVP_MAX]; uint32_t pers_len;
    uint8_t entropy_reseed[CAVP_MAX]; uint32_t entropy_reseed_len;
    uint8_t add_reseed[CAVP_MAX]; uint32_t add_reseed_len;
    uint8_t add1[CAVP_MAX]; uint32_t add1_len;
    uint8_t entropy_pr1[CAVP_MAX]; uint32_t entropy_pr1_len;
    uint8_t add2[CAVP_MAX]; uint32_t add2_len;
    uint8_t entropy_pr2[CAVP_MAX]; uint32_t entropy_pr2_len;
    uint8_t expected[CAVP_MAX]; uint32_t expected_len;
} cavp_case_t;

static cavp_case_t g_case;
static drbg_state_t g_st;
static uint8_t g_out[CAVP_MAX];

/* ---- scripted entropy source ------------------------------------------- */
typedef struct {
    const uint8_t *data;
    uint32_t len;
} ent_seg_t;

static ent_seg_t g_ent_queue[4];
static uint32_t g_ent_count;
static uint32_t g_ent_next;
static uint32_t g_ent_bad_len;
static uint32_t g_ent_calls;
static int g_ent_fail;
static uint8_t g_ent_concat[2U * CAVP_MAX];

static noxtls_return_t scripted_entropy(uint8_t *out, uint32_t len)
{
    g_ent_calls += 1U;
    if (g_ent_fail != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    if (g_ent_next >= g_ent_count) {
        g_ent_bad_len += 1U;
        return NOXTLS_RETURN_FAILED;
    }
    if (g_ent_queue[g_ent_next].len != len) {
        (void)fprintf(stderr, "    entropy request %u bytes, vector has %u\n", (unsigned)len,
                      (unsigned)g_ent_queue[g_ent_next].len);
        g_ent_bad_len += 1U;
        return NOXTLS_RETURN_FAILED;
    }
    (void)memcpy(out, g_ent_queue[g_ent_next].data, len);
    g_ent_next += 1U;
    return NOXTLS_RETURN_SUCCESS;
}

static void ent_script(const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    g_ent_count = 0U;
    g_ent_next = 0U;
    g_ent_bad_len = 0U;
    g_ent_calls = 0U;
    g_ent_fail = 0;
    if (a_len != 0U) {
        g_ent_queue[g_ent_count].data = a;
        g_ent_queue[g_ent_count].len = a_len;
        g_ent_count += 1U;
    }
    if (b_len != 0U) {
        g_ent_queue[g_ent_count].data = b;
        g_ent_queue[g_ent_count].len = b_len;
        g_ent_count += 1U;
    }
    noxtls_drbg_set_entropy_callback(scripted_entropy);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
}

static void ent_restore(void)
{
    noxtls_drbg_set_entropy_callback(NULL);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
}

static const uint8_t *opt(const uint8_t *p, uint32_t len)
{
    return (len != 0U) ? p : NULL;
}

static uint32_t keylen_of(uint32_t aes_type)
{
    return (aes_type == DRBG_AES128) ? 16U : ((aes_type == DRBG_AES192) ? 24U : 32U);
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

/* ---- one CAVP vector ---------------------------------------------------- */
static void finish_flow(const cavp_case_t *c, uint32_t pr_reseed_explicit)
{
    uint32_t bits = c->returned_bits;
    if (c->mode == 2U && pr_reseed_explicit != 0U) {
        /* 9.3.1 with prediction_resistance_request: Reseed(entropy_pr, add), Generate(Null). */
        CHECK_RC(drbg_reseed(&g_st, c->entropy_pr1, c->entropy_pr1_len, opt(c->add1, c->add1_len), c->add1_len),
                 NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_generate(&g_st, g_out, bits, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_reseed(&g_st, c->entropy_pr2, c->entropy_pr2_len, opt(c->add2, c->add2_len), c->add2_len),
                 NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_generate(&g_st, g_out, bits, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    } else {
        CHECK_RC(drbg_generate(&g_st, g_out, bits, opt(c->add1, c->add1_len), c->add1_len), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_generate(&g_st, g_out, bits, opt(c->add2, c->add2_len), c->add2_len), NOXTLS_RETURN_SUCCESS);
    }
    (void)EXPECT_MEM("ReturnedBits", g_out, c->expected, c->expected_len);
}

static void run_cavp_case(const cavp_case_t *c)
{
    uint32_t flags = (c->no_df != 0U) ? DRBG_FLAG_NO_DF : 0U;
    uint32_t keylen = keylen_of(c->aes_type);
    uint32_t internal_len = (c->no_df != 0U) ? (keylen + 16U) : (keylen + (keylen / 2U));

    /* a. explicit inputs */
    CHECK_RC(drbg_instantiate_ex(&g_st, c->aes_type, flags, c->entropy, c->entropy_len, opt(c->nonce, c->nonce_len),
                                 c->nonce_len, opt(c->pers, c->pers_len), c->pers_len), NOXTLS_RETURN_SUCCESS);
    if (c->mode == 1U) {
        CHECK_RC(drbg_reseed(&g_st, c->entropy_reseed, c->entropy_reseed_len, opt(c->add_reseed, c->add_reseed_len),
                             c->add_reseed_len), NOXTLS_RETURN_SUCCESS);
    }
    finish_flow(c, 1U);
    CHECK_RC(noxtls_drbg_uninstantiate(&g_st), NOXTLS_RETURN_SUCCESS);

    /* b. prediction resistance inside drbg_generate (entropy from the source) */
    if (c->mode == 2U) {
        CHECK_RC(drbg_instantiate_ex(&g_st, c->aes_type, flags | DRBG_FLAG_PREDICTION_RESISTANCE, c->entropy,
                                     c->entropy_len, opt(c->nonce, c->nonce_len), c->nonce_len,
                                     opt(c->pers, c->pers_len), c->pers_len), NOXTLS_RETURN_SUCCESS);
        ent_script(c->entropy_pr1, c->entropy_pr1_len, c->entropy_pr2, c->entropy_pr2_len);
        finish_flow(c, 0U);
        CHECK(g_ent_next == 2U);
        CHECK(g_ent_bad_len == 0U);
        ent_restore();
        CHECK_RC(noxtls_drbg_uninstantiate(&g_st), NOXTLS_RETURN_SUCCESS);
    }

    /* c. entropy input (|| nonce) drawn from the source by instantiate / reseed */
    if ((c->entropy_len + c->nonce_len) == internal_len) {
        (void)memcpy(g_ent_concat, c->entropy, c->entropy_len);
        (void)memcpy(&g_ent_concat[c->entropy_len], c->nonce, c->nonce_len);
        ent_script(g_ent_concat, internal_len, c->entropy_reseed, (c->mode == 1U) ? c->entropy_reseed_len : 0U);
        CHECK_RC(drbg_instantiate_ex(&g_st, c->aes_type, flags, NULL, 0U, NULL, 0U, opt(c->pers, c->pers_len),
                                     c->pers_len), NOXTLS_RETURN_SUCCESS);
        if (c->mode == 1U) {
            CHECK_RC(drbg_reseed(&g_st, NULL, 0U, opt(c->add_reseed, c->add_reseed_len), c->add_reseed_len),
                     NOXTLS_RETURN_SUCCESS);
        }
        CHECK(g_ent_bad_len == 0U);
        CHECK(g_ent_next == g_ent_count);
        ent_restore();
        finish_flow(c, 1U);
        CHECK_RC(noxtls_drbg_uninstantiate(&g_st), NOXTLS_RETURN_SUCCESS);
    }
}

static void load_header_case(const cs_drbg_cavp_case_t *h, cavp_case_t *c)
{
    (void)memset(c, 0, sizeof(*c));
    c->aes_type = h->aes_type;
    c->no_df = h->no_df;
    c->mode = h->mode;
    c->returned_bits = h->returned_bits;
    c->entropy_len = cs_hex(h->entropy, c->entropy, CAVP_MAX);
    c->nonce_len = cs_hex(h->nonce, c->nonce, CAVP_MAX);
    c->pers_len = cs_hex(h->pers, c->pers, CAVP_MAX);
    c->entropy_reseed_len = cs_hex(h->entropy_reseed, c->entropy_reseed, CAVP_MAX);
    c->add_reseed_len = cs_hex(h->add_reseed, c->add_reseed, CAVP_MAX);
    c->add1_len = cs_hex(h->add1, c->add1, CAVP_MAX);
    c->entropy_pr1_len = cs_hex(h->entropy_pr1, c->entropy_pr1, CAVP_MAX);
    c->add2_len = cs_hex(h->add2, c->add2, CAVP_MAX);
    c->entropy_pr2_len = cs_hex(h->entropy_pr2, c->entropy_pr2, CAVP_MAX);
    c->expected_len = cs_hex(h->expected, c->expected, CAVP_MAX);
}

static void test_cavp_subset(void)
{
    char what[96];
    uint32_t i;
    uint32_t run = 0U;

    for (i = 0U; i < CS_ARRAY_LEN(k_drbg_cavp); i += 1U) {
        const cs_drbg_cavp_case_t *h = &k_drbg_cavp[i];
        if (aes_type_enabled(h->aes_type) == 0) {
            continue;
        }
        (void)snprintf(what, sizeof(what), "CAVP %s AES-%u %s COUNT %u (#%u)", h->file,
                       (unsigned)(keylen_of(h->aes_type) * 8U), (h->no_df != 0U) ? "no df" : "use df",
                       (unsigned)h->count, (unsigned)i);
        cs_section(what);
        load_header_case(h, &g_case);
        run_cavp_case(&g_case);
        run += 1U;
    }
    (void)printf("CAVP subset: %u vectors run\n", (unsigned)run);
}

/* ---- complete .rsp files (optional, command line) ----------------------- */
static uint32_t parse_hex_field(const char *v, uint8_t *out)
{
    char tmp[2U * CAVP_MAX + 2U];
    size_t n = 0U;
    while ((*v != '\0') && (*v != '\r') && (*v != '\n') && (*v != ' ') && (n < (sizeof(tmp) - 1U))) {
        tmp[n] = *v;
        n += 1U;
        v += 1;
    }
    tmp[n] = '\0';
    return cs_hex(tmp, out, CAVP_MAX);
}

static void run_rsp_file(const char *path)
{
    static char line[1024];
    char section[64] = "";
    char what[160];
    FILE *f = fopen(path, "r");
    uint32_t mode = 0U;
    uint32_t aes_ok = 0U;
    uint32_t have_case = 0U;
    uint32_t gen_seen = 0U;
    uint32_t count = 0U;
    uint32_t vectors = 0U;
    uint32_t failures_before = g_cs_failures;

    if (f == NULL) {
        (void)fprintf(stderr, "cannot open %s\n", path);
        g_cs_failures += 1U;
        return;
    }
    mode = (strstr(path, "pr_true") != NULL) ? 2U : ((strstr(path, "pr_false") != NULL) ? 1U : 0U);
    for (;;) {
        char *got = fgets(line, (int)sizeof(line), f);
        char *eq;
        const char *key;
        const char *val;

        if ((got == NULL) || (strncmp(line, "COUNT", 5U) == 0) || (line[0] == '[')) {
            if ((have_case != 0U) && (aes_ok != 0U)) {
                (void)snprintf(what, sizeof(what), "%s [%s] COUNT %u", path, section, (unsigned)count);
                cs_section(what);
                if (aes_type_enabled(g_case.aes_type) != 0) {
                    run_cavp_case(&g_case);
                    vectors += 1U;
                }
            }
            have_case = 0U;
        }
        if (got == NULL) {
            break;
        }
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if ((end != NULL) && (strchr(line, '=') == NULL)) {
                *end = '\0';
                (void)snprintf(section, sizeof(section), "%s", &line[1]);
                aes_ok = (strncmp(section, "AES-", 4U) == 0) ? 1U : 0U;
                (void)memset(&g_case, 0, sizeof(g_case));
                g_case.aes_type = (strncmp(section, "AES-128", 7U) == 0) ? DRBG_AES128 :
                                  ((strncmp(section, "AES-192", 7U) == 0) ? DRBG_AES192 : DRBG_AES256);
                g_case.no_df = (strstr(section, "no df") != NULL) ? 1U : 0U;
            } else if ((end != NULL) && (strncmp(line, "[ReturnedBitsLen", 16U) == 0)) {
                g_case.returned_bits = (uint32_t)strtoul(strchr(line, '=') + 1, NULL, 10);
            } else {
                /* other section parameters are implied by the vectors */
            }
            continue;
        }
        eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        key = line;
        val = eq + 1;
        while (*val == ' ') {
            val += 1;
        }
        if (strncmp(key, "COUNT", 5U) == 0) {
            uint32_t aes_type = g_case.aes_type;
            uint32_t no_df = g_case.no_df;
            uint32_t bits = g_case.returned_bits;
            (void)memset(&g_case, 0, sizeof(g_case));
            g_case.aes_type = aes_type;
            g_case.no_df = no_df;
            g_case.returned_bits = bits;
            g_case.mode = mode;
            count = (uint32_t)strtoul(val, NULL, 10);
            have_case = 1U;
            gen_seen = 0U;
        } else if (strncmp(key, "EntropyInputReseed", 18U) == 0) {
            g_case.entropy_reseed_len = parse_hex_field(val, g_case.entropy_reseed);
        } else if (strncmp(key, "EntropyInputPR", 14U) == 0) {
            if (gen_seen <= 1U) {
                g_case.entropy_pr1_len = parse_hex_field(val, g_case.entropy_pr1);
            } else {
                g_case.entropy_pr2_len = parse_hex_field(val, g_case.entropy_pr2);
            }
        } else if (strncmp(key, "EntropyInput", 12U) == 0) {
            g_case.entropy_len = parse_hex_field(val, g_case.entropy);
        } else if (strncmp(key, "Nonce", 5U) == 0) {
            g_case.nonce_len = parse_hex_field(val, g_case.nonce);
        } else if (strncmp(key, "PersonalizationString", 21U) == 0) {
            g_case.pers_len = parse_hex_field(val, g_case.pers);
        } else if (strncmp(key, "AdditionalInputReseed", 21U) == 0) {
            g_case.add_reseed_len = parse_hex_field(val, g_case.add_reseed);
        } else if (strncmp(key, "AdditionalInput", 15U) == 0) {
            gen_seen += 1U;
            if (gen_seen == 1U) {
                g_case.add1_len = parse_hex_field(val, g_case.add1);
            } else {
                g_case.add2_len = parse_hex_field(val, g_case.add2);
            }
        } else if (strncmp(key, "ReturnedBits", 12U) == 0) {
            g_case.expected_len = parse_hex_field(val, g_case.expected);
        } else {
            /* unknown keys are ignored */
        }
    }
    (void)fclose(f);
    (void)printf("%s: %u AES CTR_DRBG vectors, %s\n", path, (unsigned)vectors,
                 (g_cs_failures == failures_before) ? "all pass" : "FAILURES");
}

/* ---- SP 800-90A limits and states --------------------------------------- */
#if NOXTLS_FEATURE_AES_128
static uint8_t g_big[(DRBG_MAX_BITS_PER_REQUEST / 8U) + 16U];

static void test_limits_and_states(void)
{
    static const uint8_t zero_ent[48] = { 0U };
    uint8_t ent[48];
    uint8_t nonce[16];
    uint8_t add[64];
    uint8_t a16[2];
    uint8_t a12[2];
    drbg_state_t before;
    uint32_t i;

    cs_fill(ent, sizeof(ent), 0x51A7E001U);
    cs_fill(nonce, sizeof(nonce), 0x51A7E002U);
    cs_fill(add, sizeof(add), 0x51A7E003U);

    cs_section("reseed counter (10.2.1.1)");
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 16U, nonce, 8U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_st.reseed_counter == 1U);
    CHECK(g_st.flags == 0U);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, add, 5U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_st.reseed_counter == 3U);
    CHECK_RC(drbg_reseed(&g_st, ent, 16U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_st.reseed_counter == 1U);

    cs_section("max_number_of_bits_per_request (Table 3)");
    CHECK_RC(drbg_generate(&g_st, g_big, DRBG_MAX_BITS_PER_REQUEST + 1U, NULL, 0U), NOXTLS_RETURN_INVALID_PARAM);
    CHECK(g_st.reseed_counter == 1U);
    CHECK_RC(drbg_generate(&g_st, g_big, DRBG_MAX_BITS_PER_REQUEST, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK(!cs_all_zero(&g_big[(DRBG_MAX_BITS_PER_REQUEST / 8U) - 16U], 16U));

    cs_section("reseed interval: automatic reseed from the source (9.3.1 step 7)");
    g_st.reseed_counter = DRBG_RESEED_INTERVAL + 1U;
    ent_script(ent, 16U, NULL, 0U);
    CHECK_RC(drbg_generate(&g_st, g_out, 64U, add, 7U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_ent_next == 1U);
    CHECK(g_st.reseed_counter == 2U);
    cs_section("reseed interval with a failing source: no output, state unchanged");
    g_st.reseed_counter = DRBG_RESEED_INTERVAL + 1U;
    (void)memcpy(&before, &g_st, sizeof(before));
    ent_script(NULL, 0U, NULL, 0U);
    g_ent_fail = 1;
    (void)memset(g_out, 0xEE, 16U);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, NULL, 0U), NOXTLS_RETURN_FAILED);
    CHECK(cs_all_zero(g_out, 16U));
    CHECK(memcmp(&before, &g_st, sizeof(before)) == 0);
    cs_section("reseed with a failing source: state unchanged");
    g_st.reseed_counter = 5U;
    (void)memcpy(&before, &g_st, sizeof(before));
    CHECK_RC(drbg_reseed(&g_st, NULL, 0U, add, 3U), NOXTLS_RETURN_FAILED);
    CHECK(memcmp(&before, &g_st, sizeof(before)) == 0);
    cs_section("stuck entropy source (all-equal bytes) is rejected");
    g_ent_fail = 0;
    ent_script(zero_ent, 24U, NULL, 0U);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, NULL, 0U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_FAILED);
    CHECK(cs_all_zero(&g_st, sizeof(g_st)));
    ent_restore();

    cs_section("df variant input rules (10.2.1.3.2, 8.6.7)");
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 15U, nonce, 8U, NULL, 0U), NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 16U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 16U, nonce, 7U, NULL, 0U), NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 24U, NULL, 0U, add, 64U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_reseed(&g_st, ent, 15U, NULL, 0U), NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_reseed(&g_st, ent, 16U, add, 64U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, add, 64U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, 0x80U, ent, 24U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_INVALID_PARAM);
    CHECK(cs_all_zero(&g_st, sizeof(g_st)));

    cs_section("no-df variant input rules (10.2.1.3.1, 10.2.1.4.1, 10.2.1.5.1)");
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, DRBG_FLAG_NO_DF, ent, 31U, NULL, 0U, NULL, 0U),
             NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, DRBG_FLAG_NO_DF, ent, 33U, NULL, 0U, NULL, 0U),
             NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, DRBG_FLAG_NO_DF, ent, 32U, nonce, 8U, NULL, 0U),
             NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, DRBG_FLAG_NO_DF, ent, 32U, NULL, 0U, add, 33U),
             NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_instantiate_ex(&g_st, DRBG_AES128, DRBG_FLAG_NO_DF, ent, 32U, NULL, 0U, add, 32U),
             NOXTLS_RETURN_SUCCESS);
    CHECK(g_st.flags == DRBG_FLAG_NO_DF);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, add, 33U), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_generate(&g_st, g_out, 128U, add, 32U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_reseed(&g_st, ent, 31U, NULL, 0U), NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    CHECK_RC(drbg_reseed(&g_st, ent, 32U, add, 33U), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_reseed(&g_st, ent, 32U, add, 32U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_update(&g_st, add, 33U), NOXTLS_RETURN_INVALID_PARAM);
    CHECK_RC(drbg_update(&g_st, add, 32U), NOXTLS_RETURN_SUCCESS);

    cs_section("leftmost bits of a partial byte");
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 24U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, a16, 16U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 24U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, a12, 12U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK(a12[0] == a16[0]);
    CHECK(a12[1] == (uint8_t)(a16[1] & 0xF0U));

    cs_section("NULL additional input with a length is the Null string");
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 24U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, a16, 16U, NULL, 9U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, ent, 24U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK_RC(drbg_generate(&g_st, a12, 16U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    CHECK(memcmp(a12, a16, 2U) == 0);

    cs_section("uninstantiate (9.4)");
    CHECK_RC(noxtls_drbg_uninstantiate(&g_st), NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(&g_st, sizeof(g_st)));
    CHECK_RC(drbg_generate(&g_st, g_out, 8U, NULL, 0U), NOXTLS_RETURN_FAILED);
    CHECK_RC(drbg_reseed(&g_st, ent, 16U, NULL, 0U), NOXTLS_RETURN_FAILED);
    CHECK_RC(drbg_update(&g_st, NULL, 0U), NOXTLS_RETURN_FAILED);

    cs_section("instances from the platform entropy source differ");
    for (i = 0U; i < 2U; i += 1U) {
        CHECK_RC(drbg_instantiate(&g_st, DRBG_AES128, NULL, 0U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(drbg_generate(&g_st, &g_out[i * 16U], 128U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    }
    CHECK(memcmp(g_out, &g_out[16], 16U) != 0);
    CHECK_RC(noxtls_drbg_uninstantiate(&g_st), NOXTLS_RETURN_SUCCESS);
}
#endif

int main(int argc, char **argv)
{
    int i;

    if (argc > 1) {
        for (i = 1; i < argc; i += 1) {
            run_rsp_file(argv[i]);
        }
        return cs_finish("crypto_sym_drbg_sp800_90a_test (CAVP files)");
    }
    test_cavp_subset();
#if NOXTLS_FEATURE_AES_128
    test_limits_and_states();
#endif
    return cs_finish("crypto_sym_drbg_sp800_90a_test");
}
