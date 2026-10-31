/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_pkc_rng_test.c
* Summary: Lifecycle of the shared PKC CTR_DRBG (noxtls_pkc_rng_generate).
*
* Checks, with a counting custom entropy source:
*  - instantiation on first use draws 3/2 x security strength bits of entropy
*    (entropy input and nonce, SP 800-90A 8.6.7 / SP 800-90C);
*  - a reseed of security-strength bits every NOXTLS_PKC_RNG_RESEED_INTERVAL
*    requests (SP 800-90A 9.2), not earlier;
*  - an entropy failure at reseed fails that request closed (output zeroed)
*    and the next request retries and succeeds;
*  - an entropy failure at instantiation fails closed and is retried.
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"
#include "pkc/noxtls_pkc_rng.h"

#include "crypto_sym_test_util.h"

static uint32_t g_calls;
static uint32_t g_last_len;
static uint32_t g_seed = 0x7E570001U;
static int g_fail;

static noxtls_return_t counting_entropy(uint8_t *out, uint32_t len)
{
    g_calls += 1U;
    g_last_len = len;
    if (g_fail != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    cs_fill(out, len, g_seed);
    g_seed += 1U;
    return NOXTLS_RETURN_SUCCESS;
}

int main(void)
{
#if NOXTLS_FEATURE_PKC
    uint8_t out[32];
    uint8_t prev[32];
    uint32_t strength = NOXTLS_FEATURE_AES_256 ? 32U : 16U;
    uint32_t i;

    noxtls_drbg_set_entropy_callback(counting_entropy);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);

    cs_section("instantiation failure is retried");
    g_fail = 1;
    (void)memset(out, 0xEE, sizeof(out));
    CHECK(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECDSA, out, 256U) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(out, sizeof(out)));
    g_fail = 0;
    g_calls = 0U;

    cs_section("instantiate on first use: 3/2 x security strength");
    CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECDSA, out, 256U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_calls == 1U);
    CHECK(g_last_len == (strength + (strength / 2U)));
    (void)memcpy(prev, out, sizeof(prev));
    CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_RSA, out, 256U), NOXTLS_RETURN_SUCCESS);
    CHECK(memcmp(prev, out, sizeof(out)) != 0);

#if NOXTLS_PKC_RNG_RESEED_INTERVAL > 0
    cs_section("reseed every NOXTLS_PKC_RNG_RESEED_INTERVAL requests");
    /* Two requests done; requests 3 .. INTERVAL use the instantiation seed. */
    for (i = 2U; i < (uint32_t)NOXTLS_PKC_RNG_RESEED_INTERVAL; i += 1U) {
        CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 64U), NOXTLS_RETURN_SUCCESS);
    }
    CHECK(g_calls == 1U);
    CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 64U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_calls == 2U);
    CHECK(g_last_len == strength);

    cs_section("entropy failure at reseed: fail closed, then retry");
    for (i = 1U; i < (uint32_t)NOXTLS_PKC_RNG_RESEED_INTERVAL; i += 1U) {
        CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 64U), NOXTLS_RETURN_SUCCESS);
    }
    CHECK(g_calls == 2U);
    g_fail = 1;
    (void)memset(out, 0xEE, sizeof(out));
    CHECK(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 256U) != NOXTLS_RETURN_SUCCESS);
    CHECK(cs_all_zero(out, sizeof(out)));
    CHECK(g_calls == 3U);
    g_fail = 0;
    CHECK_RC(noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, 256U), NOXTLS_RETURN_SUCCESS);
    CHECK(g_calls == 4U);
    CHECK(g_last_len == strength);
#else
    (void)i;
#endif

    noxtls_drbg_set_entropy_callback(NULL);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
#endif
    return cs_finish("crypto_sym_pkc_rng_test");
}
