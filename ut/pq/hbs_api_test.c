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
* File:    hbs_api_test.c
* Summary: API contract tests for the stateful hash-based signature scaffolds
*          (LMS/HSS RFC 8554, XMSS/XMSS^MT RFC 8391).  Both are not yet
*          implemented: these tests pin the size contract and make sure every
*          operation reports NOXTLS_RETURN_NOT_SUPPORTED instead of pretending
*          to succeed.
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>

#include "pq_test.h"
#include "noxtls_common.h"
#include "pkc/lms/noxtls_lms.h"

static uint8_t g_hbs_pk[128];
static uint8_t g_hbs_sk[256];
static uint8_t g_hbs_sig[9300];

#if NOXTLS_FEATURE_LMS_HSS
typedef struct
{
    noxtls_lms_param_t param;
    uint32_t pk_len;
    uint32_t sig_len;
} hbs_t_lms_size_t;

/* RFC 8554 sizes with LMOTS_SHA256_N32_W8 (see noxtls_lms.c). */
static const hbs_t_lms_size_t g_lms_sizes[] = {
    { NOXTLS_LMS_SHA256_M32_H5, 56U, 1292U },
    { NOXTLS_LMS_SHA256_M32_H10, 56U, 1452U },
    { NOXTLS_LMS_SHA256_M32_H15, 56U, 1612U },
    { NOXTLS_HSS_SHA256_M32_H10_D2, 60U, 2964U },
    { NOXTLS_HSS_SHA256_M32_H15_D2, 60U, 3284U },
};

static void hbs_t_lms(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_lms_sizes) / sizeof(g_lms_sizes[0])); i += 1U) {
        const hbs_t_lms_size_t *s = &g_lms_sizes[i];
        uint32_t sig_len = (uint32_t)sizeof(g_hbs_sig);

        PQ_CHECK(noxtls_lms_public_key_len(s->param) == s->pk_len, "LMS public key length");
        PQ_CHECK(noxtls_lms_signature_len(s->param) == s->sig_len, "LMS signature length");
        PQ_CHECK(noxtls_lms_secret_key_len(s->param) != 0U, "LMS secret key length");
        PQ_CHECK(s->pk_len <= NOXTLS_LMS_MAX_PUBLIC_KEY_LEN, "LMS max public key");
        PQ_CHECK(s->sig_len <= NOXTLS_LMS_MAX_SIGNATURE_LEN, "LMS max signature");
        PQ_CHECK(noxtls_lms_secret_key_len(s->param) <= NOXTLS_LMS_MAX_SECRET_KEY_LEN, "LMS max secret key");
        /* LMS/HSS is implemented (ut/pq/lms_kat_test.c); keep the contract cheap here. */
        PQ_CHECK_RC(noxtls_lms_keygen(s->param, NULL, s->pk_len, g_hbs_sk, noxtls_lms_secret_key_len(s->param)),
                    NOXTLS_RETURN_NULL, "LMS keygen argument check");
        PQ_CHECK_RC(noxtls_lms_sign(s->param, g_hbs_sk, g_hbs_pk, 4U, g_hbs_sig, &sig_len),
                    NOXTLS_RETURN_NOT_SUPPORTED, "LMS stateless sign fails closed");
        PQ_CHECK(noxtls_lms_verify(s->param, g_hbs_pk, g_hbs_pk, 4U, g_hbs_sig, s->sig_len) != NOXTLS_RETURN_SUCCESS,
                 "LMS verify of a garbage key/signature never reports success");
    }
    PQ_CHECK(noxtls_lms_public_key_len(NOXTLS_LMS_NONE) == 0U, "LMS invalid param");
    PQ_CHECK(noxtls_lms_signature_len((noxtls_lms_param_t)42U) == 0U, "LMS invalid param sig");
    PQ_CHECK(noxtls_lms_secret_key_len(NOXTLS_LMS_NONE) == 0U, "LMS invalid param sk");
}
#endif

/* XMSS / XMSS^MT are implemented and covered by xmss_kat_test.c. */

int noxtls_pq_test_hbs(void)
{
    pq_test_begin("hbs (LMS/HSS, XMSS scaffolds)");
#if NOXTLS_FEATURE_LMS_HSS
    hbs_t_lms();
#endif
    (void)g_hbs_pk;
    (void)g_hbs_sk;
    (void)g_hbs_sig;
    return pq_test_end("hbs (LMS/HSS, XMSS scaffolds)");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_hbs)
