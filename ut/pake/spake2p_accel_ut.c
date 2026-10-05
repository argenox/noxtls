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
* File:    spake2p_accel_ut.c
* Summary: SPAKE2+ routes every scalar multiplication through the P-256 accelerator port
*
*
*****************************************************************************/

/**
 * @file spake2p_accel_ut.c
 * @brief SPAKE2+ over a bound CC13xx-style P-256 callback (software model of the PKA).
 * @ingroup noxtls_spake2p
 *
 * Built with NOXTLS_FEATURE_CC13XX_HW_ACCEL=1. The callback computes k*P with
 * a double-and-add over noxtls_ecc_point_add() (which never re-enters the
 * accelerator) and counts invocations, proving that every SPAKE2+ scalar
 * multiplication is dispatched through noxtls_ecc_point_multiply() to the
 * accelerator port and that accelerator failures abort the exchange.
 */

#include <stdint.h>
#include <string.h>

#include "pake/noxtls_spake2p.h"
#include "pake/noxtls_spake2p_internal.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "common/noxtls_cc13xx_crypto.h"
#include "runner.h"
#include "test_assert.h"
#include "spake2p_test_vectors.h"

/** @brief Scalar multiplications per role in one exchange: e*G, w0*{M|N}, w0*{N|M}, Z, V. */
#define UT_MULS_PER_ROLE (5U)
/** @brief Bits per byte. */
#define UT_BITS (8U)

/** @brief Curve used by the software "hardware" model. */
static ecc_curve_params_t s_curve;
/** @brief Number of callback invocations. */
static uint32_t s_calls;
/** @brief Callback index (1-based) that reports a timeout; 0 disables. */
static uint32_t s_fail_at;
/** @brief Prover context. */
static noxtls_spake2p_ctx_t s_prover;
/** @brief Verifier context. */
static noxtls_spake2p_ctx_t s_verifier;

/**
 * @brief Software model of the P-256 multiply callback: double-and-add.
 * @internal
 *
 * @param[in] context Unused.
 * @param[in] scalar 32-byte big-endian scalar.
 * @param[in] x Input x.
 * @param[in] y Input y.
 * @param[out] out_x Result x.
 * @param[out] out_y Result y.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_TIMEOUT when injected.
 */
static noxtls_return_t ut_model_multiply(void *context, const uint8_t scalar[32], const uint8_t x[32],
                                         const uint8_t y[32], uint8_t out_x[32], uint8_t out_y[32])
{
    ecc_point_t base;
    ecc_point_t acc;
    ecc_point_t tmp;
    uint32_t byte_index;

    (void)context;
    ++s_calls;
    if ((s_fail_at != 0U) && (s_calls == s_fail_at)) {
        return NOXTLS_RETURN_TIMEOUT;
    }

    (void)noxtls_ecc_point_init(&base, 32U);
    (void)noxtls_ecc_point_init(&acc, 32U);
    memcpy(base.x, x, 32U);
    memcpy(base.y, y, 32U);
    for (byte_index = 0U; byte_index < 32U; ++byte_index) {
        uint32_t bit;

        for (bit = UT_BITS; bit > 0U; --bit) {
            (void)noxtls_ecc_point_add(&tmp, &acc, &acc, &s_curve);
            acc = tmp;
            if (((scalar[byte_index] >> (bit - 1U)) & 1U) != 0U) {
                (void)noxtls_ecc_point_add(&tmp, &acc, &base, &s_curve);
                acc = tmp;
            }
        }
    }

    memcpy(out_x, acc.x, 32U);
    memcpy(out_y, acc.y, 32U);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Bind the model callback and reset counters.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t ut_bind(void)
{
    noxtls_cc13xx_crypto_binding_t binding;

    memset(&binding, 0, sizeof(binding));
    binding.p256_multiply = ut_model_multiply;
    s_calls = 0U;
    s_fail_at = 0U;
    (void)noxtls_ecc_curve_free(&s_curve);
    if (noxtls_ecc_curve_init(&s_curve, NOXTLS_ECC_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    return noxtls_cc13xx_crypto_bind(&binding);
}

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/** @brief Profile exercised by this file. */
#define UT_PROFILE NOXTLS_SPAKE2P_PROFILE_RFC9383
#define UT_CTX k_rfc_context
#define UT_IDP k_rfc_id_prover
#define UT_IDV k_rfc_id_verifier
#define UT_W0 k_rfc_w0
#define UT_W1 k_rfc_w1
#define UT_L k_rfc_L
#define UT_X k_rfc_x
#define UT_Y k_rfc_y
#define UT_SHARE_P k_rfc_share_p
#define UT_SHARE_V k_rfc_share_v
#define UT_CONF_P k_rfc_confirm_p
#define UT_CONF_V k_rfc_confirm_v
#define UT_SHARED k_rfc_k_shared
#define UT_SHARED_LEN NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE
#else
#define UT_PROFILE NOXTLS_SPAKE2P_PROFILE_MATTER
#define UT_CTX k_d01_context
#define UT_IDP "client"
#define UT_IDV "server"
#define UT_W0 k_d01_w0
#define UT_W1 k_d01_w1
#define UT_L k_d01_L
#define UT_X k_d01_x
#define UT_Y k_d01_y
#define UT_SHARE_P k_d01_X
#define UT_SHARE_V k_d01_Y
#define UT_CONF_P k_d01_ca
#define UT_CONF_V k_d01_cb
#define UT_SHARED k_d01_ke
#define UT_SHARED_LEN NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE
#endif

/**
 * @brief Build the transcript parameters of the selected vector.
 * @internal
 *
 * @return Params.
 */
static noxtls_spake2p_params_t ut_params(void)
{
    noxtls_spake2p_params_t params;

    params.context = (const uint8_t *)UT_CTX;
    params.context_len = (uint32_t)strlen(UT_CTX);
    params.id_prover = (const uint8_t *)UT_IDP;
    params.id_prover_len = (uint32_t)strlen(UT_IDP);
    params.id_verifier = (const uint8_t *)UT_IDV;
    params.id_verifier_len = (uint32_t)strlen(UT_IDV);
    return params;
}

/**
 * @brief Known-answer exchange with every multiplication on the accelerator port.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_accel_known_answer_both_roles)
{
    noxtls_spake2p_params_t params = ut_params();
    uint8_t share[NOXTLS_SPAKE2P_POINT_SIZE];
    uint8_t conf[NOXTLS_SPAKE2P_CONFIRMATION_SIZE];
    uint8_t key[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE];
    uint32_t len;
    uint32_t ops_before;

    UTNOX_EQUALS(ut_bind(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 1);
    ops_before = noxtls_ecc_accel_operation_count();

    UTNOX_EQUALS(noxtls_spake2p_compute_L(UT_W1, L), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(L, UT_L, sizeof(L));
    UTNOX_EQUALS(s_calls, 1U);

    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, UT_PROFILE, &params, UT_W0, UT_W1), NOXTLS_RETURN_SUCCESS);
    len = sizeof(share);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, UT_X, share, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(share, UT_SHARE_P, sizeof(share));
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, UT_SHARE_V, sizeof(share)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, 1U + UT_MULS_PER_ROLE);
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(conf, UT_CONF_P, sizeof(conf));
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, UT_CONF_V, sizeof(conf)), NOXTLS_RETURN_SUCCESS);
    len = sizeof(key);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, key, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key, UT_SHARED, UT_SHARED_LEN);
    (void)noxtls_spake2p_free(&s_prover);

    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, UT_PROFILE, &params, UT_W0, UT_L), NOXTLS_RETURN_SUCCESS);
    len = sizeof(share);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_verifier, UT_Y, share, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(share, UT_SHARE_V, sizeof(share));
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_verifier, UT_SHARE_P, sizeof(share)), NOXTLS_RETURN_SUCCESS);
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_verifier, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(conf, UT_CONF_V, sizeof(conf));
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, UT_CONF_P, sizeof(conf)), NOXTLS_RETURN_SUCCESS);
    (void)noxtls_spake2p_free(&s_verifier);

    /* Every multiplication was served (and output-validated) by the accelerator port. */
    UTNOX_EQUALS(s_calls, 1U + (2U * UT_MULS_PER_ROLE));
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count() - ops_before, s_calls);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/**
 * @brief An accelerator timeout during Z/V aborts the exchange (no silent software fallback).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_accel_failure_aborts)
{
    noxtls_spake2p_params_t params = ut_params();
    uint8_t share[NOXTLS_SPAKE2P_POINT_SIZE];
    uint32_t len = sizeof(share);

    UTNOX_EQUALS(ut_bind(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, UT_PROFILE, &params, UT_W0, UT_L), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_verifier, UT_Y, share, &len), NOXTLS_RETURN_SUCCESS);
    s_fail_at = s_calls + 3U;  /* w0*M ok, y*T ok, y*L times out. */
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_verifier, UT_SHARE_P, sizeof(share)), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(s_verifier.state, NOXTLS_SPAKE2P_STATE_FAILED);

    /* A timeout during share generation also aborts. */
    s_fail_at = s_calls + 1U;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, UT_PROFILE, &params, UT_W0, UT_W1), NOXTLS_RETURN_SUCCESS);
    len = sizeof(share);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, UT_X, share, &len), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_FAILED);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    (void)noxtls_ecc_curve_free(&s_curve);
    return 0;
}
