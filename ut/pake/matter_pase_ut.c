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
* File:    matter_pase_ut.c
* Summary: Matter PASE cryptographic helper tests
*
*
*****************************************************************************/

/**
 * @file matter_pase_ut.c
 * @brief Matter PASE: passcode verifier, PASE context, full exchange and session keys.
 * @ingroup noxtls_matter_pase
 */

#include <stdint.h>
#include <string.h>

#include "pake/noxtls_matter_pase.h"
#include "runner.h"
#include "test_assert.h"
#include "spake2p_test_vectors.h"

/** @brief Point size shorthand. */
#define UT_PT NOXTLS_SPAKE2P_POINT_SIZE
/** @brief Scalar size shorthand. */
#define UT_SC NOXTLS_SPAKE2P_SCALAR_SIZE
/** @brief Confirmation size shorthand. */
#define UT_CF NOXTLS_SPAKE2P_CONFIRMATION_SIZE
/** @brief Session key size shorthand. */
#define UT_SK NOXTLS_MATTER_PASE_SESSION_KEY_SIZE

/** @brief Commissioner context. */
static noxtls_spake2p_ctx_t s_initiator;
/** @brief Device context. */
static noxtls_spake2p_ctx_t s_responder;

/**
 * @brief Return 1 when every byte of a buffer is zero.
 * @internal
 *
 * @param[in] buf Buffer.
 * @param[in] len Length.
 *
 * @return 1 when zero.
 */
static int ut_zero(const void *buf, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)buf;
    size_t index;

    for (index = 0U; index < len; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief Salt length of the vector (string without terminator).
 * @internal
 *
 * @return Salt length.
 */
static uint32_t ut_salt_len(void)
{
    return (uint32_t)(sizeof(k_pase_salt) - 1U);
}

/**
 * @brief Setup passcode validity rules (Matter Core section 5.1.7.1).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_passcode_rules)
{
    static const uint32_t invalid[] = {0UL, 11111111UL, 22222222UL, 33333333UL, 44444444UL, 55555555UL,
                                       66666666UL, 77777777UL, 88888888UL, 99999999UL, 12345678UL,
                                       87654321UL, 100000000UL, 0xFFFFFFFFUL};
    static const uint32_t valid[] = {1UL, 20202021UL, 99999998UL, 11111112UL, 12345679UL};
    uint32_t index;

    for (index = 0U; index < (uint32_t)(sizeof(invalid) / sizeof(invalid[0])); ++index) {
        UTNOX_EQUALS(noxtls_matter_pase_passcode_is_valid(invalid[index]), 0);
    }

    for (index = 0U; index < (uint32_t)(sizeof(valid) / sizeof(valid[0])); ++index) {
        UTNOX_EQUALS(noxtls_matter_pase_passcode_is_valid(valid[index]), 1);
    }

    return 0;
}

/**
 * @brief Passcode 20202021 / "SPAKE2P Key Salt" / 1000 iterations gives the reference w0, w1, L.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_verifier_generation)
{
    uint8_t w0[UT_SC];
    uint8_t w1[UT_SC];
    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE];
    uint8_t L[UT_PT];

    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, (const uint8_t *)k_pase_salt, ut_salt_len(),
                                                  K_PASE_ITERATIONS, w0, w1), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(w0, k_pase_w0, UT_SC);
    UTNOX_MEM_EQUAL(w1, k_pase_w1, UT_SC);
    UTNOX_EQUALS(noxtls_matter_pase_compute_verifier(K_PASE_PASSCODE, (const uint8_t *)k_pase_salt, ut_salt_len(),
                                                     K_PASE_ITERATIONS, verifier), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(verifier, k_pase_w0, UT_SC);
    UTNOX_MEM_EQUAL(&verifier[UT_SC], k_pase_L, UT_PT);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), w0, L), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(w0, k_pase_w0, UT_SC);
    UTNOX_MEM_EQUAL(L, k_pase_L, UT_PT);
    return 0;
}

/**
 * @brief Out-of-range PBKDF parameters, passcodes and malformed verifiers are rejected.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_invalid_parameters)
{
    uint8_t salt[NOXTLS_MATTER_PASE_SALT_MAX_SIZE + 1U];
    uint8_t w0[UT_SC];
    uint8_t w1[UT_SC];
    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE];
    uint8_t L[UT_PT];

    memset(salt, 0x5A, sizeof(salt));
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, NOXTLS_MATTER_PASE_SALT_MIN_SIZE - 1U,
                                                  K_PASE_ITERATIONS, w0, w1), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, NOXTLS_MATTER_PASE_SALT_MAX_SIZE + 1U,
                                                  K_PASE_ITERATIONS, w0, w1), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, NOXTLS_MATTER_PASE_SALT_MAX_SIZE,
                                                  NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MIN - 1U, w0, w1),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, NOXTLS_MATTER_PASE_SALT_MAX_SIZE,
                                                  NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MAX + 1U, w0, w1),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(12345678UL, salt, NOXTLS_MATTER_PASE_SALT_MIN_SIZE,
                                                  K_PASE_ITERATIONS, w0, w1), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_IS_TRUE(ut_zero(w0, UT_SC));
    UTNOX_IS_TRUE(ut_zero(w1, UT_SC));
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, NULL, 16U, K_PASE_ITERATIONS, w0, w1),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, 16U, K_PASE_ITERATIONS, NULL, w1),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(K_PASE_PASSCODE, salt, 16U, K_PASE_ITERATIONS, w0, NULL),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_verifier(K_PASE_PASSCODE, salt, 16U, K_PASE_ITERATIONS, NULL),
                 NOXTLS_RETURN_NULL);
    memset(verifier, 0xA5, sizeof(verifier));
    UTNOX_EQUALS(noxtls_matter_pase_compute_verifier(0U, salt, 16U, K_PASE_ITERATIONS, verifier),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_IS_TRUE(ut_zero(verifier, sizeof(verifier)));

    /* Malformed serialized verifiers. */
    memcpy(verifier, k_pase_w0, UT_SC);
    memcpy(&verifier[UT_SC], k_pase_L, UT_PT);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier) - 1U, w0, L),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(NULL, sizeof(verifier), w0, L), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), NULL, L), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), w0, NULL), NOXTLS_RETURN_NULL);
    verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE - 1U] ^= 0x01U;
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), w0, L), NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(ut_zero(w0, UT_SC));
    UTNOX_IS_TRUE(ut_zero(L, UT_PT));
    memset(verifier, 0, UT_SC);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), w0, L), NOXTLS_RETURN_INVALID_PARAM);
    return 0;
}

/**
 * @brief PASE context = SHA-256("CHIP PAKE V1 Commissioning" || request || response).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_context)
{
    uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE];

    UTNOX_EQUALS(noxtls_matter_pase_compute_context(k_pase_request, sizeof(k_pase_request),
                                                    k_pase_response, sizeof(k_pase_response), context),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(context, k_pase_context, sizeof(context));
    UTNOX_EQUALS(noxtls_matter_pase_compute_context(NULL, 1U, k_pase_response, 1U, context), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_context(k_pase_request, 1U, NULL, 1U, context), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_context(k_pase_request, 1U, k_pase_response, 1U, NULL),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_compute_context(k_pase_request, 0U, k_pase_response, 1U, context),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_matter_pase_compute_context(k_pase_request, 1U, k_pase_response, 0U, context),
                 NOXTLS_RETURN_INVALID_PARAM);
    return 0;
}

/**
 * @brief Deterministic PASE exchange: pA, pB, cA, cB and I2R/R2I/AttestationChallenge match the model.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_full_exchange_vectors)
{
    uint8_t share_p[UT_PT];
    uint8_t share_v[UT_PT];
    uint8_t ca[UT_CF];
    uint8_t cb[UT_CF];
    uint8_t i2r[2][UT_SK];
    uint8_t r2i[2][UT_SK];
    uint8_t challenge[2][NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE];
    uint32_t len;

    UTNOX_EQUALS(noxtls_matter_pase_initiator_init(&s_initiator, k_pase_context, k_pase_w0, k_pase_w1),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_matter_pase_responder_init(&s_responder, k_pase_context, k_pase_w0, k_pase_L),
                 NOXTLS_RETURN_SUCCESS);

    /* Pake1: commissioner -> device pA. */
    len = sizeof(share_p);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_initiator, k_rfc_x, share_p, &len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(share_p, k_pase_X, UT_PT);
    /* Pake2: device -> commissioner pB, cB. */
    len = sizeof(share_v);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_responder, k_rfc_y, share_v, &len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(share_v, k_pase_Y, UT_PT);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_responder, share_p, UT_PT), NOXTLS_RETURN_SUCCESS);
    len = sizeof(cb);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_responder, cb, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(cb, k_pase_cb, UT_CF);
    /* Session keys are not available before key confirmation. */
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_responder, i2r[1], r2i[1], challenge[1]),
                 NOXTLS_RETURN_NOT_INITIALIZED);
    /* Commissioner verifies cB, sends Pake3 cA. */
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_initiator, share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_initiator, cb, UT_CF), NOXTLS_RETURN_SUCCESS);
    len = sizeof(ca);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_initiator, ca, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(ca, k_pase_ca, UT_CF);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_responder, ca, UT_CF), NOXTLS_RETURN_SUCCESS);

    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, i2r[0], r2i[0], challenge[0]),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_responder, i2r[1], r2i[1], challenge[1]),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(i2r[0], k_pase_i2r, UT_SK);
    UTNOX_MEM_EQUAL(r2i[0], k_pase_r2i, UT_SK);
    UTNOX_MEM_EQUAL(challenge[0], k_pase_challenge, UT_SK);
    UTNOX_MEM_EQUAL(i2r[1], k_pase_i2r, UT_SK);
    UTNOX_MEM_EQUAL(r2i[1], k_pase_r2i, UT_SK);
    UTNOX_MEM_EQUAL(challenge[1], k_pase_challenge, UT_SK);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(NULL, i2r[0], r2i[0], challenge[0]), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, NULL, r2i[0], challenge[0]),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, i2r[0], NULL, challenge[0]),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, i2r[0], r2i[0], NULL), NOXTLS_RETURN_NULL);
    (void)noxtls_spake2p_free(&s_initiator);
    (void)noxtls_spake2p_free(&s_responder);
    UTNOX_IS_TRUE(ut_zero(&s_initiator, sizeof(s_initiator)));
    UTNOX_IS_TRUE(ut_zero(&s_responder, sizeof(s_responder)));
    return 0;
}

/**
 * @brief Passcode-derived exchange with random scalars; a wrong passcode fails at the commissioner.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_passcode_roundtrip_and_wrong_passcode)
{
    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE];
    uint8_t w0[UT_SC];
    uint8_t w1[UT_SC];
    uint8_t dev_w0[UT_SC];
    uint8_t dev_L[UT_PT];
    uint8_t share_p[UT_PT];
    uint8_t share_v[UT_PT];
    uint8_t ca[UT_CF];
    uint8_t cb[UT_CF];
    uint8_t keys[2][3][UT_SK];
    uint32_t len;
    uint32_t attempt;

    UTNOX_EQUALS(noxtls_matter_pase_compute_verifier(K_PASE_PASSCODE, (const uint8_t *)k_pase_salt, ut_salt_len(),
                                                     K_PASE_ITERATIONS, verifier), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_matter_pase_parse_verifier(verifier, sizeof(verifier), dev_w0, dev_L), NOXTLS_RETURN_SUCCESS);

    for (attempt = 0U; attempt < 2U; ++attempt) {
        uint32_t passcode = (attempt == 0U) ? K_PASE_PASSCODE : (K_PASE_PASSCODE + 1UL);
        noxtls_return_t verify_rc;

        UTNOX_EQUALS(noxtls_matter_pase_compute_w0_w1(passcode, (const uint8_t *)k_pase_salt, ut_salt_len(),
                                                      K_PASE_ITERATIONS, w0, w1), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_matter_pase_initiator_init(&s_initiator, k_pase_context, w0, w1), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_matter_pase_responder_init(&s_responder, k_pase_context, dev_w0, dev_L),
                     NOXTLS_RETURN_SUCCESS);
        len = sizeof(share_p);
        UTNOX_EQUALS(noxtls_spake2p_generate_share(&s_initiator, share_p, &len), NOXTLS_RETURN_SUCCESS);
        len = sizeof(share_v);
        UTNOX_EQUALS(noxtls_spake2p_generate_share(&s_responder, share_v, &len), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_responder, share_p, UT_PT), NOXTLS_RETURN_SUCCESS);
        len = sizeof(cb);
        UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_responder, cb, &len), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_initiator, share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
        verify_rc = noxtls_spake2p_verify_peer_confirmation(&s_initiator, cb, UT_CF);
        if (attempt == 1U) {
            UTNOX_EQUALS(verify_rc, NOXTLS_RETURN_FAILED);
            UTNOX_EQUALS(s_initiator.state, NOXTLS_SPAKE2P_STATE_FAILED);
            UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, keys[0][0], keys[0][1], keys[0][2]),
                         NOXTLS_RETURN_NOT_INITIALIZED);
            /* The device would also reject any cA the commissioner could produce. */
            memset(ca, 0, sizeof(ca));
            UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_responder, ca, UT_CF), NOXTLS_RETURN_FAILED);
            break;
        }

        UTNOX_EQUALS(verify_rc, NOXTLS_RETURN_SUCCESS);
        len = sizeof(ca);
        UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_initiator, ca, &len), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_responder, ca, UT_CF), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, keys[0][0], keys[0][1], keys[0][2]),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_responder, keys[1][0], keys[1][1], keys[1][2]),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(keys[0], keys[1], sizeof(keys[0]));
        UTNOX_IS_TRUE(memcmp(keys[0][0], keys[0][1], UT_SK) != 0);
        (void)noxtls_spake2p_free(&s_initiator);
        (void)noxtls_spake2p_free(&s_responder);
    }

    (void)noxtls_spake2p_free(&s_initiator);
    (void)noxtls_spake2p_free(&s_responder);
    UTNOX_EQUALS(noxtls_matter_pase_initiator_init(&s_initiator, NULL, w0, w1), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_matter_pase_responder_init(&s_responder, NULL, dev_w0, dev_L), NOXTLS_RETURN_NULL);
    return 0;
}

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief Session keys refuse an RFC 9383 profile context.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_matter_pase_session_keys_need_matter_profile)
{
    noxtls_spake2p_params_t params;
    uint8_t share[UT_PT];
    uint8_t i2r[UT_SK];
    uint8_t r2i[UT_SK];
    uint8_t ch[UT_SK];
    uint32_t len = sizeof(share);

    memset(&params, 0, sizeof(params));
    params.context = (const uint8_t *)k_rfc_context;
    params.context_len = (uint32_t)(sizeof(k_rfc_context) - 1U);
    params.id_prover = (const uint8_t *)k_rfc_id_prover;
    params.id_prover_len = 6U;
    params.id_verifier = (const uint8_t *)k_rfc_id_verifier;
    params.id_verifier_len = 6U;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_initiator, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_initiator, k_rfc_x, share, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_initiator, k_rfc_share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_initiator, k_rfc_confirm_v, UT_CF),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_matter_pase_derive_session_keys(&s_initiator, i2r, r2i, ch), NOXTLS_RETURN_INVALID_PARAM);
    (void)noxtls_spake2p_free(&s_initiator);
    return 0;
}
#endif
