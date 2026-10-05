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
* File:    spake2p_ut.c
* Summary: SPAKE2+ known-answer, profile and negative tests
*
*
*****************************************************************************/

/**
 * @file spake2p_ut.c
 * @brief SPAKE2+ tests: RFC 9383 Appendix C, draft-01 (Matter profile), cross-profile and negatives.
 * @ingroup noxtls_spake2p
 */

#include <stdint.h>
#include <string.h>

#include "pake/noxtls_spake2p.h"
#include "pake/noxtls_spake2p_internal.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "runner.h"
#include "test_assert.h"
#include "spake2p_test_vectors.h"

/** @brief Point size shorthand. */
#define UT_PT NOXTLS_SPAKE2P_POINT_SIZE
/** @brief Scalar size shorthand. */
#define UT_SC NOXTLS_SPAKE2P_SCALAR_SIZE
/** @brief Confirmation size shorthand. */
#define UT_CF NOXTLS_SPAKE2P_CONFIRMATION_SIZE

/** @brief P-256 order n, big-endian (out-of-range scalar tests). */
static const uint8_t s_order[UT_SC] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

/** @brief Contexts are about 1 KB; keep them off the test stack. */
static noxtls_spake2p_ctx_t s_prover;
/** @brief Verifier context. */
static noxtls_spake2p_ctx_t s_verifier;

/**
 * @brief Return 1 when every byte of a buffer is zero.
 * @internal
 *
 * @param[in] buf Buffer.
 * @param[in] len Length.
 *
 * @return 1 when zero.
 */
static int ut_all_zero(const void *buf, size_t len)
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

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief Return 1 when the context holds no secret material (aborted or freed).
 * @internal
 *
 * @param[in] ctx Context.
 *
 * @return 1 when all secret fields are zero.
 */
static int ut_secrets_erased(const noxtls_spake2p_ctx_t *ctx)
{
    return ut_all_zero(ctx->w0, sizeof(ctx->w0)) && ut_all_zero(ctx->w1, sizeof(ctx->w1)) &&
           ut_all_zero(ctx->L, sizeof(ctx->L)) && ut_all_zero(ctx->ephemeral, sizeof(ctx->ephemeral)) &&
           ut_all_zero(ctx->confirm_key_prover, sizeof(ctx->confirm_key_prover)) &&
           ut_all_zero(ctx->confirm_key_verifier, sizeof(ctx->confirm_key_verifier)) &&
           ut_all_zero(ctx->shared_key, sizeof(ctx->shared_key)) &&
           ut_all_zero(&ctx->transcript, sizeof(ctx->transcript));
}
#endif

/**
 * @brief Build transcript params from strings.
 * @internal
 *
 * @param[in] context Context string.
 * @param[in] idp Prover identity.
 * @param[in] idv Verifier identity.
 *
 * @return Params struct.
 */
static noxtls_spake2p_params_t ut_params(const char *context, const char *idp, const char *idv)
{
    noxtls_spake2p_params_t params;

    params.context = (const uint8_t *)context;
    params.context_len = (uint32_t)strlen(context);
    params.id_prover = (const uint8_t *)idp;
    params.id_prover_len = (uint32_t)strlen(idp);
    params.id_verifier = (const uint8_t *)idv;
    params.id_verifier_len = (uint32_t)strlen(idv);
    return params;
}

/** @brief Expected values for one deterministic exchange. */
typedef struct
{
    noxtls_spake2p_profile_t profile;  /**< Profile. */
    noxtls_spake2p_params_t params;    /**< Transcript inputs. */
    const uint8_t *w0;                 /**< w0. */
    const uint8_t *w1;                 /**< w1. */
    const uint8_t *L;                  /**< L. */
    const uint8_t *x;                  /**< Prover ephemeral. */
    const uint8_t *y;                  /**< Verifier ephemeral. */
    const uint8_t *share_p;            /**< shareP / X. */
    const uint8_t *share_v;            /**< shareV / Y. */
    const uint8_t *Z;                  /**< Z (NULL to skip). */
    const uint8_t *V;                  /**< V (NULL to skip). */
    const uint8_t *digest;             /**< Hash(TT) (NULL to skip). */
    const uint8_t *k_confirm_p;        /**< K_confirmP / KcA (NULL to skip). */
    const uint8_t *k_confirm_v;        /**< K_confirmV / KcB (NULL to skip). */
    uint32_t confirm_key_len;          /**< Confirmation key length. */
    const uint8_t *confirm_p;          /**< confirmP / cA. */
    const uint8_t *confirm_v;          /**< confirmV / cB. */
    const uint8_t *shared;             /**< K_shared / Ke. */
    uint32_t shared_len;               /**< Shared key length. */
} ut_kat_t;

/**
 * @brief Run the prover role of a known-answer exchange and check every value.
 * @internal
 *
 * @param[in] kat Vector.
 *
 * @return 0 on success.
 */
static int ut_run_prover_kat(const ut_kat_t *kat)
{
    uint8_t share[UT_PT];
    uint8_t z_point[UT_PT];
    uint8_t v_point[UT_PT];
    uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE];
    uint8_t conf[UT_CF];
    uint8_t key[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint32_t len = sizeof(share);

    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, kat->profile, &kat->params, kat->w0, kat->w1),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_READY);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, kat->x, share, &len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, UT_PT);
    UTNOX_MEM_EQUAL(share, kat->share_p, UT_PT);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share_ex(&s_prover, kat->share_v, UT_PT,
                                                      z_point, v_point, digest),
                 NOXTLS_RETURN_SUCCESS);
    if (kat->Z != NULL) {
        UTNOX_MEM_EQUAL(z_point, kat->Z, UT_PT);
        UTNOX_MEM_EQUAL(v_point, kat->V, UT_PT);
    }

    if (kat->digest != NULL) {
        UTNOX_MEM_EQUAL(digest, kat->digest, NOXTLS_SPAKE2P_HASH_SIZE);
    }

    UTNOX_EQUALS(s_prover.confirm_key_len, kat->confirm_key_len);
    if (kat->k_confirm_p != NULL) {
        UTNOX_MEM_EQUAL(s_prover.confirm_key_prover, kat->k_confirm_p, kat->confirm_key_len);
        UTNOX_MEM_EQUAL(s_prover.confirm_key_verifier, kat->k_confirm_v, kat->confirm_key_len);
    }

    /* w0, w1 and x are erased once the keys are derived. */
    UTNOX_IS_TRUE(ut_all_zero(s_prover.w0, UT_SC));
    UTNOX_IS_TRUE(ut_all_zero(s_prover.w1, UT_SC));
    UTNOX_IS_TRUE(ut_all_zero(s_prover.ephemeral, UT_SC));

    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, UT_CF);
    UTNOX_MEM_EQUAL(conf, kat->confirm_p, UT_CF);
    len = sizeof(key);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, key, &len), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, kat->confirm_v, UT_CF),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_CONFIRMED);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, key, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, kat->shared_len);
    UTNOX_MEM_EQUAL(key, kat->shared, kat->shared_len);

    /* Confirmation stays available after the peer is confirmed. */
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(conf, kat->confirm_p, UT_CF);

    UTNOX_EQUALS(noxtls_spake2p_free(&s_prover), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_all_zero(&s_prover, sizeof(s_prover)));
    return 0;
}

/**
 * @brief Run the verifier role of a known-answer exchange and check every value.
 * @internal
 *
 * @param[in] kat Vector.
 *
 * @return 0 on success.
 */
static int ut_run_verifier_kat(const ut_kat_t *kat)
{
    uint8_t share[UT_PT];
    uint8_t z_point[UT_PT];
    uint8_t v_point[UT_PT];
    uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE];
    uint8_t conf[UT_CF];
    uint8_t key[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint32_t len = sizeof(share);

    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, kat->profile, &kat->params, kat->w0, kat->L),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_verifier, kat->y, share, &len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(share, kat->share_v, UT_PT);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share_ex(&s_verifier, kat->share_p, UT_PT,
                                                      z_point, v_point, digest),
                 NOXTLS_RETURN_SUCCESS);
    if (kat->Z != NULL) {
        UTNOX_MEM_EQUAL(z_point, kat->Z, UT_PT);
        UTNOX_MEM_EQUAL(v_point, kat->V, UT_PT);
    }

    if (kat->digest != NULL) {
        UTNOX_MEM_EQUAL(digest, kat->digest, NOXTLS_SPAKE2P_HASH_SIZE);
    }

    UTNOX_IS_TRUE(ut_all_zero(s_verifier.L, UT_PT));
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_verifier, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(conf, kat->confirm_v, UT_CF);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, kat->confirm_p, UT_CF),
                 NOXTLS_RETURN_SUCCESS);
    len = sizeof(key);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_verifier, key, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, kat->shared_len);
    UTNOX_MEM_EQUAL(key, kat->shared, kat->shared_len);
    UTNOX_EQUALS(noxtls_spake2p_free(&s_verifier), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_all_zero(&s_verifier, sizeof(s_verifier)));
    return 0;
}

/**
 * @brief Run a random-scalar exchange between two fresh contexts.
 * @internal
 *
 * @param[in] profile_p Prover profile.
 * @param[in] profile_v Verifier profile.
 * @param[in] params Transcript inputs.
 * @param[in] w0_p Prover w0.
 * @param[in] w1_p Prover w1.
 * @param[in] w0_v Verifier w0.
 * @param[in] L_v Verifier L.
 * @param[out] keys_match Set to 1 when both confirmations verified and keys are equal.
 *
 * @return 0 when the run completed (with either outcome), non-zero on an unexpected API error.
 */
static int ut_random_exchange(noxtls_spake2p_profile_t profile_p, noxtls_spake2p_profile_t profile_v,
                              const noxtls_spake2p_params_t *params,
                              const uint8_t *w0_p, const uint8_t *w1_p,
                              const uint8_t *w0_v, const uint8_t *L_v, int *keys_match)
{
    uint8_t share_p[UT_PT];
    uint8_t share_v[UT_PT];
    uint8_t conf_p[UT_CF];
    uint8_t conf_v[UT_CF];
    uint8_t key_p[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint8_t key_v[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint32_t len;
    uint32_t key_len_p = sizeof(key_p);
    uint32_t key_len_v = sizeof(key_v);

    *keys_match = 0;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, profile_p, params, w0_p, w1_p), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, profile_v, params, w0_v, L_v), NOXTLS_RETURN_SUCCESS);
    len = sizeof(share_p);
    UTNOX_EQUALS(noxtls_spake2p_generate_share(&s_prover, share_p, &len), NOXTLS_RETURN_SUCCESS);
    len = sizeof(share_v);
    UTNOX_EQUALS(noxtls_spake2p_generate_share(&s_verifier, share_v, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_verifier, share_p, UT_PT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
    len = sizeof(conf_v);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_verifier, conf_v, &len), NOXTLS_RETURN_SUCCESS);
    len = sizeof(conf_p);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf_p, &len), NOXTLS_RETURN_SUCCESS);
    if ((noxtls_spake2p_verify_peer_confirmation(&s_prover, conf_v, UT_CF) == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_spake2p_verify_peer_confirmation(&s_verifier, conf_p, UT_CF) == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_spake2p_get_shared_key(&s_prover, key_p, &key_len_p) == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_spake2p_get_shared_key(&s_verifier, key_v, &key_len_v) == NOXTLS_RETURN_SUCCESS) &&
        (key_len_p == key_len_v) && (memcmp(key_p, key_v, key_len_p) == 0)) {
        *keys_match = 1;
    }

    (void)noxtls_spake2p_free(&s_prover);
    (void)noxtls_spake2p_free(&s_verifier);
    return 0;
}

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief Compute w0*Q for a public point Q with the NoxTLS ECC API (test helper).
 * @internal
 *
 * @param[in] scalar Scalar.
 * @param[in] q Encoded point.
 * @param[out] out Encoded result.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t ut_mul_point(const uint8_t *scalar, const uint8_t *q, uint8_t *out)
{
    ecc_curve_params_t curve;
    ecc_point_t in;
    ecc_point_t res;
    noxtls_return_t rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);

    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    (void)noxtls_ecc_point_init(&in, UT_SC);
    (void)noxtls_ecc_point_init(&res, UT_SC);
    memcpy(in.x, &q[1], UT_SC);
    memcpy(in.y, &q[1U + UT_SC], UT_SC);
    rc = noxtls_ecc_point_multiply(&res, scalar, &in, &curve);
    out[0] = 0x04U;
    memcpy(&out[1], res.x, UT_SC);
    memcpy(&out[1U + UT_SC], res.y, UT_SC);
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}
#endif

/**
 * @brief M and N are the RFC 9383 section 4 points and are valid curve points.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_group_constants)
{
    UTNOX_EQUALS(noxtls_spake2p_p256_M()[0], 0x04U);
    UTNOX_EQUALS(noxtls_spake2p_p256_M()[1], 0x88U);
    UTNOX_EQUALS(noxtls_spake2p_p256_N()[1], 0xD8U);
    UTNOX_EQUALS(noxtls_spake2p_group_validate_point(noxtls_spake2p_p256_M()), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_group_validate_point(noxtls_spake2p_p256_N()), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_group_validate_point(NULL), NOXTLS_RETURN_NULL);
    return 0;
}

/**
 * @brief Constant-time scalar range check and mod-n reduction edge cases.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_scalar_range_and_reduction)
{
    uint8_t scalar[UT_SC];
    uint8_t ws[NOXTLS_SPAKE2P_WS_SIZE];
    uint8_t w0[UT_SC];
    uint8_t w1[UT_SC];

    memset(scalar, 0, sizeof(scalar));
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(scalar), 0);
    scalar[UT_SC - 1U] = 1U;
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(scalar), 1);
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(s_order), 0);
    memcpy(scalar, s_order, UT_SC);
    scalar[UT_SC - 1U] = (uint8_t)(scalar[UT_SC - 1U] - 1U);
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(scalar), 1);
    memset(scalar, 0xFF, sizeof(scalar));
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(scalar), 0);
    UTNOX_EQUALS(noxtls_spake2p_group_scalar_is_valid(NULL), 0);

    /* (2^320 - 1) mod n for both halves. */
    memset(ws, 0xFF, sizeof(ws));
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(ws, sizeof(ws), w0, w1), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(w0, k_reduce_all_ff, UT_SC);
    UTNOX_MEM_EQUAL(w1, k_reduce_all_ff, UT_SC);

    /* PBKDF2 output from the Matter PASE vector reduces to the expected w0/w1. */
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(k_pase_ws, sizeof(k_pase_ws), w0, w1), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(w0, k_pase_w0, UT_SC);
    UTNOX_MEM_EQUAL(w1, k_pase_w1, UT_SC);

    /* w0s = n reduces to zero: rejected, outputs erased. */
    memset(ws, 0, sizeof(ws));
    memcpy(&ws[NOXTLS_SPAKE2P_WS_HALF_SIZE - UT_SC], s_order, UT_SC);
    ws[NOXTLS_SPAKE2P_WS_SIZE - 1U] = 7U;
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(ws, sizeof(ws), w0, w1), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(ut_all_zero(w0, UT_SC));
    UTNOX_IS_TRUE(ut_all_zero(w1, UT_SC));

    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(ws, sizeof(ws) - 1U, w0, w1), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(NULL, sizeof(ws), w0, w1), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(ws, sizeof(ws), NULL, w1), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_derive_w0_w1(ws, sizeof(ws), w0, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_group_reduce_mod_n(NULL, 1U, w0), NOXTLS_RETURN_NULL);
    return 0;
}

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief Build the RFC 9383 Appendix C known-answer description.
 * @internal
 *
 * @return Vector.
 */
static ut_kat_t ut_rfc_kat(void)
{
    ut_kat_t kat;

    memset(&kat, 0, sizeof(kat));
    kat.profile = NOXTLS_SPAKE2P_PROFILE_RFC9383;
    kat.params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    kat.w0 = k_rfc_w0;
    kat.w1 = k_rfc_w1;
    kat.L = k_rfc_L;
    kat.x = k_rfc_x;
    kat.y = k_rfc_y;
    kat.share_p = k_rfc_share_p;
    kat.share_v = k_rfc_share_v;
    kat.Z = k_rfc_Z;
    kat.V = k_rfc_V;
    kat.digest = k_rfc_k_main;
    kat.k_confirm_p = k_rfc_k_confirm_p;
    kat.k_confirm_v = k_rfc_k_confirm_v;
    kat.confirm_key_len = NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE;
    kat.confirm_p = k_rfc_confirm_p;
    kat.confirm_v = k_rfc_confirm_v;
    kat.shared = k_rfc_k_shared;
    kat.shared_len = NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE;
    return kat;
}

/**
 * @brief RFC 9383 Appendix C: L = w1*G.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_registration_L)
{
    uint8_t L[UT_PT];
    uint8_t bad[UT_SC];

    UTNOX_EQUALS(noxtls_spake2p_compute_L(k_rfc_w1, L), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(L, k_rfc_L, UT_PT);
    memset(bad, 0, sizeof(bad));
    UTNOX_EQUALS(noxtls_spake2p_compute_L(bad, L), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_IS_TRUE(ut_all_zero(L, UT_PT));
    UTNOX_EQUALS(noxtls_spake2p_compute_L(NULL, L), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_compute_L(k_rfc_w1, NULL), NOXTLS_RETURN_NULL);
    return 0;
}

/**
 * @brief RFC 9383 Appendix C, prover role: shareP, Z, V, K_main, keys, confirmP, K_shared.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_prover_vectors)
{
    ut_kat_t kat = ut_rfc_kat();

    return ut_run_prover_kat(&kat);
}

/**
 * @brief RFC 9383 Appendix C, verifier role: shareV, Z, V, K_main, confirmV, K_shared.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_verifier_vectors)
{
    ut_kat_t kat = ut_rfc_kat();

    return ut_run_verifier_kat(&kat);
}

/**
 * @brief Random-scalar exchange agrees; wrong password (w0/w1 mismatch) fails confirmation.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_random_exchange_and_wrong_password)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    int match = 0;

    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_RFC9383, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                    k_rfc_w0, k_rfc_w1, k_rfc_w0, k_rfc_L, &match), 0);
    UTNOX_EQUALS(match, 1);
    /* Prover derived from a different password. */
    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_RFC9383, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                    k_d01_w0, k_d01_w1, k_rfc_w0, k_rfc_L, &match), 0);
    UTNOX_EQUALS(match, 0);
    /* Same w0 but wrong w1 (L mismatch) also fails. */
    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_RFC9383, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                    k_rfc_w0, k_d01_w1, k_rfc_w0, k_rfc_L, &match), 0);
    UTNOX_EQUALS(match, 0);
    return 0;
}

/**
 * @brief Different identities or Context give different confirmations (transcript binding).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_transcript_binding)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    noxtls_spake2p_params_t other = ut_params(k_rfc_context, "clienT", k_rfc_id_verifier);
    uint8_t share[UT_PT];
    uint8_t conf[UT_CF];
    uint32_t len = sizeof(share);

    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &other, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, k_rfc_share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(memcmp(conf, k_rfc_confirm_p, UT_CF) != 0);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, k_rfc_confirm_v, UT_CF), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_FAILED);
    UTNOX_IS_TRUE(ut_secrets_erased(&s_prover));

    /* Empty identities with NULL pointers are accepted; NULL with a length is not. */
    params.id_prover = NULL;
    params.id_prover_len = 0U;
    params.id_verifier = NULL;
    params.id_verifier_len = 0U;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_SUCCESS);
    params.id_prover_len = 1U;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    params.id_prover_len = 0U;
    params.id_verifier_len = 1U;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    params.id_verifier_len = 0U;
    params.context = NULL;
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    (void)noxtls_spake2p_free(&s_prover);
    return 0;
}

/**
 * @brief Invalid peer shares are rejected and abort the exchange with secrets erased.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_invalid_peer_shares)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    uint8_t share[UT_PT];
    uint8_t bad[UT_PT];
    uint32_t len;
    uint32_t variant;

    for (variant = 0U; variant < 7U; ++variant) {
        noxtls_return_t expected = NOXTLS_RETURN_BAD_DATA;
        uint32_t bad_len = UT_PT;

        memcpy(bad, k_rfc_share_p, UT_PT);
        switch (variant) {
            case 0U: bad[0] = 0x02U; break;                                /* compressed prefix */
            case 1U: bad[UT_PT - 1U] ^= 0x01U; break;                      /* off curve */
            case 2U: memset(&bad[1], 0, UT_PT - 1U); break;                /* identity encoding */
            case 3U: memset(&bad[1], 0xFF, UT_SC); break;                  /* x >= p */
            case 4U: bad_len = UT_PT - 1U; break;                          /* truncated */
            case 5U: (void)ut_mul_point(k_rfc_w0, noxtls_spake2p_p256_M(), bad); break; /* X = w0*M: T = identity */
            default: memset(&bad[1U + UT_SC], 0xFF, UT_SC); break;         /* y >= p */
        }

        UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                                  k_rfc_w0, k_rfc_L), NOXTLS_RETURN_SUCCESS);
        len = sizeof(share);
        UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_verifier, k_rfc_y, share, &len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_verifier, bad, bad_len), expected);
        UTNOX_EQUALS(s_verifier.state, NOXTLS_SPAKE2P_STATE_FAILED);
        UTNOX_IS_TRUE(ut_secrets_erased(&s_verifier));
        /* An aborted context refuses further use. */
        len = sizeof(share);
        UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_verifier, share, &len), NOXTLS_RETURN_NOT_INITIALIZED);
    }

    /* Prover side: Y = w0*N gives T = identity. */
    UTNOX_EQUALS(ut_mul_point(k_rfc_w0, noxtls_spake2p_p256_N(), bad), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_SUCCESS);
    len = sizeof(share);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, bad, UT_PT), NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(ut_secrets_erased(&s_prover));
    return 0;
}

/**
 * @brief Wrong or truncated confirmations fail closed with secrets erased.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_wrong_confirmation)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    uint8_t share[UT_PT];
    uint8_t conf[UT_CF];
    uint8_t key[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];
    uint32_t len;
    uint32_t pass;

    for (pass = 0U; pass < 3U; ++pass) {
        UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                                  k_rfc_w0, k_rfc_L), NOXTLS_RETURN_SUCCESS);
        len = sizeof(share);
        UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_verifier, k_rfc_y, share, &len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_verifier, k_rfc_share_p, UT_PT), NOXTLS_RETURN_SUCCESS);
        memcpy(conf, k_rfc_confirm_p, UT_CF);
        if (pass == 0U) {
            conf[0] ^= 0x80U;
            UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, conf, UT_CF), NOXTLS_RETURN_FAILED);
        } else if (pass == 1U) {
            conf[UT_CF - 1U] ^= 0x01U;
            UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, conf, UT_CF), NOXTLS_RETURN_FAILED);
        } else {
            UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, conf, UT_CF - 1U),
                         NOXTLS_RETURN_FAILED);
        }

        UTNOX_EQUALS(s_verifier.state, NOXTLS_SPAKE2P_STATE_FAILED);
        UTNOX_IS_TRUE(ut_secrets_erased(&s_verifier));
        /* No retry after a failure. */
        UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_verifier, k_rfc_confirm_p, UT_CF),
                     NOXTLS_RETURN_NOT_INITIALIZED);
        len = sizeof(key);
        UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_verifier, key, &len), NOXTLS_RETURN_NOT_INITIALIZED);
    }

    return 0;
}

/**
 * @brief State machine ordering, buffer sizes and NULL arguments.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_state_and_arguments)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    uint8_t share[UT_PT];
    uint8_t conf[UT_CF];
    uint8_t zero[UT_SC];
    uint8_t bad_L[UT_PT];
    uint32_t len;

    memset(zero, 0, sizeof(zero));
    /* NULL arguments. */
    UTNOX_EQUALS(noxtls_spake2p_prover_init(NULL, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, NULL, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, NULL, k_rfc_w1),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, NULL),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(NULL, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_L),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, NULL),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_free(NULL), NOXTLS_RETURN_NULL);

    /* Out-of-range secrets, unknown profile, invalid L. */
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, zero, k_rfc_w1),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, s_order),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, s_order, k_rfc_L),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, (noxtls_spake2p_profile_t)7, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    memcpy(bad_L, k_rfc_L, UT_PT);
    bad_L[UT_PT - 1U] ^= 0x01U;
    UTNOX_EQUALS(noxtls_spake2p_verifier_init(&s_verifier, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, bad_L),
                 NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(ut_all_zero(&s_verifier, sizeof(s_verifier)));

    /* Calls out of order. */
    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, k_rfc_share_v, UT_PT), NOXTLS_RETURN_NOT_INITIALIZED);
    len = sizeof(conf);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, conf, UT_CF), NOXTLS_RETURN_NOT_INITIALIZED);

    /* Share buffer too small reports the required size and leaves the state unchanged. */
    len = UT_PT - 1U;
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(len, UT_PT);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_READY);
    /* Out-of-range ephemeral scalars. */
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, zero, share, &len), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, s_order, share, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, NULL, share, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, NULL, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_generate_share(NULL, share, &len), NOXTLS_RETURN_NULL);

    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, &len), NOXTLS_RETURN_SUCCESS);
    /* Second share generation is refused. */
    UTNOX_EQUALS(noxtls_spake2p_generate_share_with_scalar(&s_prover, k_rfc_x, share, &len),
                 NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_spake2p_generate_share(&s_prover, share, &len), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, NULL, UT_PT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(NULL, k_rfc_share_v, UT_PT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, k_rfc_share_v, UT_PT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_spake2p_process_peer_share(&s_prover, k_rfc_share_v, UT_PT), NOXTLS_RETURN_NOT_INITIALIZED);

    /* Confirmation buffer too small; NULL arguments. */
    len = UT_CF - 1U;
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, &len), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(len, UT_CF);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(NULL, conf, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, NULL, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_get_confirmation(&s_prover, conf, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(NULL, conf, UT_CF), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, NULL, UT_CF), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, k_rfc_confirm_v, UT_CF), NOXTLS_RETURN_SUCCESS);

    /* Shared key buffer too small; NULL arguments. */
    len = NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE - 1U;
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, conf, &len), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(len, NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(NULL, conf, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, NULL, &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_get_shared_key(&s_prover, conf, NULL), NOXTLS_RETURN_NULL);
    /* Verification is one-shot. */
    UTNOX_EQUALS(noxtls_spake2p_verify_peer_confirmation(&s_prover, k_rfc_confirm_v, UT_CF),
                 NOXTLS_RETURN_NOT_INITIALIZED);
    (void)noxtls_spake2p_free(&s_prover);
    UTNOX_EQUALS(s_prover.state, NOXTLS_SPAKE2P_STATE_EMPTY);
    return 0;
}

/**
 * @brief Internal helpers reject NULL and identity inputs.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_internal_helper_arguments)
{
    uint8_t out[UT_PT];
    uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE];

    UTNOX_EQUALS(noxtls_spake2p_group_mul_base(NULL, out), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_group_mul_base(k_rfc_x, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_group_compute_share(NOXTLS_SPAKE2P_ROLE_PROVER, NULL, k_rfc_w0, out),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_group_compute_zv(NULL, k_rfc_share_v, out, out), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_transcript_start(NULL, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_transcript_finish(NULL, out, out, digest), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_spake2p_kdf(NULL, 1U, digest, 1U, out, 1U), NOXTLS_RETURN_NULL);
#if NOXTLS_FEATURE_SPAKE2P_MATTER
    UTNOX_EQUALS(noxtls_spake2p_matter_derive_keys(NULL, digest), NOXTLS_RETURN_NULL);
#endif
    UTNOX_EQUALS(noxtls_spake2p_rfc9383_derive_keys(NULL, digest), NOXTLS_RETURN_NULL);
    noxtls_spake2p_abort(NULL);
    /* base_part + w0*M = identity: base_part = -(w0*M) is reported as a failed share. */
    UTNOX_EQUALS(ut_mul_point(k_rfc_w0, noxtls_spake2p_p256_M(), out), NOXTLS_RETURN_SUCCESS);
    {
        uint8_t neg[UT_PT];
        uint8_t share[UT_PT];
        uint32_t borrow = 0U;
        uint32_t index = UT_SC;
        static const uint8_t prime[UT_SC] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        memcpy(neg, out, UT_PT);
        while (index > 0U) {
            uint32_t diff;
            --index;
            diff = (uint32_t)prime[index] - (uint32_t)out[1U + UT_SC + index] - borrow;
            neg[1U + UT_SC + index] = (uint8_t)diff;
            borrow = (diff >> 31) & 1U;
        }

        UTNOX_EQUALS(noxtls_spake2p_group_compute_share(NOXTLS_SPAKE2P_ROLE_PROVER, neg, k_rfc_w0, share),
                     NOXTLS_RETURN_FAILED);
        UTNOX_IS_TRUE(ut_all_zero(share, UT_PT));
    }

    return 0;
}
#endif /* NOXTLS_FEATURE_SPAKE2P_RFC9383 */

#if NOXTLS_FEATURE_SPAKE2P_MATTER
/**
 * @brief Build the draft-bar-cfrg-spake2plus-01 known-answer description.
 * @internal
 *
 * @return Vector.
 */
static ut_kat_t ut_d01_kat(void)
{
    ut_kat_t kat;

    memset(&kat, 0, sizeof(kat));
    kat.profile = NOXTLS_SPAKE2P_PROFILE_MATTER;
    kat.params = ut_params(k_d01_context, "client", "server");
    kat.w0 = k_d01_w0;
    kat.w1 = k_d01_w1;
    kat.L = k_d01_L;
    kat.x = k_d01_x;
    kat.y = k_d01_y;
    kat.share_p = k_d01_X;
    kat.share_v = k_d01_Y;
    kat.Z = k_d01_Z;
    kat.V = k_d01_V;
    kat.digest = k_d01_ka_ke;
    kat.k_confirm_p = k_d01_kca;
    kat.k_confirm_v = k_d01_kcb;
    kat.confirm_key_len = NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE;
    kat.confirm_p = k_d01_ca;
    kat.confirm_v = k_d01_cb;
    kat.shared = k_d01_ke;
    kat.shared_len = NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE;
    return kat;
}

/**
 * @brief draft-01 vector (Matter profile), prover role: X, Z, V, Ka||Ke, KcA, KcB, cA, Ke.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_matter_prover_vectors)
{
    ut_kat_t kat = ut_d01_kat();
    uint8_t L[UT_PT];

    UTNOX_EQUALS(noxtls_spake2p_compute_L(k_d01_w1, L), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(L, k_d01_L, UT_PT);
    return ut_run_prover_kat(&kat);
}

/**
 * @brief draft-01 vector (Matter profile), verifier role: Y, Z, V, cB, Ke.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_matter_verifier_vectors)
{
    ut_kat_t kat = ut_d01_kat();

    return ut_run_verifier_kat(&kat);
}

/**
 * @brief Matter profile random exchange agrees and rejects a wrong password.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_matter_random_exchange)
{
    noxtls_spake2p_params_t params = ut_params(k_d01_context, "", "");
    int match = 0;

    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_MATTER, NOXTLS_SPAKE2P_PROFILE_MATTER, &params,
                                    k_d01_w0, k_d01_w1, k_d01_w0, k_d01_L, &match), 0);
    UTNOX_EQUALS(match, 1);
    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_MATTER, NOXTLS_SPAKE2P_PROFILE_MATTER, &params,
                                    k_rfc_w0, k_rfc_w1, k_d01_w0, k_d01_L, &match), 0);
    UTNOX_EQUALS(match, 0);
    return 0;
}
#endif /* NOXTLS_FEATURE_SPAKE2P_MATTER */

#if NOXTLS_FEATURE_SPAKE2P_RFC9383 && NOXTLS_FEATURE_SPAKE2P_MATTER
/**
 * @brief Profiles are not interchangeable: identical inputs give different confirmations and keys.
 *
 * Runs the RFC 9383 Appendix C inputs through the Matter profile; the group
 * values (shares, Z, V) and Hash(TT) are identical, but the confirmations and
 * shared key differ from RFC 9383 and match the independent model of the
 * draft-01 key schedule. An RFC 9383 peer and a Matter peer fail confirmation.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_profiles_not_interchangeable)
{
    ut_kat_t kat = ut_rfc_kat();
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, k_rfc_id_prover, k_rfc_id_verifier);
    int match = 1;

    kat.profile = NOXTLS_SPAKE2P_PROFILE_MATTER;
    kat.k_confirm_p = NULL;
    kat.k_confirm_v = NULL;
    kat.confirm_key_len = NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE;
    kat.confirm_p = k_cross_confirm_p;
    kat.confirm_v = k_cross_confirm_v;
    kat.shared = k_cross_shared;
    kat.shared_len = NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE;
    UTNOX_IS_TRUE(memcmp(k_cross_confirm_p, k_rfc_confirm_p, UT_CF) != 0);
    UTNOX_IS_TRUE(memcmp(k_cross_confirm_v, k_rfc_confirm_v, UT_CF) != 0);
    UTNOX_IS_TRUE(memcmp(k_cross_shared, k_rfc_k_shared, NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE) != 0);
    UTNOX_EQUALS(ut_run_prover_kat(&kat), 0);
    UTNOX_EQUALS(ut_run_verifier_kat(&kat), 0);

    /* Mixed profiles never complete key confirmation. */
    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_RFC9383, NOXTLS_SPAKE2P_PROFILE_MATTER, &params,
                                    k_rfc_w0, k_rfc_w1, k_rfc_w0, k_rfc_L, &match), 0);
    UTNOX_EQUALS(match, 0);
    UTNOX_EQUALS(ut_random_exchange(NOXTLS_SPAKE2P_PROFILE_MATTER, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params,
                                    k_rfc_w0, k_rfc_w1, k_rfc_w0, k_rfc_L, &match), 0);
    UTNOX_EQUALS(match, 0);
    return 0;
}
#endif

#if !NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief With the RFC 9383 profile compiled out it is reported as unsupported.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_rfc9383_profile_compiled_out)
{
    noxtls_spake2p_params_t params = ut_params(k_d01_context, "", "");

    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, k_d01_w0, k_d01_w1),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    return 0;
}
#endif

#if !NOXTLS_FEATURE_SPAKE2P_MATTER
/**
 * @brief With the Matter profile compiled out it is reported as unsupported.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_spake2p_matter_profile_compiled_out)
{
    noxtls_spake2p_params_t params = ut_params(k_rfc_context, "", "");

    UTNOX_EQUALS(noxtls_spake2p_prover_init(&s_prover, NOXTLS_SPAKE2P_PROFILE_MATTER, &params, k_rfc_w0, k_rfc_w1),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    return 0;
}
#endif
