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
* File:    noxtls_spake2p.c
* Summary: SPAKE2+ context state machine, registration and confirmation
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p.c
 * @brief SPAKE2+ public API: initialization, shares, key confirmation and registration.
 * @ingroup noxtls_spake2p
 *
 * Implements RFC 9383 (SPAKE2+, May 2023) sections 3.2-3.4 with the
 * P256-SHA256-HKDF-SHA256-HMAC-SHA256 ciphersuite. The key schedule is
 * dispatched to the selected profile (noxtls_spake2p_rfc9383.c or
 * noxtls_spake2p_matter.c); group math and the transcript are shared.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_spake2p_internal.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "kdf/noxtls_hkdf.h"
#include "mac/noxtls_hmac.h"
#include "common/noxtls_ct.h"

#if !NOXTLS_FEATURE_SPAKE2P_RFC9383 && !NOXTLS_FEATURE_SPAKE2P_MATTER
#error "SPAKE2+ requires NOXTLS_FEATURE_SPAKE2P_RFC9383 or NOXTLS_FEATURE_SPAKE2P_MATTER."
#endif

void noxtls_spake2p_abort(noxtls_spake2p_ctx_t *ctx)
{
    if (ctx != NULL) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        ctx->state = NOXTLS_SPAKE2P_STATE_FAILED;
    }
}

noxtls_return_t noxtls_spake2p_kdf(const uint8_t *ikm, uint32_t ikm_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *out, uint32_t out_len)
{
    uint8_t prk[NOXTLS_SPAKE2P_HASH_SIZE];
    uint32_t prk_len = NOXTLS_SPAKE2P_HASH_SIZE;
    noxtls_return_t rc;

    if ((ikm == NULL) || (info == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 9383 section 3.4: KDF(salt = nil, ikm, info) with HKDF-SHA256 (RFC 5869). */
    rc = noxtls_hkdf_extract(NOXTLS_HASH_SHA_256, NULL, 0U, ikm, ikm_len, prk, &prk_len);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (prk_len == NOXTLS_SPAKE2P_HASH_SIZE)) {
        rc = noxtls_hkdf_expand(NOXTLS_HASH_SHA_256, prk, prk_len, info, info_len, out, out_len);
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero(prk, sizeof(prk));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, out_len);
        rc = NOXTLS_RETURN_FAILED;
    }

    return rc;
}

/**
 * @brief Report whether a profile is compiled into this build.
 * @internal
 *
 * @param[in] profile Requested profile.
 *
 * @return 1 when available, 0 otherwise.
 */
static int noxtls_spake2p_profile_available(noxtls_spake2p_profile_t profile)
{
#if NOXTLS_FEATURE_SPAKE2P_RFC9383
    if (profile == NOXTLS_SPAKE2P_PROFILE_RFC9383) {
        return 1;
    }

#endif
#if NOXTLS_FEATURE_SPAKE2P_MATTER
    if (profile == NOXTLS_SPAKE2P_PROFILE_MATTER) {
        return 1;
    }

#endif
    return 0;
}

/**
 * @brief Common initialization for both roles.
 * @internal
 *
 * @param[out] ctx Context (erased first).
 * @param[in] profile Profile.
 * @param[in] role Role.
 * @param[in] params Transcript Context and identities.
 * @param[in] w0 w0 scalar.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code (context left EMPTY).
 */
static noxtls_return_t noxtls_spake2p_init_common(noxtls_spake2p_ctx_t *ctx,
                                                  noxtls_spake2p_profile_t profile,
                                                  noxtls_spake2p_role_t role,
                                                  const noxtls_spake2p_params_t *params,
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    noxtls_return_t rc;

    noxtls_secure_zero(ctx, sizeof(*ctx));
    if (((params->context == NULL) && (params->context_len > 0U)) ||
        ((params->id_prover == NULL) && (params->id_prover_len > 0U)) ||
        ((params->id_verifier == NULL) && (params->id_verifier_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }

    if (noxtls_spake2p_profile_available(profile) == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (noxtls_spake2p_group_scalar_is_valid(w0) == 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    ctx->profile = profile;
    ctx->role = role;
    memcpy(ctx->w0, w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
    rc = noxtls_spake2p_transcript_start(ctx, params);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }

    return rc;
}

noxtls_return_t noxtls_spake2p_prover_init(noxtls_spake2p_ctx_t *ctx,
                                           noxtls_spake2p_profile_t profile,
                                           const noxtls_spake2p_params_t *params,
                                           const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                           const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    noxtls_return_t rc;

    if ((ctx == NULL) || (params == NULL) || (w0 == NULL) || (w1 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (noxtls_spake2p_group_scalar_is_valid(w1) == 0) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_spake2p_init_common(ctx, profile, NOXTLS_SPAKE2P_ROLE_PROVER, params, w0);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(ctx->w1, w1, NOXTLS_SPAKE2P_SCALAR_SIZE);
        ctx->state = NOXTLS_SPAKE2P_STATE_READY;
    }

    return rc;
}

noxtls_return_t noxtls_spake2p_verifier_init(noxtls_spake2p_ctx_t *ctx,
                                             noxtls_spake2p_profile_t profile,
                                             const noxtls_spake2p_params_t *params,
                                             const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                             const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE])
{
    noxtls_return_t rc;

    if ((ctx == NULL) || (params == NULL) || (w0 == NULL) || (L == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_spake2p_init_common(ctx, profile, NOXTLS_SPAKE2P_ROLE_VERIFIER, params, w0);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_group_validate_point(L);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(ctx, sizeof(*ctx));
        } else {
            memcpy(ctx->L, L, NOXTLS_SPAKE2P_POINT_SIZE);
            ctx->state = NOXTLS_SPAKE2P_STATE_READY;
        }
    }

    return rc;
}

/**
 * @brief Finish share generation from ephemeral*G already computed.
 * @internal
 *
 * @param[in,out] ctx Context in READY state with ctx->ephemeral set.
 * @param[in] base_part Encoded ephemeral*G.
 * @param[out] share Output buffer.
 * @param[in,out] share_len Capacity / written length.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error (context aborted).
 */
static noxtls_return_t noxtls_spake2p_finish_share(noxtls_spake2p_ctx_t *ctx,
                                                   const uint8_t base_part[NOXTLS_SPAKE2P_POINT_SIZE],
                                                   uint8_t *share, uint32_t *share_len)
{
    uint8_t *own = (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) ? ctx->share_prover : ctx->share_verifier;
    noxtls_return_t rc;

    rc = noxtls_spake2p_group_compute_share(ctx->role, base_part, ctx->w0, own);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_spake2p_abort(ctx);
        return rc;
    }

    memcpy(share, own, NOXTLS_SPAKE2P_POINT_SIZE);
    *share_len = NOXTLS_SPAKE2P_POINT_SIZE;
    ctx->state = NOXTLS_SPAKE2P_STATE_SHARE_GENERATED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Validate arguments common to both share-generation entry points.
 * @internal
 *
 * @param[in] ctx Context.
 * @param[in] share Output buffer.
 * @param[in,out] share_len Capacity; set to the required size when too small.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code (context unchanged).
 */
static noxtls_return_t noxtls_spake2p_check_share_args(const noxtls_spake2p_ctx_t *ctx,
                                                       const uint8_t *share,
                                                       uint32_t *share_len)
{
    if ((ctx == NULL) || (share == NULL) || (share_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->state != NOXTLS_SPAKE2P_STATE_READY) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (*share_len < NOXTLS_SPAKE2P_POINT_SIZE) {
        *share_len = NOXTLS_SPAKE2P_POINT_SIZE;
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_generate_share_with_scalar(noxtls_spake2p_ctx_t *ctx,
                                                          const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                          uint8_t *share, uint32_t *share_len)
{
    uint8_t base_part[NOXTLS_SPAKE2P_POINT_SIZE];
    noxtls_return_t rc;

    rc = noxtls_spake2p_check_share_args(ctx, share, share_len);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (scalar == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (noxtls_spake2p_group_scalar_is_valid(scalar) == 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(ctx->ephemeral, scalar, NOXTLS_SPAKE2P_SCALAR_SIZE);
    rc = noxtls_spake2p_group_mul_base(ctx->ephemeral, base_part);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_finish_share(ctx, base_part, share, share_len);
    } else {
        noxtls_spake2p_abort(ctx);
    }

    noxtls_secure_zero(base_part, sizeof(base_part));
    return rc;
}

noxtls_return_t noxtls_spake2p_generate_share(noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *share, uint32_t *share_len)
{
    uint8_t base_part[NOXTLS_SPAKE2P_POINT_SIZE];
    ecc_key_t key;
    noxtls_return_t rc;

    rc = noxtls_spake2p_check_share_args(ctx, share, share_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* x or y uniformly in [1, n-1] from the NoxTLS ECC key generator (DRBG). Its
     * public point x*G is computed through noxtls_ecc_point_multiply() as well. */
    memset(&key, 0, sizeof(key));
    rc = noxtls_ecc_key_generate(&key, NOXTLS_ECC_SECP256R1);
    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        ((key.d == NULL) || (noxtls_spake2p_group_scalar_is_valid(key.d) == 0) ||
         (key.Q.size != NOXTLS_SPAKE2P_SCALAR_SIZE))) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(ctx->ephemeral, key.d, NOXTLS_SPAKE2P_SCALAR_SIZE);
        base_part[0] = NOXTLS_SPAKE2P_POINT_PREFIX_UNCOMPRESSED;
        memcpy(&base_part[1], key.Q.x, NOXTLS_SPAKE2P_SCALAR_SIZE);
        memcpy(&base_part[1U + NOXTLS_SPAKE2P_SCALAR_SIZE], key.Q.y, NOXTLS_SPAKE2P_SCALAR_SIZE);
    }

    if (key.d != NULL) {
        noxtls_secure_zero(key.d, NOXTLS_SPAKE2P_SCALAR_SIZE);
    }

    (void)noxtls_ecc_key_free(&key);
    noxtls_secure_zero(&key, sizeof(key));
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_finish_share(ctx, base_part, share, share_len);
    } else {
        noxtls_spake2p_abort(ctx);
    }

    noxtls_secure_zero(base_part, sizeof(base_part));
    return rc;
}

/**
 * @brief Dispatch the profile-specific key schedule.
 * @internal
 *
 * @param[in,out] ctx Context.
 * @param[in] digest Hash(TT).
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
static noxtls_return_t noxtls_spake2p_derive_keys(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE])
{
#if NOXTLS_FEATURE_SPAKE2P_RFC9383
    if (ctx->profile == NOXTLS_SPAKE2P_PROFILE_RFC9383) {
        return noxtls_spake2p_rfc9383_derive_keys(ctx, digest);
    }

#endif
#if NOXTLS_FEATURE_SPAKE2P_MATTER
    if (ctx->profile == NOXTLS_SPAKE2P_PROFILE_MATTER) {
        return noxtls_spake2p_matter_derive_keys(ctx, digest);
    }

#endif
    (void)digest;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_spake2p_process_peer_share_ex(noxtls_spake2p_ctx_t *ctx,
                                                     const uint8_t *peer_share,
                                                     uint32_t peer_share_len,
                                                     uint8_t *Z_out,
                                                     uint8_t *V_out,
                                                     uint8_t *digest_out)
{
    uint8_t z_point[NOXTLS_SPAKE2P_POINT_SIZE];
    uint8_t v_point[NOXTLS_SPAKE2P_POINT_SIZE];
    uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE];
    uint8_t *peer_slot;
    noxtls_return_t rc;

    if ((ctx == NULL) || (peer_share == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->state != NOXTLS_SPAKE2P_STATE_SHARE_GENERATED) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (peer_share_len != NOXTLS_SPAKE2P_POINT_SIZE) {
        noxtls_spake2p_abort(ctx);
        return NOXTLS_RETURN_BAD_DATA;
    }

    peer_slot = (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) ? ctx->share_verifier : ctx->share_prover;
    memcpy(peer_slot, peer_share, NOXTLS_SPAKE2P_POINT_SIZE);
    rc = noxtls_spake2p_group_compute_zv(ctx, peer_slot, z_point, v_point);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_transcript_finish(ctx, z_point, v_point, digest);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_derive_keys(ctx, digest);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (Z_out != NULL) {
            memcpy(Z_out, z_point, NOXTLS_SPAKE2P_POINT_SIZE);
        }

        if (V_out != NULL) {
            memcpy(V_out, v_point, NOXTLS_SPAKE2P_POINT_SIZE);
        }

        if (digest_out != NULL) {
            memcpy(digest_out, digest, NOXTLS_SPAKE2P_HASH_SIZE);
        }

        /* w0, w1, L and the ephemeral scalar are no longer needed: erase them now. */
        noxtls_secure_zero(ctx->w0, sizeof(ctx->w0));
        noxtls_secure_zero(ctx->w1, sizeof(ctx->w1));
        noxtls_secure_zero(ctx->L, sizeof(ctx->L));
        noxtls_secure_zero(ctx->ephemeral, sizeof(ctx->ephemeral));
        ctx->state = NOXTLS_SPAKE2P_STATE_KEYS_DERIVED;
    } else {
        noxtls_spake2p_abort(ctx);
    }

    noxtls_secure_zero(z_point, sizeof(z_point));
    noxtls_secure_zero(v_point, sizeof(v_point));
    noxtls_secure_zero(digest, sizeof(digest));
    return rc;
}

noxtls_return_t noxtls_spake2p_process_peer_share(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t *peer_share,
                                                  uint32_t peer_share_len)
{
    return noxtls_spake2p_process_peer_share_ex(ctx, peer_share, peer_share_len, NULL, NULL, NULL);
}

/**
 * @brief Compute HMAC-SHA256(key, data) over a 65-byte share.
 * @internal
 *
 * @param[in] key Confirmation key.
 * @param[in] key_len Key length.
 * @param[in] share Share authenticated by the MAC.
 * @param[out] mac 32-byte MAC (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_spake2p_mac(const uint8_t *key, uint32_t key_len,
                                          const uint8_t share[NOXTLS_SPAKE2P_POINT_SIZE],
                                          uint8_t mac[NOXTLS_SPAKE2P_CONFIRMATION_SIZE])
{
    uint32_t mac_len = NOXTLS_SPAKE2P_CONFIRMATION_SIZE;
    noxtls_return_t rc;

    rc = noxtls_hmac_compute(NOXTLS_HASH_SHA_256, key, key_len, share, NOXTLS_SPAKE2P_POINT_SIZE,
                             mac, &mac_len);
    if ((rc != NOXTLS_RETURN_SUCCESS) || (mac_len != NOXTLS_SPAKE2P_CONFIRMATION_SIZE)) {
        noxtls_secure_zero(mac, NOXTLS_SPAKE2P_CONFIRMATION_SIZE);
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_get_confirmation(const noxtls_spake2p_ctx_t *ctx,
                                                uint8_t *confirmation,
                                                uint32_t *confirmation_len)
{
    const uint8_t *key;
    const uint8_t *peer_share;

    if ((ctx == NULL) || (confirmation == NULL) || (confirmation_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((ctx->state != NOXTLS_SPAKE2P_STATE_KEYS_DERIVED) &&
        (ctx->state != NOXTLS_SPAKE2P_STATE_CONFIRMED)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (*confirmation_len < NOXTLS_SPAKE2P_CONFIRMATION_SIZE) {
        *confirmation_len = NOXTLS_SPAKE2P_CONFIRMATION_SIZE;
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* Prover: confirmP = MAC(K_confirmP, shareV). Verifier: confirmV = MAC(K_confirmV, shareP). */
    if (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) {
        key = ctx->confirm_key_prover;
        peer_share = ctx->share_verifier;
    } else {
        key = ctx->confirm_key_verifier;
        peer_share = ctx->share_prover;
    }

    if (noxtls_spake2p_mac(key, ctx->confirm_key_len, peer_share, confirmation) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    *confirmation_len = NOXTLS_SPAKE2P_CONFIRMATION_SIZE;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_verify_peer_confirmation(noxtls_spake2p_ctx_t *ctx,
                                                        const uint8_t *confirmation,
                                                        uint32_t confirmation_len)
{
    uint8_t expected[NOXTLS_SPAKE2P_CONFIRMATION_SIZE];
    const uint8_t *key;
    const uint8_t *own_share;
    noxtls_return_t rc;

    if ((ctx == NULL) || (confirmation == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->state != NOXTLS_SPAKE2P_STATE_KEYS_DERIVED) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (confirmation_len != NOXTLS_SPAKE2P_CONFIRMATION_SIZE) {
        noxtls_spake2p_abort(ctx);
        return NOXTLS_RETURN_FAILED;
    }

    /* The peer authenticates our share with its own confirmation key. */
    if (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) {
        key = ctx->confirm_key_verifier;
        own_share = ctx->share_prover;
    } else {
        key = ctx->confirm_key_prover;
        own_share = ctx->share_verifier;
    }

    rc = noxtls_spake2p_mac(key, ctx->confirm_key_len, own_share, expected);
    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_ct_equal(expected, confirmation, NOXTLS_SPAKE2P_CONFIRMATION_SIZE) != 0)) {
        ctx->state = NOXTLS_SPAKE2P_STATE_CONFIRMED;
    } else {
        noxtls_spake2p_abort(ctx);
        rc = NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero(expected, sizeof(expected));
    return rc;
}

noxtls_return_t noxtls_spake2p_get_shared_key(const noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *key, uint32_t *key_len)
{
    if ((ctx == NULL) || (key == NULL) || (key_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->state != NOXTLS_SPAKE2P_STATE_CONFIRMED) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (*key_len < ctx->shared_key_len) {
        *key_len = ctx->shared_key_len;
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(key, ctx->shared_key, ctx->shared_key_len);
    *key_len = ctx->shared_key_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_free(noxtls_spake2p_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(ctx, sizeof(*ctx));
    ctx->state = NOXTLS_SPAKE2P_STATE_EMPTY;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_derive_w0_w1(const uint8_t *ws, uint32_t ws_len,
                                            uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                            uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    noxtls_return_t rc;

    if ((ws == NULL) || (w0 == NULL) || (w1 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
    noxtls_secure_zero(w1, NOXTLS_SPAKE2P_SCALAR_SIZE);
    if (ws_len != NOXTLS_SPAKE2P_WS_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* RFC 9383 section 3.2: w0 = w0s mod p, w1 = w1s mod p (p = group order n). */
    rc = noxtls_spake2p_group_reduce_mod_n(ws, NOXTLS_SPAKE2P_WS_HALF_SIZE, w0);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_group_reduce_mod_n(&ws[NOXTLS_SPAKE2P_WS_HALF_SIZE],
                                               NOXTLS_SPAKE2P_WS_HALF_SIZE, w1);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        ((noxtls_spake2p_group_scalar_is_valid(w0) & noxtls_spake2p_group_scalar_is_valid(w1)) == 0)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
        noxtls_secure_zero(w1, NOXTLS_SPAKE2P_SCALAR_SIZE);
    }

    return rc;
}

noxtls_return_t noxtls_spake2p_compute_L(const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                         uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE])
{
    if ((w1 == NULL) || (L == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 9383 section 3.2: L = w1*G. */
    return noxtls_spake2p_group_mul_base(w1, L);
}
