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
* File:    noxtls_spake2p_transcript.c
* Summary: SPAKE2+ protocol transcript TT (shared by all profiles)
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_transcript.c
 * @brief Streaming SHA-256 over the SPAKE2+ transcript TT.
 * @ingroup noxtls_spake2p
 *
 * RFC 9383 section 3.3 defines TT as the concatenation of
 * len(Context)||Context, len(idProver)||idProver, len(idVerifier)||idVerifier,
 * len(M)||M, len(N)||N, len(shareP)||shareP, len(shareV)||shareV,
 * len(Z)||Z, len(V)||V and len(w0)||w0, where len() is an 8-byte
 * little-endian length. draft-bar-cfrg-spake2plus-01 section 3.3 (Matter)
 * uses the identical layout, so TT is shared and only Hash(TT) is consumed
 * differently by the profile key schedules. TT itself is never buffered.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_spake2p_internal.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "common/noxtls_ct.h"

/** @brief Bits per byte used to serialize the little-endian length prefix. */
#define NOXTLS_SPAKE2P_TT_BITS_PER_BYTE (8U)

/**
 * @brief Absorb len(data) || data into the running transcript hash.
 * @internal
 *
 * @param[in,out] ctx Context holding the SHA-256 state.
 * @param[in] data Element bytes (may be NULL when len is 0).
 * @param[in] len Element length.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_spake2p_tt_absorb(noxtls_spake2p_ctx_t *ctx,
                                                const uint8_t *data, uint32_t len)
{
    uint8_t prefix[NOXTLS_SPAKE2P_TT_LENGTH_PREFIX_SIZE];
    uint64_t value = (uint64_t)len;
    uint32_t index;

    for (index = 0U; index < NOXTLS_SPAKE2P_TT_LENGTH_PREFIX_SIZE; ++index) {
        prefix[index] = (uint8_t)(value & 0xFFU);
        value >>= NOXTLS_SPAKE2P_TT_BITS_PER_BYTE;
    }

    if (noxtls_sha256_update(&ctx->transcript, prefix, NOXTLS_SPAKE2P_TT_LENGTH_PREFIX_SIZE) !=
        NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    if ((len > 0U) &&
        (noxtls_sha256_update(&ctx->transcript, (uint8_t *)data, len) != NOXTLS_RETURN_SUCCESS)) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_transcript_start(noxtls_spake2p_ctx_t *ctx,
                                                const noxtls_spake2p_params_t *params)
{
    noxtls_return_t rc;

    if ((ctx == NULL) || (params == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (noxtls_sha256_init(&ctx->transcript, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_spake2p_tt_absorb(ctx, params->context, params->context_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, params->id_prover, params->id_prover_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, params->id_verifier, params->id_verifier_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, noxtls_spake2p_p256_M(), NOXTLS_SPAKE2P_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, noxtls_spake2p_p256_N(), NOXTLS_SPAKE2P_POINT_SIZE);
    }

    return rc;
}

noxtls_return_t noxtls_spake2p_transcript_finish(noxtls_spake2p_ctx_t *ctx,
                                                 const uint8_t Z[NOXTLS_SPAKE2P_POINT_SIZE],
                                                 const uint8_t V[NOXTLS_SPAKE2P_POINT_SIZE],
                                                 uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE])
{
    noxtls_return_t rc;

    if ((ctx == NULL) || (Z == NULL) || (V == NULL) || (digest == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_spake2p_tt_absorb(ctx, ctx->share_prover, NOXTLS_SPAKE2P_POINT_SIZE);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, ctx->share_verifier, NOXTLS_SPAKE2P_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, Z, NOXTLS_SPAKE2P_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, V, NOXTLS_SPAKE2P_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_tt_absorb(ctx, ctx->w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_sha256_finish(&ctx->transcript, digest) != NOXTLS_RETURN_SUCCESS)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero(&ctx->transcript, sizeof(ctx->transcript));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(digest, NOXTLS_SPAKE2P_HASH_SIZE);
    }

    return rc;
}
