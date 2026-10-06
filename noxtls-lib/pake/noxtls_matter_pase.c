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
* File:    noxtls_matter_pase.c
* Summary: Matter PASE cryptographic helpers on the SPAKE2+ Matter profile
*
*
*****************************************************************************/

/**
 * @file noxtls_matter_pase.c
 * @brief Matter PASE verifier, context and session-key derivation.
 * @ingroup noxtls_matter_pase
 *
 * Matter Core specification 1.x sections 3.9, 3.10, 4.14.1 and 5.1.7.1.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_matter_pase.h"
#include "noxtls_spake2p_internal.h"
#include "kdf/noxtls_pbkdf.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "common/noxtls_ct.h"

/** @brief Repeated-digit passcode stride (11111111 .. 99999999 are disallowed). */
#define NOXTLS_MATTER_PASE_REPEATED_DIGIT_STEP (11111111UL)
/** @brief Number of repeated-digit passcodes to reject (1..9). */
#define NOXTLS_MATTER_PASE_REPEATED_DIGIT_COUNT (9UL)
/** @brief Disallowed ascending sequence passcode. */
#define NOXTLS_MATTER_PASE_PASSCODE_ASCENDING (12345678UL)
/** @brief Disallowed descending sequence passcode. */
#define NOXTLS_MATTER_PASE_PASSCODE_DESCENDING (87654321UL)
/** @brief Bits per byte for the little-endian passcode encoding. */
#define NOXTLS_MATTER_PASE_BITS_PER_BYTE (8U)
/** @brief Length of the context prefix without the terminator. */
#define NOXTLS_MATTER_PASE_CONTEXT_PREFIX_LEN ((uint32_t)(sizeof(NOXTLS_MATTER_PASE_CONTEXT_PREFIX) - 1U))
/** @brief Length of the SessionKeys label without the terminator. */
#define NOXTLS_MATTER_PASE_SESSION_KEYS_INFO_LEN ((uint32_t)(sizeof(NOXTLS_MATTER_PASE_SESSION_KEYS_INFO) - 1U))

int noxtls_matter_pase_passcode_is_valid(uint32_t passcode)
{
    uint32_t digit;

    if ((passcode == 0U) || (passcode > NOXTLS_MATTER_PASE_PASSCODE_MAX) ||
        (passcode == NOXTLS_MATTER_PASE_PASSCODE_ASCENDING) ||
        (passcode == NOXTLS_MATTER_PASE_PASSCODE_DESCENDING)) {
        return 0;
    }

    for (digit = 1U; digit <= NOXTLS_MATTER_PASE_REPEATED_DIGIT_COUNT; ++digit) {
        if (passcode == (digit * NOXTLS_MATTER_PASE_REPEATED_DIGIT_STEP)) {
            return 0;
        }
    }

    return 1;
}

noxtls_return_t noxtls_matter_pase_compute_w0_w1(uint32_t passcode,
                                                 const uint8_t *salt, uint32_t salt_len,
                                                 uint32_t iterations,
                                                 uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                 uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint8_t encoded[NOXTLS_MATTER_PASE_PASSCODE_ENCODED_SIZE];
    uint8_t ws[NOXTLS_SPAKE2P_WS_SIZE];
    uint32_t value = passcode;
    uint32_t index;
    noxtls_return_t rc;

    if ((salt == NULL) || (w0 == NULL) || (w1 == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
    noxtls_secure_zero(w1, NOXTLS_SPAKE2P_SCALAR_SIZE);
    if ((noxtls_matter_pase_passcode_is_valid(passcode) == 0) ||
        (salt_len < NOXTLS_MATTER_PASE_SALT_MIN_SIZE) || (salt_len > NOXTLS_MATTER_PASE_SALT_MAX_SIZE) ||
        (iterations < NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MIN) ||
        (iterations > NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MAX)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* Matter Core section 3.10: the passcode is fed to Crypto_PBKDF as a 32-bit little-endian integer. */
    for (index = 0U; index < NOXTLS_MATTER_PASE_PASSCODE_ENCODED_SIZE; ++index) {
        encoded[index] = (uint8_t)(value & 0xFFU);
        value >>= NOXTLS_MATTER_PASE_BITS_PER_BYTE;
    }

    rc = noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, encoded, NOXTLS_MATTER_PASE_PASSCODE_ENCODED_SIZE,
                            salt, salt_len, iterations, ws, NOXTLS_SPAKE2P_WS_SIZE);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_derive_w0_w1(ws, NOXTLS_SPAKE2P_WS_SIZE, w0, w1);
    }

    noxtls_secure_zero(encoded, sizeof(encoded));
    noxtls_secure_zero(ws, sizeof(ws));
    return rc;
}

noxtls_return_t noxtls_matter_pase_compute_verifier(uint32_t passcode,
                                                    const uint8_t *salt, uint32_t salt_len,
                                                    uint32_t iterations,
                                                    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE])
{
    uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE];
    noxtls_return_t rc;

    if (verifier == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_matter_pase_compute_w0_w1(passcode, salt, salt_len, iterations, verifier, w1);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_compute_L(w1, &verifier[NOXTLS_SPAKE2P_SCALAR_SIZE]);
    }

    noxtls_secure_zero(w1, sizeof(w1));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(verifier, NOXTLS_MATTER_PASE_VERIFIER_SIZE);
    }

    return rc;
}

noxtls_return_t noxtls_matter_pase_parse_verifier(const uint8_t *verifier, uint32_t verifier_len,
                                                  uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE])
{
    noxtls_return_t rc;

    if ((verifier == NULL) || (w0 == NULL) || (L == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(w0, NOXTLS_SPAKE2P_SCALAR_SIZE);
    noxtls_secure_zero(L, NOXTLS_SPAKE2P_POINT_SIZE);
    if ((verifier_len != NOXTLS_MATTER_PASE_VERIFIER_SIZE) ||
        (noxtls_spake2p_group_scalar_is_valid(verifier) == 0)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_spake2p_group_validate_point(&verifier[NOXTLS_SPAKE2P_SCALAR_SIZE]);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(w0, verifier, NOXTLS_SPAKE2P_SCALAR_SIZE);
        memcpy(L, &verifier[NOXTLS_SPAKE2P_SCALAR_SIZE], NOXTLS_SPAKE2P_POINT_SIZE);
    }

    return rc;
}

noxtls_return_t noxtls_matter_pase_compute_context(const uint8_t *pbkdf_param_request, uint32_t request_len,
                                                   const uint8_t *pbkdf_param_response, uint32_t response_len,
                                                   uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE])
{
    noxtls_sha_ctx_t sha;
    noxtls_return_t rc;

    if ((pbkdf_param_request == NULL) || (pbkdf_param_response == NULL) || (context == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((request_len == 0U) || (response_len == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&sha, (uint8_t *)NOXTLS_MATTER_PASE_CONTEXT_PREFIX,
                                  NOXTLS_MATTER_PASE_CONTEXT_PREFIX_LEN);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&sha, (uint8_t *)pbkdf_param_request, request_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&sha, (uint8_t *)pbkdf_param_response, response_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_finish(&sha, context);
    }

    noxtls_secure_zero(&sha, sizeof(sha));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(context, NOXTLS_MATTER_PASE_CONTEXT_SIZE);
        rc = NOXTLS_RETURN_FAILED;
    }

    return rc;
}

/**
 * @brief Build SPAKE2+ transcript parameters for PASE: 32-byte context, empty identities.
 * @internal
 *
 * @param[out] params Parameters.
 * @param[in] context PASE context hash.
 */
static void noxtls_matter_pase_params(noxtls_spake2p_params_t *params,
                                      const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE])
{
    memset(params, 0, sizeof(*params));
    params->context = context;
    params->context_len = NOXTLS_MATTER_PASE_CONTEXT_SIZE;
}

noxtls_return_t noxtls_matter_pase_initiator_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    noxtls_spake2p_params_t params;

    if (context == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_matter_pase_params(&params, context);
    return noxtls_spake2p_prover_init(ctx, NOXTLS_SPAKE2P_PROFILE_MATTER, &params, w0, w1);
}

noxtls_return_t noxtls_matter_pase_responder_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE])
{
    noxtls_spake2p_params_t params;

    if (context == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_matter_pase_params(&params, context);
    return noxtls_spake2p_verifier_init(ctx, NOXTLS_SPAKE2P_PROFILE_MATTER, &params, w0, L);
}

noxtls_return_t noxtls_matter_pase_derive_session_keys(const noxtls_spake2p_ctx_t *ctx,
                                                       uint8_t i2r_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t r2i_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t attestation_challenge[NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE])
{
    uint8_t okm[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE * NOXTLS_MATTER_PASE_SESSION_KEY_COUNT];
    uint8_t ke[NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE];
    uint32_t ke_len = NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE;
    noxtls_return_t rc;

    if ((ctx == NULL) || (i2r_key == NULL) || (r2i_key == NULL) || (attestation_challenge == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(i2r_key, NOXTLS_MATTER_PASE_SESSION_KEY_SIZE);
    noxtls_secure_zero(r2i_key, NOXTLS_MATTER_PASE_SESSION_KEY_SIZE);
    noxtls_secure_zero(attestation_challenge, NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE);
    if (ctx->state != NOXTLS_SPAKE2P_STATE_CONFIRMED) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if (ctx->profile != NOXTLS_SPAKE2P_PROFILE_MATTER) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_spake2p_get_shared_key(ctx, ke, &ke_len);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (ke_len != NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    /* Matter Core section 4.14.1.3: Crypto_KDF(Ke, salt = [], "SessionKeys", 3 * 128 bits). */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_kdf(ke, ke_len, (const uint8_t *)NOXTLS_MATTER_PASE_SESSION_KEYS_INFO,
                                NOXTLS_MATTER_PASE_SESSION_KEYS_INFO_LEN, okm, (uint32_t)sizeof(okm));
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(i2r_key, okm, NOXTLS_MATTER_PASE_SESSION_KEY_SIZE);
        memcpy(r2i_key, &okm[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE], NOXTLS_MATTER_PASE_SESSION_KEY_SIZE);
        memcpy(attestation_challenge, &okm[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE * 2U],
               NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE);
    }

    noxtls_secure_zero(okm, sizeof(okm));
    noxtls_secure_zero(ke, sizeof(ke));
    return rc;
}
