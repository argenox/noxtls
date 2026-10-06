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
* File:    noxtls_matter_pase.h
* Summary: Matter PASE cryptographic helpers on the SPAKE2+ Matter profile
*
*
*****************************************************************************/

/**
 * @file noxtls_matter_pase.h
 * @brief Matter PASE crypto helpers: passcode verifier, PASE context, session keys.
 * @ingroup noxtls_matter_pase
 */

/**
 * @defgroup noxtls_matter_pase Matter PASE cryptography
 * @brief Cryptographic parts of Matter Passcode-Authenticated Session Establishment.
 *
 * Specification: Matter Core specification 1.x, section 3.9 (Crypto_PBKDF),
 * section 3.10 (SPAKE2+, draft-bar-cfrg-spake2plus-01) and section 4.14.1
 * (PASE). Uses the #NOXTLS_SPAKE2P_PROFILE_MATTER SPAKE2+ profile.
 *
 * Boundary: this module takes and returns raw byte strings only. Matter
 * TLV encoding/decoding of PBKDFParamRequest, PBKDFParamResponse, Pake1,
 * Pake2 and Pake3, session IDs, MRP and the secure-session table stay in
 * the Matter stack (NoxMatter). The caller passes the exact TLV-encoded
 * PBKDFParamRequest/Response payload bytes to
 * noxtls_matter_pase_compute_context().
 *
 * Flow (initiator = commissioner = SPAKE2+ prover; responder = device =
 * SPAKE2+ verifier):
 * - Commissioner: noxtls_matter_pase_compute_w0_w1() from the passcode and
 *   the PBKDF parameters in PBKDFParamResponse.
 * - Device: noxtls_matter_pase_parse_verifier() on its stored w0 || L
 *   (or noxtls_matter_pase_compute_verifier() during manufacturing).
 * - Both: context = noxtls_matter_pase_compute_context(request, response),
 *   then noxtls_matter_pase_initiator_init() or
 *   noxtls_matter_pase_responder_init(), then the generic SPAKE2+ calls:
 *   Pake1 carries pA (shareP), Pake2 carries pB (shareV) and cB, Pake3
 *   carries cA.
 * - After key confirmation: noxtls_matter_pase_derive_session_keys().
 */

#ifndef _NOXTLS_MATTER_PASE_H_
#define _NOXTLS_MATTER_PASE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_spake2p.h"
#include "noxtls_matter_pase_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check a setup passcode against Matter Core section 5.1.7.1.
 *
 * Valid passcodes are 00000001..99999998 excluding 11111111, 22222222, ...,
 * 99999999, 12345678 and 87654321.
 *
 * @param[in] passcode Setup passcode.
 *
 * @return 1 when allowed, 0 otherwise.
 */
int noxtls_matter_pase_passcode_is_valid(uint32_t passcode);

/**
 * @brief Commissioner side: derive w0 and w1 from the setup passcode (Matter Core section 3.10).
 *
 * w0s || w1s = PBKDF2-HMAC-SHA256(passcode as 4-byte little-endian, salt,
 * iterations, 80 bytes); w0 = w0s mod n, w1 = w1s mod n.
 *
 * @param[in] passcode Setup passcode (must satisfy noxtls_matter_pase_passcode_is_valid()).
 * @param[in] salt PBKDF salt (16 to 32 bytes).
 * @param[in] salt_len Salt length.
 * @param[in] iterations PBKDF iteration count (1000 to 100000).
 * @param[out] w0 Big-endian w0 (erased on failure).
 * @param[out] w1 Big-endian w1 (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (passcode, salt or iteration count out of range) or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_matter_pase_compute_w0_w1(uint32_t passcode,
                                                 const uint8_t *salt, uint32_t salt_len,
                                                 uint32_t iterations,
                                                 uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                 uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Manufacturing side: compute the serialized verifier w0 || L (97 bytes).
 *
 * @param[in] passcode Setup passcode.
 * @param[in] salt PBKDF salt (16 to 32 bytes).
 * @param[in] salt_len Salt length.
 * @param[in] iterations PBKDF iteration count (1000 to 100000).
 * @param[out] verifier Serialized verifier (erased on failure).
 *
 * @return As noxtls_matter_pase_compute_w0_w1(), or an ECC error.
 */
noxtls_return_t noxtls_matter_pase_compute_verifier(uint32_t passcode,
                                                    const uint8_t *salt, uint32_t salt_len,
                                                    uint32_t iterations,
                                                    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE]);

/**
 * @brief Device side: split and validate a serialized verifier w0 || L.
 *
 * @param[in] verifier Serialized verifier.
 * @param[in] verifier_len Must be NOXTLS_MATTER_PASE_VERIFIER_SIZE (97).
 * @param[out] w0 Big-endian w0 in [1, n-1] (erased on failure).
 * @param[out] L Validated uncompressed point (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (bad length or w0 out of range) or NOXTLS_RETURN_BAD_DATA (L invalid).
 */
noxtls_return_t noxtls_matter_pase_parse_verifier(const uint8_t *verifier, uint32_t verifier_len,
                                                  uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Compute the SPAKE2+ Context for PASE (Matter Core section 4.14.1.2).
 *
 * Context = SHA-256("CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse),
 * over the exact TLV payload bytes exchanged on the wire.
 *
 * @param[in] pbkdf_param_request PBKDFParamRequest payload bytes.
 * @param[in] request_len Request length (non-zero).
 * @param[in] pbkdf_param_response PBKDFParamResponse payload bytes.
 * @param[in] response_len Response length (non-zero).
 * @param[out] context 32-byte context hash.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_matter_pase_compute_context(const uint8_t *pbkdf_param_request, uint32_t request_len,
                                                   const uint8_t *pbkdf_param_response, uint32_t response_len,
                                                   uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE]);

/**
 * @brief Initialize the commissioner (initiator / SPAKE2+ prover) on the Matter profile.
 *
 * Matter PASE uses empty prover and verifier identities.
 *
 * @param[out] ctx SPAKE2+ context.
 * @param[in] context 32-byte PASE context hash.
 * @param[in] w0 Big-endian w0.
 * @param[in] w1 Big-endian w1.
 *
 * @return As noxtls_spake2p_prover_init().
 */
noxtls_return_t noxtls_matter_pase_initiator_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Initialize the device (responder / SPAKE2+ verifier) on the Matter profile.
 *
 * @param[out] ctx SPAKE2+ context.
 * @param[in] context 32-byte PASE context hash.
 * @param[in] w0 Big-endian w0.
 * @param[in] L Verifier point L.
 *
 * @return As noxtls_spake2p_verifier_init().
 */
noxtls_return_t noxtls_matter_pase_responder_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Derive the PASE session keys after key confirmation (Matter Core section 4.14.1.3).
 *
 * I2RKey || R2IKey || AttestationChallenge = HKDF-SHA256(salt = [], ikm = Ke,
 * info = "SessionKeys", 48 bytes).
 *
 * @param[in] ctx Matter-profile SPAKE2+ context in the CONFIRMED state.
 * @param[out] i2r_key Initiator-to-responder AES-CCM key (16 bytes).
 * @param[out] r2i_key Responder-to-initiator AES-CCM key (16 bytes).
 * @param[out] attestation_challenge Attestation challenge (16 bytes).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (not a Matter-profile context), NOXTLS_RETURN_NOT_INITIALIZED (not
 *         confirmed) or NOXTLS_RETURN_FAILED. Outputs are erased on failure.
 */
noxtls_return_t noxtls_matter_pase_derive_session_keys(const noxtls_spake2p_ctx_t *ctx,
                                                       uint8_t i2r_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t r2i_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t attestation_challenge[NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_MATTER_PASE_H_ */
