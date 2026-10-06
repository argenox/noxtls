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
* File:    noxtls_spake2p_internal.h
* Summary: SPAKE2+ internal interfaces shared by the module source files
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_internal.h
 * @brief Internal SPAKE2+ group, transcript and key-schedule interfaces.
 * @ingroup noxtls_spake2p
 *
 * Not part of the public API. Unit tests include this header to check
 * intermediate RFC 9383 Appendix C values (Z, V, K_main).
 */

#ifndef _NOXTLS_SPAKE2P_INTERNAL_H_
#define _NOXTLS_SPAKE2P_INTERNAL_H_

#include <stdint.h>

#include "noxtls_spake2p.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Group math (noxtls_spake2p_group.c): RFC 9383 sections 3.2, 3.3 and 4.   */
/* ------------------------------------------------------------------------ */

/**
 * @brief Constant-time check that a big-endian scalar is in [1, n-1] for P-256.
 *
 * @param[in] scalar 32-byte big-endian scalar.
 *
 * @return 1 when valid, 0 otherwise.
 */
int noxtls_spake2p_group_scalar_is_valid(const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Constant-time reduction of a big-endian integer modulo the P-256 order n.
 *
 * @param[in] in Big-endian integer.
 * @param[in] in_len Length of in in bytes (any length).
 * @param[out] out 32-byte big-endian result in [0, n-1].
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NULL.
 */
noxtls_return_t noxtls_spake2p_group_reduce_mod_n(const uint8_t *in, uint32_t in_len,
                                                  uint8_t out[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Validate an encoded point: uncompressed prefix, canonical coordinates, on curve, not identity.
 *
 * @param[in] point 65-byte encoding.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_BAD_DATA (NOXTLS_RETURN_NULL for NULL,
 *         or an ECC curve setup error).
 */
noxtls_return_t noxtls_spake2p_group_validate_point(const uint8_t point[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Compute scalar*G for a scalar in [1, n-1].
 *
 * @param[in] scalar 32-byte big-endian scalar.
 * @param[out] out 65-byte uncompressed result (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t noxtls_spake2p_group_mul_base(const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                              uint8_t out[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Compute a share: base_part + w0*{M for prover | N for verifier}.
 *
 * @param[in] role Local role; selects M (prover) or N (verifier).
 * @param[in] base_part Encoded ephemeral*G.
 * @param[in] w0 32-byte big-endian w0.
 * @param[out] share 65-byte uncompressed share (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t noxtls_spake2p_group_compute_share(noxtls_spake2p_role_t role,
                                                   const uint8_t base_part[NOXTLS_SPAKE2P_POINT_SIZE],
                                                   const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                   uint8_t share[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Compute Z and V from the validated peer share (RFC 9383 section 3.3, h = 1).
 *
 * Prover: T = Y - w0*N, Z = x*T, V = w1*T. Verifier: T = X - w0*M, Z = y*T, V = y*L.
 *
 * @param[in] ctx Context holding role, w0, w1 or L and the ephemeral scalar.
 * @param[in] peer_share Validated peer share.
 * @param[out] Z 65-byte uncompressed Z (erased on failure).
 * @param[out] V 65-byte uncompressed V (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA when T, Z or V is the identity,
 *         or another error code.
 */
noxtls_return_t noxtls_spake2p_group_compute_zv(const noxtls_spake2p_ctx_t *ctx,
                                                const uint8_t peer_share[NOXTLS_SPAKE2P_POINT_SIZE],
                                                uint8_t Z[NOXTLS_SPAKE2P_POINT_SIZE],
                                                uint8_t V[NOXTLS_SPAKE2P_POINT_SIZE]);

/* ------------------------------------------------------------------------ */
/* Transcript (noxtls_spake2p_transcript.c): RFC 9383 section 3.3.          */
/* ------------------------------------------------------------------------ */

/**
 * @brief Start TT and absorb Context, idProver, idVerifier, M and N.
 *
 * @param[in,out] ctx Context.
 * @param[in] params Context and identities.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_transcript_start(noxtls_spake2p_ctx_t *ctx,
                                                const noxtls_spake2p_params_t *params);

/**
 * @brief Absorb shareP, shareV, Z, V and w0, then output Hash(TT).
 *
 * @param[in,out] ctx Context (shares already stored).
 * @param[in] Z Encoded Z.
 * @param[in] V Encoded V.
 * @param[out] digest SHA-256(TT).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_transcript_finish(noxtls_spake2p_ctx_t *ctx,
                                                 const uint8_t Z[NOXTLS_SPAKE2P_POINT_SIZE],
                                                 const uint8_t V[NOXTLS_SPAKE2P_POINT_SIZE],
                                                 uint8_t digest[NOXTLS_SPAKE2P_HASH_SIZE]);

/* ------------------------------------------------------------------------ */
/* Key schedules: shared KDF/MAC helpers and per-profile derivation.        */
/* ------------------------------------------------------------------------ */

/**
 * @brief KDF(nil, ikm, info) = HKDF-SHA256 with an empty salt (RFC 5869).
 *
 * @param[in] ikm Input keying material.
 * @param[in] ikm_len Length of ikm.
 * @param[in] info Info label.
 * @param[in] info_len Length of info.
 * @param[out] out Output keying material (erased on failure).
 * @param[in] out_len Output length.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_kdf(const uint8_t *ikm, uint32_t ikm_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *out, uint32_t out_len);

#if NOXTLS_FEATURE_SPAKE2P_RFC9383
/**
 * @brief RFC 9383 section 3.4 key schedule from K_main = Hash(TT).
 *
 * @param[in,out] ctx Context receiving K_confirmP, K_confirmV and K_shared.
 * @param[in] k_main SHA-256(TT).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_rfc9383_derive_keys(noxtls_spake2p_ctx_t *ctx,
                                                   const uint8_t k_main[NOXTLS_SPAKE2P_HASH_SIZE]);
#endif

#if NOXTLS_FEATURE_SPAKE2P_MATTER
/**
 * @brief draft-bar-cfrg-spake2plus-01 section 3.4 (Matter) key schedule from Ka || Ke = Hash(TT).
 *
 * @param[in,out] ctx Context receiving KcA, KcB and Ke.
 * @param[in] ka_ke SHA-256(TT).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_matter_derive_keys(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t ka_ke[NOXTLS_SPAKE2P_HASH_SIZE]);
#endif

/**
 * @brief Abort: erase all secrets and mark the context FAILED.
 *
 * @param[in,out] ctx Context.
 */
void noxtls_spake2p_abort(noxtls_spake2p_ctx_t *ctx);

/**
 * @brief Process the peer share and optionally export intermediates for known-answer tests.
 *
 * Identical to noxtls_spake2p_process_peer_share(); each optional output
 * may be NULL. Callers that request intermediates own their erasure.
 *
 * @param[in,out] ctx Context in the SHARE_GENERATED state.
 * @param[in] peer_share Peer share.
 * @param[in] peer_share_len Peer share length.
 * @param[out] Z_out Optional copy of Z.
 * @param[out] V_out Optional copy of V.
 * @param[out] digest_out Optional copy of Hash(TT) (K_main, or Ka || Ke).
 *
 * @return As noxtls_spake2p_process_peer_share().
 */
noxtls_return_t noxtls_spake2p_process_peer_share_ex(noxtls_spake2p_ctx_t *ctx,
                                                     const uint8_t *peer_share,
                                                     uint32_t peer_share_len,
                                                     uint8_t *Z_out,
                                                     uint8_t *V_out,
                                                     uint8_t *digest_out);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_SPAKE2P_INTERNAL_H_ */
