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
* File:    noxtls_spake2p.h
* Summary: SPAKE2+ augmented PAKE (RFC 9383) with a Matter draft-01 profile
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p.h
 * @brief SPAKE2+ (P-256, SHA-256, HKDF-SHA256, HMAC-SHA256) prover and verifier.
 * @ingroup noxtls_spake2p
 */

/**
 * @defgroup noxtls_spake2p SPAKE2+
 * @brief SPAKE2+ augmented password-authenticated key exchange.
 *
 * Specifications:
 * - RFC 9383 "SPAKE2+, an Augmented Password-Authenticated Key Exchange
 *   (PAKE) Protocol" (May 2023), ciphersuite
 *   P256-SHA256-HKDF-SHA256-HMAC-SHA256. This is the standard and the
 *   default profile (#NOXTLS_SPAKE2P_PROFILE_RFC9383).
 * - draft-bar-cfrg-spake2plus-01 (the pre-standard draft referenced by the
 *   Matter Core specification 1.x section 3.10 for PASE). Provided only for
 *   Matter PASE interoperability (#NOXTLS_SPAKE2P_PROFILE_MATTER).
 *
 * Both profiles share the group math and the transcript:
 * - M and N are the RFC 9383 section 4 P-256 points; cofactor h = 1.
 * - shareP = X = x*G + w0*M, shareV = Y = y*G + w0*N (RFC 9383 section 3.3).
 * - Prover:   Z = h*x*(Y - w0*N), V = h*w1*(Y - w0*N).
 *   Verifier: Z = h*y*(X - w0*M), V = h*y*L.
 * - TT = len(Context)||Context || len(idProver)||idProver ||
 *        len(idVerifier)||idVerifier || len(M)||M || len(N)||N ||
 *        len(shareP)||shareP || len(shareV)||shareV || len(Z)||Z ||
 *        len(V)||V || len(w0)||w0, with 8-byte little-endian lengths.
 *   Empty identities are encoded as a zero length prefix.
 *
 * The profiles differ only in the key schedule:
 *
 * | Step              | RFC 9383 (section 3.4)                     | Matter / draft-01 (section 3.4)            |
 * |-------------------|--------------------------------------------|--------------------------------------------|
 * | Transcript digest | K_main = SHA-256(TT) (32 bytes)            | Ka or Ke = SHA-256(TT), Ka = first 16 bytes, Ke = last 16 |
 * | Confirmation keys | K_confirmP or K_confirmV = HKDF(nil, K_main, "ConfirmationKeys"), 32 + 32 bytes | KcA or KcB = HKDF(nil, Ka, "ConfirmationKeys"), 16 + 16 bytes |
 * | Prover confirms   | confirmP = HMAC(K_confirmP, shareV)        | cA = HMAC(KcA, Y)                          |
 * | Verifier confirms | confirmV = HMAC(K_confirmV, shareP)        | cB = HMAC(KcB, X)                          |
 * | Shared secret     | K_shared = HKDF(nil, K_main, "SharedKey"), 32 bytes | Ke, 16 bytes                     |
 *
 * The two profiles are therefore not interchangeable: identical inputs give
 * different confirmations and shared keys, and peers using different
 * profiles fail key confirmation.
 *
 * Message flow (RFC 9383 section 3.3, Figure 1). Each side calls
 * noxtls_spake2p_generate_share() before noxtls_spake2p_process_peer_share():
 * - Prover: init -> generate_share (send shareP) -> receive shareV ->
 *   process_peer_share -> verify_peer_confirmation(confirmV) ->
 *   get_confirmation (send confirmP) -> get_shared_key.
 * - Verifier: init -> receive shareP -> generate_share (send shareV) ->
 *   process_peer_share(shareP) -> get_confirmation (send confirmV) ->
 *   verify_peer_confirmation(confirmP) -> get_shared_key.
 *
 * Security properties:
 * - Received shares must be uncompressed SEC 1 points with canonical
 *   coordinates (less than p), on the curve and not the identity; T = peer -
 *   w0*{M|N}, Z and V must not be the identity. Any failure aborts the
 *   exchange and erases the context.
 * - Confirmation MACs are compared in constant time. A wrong confirmation
 *   aborts and erases the context; there is no retry.
 * - Secret scalars are reduced and range checked with constant-time code.
 *   Every scalar multiplication goes through noxtls_ecc_point_multiply(), so
 *   a bound platform P-256 accelerator port (for example the CC13xx PKA
 *   callback port) is used automatically. Point addition uses the generic
 *   NoxTLS affine/Jacobian helpers, which are not constant-time.
 * - All secrets (w0, w1, x or y, Z, V, keys) are erased with
 *   noxtls_secure_zero() on failure and by noxtls_spake2p_free().
 * - The context embeds a SHA-256 state (about 1 KB); allocate it statically
 *   or from a pool on small stacks.
 * - The HMAC module keeps one SHA-256 inner context, so SPAKE2+ calls must
 *   not interleave with another live HMAC-SHA256 computation.
 */

#ifndef _NOXTLS_SPAKE2P_H_
#define _NOXTLS_SPAKE2P_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_sha.h"
#include "noxtls_spake2p_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Key-schedule profile, selected per context at initialization. */
typedef enum
{
    /** RFC 9383 section 3.4 key schedule (the standard; default). */
    NOXTLS_SPAKE2P_PROFILE_RFC9383 = 0,
    /** draft-bar-cfrg-spake2plus-01 key schedule used by Matter PASE (interoperability only). */
    NOXTLS_SPAKE2P_PROFILE_MATTER = 1
} noxtls_spake2p_profile_t;

/** @brief Protocol role. */
typedef enum
{
    /** RFC 9383 Prover (holds w0, w1). Matter: PASE initiator / commissioner. */
    NOXTLS_SPAKE2P_ROLE_PROVER = 0,
    /** RFC 9383 Verifier (holds w0, L). Matter: PASE responder / commissionee device. */
    NOXTLS_SPAKE2P_ROLE_VERIFIER = 1
} noxtls_spake2p_role_t;

/** @brief Context lifecycle state (internal; exposed for diagnostics). */
typedef enum
{
    /** Unused or freed context. */
    NOXTLS_SPAKE2P_STATE_EMPTY = 0,
    /** Initialized with secrets; own share not generated yet. */
    NOXTLS_SPAKE2P_STATE_READY,
    /** Own share generated; waiting for the peer share. */
    NOXTLS_SPAKE2P_STATE_SHARE_GENERATED,
    /** Peer share processed; confirmation keys and shared key derived. */
    NOXTLS_SPAKE2P_STATE_KEYS_DERIVED,
    /** Peer confirmation verified; shared key may be exported. */
    NOXTLS_SPAKE2P_STATE_CONFIRMED,
    /** Aborted after a protocol or validation error; all secrets erased. */
    NOXTLS_SPAKE2P_STATE_FAILED
} noxtls_spake2p_state_t;

/**
 * @brief Transcript binding inputs (RFC 9383 section 3.3).
 *
 * Context is application-defined (Matter: SHA-256 of the PASE context
 * string and PBKDFParamRequest/Response). Identities may be empty
 * (length 0, pointer may be NULL).
 */
typedef struct
{
    const uint8_t *context;      /**< Context bytes (may be NULL when context_len is 0). */
    uint32_t context_len;        /**< Context length in bytes. */
    const uint8_t *id_prover;    /**< Prover identity (may be NULL when id_prover_len is 0). */
    uint32_t id_prover_len;      /**< Prover identity length in bytes. */
    const uint8_t *id_verifier;  /**< Verifier identity (may be NULL when id_verifier_len is 0). */
    uint32_t id_verifier_len;    /**< Verifier identity length in bytes. */
} noxtls_spake2p_params_t;

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
/**
 * @brief SPAKE2+ exchange context. Fields are private; use the API.
 *
 * Caller-allocated. Must be released with noxtls_spake2p_free(), which
 * erases every secret it holds.
 */
typedef struct
{
    noxtls_spake2p_profile_t profile;                              /**< Selected key-schedule profile. */
    noxtls_spake2p_role_t role;                                    /**< Local role. */
    noxtls_spake2p_state_t state;                                  /**< Lifecycle state. */
    uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE];                        /**< w0 (both roles). */
    uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE];                        /**< w1 (prover only). */
    uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE];                          /**< L = w1*G (verifier only). */
    uint8_t ephemeral[NOXTLS_SPAKE2P_SCALAR_SIZE];                 /**< x (prover) or y (verifier). */
    uint8_t share_prover[NOXTLS_SPAKE2P_POINT_SIZE];               /**< shareP (X / pA). */
    uint8_t share_verifier[NOXTLS_SPAKE2P_POINT_SIZE];             /**< shareV (Y / pB). */
    uint8_t confirm_key_prover[NOXTLS_SPAKE2P_MAX_CONFIRM_KEY_SIZE];   /**< K_confirmP or KcA. */
    uint8_t confirm_key_verifier[NOXTLS_SPAKE2P_MAX_CONFIRM_KEY_SIZE]; /**< K_confirmV or KcB. */
    uint32_t confirm_key_len;                                      /**< Length of each confirmation key. */
    uint8_t shared_key[NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE];        /**< K_shared or Ke. */
    uint32_t shared_key_len;                                       /**< Length of shared_key. */
    noxtls_sha_ctx_t transcript;                                   /**< Running SHA-256 over TT. */
} noxtls_spake2p_ctx_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize a prover (RFC 9383 Prover / Matter initiator) context.
 *
 * Absorbs Context, idProver, idVerifier, M and N into the transcript.
 *
 * @param[out] ctx Context to initialize (erased first).
 * @param[in] profile Key-schedule profile; must be compiled in.
 * @param[in] params Transcript Context and identities.
 * @param[in] w0 Big-endian w0 in [1, n-1].
 * @param[in] w1 Big-endian w1 in [1, n-1].
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL for NULL pointers,
 *         NOXTLS_RETURN_NOT_SUPPORTED for a profile not compiled in,
 *         NOXTLS_RETURN_INVALID_PARAM for an out-of-range w0/w1 or bad
 *         params, or NOXTLS_RETURN_FAILED on a hash failure.
 */
noxtls_return_t noxtls_spake2p_prover_init(noxtls_spake2p_ctx_t *ctx,
                                           noxtls_spake2p_profile_t profile,
                                           const noxtls_spake2p_params_t *params,
                                           const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                           const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Initialize a verifier (RFC 9383 Verifier / Matter responder) context.
 *
 * @param[out] ctx Context to initialize (erased first).
 * @param[in] profile Key-schedule profile; must be compiled in.
 * @param[in] params Transcript Context and identities.
 * @param[in] w0 Big-endian w0 in [1, n-1].
 * @param[in] L Registration record point L = w1*G (uncompressed SEC 1, validated).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_SUPPORTED,
 *         NOXTLS_RETURN_INVALID_PARAM (bad w0 or params), NOXTLS_RETURN_BAD_DATA
 *         (L not a valid point) or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_verifier_init(noxtls_spake2p_ctx_t *ctx,
                                             noxtls_spake2p_profile_t profile,
                                             const noxtls_spake2p_params_t *params,
                                             const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                             const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Generate the local share with a fresh random ephemeral scalar.
 *
 * Prover: shareP = x*G + w0*M. Verifier: shareV = y*G + w0*N. The
 * ephemeral scalar comes from the NoxTLS ECC key generator (DRBG).
 *
 * @param[in,out] ctx Context in the READY state.
 * @param[out] share Output buffer for the 65-byte uncompressed share.
 * @param[in,out] share_len In: capacity of share. Out: bytes written (or required size).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED
 *         (wrong state), NOXTLS_RETURN_INVALID_PARAM (buffer too small) or an
 *         ECC/DRBG error (context aborted).
 */
noxtls_return_t noxtls_spake2p_generate_share(noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *share, uint32_t *share_len);

/**
 * @brief Generate the local share with a caller-provided ephemeral scalar.
 *
 * Intended for known-answer tests and for platforms that draw the
 * ephemeral scalar from their own TRNG. In production the scalar must be
 * uniformly random in [1, n-1] and never reused.
 *
 * @param[in,out] ctx Context in the READY state.
 * @param[in] scalar Big-endian ephemeral scalar x or y in [1, n-1].
 * @param[out] share Output buffer for the 65-byte uncompressed share.
 * @param[in,out] share_len In: capacity. Out: bytes written (or required size).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_INVALID_PARAM (scalar out of range or buffer too
 *         small) or an ECC error (context aborted).
 */
noxtls_return_t noxtls_spake2p_generate_share_with_scalar(noxtls_spake2p_ctx_t *ctx,
                                                          const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                          uint8_t *share, uint32_t *share_len);

/**
 * @brief Process the peer share: validate it, compute Z and V, finish TT and derive keys.
 *
 * @param[in,out] ctx Context in the SHARE_GENERATED state.
 * @param[in] peer_share Peer share (prover receives shareV, verifier receives shareP).
 * @param[in] peer_share_len Must be NOXTLS_SPAKE2P_POINT_SIZE.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_BAD_DATA for an invalid share or identity Z/V
 *         (context aborted), or another error code (context aborted).
 */
noxtls_return_t noxtls_spake2p_process_peer_share(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t *peer_share,
                                                  uint32_t peer_share_len);

/**
 * @brief Compute the local key-confirmation MAC to send to the peer.
 *
 * Prover: confirmP / cA = HMAC(K_confirmP / KcA, shareV).
 * Verifier: confirmV / cB = HMAC(K_confirmV / KcB, shareP).
 *
 * @param[in] ctx Context in the KEYS_DERIVED or CONFIRMED state.
 * @param[out] confirmation Output buffer for the 32-byte MAC.
 * @param[in,out] confirmation_len In: capacity. Out: bytes written (or required size).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_INVALID_PARAM (buffer too small) or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_spake2p_get_confirmation(const noxtls_spake2p_ctx_t *ctx,
                                                uint8_t *confirmation,
                                                uint32_t *confirmation_len);

/**
 * @brief Verify the peer key-confirmation MAC in constant time.
 *
 * On mismatch the context is aborted and erased (no retry).
 *
 * @param[in,out] ctx Context in the KEYS_DERIVED state.
 * @param[in] confirmation Received MAC.
 * @param[in] confirmation_len Must be NOXTLS_SPAKE2P_CONFIRMATION_SIZE.
 *
 * @return NOXTLS_RETURN_SUCCESS when the MAC matches, NOXTLS_RETURN_FAILED
 *         on mismatch or wrong length (context aborted), NOXTLS_RETURN_NULL
 *         or NOXTLS_RETURN_NOT_INITIALIZED.
 */
noxtls_return_t noxtls_spake2p_verify_peer_confirmation(noxtls_spake2p_ctx_t *ctx,
                                                        const uint8_t *confirmation,
                                                        uint32_t confirmation_len);

/**
 * @brief Export the shared secret after the peer confirmation verified.
 *
 * RFC 9383 profile: K_shared (32 bytes). Matter profile: Ke (16 bytes).
 *
 * @param[in] ctx Context in the CONFIRMED state.
 * @param[out] key Output buffer.
 * @param[in,out] key_len In: capacity. Out: bytes written (or required size).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED
 *         (peer not confirmed) or NOXTLS_RETURN_INVALID_PARAM (buffer too small).
 */
noxtls_return_t noxtls_spake2p_get_shared_key(const noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *key, uint32_t *key_len);

/**
 * @brief Erase every secret in the context and return it to the EMPTY state.
 *
 * @param[in,out] ctx Context (NULL is ignored).
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NULL for a NULL context.
 */
noxtls_return_t noxtls_spake2p_free(noxtls_spake2p_ctx_t *ctx);

/**
 * @brief Derive w0 and w1 from the registration KDF output (RFC 9383 section 3.2).
 *
 * w0s = ws[0..39], w1s = ws[40..79]; w0 = w0s mod n, w1 = w1s mod n
 * (constant-time reduction). The KDF itself (PBKDF2, scrypt, Argon2, ...)
 * is application-chosen; Matter uses PBKDF2-HMAC-SHA256 (see
 * noxtls_matter_pase_compute_w0_w1()).
 *
 * @param[in] ws KDF output w0s || w1s.
 * @param[in] ws_len Must be NOXTLS_SPAKE2P_WS_SIZE (80).
 * @param[out] w0 Big-endian w0 (erased on failure).
 * @param[out] w1 Big-endian w1 (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (bad length) or NOXTLS_RETURN_FAILED (a reduced value is zero).
 */
noxtls_return_t noxtls_spake2p_derive_w0_w1(const uint8_t *ws, uint32_t ws_len,
                                            uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                            uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);

/**
 * @brief Compute the verifier registration point L = w1*G (RFC 9383 section 3.2).
 *
 * @param[in] w1 Big-endian w1 in [1, n-1].
 * @param[out] L Uncompressed SEC 1 point (erased on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (w1 out of range) or an ECC error.
 */
noxtls_return_t noxtls_spake2p_compute_L(const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                         uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

/**
 * @brief Return the RFC 9383 section 4 P-256 point M (uncompressed, 65 bytes).
 *
 * @return Pointer to static read-only storage.
 */
const uint8_t *noxtls_spake2p_p256_M(void);

/**
 * @brief Return the RFC 9383 section 4 P-256 point N (uncompressed, 65 bytes).
 *
 * @return Pointer to static read-only storage.
 */
const uint8_t *noxtls_spake2p_p256_N(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_SPAKE2P_H_ */
