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
* File:    noxtls_ecjpake.h
* Summary: EC-JPAKE (P-256, SHA-256) password-authenticated key exchange API
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake.h
 * @brief EC-JPAKE over NIST P-256 with Schnorr NIZK proofs, in the TLS form used by Thread.
 * @ingroup noxtls_ecjpake
 */

/**
 * @defgroup noxtls_ecjpake EC-JPAKE
 * @brief Elliptic-curve J-PAKE password-authenticated key exchange.
 *
 * Specifications:
 * - RFC 8236 "J-PAKE: Password-Authenticated Key Exchange by Juggling"
 *   (September 2017) section 3 (J-PAKE over Elliptic Curve).
 * - RFC 8235 "Schnorr Non-interactive Zero-Knowledge Proof" (September
 *   2017) section 3 (Schnorr NIZK proof over Elliptic Curve).
 * - draft-cragie-tls-ecjpake-01 "Elliptic Curve J-PAKE Cipher Suites for
 *   TLS" (June 2016): wire structures (section 7), user identities
 *   "client" / "server" (section 8.1), ZKP hash (section 8.2), password
 *   mapping (section 8.3), round generators (sections 8.5, 8.6) and the
 *   premaster secret (section 8.7). This is the form Thread uses for
 *   MeshCoP commissioning (PSKc and PSKd).
 *
 * Fixed implementation parameters (draft section 3): curve secp256r1,
 * hash SHA-256, uncompressed points, identity field elided from the
 * ECJPAKEKeyKPPairList; the ZKP hash uses the default identities.
 *
 * Notation (local "m" and peer "p" keys, matching the draft's client keys
 * x1, x2 and server keys x3, x4):
 * - Round one: Xm1 = G*xm1, Xm2 = G*xm2 with a ZKP for each, user ID of the
 *   local role. Wire format: ECJPAKEKeyKPPairList without identity, that is
 *   ECJPAKEKeyKP || ECJPAKEKeyKP.
 * - Round two: Gm = Xm1 + Xp1 + Xp2, xs = xm2*s mod n, Xm = Gm*xs with a
 *   ZKP for xs over generator Gm. Server wire format is ServerECJPAKEParams
 *   (ECParameters secp256r1 || ECJPAKEKeyKP); client wire format is
 *   ClientECJPAKEParams (ECJPAKEKeyKP).
 * - Key: K = (Xp - Xp2*xs)*xm2; premaster = SHA-256(str(32, K.x)).
 * - ZKP (RFC 8235 section 3.2): V = Gen*v, h = int(SHA-256(len||Gen ||
 *   len||V || len||X || len||ID)) mod n with 4-octet big-endian lengths,
 *   r = v - x*h mod n. Verification: V == Gen*r + X*h.
 *
 * Wire encodings:
 * - ECPoint: opaque point<1..2^8-1>, here always 65 octets (0x04 || X || Y).
 * - ECSchnorrZKP: ECPoint V || opaque r<1..2^8-1>. r is written big-endian
 *   in its minimal length (1..32 octets); 1..32 octets are accepted.
 *
 * Call order (either role; the TLS layer follows draft section 5):
 * - Client: init -> write_round_one (ClientHello) -> read_round_one
 *   (ServerHello) -> read_round_two (ServerKeyExchange) -> write_round_two
 *   (ClientKeyExchange) -> derive_premaster -> free.
 * - Server: init -> read_round_one (ClientHello) -> write_round_one
 *   (ServerHello) -> write_round_two (ServerKeyExchange) -> read_round_two
 *   (ClientKeyExchange) -> derive_premaster -> free.
 * - write_round_one may be called again; it returns the same octets (DTLS
 *   resends the same ClientHello after HelloVerifyRequest, RFC 6347 section
 *   4.2.1). write_round_two needs both round-one messages; read_round_two
 *   needs both round-one messages; derive_premaster needs both round-two
 *   messages.
 *
 * Security properties:
 * - Received points must be uncompressed, canonical (coordinates below p),
 *   on the curve and not the identity. The round-two generators must not be
 *   the identity (RFC 8236 section 3.2). Any failure moves the context to
 *   the FAILED state and erases its secrets; there is no retry.
 * - A peer that reflects our own round-one values fails ZKP verification,
 *   because the hash binds the sender identity ("client" or "server").
 * - Secret scalars are derived and reduced with constant-time code; every
 *   scalar multiplication goes through noxtls_ecc_point_multiply(), so a
 *   bound P-256 accelerator port (for example the CC13xx PKA port) is used.
 *   Point additions use the generic NoxTLS helpers, which operate on public
 *   values or on values that do not depend on the password alone.
 * - free() and every failure path erase scalars with noxtls_secure_zero().
 * - The context is about 0.8 KB; allocate it statically or from a pool on
 *   small stacks.
 */

#ifndef _NOXTLS_ECJPAKE_H_
#define _NOXTLS_ECJPAKE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_ecjpake_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Protocol role; selects the local and peer user identities. */
typedef enum
{
    /** TLS client ("client"; draft keys x1, x2). Thread: Joiner or Commissioner. */
    NOXTLS_ECJPAKE_ROLE_CLIENT = 0,
    /** TLS server ("server"; draft keys x3, x4). Thread: Joiner Router / Commissioner or Border Agent. */
    NOXTLS_ECJPAKE_ROLE_SERVER = 1
} noxtls_ecjpake_role_t;

/** @brief Context lifecycle state (exposed for diagnostics). */
typedef enum
{
    /** Unused or freed context. */
    NOXTLS_ECJPAKE_STATE_EMPTY = 0,
    /** Initialized; rounds in progress (see progress flags). */
    NOXTLS_ECJPAKE_STATE_ACTIVE,
    /** Premaster secret derived; secrets erased. */
    NOXTLS_ECJPAKE_STATE_DONE,
    /** Aborted after a protocol or validation error; secrets erased. */
    NOXTLS_ECJPAKE_STATE_FAILED
} noxtls_ecjpake_state_t;

/** @brief Progress flag: own round-one key pairs generated. */
#define NOXTLS_ECJPAKE_FLAG_OWN_ROUND_ONE (0x01U)
/** @brief Progress flag: peer round-one message verified. */
#define NOXTLS_ECJPAKE_FLAG_PEER_ROUND_ONE (0x02U)
/** @brief Progress flag: own round-two message generated. */
#define NOXTLS_ECJPAKE_FLAG_OWN_ROUND_TWO (0x04U)
/** @brief Progress flag: peer round-two message verified. */
#define NOXTLS_ECJPAKE_FLAG_PEER_ROUND_TWO (0x08U)

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
/**
 * @brief EC-JPAKE exchange context. Fields are private; use the API.
 *
 * Caller-allocated. Must be released with noxtls_ecjpake_free(), which
 * erases every secret it holds.
 */
typedef struct noxtls_ecjpake_ctx_s
{
    noxtls_ecjpake_role_t role;                              /**< Local role. */
    noxtls_ecjpake_state_t state;                            /**< Lifecycle state. */
    uint32_t flags;                                          /**< NOXTLS_ECJPAKE_FLAG_* progress bits. */
    uint8_t s[NOXTLS_ECJPAKE_SCALAR_SIZE];                   /**< s = int(password) mod n (secret). */
    uint8_t xm1[NOXTLS_ECJPAKE_SCALAR_SIZE];                 /**< Local first private key (secret). */
    uint8_t xm2[NOXTLS_ECJPAKE_SCALAR_SIZE];                 /**< Local second private key (secret). */
    uint8_t Xm1[NOXTLS_ECJPAKE_POINT_SIZE];                  /**< Local first public key G*xm1. */
    uint8_t Xm2[NOXTLS_ECJPAKE_POINT_SIZE];                  /**< Local second public key G*xm2. */
    uint8_t Xp1[NOXTLS_ECJPAKE_POINT_SIZE];                  /**< Peer first public key. */
    uint8_t Xp2[NOXTLS_ECJPAKE_POINT_SIZE];                  /**< Peer second public key. */
    uint8_t Xp[NOXTLS_ECJPAKE_POINT_SIZE];                   /**< Peer round-two public value. */
    uint8_t round_one[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];    /**< Encoded own round-one message. */
    uint32_t round_one_len;                                  /**< Length of round_one. */
} noxtls_ecjpake_ctx_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize a context for one exchange.
 *
 * Maps the password to s = int(password) mod n (draft-cragie-tls-ecjpake-01
 * section 8.3: the octets are read as a big-endian integer). The password is
 * not retained.
 *
 * @param[out] ctx Context to initialize (erased first).
 * @param[in] role Local role.
 * @param[in] password Shared password octets (Thread: PSKc or PSKd).
 * @param[in] password_len Length in octets, NOXTLS_ECJPAKE_PASSWORD_MIN_LEN to
 *            NOXTLS_ECJPAKE_PASSWORD_MAX_LEN.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL for NULL pointers,
 *         NOXTLS_RETURN_INVALID_PARAM for a bad role or length, or when s is 0 mod n.
 */
noxtls_return_t noxtls_ecjpake_init(noxtls_ecjpake_ctx_t *ctx,
                                    noxtls_ecjpake_role_t role,
                                    const uint8_t *password,
                                    uint32_t password_len);

/**
 * @brief Produce the local round-one message (ecjpake_key_kp_pair extension body).
 *
 * The first call generates xm1, xm2 and both ZKPs; later calls return the
 * same octets.
 *
 * @param[in,out] ctx Active context.
 * @param[out] out Output buffer.
 * @param[in] out_size Size of out; NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE always suffices.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED
 *         (wrong state), NOXTLS_RETURN_INVALID_PARAM (out_size too small) or a
 *         random / ECC failure (context FAILED).
 */
noxtls_return_t noxtls_ecjpake_write_round_one(noxtls_ecjpake_ctx_t *ctx,
                                               uint8_t *out,
                                               uint32_t out_size,
                                               uint32_t *out_len);

/**
 * @brief Parse and verify the peer round-one message (both ZKPs, peer identity).
 *
 * @param[in,out] ctx Active context without a peer round one.
 * @param[in] in Peer ecjpake_key_kp_pair extension body.
 * @param[in] in_len Length of in.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR for malformed encodings,
 *         NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER for invalid points or a failed
 *         ZKP (context FAILED on any error after the state checks).
 */
noxtls_return_t noxtls_ecjpake_read_round_one(noxtls_ecjpake_ctx_t *ctx,
                                              const uint8_t *in,
                                              uint32_t in_len);

/**
 * @brief Produce the local round-two message.
 *
 * Server: ServerECJPAKEParams (ECParameters secp256r1 || ECJPAKEKeyKP).
 * Client: ClientECJPAKEParams (ECJPAKEKeyKP).
 *
 * @param[in,out] ctx Context with both round-one messages.
 * @param[out] out Output buffer.
 * @param[in] out_size Size of out; NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE always suffices.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_INVALID_PARAM (out_size too small) or a random / ECC failure.
 */
noxtls_return_t noxtls_ecjpake_write_round_two(noxtls_ecjpake_ctx_t *ctx,
                                               uint8_t *out,
                                               uint32_t out_size,
                                               uint32_t *out_len);

/**
 * @brief Parse and verify the peer round-two message.
 *
 * Client reads ServerECJPAKEParams (curve must be named secp256r1); server
 * reads ClientECJPAKEParams.
 *
 * @param[in,out] ctx Context with both round-one messages.
 * @param[in] in Peer ServerKeyExchange / ClientKeyExchange body.
 * @param[in] in_len Length of in.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR or NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER.
 */
noxtls_return_t noxtls_ecjpake_read_round_two(noxtls_ecjpake_ctx_t *ctx,
                                              const uint8_t *in,
                                              uint32_t in_len);

/**
 * @brief Derive the TLS premaster secret PMS = SHA-256(str(32, K.x)) (draft section 8.7).
 *
 * Requires both round-two messages. On success the context moves to DONE
 * and its secrets are erased. With a wrong password both sides still derive
 * a (different) premaster; the mismatch is detected by the TLS Finished
 * messages.
 *
 * @param[in,out] ctx Context with both round-two messages.
 * @param[out] out Output buffer.
 * @param[in] out_size Size of out, at least NOXTLS_ECJPAKE_PREMASTER_SIZE.
 * @param[out] out_len Octets written (NOXTLS_ECJPAKE_PREMASTER_SIZE).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_INITIALIZED,
 *         NOXTLS_RETURN_INVALID_PARAM or an ECC / hash failure.
 */
noxtls_return_t noxtls_ecjpake_derive_premaster(noxtls_ecjpake_ctx_t *ctx,
                                                uint8_t *out,
                                                uint32_t out_size,
                                                uint32_t *out_len);

/**
 * @brief Report the context state.
 *
 * @param[in] ctx Context (may be NULL).
 *
 * @return The state; NOXTLS_ECJPAKE_STATE_EMPTY for NULL.
 */
noxtls_ecjpake_state_t noxtls_ecjpake_get_state(const noxtls_ecjpake_ctx_t *ctx);

/**
 * @brief Erase every secret and return the context to EMPTY.
 *
 * @param[in,out] ctx Context (NULL is ignored).
 */
void noxtls_ecjpake_free(noxtls_ecjpake_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECJPAKE_H_ */
