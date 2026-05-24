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
* File:    noxtls_tls_key_exchange.h
* Summary: TLS Key Exchange Implementation (ECDHE, etc.)
*
*
*****************************************************************************/

#ifndef _NOXTLS_TLS_KEY_EXCHANGE_H_
#define _NOXTLS_TLS_KEY_EXCHANGE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "mdigest/noxtls_hash.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdh/noxtls_ecdh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Max TLS 1.2 DHE ServerKeyExchange message bytes (ffdhe8192 + RSA-SHA256 signature). */
#ifndef NOXTLS_TLS12_DHE_SKX_MSG_MAX
#define NOXTLS_TLS12_DHE_SKX_MSG_MAX 12288u
#endif

/* Forward declarations - actual types are defined in NOXTLS_tls12.h and NOXTLS_tls13.h */
typedef struct tls12_context_s tls12_context_t;
typedef struct tls13_context_s tls13_context_t;

/* TLS ECDHE Key Exchange Context */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t named_group;           /* TLS named group */
    ecc_curve_t curve_type;         /* ECC curve type */
    ecc_key_t ephemeral_key;        /* Ephemeral key pair (NIST curves) */
    uint8_t x25519_private_key[32]; /* X25519 private key (little-endian) */
    uint8_t x25519_public_key[32];  /* X25519 public key (little-endian) */
    uint8_t x448_private_key[56];   /* X448 private key (little-endian) */
    uint8_t x448_public_key[56];    /* X448 public key (little-endian) */
    uint8_t *premaster_secret;     /* Premaster secret (for TLS 1.2) */
    uint32_t premaster_secret_len;  /* Premaster secret length */
    uint8_t *shared_secret;         /* Shared secret (for TLS 1.3) */
    uint32_t shared_secret_len;     /* Shared secret length */
} tls_ecdhe_context_t;
NOXTLS_MSVC_WARNING_POP

/* TLS DHE (finite-field DH) Key Exchange Context - TLS 1.2 only */
#define TLS_DHE_MAX_P_BYTES 1024
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t named_group;           /* TLS named group: RFC 7919 FFDHE 256..260 */
    uint32_t p_len;                 /* Length of p in bytes */
    uint8_t *server_private;        /* Server ephemeral private (p_len bytes) */
    uint8_t *server_public;         /* Server ephemeral public (p_len bytes) */
    uint8_t *client_private;        /* Client ephemeral private (p_len bytes) */
    uint8_t *client_public;         /* Client ephemeral public (p_len bytes) */
    uint8_t premaster_secret[TLS_DHE_MAX_P_BYTES];  /* Z = shared secret, length p_len */
    uint32_t premaster_secret_len;
} tls_dhe_context_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Map an IANA TLS named group to an internal NIST ECC curve type.
 * @param[in] named_group TLS named group (e.g. P-256, P-384, P-521, X25519, X448).
 * @param[out] curve_type For NIST curves, the matching `ecc_curve_t`. For X25519/X448 the value is a placeholder; callers must branch on @p named_group.
 * @return `NOXTLS_RETURN_SUCCESS` if recognized; `NOXTLS_RETURN_NULL` if @p curve_type is NULL; `NOXTLS_RETURN_FAILED` if unsupported.
 */
noxtls_return_t noxtls_tls_named_group_to_ecc_curve(uint16_t named_group, ecc_curve_t *curve_type);

/**
 * @brief Map an internal NIST ECC curve type to an IANA TLS named group.
 * @param[in] curve_type ECC curve identifier supported by the library.
 * @param[out] named_group Receives the TLS named group value.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p named_group is NULL; `NOXTLS_RETURN_FAILED` if @p curve_type is not mapped.
 */
noxtls_return_t noxtls_tls_ecc_curve_to_named_group(ecc_curve_t curve_type, uint16_t *named_group);

/**
 * @brief Encode an ECC public point in TLS uncompressed form (0x04 || X || Y).
 * @param[in] point Point to encode (coordinates sized for the curve).
 * @param[out] output Buffer for the encoded bytes.
 * @param[in,out] output_len On input, size of @p output; on success, written length; on `NOXTLS_RETURN_FAILED` due to size, set to required length.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if @p output is too small.
 */
noxtls_return_t noxtls_tls_encode_ecc_point_uncompressed(const ecc_point_t *point, uint8_t *output, uint32_t *output_len);

/**
 * @brief Decode a TLS uncompressed ECC point (0x04 || X || Y).
 * @param[in] encoded Encoded point bytes.
 * @param[in] encoded_len Length of @p encoded.
 * @param[out] point Receives decoded coordinates; initialized by the implementation.
 * @param[in] curve_type Curve used to validate expected coordinate sizes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on malformed or wrong-length input.
 */
noxtls_return_t noxtls_tls_decode_ecc_point_uncompressed(const uint8_t *encoded, uint32_t encoded_len, ecc_point_t *point, ecc_curve_t curve_type);

/**
 * @brief Initialize an ECDHE context for a given named group.
 * @param[out] ctx Context zeroed then filled with @p named_group; NIST curves also initialize `ephemeral_key`.
 * @param[in] named_group TLS named group for the handshake.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; other codes if the group or ECC setup fails.
 */
noxtls_return_t noxtls_tls_ecdhe_context_init(tls_ecdhe_context_t *ctx, uint16_t named_group);

/**
 * @brief Release ECDHE context key material and zero the structure.
 * @param[in,out] ctx Context to clear (safe to call with cleared context).
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_ecdhe_context_free(tls_ecdhe_context_t *ctx);

/**
 * @brief Generate a fresh ephemeral key pair for the context's named group.
 * @param[in,out] ctx Initialized ECDHE context; receives new public/private material.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; `NOXTLS_RETURN_FAILED` on cryptographic failure.
 */
noxtls_return_t noxtls_tls_ecdhe_generate_ephemeral_key(tls_ecdhe_context_t *ctx);

/**
 * @brief ECDH shared secret (NIST curves): store result in @p ctx for TLS 1.2/1.3 key schedule use.
 * @param[in,out] ctx Local ephemeral key must be valid; previous `shared_secret` is replaced.
 * @param[in] peer_public_key Peer's uncompressed point on the same curve.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on ECDH failure or allocation failure.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret(tls_ecdhe_context_t *ctx, const ecc_point_t *peer_public_key);

/**
 * @brief X25519 shared secret: replaces any previous `shared_secret` in @p ctx (32 bytes).
 * @param[in,out] ctx Must be initialized for `TLS_NAMED_GROUP_X25519` with a generated local key.
 * @param[in] peer_public_key Peer's 32-byte public key (RFC 7748).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if wrong group, all-zero shared secret, or allocation failure.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret_x25519(tls_ecdhe_context_t *ctx, const uint8_t peer_public_key[32]);

/**
 * @brief X448 shared secret: replaces any previous `shared_secret` in @p ctx (56 bytes).
 * @param[in,out] ctx Must be initialized for `TLS_NAMED_GROUP_X448` with a generated local key.
 * @param[in] peer_public_key Peer's 56-byte public key (RFC 7748).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if wrong group, all-zero shared secret, or allocation failure.
 */
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret_x448(tls_ecdhe_context_t *ctx, const uint8_t peer_public_key[56]);

/**
 * @brief Serialize the local ECDHE public key for wire encoding (raw X25519/X448 bytes or uncompressed ECC point).
 * @param[in] ctx Context with generated keys.
 * @param[out] output Buffer for the encoded public key.
 * @param[in,out] output_len On input, size of @p output; on success, written length; on undersized buffer, set to required length and returns `NOXTLS_RETURN_FAILED`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if keys are missing or buffer too small.
 */
noxtls_return_t noxtls_tls_ecdhe_get_public_key_encoded(tls_ecdhe_context_t *ctx, uint8_t *output, uint32_t *output_len);

/**
 * @brief TLS 1.2 server: build and send ECDHE ServerKeyExchange (signed when server credentials are configured).
 * @param[in,out] ctx TLS 1.2 context (server role); uses handshake workspace or temporary buffers.
 * @param[in,out] ecdhe_ctx ECDHE state with generated ephemeral key and named group.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role/build/sign errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` if allocation fails.
 */
noxtls_return_t noxtls_tls12_ecdhe_send_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/**
 * @brief TLS 1.2 client: receive and verify ECDHE ServerKeyExchange, then compute shared secret.
 * @param[in,out] ctx TLS 1.2 context (client role); requires server certificate for signature verification when signed.
 * @param[in,out] ecdhe_ctx ECDHE state matching the server's named group; receives shared secret.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on parse, verify, or ECDH errors.
 */
noxtls_return_t noxtls_tls12_ecdhe_recv_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/**
 * @brief TLS 1.2 client: send ClientKeyExchange containing the local ECDHE public key.
 * @param[in,out] ctx TLS 1.2 context (client role).
 * @param[in] ecdhe_ctx Local ECDHE public material.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role or encode errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` if allocation fails.
 */
noxtls_return_t noxtls_tls12_ecdhe_send_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/**
 * @brief TLS 1.2 server: receive ClientKeyExchange and compute ECDHE shared secret.
 * @param[in,out] ctx TLS 1.2 context (server role).
 * @param[in,out] ecdhe_ctx Server ECDHE state; receives shared secret.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on parse or ECDH errors.
 */
noxtls_return_t noxtls_tls12_ecdhe_recv_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/**
 * @brief Initialize a TLS 1.2 FFDHE (finite-field DH) context for a named RFC 7919 group.
 * @param[out] ctx Zeroed then allocated with group primes/limbs sized to @p named_group.
 * @param[in] named_group FFDHE code point (e.g. ffdhe2048).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL; `NOXTLS_RETURN_FAILED` if parameters are unknown or `malloc` fails.
 */
noxtls_return_t noxtls_tls_dhe_context_init(tls_dhe_context_t *ctx, uint16_t named_group);

/**
 * @brief Free buffers held by a DHE context and zero the structure.
 * @param[in,out] ctx Context to release.
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_dhe_context_free(tls_dhe_context_t *ctx);

/**
 * @brief Choose RSA PKCS#1 hash for TLS 1.2 ServerKeyExchange signing (scheme byte 0x01).
 * @param[in] ctx TLS 1.2 context (uses client `signature_algorithms` when present per RFC 5246).
 * @param[out] hash_byte_out Wire hash byte for SignatureAndHashAlgorithm.
 * @param[out] hash_out Internal hash algorithm id for signing.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_NOT_SUPPORTED` if client advertised algorithms exclude acceptable RSA pairs.
 */
noxtls_return_t noxtls_tls12_pick_rsa_pkcs1_skx_sig_hash(const tls12_context_t *ctx,
                                                         uint8_t *hash_byte_out,
                                                         noxtls_hash_algos_t *hash_out);

/**
 * @brief Choose ECDSA hash for TLS 1.2 ECDHE ServerKeyExchange signing (scheme byte 0x03).
 * @param[in] ctx TLS 1.2 context (uses client `signature_algorithms` when present).
 * @param[out] hash_byte_out Wire hash byte for SignatureAndHashAlgorithm.
 * @param[out] hash_out Internal hash algorithm id for signing.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_NOT_SUPPORTED` if no acceptable ECDSA pair is advertised.
 */
noxtls_return_t noxtls_tls12_pick_ecdsa_skx_sig_hash(const tls12_context_t *ctx,
                                                    uint8_t *hash_byte_out,
                                                    noxtls_hash_algos_t *hash_out);

/**
 * @brief TLS 1.2 server: build (and optionally copy) and send DHE ServerKeyExchange.
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] dhe_ctx FFDHE context with group set; server public key is generated here.
 * @param[out] msg_out Optional buffer to copy the full handshake message (e.g. for transcript hashing).
 * @param[in] msg_out_size Capacity of @p msg_out when used.
 * @param[out] msg_out_len When @p msg_out and @p msg_out_len are non-NULL, receives copied length on success.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role/build/sign errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_dhe_send_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, uint8_t *msg_out, uint32_t msg_out_size, uint32_t *msg_out_len);

/**
 * @brief TLS 1.2 client: parse DHE ServerKeyExchange from raw handshake bytes (caller supplies record payload).
 * @param[in,out] ctx TLS 1.2 client context; uses server certificate for RSA signature verify when present.
 * @param[in,out] dhe_ctx Expected named group; receives server public and derived premaster secret.
 * @param[in] record_data Handshake message bytes including 4-byte handshake header.
 * @param[in] record_len Length of @p record_data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` or `NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS` on parse/verify/DH errors.
 */
noxtls_return_t noxtls_tls12_dhe_recv_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len);

/**
 * @brief TLS 1.2 client: send DHE ClientKeyExchange with local public value.
 * @param[in,out] ctx TLS 1.2 client context.
 * @param[in,out] dhe_ctx Client public must be populated after server message processing.
 * @return `NOXTLS_RETURN_SUCCESS` if the record was sent; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role or message size errors; `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` on allocation failure.
 */
noxtls_return_t noxtls_tls12_dhe_send_client_key_exchange(tls12_context_t *ctx, const tls_dhe_context_t *dhe_ctx);

/**
 * @brief TLS 1.2 server: parse DHE ClientKeyExchange and compute premaster secret.
 * @param[in,out] ctx TLS 1.2 server context.
 * @param[in,out] dhe_ctx Server-side DHE state; receives premaster in `premaster_secret`.
 * @param[in] record_data Handshake message bytes including header.
 * @param[in] record_len Length of @p record_data.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; TLS alert codes such as `NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR` on malformed messages.
 */
noxtls_return_t noxtls_tls12_dhe_recv_client_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len);

/**
 * @brief TLS 1.3: encode one KeyShareEntry (group, length, key exchange bytes).
 * @param[in] ecdhe_ctx Local share for a single named group.
 * @param[out] output Serialized KeyShareEntry.
 * @param[in,out] output_len On input, size of @p output; on success, written length; if too small, set to required length.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` if encoding fails or buffer is too small.
 */
noxtls_return_t noxtls_tls13_key_share_encode(const tls_ecdhe_context_t *ecdhe_ctx, uint8_t *output, uint32_t *output_len);

/**
 * @brief TLS 1.3: decode one KeyShareEntry for NIST curves into an `ecc_point_t`.
 * @param[in] encoded KeyShareEntry bytes (group, length, key exchange).
 * @param[in] encoded_len Length of @p encoded.
 * @param[in] named_group Expected group; must match the wire value.
 * @param[out] public_key Decoded peer public point (not used for X25519/X448; those return `NOXTLS_RETURN_FAILED` from this API).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on mismatch, short input, Montgomery groups, or decode errors.
 */
noxtls_return_t noxtls_tls13_key_share_decode(const uint8_t *encoded, uint32_t encoded_len, uint16_t named_group, ecc_point_t *public_key);

/**
 * @brief TLS 1.3 server: consume the client's KeyShare matching @p ecdhe_ctx and compute the shared secret.
 * @param[in,out] ctx TLS 1.3 server context containing parsed client shares.
 * @param[in,out] ecdhe_ctx Local ECDHE context for the negotiated group.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role mismatch, missing share, or ECDH failure.
 */
noxtls_return_t noxtls_tls13_process_client_key_share(tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/**
 * @brief TLS 1.3 client: consume the server's KeyShare and compute the shared secret.
 * @param[in] ctx TLS 1.3 client context containing parsed server share.
 * @param[in,out] ecdhe_ctx Local ECDHE context for the negotiated group.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_FAILED` on role mismatch, missing share, or ECDH failure.
 */
noxtls_return_t noxtls_tls13_process_server_key_share(const tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_KEY_EXCHANGE_H_ */
