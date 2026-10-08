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
* File:    noxtls_tls12_ecjpake_internal.h
* Summary: TLS 1.2 engine hooks for the EC-JPAKE cipher suite
*
*
*****************************************************************************/

/**
 * @file noxtls_tls12_ecjpake_internal.h
 * @brief Hooks called by noxtls_tls12.c to build and parse EC-JPAKE handshake content.
 * @ingroup noxtls_tls12_ecjpake
 *
 * Not part of the public API. Every hook works on message bodies only; the
 * TLS 1.2 engine owns record I/O, the handshake transcript and the key
 * schedule. Message formats follow draft-cragie-tls-ecjpake-01 section 7.
 */

#ifndef NOXTLS_TLS12_ECJPAKE_INTERNAL_H_
#define NOXTLS_TLS12_ECJPAKE_INTERNAL_H_

#include <stdint.h>

#include "noxtls_tls12.h"
#include "noxtls_tls12_ecjpake.h"
#include "pake/noxtls_ecjpake.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Size of an extension header: type(2) || length(2) (RFC 5246 section 7.4.1.4). */
#define NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE (4U)

/** @brief Size of a handshake message header: type(1) || length(3) (RFC 5246 section 7.4). */
#define NOXTLS_TLS12_ECJPAKE_HS_HEADER_SIZE (4U)

/** @brief supported_groups body with one group: list length(2) || secp256r1(2) (RFC 8422 section 5.1.1). */
#define NOXTLS_TLS12_ECJPAKE_GROUPS_BODY_SIZE (4U)

/** @brief ec_point_formats body: list length(1) || uncompressed(1) (RFC 8422 section 5.1.2). */
#define NOXTLS_TLS12_ECJPAKE_POINT_FORMATS_BODY_SIZE (2U)

/** @brief ClientHello extensions written in EC-JPAKE mode (supported_groups, ec_point_formats, kkpp). */
#define NOXTLS_TLS12_ECJPAKE_CLIENT_HELLO_EXT_MAX_SIZE \
    ((3U * NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE) + NOXTLS_TLS12_ECJPAKE_GROUPS_BODY_SIZE + \
     NOXTLS_TLS12_ECJPAKE_POINT_FORMATS_BODY_SIZE + NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE)

/**
 * @brief Report whether EC-JPAKE is configured on the context (password set).
 *
 * @param[in] ctx TLS 1.2 context (may be NULL).
 *
 * @return 1 when configured, 0 otherwise.
 */
int tls12_ecjpake_active(const tls12_context_t *ctx);

/**
 * @brief Client: write the EC-JPAKE ClientHello extension block body.
 *
 * Writes supported_groups (secp256r1 only, draft section 7.2.1),
 * ec_point_formats (uncompressed) and ecjpake_key_kp_pair (section 7.2.2).
 * The round-one octets are generated once and repeated after a
 * HelloVerifyRequest (RFC 6347 section 4.2.1).
 *
 * @param[in,out] ctx Client context with EC-JPAKE configured.
 * @param[out] out Destination (extension list without the 2-octet list length).
 * @param[in] out_size Size of out.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t tls12_ecjpake_write_client_hello_extensions(tls12_context_t *ctx, uint8_t *out,
                                                            uint32_t out_size, uint32_t *out_len);

/**
 * @brief Client: verify the server round one carried in the ServerHello extension.
 *
 * @param[in,out] ctx Client context.
 * @param[in] data Extension body.
 * @param[in] len Extension body length.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR or
 *         NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER.
 */
noxtls_return_t tls12_ecjpake_client_read_server_hello_extension(tls12_context_t *ctx, const uint8_t *data,
                                                                 uint32_t len);

/**
 * @brief Client: parse ServerECJPAKEParams (ServerKeyExchange body).
 *
 * @param[in,out] ctx Client context.
 * @param[in] body ServerKeyExchange body (after the handshake header).
 * @param[in] len Body length.
 *
 * @return NOXTLS_RETURN_SUCCESS or an alert-class error code.
 */
noxtls_return_t tls12_ecjpake_client_read_server_key_exchange(tls12_context_t *ctx, const uint8_t *body,
                                                              uint32_t len);

/**
 * @brief Client: write ClientECJPAKEParams and derive the premaster secret.
 *
 * @param[in,out] ctx Client context (premaster_secret is filled).
 * @param[out] out Destination for the ClientKeyExchange body.
 * @param[in] out_size Size of out.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t tls12_ecjpake_client_write_key_exchange(tls12_context_t *ctx, uint8_t *out,
                                                        uint32_t out_size, uint32_t *out_len);

/**
 * @brief Server: validate the EC-JPAKE ClientHello (after the cookie exchange).
 *
 * Requires ecjpake_key_kp_pair, checks supported_groups / ec_point_formats
 * when present and verifies the client round one. Sends the matching fatal
 * alert on failure.
 *
 * @param[in,out] ctx Server context whose client_extensions are parsed.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t tls12_ecjpake_server_process_client_hello(tls12_context_t *ctx);

/**
 * @brief Server: write the ecjpake_key_kp_pair ServerHello extension (header included).
 *
 * @param[in,out] ctx Server context.
 * @param[out] out Destination.
 * @param[in] out_size Size of out.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t tls12_ecjpake_write_server_hello_extension(tls12_context_t *ctx, uint8_t *out,
                                                           uint32_t out_size, uint32_t *out_len);

/**
 * @brief Server: write ServerECJPAKEParams (ServerKeyExchange body).
 *
 * @param[in,out] ctx Server context.
 * @param[out] out Destination.
 * @param[in] out_size Size of out.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
noxtls_return_t tls12_ecjpake_server_write_key_exchange(tls12_context_t *ctx, uint8_t *out,
                                                        uint32_t out_size, uint32_t *out_len);

/**
 * @brief Server: parse ClientECJPAKEParams and derive the premaster secret.
 *
 * @param[in,out] ctx Server context (premaster_secret is filled).
 * @param[in] body ClientKeyExchange body (after the handshake header).
 * @param[in] len Body length.
 *
 * @return NOXTLS_RETURN_SUCCESS or an alert-class error code.
 */
noxtls_return_t tls12_ecjpake_server_read_client_key_exchange(tls12_context_t *ctx, const uint8_t *body,
                                                              uint32_t len);

/**
 * @brief Map an EC-JPAKE error to a TLS alert description.
 *
 * @param[in] rc Error code.
 *
 * @return TLS_ALERT_DECODE_ERROR, TLS_ALERT_ILLEGAL_PARAMETER or TLS_ALERT_INTERNAL_ERROR.
 */
uint8_t tls12_ecjpake_alert_for(noxtls_return_t rc);

/**
 * @brief Release the EC-JPAKE state of a context (erases secrets).
 *
 * @param[in,out] ctx TLS 1.2 context (may be NULL).
 */
void tls12_ecjpake_release(tls12_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TLS12_ECJPAKE_INTERNAL_H_ */
