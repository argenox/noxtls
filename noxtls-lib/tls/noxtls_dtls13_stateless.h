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
* File:    noxtls_dtls13_stateless.h
* Summary: DTLS 1.3 stateless HelloRetryRequest helpers (library internal)
*
*****************************************************************************/

#ifndef NOXTLS_DTLS13_STATELESS_H_
#define NOXTLS_DTLS13_STATELESS_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Fields of a ClientHello datagram that holds one unfragmented ClientHello record. */
typedef struct
{
    uint64_t record_seq;           /**< DTLSPlaintext.sequence_number (48 bits). */
    uint16_t message_seq;          /**< Handshake message_seq. */
    const uint8_t *body;           /**< ClientHello body (after the 12-byte DTLS handshake header). */
    uint32_t body_len;
    const uint8_t *session_id;     /**< legacy_session_id. */
    uint8_t session_id_len;
    const uint8_t *suites;         /**< cipher_suites vector contents. */
    uint16_t suites_len;
    const uint8_t *exts;           /**< Extension block contents (after its length). */
    uint16_t exts_len;
} dtls13_ch_view_t;

/**
 * Parse a datagram that must hold exactly one epoch-0, unfragmented ClientHello record
 * (RFC 9147 Sections 4 and 5.2). Every length is checked; the legacy_cookie must be empty
 * (RFC 9147 Section 5.1).
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for NULL; NOXTLS_RETURN_BAD_DATA.
 */
noxtls_return_t dtls13_parse_client_hello_datagram(const uint8_t *dgram, uint32_t len, dtls13_ch_view_t *view);

/**
 * Find extension @p type in a parsed ClientHello.
 * @return NOXTLS_RETURN_SUCCESS with @p data / @p data_len; NOXTLS_RETURN_FAILED when absent.
 */
noxtls_return_t dtls13_ch_find_extension(const dtls13_ch_view_t *view, uint16_t type,
                                         const uint8_t **data, uint16_t *data_len);

/**
 * Cookie of the cookie extension of a (second) ClientHello (RFC 8446 Section 4.2.2).
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_BAD_DATA when absent or malformed.
 */
noxtls_return_t dtls13_ch_cookie(const dtls13_ch_view_t *view, const uint8_t **cookie, uint16_t *cookie_len);

/**
 * Check the stateless HelloRetryRequest parameters against a second ClientHello: the
 * suite is a SHA-256 TLS 1.3 suite that CH2 offers and, with a @p group, CH2 carries
 * exactly one KeyShareEntry for it (RFC 8446 Sections 4.1.2 and 4.1.4).
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a suite that is not a
 *         SHA-256 TLS 1.3 suite; NOXTLS_RETURN_BAD_DATA when CH2 contradicts them.
 */
noxtls_return_t dtls13_ch2_check_hrr_params(const dtls13_ch_view_t *view, uint16_t cipher_suite, uint16_t group);

/**
 * Build the HelloRetryRequest handshake message (TLS 1.3 four-byte header, as it enters
 * the transcript): legacy_version DTLS 1.2, the HelloRetryRequest random, the echoed
 * legacy_session_id, @p cipher_suite, supported_versions DTLS 1.3, key_share(@p group)
 * when @p group is not 0, and the cookie (RFC 8446 Sections 4.1.3 and 4.1.4).
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_BUFFER_TOO_SMALL (*out_len = size needed).
 */
noxtls_return_t dtls13_build_hrr_message(const uint8_t *session_id, uint8_t session_id_len,
                                         uint16_t cipher_suite, uint16_t group,
                                         const uint8_t *cookie, uint16_t cookie_len,
                                         uint8_t *out, uint32_t cap, uint32_t *out_len);

/** 1 when @p cipher_suite is a TLS 1.3 suite whose hash is SHA-256 (RFC 8446 Appendix B.4). */
uint8_t dtls13_suite_is_sha256(uint16_t cipher_suite);

/** Write the synthetic message_hash handshake message for @p ch1_hash (36 bytes, RFC 8446 Section 4.4.1). */
void dtls13_message_hash(const uint8_t ch1_hash[32], uint8_t out[36]);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_DTLS13_STATELESS_H_ */
