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
* File:    noxtls_tls12_ecjpake.h
* Summary: DTLS 1.2 TLS_ECJPAKE_WITH_AES_128_CCM_8 configuration API
*
*
*****************************************************************************/

/**
 * @file noxtls_tls12_ecjpake.h
 * @brief DTLS 1.2 / TLS 1.2 EC-JPAKE cipher suite (Thread MeshCoP commissioning).
 * @ingroup noxtls_tls12_ecjpake
 */

/**
 * @defgroup noxtls_tls12_ecjpake TLS 1.2 EC-JPAKE
 * @brief TLS_ECJPAKE_WITH_AES_128_CCM_8 key exchange for the TLS 1.2 / DTLS 1.2 engine.
 *
 * Specification: draft-cragie-tls-ecjpake-01 (June 2016) section 5
 * (handshake), section 7 (extensions, ServerKeyExchange,
 * ClientKeyExchange) and section 8 (calculations), with AES-128-CCM-8
 * record protection from RFC 6655 section 3 and the DTLS 1.2 record layer
 * of RFC 6347. The draft leaves the code points "TBD"; the values used
 * here are the ones Thread MeshCoP uses on the wire (cipher suite 0xC0FF,
 * extension type 256).
 *
 * Handshake (no certificates, draft section 5):
 *   ClientHello{ecjpake_key_kp_pair, supported_groups=secp256r1,
 *   ec_point_formats=uncompressed} -> [HelloVerifyRequest -> ClientHello]
 *   -> ServerHello{ecjpake_key_kp_pair}, ServerKeyExchange, ServerHelloDone
 *   -> ClientKeyExchange, ChangeCipherSpec, Finished -> ChangeCipherSpec,
 *   Finished. Premaster secret = SHA-256(K.x); master secret and key block
 *   use the TLS 1.2 PRF with SHA-256 (RFC 5246 sections 5, 6.3 and 8.1).
 *   A wrong password is detected by the Finished check (handshake failure).
 *
 * Typical Thread use (Commissioner / Joiner as DTLS client, Border Agent /
 * Joiner Router as DTLS server). The server calls noxtls_tls12_accept_poll()
 * where the client calls noxtls_tls12_connect_poll(); the exported key block
 * is the input of the Thread KEK:
 * @code
 *   tls12_context_t dtls;
 *   noxtls_dtls12_context_init(&dtls, TLS_ROLE_CLIENT);
 *   noxtls_tls_set_io_callbacks(&dtls.base.base, send_cb, recv_cb, user);
 *   noxtls_tls_set_time_callback(&dtls.base.base, now_ms_cb);
 *   noxtls_tls12_set_ecjpake_password(&dtls, pskc_or_pskd, length);
 *   do { rc = noxtls_tls12_connect_poll(&dtls); }
 *   while ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE));
 *   noxtls_tls12_ecjpake_export_key_block(&dtls, kb, sizeof(kb), &kb_len);
 *   noxtls_tls12_send(&dtls, data, len);
 *   noxtls_tls12_recv(&dtls, buf, &len);
 *   noxtls_tls12_close(&dtls);
 *   noxtls_tls12_context_free(&dtls);
 * @endcode
 * DTLS 1.2 polling is available for EC-JPAKE contexts: an empty receive
 * (the transport returns 0) is reported as NOXTLS_RETURN_WANT_READ and the
 * DTLS flight retransmission timer runs from the time callback (RFC 6347
 * section 4.2.4).
 * The blocking noxtls_tls12_connect() / noxtls_tls12_accept() drive the
 * same handshake.
 */

#ifndef NOXTLS_TLS12_ECJPAKE_H_
#define NOXTLS_TLS12_ECJPAKE_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief TLS_ECJPAKE_WITH_AES_128_CCM_8 cipher suite (draft-cragie-tls-ecjpake-01 section 2; Thread code point). */
#define TLS_CIPHER_SUITE_ECJPAKE_WITH_AES_128_CCM_8 ((uint16_t)0xC0FFU)

/** @brief ecjpake_key_kp_pair extension type (draft-cragie-tls-ecjpake-01 section 7.2.2; Thread code point). */
#define TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR ((uint16_t)256U)

/** @brief Key block size for TLS_ECJPAKE_WITH_AES_128_CCM_8: 2 x 16-octet keys + 2 x 4-octet IVs (RFC 6655 section 3). */
#define NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE (40U)

#ifndef NOXTLS_TLS12_CONTEXT_T_DEFINED
#define NOXTLS_TLS12_CONTEXT_T_DEFINED
/** @brief TLS 1.2 context (defined in noxtls_tls12.h). */
typedef struct tls12_context_s tls12_context_t;
#endif

/**
 * @brief Enable TLS_ECJPAKE_WITH_AES_128_CCM_8 on a TLS 1.2 / DTLS 1.2 context.
 *
 * Call after noxtls_dtls12_context_init() (or noxtls_tls12_context_init())
 * and before the handshake. A client then offers only the EC-JPAKE suite; a
 * server then accepts only the EC-JPAKE suite and sends no Certificate. The
 * password is mapped to the EC-JPAKE secret immediately and is not retained.
 * Calling again replaces the previous password. The EC-JPAKE state is
 * allocated with NOXTLS_MALLOC and released by noxtls_tls12_context_free().
 *
 * @param[in,out] ctx TLS 1.2 context (client or server).
 * @param[in] password Thread PSKc (Commissioner / Border Agent) or PSKd (Joiner) octets.
 * @param[in] password_len Length, NOXTLS_ECJPAKE_PASSWORD_MIN_LEN to NOXTLS_ECJPAKE_PASSWORD_MAX_LEN.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY, or NOXTLS_RETURN_FAILED when a handshake
 *         is already in progress.
 */
noxtls_return_t noxtls_tls12_set_ecjpake_password(tls12_context_t *ctx,
                                                  const uint8_t *password,
                                                  uint32_t password_len);

/**
 * @brief Report whether the completed (or running) handshake negotiated EC-JPAKE.
 *
 * @param[in] ctx TLS 1.2 context (may be NULL).
 *
 * @return 1 when the selected cipher suite is TLS_ECJPAKE_WITH_AES_128_CCM_8, else 0.
 */
int noxtls_tls12_ecjpake_negotiated(const tls12_context_t *ctx);

/**
 * @brief Export the TLS 1.2 key block of an established EC-JPAKE session.
 *
 * Output is client_write_key || server_write_key || client_write_IV ||
 * server_write_IV (RFC 5246 section 6.3 order; MAC keys are empty for AEAD),
 * that is the first NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE octets of
 * PRF(master_secret, "key expansion", server_random || client_random).
 * Thread derives the MeshCoP KEK from this value.
 *
 * @param[in] ctx Connected TLS 1.2 context that negotiated EC-JPAKE.
 * @param[out] out Output buffer.
 * @param[in] out_size Size of out, at least NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE.
 * @param[out] out_len Octets written.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM
 *         (buffer too small) or NOXTLS_RETURN_NOT_INITIALIZED (not connected or
 *         EC-JPAKE not negotiated).
 */
noxtls_return_t noxtls_tls12_ecjpake_export_key_block(const tls12_context_t *ctx,
                                                      uint8_t *out,
                                                      uint32_t out_size,
                                                      uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TLS12_ECJPAKE_H_ */
