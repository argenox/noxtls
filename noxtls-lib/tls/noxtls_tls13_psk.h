/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_tls13_psk.h
* Summary: TLS 1.3 PSK and ECDHE-PSK key exchange (separate module)
*
* This module provides TLS 1.3 Pre-Shared Key (PSK) and ECDHE-PSK
* functionality: binder computation, ticket store, and resumption PSK derivation.
*/

#ifndef _NOXTLS_TLS13_PSK_H_
#define _NOXTLS_TLS13_PSK_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls13.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Ticket/session store constants */
#define TLS13_PSK_TICKET_ID_LEN    16
#define TLS13_PSK_TICKET_STORE_MAX 64
#define TLS13_PSK_TICKET_NONCE_MAX 32

/**
 * Check if a PSK key exchange mode is present in the extension data.
 * @param data PSK_KEY_EXCHANGE_MODES extension payload (length byte + list)
 * @param len  Length of data
 * @param mode TLS13_PSK_KE_MODE_PSK_KE (0) or TLS13_PSK_KE_MODE_PSK_DHE_KE (1)
 */
int noxtls_tls13_psk_mode_offered(const uint8_t *data, uint16_t len, uint8_t mode);

/**
 * Find pre_shared_key extension and return binder offset/length for an identity index.
 * @param client_hello     Full ClientHello (including record if applicable)
 * @param client_hello_len Length of client_hello
 * @param identity_index   Which identity (0 = first)
 * @param binder_offset    Output: offset of binder in client_hello
 * @param binder_len       Output: length of binder
 * @param selected_identity Output: set to identity_index on success
 * @param identity_out     Optional: buffer to copy identity; may be NULL
 * @param identity_out_len Optional: in/out identity length
 */
noxtls_return_t tls13_psk_find_clienthello_binder(const uint8_t *client_hello,
                                                  uint32_t client_hello_len,
                                                  uint16_t identity_index,
                                                  uint32_t *binder_offset,
                                                  uint16_t *binder_len,
                                                  uint16_t *selected_identity,
                                                  uint8_t *identity_out,
                                                  uint16_t *identity_out_len);

/**
 * Compute resumption binder (RFC 8446 4.2.11.2).
 * early_secret = HKDF-Extract(0, resumption_psk); binder_key = Derive-Secret(early_secret, "resumption", ticket_nonce)
 */
noxtls_return_t tls13_psk_compute_resumption_binder(noxtls_hash_algos_t hash_algo,
                                                    const uint8_t *resumption_psk,
                                                    uint8_t psk_len,
                                                    const uint8_t *ticket_nonce,
                                                    uint8_t ticket_nonce_len,
                                                    const uint8_t *client_hello,
                                                    uint32_t client_hello_len,
                                                    uint32_t binder_offset,
                                                    uint16_t binder_len,
                                                    uint8_t *out_binder,
                                                    const uint8_t *transcript_prefix,
                                                    uint32_t transcript_prefix_len);

/**
 * Compute external PSK binder (label "ext binder").
 */
noxtls_return_t tls13_psk_compute_external_binder(noxtls_hash_algos_t hash_algo,
                                                  const uint8_t *psk,
                                                  uint16_t psk_len,
                                                  const uint8_t *client_hello,
                                                  uint32_t client_hello_len,
                                                  uint32_t binder_offset,
                                                  uint16_t binder_len,
                                                  uint8_t *out_binder,
                                                  const uint8_t *transcript_prefix,
                                                  uint32_t transcript_prefix_len);

/**
 * Add a session ticket to the server-side store (for lookup when client resumes).
 */
noxtls_return_t tls13_psk_ticket_store_add(const uint8_t *ticket_id,
                                           uint8_t id_len,
                                           const uint8_t *resumption_psk,
                                           uint8_t psk_len,
                                           const uint8_t *ticket_nonce,
                                           uint8_t nonce_len,
                                           uint32_t ticket_age_add,
                                           uint16_t cipher_suite);

/**
 * Look up a ticket by ID. Returns internal entry pointer or NULL; do not free.
 */
const void *tls13_psk_ticket_store_lookup(const uint8_t *ticket_id, uint32_t id_len);

/**
 * Get resumption PSK and nonce from a looked-up ticket entry.
 * @param entry    Pointer from tls13_psk_ticket_store_lookup
 * @param psk_out  Buffer for resumption_psk (at least 64 bytes)
 * @param psk_len  Output length
 * @param nonce_out Buffer for ticket_nonce (at least TLS13_PSK_TICKET_NONCE_MAX)
 * @param nonce_len Output length
 */
noxtls_return_t tls13_psk_ticket_store_entry_psk(const void *entry,
                                                  uint8_t *psk_out,
                                                  uint8_t psk_out_size,
                                                  uint8_t *psk_len,
                                                  uint8_t *nonce_out,
                                                  uint8_t nonce_out_size,
                                                  uint8_t *nonce_len);

/** Return cipher_suite for a ticket entry (for server resumption). */
uint16_t noxtls_tls13_psk_ticket_store_entry_cipher_suite(const void *entry);

/**
 * Derive resumption_psk from master_secret and ticket_nonce (RFC 8446 4.6.1).
 */
noxtls_return_t tls13_psk_derive_resumption_psk(noxtls_hash_algos_t hash_algo,
                                                uint32_t hash_len,
                                                const uint8_t *master_secret,
                                                const uint8_t *handshake_transcript,
                                                uint32_t handshake_transcript_len,
                                                const uint8_t *ticket_nonce,
                                                uint32_t ticket_nonce_len,
                                                uint8_t *resumption_psk);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS13_PSK_H_ */
