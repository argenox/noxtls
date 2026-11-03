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
* File:    noxtls_tls13_psk.h
* Summary: TLS 1.3 PSK and ECDHE-PSK key exchange
*
* This module provides TLS 1.3 Pre-Shared Key (PSK) and ECDHE-PSK
* functionality: binder computation, ticket store, and resumption PSK derivation.
*
*****************************************************************************/

#ifndef NOXTLS_TLS13_PSK_H_
#define NOXTLS_TLS13_PSK_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls13.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Ticket/session store constants */
#define TLS13_PSK_TICKET_ID_LEN    16U
/** Bound the process-global cache to the application's actual session budget
 * (NOXTLS_TLS13_PSK_TICKET_STORE_MAX; server role only, 0 = no store).
 * Every provider/consumer must use the same build-wide configuration. */
#ifndef TLS13_PSK_TICKET_STORE_MAX
#if NOXTLS_FEATURE_TLS_SERVER
#define TLS13_PSK_TICKET_STORE_MAX NOXTLS_TLS13_PSK_TICKET_STORE_MAX
#else
#define TLS13_PSK_TICKET_STORE_MAX 0U
#endif
#endif
#if TLS13_PSK_TICKET_STORE_MAX > 64U
#error "TLS13 PSK ticket store supports 0..64 entries"
#endif
#define TLS13_PSK_TICKET_NONCE_MAX 32U
/** Nonce length of the tickets this server issues. */
#define TLS13_PSK_SERVER_NONCE_LEN 16U
/** Largest resumption PSK (SHA-384 hash length). */
#define TLS13_PSK_RESUMPTION_PSK_MAX 48U
/** Length of the server-configuration binding digest stored with each ticket (SHA-256). */
#define TLS13_PSK_TICKET_BINDING_LEN 32U
/** RFC 8446 4.6.1: servers MUST NOT use a ticket lifetime above seven days. */
#define TLS13_PSK_TICKET_LIFETIME_MAX 604800U

/* Ticket store (server-side session cache for resumption) */
typedef struct
{
    uint8_t ticket_id[TLS13_PSK_TICKET_ID_LEN];
    uint8_t resumption_psk[TLS13_PSK_RESUMPTION_PSK_MAX];
    uint8_t resumption_psk_len;
    uint8_t ticket_nonce[TLS13_PSK_SERVER_NONCE_LEN];
    uint8_t ticket_nonce_len;
    uint32_t ticket_age_add;
    uint16_t cipher_suite;
    /** Server configuration, SNI and ALPN the ticket was issued under (see tls13 binding). */
    uint8_t binding[TLS13_PSK_TICKET_BINDING_LEN];
    /** Advertised ticket_lifetime in seconds (capped at TLS13_PSK_TICKET_LIFETIME_MAX). */
    uint32_t lifetime;
    /** Unix seconds at issuance, or -1 when no clock was available (ticket is then single-use). */
    int64_t issued_at;
    /** Even: entry stable; odd: being rewritten (readers discard what they copied). */
    volatile uint32_t generation;
} psk_ticket_entry_t;

#if TLS13_PSK_TICKET_STORE_MAX > 0U
typedef struct
{
    psk_ticket_entry_t entries[TLS13_PSK_TICKET_STORE_MAX];
    uint32_t next_index;
} psk_ticket_store_t;
#endif

/** Copy of a validated ticket store entry, owned by the caller (wipe after use). */
typedef struct
{
    uint8_t resumption_psk[TLS13_PSK_RESUMPTION_PSK_MAX];
    uint8_t resumption_psk_len;
    uint8_t ticket_nonce[TLS13_PSK_SERVER_NONCE_LEN];
    uint8_t ticket_nonce_len;
    uint32_t ticket_age_add;
    uint16_t cipher_suite;
    /** Non-zero when the ticket must be removed once used (no clock at issuance or now). */
    uint8_t single_use;
} tls13_psk_ticket_t;

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
                                                  uint32_t transcript_prefix_len,
                                                  const uint8_t **fail_step_out);

/**
 * Add a session ticket to the server-side store (for lookup when client resumes).
 * Expired entries are swept first; a free or expired slot is preferred, else the oldest is
 * overwritten. @p binding is the issuing server's configuration digest
 * (TLS13_PSK_TICKET_BINDING_LEN bytes) and @p lifetime the advertised ticket_lifetime.
 */
noxtls_return_t tls13_psk_ticket_store_add(const uint8_t *ticket_id,
                                           uint8_t id_len,
                                           const uint8_t *resumption_psk,
                                           uint8_t psk_len,
                                           const uint8_t *ticket_nonce,
                                           uint8_t nonce_len,
                                           uint32_t ticket_age_add,
                                           uint16_t cipher_suite,
                                           const uint8_t *binding,
                                           uint32_t lifetime);

/**
 * Look up a ticket by ID and copy it out in one step.
 *
 * Succeeds only when the entry exists, was not being rewritten while it was copied, carries a
 * non-empty PSK, was issued under @p binding, and is within its lifetime (expired entries are
 * wiped). On failure @p out is wiped.
 */
noxtls_return_t tls13_psk_ticket_store_get(const uint8_t *ticket_id,
                                           uint32_t id_len,
                                           const uint8_t *binding,
                                           tls13_psk_ticket_t *out);

/** Remove (wipe) a ticket by ID, for example after a single-use ticket has been accepted. */
void tls13_psk_ticket_store_remove(const uint8_t *ticket_id, uint32_t id_len);

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

/**
 * Derive resumption_psk from resumption_master_secret and ticket_nonce (RFC 8446 4.6.1):
 * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length).
 */
noxtls_return_t tls13_psk_derive_resumption_psk_from_rms(noxtls_hash_algos_t hash_algo,
                                                         uint32_t hash_len,
                                                         const uint8_t *resumption_master_secret,
                                                         const uint8_t *ticket_nonce,
                                                         uint32_t ticket_nonce_len,
                                                         uint8_t *resumption_psk);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TLS13_PSK_H_ */
