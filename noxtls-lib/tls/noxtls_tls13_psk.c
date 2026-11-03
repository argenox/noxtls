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
* File:    noxtls_tls13_psk.c
* Summary: TLS 1.3 PSK and ECDHE-PSK (binder, ticket store, resumption PSK)
*
* Note: TLS1.2 is being phased out in favor of TLS1.3
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "noxtls_tls13_psk.h"
#include "noxtls_tls_kdf.h"
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#include "noxtls_tls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"
#include "common/noxtls_time.h"
#include "drbg/noxtls_drbg.h"

#if TLS13_PSK_TICKET_STORE_MAX > 0U
static psk_ticket_store_t psk_ticket_store;
#endif

/**
 * @brief Hash handshake bytes for PSK binder transcript input.
 *
 * Same semantics as `tls13_hash_messages`. Supports SHA-256 and SHA-384 only.
 *
 * @param[in] hash_algo     Hash algorithm from the negotiated cipher suite.
 * @param[in] messages      Transcript bytes to hash (may be NULL if @p messages_len is 0).
 * @param[in] messages_len  Length of @p messages.
 * @param[out] hash         Output digest buffer (at least 48 bytes).
 * @param[out] hash_len     On success, 32 for SHA-256 or 48 for SHA-384.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p hash or @p hash_len is NULL;
 *         `NOXTLS_RETURN_INVALID_ALGORITHM` for unsupported @p hash_algo.
 */
static noxtls_return_t psk_hash_messages(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *messages, uint32_t messages_len,
                                         uint8_t *hash, uint32_t *hash_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((hash == NULL) || (hash_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        rc = noxtls_sha256_init(&sha_ctx, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if ((messages != NULL) && (messages_len > 0U)) {
            rc = noxtls_sha256_update(&sha_ctx, messages, messages_len);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
        *hash_len = 32U;
        return noxtls_sha256_finish(&sha_ctx, hash);
    }
#if NOXTLS_FEATURE_SHA384
    if (hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        rc = noxtls_sha512_init(&sha_ctx, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if ((messages != NULL) && (messages_len > 0U)) {
            rc = noxtls_sha512_update(&sha_ctx, messages, messages_len);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
        *hash_len = 48U;
        return noxtls_sha512_finish(&sha_ctx, hash);
    }
#endif
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * @brief Hash the binder transcript input for a ClientHello.
 *
 * When @p transcript_prefix_len is 0, hashes @p client_hello_prefix only (first ClientHello).
 * After HelloRetryRequest, @p transcript_prefix is the prior transcript (message_hash + HRR)
 * concatenated with the partial second ClientHello (RFC 8446 §4.2.11.2).
 *
 * @param[in] hash_algo               Hash algorithm from the negotiated cipher suite.
 * @param[in] transcript_prefix       Optional prior transcript prefix (may be NULL if length is 0).
 * @param[in] transcript_prefix_len   Length of @p transcript_prefix.
 * @param[in] client_hello_prefix     Partial ClientHello up to (but not including) binders.
 * @param[in] client_hello_prefix_len Length of @p client_hello_prefix.
 * @param[out] hash                   Output digest buffer.
 * @param[out] hash_len               On success, digest length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` on overflow;
 *         `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` if the combined buffer cannot be allocated.
 */
static noxtls_return_t psk_hash_binder_input(noxtls_hash_algos_t hash_algo,
                                            const uint8_t *transcript_prefix,
                                            uint32_t transcript_prefix_len,
                                            const uint8_t *client_hello_prefix,
                                            uint32_t client_hello_prefix_len,
                                            uint8_t *hash,
                                            uint32_t *hash_len)
{
    if (transcript_prefix_len == 0U) { return psk_hash_messages(hash_algo, client_hello_prefix, client_hello_prefix_len, hash, hash_len); }
    if (client_hello_prefix_len > (UINT32_MAX - transcript_prefix_len)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    {
        uint32_t combined_len = (uint32_t)(transcript_prefix_len + client_hello_prefix_len);
        uint8_t *combined = (uint8_t *)NOXTLS_MALLOC(combined_len);
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        if (combined == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        noxtls_copy_u8(combined, (size_t)combined_len, transcript_prefix, (size_t)transcript_prefix_len);
        noxtls_copy_u8(&combined[transcript_prefix_len], (size_t)combined_len, client_hello_prefix, (size_t)client_hello_prefix_len);
        rc = psk_hash_messages(hash_algo, combined, combined_len, hash, hash_len);
        (void)noxtls_free(combined);
        return rc;
    }
}

/**
 * @brief Read a big-endian 16-bit value from two bytes.
 * @param[in] buf Pointer to at least two bytes.
 * @return The host-order uint16 value.
 */
static uint16_t psk_read_uint16(const uint8_t *buf) { return (uint16_t)(((uint16_t)buf[0] <<8U) | (uint16_t)buf[1]); }

static int psk_clienthello_uses_dtls_layout(const uint8_t *client_hello, uint32_t client_hello_len)
{
    if ((client_hello == NULL) || (client_hello_len < 6U)) {
        return 0;
    }

    return (client_hello[4] == 0xFEU) ? 1 : 0;
}

/**
 * @brief Locate the binder-hash prefix length inside a ClientHello.
 *
 * RFC 8446 §4.2.11.2: the binder transcript covers the partial ClientHello up to and
 * including `PreSharedKeyExtension.identities`; the binders vector is excluded.
 *
 * @param[in] client_hello     ClientHello handshake message (type 0x01u).
 * @param[in] client_hello_len Length of @p client_hello.
 * @param[out] prefix_len      On success, byte offset immediately after the identities list.
 * @return `NOXTLS_RETURN_SUCCESS` if a pre_shared_key extension is found;
 *         `NOXTLS_RETURN_NULL` on invalid pointers; `NOXTLS_RETURN_BAD_DATA` on malformed input;
 *         `NOXTLS_RETURN_FAILED` if the extension is absent.
 */
static noxtls_return_t psk_clienthello_binder_prefix_len(const uint8_t *client_hello,
                                                         uint32_t client_hello_len,
                                                         uint32_t *prefix_len)
{
    uint32_t offset = 0U;
    uint8_t session_id_len = 0U;
    uint16_t cipher_len = 0U;
    uint8_t comp_len = 0U;
    uint16_t extensions_len = 0U;

    if ((client_hello == NULL) || (prefix_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (client_hello_len < (4U + 2U + 32U + 1U + 2U + 1U + 2U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    offset = 4U + 2U + 32U;
    session_id_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)session_id_len + 2U + 1U + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    if (psk_clienthello_uses_dtls_layout(client_hello, client_hello_len) != 0) {
        uint8_t cookie_len = 0U;
        if ((offset + (1U + 2U + (1U + 2U))) > client_hello_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        cookie_len = client_hello[offset];
        offset += 1U;
        if ((offset + cookie_len + (2U + (1U + 2U))) > client_hello_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        offset += cookie_len;
    }
    cipher_len = psk_read_uint16(&client_hello[offset]);
    offset += 2U;
    if ((offset + (uint32_t)cipher_len + 1U + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_len;
    comp_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)comp_len + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += comp_len;
    extensions_len = psk_read_uint16(&client_hello[offset]);
    offset += 2U;
    if ((offset + (uint32_t)extensions_len) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t ext_end = (uint32_t)(offset + extensions_len);
        while ((offset + 4U) <= ext_end) {
            uint16_t ext_type = (uint16_t)(psk_read_uint16(&client_hello[offset]));
            uint16_t ext_len = (uint16_t)(psk_read_uint16(&client_hello[offset + 2U]));
            offset += 4U;
            if(((offset + ext_len) > ext_end)) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            if (ext_type == TLS_EXTENSION_PRE_SHARED_KEY) {
                uint32_t p = (uint32_t)(offset);
                uint16_t identities_len = 0U;
                if (ext_len < 2U) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_len = psk_read_uint16(&client_hello[p]);
                p += 2U;
                if (((uint32_t)identities_len + 2U) > ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if (identities_len < (2U + 4U)) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                p += identities_len; /* now points to binders vector length */
                if (p > client_hello_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                *prefix_len = p;
                return NOXTLS_RETURN_SUCCESS;
            }
            offset += ext_len;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Check whether a PSK key exchange mode appears in the extension payload.
 * @param[in] data PSK_KEY_EXCHANGE_MODES extension body (leading length byte + mode list).
 * @param[in] len  Length of @p data.
 * @param[in] mode `TLS13_PSK_KE_MODE_PSK_KE` (0) or `TLS13_PSK_KE_MODE_PSK_DHE_KE` (1).
 * @return 1 if @p mode is listed; 0 otherwise or on invalid input.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
int noxtls_tls13_psk_mode_offered(const uint8_t *data, uint16_t len, uint8_t mode)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if ((data == NULL) || (len < 1U)) {
        return 0;
    }
    if (((uint16_t)data[0U] + 1U) > len) {
        return 0;
    }
    for (uint16_t i = 0U; i < (uint16_t)data[0]; i += 1U) {
        if (data[1U + i] == mode) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Parse pre_shared_key in ClientHello and locate a binder for an identity index.
 * @param[in] client_hello      Full ClientHello handshake message.
 * @param[in] client_hello_len Length of @p client_hello.
 * @param[in] identity_index    Zero-based index into the identities list.
 * @param[out] binder_offset    Byte offset of the selected binder value in @p client_hello.
 * @param[out] binder_len       Length of the binder (hash length for the cipher suite).
 * @param[out] selected_identity Set to @p identity_index on success.
 * @param[out] identity_out     Optional buffer to receive the ticket identity bytes.
 * @param[in,out] identity_out_len Optional in/out identity length (required size if buffer too small).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on missing required outputs;
 *         `NOXTLS_RETURN_BAD_DATA` on malformed ClientHello; `NOXTLS_RETURN_FAILED` if extension absent.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t tls13_psk_find_clienthello_binder(const uint8_t *client_hello,
                                                  uint32_t client_hello_len,
                                                  uint16_t identity_index,
                                                  uint32_t *binder_offset,
                                                  uint16_t *binder_len,
                                                  uint16_t *selected_identity,
                                                  uint8_t *identity_out,
                                                  uint16_t *identity_out_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t offset = 0U;
    uint8_t session_id_len = 0U;
    uint16_t cipher_len = 0U;
    uint8_t comp_len = 0U;
    uint16_t extensions_len = 0U;

    if ((client_hello == NULL) || (binder_offset == NULL) || (binder_len == NULL) || (selected_identity == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (client_hello_len < (4U + 2U + 32U + 1U + 2U + 1U + 2U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    offset = 4U + 2U + 32U;
    session_id_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)session_id_len + 2U + 1U + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    if (psk_clienthello_uses_dtls_layout(client_hello, client_hello_len) != 0) {
        uint8_t cookie_len = 0U;
        if ((offset + (1U + 2U + (1U + 2U))) > client_hello_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        cookie_len = client_hello[offset];
        offset += 1U;
        if ((offset + cookie_len + (2U + (1U + 2U))) > client_hello_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        offset += cookie_len;
    }
    cipher_len = psk_read_uint16(&client_hello[offset]);
    offset += 2U;
    if ((offset + (uint32_t)cipher_len + 1U + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_len;
    comp_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)comp_len + 2U) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += comp_len;
    extensions_len = psk_read_uint16(&client_hello[offset]);
    offset += 2U;
    if ((offset + (uint32_t)extensions_len) > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t ext_end = (uint32_t)(offset + extensions_len);
        while ((offset + 4U) <= ext_end) {
            uint16_t ext_type = (uint16_t)(psk_read_uint16(&client_hello[offset]));
            uint16_t ext_len = (uint16_t)(psk_read_uint16(&client_hello[offset + 2U]));
            offset += 4U;
            if(((offset + ext_len) > ext_end)) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            if (ext_type == TLS_EXTENSION_PRE_SHARED_KEY) {
                uint32_t p = (uint32_t)(offset);
                uint16_t identities_len = 0U;
                uint16_t binders_len = 0U;
                uint32_t identities_end = 0U;
                uint16_t idx = 0U;

                if (ext_len < 2U) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_len = psk_read_uint16(&client_hello[p]);
                p += 2U;
                if (((uint32_t)identities_len + 2U) > ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if (identities_len < (2U + 4U)) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_end = p + identities_len;
                /*
                 * RFC 8446 4.2.11: walk the whole identities vector (not just up to the
                 * selected index) so the binders vector that follows is located correctly.
                 */
                while (p < identities_end) {
                    uint16_t id_len = 0U;
                    if ((p + 2U) > identities_end) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    id_len = psk_read_uint16(&client_hello[p]);
                    p += 2U;
                    if ((id_len == 0U) || (((uint32_t)id_len + 4U) > (uint32_t)(identities_end - p))) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    if (idx == identity_index) {
                        if ((identity_out != NULL) && (identity_out_len != NULL) && (*identity_out_len >= id_len)) {
                            noxtls_copy_u8(identity_out, (size_t)id_len, &client_hello[p], (size_t)id_len);
                            *identity_out_len = id_len;
                        } else if (identity_out_len != NULL) {
                            *identity_out_len = id_len;
                        } else {
                            /* MISRA 15.7: no remaining alternative */
                        }
                    }
                    p += (uint32_t)id_len + 4U;
                    if (idx == 0xFFFFU) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    idx += 1U;
                }
                if (identity_index >= idx) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if ((p + 2U) > (offset + ext_len)) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                binders_len = psk_read_uint16(&client_hello[p]);
                p += 2U;
                if ((binders_len < (1U + 32U)) || ((p + binders_len) != (offset + ext_len))) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                {
                    /* RFC 8446 4.2.11: one PskBinderEntry<32..255> per identity, same order. */
                    const uint32_t binders_end = p + (uint32_t)binders_len;
                    uint32_t selected_off = 0U;
                    uint16_t selected_len = 0U;
                    uint16_t bidx = 0U;
                    while (p < binders_end) {
                        uint16_t bl = (uint16_t)(client_hello[p]);
                        p += 1U;
                        if ((bl < 32U) || (((uint32_t)p + (uint32_t)bl) > binders_end)) {
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                        if (bidx == identity_index) {
                            selected_off = p;
                            selected_len = bl;
                        }
                        p += (uint32_t)bl;
                        bidx += 1U;
                        if (bidx > idx) {
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    }
                    if (bidx != idx) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    *binder_len = selected_len;
                    *binder_offset = selected_off;
                }
                *selected_identity = identity_index;
                return NOXTLS_RETURN_SUCCESS;
            }
            offset += ext_len;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Binder key schedule shared by resumption and external PSK binders (RFC 8446 4.2.11.2).
 *
 * early_secret = HKDF-Extract(0, PSK), binder_key = Derive-Secret(early_secret, label, ""),
 * finished_key = HKDF-Expand-Label(binder_key, "finished"), binder = HMAC(finished_key, hash).
 * early_secret is PSK-equivalent, so every intermediate is wiped on every exit.
 *
 * @param[in] hash_algo        Binder hash.
 * @param[in] hash_len         Hash length (32 or 48).
 * @param[in] psk              PSK bytes.
 * @param[in] psk_len          Length of @p psk.
 * @param[in] label            Derive-Secret label ("res binder" / "ext binder").
 * @param[in] label_len        Length of @p label.
 * @param[in] transcript_hash  Hash of the truncated ClientHello transcript.
 * @param[in] transcript_len   Length of @p transcript_hash.
 * @param[out] out_binder      Computed binder (@p hash_len bytes).
 * @param[out] fail_step_out   Optional failing step name.
 * @return `NOXTLS_RETURN_SUCCESS` on success; KDF/HMAC error otherwise.
 */
static noxtls_return_t psk_binder_from_psk(noxtls_hash_algos_t hash_algo,
                                           uint32_t hash_len,
                                           const uint8_t *psk,
                                           uint32_t psk_len,
                                           const uint8_t *label,
                                           uint32_t label_len,
                                           const uint8_t *transcript_hash,
                                           uint32_t transcript_len,
                                           uint8_t *out_binder,
                                           const uint8_t **fail_step_out)
{
    static const uint8_t finished_label[] = {
        (uint8_t)'f',(uint8_t)'i',(uint8_t)'n',(uint8_t)'i',(uint8_t)'s',(uint8_t)'h',(uint8_t)'e',(uint8_t)'d'
    };
    static const uint8_t step_extract[] = "hkdf_extract";
    static const uint8_t step_derive[] = "derive_secret";
    static const uint8_t step_expand[] = "expand_finished";
    static const uint8_t step_hmac[] = "finished_hmac";
    static const uint8_t step_verify_len[] = "verify_len";
    uint8_t early_secret[64];
    uint8_t binder_key[64];
    uint8_t finished_key[64];
    uint8_t computed_binder[64];
    uint32_t prk_len = hash_len;
    uint32_t verify_len = (uint32_t)sizeof(computed_binder);
    const uint8_t *step = NULL;
    noxtls_return_t rc = noxtls_hkdf_extract(hash_algo, NULL, 0, psk, psk_len, early_secret, &prk_len);

    if (rc != NOXTLS_RETURN_SUCCESS) {
        step = step_extract;
    } else {
        rc = tls13_derive_secret(hash_algo, early_secret, hash_len, label, label_len,
                                 NULL, 0, binder_key, hash_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            step = step_derive;
        }
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = tls13_hkdf_expand_label(hash_algo, binder_key, hash_len, finished_label, 8U,
                                     NULL, 0U, finished_key, hash_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            step = step_expand;
        }
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                                 computed_binder, &verify_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            step = step_hmac;
        } else if (verify_len != hash_len) {
            rc = NOXTLS_RETURN_FAILED;
            step = step_verify_len;
        } else {
            noxtls_copy_u8(out_binder, (size_t)hash_len, computed_binder, (size_t)hash_len);
        }
    }
    if (fail_step_out != NULL) {
        *fail_step_out = step;
    }
    noxtls_secure_zero(early_secret, sizeof(early_secret));
    noxtls_secure_zero(binder_key, sizeof(binder_key));
    noxtls_secure_zero(finished_key, sizeof(finished_key));
    noxtls_secure_zero(computed_binder, sizeof(computed_binder));
    return rc;
}

/**
 * @brief Compute the resumption PSK binder for ticket-based resumption (RFC 8446 §4.2.11.2).
 *
 * Derives `early_secret = HKDF-Extract(0, resumption_psk)`, then `binder_key` with label
 * "res binder", hashes the partial ClientHello transcript, and HMACs with the finished key.
 *
 * @param[in] hash_algo              Hash from the ticket cipher suite (SHA-256 or SHA-384).
 * @param[in] resumption_psk         PSK from the issued ticket.
 * @param[in] psk_len                Length of @p resumption_psk.
 * @param[in] ticket_nonce           Ticket nonce from the NewSessionTicket (unused in binder key for resumption label path).
 * @param[in] ticket_nonce_len       Length of @p ticket_nonce.
 * @param[in] client_hello           ClientHello containing the binder to verify.
 * @param[in] client_hello_len       Length of @p client_hello.
 * @param[in] binder_offset          Offset of the binder bytes in @p client_hello.
 * @param[in] binder_len             Expected binder length (must equal hash length).
 * @param[out] out_binder            Buffer for computed binder (hash length bytes).
 * @param[in] transcript_prefix      Optional HRR transcript prefix (NULL if length 0).
 * @param[in] transcript_prefix_len  Length of @p transcript_prefix.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for null pointers, bad layout, or KDF/HMAC failure.
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
                                                    uint32_t transcript_prefix_len)
{
    uint8_t transcript_hash[64];
    uint32_t transcript_len = (uint32_t)sizeof(transcript_hash);
    uint32_t binder_prefix_len = 0U;
    uint32_t hash_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    static const uint8_t label[] = "res binder";
    const uint32_t label_len = 10U;

    if ((resumption_psk == NULL) || (ticket_nonce == NULL) || (client_hello == NULL) || (out_binder == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((binder_len == 0U) || (binder_offset > client_hello_len) || ((uint32_t)binder_len > (client_hello_len - binder_offset))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        hash_len = 32U;
#if NOXTLS_FEATURE_SHA384
    } else if (hash_algo == NOXTLS_HASH_SHA_384) {
        hash_len = 48U;
#endif
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (binder_len != hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = psk_clienthello_binder_prefix_len(client_hello, client_hello_len, &binder_prefix_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if ((binder_offset < binder_prefix_len) || ((binder_offset + binder_len) > client_hello_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = psk_hash_binder_input(hash_algo, transcript_prefix, transcript_prefix_len,
                               client_hello, binder_prefix_len, transcript_hash, &transcript_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    (void)ticket_nonce_len;  /* the binder key does not depend on the nonce (RFC 8446 4.2.11.2) */
    rc = psk_binder_from_psk(hash_algo, hash_len, resumption_psk, (uint32_t)psk_len, label, label_len,
                             transcript_hash, transcript_len, out_binder, NULL);
    if ((rc != NOXTLS_RETURN_SUCCESS) && (rc != NOXTLS_RETURN_FAILED)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    return rc;
}

/**
 * @brief Compute the external PSK binder (RFC 8446 §4.2.11.2, label "ext binder").
 *
 * Same transcript and HKDF flow as resumption binders, but uses an externally provisioned PSK
 * and the "ext binder" Derive-Secret label.
 *
 * @param[in] hash_algo              Hash from the negotiated cipher suite.
 * @param[in] psk                    External pre-shared key bytes.
 * @param[in] psk_len                Length of @p psk.
 * @param[in] client_hello           ClientHello containing the binder to verify.
 * @param[in] client_hello_len       Length of @p client_hello.
 * @param[in] binder_offset          Offset of the binder in @p client_hello.
 * @param[in] binder_len             Expected binder length (must equal hash length).
 * @param[out] out_binder            Buffer for computed binder.
 * @param[in] transcript_prefix      Optional HRR transcript prefix.
 * @param[in] transcript_prefix_len  Length of @p transcript_prefix.
 * @return `NOXTLS_RETURN_SUCCESS` on success; error codes for invalid input or crypto failure.
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
                                                  const uint8_t **fail_step_out)
{
    uint8_t transcript_hash[64];
    uint32_t transcript_len = (uint32_t)sizeof(transcript_hash);
    uint32_t binder_prefix_len = 0U;
    uint32_t hash_len = 0U;
    uint32_t label_len = 10U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    static const uint8_t label[] = "ext binder";

    if (fail_step_out != NULL) {
        *fail_step_out = NULL;
    }

    if ((psk == NULL) || (psk_len == 0U) || (client_hello == NULL) || (out_binder == NULL)) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'n', (uint8_t)'u', (uint8_t)'l', (uint8_t)'l', 0 };
        }
        return NOXTLS_RETURN_NULL;
    }
    if ((binder_len == 0U) || (binder_offset > client_hello_len) || ((uint32_t)binder_len > (client_hello_len - binder_offset))) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'i', (uint8_t)'n', (uint8_t)'d', (uint8_t)'e', (uint8_t)'r', (uint8_t)'_', (uint8_t)'b', (uint8_t)'o', (uint8_t)'u', (uint8_t)'n', (uint8_t)'d', (uint8_t)'s', 0 };
        }
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        hash_len = 32U;
#if NOXTLS_FEATURE_SHA384
    } else if (hash_algo == NOXTLS_HASH_SHA_384) {
        hash_len = 48U;
#endif
    } else {
        /* MISRA 15.7: final else path */
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'h', (uint8_t)'a', (uint8_t)'s', (uint8_t)'h', (uint8_t)'_', (uint8_t)'a', (uint8_t)'l', (uint8_t)'g', (uint8_t)'o', 0 };
        }
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (binder_len != hash_len) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'i', (uint8_t)'n', (uint8_t)'d', (uint8_t)'e', (uint8_t)'r', (uint8_t)'_', (uint8_t)'l', (uint8_t)'e', (uint8_t)'n', 0 };
        }
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = psk_clienthello_binder_prefix_len(client_hello, client_hello_len, &binder_prefix_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'i', (uint8_t)'n', (uint8_t)'d', (uint8_t)'e', (uint8_t)'r', (uint8_t)'_', (uint8_t)'p', (uint8_t)'r', (uint8_t)'e', (uint8_t)'f', (uint8_t)'i', (uint8_t)'x', 0 };
        }
        return rc;
    }
    if ((binder_offset < binder_prefix_len) || ((binder_offset + binder_len) > client_hello_len)) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'i', (uint8_t)'n', (uint8_t)'d', (uint8_t)'e', (uint8_t)'r', (uint8_t)'_', (uint8_t)'r', (uint8_t)'a', (uint8_t)'n', (uint8_t)'g', (uint8_t)'e', 0 };
        }
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = psk_hash_binder_input(hash_algo, transcript_prefix, transcript_prefix_len,
                               client_hello, binder_prefix_len, transcript_hash, &transcript_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (fail_step_out != NULL) {
            *fail_step_out = (const uint8_t[]){ (uint8_t)'t', (uint8_t)'r', (uint8_t)'a', (uint8_t)'n', (uint8_t)'s', (uint8_t)'c', (uint8_t)'r', (uint8_t)'i', (uint8_t)'p', (uint8_t)'t', (uint8_t)'_', (uint8_t)'h', (uint8_t)'a', (uint8_t)'s', (uint8_t)'h', 0 };
        }
        return rc;
    }

    return psk_binder_from_psk(hash_algo, hash_len, psk, (uint32_t)psk_len, label, label_len,
                               transcript_hash, transcript_len, out_binder, fail_step_out);
}

#if TLS13_PSK_TICKET_STORE_MAX > 0U
/**
 * @brief Current time for ticket lifetimes.
 * @return Unix seconds, or -1 when the platform has no clock.
 */
static int64_t psk_ticket_now(void)
{
    noxtls_unix_time_t now = noxtls_time_unix_seconds();
    return (now < 0) ? (int64_t)-1 : (int64_t)now;
}

/**
 * @brief True when an entry is past its lifetime (or the clock went backwards).
 *
 * Without a clock at issuance or now the lifetime cannot be checked; such tickets are
 * single-use instead (see tls13_psk_ticket_store_get()).
 */
static int psk_ticket_expired(int64_t issued_at, uint32_t lifetime, int64_t now)
{
    int expired = 0;
    if((issued_at >= 0) && (now >= 0)) {
        if((now < issued_at) || ((uint64_t)(now - issued_at) > (uint64_t)lifetime)) {
            expired = 1;
        }
    }
    return expired;
}

/**
 * @brief Wipe one entry, marking it as being rewritten while it is cleared.
 */
static void psk_ticket_entry_wipe(psk_ticket_entry_t *e)
{
    uint32_t gen = e->generation;
    e->generation = gen + 1U;   /* odd: concurrent readers discard their copy */
    noxtls_secure_zero(e->ticket_id, sizeof(e->ticket_id));
    noxtls_secure_zero(e->resumption_psk, sizeof(e->resumption_psk));
    e->resumption_psk_len = 0U;
    noxtls_secure_zero(e->ticket_nonce, sizeof(e->ticket_nonce));
    e->ticket_nonce_len = 0U;
    e->ticket_age_add = 0U;
    e->cipher_suite = 0U;
    noxtls_secure_zero(e->binding, sizeof(e->binding));
    e->lifetime = 0U;
    e->issued_at = 0;
    e->generation = gen + 2U;   /* even again */
}
#endif

/**
 * @brief Wipe every ticket in the process-global TLS 1.3 server ticket store.
 *
 * Resumption PSKs otherwise stay in static memory until their slot is reused. The store
 * is serialised by the integrator lock installed with noxtls_drbg_set_lock_callbacks();
 * without one, call this only when no server handshake is running.
 */
void noxtls_tls13_psk_ticket_store_clear(void)
{
#if TLS13_PSK_TICKET_STORE_MAX > 0U
    uint32_t i = 0U;
    noxtls_drbg_shared_lock();
    for (i = 0U; i < TLS13_PSK_TICKET_STORE_MAX; i += 1U) {
        psk_ticket_entry_wipe(&psk_ticket_store.entries[i]);
    }
    psk_ticket_store.next_index = 0U;
    noxtls_drbg_shared_unlock();
#endif
}

/**
 * @brief Insert a session ticket into the server-side resumption store.
 *
 * Expired entries are wiped first. The new ticket takes a free slot when there is one,
 * otherwise the slot after the most recently written one (the oldest ticket) is overwritten.
 *
 * @param[in] ticket_id       Ticket identity (up to `TLS13_PSK_TICKET_ID_LEN` bytes).
 * @param[in] id_len          Length of @p ticket_id.
 * @param[in] resumption_psk  Resumption PSK derived at ticket issuance.
 * @param[in] psk_len         Length of @p resumption_psk (max 48).
 * @param[in] ticket_nonce    Nonce from NewSessionTicket.
 * @param[in] nonce_len       Length of @p ticket_nonce (max `TLS13_PSK_SERVER_NONCE_LEN`).
 * @param[in] ticket_age_add  Ticket age add value from NewSessionTicket.
 * @param[in] cipher_suite    Cipher suite used for the original connection.
 * @param[in] binding         Server configuration binding (`TLS13_PSK_TICKET_BINDING_LEN` bytes).
 * @param[in] lifetime        Advertised ticket_lifetime in seconds (capped at 7 days).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` on out-of-range lengths.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t tls13_psk_ticket_store_add(const uint8_t *ticket_id,
                                           uint8_t id_len,
                                           const uint8_t *resumption_psk,
                                           uint8_t psk_len,
                                           const uint8_t *ticket_nonce,
                                           uint8_t nonce_len,
                                           uint32_t ticket_age_add,
                                           uint16_t cipher_suite,
                                           const uint8_t *binding,
                                           uint32_t lifetime)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
#if TLS13_PSK_TICKET_STORE_MAX > 0U
    psk_ticket_entry_t *e = NULL;
    uint32_t i = 0U;
    uint32_t gen = 0U;
    int64_t now = psk_ticket_now();

    if ((ticket_id == NULL) || (id_len != TLS13_PSK_TICKET_ID_LEN) || (resumption_psk == NULL) ||
        (psk_len == 0U) || (psk_len > TLS13_PSK_RESUMPTION_PSK_MAX) || (ticket_nonce == NULL) ||
        (nonce_len > TLS13_PSK_SERVER_NONCE_LEN) || (binding == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_drbg_shared_lock();
    /* Sweep expired tickets and prefer an empty slot. */
    for (i = 0U; i < TLS13_PSK_TICKET_STORE_MAX; i += 1U) {
        psk_ticket_entry_t *c = &psk_ticket_store.entries[i];
        if ((c->resumption_psk_len != 0U) && (psk_ticket_expired(c->issued_at, c->lifetime, now) != 0)) {
            psk_ticket_entry_wipe(c);
        }
        if ((e == NULL) && (c->resumption_psk_len == 0U)) {
            e = c;
        }
    }
    if (e == NULL) {
        e = &psk_ticket_store.entries[psk_ticket_store.next_index % TLS13_PSK_TICKET_STORE_MAX];
        psk_ticket_store.next_index = (psk_ticket_store.next_index + 1U) % TLS13_PSK_TICKET_STORE_MAX;
    }
    psk_ticket_entry_wipe(e);
    gen = e->generation;
    e->generation = gen + 1U;
    noxtls_copy_u8(e->ticket_id, sizeof(e->ticket_id), ticket_id, (size_t)id_len);
    noxtls_copy_u8(e->resumption_psk, sizeof(e->resumption_psk), resumption_psk, (size_t)psk_len);
    e->resumption_psk_len = psk_len;
    e->ticket_nonce_len = nonce_len;
    noxtls_copy_u8(e->ticket_nonce, sizeof(e->ticket_nonce), ticket_nonce, (size_t)nonce_len);
    e->ticket_age_add = ticket_age_add;
    e->cipher_suite = cipher_suite;
    noxtls_copy_u8(e->binding, sizeof(e->binding), binding, (size_t)TLS13_PSK_TICKET_BINDING_LEN);
    e->lifetime = (lifetime > TLS13_PSK_TICKET_LIFETIME_MAX) ? TLS13_PSK_TICKET_LIFETIME_MAX : lifetime;
    e->issued_at = now;
    e->generation = gen + 2U;
    noxtls_drbg_shared_unlock();
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ticket_id;
    (void)id_len;
    (void)resumption_psk;
    (void)psk_len;
    (void)ticket_nonce;
    (void)nonce_len;
    (void)ticket_age_add;
    (void)cipher_suite;
    (void)binding;
    (void)lifetime;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Look up a stored session ticket by identity and copy it out.
 *
 * The copy is taken between two reads of the entry's generation counter; if the entry was
 * being rewritten (odd counter) or changed during the copy, the lookup fails rather than
 * returning a torn or zeroed PSK. The copied identity is re-compared, the PSK must be
 * non-empty, the binding must match the resuming server, and the ticket must be within its
 * lifetime (expired entries are wiped).
 *
 * Store access is serialised by the integrator lock installed with
 * noxtls_drbg_set_lock_callbacks(). Without a lock the generation check narrows, but on
 * weakly ordered CPUs does not by itself exclude, races with a concurrent
 * tls13_psk_ticket_store_add() on another thread.
 *
 * @param[in] ticket_id Ticket identity from ClientHello pre_shared_key.
 * @param[in] id_len    Must equal `TLS13_PSK_TICKET_ID_LEN`.
 * @param[in] binding   Binding of the resuming server (`TLS13_PSK_TICKET_BINDING_LEN` bytes).
 * @param[out] out      Copy of the ticket; wiped on failure.
 * @return `NOXTLS_RETURN_SUCCESS` when a usable ticket was copied; `NOXTLS_RETURN_FAILED` otherwise.
 */
noxtls_return_t tls13_psk_ticket_store_get(const uint8_t *ticket_id,
                                           uint32_t id_len,
                                           const uint8_t *binding,
                                           tls13_psk_ticket_t *out)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
#if TLS13_PSK_TICKET_STORE_MAX > 0U
    uint32_t i = 0U;
    int64_t now = psk_ticket_now();

    if (out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(out, sizeof(*out));
    if ((ticket_id == NULL) || (id_len != TLS13_PSK_TICKET_ID_LEN) || (binding == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_drbg_shared_lock();
    for (i = 0U; (i < TLS13_PSK_TICKET_STORE_MAX) && (rc != NOXTLS_RETURN_SUCCESS); i += 1U) {
        psk_ticket_entry_t *e = &psk_ticket_store.entries[i];
        uint8_t id_copy[TLS13_PSK_TICKET_ID_LEN];
        uint8_t binding_copy[TLS13_PSK_TICKET_BINDING_LEN];
        int64_t issued_at = 0;
        uint32_t lifetime = 0U;
        uint32_t gen_before = e->generation;
        uint32_t gen_after = 0U;

        if (((gen_before & 1U) != 0U) || (e->resumption_psk_len == 0U) ||
            (noxtls_ct_equal(e->ticket_id, ticket_id, (size_t)TLS13_PSK_TICKET_ID_LEN) == 0)) {
            continue;
        }
        noxtls_copy_u8(id_copy, sizeof(id_copy), e->ticket_id, sizeof(id_copy));
        noxtls_copy_u8(binding_copy, sizeof(binding_copy), e->binding, sizeof(binding_copy));
        out->resumption_psk_len = e->resumption_psk_len;
        out->ticket_nonce_len = e->ticket_nonce_len;
        if ((out->resumption_psk_len <= TLS13_PSK_RESUMPTION_PSK_MAX) &&
            (out->ticket_nonce_len <= TLS13_PSK_SERVER_NONCE_LEN)) {
            noxtls_copy_u8(out->resumption_psk, sizeof(out->resumption_psk), e->resumption_psk,
                           (size_t)out->resumption_psk_len);
            noxtls_copy_u8(out->ticket_nonce, sizeof(out->ticket_nonce), e->ticket_nonce,
                           (size_t)out->ticket_nonce_len);
        }
        out->ticket_age_add = e->ticket_age_add;
        out->cipher_suite = e->cipher_suite;
        issued_at = e->issued_at;
        lifetime = e->lifetime;
        gen_after = e->generation;

        if ((gen_after == gen_before) &&
            (out->resumption_psk_len != 0U) && (out->resumption_psk_len <= TLS13_PSK_RESUMPTION_PSK_MAX) &&
            (out->ticket_nonce_len <= TLS13_PSK_SERVER_NONCE_LEN) &&
            (noxtls_ct_equal(id_copy, ticket_id, (size_t)TLS13_PSK_TICKET_ID_LEN) != 0) &&
            (noxtls_ct_equal(binding_copy, binding, (size_t)TLS13_PSK_TICKET_BINDING_LEN) != 0)) {
            if (psk_ticket_expired(issued_at, lifetime, now) != 0) {
                psk_ticket_entry_wipe(e);
            } else {
                out->single_use = ((issued_at < 0) || (now < 0)) ? 1U : 0U;
                rc = NOXTLS_RETURN_SUCCESS;
            }
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(out, sizeof(*out));
        }
        noxtls_secure_zero(binding_copy, sizeof(binding_copy));
    }
    noxtls_drbg_shared_unlock();
#else
    (void)ticket_id;
    (void)id_len;
    (void)binding;
    if (out != NULL) {
        noxtls_secure_zero(out, sizeof(*out));
    }
#endif
    return rc;
}

/**
 * @brief Remove (wipe) the store entry with this ticket identity, if present.
 * @param[in] ticket_id Ticket identity.
 * @param[in] id_len    Must equal `TLS13_PSK_TICKET_ID_LEN`.
 */
void tls13_psk_ticket_store_remove(const uint8_t *ticket_id, uint32_t id_len)
{
#if TLS13_PSK_TICKET_STORE_MAX > 0U
    uint32_t i = 0U;
    if ((ticket_id == NULL) || (id_len != TLS13_PSK_TICKET_ID_LEN)) {
        return;
    }
    noxtls_drbg_shared_lock();
    for (i = 0U; i < TLS13_PSK_TICKET_STORE_MAX; i += 1U) {
        psk_ticket_entry_t *e = &psk_ticket_store.entries[i];
        if ((e->resumption_psk_len != 0U) &&
            (noxtls_ct_equal(e->ticket_id, ticket_id, (size_t)TLS13_PSK_TICKET_ID_LEN) != 0)) {
            psk_ticket_entry_wipe(e);
        }
    }
    noxtls_drbg_shared_unlock();
#else
    (void)ticket_id;
    (void)id_len;
#endif
}

/**
 * @brief Derive the resumption PSK for a NewSessionTicket (RFC 8446 §4.6.1).
 *
 * Computes `resumption_master_secret = Derive-Secret(master_secret, "res master", transcript)`
 * then `resumption_psk = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce)`.
 *
 * @param[in] hash_algo                  Hash algorithm for the connection.
 * @param[in] hash_len                   Hash output length in bytes (32 or 48).
 * @param[in] master_secret              Current connection master secret.
 * @param[in] handshake_transcript       Handshake transcript hashed for "res master".
 * @param[in] handshake_transcript_len   Length of @p handshake_transcript.
 * @param[in] ticket_nonce               Nonce from NewSessionTicket.
 * @param[in] ticket_nonce_len           Length of @p ticket_nonce.
 * @param[out] resumption_psk            Output buffer (at least @p hash_len bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` or `NOXTLS_RETURN_INVALID_PARAM` on bad input.
 */
noxtls_return_t tls13_psk_derive_resumption_psk(noxtls_hash_algos_t hash_algo,
                                                uint32_t hash_len,
                                                const uint8_t *master_secret,
                                                const uint8_t *handshake_transcript,
                                                uint32_t handshake_transcript_len,
                                                const uint8_t *ticket_nonce,
                                                uint32_t ticket_nonce_len,
                                                uint8_t *resumption_psk)
{
    uint8_t resumption_master_secret[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    static const uint8_t rms_label[] = {
        (uint8_t)'r',(uint8_t)'e',(uint8_t)'s',(uint8_t)' ',(uint8_t)'m',(uint8_t)'a',(uint8_t)'s',(uint8_t)'t',(uint8_t)'e',(uint8_t)'r'
    };
    const uint32_t rms_label_len = 10U;
    static const uint8_t psk_label[] = {
        (uint8_t)'r',(uint8_t)'e',(uint8_t)'s',(uint8_t)'u',(uint8_t)'m',(uint8_t)'p',(uint8_t)'t',(uint8_t)'i',(uint8_t)'o',(uint8_t)'n'
    };
    const uint32_t psk_label_len = 10U;

    if ((master_secret == NULL) || (ticket_nonce == NULL) || (resumption_psk == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((hash_len > 64U) || (ticket_nonce_len > 255U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = tls13_derive_secret(hash_algo, master_secret, hash_len, rms_label, rms_label_len,
                             handshake_transcript, handshake_transcript_len,
                             resumption_master_secret, hash_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero((resumption_master_secret), sizeof(resumption_master_secret));
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, resumption_master_secret, hash_len,
                                 psk_label, psk_label_len, ticket_nonce, ticket_nonce_len,
                                 resumption_psk, hash_len);
    noxtls_secure_zero((resumption_master_secret), sizeof(resumption_master_secret));
    return rc;
}

noxtls_return_t tls13_psk_derive_resumption_psk_from_rms(noxtls_hash_algos_t hash_algo,
                                                         uint32_t hash_len,
                                                         const uint8_t *resumption_master_secret,
                                                         const uint8_t *ticket_nonce,
                                                         uint32_t ticket_nonce_len,
                                                         uint8_t *resumption_psk)
{
    static const uint8_t psk_label[] = {
        (uint8_t)'r',(uint8_t)'e',(uint8_t)'s',(uint8_t)'u',(uint8_t)'m',(uint8_t)'p',(uint8_t)'t',(uint8_t)'i',(uint8_t)'o',(uint8_t)'n'
    };

    if ((resumption_master_secret == NULL) || (ticket_nonce == NULL) || (resumption_psk == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((hash_len == 0U) || (hash_len > 64U) || (ticket_nonce_len > 255U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return tls13_hkdf_expand_label(hash_algo, resumption_master_secret, hash_len,
                                   psk_label, (uint32_t)sizeof(psk_label), ticket_nonce, ticket_nonce_len,
                                   resumption_psk, hash_len);
}
