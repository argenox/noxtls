/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_tls13_psk.c
* Summary: TLS 1.3 PSK and ECDHE-PSK (binder, ticket store, resumption PSK)
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_tls13_psk.h"
#include "noxtls_tls_kdf.h"
#include "noxtls_tls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"

/* Hash a noxtls_message buffer (for binder transcript). Same semantics as tls13_hash_messages. */
static noxtls_return_t psk_hash_messages(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *messages, uint32_t messages_len,
                                         uint8_t *hash, uint32_t *hash_len)
{
    if(hash == NULL || hash_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha256_update(&sha_ctx, (uint8_t *)messages, messages_len);
        }
        *hash_len = 32;
        return noxtls_sha256_finish(&sha_ctx, hash);
    }
    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha512_update(&sha_ctx, (uint8_t *)messages, messages_len);
        }
        *hash_len = 48;
        return noxtls_sha512_finish(&sha_ctx, hash);
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/* RFC 8446: second ClientHello binder uses transcript = (prefix) || CH2_prefix; prefix is message_hash+HRR. */
static noxtls_return_t psk_hash_binder_input(noxtls_hash_algos_t hash_algo,
                                            const uint8_t *transcript_prefix,
                                            uint32_t transcript_prefix_len,
                                            const uint8_t *client_hello_prefix,
                                            uint32_t client_hello_prefix_len,
                                            uint8_t *hash,
                                            uint32_t *hash_len)
{
    if(transcript_prefix_len == 0U) {
        return psk_hash_messages(hash_algo, client_hello_prefix, client_hello_prefix_len, hash, hash_len);
    }
    if(client_hello_prefix_len > UINT32_MAX - transcript_prefix_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    {
        uint32_t combined_len = transcript_prefix_len + client_hello_prefix_len;
        uint8_t *combined = (uint8_t*)malloc(combined_len);
        noxtls_return_t rc;
        if(combined == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memcpy(combined, transcript_prefix, transcript_prefix_len);
        memcpy(combined + transcript_prefix_len, client_hello_prefix, client_hello_prefix_len);
        rc = psk_hash_messages(hash_algo, combined, combined_len, hash, hash_len);
        free(combined);
        return rc;
    }
}

static uint16_t psk_read_uint16(const uint8_t *buf)
{
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

/*
 * RFC 8446 §4.2.11.2: binder transcript covers partial ClientHello up to and
 * including PreSharedKeyExtension.identities (binders vector not included).
 * Returns the prefix length to hash.
 */
static noxtls_return_t psk_clienthello_binder_prefix_len(const uint8_t *client_hello,
                                                         uint32_t client_hello_len,
                                                         uint32_t *prefix_len)
{
    uint32_t offset;
    uint8_t session_id_len;
    uint16_t cipher_len;
    uint8_t comp_len;
    uint16_t extensions_len;

    if(client_hello == NULL || prefix_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(client_hello_len < 4 + 2 + 32 + 1 + 2 + 1 + 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    offset = 4 + 2 + 32;
    session_id_len = client_hello[offset++];
    if(offset + session_id_len + 2 + 1 + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    cipher_len = psk_read_uint16(client_hello + offset);
    offset += 2;
    if(offset + cipher_len + 1 + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_len;
    comp_len = client_hello[offset++];
    if(offset + comp_len + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += comp_len;
    extensions_len = psk_read_uint16(client_hello + offset);
    offset += 2;
    if(offset + extensions_len > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t ext_end = offset + extensions_len;
        while(offset + 4 <= ext_end) {
            uint16_t ext_type = psk_read_uint16(client_hello + offset);
            uint16_t ext_len = psk_read_uint16(client_hello + offset + 2);
            offset += 4;
            if(offset + ext_len > ext_end) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            if(ext_type == TLS_EXTENSION_PRE_SHARED_KEY) {
                uint32_t p = offset;
                uint16_t identities_len;
                if(ext_len < 2) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_len = psk_read_uint16(client_hello + p);
                p += 2;
                if((uint32_t)identities_len + 2 > ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(identities_len < 2 + 4) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                p += identities_len; /* now points to binders vector length */
                if(p > client_hello_len) {
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

/* Ticket store (server-side session cache for resumption) */
typedef struct
{
    uint8_t ticket_id[TLS13_PSK_TICKET_ID_LEN];
    uint8_t resumption_psk[64];
    uint8_t resumption_psk_len;
    uint8_t ticket_nonce[TLS13_PSK_TICKET_NONCE_MAX];
    uint8_t ticket_nonce_len;
    uint32_t ticket_age_add;
    uint16_t cipher_suite;
} psk_ticket_entry_t;

static struct
{
    psk_ticket_entry_t entries[TLS13_PSK_TICKET_STORE_MAX];
    uint32_t next_index;
} psk_ticket_store;

static void psk_ticket_store_init(void)
{
    memset(&psk_ticket_store, 0, sizeof(psk_ticket_store));
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
int noxtls_tls13_psk_mode_offered(const uint8_t *data, uint16_t len, uint8_t mode)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(data == NULL || len < 1) {
        return 0;
    }
    if((uint16_t)(data[0] + 1) > len) {
        return 0;
    }
    for(uint16_t i = 0; i < data[0]; i++) {
        if(data[1 + i] == mode) {
            return 1;
        }
    }
    return 0;
}

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
    uint32_t offset;
    uint8_t session_id_len;
    uint16_t cipher_len;
    uint8_t comp_len;
    uint16_t extensions_len;

    if(client_hello == NULL || binder_offset == NULL || binder_len == NULL || selected_identity == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(client_hello_len < 4 + 2 + 32 + 1 + 2 + 1 + 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    offset = 4 + 2 + 32;
    session_id_len = client_hello[offset++];
    if(offset + session_id_len + 2 + 1 + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    cipher_len = psk_read_uint16(client_hello + offset);
    offset += 2;
    if(offset + cipher_len + 1 + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_len;
    comp_len = client_hello[offset++];
    if(offset + comp_len + 2 > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += comp_len;
    extensions_len = psk_read_uint16(client_hello + offset);
    offset += 2;
    if(offset + extensions_len > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t ext_end = offset + extensions_len;
        while(offset + 4 <= ext_end) {
            uint16_t ext_type = psk_read_uint16(client_hello + offset);
            uint16_t ext_len = psk_read_uint16(client_hello + offset + 2);
            offset += 4;
            if(offset + ext_len > ext_end) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            if(ext_type == TLS_EXTENSION_PRE_SHARED_KEY) {
                uint32_t p = offset;
                uint16_t identities_len;
                uint16_t binders_len;
                uint32_t identities_end;
                uint16_t idx = 0;

                if(ext_len < 2) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_len = psk_read_uint16(client_hello + p);
                p += 2;
                if((uint32_t)identities_len + 2 > ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(identities_len < 2 + 4) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                identities_end = p + identities_len;
                while(p < identities_end && idx <= identity_index) {
                    uint16_t id_len;
                    if(p + 2 > identities_end) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    id_len = psk_read_uint16(client_hello + p);
                    p += 2;
                    if((uint32_t)id_len + 4u > (uint32_t)(identities_end - p)) {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    if(idx == identity_index) {
                        if(identity_out != NULL && identity_out_len != NULL && *identity_out_len >= id_len) {
                            memcpy(identity_out, client_hello + p, id_len);
                            *identity_out_len = id_len;
                        } else if(identity_out_len != NULL) {
                            *identity_out_len = id_len;
                        }
                    }
                    p += id_len + 4;
                    idx++;
                }
                if(identity_index >= idx) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(p + 2 > offset + ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                binders_len = psk_read_uint16(client_hello + p);
                p += 2;
                if(p + binders_len != offset + ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                for(idx = 0; idx < identity_index && p + 1 <= offset + ext_len; idx++) {
                    uint16_t bl = client_hello[p];
                    p += 1 + bl;
                }
                if(binders_len < 1 || p + 1 > offset + ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                *binder_len = client_hello[p];
                p += 1;
                if(p + *binder_len > offset + ext_len) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
                *binder_offset = p;
                *selected_identity = identity_index;
                return NOXTLS_RETURN_SUCCESS;
            }
            offset += ext_len;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

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
    uint32_t transcript_len = sizeof(transcript_hash);
    uint32_t binder_prefix_len = 0;
    uint8_t early_secret[64];
    uint8_t binder_key[64];
    uint8_t finished_key[64];
    uint8_t computed_binder[64];
    uint32_t hash_len = 0;
    uint32_t verify_len = sizeof(computed_binder);
    uint32_t prk_len = 0;
    noxtls_return_t rc;
    const uint8_t *label = (const uint8_t *)"res binder";
    const uint32_t label_len = 10;

    if(resumption_psk == NULL || ticket_nonce == NULL || client_hello == NULL || out_binder == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(binder_len == 0 || binder_offset > client_hello_len || (uint32_t)binder_len > (client_hello_len - binder_offset)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        hash_len = 32;
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        hash_len = 48;
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(binder_len != hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = psk_clienthello_binder_prefix_len(client_hello, client_hello_len, &binder_prefix_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(binder_offset < binder_prefix_len || binder_offset + binder_len > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = psk_hash_binder_input(hash_algo, transcript_prefix, transcript_prefix_len,
                               client_hello, binder_prefix_len, transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, NULL, 0, resumption_psk, psk_len, early_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_derive_secret(hash_algo, early_secret, hash_len, label, label_len,
                            NULL, 0, binder_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, binder_key, hash_len, (const uint8_t *)"finished", 8,
                                 NULL, 0, finished_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                     computed_binder, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS || verify_len != hash_len) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(out_binder, computed_binder, hash_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls13_psk_compute_external_binder(noxtls_hash_algos_t hash_algo,
                                                  const uint8_t *psk,
                                                  uint16_t psk_len,
                                                  const uint8_t *client_hello,
                                                  uint32_t client_hello_len,
                                                  uint32_t binder_offset,
                                                  uint16_t binder_len,
                                                  uint8_t *out_binder,
                                                  const uint8_t *transcript_prefix,
                                                  uint32_t transcript_prefix_len)
{
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint32_t binder_prefix_len = 0;
    uint8_t early_secret[64];
    uint8_t binder_key[64];
    uint8_t finished_key[64];
    uint8_t computed_binder[64];
    uint32_t hash_len = 0;
    uint32_t verify_len = sizeof(computed_binder);
    uint32_t prk_len = 0;
    uint32_t label_len = 10;
    noxtls_return_t rc;
    const uint8_t *label = (const uint8_t *)"ext binder";

    if(psk == NULL || psk_len == 0 || client_hello == NULL || out_binder == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(binder_len == 0 || binder_offset > client_hello_len || (uint32_t)binder_len > (client_hello_len - binder_offset)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        hash_len = 32;
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        hash_len = 48;
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(binder_len != hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = psk_clienthello_binder_prefix_len(client_hello, client_hello_len, &binder_prefix_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(binder_offset < binder_prefix_len || binder_offset + binder_len > client_hello_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = psk_hash_binder_input(hash_algo, transcript_prefix, transcript_prefix_len,
                               client_hello, binder_prefix_len, transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, NULL, 0, psk, psk_len, early_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_derive_secret(hash_algo, early_secret, hash_len, label, label_len, NULL, 0, binder_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, binder_key, hash_len, (const uint8_t *)"finished", 8,
                                 NULL, 0, finished_key, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                     computed_binder, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS || verify_len != hash_len) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(out_binder, computed_binder, hash_len);
    return NOXTLS_RETURN_SUCCESS;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t tls13_psk_ticket_store_add(const uint8_t *ticket_id,
                                           uint8_t id_len,
                                           const uint8_t *resumption_psk,
                                           uint8_t psk_len,
                                           const uint8_t *ticket_nonce,
                                           uint8_t nonce_len,
                                           uint32_t ticket_age_add,
                                           uint16_t cipher_suite)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    psk_ticket_entry_t *e;
    if(ticket_id == NULL || id_len > TLS13_PSK_TICKET_ID_LEN || resumption_psk == NULL || psk_len > 64 ||
        ticket_nonce == NULL || nonce_len > TLS13_PSK_TICKET_NONCE_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(psk_ticket_store.next_index == 0) {
        psk_ticket_store_init();
    }
    e = &psk_ticket_store.entries[psk_ticket_store.next_index % TLS13_PSK_TICKET_STORE_MAX];
    psk_ticket_store.next_index++;
    memset(e, 0, sizeof(*e));
    memcpy(e->ticket_id, ticket_id, id_len);
    e->resumption_psk_len = psk_len;
    memcpy(e->resumption_psk, resumption_psk, psk_len);
    e->ticket_nonce_len = nonce_len;
    memcpy(e->ticket_nonce, ticket_nonce, nonce_len);
    e->ticket_age_add = ticket_age_add;
    e->cipher_suite = cipher_suite;
    return NOXTLS_RETURN_SUCCESS;
}

const void *tls13_psk_ticket_store_lookup(const uint8_t *ticket_id, uint32_t id_len)
{
    uint32_t i;
    if(ticket_id == NULL || id_len != TLS13_PSK_TICKET_ID_LEN) {
        return NULL;
    }
    for(i = 0; i < TLS13_PSK_TICKET_STORE_MAX; i++) {
        psk_ticket_entry_t *e = &psk_ticket_store.entries[i];
        if(e->resumption_psk_len != 0 && memcmp(e->ticket_id, ticket_id, TLS13_PSK_TICKET_ID_LEN) == 0) {
            return e;
        }
    }
    return NULL;
}

noxtls_return_t tls13_psk_ticket_store_entry_psk(const void *entry,
                                                  uint8_t *psk_out,
                                                  uint8_t psk_out_size,
                                                  uint8_t *psk_len,
                                                  uint8_t *nonce_out,
                                                  uint8_t nonce_out_size,
                                                  uint8_t *nonce_len)
{
    const psk_ticket_entry_t *e = (const psk_ticket_entry_t *)entry;
    if(e == NULL || psk_out == NULL || psk_len == NULL || nonce_out == NULL || nonce_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(psk_out_size < e->resumption_psk_len || nonce_out_size < e->ticket_nonce_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    *psk_len = e->resumption_psk_len;
    memcpy(psk_out, e->resumption_psk, e->resumption_psk_len);
    *nonce_len = e->ticket_nonce_len;
    memcpy(nonce_out, e->ticket_nonce, e->ticket_nonce_len);
    return NOXTLS_RETURN_SUCCESS;
}

uint16_t noxtls_tls13_psk_ticket_store_entry_cipher_suite(const void *entry)
{
    const psk_ticket_entry_t *e = (const psk_ticket_entry_t *)entry;
    return e != NULL ? e->cipher_suite : 0;
}

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
    noxtls_return_t rc;
    const uint8_t *rms_label = (const uint8_t *)"res master";
    const uint32_t rms_label_len = 10;
    const uint8_t *psk_label = (const uint8_t *)"resumption";
    const uint32_t psk_label_len = 10;

    if(master_secret == NULL || ticket_nonce == NULL || resumption_psk == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_len > 64 || ticket_nonce_len > 255) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = tls13_derive_secret(hash_algo, master_secret, hash_len, rms_label, rms_label_len,
                             handshake_transcript, handshake_transcript_len,
                             resumption_master_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, resumption_master_secret, hash_len,
                                 psk_label, psk_label_len, ticket_nonce, ticket_nonce_len,
                                 resumption_psk, hash_len);
    memset(resumption_master_secret, 0, sizeof(resumption_master_secret));
    return rc;
}
