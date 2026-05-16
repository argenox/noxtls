/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls12.c
* Summary: TLS 1.2 Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "common/noxtls_ct.h"
#include "noxtls_tls12.h"
#include "noxtls_tls_kdf.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_key_exchange.h"
#include "drbg/noxtls_drbg.h"
#include "certs/noxtls_x509.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/md5/noxtls_md5.h"
#include "noxtls_tls_noxsight.h"

#ifndef NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
#define NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES 0
#endif

static int tls12_suite_supports_encrypt_then_mac(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            return 1;
        default:
            return 0;
    }
}

static void tls12_dtls_on_send_ccs(tls12_context_t *ctx);
static noxtls_return_t tls12_send_protected_alert(tls12_context_t *ctx, uint8_t level, uint8_t desc);
static int tls12_cipher_suite_is_ecdhe_ecdsa(uint16_t cs);
static noxtls_return_t tls12_handle_heartbeat_record(tls12_context_t *ctx, const uint8_t *record_data, uint32_t record_len);
static noxtls_return_t tls12_send_certificate_status(tls12_context_t *ctx);
static noxtls_return_t tls12_recv_certificate_status(tls12_context_t *ctx);

/**
 * @brief Initialize TLS 1.2 context
 */
noxtls_return_t noxtls_tls12_context_init_with_version(tls12_context_t *ctx, tls_role_t role, uint16_t version)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* For TLS 1.0/1.1 use plain TLS context init; for TLS/DTLS 1.2 use noxtls_dtls_context_init */
    if(version == TLS_VERSION_1_0 || version == TLS_VERSION_1_1) {
        memset(&ctx->base, 0, sizeof(dtls_context_t));
        if(noxtls_tls_context_init(&ctx->base.base, role, version) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(noxtls_dtls_context_init(&ctx->base, role, version) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    ctx->record_workspace = NULL;
    ctx->record_workspace_owned = 0;
    ctx->handshake_workspace = NULL;
    ctx->handshake_workspace_owned = 0;
    if(version == TLS_VERSION_1_2) {
        ctx->record_workspace = (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD);
        if(ctx->record_workspace == NULL) {
            noxtls_dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->record_workspace_owned = 1;
        ctx->handshake_workspace = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(ctx->handshake_workspace == NULL) {
            if(ctx->record_workspace_owned) {
                noxtls_free(ctx->record_workspace);
            }
            ctx->record_workspace = NULL;
            ctx->record_workspace_owned = 0;
            noxtls_dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->handshake_workspace_owned = 1;
    }
    
    memset(ctx->client_random, 0, sizeof(ctx->client_random));
    memset(ctx->server_random, 0, sizeof(ctx->server_random));
    ctx->cipher_suite = 0;
    memset(ctx->premaster_secret, 0, sizeof(ctx->premaster_secret));
    ctx->premaster_secret_len = 0;
    memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;
    ctx->server_cert = NULL;
    ctx->server_cert_len = 0;
    ctx->client_cert = NULL;
    ctx->client_cert_len = 0;
    ctx->server_cert_chain = NULL;
    ctx->server_cert_chain_len = NULL;
    ctx->server_cert_chain_count = 0;
    ctx->server_cert_parsed = NULL;  /* Initialize to NULL */
    ctx->client_cert_parsed = NULL;
    ctx->server_private_rsa = NULL;
    ctx->server_private_ecdsa = NULL;
    ctx->server_ecdsa_leaf_cert = NULL;
    ctx->server_ecdsa_leaf_cert_len = 0;
    ctx->server_rsa_pss_leaf_cert = NULL;
    ctx->server_rsa_pss_leaf_cert_len = 0;
    ctx->server_private_rsa_pss_leaf = NULL;
    ctx->server_rsa_pss_leaf_cert_parsed = NULL;
    ctx->tls12_rsa_skx_scheme_prepared = 0;
    ctx->tls12_rsa_skx_wire_scheme = 0;
    ctx->tls12_rsa_skx_sign_hash = NOXTLS_HASH_SHA_256;
    ctx->tls12_rsa_skx_sign_use_pss = 0;
    ctx->tls12_rsa_skx_use_pss_leaf_identity = 0;
    ctx->server_cipher_suites = NULL;
    ctx->server_cipher_suites_count = 0;
    ctx->server_alpn_protocols = NULL;
    ctx->server_alpn_count = 0;
    ctx->negotiated_alpn_len = 0;
    memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));
    ctx->server_session_id_len = 0;
    memset(ctx->server_session_id, 0, sizeof(ctx->server_session_id));
    ctx->session_resume = 0;
    ctx->crypto_provider = NULL;
    ctx->server_private_key_handle = NULL;
    ctx->ecdhe_ctx = NULL;
    ctx->dhe_ctx = NULL;
    ctx->handshake_messages = NULL;
    ctx->handshake_messages_len = 0;
    ctx->server_name = NULL;
    ctx->server_name_len = 0;
    ctx->server_expect_client_sni = NULL;
    ctx->server_expect_sni_fatal = 0;
    ctx->previous_verify_data_len = 0;
    ctx->renegotiation_in_progress = 0;
    ctx->server_renegotiation_requested = 0;
    ctx->client_secure_renegotiation_offered = 0;
    ctx->client_encrypt_then_mac_offered = 0;
    ctx->use_encrypt_then_mac = 0;
    ctx->extended_master_secret_offered = 0;
    ctx->extended_master_secret_negotiated = 0;
    ctx->ems_session_transcript_len = 0;
    ctx->session_resume_ems = 0;
    ctx->server_use_rpk = 0;
    ctx->server_certificate_type = TLS_CERT_TYPE_X509;
    ctx->client_certificate_type = TLS_CERT_TYPE_X509;
    ctx->server_cert_is_rpk = 0;
    ctx->client_accept_server_rpk = 0;
    ctx->client_offer_client_rpk = 0;
    ctx->request_client_auth = 0;
    ctx->client_hello_version = 0;
    ctx->tls12_beast_split_first_appdata = 0;
    ctx->rfc8446_tls13_downgrade_sh_random = 0;
    ctx->pending_app_data_len = 0;
    ctx->max_fragment_length_code = 0;
    ctx->max_record_payload = 0;
    ctx->heartbeat_enabled = 0;
    ctx->heartbeat_negotiated = 0;
    ctx->heartbeat_peer_mode = 0;
    ctx->client_heartbeat_mode = 0;
    ctx->client_request_ocsp_status = 0;
    ctx->client_offered_ocsp_status = 0;
    ctx->status_request_negotiated = 0;
    ctx->server_ocsp_response = NULL;
    ctx->server_ocsp_response_len = 0;
    ctx->peer_ocsp_response = NULL;
    ctx->peer_ocsp_response_len = 0;

    /* Zero extensions so noxtls_tls12_context_free can safely call noxtls_tls_extensions_free */
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));
    
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls12_context_init(tls12_context_t *ctx, tls_role_t role)
{
    return noxtls_tls12_context_init_with_version(ctx, role, TLS_VERSION_1_2);
}

noxtls_return_t noxtls_dtls12_context_init(tls12_context_t *ctx, tls_role_t role)
{
    noxtls_return_t rc = noxtls_tls12_context_init_with_version(ctx, role, TLS_VERSION_1_2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->base.base.version = DTLS_VERSION_1_2;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Replace TLS 1.2 internal workspaces with caller-provided buffers.
 * @param ctx TLS 1.2 context.
 * @param record_workspace Caller-managed record workspace.
 * @param record_workspace_len Record workspace length in bytes.
 * @param handshake_workspace Caller-managed handshake workspace.
 * @param handshake_workspace_len Handshake workspace length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise.
 */
noxtls_return_t tls12_set_workspaces(tls12_context_t *ctx,
                                     uint8_t *record_workspace,
                                     uint32_t record_workspace_len,
                                     uint8_t *handshake_workspace,
                                     uint32_t handshake_workspace_len)
{
    if(ctx == NULL || record_workspace == NULL || handshake_workspace == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(record_workspace_len < (uint32_t)(TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD) ||
       handshake_workspace_len < TLS_HANDSHAKE_WORKSPACE_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->record_workspace != NULL && ctx->record_workspace_owned) {
        noxtls_free(ctx->record_workspace);
    }
    if(ctx->handshake_workspace != NULL && ctx->handshake_workspace_owned) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        noxtls_free(ctx->handshake_workspace);
    }

    ctx->record_workspace = record_workspace;
    ctx->record_workspace_owned = 0;
    ctx->handshake_workspace = handshake_workspace;
    ctx->handshake_workspace_owned = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Determine named curve from cipher suite
 * 
 * For ECDHE cipher suites:
 * - AES-128 cipher suites typically use secp256r1 (P-256)
 * - AES-256 cipher suites typically use secp384r1 (P-384)
 */
static noxtls_return_t tls12_cipher_suite_to_named_curve(uint16_t cipher_suite, uint16_t *named_group)
{
    if(named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
            /* AES-128 cipher suites use secp256r1 */
            *named_group = TLS_NAMED_GROUP_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
            
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
            /* AES-256 cipher suites use secp384r1 */
            *named_group = TLS_NAMED_GROUP_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
            
        default:
            /* Debug: print the cipher suite value to help identify missing ones */
            noxtls_debug_printf("WARNING: Unknown ECDHE cipher suite: 0x%04X\n", cipher_suite);
            fflush(stdout);
            return NOXTLS_RETURN_FAILED;
    }
}

static void tls12_fill_premaster_from_shared(uint8_t *premaster, uint32_t premaster_len,
                                             const uint8_t *shared, uint32_t shared_len)
{
    if(premaster == NULL || shared == NULL || premaster_len == 0) {
        return;
    }
    memset(premaster, 0, premaster_len);
    if(shared_len > 0) {
        uint32_t copy_len = (shared_len > premaster_len) ? premaster_len : shared_len;
        /*
         * TLS ECDH premaster secret is the x-coordinate encoded as a fixed-size
         * big-endian integer (left-zero-padded). Right-align source bytes.
         */
        memcpy(premaster + (premaster_len - copy_len),
               shared + (shared_len - copy_len),
               copy_len);
    }
}

static void tls12_inc_send_seq(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        ctx->client_seq_num++;
    } else {
        ctx->server_seq_num++;
    }
}

static void tls12_inc_recv_seq(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        ctx->server_seq_num++;
    } else {
        ctx->client_seq_num++;
    }
}

#define TLS12_SESSION_CACHE_SIZE 16u
#define TLS12_SESSION_SNI_MAX 255u

typedef struct {
    uint8_t id[TLS_SESSION_ID_MAX_LEN];
    uint8_t id_len;
    uint8_t master_secret[48];
    uint16_t cipher_suite;
    uint8_t alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1u];
    uint16_t alpn_len;
    uint16_t sni_len;
    uint8_t sni[255];
    uint8_t extended_master_secret; /* RFC 7627: session established with EMS */
    uint8_t in_use;
} tls12_session_cache_entry_t;

static tls12_session_cache_entry_t g_tls12_session_cache[TLS12_SESSION_CACHE_SIZE];

#define TLS12_TICKET_CACHE_SIZE 32u
#define TLS12_TICKET_MAX_LEN 256u
#define TLS12_TICKET_LIFETIME_HINT 86400u

typedef struct {
    uint8_t ticket[TLS12_TICKET_MAX_LEN];
    uint16_t ticket_len;
    uint8_t master_secret[48];
    uint16_t cipher_suite;
    uint8_t alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1u];
    uint16_t alpn_len;
    uint16_t sni_len;
    uint8_t sni[255];
    uint8_t extended_master_secret;
    uint32_t issued_at;
    uint32_t lifetime_hint;
    uint8_t in_use;
} tls12_ticket_cache_entry_t;

static tls12_ticket_cache_entry_t g_tls12_ticket_cache[TLS12_TICKET_CACHE_SIZE];

static tls12_session_cache_entry_t *tls12_session_cache_find(const uint8_t *id, uint8_t id_len)
{
    uint32_t i;
    if(id == NULL || id_len == 0) {
        return NULL;
    }
    for(i = 0; i < TLS12_SESSION_CACHE_SIZE; i++) {
        if(g_tls12_session_cache[i].in_use &&
           g_tls12_session_cache[i].id_len == id_len &&
           memcmp(g_tls12_session_cache[i].id, id, id_len) == 0) {
            return &g_tls12_session_cache[i];
        }
    }
    return NULL;
}

static void tls12_session_cache_store(const uint8_t *id,
                                      uint8_t id_len,
                                      const uint8_t *master_secret,
                                      uint16_t cipher_suite,
                                      const uint8_t *alpn,
                                      uint16_t alpn_len,
                                      uint8_t extended_master_secret,
                                      const uint8_t *sni_host,
                                      uint16_t sni_len)
{
    tls12_session_cache_entry_t *slot = NULL;
    uint32_t i;
    if(id == NULL || id_len == 0 || master_secret == NULL) {
        return;
    }
    slot = tls12_session_cache_find(id, id_len);
    if(slot == NULL) {
        for(i = 0; i < TLS12_SESSION_CACHE_SIZE; i++) {
            if(!g_tls12_session_cache[i].in_use) {
                slot = &g_tls12_session_cache[i];
                break;
            }
        }
        if(slot == NULL) {
            slot = &g_tls12_session_cache[0];
        }
    }
    memset(slot, 0, sizeof(*slot));
    slot->in_use = 1;
    slot->id_len = id_len;
    memcpy(slot->id, id, id_len);
    memcpy(slot->master_secret, master_secret, sizeof(slot->master_secret));
    slot->cipher_suite = cipher_suite;
    if(alpn != NULL && alpn_len > 0 && alpn_len <= NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN) {
        slot->alpn_len = alpn_len;
        memcpy(slot->alpn, alpn, alpn_len);
    }
    slot->extended_master_secret = extended_master_secret ? 1u : 0u;
    if(sni_host != NULL && sni_len > 0u) {
        uint16_t copy_len = sni_len;
        if(copy_len > TLS12_SESSION_SNI_MAX) {
            copy_len = TLS12_SESSION_SNI_MAX;
        }
        slot->sni_len = copy_len;
        memcpy(slot->sni, sni_host, copy_len);
    } else {
        slot->sni_len = 0;
    }
}

static noxtls_return_t tls12_session_cache_generate_id(uint8_t *id, uint8_t *id_len)
{
    drbg_state_t drbg_state;
    if(id == NULL || id_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, id, TLS_SESSION_ID_MAX_LEN * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    *id_len = TLS_SESSION_ID_MAX_LEN;
    return NOXTLS_RETURN_SUCCESS;
}

static tls12_ticket_cache_entry_t *tls12_ticket_cache_find(const uint8_t *ticket, uint16_t ticket_len)
{
    uint32_t i;
    uint32_t now = (uint32_t)time(NULL);
    if(ticket == NULL || ticket_len == 0 || ticket_len > TLS12_TICKET_MAX_LEN) {
        return NULL;
    }
    for(i = 0; i < TLS12_TICKET_CACHE_SIZE; i++) {
        tls12_ticket_cache_entry_t *e = &g_tls12_ticket_cache[i];
        if(!e->in_use || e->ticket_len != ticket_len) {
            continue;
        }
        if(e->lifetime_hint > 0 && now > e->issued_at && (now - e->issued_at) > e->lifetime_hint) {
            memset(e, 0, sizeof(*e));
            continue;
        }
        if(memcmp(e->ticket, ticket, ticket_len) == 0) {
            return e;
        }
    }
    return NULL;
}

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): TLS ticket fields follow wire/order semantics. */
static void tls12_ticket_cache_store(const uint8_t *ticket,
                                     uint16_t ticket_len,
                                     const uint8_t *master_secret,
                                     uint16_t cipher_suite,
                                     const uint8_t *alpn,
                                     uint16_t alpn_len, /* NOLINT(bugprone-easily-swappable-parameters): grouped ticket metadata lengths */
                                     uint32_t lifetime_hint,
                                     uint8_t extended_master_secret,
                                     const uint8_t *sni_host,
                                     uint16_t sni_len)
{
    uint32_t i;
    tls12_ticket_cache_entry_t *slot = NULL;
    if(ticket == NULL || ticket_len == 0 || ticket_len > TLS12_TICKET_MAX_LEN || master_secret == NULL) {
        return;
    }
    slot = tls12_ticket_cache_find(ticket, ticket_len);
    if(slot == NULL) {
        for(i = 0; i < TLS12_TICKET_CACHE_SIZE; i++) {
            if(!g_tls12_ticket_cache[i].in_use) {
                slot = &g_tls12_ticket_cache[i];
                break;
            }
        }
        if(slot == NULL) {
            slot = &g_tls12_ticket_cache[0];
        }
    }
    memset(slot, 0, sizeof(*slot));
    slot->in_use = 1;
    slot->ticket_len = ticket_len;
    memcpy(slot->ticket, ticket, ticket_len);
    memcpy(slot->master_secret, master_secret, sizeof(slot->master_secret));
    slot->cipher_suite = cipher_suite;
    slot->issued_at = (uint32_t)time(NULL);
    slot->lifetime_hint = lifetime_hint;
    if(alpn != NULL && alpn_len > 0 && alpn_len <= NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN) {
        slot->alpn_len = alpn_len;
        memcpy(slot->alpn, alpn, alpn_len);
    }
    slot->extended_master_secret = extended_master_secret ? 1u : 0u;
    if(sni_host != NULL && sni_len > 0u) {
        uint16_t copy_len = sni_len;
        if(copy_len > TLS12_SESSION_SNI_MAX) {
            copy_len = TLS12_SESSION_SNI_MAX;
        }
        slot->sni_len = copy_len;
        memcpy(slot->sni, sni_host, copy_len);
    } else {
        slot->sni_len = 0;
    }
}

/* RFC 6066 §3: MUST NOT resume if ClientHello server_name does not match the cached session. */
static void tls12_invalidate_resume_if_sni_mismatch(tls12_context_t *ctx,
                                                    const uint8_t *client_session_id,
                                                    uint8_t session_id_len)
{
    tls12_session_cache_entry_t *sess_e;
    tls12_ticket_cache_entry_t *tick_e;
    uint16_t cached_len = 0;
    const uint8_t *cached_ptr = NULL;

    if(!ctx->session_resume) {
        return;
    }

    sess_e = NULL;
    tick_e = NULL;
    if(session_id_len > 0) {
        sess_e = tls12_session_cache_find(client_session_id, session_id_len);
    }
    if(sess_e == NULL) {
        tls_extension_t *tst = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SESSION_TICKET, &tst) == NOXTLS_RETURN_SUCCESS &&
           tst != NULL && tst->data != NULL && tst->length > 0) {
            tick_e = tls12_ticket_cache_find(tst->data, (uint16_t)tst->length);
        }
    }

    if(sess_e != NULL) {
        cached_len = sess_e->sni_len;
        if(cached_len > TLS12_SESSION_SNI_MAX) {
            cached_len = 0;
        }
        cached_ptr = (cached_len > 0u) ? sess_e->sni : NULL;
    } else if(tick_e != NULL) {
        cached_len = tick_e->sni_len;
        if(cached_len > TLS12_SESSION_SNI_MAX) {
            cached_len = 0;
        }
        cached_ptr = (cached_len > 0u) ? tick_e->sni : NULL;
    } else {
        ctx->session_resume = 0;
        ctx->session_resume_ems = 0;
        ctx->server_session_id_len = 0;
        memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
        ctx->negotiated_alpn_len = 0;
        memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));
        return;
    }

    {
        uint16_t cur_len = 0;
        const uint8_t *cur_ptr = NULL;
        const tls_sni_extension_t *cli = ctx->client_extensions.sni;

        if(cli != NULL && cli->hostname != NULL && cli->name_len > 0u) {
            cur_len = cli->name_len;
            cur_ptr = (const uint8_t *)cli->hostname;
        }

        if(cached_len != cur_len ||
           (cached_len > 0u && memcmp(cached_ptr, cur_ptr, (size_t)cached_len) != 0)) {
            ctx->session_resume = 0;
            ctx->session_resume_ems = 0;
            ctx->server_session_id_len = 0;
            memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
            ctx->negotiated_alpn_len = 0;
            memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));
        }
    }
}

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): offset/count pairing mirrors parsed ClientHello fields. */
static int tls12_client_offered_cipher(const uint8_t *record_data,
                                       uint32_t record_len,
                                       uint32_t cipher_suites_offset, /* NOLINT(bugprone-easily-swappable-parameters): parsed vector offset/count/suite tuple */
                                       uint32_t cipher_suites_count,
                                       uint16_t cipher_suite)
{
    uint32_t i;
    if(record_data == NULL || cipher_suites_offset >= record_len) {
        return 0;
    }
    for(i = 0; i < cipher_suites_count; i++) {
        uint32_t pos = cipher_suites_offset + (2u * i);
        if(pos + 1u >= record_len) {
            return 0;
        }
        if((((uint16_t)record_data[pos]) << 8 | record_data[pos + 1u]) == cipher_suite) {
            return 1;
        }
    }
    return 0;
}

static noxtls_return_t tls12_send_handshake_record(tls12_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    noxtls_return_t rc;
    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->renegotiation_in_progress) {
        uint8_t enc[TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD];
        uint32_t enc_len = (uint32_t)sizeof(enc);
        rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HANDSHAKE, msg, msg_len, enc, &enc_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, enc, enc_len);
        /* Encrypt path already advances write sequence internally. */
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, msg, msg_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
    }
    return rc;
}

static noxtls_return_t tls12_send_ccs_record(tls12_context_t *ctx)
{
    uint8_t change_cipher_spec = 0x01;
    noxtls_return_t rc;
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->renegotiation_in_progress) {
        uint8_t enc[64];
        uint32_t enc_len = (uint32_t)sizeof(enc);
        rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_CHANGE_CIPHER_SPEC, &change_cipher_spec, 1u, enc, &enc_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_CHANGE_CIPHER_SPEC, enc, enc_len);
    } else {
        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_CHANGE_CIPHER_SPEC, &change_cipher_spec, 1u);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
        ctx->server_seq_num = 0;
        tls12_dtls_on_send_ccs(ctx);
    }
    return rc;
}

static int tls12_is_dtls(const tls12_context_t *ctx)
{
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_2);
}

static void tls12_dtls_on_send_ccs(tls12_context_t *ctx)
{
    if(!tls12_is_dtls(ctx)) {
        return;
    }
    ctx->base.epoch = DTLS_EPOCH_ENCRYPTED;
    ctx->base.write_seq_num = 0;
}

static void tls12_dtls_on_recv_ccs(tls12_context_t *ctx)
{
    if(!tls12_is_dtls(ctx)) {
        return;
    }
    ctx->base.epoch = DTLS_EPOCH_ENCRYPTED;
    ctx->base.read_seq_num = 0;
    ctx->base.replay_window.window_bitmap = 0;
    ctx->base.replay_window.last_seq = 0;
}

static noxtls_return_t tls12_send_hello_verify_request(tls12_context_t *ctx,
                                                       const uint8_t *client_hello,
                                                       uint32_t client_hello_len)
{
    uint8_t hvr[TLS_MAX_SECRET_LEN];
    uint32_t offset = 0;
    uint8_t cookie[TLS_COOKIE_MAX_LEN];
    uint32_t cookie_len = sizeof(cookie);
    noxtls_return_t rc;

    if(ctx == NULL || client_hello == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_dtls_generate_cookie(&ctx->base, client_hello, client_hello_len, cookie, &cookie_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    hvr[offset++] = DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST;
    hvr[offset++] = 0x00;
    hvr[offset++] = 0x00;
    hvr[offset++] = (uint8_t)(2 + 1 + cookie_len);
    hvr[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
    hvr[offset++] = DTLS_VERSION_1_2 & 0xFF;
    hvr[offset++] = (uint8_t)cookie_len;
    memcpy(hvr + offset, cookie, cookie_len);
    offset += cookie_len;

    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, hvr, offset);
}
static noxtls_hash_algos_t tls12_get_prf_hash(uint16_t cipher_suite)
{
    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            return NOXTLS_HASH_SHA_384;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
            return NOXTLS_HASH_SHA_256;
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            /* Record MAC is SHA-1; TLS 1.2 PRF (master secret, Finished, key block) is SHA-256 (RFC 5246). */
            return NOXTLS_HASH_SHA_256;
        default:
            return NOXTLS_HASH_SHA_256;
    }
}

static uint32_t tls12_get_ecdh_premaster_len(uint16_t named_group)
{
    switch(named_group) {
        case TLS_NAMED_GROUP_SECP256R1:
            return 32;
        case TLS_NAMED_GROUP_SECP384R1:
            return 48;
        case TLS_NAMED_GROUP_SECP521R1:
            return 66;
        case TLS_NAMED_GROUP_X25519:
            return 32;
        case TLS_NAMED_GROUP_X448:
            return 56;
        default:
            return 0;
    }
}

/** Map DHE-RSA cipher suite to FFDHE named group (RFC 7919). */
static noxtls_return_t tls12_cipher_suite_to_ffdhe_group(uint16_t cipher_suite, uint16_t *named_group)
{
    if(named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
            *named_group = TLS_NAMED_GROUP_FFDHE2048;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
            *named_group = TLS_NAMED_GROUP_FFDHE3072;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

static int tls12_client_supports_group(const tls12_context_t *ctx, uint16_t group)
{
    uint32_t i;

    if(ctx == NULL || ctx->client_extensions.supported_groups == NULL) {
        return 0;
    }
    for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
        if(ctx->client_extensions.supported_groups->groups[i] == group) {
            return 1;
        }
    }
    return 0;
}

static int tls12_is_supported_ec_curve(uint16_t group)
{
    return group == TLS_NAMED_GROUP_SECP256R1 ||
           group == TLS_NAMED_GROUP_SECP384R1 ||
           group == TLS_NAMED_GROUP_SECP521R1 ||
           group == TLS_NAMED_GROUP_X25519 ||
           group == TLS_NAMED_GROUP_X448;
}

static int tls12_is_supported_ffdhe_group(uint16_t group)
{
    return group == TLS_NAMED_GROUP_FFDHE2048 ||
           group == TLS_NAMED_GROUP_FFDHE3072 ||
           group == TLS_NAMED_GROUP_FFDHE4096 ||
           group == TLS_NAMED_GROUP_FFDHE6144 ||
           group == TLS_NAMED_GROUP_FFDHE8192;
}

static noxtls_return_t tls12_select_ecdhe_named_group(const tls12_context_t *ctx,
                                                      uint16_t cipher_suite,
                                                      uint16_t *named_group)
{
    static const uint16_t preferred_curves[] = {
        TLS_NAMED_GROUP_SECP256R1,
        TLS_NAMED_GROUP_SECP384R1,
        TLS_NAMED_GROUP_SECP521R1
    };
    uint16_t preferred;
    uint32_t i;

    if(named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(tls12_cipher_suite_to_named_curve(cipher_suite, &preferred) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->client_extensions.supported_groups == NULL) {
        *named_group = preferred;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls12_client_supports_group(ctx, preferred)) {
        *named_group = preferred;
        return NOXTLS_RETURN_SUCCESS;
    }
    for(i = 0; i < (sizeof(preferred_curves) / sizeof(preferred_curves[0])); i++) {
        if(tls12_client_supports_group(ctx, preferred_curves[i])) {
            *named_group = preferred_curves[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
        uint16_t group = ctx->client_extensions.supported_groups->groups[i];
        if(tls12_is_supported_ec_curve(group)) {
            *named_group = group;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

static noxtls_return_t tls12_select_ffdhe_named_group(const tls12_context_t *ctx,
                                                      uint16_t cipher_suite,
                                                      uint16_t *named_group)
{
    static const uint16_t preferred_groups[] = {
        TLS_NAMED_GROUP_FFDHE2048,
        TLS_NAMED_GROUP_FFDHE3072,
        TLS_NAMED_GROUP_FFDHE4096,
        TLS_NAMED_GROUP_FFDHE6144,
        TLS_NAMED_GROUP_FFDHE8192
    };
    uint16_t preferred;
    uint32_t i;

    if(named_group == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(tls12_cipher_suite_to_ffdhe_group(cipher_suite, &preferred) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->client_extensions.supported_groups == NULL) {
        *named_group = preferred;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls12_client_supports_group(ctx, preferred)) {
        *named_group = preferred;
        return NOXTLS_RETURN_SUCCESS;
    }
    for(i = 0; i < (sizeof(preferred_groups) / sizeof(preferred_groups[0])); i++) {
        if(tls12_client_supports_group(ctx, preferred_groups[i])) {
            *named_group = preferred_groups[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
        uint16_t group = ctx->client_extensions.supported_groups->groups[i];
        if(tls12_is_supported_ffdhe_group(group)) {
            *named_group = group;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    /* No mutually supported FFDHE from the client's list.
     * If the offer looks like EC/FFDHE-oriented (including obsolete EC ids we do not implement,
     * e.g. secp160k1), use suite-default FFDHE for DHE_RSA (tlsfuzzer test_unsupported_curve_fallback).
     * If the list contains high codepoints that are neither our FFDHE set nor traditional EC-range
     * ids (e.g. reserved 511), fail so ClientHello handling can RSA-fallback (RFC 7919 §4). */
    {
        int allow_suite_default_ffdhe = 1;
        for(i = 0; i < ctx->client_extensions.supported_groups->count; i++) {
            uint16_t g = ctx->client_extensions.supported_groups->groups[i];
            if(tls12_is_supported_ffdhe_group(g) || tls12_is_supported_ec_curve(g)) {
                continue;
            }
            /* FFDHE groups are 256..260 in this stack; EC named groups historically use <256. */
            if(g > 255u) {
                allow_suite_default_ffdhe = 0;
                break;
            }
        }
        if(!allow_suite_default_ffdhe && ctx->client_extensions.supported_groups->count > 0u) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    *named_group = preferred;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * If the client offered both plain RSA and DHE-RSA AES-128-CBC but did not send supported_groups,
 * prefer DHE for forward secrecy (tlsfuzzer test_ffdhe_negotiation "Check if DHE preferred").
 */
static void tls12_maybe_upgrade_rsa_to_dhe_for_fs(tls12_context_t *ctx,
                                                  const uint8_t *ch_buf,
                                                  uint32_t ch_len,
                                                  uint32_t cipher_suites_offset,
                                                  uint32_t cipher_suites_count)
{
    uint16_t ng_probe;
    if(ctx == NULL || ch_buf == NULL || ctx->session_resume || ctx->renegotiation_in_progress) {
        return;
    }
    if(ctx->cipher_suite != TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA) {
        return;
    }
    if(ctx->client_extensions.supported_groups != NULL) {
        return;
    }
    if(!tls12_client_offered_cipher(ch_buf, ch_len, cipher_suites_offset, cipher_suites_count,
                                    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA)) {
        return;
    }
    ctx->cipher_suite = TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA;
    if(tls12_select_ffdhe_named_group(ctx, ctx->cipher_suite, &ng_probe) != NOXTLS_RETURN_SUCCESS) {
        ctx->cipher_suite = TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA;
    }
}

/**
 * @brief Free TLS 1.2 context
 */
noxtls_return_t noxtls_tls12_context_free(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /*
     * Ownership differs by role:
     * - Client path allocates server_cert when receiving Certificate.
     * - Server path typically points server_cert to caller-managed certificate bytes.
     * Free only for client role to avoid freeing caller-owned memory.
     */
    if(ctx->server_cert) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            noxtls_free(ctx->server_cert);
        }
        ctx->server_cert = NULL;
    }
    
    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }
    if(ctx->client_cert) {
        noxtls_free(ctx->client_cert);
        ctx->client_cert = NULL;
        ctx->client_cert_len = 0;
    }
    if(ctx->client_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }
    if(ctx->peer_ocsp_response) {
        noxtls_free(ctx->peer_ocsp_response);
        ctx->peer_ocsp_response = NULL;
        ctx->peer_ocsp_response_len = 0;
    }
    
    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
        ctx->handshake_messages = NULL;
    }
    
    /* Free ECDHE context if it exists */
    if(ctx->ecdhe_ctx) {
        noxtls_tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
        free(ctx->ecdhe_ctx);
        ctx->ecdhe_ctx = NULL;
    }
    /* Free DHE context if it exists */
    if(ctx->dhe_ctx) {
        noxtls_tls_dhe_context_free((tls_dhe_context_t*)ctx->dhe_ctx);
        free(ctx->dhe_ctx);
        ctx->dhe_ctx = NULL;
    }
    
    /* Free extensions */
    noxtls_tls_extensions_free(&ctx->client_extensions);
    noxtls_tls_extensions_free(&ctx->server_extensions);
    
    if(ctx->record_workspace) {
        if(ctx->record_workspace_owned) {
            noxtls_free(ctx->record_workspace);
        }
        ctx->record_workspace = NULL;
        ctx->record_workspace_owned = 0;
    }
    if(ctx->handshake_workspace) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(ctx->handshake_workspace_owned) {
            noxtls_free(ctx->handshake_workspace);
        }
        ctx->handshake_workspace = NULL;
        ctx->handshake_workspace_owned = 0;
    }
    noxtls_dtls_context_free(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_tls12_set_server_private_rsa(tls12_context_t *ctx, void *rsa_key)
{
    if(ctx != NULL) {
        ctx->server_private_rsa = rsa_key;
    }
}

void noxtls_tls12_set_server_private_ecdsa(tls12_context_t *ctx, void *ecc_key)
{
    if(ctx != NULL) {
        ctx->server_private_ecdsa = ecc_key;
    }
}

void noxtls_tls12_set_server_ecdsa_leaf_certificate(tls12_context_t *ctx, const uint8_t *der, uint32_t der_len)
{
    if(ctx != NULL) {
        ctx->server_ecdsa_leaf_cert = der;
        ctx->server_ecdsa_leaf_cert_len = der_len;
    }
}

void noxtls_tls12_set_server_rsa_pss_leaf_material(tls12_context_t *ctx, const uint8_t *der, uint32_t der_len, void *rsa_key, void *parsed_cert)
{
    if(ctx != NULL) {
        ctx->server_rsa_pss_leaf_cert = der;
        ctx->server_rsa_pss_leaf_cert_len = der_len;
        ctx->server_private_rsa_pss_leaf = rsa_key;
        ctx->server_rsa_pss_leaf_cert_parsed = parsed_cert;
    }
}

void noxtls_tls12_set_server_cipher_suites(tls12_context_t *ctx, const uint16_t *suites, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_cipher_suites = suites;
    ctx->server_cipher_suites_count = count;
}

void noxtls_tls12_set_server_alpn_protocols(tls12_context_t *ctx, const char **protocols, uint32_t count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_alpn_protocols = protocols;
    ctx->server_alpn_count = count;
}

void noxtls_tls12_set_server_expected_client_sni(tls12_context_t *ctx, const char *ascii_hostname, int mismatch_fatal)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_expect_client_sni = ascii_hostname;
    ctx->server_expect_sni_fatal = mismatch_fatal ? 1u : 0u;
}

void noxtls_tls12_set_server_certificate_chain(tls12_context_t *ctx,
                                               const uint8_t **certs,
                                               const uint32_t *cert_lens,
                                               uint32_t cert_count)
{
    if(ctx == NULL) {
        return;
    }
    ctx->server_cert_chain = certs;
    ctx->server_cert_chain_len = cert_lens;
    ctx->server_cert_chain_count = cert_count;
}

void noxtls_tls12_set_crypto_provider_server(tls12_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle)
{
    if(ctx != NULL) {
        ctx->crypto_provider = provider;
        ctx->server_private_key_handle = server_key_handle;
    }
}

/**
 * @brief Set optional CRL list for TLS 1.2 server certificate verification.
 * @param ctx TLS 1.2 context.
 * @param crl Parsed CRL list head, or NULL to disable CRL checks.
 * @return None.
 */
void noxtls_tls12_set_verify_crl(tls12_context_t *ctx, const noxtls_x509_crl_t *crl)
{
    if(ctx != NULL) {
        ctx->verify_crl = crl;
    }
}

void noxtls_tls12_set_server_use_rpk(tls12_context_t *ctx, int use_rpk)
{
    if(ctx != NULL) {
        ctx->server_use_rpk = (use_rpk != 0) ? 1 : 0;
    }
}

void noxtls_tls12_set_client_accept_server_rpk(tls12_context_t *ctx, int accept)
{
    if(ctx != NULL) {
        ctx->client_accept_server_rpk = (accept != 0) ? 1 : 0;
    }
}

void noxtls_tls12_set_client_offer_client_rpk(tls12_context_t *ctx, int offer)
{
    if(ctx != NULL) {
        ctx->client_offer_client_rpk = (offer != 0) ? 1 : 0;
    }
}

void noxtls_tls12_request_client_auth(tls12_context_t *ctx, int request)
{
    if(ctx != NULL) {
        ctx->request_client_auth = (request != 0) ? 1 : 0;
    }
}

/* RFC 6066: MFL code to payload size (bytes) */
static uint16_t tls12_mfl_code_to_payload(uint8_t code)
{
    switch(code) {
        case 1: return 512;
        case 2: return 1024;
        case 3: return 2048;
        case 4: return 4096;
        default: return 0;
    }
}

void noxtls_tls12_set_max_fragment_length(tls12_context_t *ctx, uint8_t code)
{
    if(ctx != NULL) {
        if(code >= 1 && code <= 4) {
            ctx->max_fragment_length_code = code;
        } else {
            ctx->max_fragment_length_code = 0;
        }
    }
}

void noxtls_tls12_set_heartbeat(tls12_context_t *ctx, int enable)
{
    if(ctx != NULL) {
        ctx->heartbeat_enabled = (enable != 0) ? 1u : 0u;
        if(ctx->heartbeat_enabled == 0u) {
            ctx->heartbeat_negotiated = 0u;
            ctx->heartbeat_peer_mode = 0u;
            ctx->client_heartbeat_mode = 0u;
        }
    }
}

void noxtls_tls12_set_client_request_ocsp_status(tls12_context_t *ctx, int enable)
{
    if(ctx != NULL) {
        ctx->client_request_ocsp_status = (enable != 0) ? 1u : 0u;
        if(ctx->client_request_ocsp_status == 0u) {
            ctx->status_request_negotiated = 0u;
        }
    }
}

void noxtls_tls12_set_server_ocsp_response(tls12_context_t *ctx, const uint8_t *ocsp_der, uint32_t ocsp_len)
{
    if(ctx != NULL) {
        if(ocsp_der != NULL && ocsp_len > 0u) {
            ctx->server_ocsp_response = ocsp_der;
            ctx->server_ocsp_response_len = ocsp_len;
        } else {
            ctx->server_ocsp_response = NULL;
            ctx->server_ocsp_response_len = 0u;
            ctx->status_request_negotiated = 0u;
        }
    }
}

noxtls_return_t noxtls_tls12_get_peer_ocsp_response(const tls12_context_t *ctx,
                                                    const uint8_t **ocsp_der,
                                                    uint32_t *ocsp_len)
{
    if(ctx == NULL || ocsp_der == NULL || ocsp_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *ocsp_der = ctx->peer_ocsp_response;
    *ocsp_len = ctx->peer_ocsp_response_len;
    if(ctx->peer_ocsp_response == NULL || ctx->peer_ocsp_response_len == 0u) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls12_validate_client_ems_extension(tls12_context_t *ctx)
{
    tls_extension_t *ex = NULL;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    ctx->extended_master_secret_offered = 0;
    if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_EXTENDED_MASTER_SECRET, &ex) != NOXTLS_RETURN_SUCCESS ||
       ex == NULL) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ex->length != 0) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        return NOXTLS_RETURN_BAD_DATA;
    }
    ctx->extended_master_secret_offered = 1;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls12_resume_ems_policy(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!ctx->session_resume) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ctx->session_resume_ems != 0 && ctx->extended_master_secret_offered == 0) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(ctx->session_resume_ems == 0 && ctx->extended_master_secret_offered != 0) {
        ctx->session_resume = 0;
        memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
        ctx->session_resume_ems = 0;
        /*
         * Declining resumption while doing a full handshake: use a new session ID
         * in ServerHello so peers (e.g. tlsfuzzer) do not set abbreviated-handshake
         * state from a matching session_id while still running Certificate/CKE.
         */
        (void)tls12_session_cache_generate_id(ctx->server_session_id, &ctx->server_session_id_len);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute TLS 1.2 master secret from premaster secret
 * 
 * According to RFC 5246 Section 8.1:
 * master_secret = PRF(premaster_secret, "master secret", client_random + server_random)[0..47]
 * 
 * The master secret is always 48 bytes.
 */
noxtls_return_t tls12_compute_master_secret(tls12_context_t *ctx, const uint8_t *premaster_secret, uint32_t premaster_secret_len)
{
    uint8_t seed[64];  /* client_random + server_random */
    noxtls_hash_algos_t hash_algo;
    noxtls_return_t rc;
    const uint8_t *pms_ptr;
    uint32_t pms_len;
    
    if(ctx == NULL || premaster_secret == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(premaster_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    pms_ptr = premaster_secret;
    pms_len = premaster_secret_len;
    {
        int is_dhe_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
        if(is_dhe_kex) {
            while(pms_len > 1u && *pms_ptr == 0x00u) {
                pms_ptr++;
                pms_len--;
            }
        }
    }
    
    /* Determine hash algorithm based on cipher suite */
    hash_algo = tls12_get_prf_hash(ctx->cipher_suite);

    if(ctx->extended_master_secret_negotiated) {
        static const char ems_label[] = "extended master secret";
        const uint32_t ems_label_len = (uint32_t)(sizeof(ems_label) - 1u);
        const uint8_t *transcript = ctx->handshake_messages;
        uint32_t tlen = ctx->ems_session_transcript_len;
        uint8_t session_hash[TLS_MAX_SECRET_LEN];
        uint32_t hash_size = 0;
        noxtls_sha512_ctx_t sha512_ctx;

        if(transcript == NULL || tlen == 0 || tlen > ctx->handshake_messages_len) {
            return NOXTLS_RETURN_FAILED;
        }

        if(ctx->base.base.version <= TLS_VERSION_1_1) {
            uint8_t md5_hash[16];
            uint8_t sha1_hash[20];
            noxtls_sha_ctx_t md5_ctx;
            noxtls_sha_ctx_t sha1_ctx;
            noxtls_md5_init(&md5_ctx);
            noxtls_md5_update(&md5_ctx, (uint8_t*)transcript, tlen);
            noxtls_md5_finish(&md5_ctx, md5_hash);
            noxtls_sha1_init(&sha1_ctx, NOXTLS_HASH_SHA1);
            noxtls_sha1_update(&sha1_ctx, transcript, tlen);
            noxtls_sha1_finish(&sha1_ctx, sha1_hash);
            memcpy(session_hash, md5_hash, 16);
            memcpy(session_hash + 16, sha1_hash, 20);
            hash_size = 36;
            rc = tls10_prf(pms_ptr, pms_len, (const uint8_t*)ems_label, ems_label_len,
                           session_hash, hash_size, ctx->master_secret, 48);
        } else if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
            noxtls_sha256_update(&sha_ctx, transcript, tlen);
            noxtls_sha256_finish(&sha_ctx, session_hash);
            hash_size = 32;
            rc = tls12_prf(pms_ptr, pms_len, (const uint8_t*)ems_label, ems_label_len,
                           session_hash, hash_size, ctx->master_secret, 48, hash_algo);
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            noxtls_sha512_init(&sha512_ctx, NOXTLS_HASH_SHA_512);
            sha512_ctx.h[0] = 0xcbbb9d5dc1059ed8ULL;
            sha512_ctx.h[1] = 0x629a292a367cd507ULL;
            sha512_ctx.h[2] = 0x9159015a3070dd17ULL;
            sha512_ctx.h[3] = 0x152fecd8f70e5939ULL;
            sha512_ctx.h[4] = 0x67332667ffc00b31ULL;
            sha512_ctx.h[5] = 0x8eb44a8768581511ULL;
            sha512_ctx.h[6] = 0xdb0c2e0d64f98fa7ULL;
            sha512_ctx.h[7] = 0x47b5481dbefa4fa4ULL;
            noxtls_sha512_update(&sha512_ctx, transcript, tlen);
            {
                uint8_t sha512_output[TLS_MAX_SECRET_LEN];
                noxtls_sha512_finish(&sha512_ctx, sha512_output);
                memcpy(session_hash, sha512_output, 48);
            }
            hash_size = 48;
            rc = tls12_prf(pms_ptr, pms_len, (const uint8_t*)ems_label, ems_label_len,
                           session_hash, hash_size, ctx->master_secret, 48, hash_algo);
        } else {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
            noxtls_sha256_update(&sha_ctx, transcript, tlen);
            noxtls_sha256_finish(&sha_ctx, session_hash);
            hash_size = 32;
            rc = tls12_prf(pms_ptr, pms_len, (const uint8_t*)ems_label, ems_label_len,
                           session_hash, hash_size, ctx->master_secret, 48, NOXTLS_HASH_SHA_256);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_debug_printf("TLS 1.2 extended master secret computed successfully\n");
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Build seed: client_random + server_random */
    memcpy(seed, ctx->client_random, 32);
    memcpy(seed + 32, ctx->server_random, 32);
    
    noxtls_debug_printf("[TLS12_DEBUG] master_secret: premaster_len=%u cipher=0x%04X\n",
                          pms_len, ctx->cipher_suite);
    fflush(stdout);
    /* Generate master secret using PRF (TLS 1.0/1.1 use MD5/SHA-1 PRF) */
    const char *label = "master secret";
    size_t label_len = strlen(label);
    if(label_len > UINT32_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->base.base.version <= TLS_VERSION_1_1) {
        rc = tls10_prf(pms_ptr, pms_len, (const uint8_t*)label, (uint32_t)label_len,
                       seed, 64, ctx->master_secret, 48);
    } else {
        rc = tls12_prf(pms_ptr, pms_len, (const uint8_t*)label, (uint32_t)label_len,
                       seed, 64, ctx->master_secret, 48, hash_algo);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_debug_printf("TLS 1.2 master secret computed successfully\n");
    noxtls_debug_printf("[TLS12_DEBUG] %s premaster[0..3]=%02X%02X%02X%02X master[0..3]=%02X%02X%02X%02X\n",
                          (ctx->base.base.role == TLS_ROLE_CLIENT) ? "client" : "server",
                          premaster_secret[0], premaster_secret[1], premaster_secret[2], premaster_secret[3],
                          ctx->master_secret[0], ctx->master_secret[1], ctx->master_secret[2], ctx->master_secret[3]);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive TLS 1.2 keys from master secret
 * 
 * According to RFC 5246 Section 6.3:
 * key_block = PRF(master_secret, "key expansion", server_random + client_random)
 * 
 * The key_block is then split based on cipher suite requirements.
 * For AES-256-CBC-SHA256:
 * - client_write_MAC_key: 32 bytes (SHA-256)
 * - server_write_MAC_key: 32 bytes (SHA-256)
 * - client_write_key: 32 bytes (AES-256)
 * - server_write_key: 32 bytes (AES-256)
 * - client_write_IV: 16 bytes
 * - server_write_IV: 16 bytes
 * Total: 144 bytes
 */
noxtls_return_t tls12_derive_keys(tls12_context_t *ctx)
{
    uint8_t *key_block;
    uint8_t seed[64];  /* server_random + client_random */
    uint32_t key_block_len;
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    noxtls_return_t rc;
    uint32_t mac_key_len;
    uint32_t enc_key_len;
    uint32_t iv_len;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    key_block = ctx->handshake_workspace;
    if(key_block == NULL) {
        key_block = (uint8_t*)noxtls_malloc(TLS_KEY_BLOCK_MAX_LEN);
        if(key_block == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    
    /* Master secret must be computed before key derivation */
    /* Check if master secret is set (not all zeros) */
    uint32_t master_secret_is_zero = 1;
    uint32_t i;
    for(i = 0; i < 48; i++) {
        if(ctx->master_secret[i] != 0) {
            master_secret_is_zero = 0;
            break;
        }
    }
    
    if(master_secret_is_zero) {
        noxtls_debug_printf("ERROR: Master secret not computed before key derivation!\n");
        if(key_block != ctx->handshake_workspace) NOXTLS_SECURE_FREE(key_block, TLS_KEY_BLOCK_MAX_LEN);
        else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Determine hash algorithm and key sizes based on cipher suite */
    switch(ctx->cipher_suite) {
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            /* RFC 7905: 32-byte keys, 12-byte fixed IV per direction (nonce = IV XOR padded seq). */
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0;
            enc_key_len = 32;
            iv_len = 12;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA_256;  /* PRF; MAC is SHA-1 */
            mac_key_len = 20;
            enc_key_len = 24;
            iv_len = 8;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA_256;  /* SHA-1 for MAC, but use SHA-256 PRF */
            mac_key_len = 20;  /* SHA-1 MAC key */
            enc_key_len = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                           ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA ||
                           ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
                           ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA) ? 16 : 32;
            iv_len = 16;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;  /* SHA-256 MAC key */
            if(ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384) {
                hash_algo = NOXTLS_HASH_SHA_384;
                mac_key_len = 48;  /* SHA-384 MAC key */
            }
            enc_key_len = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
                          ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256) ? 16 : 32;
            if(ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
               ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8) {
                mac_key_len = 0;
                iv_len = 4;
                key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            } else {
                iv_len = 16;
                key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            }
            break;
        default:
            /* Default to AES-256-CBC-SHA256 */
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;
            enc_key_len = 32;
            iv_len = 16;
            key_block_len = (mac_key_len << 1) + (enc_key_len << 1) + (iv_len << 1);
            break;
    }

    /* Build seed: server_random + client_random */
    memcpy(seed, ctx->server_random, TLS_RANDOM_SIZE);
    memcpy(seed + TLS_RANDOM_SIZE, ctx->client_random, TLS_RANDOM_SIZE);
    
    /* Generate key_block using PRF (TLS 1.0/1.1 use MD5/SHA-1 PRF) */
    const char *label = "key expansion";
    size_t label_len = strlen(label);
    if(label_len > UINT32_MAX) {
        if(key_block != ctx->handshake_workspace) NOXTLS_SECURE_FREE(key_block, TLS_KEY_BLOCK_MAX_LEN);
        else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->base.base.version <= TLS_VERSION_1_1) {
        rc = tls10_prf(ctx->master_secret, 48, (const uint8_t*)label, (uint32_t)label_len,
                       seed, 64, key_block, key_block_len);
    } else {
        rc = tls12_prf(ctx->master_secret, 48, (const uint8_t*)label, (uint32_t)label_len,
                       seed, 64, key_block, key_block_len, hash_algo);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(key_block != ctx->handshake_workspace) NOXTLS_SECURE_FREE(key_block, TLS_KEY_BLOCK_MAX_LEN);
        else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
    
    /* Split key_block into individual keys */
    /* client_write_MAC_key */
    memcpy(ctx->client_write_mac_key, key_block + offset, mac_key_len);
    offset += mac_key_len;
    
    /* server_write_MAC_key */
    memcpy(ctx->server_write_mac_key, key_block + offset, mac_key_len);
    offset += mac_key_len;
    
    /* client_write_key */
    memcpy(ctx->client_write_key, key_block + offset, enc_key_len);
    offset += enc_key_len;
    
    /* server_write_key */
    memcpy(ctx->server_write_key, key_block + offset, enc_key_len);
    offset += enc_key_len;
    
    /* client_write_IV */
    memcpy(ctx->client_write_iv, key_block + offset, iv_len);
    offset += iv_len;
    
    /* server_write_IV */
    memcpy(ctx->server_write_iv, key_block + offset, iv_len);
    offset += iv_len;
    (void)offset;
    
    noxtls_debug_printf("TLS 1.2 keys derived successfully (cipher suite: 0x%04x)\n", ctx->cipher_suite);
    noxtls_debug_printf("[TLS12_DEBUG] %s keys: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
                          (ctx->base.base.role == TLS_ROLE_CLIENT) ? "client" : "server",
                          ctx->client_write_key[0], ctx->client_write_key[1], ctx->client_write_key[2], ctx->client_write_key[3],
                          ctx->client_write_iv[0], ctx->client_write_iv[1], ctx->client_write_iv[2], ctx->client_write_iv[3],
                          ctx->server_write_key[0], ctx->server_write_key[1], ctx->server_write_key[2], ctx->server_write_key[3],
                          ctx->server_write_iv[0], ctx->server_write_iv[1], ctx->server_write_iv[2], ctx->server_write_iv[3]);
    if(key_block != ctx->handshake_workspace) NOXTLS_SECURE_FREE(key_block, TLS_KEY_BLOCK_MAX_LEN);
    else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Append handshake noxtls_message to handshake messages buffer
 */
static noxtls_return_t tls12_append_handshake_message(tls12_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    
    if(len > UINT32_MAX - ctx->handshake_messages_len) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t new_len = ctx->handshake_messages_len + len;
    /* Reallocate buffer to accommodate new noxtls_message */
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_messages, new_len);
    if(new_buffer == NULL && len > 0) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->handshake_messages = new_buffer;
    memcpy(ctx->handshake_messages + ctx->handshake_messages_len, data, len);
    ctx->handshake_messages_len = new_len;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute handshake hash for Finished noxtls_message
 * 
 * According to RFC 5246 Section 7.4.9:
 * verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..11]
 * 
 * where label is "client finished" or "server finished"
 */
static noxtls_return_t tls12_compute_finished_verify_data(tls12_context_t *ctx, const char *label, 
                                                               uint8_t *verify_data, noxtls_hash_algos_t hash_algo)
{
    uint8_t handshake_hash[TLS_MAX_SECRET_LEN];  /* Max hash size (SHA-512); TLS 1.0/1.1 use 36 (MD5||SHA1) */
    uint32_t hash_size;
    noxtls_return_t rc;
    
    if(ctx == NULL || label == NULL || verify_data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* TLS 1.0/1.1: verify_data = PRF(master_secret, label, MD5(handshake_messages) || SHA1(handshake_messages))[0..11] */
    if(ctx->base.base.version <= TLS_VERSION_1_1) {
        uint8_t md5_hash[16];
        uint8_t sha1_hash[20];
        noxtls_sha_ctx_t md5_ctx;
        noxtls_sha_ctx_t sha_ctx;
        if(ctx->handshake_messages && ctx->handshake_messages_len > 0) {
            noxtls_md5_init(&md5_ctx);
            noxtls_md5_update(&md5_ctx, (uint8_t*)ctx->handshake_messages, ctx->handshake_messages_len);
            noxtls_md5_finish(&md5_ctx, md5_hash);
            noxtls_sha1_init(&sha_ctx, NOXTLS_HASH_SHA1);
            noxtls_sha1_update(&sha_ctx, ctx->handshake_messages, ctx->handshake_messages_len);
            noxtls_sha1_finish(&sha_ctx, sha1_hash);
        } else {
            memset(md5_hash, 0, 16);
            memset(sha1_hash, 0, 20);
        }
        memcpy(handshake_hash, md5_hash, 16);
        memcpy(handshake_hash + 16, sha1_hash, 20);
        hash_size = 36;
        size_t label_len = strlen(label);
        if(label_len > UINT32_MAX) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        rc = tls10_prf(ctx->master_secret, 48, (const uint8_t*)label, (uint32_t)label_len,
                       handshake_hash, hash_size, verify_data, 12);
        return rc;
    }
    
    /* Hash all handshake messages using the hash function from cipher suite */
    noxtls_sha512_ctx_t sha512_ctx;
    
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
        if(ctx->handshake_messages && ctx->handshake_messages_len > 0) {
            noxtls_sha256_update(&sha_ctx, ctx->handshake_messages, ctx->handshake_messages_len);
        }
        noxtls_sha256_finish(&sha_ctx, handshake_hash);
        hash_size = 32;
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        /* SHA-384 uses SHA-512 with different initial values */
        /* Initialize SHA-512 context and manually set SHA-384 initial values */
        noxtls_sha512_init(&sha512_ctx, NOXTLS_HASH_SHA_512);
        /* Override with SHA-384 initial values */
        sha512_ctx.h[0] = 0xcbbb9d5dc1059ed8ULL;
        sha512_ctx.h[1] = 0x629a292a367cd507ULL;
        sha512_ctx.h[2] = 0x9159015a3070dd17ULL;
        sha512_ctx.h[3] = 0x152fecd8f70e5939ULL;
        sha512_ctx.h[4] = 0x67332667ffc00b31ULL;
        sha512_ctx.h[5] = 0x8eb44a8768581511ULL;
        sha512_ctx.h[6] = 0xdb0c2e0d64f98fa7ULL;
        sha512_ctx.h[7] = 0x47b5481dbefa4fa4ULL;
        
        if(ctx->handshake_messages && ctx->handshake_messages_len > 0) {
            noxtls_sha512_update(&sha512_ctx, ctx->handshake_messages, ctx->handshake_messages_len);
        }
        /* SHA-384 outputs first 48 bytes of SHA-512 */
        uint8_t sha512_output[TLS_MAX_SECRET_LEN];
        noxtls_sha512_finish(&sha512_ctx, sha512_output);
        memcpy(handshake_hash, sha512_output, 48);
        hash_size = 48;
    } else {
        /* Default to SHA-256 */
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
        if(ctx->handshake_messages && ctx->handshake_messages_len > 0) {
            noxtls_sha256_update(&sha_ctx, ctx->handshake_messages, ctx->handshake_messages_len);
        }
        noxtls_sha256_finish(&sha_ctx, handshake_hash);
        hash_size = 32;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] finished_hash: algo=%u len=%u hs_len=%u hash[0..3]=%02X%02X%02X%02X\n",
                          (unsigned)hash_algo, hash_size, ctx->handshake_messages_len,
                          handshake_hash[0], handshake_hash[1], handshake_hash[2], handshake_hash[3]);
    fflush(stdout);

    /* Compute verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..11] */
    size_t label_len = strlen(label);
    if(label_len > UINT32_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = tls12_prf(ctx->master_secret, 48, (const uint8_t*)label, (uint32_t)label_len,
                   handshake_hash, hash_size, verify_data, 12, hash_algo);
    
    return rc;
}

/**
 * @brief TLS 1.2 Client: Send Client Hello
 */
noxtls_return_t noxtls_tls12_send_client_hello(tls12_context_t *ctx)
{
    uint8_t *client_hello = ctx->handshake_workspace;
    if(client_hello == NULL) {
        client_hello = (uint8_t*)noxtls_malloc(TLS_CLIENT_HELLO_DEFAULT_SIZE);
        if(client_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    /* TLS 1.0/1.1: only RSA key exchange with CBC SHA suites */
    uint16_t cipher_suites_10_11[] = {
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
    };
    uint16_t cipher_suites_12[] = {
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
        ,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
#endif
    };
    uint16_t *cipher_suites = (ctx->base.base.version <= TLS_VERSION_1_1) ? cipher_suites_10_11 : cipher_suites_12;
    uint32_t num_cipher_suites = (ctx->base.base.version <= TLS_VERSION_1_1)
        ? (sizeof(cipher_suites_10_11) / sizeof(cipher_suites_10_11[0]))
        : (sizeof(cipher_suites_12) / sizeof(cipher_suites_12[0]));
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate client random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, TLS_CLIENT_HELLO_DEFAULT_SIZE);
        else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->client_random, 256, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, TLS_CLIENT_HELLO_DEFAULT_SIZE);
        else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Client Hello noxtls_message */
    client_hello[offset++] = TLS_HANDSHAKE_CLIENT_HELLO;
    client_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Version */
    if(tls12_is_dtls(ctx)) {
        client_hello[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        client_hello[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        uint16_t ver = ctx->base.base.version;
        client_hello[offset++] = (ver >> 8) & 0xFF;
        client_hello[offset++] = ver & 0xFF;
    }
    
    /* Random (32 bytes) */
    memcpy(client_hello + offset, ctx->client_random, 32);
    offset += 32;
    
    /* Session ID length (1 byte) */
    client_hello[offset++] = 0x00;  /* No session ID */

    if(tls12_is_dtls(ctx)) {
        client_hello[offset++] = (uint8_t)ctx->base.cookie_len;
        if(ctx->base.cookie_len > 0) {
            memcpy(client_hello + offset, ctx->base.cookie, ctx->base.cookie_len);
            offset += ctx->base.cookie_len;
        }
    }
    
    /* Cipher suites length (2 bytes) */
    uint16_t cipher_suites_len = (uint16_t)(num_cipher_suites << 1);
    client_hello[offset++] = (cipher_suites_len >> 8) & 0xFF;
    client_hello[offset++] = cipher_suites_len & 0xFF;
    
    /* Cipher suites (convert to network byte order) */
    for(uint32_t i = 0; i < num_cipher_suites; i++) {
        client_hello[offset++] = (cipher_suites[i] >> 8) & 0xFF;
        client_hello[offset++] = cipher_suites[i] & 0xFF;
    }
    
    /* Compression methods length (1 byte) */
    client_hello[offset++] = 0x01;
    client_hello[offset++] = 0x00;  /* NULL compression */

    /* Extensions (TLS 1.0/1.1 do not have extensions in Client Hello) */
    if(ctx->base.base.version >= TLS_VERSION_1_2) {
        uint8_t *ext_buf = client_hello + TLS_CLIENT_HELLO_BASE_SIZE;  /* Use tail of workspace for extensions */
        uint32_t ext_len = 0;

        /* SNI */
        if(ctx->server_name != NULL && ctx->server_name_len > 0) {
            uint16_t name_len = ctx->server_name_len;
            uint16_t list_len = (uint16_t)(1 + 2 + name_len);
            uint16_t ext_data_len = (uint16_t)(2 + list_len);
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = TLS_EXTENSION_SERVER_NAME;
                ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
                ext_buf[ext_len++] = (uint8_t)(list_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(list_len & 0xFF);
                ext_buf[ext_len++] = 0x00; /* host_name */
                ext_buf[ext_len++] = (uint8_t)(name_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(name_len & 0xFF);
                memcpy(ext_buf + ext_len, ctx->server_name, name_len);
                ext_len += name_len;
            }
        }

        /* Supported Groups: P-256, P-384, P-521 (standard curves for TLS 1.2 ECDHE) */
        {
            uint16_t group_list_len = 6;
            uint16_t ext_data_len = (uint16_t)(2 + group_list_len);
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SUPPORTED_GROUPS >> 8);
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SUPPORTED_GROUPS & 0xFF);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = (uint8_t)group_list_len;
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = TLS_NAMED_GROUP_SECP256R1;
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = TLS_NAMED_GROUP_SECP384R1;
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = TLS_NAMED_GROUP_SECP521R1;
            }
        }

        /* EC Point Formats (uncompressed) */
        {
            uint16_t ext_data_len = 2;
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_EC_POINT_FORMATS >> 8);
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_EC_POINT_FORMATS & 0xFF);
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = 0x02;
                ext_buf[ext_len++] = 0x01; /* list length */
                ext_buf[ext_len++] = 0x00; /* uncompressed */
            }
        }

        /* Signature Algorithms */
        {
            uint16_t sig_list_len = 12;
            uint16_t ext_data_len = (uint16_t)(2 + sig_list_len);
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SIGNATURE_ALGORITHMS >> 8);
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SIGNATURE_ALGORITHMS & 0xFF);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
                ext_buf[ext_len++] = 0x00;
                ext_buf[ext_len++] = (uint8_t)sig_list_len;
                /* rsa_pkcs1_sha256 (0x0401), rsa_pkcs1_sha384 (0x0501), rsa_pkcs1_sha1 (0x0201) */
                ext_buf[ext_len++] = 0x04; ext_buf[ext_len++] = 0x01;
                ext_buf[ext_len++] = 0x05; ext_buf[ext_len++] = 0x01;
                ext_buf[ext_len++] = 0x02; ext_buf[ext_len++] = 0x01;
                /* ecdsa_secp256r1_sha256 (0x0403), ecdsa_secp384r1_sha384 (0x0503), ecdsa_sha1 (0x0203) */
                ext_buf[ext_len++] = 0x04; ext_buf[ext_len++] = 0x03;
                ext_buf[ext_len++] = 0x05; ext_buf[ext_len++] = 0x03;
                ext_buf[ext_len++] = 0x02; ext_buf[ext_len++] = 0x03;
            }
        }

        /* RFC 7250: server_certificate_type (client accepts RPK from server) */
        if(ctx->client_accept_server_rpk) {
            uint16_t ext_data_len = 3;  /* 1 byte list length + 2 types */
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SERVER_CERTIFICATE_TYPE >> 8);
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_SERVER_CERTIFICATE_TYPE & 0xFF);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
                ext_buf[ext_len++] = 2;  /* list length: RawPublicKey, X.509 */
                ext_buf[ext_len++] = TLS_CERT_TYPE_RAW_PUBLIC_KEY;
                ext_buf[ext_len++] = TLS_CERT_TYPE_X509;
            }
        }
        /* RFC 7250: client_certificate_type (client can send RPK for client auth) */
        if(ctx->client_offer_client_rpk) {
            uint16_t ext_data_len = 3;
            if(ext_len + 4u + ext_data_len < 256u) {
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_CLIENT_CERTIFICATE_TYPE >> 8);
                ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_CLIENT_CERTIFICATE_TYPE & 0xFF);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
                ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
                ext_buf[ext_len++] = 2;
                ext_buf[ext_len++] = TLS_CERT_TYPE_RAW_PUBLIC_KEY;
                ext_buf[ext_len++] = TLS_CERT_TYPE_X509;
            }
        }
        /* RFC 6066: max_fragment_length (1=512, 2=1024, 3=2048, 4=4096) */
        if(ctx->max_fragment_length_code >= 1 && ctx->max_fragment_length_code <= 4 &&
           ext_len + 4u + 1u < 256u) {
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = TLS_EXTENSION_MAX_FRAGMENT_LENGTH;
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = 0x01;
            ext_buf[ext_len++] = ctx->max_fragment_length_code;
        }
        /* RFC 6066 status_request (OCSP stapling): status_type=ocsp, empty responder_id_list, empty request_extensions. */
        if(ctx->client_request_ocsp_status != 0u && ext_len + 4u + 5u < 256u) {
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = TLS_EXTENSION_STATUS_REQUEST;
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = 0x05;
            ext_buf[ext_len++] = 0x01; /* status_type = ocsp */
            ext_buf[ext_len++] = 0x00; /* responder_id_list length */
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = 0x00; /* request_extensions length */
            ext_buf[ext_len++] = 0x00;
        }
        /* RFC 6520: heartbeat extension */
        if(ctx->heartbeat_enabled != 0u && ext_len + 4u + 1u < 256u) {
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = TLS_EXTENSION_HEARTBEAT;
            ext_buf[ext_len++] = 0x00;
            ext_buf[ext_len++] = 0x01;
            ext_buf[ext_len++] = TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND;
        }

        /* RFC 5746: renegotiation_info (secure renegotiation) when renegotiating */
        if(ctx->renegotiation_in_progress && ctx->previous_verify_data_len > 0 &&
           (1u + ctx->previous_verify_data_len) <= 48u &&
           ext_len + 4u + 1u + (uint32_t)ctx->previous_verify_data_len < 256u) {
            uint16_t ext_data_len = (uint16_t)(1 + ctx->previous_verify_data_len);
            ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO >> 8);
            ext_buf[ext_len++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO & 0xFF);
            ext_buf[ext_len++] = (uint8_t)(ext_data_len >> 8);
            ext_buf[ext_len++] = (uint8_t)(ext_data_len & 0xFF);
            ext_buf[ext_len++] = ctx->previous_verify_data_len;
            memcpy(ext_buf + ext_len, ctx->previous_client_verify_data, ctx->previous_verify_data_len);
            ext_len += ctx->previous_verify_data_len;
        }

        if(ext_len > 0) {
            client_hello[offset++] = (uint8_t)(ext_len >> 8);
            client_hello[offset++] = (uint8_t)(ext_len & 0xFF);
            memcpy(client_hello + offset, ext_buf, ext_len);
            offset += ext_len;
        }
    }
    
    /* Update handshake noxtls_message length (skip extensions for TLS 1.0/1.1) */
    uint32_t handshake_len = offset - 4;
    client_hello[1] = (handshake_len >> 16) & 0xFF;
    client_hello[2] = (handshake_len >> 8) & 0xFF;
    client_hello[3] = handshake_len & 0xFF;

    noxtls_debug_printf("[TLS12_DEBUG] client_hello: len=%u cipher_suites=%u sni=%s\n",
                          offset, num_cipher_suites,
                          (ctx->server_name != NULL) ? ctx->server_name : "(none)");
    for(uint32_t i = 0; i < offset; i++) {
        noxtls_debug_printf("%02X", client_hello[i]);
        if(((i + 1) & 15) == 0 || i + 1 == offset) {
            noxtls_debug_printf("\n");
        } else {
            noxtls_debug_printf(" ");
        }
    }
    fflush(stdout);
    
    /* Append to handshake messages (for Finished verify_data computation) */
    if(!tls12_is_dtls(ctx) || ctx->base.cookie_len > 0) {
        tls12_append_handshake_message(ctx, client_hello, offset);
    }
    
    /* Send via record layer */
    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_hello, offset);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                        NOXTLS_EVT_CLIENT_HELLO_SENT, num_cipher_suites, offset);
    }
    if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, TLS_CLIENT_HELLO_DEFAULT_SIZE);
    else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/** Client: populate ctx from ClientHello transcript (already sent) for TLS 1.3→1.2 downgrade resume. */
static noxtls_return_t tls12_client_apply_handshake_client_hello_transcript(tls12_context_t *ctx)
{
    const uint8_t *d;
    uint32_t len;
    uint32_t o;
    uint32_t hs_body;
    uint16_t cipher_list_len;
    uint8_t sid_len;
    uint8_t comp_len;
    tls_extension_t *ex = NULL;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    d = ctx->handshake_messages;
    len = ctx->handshake_messages_len;
    if(d == NULL || len < 4u + 2u + 32u + 1u + 2u + 1u) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(d[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    hs_body = ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | (uint32_t)d[3];
    if(4u + hs_body != len || hs_body < 2u + 32u + 1u + 2u + 1u) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    o = 4u;
    ctx->client_hello_version = (uint16_t)(((uint16_t)d[o] << 8) | d[o + 1]);
    o += 2u;
    memcpy(ctx->client_random, d + o, TLS_RANDOM_SIZE);
    o += TLS_RANDOM_SIZE;
    sid_len = d[o++];
    if(o + sid_len + 2u > len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    o += sid_len;
    cipher_list_len = (uint16_t)(((uint16_t)d[o] << 8) | d[o + 1]);
    o += 2u;
    if((cipher_list_len & 1u) != 0u || o + cipher_list_len + 1u > len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    o += cipher_list_len;
    comp_len = d[o++];
    if(o + comp_len > len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    o += comp_len;

    noxtls_tls_extensions_free(&ctx->client_extensions);
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    ctx->client_offered_ocsp_status = 0u;
    ctx->client_request_ocsp_status = 0u;
    ctx->client_heartbeat_mode = 0;
    if(o < len) {
        uint32_t ext_len = len - o;
        noxtls_return_t ext_rc = noxtls_tls_parse_extensions(d + o, ext_len, &ctx->client_extensions);
        if(ext_rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls_extensions_free(&ctx->client_extensions);
            memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
            return ext_rc;
        }
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_STATUS_REQUEST, &ex) == NOXTLS_RETURN_SUCCESS &&
           ex != NULL && ex->data != NULL && ex->length >= 5u && ex->data[0] == 0x01u) {
            ctx->client_offered_ocsp_status = 1u;
        }
        ctx->client_request_ocsp_status = ctx->client_offered_ocsp_status;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_HEARTBEAT, &ex) == NOXTLS_RETURN_SUCCESS &&
           ex != NULL && ex->length == 1u && ex->data != NULL &&
           (ex->data[0] == TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND ||
            ex->data[0] == TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND)) {
            ctx->heartbeat_enabled = 1u;
            ctx->client_heartbeat_mode = ex->data[0];
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Client: continue TLS 1.2 handshake after sending a TLS 1.3 ClientHello and receiving a TLS 1.2 ServerHello.
 *
 * Takes ownership of \p client_hello_transcript and \p server_hello_handshake (malloc'd buffers) on success.
 * On failure, both buffers are freed.
 */
noxtls_return_t noxtls_tls12_client_resume_from_tls13_downgrade(tls12_context_t *ctx,
                                                                uint8_t *client_hello_transcript,
                                                                uint32_t client_hello_transcript_len,
                                                                uint8_t *server_hello_handshake,
                                                                uint32_t server_hello_handshake_len)
{
    noxtls_return_t rc;

    if(ctx == NULL) {
        if(client_hello_transcript) free(client_hello_transcript);
        if(server_hello_handshake) free(server_hello_handshake);
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        if(client_hello_transcript) free(client_hello_transcript);
        if(server_hello_handshake) free(server_hello_handshake);
        return NOXTLS_RETURN_FAILED;
    }
    if(client_hello_transcript == NULL || client_hello_transcript_len < 4u ||
       server_hello_handshake == NULL || server_hello_handshake_len < 4u) {
        if(client_hello_transcript) free(client_hello_transcript);
        if(server_hello_handshake) free(server_hello_handshake);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->handshake_messages != NULL) {
        free(ctx->handshake_messages);
        ctx->handshake_messages = NULL;
        ctx->handshake_messages_len = 0;
    }
    ctx->handshake_messages = client_hello_transcript;
    ctx->handshake_messages_len = client_hello_transcript_len;

    if(ctx->base.base.pending_server_hello != NULL) {
        free(ctx->base.base.pending_server_hello);
        ctx->base.base.pending_server_hello = NULL;
        ctx->base.base.pending_server_hello_len = 0;
    }
    ctx->base.base.pending_server_hello = server_hello_handshake;
    ctx->base.base.pending_server_hello_len = server_hello_handshake_len;

    /* One ClientHello record was already sent on the wire. */
    ctx->client_seq_num = 1u;
    ctx->server_seq_num = 0u;

    rc = tls12_client_apply_handshake_client_hello_transcript(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(ctx->handshake_messages) {
            free(ctx->handshake_messages);
            ctx->handshake_messages = NULL;
            ctx->handshake_messages_len = 0;
        }
        if(ctx->base.base.pending_server_hello) {
            free(ctx->base.base.pending_server_hello);
            ctx->base.base.pending_server_hello = NULL;
            ctx->base.base.pending_server_hello_len = 0;
        }
        noxtls_tls_extensions_free(&ctx->client_extensions);
        memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
        return rc;
    }

    ctx->base.base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);

    printf("[TLS12_DEBUG] noxtls_tls12_client_resume_from_tls13_downgrade: recv_server_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
    rc = noxtls_tls12_recv_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_server_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);

    printf("[TLS12_DEBUG] resume: recv_certificate...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
    rc = noxtls_tls12_recv_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_certificate rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);

    printf("[TLS12_DEBUG] resume: recv_server_key_exchange...\n");
    rc = noxtls_tls12_recv_server_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_server_key_exchange rc=%d\n", rc);
        return rc;
    }

    printf("[TLS12_DEBUG] resume: recv_server_hello_done...\n");
    rc = noxtls_tls12_recv_server_hello_done(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_server_hello_done rc=%d\n", rc);
        return rc;
    }

    printf("[TLS12_DEBUG] resume: send_client_key_exchange...\n");
    rc = noxtls_tls12_send_client_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: send_client_key_exchange rc=%d\n", rc);
        return rc;
    }

    printf("[TLS12_DEBUG] resume: compute_master_secret...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
    if(ctx->dhe_ctx != NULL) {
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = tls12_compute_master_secret(ctx, dhe_ctx->premaster_secret, dhe_ctx->premaster_secret_len);
    } else {
        rc = tls12_compute_master_secret(ctx, ctx->premaster_secret, ctx->premaster_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: compute_master_secret rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);

    printf("[TLS12_DEBUG] resume: derive_keys...\n");
    rc = tls12_derive_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: derive_keys rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, ctx->cipher_suite);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);

    printf("[TLS12_DEBUG] resume: send_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
    rc = noxtls_tls12_send_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: send_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }

    printf("[TLS12_DEBUG] resume: send_finished...\n");
    rc = noxtls_tls12_send_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: send_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);

    printf("[TLS12_DEBUG] resume: recv_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
    rc = noxtls_tls12_recv_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }

    printf("[TLS12_DEBUG] resume: recv_finished...\n");
    rc = noxtls_tls12_recv_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] resume: recv_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);

    ctx->base.base.state = TLS_STATE_CONNECTED;
    noxtls_dtls_mark_validated(&ctx->base);
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Server Hello
 */
noxtls_return_t noxtls_tls12_recv_server_hello(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_hello: Starting...\n");
    if(ctx->base.base.pending_server_hello != NULL && ctx->base.base.pending_server_hello_len > 0u) {
        record.type = TLS_RECORD_HANDSHAKE;
        record.length = ctx->base.base.pending_server_hello_len;
        record.data = ctx->base.base.pending_server_hello;
        ctx->base.base.pending_server_hello = NULL;
        ctx->base.base.pending_server_hello_len = 0;
    } else {
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_hello: Record received - type=%u, length=%u\n",
                          record.type, record.length);
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 38) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] == DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST && tls12_is_dtls(ctx)) {
        uint32_t offset = 4;
        uint8_t cookie_len;
        if(record.length < 7) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        offset += 2; /* server_version */
        cookie_len = record.data[offset++];
        if(offset + cookie_len > record.length || cookie_len > sizeof(ctx->base.cookie)) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->base.cookie, record.data + offset, cookie_len);
        ctx->base.cookie_len = cookie_len;
        if(record.data) free(record.data);

        /* Re-send ClientHello with cookie and wait for ServerHello */
        rc = noxtls_tls12_send_client_hello(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return noxtls_tls12_recv_server_hello(ctx);
    }

    if(record.data[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    
    /* Parse Server Hello (after 4-byte handshake header) */
    if(record.length < 4 + 2 + 32 + 1 + 2 + 1) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t offset = 4;
    /* Version (2 bytes) */
    offset += 2;
    /* Random (32 bytes) */
    memcpy(ctx->server_random, record.data + offset, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    /* Session ID */
    uint8_t session_id_len = record.data[offset++];
    if(offset + session_id_len > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += session_id_len;
    /* Cipher suite (2 bytes) */
    if(offset + 2 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    ctx->cipher_suite = (record.data[offset] << 8) | record.data[offset + 1];
    ctx->use_encrypt_then_mac = 0;
    ctx->extended_master_secret_negotiated = 0;
    ctx->heartbeat_negotiated = 0;
    ctx->heartbeat_peer_mode = 0;
    ctx->status_request_negotiated = 0;
    if(ctx->peer_ocsp_response != NULL) {
        noxtls_free(ctx->peer_ocsp_response);
        ctx->peer_ocsp_response = NULL;
        ctx->peer_ocsp_response_len = 0;
    }
    offset += 2;
    /* Compression method (1 byte) */
    if(offset + 1 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += 1;
    /* RFC 7250: parse ServerHello extensions for server_certificate_type (20) and client_certificate_type (19) */
    if(offset + 2 <= record.length) {
        uint16_t ext_len = (uint16_t)((record.data[offset] << 8) | record.data[offset + 1]);
        int server_etm_seen = 0;
        int server_heartbeat_seen = 0;
        offset += 2;
        if(offset + ext_len <= record.length && ext_len > 0) {
            uint32_t ext_end = offset + ext_len;
            while(offset + 4 <= ext_end) {
                uint16_t etype = (uint16_t)((record.data[offset] << 8) | record.data[offset + 1]);
                uint16_t elen  = (uint16_t)((record.data[offset + 2] << 8) | record.data[offset + 3]);
                offset += 4;
                if(offset + elen > ext_end) break;
                if(etype == TLS_EXTENSION_SERVER_CERTIFICATE_TYPE && elen >= 1) {
                    ctx->server_certificate_type = record.data[offset];
                } else if(etype == TLS_EXTENSION_CLIENT_CERTIFICATE_TYPE && elen >= 1) {
                    ctx->client_certificate_type = record.data[offset];
                } else if(etype == TLS_EXTENSION_ENCRYPT_THEN_MAC && elen == 0) {
                    server_etm_seen = 1;
                } else if(etype == TLS_EXTENSION_EXTENDED_MASTER_SECRET && elen == 0) {
                    ctx->extended_master_secret_negotiated = 1;
                } else if(etype == TLS_EXTENSION_MAX_FRAGMENT_LENGTH && elen >= 1) {
                    uint8_t mfl = record.data[offset];
                    if(mfl >= 1 && mfl <= 4) {
                        ctx->max_fragment_length_code = mfl;
                        ctx->max_record_payload = tls12_mfl_code_to_payload(mfl);
                    }
                } else if(etype == TLS_EXTENSION_STATUS_REQUEST) {
                    if(elen != 0u) {
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    if(ctx->client_request_ocsp_status == 0u) {
                        if(record.data) free(record.data);
                        if(ctx->base.base.send_callback != NULL) {
                            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
                        }
                        return NOXTLS_RETURN_NOT_SUPPORTED;
                    }
                    ctx->status_request_negotiated = 1u;
                } else if(etype == TLS_EXTENSION_HEARTBEAT) {
                    if(elen != 1u) {
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    {
                        uint8_t mode = record.data[offset];
                        if(mode != TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND &&
                           mode != TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND) {
                            if(record.data) free(record.data);
                            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
                        }
                        server_heartbeat_seen = 1;
                        ctx->heartbeat_peer_mode = mode;
                    }
                }
                offset += elen;
            }
        }
        if(server_etm_seen && tls12_suite_supports_encrypt_then_mac(ctx->cipher_suite)) {
            ctx->use_encrypt_then_mac = 1;
        }
        if(server_heartbeat_seen && ctx->heartbeat_enabled == 0u) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if(server_heartbeat_seen && ctx->heartbeat_enabled != 0u) {
            ctx->heartbeat_negotiated = 1u;
        }
    }
    (void)offset;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_hello: Completed\n");
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_SERVER_HELLO_RECV, ctx->cipher_suite, record.length);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Certificate
 */
static noxtls_return_t tls12_recv_handshake_message(tls12_context_t *ctx,
                                                    uint8_t expected_type,
                                                    uint8_t **out_msg,
                                                    uint32_t *out_len)
{
    tls_record_t record;
    uint8_t *msg;
    uint32_t hs_body_len;
    uint32_t hs_total_len;
    uint32_t copied;
    noxtls_return_t rc;

    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *out_msg = NULL;
    *out_len = 0;
    memset(&record, 0, sizeof(record));

    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length < 4 || record.data == NULL || record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    if(record.data[0] != expected_type) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    hs_body_len = ((uint32_t)record.data[1] << 16) |
                  ((uint32_t)record.data[2] << 8) |
                  (uint32_t)record.data[3];
    hs_total_len = 4u + hs_body_len;
    if(hs_total_len > (TLS_MAX_HANDSHAKE_SIZE + 4u)) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }

    msg = (uint8_t *)noxtls_malloc(hs_total_len);
    if(msg == NULL) {
        if(record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    copied = (record.length < hs_total_len) ? record.length : hs_total_len;
    memcpy(msg, record.data, copied);
    tls12_inc_recv_seq(ctx);
    if(record.data) noxtls_free(record.data);
    record.data = NULL;

    while(copied < hs_total_len) {
        uint32_t remain;
        uint32_t take;

        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(msg);
            return rc;
        }
        if(record.type != TLS_RECORD_HANDSHAKE || record.length == 0 || record.data == NULL) {
            if(record.data) noxtls_free(record.data);
            noxtls_free(msg);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        remain = hs_total_len - copied;
        take = (record.length < remain) ? record.length : remain;
        memcpy(msg + copied, record.data, take);
        copied += take;
        tls12_inc_recv_seq(ctx);
        if(record.length > take) {
            if(record.data) noxtls_free(record.data);
            noxtls_free(msg);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(record.data) noxtls_free(record.data);
        record.data = NULL;
    }

    *out_msg = msg;
    *out_len = hs_total_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Certificate
 */
noxtls_return_t noxtls_tls12_recv_certificate(tls12_context_t *ctx)
{
    uint8_t *hs_msg;
    uint32_t hs_len;
    noxtls_return_t rc;
    uint32_t cert_list_len;
    uint32_t cert_len;
    x509_certificate_chain_t presented_chain;
    uint8_t presented_chain_ready = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    hs_msg = NULL;
    hs_len = 0;
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Starting...\n");
    rc = tls12_recv_handshake_message(ctx, TLS_HANDSHAKE_CERTIFICATE, &hs_msg, &hs_len);
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: tls12_recv_handshake_message returned %d\n", rc);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CERTIFICATE_RECV, rc);
        return rc;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Record received - type=%u, length=%u\n",
                        TLS_RECORD_HANDSHAKE, hs_len);
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: hs_type=0x%02X\n",
                          hs_len > 0 ? hs_msg[0] : 0);

    if(hs_len < 7u) {
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Invalid record type or length\n");
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, TLS_RECORD_HANDSHAKE, hs_len);
        if(hs_msg) noxtls_free(hs_msg);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    
    if(hs_msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Not a certificate noxtls_message (got %u)\n",
                            hs_msg[0]);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, hs_msg[0], hs_len);
        if(hs_msg) noxtls_free(hs_msg);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Parsing certificate noxtls_message...\n");
    
    /* Parse Certificate noxtls_message */
    /* Certificate list length at offset 4-6 (after handshake header). */
    cert_list_len = ((uint32_t)hs_msg[4] << 16) | ((uint32_t)hs_msg[5] << 8) | (uint32_t)hs_msg[6];
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Certificate list length: %u\n", cert_list_len);
    
    {
        if(cert_list_len < 3 || cert_list_len > hs_len - 7u) {
            noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Invalid certificate list length\n");
            if(hs_msg) noxtls_free(hs_msg);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* First certificate length at offset 7-9 */
    cert_len = ((uint32_t)hs_msg[7] << 16) | ((uint32_t)hs_msg[8] << 8) | (uint32_t)hs_msg[9];
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: First certificate length: %u\n", cert_len);
    
    if(cert_len > cert_list_len - 3) {
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Certificate length exceeds list length\n");
        if(hs_msg) noxtls_free(hs_msg);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Allocating %u bytes for server certificate...\n", cert_len);
    
    /* Store server certificate */
    if(ctx->server_cert) {
        noxtls_free(ctx->server_cert);
    }
    ctx->server_cert = (uint8_t*)noxtls_malloc(cert_len);
    if(ctx->server_cert == NULL) {
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Memory allocation failed\n");
        if(hs_msg) noxtls_free(hs_msg);
        return NOXTLS_RETURN_FAILED;
    }
    
    memcpy(ctx->server_cert, hs_msg + 10, cert_len);
    ctx->server_cert_len = cert_len;
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Certificate stored (%u bytes)\n", cert_len);
    fflush(stdout);

    /* RFC 7250: If server chose Raw Public Key, payload is SubjectPublicKeyInfo; do not parse as X.509. Verify out-of-band. */
    if(ctx->server_certificate_type == TLS_CERT_TYPE_RAW_PUBLIC_KEY) {
        ctx->server_cert_is_rpk = 1;
        ctx->server_cert_parsed = NULL;  /* No X.509 structure; application uses server_cert (SPKI) for verification */
    } else {
        uint32_t chain_pos = 10u + cert_len;
        uint32_t chain_end = 7u + cert_list_len;
        if(noxtls_x509_certificate_chain_init(&presented_chain) != NOXTLS_RETURN_SUCCESS) {
            if(hs_msg) noxtls_free(hs_msg);
            return NOXTLS_RETURN_FAILED;
        }
        presented_chain_ready = 1;

        /* Parse the certificate as X.509 */
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Checking if server_cert_parsed needs cleanup...\n");
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: server_cert_parsed = %p\n", ctx->server_cert_parsed);
        fflush(stdout);

        if(ctx->server_cert_parsed != NULL) {
            noxtls_x509_certificate_free((x509_certificate_t *)ctx->server_cert_parsed);
            noxtls_free(ctx->server_cert_parsed);
            ctx->server_cert_parsed = NULL;
        }
        x509_certificate_t *parsed_cert = (x509_certificate_t *)noxtls_malloc(sizeof(x509_certificate_t));
        if(parsed_cert != NULL) {
            noxtls_x509_certificate_init(parsed_cert);
            noxtls_return_t parse_rc = noxtls_x509_certificate_parse_der(parsed_cert, ctx->server_cert, ctx->server_cert_len);
            if(parse_rc == NOXTLS_RETURN_SUCCESS) {
                ctx->server_cert_parsed = parsed_cert;
                /* Client: verify server cert is valid for the requested hostname (SAN or CN) */
                if(ctx->server_name != NULL && ctx->server_name_len > 0) {
                    noxtls_return_t hr = noxtls_x509_certificate_matches_hostname((x509_certificate_t*)ctx->server_cert_parsed,
                        (const char*)ctx->server_name, ctx->server_name_len);
                    if(hr != NOXTLS_RETURN_SUCCESS) {
                        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                        NOXTLS_EVT_CERT_VERIFY_FAIL, hr, ctx->server_name_len);
                        noxtls_x509_certificate_free(parsed_cert);
                        noxtls_free(parsed_cert);
                        ctx->server_cert_parsed = NULL;
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        if(hs_msg) noxtls_free(hs_msg);
                        return hr;
                    }
                }

                while(chain_pos + 3u <= chain_end) {
                    uint32_t issuer_len = ((uint32_t)hs_msg[chain_pos] << 16) |
                                          ((uint32_t)hs_msg[chain_pos + 1] << 8) |
                                          (uint32_t)hs_msg[chain_pos + 2];
                    x509_certificate_t issuer_cert;
                    chain_pos += 3u;
                    if(issuer_len == 0 || chain_pos + issuer_len > chain_end) {
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        if(hs_msg) noxtls_free(hs_msg);
                        return NOXTLS_RETURN_FAILED;
                    }

                    noxtls_x509_certificate_init(&issuer_cert);
                    rc = noxtls_x509_certificate_parse_der(&issuer_cert, hs_msg + chain_pos, issuer_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_x509_certificate_free(&issuer_cert);
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        if(hs_msg) noxtls_free(hs_msg);
                        return rc;
                    }

                    rc = noxtls_x509_certificate_chain_add(&presented_chain, &issuer_cert);
                    noxtls_x509_certificate_free(&issuer_cert);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        noxtls_x509_certificate_chain_free(&presented_chain);
                        if(hs_msg) noxtls_free(hs_msg);
                        return rc;
                    }
                    chain_pos += issuer_len;
                }

                if(chain_pos != chain_end) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    if(hs_msg) noxtls_free(hs_msg);
                    return NOXTLS_RETURN_FAILED;
                }

                rc = noxtls_x509_verify_server_cert_trust_ex((x509_certificate_t*)ctx->server_cert_parsed,
                                                             &presented_chain,
                                                             ctx->verify_crl,
                                                             NULL);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_x509_certificate_chain_free(&presented_chain);
                    noxtls_x509_certificate_free(parsed_cert);
                    noxtls_free(parsed_cert);
                    ctx->server_cert_parsed = NULL;
                    if(hs_msg) noxtls_free(hs_msg);
                    return rc;
                }
            } else {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_CERT_PARSE_FAIL, ctx->server_cert_len, cert_list_len);
                noxtls_x509_certificate_free(parsed_cert);
                noxtls_free(parsed_cert);
                noxtls_x509_certificate_chain_free(&presented_chain);
                if(hs_msg) noxtls_free(hs_msg);
                return parse_rc;
            }
        } else {
            noxtls_x509_certificate_chain_free(&presented_chain);
            if(hs_msg) noxtls_free(hs_msg);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, hs_msg, hs_len);
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Freeing record data...\n");
    fflush(stdout);
    if(hs_msg) noxtls_free(hs_msg);
    if(presented_chain_ready) {
        noxtls_x509_certificate_chain_free(&presented_chain);
    }
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Record data freed\n");
    fflush(stdout);
    
    if(ctx->status_request_negotiated != 0u) {
        rc = tls12_recv_certificate_status(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_certificate: Completed successfully\n");
    fflush(stdout);
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_CERTIFICATE_RECV, cert_len, cert_list_len);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Server Key Exchange
 */
noxtls_return_t noxtls_tls12_recv_server_key_exchange(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Starting...\n");
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Record received - type=%u, length=%u\n",
                          record.type, record.length);
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: hs_type=0x%02X\n",
                          record.length > 0 ? record.data[0] : 0);
    
    if(record.data[0] != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    
    /* Check key exchange type */
    int is_rsa_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
    int is_dhe_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
    
    if(is_dhe_kex) {
        /* DHE: Parse Server Key Exchange and compute premaster */
        uint16_t named_group;
        if(tls12_cipher_suite_to_ffdhe_group(ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)malloc(sizeof(tls_dhe_context_t));
        if(dhe_ctx == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_dhe_context_init(dhe_ctx, named_group);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(dhe_ctx);
            if(record.data) free(record.data);
            return rc;
        }
        ctx->dhe_ctx = dhe_ctx;
        rc = noxtls_tls12_dhe_recv_server_key_exchange(ctx, dhe_ctx, record.data, record.length);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls_dhe_context_free(dhe_ctx);
            free(dhe_ctx);
            ctx->dhe_ctx = NULL;
            if(record.data) free(record.data);
            return rc;
        }
        tls12_append_handshake_message(ctx, record.data, record.length);
        if(record.data) free(record.data);
        return NOXTLS_RETURN_SUCCESS;
    }
    
    if(!is_rsa_kex) {
        /* ECDHE: Parse Server Key Exchange noxtls_message first to get server's chosen curve */
        uint32_t msg_offset = 4;  /* Skip handshake header */
        uint8_t curve_type;
        uint16_t named_curve;
        uint8_t public_key_len;
        ecc_point_t peer_public_key;
        
        if(msg_offset >= record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        curve_type = record.data[msg_offset++];
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: curve_type=0x%02X\n", curve_type);
        fflush(stdout);
        
        if(curve_type != TLS_EC_CURVE_TYPE_NAMED) {  /* Must be named_curve */
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        if(msg_offset + 2 > record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        named_curve = (record.data[msg_offset] << 8) | record.data[msg_offset + 1];
        msg_offset += 2;
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: named_curve=0x%04X\n", named_curve);
        fflush(stdout);
        
        /* Only accept curves we support (P-256, P-384, P-521) */
        if(named_curve != TLS_NAMED_GROUP_SECP256R1 &&
           named_curve != TLS_NAMED_GROUP_SECP384R1 &&
           named_curve != TLS_NAMED_GROUP_SECP521R1) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != named_curve) {
            /* Create or replace ECDHE context with the curve from the server's noxtls_message */
            if(ecdhe_ctx != NULL) {
                noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                ctx->ecdhe_ctx = NULL;
            }
            noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: init ecdhe ctx (group=0x%04X)\n", named_curve);
            fflush(stdout);
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_tls_ecdhe_context_init(ecdhe_ctx, named_curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(ecdhe_ctx);
                if(record.data) free(record.data);
                return rc;
            }
            noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: noxtls_tls_ecdhe_generate_ephemeral_key...\n");
            fflush(stdout);
            rc = noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(record.data) free(record.data);
                return rc;
            }
            noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: local ephemeral key ready\n");
            fflush(stdout);
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Public key length */
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: reading public_key_len at offset=%u\n", msg_offset);
        fflush(stdout);
        if(msg_offset >= record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        public_key_len = record.data[msg_offset++];
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: public_key_len=%u\n",
                              public_key_len);
        fflush(stdout);
        
        /* Public key */
        if(msg_offset + public_key_len > record.length) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Decode peer's public key */
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Decoding peer public key...\n");
        fflush(stdout);
        rc = noxtls_tls_decode_ecc_point_uncompressed(record.data + msg_offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return rc;
        }
        
        /* Compute shared secret */
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Computing shared secret...\n");
        fflush(stdout);
        rc = noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return rc;
        }
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Shared secret computed\n");
        fflush(stdout);
        
        /* Create premaster secret from shared secret for TLS 1.2 */
        if(ecdhe_ctx->shared_secret != NULL && ecdhe_ctx->shared_secret_len > 0) {
            uint32_t premaster_len = tls12_get_ecdh_premaster_len(ecdhe_ctx->named_group);
            if(premaster_len == 0 || ecdhe_ctx->shared_secret_len < premaster_len ||
               premaster_len > sizeof(ctx->premaster_secret)) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_debug_printf("[TLS12_DEBUG] ecdhe premaster_len=%u (group=0x%04X) shared_len=%u\n",
                                  premaster_len, ecdhe_ctx->named_group, ecdhe_ctx->shared_secret_len);
            fflush(stdout);
            tls12_fill_premaster_from_shared(ctx->premaster_secret, premaster_len,
                                             ecdhe_ctx->shared_secret, premaster_len);
            ctx->premaster_secret_len = premaster_len;
            noxtls_debug_printf("[TLS12_DEBUG] ecdhe premaster[0..3]=%02X%02X%02X%02X\n",
                                  ctx->premaster_secret[0], ctx->premaster_secret[1],
                                  ctx->premaster_secret[2], ctx->premaster_secret[3]);
            fflush(stdout);
        } else {
            noxtls_debug_printf("ERROR: ECDHE shared secret not available after Server Key Exchange\n");
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_key_exchange: Completed\n");
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Server Hello Done
 */
noxtls_return_t noxtls_tls12_recv_server_hello_done(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_hello_done: Starting...\n");
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv_server_hello_done: Record received - type=%u, length=%u, hs_type=0x%02X\n",
                          record.type, record.length, record.length > 0 ? record.data[0] : 0);
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length != 4) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_SERVER_HELLO_DONE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    tls12_inc_recv_seq(ctx);
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Send Client Key Exchange
 * 
 * For RSA key exchange:
 * - Generate premaster secret (48 bytes: 2 bytes version + 46 bytes random)
 * - Encrypt with server's public key
 * - Send encrypted premaster secret
 * 
 * For ECDHE:
 * - Send client's ephemeral public key
 */
noxtls_return_t noxtls_tls12_send_client_key_exchange(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *client_key_exchange = ctx->handshake_workspace;
    if(client_key_exchange == NULL) {
        client_key_exchange = (uint8_t*)noxtls_malloc(TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
        if(client_key_exchange == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    noxtls_return_t rc;
    
    /* Build Client Key Exchange noxtls_message */
    client_key_exchange[offset++] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    client_key_exchange[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_key_exchange[offset++] = 0x00;
    client_key_exchange[offset++] = 0x00;
    
    /* Determine key exchange method based on cipher suite */
    /* Check if cipher suite uses RSA key exchange */
    int is_rsa_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
    
    if(is_rsa_kex) {
        uint8_t *encrypted_premaster = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + TLS_KEY_BLOCK_MAX_LEN) : (uint8_t*)noxtls_malloc(TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
        if(encrypted_premaster == NULL) {
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        uint32_t encrypted_premaster_len;
        /* RSA Key Exchange: Generate and encrypt premaster secret */
        /* Generate premaster secret: 2 bytes version + 46 bytes random */
        /* Premaster secret starts with negotiated TLS version (RFC 5246/4346/2246) */
        uint16_t ver = (ctx->base.base.version <= TLS_VERSION_1_1) ? ctx->base.base.version : TLS_VERSION_1_2;
        ctx->premaster_secret[0] = (ver >> 8) & 0xFF;
        ctx->premaster_secret[1] = ver & 0xFF;
        
        /* Generate 46 random bytes */
        if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        if(drbg_generate(&drbg_state, ctx->premaster_secret + 2, 46 * 8, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->premaster_secret_len = 48;

        if(ctx->server_cert_parsed == NULL) {
            noxtls_debug_printf("ERROR: RSA key exchange requires server certificate to be parsed\n");
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        {
            x509_certificate_t *cert = (x509_certificate_t *)ctx->server_cert_parsed;
            if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL) {
                noxtls_debug_printf("ERROR: Server certificate has no RSA public key\n");
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            uint32_t key_bytes = cert->rsa_modulus_len;
            rsa_key_size_t key_size;
            if(key_bytes == 128) {
                key_size = RSA_1024_BIT;
            } else if(key_bytes == 256) {
                key_size = RSA_2048_BIT;
            } else if(key_bytes == 384) {
                key_size = RSA_3072_BIT;
            } else if(key_bytes == 512) {
                key_size = RSA_4096_BIT;
            } else {
                noxtls_debug_printf("ERROR: Unsupported RSA key size %u\n", key_bytes);
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            rsa_key_t rsa_pub;
            rc = noxtls_rsa_key_init(&rsa_pub, key_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
            memcpy(rsa_pub.n, cert->rsa_modulus, cert->rsa_modulus_len);
            memcpy(rsa_pub.e, cert->rsa_exponent, cert->rsa_exponent_len);
            encrypted_premaster_len = TLS_CLIENT_KEY_EXCHANGE_MAX_LEN;
            rc = noxtls_rsa_encrypt(&rsa_pub, ctx->premaster_secret, 48, encrypted_premaster, &encrypted_premaster_len);
            noxtls_rsa_key_free(&rsa_pub);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: RSA encrypt premaster failed: %d\n", rc);
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
        }

        /* Encrypted premaster secret length (2 bytes) */
        client_key_exchange[offset++] = (encrypted_premaster_len >> 8) & 0xFF;
        client_key_exchange[offset++] = encrypted_premaster_len & 0xFF;
        
        /* Encrypted premaster secret */
        if(offset + encrypted_premaster_len > TLS_CLIENT_KEY_EXCHANGE_MAX_LEN) {
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(client_key_exchange + offset, encrypted_premaster, encrypted_premaster_len);
        offset += encrypted_premaster_len;
        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(encrypted_premaster, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN);
    } else if(ctx->dhe_ctx != NULL) {
        /* DHE: Send client's ephemeral public key */
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        client_key_exchange[offset++] = (dhe_ctx->p_len >> 8) & 0xFF;
        client_key_exchange[offset++] = dhe_ctx->p_len & 0xFF;
        if(offset + dhe_ctx->p_len > TLS_CLIENT_KEY_EXCHANGE_MAX_LEN) {
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(client_key_exchange + offset, dhe_ctx->client_public, dhe_ctx->p_len);
        offset += dhe_ctx->p_len;
    } else {
        /* ECDHE: Send client's ephemeral public key */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        
        if(ecdhe_ctx == NULL) {
            /* Initialize ECDHE context if not already done */
            uint16_t named_group;
            if(tls12_cipher_suite_to_named_curve(ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to determine named curve for cipher suite 0x%04X\n", ctx->cipher_suite);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            
            rc = noxtls_tls_ecdhe_context_init(ecdhe_ctx, named_group);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(ecdhe_ctx);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
            
            /* Generate ephemeral key pair */
            rc = noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return rc;
            }
            
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Get encoded public key */
        uint8_t public_key_encoded[133];  /* Max: 1 + 2*66 for P-521 */
        uint32_t public_key_len = sizeof(public_key_encoded);
        rc = noxtls_tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
        
        /* Public key length */
        client_key_exchange[offset++] = public_key_len & 0xFF;
        
        /* Public key */
        if(offset + public_key_len > TLS_CLIENT_KEY_EXCHANGE_MAX_LEN) {
            if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(client_key_exchange + offset, public_key_encoded, public_key_len);
        offset += public_key_len;
        
        /* Extract premaster secret from ECDHE context (should be computed after receiving server's key) */
        /* For now, we'll compute it after receiving Server Key Exchange */
    }
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    client_key_exchange[1] = (handshake_len >> 16) & 0xFF;
    client_key_exchange[2] = (handshake_len >> 8) & 0xFF;
    client_key_exchange[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, client_key_exchange, offset);
    if(ctx->extended_master_secret_negotiated) {
        ctx->ems_session_transcript_len = ctx->handshake_messages_len;
    }
    
    /* Send via record layer */
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_key_exchange, offset);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
    }
    if(client_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_key_exchange, TLS_CLIENT_KEY_EXCHANGE_MAX_LEN); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2 Client: Send Change Cipher Spec
 */
noxtls_return_t noxtls_tls12_send_change_cipher_spec(tls12_context_t *ctx)
{
    uint8_t change_cipher_spec = 0x01;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_CHANGE_CIPHER_SPEC, &change_cipher_spec, 1);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tls12_inc_send_seq(ctx);
        /* Reset sequence number for new cipher state */
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->client_seq_num = 0;
        } else {
            ctx->server_seq_num = 0;
        }
        tls12_dtls_on_send_ccs(ctx);
    }
    return rc;
}

/**
 * @brief TLS 1.2 Client: Send Finished
 */
noxtls_return_t noxtls_tls12_send_finished(tls12_context_t *ctx)
{
    uint8_t finished[TLS_MAX_SECRET_LEN];
    uint32_t offset = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Build Finished noxtls_message */
    finished[offset++] = TLS_HANDSHAKE_FINISHED;
    finished[offset++] = 0x00;  /* Length (3 bytes) */
    finished[offset++] = 0x00;
    finished[offset++] = (uint8_t)TLS_FINISHED_VERIFY_DATA_LEN_12;  /* verify_data length */
    
    /* Determine hash algorithm based on cipher suite */
    noxtls_hash_algos_t hash_algo = tls12_get_prf_hash(ctx->cipher_suite);
    
    /* Compute verify_data using PRF */
    /* verify_data = PRF(master_secret, "client finished", Hash(handshake_messages))[0..11] */
    if(tls12_compute_finished_verify_data(ctx, "client finished", finished + offset, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Save for RFC 5746 renegotiation_info in next handshake */
    memcpy(ctx->previous_client_verify_data, finished + offset, 12);
    ctx->previous_verify_data_len = 12;
    noxtls_debug_printf("[TLS12_DEBUG] send_finished: verify_data=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                          finished[offset + 0], finished[offset + 1], finished[offset + 2], finished[offset + 3],
                          finished[offset + 4], finished[offset + 5], finished[offset + 6], finished[offset + 7],
                          finished[offset + 8], finished[offset + 9], finished[offset + 10], finished[offset + 11]);
    fflush(stdout);
    offset += 12;
    
    /* Append our Finished to transcript for server Finished verification */
    tls12_append_handshake_message(ctx, finished, offset);
    
    /* After Change Cipher Spec, Finished noxtls_message must be encrypted */
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1;
    for(uint32_t k = 0; k < 32; k++) {
        if(ctx->client_write_key[k] != 0) {
            key_is_zero = 0;
            break;
        }
    }
    
    if(key_is_zero) {
        noxtls_debug_printf("WARNING: Keys are zero (placeholder RSA key), sending unencrypted Finished (for testing only!)\n");
        fflush(stdout);
        /* For testing with placeholder keys, send unencrypted */
        noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, finished, offset);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            tls12_inc_send_seq(ctx);
        }
        return rc;
    }
    
    /* Encrypt the Finished noxtls_message before sending */
    uint32_t encrypted_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;
    uint8_t *encrypted_finished = ctx->record_workspace;
    if(encrypted_finished == NULL) {
        encrypted_finished = (uint8_t*)noxtls_malloc(encrypted_len);
        if(encrypted_finished == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    noxtls_return_t rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HANDSHAKE, finished, offset,
                                               encrypted_finished, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ERROR: Failed to encrypt Finished noxtls_message: %d\n", rc);
        fflush(stdout);
        if(encrypted_finished != ctx->record_workspace) {
            noxtls_free(encrypted_finished);
        }
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, encrypted_finished, encrypted_len);
    if(encrypted_finished != ctx->record_workspace) {
        noxtls_free(encrypted_finished);
    }
    return rc;
}

/**
 * @brief TLS 1.2 Client: Receive Change Cipher Spec
 */
noxtls_return_t noxtls_tls12_recv_change_cipher_spec(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t ccs_plain[8];
    uint32_t ccs_len = sizeof(ccs_plain);
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    while(1) {
        uint32_t app_len = TLS_MAX_RECORD_SIZE;
        uint8_t *app_buf = NULL;
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            break;
        }
        if(!(ctx->renegotiation_in_progress && record.type == TLS_RECORD_APPLICATION_DATA)) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        app_buf = (ctx->record_workspace != NULL) ? ctx->record_workspace : (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE);
        if(app_buf == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                         record.data, record.length,
                                         app_buf, &app_len);
        if(record.data) free(record.data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
            return rc;
        }
        if(app_len > 0u) {
            if(ctx->pending_app_data_len + app_len > sizeof(ctx->pending_app_data)) {
                if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(ctx->pending_app_data + ctx->pending_app_data_len, app_buf, app_len);
            ctx->pending_app_data_len += app_len;
        }
        if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
    }
    if(ctx->renegotiation_in_progress) {
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_CHANGE_CIPHER_SPEC,
                                         record.data, record.length,
                                         ccs_plain, &ccs_len);
        if(record.data) free(record.data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ccs_len != 1u || ccs_plain[0] != TLS_RECORD_CCS_PAYLOAD) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(record.length != 1 || record.data == NULL || record.data[0] != TLS_RECORD_CCS_PAYLOAD) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls12_inc_recv_seq(ctx);
        if(record.data) free(record.data);
    }
    /* Reset sequence number for new cipher state (receive side). */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        ctx->server_seq_num = 0;
    } else {
        ctx->client_seq_num = 0;
    }
    tls12_dtls_on_recv_ccs(ctx);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Client: Receive Finished
 */
noxtls_return_t noxtls_tls12_recv_finished(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] recv_finished: record type=%u len=%u\n", record.type, record.length);
    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t *finished_msg = record.data;
    uint32_t finished_len = record.length;
    uint32_t decrypted_len = TLS_MAX_RECORD_SIZE + TLS_MAX_SECRET_LEN;
    uint8_t *decrypted = ctx->record_workspace;  /* workspace is >= TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD */
    if(decrypted == NULL) {
        decrypted = (uint8_t*)noxtls_malloc(decrypted_len);
        if(decrypted == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    /* Finished is encrypted after ChangeCipherSpec */
    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_return_t dec_rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HANDSHAKE,
                                                        record.data, record.length,
                                                        decrypted, &decrypted_len);
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished: decrypt rc=%d dec_len=%u\n", (int)dec_rc, decrypted_len);
        if(record.data) {
            free(record.data);
            record.data = NULL;
        }
        if(dec_rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_DECRYPT_FAIL, dec_rc, record.length);
            if(decrypted != ctx->record_workspace) {
                noxtls_free(decrypted);
            }
            return dec_rc;
        }
        finished_msg = decrypted;
        finished_len = decrypted_len;
    }

    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished: bad decrypted header type=%u len=%u\n",
                              finished_msg[0], finished_len);
        if(decrypted != ctx->record_workspace) {
            noxtls_free(decrypted);
        }
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify finished noxtls_message */
    /* verify_data = PRF(master_secret, "server finished", Hash(handshake_messages))[0..11] */
    noxtls_hash_algos_t hash_algo = tls12_get_prf_hash(ctx->cipher_suite);
    
    uint8_t computed_verify_data[12];
    if(tls12_compute_finished_verify_data(ctx, "server finished", computed_verify_data, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Save server verify_data for RFC 5746 renegotiation_info */
    memcpy(ctx->previous_server_verify_data, finished_msg + 4, 12);
    /* Compare verify_data (starts at offset 4 in Finished noxtls_message) */
    if(noxtls_secret_memcmp(finished_msg + 4, computed_verify_data, 12) != 0) {
        noxtls_debug_printf("ERROR: Finished noxtls_message verification failed!\n");
        noxtls_debug_printf("  received: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", finished_msg[4 + i]);
        noxtls_debug_printf("\n  expected: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", computed_verify_data[i]);
        noxtls_debug_printf("\n");
        fflush(stdout);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append peer Finished to transcript for any subsequent verify */
    tls12_append_handshake_message(ctx, finished_msg, finished_len);

    if(record.data) free(record.data);
    if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Send HelloRequest to ask client to renegotiate (RFC 5746).
 */
noxtls_return_t noxtls_tls12_send_hello_request(tls12_context_t *ctx)
{
    uint8_t hello_request[4];
    uint8_t encrypted[TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD];
    uint32_t encrypted_len = sizeof(encrypted);
    noxtls_return_t rc;
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER || ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    hello_request[0] = TLS_HANDSHAKE_HELLO_REQUEST;
    hello_request[1] = 0x00;
    hello_request[2] = 0x00;
    hello_request[3] = 0x00;
    rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HANDSHAKE,
                                     hello_request, sizeof(hello_request),
                                     encrypted, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, encrypted, encrypted_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ctx->server_renegotiation_requested = 1;
    }
    return rc;
}

/**
 * @brief TLS 1.2 Client: Connect
 */
noxtls_return_t noxtls_tls12_connect(tls12_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    /* Send Client Hello */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: send_client_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_CH);
    rc = noxtls_tls12_send_client_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: send_client_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
    
    /* Receive Server Hello */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
    rc = noxtls_tls12_recv_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
    
    /* Receive Certificate */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_certificate...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
    rc = noxtls_tls12_recv_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_certificate rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
    
    /* Receive Server Key Exchange */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_key_exchange...\n");
    rc = noxtls_tls12_recv_server_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_key_exchange rc=%d\n", rc);
        return rc;
    }
    
    /* Receive Server Hello Done */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_hello_done...\n");
    rc = noxtls_tls12_recv_server_hello_done(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_server_hello_done rc=%d\n", rc);
        return rc;
    }
    
    /* Send Client Key Exchange */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: send_client_key_exchange...\n");
    rc = noxtls_tls12_send_client_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: send_client_key_exchange rc=%d\n", rc);
        return rc;
    }
    
    /* Compute master secret from premaster secret */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: compute_master_secret...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
    if(ctx->dhe_ctx != NULL) {
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = tls12_compute_master_secret(ctx, dhe_ctx->premaster_secret, dhe_ctx->premaster_secret_len);
    } else {
        rc = tls12_compute_master_secret(ctx, ctx->premaster_secret, ctx->premaster_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: compute_master_secret rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);
    
    /* Derive keys from master secret */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: derive_keys...\n");
    rc = tls12_derive_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: derive_keys rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, ctx->cipher_suite);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
    
    /* Send Change Cipher Spec */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: send_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
    rc = noxtls_tls12_send_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: send_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    
    /* Send Finished */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: send_finished...\n");
    rc = noxtls_tls12_send_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: send_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
    
    /* Receive Change Cipher Spec */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_change_cipher_spec...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
    rc = noxtls_tls12_recv_change_cipher_spec(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_change_cipher_spec rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    
    /* Receive Finished */
    printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_finished...\n");
    rc = noxtls_tls12_recv_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] noxtls_tls12_connect: recv_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
    
    ctx->base.base.state = TLS_STATE_CONNECTED;
    noxtls_dtls_mark_validated(&ctx->base);
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Process ALPN after ClientHello extension parse; sends fatal alerts on failure. */
static noxtls_return_t tls12_process_alpn_negotiation(tls12_context_t *ctx)
{
    noxtls_tls_alpn_status_t alpn_status;
    uint16_t selected_len = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->negotiated_alpn_len = 0;
    memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));

    alpn_status = noxtls_tls_alpn_server_process(&ctx->client_extensions,
                                                ctx->server_alpn_protocols,
                                                ctx->server_alpn_count,
                                                (char *)ctx->negotiated_alpn,
                                                sizeof(ctx->negotiated_alpn) - 1u,
                                                &selected_len);
    if(alpn_status == NOXTLS_TLS_ALPN_STATUS_NONE) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(alpn_status == NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(alpn_status == NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_NO_APPLICATION_PROTOCOL);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    ctx->negotiated_alpn_len = selected_len;
    return NOXTLS_RETURN_SUCCESS;
}

/* RFC 7919 / tlsfuzzer: RSA vs DHE cipher helpers and RSA fallback when no FFDHE overlap (ClientHello paths). */
static int tls12_suite_is_pure_rsa_key_exchange(uint16_t cs)
{
    return (cs == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
}

/* TLS 1.3 cipher suite IDs (RFC 8446, IANA 0x1300–0x13FF) may appear in ClientHello for
 * compatibility but must not be selected for a TLS 1.2 handshake. */
static int tls12_cipher_suite_wire_is_tls13_range(uint16_t cs)
{
    return (cs >= 0x1300u && cs <= 0x13FFu) ? 1 : 0;
}

static int tls12_suite_requires_ffdhe_server_key_exchange(uint16_t cs)
{
    return (cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
}

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): parser inputs are intentionally grouped by ClientHello layout. */
static uint16_t tls12_select_rsa_fallback_from_client(
    const uint8_t *ch_buf,
    uint32_t cipher_suites_offset, /* NOLINT(bugprone-easily-swappable-parameters): client list bounds are paired protocol fields */
    uint32_t cipher_suites_count,
    const uint16_t *supported_suites,
    uint32_t num_supported)
{
    uint32_t j, i;
    for(j = 0; j < num_supported; j++) {
        uint16_t srv = supported_suites[j];
        if(tls12_cipher_suite_wire_is_tls13_range(srv)) {
            continue;
        }
        if(!tls12_suite_is_pure_rsa_key_exchange(srv)) {
            continue;
        }
        for(i = 0; i < cipher_suites_count; i++) {
            uint16_t cs = (uint16_t)((ch_buf[cipher_suites_offset + i * 2u] << 8) |
                                    ch_buf[cipher_suites_offset + i * 2u + 1u]);
            if(cs == srv) {
                return srv;
            }
        }
    }
    return 0;
}

/* Pick first client-offered DHE_RSA suite that the server policy allows (client order wins). */
static uint16_t tls12_select_dhe_rsa_fallback_from_client(
    const uint8_t *ch_buf,
    uint32_t cipher_suites_offset,
    uint32_t cipher_suites_count,
    const uint16_t *supported_suites,
    uint32_t num_supported)
{
    uint32_t i, j;
    for(i = 0; i < cipher_suites_count; i++) {
        uint16_t cs = (uint16_t)((ch_buf[cipher_suites_offset + i * 2u] << 8) |
                                ch_buf[cipher_suites_offset + i * 2u + 1u]);
        if(!tls12_suite_requires_ffdhe_server_key_exchange(cs)) {
            continue;
        }
        for(j = 0; j < num_supported; j++) {
            if(tls12_cipher_suite_wire_is_tls13_range(supported_suites[j])) {
                continue;
            }
            if(supported_suites[j] == cs) {
                return cs;
            }
        }
    }
    return 0;
}

/**
 * If the negotiated cipher needs ECDHE but no mutually supported curve exists for the
 * ClientHello supported_groups offer, fall back to a client-offered DHE_RSA suite or fail
 * with fatal handshake_failure before ServerHello (tlsfuzzer test_x25519 expectations).
 */
static noxtls_return_t tls12_maybe_ecdhe_group_downgrade_cipher(
    tls12_context_t *ctx,
    const uint8_t *ch_buf,
    uint32_t cipher_suites_offset,
    uint32_t cipher_suites_count,
    const uint16_t *supported_suites,
    uint32_t num_supported)
{
    uint16_t ng_probe = 0;

    if(ctx == NULL || ch_buf == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->session_resume || ctx->renegotiation_in_progress) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls12_suite_is_pure_rsa_key_exchange(ctx->cipher_suite) ||
       tls12_suite_requires_ffdhe_server_key_exchange(ctx->cipher_suite)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls12_select_ecdhe_named_group(ctx, ctx->cipher_suite, &ng_probe) == NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }
    {
        uint16_t fb = tls12_select_dhe_rsa_fallback_from_client(ch_buf, cipher_suites_offset,
                                                                cipher_suites_count,
                                                                supported_suites, num_supported);
        if(fb != 0u) {
            if(ctx->ecdhe_ctx != NULL) {
                noxtls_tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
                free(ctx->ecdhe_ctx);
                ctx->ecdhe_ctx = NULL;
            }
            ctx->cipher_suite = fb;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if(ctx->base.base.send_callback != NULL) {
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static int tls12_cs_is_rsa_key_exchange_suite(uint16_t cs)
{
    return (cs == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
            cs == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
}

static int tls12_cs_is_dhe_rsa_suite(uint16_t cs)
{
    return (cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
            cs == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
}

static int tls12_server_needs_rsa_skx_sig_prepare(const tls12_context_t *ctx)
{
    uint16_t cs;
    if(ctx == NULL || ctx->session_resume != 0) {
        return 0;
    }
    cs = ctx->cipher_suite;
    if(tls12_cipher_suite_is_ecdhe_ecdsa(cs)) {
        return 0;
    }
    if(tls12_cs_is_rsa_key_exchange_suite(cs)) {
        return 0;
    }
    if(tls12_cs_is_dhe_rsa_suite(cs)) {
        return 1;
    }
    /* ECDHE_RSA (ECDHE without ECDSA suite id). */
    return 1;
}

/**
 * @brief TLS 1.2 Server: Receive Client Hello
 */
noxtls_return_t noxtls_tls12_recv_client_hello(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t offset;
    uint16_t version;
    uint8_t session_id_len;
    const uint8_t *client_session_id = NULL;
    uint16_t cipher_suites_len;
    uint32_t cipher_suites_offset;
    uint8_t compression_methods_len;
    uint8_t use_pending = 0;
    (void)use_pending;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check if we have a pending Client Hello from version negotiation */
    if(ctx->base.base.pending_client_hello != NULL && ctx->base.base.pending_client_hello_len > 0) {
        record.type = TLS_RECORD_HANDSHAKE;
        record.version = TLS_VERSION_1_2;  /* Legacy version for TLS 1.2 */
        (void)record.version;
        if(ctx->base.base.pending_client_hello_len > TLS_MAX_CLIENT_HELLO_BYTES) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            return NOXTLS_RETURN_FAILED;
        }
        record.length = (uint32_t)ctx->base.base.pending_client_hello_len;
        record.data = (uint8_t*)malloc((size_t)record.length);
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(record.data, ctx->base.base.pending_client_hello, (size_t)record.length);
        use_pending = 1;
    } else {
        tls_record_t next_record;
        uint32_t assembled_len;
        uint32_t client_hello_total_len;

        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(record.type != TLS_RECORD_HANDSHAKE) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
        if(record.length < 1u) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
        if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
        tls12_inc_recv_seq(ctx);
        assembled_len = (uint32_t)record.length;
        while(assembled_len < 4u) {
            rc = noxtls_tls_recv_record(&ctx->base.base, &next_record);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(record.data) {
                    free(record.data);
                }
                return rc;
            }
            if(next_record.length > 0u && next_record.data == NULL) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            if(next_record.type != TLS_RECORD_HANDSHAKE) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            if(next_record.length > UINT32_MAX - assembled_len) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            {
                uint8_t *new_buf = (uint8_t*)realloc(record.data, assembled_len + (uint32_t)next_record.length);
                if(new_buf == NULL) {
                    if(next_record.data) {
                        free(next_record.data);
                    }
                    if(record.data) {
                        free(record.data);
                    }
                    return NOXTLS_RETURN_FAILED;
                }
                record.data = new_buf;
            }
            if(next_record.length > 0u && next_record.data != NULL) {
                memcpy(record.data + assembled_len, next_record.data, next_record.length);
            }
            assembled_len += (uint32_t)next_record.length;
            if(next_record.data) {
                free(next_record.data);
            }
            tls12_inc_recv_seq(ctx);
        }
        client_hello_total_len = 4u + (((uint32_t)record.data[1] << 16) |
                                       ((uint32_t)record.data[2] << 8) |
                                       (uint32_t)record.data[3]);
        if(client_hello_total_len > TLS_MAX_CLIENT_HELLO_BYTES || client_hello_total_len < 38u) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
        while(assembled_len < client_hello_total_len) {
            rc = noxtls_tls_recv_record(&ctx->base.base, &next_record);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(record.data) {
                    free(record.data);
                }
                return rc;
            }
            if(next_record.length > 0 && next_record.data == NULL) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            if(next_record.type != TLS_RECORD_HANDSHAKE) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            if(next_record.length > UINT32_MAX - assembled_len) {
                if(next_record.data) {
                    free(next_record.data);
                }
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                }
                if(record.data) {
                    free(record.data);
                }
                return NOXTLS_RETURN_FAILED;
            }
            {
                uint8_t *new_buf = (uint8_t*)realloc(record.data, assembled_len + (uint32_t)next_record.length);
                if(new_buf == NULL) {
                    if(next_record.data) {
                        free(next_record.data);
                    }
                    if(record.data) {
                        free(record.data);
                    }
                    return NOXTLS_RETURN_FAILED;
                }
                record.data = new_buf;
            }
            if(next_record.length > 0 && next_record.data != NULL) {
                memcpy(record.data + assembled_len, next_record.data, next_record.length);
            }
            assembled_len += (uint32_t)next_record.length;
            if(next_record.data) {
                free(next_record.data);
            }
            tls12_inc_recv_seq(ctx);
        }
        if(assembled_len != client_hello_total_len) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
        record.length = client_hello_total_len;
    }
    if(use_pending && ctx->base.base.pending_client_hello != NULL) {
        free(ctx->base.base.pending_client_hello);
        ctx->base.base.pending_client_hello = NULL;
        ctx->base.base.pending_client_hello_len = 0;
    }

    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    if(record.length < 38u) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }

    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    if(use_pending) {
        uint32_t pending_tot = 4u + (((uint32_t)record.data[1] << 16) |
                                     ((uint32_t)record.data[2] << 8) |
                                     (uint32_t)record.data[3]);
        if(record.length != pending_tot || pending_tot < 38u || pending_tot > TLS_MAX_CLIENT_HELLO_BYTES) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_FAILED;
        }
    }

    offset = 4;  /* Skip handshake header */
    
    noxtls_tls_extensions_free(&ctx->client_extensions);
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    ctx->client_secure_renegotiation_offered = 0;
    ctx->client_encrypt_then_mac_offered = 0;
    ctx->use_encrypt_then_mac = 0;
    ctx->client_heartbeat_mode = 0;
    ctx->heartbeat_negotiated = 0;
    ctx->heartbeat_peer_mode = 0;
    ctx->session_resume = 0;
    ctx->session_resume_ems = 0;
    ctx->server_session_id_len = 0;
    ctx->extended_master_secret_offered = 0;
    ctx->extended_master_secret_negotiated = 0;
    ctx->ems_session_transcript_len = 0;
    
    /* Version */
    if(offset + 2u > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    version = (record.data[offset] << 8) | record.data[offset + 1];
    ctx->client_hello_version = version;
    offset += 2;
    
    /* Client Random (32 bytes) */
    if(offset + 32u > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_random, record.data + offset, 32);
    offset += 32;
    
    /* Session ID length */
    if(offset >= record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    session_id_len = record.data[offset++];
    if(session_id_len > TLS_SESSION_ID_MAX_LEN || offset + session_id_len > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    client_session_id = record.data + offset;
    if(session_id_len > 0 && !ctx->renegotiation_in_progress) {
        tls12_session_cache_entry_t *entry = tls12_session_cache_find(client_session_id, session_id_len);
        if(entry != NULL) {
            ctx->session_resume = 1;
            ctx->server_session_id_len = session_id_len;
            memcpy(ctx->server_session_id, client_session_id, session_id_len);
            memcpy(ctx->master_secret, entry->master_secret, sizeof(ctx->master_secret));
            ctx->session_resume_ems = entry->extended_master_secret;
        }
    }
    offset += session_id_len;
    
    if(tls12_is_dtls(ctx)) {
        uint8_t cookie_len;
        if(offset >= record.length) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        cookie_len = record.data[offset++];
        if(offset + cookie_len > record.length) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(cookie_len == 0 ||
           noxtls_dtls_verify_cookie(&ctx->base, record.data + offset, cookie_len) != NOXTLS_RETURN_SUCCESS) {
            rc = tls12_send_hello_verify_request(ctx, record.data, record.length);
            if(record.data) free(record.data);
            return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_TIMEOUT : rc;
        }
        offset += cookie_len;
    }
    
    /* Cipher suites length */
    if(offset + 2u > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    if(cipher_suites_len == 0u ||
       (cipher_suites_len & 1u) != 0u ||
       offset + cipher_suites_len > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }
    cipher_suites_offset = offset;
    /*
     * Cipher-suite list for ClientHello.version < TLS 1.2 is the small RSA/3DES
     * set used only when TLS 1.0/1.1 are enabled. ClientHello.version 0x0300
     * (SSL 3.0) is still seen as a legacy wire marker with TLS 1.2 suites
     * (tlsfuzzer default record version, middleboxes). Treat 0x0300 like TLS 1.2
     * for suite matching; we do not implement SSL 3.0 or TLS 1.0/1.1 handshakes.
     * ctx->client_hello_version stays the on-wire value (e.g. BEAST split logic).
     */
    int legacy_client_hello_cipher_matrix =
        (version < TLS_VERSION_1_2 && version != (uint16_t)0x0300);
    
    /* Parse and select cipher suite from client's list */
    uint16_t selected_suite = 0;
    uint16_t supported_suites_10_11[] = {
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
    };
    /* When the application does not set server_cipher_suites: prefer FS + AEAD only (see https_server TLS12_FALLBACK_DEFAULT_SUITES). */
    uint16_t supported_suites_12[] = {
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
        ,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
        TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
        TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
#endif
    };
    uint16_t *default_suites = legacy_client_hello_cipher_matrix ? supported_suites_10_11 : supported_suites_12;
    uint32_t default_count = legacy_client_hello_cipher_matrix
        ? (sizeof(supported_suites_10_11) / sizeof(supported_suites_10_11[0]))
        : (sizeof(supported_suites_12) / sizeof(supported_suites_12[0]));
    const uint16_t *supported_suites = default_suites;
    uint32_t num_supported = default_count;
    uint16_t legacy_allow[96];
    uint32_t legacy_allow_count = 0;

    if(legacy_client_hello_cipher_matrix) {
        if(ctx->server_cipher_suites != NULL && ctx->server_cipher_suites_count > 0) {
            for(uint32_t k = 0; k < ctx->server_cipher_suites_count &&
                               legacy_allow_count < (sizeof(legacy_allow) / sizeof(legacy_allow[0])); k++) {
                uint16_t srv = ctx->server_cipher_suites[k];
                if(tls12_cipher_suite_wire_is_tls13_range(srv)) {
                    continue;
                }
                for(uint32_t z = 0; z < default_count; z++) {
                    if(srv == default_suites[z]) {
                        legacy_allow[legacy_allow_count++] = srv;
                        break;
                    }
                }
            }
            supported_suites = legacy_allow;
            num_supported = legacy_allow_count;
        }
    } else if(ctx->server_cipher_suites != NULL && ctx->server_cipher_suites_count > 0) {
        supported_suites = ctx->server_cipher_suites;
        num_supported = ctx->server_cipher_suites_count;
    }
    uint32_t cipher_suites_count = (uint32_t)cipher_suites_len >> 1;

    {
        uint32_t cs0 = offset;
        for(uint32_t si = 0; si < cipher_suites_count; si++) {
            uint16_t cs = (record.data[cs0 + si * 2] << 8) | record.data[cs0 + si * 2 + 1];
            if(cs == TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV) {
                ctx->client_secure_renegotiation_offered = 1;
                break;
            }
        }
    }

    noxtls_debug_printf("[TLS12_DEBUG] Client offered %u cipher suite(s):\n", (unsigned)cipher_suites_count);
    for(uint32_t i = 0; i < cipher_suites_count; i++) {
        uint16_t offered_suite = (record.data[offset + i*2] << 8) | record.data[offset + i*2 + 1];
        noxtls_debug_printf("  [TLS12_DEBUG] offered[%u] = 0x%04X\n", (unsigned)i, (unsigned)offered_suite);
    }
    fflush(stdout);
    
    for(uint32_t j = 0; j < num_supported; j++) {
        uint16_t srv = supported_suites[j];
        if(tls12_cipher_suite_wire_is_tls13_range(srv)) {
            continue;
        }
        for(uint32_t i = 0; i < cipher_suites_count; i++) {
            uint16_t client_suite = (record.data[offset + i * 2u] << 8) | record.data[offset + i * 2u + 1u];
            if(client_suite == srv) {
                selected_suite = client_suite;
                break;
            }
        }
        if(selected_suite != 0) {
            break;
        }
    }
    
    ctx->cipher_suite = selected_suite;
    noxtls_debug_printf("Selected cipher suite: 0x%04X\n", ctx->cipher_suite);
    fflush(stdout);
    offset += cipher_suites_len;
    
    /* Compression methods length */
    if(offset >= record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    compression_methods_len = record.data[offset++];
    if(compression_methods_len == 0u || offset + compression_methods_len > record.length) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
        }
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint32_t ci;
        int have_null = 0;
        for(ci = 0; ci < (uint32_t)compression_methods_len; ci++) {
            if(record.data[offset + ci] == 0u) {
                have_null = 1;
                break;
            }
        }
        if(!have_null) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
            }
            if(record.data) free(record.data);
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    offset += compression_methods_len;
    
    /* Parse extensions if present */
    if(offset < record.length) {
        uint32_t extensions_len = record.length - offset;
        if(extensions_len >= 2) {
            noxtls_return_t ext_rc = noxtls_tls_parse_extensions(record.data + offset, extensions_len, &ctx->client_extensions);
            if(ext_rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_tls_extensions_free(&ctx->client_extensions);
                memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                if(ctx->base.base.send_callback != NULL) {
                    if(ext_rc == NOXTLS_RETURN_BAD_DATA) {
                        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                    } else if(ext_rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER) {
                        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
                    } else {
                        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                    }
                }
                if(record.data) {
                    free(record.data);
                }
                return ext_rc;
            }
            {
                tls_extension_t *ext_reneg = NULL;
                tls_extension_t *ext_etm = NULL;
                tls_extension_t *ext_hb = NULL;
                tls_extension_t *ext_status = NULL;
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_RENEGOTIATION_INFO, &ext_reneg) == NOXTLS_RETURN_SUCCESS &&
                   ext_reneg != NULL) {
                    ctx->client_secure_renegotiation_offered = 1;
                }
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_ENCRYPT_THEN_MAC, &ext_etm) == NOXTLS_RETURN_SUCCESS &&
                   ext_etm != NULL && ext_etm->length == 0) {
                    ctx->client_encrypt_then_mac_offered = 1;
                }
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_HEARTBEAT, &ext_hb) == NOXTLS_RETURN_SUCCESS &&
                   ext_hb != NULL) {
                    if(ext_hb->length != 1u || ext_hb->data == NULL) {
                        if(ctx->base.base.send_callback != NULL) {
                            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                        }
                        noxtls_tls_extensions_free(&ctx->client_extensions);
                        memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                        if(record.data) {
                            free(record.data);
                        }
                        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                    }
                    if(ext_hb->data[0] != TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND &&
                       ext_hb->data[0] != TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND) {
                        if(ctx->base.base.send_callback != NULL) {
                            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
                        }
                        noxtls_tls_extensions_free(&ctx->client_extensions);
                        memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                        if(record.data) {
                            free(record.data);
                        }
                        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
                    }
                    ctx->client_heartbeat_mode = ext_hb->data[0];
                }
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_STATUS_REQUEST, &ext_status) == NOXTLS_RETURN_SUCCESS &&
                   ext_status != NULL) {
                    if(ext_status->data == NULL || ext_status->length < 5u) {
                        if(ctx->base.base.send_callback != NULL) {
                            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                        }
                        noxtls_tls_extensions_free(&ctx->client_extensions);
                        memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                        if(record.data) {
                            free(record.data);
                        }
                        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                    }
                    if(ext_status->data[0] == 0x01u) { /* ocsp */
                        uint16_t responder_id_list_len = (uint16_t)(((uint16_t)ext_status->data[1] << 8) | ext_status->data[2]);
                        uint32_t pos = 3u;
                        uint16_t request_extensions_len;
                        if(pos + responder_id_list_len + 2u > ext_status->length) {
                            if(ctx->base.base.send_callback != NULL) {
                                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                            }
                            noxtls_tls_extensions_free(&ctx->client_extensions);
                            memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                            if(record.data) {
                                free(record.data);
                            }
                            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                        }
                        pos += responder_id_list_len;
                        request_extensions_len = (uint16_t)(((uint16_t)ext_status->data[pos] << 8) | ext_status->data[pos + 1u]);
                        pos += 2u;
                        if(pos + request_extensions_len != ext_status->length) {
                            if(ctx->base.base.send_callback != NULL) {
                                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                            }
                            noxtls_tls_extensions_free(&ctx->client_extensions);
                            memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                            if(record.data) {
                                free(record.data);
                            }
                            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                        }
                        ctx->client_offered_ocsp_status = 1u;
                    }
                }
            }
            /* RFC 6066: accept client's max_fragment_length if present and valid */
            {
                tls_extension_t *ext_mfl = NULL;
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_MAX_FRAGMENT_LENGTH, &ext_mfl) == NOXTLS_RETURN_SUCCESS &&
                   ext_mfl != NULL && ext_mfl->data != NULL && ext_mfl->length >= 1) {
                    uint8_t mfl = ext_mfl->data[0];
                    if(mfl >= 1 && mfl <= 4) {
                        ctx->max_fragment_length_code = mfl;
                        ctx->max_record_payload = tls12_mfl_code_to_payload(mfl);
                    }
                }
            }
            {
                noxtls_return_t alpn_rc = tls12_process_alpn_negotiation(ctx);
                if(alpn_rc != NOXTLS_RETURN_SUCCESS) {
                    if(record.data) {
                        free(record.data);
                    }
                    return alpn_rc;
                }
            }
            if(selected_suite != 0u &&
               !ctx->session_resume && !ctx->renegotiation_in_progress &&
               tls12_suite_requires_ffdhe_server_key_exchange(ctx->cipher_suite)) {
                uint16_t ng_probe = 0;
                if(tls12_select_ffdhe_named_group(ctx, ctx->cipher_suite, &ng_probe) != NOXTLS_RETURN_SUCCESS) {
                    uint16_t fb = tls12_select_rsa_fallback_from_client(record.data, cipher_suites_offset,
                                                                        cipher_suites_count,
                                                                        supported_suites, num_supported);
                    if(fb != 0u) {
                        ctx->cipher_suite = fb;
                    } else {
                        if(ctx->base.base.send_callback != NULL) {
                            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL,
                                                        TLS_ALERT_INSUFFICIENT_SECURITY);
                        }
                        noxtls_tls_extensions_free(&ctx->client_extensions);
                        memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
                        if(record.data) {
                            free(record.data);
                        }
                        return NOXTLS_RETURN_NOT_SUPPORTED;
                    }
                }
            }
            if(selected_suite != 0u && !ctx->session_resume && !ctx->renegotiation_in_progress) {
                noxtls_return_t ecdhe_down_rc = tls12_maybe_ecdhe_group_downgrade_cipher(
                    ctx, record.data, cipher_suites_offset, cipher_suites_count,
                    supported_suites, num_supported);
                if(ecdhe_down_rc != NOXTLS_RETURN_SUCCESS) {
                    if(record.data) {
                        free(record.data);
                    }
                    return ecdhe_down_rc;
                }
            }
            if(selected_suite != 0u && !ctx->session_resume && !ctx->renegotiation_in_progress) {
                tls12_maybe_upgrade_rsa_to_dhe_for_fs(ctx, record.data, record.length,
                                                        cipher_suites_offset, cipher_suites_count);
            }
            if(!ctx->session_resume && !ctx->renegotiation_in_progress) {
                tls_extension_t *ext_st = NULL;
                if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SESSION_TICKET, &ext_st) == NOXTLS_RETURN_SUCCESS &&
                   ext_st != NULL && ext_st->data != NULL && ext_st->length > 0) {
                    tls12_ticket_cache_entry_t *ticket_entry =
                        tls12_ticket_cache_find(ext_st->data, (uint16_t)ext_st->length);
                    if(ticket_entry != NULL &&
                       tls12_client_offered_cipher(record.data, record.length,
                                                  cipher_suites_offset,
                                                  cipher_suites_count,
                                                  ticket_entry->cipher_suite)) {
                        ctx->session_resume = 1;
                        ctx->cipher_suite = ticket_entry->cipher_suite;
                        memcpy(ctx->master_secret, ticket_entry->master_secret, sizeof(ctx->master_secret));
                        ctx->session_resume_ems = ticket_entry->extended_master_secret;
                        if(ticket_entry->alpn_len > 0) {
                            ctx->negotiated_alpn_len = ticket_entry->alpn_len;
                            memcpy(ctx->negotiated_alpn, ticket_entry->alpn, ticket_entry->alpn_len);
                        } else {
                            ctx->negotiated_alpn_len = 0;
                            memset(ctx->negotiated_alpn, 0, sizeof(ctx->negotiated_alpn));
                        }
                        if(session_id_len > 0 && session_id_len <= TLS_SESSION_ID_MAX_LEN) {
                            ctx->server_session_id_len = session_id_len;
                            memcpy(ctx->server_session_id, client_session_id, session_id_len);
                        } else {
                            ctx->server_session_id_len = 0;
                        }
                    }
                }
            }
            {
                noxtls_return_t ems_rc = tls12_validate_client_ems_extension(ctx);
                if(ems_rc != NOXTLS_RETURN_SUCCESS) {
                    if(record.data) {
                        free(record.data);
                    }
                    return ems_rc;
                }
            }
        } else {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    if(selected_suite == 0u && !ctx->session_resume) {
        noxtls_debug_printf("ERROR: No supported cipher suite found in client's list\n");
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
        }
        if(record.data) {
            free(record.data);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    tls12_invalidate_resume_if_sni_mismatch(ctx, client_session_id, session_id_len);
    if(ctx->client_encrypt_then_mac_offered && tls12_suite_supports_encrypt_then_mac(ctx->cipher_suite)) {
        ctx->use_encrypt_then_mac = 1;
    }
    if(!ctx->session_resume && !ctx->renegotiation_in_progress && ctx->server_session_id_len == 0) {
        (void)tls12_session_cache_generate_id(ctx->server_session_id, &ctx->server_session_id_len);
    }
    {
        noxtls_return_t ems_rc = tls12_resume_ems_policy(ctx);
        if(ems_rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) {
                free(record.data);
            }
            return ems_rc;
        }
    }

    /* TLS 1.2: require a usable signature_algorithms entry for ECDHE-ECDSA before ServerHello (tlsfuzzer brainpool-only probes). */
    if(!ctx->session_resume && tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite)) {
        uint8_t skx_probe_wire;
        noxtls_hash_algos_t skx_probe_hash;
        if(noxtls_tls12_pick_ecdsa_skx_sig_hash(ctx, &skx_probe_wire, &skx_probe_hash) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }

    /* TLS 1.2: require a usable RSA/DHE-RSA/ECDHE-RSA ServerKeyExchange signature scheme before ServerHello. */
    if(!ctx->session_resume && tls12_server_needs_rsa_skx_sig_prepare(ctx)) {
        if(noxtls_tls12_prepare_rsa_server_key_exchange_scheme(ctx) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
            }
            if(record.data) {
                free(record.data);
            }
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, record.data, record.length);
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Send Server Hello
 */
noxtls_return_t noxtls_tls12_send_server_hello(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *server_hello = ctx->handshake_workspace;
    if(server_hello == NULL) {
        server_hello = (uint8_t*)noxtls_malloc(TLS_SERVER_HELLO_DEFAULT_SIZE);
        if(server_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    noxtls_return_t rc;
    
    /* Generate server random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->server_random, 256, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    /* RFC 8446 §4.1.3: server that also supports TLS 1.3 must signal TLS 1.2 downgrade in ServerHello.random. */
    if(ctx->rfc8446_tls13_downgrade_sh_random != 0 &&
       ctx->base.base.role == TLS_ROLE_SERVER &&
       !tls12_is_dtls(ctx) &&
       ctx->base.base.version == TLS_VERSION_1_2) {
        static const uint8_t tls13_downgrade_suffix[8] = {
            0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
        };
        memcpy(ctx->server_random + 24, tls13_downgrade_suffix, sizeof(tls13_downgrade_suffix));
    }

    /* Build Server Hello noxtls_message */
    server_hello[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    server_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;
    
    /* Version (negotiated; TLS 1.0/1.1 or 1.2) */
    uint16_t ver = tls12_is_dtls(ctx) ? (uint16_t)DTLS_VERSION_1_2 : ctx->base.base.version;
    server_hello[offset++] = (ver >> 8) & 0xFF;
    server_hello[offset++] = ver & 0xFF;
    
    /* Random (32 bytes) */
    memcpy(server_hello + offset, ctx->server_random, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Session ID length (1 byte) */
    if(ctx->server_session_id_len > 0) {
        server_hello[offset++] = ctx->server_session_id_len;
        memcpy(server_hello + offset, ctx->server_session_id, ctx->server_session_id_len);
        offset += ctx->server_session_id_len;
    } else {
        server_hello[offset++] = 0x00;  /* No session ID */
    }
    
    /* Cipher suite (2 bytes) */
    server_hello[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    server_hello[offset++] = ctx->cipher_suite & 0xFF;
    
    /* Compression method (1 byte) */
    server_hello[offset++] = 0x00;  /* NULL compression */
    /* Extensions: include RFC 5746 renegotiation_info (and others when applicable). */
    {
        uint16_t ext_block_len = 0;
        /*
         * RFC 5746: include renegotiation_info in ServerHello only if the client
         * signaled secure renegotiation (TLS_EMPTY_RENEGOTIATION_INFO_SCSV and/or
         * renegotiation_info extension). Otherwise omit it (interoperability with
         * strict peers and tlsfuzzer).
         */
        int have_reneg = (ctx->client_secure_renegotiation_offered != 0);
        int have_etm = (ctx->use_encrypt_then_mac != 0) &&
                       tls12_suite_supports_encrypt_then_mac(ctx->cipher_suite);
        int have_rpk = 0;
        int have_mfl = (ctx->max_fragment_length_code >= 1 && ctx->max_fragment_length_code <= 4);
        int have_heartbeat = (ctx->heartbeat_enabled != 0u && ctx->client_heartbeat_mode != 0u);
        int have_alpn = (ctx->negotiated_alpn_len > 0);
        int have_status_request = (ctx->client_offered_ocsp_status != 0u &&
                                   ctx->server_ocsp_response != NULL &&
                                   ctx->server_ocsp_response_len > 0u &&
                                   !ctx->session_resume);
        int have_session_ticket = 0;
        {
            tls_extension_t *ext_st = NULL;
            if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SESSION_TICKET, &ext_st) == NOXTLS_RETURN_SUCCESS &&
               ext_st != NULL) {
                /* RFC 5077: echo empty session_ticket extension in ServerHello when accepted. */
                have_session_ticket = 1;
            }
        }
        int have_ec_point_formats = 0;
        {
            tls_extension_t *epf = NULL;
            uint16_t ng_unused = 0;
            if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_EC_POINT_FORMATS, &epf) == NOXTLS_RETURN_SUCCESS &&
               epf != NULL &&
               tls12_cipher_suite_to_named_curve(ctx->cipher_suite, &ng_unused) == NOXTLS_RETURN_SUCCESS) {
                have_ec_point_formats = 1;
            }
        }
        int include_ems_sh = 0;
        {
            tls_extension_t *ems_ex = NULL;
            int client_ems = 0;
            if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_EXTENDED_MASTER_SECRET, &ems_ex) == NOXTLS_RETURN_SUCCESS &&
               ems_ex != NULL && ems_ex->length == 0) {
                client_ems = 1;
            }
            include_ems_sh = (client_ems != 0) && (!ctx->session_resume || ctx->session_resume_ems != 0);
        }
        ctx->extended_master_secret_negotiated = (uint8_t)(include_ems_sh ? 1 : 0);
        if(ctx->server_use_rpk && ctx->base.base.version >= TLS_VERSION_1_2) {
            tls_extension_t *ext20 = NULL;
            if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SERVER_CERTIFICATE_TYPE, &ext20) == NOXTLS_RETURN_SUCCESS &&
               ext20 != NULL && ext20->data != NULL && ext20->length >= 1) {
                uint8_t list_len = ext20->data[0];
                for(uint8_t i = 0; i < list_len && (uint32_t)(1 + i) < ext20->length; i++) {
                    if(ext20->data[1 + i] == TLS_CERT_TYPE_RAW_PUBLIC_KEY) {
                        have_rpk = 1;
                        ctx->server_certificate_type = TLS_CERT_TYPE_RAW_PUBLIC_KEY;
                        break;
                    }
                }
            }
        }
        if(have_reneg) {
            uint8_t reneg_data_len = 0u;
            if(ctx->renegotiation_in_progress && ctx->previous_verify_data_len > 0) {
                reneg_data_len = (uint8_t)(2u * ctx->previous_verify_data_len);
            }
            uint16_t elen = (uint16_t)(1u + reneg_data_len);
            ext_block_len += (uint16_t)(4u + elen);
        }
        if(include_ems_sh) {
            ext_block_len += 4u;
        }
        if(have_etm) {
            ext_block_len += 4;
        }
        if(have_rpk) {
            ext_block_len += 4 + 1;  /* type(2)+len(2)+cert_type(1) */
        }
        if(have_mfl) {
            ext_block_len += 4 + 1;  /* RFC 6066: max_fragment_length type(2)+len(2)+code(1) */
        }
        if(have_heartbeat) {
            ext_block_len += 4u + 1u; /* RFC 6520: heartbeat type(2)+len(2)+mode(1) */
        }
        if(have_alpn) {
            ext_block_len += (uint16_t)(4u + 2u + 1u + (uint32_t)ctx->negotiated_alpn_len);
        }
        if(have_status_request) {
            ext_block_len += 4u; /* RFC 6066: status_request in ServerHello has empty extension_data. */
        }
        if(have_session_ticket) {
            ext_block_len += 4u; /* type(2)+len(2), empty extension_data */
        }
        if(have_ec_point_formats) {
            ext_block_len += 6u; /* type(2)+len(2)+1 list len + format(1) */
        }
        if(ext_block_len > 0 && offset + 2 + ext_block_len <= TLS_SERVER_HELLO_DEFAULT_SIZE) {
            server_hello[offset++] = (uint8_t)(ext_block_len >> 8);
            server_hello[offset++] = (uint8_t)(ext_block_len & 0xFF);
            if(have_reneg) {
                uint8_t reneg_data_len = 0u;
                if(ctx->renegotiation_in_progress && ctx->previous_verify_data_len > 0) {
                    reneg_data_len = (uint8_t)(2u * ctx->previous_verify_data_len);
                }
                uint16_t elen = (uint16_t)(1u + reneg_data_len);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_RENEGOTIATION_INFO & 0xFF);
                server_hello[offset++] = (uint8_t)(elen >> 8);
                server_hello[offset++] = (uint8_t)(elen & 0xFF);
                server_hello[offset++] = reneg_data_len;
                if(reneg_data_len > 0u) {
                    memcpy(server_hello + offset, ctx->previous_client_verify_data, ctx->previous_verify_data_len);
                    offset += ctx->previous_verify_data_len;
                    memcpy(server_hello + offset, ctx->previous_server_verify_data, ctx->previous_verify_data_len);
                    offset += ctx->previous_verify_data_len;
                }
            }
            if(include_ems_sh) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_EXTENDED_MASTER_SECRET >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_EXTENDED_MASTER_SECRET & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x00;
            }
            if(have_etm) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_ENCRYPT_THEN_MAC >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_ENCRYPT_THEN_MAC & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x00;
            }
            if(have_rpk) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_SERVER_CERTIFICATE_TYPE >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_SERVER_CERTIFICATE_TYPE & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x01;
                server_hello[offset++] = TLS_CERT_TYPE_RAW_PUBLIC_KEY;
            }
            if(have_mfl) {
                server_hello[offset++] = 0x00;
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_MAX_FRAGMENT_LENGTH & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x01;
                server_hello[offset++] = ctx->max_fragment_length_code;
            }
            if(have_heartbeat) {
                server_hello[offset++] = 0x00;
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_HEARTBEAT & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x01;
                server_hello[offset++] = TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND;
            }
            if(have_alpn) {
                uint32_t alpn_written = noxtls_tls_alpn_write_selected_extension(
                    (const char *)ctx->negotiated_alpn,
                    ctx->negotiated_alpn_len,
                    server_hello + offset,
                    TLS_SERVER_HELLO_DEFAULT_SIZE - offset);
                if(alpn_written == 0) {
                    if(server_hello != ctx->handshake_workspace) {
                        NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE);
                    } else if(ctx->handshake_workspace != NULL) {
                        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                    }
                    return NOXTLS_RETURN_FAILED;
                }
                offset += alpn_written;
            }
            if(have_status_request) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_STATUS_REQUEST >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_STATUS_REQUEST & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x00;
            }
            if(have_session_ticket) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_SESSION_TICKET >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_SESSION_TICKET & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x00;
            }
            if(have_ec_point_formats) {
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_EC_POINT_FORMATS >> 8);
                server_hello[offset++] = (uint8_t)(TLS_EXTENSION_EC_POINT_FORMATS & 0xFF);
                server_hello[offset++] = 0x00;
                server_hello[offset++] = 0x02;
                server_hello[offset++] = 0x01; /* ECPointFormatList length */
                server_hello[offset++] = 0x00; /* uncompressed */
            }
            ctx->heartbeat_negotiated = (uint8_t)(have_heartbeat ? 1u : 0u);
            ctx->heartbeat_peer_mode = (uint8_t)(have_heartbeat ? ctx->client_heartbeat_mode : 0u);
            ctx->status_request_negotiated = (uint8_t)(have_status_request ? 1u : 0u);
        } else {
            server_hello[offset++] = 0x00;
            server_hello[offset++] = 0x00;
            ctx->heartbeat_negotiated = 0u;
            ctx->heartbeat_peer_mode = 0u;
            ctx->status_request_negotiated = 0u;
        }
    }
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    server_hello[1] = (handshake_len >> 16) & 0xFF;
    server_hello[2] = (handshake_len >> 8) & 0xFF;
    server_hello[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, server_hello, offset);
    
    /* Send via record layer */
    rc = tls12_send_handshake_record(ctx, server_hello, offset);
    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Certificate
 */
static int tls12_cipher_suite_is_ecdhe_ecdsa(uint16_t cs)
{
    switch(cs) {
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return 1;
        default:
            return 0;
    }
}

noxtls_return_t noxtls_tls12_send_certificate(tls12_context_t *ctx)
{
    uint32_t cert_list_len;
    uint32_t i;
    const uint8_t *leaf_der;
    uint32_t leaf_len;
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    leaf_der = ctx->server_cert;
    leaf_len = ctx->server_cert_len;
    if(tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite) &&
       ctx->server_ecdsa_leaf_cert != NULL && ctx->server_ecdsa_leaf_cert_len > 0u) {
        leaf_der = ctx->server_ecdsa_leaf_cert;
        leaf_len = ctx->server_ecdsa_leaf_cert_len;
    } else if(ctx->tls12_rsa_skx_scheme_prepared != 0 && ctx->tls12_rsa_skx_use_pss_leaf_identity != 0 &&
              ctx->server_rsa_pss_leaf_cert != NULL && ctx->server_rsa_pss_leaf_cert_len > 0u) {
        leaf_der = ctx->server_rsa_pss_leaf_cert;
        leaf_len = ctx->server_rsa_pss_leaf_cert_len;
    }
    if(leaf_der == NULL || leaf_len == 0u) {
        if(ctx->base.base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    uint8_t *certificate = ctx->handshake_workspace;
    if(certificate == NULL) {
        certificate = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(certificate == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    noxtls_return_t rc;
    
    /* Build Certificate noxtls_message */
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Certificate list length (3 bytes): leaf + optional intermediates */
    cert_list_len = leaf_len + 3;  /* +3 for cert length field */
    for(i = 0; i < ctx->server_cert_chain_count; i++) {
        if(ctx->server_cert_chain == NULL || ctx->server_cert_chain_len == NULL) {
            if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        if(ctx->server_cert_chain[i] == NULL || ctx->server_cert_chain_len[i] == 0u) {
            if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        cert_list_len += 3u + ctx->server_cert_chain_len[i];
    }
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    
    /* Certificate length (3 bytes) */
    certificate[offset++] = (leaf_len >> 16) & 0xFF;
    certificate[offset++] = (leaf_len >> 8) & 0xFF;
    certificate[offset++] = leaf_len & 0xFF;
    
    /* Certificate data */
    if(offset + leaf_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, leaf_der, leaf_len);
    offset += leaf_len;

    for(i = 0; i < ctx->server_cert_chain_count; i++) {
        uint32_t chain_len = ctx->server_cert_chain_len[i];
        certificate[offset++] = (chain_len >> 16) & 0xFF;
        certificate[offset++] = (chain_len >> 8) & 0xFF;
        certificate[offset++] = chain_len & 0xFF;
        if(offset + chain_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
            if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(certificate + offset, ctx->server_cert_chain[i], chain_len);
        offset += chain_len;
    }
    
    /* Update handshake noxtls_message length */
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, certificate, offset);
    
    /* Send via record layer */
    rc = tls12_send_handshake_record(ctx, certificate, offset);
    if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(ctx->status_request_negotiated != 0u) {
        rc = tls12_send_certificate_status(ctx);
    }
    return rc;
}

/* RFC 6066 status_request: send CertificateStatus (ocsp). Called only when status_request was negotiated. */
static noxtls_return_t tls12_send_certificate_status(tls12_context_t *ctx)
{
    uint8_t *msg;
    uint32_t offset = 0;
    uint32_t body_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->server_ocsp_response == NULL || ctx->server_ocsp_response_len == 0u) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(ctx->server_ocsp_response_len > 0xFFFFFFu) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    msg = ctx->handshake_workspace;
    if(msg == NULL) {
        msg = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(msg == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    /* Handshake header */
    msg[offset++] = TLS_HANDSHAKE_CERTIFICATE_STATUS;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* Body: CertificateStatus */
    body_len = 1u + 3u + ctx->server_ocsp_response_len;
    if(offset + body_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        if(msg != ctx->handshake_workspace) {
            NOXTLS_SECURE_FREE(msg, TLS_HANDSHAKE_WORKSPACE_SIZE);
        } else if(ctx->handshake_workspace != NULL) {
            memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    msg[offset++] = 0x01; /* status_type = ocsp */
    msg[offset++] = (uint8_t)(ctx->server_ocsp_response_len >> 16);
    msg[offset++] = (uint8_t)(ctx->server_ocsp_response_len >> 8);
    msg[offset++] = (uint8_t)(ctx->server_ocsp_response_len);
    memcpy(msg + offset, ctx->server_ocsp_response, ctx->server_ocsp_response_len);
    offset += ctx->server_ocsp_response_len;

    msg[1] = (uint8_t)(body_len >> 16);
    msg[2] = (uint8_t)(body_len >> 8);
    msg[3] = (uint8_t)body_len;

    tls12_append_handshake_message(ctx, msg, offset);
    rc = tls12_send_handshake_record(ctx, msg, offset);

    if(msg != ctx->handshake_workspace) {
        NOXTLS_SECURE_FREE(msg, TLS_HANDSHAKE_WORKSPACE_SIZE);
    } else if(ctx->handshake_workspace != NULL) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    }
    return rc;
}

/* RFC 6066 status_request: receive and store stapled OCSP response from CertificateStatus. */
static noxtls_return_t tls12_recv_certificate_status(tls12_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t ocsp_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls12_recv_handshake_message(ctx, TLS_HANDSHAKE_CERTIFICATE_STATUS, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg == NULL || msg_len < 8u) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(msg[4] != 0x01u) { /* only ocsp supported */
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    ocsp_len = ((uint32_t)msg[5] << 16) | ((uint32_t)msg[6] << 8) | (uint32_t)msg[7];
    if(ocsp_len == 0u || (8u + ocsp_len) != msg_len) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }

    if(ctx->peer_ocsp_response != NULL) {
        noxtls_free(ctx->peer_ocsp_response);
        ctx->peer_ocsp_response = NULL;
        ctx->peer_ocsp_response_len = 0;
    }
    ctx->peer_ocsp_response = (uint8_t*)noxtls_malloc(ocsp_len);
    if(ctx->peer_ocsp_response == NULL) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    memcpy(ctx->peer_ocsp_response, msg + 8, ocsp_len);
    ctx->peer_ocsp_response_len = ocsp_len;

    tls12_append_handshake_message(ctx, msg, msg_len);
    if(msg) noxtls_free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/* Encode ECDSA signature (r, s) to DER for TLS 1.2 ServerKeyExchange (same structure as TLS 1.3 CertificateVerify). */
static uint32_t tls12_ecdsa_signature_to_der(const ecdsa_signature_t *sig, uint8_t *der, uint32_t der_max)
{
    uint32_t size = sig->size;
    const uint8_t *r = sig->r;
    const uint8_t *s = sig->s;
    uint8_t r_buf[ECC_MAX_KEY_SIZE + 1];
    uint8_t s_buf[ECC_MAX_KEY_SIZE + 1];
    uint32_t r_len;
    uint32_t s_len;
    uint32_t r_off = 0;
    uint32_t s_off = 0;
    uint32_t pos = 2;

    if(der == NULL || der_max < 10 || size > ECC_MAX_KEY_SIZE) {
        return 0;
    }
    while(r_off < size && r[r_off] == 0) {
        r_off++;
    }
    if(r_off == size) {
        r_buf[0] = 0x00;
        r_len = 1;
    } else {
        r_len = size - r_off;
        if(r[r_off] >= 0x80) {
            r_buf[0] = 0x00;
            memcpy(r_buf + 1, r + r_off, r_len);
            r_len++;
        } else {
            memcpy(r_buf, r + r_off, r_len);
        }
    }
    while(s_off < size && s[s_off] == 0) {
        s_off++;
    }
    if(s_off == size) {
        s_buf[0] = 0x00;
        s_len = 1;
    } else {
        s_len = size - s_off;
        if(s[s_off] >= 0x80) {
            s_buf[0] = 0x00;
            memcpy(s_buf + 1, s + s_off, s_len);
            s_len++;
        } else {
            memcpy(s_buf, s + s_off, s_len);
        }
    }
    if(der_max < 2 + 2 + r_len + 2 + s_len) {
        return 0;
    }
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)r_len;
    memcpy(der + pos, r_buf, r_len);
    pos += r_len;
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)s_len;
    memcpy(der + pos, s_buf, s_len);
    pos += s_len;
    der[0] = 0x30;
    der[1] = (uint8_t)(pos - 2);
    return pos;
}

/**
 * @brief TLS 1.2 Server: Send Server Key Exchange
 */
noxtls_return_t noxtls_tls12_send_server_key_exchange(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check key exchange type */
    int is_rsa_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
    int is_dhe_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
    
    if(is_rsa_kex) {
        /* RSA key exchange: Server Key Exchange is not sent */
        return NOXTLS_RETURN_SUCCESS;
    } else if(is_dhe_kex) {
        uint16_t named_group;
        uint8_t *skx_buf = (ctx->handshake_workspace != NULL) ? ctx->handshake_workspace : (uint8_t*)noxtls_malloc(NOXTLS_TLS12_DHE_SKX_MSG_MAX);
        uint32_t skx_len = 0;
        noxtls_return_t rc;
        if(skx_buf == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        if(tls12_select_ffdhe_named_group(ctx, ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL,
                                            TLS_ALERT_INSUFFICIENT_SECURITY);
            }
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)malloc(sizeof(tls_dhe_context_t));
        if(dhe_ctx == NULL) {
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_tls_dhe_context_init(dhe_ctx, named_group);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(dhe_ctx);
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return rc;
        }
        ctx->dhe_ctx = dhe_ctx;
        rc = noxtls_tls12_dhe_send_server_key_exchange(ctx, dhe_ctx, skx_buf, NOXTLS_TLS12_DHE_SKX_MSG_MAX, &skx_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls_dhe_context_free(dhe_ctx);
            free(dhe_ctx);
            ctx->dhe_ctx = NULL;
            if(skx_buf != ctx->handshake_workspace) noxtls_free(skx_buf);
            return rc;
        }
        tls12_append_handshake_message(ctx, skx_buf, skx_len);
        tls12_inc_send_seq(ctx);
        if(skx_buf != ctx->handshake_workspace) {
            noxtls_free(skx_buf);
        } else if(ctx->handshake_workspace != NULL) {
            memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        }
        return rc;
    } else {
        noxtls_return_t rc;
        /* ECDHE: Send server's ephemeral public key */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        
        if(ecdhe_ctx == NULL) {
            /* Initialize ECDHE context if not already done */
            uint16_t named_group;
            if(tls12_select_ecdhe_named_group(ctx, ctx->cipher_suite, &named_group) != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to determine named curve for cipher suite 0x%04X\n", ctx->cipher_suite);
                fflush(stdout);
                if(ctx->base.base.send_callback != NULL) {
                    (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
                }
                return NOXTLS_RETURN_NOT_SUPPORTED;
            }
            
            noxtls_debug_printf("Initializing ECDHE context with named group: %d\n", named_group);
            fflush(stdout);
            
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            
            rc = noxtls_tls_ecdhe_context_init(ecdhe_ctx, named_group);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to initialize ECDHE context: %d\n", rc);
                fflush(stdout);
                free(ecdhe_ctx);
                return rc;
            }
            
            noxtls_debug_printf("Generating server ephemeral key pair (this may take a moment)...\n");
            fflush(stdout);
            
            /* Generate ephemeral key pair */
            rc = noxtls_tls_ecdhe_generate_ephemeral_key(ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("ERROR: Failed to generate ephemeral key: %d\n", rc);
                fflush(stdout);
                noxtls_tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                return rc;
            }
            
            noxtls_debug_printf("Server ephemeral key generated successfully\n");
            fflush(stdout);
            
            ctx->ecdhe_ctx = ecdhe_ctx;
        }
        
        /* Build Server Key Exchange noxtls_message ourselves to have control over handshake noxtls_message accumulation */
        /* workspace layout: server_key_exchange 0..1023, to_sign 1024..1343, sig_buf 1344..1855 */
        uint8_t *server_key_exchange = ctx->handshake_workspace;
        uint8_t *to_sign = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1024) : NULL;
        uint8_t *sig_buf = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1344) : NULL;
        if(server_key_exchange == NULL) {
            server_key_exchange = (uint8_t*)noxtls_malloc(TLS_SERVER_KEY_EXCHANGE_WORKSPACE);
            if(server_key_exchange == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            to_sign = server_key_exchange + 1024;
            sig_buf = server_key_exchange + 1344;
        }
        uint32_t offset = 0;
        uint8_t public_key_encoded[133];
        uint32_t public_key_len = sizeof(public_key_encoded);
        
        /* Build Server Key Exchange noxtls_message */
        server_key_exchange[offset++] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
        server_key_exchange[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
        server_key_exchange[offset++] = 0x00;
        server_key_exchange[offset++] = 0x00;
        
        /* Curve type: named_curve (0x03) */
        server_key_exchange[offset++] = 0x03;
        
        /* Named curve */
        server_key_exchange[offset++] = (ecdhe_ctx->named_group >> 8) & 0xFF;
        server_key_exchange[offset++] = ecdhe_ctx->named_group & 0xFF;
        
        /* Get encoded public key */
        rc = noxtls_tls_ecdhe_get_public_key_encoded(ecdhe_ctx, public_key_encoded, &public_key_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, TLS_SERVER_KEY_EXCHANGE_WORKSPACE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }

        /* Public key length */
        server_key_exchange[offset++] = public_key_len & 0xFF;
        
        /* Public key */
        memcpy(server_key_exchange + offset, public_key_encoded, public_key_len);
        offset += public_key_len;
        uint32_t params_start = 4;  /* Server Key Exchange body starts after handshake header */
        uint32_t params_len = offset - params_start;

        uint8_t rsa_skx_hi = 0;
        uint8_t rsa_skx_lo = 0;
        uint8_t ecdsa_skx_hash_wire = 0;
        noxtls_hash_algos_t skx_sign_hash = NOXTLS_HASH_SHA_256;
        int sig_written = 0;
        noxtls_return_t pre_rc = NOXTLS_RETURN_SUCCESS;

        if(tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite)) {
            pre_rc = noxtls_tls12_pick_ecdsa_skx_sig_hash(ctx, &ecdsa_skx_hash_wire, &skx_sign_hash);
        } else {
            if(ctx->tls12_rsa_skx_scheme_prepared != 0) {
                rsa_skx_hi = (uint8_t)((ctx->tls12_rsa_skx_wire_scheme >> 8) & 0xFFu);
                rsa_skx_lo = (uint8_t)(ctx->tls12_rsa_skx_wire_scheme & 0xFFu);
                skx_sign_hash = ctx->tls12_rsa_skx_sign_hash;
            } else {
                pre_rc = noxtls_tls12_pick_rsa_pkcs1_skx_sig_hash(ctx, &rsa_skx_hi, &skx_sign_hash);
                rsa_skx_lo = 0x01;
            }
        }
        if(pre_rc != NOXTLS_RETURN_SUCCESS) {
            if(server_key_exchange != ctx->handshake_workspace) {
                NOXTLS_SECURE_FREE(server_key_exchange, TLS_SERVER_KEY_EXCHANGE_WORKSPACE);
            } else if(ctx->handshake_workspace != NULL) {
                memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            }
            if(ctx->base.base.send_callback != NULL) {
                (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE);
            }
            return pre_rc;
        }

        {
            uint32_t to_sign_len = TLS_RANDOM_SIZE + TLS_RANDOM_SIZE + params_len;
            if(to_sign_len <= 320) {
                memcpy(to_sign, ctx->client_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + TLS_RANDOM_SIZE, ctx->server_random, TLS_RANDOM_SIZE);
                memcpy(to_sign + ((size_t)TLS_RANDOM_SIZE * 2u), server_key_exchange + params_start, params_len);
            }

            if(tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite) && ctx->server_private_ecdsa != NULL &&
               to_sign_len <= 320) {
                ecc_key_t *eckey = (ecc_key_t *)ctx->server_private_ecdsa;
                uint32_t coord_size = eckey->curve != NULL ? eckey->curve->size : 32u;
                ecdsa_signature_t esig;
                uint32_t der_len = 0;
                memset(&esig, 0, sizeof(esig));
                rc = noxtls_ecdsa_signature_init(&esig, coord_size);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    rc = noxtls_ecdsa_sign(eckey, to_sign, to_sign_len, &esig, skx_sign_hash);
                    if(rc == NOXTLS_RETURN_SUCCESS) {
                        der_len = tls12_ecdsa_signature_to_der(&esig, sig_buf, 512);
                        if(der_len > 0u && offset + 4u + der_len <= 1024u) {
                            server_key_exchange[offset++] = ecdsa_skx_hash_wire;
                            server_key_exchange[offset++] = 0x03; /* SignatureAlgorithm.ecdsa */
                            server_key_exchange[offset++] = (uint8_t)((der_len >> 8) & 0xFF);
                            server_key_exchange[offset++] = (uint8_t)(der_len & 0xFF);
                            memcpy(server_key_exchange + offset, sig_buf, der_len);
                            offset += der_len;
                            sig_written = 1;
                        }
                    }
                    noxtls_ecdsa_signature_free(&esig);
                }
            } else if(!tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite) &&
                      ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_sign &&
                      ctx->server_private_key_handle && to_sign_len <= 320 &&
                      (ctx->tls12_rsa_skx_scheme_prepared == 0 || ctx->tls12_rsa_skx_sign_use_pss == 0)) {
                uint32_t sig_len = 512;
                rc = ctx->crypto_provider->ops->rsa_sign(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                        to_sign, to_sign_len, sig_buf, &sig_len, (noxtls_crypto_hash_algo_t)skx_sign_hash);
                if(rc == NOXTLS_RETURN_SUCCESS && offset + 4 + sig_len <= 1024) {
                    server_key_exchange[offset++] = rsa_skx_hi;
                    server_key_exchange[offset++] = rsa_skx_lo;
                    server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
                    server_key_exchange[offset++] = sig_len & 0xFF;
                    memcpy(server_key_exchange + offset, sig_buf, sig_len);
                    offset += sig_len;
                    sig_written = 1;
                }
            } else if(!tls12_cipher_suite_is_ecdhe_ecdsa(ctx->cipher_suite) && ctx->server_private_rsa != NULL &&
                      to_sign_len <= 320) {
                const rsa_key_t *sk_rsa = (const rsa_key_t *)ctx->server_private_rsa;
                if(ctx->tls12_rsa_skx_scheme_prepared != 0 && ctx->tls12_rsa_skx_use_pss_leaf_identity != 0 &&
                   ctx->server_private_rsa_pss_leaf != NULL) {
                    sk_rsa = (const rsa_key_t *)ctx->server_private_rsa_pss_leaf;
                }
                uint32_t sig_len = 512;
                if(ctx->tls12_rsa_skx_scheme_prepared != 0 && ctx->tls12_rsa_skx_sign_use_pss != 0) {
                    rc = noxtls_rsa_sign_pss(sk_rsa, to_sign, to_sign_len, sig_buf, &sig_len, skx_sign_hash);
                } else {
                    rc = noxtls_rsa_sign(sk_rsa, to_sign, to_sign_len, sig_buf, &sig_len, skx_sign_hash);
                }
                if(rc == NOXTLS_RETURN_SUCCESS && offset + 4 + sig_len <= 1024) {
                    server_key_exchange[offset++] = rsa_skx_hi;
                    server_key_exchange[offset++] = rsa_skx_lo;
                    server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
                    server_key_exchange[offset++] = sig_len & 0xFF;
                    memcpy(server_key_exchange + offset, sig_buf, sig_len);
                    offset += sig_len;
                    sig_written = 1;
                }
            }
        }

        if(!sig_written) {
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
            server_key_exchange[offset++] = 0x00;
        }
        uint32_t handshake_len = offset - 4;
        server_key_exchange[1] = (handshake_len >> 16) & 0xFF;
        server_key_exchange[2] = (handshake_len >> 8) & 0xFF;
        server_key_exchange[3] = handshake_len & 0xFF;
        noxtls_debug_printf("Sending Server Key Exchange (ECDHE), noxtls_message length: %u bytes\n", offset);
        fflush(stdout);
        
        /* Append to handshake messages (for Finished verify_data computation) */
        tls12_append_handshake_message(ctx, server_key_exchange, offset);
        
        /* Send via record layer */
        rc = tls12_send_handshake_record(ctx, server_key_exchange, offset);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("Server Key Exchange sent successfully\n");
            fflush(stdout);
        } else {
            noxtls_debug_printf("ERROR: Failed to send Server Key Exchange: %d\n", rc);
            fflush(stdout);
        }
        if(server_key_exchange != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_key_exchange, TLS_SERVER_KEY_EXCHANGE_WORKSPACE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
}

static int tls12_server_supports_client_sigalg(uint16_t sigalg)
{
    static const uint16_t supported[] = {
        0x0807, 0x0808, 0x0603, 0x0503, 0x0403, 0x0303, 0x0203,
        0x0806, 0x080B, 0x0805, 0x080A, 0x0804, 0x0809,
        0x0601, 0x0501, 0x0401, 0x0301, 0x0201
    };
    uint32_t i;
    for(i = 0; i < (uint32_t)(sizeof(supported) / sizeof(supported[0])); i++) {
        if(supported[i] == sigalg) {
            return 1;
        }
    }
    return 0;
}

static uint32_t tls12_build_cert_request_sigalgs(tls12_context_t *ctx, uint8_t *out, uint32_t out_cap)
{
    static const uint16_t defaults[] = {
        0x0807, /* ed25519 */
        0x0808, /* ed448 */
        0x0603, /* ecdsa_secp521r1_sha512 */
        0x0503, /* ecdsa_secp384r1_sha384 */
        0x0403, /* ecdsa_secp256r1_sha256 */
        0x0303, /* ecdsa_sha224 */
        0x0203, /* ecdsa_sha1 */
        0x0806, /* rsa_pss_rsae_sha512 */
        0x080B, /* rsa_pss_pss_sha512 */
        0x0805, /* rsa_pss_rsae_sha384 */
        0x080A, /* rsa_pss_pss_sha384 */
        0x0804, /* rsa_pss_rsae_sha256 */
        0x0809, /* rsa_pss_pss_sha256 */
        0x0601, /* rsa_pkcs1_sha512 */
        0x0501, /* rsa_pkcs1_sha384 */
        0x0401, /* rsa_pkcs1_sha256 */
        0x0301, /* rsa_pkcs1_sha224 */
        0x0201  /* rsa_pkcs1_sha1 */
    };
    uint32_t out_len = 0;
    uint32_t i;

    if(ctx == NULL || out == NULL) {
        return 0;
    }
    for(i = 0; i < (uint32_t)(sizeof(defaults) / sizeof(defaults[0])); i++) {
        if(!tls12_server_supports_client_sigalg(defaults[i])) {
            continue;
        }
        if(out_len + 2u > out_cap) {
            return 0;
        }
        out[out_len++] = (uint8_t)(defaults[i] >> 8);
        out[out_len++] = (uint8_t)(defaults[i] & 0xFF);
    }
    return out_len;
}

noxtls_return_t noxtls_tls12_send_certificate_request(tls12_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t offset = 0;
    uint32_t sigalgs_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }

    msg = ctx->handshake_workspace;
    if(msg == NULL) {
        msg = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(msg == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    msg[offset++] = TLS_HANDSHAKE_CERTIFICATE_REQUEST;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    /* certificate_types<1..2^8-1>: rsa_sign + ecdsa_sign */
    msg[offset++] = 2u;
    msg[offset++] = 1u;
    msg[offset++] = 64u;

    /* supported_signature_algorithms<2..2^16-1> */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;
    sigalgs_len = tls12_build_cert_request_sigalgs(ctx, msg + offset, TLS_HANDSHAKE_WORKSPACE_SIZE - offset);
    if(sigalgs_len == 0 || (sigalgs_len & 1u) != 0) {
        if(msg != ctx->handshake_workspace) {
            NOXTLS_SECURE_FREE(msg, TLS_HANDSHAKE_WORKSPACE_SIZE);
        } else if(ctx->handshake_workspace != NULL) {
            memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        }
        return NOXTLS_RETURN_FAILED;
    }
    msg[offset - 2u] = (uint8_t)(sigalgs_len >> 8);
    msg[offset - 1u] = (uint8_t)(sigalgs_len & 0xFF);
    offset += sigalgs_len;

    /* certificate_authorities<0..2^16-1>: empty list */
    msg[offset++] = 0x00;
    msg[offset++] = 0x00;

    {
        uint32_t hs_len = offset - 4u;
        msg[1] = (uint8_t)(hs_len >> 16);
        msg[2] = (uint8_t)(hs_len >> 8);
        msg[3] = (uint8_t)(hs_len & 0xFF);
    }

    tls12_append_handshake_message(ctx, msg, offset);
    rc = tls12_send_handshake_record(ctx, msg, offset);
    if(msg != ctx->handshake_workspace) {
        NOXTLS_SECURE_FREE(msg, TLS_HANDSHAKE_WORKSPACE_SIZE);
    } else if(ctx->handshake_workspace != NULL) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    }
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Server Hello Done
 */
noxtls_return_t noxtls_tls12_send_server_hello_done(tls12_context_t *ctx)
{
    uint8_t server_hello_done[4];
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Server Hello Done noxtls_message */
    server_hello_done[0] = TLS_HANDSHAKE_SERVER_HELLO_DONE;
    server_hello_done[1] = 0x00;
    server_hello_done[2] = 0x00;
    server_hello_done[3] = 0x00;  /* Length is 0 */
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, server_hello_done, 4);
    
    /* Send via record layer */
    rc = tls12_send_handshake_record(ctx, server_hello_done, 4);
    return rc;
}

static noxtls_return_t tls12_recv_client_certificate(tls12_context_t *ctx, int *cert_present)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t cert_list_len;
    uint32_t cert_len;
    noxtls_return_t rc;

    if(ctx == NULL || cert_present == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *cert_present = 0;

    rc = tls12_recv_handshake_message(ctx, TLS_HANDSHAKE_CERTIFICATE, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 7u || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    cert_list_len = ((uint32_t)msg[4] << 16) | ((uint32_t)msg[5] << 8) | (uint32_t)msg[6];
    if(cert_list_len > (msg_len - 7u)) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(cert_list_len == 0u) {
        tls12_append_handshake_message(ctx, msg, msg_len);
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_SUCCESS;
    }
    if(cert_list_len < 3u || msg_len < 10u) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }

    cert_len = ((uint32_t)msg[7] << 16) | ((uint32_t)msg[8] << 8) | (uint32_t)msg[9];
    if(cert_len == 0u || (10u + cert_len) > msg_len || cert_len > (cert_list_len - 3u)) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }

    if(ctx->client_cert != NULL) {
        noxtls_free(ctx->client_cert);
        ctx->client_cert = NULL;
        ctx->client_cert_len = 0;
    }
    if(ctx->client_cert_parsed != NULL) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        noxtls_free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }

    ctx->client_cert = (uint8_t*)noxtls_malloc(cert_len);
    if(ctx->client_cert == NULL) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    memcpy(ctx->client_cert, msg + 10u, cert_len);
    ctx->client_cert_len = cert_len;

    {
        x509_certificate_t *parsed = (x509_certificate_t*)noxtls_malloc(sizeof(x509_certificate_t));
        if(parsed == NULL) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        noxtls_x509_certificate_init(parsed);
        rc = noxtls_x509_certificate_parse_der(parsed, ctx->client_cert, ctx->client_cert_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(parsed);
            noxtls_free(parsed);
            if(msg) noxtls_free(msg);
            return rc;
        }
        ctx->client_cert_parsed = parsed;
    }

    tls12_append_handshake_message(ctx, msg, msg_len);
    *cert_present = 1;
    if(msg) noxtls_free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls12_sig_hash_to_noxtls(uint8_t hash_id, noxtls_hash_algos_t *hash_algo)
{
    if(hash_algo == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    switch(hash_id) {
        case 1: *hash_algo = NOXTLS_HASH_MD5; return NOXTLS_RETURN_SUCCESS;
        case 2: *hash_algo = NOXTLS_HASH_SHA1; return NOXTLS_RETURN_SUCCESS;
        case 3: *hash_algo = NOXTLS_HASH_SHA_224; return NOXTLS_RETURN_SUCCESS;
        case 4: *hash_algo = NOXTLS_HASH_SHA_256; return NOXTLS_RETURN_SUCCESS;
        case 5: *hash_algo = NOXTLS_HASH_SHA_384; return NOXTLS_RETURN_SUCCESS;
        case 6: *hash_algo = NOXTLS_HASH_SHA_512; return NOXTLS_RETURN_SUCCESS;
        default: return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
}

static noxtls_return_t tls12_recv_client_certificate_verify(tls12_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint16_t sig_scheme;
    uint16_t sig_len;
    noxtls_return_t rc;
    x509_certificate_t *cert;

    if(ctx == NULL || ctx->client_cert_parsed == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls12_recv_handshake_message(ctx, TLS_HANDSHAKE_CERTIFICATE_VERIFY, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 8u || msg[0] != TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }
    sig_scheme = (uint16_t)(((uint16_t)msg[4] << 8) | (uint16_t)msg[5]);
    sig_len = (uint16_t)(((uint16_t)msg[6] << 8) | (uint16_t)msg[7]);
    if((uint32_t)8u + (uint32_t)sig_len != msg_len) {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_BAD_DATA;
    }

    cert = (x509_certificate_t*)ctx->client_cert_parsed;

    if((sig_scheme & 0x00FFu) == 0x01u) {
        noxtls_hash_algos_t hash_algo;
        uint8_t hash_id = (uint8_t)(sig_scheme >> 8);
        rsa_key_t rsa_key;
        uint32_t mod_len;
        uint32_t exp_len;
        const uint8_t *mod_ptr;
        const uint8_t *exp_ptr;
        rsa_key_size_t key_size;

        rc = tls12_sig_hash_to_noxtls(hash_id, &hash_algo);
        if(rc != NOXTLS_RETURN_SUCCESS ||
           cert->rsa_modulus == NULL || cert->rsa_exponent == NULL ||
           cert->rsa_modulus_len == 0u || cert->rsa_exponent_len == 0u) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        mod_ptr = cert->rsa_modulus;
        mod_len = cert->rsa_modulus_len;
        exp_ptr = cert->rsa_exponent;
        exp_len = cert->rsa_exponent_len;
        if(mod_len > 0u && mod_ptr[0] == 0x00u) { mod_ptr++; mod_len--; }
        if(exp_len > 0u && exp_ptr[0] == 0x00u) { exp_ptr++; exp_len--; }
        if(mod_len == 128u) key_size = RSA_1024_BIT;
        else if(mod_len == 256u) key_size = RSA_2048_BIT;
        else if(mod_len == 384u) key_size = RSA_3072_BIT;
        else if(mod_len == 512u) key_size = RSA_4096_BIT;
        else {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_rsa_key_init(&rsa_key, key_size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return rc;
        }
        memset(rsa_key.n, 0, rsa_key.key_bytes);
        memset(rsa_key.e, 0, rsa_key.key_bytes);
        memcpy(rsa_key.n + (rsa_key.key_bytes - mod_len), mod_ptr, mod_len);
        memcpy(rsa_key.e + (rsa_key.key_bytes - exp_len), exp_ptr, exp_len);
        rc = noxtls_rsa_verify(&rsa_key, ctx->handshake_messages, ctx->handshake_messages_len,
                               msg + 8u, sig_len, hash_algo);
        noxtls_rsa_key_free(&rsa_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    } else if((sig_scheme & 0x00FFu) == 0x03u) {
        noxtls_hash_algos_t hash_algo;
        void *pubkey = NULL;
        uint32_t key_type = 0;
        ecc_key_t *ecc_key;
        ecdsa_signature_t ecdsa_sig;
        uint32_t coord_size;

        rc = tls12_sig_hash_to_noxtls((uint8_t)(sig_scheme >> 8), &hash_algo);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return rc;
        }
        rc = noxtls_x509_certificate_get_public_key(cert, &pubkey, &key_type);
        if(rc != NOXTLS_RETURN_SUCCESS || pubkey == NULL || key_type != 2u) {
            if(pubkey != NULL) noxtls_free(pubkey);
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        ecc_key = (ecc_key_t*)pubkey;
        coord_size = (ecc_key->curve != NULL) ? ecc_key->curve->size : 0u;
        if(coord_size == 0u) {
            noxtls_ecc_key_free(ecc_key);
            noxtls_free(ecc_key);
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_ecdsa_signature_init(&ecdsa_sig, coord_size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecc_key_free(ecc_key);
            noxtls_free(ecc_key);
            if(msg) noxtls_free(msg);
            return rc;
        }
        rc = noxtls_ecdsa_signature_parse_der(msg + 8u, sig_len, &ecdsa_sig, coord_size);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_ecdsa_verify(ecc_key, ctx->handshake_messages, ctx->handshake_messages_len,
                                     &ecdsa_sig, hash_algo);
        }
        noxtls_ecdsa_signature_free(&ecdsa_sig);
        noxtls_ecc_key_free(ecc_key);
        noxtls_free(ecc_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    } else if(sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 ||
              sig_scheme == 0x0805u ||
              sig_scheme == 0x0806u) {
        noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
        rsa_key_t rsa_key;
        uint32_t mod_len;
        uint32_t exp_len;
        const uint8_t *mod_ptr;
        const uint8_t *exp_ptr;
        rsa_key_size_t key_size;

        if(sig_scheme == 0x0805u) {
            hash_algo = NOXTLS_HASH_SHA_384;
        } else if(sig_scheme == 0x0806u) {
            hash_algo = NOXTLS_HASH_SHA_512;
        }
        if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL ||
           cert->rsa_modulus_len == 0u || cert->rsa_exponent_len == 0u) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        mod_ptr = cert->rsa_modulus;
        mod_len = cert->rsa_modulus_len;
        exp_ptr = cert->rsa_exponent;
        exp_len = cert->rsa_exponent_len;
        if(mod_len > 0u && mod_ptr[0] == 0x00u) { mod_ptr++; mod_len--; }
        if(exp_len > 0u && exp_ptr[0] == 0x00u) { exp_ptr++; exp_len--; }
        if(mod_len == 128u) key_size = RSA_1024_BIT;
        else if(mod_len == 256u) key_size = RSA_2048_BIT;
        else if(mod_len == 384u) key_size = RSA_3072_BIT;
        else if(mod_len == 512u) key_size = RSA_4096_BIT;
        else {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_rsa_key_init(&rsa_key, key_size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return rc;
        }
        memset(rsa_key.n, 0, rsa_key.key_bytes);
        memset(rsa_key.e, 0, rsa_key.key_bytes);
        memcpy(rsa_key.n + (rsa_key.key_bytes - mod_len), mod_ptr, mod_len);
        memcpy(rsa_key.e + (rsa_key.key_bytes - exp_len), exp_ptr, exp_len);
        rc = noxtls_rsa_verify_pss(&rsa_key, ctx->handshake_messages, ctx->handshake_messages_len,
                                   msg + 8u, sig_len, hash_algo);
        noxtls_rsa_key_free(&rsa_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(msg) noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(msg) noxtls_free(msg);
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    tls12_append_handshake_message(ctx, msg, msg_len);
    if(msg) noxtls_free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Client Key Exchange
 */
noxtls_return_t noxtls_tls12_recv_client_key_exchange(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t *reasm = NULL;
    uint8_t *frag = NULL;
    const uint8_t *cke_data = NULL;
    uint32_t cke_len = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    memset(&record, 0, sizeof(record));
    if(!ctx->renegotiation_in_progress) {
        uint32_t want_len = 0;
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return (rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_BAD_DATA : rc;
        }
        
        if(record.type != TLS_RECORD_HANDSHAKE || record.data == NULL || record.length < 4u) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        
        if(record.data[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls12_inc_recv_seq(ctx);
        cke_data = record.data;
        cke_len = record.length;
        want_len = 4u + ((uint32_t)cke_data[1] << 16) + ((uint32_t)cke_data[2] << 8) + (uint32_t)cke_data[3];
        if(want_len < 6u || want_len > TLS_MAX_RECORD_SIZE) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        }
        if(cke_len < want_len) {
            reasm = (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE);
            if(reasm == NULL) {
                if(record.data) noxtls_free(record.data);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            memcpy(reasm, cke_data, cke_len);
            while(cke_len < want_len) {
                rc = noxtls_tls_recv_record(&ctx->base.base, &record);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    if(record.data) noxtls_free(record.data);
                    noxtls_free(reasm);
                    return (rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_BAD_DATA : rc;
                }
                if(record.type == TLS_RECORD_HANDSHAKE) {
                    if(record.data == NULL || record.length == 0u || cke_len + record.length > want_len) {
                        if(record.data) noxtls_free(record.data);
                        noxtls_free(reasm);
                        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                    }
                    memcpy(reasm + cke_len, record.data, record.length);
                    cke_len += record.length;
                    noxtls_free(record.data);
                    record.data = NULL;
                    continue;
                }
                if(record.data) noxtls_free(record.data);
                noxtls_free(reasm);
                if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
                    return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
                }
                return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
            }
            if(record.data) {
                noxtls_free(record.data);
                record.data = NULL;
            }
            if(cke_data == record.data) {
                /* no-op (defensive) */
            } else if(cke_data != NULL) {
                noxtls_free((void*)cke_data);
            }
            cke_data = reasm;
        } else if(cke_len > want_len) {
            if(record.data) noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        }
    } else {
        uint32_t frag_cap = TLS_MAX_RECORD_SIZE;
        uint32_t want_len = 0;
        frag = (uint8_t*)noxtls_malloc(frag_cap);
        reasm = (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE);
        if(frag == NULL || reasm == NULL) {
            if(frag) noxtls_free(frag);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        while(1) {
            uint32_t frag_len = frag_cap;
            rc = noxtls_tls_recv_record(&ctx->base.base, &record);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_free(frag);
                noxtls_free(reasm);
                return (rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_BAD_DATA : rc;
            }
            if(record.type == TLS_RECORD_HANDSHAKE) {
                rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HANDSHAKE, record.data, record.length,
                                                 frag, &frag_len);
                if(record.data) {
                    noxtls_free(record.data);
                    record.data = NULL;
                }
                if(rc != NOXTLS_RETURN_SUCCESS || frag_len == 0u) {
                    noxtls_free(frag);
                    noxtls_free(reasm);
                    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_FAILED : rc;
                }
                if(cke_len == 0u) {
                    if(frag_len < 4u || frag[0] != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
                        noxtls_free(frag);
                        noxtls_free(reasm);
                        return NOXTLS_RETURN_FAILED;
                    }
                    want_len = 4u + ((uint32_t)frag[1] << 16) + ((uint32_t)frag[2] << 8) + (uint32_t)frag[3];
                    if(want_len < 6u || want_len > TLS_MAX_RECORD_SIZE) {
                        noxtls_free(frag);
                        noxtls_free(reasm);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
                if(cke_len + frag_len > want_len) {
                    noxtls_free(frag);
                    noxtls_free(reasm);
                    return NOXTLS_RETURN_FAILED;
                }
                memcpy(reasm + cke_len, frag, frag_len);
                cke_len += frag_len;
                if(cke_len == want_len) {
                    break;
                }
                continue;
            }
            if(record.type == TLS_RECORD_APPLICATION_DATA) {
                rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, record.data, record.length,
                                                 frag, &frag_len);
                if(record.data) {
                    noxtls_free(record.data);
                    record.data = NULL;
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_free(frag);
                    noxtls_free(reasm);
                    return rc;
                }
                if(frag_len > 0u) {
                    if(ctx->pending_app_data_len + frag_len > sizeof(ctx->pending_app_data)) {
                        noxtls_free(frag);
                        noxtls_free(reasm);
                        return NOXTLS_RETURN_FAILED;
                    }
                    memcpy(ctx->pending_app_data + ctx->pending_app_data_len, frag, frag_len);
                    ctx->pending_app_data_len += frag_len;
                }
                continue;
            }
            if(record.data) noxtls_free(record.data);
            noxtls_free(frag);
            noxtls_free(reasm);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_free(frag);
        cke_data = reasm;
    }
    
    /* Parse Client Key Exchange noxtls_message */
    uint32_t msg_offset = 4;  /* Skip handshake header */
    
    /* Determine key exchange method based on cipher suite */
    int is_rsa_kex = (ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
                      ctx->cipher_suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384);
    
    if(is_rsa_kex) {
        /* RSA Key Exchange: Extract encrypted premaster secret */
        if(msg_offset + 2 > cke_len) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_FAILED;
        }
        
        uint16_t encrypted_premaster_len = (cke_data[msg_offset] << 8) | cke_data[msg_offset + 1];
        msg_offset += 2;
        
        if(msg_offset + encrypted_premaster_len > cke_len || encrypted_premaster_len > TLS_CLIENT_KEY_EXCHANGE_MAX_LEN) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_FAILED;
        }
        
        if(ctx->server_private_rsa == NULL &&
           !(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_decrypt && ctx->server_private_key_handle)) {
            noxtls_debug_printf("ERROR: RSA key exchange requires server private key\n");
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_FAILED;
        }

        /*
         * ROBOT/Bleichenbacher mitigation (implicit rejection):
         * - always derive a 48-byte premaster secret
         * - on RSA/PKCS#1/version validation failure, use random fallback
         * - continue handshake and fail uniformly at Finished verification
         */
        {
            uint8_t decrypted_pms[48];
            uint8_t fallback_pms[48];
            uint32_t decrypted_len = sizeof(decrypted_pms);
            uint32_t use_decrypted = 0u;
            uint8_t mask;
            uint16_t expected_pms_version = ctx->base.base.version;
            drbg_state_t drbg_state;

            if(ctx->client_hello_version != 0u) {
                expected_pms_version = ctx->client_hello_version;
            }
            fallback_pms[0] = (uint8_t)(expected_pms_version >> 8);
            fallback_pms[1] = (uint8_t)(expected_pms_version & 0xFF);
            if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                noxtls_secure_zero(decrypted_pms, sizeof(decrypted_pms));
                noxtls_secure_zero(fallback_pms, sizeof(fallback_pms));
                return NOXTLS_RETURN_FAILED;
            }
            if(drbg_generate(&drbg_state, fallback_pms + 2, 46u * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                noxtls_secure_zero(decrypted_pms, sizeof(decrypted_pms));
                noxtls_secure_zero(fallback_pms, sizeof(fallback_pms));
                return NOXTLS_RETURN_FAILED;
            }
            memset(decrypted_pms, 0, sizeof(decrypted_pms));

        if(ctx->crypto_provider && ctx->crypto_provider->ops && ctx->crypto_provider->ops->rsa_decrypt && ctx->server_private_key_handle) {
            rc = ctx->crypto_provider->ops->rsa_decrypt(ctx->crypto_provider->ctx, ctx->server_private_key_handle,
                    cke_data + msg_offset, encrypted_premaster_len, decrypted_pms, &decrypted_len);
        } else {
            rc = noxtls_rsa_decrypt((const rsa_key_t *)ctx->server_private_rsa,
                                    cke_data + msg_offset, encrypted_premaster_len,
                                    decrypted_pms, &decrypted_len);
        }

            if(rc == NOXTLS_RETURN_SUCCESS && decrypted_len == sizeof(decrypted_pms) &&
               decrypted_pms[0] == (uint8_t)(expected_pms_version >> 8) &&
               decrypted_pms[1] == (uint8_t)(expected_pms_version & 0xFF)) {
                use_decrypted = 1u;
            } else {
                noxtls_debug_printf("[TLS12_DEBUG] RSA premaster validation failed, using random fallback (rc=%d len=%u)\n",
                                    rc, decrypted_len);
            }

            mask = (uint8_t)(0u - (uint8_t)use_decrypted);
            for(uint32_t i = 0; i < sizeof(decrypted_pms); i++) {
                ctx->premaster_secret[i] = (uint8_t)((decrypted_pms[i] & mask) | (fallback_pms[i] & (uint8_t)~mask));
            }
            ctx->premaster_secret_len = 48u;
            noxtls_secure_zero(decrypted_pms, sizeof(decrypted_pms));
            noxtls_secure_zero(fallback_pms, sizeof(fallback_pms));
        }
    } else if(ctx->dhe_ctx != NULL) {
        /* DHE: Parse client's ephemeral public key and compute shared secret */
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = noxtls_tls12_dhe_recv_client_key_exchange(ctx, dhe_ctx, cke_data, cke_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return rc;
        }
        tls12_append_handshake_message(ctx, cke_data, cke_len);
        if(ctx->extended_master_secret_negotiated) {
            ctx->ems_session_transcript_len = ctx->handshake_messages_len;
        }
        if(record.data) noxtls_free(record.data);
        if(reasm) noxtls_free(reasm);
        return NOXTLS_RETURN_SUCCESS;
    } else {
        /* ECDHE: Extract client's ephemeral public key and compute shared secret */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        
        if(ecdhe_ctx == NULL) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            noxtls_debug_printf("ERROR: ECDHE context not initialized\n");
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Parse Client Key Exchange noxtls_message (record already received) */
        uint32_t ecdhe_msg_offset = 4;  /* Skip handshake header */
        uint8_t public_key_len;
        ecc_point_t peer_public_key;
        
        /* Public key length */
        if(ecdhe_msg_offset >= cke_len) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        }
        public_key_len = cke_data[ecdhe_msg_offset++];
        
        /* Public key */
        if(ecdhe_msg_offset + public_key_len > cke_len) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        }

        /* Decode peer's public key / raw key share (X25519/X448 are not ECPoint) */
        if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X25519) {
            if(public_key_len != 32u) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
            rc = noxtls_tls_ecdhe_compute_shared_secret_x25519(ecdhe_ctx, cke_data + ecdhe_msg_offset);
        } else if(ecdhe_ctx->named_group == TLS_NAMED_GROUP_X448) {
            if(public_key_len != 56u) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
            rc = noxtls_tls_ecdhe_compute_shared_secret_x448(ecdhe_ctx, cke_data + ecdhe_msg_offset);
        } else {
            rc = noxtls_tls_decode_ecc_point_uncompressed(cke_data + ecdhe_msg_offset, public_key_len, &peer_public_key, ecdhe_ctx->curve_type);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
            rc = noxtls_tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
        /* Exact ClientKeyExchange body: one length byte + key/point; reject padding or length/body mismatch (tlsfuzzer). */
        if(4u + 1u + (uint32_t)public_key_len != cke_len) {
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        }

        /* Create premaster secret from shared secret for TLS 1.2 */
        if(ecdhe_ctx->shared_secret != NULL && ecdhe_ctx->shared_secret_len > 0) {
            uint32_t premaster_len = tls12_get_ecdh_premaster_len(ecdhe_ctx->named_group);
            if(premaster_len == 0 || ecdhe_ctx->shared_secret_len < premaster_len ||
               premaster_len > sizeof(ctx->premaster_secret)) {
                if(record.data) noxtls_free(record.data);
                if(reasm) noxtls_free(reasm);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_debug_printf("[TLS12_DEBUG] ecdhe premaster_len=%u (group=0x%04X) shared_len=%u\n",
                                  premaster_len, ecdhe_ctx->named_group, ecdhe_ctx->shared_secret_len);
            fflush(stdout);
            tls12_fill_premaster_from_shared(ctx->premaster_secret, premaster_len,
                                             ecdhe_ctx->shared_secret, premaster_len);
            ctx->premaster_secret_len = premaster_len;
            noxtls_debug_printf("[TLS12_DEBUG] ecdhe premaster[0..3]=%02X%02X%02X%02X\n",
                                  ctx->premaster_secret[0], ctx->premaster_secret[1],
                                  ctx->premaster_secret[2], ctx->premaster_secret[3]);
            fflush(stdout);
        } else {
            noxtls_debug_printf("ERROR: ECDHE shared secret not available after Client Key Exchange\n");
            if(record.data) noxtls_free(record.data);
            if(reasm) noxtls_free(reasm);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* Append to handshake messages (for Finished verify_data computation) */
    tls12_append_handshake_message(ctx, cke_data, cke_len);
    if(ctx->extended_master_secret_negotiated) {
        ctx->ems_session_transcript_len = ctx->handshake_messages_len;
    }
    
    if(record.data) noxtls_free(record.data);
    if(reasm) noxtls_free(reasm);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Change Cipher Spec from Client
 */
noxtls_return_t noxtls_tls12_recv_change_cipher_spec_client(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t ccs_plain[8];
    uint32_t ccs_len = sizeof(ccs_plain);
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    while(1) {
        uint32_t app_len = TLS_MAX_RECORD_SIZE;
        uint8_t *app_buf = NULL;
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            break;
        }
        if(!(ctx->renegotiation_in_progress && record.type == TLS_RECORD_APPLICATION_DATA)) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        app_buf = (ctx->record_workspace != NULL) ? ctx->record_workspace : (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE);
        if(app_buf == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                         record.data, record.length,
                                         app_buf, &app_len);
        if(record.data) free(record.data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
            return rc;
        }
        if(app_len > 0u) {
            if(ctx->pending_app_data_len + app_len > sizeof(ctx->pending_app_data)) {
                if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(ctx->pending_app_data + ctx->pending_app_data_len, app_buf, app_len);
            ctx->pending_app_data_len += app_len;
        }
        if(app_buf != ctx->record_workspace) noxtls_free(app_buf);
    }
    if(ctx->renegotiation_in_progress) {
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_CHANGE_CIPHER_SPEC,
                                         record.data, record.length,
                                         ccs_plain, &ccs_len);
        if(record.data) free(record.data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ccs_len != 1u || ccs_plain[0] != TLS_RECORD_CCS_PAYLOAD) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(record.length != 1 || record.data == NULL || record.data[0] != TLS_RECORD_CCS_PAYLOAD) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls12_inc_recv_seq(ctx);
        if(record.data) free(record.data);
    }
    if(ctx->base.base.role == TLS_ROLE_SERVER) {
        ctx->client_seq_num = 0;
    } else {
        ctx->server_seq_num = 0;
    }
    tls12_dtls_on_recv_ccs(ctx);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Receive Finished from Client
 */
noxtls_return_t noxtls_tls12_recv_finished_client(tls12_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    int decrypted_finished = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: record type=%u len=%u\n", record.type, record.length);
    fflush(stdout);
    if(record.type != TLS_RECORD_HANDSHAKE) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t *finished_msg = record.data;
    uint32_t finished_len = record.length;
    uint32_t decrypted_len = TLS_MAX_RECORD_SIZE + TLS_MAX_SECRET_LEN;
    uint8_t *decrypted = ctx->record_workspace;
    if(decrypted == NULL) {
        decrypted = (uint8_t*)noxtls_malloc(decrypted_len);
        if(decrypted == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    /* Finished is encrypted after ChangeCipherSpec */
    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_return_t dec_rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HANDSHAKE,
                                                        record.data, record.length,
                                                        decrypted, &decrypted_len);
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: decrypt rc=%d dec_len=%u\n", (int)dec_rc, decrypted_len);
        fflush(stdout);
        if(record.data) {
            free(record.data);
            record.data = NULL;
        }
        if(dec_rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_DECRYPT_FAIL, dec_rc, record.length);
            if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
            return dec_rc;
        }
        finished_msg = decrypted;
        finished_len = decrypted_len;
        decrypted_finished = 1;
    }

    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: post-decrypt header type=%u len=%u\n",
                          finished_len > 0 ? finished_msg[0] : 0, finished_len);
    fflush(stdout);
    if(finished_len != 16 || finished_msg[0] != TLS_HANDSHAKE_FINISHED) {
        noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: bad decrypted header type=%u len=%u\n",
                              finished_msg[0], finished_len);
        fflush(stdout);
        if(record.data) free(record.data);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Verify finished noxtls_message */
    /* verify_data = PRF(master_secret, "client finished", Hash(handshake_messages))[0..11] */
    noxtls_hash_algos_t hash_algo = tls12_get_prf_hash(ctx->cipher_suite);
    
    uint8_t computed_verify_data[12];
    if(tls12_compute_finished_verify_data(ctx, "client finished", computed_verify_data, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: verify_data computed\n");
    fflush(stdout);

    /* Compare verify_data (starts at offset 4 in Finished noxtls_message) */
    if(noxtls_secret_memcmp(finished_msg + 4, computed_verify_data, 12) != 0) {
        noxtls_debug_printf("ERROR: Client Finished noxtls_message verification failed!\n");
        noxtls_debug_printf("  received: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", finished_msg[4 + i]);
        noxtls_debug_printf("\n  expected: ");
        for(uint32_t i = 0; i < 12; i++) noxtls_debug_printf("%02X ", computed_verify_data[i]);
        noxtls_debug_printf("\n");
        fflush(stdout);
        if(record.data) free(record.data);
        if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
        return NOXTLS_RETURN_TLS_FINISHED_VERIFY_FAILED;
    }
    /* Save client verify_data for RFC 5746 renegotiation_info */
    memcpy(ctx->previous_client_verify_data, finished_msg + 4, 12);
    noxtls_debug_printf("[TLS12_DEBUG] recv_finished_client: verify_data match\n");
    fflush(stdout);

    /* Include verified client Finished in transcript before computing server Finished. */
    tls12_append_handshake_message(ctx, finished_msg, finished_len);

    if(record.data) free(record.data);
    if(decrypted != ctx->record_workspace) noxtls_free(decrypted);
    /* Decrypt path already advances read sequence internally. */
    if(!decrypted_finished) {
        tls12_inc_recv_seq(ctx);
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2 Server: Send Change Cipher Spec
 */
noxtls_return_t noxtls_tls12_send_change_cipher_spec_server(tls12_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = tls12_send_ccs_record(ctx);
    return rc;
}

/**
 * @brief TLS 1.2 Server: Send Finished
 */
noxtls_return_t noxtls_tls12_send_finished_server(tls12_context_t *ctx)
{
    uint8_t finished[TLS_MAX_SECRET_LEN];
    uint32_t offset = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Finished noxtls_message */
    finished[offset++] = TLS_HANDSHAKE_FINISHED;
    finished[offset++] = 0x00;  /* Length (3 bytes) */
    finished[offset++] = 0x00;
    finished[offset++] = (uint8_t)TLS_FINISHED_VERIFY_DATA_LEN_12;  /* verify_data length */
    
    /* Determine hash algorithm based on cipher suite */
    noxtls_hash_algos_t hash_algo = tls12_get_prf_hash(ctx->cipher_suite);
    
    /* Compute verify_data using PRF */
    /* verify_data = PRF(master_secret, "server finished", Hash(handshake_messages))[0..11] */
    if(tls12_compute_finished_verify_data(ctx, "server finished", finished + offset, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Save for RFC 5746 renegotiation_info in next handshake */
    memcpy(ctx->previous_server_verify_data, finished + offset, 12);
    ctx->previous_verify_data_len = 12;
    offset += 12;
    
    /* After Change Cipher Spec, Finished noxtls_message must be encrypted */
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1;
    for(uint32_t k = 0; k < 32; k++) {
        if(ctx->server_write_key[k] != 0) {
            key_is_zero = 0;
            break;
        }
    }
    
    if(key_is_zero) {
        noxtls_debug_printf("WARNING: Keys are zero (placeholder RSA key), sending unencrypted Finished (for testing only!)\n");
        fflush(stdout);
        /* For testing with placeholder keys, send unencrypted */
        noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, finished, offset);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            tls12_inc_send_seq(ctx);
            tls12_append_handshake_message(ctx, finished, offset);
        }
        return rc;
    }
    
    /* Encrypt the Finished noxtls_message before sending */
    uint32_t encrypted_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;
    uint8_t *encrypted_finished = ctx->record_workspace;
    if(encrypted_finished == NULL) {
        encrypted_finished = (uint8_t*)noxtls_malloc(encrypted_len);
        if(encrypted_finished == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    noxtls_return_t rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HANDSHAKE, finished, offset,
                                               encrypted_finished, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ERROR: Failed to encrypt Finished noxtls_message: %d\n", rc);
        fflush(stdout);
        if(encrypted_finished != ctx->record_workspace) noxtls_free(encrypted_finished);
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, encrypted_finished, encrypted_len);
    if(encrypted_finished != ctx->record_workspace) noxtls_free(encrypted_finished);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        /* Encrypt path already advances write sequence internally. */
        tls12_append_handshake_message(ctx, finished, offset);
    }
    return rc;
}

static noxtls_return_t tls12_send_new_session_ticket(tls12_context_t *ctx)
{
    uint8_t msg[4 + 4 + 2 + 48];
    uint8_t ticket[48];
    uint16_t ticket_len = sizeof(ticket);
    uint32_t payload_len = 4u + 2u + (uint32_t)ticket_len;
    uint32_t lifetime_hint = TLS12_TICKET_LIFETIME_HINT;
    drbg_state_t drbg_state;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }

    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ticket, (uint32_t)ticket_len * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    msg[0] = TLS_HANDSHAKE_NEW_SESSION_TICKET;
    msg[1] = (uint8_t)((payload_len >> 16) & 0xFF);
    msg[2] = (uint8_t)((payload_len >> 8) & 0xFF);
    msg[3] = (uint8_t)(payload_len & 0xFF);
    msg[4] = (uint8_t)((lifetime_hint >> 24) & 0xFF);
    msg[5] = (uint8_t)((lifetime_hint >> 16) & 0xFF);
    msg[6] = (uint8_t)((lifetime_hint >> 8) & 0xFF);
    msg[7] = (uint8_t)(lifetime_hint & 0xFF);
    msg[8] = (uint8_t)(ticket_len >> 8);
    msg[9] = (uint8_t)(ticket_len & 0xFF);
    memcpy(msg + 10, ticket, ticket_len);

    {
        uint8_t sni_buf[255];
        uint16_t sni_sl = 0;
        if(ctx->client_extensions.sni != NULL && ctx->client_extensions.sni->hostname != NULL &&
           ctx->client_extensions.sni->name_len > 0u &&
           ctx->client_extensions.sni->name_len <= TLS12_SESSION_SNI_MAX) {
            sni_sl = ctx->client_extensions.sni->name_len;
            memcpy(sni_buf, ctx->client_extensions.sni->hostname, sni_sl);
        }
        tls12_ticket_cache_store(ticket, ticket_len, ctx->master_secret, ctx->cipher_suite,
                                 ctx->negotiated_alpn, ctx->negotiated_alpn_len, lifetime_hint,
                                 ctx->extended_master_secret_negotiated,
                                 (sni_sl > 0u) ? sni_buf : NULL,
                                 sni_sl);
    }

    tls12_append_handshake_message(ctx, msg, (uint32_t)sizeof(msg));
    rc = tls12_send_handshake_record(ctx, msg, (uint32_t)sizeof(msg));
    return rc;
}

static uint8_t tls12_sni_ascii_fold_lc(uint8_t c)
{
    if(c >= (uint8_t)'A' && c <= (uint8_t)'Z') {
        return (uint8_t)(c + 32u);
    }
    return c;
}

static int tls12_sni_eq_dns_case_insensitive(const char *expect, const char *client, uint16_t client_len)
{
    size_t elen;
    uint32_t i;

    if(expect == NULL || client == NULL || client_len == 0u) {
        return 0;
    }
    elen = strlen(expect);
    if(elen == 0u || elen != (size_t)client_len) {
        return 0;
    }
    for(i = 0; i < (uint32_t)elen; i++) {
        if(tls12_sni_ascii_fold_lc((uint8_t)expect[i]) != tls12_sni_ascii_fold_lc((uint8_t)client[i])) {
            return 0;
        }
    }
    return 1;
}

static noxtls_return_t tls12_server_maybe_alert_unrecognized_sni(tls12_context_t *ctx)
{
    const char *exp;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_SUCCESS;
    }
    exp = ctx->server_expect_client_sni;
    if(exp == NULL || exp[0] == '\0') {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ctx->client_extensions.sni == NULL ||
       ctx->client_extensions.sni->hostname == NULL ||
       ctx->client_extensions.sni->name_len == 0u) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(tls12_sni_eq_dns_case_insensitive(exp,
                                         ctx->client_extensions.sni->hostname,
                                         ctx->client_extensions.sni->name_len)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    {
        uint8_t lvl = (ctx->server_expect_sni_fatal != 0u) ? TLS_ALERT_LEVEL_FATAL : TLS_ALERT_LEVEL_WARNING;
        noxtls_return_t arc = noxtls_tls_send_alert(&ctx->base.base, lvl, TLS_ALERT_UNRECOGNIZED_NAME);
        if(arc != NOXTLS_RETURN_SUCCESS) {
            return arc;
        }
        if(ctx->server_expect_sni_fatal != 0u) {
            return NOXTLS_RETURN_TLS_ERROR;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/** Server: arm 1/n-1 style first application record split for TLS 1.0 legacy ClientHello on TLS 1.2 (tlsfuzzer downgrade). */
static void tls12_server_arm_beast_split_if_needed(tls12_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->base.base.role == TLS_ROLE_SERVER &&
       ctx->client_hello_version == TLS_VERSION_1_0 &&
       ctx->base.base.version == TLS_VERSION_1_2) {
        ctx->tls12_beast_split_first_appdata = 1u;
    } else {
        ctx->tls12_beast_split_first_appdata = 0u;
    }
}

/**
 * @brief TLS 1.2 Server: Accept connection
 */
noxtls_return_t noxtls_tls12_accept(tls12_context_t *ctx)
{
    noxtls_return_t rc;
    int client_cert_present = 0;
    int reneg_key_stage = 0;
    uint8_t old_server_write_key[sizeof(ctx->server_write_key)];
    uint8_t old_server_write_iv[sizeof(ctx->server_write_iv)];
    uint8_t old_server_write_mac_key[sizeof(ctx->server_write_mac_key)];
    uint8_t old_client_write_key[sizeof(ctx->client_write_key)];
    uint8_t old_client_write_iv[sizeof(ctx->client_write_iv)];
    uint8_t old_client_write_mac_key[sizeof(ctx->client_write_mac_key)];
    uint8_t new_server_write_key[sizeof(ctx->server_write_key)];
    uint8_t new_server_write_iv[sizeof(ctx->server_write_iv)];
    uint8_t new_server_write_mac_key[sizeof(ctx->server_write_mac_key)];
    uint8_t new_client_write_key[sizeof(ctx->client_write_key)];
    uint8_t new_client_write_iv[sizeof(ctx->client_write_iv)];
    uint8_t new_client_write_mac_key[sizeof(ctx->client_write_mac_key)];
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    /* Receive Client Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_CH);
    do {
        rc = noxtls_tls12_recv_client_hello(ctx);
        if(rc == NOXTLS_RETURN_TIMEOUT && tls12_is_dtls(ctx)) {
            continue;
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
            return rc;
        }
        break;
    } while(1);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
    
    rc = tls12_server_maybe_alert_unrecognized_sni(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Send Server Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_SH);
    rc = noxtls_tls12_send_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
    
    if(ctx->session_resume) {
        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
        rc = tls12_derive_keys(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
            return rc;
        }
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);

        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
        {
            tls_extension_t *ext_st = NULL;
            if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SESSION_TICKET, &ext_st) == NOXTLS_RETURN_SUCCESS &&
               ext_st != NULL) {
                rc = tls12_send_new_session_ticket(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
                    return rc;
                }
            }
        }
        rc = noxtls_tls12_send_change_cipher_spec_server(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
            return rc;
        }
        rc = noxtls_tls12_send_finished_server(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
            return rc;
        }
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);

        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
        rc = noxtls_tls12_recv_change_cipher_spec_client(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
            return rc;
        }
        rc = noxtls_tls12_recv_finished_client(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
            return rc;
        }
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);

        {
            uint8_t sni_buf[255];
            uint16_t sni_sl = 0;
            if(ctx->client_extensions.sni != NULL && ctx->client_extensions.sni->hostname != NULL &&
               ctx->client_extensions.sni->name_len > 0u &&
               ctx->client_extensions.sni->name_len <= TLS12_SESSION_SNI_MAX) {
                sni_sl = ctx->client_extensions.sni->name_len;
                memcpy(sni_buf, ctx->client_extensions.sni->hostname, sni_sl);
            }
            tls12_session_cache_store(ctx->server_session_id,
                                      ctx->server_session_id_len,
                                      ctx->master_secret,
                                      ctx->cipher_suite,
                                      ctx->negotiated_alpn,
                                      ctx->negotiated_alpn_len,
                                      ctx->extended_master_secret_negotiated,
                                      (sni_sl > 0u) ? sni_buf : NULL,
                                      sni_sl);
        }
        tls12_server_arm_beast_split_if_needed(ctx);
        ctx->base.base.state = TLS_STATE_CONNECTED;
        noxtls_dtls_mark_validated(&ctx->base);
        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Send Certificate */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT);
    rc = noxtls_tls12_send_certificate(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_CERT, rc);
    
    /* Send Server Key Exchange (if needed for selected cipher suite) */
    rc = noxtls_tls12_send_server_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ctx->request_client_auth) {
        rc = noxtls_tls12_send_certificate_request(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* Send Server Hello Done */
    rc = noxtls_tls12_send_server_hello_done(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ctx->request_client_auth) {
        rc = tls12_recv_client_certificate(ctx, &client_cert_present);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* Receive Client Key Exchange */
    rc = noxtls_tls12_recv_client_key_exchange(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        uint8_t alert_desc;
        if(rc == NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR) {
            alert_desc = TLS_ALERT_DECODE_ERROR;
        } else if(rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER) {
            alert_desc = TLS_ALERT_ILLEGAL_PARAMETER;
        } else if(rc == NOXTLS_RETURN_BAD_DATA || rc == NOXTLS_RETURN_FAILED) {
            alert_desc = TLS_ALERT_UNEXPECTED_MESSAGE;
        } else {
            alert_desc = TLS_ALERT_BAD_RECORD_MAC;
        }
        /* RFC 5246: malformed/interleaved key exchange leads to fatal alert. */
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, alert_desc);
        return rc;
    }

    if(ctx->renegotiation_in_progress) {
        memcpy(old_server_write_key, ctx->server_write_key, sizeof(old_server_write_key));
        memcpy(old_server_write_iv, ctx->server_write_iv, sizeof(old_server_write_iv));
        memcpy(old_server_write_mac_key, ctx->server_write_mac_key, sizeof(old_server_write_mac_key));
        memcpy(old_client_write_key, ctx->client_write_key, sizeof(old_client_write_key));
        memcpy(old_client_write_iv, ctx->client_write_iv, sizeof(old_client_write_iv));
        memcpy(old_client_write_mac_key, ctx->client_write_mac_key, sizeof(old_client_write_mac_key));
        reneg_key_stage = 1;
    }
    
    /* Compute master secret from premaster secret */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_KEY_SCHEDULE);
    if(ctx->dhe_ctx != NULL) {
        tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
        rc = tls12_compute_master_secret(ctx, dhe_ctx->premaster_secret, dhe_ctx->premaster_secret_len);
    } else {
        rc = tls12_compute_master_secret(ctx, ctx->premaster_secret, ctx->premaster_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);
    
    /* Derive keys from master secret */
    rc = tls12_derive_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);
        return rc;
    }
    if(reneg_key_stage) {
        memcpy(new_server_write_key, ctx->server_write_key, sizeof(new_server_write_key));
        memcpy(new_server_write_iv, ctx->server_write_iv, sizeof(new_server_write_iv));
        memcpy(new_server_write_mac_key, ctx->server_write_mac_key, sizeof(new_server_write_mac_key));
        memcpy(new_client_write_key, ctx->client_write_key, sizeof(new_client_write_key));
        memcpy(new_client_write_iv, ctx->client_write_iv, sizeof(new_client_write_iv));
        memcpy(new_client_write_mac_key, ctx->client_write_mac_key, sizeof(new_client_write_mac_key));
        /*
         * During renegotiation, keep decrypting peer pre-CCS handshake
         * messages with old keys. We'll switch to new client keys after
         * receiving peer CCS, and to new server keys after sending ours.
         */
        memcpy(ctx->server_write_key, old_server_write_key, sizeof(ctx->server_write_key));
        memcpy(ctx->server_write_iv, old_server_write_iv, sizeof(ctx->server_write_iv));
        memcpy(ctx->server_write_mac_key, old_server_write_mac_key, sizeof(ctx->server_write_mac_key));
        memcpy(ctx->client_write_key, old_client_write_key, sizeof(ctx->client_write_key));
        memcpy(ctx->client_write_iv, old_client_write_iv, sizeof(ctx->client_write_iv));
        memcpy(ctx->client_write_mac_key, old_client_write_mac_key, sizeof(ctx->client_write_mac_key));
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, ctx->cipher_suite);
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_KEY_SCHEDULE, rc);

    if(ctx->request_client_auth && client_cert_present) {
        rc = tls12_recv_client_certificate_verify(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* Receive Change Cipher Spec */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
    rc = noxtls_tls12_recv_change_cipher_spec_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        uint8_t alert_desc = (rc == NOXTLS_RETURN_BAD_DATA)
            ? TLS_ALERT_UNEXPECTED_MESSAGE
            : TLS_ALERT_BAD_RECORD_MAC;
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, alert_desc);
        return rc;
    }
    if(reneg_key_stage) {
        memcpy(ctx->client_write_key, new_client_write_key, sizeof(ctx->client_write_key));
        memcpy(ctx->client_write_iv, new_client_write_iv, sizeof(ctx->client_write_iv));
        memcpy(ctx->client_write_mac_key, new_client_write_mac_key, sizeof(ctx->client_write_mac_key));
    }
    
    /* Receive Finished */
    rc = noxtls_tls12_recv_finished_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        /*
         * Server write traffic is still under pre-CCS state here; per TLS 1.2,
         * fatal alert on client Finished failure is sent in current write state.
         * tlsfuzzer (test_fuzzed_finished) expects decrypt_error when verify_data
         * is wrong but the record decrypts (RFC 5246 interop practice).
         */
        {
            uint8_t alert_desc = TLS_ALERT_BAD_RECORD_MAC;
            if(rc == NOXTLS_RETURN_TLS_FINISHED_VERIFY_FAILED) {
                alert_desc = TLS_ALERT_DECRYPT_ERROR;
            } else if(rc == NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED) {
                alert_desc = TLS_ALERT_BAD_RECORD_MAC;
            }
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_FATAL, alert_desc);
        }
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
    
    /* Send Change Cipher Spec */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
    {
        tls_extension_t *ext_st = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_SESSION_TICKET, &ext_st) == NOXTLS_RETURN_SUCCESS &&
           ext_st != NULL) {
            rc = tls12_send_new_session_ticket(ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
                return rc;
            }
        }
    }
    rc = noxtls_tls12_send_change_cipher_spec_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    if(reneg_key_stage) {
        memcpy(ctx->server_write_key, new_server_write_key, sizeof(ctx->server_write_key));
        memcpy(ctx->server_write_iv, new_server_write_iv, sizeof(ctx->server_write_iv));
        memcpy(ctx->server_write_mac_key, new_server_write_mac_key, sizeof(ctx->server_write_mac_key));
    }
    
    /* Send Finished */
    rc = noxtls_tls12_send_finished_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
    
    if(!ctx->session_resume && ctx->server_session_id_len > 0) {
        uint8_t sni_buf[255];
        uint16_t sni_sl = 0;
        if(ctx->client_extensions.sni != NULL && ctx->client_extensions.sni->hostname != NULL &&
           ctx->client_extensions.sni->name_len > 0u &&
           ctx->client_extensions.sni->name_len <= TLS12_SESSION_SNI_MAX) {
            sni_sl = ctx->client_extensions.sni->name_len;
            memcpy(sni_buf, ctx->client_extensions.sni->hostname, sni_sl);
        }
        tls12_session_cache_store(ctx->server_session_id,
                                  ctx->server_session_id_len,
                                  ctx->master_secret,
                                  ctx->cipher_suite,
                                  ctx->negotiated_alpn,
                                  ctx->negotiated_alpn_len,
                                  ctx->extended_master_secret_negotiated,
                                  (sni_sl > 0u) ? sni_buf : NULL,
                                  sni_sl);
    }

    tls12_server_arm_beast_split_if_needed(ctx);
    ctx->base.base.state = TLS_STATE_CONNECTED;
    noxtls_dtls_mark_validated(&ctx->base);
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Send application data
 */
noxtls_return_t noxtls_tls12_send(tls12_context_t *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t encrypted_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;  /* Extra space for IV, padding, MAC */
    uint8_t *encrypted_record = ctx->record_workspace;
    noxtls_return_t rc;
    uint32_t max_payload = (ctx->max_record_payload > 0) ? ctx->max_record_payload : (uint32_t)TLS_MAX_RECORD_SIZE;

    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }

    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(encrypted_record == NULL) {
        encrypted_record = (uint8_t*)noxtls_malloc(encrypted_len);
        if(encrypted_record == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    /* RFC 6066: send in chunks not exceeding max_record_payload */
    uint32_t sent = 0;
    while(sent < len) {
        uint32_t chunk = len - sent;
        if(ctx->base.base.role == TLS_ROLE_SERVER &&
           ctx->tls12_beast_split_first_appdata != 0u &&
           ctx->base.base.version == TLS_VERSION_1_2 &&
           ctx->client_hello_version == TLS_VERSION_1_0 &&
           sent == 0u && len > 1u) {
            chunk = 1u;
        }
        if(chunk > max_payload) {
            chunk = max_payload;
        }
        encrypted_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;
        rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, data + sent, chunk,
                                  encrypted_record, &encrypted_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(encrypted_record != ctx->record_workspace) noxtls_free(encrypted_record);
            return rc;
        }
        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(encrypted_record != ctx->record_workspace) noxtls_free(encrypted_record);
            return rc;
        }
        sent += chunk;
        if(ctx->tls12_beast_split_first_appdata != 0u && sent == 1u &&
           ctx->client_hello_version == TLS_VERSION_1_0) {
            ctx->tls12_beast_split_first_appdata = 0u;
        }
    }
    if(encrypted_record != ctx->record_workspace) noxtls_free(encrypted_record);
    return NOXTLS_RETURN_SUCCESS;
}

/** Send alert encrypted with negotiated keys (TLS 1.2 post-ChangeCipherSpec). */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): alert uses RFC level/description tuple order. */
static noxtls_return_t tls12_send_protected_alert(tls12_context_t *ctx, uint8_t level, uint8_t desc)
{
    uint8_t plain[2];
    uint8_t enc[256];
    uint32_t enc_len = (uint32_t)sizeof(enc);
    plain[0] = level;
    plain[1] = desc;
    noxtls_return_t rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_ALERT, plain, sizeof(plain), enc, &enc_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_ALERT, enc, enc_len);
}

static noxtls_return_t tls12_handle_heartbeat_record(tls12_context_t *ctx, const uint8_t *record_data, uint32_t record_len)
{
    uint8_t *heartbeat = NULL;
    uint32_t heartbeat_len = TLS_MAX_RECORD_SIZE;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(record_len == 0u) {
        /*
         * Empty records still consume one record sequence number. Keep sequence
         * state aligned even when we ignore malformed heartbeat traffic.
         */
        tls12_inc_recv_seq(ctx);
        if(ctx->heartbeat_enabled == 0u || ctx->heartbeat_negotiated == 0u) {
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
        return NOXTLS_RETURN_SUCCESS;
    }
    if(record_len > 0u && record_data == NULL) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    heartbeat = ctx->record_workspace;
    if(heartbeat == NULL) {
        heartbeat = (uint8_t*)noxtls_malloc(heartbeat_len);
        if(heartbeat == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HEARTBEAT,
                                     record_data, record_len,
                                     heartbeat, &heartbeat_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /*
         * Interop fallback: some stacks incorrectly authenticate heartbeat
         * records with application_data content type. Try that before failing.
         */
        heartbeat_len = TLS_MAX_RECORD_SIZE;
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                         record_data, record_len,
                                         heartbeat, &heartbeat_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(heartbeat != ctx->record_workspace) {
            noxtls_free(heartbeat);
        }
        return rc;
    }

    if(ctx->heartbeat_enabled == 0u || ctx->heartbeat_negotiated == 0u) {
        if(heartbeat != ctx->record_workspace) {
            noxtls_free(heartbeat);
        }
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    {
        uint32_t max_pl = (ctx->max_record_payload > 0u)
            ? (uint32_t)ctx->max_record_payload
            : (uint32_t)TLS_MAX_RECORD_SIZE;
        if(heartbeat_len > max_pl) {
            if(heartbeat != ctx->record_workspace) {
                noxtls_free(heartbeat);
            }
            return NOXTLS_RETURN_RECORD_OVERFLOW;
        }
    }

    if(heartbeat_len < 3u) {
        if(heartbeat != ctx->record_workspace) {
            noxtls_free(heartbeat);
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        uint8_t hb_type = heartbeat[0];
        uint16_t payload_len = (uint16_t)(((uint16_t)heartbeat[1] << 8) | heartbeat[2]);
        uint32_t body_len = 3u + (uint32_t)payload_len;
        uint32_t min_len = body_len + TLS_HEARTBEAT_MIN_PADDING_LEN;

        /* RFC 6520: malformed messages are silently discarded. */
        if(min_len > heartbeat_len || body_len < 3u) {
            if(heartbeat != ctx->record_workspace) {
                noxtls_free(heartbeat);
            }
            return NOXTLS_RETURN_SUCCESS;
        }

        if(hb_type == TLS_HEARTBEAT_MESSAGE_REQUEST) {
            uint32_t response_len = body_len + TLS_HEARTBEAT_MIN_PADDING_LEN;
            uint8_t *response_plain = NULL;
            uint8_t *response_cipher = NULL;
            uint32_t response_cipher_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;

            response_plain = (uint8_t*)noxtls_malloc(response_len);
            if(response_plain == NULL) {
                if(heartbeat != ctx->record_workspace) {
                    noxtls_free(heartbeat);
                }
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }

            if(ctx->record_workspace != NULL) {
                response_cipher = ctx->record_workspace;
            } else {
                response_cipher = (uint8_t*)noxtls_malloc(response_cipher_len);
                if(response_cipher == NULL) {
                    noxtls_free(response_plain);
                    if(heartbeat != ctx->record_workspace) {
                        noxtls_free(heartbeat);
                    }
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
            }

            response_plain[0] = TLS_HEARTBEAT_MESSAGE_RESPONSE;
            response_plain[1] = (uint8_t)(payload_len >> 8);
            response_plain[2] = (uint8_t)(payload_len & 0xFF);
            if(payload_len > 0u) {
                memcpy(response_plain + 3u, heartbeat + 3u, payload_len);
            }
            {
                drbg_state_t drbg_state;
                uint32_t pad_offset = 3u + (uint32_t)payload_len;
                if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) == NOXTLS_RETURN_SUCCESS &&
                   drbg_generate(&drbg_state, response_plain + pad_offset,
                                 TLS_HEARTBEAT_MIN_PADDING_LEN * 8u,
                                 NULL, 0) == NOXTLS_RETURN_SUCCESS) {
                } else {
                    memset(response_plain + pad_offset, 0x00, TLS_HEARTBEAT_MIN_PADDING_LEN);
                }
            }

            rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HEARTBEAT,
                                             response_plain, response_len,
                                             response_cipher, &response_cipher_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HEARTBEAT,
                                            response_cipher, response_cipher_len);
            }

            if(ctx->record_workspace == NULL && response_cipher != NULL) {
                noxtls_free(response_cipher);
            }
            noxtls_free(response_plain);
            if(heartbeat != ctx->record_workspace) {
                noxtls_free(heartbeat);
            }
            return rc;
        }
    }

    if(heartbeat != ctx->record_workspace) {
        noxtls_free(heartbeat);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.2: Receive application data
 */
noxtls_return_t noxtls_tls12_recv(tls12_context_t *ctx, uint8_t *data, uint32_t *len)
{
    tls_record_t record;

    if(ctx == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->pending_app_data_len > 0u) {
        if(*len < ctx->pending_app_data_len) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(data, ctx->pending_app_data, ctx->pending_app_data_len);
        *len = ctx->pending_app_data_len;
        ctx->pending_app_data_len = 0u;
        return NOXTLS_RETURN_SUCCESS;
    }

    while(1) {
        noxtls_return_t rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(record.type == TLS_RECORD_ALERT) {
            uint8_t alert[2] = {0};
            uint32_t alert_len = sizeof(alert);
            rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_ALERT, record.data, record.length, alert, &alert_len);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv: alert decrypt failed rc=%d\n", rc);
                fflush(stdout);
                return rc;
            }
            if(alert_len == 2) {
                const char *level_str = (alert[0] == 1) ? "warning" :
                                        (alert[0] == 2) ? "fatal" : "unknown";
                const char *desc_str = "unknown";
                switch(alert[1]) {
                    case 0: desc_str = "close_notify"; break;
                    case 10: desc_str = "unexpected_message"; break;
                    case 20: desc_str = "bad_record_mac"; break;
                    case 21: desc_str = "decryption_failed"; break;
                    case 22: desc_str = "record_overflow"; break;
                    case 40: desc_str = "handshake_failure"; break;
                    case 42: desc_str = "bad_certificate"; break;
                    case 43: desc_str = "unsupported_certificate"; break;
                    case 44: desc_str = "certificate_revoked"; break;
                    case 45: desc_str = "certificate_expired"; break;
                    case 46: desc_str = "certificate_unknown"; break;
                    case 47: desc_str = "illegal_parameter"; break;
                    case 48: desc_str = "unknown_ca"; break;
                    case 49: desc_str = "access_denied"; break;
                    case 50: desc_str = "decode_error"; break;
                    case 51: desc_str = "decrypt_error"; break;
                case 52: desc_str = "too_many_cids_requested"; break;
                    case 70: desc_str = "protocol_version"; break;
                    case 71: desc_str = "insufficient_security"; break;
                    case 80: desc_str = "internal_error"; break;
                    case 86: desc_str = "inappropriate_fallback"; break;
                    case 90: desc_str = "user_canceled"; break;
                    case 109: desc_str = "missing_extension"; break;
                    case 110: desc_str = "unsupported_extension"; break;
                    case 112: desc_str = "unrecognized_name"; break;
                    case 120: desc_str = "no_application_protocol"; break;
                    default: break;
                }
                noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv: alert level=%u (%s) desc=%u (%s)\n",
                                      alert[0], level_str, alert[1], desc_str);
                fflush(stdout);
                if(alert[1] == TLS_ALERT_CLOSE_NOTIFY) {
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    *len = 0;
                    return NOXTLS_RETURN_SUCCESS;
                }
            }
            return NOXTLS_RETURN_FAILED;
        }

        if(record.type == TLS_RECORD_HANDSHAKE) {
            uint32_t handshake_len = TLS_MAX_RECORD_SIZE;
            uint8_t *handshake_buf = ctx->record_workspace;
            if(handshake_buf == NULL) {
                handshake_buf = (uint8_t*)noxtls_malloc(handshake_len);
                if(handshake_buf == NULL) {
                    if(record.data) free(record.data);
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
            }
            rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HANDSHAKE, record.data, record.length,
                                      handshake_buf, &handshake_len);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(handshake_buf != ctx->record_workspace) (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                return rc;
            }
            /* Client: HelloRequest triggers renegotiation (RFC 5746) */
            if(ctx->base.base.role == TLS_ROLE_CLIENT && handshake_len >= 1 &&
               handshake_buf[0] == TLS_HANDSHAKE_HELLO_REQUEST) {
                if(ctx->handshake_messages) {
                    free(ctx->handshake_messages);
                    ctx->handshake_messages = NULL;
                    ctx->handshake_messages_len = 0;
                }
                ctx->renegotiation_in_progress = 1;
                ctx->base.base.state = TLS_STATE_HANDSHAKING;
                rc = noxtls_tls12_send_client_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_server_hello(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_certificate(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_server_key_exchange(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_server_hello_done(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_send_client_key_exchange(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                if(ctx->dhe_ctx != NULL) {
                    tls_dhe_context_t *dhe_ctx = (tls_dhe_context_t*)ctx->dhe_ctx;
                    rc = tls12_compute_master_secret(ctx, dhe_ctx->premaster_secret, dhe_ctx->premaster_secret_len);
                } else {
                    rc = tls12_compute_master_secret(ctx, ctx->premaster_secret, ctx->premaster_secret_len);
                }
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = tls12_derive_keys(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_send_change_cipher_spec(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_send_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_change_cipher_spec(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                rc = noxtls_tls12_recv_finished(ctx);
                if(rc != NOXTLS_RETURN_SUCCESS) { (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0); ctx->renegotiation_in_progress = 0; return rc; }
                ctx->base.base.state = TLS_STATE_CONNECTED;
                ctx->renegotiation_in_progress = 0;
                (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                continue; /* Read next record (application data or another HelloRequest) */
            }
            /* Server: permit only server-requested renegotiation. */
            if(ctx->base.base.role == TLS_ROLE_SERVER && handshake_len >= 1 &&
               handshake_buf[0] == TLS_HANDSHAKE_CLIENT_HELLO) {
                if(ctx->server_renegotiation_requested == 0u) {
                    rc = tls12_send_protected_alert(ctx, TLS_ALERT_LEVEL_WARNING,
                                                    TLS_ALERT_NO_RENEGOTIATION);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                        return rc;
                    }
                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                    continue;
                }
                ctx->server_renegotiation_requested = 0u;
                if(handshake_len < 4u) {
                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                    return NOXTLS_RETURN_FAILED;
                }
                {
                    uint32_t want_len = 4u + ((uint32_t)handshake_buf[1] << 16) +
                                        ((uint32_t)handshake_buf[2] << 8) + (uint32_t)handshake_buf[3];
                    if(want_len < 4u || want_len > TLS_MAX_RECORD_SIZE) {
                        (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(handshake_len < want_len) {
                        uint8_t *frag_buf = (uint8_t*)noxtls_malloc(TLS_MAX_RECORD_SIZE);
                        if(frag_buf == NULL) {
                            (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        }
                        while(handshake_len < want_len) {
                            uint32_t frag_len = TLS_MAX_RECORD_SIZE;
                            rc = noxtls_tls_recv_record(&ctx->base.base, &record);
                            if(rc != NOXTLS_RETURN_SUCCESS) {
                                noxtls_free(frag_buf);
                                (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                                return rc;
                            }
                            if(record.type == TLS_RECORD_HANDSHAKE) {
                                rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_HANDSHAKE,
                                                                 record.data, record.length,
                                                                 frag_buf, &frag_len);
                                if(record.data) free(record.data);
                                if(rc != NOXTLS_RETURN_SUCCESS || frag_len == 0u || handshake_len + frag_len > want_len) {
                                    noxtls_free(frag_buf);
                                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                                    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_FAILED : rc;
                                }
                                memcpy(handshake_buf + handshake_len, frag_buf, frag_len);
                                handshake_len += frag_len;
                                continue;
                            }
                            if(record.type == TLS_RECORD_APPLICATION_DATA) {
                                rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA,
                                                                 record.data, record.length,
                                                                 frag_buf, &frag_len);
                                if(record.data) free(record.data);
                                if(rc != NOXTLS_RETURN_SUCCESS) {
                                    noxtls_free(frag_buf);
                                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                                    return rc;
                                }
                                if(frag_len > 0u) {
                                    if(ctx->pending_app_data_len + frag_len > sizeof(ctx->pending_app_data)) {
                                        noxtls_free(frag_buf);
                                        (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                                        return NOXTLS_RETURN_FAILED;
                                    }
                                    memcpy(ctx->pending_app_data + ctx->pending_app_data_len, frag_buf, frag_len);
                                    ctx->pending_app_data_len += frag_len;
                                }
                                continue;
                            }
                            if(record.data) free(record.data);
                            noxtls_free(frag_buf);
                            (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                            return NOXTLS_RETURN_FAILED;
                        }
                        noxtls_free(frag_buf);
                    }
                    if(handshake_len != want_len) {
                        (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
                if(ctx->handshake_messages) {
                    free(ctx->handshake_messages);
                    ctx->handshake_messages = NULL;
                    ctx->handshake_messages_len = 0;
                }
                ctx->renegotiation_in_progress = 1;
                if(ctx->base.base.pending_client_hello != NULL) {
                    free(ctx->base.base.pending_client_hello);
                    ctx->base.base.pending_client_hello = NULL;
                    ctx->base.base.pending_client_hello_len = 0;
                }
                ctx->base.base.pending_client_hello = (uint8_t*)malloc(handshake_len);
                if(ctx->base.base.pending_client_hello == NULL) {
                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                    ctx->renegotiation_in_progress = 0;
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
                memcpy(ctx->base.base.pending_client_hello, handshake_buf, handshake_len);
                ctx->base.base.pending_client_hello_len = (uint16_t)handshake_len;
                rc = noxtls_tls12_accept(ctx);
                ctx->renegotiation_in_progress = 0;
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                    return rc;
                }
                (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
                *len = 0u;
                return NOXTLS_RETURN_SUCCESS;
            }
            /* Ignore other post-handshake messages (e.g., NewSessionTicket) and read next record. */
            (handshake_buf != ctx->record_workspace ? noxtls_free(handshake_buf) : (void)0);
            continue;
        }

        if(record.type == TLS_RECORD_HEARTBEAT) {
            rc = tls12_handle_heartbeat_record(ctx, record.data, record.length);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                uint8_t ad = (rc == NOXTLS_RETURN_NOT_SUPPORTED)
                    ? TLS_ALERT_UNEXPECTED_MESSAGE
                    : (rc == NOXTLS_RETURN_RECORD_OVERFLOW)
                        ? TLS_ALERT_RECORD_OVERFLOW
                        : TLS_ALERT_BAD_RECORD_MAC;
                (void)tls12_send_protected_alert(ctx, TLS_ALERT_LEVEL_FATAL, ad);
                ctx->base.base.state = TLS_STATE_CLOSED;
                return rc;
            }
            continue;
        }

        if(record.type != TLS_RECORD_APPLICATION_DATA) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }

        /* Decrypt application data */
        rc = noxtls_tls12_decrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, record.data, record.length, data, len);
        if(record.data) free(record.data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv: app decrypt failed rc=%d\n", rc);
            fflush(stdout);
            if(rc == NOXTLS_RETURN_RECORD_OVERFLOW) {
                (void)tls12_send_protected_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_RECORD_OVERFLOW);
            } else {
                (void)tls12_send_protected_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC);
            }
            ctx->base.base.state = TLS_STATE_CLOSED;
            return NOXTLS_RETURN_FAILED;
        }
        /*
         * Some peers may tunnel heartbeat messages in application_data records.
         * If plaintext layout matches RFC 6520 heartbeat, process it here and
         * continue reading the next record.
         */
        if(ctx->heartbeat_enabled != 0u && ctx->heartbeat_negotiated != 0u && *len >= 3u) {
            uint8_t hb_type = data[0];
            uint16_t payload_len = (uint16_t)(((uint16_t)data[1] << 8) | data[2]);
            uint32_t body_len = 3u + (uint32_t)payload_len;
            uint32_t min_len = body_len + TLS_HEARTBEAT_MIN_PADDING_LEN;
            if((hb_type == TLS_HEARTBEAT_MESSAGE_REQUEST || hb_type == TLS_HEARTBEAT_MESSAGE_RESPONSE) &&
               min_len <= *len) {
                uint32_t max_pl = (ctx->max_record_payload > 0u)
                    ? (uint32_t)ctx->max_record_payload
                    : (uint32_t)TLS_MAX_RECORD_SIZE;
                if(*len > max_pl) {
                    (void)tls12_send_protected_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_RECORD_OVERFLOW);
                    ctx->base.base.state = TLS_STATE_CLOSED;
                    return NOXTLS_RETURN_RECORD_OVERFLOW;
                }
                if(hb_type == TLS_HEARTBEAT_MESSAGE_REQUEST) {
                    uint32_t response_len = body_len + TLS_HEARTBEAT_MIN_PADDING_LEN;
                    uint8_t *response_plain = (uint8_t*)noxtls_malloc(response_len);
                    uint8_t *response_cipher = NULL;
                    uint32_t response_cipher_len = TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD;
                    if(response_plain == NULL) {
                        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                    }
                    if(ctx->record_workspace != NULL) {
                        response_cipher = ctx->record_workspace;
                    } else {
                        response_cipher = (uint8_t*)noxtls_malloc(response_cipher_len);
                        if(response_cipher == NULL) {
                            noxtls_free(response_plain);
                            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        }
                    }
                    response_plain[0] = TLS_HEARTBEAT_MESSAGE_RESPONSE;
                    response_plain[1] = (uint8_t)(payload_len >> 8);
                    response_plain[2] = (uint8_t)(payload_len & 0xFF);
                    if(payload_len > 0u) {
                        memcpy(response_plain + 3u, data + 3u, payload_len);
                    }
                    {
                        drbg_state_t drbg_state;
                        uint32_t pad_offset = 3u + (uint32_t)payload_len;
                        if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS ||
                           drbg_generate(&drbg_state, response_plain + pad_offset,
                                         TLS_HEARTBEAT_MIN_PADDING_LEN * 8u,
                                         NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                            memset(response_plain + pad_offset, 0x00, TLS_HEARTBEAT_MIN_PADDING_LEN);
                        }
                    }
                    rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_HEARTBEAT,
                                                     response_plain, response_len,
                                                     response_cipher, &response_cipher_len);
                    if(rc == NOXTLS_RETURN_SUCCESS) {
                        rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HEARTBEAT,
                                                    response_cipher, response_cipher_len);
                    }
                    if(ctx->record_workspace == NULL && response_cipher != NULL) {
                        noxtls_free(response_cipher);
                    }
                    noxtls_free(response_plain);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        return rc;
                    }
                }
                continue;
            }
        }
        noxtls_debug_printf("[TLS12_DEBUG] noxtls_tls12_recv: app decrypt ok len=%u\n", *len);
        fflush(stdout);
        return rc;
    }
}

/**
 * @brief TLS 1.2: Close connection
 */
noxtls_return_t noxtls_tls12_close(tls12_context_t *ctx)
{
    noxtls_return_t rc;
    uint8_t alert[2];
    uint8_t encrypted_alert[256];
    uint32_t encrypted_len = sizeof(encrypted_alert);

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state == TLS_STATE_CLOSED) {
        return NOXTLS_RETURN_SUCCESS;
    }

    alert[0] = TLS_ALERT_LEVEL_WARNING;
    alert[1] = TLS_ALERT_CLOSE_NOTIFY;

    /*
     * After handshake, TLS 1.2 alerts are protected with the negotiated
     * record-layer keys.
     */
    if(ctx->base.base.state == TLS_STATE_CONNECTED) {
        rc = noxtls_tls12_encrypt_record(ctx, TLS_RECORD_ALERT, alert, sizeof(alert),
                                         encrypted_alert, &encrypted_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_ALERT,
                                         encrypted_alert, encrypted_len);
        } else {
            (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
        }
    } else {
        (void)noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    }
    
    ctx->base.base.state = TLS_STATE_CLOSED;
    
    return NOXTLS_RETURN_SUCCESS;
}
